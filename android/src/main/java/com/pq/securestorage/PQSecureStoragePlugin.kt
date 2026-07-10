package com.pq.securestorage

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import com.getcapacitor.JSArray
import com.getcapacitor.JSObject
import com.getcapacitor.Plugin
import com.getcapacitor.PluginCall
import com.getcapacitor.PluginMethod
import com.getcapacitor.annotation.CapacitorPlugin
import org.json.JSONObject
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation
import org.bouncycastle.jcajce.spec.KEMExtractSpec
import org.bouncycastle.jcajce.spec.KEMGenerateSpec
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec

@CapacitorPlugin(name = "PQSecureStorage")
class PQSecureStoragePlugin : Plugin() {

    companion object {
        private const val TAG = "PQSecureStoragePlugin"
        private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
        private const val MAX_STORE_KEY_LEN = 512
        private const val MAX_STORE_VALUE_LEN = 256 * 1024
    }

    private val api17 = 37 // confirm against Android 17 SDK

    // delivers BiometricPrompt callbacks off the UI thread, so the crypto in them doesn't block it
    private val cryptoExecutor = Executors.newSingleThreadExecutor()

    // off in release unless explicitly enabled (adb setprop log.tag.PQSecureStoragePlugin DEBUG),
    // so aliases and exception traces don't leak via logcat
    private fun logd(msg: String, e: Throwable? = null) {
        if (!Log.isLoggable(TAG, Log.DEBUG)) return
        if (e != null) Log.d(TAG, msg, e) else Log.d(TAG, msg)
    }

    private fun algOf(type: String?): String? = when (type) {
        "PQC_MLDSA_65" -> "ML-DSA-65"
        "PQC_MLDSA_87" -> "ML-DSA-87"
        else -> null
    }

    @PluginMethod
    fun getHardwareCapabilities(call: PluginCall) {
        val ok = Build.VERSION.SDK_INT >= api17
        val ret = JSObject()
        ret.put("supportsPqc", ok)
        // probe the real Keystore security level instead of assuming. NOTE: this reflects the TEE
        // for the AES/wrap keys; ML-KEM is always software here, and ML-DSA is hardware only if
        // KeyMint implements it (per-key attestation). See definitions.ts.
        val hw = secureHardwareAvailable()
        ret.put("hardwareBacked", hw)
        // biometricGated is about biometric availability/enrollment, not the TEE: a device can have
        // secure hardware but no enrolled biometric
        val bioAvail = BiometricManager.from(context)
            .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS
        ret.put("biometricGated", bioAvail)
        ret.put("supportedVariants", if (ok) listOf("PQC_MLDSA_65", "PQC_MLDSA_87") else emptyList<String>())
        // ML-KEM works via software (BouncyCastle) on any API; the private key is wrapped by a
        // Keystore AES key. AndroidKeyStore does not expose ML-KEM to apps, so it is NOT in the SEP.
        ret.put("supportedKem", listOf("PQC_MLKEM_768", "PQC_MLKEM_1024"))
        ret.put("kemInSecureEnclave", false)
        call.resolve(ret)
    }

    @PluginMethod
    fun generateKeyPair(call: PluginCall) {
        val alias = call.getString("keyAlias") ?: return call.reject("Missing keyAlias parameter", "E_MISSING_PARAMS")
        if (!safeAlias(call, alias)) return
        val alg = algOf(call.getString("type")) ?: return call.reject("Unsupported key type", "E_UNSUPPORTED")
        val overwrite = call.getBoolean("overwrite") ?: false
        val ks = try {
            KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        } catch (e: Exception) {
            logd("generateKeyPair keystore load failed for alias=$alias", e)
            return call.reject("Key generation failed", "E_KEYGEN")
        }
        val exists = ks.containsAlias(alias)
        if (exists && !overwrite) {
            // alias may back a live identity already -- refuse to silently clobber it
            return call.reject("Alias already exists", "E_ALIAS_EXISTS")
        }
        if (exists) {
            // destructive overwrite of a live signing key: require a real biometric bound to the
            // EXISTING key first, so a silent bridge caller can't rotate/brick an identity key
            val hostActivity = activity as? FragmentActivity
                ?: return call.reject("Host activity is not a FragmentActivity", "E_NO_ACTIVITY")
            authForExistingSign(hostActivity, alias, call) { doGenerateSigningKey(alias, alg, call) }
            return
        }
        doGenerateSigningKey(alias, alg, call)
    }

    @Volatile private var hwCache: Boolean? = null

    // generate a throwaway Keystore AES key and read its real security level: true only if the TEE
    // (or StrongBox) actually backs it, false if KeyMint fell back to the software keystore. Cached
    // and serialized: the answer never changes at runtime, so this is not a keygen on every call and
    // two callers can't race the shared probe alias.
    @Synchronized
    private fun secureHardwareAvailable(): Boolean {
        hwCache?.let { return it }
        val probeAlias = "__pq_hw_probe__"
        val hw = try {
            val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)
            kg.init(
                KeyGenParameterSpec.Builder(probeAlias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .build()
            )
            val key = kg.generateKey()
            val info = SecretKeyFactory.getInstance(key.algorithm, KEYSTORE_PROVIDER)
                .getKeySpec(key, KeyInfo::class.java) as KeyInfo
            // minSdk 34 -> securityLevel is always available (API 31+)
            info.securityLevel != KeyProperties.SECURITY_LEVEL_SOFTWARE
        } catch (e: Exception) {
            logd("hw probe failed", e)
            false
        } finally {
            try {
                KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }.deleteEntry(probeAlias)
            } catch (e: Exception) {
                logd("hw probe cleanup failed", e)
            }
        }
        hwCache = hw
        return hw
    }

    private fun doGenerateSigningKey(alias: String, alg: String, call: PluginCall) {
        try {
            // no pre-delete. Generating to an existing alias replaces it; a failed keygen
            // leaves the old key intact instead of destroying it first.
            //
            // AndroidKeyStore does NOT guarantee TEE/StrongBox placement -- if KeyMint doesn't
            // implement ML-DSA in hardware on this device it silently falls back to the software
            // keystore. getHardwareCapabilities probes the real security level instead of assuming.
            val kpg = KeyPairGenerator.getInstance(alg, KEYSTORE_PROVIDER)
            kpg.initialize(
                KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
                    // Per-operation auth: timeout 0 means there's no time window where the key
                    // just sits unlocked. Every use needs a fresh biometric bound to the specific
                    // CryptoObject/Signature it was requested for (see sign() below). That's what
                    // closes the GHSA-vx5f-vmr6-32wf bypass.
                    .setUserAuthenticationRequired(true)
                    .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                    .build()
            )
            val kp = kpg.generateKeyPair()
            val ret = JSObject()
            ret.put("publicKey", Base64.encodeToString(rawFromSpki(kp.public.encoded), Base64.NO_WRAP))
            call.resolve(ret)
        } catch (e: Exception) {
            logd("generateKeyPair failed for alias=$alias", e)
            call.reject("Key generation failed", "E_KEYGEN")
        }
    }

    // prompt with a Signature bound to an existing Keystore signing key (proves a real biometric on
    // THAT key, GHSA-safe), then run [after]. Gates destructive overwrite of an identity key.
    private fun authForExistingSign(hostActivity: FragmentActivity, alias: String, call: PluginCall, after: () -> Unit) {
        try {
            val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
            val priv = ks.getKey(alias, null) as? java.security.PrivateKey
                ?: return after() // no live key to protect (e.g. half-written alias) -> allow overwrite
            val signer = Signature.getInstance(priv.algorithm)
            try {
                signer.initSign(priv)
            } catch (e: KeyPermanentlyInvalidatedException) {
                // old key already dead (enrollment changed): nothing to protect, allow the overwrite
                logd("existing key invalidated, allowing overwrite for alias=$alias", e)
                return after()
            }
            val cryptoObject = BiometricPrompt.CryptoObject(signer)
            hostActivity.runOnUiThread {
                val settled = AtomicBoolean(false)
                val callback = object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        if (!settled.compareAndSet(false, true)) return
                        try {
                            // a real op with the bound signer: a forged callback can't produce it
                            val s = result.cryptoObject!!.signature!!
                            s.update(byteArrayOf(0)); s.sign()
                            after()
                        } catch (e: KeyPermanentlyInvalidatedException) {
                            logd("existing key invalidated mid-auth, allowing overwrite for alias=$alias", e)
                            after()
                        } catch (e: Exception) {
                            logd("overwrite auth failed for alias=$alias", e)
                            call.reject("Authentication failed", "E_AUTH_FAILED")
                        }
                    }
                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        if (!settled.compareAndSet(false, true)) return
                        call.reject("Authentication failed", "E_AUTH_FAILED")
                    }
                    override fun onAuthenticationFailed() {}
                }
                val promptInfo = BiometricPrompt.PromptInfo.Builder()
                    .setTitle("Authorize key replacement")
                    .setNegativeButtonText("Cancel")
                    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                    .build()
                try {
                    BiometricPrompt(hostActivity, cryptoExecutor, callback).authenticate(promptInfo, cryptoObject)
                } catch (e: Exception) {
                    if (settled.compareAndSet(false, true)) {
                        logd("overwrite prompt failed to start", e)
                        call.reject("Authentication failed", "E_AUTH_FAILED")
                    }
                }
            }
        } catch (e: Exception) {
            logd("overwrite auth setup failed for alias=$alias", e)
            call.reject("Authentication failed", "E_AUTH_FAILED")
        }
    }

    @PluginMethod
    fun getPublicKey(call: PluginCall) {
        val alias = call.getString("keyAlias") ?: return call.reject("Missing keyAlias parameter", "E_MISSING_PARAMS")
        if (!safeAlias(call, alias)) return
        try {
            val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
            val cert = ks.getCertificate(alias) ?: return call.reject("Key not found", "E_PUBKEY")
            val ret = JSObject()
            ret.put("publicKey", Base64.encodeToString(rawFromSpki(cert.publicKey.encoded), Base64.NO_WRAP))
            call.resolve(ret)
        } catch (e: Exception) {
            logd("getPublicKey failed for alias=$alias", e)
            call.reject("Failed to retrieve public key", "E_PUBKEY")
        }
    }

    @PluginMethod
    fun sign(call: PluginCall) {
        val alias = call.getString("keyAlias") ?: return call.reject("Missing keyAlias parameter", "E_MISSING_PARAMS")
        if (!safeAlias(call, alias)) return
        val data = call.getString("data") ?: return call.reject("Missing data parameter", "E_MISSING_PARAMS")
        val type = call.getString("type") ?: return call.reject("Missing type parameter", "E_MISSING_PARAMS")
        val alg = algOf(type) ?: return call.reject("Unsupported key type", "E_UNSUPPORTED")
        // optional host-supplied prompt text (NOT a consent guarantee, see definitions.ts). Cap the
        // length so a caller can't push a giant string or shove real content off-screen.
        val description = call.getString("description")?.take(200)

        // Capacitor's BridgeActivity is a FragmentActivity, which is what BiometricPrompt needs
        // to host its DialogFragment. Any custom host activity has to be one too.
        val hostActivity = activity as? FragmentActivity
            ?: return call.reject("Host activity is not a FragmentActivity", "E_NO_ACTIVITY")

        try {
            val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
            val priv = ks.getKey(alias, null) as? java.security.PrivateKey ?: return call.reject("Key not found", "E_KEY_NOT_FOUND")

            // initSign() here does NOT unlock the key -- it just prepares the Signature object.
            // The Keystore only actually releases the key material inside sign()/update(), and
            // only for the exact Signature instance a real biometric match was bound to below.
            val signer = Signature.getInstance(alg)
            signer.initSign(priv)
            val cryptoObject = BiometricPrompt.CryptoObject(signer)

            // Plugin methods run off the main thread in Capacitor; BiometricPrompt has to be
            // built and started on the UI thread.
            hostActivity.runOnUiThread {
                // guards against onAuthenticationFailed firing more than once (the OS lets the
                // user retry a misread biometric without dismissing the prompt) and then a later
                // callback trying to settle the same call again
                val settled = AtomicBoolean(false)
                val callback = object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        if (!settled.compareAndSet(false, true)) return
                        try {
                            // the SAME Signature the Keystore just hardware-unlocked for this one
                            // authenticated match -- signing with anything else (e.g. a Signature
                            // built after a hooked/forged onAuthenticationSucceeded callback)
                            // throws, because that key was never released
                            val boundSigner = result.cryptoObject!!.signature!!
                            boundSigner.update(Base64.decode(data, Base64.DEFAULT))
                            val ret = JSObject()
                            ret.put("signature", Base64.encodeToString(boundSigner.sign(), Base64.NO_WRAP))
                            call.resolve(ret)
                        } catch (e: KeyPermanentlyInvalidatedException) {
                            logd("sign: key invalidated by enrollment change for alias=$alias", e)
                            call.reject("Biometric enrollment changed; key invalidated", "E_KEY_INVALIDATED")
                        } catch (e: Exception) {
                            logd("sign failed for alias=$alias", e)
                            call.reject("Signing failed", "E_SIGN")
                        }
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        if (!settled.compareAndSet(false, true)) return
                        call.reject("Authentication failed", "E_AUTH_FAILED")
                    }

                    override fun onAuthenticationFailed() {
                        // Biometric attempt did not match, but the prompt stays open for retry.
                        // Only onAuthenticationError and onAuthenticationSucceeded settle the call.
                    }
                }

                val promptInfo = BiometricPrompt.PromptInfo.Builder()
                    .setTitle("Authorize signature")
                    .apply { if (description != null) setSubtitle(description) }
                    .setNegativeButtonText("Cancel")
                    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                    .build()

                try {
                    BiometricPrompt(hostActivity, cryptoExecutor, callback).authenticate(promptInfo, cryptoObject)
                } catch (e: Exception) {
                    if (settled.compareAndSet(false, true)) {
                        logd("biometric prompt failed to start", e)
                        call.reject("Authentication failed", "E_AUTH_FAILED")
                    }
                }
            }
        } catch (e: KeyPermanentlyInvalidatedException) {
            logd("sign setup: key invalidated by enrollment change for alias=$alias", e)
            call.reject("Biometric enrollment changed; key invalidated", "E_KEY_INVALIDATED")
        } catch (e: Exception) {
            logd("sign setup failed for alias=$alias", e)
            call.reject("Signing failed", "E_SIGN")
        }
    }

    // ==== at-rest AES-256-GCM (AndroidKeyStore, TEE, no per-op biometric) ====

    @PluginMethod
    fun encryptAtRest(call: PluginCall) {
        val alias = call.getString("keyAlias") ?: return call.reject("Missing keyAlias parameter", "E_MISSING_PARAMS")
        if (!safeAlias(call, alias)) return
        val data = call.getString("data") ?: return call.reject("Missing data parameter", "E_MISSING_PARAMS")
        try {
            val key = getOrCreateAtRestKey(alias)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key)
            val iv = cipher.iv // 12 bytes
            val ct = cipher.doFinal(Base64.decode(data, Base64.DEFAULT)) // includes tag
            val frame = iv + ct // nonce(12) || aeadCt(+tag16)
            val ret = JSObject()
            ret.put("ciphertext", Base64.encodeToString(frame, Base64.NO_WRAP))
            call.resolve(ret)
        } catch (e: Exception) {
            logd("encryptAtRest failed for alias=$alias", e)
            call.reject("Encrypt failed", "E_ENCRYPT")
        }
    }

    @PluginMethod
    fun decryptAtRest(call: PluginCall) {
        val alias = call.getString("keyAlias") ?: return call.reject("Missing keyAlias parameter", "E_MISSING_PARAMS")
        if (!safeAlias(call, alias)) return
        val data = call.getString("data") ?: return call.reject("Missing data parameter", "E_MISSING_PARAMS")
        try {
            val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
            val key = ks.getKey(atRestAlias(alias), null) as? SecretKey
                ?: return call.reject("Key not found", "E_KEY_NOT_FOUND")
            val frame = Base64.decode(data, Base64.DEFAULT)
            val iv = frame.copyOfRange(0, 12)
            val ct = frame.copyOfRange(12, frame.size)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
            val plain = cipher.doFinal(ct)
            val ret = JSObject()
            ret.put("plaintext", Base64.encodeToString(plain, Base64.NO_WRAP))
            call.resolve(ret)
        } catch (e: Exception) {
            logd("decryptAtRest failed for alias=$alias", e)
            call.reject("Decrypt failed", "E_DECRYPT")
        }
    }

    // ==== asymmetric ML-KEM ====
    //
    // AndroidKeyStore exposes ML-DSA to apps but NOT ML-KEM, so decapsulation is software
    // (BouncyCastle). To keep custody close to hardware: the ML-KEM private key is stored
    // WRAPPED by a biometric-gated Keystore AES key (TEE). Decrypt unwraps it inside a
    // BiometricPrompt CryptoObject (the same GHSA-safe binding as sign()), so a hooked
    // onAuthenticationSucceeded can't release the wrap key. The unwrapped private and the
    // per-message shared secret live in memory only for the decap.
    //
    // on-device-confirm: exact BC labels -- KeyPairGenerator/KeyFactory/KeyGenerator "ML-KEM",
    // MLKEMParameterSpec.ml_kem_768/1024, KEMGenerateSpec/KEMExtractSpec, SecretKeyWithEncapsulation
    // getEncapsulation()/encoded; and that Android's ChaCha20-Poly1305 provider is present.

    // per-alias in-flight guard: the version read-modify-write and wrap-key rotation must not
    // interleave, or two concurrent calls clobber each other's wrap key and brick the private
    private val kemGenerating = java.util.concurrent.ConcurrentHashMap.newKeySet<String>()

    @PluginMethod
    fun generateKemKeyPair(call: PluginCall) {
        val alias = call.getString("keyAlias") ?: return call.reject("Missing keyAlias parameter", "E_MISSING_PARAMS")
        if (!safeAlias(call, alias)) return
        val type = call.getString("type") ?: return call.reject("Missing type parameter", "E_MISSING_PARAMS")
        val spec = mlkemSpecOf(type) ?: return call.reject("Unsupported KEM type", "E_UNSUPPORTED")
        val overwrite = call.getBoolean("overwrite") ?: false
        val hostActivity = activity as? FragmentActivity
            ?: return call.reject("Host activity is not a FragmentActivity", "E_NO_ACTIVITY")
        if (!kemGenerating.add(alias)) return call.reject("Key generation in progress, retry", "E_BUSY")
        try {
            if (!overwrite && kemPrefs().contains(kemPubKeyKey(alias))) {
                kemGenerating.remove(alias)
                return call.reject("Alias already exists", "E_ALIAS_EXISTS")
            }
            val kpg = KeyPairGenerator.getInstance("ML-KEM", bc)
            kpg.initialize(spec, SecureRandom())
            val kp = kpg.generateKeyPair()
            val privBytes = kp.private.encoded // PKCS8
            val rawPub = rawFromSpki(kp.public.encoded) // raw FIPS-203 bytes

            val oldVer = kemPrefs().getInt(kemWrapVerKey(alias), -1)
            val newVer = oldVer + 1
            val wrapKey = createKemWrapKey(alias, newVer)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, wrapKey)
            authenticateCipher(hostActivity, cipher, "Authenticate to create your PQ key", call,
                onError = { kemGenerating.remove(alias) }) { boundCipher ->
                val wrapped = boundCipher.iv + boundCipher.doFinal(privBytes)
                privBytes.fill(0) // raw ML-KEM private no longer needed after wrapping
                // commit() is synchronous+durable, so the old wrap key is retired ONLY after the
                // new state is on disk (a crash can't leave prefs pointing at a deleted key)
                val committed = kemPrefs().edit()
                    .putString(kemPrivKey(alias), Base64.encodeToString(wrapped, Base64.NO_WRAP))
                    .putString(kemPubKeyKey(alias), Base64.encodeToString(rawPub, Base64.NO_WRAP))
                    .putString(kemTagKey(alias), pubTag("kem:$alias", rawPub)) // integrity tag
                    .putString(kemTypeKey(alias), type)
                    .putInt(kemWrapVerKey(alias), newVer)
                    .commit()
                if (committed) {
                    if (oldVer >= 0) {
                        try {
                            val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
                            if (ks.containsAlias(kemWrapAlias(alias, oldVer))) ks.deleteEntry(kemWrapAlias(alias, oldVer))
                        } catch (e: Exception) {
                            logd("kem wrap rotate cleanup failed", e)
                        }
                    }
                    kemGenerating.remove(alias)
                    val ret = JSObject()
                    ret.put("publicKey", Base64.encodeToString(rawPub, Base64.NO_WRAP))
                    call.resolve(ret)
                } else {
                    kemGenerating.remove(alias)
                    call.reject("KEM key generation failed", "E_KEYGEN")
                }
            }
        } catch (e: Exception) {
            kemGenerating.remove(alias)
            logd("generateKemKeyPair failed for alias=$alias", e)
            call.reject("KEM key generation failed", "E_KEYGEN")
        }
    }

    @PluginMethod
    fun getKemPublicKey(call: PluginCall) {
        val alias = call.getString("keyAlias") ?: return call.reject("Missing keyAlias parameter", "E_MISSING_PARAMS")
        if (!safeAlias(call, alias)) return
        val pub = kemPrefs().getString(kemPubKeyKey(alias), null)
            ?: return call.reject("Key not found", "E_KEY_NOT_FOUND")
        // refuse to hand out a public key whose integrity tag doesn't verify (someone tampered
        // the prefs and the app would otherwise advertise an attacker key for inbound encryption)
        val tag = kemPrefs().getString(kemTagKey(alias), null)
        if (!verifyPubTag("kem:$alias", Base64.decode(pub, Base64.DEFAULT), tag)) {
            return call.reject("Public key integrity check failed", "E_TAMPERED")
        }
        val ret = JSObject()
        ret.put("publicKey", pub)
        call.resolve(ret)
    }

    @PluginMethod
    fun encryptTo(call: PluginCall) {
        val pubStr = call.getString("recipientPublicKey") ?: return call.reject("Missing recipientPublicKey", "E_MISSING_PARAMS")
        val type = call.getString("type") ?: return call.reject("Missing type parameter", "E_MISSING_PARAMS")
        val data = call.getString("data") ?: return call.reject("Missing data parameter", "E_MISSING_PARAMS")
        val oid = mlkemOidOf(type) ?: return call.reject("Unsupported KEM type", "E_UNSUPPORTED")
        try {
            // the peer sends a raw public key; rebuild the SPKI wrapper JCA needs to parse it
            val pubKey = mlkemPublicFromRaw(Base64.decode(pubStr, Base64.DEFAULT), oid)
            // encapsulate (software, no alias/biometric) -> (kemCt, sharedSecret)
            val kg = KeyGenerator.getInstance("ML-KEM", bc)
            kg.init(KEMGenerateSpec(pubKey, "AES"), SecureRandom())
            val enc = kg.generateKey() as SecretKeyWithEncapsulation
            val kemCt = enc.encapsulation
            val sharedSecret = enc.encoded // 32 bytes
            val nonce = ByteArray(12).also { SecureRandom().nextBytes(it) }
            val aead = try {
                val cipher = Cipher.getInstance("ChaCha20-Poly1305")
                cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(sharedSecret, "ChaCha20"),
                    javax.crypto.spec.IvParameterSpec(nonce))
                cipher.doFinal(Base64.decode(data, Base64.DEFAULT))
            } finally {
                sharedSecret.fill(0)
            }
            val frame = kemCt + nonce + aead // kemCt || nonce(12) || aeadCt(+tag16)
            val ret = JSObject()
            ret.put("ciphertext", Base64.encodeToString(frame, Base64.NO_WRAP))
            call.resolve(ret)
        } catch (e: Exception) {
            logd("encryptTo failed", e)
            call.reject("Encrypt failed", "E_ENCRYPT")
        }
    }

    @PluginMethod
    fun decrypt(call: PluginCall) {
        val alias = call.getString("keyAlias") ?: return call.reject("Missing keyAlias parameter", "E_MISSING_PARAMS")
        if (!safeAlias(call, alias)) return
        val type = call.getString("type") ?: return call.reject("Missing type parameter", "E_MISSING_PARAMS")
        val data = call.getString("data") ?: return call.reject("Missing data parameter", "E_MISSING_PARAMS")
        val ctLen = when (type) {
            "PQC_MLKEM_768" -> 1088
            "PQC_MLKEM_1024" -> 1568
            else -> return call.reject("Unsupported KEM type", "E_UNSUPPORTED")
        }
        val hostActivity = activity as? FragmentActivity
            ?: return call.reject("Host activity is not a FragmentActivity", "E_NO_ACTIVITY")
        try {
            val storedType = kemPrefs().getString(kemTypeKey(alias), null)
                ?: return call.reject("Key not found", "E_KEY_NOT_FOUND")
            if (storedType != type) return call.reject("Key type mismatch", "E_TYPE_MISMATCH")
            val privStr = kemPrefs().getString(kemPrivKey(alias), null)
                ?: return call.reject("Key not found", "E_KEY_NOT_FOUND")
            val ver = kemPrefs().getInt(kemWrapVerKey(alias), -1)
            if (ver < 0) return call.reject("Key not found", "E_KEY_NOT_FOUND")
            val privBlob = Base64.decode(privStr, Base64.DEFAULT)
            val frame = Base64.decode(data, Base64.DEFAULT)
            if (frame.size <= ctLen + 12) return call.reject("Malformed ciphertext", "E_BAD_CIPHERTEXT")

            val wrapIv = privBlob.copyOfRange(0, 12)
            val wrapped = privBlob.copyOfRange(12, privBlob.size)
            val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
            val wrapKey = ks.getKey(kemWrapAlias(alias, ver), null) as? SecretKey
                ?: return call.reject("Key not found", "E_KEY_NOT_FOUND")
            val unwrapCipher = Cipher.getInstance("AES/GCM/NoPadding")
            unwrapCipher.init(Cipher.DECRYPT_MODE, wrapKey, GCMParameterSpec(128, wrapIv))

            authenticateCipher(hostActivity, unwrapCipher, "Authenticate to decrypt with your PQ key", call) { boundCipher ->
                val privBytes = boundCipher.doFinal(wrapped)
                val privKey = KeyFactory.getInstance("ML-KEM", bc).generatePrivate(PKCS8EncodedKeySpec(privBytes))
                val kemCt = frame.copyOfRange(0, ctLen)
                val nonce = frame.copyOfRange(ctLen, ctLen + 12)
                val aead = frame.copyOfRange(ctLen + 12, frame.size)
                val kg = KeyGenerator.getInstance("ML-KEM", bc)
                kg.init(KEMExtractSpec(privKey, kemCt, "AES"))
                val dec = kg.generateKey() as SecretKeyWithEncapsulation
                val sharedSecret = dec.encoded
                val cipher = Cipher.getInstance("ChaCha20-Poly1305")
                cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(sharedSecret, "ChaCha20"),
                    javax.crypto.spec.IvParameterSpec(nonce))
                val plain = cipher.doFinal(aead)
                privBytes.fill(0)
                sharedSecret.fill(0)
                val ret = JSObject()
                ret.put("plaintext", Base64.encodeToString(plain, Base64.NO_WRAP))
                call.resolve(ret)
            }
        } catch (e: KeyPermanentlyInvalidatedException) {
            logd("decrypt: key invalidated by biometric enrollment", e)
            call.reject("Biometric enrollment changed; key invalidated", "E_KEY_INVALIDATED")
        } catch (e: Exception) {
            logd("decrypt failed for alias=$alias", e)
            call.reject("Decrypt failed", "E_DECRYPT")
        }
    }

    // ==== helpers ====

    private val bc by lazy {
        BouncyCastleProvider().also { java.security.Security.addProvider(it) }
    }

    private fun mlkemSpecOf(type: String?): MLKEMParameterSpec? = when (type) {
        "PQC_MLKEM_768" -> MLKEMParameterSpec.ml_kem_768
        "PQC_MLKEM_1024" -> MLKEMParameterSpec.ml_kem_1024
        else -> null
    }

    // ---- public key wire format ----
    // Public keys cross the JS bridge as raw fixed-length bytes (FIPS 203/204), same as iOS
    // CryptoKit rawRepresentation. JCA getEncoded() returns a DER SubjectPublicKeyInfo, so strip
    // the wrapper on the way out and rebuild it on the way in.
    // on-device-confirm: NISTObjectIdentifiers constant names for ML-KEM/ML-DSA, and that
    // SubjectPublicKeyInfo.publicKeyData.bytes equals the raw key bytes (1568 for ML-KEM-1024 etc).
    private fun mlkemOidOf(type: String?): ASN1ObjectIdentifier? = when (type) {
        "PQC_MLKEM_768" -> NISTObjectIdentifiers.id_alg_ml_kem_768
        "PQC_MLKEM_1024" -> NISTObjectIdentifiers.id_alg_ml_kem_1024
        else -> null
    }

    private fun rawFromSpki(encoded: ByteArray): ByteArray =
        SubjectPublicKeyInfo.getInstance(encoded).publicKeyData.bytes

    private fun mlkemPublicFromRaw(raw: ByteArray, oid: ASN1ObjectIdentifier): PublicKey {
        // reject a wrong-size raw key before wrapping it in SPKI (FIPS-203 fixed lengths)
        val expected = when (oid) {
            NISTObjectIdentifiers.id_alg_ml_kem_768 -> 1184
            NISTObjectIdentifiers.id_alg_ml_kem_1024 -> 1568
            else -> throw IllegalArgumentException("unsupported ML-KEM oid")
        }
        if (raw.size != expected) throw IllegalArgumentException("bad ML-KEM public key length")
        val spki = SubjectPublicKeyInfo(AlgorithmIdentifier(oid), raw)
        return KeyFactory.getInstance("ML-KEM", bc).generatePublic(X509EncodedKeySpec(spki.encoded))
    }

    // ---- public-key integrity tag ----
    // Stored pubs live in tamperable prefs and get encapsulated to with no biometric. Tag them with
    // an HMAC keyed by a non-exportable Keystore key so a swapped pub is rejected before we encrypt
    // to it. The context string pins a tag to one entry so it can't be moved between aliases.
    private val pubTagKeyAlias = "__pq_pub_tag_hmac__"

    private fun getOrCreatePubTagKey(): SecretKey {
        val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        (ks.getKey(pubTagKeyAlias, null) as? SecretKey)?.let { return it }
        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, KEYSTORE_PROVIDER)
        kg.init(
            KeyGenParameterSpec.Builder(
                pubTagKeyAlias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            ).build()
        )
        return kg.generateKey()
    }

    // 4-byte length prefix per field so concatenated inputs can't be reinterpreted (a 2-byte
    // prefix wraps past 64KiB and lets a long field collide with a short one)
    private fun macPut(mac: Mac, b: ByteArray) {
        val n = b.size
        mac.update(byteArrayOf((n ushr 24).toByte(), (n ushr 16).toByte(), (n ushr 8).toByte(), n.toByte()))
        mac.update(b)
    }

    private fun pubTag(context: String, rawPub: ByteArray): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(getOrCreatePubTagKey())
        macPut(mac, context.toByteArray(Charsets.UTF_8))
        macPut(mac, rawPub)
        return Base64.encodeToString(mac.doFinal(), Base64.NO_WRAP)
    }

    private fun verifyPubTag(context: String, rawPub: ByteArray, tag: String?): Boolean {
        if (tag == null) return false
        return MessageDigest.isEqual(
            pubTag(context, rawPub).toByteArray(Charsets.UTF_8),
            tag.toByteArray(Charsets.UTF_8)
        )
    }

    // ---- store item integrity MAC ----
    // Items are encapsulated to the store's PUBLIC key, so a prefs writer could otherwise inject or
    // swap arbitrary values. A Keystore-held HMAC over (itemKey || frame) makes forgery need the TEE
    // key, and binds the value to its key name. Verified before decrypting.
    private val ssMacAlias = "__pq_ss_mac__"

    private fun getOrCreateStoreMacKey(): SecretKey {
        val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        (ks.getKey(ssMacAlias, null) as? SecretKey)?.let { return it }
        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, KEYSTORE_PROVIDER)
        kg.init(
            KeyGenParameterSpec.Builder(ssMacAlias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY).build()
        )
        return kg.generateKey()
    }

    // MAC binds the item to its key name AND its biometric mode, so a prefs writer can't move a
    // value between keys or downgrade a bio item to silent.
    private fun storeMac(itemKey: String, mode: String, frame: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(getOrCreateStoreMacKey())
        macPut(mac, itemKey.toByteArray(Charsets.UTF_8))
        macPut(mac, mode.toByteArray(Charsets.UTF_8))
        macPut(mac, frame)
        return mac.doFinal()
    }

    // legacy items were written before the mode existed (2-part "frame.mac"); treated as bio
    private fun storeMacLegacy(itemKey: String, frame: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(getOrCreateStoreMacKey())
        macPut(mac, itemKey.toByteArray(Charsets.UTF_8))
        macPut(mac, frame)
        return mac.doFinal()
    }

    // ---- item-name confidentiality ----
    // The SharedPreferences key is a keyed hash of the item name (not the plaintext), so a prefs
    // reader never sees names like "seed-phrase". The real name is also stored AES-encrypted inside
    // the value so keys() can still list them. Both keys live in the TEE.
    private val ssNameKeyAlias = "__pq_ss_namekey__"

    private fun getOrCreateStoreNameKey(): SecretKey {
        val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        (ks.getKey(ssNameKeyAlias, null) as? SecretKey)?.let { return it }
        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)
        kg.init(
            KeyGenParameterSpec.Builder(ssNameKeyAlias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return kg.generateKey()
    }

    // deterministic keyed hash -> the prefs key. Same name always maps to the same tag (so lookups
    // work), but the TEE HMAC key means it can't be reversed or forged.
    private fun nameTag(name: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(getOrCreateStoreMacKey())
        macPut(mac, "name".toByteArray(Charsets.UTF_8)) // domain-separate from storeMac
        macPut(mac, name.toByteArray(Charsets.UTF_8))
        return Base64.encodeToString(mac.doFinal(), Base64.NO_WRAP)
    }

    private fun encName(name: String): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateStoreNameKey())
        return Base64.encodeToString(cipher.iv + cipher.doFinal(name.toByteArray(Charsets.UTF_8)), Base64.NO_WRAP)
    }

    private fun decName(encB64: String): String {
        val blob = Base64.decode(encB64, Base64.DEFAULT)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, getOrCreateStoreNameKey(), GCMParameterSpec(128, blob.copyOfRange(0, 12)))
        return String(cipher.doFinal(blob.copyOfRange(12, blob.size)), Charsets.UTF_8)
    }

    // extract the mode field without the name / MAC check (only used to decide whether clear() should
    // prompt; the real integrity check is in parseStoreItem on read)
    private fun storedMode(stored: String): String {
        val parts = stored.split(".")
        return when (parts.size) {
            4 -> parts[1]
            3 -> parts[0]
            else -> "b"
        }
    }

    // reject aliases that could collide with the plugin's internal Keystore entries (they use a
    // "__pq" prefix and "." suffixes); dots are disallowed so a user alias can never equal an
    // internal suffixed entry like "$alias.aes"/"$alias.kemwrap".
    private val aliasRegex = Regex("^[A-Za-z0-9_-]{1,64}$")

    private fun safeAlias(call: PluginCall, alias: String): Boolean {
        if (!aliasRegex.matches(alias) || alias.startsWith("__pq")) {
            call.reject("Invalid key alias", "E_BAD_ALIAS")
            return false
        }
        return true
    }

    private fun atRestAlias(alias: String) = "$alias.aes"
    private fun kemWrapAlias(alias: String, ver: Int) = "$alias.kemwrap.$ver"
    private fun kemWrapVerKey(alias: String) = "$alias.wrapver"
    private fun kemPrefs() = context.getSharedPreferences("pq_kem", android.content.Context.MODE_PRIVATE)
    private fun kemPrivKey(alias: String) = "$alias.priv"
    private fun kemPubKeyKey(alias: String) = "$alias.pub"
    private fun kemTypeKey(alias: String) = "$alias.type"
    private fun kemTagKey(alias: String) = "$alias.tag"

    private fun getOrCreateAtRestKey(alias: String): SecretKey {
        val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        (ks.getKey(atRestAlias(alias), null) as? SecretKey)?.let { return it }
        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)
        kg.init(
            KeyGenParameterSpec.Builder(
                atRestAlias(alias),
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return kg.generateKey()
    }

    private fun createKemWrapKey(alias: String, ver: Int): SecretKey {
        // a fresh wrap key per generation (versioned alias). On overwrite the old version is
        // deleted after the new keypair is persisted, so a restored pre-rotation wrapped-private
        // can no longer be unwrapped. Clear any orphan at this version first (cancelled attempt).
        val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        if (ks.containsAlias(kemWrapAlias(alias, ver))) ks.deleteEntry(kemWrapAlias(alias, ver))
        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)
        kg.init(
            KeyGenParameterSpec.Builder(
                kemWrapAlias(alias, ver),
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                // per-op biometric bound to the cipher (same GHSA-safe pattern as sign())
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                .build()
        )
        return kg.generateKey()
    }

    // shared BiometricPrompt(CryptoObject(cipher)) flow -- the Keystore only releases the wrap
    // key inside the exact Cipher a real biometric match unlocked, so a hooked callback is useless
    private fun authenticateCipher(
        hostActivity: FragmentActivity,
        cipher: Cipher,
        reason: String,
        call: PluginCall,
        onError: () -> Unit = {},
        onSuccess: (Cipher) -> Unit
    ) {
        val cryptoObject = BiometricPrompt.CryptoObject(cipher)
        hostActivity.runOnUiThread {
            val settled = AtomicBoolean(false)
            // background executor: the KEM/AES work in onSuccess runs off the UI thread
            val callback = object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    if (!settled.compareAndSet(false, true)) return
                    try {
                        onSuccess(result.cryptoObject!!.cipher!!)
                    } catch (e: KeyPermanentlyInvalidatedException) {
                        // biometric set changed mid-op: the key is gone, tell the caller to re-enroll
                        logd("key invalidated during cipher op", e)
                        onError()
                        call.reject("Biometric enrollment changed; key invalidated", "E_KEY_INVALIDATED")
                    } catch (e: Exception) {
                        logd("cipher op failed", e)
                        onError()
                        call.reject("Operation failed", "E_CRYPTO")
                    }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    if (!settled.compareAndSet(false, true)) return
                    onError()
                    call.reject("Authentication failed", "E_AUTH_FAILED")
                }

                override fun onAuthenticationFailed() {
                    // biometric mismatch, prompt stays open for retry -- don't settle
                }
            }
            try {
                val promptInfo = BiometricPrompt.PromptInfo.Builder()
                    .setTitle(reason)
                    .setNegativeButtonText("Cancel")
                    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                    .build()
                BiometricPrompt(hostActivity, cryptoExecutor, callback).authenticate(promptInfo, cryptoObject)
            } catch (e: Exception) {
                // authenticate() can throw if the activity is backgrounding; settle the call so the
                // caller's in-flight latch (ssInitializing / kemGenerating) is always released
                if (settled.compareAndSet(false, true)) {
                    logd("biometric prompt failed to start", e)
                    onError()
                    call.reject("Authentication failed", "E_AUTH_FAILED")
                }
            }
        }
    }

    // ==== secure storage (self-addressed ML-KEM-1024 envelope, silent write / gated read) ====
    //
    // The store owns one ML-KEM-1024 keypair. setItem encapsulates to its public key (software,
    // no auth). getItem decapsulates with the private key, which is stored WRAPPED by an
    // auth-required Keystore AES key and unwrapped inside a BiometricPrompt CryptoObject (same
    // GHSA-safe binding as sign/decrypt). The first setItem creates the keypair and wraps the
    // private, which needs one biometric prompt; after that setItem is silent.

    private val ssMasterAlias = "__pq_ss_master__"    // bio wrap key (auth-required)
    private val ssSilentAlias = "__pq_ss_silent__"    // silent wrap key (no auth)
    private val ssInitializing = AtomicBoolean(false)       // bio keypair provisioning
    private val ssInitializingSilent = AtomicBoolean(false) // silent keypair provisioning

    private fun storeItems() = context.getSharedPreferences("pq_secure_store", android.content.Context.MODE_PRIVATE)
    private fun storeMeta() = context.getSharedPreferences("pq_secure_store_key", android.content.Context.MODE_PRIVATE)

    private class StoreItem(val mode: String, val frame: ByteArray)

    // parse "mode.frame.mac" (new) or legacy "frame.mac" (=bio); verify the MAC. null = corrupt/forged.
    // base64 NO_WRAP never contains '.', so splitting on it is unambiguous.
    private fun parseStoreItem(key: String, stored: String): StoreItem? {
        val parts = stored.split(".")
        return try {
            when (parts.size) {
                4 -> {
                    // encName . mode . frame . mac  (encName is only for keys(); ignored here)
                    val mode = parts[1]
                    if (mode != "s" && mode != "b") return null
                    val frame = Base64.decode(parts[2], Base64.DEFAULT)
                    val mac = Base64.decode(parts[3], Base64.DEFAULT)
                    if (MessageDigest.isEqual(mac, storeMac(key, mode, frame))) StoreItem(mode, frame) else null
                }
                3 -> {
                    val mode = parts[0]
                    if (mode != "s" && mode != "b") return null
                    val frame = Base64.decode(parts[1], Base64.DEFAULT)
                    val mac = Base64.decode(parts[2], Base64.DEFAULT)
                    if (MessageDigest.isEqual(mac, storeMac(key, mode, frame))) StoreItem(mode, frame) else null
                }
                2 -> {
                    val frame = Base64.decode(parts[0], Base64.DEFAULT)
                    val mac = Base64.decode(parts[1], Base64.DEFAULT)
                    if (MessageDigest.isEqual(mac, storeMacLegacy(key, frame))) StoreItem("b", frame) else null
                }
                else -> null
            }
        } catch (e: Exception) {
            null
        }
    }

    @PluginMethod
    fun setItem(call: PluginCall) {
        val key = call.getString("key") ?: return call.reject("Missing key", "E_MISSING_PARAMS")
        val value = call.getString("value") ?: return call.reject("Missing value", "E_MISSING_PARAMS")
        // bound both so a caller can't fill prefs/keystore with a giant blob (DoS)
        if (key.isEmpty() || key.length > MAX_STORE_KEY_LEN || value.length > MAX_STORE_VALUE_LEN) {
            return call.reject("Key or value out of bounds", "E_INVALID_ARGS")
        }
        val newMode = if (call.getBoolean("requireBiometric") ?: false) "b" else "s"
        val existing = storeItems().getString(key, null)
        val existingItem = existing?.let { parseStoreItem(key, it) }
        if (existing != null && existingItem == null) {
            return call.reject("Store item integrity check failed", "E_TAMPERED")
        }
        // overwriting a bio item requires biometric, so a silent bridge caller can't replace or
        // downgrade a secret that was stored biometric
        if (existingItem?.mode == "b") {
            return overwriteBioItem(call, key, value, newMode)
        }
        if (newMode == "s") setSilent(call, key, value) else setBio(call, key, value)
    }

    // silent write: encapsulate to the silent tier public (provisioning it once if absent, no prompt)
    private fun setSilent(call: PluginCall, key: String, value: String) {
        try {
            val pub = ensureSilentPub(call) ?: return
            persistItem(key, value, pub, "s")
            call.resolve()
        } catch (e: Exception) {
            logd("setItem(silent) failed for key=$key", e)
            call.reject("Store failed", "E_ENCRYPT")
        }
    }

    // bio write: encapsulate to the bio tier public. Encapsulation needs no private, so it's silent
    // once the bio keypair exists; only the first-ever bio write prompts to wrap the bio private.
    private fun setBio(call: PluginCall, key: String, value: String) {
        val meta = storeMeta()
        val pubB64 = meta.getString("pub", null)
        if (meta.contains("priv") && pubB64 != null) {
            // a bio write after a biometric enrollment change encapsulates to a keypair whose private
            // can never be unwrapped again. Detect the dead wrap key: if it's alive, take the fast
            // path; if it's invalidated, rotate to a fresh bio keypair (old bio items were already
            // unreadable, so nothing extra is lost) instead of bricking every future bio write.
            val invalidated = try {
                val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
                (ks.getKey(ssMasterAlias, null) as? SecretKey)?.let {
                    Cipher.getInstance("AES/GCM/NoPadding").init(Cipher.ENCRYPT_MODE, it)
                }
                false
            } catch (e: KeyPermanentlyInvalidatedException) {
                true
            } catch (e: Exception) {
                false // other init errors (needs auth etc.) mean the key is still usable
            }
            if (!invalidated) {
                try {
                    val rawPub = Base64.decode(pubB64, Base64.DEFAULT)
                    if (!verifyPubTag("ss:master", rawPub, meta.getString("tag", null))) {
                        return call.reject("Store key integrity check failed", "E_TAMPERED")
                    }
                    persistItem(key, value, mlkemPublicFromRaw(rawPub, NISTObjectIdentifiers.id_alg_ml_kem_1024), "b")
                    call.resolve()
                } catch (e: Exception) {
                    logd("setItem(bio) failed for key=$key", e)
                    call.reject("Store failed", "E_ENCRYPT")
                }
                return
            }
            // dead bio tier: drop the invalidated wrap key + stale meta, then fall through to
            // re-provision a fresh keypair below
            try {
                val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
                if (ks.containsAlias(ssMasterAlias)) ks.deleteEntry(ssMasterAlias)
            } catch (e: Exception) {
                logd("setItem(bio) rotate: delete failed", e)
            }
            meta.edit().remove("priv").remove("pub").remove("tag").commit()
        }
        val hostActivity = activity as? FragmentActivity
            ?: return call.reject("Host activity is not a FragmentActivity", "E_NO_ACTIVITY")
        if (!ssInitializing.compareAndSet(false, true)) {
            return call.reject("Store is initializing, retry", "E_BUSY")
        }
        try {
            val kpg = KeyPairGenerator.getInstance("ML-KEM", bc)
            kpg.initialize(MLKEMParameterSpec.ml_kem_1024, SecureRandom())
            val kp = kpg.generateKeyPair()
            val privBytes = kp.private.encoded
            val rawPub = rawFromSpki(kp.public.encoded)
            val wrapKey = getOrCreateSsMasterWrapKey()
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, wrapKey)
            authenticateCipher(hostActivity, cipher, "Authenticate to set up secure storage", call,
                onError = { ssInitializing.set(false) }) { boundCipher ->
                val wrapped = boundCipher.iv + boundCipher.doFinal(privBytes)
                privBytes.fill(0)
                val ok = meta.edit()
                    .putString("priv", Base64.encodeToString(wrapped, Base64.NO_WRAP))
                    .putString("pub", Base64.encodeToString(rawPub, Base64.NO_WRAP))
                    .putString("tag", pubTag("ss:master", rawPub))
                    .commit()
                if (ok) {
                    persistItem(key, value, kp.public, "b")
                    ssInitializing.set(false)
                    call.resolve()
                } else {
                    ssInitializing.set(false)
                    call.reject("Store failed", "E_ENCRYPT")
                }
            }
        } catch (e: Exception) {
            ssInitializing.set(false)
            logd("setItem(bio) keygen failed for key=$key", e)
            call.reject("Store failed", "E_ENCRYPT")
        }
    }

    // replacing a bio item: prove biometric first (bind to the bio wrap key), then write in the
    // requested mode (bio kept, or silent = an explicit user-authorized downgrade)
    private fun overwriteBioItem(call: PluginCall, key: String, value: String, newMode: String) {
        val hostActivity = activity as? FragmentActivity
            ?: return call.reject("Host activity is not a FragmentActivity", "E_NO_ACTIVITY")
        val privB64 = storeMeta().getString("priv", null)
        val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        val wrapKey = ks.getKey(ssMasterAlias, null) as? SecretKey
        if (privB64 == null || wrapKey == null) {
            return call.reject("Store key missing", "E_KEY_NOT_FOUND")
        }
        try {
            val privBlob = Base64.decode(privB64, Base64.DEFAULT)
            val wrapped = privBlob.copyOfRange(12, privBlob.size)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, wrapKey, GCMParameterSpec(128, privBlob.copyOfRange(0, 12)))
            authenticateCipher(hostActivity, cipher, "Authenticate to replace your secret", call) { boundCipher ->
                try {
                    // unwrap with the bound cipher so a forged callback can't replace/downgrade the item
                    boundCipher.doFinal(wrapped)
                    if (newMode == "b") {
                        val rawPub = Base64.decode(storeMeta().getString("pub", null), Base64.DEFAULT)
                        // verify the store pub tag (same as setBio) so a swapped pub can't redirect
                        // the re-encapsulated value to an attacker key
                        if (!verifyPubTag("ss:master", rawPub, storeMeta().getString("tag", null))) {
                            call.reject("Store key integrity check failed", "E_TAMPERED")
                            return@authenticateCipher
                        }
                        persistItem(key, value, mlkemPublicFromRaw(rawPub, NISTObjectIdentifiers.id_alg_ml_kem_1024), "b")
                        call.resolve()
                    } else {
                        val pub = ensureSilentPub(call) ?: return@authenticateCipher
                        persistItem(key, value, pub, "s")
                        call.resolve()
                    }
                } catch (e: Exception) {
                    logd("overwriteBioItem persist failed for key=$key", e)
                    call.reject("Store failed", "E_ENCRYPT")
                }
            }
        } catch (e: KeyPermanentlyInvalidatedException) {
            logd("overwriteBioItem: bio key invalidated", e)
            call.reject("Biometric enrollment changed; store key invalidated", "E_KEY_INVALIDATED")
        } catch (e: Exception) {
            logd("overwriteBioItem failed for key=$key", e)
            call.reject("Store failed", "E_ENCRYPT")
        }
    }

    // silent tier public, provisioning the silent keypair on first use (no prompt). Rejects the
    // call (and returns null) on tamper or provisioning contention.
    private fun ensureSilentPub(call: PluginCall): PublicKey? {
        val meta = storeMeta()
        val pubB64 = meta.getString("pub_s", null)
        if (meta.contains("priv_s") && pubB64 != null) {
            val rawPub = Base64.decode(pubB64, Base64.DEFAULT)
            if (!verifyPubTag("ss:silent", rawPub, meta.getString("tag_s", null))) {
                call.reject("Store key integrity check failed", "E_TAMPERED"); return null
            }
            return mlkemPublicFromRaw(rawPub, NISTObjectIdentifiers.id_alg_ml_kem_1024)
        }
        if (!ssInitializingSilent.compareAndSet(false, true)) {
            call.reject("Store is initializing, retry", "E_BUSY"); return null
        }
        try {
            // re-check under the gate in case another thread just provisioned
            val pb = meta.getString("pub_s", null)
            if (meta.contains("priv_s") && pb != null) {
                val rawPub = Base64.decode(pb, Base64.DEFAULT)
                if (!verifyPubTag("ss:silent", rawPub, meta.getString("tag_s", null))) {
                    call.reject("Store key integrity check failed", "E_TAMPERED"); return null
                }
                return mlkemPublicFromRaw(rawPub, NISTObjectIdentifiers.id_alg_ml_kem_1024)
            }
            val kpg = KeyPairGenerator.getInstance("ML-KEM", bc)
            kpg.initialize(MLKEMParameterSpec.ml_kem_1024, SecureRandom())
            val kp = kpg.generateKeyPair()
            val rawPub = rawFromSpki(kp.public.encoded)
            val wrapKey = getOrCreateSsSilentWrapKey()
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, wrapKey)
            val privBytes = kp.private.encoded
            val wrapped = cipher.iv + cipher.doFinal(privBytes)
            privBytes.fill(0)
            val ok = meta.edit()
                .putString("priv_s", Base64.encodeToString(wrapped, Base64.NO_WRAP))
                .putString("pub_s", Base64.encodeToString(rawPub, Base64.NO_WRAP))
                .putString("tag_s", pubTag("ss:silent", rawPub))
                .commit()
            if (!ok) { call.reject("Store failed", "E_ENCRYPT"); return null }
            return kp.public
        } finally {
            ssInitializingSilent.set(false)
        }
    }

    private fun persistItem(key: String, value: String, pub: PublicKey, mode: String) {
        val kg = KeyGenerator.getInstance("ML-KEM", bc)
        kg.init(KEMGenerateSpec(pub, "AES"), SecureRandom())
        val enc = kg.generateKey() as SecretKeyWithEncapsulation
        val kemCt = enc.encapsulation
        val sharedSecret = enc.encoded
        val nonce = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val aead = try {
            val cipher = Cipher.getInstance("ChaCha20-Poly1305")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(sharedSecret, "ChaCha20"),
                javax.crypto.spec.IvParameterSpec(nonce))
            cipher.doFinal(value.toByteArray(Charsets.UTF_8))
        } finally {
            sharedSecret.fill(0)
        }
        val frame = kemCt + nonce + aead
        // encName . mode . frame . mac, stored under a keyed hash of the name (not the name itself)
        val stored = encName(key) + "." +
            mode + "." +
            Base64.encodeToString(frame, Base64.NO_WRAP) + "." +
            Base64.encodeToString(storeMac(key, mode, frame), Base64.NO_WRAP)
        storeItems().edit().putString(nameTag(key), stored).apply()
    }

    // decapsulate the ML-KEM ciphertext with the (already unwrapped) private and open the ChaCha frame
    private fun decapsAndDecrypt(privBytes: ByteArray, frame: ByteArray, ctLen: Int): String {
        val priv = KeyFactory.getInstance("ML-KEM", bc).generatePrivate(PKCS8EncodedKeySpec(privBytes))
        val kemCt = frame.copyOfRange(0, ctLen)
        val nonce = frame.copyOfRange(ctLen, ctLen + 12)
        val aead = frame.copyOfRange(ctLen + 12, frame.size)
        val kg = KeyGenerator.getInstance("ML-KEM", bc)
        kg.init(KEMExtractSpec(priv, kemCt, "AES"))
        val dec = kg.generateKey() as SecretKeyWithEncapsulation
        val shared = dec.encoded
        try {
            val cipher = Cipher.getInstance("ChaCha20-Poly1305")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(shared, "ChaCha20"),
                javax.crypto.spec.IvParameterSpec(nonce))
            return String(cipher.doFinal(aead), Charsets.UTF_8)
        } finally {
            // best-effort wipe of the raw private and shared secret from the heap (JVM copies in
            // SecretKeySpec/GC still linger; the plaintext String is immutable and can't be wiped)
            shared.fill(0)
            privBytes.fill(0)
        }
    }

    @PluginMethod
    fun getItem(call: PluginCall) {
        val key = call.getString("key") ?: return call.reject("Missing key", "E_MISSING_PARAMS")
        val stored = storeItems().getString(nameTag(key), null)
        if (stored == null) {
            val ret = JSObject(); ret.put("value", JSONObject.NULL); call.resolve(ret); return
        }
        val item = parseStoreItem(key, stored)
            ?: return call.reject("Store item integrity check failed", "E_TAMPERED")
        val ctLen = 1568 // ML-KEM-1024
        if (item.frame.size <= ctLen + 12) return call.reject("Malformed stored item", "E_BAD_CIPHERTEXT")
        // pick the tier by the (MAC-verified) mode: silent reads without a prompt, bio prompts
        val metaPriv = if (item.mode == "b") "priv" else "priv_s"
        val wrapAlias = if (item.mode == "b") ssMasterAlias else ssSilentAlias
        val privB64 = storeMeta().getString(metaPriv, null)
            ?: return call.reject("Store key missing", "E_KEY_NOT_FOUND")
        try {
            val privBlob = Base64.decode(privB64, Base64.DEFAULT)
            val wrapIv = privBlob.copyOfRange(0, 12)
            val wrapped = privBlob.copyOfRange(12, privBlob.size)
            val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
            val wrapKey = ks.getKey(wrapAlias, null) as? SecretKey
                ?: return call.reject("Store key missing", "E_KEY_NOT_FOUND")
            val unwrapCipher = Cipher.getInstance("AES/GCM/NoPadding")
            unwrapCipher.init(Cipher.DECRYPT_MODE, wrapKey, GCMParameterSpec(128, wrapIv))
            if (item.mode == "s") {
                // silent wrap key is not auth-bound: unwrap and decapsulate inline, no prompt
                val privBytes = unwrapCipher.doFinal(wrapped)
                val ret = JSObject()
                ret.put("value", decapsAndDecrypt(privBytes, item.frame, ctLen))
                call.resolve(ret)
            } else {
                val hostActivity = activity as? FragmentActivity
                    ?: return call.reject("Host activity is not a FragmentActivity", "E_NO_ACTIVITY")
                authenticateCipher(hostActivity, unwrapCipher, "Authenticate to read your secret", call) { boundCipher ->
                    val privBytes = boundCipher.doFinal(wrapped)
                    val ret = JSObject()
                    ret.put("value", decapsAndDecrypt(privBytes, item.frame, ctLen))
                    call.resolve(ret)
                }
            }
        } catch (e: KeyPermanentlyInvalidatedException) {
            logd("getItem: store key invalidated by biometric enrollment", e)
            call.reject("Biometric enrollment changed; store key invalidated", "E_KEY_INVALIDATED")
        } catch (e: Exception) {
            logd("getItem failed for key=$key", e)
            call.reject("Read failed", "E_DECRYPT")
        }
    }

    // keys/hasItem stay silent (enumerating names leaks nothing). removeItem/clear prompt ONLY for
    // biometric items, so silent items keep the drop-in @evva behaviour.
    @PluginMethod
    fun removeItem(call: PluginCall) {
        val key = call.getString("key") ?: return call.reject("Missing key", "E_MISSING_PARAMS")
        val stored = storeItems().getString(nameTag(key), null) ?: run { call.resolve(); return }
        val item = parseStoreItem(key, stored)
        // silent or unreadable (corrupt) items delete without a prompt
        if (item == null || item.mode == "s") {
            storeItems().edit().remove(nameTag(key)).commit(); call.resolve(); return
        }
        val hostActivity = activity as? FragmentActivity
            ?: return call.reject("Host activity is not a FragmentActivity", "E_NO_ACTIVITY")
        val privB64 = storeMeta().getString("priv", null)
        val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        val wrapKey = ks.getKey(ssMasterAlias, null) as? SecretKey
        if (privB64 == null || wrapKey == null) {
            storeItems().edit().remove(nameTag(key)).commit(); call.resolve(); return
        }
        try {
            val privBlob = Base64.decode(privB64, Base64.DEFAULT)
            val wrapped = privBlob.copyOfRange(12, privBlob.size)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, wrapKey, GCMParameterSpec(128, privBlob.copyOfRange(0, 12)))
            authenticateCipher(hostActivity, cipher, "Authenticate to delete your secret", call) { boundCipher ->
                // unwrap with the bound cipher so a forged callback can't trigger the delete
                boundCipher.doFinal(wrapped)
                storeItems().edit().remove(nameTag(key)).commit()
                call.resolve()
            }
        } catch (e: KeyPermanentlyInvalidatedException) {
            // key already unusable, the value is unreadable anyway -> allow the delete
            logd("removeItem: store key invalidated, removing", e)
            storeItems().edit().remove(nameTag(key)).commit()
            call.resolve()
        } catch (e: Exception) {
            logd("removeItem failed for key=$key", e)
            call.reject("Remove failed", "E_REMOVE")
        }
    }

    @PluginMethod
    fun hasItem(call: PluginCall) {
        val key = call.getString("key") ?: return call.reject("Missing key", "E_MISSING_PARAMS")
        val ret = JSObject()
        ret.put("exists", storeItems().contains(nameTag(key)))
        call.resolve(ret)
    }

    @PluginMethod
    fun keys(call: PluginCall) {
        val arr = JSArray()
        // prefs keys are hashed; recover the real names from the encrypted encName field
        for ((k, v) in storeItems().all) {
            val stored = v as? String ?: continue
            val parts = stored.split(".")
            try {
                if (parts.size == 4) arr.put(decName(parts[0])) else arr.put(k) // legacy plaintext key
            } catch (e: Exception) {
                logd("keys: skip undecodable entry", e)
            }
        }
        val ret = JSObject()
        ret.put("keys", arr)
        call.resolve(ret)
    }

    @PluginMethod
    fun clear(call: PluginCall) {
        // prompt once only if the store holds at least one biometric item. The prefs key is a hash
        // now, so read the mode field directly (this only decides whether to prompt; clear wipes all).
        val anyBio = storeItems().all.any { (_, v) ->
            (v as? String)?.let { storedMode(it) == "b" } ?: false
        }
        val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        val privB64 = storeMeta().getString("priv", null)
        val wrapKey = ks.getKey(ssMasterAlias, null) as? SecretKey
        if (!anyBio || privB64 == null || wrapKey == null) {
            doClearWipe(); call.resolve(); return
        }
        val hostActivity = activity as? FragmentActivity
            ?: return call.reject("Host activity is not a FragmentActivity", "E_NO_ACTIVITY")
        try {
            val privBlob = Base64.decode(privB64, Base64.DEFAULT)
            val wrapped = privBlob.copyOfRange(12, privBlob.size)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, wrapKey, GCMParameterSpec(128, privBlob.copyOfRange(0, 12)))
            authenticateCipher(hostActivity, cipher, "Authenticate to erase secure storage", call) { boundCipher ->
                // actually unwrap with the bound cipher: a forged onAuthenticationSucceeded that
                // replays our un-unlocked cipher throws here, so the wipe only runs on a real match
                boundCipher.doFinal(wrapped)
                doClearWipe()
                call.resolve()
            }
        } catch (e: KeyPermanentlyInvalidatedException) {
            // key gone, bio items already unreadable -> let the user wipe it
            logd("clear: store key invalidated, wiping", e)
            doClearWipe()
            call.resolve()
        } catch (e: Exception) {
            logd("clear failed", e)
            call.reject("Clear failed", "E_CLEAR")
        }
    }

    private fun doClearWipe() {
        // commit() the prefs wipe BEFORE deleting the Keystore keys. apply() is async, so a crash
        // could leave items on disk while the keys are already gone -> unreadable E_TAMPERED forever.
        storeItems().edit().clear().commit()
        storeMeta().edit().clear().commit()
        try {
            val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
            for (a in listOf(ssMasterAlias, ssSilentAlias, ssMacAlias, ssNameKeyAlias)) {
                if (ks.containsAlias(a)) ks.deleteEntry(a)
            }
        } catch (e: Exception) {
            logd("clear: keystore delete failed", e)
        }
    }

    private fun getOrCreateSsMasterWrapKey(): SecretKey {
        val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        (ks.getKey(ssMasterAlias, null) as? SecretKey)?.let { return it }
        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)
        kg.init(
            KeyGenParameterSpec.Builder(
                ssMasterAlias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                .build()
        )
        return kg.generateKey()
    }

    // silent tier wrap key: same AES-256-GCM in the TEE but NO auth requirement, so the silent
    // private can be unwrapped without a biometric prompt
    private fun getOrCreateSsSilentWrapKey(): SecretKey {
        val ks = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        (ks.getKey(ssSilentAlias, null) as? SecretKey)?.let { return it }
        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)
        kg.init(
            KeyGenParameterSpec.Builder(
                ssSilentAlias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return kg.generateKey()
    }
}
