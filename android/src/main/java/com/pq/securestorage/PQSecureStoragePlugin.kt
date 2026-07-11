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
        private const val MAX_CRYPTO_INPUT = 10 * 1024 * 1024 // decoded-byte cap on crypto ops
    }


    // delivers BiometricPrompt callbacks off the UI thread, so the crypto in them doesn't block it
    private val cryptoExecutor = Executors.newSingleThreadExecutor()

    // off in release unless explicitly enabled (adb setprop log.tag.PQSecureStoragePlugin DEBUG),
    // so aliases and exception traces don't leak via logcat
    private fun logd(msg: String, e: Throwable? = null) {
        if (!Log.isLoggable(TAG, Log.DEBUG)) return
        if (e != null) Log.d(TAG, msg, e) else Log.d(TAG, msg)
    }

    // signature algorithm registry: JCA keypair algo, JCA signature algo, and whether it is EC
    // (EC needs the curve spec on keygen and DER->raw + point compression on the wire).
    private data class SigAlg(val keyPairAlgo: String, val signatureAlgo: String, val isEc: Boolean, val wrapped: Boolean)
    private fun sigAlgOf(type: String?): SigAlg? = when (type) {
        "PQC_MLDSA_65" -> SigAlg("ML-DSA-65", "ML-DSA-65", false, false)
        "PQC_MLDSA_87" -> SigAlg("ML-DSA-87", "ML-DSA-87", false, false)
        "ECDSA_256R1" -> SigAlg("EC", "SHA256withECDSA", true, false)
        "ED25519" -> SigAlg("Ed25519", "Ed25519", false, true)
        else -> null
    }

    // Ed25519 keygen/sign in software (BouncyCastle); the private seed is wrapped by a Keystore key
    // at rest (this is the tier=wrapped path). Returns (seed32, pub32).
    private fun ed25519Keygen(): Pair<ByteArray, ByteArray> {
        val kpg = org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator()
        kpg.init(org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters(SecureRandom()))
        val kp = kpg.generateKeyPair()
        val seed = (kp.private as org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters).encoded
        val pub = (kp.public as org.bouncycastle.crypto.params.Ed25519PublicKeyParameters).encoded
        return seed to pub
    }
    private fun ed25519Sign(seed: ByteArray, msg: ByteArray): ByteArray {
        val signer = org.bouncycastle.crypto.signers.Ed25519Signer()
        signer.init(true, org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters(seed, 0))
        signer.update(msg, 0, msg.size)
        return signer.generateSignature()
    }

    private fun sigPrefs() = context.getSharedPreferences("pq_sig", android.content.Context.MODE_PRIVATE)
    private fun sigWrapAlias(alias: String) = "__pq_sigwrap_$alias"
    private fun sigPrivKey(alias: String) = "$alias.priv"
    private fun sigPubKey(alias: String) = "$alias.pub"
    private fun sigTypeKey(alias: String) = "$alias.type"
    private fun sigTagKey(alias: String) = "$alias.tag"

    // wrapped signing key generation: software keypair, private seed wrapped by a per-alias Keystore
    // AES key (auth-required if biometric), stored in prefs. Mirrors generateKemKeyPair incl. the
    // biometric overwrite gate.
    private fun generateWrappedSigningKey(alias: String, type: String, overwrite: Boolean, requireBiometric: Boolean, call: PluginCall) {
        if (!sigGenerating.add(alias)) return call.reject("Key generation in progress, retry", "E_BUSY")
        try {
            val exists = sigPrefs().contains(sigPubKey(alias))
            if (!overwrite && exists) {
                sigGenerating.remove(alias)
                return call.reject("Alias already exists", "E_ALIAS_EXISTS")
            }
            val runGeneration: () -> Unit = {
                try {
                    val (seed, pub) = ed25519Keygen()
                    val ks = keystore()
                    if (ks.containsAlias(sigWrapAlias(alias))) ks.deleteEntry(sigWrapAlias(alias))
                    val wrapKey = getOrCreateAesKey(sigWrapAlias(alias), requireBiometric)
                    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                    cipher.init(Cipher.ENCRYPT_MODE, wrapKey)
                    val persist = { c: Cipher ->
                        val wrapped = c.iv + c.doFinal(seed)
                        seed.fill(0)
                        val committed = sigPrefs().edit()
                            .putString(sigPrivKey(alias), Base64.encodeToString(wrapped, Base64.NO_WRAP))
                            .putString(sigPubKey(alias), Base64.encodeToString(pub, Base64.NO_WRAP))
                            .putString(sigTypeKey(alias), type)
                            .putString(sigTagKey(alias), pubTag("sig:$alias", pub))
                            .commit()
                        sigGenerating.remove(alias)
                        if (committed) {
                            val ret = JSObject()
                            ret.put("publicKey", Base64.encodeToString(pub, Base64.NO_WRAP))
                            call.resolve(ret)
                        } else {
                            call.reject("Key generation failed", "E_KEYGEN")
                        }
                    }
                    if (requireBiometric) {
                        val host = activity as? FragmentActivity
                        if (host == null) {
                            sigGenerating.remove(alias)
                            call.reject("Host activity is not a FragmentActivity", "E_NO_ACTIVITY")
                        } else {
                            authenticateCipher(host, cipher, "Authenticate to create your key", call,
                                onError = { sigGenerating.remove(alias) }) { boundCipher -> persist(boundCipher) }
                        }
                    } else {
                        persist(cipher)
                    }
                } catch (e: Exception) {
                    sigGenerating.remove(alias)
                    logd("generateWrappedSigningKey failed for alias=$alias", e)
                    call.reject("Key generation failed", "E_KEYGEN")
                }
            }
            val existingWrap = if (exists) (try { keystore().getKey(sigWrapAlias(alias), null) as? SecretKey } catch (e: Exception) { null }) else null
            if (existingWrap != null && secretKeyRequiresAuth(existingWrap)) {
                val host = activity as? FragmentActivity
                if (host == null) {
                    sigGenerating.remove(alias)
                    return call.reject("Host activity is not a FragmentActivity", "E_NO_ACTIVITY")
                }
                val gateCipher = Cipher.getInstance("AES/GCM/NoPadding")
                try {
                    gateCipher.init(Cipher.ENCRYPT_MODE, existingWrap)
                } catch (e: KeyPermanentlyInvalidatedException) {
                    logd("existing sig wrap invalidated, allowing overwrite for alias=$alias", e)
                    runGeneration()
                    return
                }
                authenticateCipher(host, gateCipher, "Authorize key replacement", call,
                    onError = { sigGenerating.remove(alias) }) { boundCipher ->
                    boundCipher.doFinal(byteArrayOf(0))
                    runGeneration()
                }
            } else {
                runGeneration()
            }
        } catch (e: Exception) {
            sigGenerating.remove(alias)
            logd("generateWrappedSigningKey failed for alias=$alias", e)
            call.reject("Key generation failed", "E_KEYGEN")
        }
    }

    // sign with a wrapped (software) key: unwrap the seed inside the biometric-bound cipher, sign,
    // and zeroize the seed
    private fun signWrapped(alias: String, description: String?, input: ByteArray, call: PluginCall) {
        try {
            val privB64 = sigPrefs().getString(sigPrivKey(alias), null)
                ?: return call.reject("Key not found", "E_KEY_NOT_FOUND")
            val wrapped = Base64.decode(privB64, Base64.DEFAULT)
            val iv = wrapped.copyOfRange(0, 12)
            val ct = wrapped.copyOfRange(12, wrapped.size)
            val wrapKey = keystore().getKey(sigWrapAlias(alias), null) as? SecretKey
                ?: return call.reject("Key not found", "E_KEY_NOT_FOUND")
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, wrapKey, GCMParameterSpec(128, iv))
            val doSign = { c: Cipher ->
                val seed = c.doFinal(ct)
                try {
                    val ret = JSObject()
                    ret.put("signature", Base64.encodeToString(ed25519Sign(seed, input), Base64.NO_WRAP))
                    call.resolve(ret)
                } finally {
                    seed.fill(0)
                }
            }
            if (secretKeyRequiresAuth(wrapKey)) {
                val host = activity as? FragmentActivity
                    ?: return call.reject("Host activity is not a FragmentActivity", "E_NO_ACTIVITY")
                authenticateCipher(host, cipher, description ?: "Authorize signature", call) { boundCipher -> doSign(boundCipher) }
            } else {
                doSign(cipher)
            }
        } catch (e: KeyPermanentlyInvalidatedException) {
            logd("signWrapped: key invalidated for alias=$alias", e)
            call.reject("Biometric enrollment changed; key invalidated", "E_KEY_INVALIDATED")
        } catch (e: Exception) {
            logd("signWrapped failed for alias=$alias", e)
            call.reject("Signing failed", "E_SIGN")
        }
    }

    // compressed SEC1 point (33B: 0x02/0x03 || X) for an EC public key -- the CESR form
    private fun compressEcPoint(pub: java.security.PublicKey): ByteArray {
        val w = (pub as java.security.interfaces.ECPublicKey).w
        val prefix = if (w.affineY.testBit(0)) 0x03.toByte() else 0x02.toByte()
        return byteArrayOf(prefix) + toFixed(w.affineX, 32)
    }
    // big-endian fixed-length bytes (strips the sign byte / left-pads short values)
    private fun toFixed(v: java.math.BigInteger, len: Int): ByteArray {
        val b = v.toByteArray()
        if (b.size == len) return b
        val out = ByteArray(len)
        if (b.size == len + 1 && b[0] == 0.toByte()) System.arraycopy(b, 1, out, 0, len)
        else System.arraycopy(b, 0, out, len - b.size, b.size)
        return out
    }
    // DER ECDSA signature -> raw r||s (64B)
    private fun ecdsaDerToRaw(der: ByteArray): ByteArray {
        val seq = org.bouncycastle.asn1.ASN1Sequence.getInstance(der)
        val r = (seq.getObjectAt(0) as org.bouncycastle.asn1.ASN1Integer).positiveValue
        val s = (seq.getObjectAt(1) as org.bouncycastle.asn1.ASN1Integer).positiveValue
        return toFixed(r, 32) + toFixed(s, 32)
    }

    private fun keystore(): KeyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }

    // reject an oversized input before decoding it (the base64 string bounds the decoded size), then
    // confirm the decoded size. Returns null and rejects the call on either check.
    private fun decodeCapped(call: PluginCall, data: String): ByteArray? {
        if (data.length > MAX_CRYPTO_INPUT * 2) { call.reject("Input too large", "E_INPUT_TOO_LARGE"); return null }
        val bytes = Base64.decode(data, Base64.DEFAULT)
        if (bytes.size > MAX_CRYPTO_INPUT) { call.reject("Input too large", "E_INPUT_TOO_LARGE"); return null }
        return bytes
    }

    @PluginMethod
    fun getHardwareCapabilities(call: PluginCall) {
        val ok = pqcSigningSupported()
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
        // ECDSA P-256 always available; Ed25519 always available in software (wrapped); ML-DSA only
        // if KeyMint implements it
        val variants = mutableListOf("ECDSA_256R1", "ED25519")
        if (ok) { variants.add("PQC_MLDSA_65"); variants.add("PQC_MLDSA_87") }
        ret.put("supportedVariants", variants)
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
        val type = call.getString("type")
        val sa = sigAlgOf(type) ?: return call.reject("Unsupported key type", "E_UNSUPPORTED")
        val overwrite = call.getBoolean("overwrite") ?: false
        val requireBiometric = call.getBoolean("requireBiometric") ?: true
        if (sa.wrapped) return generateWrappedSigningKey(alias, type!!, overwrite, requireBiometric, call)
        val ks = try {
            keystore()
        } catch (e: Exception) {
            logd("generateKeyPair keystore load failed for alias=$alias", e)
            return call.reject("Key generation failed", "E_KEYGEN")
        }
        val exists = ks.containsAlias(alias)
        if (exists && !overwrite) {
            // alias may back a live identity already -- refuse to silently clobber it
            return call.reject("Alias already exists", "E_ALIAS_EXISTS")
        }
        // gate the overwrite behind a biometric ONLY when the existing key is itself biometric -- a
        // silent key isn't biometrically protected, so its overwrite is silent too
        val existingBio = exists && (ks.getKey(alias, null) as? java.security.PrivateKey)?.let { keyRequiresAuth(it) } == true
        if (existingBio) {
            val hostActivity = activity as? FragmentActivity
                ?: return call.reject("Host activity is not a FragmentActivity", "E_NO_ACTIVITY")
            authForExistingSign(hostActivity, alias, call) { doGenerateSigningKey(alias, sa, requireBiometric, call) }
            return
        }
        doGenerateSigningKey(alias, sa, requireBiometric, call)
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
                keystore().deleteEntry(probeAlias)
            } catch (e: Exception) {
                logd("hw probe cleanup failed", e)
            }
        }
        hwCache = hw
        return hw
    }

    @Volatile private var pqcCache: Boolean? = null

    // whether AndroidKeyStore actually exposes ML-DSA keygen on this device. Probe it, don't guess an
    // API level: Keystore ML-DSA depends on KeyMint, not just the OS version. getInstance resolves the
    // algorithm without generating a key, so it is cheap and side-effect free.
    private fun pqcSigningSupported(): Boolean {
        pqcCache?.let { return it }
        val ok = try {
            KeyPairGenerator.getInstance("ML-DSA-65", KEYSTORE_PROVIDER)
            true
        } catch (e: Exception) {
            logd("ML-DSA keystore probe failed", e); false
        }
        pqcCache = ok
        return ok
    }

    // whether a Keystore key was created with per-op user authentication (biometric). This is the
    // authoritative key property (not tamperable metadata); on failure assume auth required (safe).
    private fun keyRequiresAuth(key: java.security.PrivateKey): Boolean = try {
        (KeyFactory.getInstance(key.algorithm, KEYSTORE_PROVIDER).getKeySpec(key, KeyInfo::class.java) as KeyInfo)
            .isUserAuthenticationRequired
    } catch (e: Exception) {
        logd("keyRequiresAuth probe failed", e); true
    }

    private fun secretKeyRequiresAuth(key: SecretKey): Boolean = try {
        (SecretKeyFactory.getInstance(key.algorithm, KEYSTORE_PROVIDER).getKeySpec(key, KeyInfo::class.java) as KeyInfo)
            .isUserAuthenticationRequired
    } catch (e: Exception) {
        logd("secretKeyRequiresAuth probe failed", e); true
    }

    private fun doGenerateSigningKey(alias: String, sa: SigAlg, requireBiometric: Boolean, call: PluginCall) {
        try {
            // no pre-delete. Generating to an existing alias replaces it; a failed keygen
            // leaves the old key intact instead of destroying it first.
            //
            // AndroidKeyStore does NOT guarantee TEE/StrongBox placement -- if KeyMint doesn't
            // implement ML-DSA in hardware on this device it silently falls back to the software
            // keystore. getHardwareCapabilities probes the real security level instead of assuming.
            val kpg = KeyPairGenerator.getInstance(sa.keyPairAlgo, KEYSTORE_PROVIDER)
            val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
            if (sa.isEc) {
                spec.setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
            }
            if (requireBiometric) {
                // Per-operation auth: timeout 0 means the key never sits unlocked. Every use needs a
                // fresh biometric bound to the specific Signature (see sign()) -- closes GHSA-vx5f.
                spec.setUserAuthenticationRequired(true)
                    .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            }
            kpg.initialize(spec.build())
            val kp = kpg.generateKeyPair()
            val pubRaw = if (sa.isEc) compressEcPoint(kp.public) else rawFromSpki(kp.public.encoded)
            val ret = JSObject()
            ret.put("publicKey", Base64.encodeToString(pubRaw, Base64.NO_WRAP))
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
            val priv = keystore().getKey(alias, null) as? java.security.PrivateKey
                ?: return after() // no live key to protect (e.g. half-written alias) -> allow overwrite
            val signer = Signature.getInstance(priv.algorithm)
            try {
                signer.initSign(priv)
            } catch (e: KeyPermanentlyInvalidatedException) {
                // old key already dead (enrollment changed): nothing to protect, allow the overwrite
                logd("existing key invalidated, allowing overwrite for alias=$alias", e)
                return after()
            }
            // a real op with the bound signer proves the biometric; a forged callback can't produce
            // it. A mid-auth invalidation surfaces as E_KEY_INVALIDATED here; a retry then hits the
            // initSign check above and allows the overwrite.
            authenticateSignature(hostActivity, signer, "Authorize key replacement", null, call) { boundSigner ->
                boundSigner.update(byteArrayOf(0)); boundSigner.sign()
                after()
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
            // wrapped signing keys live in prefs, not the Keystore
            val sigPub = sigPrefs().getString(sigPubKey(alias), null)
            if (sigPub != null) {
                val tag = sigPrefs().getString(sigTagKey(alias), null)
                if (tag == null || !verifyPubTag("sig:$alias", Base64.decode(sigPub, Base64.DEFAULT), tag)) {
                    return call.reject("Public key integrity check failed", "E_TAMPERED")
                }
                val ret = JSObject()
                ret.put("publicKey", sigPub)
                return call.resolve(ret)
            }
            val ks = keystore()
            val cert = ks.getCertificate(alias) ?: return call.reject("Key not found", "E_PUBKEY")
            val pub = cert.publicKey
            val pubRaw = if (pub is java.security.interfaces.ECPublicKey) compressEcPoint(pub) else rawFromSpki(pub.encoded)
            val ret = JSObject()
            ret.put("publicKey", Base64.encodeToString(pubRaw, Base64.NO_WRAP))
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
        val sa = sigAlgOf(type) ?: return call.reject("Unsupported key type", "E_UNSUPPORTED")
        // optional host-supplied prompt text (NOT a consent guarantee, see definitions.ts). Cap the
        // length so a caller can't push a giant string or shove real content off-screen.
        val description = call.getString("description")?.take(200)
        val input = decodeCapped(call, data) ?: return
        if (sa.wrapped) return signWrapped(alias, description, input, call)

        try {
            val priv = keystore().getKey(alias, null) as? java.security.PrivateKey
                ?: return call.reject("Key not found", "E_KEY_NOT_FOUND")
            // initSign() does NOT unlock the key -- the Keystore only releases material inside
            // sign()/update(), and (for a biometric key) only for the Signature a real match bound.
            val signer = Signature.getInstance(sa.signatureAlgo)
            signer.initSign(priv)
            // EC yields a DER signature; CESR/the wire want raw r||s
            val encodeSig = { raw: ByteArray -> Base64.encodeToString(if (sa.isEc) ecdsaDerToRaw(raw) else raw, Base64.NO_WRAP) }
            if (keyRequiresAuth(priv)) {
                // Capacitor's BridgeActivity is a FragmentActivity, needed to host BiometricPrompt
                val hostActivity = activity as? FragmentActivity
                    ?: return call.reject("Host activity is not a FragmentActivity", "E_NO_ACTIVITY")
                authenticateSignature(hostActivity, signer, "Authorize signature", description, call) { boundSigner ->
                    boundSigner.update(input)
                    val ret = JSObject()
                    ret.put("signature", encodeSig(boundSigner.sign()))
                    call.resolve(ret)
                }
            } else {
                // silent key: sign directly, no prompt
                signer.update(input)
                val ret = JSObject()
                ret.put("signature", encodeSig(signer.sign()))
                call.resolve(ret)
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
        val input = decodeCapped(call, data) ?: return
        try {
            val key = getOrCreateAtRestKey(alias)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key)
            val iv = cipher.iv // 12 bytes
            val ct = cipher.doFinal(input) // includes tag
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
            val ks = keystore()
            val key = ks.getKey(atRestAlias(alias), null) as? SecretKey
                ?: return call.reject("Key not found", "E_KEY_NOT_FOUND")
            val frame = decodeCapped(call, data) ?: return
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

    // per-key guard so two setItem on the same key can't race the item-key create; global latch so
    // only one biometric prompt shows at a time (no prompt spam / stacking)
    private val storeWriting = java.util.concurrent.ConcurrentHashMap.newKeySet<String>()
    private val sigGenerating = java.util.concurrent.ConcurrentHashMap.newKeySet<String>()
    private val authInFlight = java.util.concurrent.atomic.AtomicBoolean(false)
    // serialize creation of the shared internal keys (HMAC/name/at-rest); the getKey hit stays lock-free
    private val keyCreateLock = Any()

    @PluginMethod
    fun generateKemKeyPair(call: PluginCall) {
        val alias = call.getString("keyAlias") ?: return call.reject("Missing keyAlias parameter", "E_MISSING_PARAMS")
        if (!safeAlias(call, alias)) return
        val type = call.getString("type") ?: return call.reject("Missing type parameter", "E_MISSING_PARAMS")
        val spec = mlkemSpecOf(type) ?: return call.reject("Unsupported KEM type", "E_UNSUPPORTED")
        val overwrite = call.getBoolean("overwrite") ?: false
        val requireBiometric = call.getBoolean("requireBiometric") ?: true
        if (!kemGenerating.add(alias)) return call.reject("Key generation in progress, retry", "E_BUSY")
        try {
            val exists = kemPrefs().contains(kemPubKeyKey(alias))
            if (!overwrite && exists) {
                kemGenerating.remove(alias)
                return call.reject("Alias already exists", "E_ALIAS_EXISTS")
            }

            // the heavy path: generate the keypair, wrap the private, rotate the wrap key
            val runGeneration: () -> Unit = {
                try {
                    val kpg = KeyPairGenerator.getInstance("ML-KEM", bc)
                    kpg.initialize(spec, SecureRandom())
                    val kp = kpg.generateKeyPair()
                    val privBytes = kp.private.encoded // PKCS8
                    val rawPub = rawFromSpki(kp.public.encoded) // raw FIPS-203 bytes

                    val oldVer = kemPrefs().getInt(kemWrapVerKey(alias), -1)
                    val newVer = oldVer + 1
                    val wrapKey = createKemWrapKey(alias, newVer, requireBiometric)
                    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                    cipher.init(Cipher.ENCRYPT_MODE, wrapKey)

                    // wrap the private + rotate. commit() is synchronous+durable, so the old wrap key is
                    // retired ONLY after the new state is on disk (a crash can't point prefs at a deleted key)
                    val persist = { c: Cipher ->
                        val wrapped = c.iv + c.doFinal(privBytes)
                        privBytes.fill(0)
                        val committed = kemPrefs().edit()
                            .putString(kemPrivKey(alias), Base64.encodeToString(wrapped, Base64.NO_WRAP))
                            .putString(kemPubKeyKey(alias), Base64.encodeToString(rawPub, Base64.NO_WRAP))
                            .putString(kemTagKey(alias), pubTag("kem:$alias", rawPub))
                            .putString(kemTypeKey(alias), type)
                            .putInt(kemWrapVerKey(alias), newVer)
                            .commit()
                        if (committed && oldVer >= 0) {
                            try {
                                val ks = keystore()
                                if (ks.containsAlias(kemWrapAlias(alias, oldVer))) ks.deleteEntry(kemWrapAlias(alias, oldVer))
                            } catch (e: Exception) {
                                logd("kem wrap rotate cleanup failed", e)
                            }
                        }
                        kemGenerating.remove(alias)
                        if (committed) {
                            val ret = JSObject()
                            ret.put("publicKey", Base64.encodeToString(rawPub, Base64.NO_WRAP))
                            call.resolve(ret)
                        } else {
                            call.reject("KEM key generation failed", "E_KEYGEN")
                        }
                    }

                    if (requireBiometric) {
                        val hostActivity = activity as? FragmentActivity
                        if (hostActivity == null) {
                            kemGenerating.remove(alias)
                            call.reject("Host activity is not a FragmentActivity", "E_NO_ACTIVITY")
                        } else {
                            authenticateCipher(hostActivity, cipher, "Authenticate to create your PQ key", call,
                                onError = { kemGenerating.remove(alias) }) { boundCipher -> persist(boundCipher) }
                        }
                    } else {
                        persist(cipher) // no-auth wrap key: wrap silently, no prompt
                    }
                } catch (e: Exception) {
                    kemGenerating.remove(alias)
                    logd("generateKemKeyPair failed for alias=$alias", e)
                    call.reject("KEM key generation failed", "E_KEYGEN")
                }
            }

            // gate the overwrite behind a biometric ONLY when the existing KEM key is itself biometric,
            // same rule as generateKeyPair for signing. Without this, overwrite:true silently destroys
            // and downgrades a biometric KEM private (runGeneration retires the old wrap key).
            val existingVer = kemPrefs().getInt(kemWrapVerKey(alias), -1)
            val existingWrap = if (exists && existingVer >= 0) {
                keystore().getKey(kemWrapAlias(alias, existingVer), null) as? SecretKey
            } else null
            if (existingWrap != null && secretKeyRequiresAuth(existingWrap)) {
                val hostActivity = activity as? FragmentActivity
                if (hostActivity == null) {
                    kemGenerating.remove(alias)
                    return call.reject("Host activity is not a FragmentActivity", "E_NO_ACTIVITY")
                }
                val gateCipher = Cipher.getInstance("AES/GCM/NoPadding")
                try {
                    gateCipher.init(Cipher.ENCRYPT_MODE, existingWrap)
                } catch (e: KeyPermanentlyInvalidatedException) {
                    // old key already dead (enrollment changed): nothing to protect, allow overwrite
                    logd("existing kem wrap invalidated, allowing overwrite for alias=$alias", e)
                    runGeneration()
                    return
                }
                authenticateCipher(hostActivity, gateCipher, "Authorize key replacement", call,
                    onError = { kemGenerating.remove(alias) }) { boundCipher ->
                    boundCipher.doFinal(byteArrayOf(0)) // prove a real biometric released the existing key
                    runGeneration()
                }
            } else {
                runGeneration()
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
        val input = decodeCapped(call, data) ?: return
        try {
            // the peer sends a raw public key; rebuild the SPKI wrapper JCA needs to parse it
            val pubKey = mlkemPublicFromRaw(Base64.decode(pubStr, Base64.DEFAULT), oid)
            // encapsulate (software, no alias/biometric) -> frame = kemCt || nonce(12) || aead(+tag)
            val frame = encapAndSeal(pubKey, input)
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
        try {
            val storedType = kemPrefs().getString(kemTypeKey(alias), null)
                ?: return call.reject("Key not found", "E_KEY_NOT_FOUND")
            if (storedType != type) return call.reject("Key type mismatch", "E_TYPE_MISMATCH")
            val privStr = kemPrefs().getString(kemPrivKey(alias), null)
                ?: return call.reject("Key not found", "E_KEY_NOT_FOUND")
            val ver = kemPrefs().getInt(kemWrapVerKey(alias), -1)
            if (ver < 0) return call.reject("Key not found", "E_KEY_NOT_FOUND")
            val privBlob = Base64.decode(privStr, Base64.DEFAULT)
            val frame = decodeCapped(call, data) ?: return
            if (frame.size <= ctLen + 12) return call.reject("Malformed ciphertext", "E_BAD_CIPHERTEXT")

            val wrapIv = privBlob.copyOfRange(0, 12)
            val wrapped = privBlob.copyOfRange(12, privBlob.size)
            val wrapKey = keystore().getKey(kemWrapAlias(alias, ver), null) as? SecretKey
                ?: return call.reject("Key not found", "E_KEY_NOT_FOUND")
            val unwrapCipher = Cipher.getInstance("AES/GCM/NoPadding")
            unwrapCipher.init(Cipher.DECRYPT_MODE, wrapKey, GCMParameterSpec(128, wrapIv))

            if (secretKeyRequiresAuth(wrapKey)) {
                val hostActivity = activity as? FragmentActivity
                    ?: return call.reject("Host activity is not a FragmentActivity", "E_NO_ACTIVITY")
                authenticateCipher(hostActivity, unwrapCipher, "Authenticate to decrypt with your PQ key", call) { boundCipher ->
                    val plain = decapsulate(boundCipher.doFinal(wrapped), frame, ctLen)
                    val ret = JSObject()
                    ret.put("plaintext", Base64.encodeToString(plain, Base64.NO_WRAP))
                    call.resolve(ret)
                }
            } else {
                // no-auth wrap key: unwrap + decapsulate inline, no prompt
                val plain = decapsulate(unwrapCipher.doFinal(wrapped), frame, ctLen)
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

    // get-or-create a non-exportable HMAC-SHA256 Keystore key under an alias
    private fun getOrCreateHmacKey(alias: String): SecretKey {
        (keystore().getKey(alias, null) as? SecretKey)?.let { return it }
        return synchronized(keyCreateLock) {
            (keystore().getKey(alias, null) as? SecretKey)?.let { return@synchronized it }
            val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, KEYSTORE_PROVIDER)
            kg.init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY).build())
            kg.generateKey()
        }
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
        mac.init(getOrCreateHmacKey(pubTagKeyAlias))
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

    // ---- item-name confidentiality ----
    // The SharedPreferences key is a keyed hash of the item name (not the plaintext), so a prefs
    // reader never sees names like "seed-phrase". The real name is also stored AES-encrypted inside
    // the value so keys() can still list them. Both keys live in the TEE.
    private val ssNameKeyAlias = "__pq_ss_namekey__"

    private fun getOrCreateStoreNameKey(): SecretKey = getOrCreateAesKey(ssNameKeyAlias, false)

    // deterministic keyed hash -> the prefs key. Same name always maps to the same tag (so lookups
    // work), but the TEE HMAC key means it can't be reversed or forged.
    private fun nameTag(name: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(getOrCreateHmacKey(ssMacAlias))
        macPut(mac, "name".toByteArray(Charsets.UTF_8)) // domain-separate from the item-key tag
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

    // get-or-create an AES-256-GCM Keystore key. authRequired binds it to a per-op strong biometric.
    private fun getOrCreateAesKey(alias: String, authRequired: Boolean): SecretKey {
        (keystore().getKey(alias, null) as? SecretKey)?.let { return it }
        return synchronized(keyCreateLock) {
            (keystore().getKey(alias, null) as? SecretKey)?.let { return@synchronized it }
            val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)
            val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
            if (authRequired) {
                spec.setUserAuthenticationRequired(true)
                    .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            }
            kg.init(spec.build())
            kg.generateKey()
        }
    }

    private fun getOrCreateAtRestKey(alias: String): SecretKey = getOrCreateAesKey(atRestAlias(alias), false)

    private fun createKemWrapKey(alias: String, ver: Int, requireBiometric: Boolean): SecretKey {
        // a fresh wrap key per generation (versioned alias). On overwrite the old version is
        // deleted after the new keypair is persisted, so a restored pre-rotation wrapped-private
        // can no longer be unwrapped. Clear any orphan at this version first (cancelled attempt).
        val ks = keystore()
        if (ks.containsAlias(kemWrapAlias(alias, ver))) ks.deleteEntry(kemWrapAlias(alias, ver))
        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)
        val spec = KeyGenParameterSpec.Builder(
            kemWrapAlias(alias, ver),
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
        if (requireBiometric) {
            // per-op biometric bound to the cipher (same GHSA-safe pattern as sign())
            spec.setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
        }
        kg.init(spec.build())
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
        // only one prompt at a time; a second concurrent op is rejected, not stacked
        if (!authInFlight.compareAndSet(false, true)) {
            onError()
            return call.reject("Another authentication is in progress", "E_BUSY")
        }
        val cryptoObject = BiometricPrompt.CryptoObject(cipher)
        hostActivity.runOnUiThread {
            val settled = AtomicBoolean(false)
            // background executor: the KEM/AES work in onSuccess runs off the UI thread
            val callback = object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    if (!settled.compareAndSet(false, true)) return
                    // the prompt is dismissed now, so free the latch before onSuccess -- onSuccess may
                    // legitimately chain a second prompt (e.g. biometric KEM overwrite)
                    authInFlight.set(false)
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
                    authInFlight.set(false)
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
                    authInFlight.set(false)
                    call.reject("Authentication failed", "E_AUTH_FAILED")
                }
            }
        }
    }

    // same GHSA-safe BiometricPrompt flow as authenticateCipher, but bound to a Signature (for the
    // signing key). onSuccess runs the real sign op with the hardware-unlocked signer.
    private fun authenticateSignature(
        hostActivity: FragmentActivity,
        signer: Signature,
        title: String,
        subtitle: String?,
        call: PluginCall,
        onSuccess: (Signature) -> Unit
    ) {
        // only one prompt at a time; a second concurrent op is rejected, not stacked
        if (!authInFlight.compareAndSet(false, true)) {
            return call.reject("Another authentication is in progress", "E_BUSY")
        }
        val cryptoObject = BiometricPrompt.CryptoObject(signer)
        hostActivity.runOnUiThread {
            val settled = AtomicBoolean(false)
            val callback = object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    if (!settled.compareAndSet(false, true)) return
                    // prompt dismissed; free the latch before onSuccess in case it chains a prompt
                    authInFlight.set(false)
                    try {
                        onSuccess(result.cryptoObject!!.signature!!)
                    } catch (e: KeyPermanentlyInvalidatedException) {
                        logd("signature op: key invalidated by enrollment change", e)
                        call.reject("Biometric enrollment changed; key invalidated", "E_KEY_INVALIDATED")
                    } catch (e: Exception) {
                        logd("signature op failed", e)
                        call.reject("Signing failed", "E_SIGN")
                    }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    if (!settled.compareAndSet(false, true)) return
                    authInFlight.set(false)
                    call.reject("Authentication failed", "E_AUTH_FAILED")
                }

                override fun onAuthenticationFailed() {
                    // biometric mismatch, prompt stays open for retry -- don't settle
                }
            }
            try {
                val promptInfo = BiometricPrompt.PromptInfo.Builder()
                    .setTitle(title)
                    .apply { if (subtitle != null) setSubtitle(subtitle) }
                    .setNegativeButtonText("Cancel")
                    .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                    .build()
                BiometricPrompt(hostActivity, cryptoExecutor, callback).authenticate(promptInfo, cryptoObject)
            } catch (e: Exception) {
                if (settled.compareAndSet(false, true)) {
                    logd("biometric prompt failed to start", e)
                    authInFlight.set(false)
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

    private val itemAliasPrefix = "__pq_ss_i_"

    private fun storeItems() = context.getSharedPreferences("pq_secure_store", android.content.Context.MODE_PRIVATE)

    // per-item Keystore alias derived from the name (url-safe base64 so it's a valid alias)
    private fun itemKeyAlias(name: String): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(getOrCreateHmacKey(ssMacAlias))
        macPut(mac, "itemkey".toByteArray(Charsets.UTF_8))
        macPut(mac, name.toByteArray(Charsets.UTF_8))
        return itemAliasPrefix + Base64.encodeToString(mac.doFinal(), Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
    }

    // afterFirstUnlock* keeps the key usable while the device is locked; everything else requires unlock
    private fun unlockRequiredFor(accessibility: String?): Boolean =
        accessibility != "afterFirstUnlock" && accessibility != "afterFirstUnlockThisDeviceOnly"

    // on probe failure assume auth required (fail safe), same as keyRequiresAuth/secretKeyRequiresAuth
    private fun isAuthRequired(key: SecretKey): Boolean = try {
        val info = SecretKeyFactory.getInstance(key.algorithm, KEYSTORE_PROVIDER)
            .getKeySpec(key, KeyInfo::class.java) as KeyInfo
        info.isUserAuthenticationRequired
    } catch (e: Exception) {
        logd("isAuthRequired probe failed", e); true
    }

    // create (replacing any existing) the per-item AES-256-GCM key: StrongBox-backed where available,
    // setUnlockedDeviceRequired for accessibility, per-op strong biometric when authRequired.
    private fun createItemKey(alias: String, authRequired: Boolean, unlockRequired: Boolean): SecretKey {
        val ks = keystore()
        if (ks.containsAlias(alias)) ks.deleteEntry(alias)
        fun build(strongBox: Boolean): SecretKey {
            val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)
            val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUnlockedDeviceRequired(unlockRequired)
            if (authRequired) {
                spec.setUserAuthenticationRequired(true)
                    .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            }
            if (strongBox) spec.setIsStrongBoxBacked(true)
            kg.init(spec.build())
            return kg.generateKey()
        }
        return try {
            build(true)
        } catch (e: android.security.keystore.StrongBoxUnavailableException) {
            build(false)
        }
    }

    // stored under nameTag(name): encName . iv . ct  (AES-256-GCM under the item key, name as AAD).
    // GCM + the per-item key give integrity, so there's no separate MAC.
    private fun storedValue(name: String, iv: ByteArray, ct: ByteArray): String =
        encName(name) + "." + Base64.encodeToString(iv, Base64.NO_WRAP) + "." + Base64.encodeToString(ct, Base64.NO_WRAP)

    @PluginMethod
    fun setItem(call: PluginCall) {
        val key = call.getString("key") ?: return call.reject("Missing key", "E_MISSING_PARAMS")
        val value = call.getString("value") ?: return call.reject("Missing value", "E_MISSING_PARAMS")
        // bound both so a caller can't fill prefs/keystore with a giant blob (DoS)
        if (key.isEmpty() || key.length > MAX_STORE_KEY_LEN || value.length > MAX_STORE_VALUE_LEN) {
            return call.reject("Key or value out of bounds", "E_INVALID_ARGS")
        }
        if (!storeWriting.add(key)) return call.reject("Store write in progress, retry", "E_BUSY")
        val done = { storeWriting.remove(key); Unit }
        val newBio = call.getBoolean("requireBiometric") ?: false
        val alias = itemKeyAlias(key)
        val existing = try { keystore().getKey(alias, null) as? SecretKey } catch (e: Exception) { null }
        // an item's tier is fixed at creation; a change must go through removeItem. Enforce it even
        // when the key was invalidated by an enrollment change (isAuthRequired reads metadata, still
        // valid on an invalidated key), so a bio item can't be silently recreated as silent. Only
        // when a real item exists -- an orphan key from a cancelled write shouldn't block a fresh one.
        if (existing != null && storeItems().contains(nameTag(key)) && isAuthRequired(existing) != newBio) {
            done()
            return call.reject("Item exists with a different requireBiometric; removeItem first", "E_TIER_MISMATCH")
        }
        val itemKey: SecretKey = if (existing != null && !invalidated(existing)) {
            existing // reuse (an accessibility change on overwrite is ignored -- set at creation)
        } else {
            try {
                createItemKey(alias, newBio, unlockRequiredFor(call.getString("accessibility")))
            } catch (e: Exception) {
                logd("setItem: key create failed for key=$key", e)
                done()
                return call.reject("Store failed", "E_ENCRYPT")
            }
        }
        encryptAndStore(call, key, value, itemKey, newBio, done)
    }

    // a reused bio key is dead after a biometric enrollment change; detect it so setItem recreates
    private fun invalidated(key: SecretKey): Boolean = try {
        Cipher.getInstance("AES/GCM/NoPadding").init(Cipher.ENCRYPT_MODE, key)
        false
    } catch (e: KeyPermanentlyInvalidatedException) {
        true
    } catch (e: Exception) {
        false // other errors (e.g. needs auth) mean the key is still usable
    }

    private fun encryptAndStore(call: PluginCall, key: String, value: String, itemKey: SecretKey, bio: Boolean, done: () -> Unit) {
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, itemKey)
            val iv = cipher.iv
            if (!bio) {
                cipher.updateAAD(key.toByteArray(Charsets.UTF_8))
                val ct = cipher.doFinal(value.toByteArray(Charsets.UTF_8))
                storeItems().edit().putString(nameTag(key), storedValue(key, iv, ct)).commit()
                done()
                call.resolve()
            } else {
                // a biometric item's own key gates the WRITE too (encrypt needs the key), so the
                // prompt here is the same gate that blocks a silent bridge caller from overwriting it
                val hostActivity = activity as? FragmentActivity
                    ?: run { done(); return call.reject("Host activity is not a FragmentActivity", "E_NO_ACTIVITY") }
                authenticateCipher(hostActivity, cipher, "Authenticate to save your secret", call,
                    onError = { done() }) { boundCipher ->
                    boundCipher.updateAAD(key.toByteArray(Charsets.UTF_8))
                    val ct = boundCipher.doFinal(value.toByteArray(Charsets.UTF_8))
                    storeItems().edit().putString(nameTag(key), storedValue(key, iv, ct)).commit()
                    done()
                    call.resolve()
                }
            }
        } catch (e: Exception) {
            logd("setItem encrypt failed for key=$key", e)
            done()
            call.reject("Store failed", "E_ENCRYPT")
        }
    }

    // ML-KEM encapsulate to pub + ChaCha20-Poly1305 seal -> frame = kemCt || nonce(12) || aead(+tag)
    private fun encapAndSeal(pub: PublicKey, plaintext: ByteArray): ByteArray {
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
            cipher.doFinal(plaintext)
        } finally {
            sharedSecret.fill(0)
        }
        return kemCt + nonce + aead
    }

    // decapsulate the frame with the (already unwrapped) private. Wipes privBytes + shared secret
    // (best-effort: JVM copies in SecretKeySpec/GC still linger).
    private fun decapsulate(privBytes: ByteArray, frame: ByteArray, ctLen: Int): ByteArray {
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
            return cipher.doFinal(aead)
        } finally {
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
        val parts = stored.split(".")
        if (parts.size != 3) return call.reject("Store item corrupt", "E_TAMPERED")
        val itemKey = (try { keystore().getKey(itemKeyAlias(key), null) as? SecretKey } catch (e: Exception) { null })
            ?: return call.reject("Store key missing", "E_KEY_NOT_FOUND")
        try {
            val iv = Base64.decode(parts[1], Base64.DEFAULT)
            val ct = Base64.decode(parts[2], Base64.DEFAULT)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, itemKey, GCMParameterSpec(128, iv))
            if (!isAuthRequired(itemKey)) {
                cipher.updateAAD(key.toByteArray(Charsets.UTF_8))
                val ret = JSObject(); ret.put("value", String(cipher.doFinal(ct), Charsets.UTF_8)); call.resolve(ret)
            } else {
                val hostActivity = activity as? FragmentActivity
                    ?: return call.reject("Host activity is not a FragmentActivity", "E_NO_ACTIVITY")
                authenticateCipher(hostActivity, cipher, "Authenticate to read your secret", call) { boundCipher ->
                    boundCipher.updateAAD(key.toByteArray(Charsets.UTF_8))
                    val ret = JSObject(); ret.put("value", String(boundCipher.doFinal(ct), Charsets.UTF_8)); call.resolve(ret)
                }
            }
        } catch (e: KeyPermanentlyInvalidatedException) {
            logd("getItem: key invalidated by biometric enrollment for key=$key", e)
            call.reject("Biometric enrollment changed; store key invalidated", "E_KEY_INVALIDATED")
        } catch (e: Exception) {
            logd("getItem failed for key=$key", e)
            call.reject("Read failed", "E_DECRYPT")
        }
    }

    // keys/hasItem stay silent (enumerating names leaks nothing). removeItem prompts only for a
    // biometric item, so silent items keep the drop-in behaviour.
    @PluginMethod
    fun removeItem(call: PluginCall) {
        val key = call.getString("key") ?: return call.reject("Missing key", "E_MISSING_PARAMS")
        val alias = itemKeyAlias(key)
        val itemKey = try { keystore().getKey(alias, null) as? SecretKey } catch (e: Exception) { null }
        val del = {
            try { keystore().deleteEntry(alias) } catch (e: Exception) { logd("removeItem: key delete failed", e) }
            storeItems().edit().remove(nameTag(key)).commit()
            call.resolve()
        }
        if (itemKey == null || !isAuthRequired(itemKey)) { del(); return }
        val hostActivity = activity as? FragmentActivity
            ?: return call.reject("Host activity is not a FragmentActivity", "E_NO_ACTIVITY")
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, itemKey)
            authenticateCipher(hostActivity, cipher, "Authenticate to delete your secret", call) { boundCipher ->
                boundCipher.doFinal(ByteArray(0)) // real op proves the biometric before the delete
                del()
            }
        } catch (e: KeyPermanentlyInvalidatedException) {
            // key already unusable, the value is unreadable anyway -> allow the delete
            logd("removeItem: key invalidated, removing", e)
            del()
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
        for ((_, v) in storeItems().all) {
            val parts = (v as? String)?.split(".") ?: continue
            if (parts.size != 3) continue
            try {
                arr.put(decName(parts[0]))
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
        val ks = keystore()
        val itemAliases = ks.aliases().toList().filter { it.startsWith(itemAliasPrefix) }
        val bioAlias = itemAliases.firstOrNull { a ->
            (ks.getKey(a, null) as? SecretKey)?.let { isAuthRequired(it) } ?: false
        }
        if (bioAlias == null) { doClearWipe(); call.resolve(); return }
        // prompt once, bound to a biometric item's key, before wiping
        val hostActivity = activity as? FragmentActivity
            ?: return call.reject("Host activity is not a FragmentActivity", "E_NO_ACTIVITY")
        try {
            val bioKey = ks.getKey(bioAlias, null) as SecretKey
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, bioKey)
            authenticateCipher(hostActivity, cipher, "Authenticate to erase secure storage", call) { boundCipher ->
                boundCipher.doFinal(ByteArray(0))
                doClearWipe()
                call.resolve()
            }
        } catch (e: KeyPermanentlyInvalidatedException) {
            logd("clear: key invalidated, wiping", e)
            doClearWipe()
            call.resolve()
        } catch (e: Exception) {
            logd("clear failed", e)
            call.reject("Clear failed", "E_CLEAR")
        }
    }

    private fun doClearWipe() {
        // wipe prefs, then delete every per-item key plus the name-hashing/encryption keys
        storeItems().edit().clear().commit()
        try {
            val ks = keystore()
            for (a in ks.aliases().toList().filter { it.startsWith(itemAliasPrefix) }) {
                try { ks.deleteEntry(a) } catch (e: Exception) { logd("clear: item key delete failed", e) }
            }
            for (a in listOf(ssMacAlias, ssNameKeyAlias)) {
                if (ks.containsAlias(a)) ks.deleteEntry(a)
            }
        } catch (e: Exception) {
            logd("clear: keystore delete failed", e)
        }
    }
}
