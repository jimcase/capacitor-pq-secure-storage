package com.capacitorpqsecurestorage

import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation
import org.bouncycastle.jcajce.spec.KEMExtractSpec
import org.bouncycastle.jcajce.spec.KEMGenerateSpec
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.BeforeClass
import org.junit.Test
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.Provider
import java.security.SecureRandom
import java.security.Security
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

// Pure-JVM tests for the crypto the Android plugin relies on. Runs with `./gradlew test`, no
// device. Validates BouncyCastle ML-KEM (the open shared-secret question), the raw<->SPKI
// public-key round-trip the wire format depends on, and the ChaCha20-Poly1305 framing.
class MlKemCryptoTest {
    companion object {
        @BeforeClass
        @JvmStatic
        fun setup() {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    @Test
    fun sharedSecretMatches768() = roundTrip(MLKEMParameterSpec.ml_kem_768)

    @Test
    fun sharedSecretMatches1024() = roundTrip(MLKEMParameterSpec.ml_kem_1024)

    private fun roundTrip(spec: MLKEMParameterSpec) {
        val kpg = KeyPairGenerator.getInstance("ML-KEM", "BC")
        kpg.initialize(spec, SecureRandom())
        val kp = kpg.generateKeyPair()

        val enc = KeyGenerator.getInstance("ML-KEM", "BC")
            .apply { init(KEMGenerateSpec.Builder(kp.public, "AES", 256).withNoKdf().build(), SecureRandom()) }
            .generateKey() as SecretKeyWithEncapsulation
        val dec = KeyGenerator.getInstance("ML-KEM", "BC")
            .apply { init(KEMExtractSpec.Builder(kp.private, enc.encapsulation, "AES", 256).withNoKdf().build()) }
            .generateKey() as SecretKeyWithEncapsulation

        assertArrayEquals("encapsulate/decapsulate shared secret must match", enc.encoded, dec.encoded)
        assertEquals("shared secret is 32 bytes (raw K, no KDF)", 32, enc.encoded.size)
    }

    @Test
    fun rawPublicKeyRoundTripsThroughSpki() {
        val kpg = KeyPairGenerator.getInstance("ML-KEM", "BC")
        kpg.initialize(MLKEMParameterSpec.ml_kem_1024, SecureRandom())
        val pub = kpg.generateKeyPair().public

        val raw = SubjectPublicKeyInfo.getInstance(pub.encoded).publicKeyData.bytes
        assertEquals("ML-KEM-1024 raw public key is 1568 bytes", 1568, raw.size)

        val spki = SubjectPublicKeyInfo(AlgorithmIdentifier(NISTObjectIdentifiers.id_alg_ml_kem_1024), raw)
        val rebuilt = KeyFactory.getInstance("ML-KEM", "BC").generatePublic(X509EncodedKeySpec(spki.encoded))
        // if the raw<->SPKI round-trip is wrong, encapsulation throws
        KeyGenerator.getInstance("ML-KEM", "BC").apply { init(KEMGenerateSpec(rebuilt, "AES"), SecureRandom()) }.generateKey()
    }

    private val bc: Provider = BouncyCastleProvider()
    private val msg = "from a peer".toByteArray()

    private fun b64(s: String): ByteArray = java.util.Base64.getDecoder().decode(s)

    private fun katPrivate(): PrivateKey =
        KeyFactory.getInstance("ML-KEM", bc).generatePrivate(PKCS8EncodedKeySpec(b64(MlKemKat.PRIVATE_PKCS8)))

    private fun chacha(mode: Int, key: ByteArray, nonce: ByteArray, input: ByteArray, aad: ByteArray? = null): ByteArray =
        Cipher.getInstance("ChaCha20-Poly1305").run {
            init(mode, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce))
            if (aad != null) updateAAD(aad)
            doFinal(input)
        }

    private fun assertFails(what: String, block: () -> Unit) {
        try {
            block()
            fail("expected $what to throw")
        } catch (e: Exception) {
            // expected
        }
    }

    // a ciphertext produced by noble: the frame an iOS, web or keripy peer would send
    @Test
    fun opensAFrameSealedWithTheRawSecretOfAnotherLibrary() {
        val nonce = ByteArray(12) { it.toByte() }
        val aead = chacha(Cipher.ENCRYPT_MODE, b64(MlKemKat.SHARED_SECRET), nonce, msg)
        val frame = b64(MlKemKat.CIPHER_TEXT) + nonce + aead
        assertArrayEquals(msg, MlKemCrypto.decapsulate(bc, katPrivate(), frame, 1088))
    }

    // the other direction: what Android seals must open with the raw K a peer derives
    @Test
    fun sealedFrameIsKeyedWithTheRawSharedSecret() {
        val pub = MlKemCrypto.publicFromRaw(bc, b64(MlKemKat.PUBLIC_RAW), NISTObjectIdentifiers.id_alg_ml_kem_768)
        val frame = MlKemCrypto.encapAndSeal(bc, pub, msg)
        val kemCt = frame.copyOfRange(0, 1088)
        val nonce = frame.copyOfRange(1088, 1100)
        val aead = frame.copyOfRange(1100, frame.size)
        val k = KeyGenerator.getInstance("ML-KEM", bc)
            .apply { init(KEMExtractSpec.Builder(katPrivate(), kemCt, "AES", 256).withNoKdf().build()) }
            .generateKey().encoded
        assertArrayEquals(msg, chacha(Cipher.DECRYPT_MODE, k, nonce, aead))
    }

    @Test
    fun encapAndSealRoundTripsThroughDecapsulate() {
        val pub = MlKemCrypto.publicFromRaw(bc, b64(MlKemKat.PUBLIC_RAW), NISTObjectIdentifiers.id_alg_ml_kem_768)
        val frame = MlKemCrypto.encapAndSeal(bc, pub, msg)
        assertArrayEquals(msg, MlKemCrypto.decapsulate(bc, katPrivate(), frame, 1088))
    }

    @Test
    fun aadBindsTheFrameToItsHeader() {
        val pub = MlKemCrypto.publicFromRaw(bc, b64(MlKemKat.PUBLIC_RAW), NISTObjectIdentifiers.id_alg_ml_kem_768)
        val frame = MlKemCrypto.encapAndSeal(bc, pub, msg, Frames.header(0x01))
        assertArrayEquals(msg, MlKemCrypto.decapsulate(bc, katPrivate(), frame, 1088, Frames.header(0x01)))
        assertFails("a frame opened without its aad") { MlKemCrypto.decapsulate(bc, katPrivate(), frame, 1088) }
        assertFails("a frame opened with another suite header") {
            MlKemCrypto.decapsulate(bc, katPrivate(), frame, 1088, Frames.header(0x02))
        }
    }

    // a v2 body from noble or CryptoKit: ChaCha20-Poly1305 keyed with the raw K, header as aad
    @Test
    fun opensAV2FrameSealedByAnotherLibrary() {
        val nonce = ByteArray(12) { it.toByte() }
        val aead = chacha(Cipher.ENCRYPT_MODE, b64(MlKemKat.SHARED_SECRET), nonce, msg, Frames.header(0x01))
        val body = b64(MlKemKat.CIPHER_TEXT) + nonce + aead
        assertArrayEquals(msg, MlKemCrypto.decapsulate(bc, katPrivate(), body, 1088, Frames.header(0x01)))
    }

    @Test
    fun aTruncatedV2BodyThrowsInsteadOfReturningGarbage() {
        val pub = MlKemCrypto.publicFromRaw(bc, b64(MlKemKat.PUBLIC_RAW), NISTObjectIdentifiers.id_alg_ml_kem_768)
        val body = MlKemCrypto.encapAndSeal(bc, pub, msg, Frames.header(0x01))
        for (len in intArrayOf(body.size - 1, body.size - 16, 1100, 1090, 1000, 0)) {
            assertFails("a body cut to $len bytes") {
                MlKemCrypto.decapsulate(bc, katPrivate(), body.copyOfRange(0, len), 1088, Frames.header(0x01))
            }
        }
    }

    @Test
    fun publicFromRawRejectsAWrongLength() {
        try {
            MlKemCrypto.publicFromRaw(bc, ByteArray(1183), NISTObjectIdentifiers.id_alg_ml_kem_768)
            fail("expected a length error")
        } catch (e: IllegalArgumentException) {
            // expected
        }
    }

    @Test
    fun chachaPolyRoundTrips() {
        val key = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val nonce = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val msg = "quantum-safe".toByteArray()

        val ct = Cipher.getInstance("ChaCha20-Poly1305").run {
            init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce))
            doFinal(msg)
        }
        val pt = Cipher.getInstance("ChaCha20-Poly1305").run {
            init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "ChaCha20"), IvParameterSpec(nonce))
            doFinal(ct)
        }
        assertArrayEquals(msg, pt)
    }
}
