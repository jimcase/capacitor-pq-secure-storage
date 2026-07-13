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
import org.junit.BeforeClass
import org.junit.Test
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Security
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
            .apply { init(KEMGenerateSpec(kp.public, "AES"), SecureRandom()) }
            .generateKey() as SecretKeyWithEncapsulation
        val dec = KeyGenerator.getInstance("ML-KEM", "BC")
            .apply { init(KEMExtractSpec(kp.private, enc.encapsulation, "AES")) }
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
