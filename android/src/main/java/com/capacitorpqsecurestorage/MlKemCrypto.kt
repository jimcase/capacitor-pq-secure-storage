package com.capacitorpqsecurestorage

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation
import org.bouncycastle.jcajce.spec.KEMExtractSpec
import org.bouncycastle.jcajce.spec.KEMGenerateSpec
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.Provider
import java.security.PublicKey
import java.security.SecureRandom
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

// ML-KEM encapsulate + ChaCha20-Poly1305 frame, no Android classes so it runs in plain JVM tests.
// frame = kemCt || nonce(12) || aead(+tag)
// The key is the raw FIPS 203 secret K, same as iOS CryptoKit and noble. BC's short KEM specs run K
// through KDF3-SHA256 by default, and then nothing else can open the frame, so keep withNoKdf().
internal object MlKemCrypto {
    // FIPS 203 raw public key sizes
    fun rawPublicLength(oid: ASN1ObjectIdentifier): Int = when (oid) {
        NISTObjectIdentifiers.id_alg_ml_kem_768 -> 1184
        NISTObjectIdentifiers.id_alg_ml_kem_1024 -> 1568
        else -> throw IllegalArgumentException("unsupported ML-KEM oid")
    }

    // the peer sends a raw public key; rebuild the SPKI wrapper JCA needs to parse it
    fun publicFromRaw(bc: Provider, raw: ByteArray, oid: ASN1ObjectIdentifier): PublicKey {
        if (raw.size != rawPublicLength(oid)) throw IllegalArgumentException("bad ML-KEM public key length")
        val spki = SubjectPublicKeyInfo(AlgorithmIdentifier(oid), raw)
        return KeyFactory.getInstance("ML-KEM", bc).generatePublic(X509EncodedKeySpec(spki.encoded))
    }

    fun encapAndSeal(bc: Provider, pub: PublicKey, plaintext: ByteArray, aad: ByteArray? = null): ByteArray {
        val kg = KeyGenerator.getInstance("ML-KEM", bc)
        kg.init(KEMGenerateSpec.Builder(pub, "AES", 256).withNoKdf().build(), SecureRandom())
        val enc = kg.generateKey() as SecretKeyWithEncapsulation
        val kemCt = enc.encapsulation
        val sharedSecret = enc.encoded
        val nonce = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val aead = try {
            val cipher = Cipher.getInstance("ChaCha20-Poly1305")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(sharedSecret, "ChaCha20"), IvParameterSpec(nonce))
            if (aad != null) cipher.updateAAD(aad)
            cipher.doFinal(plaintext)
        } finally {
            sharedSecret.fill(0)
        }
        return kemCt + nonce + aead
    }

    fun decapsulate(bc: Provider, priv: PrivateKey, frame: ByteArray, ctLen: Int, aad: ByteArray? = null): ByteArray {
        val kemCt = frame.copyOfRange(0, ctLen)
        val nonce = frame.copyOfRange(ctLen, ctLen + 12)
        val aead = frame.copyOfRange(ctLen + 12, frame.size)
        val kg = KeyGenerator.getInstance("ML-KEM", bc)
        kg.init(KEMExtractSpec.Builder(priv, kemCt, "AES", 256).withNoKdf().build())
        val shared = (kg.generateKey() as SecretKeyWithEncapsulation).encoded
        try {
            val cipher = Cipher.getInstance("ChaCha20-Poly1305")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(shared, "ChaCha20"), IvParameterSpec(nonce))
            if (aad != null) cipher.updateAAD(aad)
            return cipher.doFinal(aead)
        } finally {
            shared.fill(0)
        }
    }
}
