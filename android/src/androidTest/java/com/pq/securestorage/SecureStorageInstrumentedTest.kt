package com.pq.securestorage

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertArrayEquals
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec

// Device/emulator tests for the non-biometric AndroidKeyStore path (the encryptAtRest primitive).
// sign/decrypt/getItem gate on a real biometric prompt, so those are manual on-device only.
@RunWith(AndroidJUnit4::class)
class SecureStorageInstrumentedTest {
    @Test
    fun keystoreAesGcmRoundTripsOnDevice() {
        val alias = "pqss.test.aes"
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        kg.init(
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        val key = kg.generateKey()
        val msg = "secret at rest".toByteArray()

        val enc = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key) }
        val iv = enc.iv
        val ct = enc.doFinal(msg)

        val dec = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
        }
        assertArrayEquals(msg, dec.doFinal(ct))
        ks.deleteEntry(alias)
    }
}
