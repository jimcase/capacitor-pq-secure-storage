package com.capacitorpqsecurestorage

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.fail
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.NoSuchAlgorithmException
import java.security.Signature
import java.security.spec.ECGenParameterSpec

class PolicyTest {
    @Test
    fun reusesAKeyThatHasAnItemBehindIt() {
        assertEquals("k", Policy.reusableItemKey("k", itemPresent = true) { false })
    }

    // an orphan key from a failed write may carry the wrong tier, so it is never reused
    @Test
    fun recreatesAnOrphanKey() {
        assertNull(Policy.reusableItemKey("k", itemPresent = false) { false })
    }

    @Test
    fun recreatesAnInvalidatedKey() {
        assertNull(Policy.reusableItemKey("k", itemPresent = true) { true })
    }

    @Test
    fun createsWhenThereIsNoKeyAtAll() {
        assertNull(Policy.reusableItemKey<String>(null, itemPresent = true) { false })
    }

    @Test
    fun doesNotProbeAnOrphanKey() {
        var probed = false
        Policy.reusableItemKey("k", itemPresent = false) { probed = true; false }
        assertEquals(false, probed)
    }

    @Test
    fun picksTheFirstBiometricKeyThatCanStillUnlock() {
        val keys = listOf("dead1", "live1", "live2")
        assertEquals("live1", Policy.pickLiveBioKey(keys) { it.startsWith("dead") })
    }

    // after an enrollment change every old key is dead: they guard nothing, so there is no prompt target
    @Test
    fun returnsNullWhenEveryBiometricKeyIsDead() {
        assertNull(Policy.pickLiveBioKey(listOf("dead1", "dead2")) { true })
    }

    @Test
    fun returnsNullWithNoBiometricKeys() {
        assertNull(Policy.pickLiveBioKey(emptyList<String>()) { false })
    }

    // the Keystore reports "EC" for these keys, which names a KeyFactory, not a Signature
    @Test
    fun theRawEcAlgorithmNameIsNotASignature() {
        val kp = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        try {
            Signature.getInstance(kp.private.algorithm)
            fail("expected NoSuchAlgorithmException")
        } catch (e: NoSuchAlgorithmException) {
            // expected
        }
    }

    @Test
    fun ecKeysSignWithSha256WithEcdsa() {
        val kp = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        assertEquals("SHA256withECDSA", Policy.signatureAlgoFor(kp.private.algorithm))
        Signature.getInstance(Policy.signatureAlgoFor(kp.private.algorithm)).initSign(kp.private)
    }

    @Test
    fun otherAlgorithmsKeepTheirName() {
        assertEquals("ML-DSA-65", Policy.signatureAlgoFor("ML-DSA-65"))
        assertEquals("Ed25519", Policy.signatureAlgoFor("Ed25519"))
    }

    // a wrapped key made before wrap keys were versioned has no version in prefs and keeps its alias
    @Test
    fun anUnversionedWrapKeyKeepsTheLegacyAlias() {
        assertEquals("__pq_sigwrap_id", Policy.sigWrapAlias("id", -1))
    }

    @Test
    fun versionedWrapKeysGetTheirOwnAlias() {
        assertEquals("__pq_sigwrap_id.0", Policy.sigWrapAlias("id", 0))
        assertEquals("__pq_sigwrap_id.3", Policy.sigWrapAlias("id", 3))
    }

    // the new key must not share an alias with the live one, or retiring the old would delete the new
    @Test
    fun consecutiveVersionsNeverCollide() {
        val aliases = (-1..4).map { Policy.sigWrapAlias("id", it) }
        assertEquals(aliases.size, aliases.toSet().size)
    }
}
