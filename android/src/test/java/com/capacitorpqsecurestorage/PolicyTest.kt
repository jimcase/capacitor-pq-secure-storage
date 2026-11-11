package com.capacitorpqsecurestorage

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
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

    @Test
    fun anAbsentOptionTakesTheDefault() {
        assertEquals(true, Policy.booleanOption(null, true))
        assertEquals(false, Policy.booleanOption(null, false))
    }

    @Test
    fun aRealBooleanIsUsedAsIs() {
        assertEquals(true, Policy.booleanOption(true, false))
        assertEquals(false, Policy.booleanOption(false, true))
    }

    // setItem({ requireBiometric: "true" }) used to store a silent item with no error
    @Test
    fun aValueThatIsNotABooleanIsInvalid() {
        assertNull(Policy.booleanOption("true", false))
        assertNull(Policy.booleanOption(1, false))
        assertNull(Policy.booleanOption(Any(), true))
    }

    @Test fun storeRejectsOneItemOverTheCap() { assertFalse(Policy.storeHasRoom(512, 0L, replacing = false, newEntryChars = 1)) }
    @Test fun storeAcceptsAReplacementAtTheCap() { assertTrue(Policy.storeHasRoom(512, 0L, replacing = true, newEntryChars = 1)) }
    @Test fun storeRejectsWhenTheTextBudgetIsExceeded() { assertFalse(Policy.storeHasRoom(1, Policy.MAX_STORE_TOTAL_CHARS - 10L, replacing = false, newEntryChars = 11)) }
    @Test fun storeAcceptsExactlyTheTextBudget() { assertTrue(Policy.storeHasRoom(1, Policy.MAX_STORE_TOTAL_CHARS - 10L, replacing = false, newEntryChars = 10)) }
    @Test fun entryEstimateCoversTheBase64Growth() { assertTrue(Policy.storedEntryEstimate(10, 262144) >= 349_600) }
    @Test fun aliasCapAllowsAnOverwrite() { assertTrue(Policy.canAddAlias(256, exists = true)); assertFalse(Policy.canAddAlias(256, exists = false)) }
    @Test fun ecKeyMatchesOnlyEcdsa() { assertFalse(Policy.hardwareTypeMismatch("EC", 33, "ECDSA_256R1")); assertTrue(Policy.hardwareTypeMismatch("EC", 33, "PQC_MLDSA_65")) }
    @Test fun mldsaIsToldApartByPublicKeyLength() { assertFalse(Policy.hardwareTypeMismatch("ML-DSA", 1952, "PQC_MLDSA_65")); assertTrue(Policy.hardwareTypeMismatch("ML-DSA", 1952, "PQC_MLDSA_87")) }

    @Test fun replacementPromptIsTheUsualOneWhenTheNewKeyStaysBiometric() { assertEquals("Authorize key replacement", Policy.replacementPrompt(true)) }
    @Test fun replacementPromptNamesTheDropWhenTheNewKeyIsSilent() { assertEquals("Replace this key with one that does not need biometrics", Policy.replacementPrompt(false)) }

    @Test
    fun aProbeThatWorksIsTrueAndCleansUp() {
        var cleaned = false
        assertTrue(Policy.probe(make = {}, cleanup = { cleaned = true }))
        assertTrue(cleaned)
    }

    @Test
    fun aProbeThatThrowsIsFalseAndStillCleansUp() {
        var cleaned = false
        assertFalse(Policy.probe(make = { throw IllegalStateException("keymint") }, cleanup = { cleaned = true }))
        assertTrue(cleaned)
    }

    @Test
    fun aProbeCleansUpAfterMakeWhetherItWorksOrNot() {
        val calls = mutableListOf<String>()
        Policy.probe(make = { calls.add("make") }, cleanup = { calls.add("cleanup") })
        Policy.probe(make = { calls.add("make"); throw IllegalStateException("keymint") }, cleanup = { calls.add("cleanup") })
        assertEquals(listOf("make", "cleanup", "make", "cleanup"), calls)
    }

    @Test
    fun aCleanupThatThrowsDoesNotChangeTheAnswer() {
        assertTrue(Policy.probe(make = {}, cleanup = { throw IllegalStateException("gone") }))
        assertFalse(Policy.probe(make = { throw IllegalStateException("x") }, cleanup = { throw IllegalStateException("gone") }))
    }

    @Test fun aPromptWhileTheSensorIsBusyIsUnavailable() { assertEquals("E_BIOMETRY_UNAVAILABLE", Policy.promptErrorCode(BiometricPrompt.ERROR_HW_UNAVAILABLE)) }
    @Test fun aPromptWithNoSensorIsUnavailable() { assertEquals("E_BIOMETRY_UNAVAILABLE", Policy.promptErrorCode(BiometricPrompt.ERROR_HW_NOT_PRESENT)) }
    @Test fun aPromptWithNothingEnrolledIsUnavailable() { assertEquals("E_BIOMETRY_UNAVAILABLE", Policy.promptErrorCode(BiometricPrompt.ERROR_NO_BIOMETRICS)) }
    @Test fun aLockoutIsUnavailable() { assertEquals("E_BIOMETRY_UNAVAILABLE", Policy.promptErrorCode(BiometricPrompt.ERROR_LOCKOUT)) }
    @Test fun aPermanentLockoutIsUnavailable() { assertEquals("E_BIOMETRY_UNAVAILABLE", Policy.promptErrorCode(BiometricPrompt.ERROR_LOCKOUT_PERMANENT)) }
    @Test fun aSensorThatWaitsForASecurityUpdateIsUnavailable() { assertEquals("E_BIOMETRY_UNAVAILABLE", Policy.promptErrorCode(BiometricPrompt.ERROR_SECURITY_UPDATE_REQUIRED)) }
    @Test fun aDeviceWithNoPinOrPasswordIsUnavailable() { assertEquals("E_BIOMETRY_UNAVAILABLE", Policy.promptErrorCode(BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL)) }

    // the user or the system ended a prompt that could run: the host must not read it as no biometric
    @Test
    fun aCancelledPromptStaysAuthFailed() {
        for (code in listOf(BiometricPrompt.ERROR_USER_CANCELED, BiometricPrompt.ERROR_NEGATIVE_BUTTON, BiometricPrompt.ERROR_CANCELED)) {
            assertEquals("code $code", "E_AUTH_FAILED", Policy.promptErrorCode(code))
        }
    }

    @Test
    fun otherPromptErrorsStayAuthFailed() {
        for (code in listOf(BiometricPrompt.ERROR_TIMEOUT, BiometricPrompt.ERROR_UNABLE_TO_PROCESS, BiometricPrompt.ERROR_NO_SPACE,
                BiometricPrompt.ERROR_VENDOR)) {
            assertEquals("code $code", "E_AUTH_FAILED", Policy.promptErrorCode(code))
        }
    }

    @Test fun anUnknownPromptErrorIsAuthFailed() { assertEquals("E_AUTH_FAILED", Policy.promptErrorCode(999)); assertEquals("E_AUTH_FAILED", Policy.promptErrorCode(-1)) }

    @Test fun aBiometricIsUsableOnlyOnSuccess() { assertTrue(Policy.biometryUsable(BiometricManager.BIOMETRIC_SUCCESS)) }

    @Test
    fun noBiometricIsUsableOnAnyOtherAnswer() {
        for (r in listOf(BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED, BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE,
                BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE, BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED,
                BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED, BiometricManager.BIOMETRIC_STATUS_UNKNOWN)) {
            assertFalse("answer $r", Policy.biometryUsable(r))
        }
    }

    // biometric 1.1.0 drops a prompt asked after onStop with no callback at all
    @Test fun aPromptCanStartInTheForeground() { assertTrue(Policy.promptCanStart(stateSaved = false, finishing = false)) }
    @Test fun aPromptCannotStartOnceTheActivityIsStopped() { assertFalse(Policy.promptCanStart(stateSaved = true, finishing = false)) }
    @Test fun aPromptCannotStartOnAFinishingActivity() { assertFalse(Policy.promptCanStart(stateSaved = false, finishing = true)) }

    // android deletes the alias of a failed keygen, and on a replace that alias still holds the old key
    @Test
    fun aReplaceThatFailsTheTrialNeverTouchesTheRealAlias() {
        val calls = mutableListOf<String>()
        try {
            Policy.replaceKey(true, trial = { calls.add("trial"); throw IllegalStateException("keymint") },
                cleanup = { calls.add("cleanup") }, real = { calls.add("real") })
            fail("should throw")
        } catch (e: IllegalStateException) {
        }
        assertEquals(listOf("trial", "cleanup"), calls)
    }

    @Test
    fun aReplaceRunsTheTrialThenCleansUpThenTheRealKeygen() {
        val calls = mutableListOf<String>()
        assertEquals("k", Policy.replaceKey(true, trial = { calls.add("trial") }, cleanup = { calls.add("cleanup") },
            real = { calls.add("real"); "k" }))
        assertEquals(listOf("trial", "cleanup", "real"), calls)
    }

    @Test
    fun aNewAliasSkipsTheTrial() {
        val calls = mutableListOf<String>()
        Policy.replaceKey(false, trial = { calls.add("trial") }, cleanup = { calls.add("cleanup") }, real = { calls.add("real") })
        assertEquals(listOf("real"), calls)
    }

    @Test fun theTrialAliasIsReservedAndPerAlias() { assertEquals("__pq_trial_id", Policy.trialAlias("id")) }
}
