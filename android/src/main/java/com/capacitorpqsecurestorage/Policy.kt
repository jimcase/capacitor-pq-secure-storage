package com.capacitorpqsecurestorage

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt

// Decisions the plugin takes about keys, kept free of Android classes so plain JVM tests cover them.
internal object Policy {
    // The key to reuse for a setItem, or null to create a fresh one. Only a key with a real item
    // behind it is reused: an orphan left by a failed write can have any tier, so it is recreated
    // with the tier the caller asks for. [invalidated] is not called for an orphan.
    fun <K : Any> reusableItemKey(existing: K?, itemPresent: Boolean, invalidated: (K) -> Boolean): K? {
        if (existing == null || !itemPresent) return null
        return if (invalidated(existing)) null else existing
    }

    // The biometric key to bind a collective wipe prompt to. Keys killed by an enrollment change
    // guard nothing, and an invalidation on one of them must not read as "nothing to protect" while
    // live biometric items remain, so pick one that can still unlock. Null means there is none.
    fun <K : Any> pickLiveBioKey(bioKeys: List<K>, invalidated: (K) -> Boolean): K? =
        bioKeys.firstOrNull { !invalidated(it) }

    // The Keystore reports "EC" as the algorithm of an ECDSA private key. That is a KeyFactory name:
    // Signature.getInstance("EC") does not exist, so the overwrite gate could never sign for it.
    fun signatureAlgoFor(keyAlgorithm: String): String =
        if (keyAlgorithm == "EC") "SHA256withECDSA" else keyAlgorithm

    // Alias of the Keystore key that wraps an Ed25519 seed. Each generation gets its own versioned
    // key, so the live one survives until the new state is committed. A key made before this was
    // versioned has no version in prefs (-1) and keeps the plain alias. User aliases cannot hold a
    // dot, so a versioned alias never collides with another alias's plain one.
    fun sigWrapAlias(alias: String, ver: Int): String =
        if (ver < 0) "__pq_sigwrap_$alias" else "__pq_sigwrap_$alias.$ver"

    // An optional boolean option from JS: the default when absent, null when it is present but not a
    // real boolean. Taking the default there made setItem({ requireBiometric: "true" }) store a
    // silent item with no error.
    fun booleanOption(raw: Any?, default: Boolean): Boolean? = when (raw) {
        null -> default
        is Boolean -> raw
        else -> null
    }

    // a downgrade must not read like a normal rotation
    fun replacementPrompt(newRequiresBiometric: Boolean): String =
        if (newRequiresBiometric) "Authorize key replacement"
        else "Replace this key with one that does not need biometrics"

    // the BiometricPrompt ints are compile time constants, so this still runs in plain JVM tests
    fun promptErrorCode(errorCode: Int): String = when (errorCode) {
        BiometricPrompt.ERROR_HW_UNAVAILABLE,
        BiometricPrompt.ERROR_HW_NOT_PRESENT,
        BiometricPrompt.ERROR_NO_BIOMETRICS,
        BiometricPrompt.ERROR_LOCKOUT,
        BiometricPrompt.ERROR_LOCKOUT_PERMANENT,
        BiometricPrompt.ERROR_SECURITY_UPDATE_REQUIRED,
        BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL -> "E_BIOMETRY_UNAVAILABLE"
        else -> "E_AUTH_FAILED"
    }

    fun biometryUsable(canAuthenticate: Int): Boolean = canAuthenticate == BiometricManager.BIOMETRIC_SUCCESS

    const val MAX_STORE_ITEMS = 512
    const val MAX_STORE_TOTAL_CHARS = 16 * 1024 * 1024
    const val MAX_ALIASES_PER_KIND = 256

    // Upper bound of the text an item adds to the prefs file: base64 of the ciphertext and of the
    // encrypted name, the IV and the separators. It overestimates on purpose.
    fun storedEntryEstimate(keyUtf8: Int, valueUtf8: Int): Int = 4 * (keyUtf8 + valueUtf8) / 3 + 128

    // Whether a write still fits. [charsNow] must not count the entry being replaced.
    fun storeHasRoom(itemsNow: Int, charsNow: Long, replacing: Boolean, newEntryChars: Int): Boolean {
        val items = if (replacing) itemsNow else itemsNow + 1
        return items <= MAX_STORE_ITEMS && charsNow + newEntryChars <= MAX_STORE_TOTAL_CHARS
    }

    fun canAddAlias(pubCount: Int, exists: Boolean): Boolean = exists || pubCount < MAX_ALIASES_PER_KIND

    // Hardware keys carry no stored type, so what the caller asked for is checked against the key
    // itself: EC is ECDSA, and the two ML-DSA levels differ in public key length (1952 / 2592).
    fun hardwareTypeMismatch(keyAlgorithm: String, rawPubLength: Int, requested: String): Boolean {
        val isEc = keyAlgorithm == "EC"
        return when (requested) {
            "ECDSA_256R1" -> !isEc
            "PQC_MLDSA_65" -> isEc || rawPubLength != 1952
            "PQC_MLDSA_87" -> isEc || rawPubLength != 2592
            else -> true
        }
    }
}
