package com.capacitorpqsecurestorage

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
}
