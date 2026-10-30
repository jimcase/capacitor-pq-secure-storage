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
}
