package com.capacitorpqsecurestorage

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

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
}
