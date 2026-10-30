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
}
