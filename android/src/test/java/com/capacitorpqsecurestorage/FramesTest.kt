package com.capacitorpqsecurestorage

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class FramesTest {
    private fun bytes(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }

    private val v1 = { f: ByteArray ->
        if (f[0] != 0xaa.toByte()) throw IllegalStateException("v1")
        "v1"
    }
    private val v2 = { _: ByteArray, s: Int, body: ByteArray ->
        if (body[0] != 0xbb.toByte()) throw IllegalStateException("v2")
        "v2:$s"
    }

    @Test
    fun headerIsMagicVersionAndSuite() {
        assertArrayEquals(bytes(0x50, 0x51, 0x02, 0x12), Frames.header(0x12))
    }

    @Test
    fun parseReturnsNullWithoutMagicOrUnderFourBytes() {
        assertEquals(Frames.Header(2, 1), Frames.parse(bytes(0x50, 0x51, 0x02, 0x01, 9)))
        assertNull(Frames.parse(bytes(0x50, 0x51, 0x02)))
        assertNull(Frames.parse(bytes(0x04, 0x51, 0x02, 0x01)))
    }

    @Test
    fun suiteRangesFollowTheMethod() {
        val known = (0..0x30).filter { Frames.isKnown(it) }
        assertEquals(listOf(0x01, 0x02, 0x10, 0x11, 0x12), known)
        assertTrue(Frames.isKemSuite(0x01) && Frames.isKemSuite(0x0f) && !Frames.isKemSuite(0x10))
        assertTrue(Frames.isAtRestSuite(0x10) && Frames.isAtRestSuite(0x1f) && !Frames.isAtRestSuite(0x20))
        assertFalse(Frames.isKemSuite(0x00))
        assertEquals(0x01, Frames.kemSuiteOf("PQC_MLKEM_768"))
        assertEquals(0x02, Frames.kemSuiteOf("PQC_MLKEM_1024"))
        assertNull(Frames.kemSuiteOf("PQC_MLDSA_65"))
    }

    @Test
    fun formatOptionReadsNumbersOnly() {
        assertEquals(1, Frames.formatOption(null))
        assertEquals(1, Frames.formatOption(1))
        assertEquals(2, Frames.formatOption(2))
        assertEquals(2, Frames.formatOption(2L))
        assertEquals(2, Frames.formatOption(2.0))
        for (bad in listOf<Any>("2", 1.5, 3, 0, true)) assertNull(Frames.formatOption(bad))
    }

    @Test
    fun openPrefersV2ThenFallsBackToV1() {
        val ok = Frames.open(bytes(0x50, 0x51, 2, 0x01, 0xbb), true, { true }, v2, v1)
        assertEquals(Frames.Open.Ok("v2:1", 2), ok)

        // a v1 frame can start with the v2 bytes by chance, so a failed v2 must not stop v1
        val f = bytes(0x50, 0x51, 2, 0x01, 0x00)
        val back = Frames.open(f, true, { true }, v2) { x -> if (x === f) "whole" else "no" }
        assertEquals(Frames.Open.Ok("whole", 1), back)
    }

    @Test
    fun openSkipsASuiteOfTheOtherMethod() {
        val other = Frames.open(bytes(0x50, 0x51, 2, 0x10, 0xbb), true, { true }, v2, v1)
        assertEquals(Frames.Open.Failed<String>(false), other)
        val refused = Frames.open(bytes(0x50, 0x51, 2, 0x01, 0xbb), true, { false }, v2, v1)
        assertEquals(Frames.Open.Failed<String>(false), refused)
        val atRest = Frames.open(bytes(0x50, 0x51, 2, 0x01, 0xbb), false, { true }, v2, v1)
        assertEquals(Frames.Open.Failed<String>(false), atRest)
    }

    @Test
    fun openFlagsANewerVersionOrUnknownSuiteOnlyAfterV1Fails() {
        val newer = Frames.open(bytes(0x50, 0x51, 3, 0x01, 0xbb), true, { true }, v2, v1)
        assertEquals(Frames.Open.Failed<String>(true), newer)
        val unknown = Frames.open(bytes(0x50, 0x51, 2, 0x0e, 0xbb), true, { true }, v2, v1)
        assertEquals(Frames.Open.Failed<String>(true), unknown)
        val readable = Frames.open(bytes(0x50, 0x51, 3, 0x01), true, { true }, v2) { "v1" }
        assertEquals(Frames.Open.Ok("v1", 1), readable)
    }

    @Test
    fun openNeverThrowsOnAShortFrame() {
        val r = Frames.open(bytes(0x50), false, { true }, v2, v1)
        assertEquals(Frames.Open.Failed<String>(false), r)
    }
}
