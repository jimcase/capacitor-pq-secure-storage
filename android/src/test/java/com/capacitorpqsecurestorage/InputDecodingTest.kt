package com.capacitorpqsecurestorage

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.fail
import org.junit.Test

class InputDecodingTest {
    @Test
    fun decodesValidBase64() {
        assertArrayEquals(byteArrayOf(104, 105), decodeBase64Capped("aGk="))
    }

    @Test
    fun skipsLineBreaksAndSpaces() {
        assertArrayEquals("hello world".toByteArray(), decodeBase64Capped("aGVsbG8g\nd29y bGQ="))
    }

    @Test
    fun rejectsCharactersOutsideTheAlphabet() {
        try {
            decodeBase64Capped("***")
            fail("expected IllegalArgumentException")
        } catch (e: IllegalArgumentException) {
            // expected
        }
    }

    @Test
    fun rejectsALongStringBeforeDecodingIt() {
        try {
            decodeBase64Capped("A".repeat(9), maxBytes = 4)
            fail("expected InputTooLargeException")
        } catch (e: InputTooLargeException) {
            // expected
        }
    }

    @Test
    fun rejectsWhenTheDecodedSizeIsOverTheCap() {
        try {
            decodeBase64Capped("AAAAAAAA", maxBytes = 4) // 8 chars fit the length bound, 6 bytes do not
            fail("expected InputTooLargeException")
        } catch (e: InputTooLargeException) {
            // expected
        }
    }
}
