package com.capacitorpqsecurestorage

internal const val MAX_CRYPTO_INPUT = 10 * 1024 * 1024 // decoded-byte cap on crypto ops

internal class InputTooLargeException : Exception("Input too large")

// Base64 text from JS, bounded before and after decoding. The string length bounds the decoded
// size, so an oversized input is rejected without allocating the big buffer. Line breaks and spaces
// are skipped (as android.util.Base64 did); anything else outside the alphabet throws
// IllegalArgumentException instead of decoding to garbage.
internal fun decodeBase64Capped(data: String, maxBytes: Int = MAX_CRYPTO_INPUT): ByteArray {
    if (data.length > maxBytes * 2) throw InputTooLargeException()
    val clean = data.filterNot { it == '\n' || it == '\r' || it == ' ' || it == '\t' }
    val bytes = java.util.Base64.getDecoder().decode(clean)
    if (bytes.size > maxBytes) throw InputTooLargeException()
    return bytes
}
