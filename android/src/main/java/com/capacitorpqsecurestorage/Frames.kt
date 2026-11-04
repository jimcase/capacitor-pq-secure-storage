package com.capacitorpqsecurestorage

// The v2 frame header and the read rule, kept free of Android classes so plain JVM tests cover them.
// 0x01..0x0F is encryptTo, 0x10..0x1F is encryptAtRest.
internal object Frames {
    const val HEADER_LEN = 4
    const val VERSION = 2
    val MAGIC = byteArrayOf(0x50, 0x51)

    const val KEM_MLKEM_768 = 0x01
    const val KEM_MLKEM_1024 = 0x02
    const val AT_REST_AES_GCM = 0x10
    const val AT_REST_SEP_ECIES = 0x11
    const val AT_REST_SEP_MLKEM = 0x12

    data class Header(val version: Int, val suite: Int)

    fun header(suite: Int): ByteArray = byteArrayOf(MAGIC[0], MAGIC[1], VERSION.toByte(), suite.toByte())

    // null under 4 bytes or without the PQ mark
    fun parse(frame: ByteArray): Header? {
        if (frame.size < HEADER_LEN || frame[0] != MAGIC[0] || frame[1] != MAGIC[1]) return null
        return Header(frame[2].toInt() and 0xff, frame[3].toInt() and 0xff)
    }

    fun isKnown(suite: Int): Boolean = when (suite) {
        KEM_MLKEM_768, KEM_MLKEM_1024, AT_REST_AES_GCM, AT_REST_SEP_ECIES, AT_REST_SEP_MLKEM -> true
        else -> false
    }

    fun isKemSuite(suite: Int): Boolean = suite in 0x01..0x0f

    fun isAtRestSuite(suite: Int): Boolean = suite in 0x10..0x1f

    fun kemSuiteOf(type: String): Int? = when (type) {
        "PQC_MLKEM_768" -> KEM_MLKEM_768
        "PQC_MLKEM_1024" -> KEM_MLKEM_1024
        else -> null
    }

    // The frame format from JS: 1 when absent, null when it is present but not 1 or 2. A JSON null
    // has to be mapped to Kotlin null by the caller, as for the boolean options.
    fun formatOption(raw: Any?): Int? = when (raw) {
        null -> 1
        is Number -> when (raw.toDouble()) {
            1.0 -> 1
            2.0 -> 2
            else -> null
        }
        else -> null
    }

    sealed class Open<T> {
        data class Ok<T>(val value: T, val readAs: Int) : Open<T>()
        data class Failed<T>(val unsupported: Boolean) : Open<T>()
    }

    // v2 first when the header fits the method, then v1 on the whole frame. A v1 frame can start
    // with the v2 bytes by chance (2^-24), so a failed v2 must not stop the v1 try.
    fun <T> open(
        frame: ByteArray,
        forKem: Boolean,
        suiteOk: (Int) -> Boolean,
        openV2: (header: ByteArray, suite: Int, body: ByteArray) -> T,
        openV1: (ByteArray) -> T,
    ): Open<T> {
        val h = parse(frame)
        if (h != null && h.version == VERSION && isKnown(h.suite) &&
            (if (forKem) isKemSuite(h.suite) else isAtRestSuite(h.suite)) && suiteOk(h.suite)
        ) {
            try {
                val value = openV2(frame.copyOfRange(0, HEADER_LEN), h.suite, frame.copyOfRange(HEADER_LEN, frame.size))
                return Open.Ok(value, 2)
            } catch (e: Exception) {
                // fall through to v1
            }
        }
        return try {
            Open.Ok(openV1(frame), 1)
        } catch (e: Exception) {
            Open.Failed(h != null && (h.version != VERSION || !isKnown(h.suite)))
        }
    }
}
