package com.capacitorpqsecurestorage

import android.content.SharedPreferences
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

// like SharedPreferencesImpl: commit() changes the map first, then the "disk write" may fail
private class FakePrefs(init: Map<String, Any?> = emptyMap()) : SharedPreferences {
    val map = HashMap(init)
    var failWrites = 0

    override fun getAll(): MutableMap<String, *> = HashMap(map)
    override fun getString(key: String?, defValue: String?) = map[key] as String? ?: defValue
    override fun getStringSet(key: String?, defValues: MutableSet<String>?) = defValues
    override fun getInt(key: String?, defValue: Int) = map[key] as Int? ?: defValue
    override fun getLong(key: String?, defValue: Long) = map[key] as Long? ?: defValue
    override fun getFloat(key: String?, defValue: Float) = map[key] as Float? ?: defValue
    override fun getBoolean(key: String?, defValue: Boolean) = map[key] as Boolean? ?: defValue
    override fun contains(key: String?) = map.containsKey(key)
    override fun registerOnSharedPreferenceChangeListener(l: SharedPreferences.OnSharedPreferenceChangeListener?) {}
    override fun unregisterOnSharedPreferenceChangeListener(l: SharedPreferences.OnSharedPreferenceChangeListener?) {}

    override fun edit(): SharedPreferences.Editor = object : SharedPreferences.Editor {
        val puts = HashMap<String, Any?>()
        val removes = HashSet<String>()
        var clear = false
        override fun putString(key: String, value: String?) = apply { puts[key] = value }
        override fun putStringSet(key: String, values: MutableSet<String>?) = apply { puts[key] = values }
        override fun putInt(key: String, value: Int) = apply { puts[key] = value }
        override fun putLong(key: String, value: Long) = apply { puts[key] = value }
        override fun putFloat(key: String, value: Float) = apply { puts[key] = value }
        override fun putBoolean(key: String, value: Boolean) = apply { puts[key] = value }
        override fun remove(key: String) = apply { removes.add(key) }
        override fun clear() = apply { clear = true }
        override fun commit(): Boolean {
            if (clear) map.clear()
            removes.forEach { map.remove(it) }
            map.putAll(puts)
            if (failWrites > 0) { failWrites--; return false }
            return true
        }
        override fun apply() { commit() }
    }
}

class PrefsTest {
    @Test
    fun aFailedWritePutsTheOldValuesBackInMemory() {
        val p = FakePrefs(mapOf("a.pub" to "old", "a.wrapver" to 0, "other" to "x"))
        p.failWrites = 1
        val ok = commitOrRevert(p, listOf("a.pub", "a.wrapver", "a.tag")) {
            it.putString("a.pub", "new").putInt("a.wrapver", 1).putString("a.tag", "t")
        }
        assertFalse(ok)
        assertEquals(mapOf("a.pub" to "old", "a.wrapver" to 0, "other" to "x"), p.map)
    }

    @Test
    fun aFailedRemoveBringsTheEntryBack() {
        val p = FakePrefs(mapOf("tag" to "v"))
        p.failWrites = 1
        assertFalse(commitOrRevert(p, listOf("tag")) { it.remove("tag") })
        assertEquals(mapOf("tag" to "v"), p.map)
    }

    @Test
    fun aFailedClearBringsEverythingBack() {
        val p = FakePrefs(mapOf("a" to "1", "b" to "2"))
        p.failWrites = 1
        assertFalse(commitOrRevert(p, p.all.keys) { it.clear() })
        assertEquals(mapOf("a" to "1", "b" to "2"), p.map)
    }

    @Test
    fun aGoodWriteKeepsTheChange() {
        val p = FakePrefs(mapOf("a" to "1"))
        assertTrue(commitOrRevert(p, listOf("a", "b")) { it.putString("a", "2").putString("b", "3") })
        assertEquals(mapOf("a" to "2", "b" to "3"), p.map)
    }
}
