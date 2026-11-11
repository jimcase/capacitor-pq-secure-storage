package com.capacitorpqsecurestorage

import android.content.SharedPreferences

// SharedPreferences.commit() changes the map in memory before it writes the file, and keeps the
// change when the write fails. So a call that says "failed" would still serve the new state in this
// process, and the next good commit to the file would write it for real. On a failed write this
// puts the old values of [keys] back in memory (that second commit fixes memory even if its own
// write fails too). No string sets in this plugin's prefs.
internal fun commitOrRevert(prefs: SharedPreferences, keys: Collection<String>, change: (SharedPreferences.Editor) -> Unit): Boolean {
    val all = prefs.all
    val before = keys.associateWith { all[it] }
    val e = prefs.edit()
    change(e)
    if (e.commit()) return true
    val r = prefs.edit()
    for ((k, v) in before) {
        when (v) {
            is String -> r.putString(k, v)
            is Int -> r.putInt(k, v)
            is Long -> r.putLong(k, v)
            is Boolean -> r.putBoolean(k, v)
            is Float -> r.putFloat(k, v)
            else -> r.remove(k)
        }
    }
    r.commit()
    return false
}
