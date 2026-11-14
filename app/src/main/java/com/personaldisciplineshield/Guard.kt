package com.personaldisciplineshield

import android.content.Context
import android.os.SystemClock
import android.util.Base64
import android.widget.Toast
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Impulse-proof lock. Weakening any protection needs: PIN -> wait DELAY_MS -> short WINDOW_MS.
 * Tip: let a trusted person set the PIN so you do not know it.
 */
object Guard {
    private const val PIN_HASH = "pin_hash"
    private const val PIN_SALT = "pin_salt"
    private const val UNLOCK_AT = "unlock_at_elapsed"

    const val DELAY_MS = 15 * 60 * 1000L   // change to taste (e.g. 24h = 24*60*60*1000L)
    const val WINDOW_MS = 5 * 60 * 1000L
    const val MIN_LENGTH = 16

    fun hasPin(c: Context) = Prefs.getString(c, PIN_HASH) != null

    private fun hash(pin: String, salt: ByteArray): String {
        val md = MessageDigest.getInstance("SHA-256")
        md.update(salt)
        return Base64.encodeToString(md.digest(pin.toByteArray()), Base64.NO_WRAP)
    }

    fun setPin(c: Context, pin: String) {
        val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }
        Prefs.putString(c, PIN_SALT, Base64.encodeToString(salt, Base64.NO_WRAP))
        Prefs.putString(c, PIN_HASH, hash(pin, salt))
        lock(c)
    }

    fun checkPin(c: Context, pin: String): Boolean {
        val salt = Prefs.getString(c, PIN_SALT)?.let { Base64.decode(it, Base64.NO_WRAP) } ?: return false
        return hash(pin, salt) == Prefs.getString(c, PIN_HASH)
    }

    /** Uses the monotonic clock (changing the phone's date cannot shorten the wait).
     *  A value from before a reboot is impossible in the new boot, so it is treated as "none". */
    private fun unlockAt(c: Context): Long {
        val v = Prefs.getLong(c, UNLOCK_AT)
        return if (v > SystemClock.elapsedRealtime() + DELAY_MS) 0L else v
    }

    fun requestUnlock(c: Context) =
        Prefs.putLong(c, UNLOCK_AT, SystemClock.elapsedRealtime() + DELAY_MS)

    fun lock(c: Context) = Prefs.putLong(c, UNLOCK_AT, 0L)

    /** No PIN set = guard not armed = everything is changeable. */
    fun isUnlocked(c: Context): Boolean {
        if (!hasPin(c)) return true
        val at = unlockAt(c)
        val now = SystemClock.elapsedRealtime()
        return at in 1L..now && now < at + WINDOW_MS
    }

    fun waitingMs(c: Context): Long {
        return (unlockAt(c) - SystemClock.elapsedRealtime()).coerceAtLeast(0L)
    }

    fun openRemainingMs(c: Context): Long {
        return (unlockAt(c) + WINDOW_MS - SystemClock.elapsedRealtime()).coerceAtLeast(0L)
    }

    /** Call before any action that weakens protection. */
    fun require(c: Context): Boolean {
        if (isUnlocked(c)) return true
        val w = waitingMs(c)
        val msg = if (w > 0) "Locked. Unlock opens in ${w / 60000 + 1} min."
        else "Locked. Open Advanced protection > Request unlock."
        Toast.makeText(c, msg, Toast.LENGTH_LONG).show()
        return false
    }
}
