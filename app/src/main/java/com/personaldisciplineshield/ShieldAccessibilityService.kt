package com.personaldisciplineshield

import android.accessibilityservice.AccessibilityService
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Rect
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.view.Display
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import android.widget.Toast
import java.util.concurrent.Executors

/**
 * 1) Blocks chosen apps  2) Blocks chosen keywords typed/searched (text fields + browser URL bars)
 * 3) Guards Settings/uninstall screens that expose this app (when PIN lock is armed and locked)
 * 4) Optional screenshot check with an on-device image classifier (Android 11+)
 */
class ShieldAccessibilityService : AccessibilityService() {

    private val handler = Handler(Looper.getMainLooper())
    private val worker = Executors.newSingleThreadExecutor()
    private var lastAction = 0L
    private var lastScan = 0L
    private var lastShot = 0L
    @Volatile private var shotBusy = false
    private val strikes = ArrayList<Long>()
    private var classifier: NsfwClassifier? = null
    private val imageThreshold = 0.80f

    // Settings lockdown (allow-list) state
    // Includes MIUI Security app and Battery (powerkeeper): permissions/autostart/force-stop screens live there.
    private val lockdownPackages = setOf(
        "com.android.settings", "com.oplus.settings", "com.coloros.settings",
        "com.miui.securitycenter", "com.miui.powerkeeper"
    )
    // Rows of the Settings home / category lists (stock Android + MIUI). If any is on screen it is a list, not an allowed page.
    private val homepageMarkers = setOf(
        "mobile networks", "sim cards & mobile networks", "connection & sharing",
        "network & internet", "connected devices", "passwords & security",
        "additional settings", "about phone", "lock screen & password", "special features"
    )
    private var settingsHome = false
    // Never blockable by the app-block list (would break Settings, permissions, installers, calling, launcher).
    private val protectedPackages = setOf(
        "com.android.settings", "com.miui.securitycenter", "com.miui.powerkeeper",
        "com.android.systemui", "com.android.phone", "com.android.server.telecom",
        "com.google.android.permissioncontroller", "com.android.permissioncontroller",
        "com.google.android.packageinstaller", "com.android.packageinstaller",
        "com.miui.packageinstaller", "com.coloros.safecenter", "com.oplus.settings",
        "com.android.providers.settings"
    )
    private fun isProtectedPackage(pkg: String) =
        pkg == packageName || pkg == launcherPkg || pkg in protectedPackages
    // Activity class-name fragments that are always allowed (Wi-Fi, Bluetooth, hotspot pages and panels)
    private val allowedClassTokens = listOf("wifi", "bluetooth", "tether", "hotspot", "networkprovider", "settingspanel")
    private var settingsAllowed = false
    private var lastStateChange = 0L
    private var lastLockdownScan = 0L
    private var lastSettingsClass = ""

    // WhatsApp
    private val whatsappPkgs = setOf("com.whatsapp", "com.whatsapp.w4b")
    private val channelWords = setOf("find channels", "explore channels")
    private var waPausedUntil = 0L
    private val waActions = ArrayList<Long>()
    private var lastWa = 0L
    private var lastWaAction = 0L
    private var lastBeat = 0L
    private var lastDump = 0L

    private val settingsPackages = setOf(
        "com.android.settings", "com.google.android.packageinstaller",
        "com.android.packageinstaller", "com.samsung.android.packageinstaller",
        "com.google.android.permissioncontroller", "com.android.permissioncontroller",
        "com.miui.securitycenter", "com.miui.packageinstaller",
        "com.coloros.safecenter", "com.oplus.settings", "com.android.vending"
    )

    private val browserUrlBars = listOf(
        "com.android.chrome:id/url_bar",
        "com.brave.browser:id/url_bar",
        "com.microsoft.emmx:id/url_bar",
        "org.mozilla.firefox:id/mozac_browser_toolbar_url_view",
        "com.sec.android.app.sbrowser:id/location_bar_edit_text",
        "com.opera.browser:id/url_field",
        "com.duckduckgo.mobile.android:id/omnibarTextInput"
    )

    private val launcherPkg: String? by lazy {
        packageManager.resolveActivity(
            Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_HOME), 0
        )?.activityInfo?.packageName
    }

    override fun onServiceConnected() {
        classifier = NsfwClassifier(this).takeIf { it.available }
    }

    override fun onAccessibilityEvent(e: AccessibilityEvent?) {
        e ?: return
        val pkg = e.packageName?.toString() ?: return
        heartbeat(e, pkg)
        if (pkg == packageName || pkg == "com.android.systemui") return
        val type = e.eventType
        if (pkg !in lockdownPackages && type == AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED) settingsAllowed = false

        if (Prefs.enabled(this, Prefs.DEBUG, false) && (pkg in whatsappPkgs || pkg in lockdownPackages)) dumpScreen(e, pkg)

        // 1) Blocked apps
        if (type == AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED &&
            Prefs.enabled(this, Prefs.APPS_ON, true) &&
            !isProtectedPackage(pkg) && pkg in Prefs.strings(this, Prefs.BLOCKED_APPS)
        ) {
            punish("app blocked"); return
        }

        // 2) Settings / uninstall guard
        if (pkg in settingsPackages && guardActive()) {
            if (scanSettings()) { punish("protected screen"); return }
        }

        // 2b) Settings app lockdown: only allow-listed pages (Wi-Fi, Bluetooth, hotspot...)
        if (pkg in lockdownPackages && lockdownActive()) {
            if (settingsLockdown(e)) { punish("settings locked"); return }
        }

        // 2c) WhatsApp: keep chats, block Channels / Updates tab
        if (pkg in whatsappPkgs && Prefs.enabled(this, Prefs.WA_CHANNELS, true)) {
            if (checkWhatsApp(e)) return
        }

        // 3) Keywords
        if (Prefs.enabled(this, Prefs.KEYWORDS_ON, true) && !e.isPassword) {
            if (checkKeywords(e, pkg)) { punish("blocked keyword"); return }
        }

        // 4) Images (optional)
        if (type == AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED ||
            type == AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED
        ) maybeScreenshot(pkg)
    }

    override fun onInterrupt() {}

    // ---------- Settings guard ----------
    private fun guardActive() =
        Prefs.enabled(this, Prefs.SETTINGS_GUARD, true) &&
            Guard.hasPin(this) && !Guard.isUnlocked(this)

    private fun scanSettings(): Boolean {
        val now = SystemClock.elapsedRealtime()
        if (now - lastScan < 250) return false
        lastScan = now
        val root = rootInActiveWindow ?: return false
        val sb = StringBuilder()
        collectText(root, sb, intArrayOf(500), 0)
        val text = sb.toString().lowercase()
        val label = applicationInfo.loadLabel(packageManager).toString().lowercase()
        // "private dns" is English-only; the app label matches on any language.
        return text.contains(label) || text.contains("private dns")
    }

    private fun collectText(n: AccessibilityNodeInfo, sb: StringBuilder, budget: IntArray, depth: Int) {
        if (budget[0]-- <= 0 || depth > 30) return
        n.text?.let { sb.append(it).append('\n') }
        n.contentDescription?.let { sb.append(it).append('\n') }
        for (i in 0 until n.childCount) {
            val ch = n.getChild(i) ?: continue
            collectText(ch, sb, budget, depth + 1)
        }
    }

    // ---------- Diagnostics ----------
    private fun heartbeat(e: AccessibilityEvent, pkg: String) {
        val now = SystemClock.elapsedRealtime()
        if (now - lastBeat < 1000) return
        lastBeat = now
        val time = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US).format(java.util.Date())
        Prefs.putString(this, "dbg_last_event", "$time  $pkg  ${e.className}")
    }

    /** Saves what the service can see on screen (only while Diagnostics is switched on). */
    private fun dumpScreen(e: AccessibilityEvent, pkg: String) {
        val now = SystemClock.elapsedRealtime()
        if (now - lastDump < 1500) return
        lastDump = now
        val root = rootInActiveWindow ?: return
        val h = resources.displayMetrics.heightPixels.coerceAtLeast(1)
        val parts = ArrayList<String>()
        fun walk(n: AccessibilityNodeInfo, depth: Int, budget: IntArray) {
            if (budget[0]-- <= 0 || depth > 30 || parts.size > 60) return
            val t = n.text?.toString()?.trim().orEmpty()
            val d = n.contentDescription?.toString()?.trim().orEmpty()
            val label = (t + if (d.isNotEmpty()) " [$d]" else "").trim()
            if (label.isNotEmpty()) {
                val r = Rect()
                n.getBoundsInScreen(r)
                parts.add("${r.top * 100 / h}%: ${label.take(40)}${if (n.isSelected) " (selected)" else ""}")
            }
            for (i in 0 until n.childCount) n.getChild(i)?.let { walk(it, depth + 1, budget) }
        }
        walk(root, 0, intArrayOf(300))
        val key = if (pkg in whatsappPkgs) "dbg_screen_wa" else "dbg_screen_settings"
        Prefs.putString(this, key, "$pkg | ${e.className}\n" + parts.joinToString("\n").take(1500))
    }

    // ---------- Settings lockdown (allow-list) ----------
    // Active while the switch is ON. With a PIN set it also pauses during the unlock window.
    private fun lockdownActive() =
        Prefs.enabled(this, Prefs.SETTINGS_LOCKDOWN, false) &&
            (!Guard.hasPin(this) || !Guard.isUnlocked(this))

    /** Returns true when the current Settings screen must be blocked. */
    private fun settingsLockdown(e: AccessibilityEvent): Boolean {
        val now = SystemClock.elapsedRealtime()
        val isState = e.eventType == AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED
        val cls = e.className?.toString()?.lowercase() ?: ""
        // Dialogs/popups (android.*) keep the state of the page below them.
        if (isState && !cls.startsWith("android.") && !cls.startsWith("androidx.")) {
            settingsAllowed = allowedClassTokens.any { cls.contains(it) }
            settingsHome = cls.contains("miuisettings") || cls.contains("homepage")
            lastStateChange = now
            lastSettingsClass = cls
        }
        if (settingsAllowed) return false
        if (!isState && now - lastLockdownScan < 200) return false
        lastLockdownScan = now
        val root = rootInActiveWindow ?: return false
        val header = headerTexts(root)
        if (headerAllowed(header)) { settingsAllowed = true; return false }
        if (now - lastStateChange < 700) {
            // Page may still be loading; look again shortly.
            handler.postDelayed({ recheckSettings() }, 750)
            return false
        }
        recordBlock(header)
        return true
    }

    private fun recheckSettings() {
        if (!lockdownActive() || settingsAllowed) return
        val root = rootInActiveWindow ?: return
        val p = root.packageName?.toString() ?: return
        if (p !in lockdownPackages) return
        val header = headerTexts(root)
        if (headerAllowed(header)) { settingsAllowed = true; return }
        recordBlock(header)
        punish("settings locked")
    }

    private fun headerAllowed(header: List<String>): Boolean {
        // MIUI's Settings home lists "Wi-Fi" and "Bluetooth" rows near the top, so a title match alone is not enough.
        if (settingsHome || header.any { it in homepageMarkers }) return false
        val allowed = Prefs.allowedSettings(this)
        return header.any { it in allowed }
    }

    private fun recordBlock(header: List<String>) {
        Prefs.putString(this, "last_settings_block", "$lastSettingsClass | ${header.joinToString(", ")}")
    }

    /** Lower-cased short texts in the top part of the screen (page title area). */
    private fun headerTexts(root: AccessibilityNodeInfo): List<String> {
        val limit = resources.displayMetrics.heightPixels * 0.38
        val out = ArrayList<String>()
        fun walk(n: AccessibilityNodeInfo, depth: Int, budget: IntArray) {
            if (budget[0]-- <= 0 || depth > 30) return
            val t = n.text?.toString()?.trim()?.lowercase()
            if (!t.isNullOrEmpty() && t.length <= 40) {
                val r = Rect()
                n.getBoundsInScreen(r)
                if (r.top < limit && r.bottom > 0) out.add(t)
            }
            for (i in 0 until n.childCount) n.getChild(i)?.let { walk(it, depth + 1, budget) }
        }
        walk(root, 0, intArrayOf(400))
        return out
    }

    // ---------- WhatsApp: block Channels / Updates tab ----------
    private fun checkWhatsApp(e: AccessibilityEvent): Boolean {
        val now = SystemClock.elapsedRealtime()
        if (now < waPausedUntil) return false
        val cls = e.className?.toString()?.lowercase() ?: ""
        var rule: String? = if (cls.contains("newsletter")) "class:$cls" else null // WhatsApp's internal name for Channels
        var root: AccessibilityNodeInfo? = null
        if (rule == null) {
            if (e.eventType != AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED && now - lastWa < 250) return false
            lastWa = now
            root = rootInActiveWindow
            if (root == null) return false
            rule = channelsUi(root, false, intArrayOf(400), 0)
        }
        if (rule == null) return false
        if (now - lastWaAction < 800) return true
        lastWaAction = now

        // Safety valve: if this keeps firing, pause the rule so WhatsApp never becomes unusable.
        waActions.add(now)
        waActions.removeAll { now - it > 10_000L }
        if (waActions.size >= 4) {
            waActions.clear()
            waPausedUntil = now + 60_000L
            Prefs.putString(this, "last_wa_block", "PAUSED 60s after repeated hits. Last rule: $rule | $cls")
            Toast.makeText(this, "Shield: WhatsApp rule paused for 1 min (see Diagnostics)", Toast.LENGTH_LONG).show()
            return false
        }

        Prefs.putString(this, "last_wa_block", "$rule | $cls")
        val r = root ?: rootInActiveWindow
        val clicked = r != null && goToChatsTab(r)
        // Back is used only for screens WhatsApp itself names as Channels ("newsletter"); never for tab guesses.
        if (!clicked && rule.startsWith("class:")) performGlobalAction(GLOBAL_ACTION_BACK)
        Toast.makeText(this, "Shield: WhatsApp Channels blocked", Toast.LENGTH_SHORT).show()
        Prefs.increment(this, "a11y_blocks")
        return true
    }

    /** Returns a description of the matching rule, or null. Plain "Channels" text is NOT used (it appears on other screens). */
    private fun channelsUi(n: AccessibilityNodeInfo, parentSelected: Boolean, budget: IntArray, depth: Int): String? {
        if (budget[0]-- <= 0 || depth > 30) return null
        val t = n.text?.toString()?.trim()?.lowercase()
        val d = n.contentDescription?.toString()?.trim()?.lowercase()
        if (t != null && t in channelWords) return "phrase:$t"
        if (d != null && d in channelWords) return "phrase:$d"
        if ((t == "updates" || d == "updates") && (n.isSelected || parentSelected)) return "updates-tab-selected"
        val sel = n.isSelected
        for (i in 0 until n.childCount) {
            val c = n.getChild(i) ?: continue
            val r = channelsUi(c, sel, budget, depth + 1)
            if (r != null) return r
        }
        return null
    }

    private fun goToChatsTab(root: AccessibilityNodeInfo): Boolean {
        val found = root.findAccessibilityNodeInfosByText("Chats") ?: return false
        val r = Rect()
        val tabs = found.filter {
            it.text?.toString()?.trim().equals("Chats", true) ||
                it.contentDescription?.toString()?.trim()?.startsWith("Chats", true) == true
        }.sortedByDescending { it.getBoundsInScreen(r); r.top }
        for (n in tabs) {
            var c: AccessibilityNodeInfo? = n
            var hops = 0
            while (c != null && !c.isClickable && hops++ < 4) c = c.parent
            if (c != null && c.isClickable && c.performAction(AccessibilityNodeInfo.ACTION_CLICK)) return true
        }
        return false
    }

    // ---------- Keywords ----------
    private fun checkKeywords(e: AccessibilityEvent, pkg: String): Boolean {
        val kws = Prefs.strings(this, Prefs.KEYWORDS).map { it.lowercase().trim() }.filter { it.isNotEmpty() }
        if (kws.isEmpty()) return false
        val texts = ArrayList<String>()
        if (e.eventType == AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED) {
            e.text?.forEach { texts.add(it.toString()) }
        }
        val root = rootInActiveWindow
        if (root != null) {
            for (id in browserUrlBars) {
                if (!id.startsWith("$pkg:")) continue
                root.findAccessibilityNodeInfosByViewId(id)?.forEach { n ->
                    n.text?.let { texts.add(it.toString()) }
                }
            }
            val focused = root.findFocus(AccessibilityNodeInfo.FOCUS_INPUT)
            if (focused != null && !focused.isPassword) focused.text?.let { texts.add(it.toString()) }
        }
        return texts.any { t ->
            val low = t.lowercase()
            kws.any { low.contains(it) }
        }
    }

    // ---------- Images ----------
    private fun maybeScreenshot(pkg: String) {
        if (Build.VERSION.SDK_INT < 30) return
        if (!Prefs.enabled(this, Prefs.IMAGE_ON, false)) return
        if (pkg == launcherPkg) return
        val clf = classifier ?: return
        val now = SystemClock.elapsedRealtime()
        if (shotBusy || now - lastShot < 2000) return
        shotBusy = true
        lastShot = now
        takeScreenshot(Display.DEFAULT_DISPLAY, mainExecutor, object : TakeScreenshotCallback {
            override fun onSuccess(result: ScreenshotResult) {
                val hb = result.hardwareBuffer
                val bmp: Bitmap? = try {
                    Bitmap.wrapHardwareBuffer(hb, result.colorSpace)?.copy(Bitmap.Config.ARGB_8888, false)
                } finally { hb.close() }
                if (bmp == null) { shotBusy = false; return }
                worker.execute {
                    try {
                        if (clf.score(bmp) >= imageThreshold) handler.post { punish("explicit image") }
                    } catch (_: Exception) {
                    } finally {
                        bmp.recycle(); shotBusy = false
                    }
                }
            }
            override fun onFailure(errorCode: Int) { shotBusy = false }
        })
    }

    // ---------- Reaction ----------
    private fun punish(reason: String) {
        val now = SystemClock.elapsedRealtime()
        if (now - lastAction < 700) return
        lastAction = now
        performGlobalAction(GLOBAL_ACTION_HOME)
        Toast.makeText(this, "Shield: $reason", Toast.LENGTH_SHORT).show()
        Prefs.increment(this, "a11y_blocks")

        // 3 strikes in 5 minutes => lock the screen (needs Device Admin)
        strikes.add(now)
        strikes.removeAll { now - it > 5 * 60_000L }
        if (strikes.size >= 3) {
            strikes.clear()
            val dpm = getSystemService(DevicePolicyManager::class.java)
            if (dpm?.isAdminActive(ComponentName(this, ShieldAdminReceiver::class.java)) == true) {
                try { dpm.lockNow() } catch (_: Exception) {}
            }
        }
    }

    override fun onDestroy() {
        worker.shutdown()
        super.onDestroy()
    }
}
