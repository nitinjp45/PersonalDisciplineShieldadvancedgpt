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
    // Activity class-name fragments that identify explicitly permitted connectivity pages.
    private val allowedClassTokens = listOf("wifi", "bluetooth", "tether", "hotspot", "networkprovider", "settingspanel")
    private var lastStateChange = 0L
    private var lastLockdownScan = 0L
    private var lastSettingsClass = ""

    // WhatsApp
    private val whatsappPkgs = setOf("com.whatsapp", "com.whatsapp.w4b")
    private val channelWords = setOf("channels", "find channels", "explore channels")
    private var lastWa = 0L
    private var lastWaAction = 0L

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

    // Safety exclusion: these packages must never be blocked by the user app-block list.
    // This prevents accidental loss of access to Settings, system UI, permissions, installers or calling.
    private val protectedPackages = setOf(
        "com.android.settings", "com.miui.securitycenter", "com.miui.powerkeeper",
        "com.android.systemui", "com.android.phone", "com.android.server.telecom",
        "com.google.android.permissioncontroller", "com.android.permissioncontroller",
        "com.google.android.packageinstaller", "com.android.packageinstaller",
        "com.miui.packageinstaller", "com.coloros.safecenter", "com.oplus.settings",
        "com.android.providers.settings"
    )

    private fun isProtectedPackage(pkg: String): Boolean =
        pkg == packageName || pkg == launcherPkg || pkg in protectedPackages

    override fun onServiceConnected() {
        classifier = NsfwClassifier(this).takeIf { it.available }
    }

    override fun onAccessibilityEvent(e: AccessibilityEvent?) {
        e ?: return
        val pkg = e.packageName?.toString() ?: return
        if (pkg == packageName || pkg == "com.android.systemui") return
        val type = e.eventType

        // 1) Blocked apps
        if (type == AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED &&
            Prefs.enabled(this, Prefs.APPS_ON, true) &&
            !isProtectedPackage(pkg) &&
            pkg in Prefs.strings(this, Prefs.BLOCKED_APPS)
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

    // ---------- Settings lockdown (allow-list) ----------
    private fun lockdownActive() =
        guardActive() && Prefs.enabled(this, Prefs.SETTINGS_LOCKDOWN, false)

    /** Returns true when the current Settings screen must be blocked.
     * Re-evaluate the visible page on every event. Do not keep an "allowed" flag:
     * MIUI often reuses one Activity while navigating from Wi-Fi back to Settings home.
     */
    private fun settingsLockdown(e: AccessibilityEvent): Boolean {
        val now = SystemClock.elapsedRealtime()
        val isState = e.eventType == AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED
        val cls = e.className?.toString()?.lowercase() ?: ""
        if (isState) {
            lastStateChange = now
            lastSettingsClass = cls
        }
        if (!isState && now - lastLockdownScan < 180) return false
        lastLockdownScan = now

        val root = rootInActiveWindow ?: return false
        val header = headerTexts(root)
        val currentClass = if (cls.isNotBlank()) cls else lastSettingsClass

        // Allow only a positively identified connectivity subpage. The Settings
        // landing page is blocked even when its list contains Wi-Fi/Bluetooth rows.
        if (isSettingsHome(currentClass, header)) {
            recordBlock(header)
            return true
        }
        if (isAllowedSettingsPage(currentClass, header)) return false

        // Accessibility tree may be empty while MIUI is transitioning between pages.
        if (now - lastStateChange < 900) {
            handler.removeCallbacks(settingsRecheck)
            handler.postDelayed(settingsRecheck, 950)
            return false
        }
        recordBlock(header)
        return true
    }

    private val settingsRecheck = Runnable {
        if (!lockdownActive()) return@Runnable
        val root = rootInActiveWindow ?: return@Runnable
        val pkg = root.packageName?.toString() ?: return@Runnable
        if (pkg !in lockdownPackages) return@Runnable
        val header = headerTexts(root)
        val cls = lastSettingsClass
        if (isSettingsHome(cls, header) || !isAllowedSettingsPage(cls, header)) {
            recordBlock(header)
            punish("settings locked")
        }
    }

    private fun isSettingsHome(cls: String, header: List<String>): Boolean {
        if (cls.contains("miuisettings") || cls.contains("settingshomepage") || cls.contains("homepage")) return true
        // Common Settings landing-page headings. Keep this exact to avoid blocking
        // a subpage merely because its parent tree contains the word Settings.
        val homeTitles = setOf("settings", "search settings", "settings home", "all settings")
        return header.take(3).any { it in homeTitles } || header.any { it in homepageMarkers }
    }

    private fun isAllowedSettingsPage(cls: String, header: List<String>): Boolean {
        if (allowedClassTokens.any { cls.contains(it) }) return true
        val allowed = Prefs.allowedSettings(this).map { it.trim().lowercase() }.filter { it.isNotEmpty() }
        return header.any { h -> allowed.any { a -> h == a || h.startsWith("$a ") } }
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

    // ---------- WhatsApp: block only when Channels/Updates is the SELECTED tab ----------
    private fun checkWhatsApp(e: AccessibilityEvent): Boolean {
        val now = SystemClock.elapsedRealtime()
        if (e.eventType != AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED && now - lastWa < 220) return false
        lastWa = now
        val root = rootInActiveWindow ?: return false

        // A tab label can remain visible on the main WhatsApp page even when it is
        // not open. Never block merely because the word "Channels" exists.
        val selectedBlockedTab = selectedTabName(root, false, intArrayOf(500), 0)
        if (!selectedBlockedTab) return false

        // Return to Chats only if its tab is actually present and clickable.
        // Never use GLOBAL_ACTION_BACK as a fallback: that can exit WhatsApp.
        if (now - lastWaAction < 800) return true
        val movedToChats = goToChatsTab(root)
        if (movedToChats) {
            lastWaAction = now
            Toast.makeText(this, "Shield: WhatsApp Channels / Updates blocked", Toast.LENGTH_SHORT).show()
            Prefs.increment(this, "a11y_blocks")
            return true
        }
        // If WhatsApp exposes no accessible Chats control, fail open rather than
        // closing the app or navigating to an unrelated screen.
        return false
    }

    private fun selectedTabName(n: AccessibilityNodeInfo, parentSelected: Boolean, budget: IntArray, depth: Int): Boolean {
        if (budget[0]-- <= 0 || depth > 30) return false
        val t = n.text?.toString()?.trim()?.lowercase()
        val d = n.contentDescription?.toString()?.trim()?.lowercase()
        val label = t ?: d
        val selected = n.isSelected || parentSelected
        if (selected && (label == "channels" || label == "updates" || label == "newsletter")) return true
        val thisSelected = n.isSelected
        for (i in 0 until n.childCount) {
            val c = n.getChild(i) ?: continue
            if (selectedTabName(c, thisSelected, budget, depth + 1)) return true
        }
        return false
    }

    private fun goToChatsTab(root: AccessibilityNodeInfo): Boolean {
        val found = root.findAccessibilityNodeInfosByText("Chats") ?: return false
        for (n in found) {
            val label = n.text?.toString()?.trim()
            val desc = n.contentDescription?.toString()?.trim()
            if (!label.equals("Chats", true) && !desc.equals("Chats", true)) continue
            var c: AccessibilityNodeInfo? = n
            var hops = 0
            while (c != null && !c.isClickable && hops++ < 5) c = c.parent
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
