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
        "com.miui.securitycenter", "com.miui.powerkeeper", "com.xiaomi.misettings"
    )
    // Rows of the Settings home / category lists (stock Android + MIUI). If any is on screen it is a list, not an allowed page.
    private val homepageMarkers = setOf(
        "mobile networks", "sim cards & mobile networks", "connection & sharing",
        "network & internet", "connected devices", "passwords & security",
        "additional settings", "about phone", "lock screen & password", "special features"
    )
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
    private val allowedClassTokens = listOf("wifi", "bluetooth", "tether", "hotspot", "networkprovider", "settingspanel", "pairing")
    // Texts shown by pairing / connect dialogs (matched as a part of the text).
    private val allowedPhrases = listOf("bluetooth pairing", "pairing request", "pairing code", "pair with", "pair and connect")
    private var lastStateChange = 0L
    private var lastLockdownScan = 0L
    private var lastSettingsClass = ""
    private var settingsRecheckPending = false

    // WhatsApp
    private val whatsappPkgs = setOf("com.whatsapp", "com.whatsapp.w4b")
    private val channelWords = setOf("find channels", "explore channels")
    private var lastWaAction = 0L
    private var waRetryPending = false
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
            if (
                type == AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED ||
                type == AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED ||
                type == AccessibilityEvent.TYPE_WINDOWS_CHANGED
            ) {
                if (settingsLockdown(e)) { punish("settings locked"); return }
            }
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
    // Settings lockdown is deliberately independent of the main Protection unlock window.
    private fun lockdownActive() =
        Prefs.enabled(this, Prefs.SETTINGS_LOCKDOWN, false)

    /** Evaluate the current Settings page on every relevant accessibility event. */
    private fun settingsLockdown(e: AccessibilityEvent): Boolean {
        val now = SystemClock.elapsedRealtime()
        val isState = e.eventType == AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED
        val cls = e.className?.toString()?.lowercase().orEmpty()

        if (isState) {
            lastStateChange = now
            lastSettingsClass = cls
        }

        if (!isState && now - lastLockdownScan < 140L) return false
        lastLockdownScan = now

        val root = rootInActiveWindow
        if (root == null) {
            scheduleSettingsRecheck()
            return false
        }

        val rootPkg = root.packageName?.toString()
        if (rootPkg != null && rootPkg !in lockdownPackages) return false

        val header = headerTexts(root)
        if (isAllowedSettingsPage(cls, header)) return false

        // Wait briefly for MIUI/Android to finish rendering a newly opened page.
        if (now - lastStateChange < 350L) {
            scheduleSettingsRecheck()
            return false
        }

        recordBlock(header)
        return true
    }

    private fun scheduleSettingsRecheck() {
        if (settingsRecheckPending) return
        settingsRecheckPending = true
        handler.postDelayed({
            settingsRecheckPending = false
            recheckSettings()
        }, 380L)
    }

    private fun recheckSettings() {
        if (!lockdownActive()) return
        val root = rootInActiveWindow ?: return
        val pkg = root.packageName?.toString() ?: return
        if (pkg !in lockdownPackages) return

        val header = headerTexts(root)
        if (isAllowedSettingsPage(lastSettingsClass, header)) return

        recordBlock(header)
        punish("settings locked")
    }

    private fun isAllowedSettingsPage(cls: String, header: List<String>): Boolean {
        val classAllowed = allowedClassTokens.any { cls.contains(it) }
        if (classAllowed) return true

        // A Settings home/category list is never an allowed page, even if it contains
        // Wi-Fi/Bluetooth rows lower in the hierarchy.
        val homeMarkerCount = header.count { h ->
            homepageMarkers.any { marker -> h.contains(marker) }
        }
        if (homeMarkerCount >= 2) return false

        val allowed = Prefs.allowedSettings(this)
        val pairing = header.any { h ->
            allowedPhrases.any { phrase -> h.contains(phrase) } ||
                h.contains("pair new device") ||
                h.contains("available devices")
        }
        if (pairing) return true

        return header.any { h ->
            allowed.any { token -> h == token || h.contains(token) }
        }
    }

    private fun recordBlock(header: List<String>) {
        Prefs.putString(
            this,
            "last_settings_block",
            "$lastSettingsClass | ${header.joinToString(", ")}"
        )
    }

    /** Lower-cased short texts in the top part of the screen (page title area). */
    private fun headerTexts(root: AccessibilityNodeInfo): List<String> {
        val limit = resources.displayMetrics.heightPixels * 0.38
        val out = ArrayList<String>()
        fun walk(n: AccessibilityNodeInfo, depth: Int, budget: IntArray) {
            if (budget[0]-- <= 0 || depth > 30) return
            val t = n.text?.toString()?.trim()?.lowercase()
            val d = n.contentDescription?.toString()?.trim()?.lowercase()
            val r = Rect()
            n.getBoundsInScreen(r)
            if (r.top < limit && r.bottom > 0) {
                if (!t.isNullOrEmpty() && t.length <= 60) out.add(t)
                if (!d.isNullOrEmpty() && d.length <= 60) out.add(d)
            }
            for (i in 0 until n.childCount) n.getChild(i)?.let { walk(it, depth + 1, budget) }
        }
        walk(root, 0, intArrayOf(400))
        return out
    }

    // ---------- WhatsApp: block the complete Updates tab (Status + Channels) ----------
    private fun checkWhatsApp(e: AccessibilityEvent): Boolean {
        val cls = e.className?.toString()?.lowercase().orEmpty()
        val root = rootInActiveWindow
        val rootPkg = root?.packageName?.toString()
        if (rootPkg != null && rootPkg !in whatsappPkgs) return false

        val rule = if (cls.contains("newsletter")) {
            "whatsapp-newsletter:$cls"
        } else {
            if (root == null) return false
            channelsUi(root, false, intArrayOf(700), 0)
        } ?: return false

        val now = SystemClock.elapsedRealtime()
        if (now - lastWaAction >= 650L) {
            lastWaAction = now
            Prefs.putString(this, "last_wa_block", "$rule | $cls")
            val clicked = root != null && goToChatsTab(root)
            if (!clicked && rule.startsWith("whatsapp-newsletter:")) {
                performGlobalAction(GLOBAL_ACTION_BACK)
            }
            Prefs.increment(this, "a11y_blocks")
        }

        // Recheck after WhatsApp finishes its tab animation. No timed pause/loop breaker.
        scheduleWhatsAppRetry()
        return true
    }

    private fun scheduleWhatsAppRetry() {
        if (waRetryPending) return
        waRetryPending = true
        handler.postDelayed({
            waRetryPending = false
            if (!Prefs.enabled(this, Prefs.WA_CHANNELS, true)) return@postDelayed

            val root = rootInActiveWindow ?: return@postDelayed
            val pkg = root.packageName?.toString()
            if (pkg == null || pkg !in whatsappPkgs) return@postDelayed

            val rule = channelsUi(root, false, intArrayOf(700), 0) ?: return@postDelayed
            val now = SystemClock.elapsedRealtime()
            if (now - lastWaAction >= 650L) {
                lastWaAction = now
                Prefs.putString(this, "last_wa_block", "retry:$rule")
                goToChatsTab(root)
            }
        }, 350L)
    }

    /**
     * WhatsApp's Updates tab contains Status and Channels. Detect the selected
     * Updates tab, including descriptions such as "Updates, selected" and
     * selection exposed on a parent node. Do not block a normal Status mention.
     */
    private fun channelsUi(
        n: AccessibilityNodeInfo,
        parentSelected: Boolean,
        budget: IntArray,
        depth: Int
    ): String? {
        if (budget[0]-- <= 0 || depth > 30) return null

        val t = n.text?.toString()?.trim()?.lowercase().orEmpty()
        val d = n.contentDescription?.toString()?.trim()?.lowercase().orEmpty()

        if (t in channelWords) return "phrase:$t"
        if (d in channelWords) return "phrase:$d"

        val updatesLabel = t == "updates" || d == "updates" ||
            t.startsWith("updates,") || d.startsWith("updates,") ||
            t.startsWith("updates ") || d.startsWith("updates ")

        val selected = n.isSelected || n.isChecked || parentSelected ||
            d.contains("selected") || t.contains("selected")

        if (updatesLabel && selected) return "updates-tab-selected"

        val childSelected = n.isSelected || n.isChecked
        for (i in 0 until n.childCount) {
            val child = n.getChild(i) ?: continue
            val result = channelsUi(child, childSelected, budget, depth + 1)
            if (result != null) return result
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
