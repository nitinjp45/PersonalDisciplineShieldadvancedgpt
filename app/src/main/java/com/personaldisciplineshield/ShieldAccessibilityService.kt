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
 * 1) Blocks chosen apps
 * 2) Blocks chosen keywords typed/searched
 * 3) Guards Settings/uninstall screens
 * 4) Optional screenshot check with an on-device image classifier
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

    // Settings lockdown
    private val lockdownPackages = setOf(
        "com.android.settings",
        "com.oplus.settings",
        "com.coloros.settings",
        "com.miui.securitycenter",
        "com.miui.powerkeeper"
    )

    private val homepageMarkers = setOf(
        "mobile networks",
        "sim cards & mobile networks",
        "connection & sharing",
        "network & internet",
        "connected devices",
        "passwords & security",
        "additional settings",
        "about phone",
        "lock screen & password",
        "special features"
    )

    private val protectedPackages = setOf(
        "com.android.settings",
        "com.miui.securitycenter",
        "com.miui.powerkeeper",
        "com.android.systemui",
        "com.android.phone",
        "com.android.server.telecom",
        "com.google.android.permissioncontroller",
        "com.android.permissioncontroller",
        "com.google.android.packageinstaller",
        "com.android.packageinstaller",
        "com.miui.packageinstaller",
        "com.coloros.safecenter",
        "com.oplus.settings",
        "com.android.providers.settings"
    )

    private fun isProtectedPackage(pkg: String) =
        pkg == packageName || pkg == launcherPkg || pkg in protectedPackages

    private val allowedClassTokens = listOf(
        "wifi",
        "bluetooth",
        "tether",
        "hotspot",
        "networkprovider",
        "settingspanel"
    )

    private var lastStateChange = 0L
    private var lastLockdownScan = 0L
    private var lastSettingsClass = ""
    private var settingsRecheckPending = false
    private var settingsRecheckAttempts = 0

    // WhatsApp
    private val whatsappPkgs = setOf(
        "com.whatsapp",
        "com.whatsapp.w4b"
    )

    private val channelWords = setOf(
        "find channels",
        "explore channels"
    )

    private var lastWaAction = 0L
    private var waRetryPending = false

    private var lastBeat = 0L
    private var lastDump = 0L

    private val settingsPackages = setOf(
        "com.android.settings",
        "com.google.android.packageinstaller",
        "com.android.packageinstaller",
        "com.samsung.android.packageinstaller",
        "com.google.android.permissioncontroller",
        "com.android.permissioncontroller",
        "com.miui.securitycenter",
        "com.miui.packageinstaller",
        "com.coloros.safecenter",
        "com.oplus.settings",
        "com.android.vending"
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
            Intent(Intent.ACTION_MAIN)
                .addCategory(Intent.CATEGORY_HOME),
            0
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

        if (
            Prefs.enabled(this, Prefs.DEBUG, false) &&
            (pkg in whatsappPkgs || pkg in lockdownPackages)
        ) {
            dumpScreen(e, pkg)
        }

        // 1. Block selected applications
        if (
            type == AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED &&
            Prefs.enabled(this, Prefs.APPS_ON, true) &&
            !isProtectedPackage(pkg) &&
            pkg in Prefs.strings(this, Prefs.BLOCKED_APPS)
        ) {
            punish("app blocked")
            return
        }

        // 2. Settings / uninstall guard
        if (pkg in settingsPackages && guardActive()) {
            if (scanSettings()) {
                punish("protected screen")
                return
            }
        }

        // 3. Settings lockdown
        if (pkg in lockdownPackages && lockdownActive()) {
            if (settingsLockdown(e)) {
                punish("settings locked")
                return
            }
        }

        // 4. WhatsApp Channels / Updates blocking
        if (
            pkg in whatsappPkgs &&
            Prefs.enabled(this, Prefs.WA_CHANNELS, true)
        ) {
            if (checkWhatsApp(e)) return
        }

        // 5. Keyword blocking
        if (
            Prefs.enabled(this, Prefs.KEYWORDS_ON, true) &&
            !e.isPassword
        ) {
            if (checkKeywords(e, pkg)) {
                punish("blocked keyword")
                return
            }
        }

        // 6. Optional image checking
        if (
            type == AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED ||
            type == AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED
        ) {
            maybeScreenshot(pkg)
        }
    }

    override fun onInterrupt() {}

    // --------------------------------------------------
    // SETTINGS GUARD
    // --------------------------------------------------

    private fun guardActive() =
        Prefs.enabled(this, Prefs.SETTINGS_GUARD, true) &&
            Guard.hasPin(this) &&
            !Guard.isUnlocked(this)

    private fun scanSettings(): Boolean {
        val now = SystemClock.elapsedRealtime()

        if (now - lastScan < 250) return false

        lastScan = now

        val root = rootInActiveWindow ?: return false

        val sb = StringBuilder()

        collectText(root, sb, intArrayOf(500), 0)

        val text = sb.toString().lowercase()

        val label = applicationInfo
            .loadLabel(packageManager)
            .toString()
            .lowercase()

        return text.contains(label) || text.contains("private dns")
    }

    private fun collectText(
        n: AccessibilityNodeInfo,
        sb: StringBuilder,
        budget: IntArray,
        depth: Int
    ) {
        if (budget[0]-- <= 0 || depth > 30) return

        n.text?.let {
            sb.append(it).append('\n')
        }

        n.contentDescription?.let {
            sb.append(it).append('\n')
        }

        for (i in 0 until n.childCount) {
            val ch = n.getChild(i) ?: continue
            collectText(ch, sb, budget, depth + 1)
        }
    }

    // --------------------------------------------------
    // DIAGNOSTICS
    // --------------------------------------------------

    private fun heartbeat(e: AccessibilityEvent, pkg: String) {
        val now = SystemClock.elapsedRealtime()

        if (now - lastBeat < 1000) return

        lastBeat = now

        val time = java.text.SimpleDateFormat(
            "HH:mm:ss",
            java.util.Locale.US
        ).format(java.util.Date())

        Prefs.putString(
            this,
            "dbg_last_event",
            "$time  $pkg  ${e.className}"
        )
    }

    private fun dumpScreen(
        e: AccessibilityEvent,
        pkg: String
    ) {
        val now = SystemClock.elapsedRealtime()

        if (now - lastDump < 1500) return

        lastDump = now

        val root = rootInActiveWindow ?: return

        val h = resources.displayMetrics.heightPixels.coerceAtLeast(1)

        val parts = ArrayList<String>()

        fun walk(
            n: AccessibilityNodeInfo,
            depth: Int,
            budget: IntArray
        ) {
            if (
                budget[0]-- <= 0 ||
                depth > 30 ||
                parts.size > 60
            ) return

            val t = n.text?.toString()?.trim().orEmpty()

            val d = n.contentDescription
                ?.toString()
                ?.trim()
                .orEmpty()

            val label = (
                t + if (d.isNotEmpty()) " [$d]" else ""
            ).trim()

            if (label.isNotEmpty()) {
                val r = Rect()

                n.getBoundsInScreen(r)

                parts.add(
                    "${r.top * 100 / h}%: " +
                        "${label.take(40)}" +
                        if (n.isSelected) " (selected)" else ""
                )
            }

            for (i in 0 until n.childCount) {
                n.getChild(i)?.let {
                    walk(it, depth + 1, budget)
                }
            }
        }

        walk(root, 0, intArrayOf(300))

        val key = if (pkg in whatsappPkgs) {
            "dbg_screen_wa"
        } else {
            "dbg_screen_settings"
        }

        Prefs.putString(
            this,
            key,
            "$pkg | ${e.className}\n" +
                parts.joinToString("\n").take(1500)
        )
    }

    // --------------------------------------------------
    // SETTINGS LOCKDOWN
    // --------------------------------------------------

    private fun lockdownActive() =
        Prefs.enabled(this, Prefs.SETTINGS_LOCKDOWN, false) &&
            (!Guard.hasPin(this) || !Guard.isUnlocked(this))

    private fun settingsLockdown(
        e: AccessibilityEvent
    ): Boolean {

        val now = SystemClock.elapsedRealtime()

        val isState =
            e.eventType == AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED

        val cls = e.className
            ?.toString()
            ?.lowercase()
            .orEmpty()

        if (isState) {
            lastStateChange = now
            lastSettingsClass = cls
            settingsRecheckAttempts = 0
        }

        if (!isState && now - lastLockdownScan < 120) {
            return false
        }

        lastLockdownScan = now

        val root = rootInActiveWindow

        if (root == null) {
            scheduleSettingsRecheck()
            return false
        }

        val rootPkg = root.packageName?.toString()

        if (rootPkg != null && rootPkg !in lockdownPackages) {
            return false
        }

        val classAllowed = allowedClassTokens.any {
            cls.contains(it)
        }

        val header = headerTexts(root)

        if (classAllowed || headerAllowed(header)) {
            return false
        }

        if (now - lastStateChange < 1000L) {
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
        }, 400L)
    }

    private fun recheckSettings() {
        if (!lockdownActive()) return

        val root = rootInActiveWindow

        if (root == null) {
            if (settingsRecheckAttempts++ < 3) {
                scheduleSettingsRecheck()
            }
            return
        }

        val p = root.packageName?.toString() ?: return

        if (p !in lockdownPackages) return

        val clsAllowed = allowedClassTokens.any {
            lastSettingsClass.contains(it)
        }

        val header = headerTexts(root)

        if (clsAllowed || headerAllowed(header)) return

        if (
            SystemClock.elapsedRealtime() - lastStateChange < 1000L &&
            settingsRecheckAttempts++ < 3
        ) {
            scheduleSettingsRecheck()
            return
        }

        recordBlock(header)

        punish("settings locked")
    }

    private fun headerAllowed(header: List<String>): Boolean {

        if (
            header.any { marker ->
                homepageMarkers.any { marker.contains(it) }
            }
        ) {
            return false
        }

        val allowed = Prefs.allowedSettings(this)

        val pairingFlow = header.any { h ->
            h.contains("pair new device") ||
                h.contains("pairing") ||
                h.contains("available devices") ||
                h.contains("bluetooth")
        }

        if (pairingFlow) return true

        return header.any { h ->
            allowed.any { token ->
                h == token || h.contains(token)
            }
        }
    }

    private fun recordBlock(header: List<String>) {
        Prefs.putString(
            this,
            "last_settings_block",
            "$lastSettingsClass | ${header.joinToString(", ")}"
        )
    }

    private fun headerTexts(
        root: AccessibilityNodeInfo
    ): List<String> {

        val limit = resources.displayMetrics.heightPixels * 0.38

        val out = ArrayList<String>()

        fun walk(
            n: AccessibilityNodeInfo,
            depth: Int,
            budget: IntArray
        ) {
            if (budget[0]-- <= 0 || depth > 30) return

            val t = n.text
                ?.toString()
                ?.trim()
                ?.lowercase()

            val d = n.contentDescription
                ?.toString()
                ?.trim()
                ?.lowercase()

            val r = Rect()

            n.getBoundsInScreen(r)

            if (r.top < limit && r.bottom > 0) {
                if (!t.isNullOrEmpty() && t.length <= 60) {
                    out.add(t)
                }

                if (!d.isNullOrEmpty() && d.length <= 60) {
                    out.add(d)
                }
            }

            for (i in 0 until n.childCount) {
                n.getChild(i)?.let {
                    walk(it, depth + 1, budget)
                }
            }
        }

        walk(root, 0, intArrayOf(400))

        return out
    }

    // --------------------------------------------------
    // WHATSAPP CHANNELS / UPDATES BLOCKING
    // --------------------------------------------------

    private fun checkWhatsApp(
        e: AccessibilityEvent
    ): Boolean {

        val cls = e.className
            ?.toString()
            ?.lowercase()
            .orEmpty()

        val root = rootInActiveWindow

        val rootPkg = root?.packageName?.toString()

        if (rootPkg != null && rootPkg !in whatsappPkgs) {
            return false
        }

        val rule = if (cls.contains("newsletter")) {
            "class:$cls"
        } else {
            if (root == null) return false

            channelsUi(
                root,
                false,
                intArrayOf(700),
                0
            )
        } ?: return false

        val now = SystemClock.elapsedRealtime()

        if (now - lastWaAction >= 700L) {

            lastWaAction = now

            Prefs.putString(
                this,
                "last_wa_block",
                "$rule | $cls"
            )

            val clicked =
                root != null && goToChatsTab(root)

            if (!clicked && rule.startsWith("class:")) {
                performGlobalAction(GLOBAL_ACTION_BACK)
            }

            Prefs.increment(this, "a11y_blocks")

            Toast.makeText(
                this,
                "Shield: WhatsApp Channels blocked",
                Toast.LENGTH_SHORT
            ).show()
        }

        scheduleWhatsAppRetry()

        return true
    }

    private fun scheduleWhatsAppRetry() {

        if (waRetryPending) return

        waRetryPending = true

        handler.postDelayed({

            waRetryPending = false

            if (!Prefs.enabled(this, Prefs.WA_CHANNELS, true)) {
                return@postDelayed
            }

            val root = rootInActiveWindow ?: return@postDelayed

            val pkg = root.packageName?.toString()

            if (pkg == null || pkg !in whatsappPkgs) {
                return@postDelayed
            }

            val rule = channelsUi(
                root,
                false,
                intArrayOf(700),
                0
            ) ?: return@postDelayed

            val now = SystemClock.elapsedRealtime()

            if (now - lastWaAction >= 700L) {

                lastWaAction = now

                Prefs.putString(
                    this,
                    "last_wa_block",
                    "retry:$rule"
                )

                if (!goToChatsTab(root)) {
                    if (rule.startsWith("class:")) {
                        performGlobalAction(GLOBAL_ACTION_BACK)
                    }
                }
            }

        }, 350L)
    }

    private fun channelsUi(
        n: AccessibilityNodeInfo,
        parentSelected: Boolean,
        budget: IntArray,
        depth: Int
    ): String? {

        if (budget[0]-- <= 0 || depth > 30) {
            return null
        }

        val t = n.text
            ?.toString()
            ?.trim()
            ?.lowercase()

        val d = n.contentDescription
            ?.toString()
            ?.trim()
            ?.lowercase()

        if (t != null && t in channelWords) {
            return "phrase:$t"
        }

        if (d != null && d in channelWords) {
            return "phrase:$d"
        }

        if (
            (t == "updates" || d == "updates") &&
            (n.isSelected || parentSelected)
        ) {
            return "updates-tab-selected"
        }

        val sel = n.isSelected

        for (i in 0 until n.childCount) {
            val c = n.getChild(i) ?: continue

            val r = channelsUi(
                c,
                sel,
                budget,
                depth + 1
            )

            if (r != null) return r
        }

        return null
    }

    private fun goToChatsTab(
        root: AccessibilityNodeInfo
    ): Boolean {

        val found =
            root.findAccessibilityNodeInfosByText("Chats") ?: return false

        for (n in found) {

            val label = n.text
                ?.toString()
                ?.trim()
                ?: n.contentDescription
                    ?.toString()
                    ?.trim()
                    .orEmpty()

            if (!label.equals("Chats", true)) continue

            var c: AccessibilityNodeInfo? = n
            var hops = 0

            while (
                c != null &&
                !c.isClickable &&
                hops++ < 5
            ) {
                c = c.parent
            }

            if (
                c != null &&
                c.isClickable &&
                c.performAction(AccessibilityNodeInfo.ACTION_CLICK)
            ) {
                return true
            }
        }

        return false
    }

    // --------------------------------------------------
    // KEYWORDS
    // --------------------------------------------------

    private fun checkKeywords(
        e: AccessibilityEvent,
        pkg: String
    ): Boolean {

        val kws = Prefs.strings(this, Prefs.KEYWORDS)
            .map { it.lowercase().trim() }
            .filter { it.isNotEmpty() }

        if (kws.isEmpty()) return false

        val texts = ArrayList<String>()

        if (e.eventType == AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED) {
            e.text?.forEach {
                texts.add(it.toString())
            }
        }

        val root = rootInActiveWindow

        if (root != null) {

            for (id in browserUrlBars) {

                if (!id.startsWith("$pkg:")) continue

                root.findAccessibilityNodeInfosByViewId(id)?.forEach { n ->
                    n.text?.let {
                        texts.add(it.toString())
                    }
                }
            }

            val focused = root.findFocus(
                AccessibilityNodeInfo.FOCUS_INPUT
            )

            if (focused != null && !focused.isPassword) {
                focused.text?.let {
                    texts.add(it.toString())
                }
            }
        }

        return texts.any { t ->

            val low = t.lowercase()

            kws.any { low.contains(it) }
        }
    }

    // --------------------------------------------------
    // IMAGES
    // --------------------------------------------------

    private fun maybeScreenshot(pkg: String) {

        if (Build.VERSION.SDK_INT < 30) return

        if (!Prefs.enabled(this, Prefs.IMAGE_ON, false)) return

        if (pkg == launcherPkg) return

        val clf = classifier ?: return

        val now = SystemClock.elapsedRealtime()

        if (shotBusy || now - lastShot < 2000) return

        shotBusy = true
        lastShot = now

        takeScreenshot(
            Display.DEFAULT_DISPLAY,
            mainExecutor,
            object : TakeScreenshotCallback {

                override fun onSuccess(result: ScreenshotResult) {

                    val hb = result.hardwareBuffer

                    val bmp: Bitmap? = try {
                        Bitmap.wrapHardwareBuffer(
                            hb,
                            result.colorSpace
                        )?.copy(
                            Bitmap.Config.ARGB_8888,
                            false
                        )
                    } finally {
                        hb.close()
                    }

                    if (bmp == null) {
                        shotBusy = false
                        return
                    }

                    worker.execute {

                        try {
                            if (clf.score(bmp) >= imageThreshold) {
                                handler.post {
                                    punish("explicit image")
                                }
                            }
                        } catch (_: Exception) {
                        } finally {
                            bmp.recycle()
                            shotBusy = false
                        }
                    }
                }

                override fun onFailure(errorCode: Int) {
                    shotBusy = false
                }
            }
        )
    }

    // --------------------------------------------------
    // BLOCKING ACTION
    // --------------------------------------------------

    private fun punish(reason: String) {

        val now = SystemClock.elapsedRealtime()

        if (now - lastAction < 700) return

        lastAction = now

        performGlobalAction(GLOBAL_ACTION_HOME)

        Toast.makeText(
            this,
            "Shield: $reason",
            Toast.LENGTH_SHORT
        ).show()

        Prefs.increment(this, "a11y_blocks")

        // 3 strikes in 5 minutes => lock screen (requires Device Admin)
        strikes.add(now)

        strikes.removeAll {
            now - it > 5 * 60_000L
        }

        if (strikes.size >= 3) {

            strikes.clear()

            val dpm = getSystemService(
                DevicePolicyManager::class.java
            )

            if (
                dpm?.isAdminActive(
                    ComponentName(
                        this,
                        ShieldAdminReceiver::class.java
                    )
                ) == true
            ) {
                try {
                    dpm.lockNow()
                } catch (_: Exception) {
                }
            }
        }
    }

    override fun onDestroy() {
        worker.shutdown()
        super.onDestroy()
    }
}
