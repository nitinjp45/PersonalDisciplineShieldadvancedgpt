package com.personaldisciplineshield

import android.app.Activity
import android.app.AlertDialog
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Intent
import android.graphics.Typeface
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.text.InputType
import android.widget.*

class AdvancedActivity : Activity() {
    private lateinit var lockStatus: TextView
    private lateinit var adminStatus: TextView
    private lateinit var a11yStatus: TextView
    private lateinit var imageStatus: TextView
    private lateinit var kwList: LinearLayout
    private lateinit var allowedList: LinearLayout
    private lateinit var blockedView: TextView
    private lateinit var content: LinearLayout
    private val admin by lazy { ComponentName(this, ShieldAdminReceiver::class.java) }
    private val dpm by lazy { getSystemService(DevicePolicyManager::class.java) }

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()
    private fun lp() = LinearLayout.LayoutParams(-1, -2).apply { topMargin = dp(5); bottomMargin = dp(5) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(22), dp(20), dp(20))
        }
        val scroll = ScrollView(this).apply {
            setBackgroundColor(0xFFF5F6FA.toInt())
            addView(content)
        }
        setContentView(scroll)
        build()
    }

    override fun onResume() { super.onResume(); if (::lockStatus.isInitialized) refresh() }

    private fun section(t: String) = content.addView(TextView(this).apply {
        text = t; textSize = 14f; setTypeface(null, Typeface.BOLD)
        setTextColor(0xFF344054.toInt()); setPadding(0, dp(18), 0, dp(5))
    })

    private fun note(t: String) = TextView(this).apply {
        text = t; textSize = 12f; setTextColor(0xFF6B7280.toInt()); setPadding(0, dp(4), 0, dp(4))
    }

    private fun button(t: String, onClick: () -> Unit) = Button(this).apply {
        text = t; setOnClickListener { onClick() }
    }

    private fun toggle(title: String, key: String, default: Boolean, onChanged: (() -> Unit)? = null) {
        content.addView(Switch(this).apply {
            text = title; textSize = 15f
            isChecked = Prefs.enabled(this@AdvancedActivity, key, default)
            setOnCheckedChangeListener { v, on ->
                if (!on && !Guard.require(this@AdvancedActivity)) { v.isChecked = true; return@setOnCheckedChangeListener }
                Prefs.setEnabled(this@AdvancedActivity, key, on)
                onChanged?.invoke()
            }
        }, lp())
    }

    private fun ask(title: String, password: Boolean, onOk: (String) -> Unit) {
        val et = EditText(this).apply {
            inputType = if (password) InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_VARIATION_PASSWORD
            else InputType.TYPE_CLASS_TEXT
        }
        AlertDialog.Builder(this).setTitle(title).setView(et)
            .setPositiveButton("OK") { _, _ -> onOk(et.text.toString().trim()) }
            .setNegativeButton("Cancel", null).show()
    }

    private fun build() {
        content.addView(TextView(this).apply {
            text = "Advanced protection"; textSize = 22f
            setTypeface(null, Typeface.BOLD); setTextColor(0xFF172033.toInt())
        })

        // ---- Lock ----
        section("IMPULSE LOCK (PIN + waiting time)")
        lockStatus = TextView(this).apply { textSize = 14f }
        content.addView(lockStatus)
        content.addView(button("Set / change PIN") {
            if (Guard.hasPin(this) && !Guard.require(this)) return@button
            ask("New PIN (6+ digits)", true) { pin ->
                if (pin.length < 6) toast("PIN must be at least 6 digits")
                else { Guard.setPin(this, pin); toast("PIN set. Protection is now locked."); refresh() }
            }
        }, lp())
        content.addView(button("Request unlock (starts ${Guard.DELAY_MS / 60000}-min wait)") {
            if (!Guard.hasPin(this)) { toast("Set a PIN first"); return@button }
            ask("Enter PIN", true) { pin ->
                if (Guard.checkPin(this, pin)) { Guard.requestUnlock(this); toast("Unlock opens after the wait"); refresh() }
                else toast("Wrong PIN")
            }
        }, lp())
        content.addView(button("Lock now") { Guard.lock(this); refresh() }, lp())
        content.addView(note("Tip: ask a trusted person to set the PIN so you do not know it."))

        // ---- Device admin ----
        section("DEVICE ADMIN (screen-lock safeguard)")
        adminStatus = TextView(this).apply { textSize = 14f }
        content.addView(adminStatus)
        content.addView(button("Enable Device Admin") {
            startActivity(Intent(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN)
                .putExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN, admin)
                .putExtra(DevicePolicyManager.EXTRA_ADD_EXPLANATION,
                    "Allows Shield to lock the screen after repeated blocking events. Standard Device Admin does not prevent uninstall."))
        }, lp())
        content.addView(button("Remove Device Admin (needs unlock)") {
            if (!Guard.require(this)) return@button
            dpm.removeActiveAdmin(admin); refresh()
        }, lp())

        // ---- Accessibility ----
        section("ACCESSIBILITY SERVICE (keywords, apps, settings guard, images)")
        a11yStatus = TextView(this).apply { textSize = 14f }
        content.addView(a11yStatus)
        content.addView(button("Open Accessibility settings") {
            startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))
        }, lp())
        content.addView(note("Android 13+ sideloaded apps: first open App info > ⋮ > Allow restricted settings."))
        toggle("Guard Settings / uninstall screens", Prefs.SETTINGS_GUARD, true)

        // ---- MIUI / Redmi helpers ----
        section("MIUI / REDMI SETUP (do this BEFORE setting the PIN)")
        content.addView(button("1. Autostart: turn ON for this app") {
            openOrDetails(Intent().setClassName("com.miui.securitycenter",
                "com.miui.permcenter.autostart.AutoStartManagementActivity"))
        }, lp())
        content.addView(button("2. Battery saver: choose No restrictions") {
            openOrDetails(Intent().setClassName("com.miui.powerkeeper",
                "com.miui.powerkeeper.ui.HiddenAppsConfigActivity")
                .putExtra("package_name", packageName)
                .putExtra("package_label", "Personal Discipline Shield"))
        }, lp())
        content.addView(button("App details page") { openOrDetails(null) }, lp())
        content.addView(note("3. Open Recents, then long-press (or pull down on) this app's card and tap the lock icon so 'Clear all' cannot kill it. MIUI otherwise stops the VPN and the accessibility service in the background."))

        // ---- Settings lockdown ----
        section("SETTINGS APP LOCKDOWN (allow only some pages)")
        toggle("Lock Settings app (only pages listed below stay open)", Prefs.SETTINGS_LOCKDOWN, false)
        content.addView(button("Open Wi-Fi settings") { openSettings(Settings.ACTION_WIFI_SETTINGS) }, lp())
        content.addView(button("Open Bluetooth settings") { openSettings(Settings.ACTION_BLUETOOTH_SETTINGS) }, lp())
        content.addView(button("Open Hotspot settings") { openHotspot() }, lp())
        content.addView(note("Wi-Fi, Bluetooth and Hotspot also work from the Quick Settings tiles (swipe down); those are never blocked. Long-press a tile to open its page. Requires a PIN to be set; it blocks the Settings home page and unknown pages while the PIN is locked. Wi-Fi, Bluetooth and Hotspot pages remain allowed."))
        val allowInput = EditText(this).apply { hint = "allowed page title, e.g. wi-fi"; setSingleLine(true) }
        content.addView(allowInput, lp())
        content.addView(button("Allow this Settings page title") {
            if (!Guard.require(this)) return@button
            val t = allowInput.text.toString().trim().lowercase()
            if (t.length < 3) { toast("At least 3 characters"); return@button }
            val s = Prefs.allowedSettings(this).toMutableSet(); s.add(t)
            Prefs.saveStrings(this, Prefs.ALLOWED_SETTINGS, s); allowInput.text.clear(); renderAllowed()
        }, lp())
        allowedList = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        content.addView(allowedList)
        content.addView(button("Reset allowed list to defaults") {
            if (!Guard.require(this)) return@button
            Prefs.remove(this, Prefs.ALLOWED_SETTINGS); renderAllowed()
        }, lp())
        blockedView = TextView(this).apply { textSize = 12f; setTextColor(0xFF6B7280.toInt()) }
        content.addView(blockedView)
        content.addView(note("If a page you need gets blocked, unlock, open it, then read 'Last blocked Settings screen' above and add its title."))
        renderAllowed()

        // ---- WhatsApp ----
        section("WHATSAPP")
        toggle("Block Channels / Updates tab in WhatsApp", Prefs.WA_CHANNELS, true)
        content.addView(note("Only blocks when Channels or Updates is the currently selected tab. It returns to Chats when that tab control is available; it never presses Back or closes WhatsApp. WhatsApp must NOT be in your blocked apps list. Works best with English tab labels."))

        // ---- Keywords ----
        section("BLOCKED KEYWORDS")
        toggle("Keyword blocking (search boxes + browser URL bars)", Prefs.KEYWORDS_ON, true)
        val kwInput = EditText(this).apply { hint = "keyword"; setSingleLine(true) }
        content.addView(kwInput, lp())
        content.addView(button("Add keyword") {
            val k = kwInput.text.toString().trim().lowercase()
            if (k.length < 3) { toast("At least 3 characters"); return@button }
            val s = Prefs.strings(this, Prefs.KEYWORDS); s.add(k)
            Prefs.saveStrings(this, Prefs.KEYWORDS, s); kwInput.text.clear(); renderKeywords()
        }, lp())
        kwList = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        content.addView(kwList)
        renderKeywords()

        // ---- Apps ----
        section("BLOCKED APPS")
        toggle("App blocking", Prefs.APPS_ON, true)
        content.addView(button("Choose apps to block") { pickApps() }, lp())

        // ---- Images ----
        section("EXPLICIT IMAGE GUARD (experimental)")
        toggle("Scan screen for explicit images", Prefs.IMAGE_ON, false) { refresh() }
        imageStatus = TextView(this).apply { textSize = 13f }
        content.addView(imageStatus)
        content.addView(note("Needs Android 11+ and a model file at assets/nsfw.tflite. Accuracy depends on the model; expect misses and false alarms."))

        refresh()
    }

    private fun openOrDetails(intent: Intent?) {
        try {
            if (intent == null) throw IllegalStateException()
            startActivity(intent)
        } catch (_: Exception) {
            try {
                startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS)
                    .setData(Uri.parse("package:$packageName")))
            } catch (_: Exception) { toast("Open Settings > Apps > Manage apps manually") }
        }
    }

    private fun renderAllowed() {
        allowedList.removeAllViews()
        Prefs.allowedSettings(this).sorted().forEach { t ->
            val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = android.view.Gravity.CENTER_VERTICAL }
            row.addView(TextView(this).apply { text = t; textSize = 14f }, LinearLayout.LayoutParams(0, -2, 1f))
            row.addView(button("Remove") {
                if (!Guard.require(this)) return@button
                val s = Prefs.allowedSettings(this).toMutableSet(); s.remove(t)
                Prefs.saveStrings(this, Prefs.ALLOWED_SETTINGS, s); renderAllowed()
            })
            allowedList.addView(row)
        }
    }

    private fun openSettings(action: String) {
        try { startActivity(Intent(action)) } catch (_: Exception) { toast("Could not open that page") }
    }

    private fun openHotspot() {
        try {
            startActivity(Intent().setClassName("com.android.settings", "com.android.settings.Settings\$TetherSettingsActivity"))
        } catch (_: Exception) {
            toast("Use the Hotspot tile in Quick Settings (swipe down)")
        }
    }

    private fun renderKeywords() {
        kwList.removeAllViews()
        Prefs.strings(this, Prefs.KEYWORDS).sorted().forEach { k ->
            val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = android.view.Gravity.CENTER_VERTICAL }
            row.addView(TextView(this).apply { text = k; textSize = 14f }, LinearLayout.LayoutParams(0, -2, 1f))
            row.addView(button("Remove") {
                if (!Guard.require(this)) return@button
                val s = Prefs.strings(this, Prefs.KEYWORDS); s.remove(k)
                Prefs.saveStrings(this, Prefs.KEYWORDS, s); renderKeywords()
            })
            kwList.addView(row)
        }
    }

    private fun isProtectedAppPackage(pkg: String): Boolean {
        val protected = setOf(
            "com.android.settings", "com.miui.securitycenter", "com.miui.powerkeeper",
            "com.android.systemui", "com.android.phone", "com.android.server.telecom",
            "com.google.android.permissioncontroller", "com.android.permissioncontroller",
            "com.google.android.packageinstaller", "com.android.packageinstaller",
            "com.miui.packageinstaller", "com.coloros.safecenter", "com.oplus.settings",
            "com.android.providers.settings"
        )
        val home = packageManager.resolveActivity(
            Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_HOME), 0
        )?.activityInfo?.packageName
        return pkg == home || pkg in protected
    }

    private fun pickApps() {
        val pm = packageManager
        val launch = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        val apps = pm.queryIntentActivities(launch, 0)
            .map { it.activityInfo.packageName to it.loadLabel(pm).toString() }
            .filter { it.first != packageName && !isProtectedAppPackage(it.first) }
            .distinctBy { it.first }
            .sortedBy { it.second.lowercase() }
        val saved = Prefs.strings(this, Prefs.BLOCKED_APPS)
        val current = saved.filterNot { isProtectedAppPackage(it) }.toMutableSet()
        if (current != saved) Prefs.saveStrings(this, Prefs.BLOCKED_APPS, current)
        val checked = BooleanArray(apps.size) { apps[it].first in current }
        AlertDialog.Builder(this).setTitle("Block these apps")
            .setMultiChoiceItems(apps.map { it.second }.toTypedArray(), checked) { _, i, b -> checked[i] = b }
            .setPositiveButton("Save") { _, _ ->
                val chosen = apps.filterIndexed { i, _ -> checked[i] }.map { it.first }.toMutableSet()
                // keep entries for apps no longer launchable
                val kept = current.filter { p -> apps.none { it.first == p } }
                chosen.addAll(kept)
                if ((current - chosen).isNotEmpty() && !Guard.require(this)) return@setPositiveButton
                Prefs.saveStrings(this, Prefs.BLOCKED_APPS, chosen)
                toast("${chosen.size} app(s) blocked")
            }
            .setNegativeButton("Cancel", null).show()
    }

    private fun a11yEnabled(): Boolean {
        val s = Settings.Secure.getString(contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES) ?: return false
        return s.contains(packageName + "/" + ShieldAccessibilityService::class.java.name)
    }

    private fun refresh() {
        lockStatus.text = when {
            !Guard.hasPin(this) -> "Lock: NOT ARMED (set a PIN to arm)"
            Guard.isUnlocked(this) -> "Lock: UNLOCKED, closes in ${Guard.openRemainingMs(this) / 60000 + 1} min"
            Guard.waitingMs(this) > 0 -> "Lock: unlock pending, opens in ${Guard.waitingMs(this) / 60000 + 1} min"
            else -> "Lock: LOCKED"
        }
        adminStatus.text = if (dpm.isAdminActive(admin)) {
            if (dpm.isDeviceOwnerApp(packageName)) "Device Admin: ACTIVE (Device Owner policies available)"
            else "Device Admin: ACTIVE (screen-lock safeguard; uninstall is NOT blocked)"
        } else "Device Admin: OFF"
        a11yStatus.text = if (a11yEnabled()) "Accessibility: ON" else "Accessibility: OFF (required for most features)"
        val hasModel = try { assets.list("")?.contains("nsfw.tflite") == true } catch (_: Exception) { false }
        imageStatus.text = "Model: ${if (hasModel) "found" else "missing"}  |  Android 11+: ${Build.VERSION.SDK_INT >= 30}"
        blockedView.text = "Last blocked Settings screen: ${Prefs.getString(this, "last_settings_block") ?: "none yet"}"
    }

    private fun toast(m: String) = Toast.makeText(this, m, Toast.LENGTH_SHORT).show()
}
