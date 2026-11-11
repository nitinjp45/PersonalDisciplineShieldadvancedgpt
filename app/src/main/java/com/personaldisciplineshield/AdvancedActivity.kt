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
import android.view.View
import android.widget.*

class AdvancedActivity : Activity() {
    private lateinit var lockStatus: TextView
    private lateinit var adminStatus: TextView
    private lateinit var a11yStatus: TextView
    private lateinit var imageStatus: TextView
    private lateinit var kwList: LinearLayout
    private lateinit var allowedList: LinearLayout
    private lateinit var blockedView: TextView
    private lateinit var diagView: TextView
    private lateinit var blockedAppsView: TextView
    private lateinit var lockdownStatusView: TextView
    private lateinit var waStatusView: TextView
    private lateinit var dnsProviderStatus: TextView
    // Settings-type apps are handled by the Settings lockdown, never by the app blocker.
    private val hiddenApps: Set<String> by lazy {
        val home = packageManager.resolveActivity(
            Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_HOME), 0
        )?.activityInfo?.packageName
        setOf(
            "com.android.settings", "com.miui.securitycenter", "com.miui.powerkeeper",
            "com.android.systemui", "com.android.phone", "com.android.server.telecom",
            "com.google.android.permissioncontroller", "com.android.permissioncontroller",
            "com.google.android.packageinstaller", "com.android.packageinstaller",
            "com.miui.packageinstaller", "com.coloros.safecenter", "com.oplus.settings",
            "com.coloros.settings", "com.android.providers.settings"
        ) + listOfNotNull(home)
    }
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
            if (password) {
                // Mask PIN digits and prevent keyboard suggestions/autofill.
                isSingleLine = true
                importantForAutofill = android.view.View.IMPORTANT_FOR_AUTOFILL_NO
            }
        }
        AlertDialog.Builder(this).setTitle(title).setView(et)
            .setPositiveButton("OK") { _, _ -> onOk(et.text.toString().trim()) }
            .setNegativeButton("Cancel", null).show()
    }

    private fun build() {
        content.addView(TextView(this).apply {
            val ver = try { packageManager.getPackageInfo(packageName, 0).versionName } catch (_: Exception) { "?" }
            text = "Advanced protection  (build $ver)"; textSize = 22f
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
        section("DEVICE ADMIN (uninstall speed-bump + screen lock)")
        adminStatus = TextView(this).apply { textSize = 14f }
        content.addView(adminStatus)
        content.addView(button("Enable Device Admin") {
            startActivity(Intent(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN)
                .putExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN, admin)
                .putExtra(DevicePolicyManager.EXTRA_ADD_EXPLANATION,
                    "Makes uninstalling require removing this admin first, and lets Shield lock the screen after repeated blocked attempts."))
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

        // ---- Encrypted DNS provider ----
        section("DNS PROVIDER (ENCRYPTED DNS-OVER-TLS)")
        content.addView(note(
            "Choose which encrypted DNS provider handles all DNS queries forwarded by Shield. " +
                "Provider changes apply to the next DNS query while the VPN is running. " +
                "There is no plaintext DNS fallback."
        ))

        val dnsProviderIds = listOf(
            "nextdns",
            "cloudflare",
            "cloudflare_security",
            "cloudflare_family",
            "quad9",
            "google",
            "adguard",
            "custom"
        )
        val dnsProviderLabels = listOf(
            "NextDNS – private profile",
            "Cloudflare – standard",
            "Cloudflare – malware protection",
            "Cloudflare – family (adult + malware)",
            "Quad9 – malware protection",
            "Google Public DNS",
            "AdGuard DNS – ads and trackers",
            "Custom DNS-over-TLS provider"
        )

        val dnsSpinner = Spinner(this)
        val dnsAdapter = ArrayAdapter(
            this,
            android.R.layout.simple_spinner_item,
            dnsProviderLabels
        ).apply {
            setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        }
        dnsSpinner.adapter = dnsAdapter
        val currentDnsId = Prefs.getString(this, Prefs.DNS_PROVIDER) ?: "nextdns"
        dnsSpinner.setSelection(dnsProviderIds.indexOf(currentDnsId).coerceAtLeast(0))
        content.addView(dnsSpinner, lp())

        val customDnsHost = EditText(this).apply {
            hint = "DoT hostname, e.g. dns.example.com"
            setSingleLine(true)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
            setText(Prefs.getString(this@AdvancedActivity, Prefs.DNS_CUSTOM_HOST) ?: "")
        }
        val customDnsBootstrap = EditText(this).apply {
            hint = "Bootstrap IPv4 IPs, comma-separated"
            setSingleLine(true)
            inputType = InputType.TYPE_CLASS_TEXT
            setText(Prefs.getString(this@AdvancedActivity, Prefs.DNS_CUSTOM_BOOTSTRAP) ?: "")
        }
        val customDnsSave = button("Save custom DNS provider") {
            val host = customDnsHost.text.toString().trim()
            val bootstrap = customDnsBootstrap.text.toString().trim()
            if (Prefs.saveCustomDns(this, host, bootstrap)) {
                dnsSpinner.setSelection(dnsProviderIds.indexOf("custom"))
                dnsProviderStatus.text =
                    "Selected: Custom DoT – $host (applies to the next DNS query)"
                toast("Custom DNS-over-TLS provider saved")
            } else {
                toast("Enter a valid hostname and one or more IPv4 bootstrap IPs")
            }
        }

        val customVisibility = View.GONE
        customDnsHost.visibility = customVisibility
        customDnsBootstrap.visibility = customVisibility
        customDnsSave.visibility = customVisibility
        content.addView(customDnsHost, lp())
        content.addView(customDnsBootstrap, lp())
        content.addView(customDnsSave, lp())

        dnsProviderStatus = TextView(this).apply {
            textSize = 12f
            setTextColor(0xFF6B7280.toInt())
        }
        content.addView(dnsProviderStatus, lp())

        dnsSpinner.onItemSelectedListener =
            object : android.widget.AdapterView.OnItemSelectedListener {
                override fun onNothingSelected(parent: android.widget.AdapterView<*>?) = Unit

                override fun onItemSelected(
                    parent: android.widget.AdapterView<*>?,
                    view: android.view.View?,
                    position: Int,
                    id: Long
                ) {
                    val providerId = dnsProviderIds[position]
                    val isCustom = providerId == "custom"

                    customDnsHost.visibility = if (isCustom) View.VISIBLE else View.GONE
                    customDnsBootstrap.visibility = if (isCustom) View.VISIBLE else View.GONE
                    customDnsSave.visibility = if (isCustom) View.VISIBLE else View.GONE

                    if (!isCustom) {
                        Prefs.setDnsProvider(this@AdvancedActivity, providerId)
                        val endpoint = Prefs.dnsEndpoint(this@AdvancedActivity)
                        dnsProviderStatus.text = endpoint?.let {
                            "Selected: ${it.label}  |  ${it.hostname}:853"
                        } ?: "Selected DNS provider is invalid"
                    } else {
                        dnsProviderStatus.text =
                            "Custom DoT requires a hostname and numeric bootstrap IPv4 address(es)."
                    }
                }
            }

        Prefs.dnsEndpoint(this)?.let {
            dnsProviderStatus.text = "Selected: ${it.label}  |  ${it.hostname}:853"
        }

        // ---- Settings lockdown ----
        section("SETTINGS APP LOCKDOWN (allow only some pages)")
        toggle("Lock Settings app (only pages listed below stay open)", Prefs.SETTINGS_LOCKDOWN, false) { refresh() }
        lockdownStatusView = TextView(this).apply { textSize = 13f; setTypeface(null, Typeface.BOLD) }
        content.addView(lockdownStatusView)
        content.addView(button("Open Wi-Fi settings") { openSettings(Settings.ACTION_WIFI_SETTINGS) }, lp())
        content.addView(button("Open Bluetooth settings") { openSettings(Settings.ACTION_BLUETOOTH_SETTINGS) }, lp())
        content.addView(button("Open Hotspot settings") { openHotspot() }, lp())
        content.addView(note("Wi-Fi, Bluetooth and Hotspot also work from the Quick Settings tiles (swipe down); those are never blocked. Long-press a tile to open its page. Settings lockdown remains active whenever this switch is ON, regardless of the main Protection LOCKED/UNLOCKED state."))
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
        content.addView(note("Chats, calls and groups stay open. Channels sit inside the Updates tab together with Status, so the whole Updates tab is blocked. WhatsApp must NOT be in your blocked apps list. Works with the English WhatsApp interface."))

        waStatusView = TextView(this).apply { textSize = 12f; setTextColor(0xFF6B7280.toInt()) }
        content.addView(waStatusView)

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
        blockedAppsView = TextView(this).apply { textSize = 13f }
        content.addView(blockedAppsView)
        content.addView(button("Clear all blocked apps (needs unlock)") {
            if (!Guard.require(this)) return@button
            Prefs.saveStrings(this, Prefs.BLOCKED_APPS, emptySet()); refresh()
        }, lp())

        // ---- Images ----
        section("EXPLICIT IMAGE GUARD (experimental)")
        toggle("Scan screen for explicit images", Prefs.IMAGE_ON, false) { refresh() }
        imageStatus = TextView(this).apply { textSize = 13f }
        content.addView(imageStatus)
        content.addView(note("Needs Android 11+ and a model file at assets/nsfw.tflite. Accuracy depends on the model; expect misses and false alarms."))

        // ---- Diagnostics ----
        section("DIAGNOSTICS (use this if something does not block)")
        content.addView(Switch(this).apply {
            text = "Record on-screen text for WhatsApp / Settings"
            textSize = 15f
            isChecked = Prefs.enabled(this@AdvancedActivity, Prefs.DEBUG, false)
            setOnCheckedChangeListener { _, on -> Prefs.setEnabled(this@AdvancedActivity, Prefs.DEBUG, on) }
        }, lp())
        content.addView(note("Switch on, open WhatsApp > Updates tab (NOT a chat), then Settings > Wi-Fi, come back here and tap Refresh. The saved text is whatever was on screen, so never record while a private chat is open, and clear it after use."))
        diagView = TextView(this).apply { textSize = 11f; setTextIsSelectable(true) }
        content.addView(diagView)
        content.addView(button("Refresh diagnostics") { refresh() }, lp())
        content.addView(button("Clear recorded text") {
            Prefs.remove(this, "dbg_screen_wa"); Prefs.remove(this, "dbg_screen_settings"); Prefs.remove(this, "dbg_last_event")
            refresh()
        }, lp())

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

    private fun pickApps() {
        val pm = packageManager
        val launch = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        val apps = pm.queryIntentActivities(launch, 0)
            .map { it.activityInfo.packageName to it.loadLabel(pm).toString() }
            .filter { it.first != packageName && it.first !in hiddenApps }
            .distinctBy { it.first }
            .sortedBy { it.second.lowercase() }
        val current = Prefs.strings(this, Prefs.BLOCKED_APPS)
        val checked = BooleanArray(apps.size) { apps[it].first in current }
        AlertDialog.Builder(this).setTitle("Block these apps")
            .setMultiChoiceItems(apps.map { it.second }.toTypedArray(), checked) { _, i, b -> checked[i] = b }
            .setPositiveButton("Save") { _, _ ->
                val chosen = apps.filterIndexed { i, _ -> checked[i] }.map { it.first }.toMutableSet()
                // keep entries for apps no longer launchable
                val kept = current.filter { p -> apps.none { it.first == p } }
                chosen.addAll(kept.filter { it !in hiddenApps })
                if (((current - hiddenApps) - chosen).isNotEmpty() && !Guard.require(this)) return@setPositiveButton
                Prefs.saveStrings(this, Prefs.BLOCKED_APPS, chosen)
                toast("${chosen.size} app(s) blocked")
            }
            .setNegativeButton("Cancel", null).show()
    }

    private fun appLabel(p: String): String = try {
        packageManager.getApplicationLabel(packageManager.getApplicationInfo(p, 0)).toString()
    } catch (_: Exception) { p }

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
            if (dpm.isDeviceOwnerApp(packageName)) "Device Admin: ACTIVE (Device Owner: hard uninstall block)"
            else "Device Admin: ACTIVE (uninstall needs admin removal first; not a hard block)"
        } else "Device Admin: OFF"
        a11yStatus.text = if (a11yEnabled()) "Accessibility: ON" else "Accessibility: OFF (required for most features)"
        val hasModel = try { assets.list("")?.contains("nsfw.tflite") == true } catch (_: Exception) { false }
        imageStatus.text = "Model: ${if (hasModel) "found" else "missing"}  |  Android 11+: ${Build.VERSION.SDK_INT >= 30}"
        blockedView.text = "Last blocked Settings screen: ${Prefs.getString(this, "last_settings_block") ?: "none yet"}"
        val blockedNow = Prefs.strings(this, Prefs.BLOCKED_APPS).map { appLabel(it) }.sorted()
        blockedAppsView.text = if (blockedNow.isEmpty()) "Blocked apps: none" else "Blocked apps: " + blockedNow.joinToString(", ")
        val armed = Guard.hasPin(this)
        val lockdownOn = Prefs.enabled(this, Prefs.SETTINGS_LOCKDOWN, false)
        val guardOn = Prefs.enabled(this, Prefs.SETTINGS_GUARD, true)
        val lockdownActive = lockdownOn
        lockdownStatusView.text = when {
            !lockdownOn -> "Status: OFF (switch is off)"
            else -> "Status: ACTIVE (independent of main Protection status)"
        }
        waStatusView.text = "Last WhatsApp block: ${Prefs.getString(this, "last_wa_block") ?: "none yet"}"
        diagView.text = "Accessibility service enabled: ${a11yEnabled()}\n" +
            "PIN set: $armed   unlocked right now: ${Guard.isUnlocked(this)}\n" +
            "Settings lockdown switch: $lockdownOn   guard switch: $guardOn\n" +
            "=> Settings lockdown active now: $lockdownActive\n" +
            "WhatsApp channel block switch: ${Prefs.enabled(this, Prefs.WA_CHANNELS, true)}\n" +
            "Last event seen by service: ${Prefs.getString(this, "dbg_last_event") ?: "none (service not receiving events)"}\n\n" +
            "--- WhatsApp screen ---\n${Prefs.getString(this, "dbg_screen_wa") ?: "-"}\n\n" +
            "--- Settings screen ---\n${Prefs.getString(this, "dbg_screen_settings") ?: "-"}"
    }

    private fun toast(m: String) = Toast.makeText(this, m, Toast.LENGTH_SHORT).show()
}
