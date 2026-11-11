package com.personaldisciplineshield

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.graphics.Typeface
import android.view.Gravity
import android.widget.*
import android.text.InputType

class MainActivity : Activity() {
    private lateinit var root: LinearLayout
    private lateinit var status: TextView
    private lateinit var stats: TextView
    private val vpnRequest = 701

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        buildScreen()
    }

    override fun onResume() {
        super.onResume()
        if (::status.isInitialized) refresh()
    }

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    private fun buildScreen() {
        root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(22), dp(20), dp(20))
            setBackgroundColor(0xFFF5F6FA.toInt())
        }
        val scroll = ScrollView(this)
        val content = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        scroll.addView(content)
        root.addView(scroll, LinearLayout.LayoutParams(-1, 0, 1f))

        content.addView(TextView(this).apply {
            text = "Personal Discipline Shield"
            textSize = 23f
            setTypeface(null, Typeface.BOLD)
            setTextColor(0xFF172033.toInt())
        })
        content.addView(TextView(this).apply {
            text = "Stage 4.2  •  DNS + app + keyword + discipline safeguards"
            textSize = 13f
            setTextColor(0xFF5D6678.toInt())
            setPadding(0, dp(5), 0, dp(14))
        })

        status = TextView(this).apply {
            textSize = 15f
            setTextColor(0xFF344054.toInt())
            setPadding(dp(12), dp(12), dp(12), dp(12))
            setBackgroundColor(0xFFE7ECF4.toInt())
        }
        content.addView(status)

        content.addView(Button(this).apply {
            text = "Enable DNS Protection"
            setOnClickListener { requestVpn() }
        }, fullWidth())

        content.addView(Button(this).apply {
            text = "Turn Protection Off"
            setOnClickListener {
                if (!Guard.require(this@MainActivity)) return@setOnClickListener
                val stop = Intent(this@MainActivity, DnsVpnService::class.java)
                    .setAction(DnsVpnService.ACTION_STOP)
                startServiceCompat(stop)
                status.postDelayed({ refresh() }, 300)
                status.postDelayed({ refresh() }, 1000)
            }
        }, fullWidth())

        content.addView(Button(this).apply {
            text = "Advanced protection (lock, admin, keywords, apps)"
            setOnClickListener { startActivity(Intent(this@MainActivity, AdvancedActivity::class.java)) }
        }, fullWidth())

        section(content, "BLOCKING CATEGORIES")
        addToggle(content, "Adult websites", Prefs.ADULT)
        addToggle(content, "YouTube and Shorts", Prefs.YOUTUBE)
        addToggle(content, "Social media", Prefs.SOCIAL)
        addToggle(content, "Custom domains", Prefs.CUSTOM)

        section(content, "YOUR CUSTOM BLOCKLIST")
        val domainInput = EditText(this).apply {
            hint = "example.com"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
            setSingleLine(true)
        }
        content.addView(domainInput, fullWidth())
        content.addView(Button(this).apply {
            text = "Add domain"
            setOnClickListener {
                val cleaned = domainInput.text.toString().trim().lowercase()
                    .removePrefix("https://").removePrefix("http://").substringBefore("/")
                    .substringBefore(":").removePrefix("www.")
                if (!cleaned.matches(Regex("(?i)^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$")) ||
                    !cleaned.contains(".") || cleaned.contains("..")) {
                    Toast.makeText(this@MainActivity, "Enter a valid domain, e.g. example.com", Toast.LENGTH_SHORT).show()
                } else {
                    val set = Prefs.domains(this@MainActivity)
                    set.add(cleaned)
                    Prefs.saveDomains(this@MainActivity, set)
                    domainInput.text.clear()
                    renderDomains()
                    Toast.makeText(this@MainActivity, "Domain added", Toast.LENGTH_SHORT).show()
                }
            }
        }, fullWidth())

        val domainList = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        content.addView(domainList)
        domainList.tag = "domain_list"
        renderDomains()

        section(content, "BLOCKING STATISTICS")
        stats = TextView(this).apply {
            textSize = 14f
            setTextColor(0xFF344054.toInt())
            setPadding(0, dp(6), 0, dp(12))
        }
        content.addView(stats)
        content.addView(Button(this).apply {
            text = "Refresh statistics"
            setOnClickListener { refresh() }
        }, fullWidth())

        content.addView(TextView(this).apply {
            text = "After removing a domain, close and reopen the browser if it still shows the old blocked result. Browsers and Android may cache DNS failures. If needed, briefly toggle Wi-Fi or mobile data to refresh the network cache."
            textSize = 12f
            setTextColor(0xFF6B7280.toInt())
            setPadding(0, dp(14), 0, dp(6))
        })
        content.addView(TextView(this).apply {
            text = "Important: DNS filtering is not complete device control. Private DNS, encrypted DNS apps, cached connections, IPv6 and direct-IP connections may bypass filtering. YouTube filtering blocks YouTube broadly, not Shorts selectively."
            textSize = 12f
            setTextColor(0xFF6B7280.toInt())
            setPadding(0, dp(8), 0, dp(10))
        })

        setContentView(root)
        refresh()
    }

    private fun startServiceCompat(intent: Intent) {
        if (intent.action == DnsVpnService.ACTION_STOP) {
            // The app is in the foreground when this button is tapped.
            // Use startService for the stop command; no new foreground start is needed.
            startService(intent)
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
    }

    private fun fullWidth() = LinearLayout.LayoutParams(-1, -2).apply {
        topMargin = dp(5)
        bottomMargin = dp(5)
    }

    private fun section(parent: LinearLayout, title: String) {
        parent.addView(TextView(this).apply {
            text = title
            textSize = 14f
            setTypeface(null, Typeface.BOLD)
            setTextColor(0xFF344054.toInt())
            setPadding(0, dp(18), 0, dp(5))
        })
    }

    private fun addToggle(parent: LinearLayout, title: String, key: String) {
        val sw = Switch(this).apply {
            text = title
            textSize = 15f
            isChecked = Prefs.enabled(this@MainActivity, key)
            setOnCheckedChangeListener { v, checked ->
                if (!checked && !Guard.require(this@MainActivity)) {
                    (v as Switch).isChecked = true
                    return@setOnCheckedChangeListener
                }
                Prefs.setEnabled(this@MainActivity, key, checked)
            }
        }
        parent.addView(sw, fullWidth())
    }

    private fun renderDomains() {
        val list = root.findViewWithTag<LinearLayout>("domain_list") ?: return
        list.removeAllViews()
        val domains = Prefs.domains(this).sorted()
        if (domains.isEmpty()) {
            list.addView(TextView(this).apply {
                text = "No custom domains added"
                textSize = 13f
            })
        }
        domains.forEach { domain ->
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
            }
            row.addView(TextView(this).apply {
                text = domain
                textSize = 14f
            }, LinearLayout.LayoutParams(0, -2, 1f))
            row.addView(Button(this).apply {
                text = "Remove"
                setOnClickListener {
                    if (!Guard.require(this@MainActivity)) return@setOnClickListener
                    val updated = Prefs.domains(this@MainActivity)
                    updated.remove(domain)
                    Prefs.saveDomains(this@MainActivity, updated)
                    renderDomains()
                    Toast.makeText(
                        this@MainActivity,
                        "Removed. If it remains blocked, refresh the browser's DNS cache.",
                        Toast.LENGTH_LONG
                    ).show()
                }
            })
            list.addView(row)
        }
    }

  private fun requestVpn() {
    val prepare = VpnService.prepare(this)

    if (prepare != null) {
        startActivityForResult(prepare, vpnRequest)
    } else {
        Toast.makeText(
            this,
            "VPN permission is already granted",
            Toast.LENGTH_SHORT
        ).show()

        startProtection()
    }
}

    private fun startProtection() {
        val start = Intent(this, DnsVpnService::class.java)
        startServiceCompat(start)
        status.postDelayed({ refresh() }, 400)
        status.postDelayed({ refresh() }, 1200)
    }

    @Deprecated("Deprecated in Android API")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == vpnRequest && resultCode == RESULT_OK) startProtection()
    }

    private fun refresh() {
        val active = Prefs.isVpnActive(this)
        status.text = if (active) {
            "Protection status: ON  •  VPN service active"
        } else {
            "Protection status: OFF"
        }
        stats.text = "Total blocked: ${Prefs.count(this, "total_blocked")}\n" +
    "Adult: ${Prefs.count(this, "blocked_adult")}\n" +
    "YouTube: ${Prefs.count(this, "blocked_youtube")}\n" +
    "Social media: ${Prefs.count(this, "blocked_social")}\n" +
    "Custom: ${Prefs.count(this, "blocked_custom")}\n" +
    "DNS forwarding errors: ${Prefs.count(this, "dns_errors")}\n\n" +
    "LAST DNS ERROR:\n${Prefs.lastDnsError(this)}"
    }
}
