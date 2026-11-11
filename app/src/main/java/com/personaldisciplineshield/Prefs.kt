package com.personaldisciplineshield

import android.content.Context

object Prefs {
    private const val FILE = "shield_settings"
    private fun p(c: Context) =
        c.getSharedPreferences(FILE, Context.MODE_PRIVATE)

    const val ADULT = "cat_adult"
    const val YOUTUBE = "cat_youtube"
    const val SOCIAL = "cat_social"
    const val CUSTOM = "cat_custom"

    // Stage 4
    const val KEYWORDS_ON = "cat_keywords"
    const val APPS_ON = "cat_apps"
    const val IMAGE_ON = "cat_image"
    const val SETTINGS_GUARD = "guard_settings"
    const val KEYWORDS = "kw_list"
    const val BLOCKED_APPS = "blocked_apps"
    const val SETTINGS_LOCKDOWN = "guard_settings_lockdown"
    const val WA_CHANNELS = "wa_channels"
    const val DEBUG = "debug_dump"
    const val ALLOWED_SETTINGS = "allowed_settings_titles"

    val DEFAULT_ALLOWED_SETTINGS = setOf(
        "wi-fi", "wifi", "internet", "bluetooth", "hotspot", "tethering",
        "hotspot & tethering", "wi-fi hotspot", "mobile hotspot", "portable hotspot",
        "mobile hotspot and tethering", "saved networks", "wi-fi preferences", "network preferences",
        "wlan", "portable wi-fi hotspot", "personal hotspot",
        "pair new device", "pairing", "bluetooth pairing", "available devices"
    )

    fun enabled(c: Context, key: String, default: Boolean = true) =
        p(c).getBoolean(key, default)

    fun setEnabled(c: Context, key: String, value: Boolean) {
        p(c).edit().putBoolean(key, value).apply()
    }

    fun domains(c: Context): MutableSet<String> =
        p(c).getStringSet("custom_domains", emptySet())
            ?.toMutableSet() ?: mutableSetOf()

    fun saveDomains(c: Context, domains: Set<String>) {
        p(c).edit().putStringSet("custom_domains", domains.toSet()).commit()
    }

    fun strings(c: Context, key: String): MutableSet<String> =
        p(c).getStringSet(key, emptySet())?.toMutableSet() ?: mutableSetOf()

    fun saveStrings(c: Context, key: String, values: Set<String>) {
        p(c).edit().putStringSet(key, values.toSet()).commit()
    }

    fun getString(c: Context, key: String): String? = p(c).getString(key, null)
    fun putString(c: Context, key: String, v: String) { p(c).edit().putString(key, v).commit() }
    fun getLong(c: Context, key: String, def: Long = 0L) = p(c).getLong(key, def)
    fun putLong(c: Context, key: String, v: Long) { p(c).edit().putLong(key, v).commit() }

    fun has(c: Context, key: String) = p(c).contains(key)
    fun remove(c: Context, key: String) { p(c).edit().remove(key).commit() }

    /** Page titles allowed while the Settings app is locked (defaults until the user edits). */
    fun allowedSettings(c: Context): Set<String> =
        if (has(c, ALLOWED_SETTINGS)) strings(c, ALLOWED_SETTINGS) else DEFAULT_ALLOWED_SETTINGS

    fun count(c: Context, key: String) =
        p(c).getLong(key, 0L)

    fun increment(c: Context, key: String) {
        p(c).edit().putLong(key, count(c, key) + 1L).apply()
    }

    fun isVpnActive(c: Context) =
        p(c).getBoolean("vpn_active", false)

    fun setVpnActive(c: Context, active: Boolean) {
        p(c).edit().putBoolean("vpn_active", active).commit()
    }

    // True once the user has turned protection on; used to auto-start after reboot.
    fun vpnWanted(c: Context) = p(c).getBoolean("vpn_wanted", false)
    fun setVpnWanted(c: Context, v: Boolean) {
        p(c).edit().putBoolean("vpn_wanted", v).commit()
    }

    fun setLastDnsError(c: Context, message: String) {
        p(c).edit().putString("last_dns_error", message).apply()
    }

    fun lastDnsError(c: Context): String =
        p(c).getString("last_dns_error", "Not tested yet") ?: "Not tested yet"

    // Encrypted DNS provider selection (DNS-over-TLS only; no plaintext fallback).
    const val DNS_PROVIDER = "dns_provider"
    const val DNS_CUSTOM_HOST = "dns_custom_host"
    const val DNS_CUSTOM_BOOTSTRAP = "dns_custom_bootstrap"

    data class DnsEndpoint(
        val id: String,
        val label: String,
        val hostname: String,
        val bootstrapIps: List<String>
    )

    fun dnsEndpoint(c: Context): DnsEndpoint? {
        val id = p(c).getString(DNS_PROVIDER, "nextdns") ?: "nextdns"
        return when (id) {
            "nextdns" -> DnsEndpoint(
                id, "NextDNS (private profile)", "b72114.dns.nextdns.io",
                listOf("45.90.28.0", "45.90.30.0")
            )
            "cloudflare" -> DnsEndpoint(
                id, "Cloudflare", "one.one.one.one",
                listOf("1.1.1.1", "1.0.0.1")
            )
            "cloudflare_security" -> DnsEndpoint(
                id, "Cloudflare Security", "security.cloudflare-dns.com",
                listOf("1.1.1.2", "1.0.0.2")
            )
            "cloudflare_family" -> DnsEndpoint(
                id, "Cloudflare Family", "family.cloudflare-dns.com",
                listOf("1.1.1.3", "1.0.0.3")
            )
            "quad9" -> DnsEndpoint(
                id, "Quad9", "dns.quad9.net",
                listOf("9.9.9.9", "149.112.112.112")
            )
            "google" -> DnsEndpoint(
                id, "Google Public DNS", "dns.google",
                listOf("8.8.8.8", "8.8.4.4")
            )
            "adguard" -> DnsEndpoint(
                id, "AdGuard DNS", "dns.adguard-dns.com",
                listOf("94.140.14.14", "94.140.15.15")
            )
            "custom" -> {
                val host = p(c).getString(DNS_CUSTOM_HOST, "")?.trim()?.lowercase().orEmpty()
                val ips = p(c).getString(DNS_CUSTOM_BOOTSTRAP, "")
                    ?.split(",")?.map { it.trim() }?.filter { it.isNotEmpty() }
                    .orEmpty()
                if (!isValidDnsHostname(host) || ips.isEmpty() || ips.any { !isValidIpv4(it) }) {
                    null
                } else {
                    DnsEndpoint(id, "Custom ($host)", host, ips)
                }
            }
            else -> null
        }
    }

    fun setDnsProvider(c: Context, id: String) {
        p(c).edit().putString(DNS_PROVIDER, id).commit()
    }

    fun saveCustomDns(c: Context, hostname: String, bootstrapIps: String): Boolean {
        val host = hostname.trim().lowercase()
        val ips = bootstrapIps.split(",").map { it.trim() }.filter { it.isNotEmpty() }
        if (!isValidDnsHostname(host) || ips.isEmpty() || ips.any { !isValidIpv4(it) }) return false
        return p(c).edit()
            .putString(DNS_CUSTOM_HOST, host)
            .putString(DNS_CUSTOM_BOOTSTRAP, ips.joinToString(","))
            .putString(DNS_PROVIDER, "custom")
            .commit()
    }

    private fun isValidDnsHostname(host: String): Boolean {
        if (host.length !in 1..253 || host.endsWith(".")) return false
        return host.split(".").all { label ->
            label.length in 1..63 &&
                label.first().isLetterOrDigit() &&
                label.last().isLetterOrDigit() &&
                label.all { it.isLetterOrDigit() || it == '-' }
        }
    }

    private fun isValidIpv4(value: String): Boolean {
        val parts = value.split(".")
        return parts.size == 4 && parts.all {
            it.isNotEmpty() && it.all { ch -> ch in '0'..'9' } &&
                (it.toIntOrNull()?.let { n -> n in 0..255 } == true)
        }
    }
}
