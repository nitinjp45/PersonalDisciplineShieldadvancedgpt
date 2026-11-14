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
    const val DOT_ON = "dns_over_tls"
    const val DOT_STRICT = "dns_over_tls_strict"
    const val DNS_PROVIDER = "dns_provider"
    const val DNS_CUSTOM_HOST = "dns_custom_host"
    const val DNS_CUSTOM_BOOTSTRAP = "dns_custom_bootstrap"
    const val ALLOWED_SETTINGS = "allowed_settings_titles"

    data class DnsProvider(
        val id: String,
        val label: String,
        val hostname: String,
        val bootstrapIps: List<String>
    )

    // Bootstrap IPs are used only to establish the TLS connection. The TLS
    // certificate is still verified against hostname, including SNI.
    val DNS_PROVIDERS = listOf(
        DnsProvider("nextdns", "NextDNS – Private profile", "b72114.dns.nextdns.io",
            listOf("45.90.28.0", "45.90.30.0")),
        DnsProvider("cloudflare", "Cloudflare", "one.one.one.one",
            listOf("1.1.1.1", "1.0.0.1")),
        DnsProvider("cloudflare-security", "Cloudflare Security", "security.cloudflare-dns.com",
            listOf("1.1.1.2", "1.0.0.2")),
        DnsProvider("cloudflare-family", "Cloudflare Family", "family.cloudflare-dns.com",
            listOf("1.1.1.3", "1.0.0.3")),
        DnsProvider("quad9", "Quad9", "dns.quad9.net",
            listOf("9.9.9.9", "149.112.112.112")),
        DnsProvider("google", "Google Public DNS", "dns.google",
            listOf("8.8.8.8", "8.8.4.4")),
        DnsProvider("adguard", "AdGuard DNS", "dns.adguard-dns.com",
            listOf("94.140.14.14", "94.140.15.15")),
        DnsProvider("adguard-family", "AdGuard Family", "family.adguard-dns.com",
            listOf("94.140.14.15", "94.140.15.16"))
    )

    fun dnsProvider(c: Context): DnsProvider {
        val id = getString(c, DNS_PROVIDER) ?: "nextdns"
        if (id == "custom") {
            val host = getString(c, DNS_CUSTOM_HOST)?.trim().orEmpty()
            val bootstrap = getString(c, DNS_CUSTOM_BOOTSTRAP)?.trim().orEmpty()
            return DnsProvider("custom", "Custom DoT", host, bootstrap.split(',').map { it.trim() }.filter { it.isNotEmpty() })
        }
        return DNS_PROVIDERS.firstOrNull { it.id == id } ?: DNS_PROVIDERS.first()
    }

    fun dnsProviderLabel(c: Context): String = dnsProvider(c).label

    fun validDnsHostname(host: String): Boolean {
        if (host.isBlank() || host.length > 253 || !host.contains('.')) return false
        return host.split('.').all { label ->
            label.isNotEmpty() && label.length <= 63 &&
                label.matches(Regex("[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"))
        }
    }

    fun validIpv4(value: String): Boolean {
        val parts = value.split('.')
        if (parts.size != 4) return false
        return parts.all { part ->
            part.toIntOrNull()?.let { number ->
                number in 0..255 && (part == "0" || !part.startsWith("0"))
            } == true
        }
    }

    val DEFAULT_ALLOWED_SETTINGS = setOf(
        "wi-fi", "wifi", "internet", "bluetooth", "hotspot", "tethering",
        "hotspot & tethering", "wi-fi hotspot", "mobile hotspot", "portable hotspot",
        "mobile hotspot and tethering", "saved networks", "wi-fi preferences", "network preferences",
        "wlan", "portable wi-fi hotspot", "personal hotspot"
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

    /** Strict encrypted DNS is the 0.5.3 policy. This migration also updates existing installs. */
    fun enforceStrictDns(c: Context) {
        p(c).edit()
            .putBoolean(DOT_ON, true)
            .putBoolean(DOT_STRICT, true)
            .apply()
    }
}
