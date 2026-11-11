package com.personaldisciplineshield

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLPeerUnverifiedException
import kotlin.concurrent.thread

/**
 * DNS-only VPN service. It intercepts UDP and TCP DNS on IPv4 and IPv6.
 * TCP handling is intentionally limited to DNS sessions (not a general TCP stack).
 */
class DnsVpnService : VpnService() {

    @Volatile private var running = false
    @Volatile private var userRequested = false
    private var vpn: ParcelFileDescriptor? = null
    private val recoveryHandler = Handler(Looper.getMainLooper())
    private var recoveryAttempts = 0
    private val maxRecoveryAttempts = 5

    private data class TcpSession(
        val key: String,
        val ipv6: Boolean,
        val clientIp: ByteArray,
        val serverIp: ByteArray,
        val clientPort: Int,
        val serverPort: Int,
        var clientNext: Long,
        var serverNext: Long,
        val input: ByteArrayOutputStream = ByteArrayOutputStream(),
        var lastResponse: List<ByteArray> = emptyList(),
        var lastResponseEnd: Long = 0L
    )

    private val tcpSessions = ConcurrentHashMap<String, TcpSession>()

    // Reuse one strict DoT connection to avoid a TLS handshake for every DNS query.
    private val dotLock = Any()
    private var dotSocket: SSLSocket? = null
    private var dotEndpointKey: String? = null
    private var dotBootstrapIp: String? = null

    companion object {
        const val ACTION_STOP = "com.personaldisciplineshield.ACTION_STOP"
        private const val CHANNEL_ID = "shield_vpn_status"
        private const val NOTIFICATION_ID = 2401
        private const val DNS_PORT = 53
        private const val TCP_MSS = 1000
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            // PIN lock: ignore stop requests (also from the notification button) while locked.
            if (!Guard.isUnlocked(this)) {
                if (!running) stopSelf()
                return START_STICKY
            }
            Prefs.setVpnWanted(this, false)
            userRequested = false
            recoveryHandler.removeCallbacksAndMessages(null)
            stopVpnAndService()
            return START_NOT_STICKY
        }

        // A null intent can occur when Android recreates a START_STICKY service
        // after an unexpected process/service termination.
        userRequested = true
        Prefs.setVpnWanted(this, true)
        if (!running) {
            startForeground(NOTIFICATION_ID, buildNotification())
            startVpn()
        }
        return START_STICKY
    }

    private fun buildNotification(): Notification {
        createNotificationChannel()
        val openIntent = PendingIntent.getActivity(
            this, 11,
            Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val stopIntent = PendingIntent.getService(
            this, 12,
            Intent(this, DnsVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION") Notification.Builder(this)
        }
        return builder.setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle("Personal Discipline Shield")
            .setContentText("DNS protection is active")
            .setContentIntent(openIntent)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .addAction(android.R.drawable.ic_lock_lock, "Turn Off", stopIntent)
            .build()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val manager = getSystemService(NotificationManager::class.java)
            val channel = NotificationChannel(
                CHANNEL_ID, "DNS protection status", NotificationManager.IMPORTANCE_LOW
            )
            channel.description = "Shows when DNS protection is active"
            manager.createNotificationChannel(channel)
        }
    }

    private fun startVpn() {
        try {
            val established = Builder()
                .setSession("Personal Discipline Shield")
                .addAddress("10.111.0.2", 32)
                .addDnsServer("10.111.0.1")
                .addRoute("10.111.0.1", 32)
                .addAddress("fd00:1111::2", 128)
                .addDnsServer("fd00:1111::1")
                .addRoute("fd00:1111::1", 128)
                .setMtu(1500)
                .establish()

            if (established == null) {
                userRequested = false
                Prefs.setLastDnsError(this, "VPN establishment failed or VPN permission unavailable")
                Prefs.setVpnActive(this, false)
                stopVpnAndService()
                return
            }
            vpn = established
            running = true
            Prefs.setVpnActive(this, true)
            Prefs.setLastDnsError(this, "VPN active. Waiting for DNS query.")

            // Clear the retry counter only after the tunnel has remained healthy
            // for a full minute, so repeated immediate crashes do not retry forever.
            recoveryHandler.postDelayed({ if (running) recoveryAttempts = 0 }, 60000L)
            thread(name = "ShieldDnsLoop") {
                val input = FileInputStream(established.fileDescriptor)
                val output = FileOutputStream(established.fileDescriptor)
                val buffer = ByteArray(32767)
                var loopFailure: Exception? = null
                try {
                    while (running) {
                        val length = input.read(buffer)
                        if (length <= 0) continue
                        handlePacket(buffer.copyOf(length), output)
                    }
                } catch (e: Exception) {
                    if (running) {
                        loopFailure = e
                        Prefs.increment(this, "dns_errors")
                        Prefs.setLastDnsError(
                            this, "VPN packet loop: ${e.javaClass.simpleName}: ${e.message}"
                        )
                    }
                } finally {
                    try { input.close() } catch (_: Exception) {}
                    try { output.close() } catch (_: Exception) {}
                    if (loopFailure != null) recoverAfterPacketLoopFailure(established)
                }
            }
        } catch (e: Exception) {
            Prefs.setLastDnsError(
                this, "VPN startup: ${e.javaClass.simpleName}: ${e.message}"
            )
            Prefs.setVpnActive(this, false)
            scheduleRecovery("VPN startup failed")
        }
    }

    private fun recoverAfterPacketLoopFailure(failedVpn: ParcelFileDescriptor) {
        if (vpn !== failedVpn) return
        running = false
        vpn = null
        try { failedVpn.close() } catch (_: Exception) {}
        Prefs.setVpnActive(this, false)
        if (userRequested) scheduleRecovery("VPN packet loop stopped unexpectedly")
    }

    private fun scheduleRecovery(reason: String) {
        if (!userRequested || recoveryAttempts >= maxRecoveryAttempts) {
            Prefs.setLastDnsError(this, "$reason; automatic recovery stopped after $recoveryAttempts attempts")
            return
        }
        recoveryAttempts++
        val delayMs = (2000L * (1L shl (recoveryAttempts - 1))).coerceAtMost(30000L)
        Prefs.setLastDnsError(this, "$reason; recovery attempt $recoveryAttempts/$maxRecoveryAttempts in ${delayMs / 1000}s")
        recoveryHandler.postDelayed({
            if (userRequested && !running) startVpn()
        }, delayMs)
    }

    override fun onRevoke() {
        userRequested = false
        recoveryHandler.removeCallbacksAndMessages(null)
        Prefs.setLastDnsError(this, "VPN permission was revoked by Android or the user")
        stopVpnAndService()
        super.onRevoke()
    }

    private fun stopVpnAndService() {
        recoveryHandler.removeCallbacksAndMessages(null)
        running = false
        tcpSessions.clear()
        closeDotConnection()
        Prefs.setVpnActive(this, false)
        try { vpn?.close() } catch (_: Exception) {}
        vpn = null
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) stopForeground(STOP_FOREGROUND_REMOVE)
        else {
            @Suppress("DEPRECATION") stopForeground(true)
        }
        stopSelf()
    }

    override fun onDestroy() {
        recoveryHandler.removeCallbacksAndMessages(null)
        running = false
        tcpSessions.clear()
        closeDotConnection()
        Prefs.setVpnActive(this, false)
        try { vpn?.close() } catch (_: Exception) {}
        vpn = null
        super.onDestroy()
    }

    private fun handlePacket(packet: ByteArray, output: FileOutputStream) {
        if (!running || packet.isEmpty()) return
        when ((packet[0].toInt() ushr 4) and 0x0F) {
            4 -> handleIpv4(packet, output)
            6 -> handleIpv6(packet, output)
        }
    }

    private fun handleIpv4(packet: ByteArray, output: FileOutputStream) {
        if (packet.size < 20) return
        val ihl = (packet[0].toInt() and 0x0F) * 4
        if (ihl < 20 || packet.size < ihl) return
        val totalLength = u16(packet, 2).coerceAtMost(packet.size)
        if (totalLength < ihl) return
        val fragment = u16(packet, 6)
        if ((fragment and 0x3FFF) != 0) return
        when (packet[9].toInt() and 0xFF) {
            17 -> handleIpv4Udp(packet.copyOf(totalLength), ihl, output)
            6 -> handleTcp(packet.copyOf(totalLength), false, ihl, output)
        }
    }

    private fun handleIpv4Udp(packet: ByteArray, ihl: Int, output: FileOutputStream) {
        if (packet.size < ihl + 8 || u16(packet, ihl + 2) != DNS_PORT) return
        val udpLength = u16(packet, ihl + 4)
        if (udpLength < 8 || ihl + udpLength > packet.size) return
        val query = packet.copyOfRange(ihl + 8, ihl + udpLength)
        val responseDns = processDns(query) ?: return
        writeTunPacket(output, buildIpv4UdpResponse(packet, ihl, responseDns))
    }

    private fun handleIpv6(packet: ByteArray, output: FileOutputStream) {
        if (packet.size < 40) return
        val payloadLength = u16(packet, 4)
        val packetEnd = (40 + payloadLength).coerceAtMost(packet.size)
        var next = packet[6].toInt() and 0xFF
        var offset = 40
        var count = 0
        while (next != 17 && next != 6 && count++ < 8) {
            if (offset + 2 > packetEnd) return
            when (next) {
                0, 43, 60 -> {
                    val following = packet[offset].toInt() and 0xFF
                    val size = ((packet[offset + 1].toInt() and 0xFF) + 1) * 8
                    if (size < 8 || offset + size > packetEnd) return
                    next = following; offset += size
                }
                44 -> {
                    if (offset + 8 > packetEnd) return
                    val following = packet[offset].toInt() and 0xFF
                    val frag = u16(packet, offset + 2)
                    if ((frag and 0xFFF9) != 0) return
                    next = following; offset += 8
                }
                51 -> {
                    val following = packet[offset].toInt() and 0xFF
                    val size = ((packet[offset + 1].toInt() and 0xFF) + 2) * 4
                    if (size < 8 || offset + size > packetEnd) return
                    next = following; offset += size
                }
                else -> return
            }
        }
        val bounded = packet.copyOf(packetEnd)
        when (next) {
            17 -> handleIpv6Udp(bounded, offset, output)
            6 -> handleTcp(bounded, true, offset, output)
        }
    }

    private fun handleIpv6Udp(packet: ByteArray, offset: Int, output: FileOutputStream) {
        if (offset + 8 > packet.size || u16(packet, offset + 2) != DNS_PORT) return
        Prefs.increment(this, "ipv6_dns_received")
        val length = u16(packet, offset + 4)
        if (length < 8 || offset + length > packet.size) return
        val query = packet.copyOfRange(offset + 8, offset + length)
        val responseDns = processDns(query) ?: return
        writeTunPacket(output, buildIpv6UdpResponse(packet, offset, responseDns))
        Prefs.increment(this, "ipv6_dns_processed")
    }

    private fun processDns(query: ByteArray): ByteArray? {
        if (query.size < 12) return null
        if ((u16(query, 2) and 0x8000) != 0) return null
        val domain = readQuestionName(query) ?: return null
        val category = blockedCategory(domain)
        if (category != null) {
            Prefs.increment(this, "total_blocked")
            Prefs.increment(this, "blocked_$category")
            return buildNxDomainResponse(query)
        }
        val answer = forwardDnsUdp(query)
        if (answer == null) {
            Prefs.increment(this, "dns_errors")
            Prefs.setLastDnsError(this, "Encrypted DNS-over-TLS forwarding failed for $domain")
        }
        return answer
    }

    private fun buildNxDomainResponse(query: ByteArray): ByteArray {
        val response = query.copyOf()
        val flags = (u16(query, 2) and 0x0100) or 0x8083
        response[2] = (flags ushr 8).toByte()
        response[3] = flags.toByte()
        for (i in 6..11) response[i] = 0
        return response
    }

    private fun blockedCategory(domain: String): String? {
        val host = domain.lowercase().trimEnd('.')
        fun matches(domains: List<String>) = domains.any { host == it || host.endsWith(".$it") }
        if (Prefs.enabled(this, Prefs.ADULT, true) && (matches(listOf(
                "pornhub.com", "xvideos.com", "xnxx.com", "xhamster.com", "redtube.com",
                "youporn.com", "tube8.com", "spankbang.com", "chaturbate.com",
                "onlyfans.com", "adultfriendfinder.com"
            )) || adultListed(host) || adultHeuristic(host))) return "adult"
        if (Prefs.enabled(this, Prefs.YOUTUBE, true) && matches(listOf(
                "youtube.com", "youtube-nocookie.com", "youtu.be", "ytimg.com", "googlevideo.com"
            ))) return "youtube"
        if (Prefs.enabled(this, Prefs.SOCIAL, true) && matches(listOf(
                "facebook.com", "fb.com", "instagram.com", "threads.net", "twitter.com",
                "x.com", "tiktok.com", "snapchat.com", "reddit.com"
            ))) return "social"
        if (Prefs.enabled(this, Prefs.CUSTOM, true)) {
            val custom = Prefs.domains(this).map { it.lowercase().trim().trimStart('.').trimEnd('.') }
            if (matches(custom)) return "custom"
        }
        return null
    }

    // Larger list from assets/blocklist_adult.txt (plain domains or hosts-file lines).
    private val adultSet: Set<String> by lazy {
        try {
            assets.open("blocklist_adult.txt").bufferedReader().useLines { lines ->
                lines.map { it.trim().lowercase() }
                    .filter { it.isNotEmpty() && !it.startsWith("#") }
                    .map { it.split(Regex("\\s+")).last() }
                    .filter { it.contains('.') }
                    .toHashSet()
            }
        } catch (_: Exception) { emptySet<String>() }
    }

    private fun adultListed(host: String): Boolean {
        var h = host
        while (h.contains('.')) {
            if (h in adultSet) return true
            h = h.substringAfter('.')
        }
        return false
    }

    // Cheap heuristic for unknown adult domains. May rarely block innocent hosts.
    private val adultTokens = listOf("porn", "xxx", "xvideo", "xnxx", "hentai", "nsfw", "camgirl")
    private fun adultHeuristic(host: String) = adultTokens.any { host.contains(it) }

    private fun readQuestionName(dns: ByteArray): String? {
        if (dns.size < 17) return null
        var offset = 12
        val labels = ArrayList<String>()
        while (offset < dns.size) {
            val length = dns[offset++].toInt() and 0xFF
            if (length == 0) break
            if ((length and 0xC0) != 0 || length > 63 || offset + length > dns.size) return null
            labels.add(String(dns, offset, length, Charsets.US_ASCII))
            offset += length
        }
        if (labels.isEmpty() || offset + 4 > dns.size) return null
        return labels.joinToString(".").lowercase()
    }

    // Both intercepted UDP and TCP DNS requests are forwarded using strict DNS-over-TLS.
    // There is deliberately no plaintext DNS fallback.
    private fun forwardDnsUdp(query: ByteArray): ByteArray? = forwardDnsOverTls(query)

    private fun forwardDnsTcp(query: ByteArray): ByteArray? = forwardDnsOverTls(query)

    private fun forwardDnsOverTls(query: ByteArray): ByteArray? = synchronized(dotLock) {
        if (query.size !in 12..65535) return@synchronized null

        val endpoint = Prefs.dnsEndpoint(this)
        if (endpoint == null) {
            Prefs.setLastDnsError(
                this,
                "DNS provider is invalid. Check the custom hostname and bootstrap IPv4 address."
            )
            Prefs.increment(this, "dns_errors")
            return@synchronized null
        }

        val endpointKey = "${endpoint.hostname}|${endpoint.bootstrapIps.joinToString(",")}"

        // Switching provider closes the previous provider's encrypted connection.
        if (dotEndpointKey != endpointKey) closeDotConnection()

        val diagnostics = ArrayList<String>()

        // First try the existing persistent TLS connection.
        val existing = dotSocket
        if (existing != null && !existing.isClosed && existing.isConnected) {
            try {
                val response = exchangeDot(existing, query)
                Prefs.setLastDnsError(
                    this,
                    "SUCCESS: persistent DoT ${endpoint.hostname}:853 via $dotBootstrapIp"
                )
                return@synchronized response
            } catch (e: Exception) {
                diagnostics.add(
                    "$dotBootstrapIp reused-connection=${e.javaClass.simpleName}:${e.message ?: "failed"}"
                )
                closeDotConnection()
            }
        }

        // Bootstrap IPs are numeric and are used only for the TCP route.
        // TLS SNI and certificate verification always use endpoint.hostname.
        for (bootstrapIp in endpoint.bootstrapIps) {
            var candidate: SSLSocket? = null
            try {
                candidate = connectDot(endpoint, bootstrapIp)
                val response = exchangeDot(candidate, query)

                dotSocket = candidate
                dotEndpointKey = endpointKey
                dotBootstrapIp = bootstrapIp
                candidate = null // ownership transferred to dotSocket

                Prefs.setLastDnsError(
                    this,
                    "SUCCESS: DoT ${endpoint.hostname}:853 via $bootstrapIp"
                )
                return@synchronized response
            } catch (e: Exception) {
                diagnostics.add(
                    "$bootstrapIp ${e.javaClass.simpleName}:${e.message ?: "failed"}"
                )
            } finally {
                try { candidate?.close() } catch (_: Exception) {}
            }
        }

        closeDotConnection()
        Prefs.increment(this, "dns_errors")
        Prefs.setLastDnsError(
            this,
            "DoT failed for ${endpoint.hostname}: " + diagnostics.joinToString(" | ")
        )
        null
    }

    private fun connectDot(
        endpoint: Prefs.DnsEndpoint,
        bootstrapIp: String
    ): SSLSocket {
        val raw = Socket()
        try {
            // Bind first, then protect, then connect. This prevents the upstream
            // connection from being routed back into this VPN's virtual DNS.
            raw.bind(InetSocketAddress(0))
            if (!protect(raw)) {
                throw java.io.IOException("VpnService.protect(socket) returned false")
            }

            val address = InetAddress.getByName(bootstrapIp) // numeric IPv4 bootstrap only
            raw.connect(InetSocketAddress(address, 853), 4500)
            raw.tcpNoDelay = true
            raw.soTimeout = 5000

            // The bootstrap IP is used for routing; hostname is used for TLS SNI
            // and certificate identity verification.
            val tls = (SSLSocketFactory.getDefault() as SSLSocketFactory)
                .createSocket(raw, endpoint.hostname, 853, true) as SSLSocket

            tls.soTimeout = 5000

            val supported = tls.supportedProtocols.toSet()
            val secureProtocols = listOf("TLSv1.3", "TLSv1.2")
                .filter { it in supported }
            if (secureProtocols.isEmpty()) {
                tls.close()
                throw java.io.IOException("TLS 1.2 or newer is unavailable")
            }
            tls.enabledProtocols = secureProtocols.toTypedArray()

            tls.startHandshake()

            // Verify the certificate identity against the DoT hostname.
            // The layered socket hostname supplies SNI; this checks the peer name.
            if (!HttpsURLConnection.getDefaultHostnameVerifier().verify(
                    endpoint.hostname, tls.session
                )
            ) {
                tls.close()
                throw SSLPeerUnverifiedException(
                    "TLS certificate does not match ${endpoint.hostname}"
                )
            }

            return tls
        } catch (e: Exception) {
            try { raw.close() } catch (_: Exception) {}
            throw e
        }
    }

    private fun exchangeDot(socket: SSLSocket, query: ByteArray): ByteArray {
        val output = DataOutputStream(socket.outputStream)
        output.writeShort(query.size)
        output.write(query)
        output.flush()

        val input = DataInputStream(socket.inputStream)
        val responseLength = input.readUnsignedShort()
        if (responseLength < 12) {
            throw java.io.IOException("Invalid DoT response length: $responseLength")
        }

        val response = ByteArray(responseLength)
        input.readFully(response)

        if (!validDnsResponse(query, response)) {
            throw java.io.IOException("DNS response validation failed")
        }

        return response
    }

    private fun closeDotConnection() {
        synchronized(dotLock) {
            try { dotSocket?.close() } catch (_: Exception) {}
            dotSocket = null
            dotEndpointKey = null
            dotBootstrapIp = null
        }
    }

    private fun validDnsResponse(query: ByteArray, response: ByteArray): Boolean =
        response.size >= 12 && u16(response, 0) == u16(query, 0) &&
            (u16(response, 2) and 0x8000) != 0

    // TCP DNS: a small purpose-built TCP endpoint on the virtual DNS address.
    private fun handleTcp(packet: ByteArray, ipv6: Boolean, ipOffset: Int, output: FileOutputStream) {
        val tcp = ipOffset
        if (packet.size < tcp + 20 || u16(packet, tcp + 2) != DNS_PORT) return
        if (ipv6) Prefs.increment(this, "ipv6_dns_received")
        val headerLen = ((packet[tcp + 12].toInt() ushr 4) and 0x0F) * 4
        if (headerLen < 20 || packet.size < tcp + headerLen) return
        val flags = packet[tcp + 13].toInt() and 0xFF
        val srcPort = u16(packet, tcp)
        val seq = u32(packet, tcp + 4)
        val ack = u32(packet, tcp + 8)
        val payload = packet.copyOfRange(tcp + headerLen, packet.size)
        val clientIp = if (ipv6) packet.copyOfRange(8, 24) else packet.copyOfRange(12, 16)
        val serverIp = if (ipv6) packet.copyOfRange(24, 40) else packet.copyOfRange(16, 20)
        val key = (if (ipv6) "6" else "4") + ":" +
            clientIp.joinToString("") { "%02x".format(it) } + ":" +
            serverIp.joinToString("") { "%02x".format(it) } + ":$srcPort"

        if ((flags and 0x04) != 0) { tcpSessions.remove(key); return }
        if ((flags and 0x02) != 0) {
            val old = tcpSessions[key]
            if (old != null) {
                writeTunPacket(output, makeTcpPacket(old, old.serverNext, old.clientNext, 0x12, ByteArray(0)))
                return
            }
            val serverSeq = (System.nanoTime() and 0x7FFFFFFFL) + 1L
            val session = TcpSession(
                key, ipv6, clientIp, serverIp, srcPort, DNS_PORT,
                (seq + 1L) and 0xFFFFFFFFL, (serverSeq + 1L) and 0xFFFFFFFFL
            )
            tcpSessions[key] = session
            writeTunPacket(output, makeTcpPacket(session, serverSeq, session.clientNext, 0x12, ByteArray(0)))
            return
        }
        val session = tcpSessions[key] ?: return
        synchronized(session) {
            if ((flags and 0x01) != 0) {
                session.clientNext = (seq + payload.size + 1L) and 0xFFFFFFFFL
                writeTunPacket(output, makeTcpPacket(session, session.serverNext, session.clientNext, 0x11, ByteArray(0)))
                tcpSessions.remove(key)
                return
            }
            if (payload.isEmpty()) return
            if (seq != session.clientNext) {
                // Duplicate/out-of-order segment: acknowledge the next expected byte.
                if (seq < session.clientNext) session.lastResponse.forEach { writeTunPacket(output, it) }
                writeTunPacket(output, makeTcpPacket(session, session.serverNext, session.clientNext, 0x10, ByteArray(0)))
                return
            }
            session.clientNext = (session.clientNext + payload.size) and 0xFFFFFFFFL
            session.input.write(payload)
            writeTunPacket(output, makeTcpPacket(session, session.serverNext, session.clientNext, 0x10, ByteArray(0)))

            var bytes = session.input.toByteArray()
            while (bytes.size >= 2) {
                val dnsLength = u16(bytes, 0)
                if (dnsLength == 0 || bytes.size < dnsLength + 2) break
                val query = bytes.copyOfRange(2, dnsLength + 2)
                val domain = readQuestionName(query)
                val category = domain?.let { blockedCategory(it) }
                val answer = if (category != null) {
                    Prefs.increment(this, "total_blocked")
                    Prefs.increment(this, "blocked_$category")
                    buildNxDomainResponse(query)
                } else {
                    val forwarded = forwardDnsTcp(query)
                    if (forwarded == null) {
                        Prefs.increment(this, "dns_errors")
                        null
                    } else forwarded
                }
                if (answer != null) {
                    val framed = ByteArray(answer.size + 2)
                    put16(framed, 0, answer.size)
                    System.arraycopy(answer, 0, framed, 2, answer.size)
                    val packets = sendTcpData(session, framed, output)
                    session.lastResponse = packets
                    session.lastResponseEnd = session.serverNext
                    if (ipv6) Prefs.increment(this, "ipv6_dns_processed")
                }
                bytes = bytes.copyOfRange(dnsLength + 2, bytes.size)
            }
            session.input.reset()
            session.input.write(bytes)
        }
    }

    private fun sendTcpData(session: TcpSession, data: ByteArray, output: FileOutputStream): List<ByteArray> {
        val packets = ArrayList<ByteArray>()
        var offset = 0
        while (offset < data.size) {
            val end = (offset + TCP_MSS).coerceAtMost(data.size)
            val part = data.copyOfRange(offset, end)
            val packet = makeTcpPacket(session, session.serverNext, session.clientNext, 0x18, part)
            writeTunPacket(output, packet)
            packets.add(packet)
            session.serverNext = (session.serverNext + part.size) and 0xFFFFFFFFL
            offset = end
        }
        return packets
    }

    private fun makeTcpPacket(
        s: TcpSession, sequence: Long, acknowledgement: Long, flags: Int, payload: ByteArray
    ): ByteArray {
        val tcpLen = 20 + payload.size
        val ipLen = if (s.ipv6) 40 else 20
        val packet = ByteArray(ipLen + tcpLen)
        if (s.ipv6) {
            packet[0] = 0x60
            put16(packet, 4, tcpLen)
            packet[6] = 6
            packet[7] = 64
            System.arraycopy(s.serverIp, 0, packet, 8, 16)
            System.arraycopy(s.clientIp, 0, packet, 24, 16)
        } else {
            packet[0] = 0x45
            put16(packet, 2, packet.size)
            put16(packet, 4, 0)
            put16(packet, 6, 0)
            packet[8] = 64
            packet[9] = 6
            System.arraycopy(s.serverIp, 0, packet, 12, 4)
            System.arraycopy(s.clientIp, 0, packet, 16, 4)
        }
        val t = ipLen
        put16(packet, t, s.serverPort)
        put16(packet, t + 2, s.clientPort)
        put32(packet, t + 4, sequence)
        put32(packet, t + 8, acknowledgement)
        packet[t + 12] = 0x50
        packet[t + 13] = flags.toByte()
        put16(packet, t + 14, 32768)
        put16(packet, t + 16, 0)
        put16(packet, t + 18, 0)
        if (payload.isNotEmpty()) System.arraycopy(payload, 0, packet, t + 20, payload.size)
        val checksum = tcpChecksum(packet, ipLen, tcpLen, s.ipv6)
        put16(packet, t + 16, checksum)
        if (!s.ipv6) put16(packet, 10, ipv4HeaderChecksum(packet, 20))
        return packet
    }

    private fun buildIpv4UdpResponse(request: ByteArray, ihl: Int, dns: ByteArray): ByteArray {
        val udpLength = 8 + dns.size
        val response = ByteArray(ihl + udpLength)
        System.arraycopy(request, 0, response, 0, ihl)
        System.arraycopy(request, 16, response, 12, 4)
        System.arraycopy(request, 12, response, 16, 4)
        response[0] = ((4 shl 4) or (ihl / 4)).toByte()
        put16(response, 2, response.size)
        put16(response, 6, 0)
        response[8] = 64
        response[9] = 17
        put16(response, 10, 0)
        put16(response, 10, ipv4HeaderChecksum(response, ihl))
        put16(response, ihl, u16(request, ihl + 2))
        put16(response, ihl + 2, u16(request, ihl))
        put16(response, ihl + 4, udpLength)
        put16(response, ihl + 6, 0)
        System.arraycopy(dns, 0, response, ihl + 8, dns.size)
        return response
    }

    private fun buildIpv6UdpResponse(request: ByteArray, udpOffset: Int, dns: ByteArray): ByteArray {
        val udpLength = 8 + dns.size
        val response = ByteArray(40 + udpLength)
        response[0] = 0x60
        put16(response, 4, udpLength)
        response[6] = 17
        response[7] = 64
        System.arraycopy(request, 24, response, 8, 16)
        System.arraycopy(request, 8, response, 24, 16)
        put16(response, 40, u16(request, udpOffset + 2))
        put16(response, 42, u16(request, udpOffset))
        put16(response, 44, udpLength)
        put16(response, 46, 0)
        System.arraycopy(dns, 0, response, 48, dns.size)
        put16(response, 46, udpChecksum(response, 40, udpLength, true))
        return response
    }

    private fun ipv4HeaderChecksum(packet: ByteArray, length: Int): Int {
        var sum = 0L
        var i = 0
        while (i + 1 < length) { sum += u16(packet, i); i += 2 }
        if (i < length) sum += (packet[i].toInt() and 0xFF) shl 8
        while ((sum ushr 16) != 0L) sum = (sum and 0xFFFF) + (sum ushr 16)
        return sum.inv().toInt() and 0xFFFF
    }

    private fun udpChecksum(packet: ByteArray, offset: Int, length: Int, ipv6: Boolean): Int =
        transportChecksum(packet, offset, length, ipv6, 17)

    private fun tcpChecksum(packet: ByteArray, offset: Int, length: Int, ipv6: Boolean): Int =
        transportChecksum(packet, offset, length, ipv6, 6)

    private fun transportChecksum(packet: ByteArray, offset: Int, length: Int, ipv6: Boolean, protocol: Int): Int {
        var sum = 0L
        if (ipv6) {
            for (i in 8 until 40 step 2) sum += u16(packet, i).toLong()
            sum += ((length ushr 16) and 0xFFFF).toLong()
            sum += (length and 0xFFFF).toLong()
            sum += protocol.toLong()
        } else {
            sum += u16(packet, 12).toLong() + u16(packet, 14) + u16(packet, 16) + u16(packet, 18)
            sum += protocol.toLong() + length.toLong()
        }
        var i = offset
        val end = offset + length
        while (i + 1 < end) { sum += u16(packet, i).toLong(); i += 2 }
        if (i < end) sum += (packet[i].toInt() and 0xFF).toLong() shl 8
        while ((sum ushr 16) != 0L) sum = (sum and 0xFFFF) + (sum ushr 16)
        val result = sum.inv().toInt() and 0xFFFF
        return if (result == 0) 0xFFFF else result
    }

    private fun writeTunPacket(output: FileOutputStream, packet: ByteArray) {
        synchronized(output) {
            if (running) { output.write(packet); output.flush() }
        }
    }

    private fun u16(b: ByteArray, o: Int): Int =
        ((b[o].toInt() and 0xFF) shl 8) or (b[o + 1].toInt() and 0xFF)

    private fun u32(b: ByteArray, o: Int): Long =
        ((b[o].toLong() and 0xFF) shl 24) or
            ((b[o + 1].toLong() and 0xFF) shl 16) or
            ((b[o + 2].toLong() and 0xFF) shl 8) or
            (b[o + 3].toLong() and 0xFF)

    private fun put16(b: ByteArray, o: Int, value: Int) {
        b[o] = (value ushr 8).toByte(); b[o + 1] = value.toByte()
    }

    private fun put32(b: ByteArray, o: Int, value: Long) {
        b[o] = (value ushr 24).toByte()
        b[o + 1] = (value ushr 16).toByte()
        b[o + 2] = (value ushr 8).toByte()
        b[o + 3] = value.toByte()
    }
}
