package com.personaldisciplineshield

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (!Prefs.vpnWanted(context)) return
        if (VpnService.prepare(context) != null) return // permission no longer granted
        val i = Intent(context, DnsVpnService::class.java)
        try {
            if (Build.VERSION.SDK_INT >= 26) context.startForegroundService(i) else context.startService(i)
        } catch (_: Exception) {}
    }
}
