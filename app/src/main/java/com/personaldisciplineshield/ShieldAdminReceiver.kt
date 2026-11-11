package com.personaldisciplineshield

import android.app.admin.DeviceAdminReceiver
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.Build

/** Standard Device Admin can support screen locking; OS-level uninstall blocking requires Device Owner. */
class ShieldAdminReceiver : DeviceAdminReceiver() {

    override fun onEnabled(context: Context, intent: Intent) {
        applyOwnerPolicies(context)
    }

    override fun onDisableRequested(context: Context, intent: Intent): CharSequence =
        "Turning this off disables Shield admin safeguards. Standard Device Admin does not prevent uninstall."

    companion object {
        /**
         * Only takes effect if the app was made Device Owner over adb (optional, see README):
         *   adb shell dpm set-device-owner com.personaldisciplineshield/.ShieldAdminReceiver
         */
        fun applyOwnerPolicies(c: Context) {
            val dpm = c.getSystemService(DevicePolicyManager::class.java) ?: return
            if (!dpm.isDeviceOwnerApp(c.packageName)) return
            val cn = ComponentName(c, ShieldAdminReceiver::class.java)
            try { dpm.setUninstallBlocked(cn, c.packageName, true) } catch (_: Exception) {}
            if (Build.VERSION.SDK_INT >= 24) {
                // lockdown=false on purpose: true cuts internet whenever the VPN is down.
                try { dpm.setAlwaysOnVpnPackage(cn, c.packageName, false) } catch (_: Exception) {}
            }
        }
    }
}
