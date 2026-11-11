# Stage 4.2 Device Test Plan

Keep **Settings app lockdown OFF** for this entire first test pass. Do not set the permanent PIN until basic functions pass.

## 1. Install and DNS baseline
- Build APK using GitHub Actions and install it over the existing app.
- Open the app and enable DNS protection. Confirm VPN key/icon appears.
- Test ordinary browsing and DNS blocking for one known blocked domain.
- Confirm Wi-Fi and mobile data still work.
- Reboot once and confirm Always-on VPN returns.

## 2. Essential system access
- Open Android Settings, Wi-Fi, Bluetooth and Hotspot.
- Open app permissions and app info.
- Make a phone call and open the notification shade / Quick Settings.
- Confirm none of these screens is sent Home by the blocked-app feature.

## 3. Accessibility features
- Enable Accessibility service.
- Block one non-essential test app and confirm it returns Home.
- Remove that test app from the block list and confirm it opens normally.
- Test one keyword in a browser search box.
- Confirm WhatsApp Chats, Calls and Groups remain usable. Test Updates/Channels only if that feature is enabled.

## 4. MIUI background survival
- Enable Autostart for Shield.
- Set Battery to No restrictions.
- Lock Shield in Recents.
- Leave the phone idle and confirm VPN remains active.

## 5. PIN timing
- Only after the above tests pass, ask a trusted person to set the PIN.
- Confirm a protection change is blocked while locked.
- Request unlock and verify the wait countdown. The timer is monotonic and a reboot expires any pending unlock safely.

## 6. Optional Settings lockdown (separate, high caution)
- Leave OFF unless you have a recovery path.
- If you decide to test, do so before setting a PIN, with no critical task in progress.
- Verify Wi-Fi, Bluetooth, Hotspot, app permissions, Accessibility settings, battery/autostart and app info.
- If any required page is blocked, disable lockdown before arming the PIN.
