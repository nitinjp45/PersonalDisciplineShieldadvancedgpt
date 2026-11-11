# Personal Discipline Shield — Stage 4.2 Safety Update

This update is based on the latest supplied Claude source. It preserves the DNS VPN implementation and the added MIUI/Redmi setup helpers, optional Settings allow-list lockdown, and WhatsApp Channels/Updates blocking.

## Included
- DNS-only VPN protection and the existing domain categories/custom blocklist.
- PIN + waiting-time lock. The unlock timer now uses Android's monotonic elapsed clock rather than the changeable wall clock. A reboot safely expires a pending unlock window.
- Accessibility-based blocked-app and keyword enforcement, plus the existing Settings/uninstall-screen guard.
- Safety exclusions: the launcher, Android/MIUI Settings, System UI, permission controllers, installers, phone/telecom and core settings providers cannot be selected or blocked by the app-block list.
- MIUI/Redmi Autostart, battery restriction and Recents-lock helper shortcuts.
- Optional Settings page allow-list lockdown (OFF by default). Test carefully before enabling; OEM labels and screen structures can vary.
- WhatsApp Channels/Updates tab blocking (English UI/accessibility labels; may change with WhatsApp updates).
- Device Admin can support the screen-lock safeguard. **Standard Device Admin does not prevent uninstall.** OS-level uninstall blocking requires Device Owner authority, which is not available through ordinary Device Admin activation.

## Safe installation and test order
1. Build/install the APK from GitHub Actions.
2. Open the app and test DNS protection first. Keep Settings lockdown OFF.
3. Enable Device Admin if you want the repeated-strike screen-lock safeguard.
4. Enable the Accessibility service and test blocked apps/keywords.
5. On MIUI/Redmi, enable Autostart, set Battery to No restrictions, and lock the app in Recents.
6. Test Wi-Fi, Bluetooth, hotspot, calls, app permissions and reboot recovery.
7. Only after these tests, consider setting the PIN. Keep Settings lockdown OFF until separately tested on the device.

## Important limitations
- A determined device owner can still bypass/remove an ordinary app. Standard Device Admin is not uninstall protection. Device Owner provisioning is a separate managed-device setup and can require a fresh/reset device; do not attempt it on a personal phone without understanding the consequences.
- Settings lockdown is heuristic and can block an unexpected OEM Settings page. It is disabled by default. Do not enable it unless you have tested recovery and the allow-list on this exact device/MIUI version.
- WhatsApp tab detection depends on the English accessibility labels and may stop working after WhatsApp updates or with another app language.
- Image classification is unavailable until a compatible, licensed `nsfw.tflite` model is supplied in `app/src/main/assets/`. The project currently does not include that model; do not enable image blocking expecting it to work.
- Accessibility keyword blocking can only inspect text exposed by Android accessibility APIs. Apps using protected/hidden content, alternate browsers, private DNS or their own encrypted DNS may bypass domain/keyword checks.
- No software-only setup is tamper-proof against safe mode, ADB access, factory reset or removal of required permissions.

## Build
Push the project to GitHub and run the existing **Build APK** workflow under Actions. The DNS VPN source (`DnsVpnService.kt`) is intentionally unchanged in this update.
