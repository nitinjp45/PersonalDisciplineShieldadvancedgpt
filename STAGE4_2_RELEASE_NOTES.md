# Stage 4.2 Release Notes

- Integrated monotonic-clock PIN wait/open timing from the safety patch. Existing wall-clock unlock requests are intentionally not migrated; the new timer key starts locked safely.
- Added hard exclusions for core Android/MIUI packages in both the app picker and runtime blocked-app enforcement.
- Corrected Device Admin wording: ordinary Device Admin does not block uninstall; Device Owner is required for OS-level uninstall blocking.
- Retained the latest Settings allow-list lockdown and WhatsApp Channels/Updates feature additions. Settings lockdown remains OFF by default.
- `DnsVpnService.kt` is byte-for-byte unchanged from the supplied latest source.
- NSFW model remains absent; image classification cannot operate until a compatible model is supplied.
