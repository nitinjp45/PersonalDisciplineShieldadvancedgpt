# Stage 4.3 device test plan

1. Build/install the APK; leave Settings lockdown OFF initially.
2. Open WhatsApp Chats. Confirm it stays open. Confirm switching to an unselected Channels label does not trigger blocking.
3. Select Channels/Updates. Confirm the app returns to Chats if the Chats tab is exposed. Confirm WhatsApp does not close.
4. If WhatsApp remains in Channels/Updates because its tab controls are not exposed to Accessibility, capture the accessibility diagnostic rather than relying on Back navigation.
5. Set/arm PIN, lock the guard, enable Settings lockdown.
6. Open Settings home: it should return Home.
7. Open Wi-Fi, Bluetooth and Hotspot using the app shortcuts: these should remain accessible.
8. Navigate back to Settings home from an allowed connectivity page: it should be blocked again.
9. Verify Quick Settings tiles, calls, mobile data and Bluetooth still work.
10. Verify DNS VPN IPv4/IPv6 UDP/TCP tests from the Stage 3B.2 test plan.
