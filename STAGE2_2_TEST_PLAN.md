# Stage 2.2 test plan

1. Install the APK and open the app.
2. Leave all category switches enabled initially.
3. Add a test domain to Custom domains, e.g. `example.org`, and confirm it appears in the list.
4. Enable DNS Protection and approve Android's VPN permission.
5. Confirm an ordinary site such as `example.com` still opens.
6. Confirm a domain in an enabled category is blocked.
7. Turn one category off and test again; that category should no longer be blocked.
8. Check that counters increase after blocked requests.
9. Turn protection off and confirm normal internet access returns.
10. Restart the app and confirm switches/custom domains remain saved.

If connectivity behaves unexpectedly, tap Turn Protection Off. You can also disconnect the VPN under Android Settings > Network & internet > VPN.

Do not enable “Block connections without VPN” during testing.
