# Stage 2 test plan

1. Install the Stage 2 APK over Stage 1 (same application ID/signing key from the same GitHub repository workflow).
2. Open the app. Do not enable Android VPN lockdown.
3. Tap Enable DNS Protection and accept Android's VPN permission prompt.
4. Confirm the persistent VPN notification appears.
5. Test a normal site, such as example.com.
6. Test a listed blocked domain, such as youtube.com or pornhub.com.
7. Tap Turn Protection Off and confirm normal browsing resumes.
8. If normal browsing fails while protection is on, turn it off immediately and report the result.

Do not treat this prototype as a complete safety barrier. It is a limited DNS filtering experiment.
