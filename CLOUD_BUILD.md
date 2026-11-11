# GitHub Actions cloud build

The workflow is `.github/workflows/build-apk.yml`.

It runs on pushes to `main` and can also be started manually from the GitHub Actions tab. It uses JDK 17, Gradle 8.9, Android SDK setup, and builds `:app:assembleDebug`. The resulting APK is uploaded as a 14-day GitHub Actions artifact.

The current app is a non-blocking Stage 1 dashboard. It is not a content blocker yet.
