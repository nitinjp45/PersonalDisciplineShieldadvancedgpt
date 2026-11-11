
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.personaldisciplineshield"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.personaldisciplineshield"
        minSdk = 23
        targetSdk = 35
        versionCode = 7
        versionName = "0.4.5"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    // Needed so the optional nsfw.tflite model can be memory-mapped from assets.
    androidResources {
        noCompress += "tflite"
    }
}

dependencies {
    implementation("org.tensorflow:tensorflow-lite:2.14.0")
}
