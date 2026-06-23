plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.benjaminchodroff.trezorcore"
    compileSdk = 34

    defaultConfig {
        minSdk = 26  // Android 8.0; Ledger Live and most BLE wallet apps draw the line here.
        consumerProguardFiles("consumer-rules.pro")

        // The .so files cargo-ndk drops into src/main/jniLibs/<abi>/
        // are picked up automatically by AGP. No ndk{} block needed
        // because we're not invoking ndkBuild ourselves.
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    // UniFFI-generated Kotlin glue uses JNA to load the native lib.
    // Pin to a recent stable.
    implementation("net.java.dev.jna:jna:5.14.0@aar")

    // Coroutines for async-callback support that UniFFI's async
    // bindings rely on.
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
}
