plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.vguest.app"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.vguest.app"
        minSdk = 28
        // targetSdk 28 places the app in untrusted_app_27 on Android 13 so
        // extracted AOSP 12 binaries in filesDir/rootfs remain executable (W^X).
        @Suppress("ExpiredTargetSdkVersion")
        targetSdk = 28
        versionCode = 1
        versionName = "0.4.0-phase4"

        ndk {
            abiFilters += listOf("arm64-v8a")
        }
    }

    signingConfigs {
        create("vguestDebug") {
            storeFile = file("vguest-debug.keystore")
            storePassword = "android"
            keyAlias = "vguestdebug"
            keyPassword = "android"
        }
    }

    buildTypes {
        debug {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("vguestDebug")
        }
        release {
            isMinifyEnabled = false
        }
    }

    packaging {
        jniLibs {
            // Ensure libguest_runner.so is extracted to nativeLibraryDir as an executable file
            useLegacyPackaging = true
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    lint {
        abortOnError = false
        checkReleaseBuilds = false
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.12.0")
    implementation("androidx.appcompat:appcompat:1.6.1")
    implementation("com.github.luben:zstd-jni:1.5.5-11@aar")
    implementation("org.apache.commons:commons-compress:1.26.1")
}
