plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.pkapp.spike"
    compileSdk = 35   // 本机工具链仅装 android-35 平台；targetSdk 仍 34
    buildToolsVersion = "35.0.0"   // 本机工具链仅有 35.0.0
    defaultConfig {
        applicationId = "com.pkapp.spike"
        minSdk = 28
        targetSdk = 34
    }
    buildTypes {
        release { isMinifyEnabled = false }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}
