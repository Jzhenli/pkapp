plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.pkapp.shell"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.pkapp.shell"
        minSdk = 24
        targetSdk = 35
        versionCode = 1
        versionName = "0.2.0"
        // M2 真机回归：arm64-v8a 单 ABI（模拟器 x86_64 时在 ndk.abiFilters 增补并重跑 prepare_runtime.py）
        ndk { abiFilters += listOf("arm64-v8a") }
        externalNativeBuild { cmake { arguments += listOf("-DANDROID_STL=none") } }
    }
    externalNativeBuild { cmake { path = file("src/main/cpp/CMakeLists.txt"); version = "3.22.1" } }
    // libpython 与扩展 .so 需解压到 nativeLibraryDir（applocal _inject_native 经
    // MYAPP_NATIVE_LIB_DIR 按目录预载 + sys.path 注入，协议 §4.4 W^X 形态）
    packaging { jniLibs { useLegacyPackaging = true } }
    androidResources { noCompress += "spk" }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}
