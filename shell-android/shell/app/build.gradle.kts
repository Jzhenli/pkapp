plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// release 签名（★v1.2★）：pkapp 经 -PpkappKs/-PpkappKsPass/-PpkappKsAlias 注入
//（密码只走 env→-P 链，不落文件）；无 property = 直接构建壳工程，release 不挂签名
val ksFile = project.findProperty("pkappKs") as String?
val ksPass = project.findProperty("pkappKsPass") as String?
val ksAlias = project.findProperty("pkappKsAlias") as String? ?: "pkapp"

android {
    namespace = "com.pkapp.shell"
    compileSdk = 35
    // 显式锁定 NDK（消除 AGP 默认值漂移；pkapp fetch android 的 ndk-27 pin 锁定同一版本）
    ndkVersion = "27.0.12077973"

    signingConfigs {
        if (ksFile != null && ksPass != null) {
            create("pkapp") {
                storeFile = file(ksFile)
                storePassword = ksPass
                keyAlias = ksAlias
                keyPassword = ksPass
            }
        }
    }

    buildTypes {
        getByName("release") {
            if (ksFile != null && ksPass != null) {
                signingConfig = signingConfigs.getByName("pkapp")
            }
        }
    }

    defaultConfig {
        // applicationId 由 pkapp 按项目 [platforms.android].package 经 -PpkappAppId 注入
        //（无 property 时回退默认 = 直接用 gradle 构建壳工程）。namespace 保持不变：
        // R 类/Activity 类路径与安装身份（applicationId）分离是 Android 常规形态
        applicationId = project.findProperty("pkappAppId") as String? ?: "com.pkapp.shell"
        // 应用显示名（★v1.2★）：项目 app.name 经 -PpkappLabel 注入；缺省 = 直接构建壳
        manifestPlaceholders["pkappLabel"] =
            project.findProperty("pkappLabel") as String? ?: "PKApp Shell"
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
