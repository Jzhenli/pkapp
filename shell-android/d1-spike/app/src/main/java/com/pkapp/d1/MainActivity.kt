package com.pkapp.d1

import android.app.Activity
import android.os.Build
import android.os.Bundle
import android.util.Log
import java.io.File

/** D1 硬闸入口：载 libpython → 载 JNI 壳 → bootPython()；logcat tag D1 / py-print。 */
class MainActivity : Activity() {
    companion object { const val TAG = "D1" }

    external fun bootPython(stdlibPath: String): Int

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Log.i(TAG, "onCreate device=${Build.MODEL} abi=${Build.SUPPORTED_ABIS.joinToString(",")}")
        try {
            val nativeDir = applicationInfo.nativeLibraryDir
            System.load(File(nativeDir, "libpython3.12.so").absolutePath)
            Log.i(TAG, "libpython3.12.so loaded")
            System.load(File(nativeDir, "libpython_boot.so").absolutePath)
            Log.i(TAG, "libpython_boot.so loaded")

            val stdlib = File(filesDir, "stdlib.zip")
            if (!stdlib.exists()) {
                assets.open("stdlib.zip").use { input ->
                    stdlib.outputStream().use { input.copyTo(it) }
                }
            }
            Log.i(TAG, "stdlib.zip ready (${stdlib.length()} B) at ${stdlib.absolutePath}")
            val rc = bootPython(stdlib.absolutePath)
            Log.i(TAG, "bootPython rc=$rc")
        } catch (t: Throwable) {
            Log.e(TAG, "boot failed", t)
        }
    }
}
