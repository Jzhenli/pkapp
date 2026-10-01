package com.pkapp.shell

import android.util.Log
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** 壳日志：logcat + filesDir/cache/log 双写（协议 §7 的 Android 形态）。
 *  C 泵线程持有同一路径的 fd 追加写 Python 侧输出；本类承担 Java 侧锚点与按天轮转留 7 份。 */
object ShellLog {
    private lateinit var logFile: File
    private const val TAG = "shell"

    fun init(logDir: File, appName: String) {
        val date = SimpleDateFormat("yyyyMMdd", Locale.US).format(Date())
        logFile = File(logDir, "$appName-$date.log")
        // 轮转清理：按天命名 + mtime 双重判据（同 Windows 壳）
        val cutoff = System.currentTimeMillis() - 7L * 86400_000
        logDir.listFiles()?.forEach {
            if (it.name.startsWith("$appName-") && it.name.endsWith(".log") && it.lastModified() < cutoff)
                it.delete()
        }
    }

    fun slog(msg: String) {
        Log.i(TAG, msg)
        try {
            if (::logFile.isInitialized)
                logFile.appendText("${SimpleDateFormat("MM-dd HH:mm:ss.SSS", Locale.US).format(Date())} [shell] $msg\n")
        } catch (_: Exception) {
            // 日志不可写（cache 被清等）不得反噬壳
        }
    }
}
