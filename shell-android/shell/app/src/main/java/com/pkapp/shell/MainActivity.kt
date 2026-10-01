package com.pkapp.shell

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.Process
import android.os.SystemClock
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.webkit.WebResourceError
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Button
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import java.io.File
import java.security.SecureRandom
import java.util.zip.ZipInputStream

/** M2 Android 壳（SHELL_PROTOCOL §10.2 九步投影）：
 *  0 单实例=launcher/singleTask；1 验签=APK 签名；2 指纹比对/全量解压（staging→原子让位）；
 *  3 预清理 ready/握手码；4 env 注入（JNI setenv）；5 stdio 泵（engine.c）；
 *  6 libpython 已随 APK；7 runtime.version 记账；8 bootstrap→归 GIL；
 *  8.5/9 主 looper Handler 轮询 ready（= Windows WM_TIMER）+ 握手码导航（★v1.2★ 镜像语义）。
 *  线程模型：boot 在后台线程（Android 禁阻塞 UI——ANR），轮询恒在主 looper（协议禁独立轮询线程）。 */
class MainActivity : Activity() {

    companion object {
        init { System.loadLibrary("engine") }
        private const val TICK_MS = 500L
        private const val BOOT_TIMEOUT_MS = 120_000L      // §5 冷启动独立档
        private const val HEARTBEAT_DEAD_MS = 30_000L     // §5 seq 判死窗口
        private const val PH_COLD = 0
        private const val PH_RUNTIME = 1
        private const val PH_DEAD = 2
    }

    private external fun engineBoot(pairs: Array<String>, entry: String, logPath: String): Int
    private external fun engineOnBackground()

    private lateinit var root: FrameLayout
    private lateinit var loading: TextView
    private var webview: WebView? = null
    private val main = Handler(Looper.getMainLooper())

    @Volatile private var phase = PH_COLD
    @Volatile private var booted = false
    private var bootStart = 0L
    private var lastSeq = -1L
    private var lastSeqChange = 0L
    private var port = 0L

    private lateinit var dataDir: File
    private lateinit var cache: File
    private lateinit var logDir: File
    private lateinit var runtimeDir: File
    private lateinit var readyFile: File
    private lateinit var diagFile: File
    private lateinit var handshakeFile: File
    private lateinit var logFile: File

    // ---------------------------------------------------------------- 生命周期
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val files = filesDir
        dataDir = File(files, "data"); cache = File(files, "cache")
        logDir = File(cache, "log"); runtimeDir = File(files, "runtime")
        readyFile = File(cache, "ready"); diagFile = File(cache, "diag.json")
        handshakeFile = File(cache, "handshake")
        for (d in arrayOf(dataDir, cache, logDir)) d.mkdirs()
        val appName = packageName.substringAfterLast('.')
        ShellLog.init(logDir, appName)
        logFile = File(logDir, "$appName-${java.text.SimpleDateFormat("yyyyMMdd", java.util.Locale.US).format(java.util.Date())}.log")

        buildUi()
        startService(Intent(this, BootService::class.java))
        Thread { boot() }.start()
    }

    override fun onPause() {
        super.onPause()
        if (booted) engineOnBackground()
    }

    override fun onResume() {
        super.onResume()
        // MagicOS 会冻结后台进程（实测：切后台约 1s 后心跳冻结，回前台立即恢复）。
        // 冻结期间 uptimeMillis 照走而 tick 不跑，回前台首拍 now-lastSeqChange
        // 会虚超 30s → 假错误页。恢复可见即重置宽限窗，给心跳一拍追赶时间。
        if (booted) lastSeqChange = SystemClock.uptimeMillis()
    }

    override fun onDestroy() {
        super.onDestroy()
        main.removeCallbacksAndMessages(null)
    }

    // ---------------------------------------------------------------- UI（加载层/错误页，§9 绝不黑屏）
    private fun buildUi() {
        root = FrameLayout(this)
        loading = TextView(this).apply {
            gravity = Gravity.CENTER
            textSize = 18f
            setTextColor(0xFF555555.toInt())
            setTypeface(android.graphics.Typeface.DEFAULT_BOLD)
            setBackgroundColor(0xFFFFFFFF.toInt())
            text = "正在启动，请稍候…"
        }
        root.addView(loading, FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
        setContentView(root)
    }

    /** C 侧 JNI 回调（boot 线程）——阶段文案镜像 Windows set_splash 四阶段。 */
    fun setBootStage(text: String) {
        runOnUiThread { setStage(text) }
    }

    private fun setStage(text: String) {
        if (::loading.isInitialized) loading.text = text
    }

    private fun hideLoading() {
        if (::loading.isInitialized) loading.visibility = View.GONE
    }

    private fun showError(msg: String, recoverable: Boolean) {
        phase = PH_DEAD
        main.removeCallbacks(tick)
        hideLoading()
        webview?.visibility = View.GONE
        val box = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(0xFFFFFFFF.toInt())
            setPadding(px(24), px(48), px(24), px(24))
        }
        box.addView(TextView(this).apply {
            text = "${title} 启动失败\n\n$msg\n\n诊断详情: $diagFile\n日志目录: $logDir"
            setTextColor(0xFF222222.toInt())
            textSize = 14f
        }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
        val buttons = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        if (recoverable) {
            buttons.addView(Button(this).apply {
                text = "重启"
                setOnClickListener {
                    // Windows=ExitProcess(3)+看门狗；Android=整进程重启（M2 形态，用户重开图标）
                    Process.killProcess(Process.myPid())
                }
            })
        }
        buttons.addView(Button(this).apply {
            text = "退出"
            setOnClickListener { finishAffinity() }
        })
        box.addView(buttons, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
        root.addView(box, FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
    }

    private fun px(dip: Int): Int = (dip * resources.displayMetrics.density).toInt()

    // ---------------------------------------------------------------- 步骤 1-8（后台线程）
    private fun boot() {
        try {
            slog("shell boot begin (platform=android, identity=$packageName)")
            // 步骤 1-2：spk 读取 + 指纹比对 / 全量解压（验签由 APK 签名承担）
            val mf = ensureRuntimeExtracted()
            ensureStdlib()
            // 步骤 3：预清理旧 ready 与旧握手码（避免存活假象/陈旧码）
            readyFile.delete(); handshakeFile.delete()
            // 步骤 4：环境变量（含新 token；embedded 恒 STRICT_AUTH=1 防 loopback 裸奔 §12.2⑧）
            val pairs = arrayOf(
                "MYAPP_PLATFORM=android",
                "MYAPP_DATA_DIR=$dataDir",
                "MYAPP_CACHE_DIR=$cache",
                "MYAPP_LOG_DIR=$logDir",
                "MYAPP_READY_FILE=$readyFile",
                "MYAPP_DIAG_FILE=$diagFile",
                "MYAPP_STATIC_DIR=${File(runtimeDir, "dist")}",
                "MYAPP_PORT=0",
                "MYAPP_VERSION=${mf.version}",
                "MYAPP_MANIFEST_PATH=${File(runtimeDir, "manifest")}",
                "MYAPP_NATIVE_LIB_DIR=${applicationInfo.nativeLibraryDir}",
                "MYAPP_STRICT_AUTH=1",
                "MYAPP_HANDSHAKE_FILE=$handshakeFile",
                "MYAPP_TOKEN=${randomHex()}",
                // 四条目：stdlib.zip → site-packages → runtime 根 → nativeLibraryDir。
                // ① runtime 根必须显式在列：Windows 靠 _pth "import site" 的 site.getsitepackages()
                //   把 sys.prefix（= _pth 同目录 = runtime 根）隐性加进 sys.path，import app.main
                //   才成立；Android Py_NoSiteFlag=1 无 site 处理，缺它则 "No module named 'app'"。
                // ② nativeLibraryDir：扩展模块（_struct/_hashlib 等）须在 `import applocal`
                //   前可导入（bootstrap 内的 _inject_native 来不及）。
                "PYTHONPATH=${File(filesDir, "stdlib.zip")}:${File(runtimeDir, "site-packages")}:$runtimeDir:${applicationInfo.nativeLibraryDir}",
                "PYTHONDONTWRITEBYTECODE=1",
            )
            slog("env set (strict_auth=1, token minted)")
            bootStart = SystemClock.uptimeMillis()
            lastSeqChange = bootStart
            val rc = engineBoot(pairs, mf.entry, logFile.absolutePath)
            if (rc != 0) {
                val d = readDiagError()
                main.post { showError(
                    if (rc == -2) "应用引导失败（详见 diag.json）。$d" else "解释器初始化失败。", true) }
                return
            }
            booted = true
            main.post { onBootOk() }
        } catch (e: Exception) {
            slog("boot exception: $e")
            main.post { showError("启动异常：${e.message}", true) }
        }
    }

    private fun onBootOk() {
        setupWebView()
        main.postDelayed(tick, TICK_MS) // 步骤 8.5/9：主 looper 轮询（协议禁独立轮询线程）
    }

    /** 步骤 1-2：指纹命中跳过解压；否则 staging 全量解压 → 旧区让位 → 原子 rename → 记账（铁律①）。 */
    private fun ensureRuntimeExtracted(): ManifestInfo {
        slog("load spk begin")
        val mf = readManifestFromSpk()
        slog("spk loaded, manifest parsed (app_version=${mf.version})")
        val fp = readFingerprint()
        if (fp != null && fp.first == mf.version && fp.second == mf.spkHash) {
            slog("fingerprint hit, skip extract")
            return mf
        }
        slog("fingerprint miss, extracting")
        val staging = File(filesDir, "runtime.new-${Process.myPid()}")
        staging.deleteRecursively(); staging.mkdirs()
        assets.open("runtime.spk").use { raw ->
            ZipInputStream(raw).use { z ->
                while (true) {
                    val e = z.nextEntry ?: break
                    if (e.isDirectory) continue
                    val f = File(staging, e.name)
                    if (!f.canonicalPath.startsWith(staging.canonicalPath + File.separator))
                        throw SecurityException("spk 条目路径非法: ${e.name}")
                    f.parentFile?.mkdirs()
                    f.outputStream().use { z.copyTo(it) }
                }
            }
        }
        val old = File(filesDir, "runtime.old")
        old.deleteRecursively()
        if (runtimeDir.exists()) runtimeDir.renameTo(old)
        if (!staging.renameTo(runtimeDir)) throw IllegalStateException("staging 就位失败")
        old.deleteRecursively()
        // 步骤 7：记账（解压成功后——指纹规则③′）
        writeAtomic(File(runtimeDir, "runtime.version"),
            "app_version=${mf.version}\nspk_hash=${mf.spkHash}\n")
        slog("runtime staging ready")
        return mf
    }

    /** assets 解释器件：stdlib.zip（modules 走 jniLibs→nativeLibraryDir，无解压）。APK 更新后重铺。 */
    private fun ensureStdlib() {
        val target = File(filesDir, "stdlib.zip")
        val marker = File(filesDir, ".rt-apk")
        val key = "${packageManager.getPackageInfo(packageName, 0).longVersionCode}"
        if (target.isFile && marker.isFile && marker.readText() == key) return
        slog("extract assets runtime (stdlib.zip)")
        val tmp = File(filesDir, "stdlib.zip.tmp${Process.myPid()}")
        assets.open("stdlib.zip").use { input -> tmp.outputStream().use { input.copyTo(it) } }
        if (!tmp.renameTo(target)) { tmp.copyTo(target, overwrite = true); tmp.delete() }
        writeAtomic(marker, key)
    }

    private fun readManifestFromSpk(): ManifestInfo {
        assets.open("runtime.spk").use { raw ->
            ZipInputStream(raw).use { z ->
                while (true) {
                    val e = z.nextEntry ?: throw IllegalStateException("spk 内无 manifest 条目")
                    if (e.name != "manifest") continue // nextEntry 自动跳过剩余数据
                    return parseManifest(z.readBytes().decodeToString())
                }
            }
        }
        throw IllegalStateException("spk 内无 manifest 条目")
    }

    private fun parseManifest(text: String): ManifestInfo {
        val map = text.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("#") && '=' in it }
            .associate { it.substringBefore('=').trim() to it.substringAfter('=').trim() }
        return ManifestInfo(
            version = map["app_version"] ?: "",
            entry = map["entry"] ?: throw IllegalStateException("manifest 缺 entry"),
            spkHash = (map["spk_hash"] ?: "").removePrefix("sha256:"),
            minVersion = map["min_app_version"] ?: "")
    }

    private fun readFingerprint(): Pair<String, String>? = try {
        val t = File(runtimeDir, "runtime.version").readText()
        val v = Regex("app_version=(\\S+)").find(t)?.groupValues?.get(1)
        val h = Regex("spk_hash=(\\S+)").find(t)?.groupValues?.get(1)
        if (v != null && h != null) v to h.removePrefix("sha256:") else null
    } catch (_: Exception) { null }

    // ---------------------------------------------------------------- 步骤 8.5/9：WebView + 轮询
    @SuppressLint("SetJavaScriptEnabled")
    private fun setupWebView() {
        val wv = WebView(this)
        wv.layoutParams = FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT)
        root.addView(wv)
        webview = wv
        loading.bringToFront() // webview 宿主后创建盖住加载层：抬回最上继续遮挡白屏（镜像 CtlHandler）
        setStage("正在加载页面…")
        wv.settings.apply {
            javaScriptEnabled = true
            domStorageEnabled = true // token 存 sessionStorage（strict_auth 页面契约）
        }
        wv.webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
                // 步骤 9（★v1.2★）：URL 带码→镜像入文件；无码→新随机码作废遗留
                if (request.isForMainFrame)
                    writeAtomic(handshakeFile, uriHandshake(request.url) ?: randomHex())
                return false
            }
            override fun onPageFinished(view: WebView, url: String?) {
                slog("nav completed ok=1")
                hideLoading()
            }
            override fun onReceivedError(view: WebView, request: WebResourceRequest, error: WebResourceError) {
                if (request.isForMainFrame) {
                    slog("nav error: ${error.description}")
                    main.post { showError("页面加载失败：${error.description}", true) }
                }
            }
        }
        slog("webview ready")
    }

    private fun navigateToApp() {
        val wv = webview ?: return
        val code = randomHex()
        writeAtomic(handshakeFile, code)
        setStage("正在加载页面…")
        slog("navigate port=$port")
        wv.loadUrl("http://127.0.0.1:$port/?handshake=$code")
    }

    private val tick = object : Runnable {
        override fun run() {
            if (phase == PH_DEAD) return
            val now = SystemClock.uptimeMillis()
            val ri = readReady()
            if (phase == PH_COLD) {
                if (ri != null && ri.ready && ri.port > 0) {
                    port = ri.port; lastSeq = ri.seq; lastSeqChange = now
                    phase = PH_RUNTIME
                    slog("ready seen port=$port seq=$lastSeq")
                    navigateToApp()
                    main.postDelayed(this, TICK_MS)
                    return
                }
                if (now - bootStart > BOOT_TIMEOUT_MS) {
                    val d = readDiagError()
                    showError("启动超时：120 秒内未收到就绪信号。$d", true)
                    return
                }
            } else if (phase == PH_RUNTIME) {
                if (ri == null) { // 仅"曾出现过"后消失才判死（§5 v1.1 前提）
                    showError("运行时心跳中断（ready 文件消失）。", true); return
                }
                if (!ri.ready) { showError("运行时报告未就绪。", true); return }
                if (ri.seq >= 0 && ri.seq != lastSeq) {
                    lastSeq = ri.seq; lastSeqChange = now
                    if (ri.port > 0 && ri.port != port) port = ri.port
                }
                if (now - lastSeqChange > HEARTBEAT_DEAD_MS) {
                    val d = readDiagError()
                    showError("运行时心跳超时（30 秒无响应）。$d", true); return
                }
            }
            main.postDelayed(this, TICK_MS)
        }
    }

    // ---------------------------------------------------------------- 工具
    private data class ReadyInfo(val ready: Boolean, val port: Long, val seq: Long)
    private data class ManifestInfo(
        val version: String, val entry: String, val spkHash: String, val minVersion: String)

    /** 迷你解析；文件不存在/解析失败按"未就绪/序列不变"处理（项目硬约束）。 */
    private fun readReady(): ReadyInfo? = try {
        val t = readyFile.readText()
        ReadyInfo(
            ready = Regex("\"ready\"\\s*:\\s*(true|false)").find(t)?.groupValues?.get(1) == "true",
            port = Regex("\"port\"\\s*:\\s*(-?\\d+)").find(t)?.groupValues?.get(1)?.toLongOrNull() ?: -1,
            seq = Regex("\"seq\"\\s*:\\s*(-?\\d+)").find(t)?.groupValues?.get(1)?.toLongOrNull() ?: -1)
    } catch (_: Exception) { null }

    private fun readDiagError(): String = try {
        val t = diagFile.readText()
        Regex("\"error\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"").find(t)
            ?.groupValues?.get(1)?.replace("\\\"", "\"")?.replace("\\\\", "\\") ?: ""
    } catch (_: Exception) { "" }

    private fun uriHandshake(uri: Uri): String? {
        val v = uri.getQueryParameter("handshake") ?: return null
        return if (v.length == 64 && v.all { it in '0'..'9' || it in 'a'..'f' }) v else null
    }

    private fun randomHex(): String {
        val b = ByteArray(32)
        SecureRandom().nextBytes(b)
        return b.joinToString("") { "%02x".format(it) }
    }

    /** 原子写（tmp+rename，项目硬约束）。 */
    private fun writeAtomic(f: File, data: String) {
        val tmp = File(f.parentFile, f.name + ".tmp${Process.myPid()}")
        tmp.writeText(data)
        if (!tmp.renameTo(f)) { tmp.copyTo(f, overwrite = true); tmp.delete() }
    }

    private fun slog(msg: String) = ShellLog.slog(msg)
}
