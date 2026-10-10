package com.pkapp.shell

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Process
import org.json.JSONObject

/** 前台服务 = L1 保活宿主 + L2 复活中转 + 心跳 writer 宿主。
 *  - L1（§5）：START_STICKY + 常驻通知把进程抬出 cached 桶——前后台切换/息屏时 uvicorn
 *    与探测心跳不中断（M2 验收项）。type=specialUse（嵌入式本地服务无标准类型可依）。
 *  - L2 中转（§4.2-3 ★C2★，方案 WatchdogService 职责并入本服务——壳唯一 FGS）：
 *    闹钟/BOOT/僵死自杀链统一经 startForegroundService 到达，服务内拉起 MainActivity
 *    （经 Watchdog.fireReviveActivity：setAlarmClock 直发 activity PI 豁免 BAL——
 *    真机证伪 FGS startActivity 被 Android 12+ 拦截，见 Watchdog 注释）。
 *  - 心跳 writer（§4.1）：壳侧写者，merge 写 ts/pid/healthz_ok。写条件 =
 *    MainActivity.runtimeLive && ready 健康——runtime 未起/已死不写，让 ts 自然过期
 *    交 L2 复活（§6.1「停写心跳」的壳侧形态；进程死亡自然停写）；进程活着但 Activity
 *    被销毁（MagicOS 息屏形态）时 runtimeLive 静态位仍在 → 照常续写，防误复活。
 *    Handler 挂主 looper：主线程僵死时 writer 同停 → ts 过期 → L2 兜底（§6.6 之前
 *    的保底形态；真僵死连广播都收不到，§6.6 阶段 3 补看门狗线程）。
 */
class BootService : Service() {

    companion object {
        // 冻结 vs 真死甄别宽限：冻结 ROM（MagicOS 实测形态）解冻瞬间 writer 欠账拍先补写，
        // 10s 复核见新鲜即免杀——防「息屏冻结 → 闹钟唤醒 → 误杀健康进程」。
        private const val GRACE_RECHECK_MS = 10_000L
    }

    private var main: Handler? = null
    private var healthyStreak = 0L

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        nm.createNotificationChannel(NotificationChannel(
            "pkapp-shell", "应用服务", NotificationManager.IMPORTANCE_MIN))
        Watchdog.ensureAlertChannel(this)   // ★R4★ 熔断 channel 预建（API 26+ 强制）
        Watchdog.scheduleNextAlarm(this)    // ★R2★ 每入口幂等重排（Service 重建含 STICKY 也要补排）
        startHeartbeatWriter()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(1, buildNotification())
        val why = when {
            intent == null -> "RESTART"                              // STICKY 重建特征（无 extra）
            intent.hasExtra(Watchdog.EXTRA_FROM_ALARM) -> "ALARM"
            intent.hasExtra(Watchdog.EXTRA_FROM_BOOT) -> "BOOT"
            else -> "APP"
        }
        Watchdog.slog("service why=$why pid=${Process.myPid()}")
        when (why) {
            // 僵死自杀（killProcess）后的 STICKY 重建尾巴：内存态全丢，靠持久 pending_revive
            // 记得"欠 MainActivity 一次拉起"（§4.2-3 ★P1★）。计数已在 kill 前完成，勿重复。
            "RESTART" -> if (Watchdog.readState(this)?.pendingRevive == true)
                revive("sticky_pending", count = false)
            "ALARM" -> onAlarmDelivery()
            "BOOT" -> revive("boot", count = false)   // 断电恢复直拉（§4.2-4）；开机自启不算 revive 计数
            // "APP"：常规应用启动投递，无复活动作
        }
        return START_STICKY
    }

    override fun onDestroy() {
        main?.removeCallbacksAndMessages(null)
        super.onDestroy()
    }

    // ------------------------------------------------------ L2：复活分支
    /** 闹钟投递（receiver 已过 freshness + 熔断门）：按心跳 pid 分死进程复活 / 同进程僵死。 */
    private fun onAlarmDelivery() {
        val st = Watchdog.readState(this) ?: return
        val ttl = Watchdog.config(this).ttlSec
        if (!Watchdog.isStale(st, ttl)) return            // receiver 判活后到服务起之间又活了
        if (st.pid != Process.myPid()) {
            // 心跳 pid = 旧进程：本进程即 L2 复活本体（§4.2-3 进程整死分支，单周期直拉）
            Watchdog.slog("heartbeat pid=${st.pid} != mine, dead-process revival")
            revive("alarm_dead", count = true)
        } else {
            // 同进程心跳过期：冻结 ROM 解冻瞬间 / runtime 死（writer 停写）两种形态。
            // 宽限复核防冻结误杀；复核仍过期 = runtime 真死 → 置 pending_revive +
            // killProcess（★N1★ 自杀只用 killProcess，绝禁 force-stop）→ STICKY 重建尾巴拉起。
            //（主线程真僵死时本回调也不执行——L2 对僵死全盲，§6.6 阶段 3 补看门狗线程）
            Watchdog.slog("heartbeat stale in-process, grace recheck in ${GRACE_RECHECK_MS}ms")
            main?.postDelayed({
                val s2 = Watchdog.readState(this) ?: return@postDelayed
                if (!Watchdog.isStale(s2, Watchdog.config(this).ttlSec)) {
                    Watchdog.slog("grace recheck fresh (frozen-unfreeze), skip")
                    return@postDelayed
                }
                Watchdog.slog("grace recheck still stale, killProcess for STICKY rebuild")
                if (!countRevive()) return@postDelayed    // 熔断已开：不复活，求救通知已挂
                Watchdog.mergeWrite(this) { put("pending_revive", true) }
                Process.killProcess(Process.myPid())
            }, GRACE_RECHECK_MS)
        }
    }

    /** 复活执行：计数（可选）→ 拉 MainActivity（带 EXTRA_FROM_WATCHDOG=自动语义不清零）→
     *  清 pending_revive。 */
    private fun revive(reason: String, count: Boolean) {
        if (count && !countRevive()) return
        Watchdog.fireReviveActivity(this)   // 闹钟 PI 直发（FGS startActivity 被 BAL 拦，真机实测）
        Watchdog.audit(this, "revive",
            JSONObject().put("reason", reason).put("pid", Process.myPid()))
        Watchdog.mergeWrite(this) { put("pending_revive", false) }
    }

    /** 熔断计数（§4.4 ★C3★）：窗口 T 内第 N 次 revive → circuit_open + 求救通知。
     *  计数口径（§12-2 决议）：仅 L1/L2 revive 事件，L0 秒级自愈不进此路径。 */
    private fun countRevive(): Boolean {
        val c = Watchdog.config(this)
        val now = System.currentTimeMillis()
        var opened = false
        Watchdog.mergeWrite(this) {
            var win = optLong("circuit_window_start_ts")
            var n = optInt("circuit_count", 0)
            if (win <= 0L || now - win > c.burstWinSec * 1000) { win = now; n = 0 }
            n++
            put("circuit_window_start_ts", win)
            put("circuit_count", n)
            if (n >= c.burstLimit) { put("circuit_open", true); opened = true }
        }
        if (opened) {
            Watchdog.audit(this, "circuit_open",
                JSONObject().put("window_sec", c.burstWinSec).put("limit", c.burstLimit))
            Watchdog.alertNotify(this)
        }
        return !opened
    }

    // ------------------------------------------------------ 心跳 writer（§4.1 壳侧写者）
    private fun startHeartbeatWriter() {
        if (main != null) return
        val h = Handler(Looper.getMainLooper())
        main = h
        val tick = object : Runnable {
            override fun run() {
                val c = Watchdog.config(this@BootService)
                heartbeatTick(c)
                h.postDelayed(this, c.writeSec * 1000)
            }
        }
        h.post(tick)
    }

    private fun heartbeatTick(c: Watchdog.Config) {
        val healthy = Watchdog.readyHealthy(this)
        if (MainActivity.runtimeLive && healthy) {
            Watchdog.mergeWrite(this) {
                put("ts", System.currentTimeMillis())
                put("pid", Process.myPid())
                put("healthz_ok", true)
            }
            healthyStreak += c.writeSec
            // 健康清零评估点归 writer（§4.4 ★P2★：30s 跑一次、天然持有 healthz 连续性
            // 上下文）；★S3★ 例外允许 writer 经 merge 写 circuit_count。
            val st = Watchdog.readState(this)
            if (st != null && !st.open && st.count > 0 && healthyStreak >= c.healthyResetSec) {
                Watchdog.mergeWrite(this) {
                    put("circuit_count", 0)
                    put("circuit_window_start_ts", 0L)
                }
                healthyStreak = 0
                Watchdog.slog("healthy window reached, circuit count reset")
            }
        } else {
            healthyStreak = 0   // runtime 未起/已死：停写 → ts 过期 → L2 兜底（§6.1「停写心跳」）
        }
    }

    // ------------------------------------------------------ 常驻通知（L1）
    private fun buildNotification(): Notification {
        val builder = if (Build.VERSION.SDK_INT >= 26) {
            Notification.Builder(this, "pkapp-shell")
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        builder.setContentTitle("应用服务运行中")
            .setContentText("本地服务正在运行")
            .setSmallIcon(R.drawable.ic_app)
            .setOngoing(true)
        if (Build.VERSION.SDK_INT >= 31)
            builder.setForegroundServiceBehavior(Notification.FOREGROUND_SERVICE_IMMEDIATE)
        return builder.build()
    }
}
