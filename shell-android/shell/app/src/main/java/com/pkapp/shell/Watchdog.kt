package com.pkapp.shell

import android.app.AlarmManager
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Process
import android.provider.Settings
import android.util.Log
import org.json.JSONObject
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.zip.ZipInputStream

/* L2 进程外兜底（docs/ANDROID_7x24_WATCHDOG_PLAN.md §4）：
 *  - 心跳文件合同（§4.1）：files/heartbeat.json，双写者各写各的字段（★P2★ merge 读改写，
 *    禁整文件覆写）；writer 侧在 BootService，receiver/service 侧在本文件。
 *  - setAlarmClock 主案（§4.2-2 ★C1★）：一次性闹钟触发后重设（★P3★），每入口幂等重排（★R2★）。
 *  - 复活统一经前台服务中转（§4.2-3 ★C2★）——服务即 BootService（壳唯一 FGS，
 *    方案中 WatchdogService 的职责并入它，避免双常驻服务双通知）。
 *  - Boot-loop 熔断（§4.4 ★C3★）：窗口 T 内 revive ≥ N → 停止自动复活 + 常驻求救通知。
 *  - pending_revive 持久标志（★P1★）：僵死自杀 killProcess 后 STICKY 重建（intent 无
 *    extra、内存态全丢）靠它记得"欠 MainActivity 一次拉起"。
 * 组件命名对照：方案 WatchdogReceiver = 本文件 WatchdogReceiver；WatchdogService → BootService。
 */
object Watchdog {
    const val EXTRA_FROM_WATCHDOG = "from_watchdog" // 自动复活链投递 MainActivity 的标记（无此 extra = 人工语义 ★S3★）
    const val EXTRA_FROM_ALARM = "from_alarm"
    const val EXTRA_FROM_BOOT = "from_boot"
    private const val TAG = "watchdog"
    private const val STATE_FILE = "heartbeat.json"
    const val CHANNEL_ALERT = "watchdog-alert"
    const val NOTIFY_ID_CIRCUIT = 2001

    data class Config(
        val alarmSec: Long, val ttlSec: Long, val writeSec: Long,
        val burstWinSec: Long, val burstLimit: Int, val healthyResetSec: Long)

    @Volatile private var cfgCache: Config? = null

    /** §8 配置：toml 单一入口 → pkapp 打包期投影为 spk manifest `watcher_*` 扩展键
     *  （同 [network].port 通道，签名覆盖、壳 C/Java 解析器对未知键忽略）；
     *  缺键/裸壳直建 = §8 默认值。进程内缓存。 */
    fun config(ctx: Context): Config {
        cfgCache?.let { return it }
        val m = HashMap<String, String>()
        try {
            ctx.assets.open("runtime.spk").use { raw ->
                ZipInputStream(raw).use { z ->
                    while (true) {
                        val e = z.nextEntry ?: break
                        if (e.isDirectory || e.name != "manifest") continue
                        z.readBytes().decodeToString().lineSequence()
                            .map { it.trim() }
                            .filter { it.isNotEmpty() && !it.startsWith("#") && '=' in it }
                            .forEach { m[it.substringBefore('=').trim()] = it.substringAfter('=').trim() }
                        break
                    }
                }
            }
        } catch (_: Exception) { /* 裸壳无 spk：全默认 */ }
        fun k(key: String, dflt: Long) = m["watcher_$key"]?.toLongOrNull() ?: dflt
        return Config(
            alarmSec = k("alarm_interval", 300),
            ttlSec = k("heartbeat_ttl", 180),
            writeSec = k("healthz_interval", 30),
            burstWinSec = k("revive_burst_window", 1800),
            burstLimit = k("revive_burst_limit", 3).toInt(),
            healthyResetSec = k("healthy_reset_window", 300),
        ).also { cfgCache = it }
    }

    // ------------------------------------------------------ 心跳文件合同（§4.1/§4.4）
    // writer(BootService) 拥有 ts/pid/healthz_ok；receiver/service 拥有 circuit_*/pending_revive；
    // 唯一例外（★S3★）：writer 健康清零经 merge 写 circuit_count。
    class State(val ts: Long, val pid: Int, val healthzOk: Boolean,
                val winStart: Long, val count: Int, val open: Boolean, val pendingRevive: Boolean)

    private fun stateFile(ctx: Context) = File(ctx.filesDir, STATE_FILE)

    fun readState(ctx: Context): State? = try {
        val o = JSONObject(stateFile(ctx).readText())
        State(o.optLong("ts"), o.optInt("pid", -1), o.optBoolean("healthz_ok", false),
            o.optLong("circuit_window_start_ts"), o.optInt("circuit_count", 0),
            o.optBoolean("circuit_open", false), o.optBoolean("pending_revive", false))
    } catch (_: Exception) { null }

    fun isStale(st: State, ttlSec: Long): Boolean =
        System.currentTimeMillis() - st.ts > ttlSec * 1000

    /** ★P2★ merge 读改写：只动 patch 里的字段，对方字段原样保留。同进程 synchronized；
     *  跨进程写撞窗口极窄且 merge 保对方字段——最坏丢一次单侧更新（心跳晚 30s/计数晚一拍，
     *  下一周期自然收敛），不引入跨进程文件锁复杂度。原子写 = tmp + 同目录 rename（★M5★）。 */
    fun mergeWrite(ctx: Context, patch: JSONObject.() -> Unit) {
        synchronized(this) {
            val o = try { JSONObject(stateFile(ctx).readText()) } catch (_: Exception) { JSONObject() }
            o.apply(patch)
            val f = stateFile(ctx)
            val tmp = File(f.parentFile, f.name + ".tmp${Process.myPid()}")
            try {
                tmp.writeText(o.toString())
                if (!tmp.renameTo(f)) { tmp.copyTo(f, overwrite = true); tmp.delete() }
            } catch (_: Exception) {
                tmp.delete()
            }
        }
    }

    /** runtime 健康探针（阶段 1 形态）：ready 文件在场且 port>0（与 MainActivity 轮询同源；
     *  阶段 3 §6.1 换 healthz HTTP 轮询）。 */
    fun readyHealthy(ctx: Context): Boolean = try {
        val t = File(File(ctx.filesDir, "cache"), "ready").readText()
        Regex("\"ready\"\\s*:\\s*true").containsMatchIn(t) &&
            (Regex("\"port\"\\s*:\\s*(\\d+)").find(t)?.groupValues?.get(1)?.toLongOrNull() ?: 0L) > 0L
    } catch (_: Exception) { false }

    // ------------------------------------------------------ setAlarmClock 主案（§4.2-2）
    /** 一次性闹钟：触发后重设成周期（★P3★）；MainActivity/BootService/receiver 每入口
     *  幂等重排（★R2★，防"触发广播被僵死进程吃掉后链条断"）。 */
    fun scheduleNextAlarm(ctx: Context) {
        val am = ctx.getSystemService(Context.ALARM_SERVICE) as AlarmManager
        val triggerAt = System.currentTimeMillis() + config(ctx).alarmSec * 1000
        val pi = PendingIntent.getBroadcast(ctx, 1001,
            Intent(ctx, WatchdogReceiver::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val show = PendingIntent.getActivity(ctx, 1002,
            Intent(ctx, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        try {
            am.setAlarmClock(AlarmManager.AlarmClockInfo(triggerAt, show), pi)
        } catch (e: Exception) {
            // ★SPIKE 证伪★：未获 SCHEDULE_EXACT_ALARM 时 API 31 直接 SecurityException
            Log.e(TAG, "setAlarmClock FAILED: $e")
        }
    }

    /** 复活拉起 MainActivity（多通道渐进，按设备宽松度自然取用——BAL 限制强度是
     *  ROM 相关的：测试机 Motorola Android 12/13 实测 FGS 直启与闹钟 PI 双双被
     *  ActivityTaskManager "Abort background activity starts" 拦截，但工控平板等
     *  宽松 ROM 上这两条通道可能直接可用）：
     *  ① 直启恒先做：SWO 已授权（SYSTEM_ALERT_WINDOW 官方豁免项）时任何 ROM 恒通
     *     ——严格 ROM 的保底；宽松 ROM 未授权同样命中；
     *  ② SWO 未授权再排闹钟 PI 兜一手（部分 ROM 豁免；宽松 ROM 与直启双到无碍，
     *     singleTask 吸收重复投递）。
     *  全部落空时（严格 ROM 且未授权 SWO）：求救通知引导 + 下一闹钟重试（熔断器
     *  兜住循环），用户授权 SWO 后链条即闭环。 */
    fun fireReviveActivity(ctx: Context) {
        try {
            val intent = Intent(ctx, MainActivity::class.java)
                .putExtra(EXTRA_FROM_WATCHDOG, true)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            ctx.startActivity(intent)   // 直启优先：宽松 ROM 此刻即命中；严格 ROM 被静默吞掉，无害
            if (!Settings.canDrawOverlays(ctx)) {   // SWO 未授权：闹钟 PI 再兜一手（部分 ROM 豁免）
                val am = ctx.getSystemService(Context.ALARM_SERVICE) as AlarmManager
                val pi = PendingIntent.getActivity(ctx, 1003,
                    Intent(ctx, MainActivity::class.java)
                        .putExtra(EXTRA_FROM_WATCHDOG, true),
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
                am.setAlarmClock(
                    AlarmManager.AlarmClockInfo(System.currentTimeMillis() + 500, pi), pi)
            }
        } catch (e: Exception) {
            Log.e(TAG, "fireReviveActivity FAILED: $e")
        }
    }

    // ------------------------------------------------------ 熔断求救通知（§4.4）
    /** ★R4★ channel 预建：API 26+ 强制；receiver 后台发通知无 channel 即静默丢弃。 */
    fun ensureAlertChannel(ctx: Context) {
        if (Build.VERSION.SDK_INT < 26) return
        val ch = NotificationChannel(CHANNEL_ALERT, "看门狗告警", NotificationManager.IMPORTANCE_HIGH)
        ch.enableVibration(true)
        (ctx.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager)
            .createNotificationChannel(ch)
    }

    /** 熔断常驻通知（显式求救）：点击拉起 MainActivity（无 EXTRA_FROM_WATCHDOG = 人工语义
     *  → 壳内执行熔断复位，§4.4 复位 b / ★S3★）。request code 1004 独立于 scheduleNextAlarm
     *  的 1002 show intent（PI 匹配不看 extras——共用会在将来任一处加 extra 时静默牵连另一处）。 */
    fun alertNotify(ctx: Context) {
        ensureAlertChannel(ctx)
        val pi = PendingIntent.getActivity(ctx, 1004,
            Intent(ctx, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val n = if (Build.VERSION.SDK_INT >= 26) Notification.Builder(ctx, CHANNEL_ALERT)
                else @Suppress("DEPRECATION") Notification.Builder(ctx)
        n.setContentTitle("应用需要人工干预")
            .setContentText("自动恢复已熔断（短时间内多次复活失败），请打开应用处理")
            .setSmallIcon(R.drawable.ic_app)
            .setOngoing(true)
            .setContentIntent(pi)
        try {
            (ctx.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager)
                .notify(NOTIFY_ID_CIRCUIT, n.build())
        } catch (e: Exception) {
            Log.e(TAG, "alert notify FAILED: $e")
        }
    }

    fun cancelAlert(ctx: Context) {
        try {
            (ctx.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager)
                .cancel(NOTIFY_ID_CIRCUIT)
        } catch (_: Exception) { }
    }

    // ------------------------------------------------------ 审计 / 日志
    /** 审计旁路（§4.2-5）：与 applocal record_event 同 schema 同文件（<log_dir>/audit.log
     *  JSONL，source="watchdog"）。仅记账干预事件；任何失败静默（审计绝不反噬主路径）。 */
    fun audit(ctx: Context, event: String, detail: JSONObject? = null) {
        try {
            val logDir = File(File(ctx.filesDir, "cache"), "log")
            logDir.mkdirs()
            val fmt = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss", Locale.US)
            fmt.timeZone = TimeZone.getTimeZone("UTC")
            val rec = JSONObject()
                .put("ts", fmt.format(Date()) + "Z")
                .put("source", "watchdog")
                .put("event", event)
            if (detail != null) rec.put("detail", detail)
            File(logDir, "audit.log").appendText(rec.toString() + "\n")
        } catch (_: Exception) { }
        Log.i(TAG, "audit $event ${detail ?: ""}")
    }

    fun slog(msg: String) = Log.i(TAG, msg)
}

/** L2 闹钟 receiver（§4.1）：短命进程只做判活分流 + FGS 中转，复活动作全在服务侧。
 *  判活 = 心跳文件 ts 新鲜度（跨进程判活合同）；熔断开 → 只记账不复活。 */
class WatchdogReceiver : BroadcastReceiver() {
    override fun onReceive(ctx: Context, intent: Intent) {
        Watchdog.scheduleNextAlarm(ctx)                       // ★P3★ 触发后立即重设周期
        val c = Watchdog.config(ctx)
        val st = Watchdog.readState(ctx)
        if (st == null) {
            Watchdog.slog("alarm fired, no heartbeat state yet, skip")
            return
        }
        if (!Watchdog.isStale(st, c.ttlSec)) {
            Watchdog.slog("alarm fired, heartbeat fresh, healthy=${st.healthzOk}")
            return                                            // 活着：仅记账，不干预（§4.1）
        }
        if (st.open) {
            // 熔断态：停止自动复活；保持求救通知在场（设备重启后通知重建也在此）
            Watchdog.slog("alarm fired but CIRCUIT OPEN, revive blocked")
            Watchdog.audit(ctx, "revive_blocked",
                JSONObject().put("reason", "circuit_open").put("count", st.count))
            Watchdog.alertNotify(ctx)
            return
        }
        Watchdog.slog("alarm fired, heartbeat STALE (pid=${st.pid}) -> relay to FGS")
        try {
            ctx.startForegroundService(
                Intent(ctx, BootService::class.java).putExtra(Watchdog.EXTRA_FROM_ALARM, true))
        } catch (e: Exception) {
            Watchdog.slog("relay startForegroundService BLOCKED: $e")
        }
    }
}

/** 开机自启（§4.2-4）：后台上下文直拉 Activity 会被静默拦截（★N3★）——同经 FGS 中转。
 *  注：OEM 自启门禁（★R-10★，spike 实测）可能拦截本 receiver，部署验收必查 §7.3。 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(ctx: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        Watchdog.slog("BOOT_COMPLETED received")
        try {
            ctx.startForegroundService(
                Intent(ctx, BootService::class.java).putExtra(Watchdog.EXTRA_FROM_BOOT, true))
        } catch (e: Exception) {
            Watchdog.slog("boot relay BLOCKED: $e")
        }
    }
}
