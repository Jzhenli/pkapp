package com.pkapp.spike

import android.app.AlarmManager
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Process
import android.util.Log
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/* watchdog spike：文档 docs/ANDROID_7x24_WATCHDOG_PLAN.md 三个未验证假设的实机探针。
 * 全部关键点打 logcat tag=SPIKE，验证流程靠 adb 驱动，无需人手点 UI。
 *
 * 假设1（L1 根基）：kill -9 后 START_STICKY 是否重建服务 → WatchdogService.onCreate log
 * 假设2（L2 根基）：进程整死后 setAlarmClock 是否真触发、精度多少 → AlarmReceiver log
 * 假设3（C2）：receiver（后台上下文）startForegroundService 是否被拦 + 服务内
 *            start Activity 是否可拉起 UI（后台启动限制绕过）→ 各 log + AM 行
 * 顺带验证：R3 触发后重设成周期；S3 的 EXTRA_FROM_WATCHDOG 启动来源区分。
 */
const val TAG = "SPIKE"
const val CHANNEL_ID = "spike"
const val ALARM_INTERVAL_MS = 60_000L   // spike 用 60s 快验证（正式方案 300s）
const val EXTRA_FROM_ALARM = "from_alarm"
const val EXTRA_FROM_BOOT = "from_boot"

fun now(): String = SimpleDateFormat("HH:mm:ss.SSS", Locale.US).format(Date())

fun scheduleNextAlarm(ctx: Context): Long {
    val am = ctx.getSystemService(Context.ALARM_SERVICE) as AlarmManager
    val triggerAt = System.currentTimeMillis() + ALARM_INTERVAL_MS
    // setAlarmClock：不受 Doze/节流、无需 SCHEDULE_EXACT_ALARM（manifest 刻意未声明）
    val pi = PendingIntent.getBroadcast(
        ctx, 1001,
        Intent(ctx, AlarmReceiver::class.java).putExtra("trigger_at", triggerAt),
        PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
    )
    val show = PendingIntent.getActivity(
        ctx, 1002,
        Intent(ctx, MainActivity::class.java),
        PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
    )
    am.setAlarmClock(AlarmManager.AlarmClockInfo(triggerAt, show), pi)
    Log.i(TAG, "alarm scheduled at=+$ALARM_INTERVAL_MS ms (${now()})")
    return triggerAt
}

class MainActivity : android.app.Activity() {
    override fun onCreate(savedInstanceState: android.os.Bundle?) {
        super.onCreate(savedInstanceState)
        val from = when {
            intent.hasExtra(EXTRA_FROM_ALARM) -> "ALARM"
            intent.hasExtra(EXTRA_FROM_BOOT) -> "BOOT"
            else -> "MANUAL"
        }
        Log.i(TAG, "activity onCreate source=$from (S3 启动来源区分)")
        val tv = android.widget.TextView(this)
        tv.textSize = 14f
        tv.setPadding(32, 32, 32, 32)
        tv.text = "SPIKE 运行中\n来源: $from\n看 logcat -s SPIKE"
        setContentView(tv)
        // 前台服务 + 首条闹钟（R2：应用启动初始化排程）
        startForegroundService(Intent(this, WatchdogService::class.java))
        scheduleNextAlarm(this)
    }
}

class WatchdogService : Service() {
    private lateinit var handler: Handler
    private var beats = 0

    override fun onCreate() {
        super.onCreate()
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_ID, "spike", NotificationManager.IMPORTANCE_LOW)
        )
        val n: Notification = Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("watchdog spike")
            .setSmallIcon(android.R.drawable.ic_menu_manage)
            .build()
        startForeground(1, n)
        Log.i(TAG, "SERVICE onCreate pid=${Process.myPid()} (假设1: 若 kill 后出现=STICKY 重建成立)")
        // R2 落实到代码：Service 每次重建（含 STICKY）都重排闹钟——否则链条断在重建服务
        scheduleNextAlarm(this)
        // L0 原型：独立看门狗线程（S 轮实证：主线程僵死时 broadcast 投递无效，
        // 必须由活着的线程检测僵死并 killProcess）
        Thread {
            var last = beats
            var stuck = 0
            repeat(10) {
                Thread.sleep(9_000)
                if (beats == last) { stuck++; Log.w(TAG, "watchdog: no heartbeat x$stuck") }
                else { stuck = 0; last = beats }
                if (stuck >= 3) {
                    Log.e(TAG, "watchdog: main thread STUCK 27s+ -> killProcess (L0 自杀)")
                    Process.killProcess(Process.myPid())
                }
            }
        }.apply { isDaemon = true; name = "spike-watchdog" }.start()
        handler = Handler(Looper.getMainLooper())
        val tick = object : Runnable {
            override fun run() {
                beats++
                Log.i(TAG, "heartbeat #$beats pid=${Process.myPid()} (${now()})")
                handler.postDelayed(this, 15_000)
            }
        }
        handler.post(tick)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val why = when {
            intent == null -> "RESTART(null-intent,STICKY 重建)"   // START_STICKY 重建特征
            intent.hasExtra(EXTRA_FROM_ALARM) -> "ALARM"
            intent.hasExtra(EXTRA_FROM_BOOT) -> "BOOT"
            else -> "APP"
        }
        Log.i(TAG, "SERVICE onStartCommand why=$why pid=${Process.myPid()} (${now()})")
        // C2/P1：复活路径服务内拉起 MainActivity（前台服务上下文豁免后台启动限制）
        if (why == "ALARM" || why == "BOOT") {
            val i = Intent(this, MainActivity::class.java)
            if (why == "ALARM") i.putExtra(EXTRA_FROM_ALARM, true)
            if (why == "BOOT") i.putExtra(EXTRA_FROM_BOOT, true)
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            try {
                startActivity(i)
                Log.i(TAG, "service->startActivity OK ($why)")
            } catch (e: Exception) {
                Log.e(TAG, "service->startActivity FAILED ($why): $e")
            }
        }
        return START_STICKY
    }

    override fun onDestroy() = Log.i(TAG, "SERVICE onDestroy pid=${Process.myPid()}").let {}
    override fun onBind(intent: Intent?): IBinder? = null
}

class AlarmReceiver : BroadcastReceiver() {
    override fun onReceive(ctx: Context, intent: Intent) {
        val scheduled = intent.getLongExtra("trigger_at", 0L)
        val deviation = System.currentTimeMillis() - scheduled
        // 假设2+P3：setAlarmClock 触发 + 触发后重设成周期；deviation=实际-预定
        Log.i(TAG, "ALARM FIRED (假设2) deviation=${deviation}ms (${now()})")
        scheduleNextAlarm(ctx)
        try {
            ctx.startForegroundService(
                Intent(ctx, WatchdogService::class.java).putExtra(EXTRA_FROM_ALARM, true)
            )
            Log.i(TAG, "receiver->startForegroundService OK (假设3/C2)")
        } catch (e: Exception) {
            Log.e(TAG, "receiver->startForegroundService BLOCKED: $e")
        }
    }
}

/* 确定性僵死模拟器：onReceive 在主线程 sleep 120s（等价真机观察到的 crash 后 FocusEvent 僵死形态）。
 * 验证目标：看门狗线程须在系统 60s 背景广播超时前（~36s）killProcess 自杀 → STICKY 重建。
 * 驱动：adb shell am broadcast -a com.pkapp.spike.ZOMBIE -n com.pkapp.spike/.ZombieReceiver */
class ZombieReceiver : BroadcastReceiver() {
    override fun onReceive(ctx: Context, intent: Intent) {
        Log.e(TAG, "ZOMBIE: main thread hang 120s from now (${now()}) pid=${Process.myPid()}")
        try { Thread.sleep(120_000) } catch (_: InterruptedException) {}
        Log.e(TAG, "ZOMBIE: hang ended (${now()})")   // 预期不可达——看门狗应先杀进程
    }
}

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(ctx: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        Log.i(TAG, "BOOT_COMPLETED received (${now()})")
        try {
            ctx.startForegroundService(
                Intent(ctx, WatchdogService::class.java).putExtra(EXTRA_FROM_BOOT, true)
            )
            Log.i(TAG, "boot->startForegroundService OK")
        } catch (e: Exception) {
            Log.e(TAG, "boot->startForegroundService BLOCKED: $e")
        }
    }
}
