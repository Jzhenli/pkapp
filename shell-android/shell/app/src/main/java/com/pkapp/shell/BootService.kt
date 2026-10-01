package com.pkapp.shell

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.os.Build
import android.os.IBinder

/** 前台服务：把进程抬出 cached 桶——前后台切换/息屏时 uvicorn 与探测心跳不中断（M2 验收项）。
 *  type=specialUse（嵌入式本地服务无标准类型可依）；通知通道 IMPORTANCE_MIN 静默常驻。 */
class BootService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(1, buildNotification())
        return START_STICKY
    }

    private fun buildNotification(): Notification {
        val builder = if (Build.VERSION.SDK_INT >= 26) {
            val ch = NotificationChannel(
                "pkapp-shell", "应用服务", NotificationManager.IMPORTANCE_MIN)
            (getSystemService(NOTIFICATION_SERVICE) as NotificationManager)
                .createNotificationChannel(ch)
            Notification.Builder(this, ch.id)
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
