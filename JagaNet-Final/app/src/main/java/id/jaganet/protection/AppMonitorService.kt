package id.jaganet.protection

import android.app.AppOpsManager
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper

class AppMonitorService : Service() {
    private val handler = Handler(Looper.getMainLooper())
    @Volatile private var active = false
    private val task = object : Runnable {
        override fun run() {
            if (!active) return
            try {
                check(hasUsageAccess()) { "Izin Usage Access tidak tersedia" }
                val usm = getSystemService(Context.USAGE_STATS_SERVICE) as UsageStatsManager
                val now = System.currentTimeMillis()
                val events = usm.queryEvents(now - 20_000, now)
                val event = android.app.usage.UsageEvents.Event()
                var foreground: String? = null
                while (events.hasNextEvent()) {
                    events.getNextEvent(event)
                    if (event.eventType == android.app.usage.UsageEvents.Event.MOVE_TO_FOREGROUND ||
                        (Build.VERSION.SDK_INT >= 29 && event.eventType == android.app.usage.UsageEvents.Event.ACTIVITY_RESUMED)) {
                        foreground = event.packageName
                    }
                }
                val prefs = getSharedPreferences(DomainVpnService.PREFS, MODE_PRIVATE)
                val current = foreground ?: prefs.getString("foreground_package", null)
                val watched = current != null && current in RiskStore.watchedPackages(this@AppMonitorService)
                prefs.edit().putBoolean("app_active", true).putLong("app_heartbeat", now)
                    .putString("foreground_package", current).putBoolean("risky_app_detected", watched)
                    .putString("last_risky_package", if (watched) current else prefs.getString("last_risky_package", null))
                    .putString("app_message", if (watched) "PERINGATAN: aplikasi ada dalam daftar pantauan pengguna." else "Usage Access terbaca; aplikasi latar depan dipantau.")
                    .apply()
                if (watched) RiskStore.log(this@AppMonitorService, "Aplikasi pantauan aktif: $current")
            } catch (t: Throwable) {
                getSharedPreferences(DomainVpnService.PREFS, MODE_PRIVATE).edit().putBoolean("app_active", false)
                    .putString("app_message", "Pemantauan gagal: ${t.message}").apply()
            }
            handler.postDelayed(this, 2000)
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(42, notification())
        if (!hasUsageAccess()) {
            getSharedPreferences(DomainVpnService.PREFS, MODE_PRIVATE).edit().putBoolean("app_active", false)
                .putString("app_message", "Izin Usage Access belum diberikan.").apply()
            stopSelf(); return START_NOT_STICKY
        }
        active = true; handler.removeCallbacks(task); handler.post(task)
        return START_STICKY
    }

    private fun hasUsageAccess(): Boolean {
        val ops = getSystemService(Context.APP_OPS_SERVICE) as AppOpsManager
        val mode = if (Build.VERSION.SDK_INT >= 29) ops.unsafeCheckOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, android.os.Process.myUid(), packageName)
        else ops.checkOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, android.os.Process.myUid(), packageName)
        return mode == AppOpsManager.MODE_ALLOWED
    }

    override fun onDestroy() {
        active = false; handler.removeCallbacks(task)
        getSharedPreferences(DomainVpnService.PREFS, MODE_PRIVATE).edit().putBoolean("app_active", false)
            .putString("app_message", "Pemantauan aplikasi dihentikan.").apply()
        stopForeground(STOP_FOREGROUND_REMOVE); super.onDestroy()
    }
    override fun onBind(intent: Intent?): IBinder? = null

    private fun notification(): Notification {
        val id = "jaganet_apps"
        if (Build.VERSION.SDK_INT >= 26) getSystemService(NotificationManager::class.java)
            .createNotificationChannel(NotificationChannel(id, "Jaga Net App Monitor", NotificationManager.IMPORTANCE_LOW))
        val b = if (Build.VERSION.SDK_INT >= 26) Notification.Builder(this, id) else Notification.Builder(this)
        return b.setContentTitle("Jaga Net — App monitor").setContentText("Memantau aplikasi latar depan")
            .setSmallIcon(android.R.drawable.ic_menu_view).build()
    }
}
