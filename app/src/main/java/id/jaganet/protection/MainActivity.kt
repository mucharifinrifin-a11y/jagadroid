package id.jaganet.protection

import android.app.Activity
import android.app.AppOpsManager
import android.content.Context
import android.content.Intent
import android.graphics.Typeface
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.view.View
import android.view.inputmethod.InputMethodManager
import android.widget.*
import java.net.InetAddress
import java.text.DateFormat
import java.util.Date
import kotlin.concurrent.thread

class MainActivity : Activity() {
    private lateinit var prefs: android.content.SharedPreferences
    private lateinit var summary: TextView
    private lateinit var dnsCard: TextView
    private lateinit var appCard: TextView
    private lateinit var feedCard: TextView
    private lateinit var logCard: TextView
    private lateinit var activate: Button
    private lateinit var stop: Button
    private lateinit var testButton: Button
    private lateinit var feedButton: Button
    private lateinit var packageInput: EditText
    private lateinit var packageList: TextView
    private val refresh = object : Runnable { override fun run() { render(); window.decorView.postDelayed(this, 1200) } }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        prefs = getSharedPreferences(DomainVpnService.PREFS, MODE_PRIVATE)
        buildUi()
    }

    private fun buildUi() {
        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setBackgroundColor(0xFF071B17.toInt()) }
        val scroll = ScrollView(this)
        val content = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(20, 26, 20, 28) }
        content.addView(label("JAGA NET", 30, 0xFF8AF0C6.toInt(), true))
        content.addView(label("Perlindungan domain dan aplikasi", 14, 0xFFB6C9C1.toInt(), false))
        content.addView(space(18))
        summary = label("PERLINDUNGAN BELUM AKTIF", 18, 0xFFFFFFFF.toInt(), true); content.addView(card(summary))
        dnsCard = label("Detektor domain/DNS: belum aktif", 14, 0xFFE4F1EC.toInt(), false); content.addView(card(dnsCard))
        appCard = label("Detektor aplikasi: belum aktif", 14, 0xFFE4F1EC.toInt(), false); content.addView(card(appCard))
        activate = button("AKTIFKAN PERLINDUNGAN") { activateProtection() }; content.addView(activate)
        stop = button("HENTIKAN PERLINDUNGAN") { stopProtection() }; content.addView(stop)
        content.addView(space(18)); content.addView(label("DAFTAR RISIKO DOMAIN", 17, 0xFF8AF0C6.toInt(), true))
        feedCard = label("Daftar lokal: 3 domain uji", 13, 0xFFE4F1EC.toInt(), false); content.addView(card(feedCard))
        feedButton = button("PERBARUI DAFTAR PHISHING") { updateFeed() }; content.addView(feedButton)
        content.addView(label("Sumber: Phishing.Database — komunitas open-source. Feed dapat mengandung false positive; daftar lama tetap dipakai bila pembaruan gagal.", 12, 0xFFA9BBB4.toInt(), false))
        content.addView(space(18)); content.addView(label("DAFTAR PANTAU APLIKASI", 17, 0xFF8AF0C6.toInt(), true))
        content.addView(label("Masukkan package ID aplikasi yang ingin ditandai. Mesin memantau aplikasi latar depan dan membandingkannya dengan daftar ini.", 12, 0xFFA9BBB4.toInt(), false))
        packageInput = EditText(this).apply { hint = "contoh: com.example.suspicious"; setSingleLine(true); textSize = 14f }
        content.addView(packageInput)
        content.addView(button("TAMBAHKAN PACKAGE ID") { addPackage() })
        packageList = label("Belum ada package pantauan.", 13, 0xFFE4F1EC.toInt(), false); content.addView(card(packageList))
        content.addView(button("BUKA IZIN USAGE ACCESS") { startActivity(Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS)) })
        content.addView(space(18)); content.addView(label("PENGUJIAN KONEKSI", 17, 0xFF8AF0C6.toInt(), true))
        testButton = button("UJI RESOLUSI DNS") { testDns() }; content.addView(testButton)
        content.addView(label("Pengujian memeriksa resolusi nama melalui resolver Android. Tes ini tidak membuktikan seluruh jenis trafik telah difilter.", 12, 0xFFA9BBB4.toInt(), false))
        content.addView(space(18)); content.addView(label("RIWAYAT DETEKSI", 17, 0xFF8AF0C6.toInt(), true))
        logCard = label("Belum ada aktivitas.", 12, 0xFFE4F1EC.toInt(), false); content.addView(card(logCard))
        content.addView(space(14)); content.addView(label("BATASAN TEKNIS", 12, 0xFFFFD28A.toInt(), true))
        content.addView(label("Filter jaringan saat ini memproses DNS IPv4 UDP/53 yang melewati resolver Android. DNS-over-HTTPS, DNS-over-TLS, DNS IPv6, DNS TCP, resolver khusus aplikasi, dan trafik yang tidak menggunakan DNS sistem dapat melewati filter. Pemantauan aplikasi hanya menandai package ID yang kamu masukkan; ini bukan antivirus pemindai APK.", 12, 0xFFB8C7C1.toInt(), false))
        scroll.addView(content); root.addView(scroll); setContentView(root)
    }

    private fun activateProtection() {
        activate.isEnabled = false
        if (!hasUsageAccess()) {
            activate.isEnabled = true
            summary.text = "IZIN USAGE ACCESS DIPERLUKAN — aktifkan izin lalu tekan tombol lagi."
            startActivity(Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS)); return
        }
        val consent = VpnService.prepare(this)
        if (consent != null) startActivityForResult(consent, REQ_VPN) else startEngines()
    }

    @Deprecated("Kept for compatibility with Android versions supported by this app")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQ_VPN) {
            if (resultCode == RESULT_OK) startEngines()
            else { summary.text = "IZIN VPN DITOLAK — detektor domain tidak aktif."; activate.isEnabled = true }
        }
    }

    private fun startEngines() {
        try {
            val vpn = Intent(this, DomainVpnService::class.java)
            val app = Intent(this, AppMonitorService::class.java)
            if (Build.VERSION.SDK_INT >= 26) { startForegroundService(vpn); startForegroundService(app) }
            else { startService(vpn); startService(app) }
            summary.text = "PERINTAH DIKIRIM — menunggu verifikasi kedua layanan…"
            RiskStore.log(this, "Pengguna meminta aktivasi perlindungan")
        } catch (t: Throwable) { summary.text = "GAGAL MEMULAI: ${t.message}" }
        activate.isEnabled = true
    }

    private fun stopProtection() {
        stopService(Intent(this, DomainVpnService::class.java)); stopService(Intent(this, AppMonitorService::class.java))
        summary.text = "PERINTAH PENGHENTIAN DIKIRIM"; RiskStore.log(this, "Perlindungan dihentikan pengguna"); render()
    }

    private fun updateFeed() {
        feedButton.isEnabled = false; feedCard.text = "Mengunduh dan memvalidasi daftar phishing…"
        thread(name = "JagaNet-Feed") {
            val result = FeedUpdater.update(this)
            runOnUiThread {
                feedButton.isEnabled = true
                feedCard.text = result.fold({ "Berhasil: $it domain tersimpan. Daftar uji lokal tetap tersedia." }, { "GAGAL memperbarui feed: ${it.message}. Daftar tersimpan tidak dihapus." })
                render()
            }
        }
    }

    private fun testDns() {
        testButton.isEnabled = false; summary.text = "SEDANG MENGUJI RESOLUSI DNS…"
        thread(name = "JagaNet-DNSTest") {
            val result = runCatching { InetAddress.getAllByName("example.com").joinToString { it.hostAddress ?: "?" } }
            runOnUiThread {
                testButton.isEnabled = true
                summary.text = result.fold({ "DNS BERHASIL: $it" }, { "DNS GAGAL: ${it.message}" })
                RiskStore.log(this, summary.text.toString())
            }
        }
    }

    private fun addPackage() {
        val value = packageInput.text.toString().trim()
        if (RiskStore.addPackage(this, value)) {
            packageInput.setText(""); (getSystemService(INPUT_METHOD_SERVICE) as InputMethodManager).hideSoftInputFromWindow(packageInput.windowToken, 0)
            RiskStore.log(this, "Package ditambahkan ke daftar pantau: $value"); render()
        } else Toast.makeText(this, "Package ID tidak valid. Contoh: com.example.app", Toast.LENGTH_LONG).show()
    }

    private fun hasUsageAccess(): Boolean {
        val ops = getSystemService(Context.APP_OPS_SERVICE) as AppOpsManager
        val mode = if (Build.VERSION.SDK_INT >= 29) ops.unsafeCheckOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, android.os.Process.myUid(), packageName)
        else ops.checkOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, android.os.Process.myUid(), packageName)
        return mode == AppOpsManager.MODE_ALLOWED
    }

    private fun render() {
        val vpn = prefs.getBoolean("vpn_active", false)
        val app = prefs.getBoolean("app_active", false) && hasUsageAccess()
        dnsCard.text = "Detektor domain/DNS: ${if (vpn) "AKTIF" else "TIDAK AKTIF"}\n${prefs.getString("vpn_message", "Belum dijalankan") ?: ""}"
        appCard.text = "Detektor aplikasi: ${if (app) "AKTIF" else "TIDAK AKTIF"}\n${prefs.getString("app_message", "Belum dijalankan") ?: ""}\nAplikasi latar depan: ${prefs.getString("foreground_package", "—") ?: "—"}\n${if (prefs.getBoolean("risky_app_detected", false)) "PERINGATAN: ${prefs.getString("last_risky_package", "")}" else "Tidak ada package pantauan terdeteksi."}"
        summary.text = if (vpn && app) "KEDUA MESIN DETEKTOR AKTIF" else "PERLINDUNGAN BELUM LENGKAP"
        stop.isEnabled = vpn || app
        val updated = prefs.getLong("feed_updated_at", 0L)
        feedCard.text = "${RiskStore.domains(this).size} domain tersimpan (termasuk domain uji).\nPembaruan terakhir: ${if (updated > 0) DateFormat.getDateTimeInstance().format(Date(updated)) else "belum pernah"}"
        packageList.text = RiskStore.watchedPackages(this).sorted().joinToString("\n") { "• $it" }.ifBlank { "Belum ada package pantauan." }
        logCard.text = prefs.getString("event_log", "").orEmpty().lines().take(12).joinToString("\n") { row ->
            val parts = row.split('|', limit = 2); if (parts.size == 2) "${DateFormat.getTimeInstance().format(Date(parts[0].toLongOrNull() ?: 0L))}  ${parts[1]}" else row
        }.ifBlank { "Belum ada aktivitas." }
    }

    override fun onResume() { super.onResume(); if (::prefs.isInitialized) window.decorView.post(refresh) }
    override fun onPause() { if (::prefs.isInitialized) window.decorView.removeCallbacks(refresh); super.onPause() }

    private fun label(value: String, size: Int, color: Int, bold: Boolean) = TextView(this).apply {
        text = value; textSize = size.toFloat(); setTextColor(color); if (bold) setTypeface(null, Typeface.BOLD); setPadding(4, 8, 4, 8)
    }
    private fun card(view: View) = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL; setPadding(14, 10, 14, 10); setBackgroundColor(0xFF12352C.toInt()); addView(view)
        val p = LinearLayout.LayoutParams(-1, -2); p.bottomMargin = 10; layoutParams = p
    }
    private fun button(title: String, action: () -> Unit) = Button(this).apply {
        text = title; isAllCaps = false; setOnClickListener { action() }; val p = LinearLayout.LayoutParams(-1, -2); p.bottomMargin = 8; layoutParams = p
    }
    private fun space(h: Int) = View(this).apply { layoutParams = LinearLayout.LayoutParams(1, h) }
    companion object { private const val REQ_VPN = 710 }
}
