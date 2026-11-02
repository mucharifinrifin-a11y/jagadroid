package id.jaganet.protection

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

/** DNS filter VPN. Only the synthetic DNS endpoint is routed into this TUN; other IP traffic is not routed. */
class DomainVpnService : VpnService() {
    @Volatile private var tun: ParcelFileDescriptor? = null
    private val running = AtomicBoolean(false)
    @Volatile private var worker: Thread? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(NOTIFICATION_ID, notification())
        if (running.compareAndSet(false, true)) startTunnel()
        return START_STICKY
    }

    private fun startTunnel() {
        try {
            val descriptor = Builder().setSession("Jaga Net DNS Filter").setMtu(1500)
                .addAddress(VPN_DNS, 32).addDnsServer(VPN_DNS).addRoute(VPN_DNS, 32)
                .setBlocking(true).establish()
            if (descriptor == null) throw IllegalStateException("Android tidak memberikan antarmuka VPN/TUN. Periksa izin VPN atau konflik VPN lain.")
            tun = descriptor
            worker = thread(name = "JagaNet-DNS", isDaemon = true) { dnsLoop(descriptor) }
            if (worker?.isAlive != true) throw IllegalStateException("Thread pemroses DNS tidak berhasil berjalan")
            state(true, "TUN aktif; pemroses DNS UDP/53 berjalan.")
            RiskStore.log(this, "Detektor DNS aktif")
        } catch (t: Throwable) {
            running.set(false); state(false, "Gagal mengaktifkan VPN: ${t.message ?: t.javaClass.simpleName}")
            RiskStore.log(this, "Gagal aktivasi DNS: ${t.message}")
            stopSelf()
        }
    }

    private data class Packet(val src: ByteArray, val dst: ByteArray, val srcPort: Int, val dstPort: Int, val dns: ByteArray, val name: String)

    private fun dnsLoop(fd: ParcelFileDescriptor) {
        val input = FileInputStream(fd.fileDescriptor)
        val output = FileOutputStream(fd.fileDescriptor)
        val buffer = ByteArray(32767)
        try {
            while (running.get()) {
                val length = input.read(buffer)
                if (length <= 0) continue
                val parsed = parsePacket(buffer.copyOf(length)) ?: continue
                val response = if (RiskStore.isRiskyDomain(this, parsed.name)) {
                    RiskStore.recordBlocked(this, parsed.name)
                    RiskStore.log(this, "Domain diblokir: ${parsed.name}")
                    blockedResponse(parsed.dns)
                } else forwardDns(parsed.dns)
                if (response != null && running.get()) output.write(buildReply(parsed, response))
            }
        } catch (t: Throwable) {
            if (running.get()) {
                state(false, "Worker DNS berhenti: ${t.message ?: t.javaClass.simpleName}")
                RiskStore.log(this, "Worker DNS gagal: ${t.message}")
            }
        } finally {
            running.set(false)
            try { input.close() } catch (_: Exception) {}
            try { output.close() } catch (_: Exception) {}
            try { fd.close() } catch (_: Exception) {}
            tun = null
        }
    }

    private fun parsePacket(p: ByteArray): Packet? {
        if (p.size < 28 || (p[0].toInt() ushr 4 and 0xF) != 4) return null
        val ihl = (p[0].toInt() and 0xF) * 4
        if (ihl < 20 || p.size < ihl + 8 || (p[9].toInt() and 0xFF) != 17) return null
        val fragment = u16(p, 6)
        if ((fragment and 0x3FFF) != 0) return null
        val src = p.copyOfRange(12, 16); val dst = p.copyOfRange(16, 20)
        val srcPort = u16(p, ihl); val dstPort = u16(p, ihl + 2); val udpLength = u16(p, ihl + 4)
        if (dstPort != 53 || udpLength < 8 || p.size < ihl + udpLength) return null
        val dns = p.copyOfRange(ihl + 8, ihl + udpLength)
        val name = readQName(dns) ?: return null
        return Packet(src, dst, srcPort, dstPort, dns, name)
    }

    private fun readQName(dns: ByteArray): String? {
        if (dns.size < 17) return null
        var i = 12; val labels = ArrayList<String>()
        while (i < dns.size) {
            val n = dns[i++].toInt() and 0xFF
            if (n == 0) break
            if (n > 63 || i + n > dns.size) return null
            val label = String(dns, i, n, Charsets.US_ASCII)
            if (label.any { it.code < 33 || it.code > 126 }) return null
            labels.add(label); i += n
            if (labels.size > 40) return null
        }
        return labels.takeIf { it.isNotEmpty() }?.joinToString(".")?.lowercase()
    }

    private fun forwardDns(query: ByteArray): ByteArray? {
        val servers = listOf("1.1.1.1", "8.8.8.8")
        for (server in servers) {
            var socket: DatagramSocket? = null
            try {
                socket = DatagramSocket()
                check(protect(socket)) { "Tidak dapat mengecualikan socket upstream dari VPN" }
                socket.soTimeout = 2800
                val target = InetAddress.getByName(server)
                socket.send(DatagramPacket(query, query.size, target, 53))
                val data = ByteArray(4096); val packet = DatagramPacket(data, data.size)
                socket.receive(packet)
                val response = data.copyOf(packet.length)
                if (response.size >= 12 && response[0] == query[0] && response[1] == query[1] && (response[2].toInt() and 0x80) != 0) return response
            } catch (_: Throwable) {
                // Try the next resolver. Do not claim DNS is healthy if both fail.
            } finally { socket?.close() }
        }
        state(true, "TUN hidup, tetapi kedua DNS upstream gagal. Resolusi nama mungkin terganggu.")
        return null
    }

    private fun blockedResponse(query: ByteArray): ByteArray {
        val out = query.copyOf()
        out[2] = ((out[2].toInt() and 0xFF) or 0x80).toByte()
        out[3] = ((out[3].toInt() and 0xF0) or 0x03).toByte()
        for (i in 6..11) out[i] = 0
        return out
    }

    private fun buildReply(req: Packet, dns: ByteArray): ByteArray {
        val total = 28 + dns.size
        val p = ByteArray(total)
        p[0] = 0x45; p[2] = (total ushr 8).toByte(); p[3] = total.toByte()
        p[4] = 0; p[5] = 1; p[8] = 64; p[9] = 17
        System.arraycopy(req.dst, 0, p, 12, 4); System.arraycopy(req.src, 0, p, 16, 4)
        val ipSum = checksum(p, 0, 20); p[10] = (ipSum ushr 8).toByte(); p[11] = ipSum.toByte()
        p[20] = (req.dstPort ushr 8).toByte(); p[21] = req.dstPort.toByte()
        p[22] = (req.srcPort ushr 8).toByte(); p[23] = req.srcPort.toByte()
        val udpLen = 8 + dns.size; p[24] = (udpLen ushr 8).toByte(); p[25] = udpLen.toByte()
        System.arraycopy(dns, 0, p, 28, dns.size)
        return p
    }

    private fun checksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0L; var i = offset
        while (i < offset + length - 1) { sum += (((data[i].toInt() and 255) shl 8) or (data[i+1].toInt() and 255)).toLong(); i += 2 }
        if (i < offset + length) sum += ((data[i].toInt() and 255) shl 8).toLong()
        while ((sum ushr 16) != 0L) sum = (sum and 0xFFFF) + (sum ushr 16)
        return sum.inv().toInt() and 0xFFFF
    }
    private fun u16(b: ByteArray, i: Int) = ((b[i].toInt() and 255) shl 8) or (b[i+1].toInt() and 255)

    private fun state(active: Boolean, message: String) {
        getSharedPreferences(PREFS, MODE_PRIVATE).edit().putBoolean("vpn_active", active)
            .putString("vpn_message", message).putLong("vpn_state_at", System.currentTimeMillis()).apply()
    }

    private fun notification(): Notification {
        val channel = "jaganet_vpn"
        if (Build.VERSION.SDK_INT >= 26) getSystemService(NotificationManager::class.java)
            .createNotificationChannel(NotificationChannel(channel, "Jaga Net DNS Protection", NotificationManager.IMPORTANCE_LOW))
        val b = if (Build.VERSION.SDK_INT >= 26) Notification.Builder(this, channel) else Notification.Builder(this)
        return b.setContentTitle("Jaga Net — DNS filter").setContentText("Memproses DNS IPv4 UDP/53")
            .setSmallIcon(android.R.drawable.ic_lock_lock).build()
    }

    override fun onRevoke() { stopVpn("Izin VPN dicabut oleh Android/pengguna."); super.onRevoke() }
    override fun onDestroy() { stopVpn("Layanan VPN dihentikan."); super.onDestroy() }
    private fun stopVpn(reason: String) {
        running.set(false); try { tun?.close() } catch (_: Exception) {}; tun = null
        state(false, reason); stopForeground(STOP_FOREGROUND_REMOVE)
    }

    companion object {
        const val PREFS = "jaganet"
        const val VPN_DNS = "10.77.0.2"
        const val NOTIFICATION_ID = 41
    }
}
