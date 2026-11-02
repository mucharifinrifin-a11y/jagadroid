package id.jaganet.protection

import android.content.Context
import java.net.IDN
import java.util.Locale
import java.io.File

object RiskStore {
    private const val PREFS = "jaganet"
    private const val PACKAGE_SET = "package_watch_v1"
    private val builtInTestDomains = setOf("phishing.test", "malware.test", "uji-ancaman.test")
    @Volatile private var domainCache: Set<String>? = null

    fun normalizeDomain(value: String): String? {
        val raw = value.trim().trimEnd('.').lowercase(Locale.ROOT)
        if (raw.isBlank() || raw.length > 253 || raw.contains('/') || raw.contains(':') || raw.contains(' ')) return null
        return try {
            val ascii = IDN.toASCII(raw, IDN.USE_STD3_ASCII_RULES).lowercase(Locale.ROOT)
            if (ascii.split('.').any { it.isBlank() || it.length > 63 } || !ascii.contains('.')) null else ascii
        } catch (_: Exception) { null }
    }

    fun isRiskyDomain(context: Context, host: String): Boolean {
        val normalized = normalizeDomain(host) ?: return false
        val all = domains(context)
        var candidate = normalized
        while (true) {
            if (candidate in all) return true
            val dot = candidate.indexOf('.')
            if (dot < 0) return false
            candidate = candidate.substring(dot + 1)
        }
    }

    fun domains(context: Context): Set<String> {
        domainCache?.let { return it }
        synchronized(this) {
            domainCache?.let { return it }
            val file = File(context.filesDir, "phishing-domains.txt")
            val loaded = if (file.isFile) runCatching { file.useLines { lines -> lines.mapNotNull { normalizeDomain(it) }.toSet() } }.getOrDefault(emptySet()) else emptySet()
            return (builtInTestDomains + loaded).also { domainCache = it }
        }
    }

    fun saveDomains(context: Context, domains: Set<String>) {
        val target = File(context.filesDir, "phishing-domains.txt")
        val temp = File(context.filesDir, "phishing-domains.tmp")
        temp.bufferedWriter(Charsets.UTF_8).use { writer -> domains.forEach { writer.append(it).append('\n') } }
        if (target.exists() && !target.delete()) throw IllegalStateException("Tidak dapat mengganti cache domain lama")
        if (!temp.renameTo(target)) throw IllegalStateException("Tidak dapat menyimpan cache domain baru")
        synchronized(this) { domainCache = builtInTestDomains + domains.toSet() }
    }

    fun watchedPackages(context: Context): Set<String> =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getStringSet(PACKAGE_SET, emptySet()).orEmpty()

    fun addPackage(context: Context, packageName: String): Boolean {
        val p = packageName.trim()
        if (!Regex("^[A-Za-z0-9_]+(\\.[A-Za-z0-9_]+)+$").matches(p)) return false
        val set = watchedPackages(context).toMutableSet(); set.add(p)
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putStringSet(PACKAGE_SET, set).apply()
        return true
    }

    fun removePackage(context: Context, packageName: String) {
        val set = watchedPackages(context).toMutableSet(); set.remove(packageName)
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putStringSet(PACKAGE_SET, set).apply()
    }

    fun recordBlocked(context: Context, domain: String) {
        val p = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        p.edit().putInt("blocked_domains", p.getInt("blocked_domains", 0) + 1)
            .putString("last_blocked_domain", domain).putLong("last_blocked_at", System.currentTimeMillis()).apply()
    }

    fun log(context: Context, line: String) {
        val p = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val old = p.getString("event_log", "").orEmpty().lines().filter { it.isNotBlank() }.take(79)
        p.edit().putString("event_log", (listOf("${System.currentTimeMillis()}|$line") + old).joinToString("\n")).apply()
    }
}
