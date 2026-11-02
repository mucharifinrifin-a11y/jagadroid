package id.jaganet.protection

import android.content.Context
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL

object FeedUpdater {
    // Community-maintained active phishing-domain feed. Built-in test domains are kept separately.
    private const val FEED_URL = "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt"
    fun update(context: Context): Result<Int> = runCatching {
        val connection = (URL(FEED_URL).openConnection() as HttpURLConnection).apply {
            connectTimeout = 15000; readTimeout = 25000; requestMethod = "GET"
            setRequestProperty("User-Agent", "JagaNet-Android/1.1")
            setRequestProperty("Accept", "text/plain")
        }
        try {
            val code = connection.responseCode
            check(code == 200) { "Server feed membalas HTTP $code" }
            val parsed = LinkedHashSet<String>()
            BufferedReader(InputStreamReader(connection.inputStream, Charsets.UTF_8)).use { reader ->
                while (true) {
                    val line = reader.readLine() ?: break
                    val candidate = line.trim().substringBefore('#').trim()
                    if (candidate.isBlank() || candidate.startsWith("!") || candidate.startsWith("[") || candidate.contains(" ")) continue
                    val domain = RiskStore.normalizeDomain(candidate.removePrefix("0.0.0.0 ").removePrefix("127.0.0.1 "))
                    if (domain != null) parsed.add(domain)
                    require(parsed.size <= 600_000) { "Feed melewati batas keamanan 600.000 domain" }
                }
            }
            check(parsed.size >= 1000) { "Feed tidak lengkap atau formatnya berubah (${parsed.size} domain)" }
            RiskStore.saveDomains(context, parsed)
            context.getSharedPreferences(DomainVpnService.PREFS, Context.MODE_PRIVATE).edit()
                .putLong("feed_updated_at", System.currentTimeMillis()).putString("feed_source", FEED_URL).apply()
            RiskStore.log(context, "Daftar phishing diperbarui: ${parsed.size} domain")
            parsed.size
        } finally { connection.disconnect() }
    }
}
