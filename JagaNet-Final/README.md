# Jaga Net Android — source project 1.1.0

Aplikasi Android native Kotlin untuk pengujian proteksi DNS dan pemantauan aplikasi latar depan.

## Fitur
- VPNService DNS filter: route hanya ke alamat DNS virtual `10.77.0.2/32`; trafik IP lain tidak diarahkan ke TUN.
- Forwarding DNS UDP/53 ke Cloudflare `1.1.1.1`, fallback Google `8.8.8.8` menggunakan socket yang di-protect dari VPN.
- Domain phishing feed aktif dari Phishing.Database (GitHub raw). Download manual melalui tombol; parsing divalidasi, batas 600.000 entri; cache lama dipertahankan jika update gagal.
- Domain uji lokal `phishing.test`, `malware.test`, `uji-ancaman.test` tetap tersedia untuk pengujian.
- App foreground monitor memakai Usage Access dan membandingkan package ID dengan daftar pantauan yang dimasukkan pengguna.
- Status mesin terpisah, log peristiwa, uji resolusi DNS, dan notifikasi foreground service.

## Build
1. Ekstrak ZIP.
2. Buka folder `JagaNet-Final` di Android Studio (Hedgehog atau lebih baru).
3. Gunakan JDK 17 dan Android SDK Platform 35; tunggu Gradle Sync.
4. Build > Build APK(s). APK debug akan berada di `app/build/outputs/apk/debug/`.

## Izin saat penggunaan
- Pengguna harus menyetujui VPN Android.
- Pengguna harus mengaktifkan Usage Access untuk Jaga Net.
- Android 13+ mungkin meminta izin notifikasi.

## Pengujian
1. Pasang APK dan berikan izin VPN + Usage Access.
2. Tekan **PERBARUI DAFTAR PHISHING** saat internet tersedia. Feed aktif Phishing.Database diunduh ke cache lokal. Jika feed gagal, daftar lama tidak dihapus.
3. Tekan **AKTIFKAN PERLINDUNGAN**. Pastikan dua kartu status menunjukkan AKTIF.
4. Tekan **UJI RESOLUSI DNS** dan buka beberapa situs normal untuk memastikan koneksi tetap berjalan.
5. Untuk uji domain, gunakan resolver sistem pada lingkungan pengujian dan query `phishing.test` / `malware.test`; domain `.test` adalah domain reserved, bukan situs publik. Karena Android/browser dapat melakukan cache, gunakan sesi baru atau bersihkan cache DNS.
6. Untuk uji aplikasi, masukkan package ID aplikasi uji yang ingin ditandai, lalu buka aplikasi tersebut. Detektor hanya menandai package yang telah dimasukkan.

## Batasan yang harus dipahami
Ini bukan antivirus penuh dan tidak menjamin semua ancaman terdeteksi. Filter VPN ini hanya memproses DNS IPv4 UDP/53 yang masuk ke resolver virtual Android. DNS-over-HTTPS, DNS-over-TLS, DNS IPv6, DNS TCP, resolver hard-coded aplikasi, koneksi langsung ke IP, dan beberapa konfigurasi Private DNS dapat melewati filter atau membuat DNS tidak tersedia. Aplikasi monitor bukan pemindai APK; ia hanya memantau package foreground dan mencocokkannya dengan daftar pantauan manual. Feed komunitas dapat mengandung false positive dan tidak mencakup semua phishing/malware.

Untuk perlindungan jaringan penuh diperlukan implementasi packet stack lengkap (IPv4/IPv6, TCP/UDP, fragmentasi, DNS TCP), kebijakan Private DNS/DoH yang kompatibel, threat intelligence multi-sumber, serta pengujian perangkat nyata lintas vendor. Jangan memasarkan build ini sebagai perlindungan menyeluruh.

## Sumber feed
Phishing.Database: https://github.com/Phishing-Database/Phishing.Database
Feed yang dipakai: https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt
