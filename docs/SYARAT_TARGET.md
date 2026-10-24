# Syarat target: apa yang benar-benar menentukan rantai jalan

Dokumen ini ditulis dari percobaan langsung, bukan dari membaca kode orang.
Setiap baris di tabel bawah punya container dan perintah yang bisa diulang.

## Prasyarat versi: fix-floor dan tanggal sebenarnya

Rantai ini hanya sah untuk build **di bawah** fix-floor. Angka di bawah
diambil dari advisory php.net, bukan dari ingatan:

| Cabang | Terakhir rentan | Fix-floor |
|---|---|---|
| 8.5 | 8.5.11 | **8.5.12** |
| 8.4 | 8.4.26 | **8.4.27** |
| 8.3 | 8.3.35 | **8.3.36** |
| 8.2 | 8.2.34 | **8.2.35** |

Build resmi 8.5.12 dan 8.4.27 keluar **22 Okt 2026** (bukan 21 — tanggal ini
sempat salah di dokumentasi awal repo). Build yang lebih baru dari fix-floor
**tidak** dieksploitasi oleh rantai ini; `preflight` melaporkan dukungan versi
sebelum ada paket dikirim.

## Peringatan mitigasi yang sering dikutip salah

| Yang sering disarankan | Kenyataannya |
|---|---|
| `memory_limit=-1` sebagai mitigasi | **BUKAN mitigasi lengkap.** Batas memori besar hanya memindahkan titik kegagalan; jalur `longjmp` tetap bisa tercapai. Jangan jadikan ini alasan "sudah aman". |
| `session.upload_progress.enabled=Off` | Menutup CVE-2026-109618, **tidak** menutup CVE-2026-109619 (rantai yang dipakai tool ini). |
| Menunggu patch tanpa mitigasi lain | Eksploitasi liar tercatat sejak **17 Okt 2026**, empat hari sebelum build patch terbit. |

Selain dua CVE di atas, advisory 23 Okt 2026 mencatat **CVE-2026-115560**
("Session upload progress") yang fix-nya menyusul. Ini dicatat sebagai
informasi — **bukan** blocker rantai dan bukan alasan menahan rilis.

## Ringkasnya

Rantai gagal di stage 1 (`HEAP_LEAK_FAILED`) bukan karena jumlah worker
Apache, melainkan karena **request tidak pernah sampai utuh ke PHP**.
Kalau `post_max_size` lebih kecil dari body yang kita kirim, PHP membuang
body itu sebelum kode apa pun jalan — dan tidak ada yang bisa dileak.

Dua setelan yang wajib longgar:

| Setelan | Kenapa | Nilai aman |
|---|---|---|
| `post_max_size` | body stage-1 lebih besar dari `memory_limit`; kalau ini lebih kecil, body dibuang mentah-mentah | ≥ 64M |
| `upload_max_filesize` | batas per-file untuk field multipart | ≥ 64M |

Setelan yang **tidak** berpengaruh (sudah diuji):

| Setelan | Dugaan | Hasil uji |
|---|---|---|
| `MaxRequestWorkers` | butuh 150 worker, sisakan 1 untuk rantai (klaim 9bie) | **tidak terbukti** — jalan di 1 worker, jalan di 150 worker |
| `StartServers` / `MinSpareServers` | sama | tidak berpengaruh |
| `KeepAlive` | harus Off | membantu determinisme, bukan syarat |
| `display_errors = On` vs `STDOUT` | harus On | tidak wajib; probe menangani keduanya (`STDOUT` di Apache berarti pesan fatal tidak masuk respons HTTP) |

## Percobaan yang membuktikannya

Basis: `php:8.4.26-apache` stock, `memory_limit=8M`, mount sama seperti lab repo.

| # | `MaxRequestWorkers` | `post_max_size` | Hasil |
|---|---|---|---|
| 1 | 150 (stock) | **8M** (stock) | `HEAP_LEAK_FAILED` 4,2s — 3 percobaan |
| 2 | **1** | **8M** | `HEAP_LEAK_FAILED` 4,1s — jadi worker BUKAN penyebabnya |
| 3 | 1 | **64M** | `PROOF (8.0s): uid=33(www-data)` |
| 4 | **150** | **64M** | `PROOF (7.7s): uid=33(www-data)` — 1 retry stage-1, lalu sukses |

Baris 2 adalah yang membatalkan klaim worker pinning: dengan 1 worker
(tanpa kompetisi sama sekali) rantai tetap gagal. Baris 3 dan 4 lolos
dengan jumlah worker yang berbeda-beda. Variabelnya `post_max_size`.

## Cara memeriksa target sebelum menembak

```bash
# 1. batas body yang dilihat PHP
php -i | grep -E '^post_max_size|^upload_max_filesize|^memory_limit'

# 2. kalau punya akses HTTP saja: kirim body besar, lihat apakah dibuang
#    (respons kosong / 413 = body tidak sampai)
```

## Kanal bukti: `--proof-file`

`-c 'id'` tanpa redirect selalu berakhir **BLIND**: eksekusi bisa sukses tapi
tidak ada apa pun yang kembali dalam respons HTTP. Kanal bukti memerlukan
redirect ke file di target, dan `--proof-file NAME` adalah cara yang didukung:

```bash
php2shell.py exploit -u http://target/index.php --yes --proof-file pv
# setara -c 'id>/out/pv'  ->  hasil dibaca dari /out/pv
```

Nama file dibatasi `[A-Za-z0-9_-]{1,24}` dan perintah dasarnya wajib termasuk
perintah identitas (`id`/`whoami`/`uname`/`hostname`/`pwd`). Ini bukan
kemudahan kosmetik: membentuk redirect berarti membuka jalur tulis ke disk
target, jadi permukaannya sengaja sempit. Jalur baca di sisi host adalah
`<repo>/out/<NAME>` (mount `/out` milik lab).

`php2shell.py preflight -u <url>` mencetak skor + dukungan build, tapi
**tidak** bisa mengukur `post_max_size` dari luar tanpa mengirim body besar.
Itulah sebabnya probe `memory_limit` di `lib/memprobe.py` mengirim field
16 MB: kalau target memakai `post_max_size` yang lebih kecil, probe
mengembalikan "tidak terbaca" — dan itu sendiri sudah sinyal bahwa body
tidak akan sampai.

## Untuk lab

`docker/php.ini` di repo sudah memuat nilai yang benar:

```ini
memory_limit = 8M
post_max_size = 64M
upload_max_filesize = 64M
session.upload_progress.enabled = On
session.upload_progress.cleanup = On
```

`docker/apache.conf` sengaja memakai **1 worker** (`MaxRequestWorkers 1`)
bukan karena rantai membutuhkannya, tapi supaya lab deterministik: rotasi
worker (`rotate()`) yang dipakai strategi retry jadi bisa diprediksi.
Di produksi, jumlah worker bebas — asal `post_max_size` cukup.

## Kredit

Klaim "150 worker, sisakan 1" berasal dari
`9bie/php2shell-bypass-aslr-exp`. Diuji ulang di sini dan tidak terbukti
sebagai syarat; angka 150 ternyata hanya bawaan `mpm_prefork.conf` stock,
bukan setelan yang dipilih penulisnya.
