# Catatan riset tertutup

Dokumen ini mencatat **hipotesis yang sudah diuji dan ditutup**, supaya tidak
ada yang mengira masih terbuka. Setiap penutupan harus menyebut bukti yang
membantahnya, bukan sekadar "sudah dicek".

---

## 1. PDO `setFetchMode()` saat fetch — TIDAK ADA UAF

**Status: DITUTUP 2026-10-24. Bukan kerentanan.**

Hipotesis awal: memanggil `PDOStatement::setFetchMode(PDO::FETCH_INTO, $obj)`
di tengah iterasi `fetch()` bisa membuat `stmt->fetch.into` dibebaskan sementara
`do_fetch()` masih memegang pointer lama → UAF.

**Bukti pembantah**, dibaca dari `php-8.4.26.tar.xz` resmi
(`ext/pdo/pdo_stmt.c`), bukan dari ingatan:

| Baris | Isi | Arti |
|---|---|---|
| 1722–1726 | `case PDO_FETCH_INTO:` → `if (!Z_ISUNDEF) { zval_ptr_dtor; ZVAL_UNDEF }` | destruksi terjadi **sebelum** mode baru dipasang, dan langsung di-undef |
| 1843–1856 | wajib `Z_TYPE(args[0]) == IS_OBJECT`, lalu `ZVAL_COPY(&stmt->fetch.into, &args[0])` | `ZVAL_COPY` menaikkan refcount — objek tidak bisa dibebaskan pemilik aslinya saat masih dirujuk stmt |
| 864–873 | `do_fetch()`: `if (Z_ISUNDEF(stmt->fetch.into)) { raise "No fetch-into object specified."; return 0; }` | setiap pembacaan dijaga; tidak ada deref buta |
| 2149–2151 | `free_obj`: dtor hanya bila `!Z_ISUNDEF && default_fetch_type == PDO_FETCH_INTO` | tidak ada double-free saat shutdown |

Enam situs referensi `fetch.into` di seluruh file: `865/866`, `873`,
`1723/1724/1725`, `1856`, `2102`, `2149/2150/2151`. Semuanya ber-guard atau
berurutan benar (`dtor` → `undef` → `copy`).

**Kesimpulan:** tidak ada stale pointer, tidak ada jalur baca tanpa cek.
Hipotesis gugur di tingkat source.

**Yang TIDAK dilakukan:** build ASAN 2–3 GB. Alasannya biaya, bukan
kelalaian — hipotesis sudah dibantah oleh kode yang akan diuji, jadi build
tidak akan menambah informasi. Kalau nanti ada varian baru (mis.
`FETCH_CLASS` + `ctor_args`, atau interaksi `PDO::ATTR_STATEMENT_CLASS`),
build ASAN baru punya alasan.

---

## 2. "Worker pinning 150" sebagai prasyarat rantai — SALAH

**Status: DITUTUP 2026-10-24.**

Klaim upstream (9bie) bahwa `MaxRequestWorkers 150` + sisakan 1 worker
dibutuhkan. Uji terkontrol di `p2s-lab-8426`:

| MaxRequestWorkers | post_max_size | Hasil |
|---|---|---|
| 150 | 8M | `HEAP_LEAK_FAILED` 4,2s |
| 1 | 8M | `HEAP_LEAK_FAILED` 4,1s |
| 1 | 64M | **`PROOF (8,0s): uid=33(www-data)`** |
| 150 | 64M | **`PROOF (7,7s)`** |

Variabel yang menentukan = `post_max_size` (`body_cap`), bukan jumlah worker.
Angka 150 ternyata hanya bawaan `mpm_prefork.conf` stock.

---

## 3. Persistence lintas restart — NOL

**Status: DITUTUP 2026-10-24.**

PID induk 14378 → 57520 setelah `docker restart`; worker lama hilang. Cookie
sesi lama dijawab `HTTP 200, Content-Length: 3, isi "OK"` — request dilayani,
nol eksekusi. File `/out/p1` masih ada sesudah restart, tetapi itu **artefak
hasil eksekusi**, bukan bukti akses. Rerun rantai dari nol tetap
`PROOF (10,5s)`.

---

## 4. `memory_limit=-1` sebagai mitigasi lengkap — SALAH

**Status: DITUTUP 2026-10-24.**

`memory_limit=-1` menghapus satu jalur pemicu (OOM fatal), tetapi trigger
CVE-2026-109619 tetap bisa menghasilkan fatal error bentuk lain dan `longjmp`
di tengah callback. Mitigasi lengkap tetap: patch ke fix-floor
(8.2.35 / 8.3.36 / 8.4.27 / 8.5.12).

---

## 5. Tanggal build 8.5.12 / 8.4.27 — 22 Oktober, bukan 21

**Status: KOREKSI FAKTA 2026-10-24.**

Rilis awal dijadwalkan 21 Okt, build final keluar **22 Okt 2026**. Dua build
dengan nomor versi sama bisa berbeda tanggal; verifikasi tanggal paket, bukan
hanya nomor versi.

---

## 6. CVE-2026-115560 — NYATA (koreksi atas penolakan saya sendiri)

**Status: KOREKSI 2026-10-24.**

Saya sempat menolaknya sebagai palsu karena MITRE mengembalikan 404. Itu salah:
advisory php.net 23 Okt 2026 ("Session upload progress") membuktikannya nyata.
Dicatat di `lib/advisory.py` sebagai **informasi**, bukan blocker, dan bukan
bagian rantai yang dieksploitasi toolkit ini.

Pelajaran: 404 di satu sumber bukan bukti ketiadaan. Cek sumber primer vendor
sebelum menyimpulkan sesuatu "tidak ada".
