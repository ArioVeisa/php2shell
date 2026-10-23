"""banner.py — ASCII art + identitas toolkit php2shell.

Semua teks di sini murni presentasi. Tidak ada logika jaringan.
Warna mati otomatis bila stdout bukan TTY atau NO_COLOR diset.
"""

from __future__ import annotations

import os
import sys

CVE_IDS = "CVE-2026-109618 / CVE-2026-109619"

# Font standard, DIGENERATE dengan `figlet -w 100 "PHP2SHELL"` — jangan
# diketik manual. Versi lama salah: terbaca P-H-P-P-S-H-E-L-L (P dobel,
# angka 2 hilang) karena huruf 'P' keempat dan '2' tertukar saat ditulis tangan.
ART = r"""
 ____  _   _ ____ ____  ____  _   _ _____ _     _
|  _ \| | | |  _ \___ \/ ___|| | | | ____| |   | |
| |_) | |_| | |_) |__) \___ \| |_| |  _| | |   | |
|  __/|  _  |  __// __/ ___) |  _  | |___| |___| |___
|_|   |_| |_|_|  |_____|____/|_| |_|_____|_____|_____|
"""

TAGLINE = (
    "  PHP session.upload_progress UAF  ->  unauthenticated RCE\n"
    "  CVE-2026-109618  +  CVE-2026-109619   |   CVSS 9.2   |   PHP 5.4 - 8.x\n"
)

USAGE_HINT = (
    "  mode       : scan  |  detect  |  preflight  |  exploit  |  shell\n"
    "  cepat      : php2shell.py scan -l targets.txt\n"
    "  bantuan    : php2shell.py --help\n"
)

# Urutan fix per branch (fix-floor). Dipakai juga oleh deteksi.
FIX_FLOOR = {
    "8.5": "8.5.12",
    "8.4": "8.4.27",
    "8.3": "8.3.36",
    "8.2": "8.2.35",
}
LAST_VULN = {
    "8.5": "8.5.11",
    "8.4": "8.4.26",
    "8.3": "8.3.35",
    "8.2": "8.2.34",
}

_WIDTH = 64


def _use_color() -> bool:
    """Warna default AKTIF — ASCII yang tenggelam tidak ada gunanya.

    Dimatikan hanya bila NO_COLOR diset atau TERM=dumb.
    """
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM", "") == "dumb":
        return False
    return True


class C:
    """ANSI 256-color (lebih terang & kontras tinggi di terminal gelap)."""

    def __init__(self, on: bool):
        self.on = on

    def _w(self, code: str, s: str) -> str:
        return f"\033[{code}m{s}\033[0m" if self.on else s

    # 256-color: nomor 196-231 = warna terang
    def red(self, s):     return self._w("38;5;203", s)
    def green(self, s):   return self._w("38;5;48", s)
    def yellow(self, s):  return self._w("38;5;220", s)
    def blue(self, s):    return self._w("38;5;39", s)
    def magenta(self, s): return self._w("38;5;207", s)
    def cyan(self, s):    return self._w("38;5;51", s)
    def grey(self, s):    return self._w("38;5;245", s)
    def white(self, s):   return self._w("38;5;255", s)
    def bold(self, s):    return self._w("1", s)
    def dim(self, s):     return self._w("2", s)


def art(c: "C") -> str:
    """ASCII dengan gradasi warna per baris — tetap terbaca tanpa warna."""
    if not c.on:
        return ART.strip("\n")
    lines = ART.strip("\n").splitlines()
    paints = (c.cyan, c.cyan, c.blue, c.blue, c.magenta)
    return "\n".join(paints[i % len(paints)](ln) for i, ln in enumerate(lines))


def _rule(ch: str = "-") -> str:
    return "  " + ch * _WIDTH


def render(mode: str = "", profile: str = "", delay: float = 0.0,
           stealth: bool = True, version: str = "1.2") -> str:
    c = C(_use_color())
    out = []
    out.append(art(c))
    out.append("  " + c.bold(c.white("P H P 2 S H E L L")) +
               c.dim(f"  v{version}") + c.grey("  -  toolkit terpadu"))
    out.append(c.grey("  " + "-" * _WIDTH))
    out.append(c.yellow("  CVE-2026-109618") + c.white("  +  ") +
               c.yellow("CVE-2026-109619") + c.white("   CVSS 9.2  unauth RCE  PHP 5.4-8.x"))
    out.append(c.white("  fix-floor: ") +
               c.green("8.2.35") + c.white(" / ") +
               c.green("8.3.36") + c.white(" / ") +
               c.green("8.4.27") + c.white(" / ") +
               c.green("8.5.12"))
    out.append(c.white("  terakhir rentan: ") +
               c.red("8.2.34") + c.white(" / ") +
               c.red("8.3.35") + c.white(" / ") +
               c.red("8.4.26") + c.white(" / ") +
               c.red("8.5.11"))
    out.append(c.grey("  " + "-" * _WIDTH))

    if mode:
        out.append(c.white("  mode   : ") + c.bold(c.cyan(mode)))
    if profile:
        out.append(c.white("  ja3    : ") + c.cyan(profile))
    if delay:
        out.append(c.white("  delay  : ") + c.cyan(f"{delay}s") + c.grey("  (+jitter)"))
    if stealth:
        out.append(c.white("  stealth: ") + c.green("curl_cffi JA3 impersonate"))
    else:
        out.append(c.white("  stealth: ") +
                   c.red("urllib fallback - MUDAH TERDETEKSI") +
                   c.grey(" (pip install curl_cffi)"))
    out.append(c.grey("  " + "-" * _WIDTH))
    return "\n".join(out)


def splash() -> str:
    """Tampilan saat dipanggil tanpa argumen.

    Ringkas dengan sengaja: pagar TIDAK dicetak di sini karena (a) sudah
    ditegakkan di kode, bukan di teks, dan (b) berulang tiap kali CLI dibuka.
    Penjelasan pagar ada di `--help`.
    """
    c = C(_use_color())
    out = [render()]
    out.append("")
    out.append(c.cyan(USAGE_HINT.rstrip("\n")))
    out.append("")
    out.append(c.grey("  pagar & peringatan: php2shell.py --help  |  rincian: README.md"))
    return "\n".join(out)


GUARDS_TEXT = (
    "  Pagar ditegakkan di KODE, bukan di teks — tidak bisa dimatikan dari CLI:\n"
    "    - exploit hanya pada target READY + konfirmasi (--yes atau jawab y)\n"
    "    - perintah proof: id / whoami / uname / hostname / pwd, maks 14 byte\n"
    "    - chaining ( ; | & $ ` > < ) DITOLAK\n"
    "    - --revshell TIDAK ADA di parser dan diblokir di level runner\n"
    "    - rantai berjalan in-process dari lib/chain.py; sha256-nya dicetak tiap run\n"
)
