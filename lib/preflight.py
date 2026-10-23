"""preflight.py — skor kesiapan exploit untuk satu target (non-destruktif).

Yang dinilai hanya yang bisa dilihat dari luar + yang diketahui publik tentang
`exploit.py` upstream. Tujuannya menjawab satu pertanyaan: "kalau saya jalankan
exploit di sini, apakah punya peluang, atau hanya membuang waktu/memicu alarm?"

BUKAN exploit. Tidak mengirim payload OOM 3MB/12MB.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .detect import Detection

# Pra-syarat yang dibaca langsung dari header komentar exploit.py (baris 1-48).
# Catatan: exploit.py menyebut display_errors=1, tetapi jalur leak tool ini ada di
# header Set-Cookie sehingga display_errors tidak menentukan (lihat blok di bawah).
PREREQS = (
    ("display_errors", "display_errors=1 (kenyamanan; leak tetap jalan saat off)"),
    ("upload_progress", "session.upload_progress.enabled=On (konsumen rantai 109619)"),
    ("version", "versi di bawah fix-floor ATAU EOL"),
)


@dataclass
class Preflight:
    url: str
    score: int = 0            # 0..90
    max_score: int = 90
    ready: bool = False
    checks: dict[str, str] = field(default_factory=dict)
    blockers: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "url": self.url,
            "score": self.score,
            "max_score": self.max_score,
            "ready": self.ready,
            "checks": self.checks,
            "blockers": self.blockers,
            "notes": self.notes,
        }


def preflight(d: Detection) -> Preflight:
    p = Preflight(url=d.url)
    pts = 0

    # FILOSOFI (revisi permintaan operator, 23 Okt 2026): deteksi = INFORMASI,
    # bukan GERBANG. Versi tak terdeteksi (CDN menyembunyikan header) bukan
    # alasan menahan exploit — justru target di balik CDN adalah kasus nyata.
    # Yang tetap diblokir HANYA dua hal:
    #   1. target TIDAK BISA dihubungi (fitn jelas membuang waktu), dan
    #   2. versi TERBACA dan sudah >= fix-floor (patched) — menembak versi
    #      yang terbaca sudah-patch adalah crash sia-sia.
    # Selain itu: jalan. Skor tetap dihitung sebagai sinyal kenyamanan.

    # --- versi (30) ---
    if d.verdict == "vulnerable":
        pts += 30
        p.checks["version"] = f"OK — {d.php_version or d.branch} di bawah fix-floor"
    elif d.verdict == "eol":
        pts += 30
        p.checks["version"] = f"OK — {d.php_version or d.branch} EOL (tak akan dipatch)"
    elif d.verdict == "patched":
        p.checks["version"] = f"BLOCK — {d.php_version} sudah >= {d.fix_floor}"
        p.blockers.append(
            f"versi {d.php_version} sudah dipatch (fix {d.fix_floor}); "
            "CVE-2026-109619/109618 tidak berlaku"
        )
    else:
        pts += 15
        p.checks["version"] = ("TIDAK DIKETAHUI — versi tak bocor (CDN/headers "
                               "bersih); RANTAI TETAP JALAN — offset default "
                               "bookworm, bila build beda panggilan butuh retry")
        p.notes.append(
            "versi tidak terdeteksi: rantai tetap dieksekusi (bukan blocker). "
            "Kalau gagal di stage leak, kemungkinan build ≠ bookworm gunakan "
            "--zif-offset/--dtor-offset hasil ukur binari target."
        )

    # --- upload_progress (30) ---
    if d.upload_progress == "on":
        pts += 30
        p.checks["upload_progress"] = "OK — konsumen rantai 109619 terbuka"
    elif d.upload_progress == "off":
        p.checks["upload_progress"] = "BLOCK-ish — konsumen rantai 109619 tertutup"
        p.notes.append(
            "upload_progress tampak off; jalur konsumen 109619 kemungkinan "
            "tertutup, tapi ini BUKAN bukti aman (produser OOM 109618/109619 "
            "tetap ada — patch versi satu-satunya mitigasi penuh)"
        )
    else:
        p.checks["upload_progress"] = "TIDAK DIKETAHUI (edge/WAF menutupi jawaban)"
        p.notes.append(
            "upload_progress tidak terlihat: bisa WAF, bisa konfigurasi. "
            "Jangan simpulkan aman."
        )

    # --- display_errors (30) ---
    # PENTING: rantai tool ini TIDAK memakai error report sebagai kanal leak. Leak
    # diambil dari header Set-Cookie (OOB read lewat PS(id)), jadi display_errors=off
    # TIDAK menutup jalur. Ini sudah dibuktikan di DISPLAY_ERRORS_OFF.md: dengan
    # display_errors=0 dan ASLR aktif, chunk_base tetap terbaca (47 pointer).
    # Laporan VulnCheck juga menyebut exploit berjalan pada 8.4.26 dengan
    # display_errors=Off. Karena itu off hanya menurunkan sinyal kenyamanan,
    # BUKAN blocker — kalau dijadikan blocker, target rentan akan ditahan (false negative).
    if d.display_errors == "on":
        pts += 30
        p.checks["display_errors"] = "OK — error report tampil (kenyamanan, bukan syarat)"
    elif d.display_errors == "off":
        pts += 15
        p.checks["display_errors"] = "NETRAL — leak lewat Set-Cookie, bukan error report"
    else:
        p.checks["display_errors"] = "TIDAK DIKETAHUI"

    p.score = min(pts, p.max_score)
    # Aturan READY (revisi 23 Okt 2026): HANYA blocker keras yang menahan.
    # Blocker = target tak terjangkau, atau versi TERBACA sudah-patch.
    # Skor rendah / "tidak diketahui" TIDAK menahan — exploit tetap jalan;
    # skor tinggal sinyal kenyamanan untuk operator.
    p.ready = not p.blockers
    if not d.reachable:
        p.blockers.append(f"target tidak bisa dihubungi (HTTP {d.status})")
        p.ready = False
    return p


def verdict_line(d: Detection, p: Preflight) -> str:
    """Satu baris untuk tabel terminal."""
    ver = d.php_version or (d.branch or "?")
    return (
        f"{d.verdict:<10} | {ver:<8} | up={d.upload_progress:<7} | "
        f"disp={d.display_errors:<7} | score={p.score:>2}/{p.max_score} | "
        f"{'READY' if p.ready else 'NO'}"
    )
