"""Tes preflight: display_errors TIDAK boleh memblokir target rentan.

Latar: rantai tool ini mengambil leak dari header Set-Cookie (OOB read lewat
PS(id)), bukan dari error report di body. DISPLAY_ERRORS_OFF.md membuktikan
leak tetap terbaca saat display_errors=0 dengan ASLR aktif, dan laporan
VulnCheck menyebut exploit berjalan pada 8.4.26 dengan display_errors=Off.
Karena itu nilai off hanya mengurangi skor, tidak boleh menambah blocker.
"""

import os
import sys
import unittest

# Suite dijalankan dari root repo (discover -s tests -t .), jadi paket
# diimpor sebagai lib.*. Kalau file ini dijalankan langsung dari
# folder toolkit, sys.path perlu ditambah supaya 'toolkit' tetap bisa diimpor.
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from lib.detect import Detection
from lib.preflight import preflight


def _detection(disp: str, verdict: str = "vulnerable") -> Detection:
    return Detection(
        url="http://contoh.invalid/",
        reachable=True,
        status=200,
        php_version="8.4.26",
        branch="8.4",
        verdict=verdict,
        fix_floor="8.4.27",
        upload_progress="on",
        display_errors=disp,
    )


class TestDisplayErrorsBukanBlocker(unittest.TestCase):
    def test_off_tidak_menambah_blocker(self) -> None:
        for disp in ("on", "off", "unknown"):
            with self.subTest(disp=disp):
                self.assertEqual(preflight(_detection(disp)).blockers, [])

    def test_off_tetap_ready(self) -> None:
        self.assertTrue(preflight(_detection("off")).ready)

    def test_off_menurunkan_skor_tapi_tidak_ke_nol(self) -> None:
        on = preflight(_detection("on")).score
        off = preflight(_detection("off")).score
        self.assertGreater(off, 0)
        self.assertLess(off, on)

    def test_target_patched_tetap_diblokir(self) -> None:
        d = _detection("on", verdict="patched")
        d.php_version = "8.4.27"
        d.fix_floor = "8.4.27"
        p = preflight(d)
        self.assertFalse(p.ready)
        self.assertTrue(p.blockers)

    def test_versi_tidak_diketahui_tetap_ready(self) -> None:
        """Aturan baru (23 Okt 2026): deteksi = informasi, bukan gerbang.

        Versi tak bocor (CDN menyembunyikan header) TIDAK BOLEH menahan
        exploit — justru target di balik CDN adalah kasus lapangan nyata.
        Rantai tetap jalan dengan offset default; kalau build beda, ya
        gagal di stage leak dan operator isi offset manual.
        """
        d = _detection("unknown", verdict="unknown")
        d.php_version = None
        d.upload_progress = "unknown"
        p = preflight(d)
        self.assertTrue(p.ready, "versi unknown tidak boleh memblokir exploit")
        self.assertEqual(p.blockers, [])

    def test_target_tidak_terjangkau_tetap_diblokir(self) -> None:
        d = _detection("unknown", verdict="unknown")
        d.reachable = False
        d.status = 0
        p = preflight(d)
        self.assertFalse(p.ready)
        self.assertTrue(any("tidak bisa dihubungi" in b for b in p.blockers))

    def test_teks_check_tidak_menyesatkan(self) -> None:
        teks = preflight(_detection("off")).checks["display_errors"]
        self.assertNotIn("BLOCK", teks)
        self.assertIn("Set-Cookie", teks)


if __name__ == "__main__":
    unittest.main()
