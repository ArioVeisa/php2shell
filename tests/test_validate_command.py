"""Tes unit pagar perintah (lib/exploit_runner.validate_command).

Kontrak fungsi: mengembalikan STRING alasan penolakan, atau '' bila perintah sah.
Tes di sini menguji nilai kembalian itu, bukan exception.

Menggantikan klaim README "validasi perintah unit 15/15 lulus" yang sebelumnya
tidak punya file tes sama sekali.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib.exploit_runner import (  # noqa: E402
    ALLOWED_CMDS,
    FORBIDDEN_CMD_TOKENS,
    MAX_CMD_BYTES,
    validate_command,
)

DIIZINKAN = ["id", "whoami"]   # default whitelist (uname/hostname/pwd = --allow-cmd)

# --allow-cmd: tambahan opsional. Uji semantiknya di test_allow_cmd di bawah.
EXTRA_VIA_FLAG = ["uname", "hostname", "pwd", "ls"]

DITOLAK_OPERATOR = [
    "id; uname -a",
    "id|whoami",
    "id&",
    "id$HOME",
    "id>x",
    "id<x",
    "`id`",
    "id\\whoami",
    "whoami\nid",
    "whoami\r\nid",
]

DITOLAK_TOOL_LAIN = [
    "sh -c id",
    "bash -i",
    "nc 1.2.3.4 4",
    "curl evil.com",
    "wget evil.com",
    "base64 /etc/passwd",
    "chmod 777 x",
    "rm -rf x",
    "cat x",
    "ls /",
    "find / -name x",
    "python -c 1",
    "perl -e 1",
]

DITOLAK_KONTEKS = ["", "   ", "idXXXXXXXXXXXXXXXXXXXXXXXXXX", "whoami -a -b -c -d"]


class TestPagarPerintah(unittest.TestCase):
    def setUp(self):
        # ALLOWED_CMDS adalah state GLOBAL. test_allow_cmd_semantik
        # mengaktifkan 'ls' lewat --allow-cmd; tanpa reset di sini, urutan
        # eksekusi yang berbeda membuat 'ls /' lolos di test_tool_lain_ditolak.
        # Reset per-tes membuat hasil tidak bergantung urutan.
        from lib.exploit_runner import set_allowed_cmds
        set_allowed_cmds(None)

    def tearDown(self):
        from lib.exploit_runner import set_allowed_cmds
        set_allowed_cmds(None)

    def test_perintah_diizinkan(self):
        for c in DIIZINKAN:
            with self.subTest(cmd=c):
                self.assertEqual(validate_command(c), "", f"{c!r} harus sah")
                self.assertIn(c, ALLOWED_CMDS)

    def test_allow_cmd_semantik(self):
        """--allow-cmd: tambahan bounded; default dikembalikan setelah reset."""
        from lib.exploit_runner import set_allowed_cmds
        # sebelum: uname/ls ditolak
        self.assertNotEqual(validate_command("uname"), "")
        self.assertNotEqual(validate_command("ls"), "")
        # aktifkan: uname & ls jadi sah (termasuk pola proof-redirect)
        wl = set_allowed_cmds(EXTRA_VIA_FLAG)
        for c in EXTRA_VIA_FLAG:
            self.assertIn(c, wl)
            self.assertEqual(validate_command(c), "", f"{c!r} sah setelah --allow-cmd")
        self.assertEqual(validate_command("ls>/out/p1"), "")
        # tetap diblokir walau --allow-cmd dicoba
        with self.assertRaises(ValueError):
            set_allowed_cmds(["bash"])
        with self.assertRaises(ValueError):
            set_allowed_cmds(["nc"])
        # reset kembali ke default
        set_allowed_cmds(None)
        self.assertNotEqual(validate_command("ls"), "")
        self.assertEqual(validate_command("id"), "")

    def test_operator_shell_ditolak(self):
        for c in DITOLAK_OPERATOR:
            with self.subTest(cmd=c):
                why = validate_command(c)
                self.assertNotEqual(why, "", f"{c!r} harus ditolak")

    def test_tool_lain_ditolak(self):
        for c in DITOLAK_TOOL_LAIN:
            with self.subTest(cmd=c):
                self.assertNotEqual(validate_command(c), "", f"{c!r} harus ditolak")

    def test_perintah_kosong_ditolak(self):
        for c in ("", "   ", "\t"):
            with self.subTest(cmd=c):
                self.assertNotEqual(validate_command(c), "")

    def test_batas_byte_ditegakkan(self):
        pas = "id" + " " * (MAX_CMD_BYTES - 2)          # 14 byte: masih sah
        lewat = "id" + " " * (MAX_CMD_BYTES - 1)        # 15 byte: ditolak
        self.assertEqual(len(pas.encode()), MAX_CMD_BYTES)
        self.assertEqual(validate_command(pas), "")
        self.assertNotEqual(validate_command(lewat), "")
        self.assertIn("byte", validate_command(lewat))

    def test_spasi_di_tepi_dinormalkan(self):
        self.assertEqual(validate_command("  id  "), "")
        self.assertEqual(validate_command("id "), "")

    def test_alasan_penolakan_informatif(self):
        """Pesan penolakan harus menyebut sebabnya, bukan sekadar 'ditolak'."""
        self.assertIn("byte", validate_command("id" + "x" * 30))
        why = validate_command("cat /etc/passwd")
        self.assertTrue("ditolak" in why.lower(), why)

    def test_setiap_token_terlarang_benar_benar_diblokir(self):
        """Setiap token di FORBIDDEN_CMD_TOKENS harus memicu penolakan."""
        for tok in FORBIDDEN_CMD_TOKENS:
            with self.subTest(token=tok):
                self.assertNotEqual(
                    validate_command("id" + tok), "",
                    f"token {tok!r} lolos padahal terdaftar terlarang",
                )

    def test_allowed_cmds_konsisten_dengan_pagar(self):
        """Semua yang ada di ALLOWED_CMDS harus lolos tanpa alasan."""
        for c in ALLOWED_CMDS:
            with self.subTest(cmd=c):
                self.assertEqual(validate_command(c), "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
