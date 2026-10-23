"""Tes pagar + kontrak CLI php2shell (tanpa jaringan, tanpa target hidup).

Semua tes di sini harus jalan offline: yang diuji adalah perilaku parser,
pagar keamanan, exit code, dan artefak yang dihasilkan generator shell.

    /home/lota1337/myenv/bin/python -m unittest discover -s tests -v
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

VERSI_DIHARAPKAN = "1.2"
TOOLKIT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI = os.path.join(TOOLKIT, "php2shell.py")
PY = sys.executable


def run(*args, timeout=120):
    """Jalankan CLI, kembalikan (rc, stdout, stderr). rc diambil dari subprocess."""
    p = subprocess.run(
        [PY, CLI, *args],
        cwd=TOOLKIT,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return p.returncode, p.stdout, p.stderr


class TestPagarRewshell(unittest.TestCase):
    """--revshell harus tidak ada di parser DAN ditolak di level runner."""

    def test_revshell_bukan_flag_sah(self):
        rc, out, err = run("exploit", "-u", "http://127.0.0.1:9/x.php",
                           "--revshell", "10.0.0.1:4444", timeout=60)
        self.assertEqual(rc, 2, "flag --revshell seharusnya ditolak argparse")
        self.assertIn("unrecognized arguments", err)

    def test_revshell_hanya_disebut_sebagai_pagar(self):
        """--revshell boleh disebut di teks pagar, tapi tidak boleh jadi opsi parser."""
        rc, out, err = run("--help")
        self.assertEqual(rc, 0)
        for baris in out.splitlines():
            if "--revshell" in baris:
                self.assertIn("TIDAK ADA", baris,
                              f"--revshell muncul di luar teks pagar: {baris!r}")


class TestPagarChaining(unittest.TestCase):
    """Perintah proof dengan chaining ditolak sebelum menyentuh jaringan."""

    def test_chaining_ditolak(self):
        for cmd in ("id; ls", "id | tee x", "id && whoami", "id > /tmp/x"):
            rc, out, err = run("exploit", "-u", "http://127.0.0.1:9/x.php",
                               "-c", cmd, "--yes", "--force", timeout=120)
            gabung = out + err
            self.assertNotEqual(rc, 0, f"cmd {cmd!r} seharusnya ditolak")
            self.assertTrue(
                re.search(r"DITOLAK|ditolak|chaining|tidak sah|maks", gabung),
                f"cmd {cmd!r} ditolak tanpa pesan jelas: {gabung[-300:]}",
            )


class TestCveTidakDidukung(unittest.TestCase):
    """CVE yang tidak diimplementasikan harus gagal cepat di parser,
    bukan setelah 300 detik."""

    def test_109618_ditolak_cepat(self):
        import time
        t0 = time.time()
        rc, out, err = run("exploit", "-u", "http://127.0.0.1:9/x.php",
                           "--cve", "CVE-2026-109618", "--force", "--yes", timeout=120)
        durasi = time.time() - t0
        self.assertEqual(rc, 2, "harus exit 2 (usage error)")
        self.assertIn("tidak diimplementasikan", err)
        self.assertLess(durasi, 20, "harus gagal cepat, bukan menunggu rantai")

    def test_109619_diterima_parser(self):
        rc, out, err = run("exploit", "-u", "http://127.0.0.1:9/x.php",
                           "--cve", "CVE-2026-109619", "--force", "--yes", timeout=180)
        self.assertNotIn("tidak diimplementasikan", err)


class TestExitCode(unittest.TestCase):
    """Exit code harus membedakan salah pakai (2) dari hasil scan (0/1)."""

    def test_target_file_tidak_ada_exit_2(self):
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            path = f.name + ".tidak-ada"
        rc, out, err = run("scan", "-l", path)
        self.assertEqual(rc, 2)
        self.assertIn("tidak ada", err)

    def test_target_file_kosong_exit_2(self):
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            path = f.name
        rc, out, err = run("scan", "-l", path)
        self.assertEqual(rc, 2, "file kosong bukan hasil scan bersih")
        self.assertIn("tidak menghasilkan target", err)

    def test_detect_tanpa_url_exit_2(self):
        rc, out, err = run("detect")
        self.assertEqual(rc, 2)
        self.assertIn("butuh -u", err)


class TestGeneratorShell(unittest.TestCase):
    """shell: artefak dibuat, password kuat, file kredensial mode 600."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="php2shell-test-")
        cls.out = os.path.join(cls.tmp, "out")
        cls.rc, cls.stdout, cls.stderr = run("shell", "--out", cls.out,
                                             "--ttl", "72", timeout=180)

    def test_rc_nol(self):
        self.assertEqual(self.rc, 0, self.stderr[-400:])

    def test_file_php_dan_kredensial_ada(self):
        files = os.listdir(self.out)
        php = [f for f in files if f.endswith(".php")]
        self.assertEqual(len(php), 1, f"harus tepat 1 webshell: {files}")
        self.assertIn("CREDENTIALS.txt", files)

    def test_password_kuat(self):
        with open(os.path.join(self.out, "CREDENTIALS.txt")) as fh:
            isi = fh.read()
        m = re.search(r"password\s*:\s*(\S+)", isi)
        self.assertIsNotNone(m, "format CREDENTIALS.txt berubah")
        assert m is not None
        pw = m.group(1)
        self.assertGreaterEqual(len(pw), 24, "password terlalu pendek")
        # Charset aman-URL: tidak perlu escaping di curl/POST, tetap dicampur simbol.
        self.assertRegex(pw, r"^[A-Za-z0-9_-]+$", "password memuat karakter tidak aman URL")

    def test_mode_kredensial_600(self):
        st = os.stat(os.path.join(self.out, "CREDENTIALS.txt"))
        self.assertEqual(st.st_mode & 0o077, 0, "CREDENTIALS.txt harus 600")

    def test_webshell_lolos_php_lint(self):
        php = [f for f in os.listdir(self.out) if f.endswith(".php")][0]
        p = subprocess.run(["php", "-l", os.path.join(self.out, php)],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("No syntax errors", p.stdout)

    def test_webshell_pakai_password_hash(self):
        """Password harus disimpan sebagai hash bcrypt, bukan plaintext."""
        php = [f for f in os.listdir(self.out) if f.endswith(".php")][0]
        with open(os.path.join(self.out, php)) as fh:
            src = fh.read()
        with open(os.path.join(self.out, "CREDENTIALS.txt")) as fh:
            isi = fh.read()
        pw = re.search(r"password\s*:\s*(\S+)", isi).group(1)
        self.assertNotIn(pw, src, "password plaintext bocor ke dalam webshell")
        self.assertIn("password_verify", src, "harus verifikasi lewat password_verify")
        self.assertRegex(src, r"\$2[aby]\$", "hash harus bcrypt ($2y$/$2b$)")


class TestAuditTrail(unittest.TestCase):
    """--audit harus benar-benar menulis JSONL valid per request."""

    def test_audit_jsonl_valid(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "audit.jsonl")
            run("detect", "-u", "http://127.0.0.1:9/x.php", "--audit", path,
                timeout=120)
            self.assertTrue(os.path.exists(path), "audit file tidak dibuat")
            with open(path) as fh:
                baris = [l for l in fh.read().splitlines() if l.strip()]
            self.assertGreaterEqual(len(baris), 1)
            for l in baris:
                rec = json.loads(l)
                self.assertIn("ts", rec)
                self.assertIn("url", rec)
                self.assertIn("status", rec)


class TestOutputLaporan(unittest.TestCase):
    """--json / --csv harus menghasilkan file yang bisa dibaca mesin."""

    def test_json_dan_csv(self):
        with tempfile.TemporaryDirectory() as d:
            j = os.path.join(d, "out.json")
            c = os.path.join(d, "out.csv")
            run("detect", "-u", "http://127.0.0.1:9/x.php", "--json", j,
                "--csv", c, timeout=120)
            self.assertTrue(os.path.exists(j), "json tidak dibuat")
            with open(j) as fh:
                data = json.load(fh)
            self.assertIsInstance(data, (list, dict))
            self.assertTrue(os.path.exists(c), "csv tidak dibuat")
            with open(c) as fh:
                head = fh.read().splitlines()
            self.assertGreaterEqual(len(head), 1)
            self.assertIn(",", head[0], "csv tanpa header berdelimiter")


class TestKlaimBanner(unittest.TestCase):
    """Banner mengklaim sha256 mesin rantai dicetak tiap run: buktikan benar."""

    def test_sha256_dicetak_dan_cocok(self):
        """Banner mencetak sha256 mesin rantai yang BENAR-BENAR dipakai.

        Dulu tes ini mengecek sha256 exploit.py, dari masa toolkit masih
        memanggil subprocess. Sejak rantai diport ke lib/chain.py, file yang
        dieksekusi adalah chain.py — mencetak hash exploit.py justru
        menyesatkan. Yang diuji sekarang: hash yang tercetak cocok dengan
        file mesin rantai di disk.
        """
        import hashlib
        with open(os.path.join(TOOLKIT, "lib", "chain.py"), "rb") as fh:
            asli = hashlib.sha256(fh.read()).hexdigest()
        rc, out, err = run("scan", "-l", "/tidak/ada.txt", timeout=60)
        self.assertIn(asli, out + err, "sha256 lib/chain.py tidak dicetak banner")
        self.assertIn("lib/chain.py", out + err)

    def test_tidak_ada_subprocess_ke_exploit_py(self):
        """Toolkit mandiri: rantai in-process, tidak memanggil exploit.py.

        Memakai AST, bukan pencocokan teks: docstring dan komentar boleh
        menyebut "subprocess" (justru harus, untuk menyatakan modul ini tidak
        memakainya). Yang diperiksa hanyalah import dan pemanggilan nyata.
        """
        import ast
        path = os.path.join(TOOLKIT, "lib", "exploit_runner.py")
        with open(path) as fh:
            tree = ast.parse(fh.read(), filename=path)

        mods = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                mods.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                mods.add(node.module.split(".")[0])
        self.assertNotIn("subprocess", mods,
                         "exploit_runner.py masih mengimpor subprocess")

        dipanggil = {n.func.id for n in ast.walk(tree)
                     if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
        self.assertNotIn("system", dipanggil)
        self.assertNotIn("run", dipanggil,
                         "exploit_runner.py masih memanggil subprocess.run")

        # Bukti positif: mesin rantai internal benar-benar dipakai.
        src = open(path).read()
        self.assertIn("chain_mod", src,
                      "exploit_runner.py tidak memakai mesin rantai internal")

    def test_exploit_py_tidak_dimodifikasi(self):
        """exploit.py upstream tidak dibawa di repo ini (krdit di README).
        Sebagai gantinya: pastikan mesin rantai internal TETAP byte-identik
        dengan referensi — simpan sha256 chain.py dan bandingkan."""
        import hashlib
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        p = os.path.join(here, "lib", "chain.py")
        now = hashlib.sha256(open(p, "rb").read()).hexdigest()
        # hash ini TERVERIFIKASI saat pemisahan repo (23 Okt 2026)
        self.assertEqual(now,
            "ca6550d9a9b7da398b8e84ac705ba23cf7f6d89ebf5d5c753d5152d2dcca0e88",
            "lib/chain.py berubah — perbarui hash ini setelah review")


class TestBannerTanpaArgumen(unittest.TestCase):
    def test_splash_rc_nol(self):
        rc, out, err = run()
        self.assertEqual(rc, 0)
        bersih = re.sub(r"\x1b\[[0-9;]*m", "", out)
        rata = re.sub(r"[^A-Z0-9]", "", bersih.upper())
        self.assertIn("PHP2SHELL", rata)


class TestVersion(unittest.TestCase):
    """--version harus exit 0 dan satu baris, di posisi mana pun.

    Regresi yang dijaga: dulu --version tidak terdaftar sehingga argparse
    keluar 2 (terlihat seperti error), dan saat sempat didaftarkan lewat
    action="version", formatter BannerHelp membuat banner penuh tercetak
    sehingga output tidak lagi satu baris / tidak skripable.
    """

    def test_version_top_level(self):
        for flag in ("--version", "-V"):
            with self.subTest(flag=flag):
                rc, out, err = run(flag, timeout=60)
                self.assertEqual(rc, 0, f"{flag} harus exit 0, dapat {rc}")
                teks = re.sub(r"\x1b\[[0-9;]*m", "", out).strip()
                self.assertEqual(len(teks.splitlines()), 1,
                                 f"{flag} harus satu baris, dapat: {teks!r}")
                self.assertIn("php2shell", teks)
                self.assertIn(VERSI_DIHARAPKAN, teks)

    def test_version_setelah_subcommand(self):
        rc, out, err = run("scan", "--version", timeout=60)
        self.assertEqual(rc, 0)
        teks = re.sub(r"\x1b\[[0-9;]*m", "", out).strip()
        self.assertEqual(len(teks.splitlines()), 1, teks)
        self.assertIn(VERSI_DIHARAPKAN, teks)

    def test_version_bukan_banner(self):
        """Baris versi tidak boleh membawa ASCII art banner."""
        rc, out, err = run("--version", timeout=60)
        self.assertNotIn("____", out, "banner ASCII ikut tercetak di --version")


if __name__ == "__main__":
    unittest.main(verbosity=2)
