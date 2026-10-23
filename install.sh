#!/usr/bin/env bash
# install.sh — php2shell one-shot installer
#
# Apa yang dilakukan:
#   1. cek python3 >= 3.9 + docker (opsional, utk lab)
#   2. buat venv .venv di folder repo
#   3. pasang dependencies (curl_cffi, bcrypt) di venv
#   4. smoke test: banner CLI tampil, tests cepat
#   5. (opsional) symlink `php2shell` ke ~/.local/bin supaya bisa dipanggil global
#
# Pakai:
#   bash install.sh            # install lengkap
#   bash install.sh --no-bin   # tanpa symlink global
#
# Jalankan TANPA root. Docker kalau belum ada → di-skip dengan pesan
# (lab tetap bisa dipakai setelah docker siap — lihat lab/pasang_docker.sh).

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"
ROOT="$(pwd)"
NO_BIN=0
[ "${1:-}" = "--no-bin" ] && NO_BIN=1

bold()  { printf '\033[1m%s\033[0m\n' "$*"; }
ok()    { printf '  \033[32m[ok]\033[0m %s\n' "$*"; }
warn()  { printf '  \033[33m[!!]\033[0m %s\n' "$*"; }
fail()  { printf '  \033[31m[x]\033[0m %s\n' "$*"; exit 1; }

echo
bold "== php2shell installer =="

# --- 1) prasyarat -----------------------------------------------------------
command -v python3 >/dev/null 2>&1 || fail "python3 tidak ada — pasang dulu (apt install python3 python3-venv python3-pip)"
PYVER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PYOK=$(python3 -c 'import sys; print(1 if sys.version_info >= (3,9) else 0)')
[ "$PYOK" = "1" ] || fail "python3 $PYVER < 3.9 — upgrade dulu"
ok "python3 $PYVER"

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    ok "docker aktif (lab siap: bash lab/lab_docker.sh start)"
elif command -v docker >/dev/null 2>&1; then
    warn "docker terpasang tapi daemon tak bisa diakses user ini — jalankan: sudo usermod -aG docker \$USER lalu logout/login"
else
    warn "docker tidak ada — lab exploit tidak bisa jalan (tool detect/preflight tetap jalan). Lihat lab/pasang_docker.sh"
fi

# --- 2) venv ----------------------------------------------------------------
if [ ! -d .venv ]; then
    echo "  * membuat venv .venv ..."
    python3 -m venv .venv || fail "gagal membuat venv (butuh paket python3-venv)"
fi
# shellcheck disable=SC1091
source .venv/bin/activate
ok "venv .venv siap ($(python --version 2>&1))"

# --- 3) dependencies --------------------------------------------------------
echo "  * memasang dependencies (curl_cffi, bcrypt) ..."
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt || fail "pip install gagal"
ok "dependencies terpasang"

# --- 4) smoke test ----------------------------------------------------------
echo "  * smoke test ..."
python php2shell.py 2>&1 | grep -q "P H P 2 S H E L L" || fail "CLI tidak menampilkan banner"
ok "CLI jalan"
python -c "import curl_cffi" 2>/dev/null && ok "curl_cffi impersonation aktif (stealth mode)" \
    || warn "curl_cffi gagal import — tool jalan mode urllib (mudah terdeteksi)"
python -m unittest discover -s tests -t . 2>&1 | tail -1 | grep -q "^OK" \
    && ok "unit tests lulus" \
    || warn "unit tests tidak lulus penuh — cek: python -m unittest discover -s tests -t ."

# --- 5) symlink global (opsional) -------------------------------------------
if [ "$NO_BIN" = 0 ]; then
    BIN_DIR="$HOME/.local/bin"
    mkdir -p "$BIN_DIR"
    cat > "$BIN_DIR/php2shell" <<EOF
#!/usr/bin/env bash
# wrapper php2shell (dibuat install.sh)
exec "$ROOT/.venv/bin/python" "$ROOT/php2shell.py" "\$@"
EOF
    chmod +x "$BIN_DIR/php2shell"
    if [[ ":$PATH:" == *":$BIN_DIR:"* ]]; then
        ok "perintah global: php2shell --help"
    else
        warn "bin dir \$HOME/.local/bin belum di PATH — tambahkan: echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.zshrc"
    fi
fi

echo
bold "== SELESAI =="
cat <<'EOS'

Pasca-install:
  bash lab/lab_docker.sh start                       # nyalakan lab rentan
  python3 docker/offsets.py                          # ambil offset libphp (wajib fresh)
  php2shell exploit -u http://127.0.0.1:8095/index.php \
      --force --yes --exploit-profile bookworm -c 'id>/out/p1'

Tanpa venv (global pip): pip install -r requirements.txt lalu
  python php2shell.py --help

_Hanya untuk sistem milik sendiri / dengan izin tertulis._
EOS
