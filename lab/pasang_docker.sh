#!/bin/bash
# pasang_docker.sh — langkah yang butuh root, dijalankan SEKALI oleh user.
#
# Kenapa dipisah: agent tidak boleh menebak password sudo. Skrip ini hanya
# melakukan yang benar-benar perlu root, lalu selesai.
#
# Pakai:  bash pasang_docker.sh
#
# Hasil akhir: paket docker.io terpasang, user masuk grup docker, dan
# data-root tetap di /var/lib/docker (ext4). SSD eksternal dipakai untuk
# arsip image (docker save/load), BUKAN untuk data-root — filesystem NTFS
# memaksa permission 777 dan mount nosuid, docker menolak itu.

set -u

# Skrip ini WAJIB root. Tanpa cek ini, `apt-get` gagal di tengah dengan pesan
# dpkg lock yang membingungkan, padahal masalahnya cuma lupa sudo.
if [ "$(id -u)" -ne 0 ]; then
    echo "GAGAL: skrip ini harus dijalankan sebagai root." >&2
    echo "       pakai: sudo bash $0" >&2
    exit 1
fi

# $USER di dalam `sudo bash` bernilai "root", jadi menambahkan $USER ke grup
# docker akan memasukkan ROOT, bukan pemilik sesi. Ambil user asli dari
# SUDO_USER, dan tolak kalau tidak ada (mis. dijalankan dari root shell).
TARGET_USER="${SUDO_USER:-}"
if [ -z "$TARGET_USER" ] || [ "$TARGET_USER" = "root" ]; then
    echo "GAGAL: tidak tahu user mana yang harus masuk grup docker." >&2
    echo "       jalankan lewat 'sudo bash $0' dari akun user biasa," >&2
    echo "       atau set TARGET_USER=namaakun secara eksplisit." >&2
    exit 1
fi
echo "   user sasaran untuk grup docker: $TARGET_USER"

echo "== 1/4 periksa ruang (butuh >=1.5G di /var/lib/docker) =="
avail_kb=$(df -Pk /var/lib | tail -1 | awk '{print $4}')
avail_gb=$(( avail_kb / 1024 / 1024 ))
echo "   tersedia: ${avail_gb}G"
if [ "$avail_gb" -lt 1 ]; then
    echo "   GAGAL: ruang tidak cukup. Kosongkan /var/lib dulu." >&2
    exit 1
fi

echo "== 2/4 pasang docker.io =="
apt-get install -y docker.io || { echo "GAGAL: apt install" >&2; exit 1; }

echo "== 3/4 aktifkan + enable daemon =="
systemctl enable --now docker || { echo "GAGAL: start daemon" >&2; exit 1; }
sleep 2
systemctl is-active docker

echo "== 4/4 masukkan $TARGET_USER ke grup docker =="
usermod -aG docker "$TARGET_USER"

echo
echo "== verifikasi =="
docker --version
docker info --format '{{.ServerVersion}} root={{.DockerRootDir}} cgroup={{.CgroupDriver}}'
echo
echo "SELESAI."
echo "PENTING: logout lalu login lagi (atau 'newgrp docker') agar grup aktif."
echo "Setelah itu kembali ke sesi Hermes dan bilang 'docker siap'."
