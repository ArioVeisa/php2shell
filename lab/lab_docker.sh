#!/bin/bash
# lab_docker.sh — lab PHP 8.4.26 (RENTAN) untuk menguji rantai 109619.
#
# SINKRON dengan konfigurasi penulis (docker/php.ini + docker/apache.conf +
# docker/www) yang terverifikasi RCE 3/3 di :8088. Lab ini me-mount FILE YANG
# SAMA, hanya beda container-name dan port (8095) supaya bisa jalan berdampingan.
#
# 5 syarat rantai (semua wajib, sudah tertanam di config penulis):
#   MaxRequestWorkers 1          -> producer & konsumen satu worker yang sama
#   KeepAlive Off                -> tiap request koneksi baru (rotasi bersih)
#   memory_limit=8M + cleanup=On -> OOM terkontrol di php_session_initialize()
#   max_input_vars besar         -> 1001+ field tidak terpotong
#   max_file_uploads besar       -> part file rantai tidak terpotong
#
# Pakai:
#   bash lab/lab_docker.sh start     # nyalakan (butuh docker, lihat pasang_docker.sh)
#   bash lab/lab_docker.sh status    # cek
#   bash lab/lab_docker.sh stop      # matikan
#   bash lab/lab_docker.sh destroy   # hapus container

set -u

NAME=p2s-lab-8426
IMAGE=php:8.4.26-apache
PORT=8095
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"   # root repo php2shell/ (punya docker/)
DOCKER_DIR="$REPO_DIR/docker"
OUT_DIR="${REPO_OUT_DIR:-$REPO_DIR/out}"

CMD="${1:-start}"

case "$CMD" in
start)
    if ! command -v docker >/dev/null 2>&1; then
        echo "GAGAL: docker tidak ada. Jalankan lab/pasang_docker.sh dulu (butuh root)." >&2
        exit 1
    fi
    for f in "$DOCKER_DIR/php.ini" "$DOCKER_DIR/apache.conf" "$DOCKER_DIR/www/index.php"; do
        [ -f "$f" ] || { echo "GAGAL: file penulis tidak ada: $f" >&2; exit 1; }
    done

    echo "== tarik image $IMAGE =="
    docker pull "$IMAGE" >/dev/null 2>&1 || true

    echo "== hapus container lama (kalau ada) =="
    docker rm -f "$NAME" >/dev/null 2>&1

    mkdir -p "$OUT_DIR"

    echo "== jalankan $NAME di 127.0.0.1:$PORT (mount config penulis) =="
    docker run -d --name "$NAME" \
        -p "127.0.0.1:$PORT:80" \
        -v "$DOCKER_DIR/php.ini":/usr/local/etc/php/conf.d/zz-php2shell.ini:ro \
        -v "$DOCKER_DIR/apache.conf":/etc/apache2/conf-enabled/zz-php2shell.conf:ro \
        -v "$DOCKER_DIR/www":/var/www/html:ro \
        -v "$OUT_DIR":/out \
        --entrypoint /bin/sh \
        "$IMAGE" -c 'chmod 1777 /out 2>/dev/null || true; exec apache2-foreground' \
    || { echo "GAGAL: run" >&2; exit 1; }

    echo "== tunggu siap =="
    code=""
    for i in $(seq 1 30); do
        code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://127.0.0.1:$PORT/index.php" 2>/dev/null)
        if [ "$code" = "200" ]; then
            echo "   SIAP  http://127.0.0.1:$PORT/index.php  (HTTP $code)"
            break
        fi
        sleep 1
    done
    [ "$code" = "200" ] || { echo "   GAGAL siap (HTTP $code)"; docker logs --tail 25 "$NAME"; exit 1; }

    echo
    echo "== bukti konfigurasi (versi + syarat rantai) =="
    curl -s --max-time 5 "http://127.0.0.1:$PORT/index.php" 2>/dev/null
    echo
    echo "LAB SIAP: http://127.0.0.1:$PORT/index.php"
    echo "offsets:  python3 $DOCKER_DIR/offsets.py   # wajib fresh sebelum exploit"
    ;;

status)
    docker ps -a --filter "name=$NAME" --format '  {{.Names}}  {{.Status}}  {{.Ports}}'
    curl -s -o /dev/null -w "  HTTP %{http_code}\n" --max-time 3 "http://127.0.0.1:$PORT/index.php" 2>/dev/null
    ;;

stop)
    docker rm -f "$NAME" 2>&1 | tail -1
    ;;

destroy)
    docker rm -f "$NAME" >/dev/null 2>&1
    ;;

*)
    echo "pakai: bash lab/lab_docker.sh {start|status|stop|destroy}" >&2
    exit 2
    ;;
esac
