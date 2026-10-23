# shell/ — Webshell berpassword (proof-of-concept aman)

Generator webshell T1–T13 dengan pengaman berlapis. **Generator saja —
tidak meng-upload ke mana pun.**

## Ciri shell yang dihasilkan (T1–T13)

| Fitur | Implementasi |
|---|---|
| Nama file | random 32+ hex (`out/<32hex>.php`) |
| Password | bcrypt hash — plaintext TIDAK disimpan di shell, hanya `CREDENTIALS.txt` lokal |
| Command whitelist | hanya `id`, `whoami`, `uname`, `hostname`, `pwd` (proof-of-access, bukan eksekusi bebas) |
| TTL | kedaluwarsa otomatis via `--ttl` jam (default 72) |
| Rate limit | sleep antar perintah |
| No backdoor | tidak reverse-connect, tidak persist, tanpa auto-exec |

`CREDENTIALS.txt` berisi kredensial — **jangan commit** (sudah gitignored).

## Pakai

```bash
PY=/home/lota1337/myenv/bin/python
$PY ../php2shell.py shell --out shell/out --ttl 72
# → out/<32hex>.php + out/CREDENTIALS.txt
# upload manual dari out/ — tanggung jawab operator
```

## Prinsip

> "shell yg aman itu seperti laman login admin" — bukan backdoor.
> Tidak ada `--revshell` di toolkit ini; diblokir di level runner.
