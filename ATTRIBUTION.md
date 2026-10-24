# Attribution

php2shell is a **reproduction, orchestration and hardening toolkit** built on
top of prior public research. The exploit technique is not ours. This file
exists so nobody has to guess where each part came from.

## Upstream research (not ours)

| Project | Author | What we took | Status |
|---|---|---|---|
| [`9bie/php2shell-bypass-aslr-exp`](https://github.com/9bie/php2shell-bypass-aslr-exp) | **9bie (Qi Deng)** | The core chain: 2-request `session.upload_progress` UAF (CVE-2026-109619), the ASLR bypass via heap leak + `libphp` base leak, and the `pDestructor = zif_system` actuator. `lib/chain.py` is a **port** of this `exploit.py`'s logic into an in-process module. | No license file published upstream. Ported with explicit credit; see "License status" below. |
| [`ikow/php2shell-poc`](https://github.com/ikow/php2shell-poc) | **ikow** | The CVE-2026-109618 OOM-trigger verifier (`poc/verify_oom_trigger.py`) used as the reference for our 109618 crash evidence. | Referenced, not vendored. |
| PHP security advisories | **PHP Group** | `GHSA-w8hw-w9fx-j79w` → CVE-2026-109618, `GHSA-6wmf-4rv5-p3rp` → CVE-2026-109619; the fix-floor table (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12). | Public advisory, factual data. |
| `curl_cffi` | **lexiforest / yifeikong** | JA3/TLS impersonation used by `lib/transport.py`. | MIT — installed as a dependency, not vendored. |

## What is original to this repo

- Unified CLI with 5 modes (`scan` / `detect` / `preflight` / `exploit` / `shell`)
- `lib/chain.py` packaged as an in-process engine (no subprocess, no external
  script), verified function-by-function against the upstream `exploit.py`
- Auto-proof: reading the command output back from the mounted `out/p1`
- The command fence (whitelist, 14-byte cap, chaining rejection, no revshell)
- Preflight scoring model + the "detection is information, not a gate" policy
- Stealth layer: JA3 profile rotation, jitter, JSONL request audit
- Test suite (46 tests), installer, Docker lab, GPL-3.0 wrapper

## License status (read this)

This repo is released under **GPL-3.0-only** — that covers the code *we* wrote.

Because the upstream `9bie/php2shell-bypass-aslr-exp` publishes **no license
file**, default copyright applies to that upstream code ("all rights
reserved"). Our GPL-3.0 does **not** override that for the portions that are
substantially a port of it. The honest position is:

1. We credit 9bie explicitly, in this file, in the README, and in
   `lib/chain.py`'s header.
2. If you are 9bie (or acting for them) and you object to the port, open an
   issue — we will either remove the port or add your license terms to it,
   your choice.
3. A clean-room reimplementation of the chain from the published write-up is
   the only way to have an unambiguously GPL-3.0-only `lib/chain.py`. Until
   that happens, treat `lib/chain.py` as "GPL-3.0 with upstream attribution".

If you are reusing this repo and you care about license hygiene, that
distinction matters: **do not represent `lib/chain.py` as purely our work.**

## Ethical position

This toolkit proves *access*, not *damage*. Commands are capped at 14 bytes,
restricted to `id` / `whoami` / `uname` / `hostname` / `pwd`, chaining
operators are rejected, and `--revshell` does not exist in the parser. That is
deliberate: a public repo containing a general-purpose RCE must not be a
ready-made backdoor.

## The Zer061 fork (clarification, 2026-10-24)

The `exploit.py` this toolkit was verified against lives in
`github.com/Zer061/CVE-2026-109618` (local path
`/home/lota1337/python/CVE-2026-109618/`, sha256
`ea92568319637e1913e20d9ceb1e6d89315c2393f8eac3fb6a2975bc1a1f6927`).

That repo's history is a **mixture of four authors**, not Zer061's work alone:

| Commit | Author | Content |
|---|---|---|
| `adc5f9b` | 9bie | original chain |
| `4586f5c` | my `<my@fubuki.invalid>` | English README |
| `5fc5669` | v.dir.mir `<v.dir.mir@vinsoc.vn>` | **added `--revshell`** + bash/python/perl payload + `nc` listener |
| `4752adc` | Zer061 | README update (fork head) |

We do **not** use the `--revshell` path: it is absent from the parser and
blocked in the runner.

## Anti-malware audit (2026-10-24)

Both this repo and the Zer061 source folder were checked for:

| Check | Result |
|---|---|
| hardcoded outbound hosts (C2) | none — only `127.0.0.1`, `localhost`, doc URLs |
| credential theft (`~/.ssh`, `.aws`, `/etc/shadow`, upload cookies) | none |
| persistence (`crontab`, `systemd`, `.bashrc`, `rc.local`, autostart) | none |
| obfuscation (mass `b64decode`, hex blobs, `chr()` chains) | none — `\x..` sequences are protocol byte arrays in `tools/align8.py`, `tools/warn_probe.py` |
| unknown binaries | none — only official `php-8.4.26.tar.gz` + one PNG |
| `subprocess`/`os.system`/`eval`/`exec` | legitimate only: `docker cp` for `libphp.so`, the `safe_shell.py` generator, test suite |
| raw `socket.create_connection` | required — the chain speaks TCP directly so TLS/handshake is not normalised by a library |
| `--revshell` / reverse-shell payloads | not present in parser, blocked in code |

All 31 git-tracked files were hashed with `sha256sum`; 46/46 tests pass.
