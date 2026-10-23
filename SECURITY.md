# Security Policy — php2shell

## Reporting a vulnerability

Found a bug in this *tooling* (not in PHP itself)? Please open a private
report: use GitHub "Report a vulnerability" on this repository, or email the
owner. Please do **not** open a public issue for anything exploit-related.

## Scope of this repository

This repository distributes a **reproduction toolkit** for two already-patched
PHP vulnerabilities (CVE-2026-109618 / CVE-2026-109619). The underlying PHP
bugs are tracked and fixed by the PHP Group:

- PHP release announcement: https://www.php.net/archive/2026.php#2026-10-21-5
- Fixed in: 8.2.35, 8.3.36, 8.4.27, 8.5.12

Vulnerabilities in PHP itself are **out of scope** for this repo — report
them to https://github.com/php/php-src/blob/master/SECURITY.md.

## Intended use

- Owned systems / written authorization only.
- Proof-of-access design: identity commands only (`id`, `whoami`, …),
  bounded `--allow-cmd` additions, no reverse shell, no exfiltration
  primitives, 14-byte command carrier limit.
- Unauthorized use against third-party systems is illegal and unsupported.
