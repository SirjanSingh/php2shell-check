# php2shell-check

Fast, zero-dependency checker and remediation helper for the **PHP2Shell** remote
code execution flaws — **CVE-2026-109618** and **CVE-2026-109619**.

> **What this is:** a *defensive* tool. It inspects the PHP install on the
> machine it runs on, tells you whether you're affected, and gives you the exact
> steps to fix it. It sends **no** exploit traffic and cannot be aimed at a
> remote host. It is not an exploit and does not contain one.

## The vulnerability

On **2026-10-21** the PHP project shipped emergency patches for two critical
core RCE vulnerabilities, collectively nicknamed *PHP2Shell*:

| | |
|---|---|
| CVEs | CVE-2026-109618, CVE-2026-109619 |
| Severity | Critical — CVSS v4.0 **9.2** |
| Affected | PHP **5.4 through 8.5** |
| Fixed in | **8.5.12, 8.4.27, 8.3.36, 8.2.35** |
| Workaround | Disabling `session.upload_progress` blocks the confirmed path but is **incomplete** — patching is the only full fix |

PHP 5.x and 7.x are end-of-life and receive **no** official fix; affected servers
on those branches must move to a supported, patched branch.

## Install

Single file, no dependencies, Python 3.9+:

```bash
curl -O https://raw.githubusercontent.com/SirjanSingh/shiny-php/main/php2shell_check.py
chmod +x php2shell_check.py
```

## Usage

### Check this machine

```bash
./php2shell_check.py check
```

```
PHP2Shell check  (CVE-2026-109618, CVE-2026-109619, disclosed 2026-10-21)

  /usr/bin/php
    PHP 8.4.26 (cli) (built: Oct  1 2026 10:00:00) (NTS)
    AFFECTED: PHP 8.4.26 is affected. Update to 8.4.27 or later on this branch.

Action required. Run `php2shell-check harden` for the exact upgrade steps.
```

### Check a version string (no live PHP needed — great for CI / inventory)

```bash
./php2shell_check.py check --version 8.3.40
```

### Machine-readable output

```bash
./php2shell_check.py check --json
```

Exit codes: `0` not affected · `1` affected · `2` couldn't determine. Drop it
straight into CI:

```bash
./php2shell_check.py check --json || echo "patch PHP before shipping"
```

### Remediate

```bash
./php2shell_check.py harden              # print exact upgrade + workaround steps
./php2shell_check.py harden --apply --conf-dir /etc/php/8.4/fpm/conf.d
```

`harden` detects your OS and prints the right package-manager commands. With
`--apply` it writes a drop-in ini that disables `session.upload_progress` — a
**partial** mitigation; it will still tell you to update PHP.

### Scan logs for attack attempts

```bash
./php2shell_check.py scan-logs /var/log/apache2/error.log /var/log/modsec_audit.log
./php2shell_check.py scan-logs /var/log/nginx/access.log --json
```

Read-only. It flags **attempts**, not confirmed compromise, keying on indicators
published by security vendors after disclosure:

| Indicator | Log type | Source |
|---|---|---|
| `PHP_SESSION_UPLOAD_PROGRESS` in a request body | WAF / ModSecurity / body | Splunk, Zafran |
| Upload `filename=` with a `<?php` tag | WAF / body | Splunk |
| Serialized PHP object marker (`O:..`, `a:..`) in a body | WAF / body | Splunk |
| `PHP Fatal error … Unknown on line 0` | PHP / error log | Abstract Security |
| Apache `AH00052` child-exit | Apache error log | Abstract Security |
| Repeated large POSTs from one source IP | access log (heuristic) | Bitdefender, Beazley |

> **Important:** plain access logs almost never record request bodies, so a clean
> access-log scan is **not** an all-clear — the body/field indicators need a
> WAF/ModSecurity log. And patch PHP regardless; detection is not prevention.
> These are behavioral signals based on expected exploit behavior, not confirmed
> atomic IoCs — validate against your own logs.

## Tests

```bash
python -m unittest discover tests
```

## Sources

- [The Hacker News — PHP emergency patches for PHP2Shell RCE](https://thehackernews.com/2026/10/php-issues-emergency-patches-for-two.html)
- [Qualys — find, mitigate, and patch PHP2Shell](https://blog.qualys.com/vulnerabilities-threat-research/2026/10/20/php-announces-critical-security-release-for-two-vulnerabilities)
- [DigitalOcean — Critical PHP RCE, patch now](https://www.digitalocean.com/blog/critical-php-rce-vulnerabilities-patch-now)
- [Patchstack — PHP major vulnerability alert 10/2026](https://patchstack.com/articles/php-major-vulnerability-alert-10-2026/)

Detection guidance:

- [Splunk Research — PHP session upload progress detections](https://research.splunk.com/web/47b3ff26-c4cc-4413-9bf3-f44dbac36785/)
- [Abstract Security — PHP2Shell log artifacts](https://www.abstract.security/blog/php2shell-critical-php-rce-vulnerabilities-cve-2026-109618-and-cve-2026-109619)
- [Bitdefender — PHP2Shell technical advisory](https://www.bitdefender.com/en-us/blog/businessinsights/technical-advisory-php2shell-pre-auth-rce)
- [Zafran — PHP2Shell everything you need to know](https://www.zafran.io/resources/php2shell-everything-you-need-to-know-about-the-two-critical-php-vulnerabilities)

> Version/fix data in this tool reflects the 2026-10-21 release. Always confirm
> against [php.net](https://www.php.net/) for your exact branch.

## License

MIT — see [LICENSE](LICENSE).
