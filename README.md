# php2shell-check

[![CI](https://github.com/SirjanSingh/shiny-php/actions/workflows/ci.yml/badge.svg)](https://github.com/SirjanSingh/shiny-php/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)
![Dependencies: none](https://img.shields.io/badge/dependencies-none-brightgreen)

Fast, zero-dependency checker and remediation helper for the **PHP2Shell** remote
code execution flaws — **CVE-2026-109618** and **CVE-2026-109619**.

> **What this is:** a *defensive* tool. It inspects systems you operate — the
> local PHP install, version strings, Dockerfiles/compose files, your own
> running containers, and your own logs — tells you whether you're affected, and
> gives you the exact steps to fix it. It sends **no** exploit traffic and cannot
> be aimed at a remote host. It is not an exploit and does not contain one.

## Respond in 60 seconds

```bash
curl -sO https://raw.githubusercontent.com/SirjanSingh/shiny-php/main/php2shell_check.py
python3 php2shell_check.py check      # Am I affected?
python3 php2shell_check.py harden     # If so, exact fix for my OS
# Then update PHP to 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 and re-check.
```

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

Or install it as a command with `pipx` (or `pip`):

```bash
pipx install php2shell-check          # from PyPI
# or straight from source, no release needed:
pipx install git+https://github.com/SirjanSingh/shiny-php
php2shell-check check
```

> Maintainers: see [RELEASING.md](RELEASING.md) for the one-time PyPI
> Trusted-Publishing setup. Tagging `vX.Y.Z` then publishes automatically.

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

### Scan Docker images

```bash
./php2shell_check.py scan-docker                       # Dockerfiles/compose in cwd
./php2shell_check.py scan-docker path/to/Dockerfile compose.yml
./php2shell_check.py scan-docker --running             # + your running containers
```

Reads PHP base-image tags. A pinned tag (`php:8.3.10`) is judged exactly; a
floating branch tag (`php:8.4`) is flagged as ambiguous (pin a patched tag),
and an end-of-life branch tag (`php:8.1`) is flagged affected outright.

### Check a whole fleet (offline)

```bash
./php2shell_check.py check --inventory hosts.txt
```

`hosts.txt` is one `label version` per line — straight from your inventory /
Ansible facts, no network or SSH involved:

```
web01 8.3.10
web02=8.4.27
db01: 7.4.33
```

### SARIF → GitHub code scanning

```bash
./php2shell_check.py check --sarif > results.sarif
./php2shell_check.py scan-logs /var/log/modsec_audit.log --sarif > results.sarif
```

Upload it so findings land in your repo's **Security** tab:

```yaml
# .github/workflows/php2shell.yml
- run: python php2shell_check.py scan-docker --sarif > results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Why there's no remote "URL scan" mode

Some PHP2Shell tools send a crafted probe to a target URL to test it. This one
deliberately doesn't. It only inspects systems you operate (local, inventory,
your Dockerfiles, your containers, your logs), so you can't accidentally point it
at a host you don't own, and running it is never itself an attack. If you want to
check a server, run it **on** that server. Full reasoning in [SECURITY.md](SECURITY.md).

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
