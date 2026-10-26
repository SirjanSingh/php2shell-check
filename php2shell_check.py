#!/usr/bin/env python3
"""php2shell-check — detect and help remediate the PHP2Shell RCE flaws.

PHP2Shell is the common name for two critical PHP core remote-code-execution
vulnerabilities disclosed in October 2026:

    CVE-2026-109618
    CVE-2026-109619

Both are rated Critical (CVSS v4.0 9.2) and affect PHP 5.4 through 8.5.
They were fixed in PHP 8.5.12, 8.4.27, 8.3.36 and 8.2.35 (released
2026-10-21). Config-only workarounds are incomplete: disabling
session.upload_progress blocks the confirmed session paths but not all
variants, so the only full fix is to update PHP.

This tool INSPECTS the environment it runs in. It reports whether the local
PHP install is affected and tells you how to fix it. It does not send any
exploit traffic and it cannot be pointed at a remote host — it is a
defensive checker/preventer, not an attack tool.

Usage:
    php2shell-check check [--php-binary PATH] [--version X.Y.Z] [--json]
    php2shell-check harden [--apply] [--conf-dir DIR] [--php-binary PATH]

Exit codes (check):
    0  not affected (patched, or a branch with no known issue)
    1  affected — action required
    2  could not determine (no PHP found / unparseable version)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from typing import Optional

__version__ = "0.1.0"

# --- Vulnerability data -----------------------------------------------------

CVES = ["CVE-2026-109618", "CVE-2026-109619"]
DISCLOSED = "2026-10-21"

# Minimum patched release for each still-supported branch. A version on one of
# these branches is safe only at or above the given patch number.
FIXED_PATCH = {
    (8, 5): 12,
    (8, 4): 27,
    (8, 3): 36,
    (8, 2): 35,
}

# Lowest version the advisory lists as affected.
AFFECTED_FROM = (5, 4, 0)

# Branches at or below this are end-of-life: no official fix ships for them,
# so the only remediation is moving to a supported, patched branch.
EOL_MAX_BRANCH = (8, 1)

RECOMMENDED_UPGRADE = "8.4.27 (or the latest 8.4.x), or stay on your branch at its patched release"


# --- Version parsing --------------------------------------------------------

_VERSION_RE = re.compile(r"\b(\d+)\.(\d+)\.(\d+)")


def parse_version(text: str) -> Optional[tuple[int, int, int]]:
    """Pull the first X.Y.Z out of arbitrary text (e.g. `php -v` output)."""
    m = _VERSION_RE.search(text)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


# --- Verdict logic ----------------------------------------------------------

STATUS_PATCHED = "patched"
STATUS_VULNERABLE = "vulnerable"
STATUS_VULNERABLE_EOL = "vulnerable_eol"
STATUS_UNKNOWN = "unknown"


@dataclass
class Verdict:
    version: Optional[tuple[int, int, int]]
    status: str
    detail: str
    fixed_version: Optional[str] = None

    @property
    def affected(self) -> bool:
        return self.status in (STATUS_VULNERABLE, STATUS_VULNERABLE_EOL)

    @property
    def version_str(self) -> Optional[str]:
        return ".".join(map(str, self.version)) if self.version else None


def assess(version: Optional[tuple[int, int, int]]) -> Verdict:
    if version is None:
        return Verdict(None, STATUS_UNKNOWN, "Could not determine a PHP version.")

    major, minor, patch = version
    branch = (major, minor)

    # Newer than anything we know about — can't claim it's affected.
    if branch > max(FIXED_PATCH):
        return Verdict(
            version, STATUS_UNKNOWN,
            f"PHP {major}.{minor} is newer than this tool's data "
            f"(last updated for the {DISCLOSED} release). Verify against php.net.",
        )

    # A still-supported branch with a known fixed patch level.
    if branch in FIXED_PATCH:
        fixed = FIXED_PATCH[branch]
        fixed_str = f"{major}.{minor}.{fixed}"
        if patch >= fixed:
            return Verdict(version, STATUS_PATCHED,
                           f"PHP {major}.{minor}.{patch} includes the PHP2Shell fix "
                           f"(fixed in {fixed_str}).",
                           fixed_version=fixed_str)
        return Verdict(version, STATUS_VULNERABLE,
                       f"PHP {major}.{minor}.{patch} is affected. "
                       f"Update to {fixed_str} or later on this branch.",
                       fixed_version=fixed_str)

    # Older branch. Affected if within the advisory's range; EOL either way.
    if version >= AFFECTED_FROM and branch <= EOL_MAX_BRANCH:
        return Verdict(version, STATUS_VULNERABLE_EOL,
                       f"PHP {major}.{minor}.{patch} is affected and end-of-life — "
                       f"no official patch ships for it. Move to a supported branch "
                       f"({RECOMMENDED_UPGRADE}).")

    if version < AFFECTED_FROM:
        return Verdict(version, STATUS_VULNERABLE_EOL,
                       f"PHP {major}.{minor}.{patch} predates the advisory's stated "
                       f"range and is long end-of-life; treat as exposed and upgrade "
                       f"to a supported branch ({RECOMMENDED_UPGRADE}).")

    return Verdict(version, STATUS_UNKNOWN,
                   f"PHP {major}.{minor}.{patch}: unable to classify; verify against php.net.")


# --- PHP discovery ----------------------------------------------------------

@dataclass
class PhpInstall:
    binary: str
    raw_version: str
    verdict: Verdict
    upload_progress_enabled: Optional[bool] = None
    config: dict = field(default_factory=dict)
    stale: list = field(default_factory=list)


def _run(cmd: list[str]) -> Optional[str]:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return None
    return (out.stdout or "") + (out.stderr or "")


def find_php_binaries(explicit: Optional[str] = None) -> list[str]:
    if explicit:
        return [explicit]
    candidates = ["php", "php-fpm", "php8.5", "php8.4", "php8.3", "php8.2",
                  "php8.1", "php8.0", "php7.4"]
    found: list[str] = []
    for name in candidates:
        path = shutil.which(name)
        if path and path not in found:
            found.append(path)
    return found


# php.ini settings worth surfacing. They only reduce exposure while PHP is
# unpatched; none of them is a fix (see posture_notes).
POSTURE_KEYS = (
    "session.upload_progress.enabled",
    "session.upload_progress.cleanup",
    "post_max_size",
    "memory_limit",
    "fatal_error_backtraces",
)


def parse_ini_posture(text: str) -> dict:
    """Pull POSTURE_KEYS out of `php -i` text. `php -i` prints
    `key => local value => master value`; the local (effective) value is kept."""
    out = {}
    for key in POSTURE_KEYS:
        m = re.search(rf"^{re.escape(key)}\s*=>\s*([^=\n]*?)\s*(?:=>|$)",
                      text, re.MULTILINE)
        if m:
            out[key] = m.group(1).strip()
    return out


def _ini_bool(value: Optional[str]) -> Optional[bool]:
    if value is None:
        return None
    return value.strip().lower() in ("on", "1", "enabled", "true", "yes")


def read_ini_posture(binary: str) -> dict:
    text = _run([binary, "-i"])
    return parse_ini_posture(text) if text else {}


def inspect_binary(binary: str) -> Optional[PhpInstall]:
    raw = _run([binary, "-v"])
    if raw is None:
        return None
    verdict = assess(parse_version(raw))
    install = PhpInstall(binary=binary, raw_version=raw.strip().splitlines()[0] if raw.strip() else "",
                         verdict=verdict)
    # `php-fpm -i` reports the FPM SAPI's ini, which can differ from the CLI's.
    if os.path.basename(binary).startswith("php"):
        install.config = read_ini_posture(binary)
        install.upload_progress_enabled = _ini_bool(
            install.config.get("session.upload_progress.enabled"))
    return install


# --- Output -----------------------------------------------------------------

def _c(text: str, color: str, use_color: bool) -> str:
    if not use_color:
        return text
    codes = {"red": "31", "green": "32", "yellow": "33", "bold": "1"}
    return f"\033[{codes[color]}m{text}\033[0m"


def posture_notes(ins: PhpInstall) -> list[str]:
    """Config-posture lines for an affected install. These describe temporary
    exposure reduction (per Elastic's relay of the PHP security team's guidance),
    never a fix, so they are only shown while the install is still affected."""
    cfg = ins.config
    if not cfg or not ins.verdict.affected:
        return []
    notes = []
    shown = [f"{k}={cfg[k]}" for k in
             ("session.upload_progress.enabled", "post_max_size", "memory_limit")
             if k in cfg]
    if shown:
        notes.append("config: " + "  ".join(shown))
    if ins.upload_progress_enabled is True:
        notes.append("session.upload_progress.enabled is On — this is the "
                     "confirmed exploit path. Disabling it is a PARTIAL workaround only.")
    if (ins.verdict.version or ())[:2] == (8, 5) and _ini_bool(cfg.get("fatal_error_backtraces")):
        notes.append("fatal_error_backtraces is on; Elastic advises 0 on PHP 8.5 "
                     "as a temporary measure.")
    if shown:
        notes.append("settings like these only reduce exposure and must be set in "
                     "php.ini / the FPM pool / server config (ini_set() and "
                     ".user.ini do not help). Update PHP.")
    return notes


def print_human(installs: list[PhpInstall], use_color: bool) -> None:
    print(_c("PHP2Shell check", "bold", use_color) +
          f"  ({', '.join(CVES)}, disclosed {DISCLOSED})")
    print()
    if not installs:
        print(_c("No PHP binary found on PATH.", "yellow", use_color))
        print("Pass --php-binary /path/to/php, or --version X.Y.Z to check a version string.")
        return
    for ins in installs:
        v = ins.verdict
        if v.status == STATUS_PATCHED:
            tag = _c("OK — patched", "green", use_color)
        elif v.affected:
            tag = _c("AFFECTED", "red", use_color)
        else:
            tag = _c("UNKNOWN", "yellow", use_color)
        print(f"  {ins.binary}")
        print(f"    {ins.raw_version}")
        print(f"    {tag}: {v.detail}")
        for note in posture_notes(ins):
            print(f"    note: {note}")
        print()

    if any(i.verdict.affected for i in installs):
        print(_c("Action required.", "red", use_color) +
              " Run `php2shell-check harden` for the exact upgrade steps.")


# --- harden / preventer ------------------------------------------------------

PARTIAL_WORKAROUND_INI = (
    "; php2shell-check: PARTIAL mitigation for {cves}.\n"
    "; This blocks the confirmed session.upload_progress exploit path only.\n"
    "; It is NOT a full fix — you MUST still update PHP to a patched release.\n"
    "session.upload_progress.enabled = Off\n"
).format(cves=", ".join(CVES))


def detect_os() -> str:
    try:
        with open("/etc/os-release", encoding="utf-8") as fh:
            data = fh.read()
    except OSError:
        return "unknown"
    m = re.search(r'^ID=("?)([\w-]+)\1', data, re.MULTILINE)
    return m.group(2) if m else "unknown"


def upgrade_commands(os_id: str) -> list[str]:
    table = {
        "debian": ["sudo apt update", "sudo apt install --only-upgrade php php-fpm php-cli"],
        "ubuntu": ["sudo apt update", "sudo apt install --only-upgrade php php-fpm php-cli"],
        "rhel": ["sudo dnf update php php-fpm php-cli"],
        "centos": ["sudo dnf update php php-fpm php-cli"],
        "fedora": ["sudo dnf update php php-fpm php-cli"],
        "rocky": ["sudo dnf update php php-fpm php-cli"],
        "almalinux": ["sudo dnf update php php-fpm php-cli"],
        "alpine": ["sudo apk update", "sudo apk upgrade php84 php84-fpm  # match your php8x package"],
    }
    return table.get(os_id, [
        "# Unrecognized OS. Update PHP via your package manager or rebuild your",
        "# container from an official image tag: php:8.4.27-fpm / 8.3.36 / 8.2.35 / 8.5.12",
    ])


def cmd_harden(args: argparse.Namespace) -> int:
    installs = [i for b in find_php_binaries(args.php_binary)
                if (i := inspect_binary(b)) is not None]
    os_id = detect_os()

    print(f"PHP2Shell preventer  ({', '.join(CVES)})")
    print()
    print("1) Full fix — update PHP to a patched release:")
    print(f"   target branches: 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 (detected OS: {os_id})")
    for line in upgrade_commands(os_id):
        print(f"     {line}")
    print("   After updating, re-run `php2shell-check check` to confirm.")
    print()
    print("2) Partial workaround — disable session.upload_progress (NOT a substitute for patching):")

    if not args.apply:
        print("   Drop-in php.ini snippet (write it with --apply --conf-dir <dir>):")
        print()
        for line in PARTIAL_WORKAROUND_INI.splitlines():
            print(f"     {line}")
        print()
        print("   Re-run with --apply to write this to a conf.d directory.")
        return 0

    conf_dir = args.conf_dir
    if not conf_dir:
        print("   --apply needs --conf-dir pointing at your PHP conf.d "
              "(e.g. /etc/php/8.4/fpm/conf.d). Nothing written.", file=sys.stderr)
        return 2
    target = os.path.join(conf_dir, "99-php2shell-mitigation.ini")
    try:
        os.makedirs(conf_dir, exist_ok=True)
        with open(target, "w", encoding="utf-8") as fh:
            fh.write(PARTIAL_WORKAROUND_INI)
    except OSError as exc:
        print(f"   Failed to write {target}: {exc}", file=sys.stderr)
        return 2
    print(f"   Wrote {target}")
    print("   Reload PHP-FPM / your web server for it to take effect, "
          "then STILL update PHP.")
    return 0


# --- scan-logs / detection ---------------------------------------------------
#
# These indicators are behavioral detection guidance published by security
# vendors after the 2026-10-21 disclosure. They detect *attempts*; they are not
# exploit code and do not reproduce the vulnerability. Each carries its source
# so the logic is auditable. Validate against your own logs — vendors note these
# are based on expected exploit behavior, not confirmed atomic IoCs.

@dataclass
class Indicator:
    id: str
    severity: str          # high | medium | low
    log_types: tuple       # which log kinds this applies to
    pattern: "re.Pattern"
    description: str
    source: str


LINE_INDICATORS = [
    Indicator(
        "upload_progress_field", "high", ("waf", "body"),
        re.compile(r"PHP_SESSION_UPLOAD_PROGRESS"),
        "PHP_SESSION_UPLOAD_PROGRESS field in a request body — near-zero "
        "legitimate use; with the setting disabled it is effectively an attempt.",
        "Splunk / Zafran",
    ),
    Indicator(
        "php_tag_in_upload", "high", ("waf", "body"),
        re.compile(r'filename="[^"]*<\?(?:php|=)', re.IGNORECASE),
        "Upload filename contains a PHP open tag — attempt to smuggle "
        "executable PHP through session upload-progress handling.",
        "Splunk",
    ),
    Indicator(
        "serialized_in_upload", "high", ("waf", "body"),
        re.compile(r'(?:O:\d+:"|a:\d+:\{)'),
        "Serialized PHP object/array marker in a request body — payload shape "
        "for the upload-progress deserialization path.",
        "Splunk",
    ),
    Indicator(
        "php_fatal_unknown_line0", "medium", ("error",),
        re.compile(r"Unknown on line 0"),
        "PHP fatal error on 'Unknown on line 0' — memory exhaustion outside "
        "normal script execution, consistent with the use-after-free trigger.",
        "Abstract Security",
    ),
    Indicator(
        "apache_child_exit", "low", ("error",),
        re.compile(r"AH00052"),
        "Apache child-process exit (AH00052) — large/malformed POSTs can crash "
        "workers; noisy on its own, corroborating alongside the above.",
        "Abstract Security",
    ),
]

# Access-log heuristic thresholds (bodies are usually not logged, so we fall
# back to volume signals).
_ACCESS_RE = re.compile(
    r'^(\S+)\s+\S+\s+\S+\s+\[[^\]]+\]\s+"(\S+)\s+(\S+)[^"]*"\s+(\d{3})\s+(\S+)'
)
DEFAULT_LARGE_POST_BYTES = 100_000
DEFAULT_BURST = 3


@dataclass
class Finding:
    file: str
    line_no: int
    indicator_id: str
    severity: str
    excerpt: str


@dataclass
class AccessAlert:
    file: str
    ip: str
    large_posts: int
    total_posts: int


def guess_log_type(sample: str) -> str:
    if "PHP_SESSION_UPLOAD_PROGRESS" in sample or "filename=" in sample:
        return "waf"
    if "Unknown on line 0" in sample or "AH00052" in sample or "PHP Fatal" in sample:
        return "error"
    if _ACCESS_RE.search(sample):
        return "access"
    return "unknown"


def scan_file(path: str, forced_type: Optional[str],
              large_bytes: int, burst: int) -> tuple[list[Finding], list[AccessAlert]]:
    findings: list[Finding] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError as exc:
        return [Finding(path, 0, "read_error", "low", str(exc))], []

    log_type = forced_type or guess_log_type("".join(lines[:50]))

    # Line-level indicator matches (applied regardless of type guess; the type
    # just decides which indicators are relevant to avoid noise).
    for i, line in enumerate(lines, 1):
        for ind in LINE_INDICATORS:
            if forced_type and forced_type not in ind.log_types:
                continue
            if ind.pattern.search(line):
                findings.append(Finding(path, i, ind.id, ind.severity,
                                        line.strip()[:300]))

    # Access-log volume heuristic.
    alerts: list[AccessAlert] = []
    if log_type in ("access", "unknown") and forced_type != "error":
        per_ip_large: dict[str, int] = {}
        per_ip_total: dict[str, int] = {}
        for line in lines:
            m = _ACCESS_RE.search(line)
            if not m:
                continue
            ip, method, _path, _status, size = m.groups()
            if method.upper() != "POST":
                continue
            per_ip_total[ip] = per_ip_total.get(ip, 0) + 1
            if size.isdigit() and int(size) >= large_bytes:
                per_ip_large[ip] = per_ip_large.get(ip, 0) + 1
        for ip, large in per_ip_large.items():
            if large >= burst:
                alerts.append(AccessAlert(path, ip, large, per_ip_total.get(ip, 0)))

    return findings, alerts


def cmd_scan_logs(args: argparse.Namespace) -> int:
    if not args.paths:
        print("Usage: php2shell-check scan-logs LOGFILE [LOGFILE ...] "
              "[--type access|error|waf] [--json]", file=sys.stderr)
        return 2

    all_findings: list[Finding] = []
    all_alerts: list[AccessAlert] = []
    for path in args.paths:
        f, a = scan_file(path, args.type, args.large_bytes, args.burst)
        all_findings.extend(f)
        all_alerts.extend(a)

    if getattr(args, "sarif", False):
        print(json.dumps(scan_to_sarif(all_findings, all_alerts), indent=2))
    elif args.json:
        print(json.dumps({
            "cves": CVES,
            "findings": [asdict(f) for f in all_findings],
            "access_alerts": [asdict(a) for a in all_alerts],
        }, indent=2))
    else:
        print(f"PHP2Shell log scan  ({', '.join(CVES)})\n")
        if not all_findings and not all_alerts:
            print("  No indicators matched.")
            print("  NOTE: plain access logs rarely contain request bodies, so a")
            print("  clean scan here is NOT an all-clear. For body/field detection")
            print("  point this at WAF/ModSecurity logs, and still patch PHP.")
            return 0
        order = {"high": 0, "medium": 1, "low": 2}
        for f in sorted(all_findings, key=lambda x: order.get(x.severity, 9)):
            print(f"  [{f.severity.upper()}] {f.indicator_id}  {f.file}:{f.line_no}")
            print(f"      {f.excerpt}")
        for a in all_alerts:
            print(f"  [HEURISTIC] large-POST burst from {a.ip} in {a.file}: "
                  f"{a.large_posts} large POSTs ({a.total_posts} POSTs total)")
        print("\n  Review context before acting; these flag attempts, not "
              "confirmed compromise. Patch PHP regardless.")
    return exit_code_for([f.severity for f in all_findings] + ["medium"] * len(all_alerts),
                         args.fail_on, 1 if (all_findings or all_alerts) else 0)


# --- SARIF output ------------------------------------------------------------
# SARIF lets CI upload results to GitHub code scanning (Security tab).

REPO_URL = "https://github.com/SirjanSingh/shiny-php"
_SARIF_LEVEL = {"high": "error", "medium": "warning", "low": "note"}


def _sarif_doc(rules: list, results: list) -> dict:
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "php2shell-check",
                "version": __version__,
                "informationUri": REPO_URL,
                "rules": rules,
            }},
            "results": results,
        }],
    }


def check_to_sarif(installs: list) -> dict:
    rule = {
        "id": "php2shell-affected",
        "name": "PHP2ShellAffectedVersion",
        "shortDescription": {
            "text": f"PHP version affected by PHP2Shell ({', '.join(CVES)})"},
        "helpUri": REPO_URL,
    }
    results = [{
        "ruleId": "php2shell-affected",
        "level": "error",
        "message": {"text": ins.verdict.detail},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": ins.binary}}}],
    } for ins in installs if ins.verdict.affected]
    return _sarif_doc([rule], results)


def scan_to_sarif(findings: list, alerts: list) -> dict:
    rules = [{
        "id": ind.id, "name": ind.id,
        "shortDescription": {"text": ind.description},
        "helpUri": REPO_URL,
        "properties": {"severity": ind.severity, "source": ind.source},
    } for ind in LINE_INDICATORS]
    rules.append({"id": "large_post_burst", "name": "large_post_burst",
                  "shortDescription": {"text": "Large-POST burst from one source IP"},
                  "helpUri": REPO_URL})
    results = [{
        "ruleId": f.indicator_id,
        "level": _SARIF_LEVEL.get(f.severity, "warning"),
        "message": {"text": f.excerpt},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": f.file},
            "region": {"startLine": max(f.line_no, 1)}}}],
    } for f in findings]
    results.extend({
        "ruleId": "large_post_burst",
        "level": "warning",
        "message": {"text": f"{a.large_posts} large POSTs from {a.ip} "
                            f"({a.total_posts} total)"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": a.file}}}],
    } for a in alerts)
    return _sarif_doc(rules, results)


# --- fleet inventory ---------------------------------------------------------

_INV_RE = re.compile(r"^\s*(?:(?P<label>[^#=:\s]+)\s*[:=\s]\s*)?(?P<ver>\d+\.\d+\.\d+)")


def read_inventory(path: str) -> list:
    """Parse a file of `label version`, `label=version`, or bare `version` lines
    for offline fleet checks (no network, no SSH)."""
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError as exc:
        return [PhpInstall(f"(inventory {path})", "",
                           Verdict(None, STATUS_UNKNOWN, str(exc)))]
    installs = []
    for raw in lines:
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        m = _INV_RE.match(raw)
        if not m:
            continue
        label = m.group("label") or m.group("ver")
        installs.append(PhpInstall(label, m.group("ver"),
                                   assess(parse_version(m.group("ver")))))
    return installs


# --- docker scanning ---------------------------------------------------------

_PHP_IMAGE_RE = re.compile(r"\bphp:([A-Za-z0-9][A-Za-z0-9._-]*)")
_BRANCH_RE = re.compile(r"^(\d+)\.(\d+)(?:$|[^.\d])")


def assess_tag(tag: str) -> Verdict:
    """Assess a Docker image tag. Full X.Y.Z is assessed exactly; a floating
    branch tag (php:8.4) is ambiguous for supported branches and definitively
    affected for end-of-life ones."""
    v = parse_version(tag)
    if v is not None:
        return assess(v)
    m = _BRANCH_RE.match(tag)
    if not m:
        return Verdict(None, STATUS_UNKNOWN,
                       f"php:{tag} has no version in the tag — pin a full "
                       f"patched tag (e.g. php:8.4.27).")
    branch = (int(m.group(1)), int(m.group(2)))
    if branch in FIXED_PATCH:
        fixed = f"{branch[0]}.{branch[1]}.{FIXED_PATCH[branch]}"
        return Verdict(None, STATUS_UNKNOWN,
                       f"php:{m.group(1)}.{m.group(2)} is a floating branch tag — "
                       f"it may or may not include the fix ({fixed}). "
                       f"Pin php:{fixed} or later.")
    if (5, 4) <= branch <= EOL_MAX_BRANCH:
        return Verdict(None, STATUS_VULNERABLE_EOL,
                       f"php:{m.group(1)}.{m.group(2)} is an end-of-life branch "
                       f"with no official fix — move to a supported branch "
                       f"({RECOMMENDED_UPGRADE}).")
    return Verdict(None, STATUS_UNKNOWN,
                   f"php:{m.group(1)}.{m.group(2)} could not be classified; "
                   f"verify against php.net.")
DEFAULT_DOCKER_FILES = ["Dockerfile", "docker-compose.yml", "docker-compose.yaml",
                        "compose.yml", "compose.yaml"]


@dataclass
class DockerHit:
    source: str
    line_no: int
    image_tag: str
    verdict: Verdict


def scan_docker_files(paths: list) -> list:
    hits = []
    for path in paths:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except OSError:
            continue
        for i, line in enumerate(lines, 1):
            for m in _PHP_IMAGE_RE.finditer(line):
                tag = m.group(1)
                hits.append(DockerHit(path, i, f"php:{tag}", assess_tag(tag)))
    return hits


def scan_running_containers() -> tuple:
    docker = shutil.which("docker")
    if not docker:
        return [], "docker CLI not found on PATH"
    out = _run([docker, "ps", "--format", "{{.ID}} {{.Image}}"])
    if out is None:
        return [], "could not run `docker ps` (is the daemon running / permitted?)"
    hits = []
    for line in out.splitlines():
        parts = line.split(None, 1)
        if not parts:
            continue
        cid, image = parts[0], (parts[1] if len(parts) > 1 else "?")
        ver = parse_version(_run([docker, "exec", cid, "php", "-v"]) or "")
        if ver is None:
            continue
        hits.append(DockerHit(f"container {cid} ({image})", 0, image, assess(ver)))
    return hits, None


def cmd_scan_docker(args: argparse.Namespace) -> int:
    paths = args.paths or [p for p in DEFAULT_DOCKER_FILES if os.path.exists(p)]
    hits = scan_docker_files(paths)
    note = None
    if args.running:
        running, note = scan_running_containers()
        hits.extend(running)

    affected = [h for h in hits if h.verdict.affected]
    unknown = [h for h in hits if h.verdict.status == STATUS_UNKNOWN]

    if args.json:
        print(json.dumps({"cves": CVES, "note": note, "hits": [
            {"source": h.source, "line": h.line_no, "image": h.image_tag,
             "version": h.verdict.version_str, "status": h.verdict.status,
             "affected": h.verdict.affected, "detail": h.verdict.detail}
            for h in hits]}, indent=2))
    else:
        print(f"PHP2Shell Docker scan  ({', '.join(CVES)})\n")
        if note:
            print(f"  note: {note}\n")
        if not hits:
            print("  No PHP images found. Pass Dockerfile/compose paths, or --running.")
            return 0
        for h in hits:
            tag = ("AFFECTED" if h.verdict.affected else
                   "OK" if h.verdict.status == STATUS_PATCHED else "UNKNOWN")
            loc = h.source + (f":{h.line_no}" if h.line_no else "")
            print(f"  [{tag}] {h.image_tag}  {loc}")
            print(f"      {h.verdict.detail}")
        if unknown:
            print("\n  UNKNOWN = a branch tag with no patch number (e.g. php:8.3). "
                  "Pin a full patched tag such as php:8.3.36.")
    sevs = ["high" if h.verdict.affected else "medium"
            for h in hits if h.verdict.affected or h.verdict.status == STATUS_UNKNOWN]
    return exit_code_for(sevs, args.fail_on, 1 if affected else 0)


# --- exit codes / --fail-on --------------------------------------------------

FAIL_ON_CHOICES = ("high", "medium", "low", "none")
_SEV_RANK = {"low": 1, "medium": 2, "high": 3}


def exit_code_for(severities: list, fail_on: Optional[str], default: int) -> int:
    """Exit 1 when any severity reaches the --fail-on threshold, else 0.
    No --fail-on keeps each command's historical exit code (`default`);
    `none` never fails."""
    if fail_on is None:
        return default
    if fail_on == "none":
        return 0
    threshold = _SEV_RANK[fail_on]
    return 1 if any(_SEV_RANK.get(s, 0) >= threshold for s in severities) else 0


def install_severity(ins: PhpInstall) -> Optional[str]:
    """high = affected (or still running replaced code); medium = undetermined."""
    if ins.verdict.affected or ins.stale:
        return "high"
    if ins.verdict.status == STATUS_UNKNOWN:
        return "medium"
    return None


def check_exit_code(installs: list, fail_on: Optional[str]) -> int:
    if not installs:
        default = 2
    elif any(i.verdict.affected or i.stale for i in installs):
        default = 1
    elif all(i.verdict.status == STATUS_UNKNOWN for i in installs):
        default = 2
    else:
        default = 0
    if not installs and fail_on not in (None, "none"):
        return 2  # nothing was checked, so a threshold can't be evaluated
    return exit_code_for([install_severity(i) for i in installs], fail_on, default)


def add_fail_on(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--fail-on", choices=FAIL_ON_CHOICES, metavar="LEVEL",
        help="exit 1 only for findings at or above LEVEL (high|medium|low), or "
             "'none' to always exit 0. Default: the command's usual exit codes")


# --- check command -----------------------------------------------------------

def cmd_check(args: argparse.Namespace) -> int:
    if getattr(args, "inventory", None):
        installs = read_inventory(args.inventory)
    elif args.version:
        v = parse_version(args.version)
        verdict = assess(v)
        install = PhpInstall(binary=f"(version string: {args.version})",
                             raw_version=args.version, verdict=verdict)
        installs = [install]
    else:
        installs = [i for b in find_php_binaries(args.php_binary)
                    if (i := inspect_binary(b)) is not None]

    if getattr(args, "sarif", False):
        print(json.dumps(check_to_sarif(installs), indent=2))
    elif args.json:
        payload = {
            "cves": CVES,
            "disclosed": DISCLOSED,
            "installs": [
                {
                    "binary": i.binary,
                    "version": i.verdict.version_str,
                    "status": i.verdict.status,
                    "affected": i.verdict.affected,
                    "fixed_version": i.verdict.fixed_version,
                    "upload_progress_enabled": i.upload_progress_enabled,
                    "config": i.config,
                    "detail": i.verdict.detail,
                }
                for i in installs
            ],
        }
        print(json.dumps(payload, indent=2))
    else:
        print_human(installs, use_color=sys.stdout.isatty() and not args.no_color)

    return check_exit_code(installs, args.fail_on)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="php2shell-check",
        description="Detect and help remediate the PHP2Shell RCE flaws "
                    f"({', '.join(CVES)}).",
    )
    p.add_argument("--version", action="version",
                   version=f"php2shell-check {__version__}")
    sub = p.add_subparsers(dest="command")

    c = sub.add_parser("check", help="detect affected PHP installs")
    c.add_argument("--php-binary", help="check a specific php binary path")
    c.add_argument("--version", dest="version", metavar="X.Y.Z",
                   help="assess a version string instead of a live binary")
    c.add_argument("--inventory", metavar="FILE",
                   help="offline fleet check: a file of `label version` lines "
                        "(no network, no SSH)")
    c.add_argument("--json", action="store_true", help="machine-readable output")
    c.add_argument("--sarif", action="store_true",
                   help="SARIF output for GitHub code scanning")
    c.add_argument("--no-color", action="store_true", help="disable ANSI color")
    add_fail_on(c)
    c.set_defaults(func=cmd_check)

    h = sub.add_parser("harden", help="show/apply remediation steps")
    h.add_argument("--apply", action="store_true",
                   help="write the partial-workaround ini (needs --conf-dir)")
    h.add_argument("--conf-dir", help="PHP conf.d directory to write the ini into")
    h.add_argument("--php-binary", help="inspect a specific php binary path")
    h.set_defaults(func=cmd_harden)

    s = sub.add_parser("scan-logs",
                       help="scan web/PHP logs for PHP2Shell attack indicators")
    s.add_argument("paths", nargs="*", help="log files to scan")
    s.add_argument("--type", choices=("access", "error", "waf", "body"),
                   help="force log type (default: auto-detect per file)")
    s.add_argument("--large-bytes", type=int, default=DEFAULT_LARGE_POST_BYTES,
                   help=f"POST size (bytes) counted as 'large' "
                        f"(default {DEFAULT_LARGE_POST_BYTES})")
    s.add_argument("--burst", type=int, default=DEFAULT_BURST,
                   help=f"large-POST count from one IP to alert on "
                        f"(default {DEFAULT_BURST})")
    s.add_argument("--json", action="store_true", help="machine-readable output")
    s.add_argument("--sarif", action="store_true",
                   help="SARIF output for GitHub code scanning")
    add_fail_on(s)
    s.set_defaults(func=cmd_scan_logs)

    d = sub.add_parser("scan-docker",
                       help="scan Dockerfiles/compose files and running containers")
    d.add_argument("paths", nargs="*",
                   help="Dockerfile/compose paths (default: common files in cwd)")
    d.add_argument("--running", action="store_true",
                   help="also read PHP versions from running containers via docker")
    d.add_argument("--json", action="store_true", help="machine-readable output")
    add_fail_on(d)
    d.set_defaults(func=cmd_scan_docker)

    return p


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        # Default to `check` for a bare invocation.
        args = parser.parse_args(["check", *(argv or [])])
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
