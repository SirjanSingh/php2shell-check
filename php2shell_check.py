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

A separate, later issue, CVE-2026-115560 (disclosed 2026-10-23), is NOT fixed by
those releases and has no patch yet. It needs an unusual setup: a non-default
session.serialize_handler switched to `php` at runtime with ini_set(), with
session.upload_progress.enabled still on. `check` reports the config side of
that and `scan-code` looks for the application-code side.

Usage:
    php2shell-check check [--php-binary PATH] [--version X.Y.Z] [--json]
                          [--inventory FILE | --ssh-hosts FILE [--ssh-jobs N]]
                          [--no-restart-check] [--fail-on LEVEL]
                          [--markdown FILE] [--html FILE]
    php2shell-check harden [--apply] [--conf-dir DIR] [--php-binary PATH]
    php2shell-check scan-logs LOGFILE [...] [--fail-on LEVEL]
    php2shell-check scan-docker [PATH ...] [--image IMAGE ...] [--running]
                                [--fail-on LEVEL] [--markdown FILE] [--html FILE]
    php2shell-check scan-code PATH [...] [--json] [--fail-on LEVEL]
    php2shell-check rules [--format modsecurity|sigma|suricata|all]
                          [--output DIR] [--block]

Exit codes (check):
    0  not affected (patched, or a branch with no known issue)
    1  affected, or PHP processes still running code replaced on disk
    2  could not determine (no PHP found / unparseable version)
Exit codes (scan-docker): the same 0 and 1; 2 when nothing is affected and
every --image probe is UNKNOWN (or a report file cannot be written).
--fail-on high|medium|low|none changes this to "1 only at or above that level".
"""

from __future__ import annotations

import argparse
import gzip
import html
import json
import os
import re
import shutil
import subprocess
import sys
import uuid
import zlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional

__version__ = "0.3.0"

# --- Vulnerability data -----------------------------------------------------

CVES = ["CVE-2026-109618", "CVE-2026-109619"]
DISCLOSED = "2026-10-21"

# A separate, later issue. The 2026-10-21 releases do NOT fix it, and PHP has
# named no fixed version yet ("the next regular bugfix release"). It needs an
# unusual combination: session.serialize_handler set to php_binary or
# php_serialize in config, an app that switches it to `php` with ini_set()
# before session_start(), and session.upload_progress.enabled still on.
CVE_SESSION = "CVE-2026-115560"
DISCLOSED_SESSION = "2026-10-23"

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
# A version-affected build whose distro changelog names both CVEs.
STATUS_PATCHED_BACKPORT = "patched_backport"


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
class PackageInfo:
    manager: str  # "dpkg" | "rpm"
    name: str
    version: str
    cves: Optional[list]  # IDs from CVES found in the changelog, sorted; None = changelog not available


@dataclass
class PhpInstall:
    binary: str
    raw_version: str
    verdict: Verdict
    upload_progress_enabled: Optional[bool] = None
    config: dict = field(default_factory=dict)
    stale: list = field(default_factory=list)
    package: Optional[PackageInfo] = None


def _run(cmd: list[str]) -> Optional[str]:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return None
    return (out.stdout or "") + (out.stderr or "")


def _run_ok(cmd: list[str]) -> Optional[str]:
    """stdout of a command that exited 0, else None (also when it is not installed)."""
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout if out.returncode == 0 else None


# --- distro backports --------------------------------------------------------
#
# Some vendors fix a CVE without moving to the upstream fixed version (RHEL
# 8.0.30-8.el9_8.1, AlmaLinux .alma.1 rebuilds, Remi builds of EOL branches), so
# the version string alone over-reports. Debian and Ubuntu security updates move
# to the fixed upstream version, which the version check already covers. An
# affected version counts as patched only when the package that owns the binary
# is that same upstream version and its changelog names BOTH CVE IDs.

_PKG_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+_-]*")


def changelog_cves(text: str) -> list:
    """The members of CVES that appear in `text`, sorted. An ID followed by
    another digit is a different CVE (CVE-2026-1096185), so it does not count."""
    return sorted(c for c in CVES if re.search(re.escape(c) + r"(?![0-9])", text))


def package_for_binary(binary: str) -> Optional[PackageInfo]:
    """The dpkg or rpm package that owns `binary`, or None when neither tool
    is installed or neither owns the file."""
    path = os.path.realpath(binary)
    if shutil.which("dpkg"):
        owner = _run_ok(["dpkg", "-S", path])
        if owner and owner.strip():
            name = owner.splitlines()[0].split(":")[0].split(",")[0].strip()
            version = _run_ok(["dpkg-query", "-W", "-f=${Version}", name]) if shutil.which("dpkg-query") else None
            if version and version.strip() and _PKG_NAME_RE.fullmatch(name):
                return PackageInfo("dpkg", name, _clean(version.strip()), None)
    if shutil.which("rpm"):
        owner = _run_ok(["rpm", "-qf", "--qf", "%{NAME} %{VERSION}-%{RELEASE}", path])
        parts = owner.split() if owner else []
        if len(parts) == 2 and _PKG_NAME_RE.fullmatch(parts[0]):
            return PackageInfo("rpm", parts[0], _clean(parts[1]), None)
    return None


def read_package_changelog(pkg: PackageInfo, doc_root: str = "/usr/share/doc") -> Optional[str]:
    """The package's changelog text, or None if nothing is readable. An empty
    changelog is None too: it proves nothing about the CVEs (the sh probe
    says NOCHANGELOG for it). `doc_root` is injectable for tests."""
    if pkg.manager == "rpm":
        text = _run_ok(["rpm", "-q", "--changelog", pkg.name])
        return text if text and text.strip() else None
    # php8.2-cli ships no changelog of its own; php8.2-common carries it.
    names = [pkg.name]
    common = re.sub(r"-[a-z]+$", "-common", pkg.name)
    if common not in names:
        names.append(common)
    for name in names:
        try:
            with gzip.open(os.path.join(doc_root, name, "changelog.Debian.gz"), "rt",
                           encoding="utf-8", errors="replace") as fh:
                text = fh.read()
            return text if text.strip() else None
        except (OSError, EOFError, zlib.error):
            continue
    return None


def _package_matches(ins: PhpInstall) -> bool:
    """True when the package's upstream version (no epoch, no release) is the
    version PHP itself reports. A source build or a COPY --from binary over a
    packaged path runs other code than the package's changelog describes."""
    upstream = parse_version(ins.package.version.split(":", 1)[-1].rsplit("-", 1)[0])
    return upstream is not None and upstream == ins.verdict.version


def apply_backport(ins: PhpInstall) -> None:
    """Upgrade an affected verdict to patched_backport when the owning
    package is the running build and its changelog names every CVE in CVES."""
    pkg = ins.package
    if not (ins.verdict.affected and pkg and pkg.cves is not None
            and all(c in pkg.cves for c in CVES) and _package_matches(ins)):
        return
    old = ins.verdict
    ins.verdict = Verdict(
        old.version, STATUS_PATCHED_BACKPORT,
        f"PHP {old.version_str} with a distro backport: {pkg.manager} package "
        f"{_clean(pkg.name)} {_clean(pkg.version)} changelog names {', '.join(CVES)}.",
        fixed_version=old.fixed_version)


def backport_notes(ins: PhpInstall) -> list[str]:
    """Why an affected install with a known package was not treated as patched."""
    pkg = ins.package
    if not pkg or not ins.verdict.affected:
        return []
    who = f"package {_clean(pkg.name)} {_clean(pkg.version)}"
    if not _package_matches(ins):
        return [f"{who} does not match running PHP {ins.verdict.version_str}; "
                f"not treated as patched"]
    if pkg.cves is None:
        return [f"{who}: changelog not available, cannot confirm a distro backport; "
                f"check your vendor advisory"]
    found = ", ".join(pkg.cves) or "neither CVE"
    missing = ", ".join(c for c in CVES if c not in pkg.cves)
    if not missing:
        return []  # apply_backport upgrades this install; nothing to explain
    return [f"{who}: changelog names {found}, missing {missing}; not treated as patched"]


PHP_CANDIDATES = ("php", "php-fpm", "php8.5", "php8.4", "php8.3", "php8.2",
                  "php8.1", "php8.0", "php7.4")


def find_php_binaries(explicit: Optional[str] = None) -> list[str]:
    if explicit:
        return [explicit]
    found: list[str] = []
    for name in PHP_CANDIDATES:
        path = shutil.which(name)
        if path and path not in found:
            found.append(path)
    return found


# php.ini settings worth surfacing. They only reduce exposure while PHP is
# unpatched; none of them is a fix (see posture_notes).
POSTURE_KEYS = (
    "session.upload_progress.enabled",
    "session.upload_progress.cleanup",
    "session.serialize_handler",
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
    install.package = package_for_binary(binary)
    if install.package:
        text = read_package_changelog(install.package)
        install.package.cves = changelog_cves(text) if text is not None else None
        apply_backport(install)
    # `php-fpm -i` reports the FPM SAPI's ini, which can differ from the CLI's.
    if os.path.basename(binary).startswith("php"):
        install.config = read_ini_posture(binary)
        install.upload_progress_enabled = _ini_bool(
            install.config.get("session.upload_progress.enabled"))
    return install


# --- restart awareness -------------------------------------------------------
#
# Upgrading the package fixes the file on disk, but a running php-fpm/Apache
# worker keeps executing the code it already mapped until it is restarted. When
# the package manager replaces a file it unlinks the old one, so a still-running
# process shows the old path as "(deleted)" in /proc/<pid>/exe or /proc/<pid>/maps.

@dataclass
class StaleProcess:
    name: str
    pids: list
    reason: str


def _read_text(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _stale_reason(base: str, check_exe: bool) -> Optional[str]:
    """Why the process at /proc/<pid> still runs replaced PHP code, or None.
    Raises PermissionError when /proc/<pid>/exe or maps is not readable."""
    if check_exe:
        try:
            target = os.readlink(os.path.join(base, "exe"))
        except PermissionError:
            raise
        except OSError:
            target = ""  # e.g. a zombie has no exe link; maps may still tell
        if target.endswith(" (deleted)"):
            return f"binary replaced on disk ({target[:-len(' (deleted)')]})"
    for line in _read_text(os.path.join(base, "maps")).splitlines():
        if not line.endswith(" (deleted)"):
            continue
        parts = line.split(None, 5)
        if len(parts) < 6:
            continue
        name = os.path.basename(parts[5][:-len(" (deleted)")])
        if name.startswith(("php", "libphp")):
            return f"library replaced on disk ({name})"
    return None


def find_stale_php_processes(proc_root: str = "/proc") -> tuple:
    """Find php-fpm/php-cgi (and mod_php Apache) processes still running PHP
    code that has been replaced on disk. Returns (list[StaleProcess], note).
    Linux only; `proc_root` is injectable for tests."""
    if not os.path.isdir(proc_root):
        return [], "restart check needs Linux /proc, which is not available here"
    groups: dict = {}
    denied = 0
    for entry in os.listdir(proc_root):
        if not entry.isdigit():
            continue
        base = os.path.join(proc_root, entry)
        try:
            comm = _read_text(os.path.join(base, "comm")).strip()
        except OSError:
            continue  # exited while we were walking /proc
        is_php = comm.startswith("php")
        if not (is_php or comm in ("apache2", "httpd")):
            continue
        try:
            reason = _stale_reason(base, check_exe=is_php)
        except PermissionError:
            denied += 1
            continue
        except OSError:
            continue
        if reason:
            groups.setdefault((comm, reason), []).append(int(entry))
    stale = [StaleProcess(name, sorted(pids), reason)
             for (name, reason), pids in sorted(groups.items())]
    note = None
    if denied:
        note = (f"{denied} PHP/web process(es) could not be inspected "
                f"(permission denied) — run as root to see all workers")
    return stale, note


def print_stale(stale: list, use_color: bool, indent: str = "  ") -> None:
    for sp in stale:
        pids = ", ".join(map(str, sp.pids[:8])) + (", ..." if len(sp.pids) > 8 else "")
        print(indent + _c("RESTART NEEDED", "red", use_color) +
              f"  {sp.name} (pid {pids}): {sp.reason}")
    if stale:
        print(indent + "  An upgrade is not active until the process restarts. Restart "
                       "php-fpm / apache2 / your PHP service, then re-check.")


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


def session_handler_notes(ins: PhpInstall) -> list[str]:
    """CVE-2026-115560 posture. Unlike posture_notes this applies to patched
    installs too: the 2026-10-21 releases do not fix it. It never changes the
    exit code, because a config note cannot show the app-side `ini_set()` that
    the issue also needs (that is what `scan-code` looks for)."""
    cfg = ins.config
    if not cfg or ins.upload_progress_enabled is not True:
        return []
    handler = cfg.get("session.serialize_handler", "").strip().lower()
    lead = (f"{CVE_SESSION} (disclosed {DISCLOSED_SESSION}, no fixed release yet; "
            "not fixed by the 2026-10-21 updates): "
            "session.upload_progress.enabled is On")
    if handler in ("php_binary", "php_serialize"):
        lead += f" and session.serialize_handler={handler}"
    notes = [lead + ". Exploitable only if application code also switches the "
             "handler to 'php' with ini_set() before session_start(): "
             "run `php2shell-check scan-code /var/www` to look for that."]
    notes.append("PHP's interim advice: session.upload_progress.enabled=0 in "
                 "php.ini / the FPM pool (not ini_set or .user.ini), then restart workers.")
    return notes


def print_human(installs: list[PhpInstall], use_color: bool,
                stale: Optional[list] = None, stale_note: Optional[str] = None) -> None:
    """`stale`/`stale_note` are the local restart-check results; remote hosts
    carry theirs on each PhpInstall."""
    stale = stale or []
    print(_c("PHP2Shell check", "bold", use_color) +
          f"  ({', '.join(CVES)}, disclosed {DISCLOSED})")
    print()
    if not installs:
        print(_c("No PHP binary found on PATH.", "yellow", use_color))
        print("Pass --php-binary /path/to/php, or --version X.Y.Z to check a version string.")
        print()
    for ins in installs:
        v = ins.verdict
        if v.status == STATUS_PATCHED:
            tag = _c("OK — patched", "green", use_color)
        elif v.status == STATUS_PATCHED_BACKPORT:
            tag = _c("OK, patched (distro backport)", "green", use_color)
        elif v.affected:
            tag = _c("AFFECTED", "red", use_color)
        else:
            tag = _c("UNKNOWN", "yellow", use_color)
        print(f"  {ins.binary}")
        if ins.raw_version:
            print(f"    {ins.raw_version}")
        print(f"    {tag}: {v.detail}")
        for note in backport_notes(ins):
            print(f"    note: {note}")
        for note in posture_notes(ins):
            print(f"    note: {note}")
        for note in session_handler_notes(ins):
            print(f"    note: {note}")
        print_stale(ins.stale, use_color, indent="    ")
        print()

    if stale:
        print(_c("Running processes", "bold", use_color))
        print_stale(stale, use_color)
        print()
    if stale_note:
        print(f"  note: {stale_note}")
        print()

    if any(i.verdict.affected for i in installs):
        print(_c("Action required.", "red", use_color) +
              " Run `php2shell-check harden` for the exact upgrade steps.")
    elif stale or any(i.stale for i in installs):
        print(_c("Restart required.", "red", use_color) +
              " Processes are still running PHP code that was replaced on disk.")


# --- harden / preventer ------------------------------------------------------

PARTIAL_WORKAROUND_INI = (
    "; php2shell-check: PARTIAL mitigation for {cves}.\n"
    "; This blocks the confirmed session.upload_progress exploit path only.\n"
    "; It is NOT a full fix — you MUST still update PHP to a patched release.\n"
    "; It is also PHP's interim advice for {session_cve}, which the October 21\n"
    "; updates do not fix.\n"
    "session.upload_progress.enabled = Off\n"
).format(cves=", ".join(CVES), session_cve=CVE_SESSION)


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


# --- scan-code (CVE-2026-115560) ----------------------------------------------
#
# The session-handler issue needs application code that switches
# session.serialize_handler to `php` at runtime with ini_set(). Nothing else on
# the box can tell you that, so this greps PHP sources and config files for it.
# Read-only, local, stdlib: it opens files and never runs or fetches anything.
# It finds the code-side precondition only; whether the issue is reachable also
# depends on session.upload_progress.enabled (see `check`).

CODE_SUFFIXES = (".php", ".phtml", ".inc", ".php3", ".php4", ".php5", ".php7",
                 ".phps", ".ini", ".conf")
CODE_NAMES = (".htaccess", ".user.ini")
CODE_MAX_BYTES = 5_000_000

_INI_SET_RE = re.compile(
    r"""ini_set\s*\(\s*(['"])session\.serialize_handler\1\s*,\s*(?P<value>[^)]*)\)""",
    re.IGNORECASE)
_CONFIG_HANDLER_RE = re.compile(
    r"""(?:^|[\s;])(?:php_(?:admin_)?value\s+)?session\.serialize_handler\s*[= ]\s*
        ["']?(?P<value>php_binary|php_serialize)\b""",
    re.IGNORECASE | re.VERBOSE)


@dataclass
class CodeFinding:
    file: str
    line_no: int
    kind: str
    severity: str
    excerpt: str


CODE_KINDS = {
    "ini_set_php": ("high",
                    "ini_set() switches session.serialize_handler to 'php' - the "
                    "code half of the CVE-2026-115560 precondition"),
    "ini_set_other": ("medium",
                      "ini_set() changes session.serialize_handler to a value this "
                      "scan cannot read statically - review it"),
    "config_nondefault": ("low",
                          "session.serialize_handler is set to php_binary/php_serialize "
                          "here - the config half of the precondition, harmless alone"),
}


def classify_code_line(line: str) -> Optional[str]:
    m = _INI_SET_RE.search(line)
    if m:
        value = m.group("value").strip().strip("'\"").strip().lower()
        return "ini_set_php" if value == "php" else "ini_set_other"
    if _CONFIG_HANDLER_RE.search(line):
        return "config_nondefault"
    return None


def iter_code_files(paths: list) -> tuple:
    """Yield-free walk: returns (files, errors). Symlinks are not followed."""
    files: list = []
    errors: list = []
    for root in paths:
        if os.path.islink(root) or not os.path.exists(root):
            errors.append(f"{root}: not found or a symlink")
            continue
        if os.path.isfile(root):
            files.append(root)
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = [d for d in dirnames if d != ".git"]
            for name in filenames:
                full = os.path.join(dirpath, name)
                if os.path.islink(full):
                    continue
                if name.lower().endswith(CODE_SUFFIXES) or name.lower() in CODE_NAMES:
                    files.append(full)
    return files, errors


def scan_code_file(path: str) -> list:
    try:
        if os.path.getsize(path) > CODE_MAX_BYTES:
            return []
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return []
    out = []
    for n, line in enumerate(lines, 1):
        kind = classify_code_line(line)
        if kind:
            out.append(CodeFinding(path, n, kind, CODE_KINDS[kind][0],
                                   _clean(line.strip()[:300])))
    return out


def cmd_scan_code(args: argparse.Namespace) -> int:
    if not args.paths:
        print("Usage: php2shell-check scan-code PATH [PATH ...] [--json]",
              file=sys.stderr)
        return 2
    files, errors = iter_code_files(args.paths)
    findings: list = []
    for f in files:
        findings.extend(scan_code_file(f))
    for err in errors:
        print(f"warning: {err}", file=sys.stderr)
    if errors and not files:
        return 2

    if args.json:
        print(json.dumps({
            "cve": CVE_SESSION,
            "files_scanned": len(files),
            "findings": [asdict(f) for f in findings],
        }, indent=2))
    else:
        print(f"Session-handler code scan  ({CVE_SESSION}, disclosed {DISCLOSED_SESSION})\n")
        print(f"  scanned {len(files)} file(s)\n")
        order = {"high": 0, "medium": 1, "low": 2}
        for f in sorted(findings, key=lambda x: order.get(x.severity, 9)):
            print(f"  [{f.severity.upper()}] {f.kind}  {f.file}:{f.line_no}")
            print(f"      {f.excerpt}")
            print(f"      {CODE_KINDS[f.kind][1]}")
        if not findings:
            print("  No runtime serialize_handler switch found.")
        print("\n  This only finds the application-code precondition. The issue is "
              "reachable only while")
        print("  session.upload_progress.enabled is On, and PHP has not released a fix "
              "yet; its interim")
        print("  advice is session.upload_progress.enabled=0 in php.ini / the FPM pool, "
              "then restart workers.")
    return exit_code_for([f.severity for f in findings], args.fail_on,
                         1 if any(f.severity in ("high", "medium") for f in findings) else 0)


# --- SARIF output ------------------------------------------------------------
# SARIF lets CI upload results to GitHub code scanning (Security tab).

REPO_URL = "https://github.com/SirjanSingh/php2shell-check"
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


def check_to_sarif(installs: list, stale: Optional[list] = None) -> dict:
    rule = {
        "id": "php2shell-affected",
        "name": "PHP2ShellAffectedVersion",
        "shortDescription": {
            "text": f"PHP version affected by PHP2Shell ({', '.join(CVES)})"},
        "helpUri": REPO_URL,
    }
    restart_rule = {
        "id": "php2shell-restart-pending",
        "name": "PHP2ShellRestartPending",
        "shortDescription": {
            "text": "PHP process still running code that was replaced on disk"},
        "helpUri": REPO_URL,
    }
    results = [{
        "ruleId": "php2shell-affected",
        "level": "error",
        "message": {"text": ins.verdict.detail},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": ins.binary}}}],
    } for ins in installs if ins.verdict.affected]
    pending = [(ins.binary, sp) for ins in installs for sp in ins.stale]
    pending += [("(local processes)", sp) for sp in (stale or [])]
    results.extend({
        "ruleId": "php2shell-restart-pending",
        "level": "error",
        "message": {"text": f"{sp.name} (pid {', '.join(map(str, sp.pids))}): {sp.reason}"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": where}}}],
    } for where, sp in pending)
    return _sarif_doc([rule, restart_rule], results)


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


# --- rules: ready-to-paste mitigations ---------------------------------------
#
# `rules` turns the indicators scan-logs already uses into WAF/IDS/SIEM rules.
# LINE_INDICATORS stays the source of truth for ids, severity, description and
# source; _RULE_SPECS only adds the per-format expression for each one (a Python
# regex can't be translated mechanically). A test fails if an indicator has no
# spec, so the two cannot drift apart.

RULE_REFERENCES = [
    ("Splunk Research", "https://research.splunk.com/web/47b3ff26-c4cc-4413-9bf3-f44dbac36785/"),
    ("Zafran", "https://www.zafran.io/resources/php2shell-everything-you-need-to-know-about-the-two-critical-php-vulnerabilities"),
    ("Abstract Security", "https://www.abstract.security/blog/php2shell-critical-php-rce-vulnerabilities-cve-2026-109618-and-cve-2026-109619"),
    ("ikow/php2shell-poc detection rules", "https://github.com/ikow/php2shell-poc/tree/main/detection"),
    ("Elastic Security Labs", "https://www.elastic.co/security-labs/threat-command/php2shell-php-rce-detection"),
]

# modsec: (variable, regex[, (chained variable, chained regex)]).
# suricata: sticky-buffer fragment. sigma: keyword groups, ANDed; each group's
# items are ORed ('*' is Sigma's wildcard). block: safe to deny/drop with --block.
_RULE_SPECS = {
    "upload_progress_field": {
        "title": "PHP_SESSION_UPLOAD_PROGRESS field in request body",
        "modsec": ("ARGS_NAMES", r"(?i)PHP_SESSION_UPLOAD_PROGRESS", None),
        "suricata": r'http.request_body; content:"PHP_SESSION_UPLOAD_PROGRESS"; nocase;',
        "sigma": [["PHP_SESSION_UPLOAD_PROGRESS"]],
        "block": True,
    },
    "php_tag_in_upload": {
        "title": "PHP open tag in upload filename",
        "modsec": ("FILES", r"(?i)<\?(?:php|=)", None),
        "suricata": r'http.request_body; content:"filename="; nocase; '
                    r'pcre:"/filename=\x22[^\x22]*<\?(?:php|=)/i";',
        "sigma": [['filename="*<?php*', 'filename="*<?=*']],
        "block": True,
    },
    # Scoped to requests that also carry the upload-progress field: a bare
    # serialized-object marker is far too common in legitimate bodies to match alone.
    "serialized_in_upload": {
        "title": "Serialized PHP data alongside the upload-progress field",
        "modsec": ("ARGS_NAMES", r"(?i)PHP_SESSION_UPLOAD_PROGRESS",
                   ("ARGS", r"(?:O:\d+:\x22|a:\d+:\{)")),
        "suricata": r'http.request_body; content:"PHP_SESSION_UPLOAD_PROGRESS"; nocase; '
                    r'pcre:"/(?:O:\d+:\x22|a:\d+:\{)/";',
        "sigma": [["PHP_SESSION_UPLOAD_PROGRESS"], ['O:*:"*', 'a:*:{*']],
        "block": False,
    },
    "php_fatal_unknown_line0": {
        "title": "PHP fatal error on Unknown line 0",
        "sigma": [["Unknown on line 0"]],
    },
    "apache_child_exit": {
        "title": "Apache child process exit AH00052",
        "sigma": [["AH00052"]],
    },
}

MODSEC_ID_BASE = 99100      # ModSecurity reserves ids 1-99999 for local rules
SURICATA_SID_BASE = 1000100  # conventional local sid range
BURST_COUNT, BURST_SECONDS = 3, 120
RULE_FILENAMES = {
    "modsecurity": "php2shell-modsecurity.conf",
    "sigma": "php2shell-sigma.yml",
    "suricata": "php2shell-suricata.rules",
}


def _rule_header(extra: list, prefix: str = "# ") -> str:
    lines = [
        f"php2shell-check {__version__} - rules for {', '.join(CVES)}",
        "",
        "These detect exploitation ATTEMPTS. They are not a fix: update PHP to",
        "8.5.12 / 8.4.27 / 8.3.36 / 8.2.35. Test in detect-only mode first.",
        "",
        "Body-inspection limit: WAFs and IDS typically inspect only a prefix of a",
        "request body (many stop at 64 KB, per the ikow/php2shell-poc detection",
        "README), and an attacker can pad past it. A rule that stays quiet is NOT an",
        "all-clear: raise your body-inspection limit and/or reject oversized bodies.",
        "",
        "Field name: the rules assume the default session.upload_progress.name,",
        "PHP_SESSION_UPLOAD_PROGRESS. If you changed that ini setting, change the rules.",
        "",
        "Generated from the same indicators as `php2shell-check scan-logs`. The",
        "syntax is not validated against a live engine by this tool: load the rules",
        "on a test instance and check they parse before deploying.",
    ]
    lines += [""] + extra if extra else []
    lines += ["", "Sources:"] + [f"  {name}: {url}" for name, url in RULE_REFERENCES]
    return "\n".join(prefix + line if line else prefix.rstrip() for line in lines) + "\n"


def _specs_for(fmt: str) -> list:
    return [(ind, _RULE_SPECS[ind.id]) for ind in LINE_INDICATORS
            if fmt in _RULE_SPECS.get(ind.id, {})]


def render_modsecurity(block: bool = False, id_base: int = MODSEC_ID_BASE) -> str:
    out = [_rule_header([
        "Needs SecRuleEngine On and SecRequestBodyAccess On. Multipart field names",
        "are read from ARGS_NAMES and upload filenames from FILES, both in phase 2.",
        "Detect-only (pass,log) unless generated with --block; only the specific,",
        "high-severity rules are ever switched to deny.",
    ])]
    for offset, (ind, spec) in enumerate(_specs_for("modsec")):
        var, rx, chain = spec["modsec"]
        denies = block and spec["block"] and ind.severity == "high"
        disp = "deny,status:403" if denies else "pass"
        tags = ",".join(f"tag:'{t}'" for t in ["php2shell", *CVES])
        actions = (f"id:{id_base + offset},phase:2,t:none,{disp},log,auditlog,"
                   f"severity:'CRITICAL',msg:'PHP2Shell: {spec['title']}',{tags}")
        if chain:
            out.append(f'SecRule {var} "@rx {rx}" \\\n    "{actions},chain"\n'
                       f'    SecRule {chain[0]} "@rx {chain[1]}" "t:none"\n')
        else:
            out.append(f'SecRule {var} "@rx {rx}" \\\n    "{actions}"\n')
    return "\n".join(out)


def render_suricata(block: bool = False, sid_base: int = SURICATA_SID_BASE) -> str:
    out = [_rule_header([
        "Needs the HTTP app-layer parser and TLS terminated or decrypted upstream.",
        "How much of a body is inspected is set by request-body-limit in the libhtp",
        "section of suricata.yaml. `drop` only acts when Suricata runs inline (IPS);",
        "otherwise it behaves like alert. Rules are `alert` unless generated with --block.",
    ])]
    refs = "reference:cve,2026-109618; reference:cve,2026-109619; "
    sid = sid_base
    for ind, spec in _specs_for("suricata"):
        action = "drop" if (block and spec["block"] and ind.severity == "high") else "alert"
        base = (f'{action} http any any -> any any (msg:"PHP2Shell: {spec["title"]}"; '
                f'flow:established,to_server; {spec["suricata"]} '
                f'classtype:attempted-admin; {refs}')
        out.append(f"{base}sid:{sid}; rev:1;)")
        sid += 1
        if ind.id == "upload_progress_field":
            out.append(
                f'alert http any any -> any any (msg:"PHP2Shell: repeated '
                f'upload-progress requests from one source"; flow:established,to_server; '
                f'{spec["suricata"]} detection_filter:track by_src, '
                f'count {BURST_COUNT}, seconds {BURST_SECONDS}; '
                f'classtype:attempted-admin; {refs}sid:{sid}; rev:1;)')
            sid += 1
    return "\n".join(out) + "\n"


def _yq(text: str) -> str:
    """Single-quoted YAML scalar."""
    return "'" + text.replace("'", "''") + "'"


def render_sigma() -> str:
    docs = []
    for ind in LINE_INDICATORS:
        spec = _RULE_SPECS.get(ind.id)
        if not spec or "sigma" not in spec:
            continue
        rid = uuid.uuid5(uuid.NAMESPACE_URL, f"{REPO_URL}/sigma/{ind.id}")
        lines = [
            f"title: {_yq('PHP2Shell - ' + spec['title'])}",
            f"id: {rid}",
            "status: experimental",
            f"description: {_yq(ind.description)}",
            "references:",
            *[f"  - {url}" for _, url in RULE_REFERENCES],
            "author: php2shell-check",
            f"date: {DISCLOSED}",
            "tags:",
            "  - attack.initial-access",
            "  - attack.t1190",
            *[f"  - cve.{c[4:].lower()}" for c in CVES],
            "logsource:",
            "  category: webserver  # map to the WAF / web / PHP error log in your pipeline",
            "detection:",
        ]
        names = []
        for n, group in enumerate(spec["sigma"], 1):
            name = f"kw{n}"
            names.append(name)
            lines.append(f"  {name}:")
            lines += [f"    - {_yq(item)}" for item in group]
        lines += [f"  condition: {' and '.join(names)}",
                  "falsepositives:",
                  f"  - {_yq('Legitimate use is rare; review context before acting.')}",
                  f"level: {ind.severity}"]
        docs.append("\n".join(lines) + "\n")
    return _rule_header([
        "One Sigma rule per YAML document. Field-less keyword searches are used",
        "because Sigma has no standard request-body field; convert with your backend.",
    ]) + "---\n" + "---\n".join(docs)


_RENDERERS = {"modsecurity": render_modsecurity, "sigma": render_sigma,
              "suricata": render_suricata}


def cmd_rules(args: argparse.Namespace) -> int:
    formats = list(_RENDERERS) if args.format == "all" else [args.format]
    rendered = {}
    for fmt in formats:
        if fmt == "modsecurity":
            rendered[fmt] = render_modsecurity(args.block, args.id_base)
        elif fmt == "suricata":
            rendered[fmt] = render_suricata(args.block, args.sid_base)
        else:
            rendered[fmt] = render_sigma()
    if args.output:
        try:
            os.makedirs(args.output, exist_ok=True)
            for fmt, text in rendered.items():
                path = os.path.join(args.output, RULE_FILENAMES[fmt])
                with open(path, "w", encoding="utf-8", newline="\n") as fh:
                    fh.write(text)
                print(f"Wrote {path}")
        except OSError as exc:
            print(f"Failed to write rules: {exc}", file=sys.stderr)
            return 2
        return 0
    for fmt, text in rendered.items():
        if len(rendered) > 1:
            print(f"# ===== {RULE_FILENAMES[fmt]} =====")
        print(text)
    return 0


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
    install: Optional[PhpInstall] = None  # set when an image or container was probed


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


# Images and containers get the same read-only probe as SSH hosts, piped to
# `sh -s` on stdin. Images run with `--network none` and no capabilities. One with no `sh`
# (distroless) falls back to `php -v`.
_IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@-]*$")
# Detail prefix of a probe that ran and found no PHP (as opposed to one that failed).
_NO_PHP = "no PHP found"


def _docker_probe(sh_cmd: list, php_cmd: list, label: str, timeout: int) -> list:
    """Run the probe through docker. Never raises: anything that stops the
    probe comes back as an UNKNOWN record carrying the reason."""
    def unknown(reason: str) -> list:
        return [PhpInstall(label, "", Verdict(None, STATUS_UNKNOWN, reason))]

    def run(cmd: list, **kw) -> tuple:
        try:
            return subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=timeout, **kw), None
        except subprocess.TimeoutExpired:
            return None, f"docker timed out after {timeout}s"
        except OSError as exc:
            return None, f"could not run docker: {exc}"

    if not shutil.which("docker"):
        return unknown("docker CLI not found on PATH")
    proc, err = run(sh_cmd, input=build_remote_probe())
    if err:
        return unknown(err)
    if proc.stdout.strip():
        return parse_remote_probe(label, proc.stdout)
    # Nothing printed: no `sh` in the image, or no PHP on its PATH.
    sh_rc = proc.returncode
    proc, err = run(php_cmd, stdin=subprocess.DEVNULL)
    if err:
        return unknown(err)
    out = _clean((proc.stdout or "").replace("\r", ""))
    ver = parse_version(out) if proc.returncode == 0 else None
    if ver is None:
        stderr = _clean(proc.stderr or "")
        lines = stderr.strip().splitlines()
        # 127 (or docker exec's 126 with "executable file not found"): `php` is
        # not there. Any other 126 means it is there but cannot be invoked.
        missing = sh_rc in (0, 126, 127) and (proc.returncode == 127
                                              or "executable file not found" in stderr)
        what = _NO_PHP if missing else "docker probe failed"
        return unknown(f"{what} (sh probe exit {sh_rc}, php -v exit "
                       f"{proc.returncode}): {lines[-1] if lines else 'no error output'}")
    first = out.strip().splitlines()[0]
    return [PhpInstall(f"{label}: php", first, assess(ver))]


def probe_image(image: str, timeout: int = 300) -> list:
    """Probe an image in a throwaway, network-less container. docker pulls
    the image first if it is not present locally."""
    label = f"image {_clean(image)}"
    if not _IMAGE_RE.match(image):
        return [PhpInstall(label, "", Verdict(
            None, STATUS_UNKNOWN, f"not a plain image reference: {_clean(image)!r}"))]
    hardening = ["--network", "none", "--cap-drop", "ALL",
                 "--security-opt", "no-new-privileges"]
    return _docker_probe(
        ["docker", "run", "--rm", "-i", *hardening, "--entrypoint", "sh", image, "-s"],
        ["docker", "run", "--rm", *hardening, "--entrypoint", "php", image, "-v"],
        label, timeout)


def probe_container(cid: str, name: str, timeout: int = 60) -> list:
    """Probe a running container with `docker exec`."""
    label = f"container {_clean(name)}"
    if not _IMAGE_RE.match(cid):
        return [PhpInstall(label, "", Verdict(
            None, STATUS_UNKNOWN, f"not a plain container id: {_clean(cid)!r}"))]
    return _docker_probe(["docker", "exec", "-i", cid, "sh", "-s"],
                         ["docker", "exec", cid, "php", "-v"], label, timeout)


def scan_running_containers() -> tuple:
    if not shutil.which("docker"):
        return [], "docker CLI not found on PATH"
    out = _run_ok(["docker", "ps", "--format", "{{.ID}}\t{{.Names}}\t{{.Image}}"])
    if out is None:
        return [], "could not run `docker ps` (is the daemon running / permitted?)"
    hits = []
    for line in _clean(out.replace("\r", "")).splitlines():
        parts = line.split("\t")
        if len(parts) != 3 or not parts[0]:
            continue
        cid, name, image = parts
        label = f"container {name}"
        for ins in probe_container(cid, name):
            # A container with no PHP binary (a database, a proxy) is not a finding;
            # a probe that failed (timeout, exec refused) is, as UNKNOWN.
            if (ins.binary == label and not ins.stale
                    and ins.verdict.detail.startswith(_NO_PHP)):
                continue
            hits.append(DockerHit(f"{label} ({image})", 0, image, ins.verdict, install=ins))
    return hits, None


def cmd_scan_docker(args: argparse.Namespace) -> int:
    paths = args.paths or [p for p in DEFAULT_DOCKER_FILES if os.path.exists(p)]
    hits = scan_docker_files(paths)
    image_hits = [DockerHit(f"image {_clean(image)}", 0, _clean(image), ins.verdict, install=ins)
                  for image in (args.image or []) for ins in probe_image(image)]
    hits.extend(image_hits)
    note = None
    if args.running:
        running, note = scan_running_containers()
        hits.extend(running)

    def stale(h: DockerHit) -> bool:
        return bool(h.install and h.install.stale)

    report_err = write_reports(args, "PHP2Shell Docker scan", rows_from_hits(hits))
    if report_err:
        print(report_err, file=sys.stderr)

    affected = [h for h in hits if h.verdict.affected or stale(h)]
    unknown = [h for h in hits if h.verdict.status == STATUS_UNKNOWN]

    if args.json:
        rows = []
        for h in hits:
            row = {"source": h.source, "line": h.line_no, "image": h.image_tag,
                   "binary": h.install.binary if h.install else None,
                   "version": h.verdict.version_str, "status": h.verdict.status,
                   "affected": h.verdict.affected, "detail": h.verdict.detail}
            if h.install:
                row.update({
                    "config": h.install.config,
                    "package": asdict(h.install.package) if h.install.package else None,
                    "stale_processes": [asdict(s) for s in h.install.stale],
                    "backport_notes": backport_notes(h.install),
                })
            rows.append(row)
        print(json.dumps({"cves": CVES, "note": note, "hits": rows}, indent=2))
    else:
        print(f"PHP2Shell Docker scan  ({', '.join(CVES)})\n")
        if note:
            print(f"  note: {note}\n")
        if not hits:
            print("  No PHP images found. Pass Dockerfile/compose paths, --image, or --running.")
            return 2 if report_err else 0
        for h in hits:
            tag = ("AFFECTED" if h.verdict.affected else
                   "OK" if h.verdict.status == STATUS_PATCHED else
                   "OK (distro backport)" if h.verdict.status == STATUS_PATCHED_BACKPORT else
                   "UNKNOWN")
            loc = h.source + (f":{h.line_no}" if h.line_no else "")
            print(f"  [{tag}] {h.image_tag}  {loc}")
            if h.install and h.install.raw_version:
                print(f"      {h.install.binary}: {h.install.raw_version}")
            print(f"      {h.verdict.detail}")
            if h.install:
                for n in backport_notes(h.install):
                    print(f"      note: {n}")
                print_stale(h.install.stale, use_color=False, indent="      ")
        if any(h.install is None for h in unknown):
            print("\n  UNKNOWN = a branch tag with no patch number (e.g. php:8.3). "
                  "Pin a full patched tag such as php:8.3.36.")
    if affected:
        default = 1
    elif image_hits and all(h.verdict.status == STATUS_UNKNOWN for h in image_hits):
        default = 2
    else:
        default = 0
    sevs = ["high" if h.verdict.affected or stale(h) else "medium"
            for h in hits if h.verdict.affected or stale(h) or h.verdict.status == STATUS_UNKNOWN]
    return 2 if report_err else exit_code_for(sevs, args.fail_on, default)


# --- SSH fleet mode ----------------------------------------------------------
#
# For hosts YOU administer and hold keys for. The same fixed, read-only probe is
# piped to `ssh HOST sh -s` on stdin (so nothing needs quoting for the remote
# shell, and the host string never reaches a local shell). It runs `php -v`,
# reads a few ini values and looks for processes on replaced code; it writes
# nothing, opens no ports and sends no exploit traffic.

_REMOTE_PROBE_TEMPLATE = r"""PROC=@PROC@
# One "CVE <id>" line per ID in changelog text $1. An ID needs a non-digit
# after it (CVE-2026-1096185 is not ours). Empty text, or a grep with no -o,
# is NOCHANGELOG rather than "names neither".
cve_lines() {
  [ -n "$1" ] || { echo NOCHANGELOG; return; }
  m=$(printf '%s\n' "$1" | grep -oE '(@CVE_RE@)([^0-9]|$)' 2>/dev/null)
  [ $? -le 1 ] || { echo NOCHANGELOG; return; }
  [ -z "$m" ] || printf '%s\n' "$m" | grep -oE 'CVE-[0-9]+-[0-9]+' | sort -u | sed 's/^/CVE /'
}
seen=" "
for name in @NAMES@; do
  p=$(command -v "$name" 2>/dev/null) || continue
  case "$seen" in *" $p "*) continue ;; esac
  seen="$seen$p "
  echo "BIN $p"
  "$p" -v 2>&1 | head -n 1 | sed 's/^/VER /'
  "$p" -i 2>/dev/null | grep -E '^(session\.upload_progress\.(enabled|cleanup)|session\.serialize_handler|post_max_size|memory_limit|fatal_error_backtraces) =>' | sed 's/^/INI /'
  real=$(readlink -f "$p" 2>/dev/null || echo "$p")
  if command -v dpkg >/dev/null 2>&1 && pkg=$(dpkg -S "$real" 2>/dev/null | head -n 1 | cut -d: -f1 | cut -d, -f1) && [ -n "$pkg" ]; then
    echo "PKG dpkg $pkg $(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null)"
    cl=""
    for d in "$pkg" "$(echo "$pkg" | sed 's/-[a-z]*$/-common/')"; do
      [ -r "@DOC@/$d/changelog.Debian.gz" ] && { cl="@DOC@/$d/changelog.Debian.gz"; break; }
    done
    txt=""
    [ -z "$cl" ] || txt=$(gzip -dc "$cl" 2>/dev/null)
    cve_lines "$txt"
  elif command -v rpm >/dev/null 2>&1 && pkg=$(rpm -qf --qf '%{NAME} %{VERSION}-%{RELEASE}' "$real" 2>/dev/null); then
    echo "PKG rpm $pkg"
    cve_lines "$(rpm -q --changelog "${pkg%% *}" 2>/dev/null)"
  fi
done
for d in "$PROC"/[0-9]*; do
  pid=${d##*/}
  comm=$(cat "$d/comm" 2>/dev/null) || continue
  case "$comm" in
    php*) check_exe=1 ;;
    apache2|httpd) check_exe=0 ;;
    *) continue ;;
  esac
  if [ "$check_exe" = 1 ]; then
    exe=$(readlink "$d/exe" 2>/dev/null)
    case "$exe" in
      *" (deleted)")
        echo "STALE $pid $comm binary replaced on disk ($(printf %s "$exe" | sed 's/ (deleted)$//'))"
        continue ;;
    esac
  fi
  lib=$(grep ' (deleted)$' "$d/maps" 2>/dev/null | sed 's/ (deleted)$//' | awk '{print $NF}' | sed 's|.*/||' | grep -E '^(php|libphp)' | head -n 1)
  if [ -n "$lib" ]; then echo "STALE $pid $comm library replaced on disk ($lib)"; fi
done
exit 0
"""


def build_remote_probe(proc_root: str = "/proc", doc_root: str = "/usr/share/doc") -> str:
    # Escape ERE metacharacters only: grep 3.8+ warns about a stray `\-`.
    cve_re = "|".join(re.sub(r"[.^$*+?()\[\]{}|\\]", r"\\\g<0>", c) for c in CVES)
    return (_REMOTE_PROBE_TEMPLATE.replace("@PROC@", proc_root)
            .replace("@NAMES@", " ".join(PHP_CANDIDATES))
            .replace("@DOC@", doc_root)
            .replace("@CVE_RE@", cve_re))


_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9@._:%-]*$")


def read_ssh_hosts(path: str) -> list:
    """Parse a hosts file: one `host` or `user@host` per line, `#` comments.
    Returns (line_no, entry, error) tuples; error is None for a usable entry.
    Anything that could be read as an ssh option (leading `-`) or contains
    whitespace is rejected rather than passed on."""
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError as exc:
        return [(0, path, f"cannot read hosts file: {exc}")]
    entries = []
    for n, raw in enumerate(lines, 1):
        entry = raw.split("#", 1)[0].strip()
        if not entry:
            continue
        if _HOST_RE.match(entry):
            entries.append((n, entry, None))
        else:
            entries.append((n, entry, "not a plain host or user@host entry"))
    return entries


_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def _clean(text: str) -> str:
    """Remote output is untrusted: drop control characters (e.g. ANSI escapes)
    before it is printed to the operator's terminal."""
    return _CONTROL_RE.sub("?", text)


def parse_remote_probe(host: str, text: str) -> list:
    """Turn the probe's `BIN`/`VER`/`INI`/`PKG`/`CVE`/`NOCHANGELOG`/`STALE`
    lines into PhpInstall records (one per binary). Restart findings belong to
    the host: they are attached to its first record, or to a placeholder when
    no PHP binary was found."""
    text = _clean(text.replace("\r", ""))
    installs: list = []
    stale_groups: dict = {}
    current = None
    ini_lines: list = []

    def close() -> None:
        if current is not None:
            current.config = parse_ini_posture("\n".join(ini_lines))
            current.upload_progress_enabled = _ini_bool(
                current.config.get("session.upload_progress.enabled"))
            apply_backport(current)

    for line in text.splitlines():
        tag, _, rest = line.partition(" ")
        if tag == "BIN":
            close()
            ini_lines = []
            current = PhpInstall(f"{host}: {rest}", "", assess(None))
            installs.append(current)
        elif tag == "VER" and current is not None:
            current.raw_version = rest.strip()
            current.verdict = assess(parse_version(rest))
        elif tag == "INI" and current is not None:
            ini_lines.append(rest)
        elif tag == "PKG" and current is not None:
            parts = rest.split()
            if (len(parts) == 3 and parts[0] in ("dpkg", "rpm")
                    and _PKG_NAME_RE.fullmatch(parts[1])):
                current.package = PackageInfo(parts[0], parts[1], _clean(parts[2]), [])
        elif tag == "CVE" and current is not None and current.package is not None:
            cve = rest.strip()
            cves = current.package.cves
            if cve in CVES and cves is not None and cve not in cves:
                current.package.cves = sorted(cves + [cve])
        elif tag == "NOCHANGELOG" and current is not None and current.package is not None:
            current.package.cves = None
        elif tag == "STALE":
            parts = rest.split(None, 2)
            if len(parts) == 3 and parts[0].isdigit():
                stale_groups.setdefault((parts[1], parts[2]), []).append(int(parts[0]))
    close()
    stale = [StaleProcess(name, sorted(pids), reason)
             for (name, reason), pids in sorted(stale_groups.items())]
    if not installs:
        installs.append(PhpInstall(
            host, "", Verdict(None, STATUS_UNKNOWN, "No PHP binary found on this host.")))
    installs[0].stale = stale
    return installs


def probe_host(host: str, timeout: int = 90) -> list:
    """Run the probe on one host over ssh. Never raises: a host that can't be
    reached comes back as an UNKNOWN record carrying the reason."""
    def unknown(reason: str) -> list:
        return [PhpInstall(host, "", Verdict(None, STATUS_UNKNOWN, reason))]

    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
           "--", host, "sh", "-s"]
    try:
        proc = subprocess.run(cmd, input=build_remote_probe(), capture_output=True,
                              text=True, timeout=timeout)
    except FileNotFoundError:
        return unknown("the `ssh` client was not found on PATH")
    except subprocess.TimeoutExpired:
        return unknown(f"ssh timed out after {timeout}s")
    except OSError as exc:
        return unknown(f"could not run ssh: {exc}")
    if proc.returncode != 0 and not proc.stdout.strip():
        err = (proc.stderr or "").strip().splitlines()
        return unknown(f"ssh failed (exit {proc.returncode}): "
                       f"{err[-1] if err else 'no error output'}")
    return parse_remote_probe(host, proc.stdout)


def scan_ssh_hosts(path: str, jobs: int = 8) -> list:
    from concurrent.futures import ThreadPoolExecutor
    entries = read_ssh_hosts(path)
    good = list(dict.fromkeys(e for _, e, err in entries if err is None))
    with ThreadPoolExecutor(max_workers=max(1, min(jobs, len(good) or 1))) as pool:
        probed = dict(zip(good, pool.map(probe_host, good)))
    installs: list = []
    emitted: set = set()
    for n, entry, err in entries:
        if err is not None:
            installs.append(PhpInstall(
                f"{path}:{n}", "", Verdict(None, STATUS_UNKNOWN, f"{err}: {entry!r}")))
        elif entry not in emitted:
            emitted.add(entry)
            installs.extend(probed[entry])
    return installs


# --- reports -----------------------------------------------------------------
#
# --markdown / --html write the same findings to a file as well as the normal
# output, so a CI job can attach them (Markdown renders in a GitHub job summary).

@dataclass
class ReportRow:
    target: str
    source: str  # "local" | "ssh" | "inventory" | "version" | "dockerfile" | "image" | "container"
    version: Optional[str]
    status: str
    detail: str
    notes: list = field(default_factory=list)


STATUS_RESTART = "restart_needed"
# Worst first; also the order of the report table.
_STATUS_ORDER = (STATUS_VULNERABLE, STATUS_VULNERABLE_EOL, STATUS_RESTART,
                 STATUS_UNKNOWN, STATUS_PATCHED_BACKPORT, STATUS_PATCHED)
_STATUS_LABEL = {
    STATUS_VULNERABLE: "vulnerable",
    STATUS_VULNERABLE_EOL: "vulnerable (EOL)",
    STATUS_RESTART: "restart needed",
    STATUS_UNKNOWN: "unknown",
    STATUS_PATCHED_BACKPORT: "patched (backport)",
    STATUS_PATCHED: "patched",
}
_STATUS_CLASS = {
    STATUS_VULNERABLE: "bad", STATUS_VULNERABLE_EOL: "bad",
    STATUS_RESTART: "warn", STATUS_UNKNOWN: "warn",
    STATUS_PATCHED_BACKPORT: "ok", STATUS_PATCHED: "ok",
}


def _stale_line(sp: StaleProcess) -> str:
    pids = ", ".join(map(str, sp.pids[:8])) + (", ..." if len(sp.pids) > 8 else "")
    return f"{sp.name} (pid {pids}): {sp.reason}"


def _install_notes(ins: PhpInstall) -> list:
    notes = backport_notes(ins) + posture_notes(ins) + session_handler_notes(ins)
    notes += [f"restart needed: {_stale_line(sp)}" for sp in ins.stale]
    return notes


def _row_status(verdict: Verdict, stale: list) -> str:
    # An affected build stays affected: the fix is the upgrade plus a restart.
    if stale and not verdict.affected:
        return STATUS_RESTART
    return verdict.status


def _row_detail(verdict: Verdict, stale: list) -> str:
    if stale and not verdict.affected:
        return ("Processes still run PHP code replaced on disk; restart them. "
                + verdict.detail)
    return verdict.detail


def rows_from_installs(installs: list, source: str, stale: Optional[list] = None) -> list:
    rows = [ReportRow(_clean(i.binary), source, i.verdict.version_str or _clean(i.raw_version) or None,
                      _row_status(i.verdict, i.stale), _clean(_row_detail(i.verdict, i.stale)),
                      [_clean(n) for n in _install_notes(i)])
            for i in installs]
    if stale:
        rows.append(ReportRow(
            "running PHP processes", "local", None, STATUS_RESTART,
            "Processes are still running PHP code that was replaced on disk. Restart "
            "php-fpm / apache2 / your PHP service, then re-check.",
            [_clean(_stale_line(sp)) for sp in stale]))
    return rows


def rows_from_hits(hits: list) -> list:
    rows = []
    for h in hits:
        ins = h.install
        if ins:
            tag = _clean(h.image_tag)
            target = _clean(ins.binary) + ("" if tag in ins.binary else f" ({tag})")
            source = "image" if h.source.startswith("image ") else "container"
            notes = _install_notes(ins)
            stale = ins.stale
        else:
            target = f"{_clean(h.source)}:{h.line_no} ({_clean(h.image_tag)})"
            source, notes, stale = "dockerfile", [], []
        rows.append(ReportRow(target, source, h.verdict.version_str,
                              _row_status(h.verdict, stale), _clean(_row_detail(h.verdict, stale)),
                              [_clean(n) for n in notes]))
    return rows


def _summary_counts(rows: list) -> list:
    def n(*statuses: str) -> int:
        return sum(r.status in statuses for r in rows)

    parts = [(n(STATUS_VULNERABLE, STATUS_VULNERABLE_EOL), "affected"),
             (n(STATUS_RESTART), "restart needed"),
             (n(STATUS_UNKNOWN), "unknown"),
             (n(STATUS_PATCHED, STATUS_PATCHED_BACKPORT), "patched")]
    return [f"{c} {word}" for c, word in parts if c]


def _sorted_rows(rows: list) -> list:
    rank = {s: i for i, s in enumerate(_STATUS_ORDER)}
    return sorted(rows, key=lambda r: rank.get(r.status, len(rank)))  # stable


def _md(text: str) -> str:
    """Make untrusted text safe inside a Markdown table cell or list item."""
    text = html.escape(_clean(str(text)).replace("—", "-"), quote=False)
    for ch in ("\\", "`", "|", "*", "_", "[", "]"):
        text = text.replace(ch, "\\" + ch)
    return " ".join(text.split())


def render_markdown(title: str, rows: list, generated_at: str) -> str:
    out = [f"## {_md(title)}", ""]
    out.append(" · ".join(_summary_counts(rows)) if rows else "No PHP installs found.")
    out += ["", f"Generated {_md(generated_at)}. Checked against {', '.join(CVES)}.", ""]
    rows = _sorted_rows(rows)
    if rows:
        out += ["| Status | Target | Version | Detail |", "| --- | --- | --- | --- |"]
        for r in rows:
            out.append(f"| {_STATUS_LABEL.get(r.status, _md(r.status))} | {_md(r.target)} "
                       f"| {_md(r.version or '')} | {_md(r.detail)} |")
        out.append("")
    for r in rows:
        if r.notes:
            plural = "s" if len(r.notes) != 1 else ""
            out += ["<details>",
                    f"<summary>{html.escape(_clean(r.target), quote=False)} "
                    f"({len(r.notes)} note{plural})</summary>", ""]
            out += [f"- {_md(n)}" for n in r.notes]
            out += ["", "</details>", ""]
    return "\n".join(out).rstrip("\n") + "\n"


_FAVICON = ("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E"
            "%3Cpath d='M16 2l11 4v9c0 7-4.6 12.5-11 15C9.6 27.5 5 22 5 15V6z' fill='%230f766e'/%3E"
            "%3Cpath d='M10.5 16l4 4 7-8' fill='none' stroke='%23ffffff' stroke-width='2.5' "
            "stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E")

_HTML_CSS = """
:root {
  --bg: #f6f7f9; --surface: #ffffff; --fg: #1b1f24; --muted: #5b6573; --border: #d6dbe1;
  --bad-bg: #fde4e1; --bad-fg: #9b1c12;
  --warn-bg: #fdf0c8; --warn-fg: #7a4b00;
  --ok-bg: #d9f2e1; --ok-fg: #14602c;
  color-scheme: light;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #14181d; --surface: #1c2229; --fg: #e6e9ed; --muted: #9aa5b2; --border: #323b46;
    --bad-bg: #4a1d19; --bad-fg: #ffb4ab;
    --warn-bg: #45350d; --warn-fg: #f5cf73;
    --ok-bg: #173a24; --ok-fg: #95dca9;
    color-scheme: dark;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--fg);
  font: 15px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; }
main { max-width: 72rem; margin: 0 auto; padding: 24px 16px 48px; }
h1 { font-size: 1.5rem; margin: 0 0 4px; }
.summary { font-size: 1.05rem; margin: 8px 0 4px; }
.meta { color: var(--muted); margin: 0 0 20px; font-size: 0.9rem; }
.scroll { overflow-x: auto; background: var(--surface); border: 1px solid var(--border);
  border-radius: 8px; }
table { border-collapse: collapse; width: 100%; min-width: 44rem; }
th, td { text-align: left; vertical-align: top; padding: 10px 12px;
  border-bottom: 1px solid var(--border); overflow-wrap: break-word; }
th { white-space: nowrap; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.04em; color: var(--muted); }
tr:last-child td { border-bottom: 0; }
.ver { white-space: nowrap; }
.pill { display: inline-block; padding: 2px 10px; border-radius: 999px; font-size: 0.8rem;
  font-weight: 600; white-space: nowrap; }
.bad { background: var(--bad-bg); color: var(--bad-fg); }
.warn { background: var(--warn-bg); color: var(--warn-fg); }
.ok { background: var(--ok-bg); color: var(--ok-fg); }
details { margin-top: 6px; color: var(--muted); }
summary { cursor: pointer; }
ul { margin: 6px 0 0; padding-left: 20px; }
code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.92em; }
"""


def render_html(title: str, rows: list, generated_at: str) -> str:
    def esc(value) -> str:
        return html.escape(_clean(str(value)).replace("—", "-"), quote=True)

    rows = _sorted_rows(rows)
    body = []
    if rows:
        body.append('<div class="scroll"><table>\n<thead><tr><th>Status</th><th>Target</th>'
                    '<th class="ver">Version</th><th>Detail</th></tr></thead>\n<tbody>')
        for r in rows:
            cls = _STATUS_CLASS.get(r.status, "warn")
            label = _STATUS_LABEL.get(r.status, r.status)
            notes = ""
            if r.notes:
                plural = "s" if len(r.notes) != 1 else ""
                notes = (f"<details><summary>{len(r.notes)} note{plural}</summary><ul>"
                         + "".join(f"<li>{esc(n)}</li>" for n in r.notes) + "</ul></details>")
            body.append(f'<tr><td><span class="pill {cls}">{esc(label)}</span></td>'
                        f"<td><code>{esc(r.target)}</code></td><td class='ver'>{esc(r.version or '')}</td>"
                        f"<td>{esc(r.detail)}{notes}</td></tr>")
        body.append("</tbody></table></div>")
    summary = " · ".join(_summary_counts(rows)) if rows else "No PHP installs found."
    return (
        '<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        '<title>PHP2Shell report</title>\n'
        f'<link rel="icon" href="{_FAVICON}">\n<style>{_HTML_CSS}</style>\n</head>\n<body>\n<main>\n'
        f'<h1>{esc(title)}</h1>\n<p class="summary">{esc(summary)}</p>\n'
        f'<p class="meta">Generated {esc(generated_at)}. Checked against {esc(", ".join(CVES))}.</p>\n'
        + "\n".join(body) + "\n</main>\n</body>\n</html>\n")


def write_reports(args: argparse.Namespace, title: str, rows: list) -> Optional[str]:
    """Write --markdown / --html if given. Returns an error message, or None."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for path, render in ((getattr(args, "markdown", None), render_markdown),
                         (getattr(args, "html", None), render_html)):
        if not path:
            continue
        try:
            with open(path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(render(title, rows, now))
        except OSError as exc:
            return f"could not write report {path}: {exc.strerror or exc}"
    return None


def add_report_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--markdown", metavar="FILE",
                        help="also write a Markdown report (renders in a GitHub job summary)")
    parser.add_argument("--html", metavar="FILE",
                        help="also write a self-contained HTML report")


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


def check_exit_code(installs: list, fail_on: Optional[str],
                    local_stale: bool = False) -> int:
    """`local_stale`: the local restart check found workers on replaced code."""
    if any(i.verdict.affected or i.stale for i in installs) or local_stale:
        default = 1
    elif not installs or all(i.verdict.status == STATUS_UNKNOWN for i in installs):
        default = 2
    else:
        default = 0
    if not installs and not local_stale and fail_on not in (None, "none"):
        return 2  # nothing was checked, so a threshold can't be evaluated
    sevs = [install_severity(i) for i in installs] + (["high"] if local_stale else [])
    return exit_code_for(sevs, fail_on, default)


def add_fail_on(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--fail-on", choices=FAIL_ON_CHOICES, metavar="LEVEL",
        help="exit 1 only for findings at or above LEVEL (high|medium|low), or "
             "'none' to always exit 0. Default: the command's usual exit codes")


# --- check command -----------------------------------------------------------

def cmd_check(args: argparse.Namespace) -> int:
    live = False
    source = "inventory"
    if getattr(args, "inventory", None):
        installs = read_inventory(args.inventory)
    elif getattr(args, "ssh_hosts", None):
        source = "ssh"
        installs = scan_ssh_hosts(args.ssh_hosts, args.ssh_jobs)
    elif args.version:
        source = "version"
        v = parse_version(args.version)
        verdict = assess(v)
        install = PhpInstall(binary=f"(version string: {args.version})",
                             raw_version=args.version, verdict=verdict)
        installs = [install]
    else:
        installs = [i for b in find_php_binaries(args.php_binary)
                    if (i := inspect_binary(b)) is not None]
        live = True
        source = "local"

    # Restart awareness only makes sense for the machine we are running on.
    stale: list = []
    stale_note: Optional[str] = None
    if live and not args.no_restart_check:
        stale, stale_note = find_stale_php_processes()

    if getattr(args, "sarif", False):
        print(json.dumps(check_to_sarif(installs, stale), indent=2))
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
                    "session_handler_notes": session_handler_notes(i),
                    "stale_processes": [asdict(s) for s in i.stale],
                    "detail": i.verdict.detail,
                    "package": asdict(i.package) if i.package else None,
                    "backport_notes": backport_notes(i),
                }
                for i in installs
            ],
            "stale_processes": [asdict(s) for s in stale],
            "restart_check_note": stale_note,
        }
        print(json.dumps(payload, indent=2))
    else:
        print_human(installs, use_color=sys.stdout.isatty() and not args.no_color,
                    stale=stale, stale_note=stale_note)

    code = check_exit_code(installs, args.fail_on, local_stale=bool(stale))
    err = write_reports(args, "PHP2Shell check", rows_from_installs(installs, source, stale))
    if err:
        print(err, file=sys.stderr)
        return 2
    return code


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
    c.add_argument("--ssh-hosts", metavar="FILE",
                   help="fleet check over ssh: a file of `host` / `user@host` lines. "
                        "Runs a fixed read-only probe on hosts you hold keys for "
                        "(key auth only; known_hosts is honoured)")
    c.add_argument("--ssh-jobs", type=int, default=8, metavar="N",
                   help="hosts to probe in parallel with --ssh-hosts (default 8)")
    c.add_argument("--json", action="store_true", help="machine-readable output")
    c.add_argument("--sarif", action="store_true",
                   help="SARIF output for GitHub code scanning")
    c.add_argument("--no-color", action="store_true", help="disable ANSI color")
    add_report_args(c)
    c.add_argument("--no-restart-check", action="store_true",
                   help="skip the check for running PHP processes that still "
                        "execute code replaced on disk (Linux /proc)")
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
    d.add_argument("--image", action="append", metavar="IMAGE",
                   help="probe an image in a throwaway container with no network "
                        "(docker pulls it if missing). Repeatable")
    d.add_argument("--running", action="store_true",
                   help="also probe running containers via `docker exec` (read-only)")
    d.add_argument("--json", action="store_true", help="machine-readable output")
    add_report_args(d)
    add_fail_on(d)
    d.set_defaults(func=cmd_scan_docker)

    k = sub.add_parser("scan-code",
                       help="look for runtime session.serialize_handler switches "
                            "(CVE-2026-115560)")
    k.add_argument("paths", nargs="*", help="directories or files to scan")
    k.add_argument("--json", action="store_true", help="machine-readable output")
    add_fail_on(k)
    k.set_defaults(func=cmd_scan_code)

    r = sub.add_parser("rules",
                       help="emit ready-to-paste ModSecurity / Sigma / Suricata rules")
    r.add_argument("--format", choices=("modsecurity", "sigma", "suricata", "all"),
                   default="all", help="rule format (default: all)")
    r.add_argument("--output", metavar="DIR",
                   help="write one file per format into DIR instead of printing")
    r.add_argument("--block", action="store_true",
                   help="ModSecurity deny / Suricata drop for the specific high-severity "
                        "rules instead of detect-only")
    r.add_argument("--id-base", type=int, default=MODSEC_ID_BASE,
                   help=f"first ModSecurity rule id (default {MODSEC_ID_BASE})")
    r.add_argument("--sid-base", type=int, default=SURICATA_SID_BASE,
                   help=f"first Suricata sid (default {SURICATA_SID_BASE})")
    r.set_defaults(func=cmd_rules)

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
