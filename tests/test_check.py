"""Tests for php2shell-check version/verdict logic. Run: python -m pytest, or
   python -m unittest discover tests."""

import contextlib
import gzip
import io
import json
import os
import re
import shutil
import subprocess
import sys
import unittest
import uuid
from unittest import mock

try:  # optional: validates the generated Sigma rules when available
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tempfile  # noqa: E402

from php2shell_check import (  # noqa: E402
    assess,
    assess_tag,
    parse_version,
    scan_file,
    scan_docker_files,
    scan_running_containers,
    probe_image,
    probe_container,
    read_inventory,
    check_to_sarif,
    scan_to_sarif,
    guess_log_type,
    parse_ini_posture,
    posture_notes,
    exit_code_for,
    check_exit_code,
    find_stale_php_processes,
    render_modsecurity,
    render_suricata,
    render_sigma,
    read_ssh_hosts,
    parse_remote_probe,
    probe_host,
    scan_ssh_hosts,
    build_remote_probe,
    session_handler_notes,
    changelog_cves,
    package_for_binary,
    read_package_changelog,
    apply_backport,
    backport_notes,
    inspect_binary,
    ReportRow,
    rows_from_installs,
    rows_from_hits,
    render_markdown,
    render_html,
    DockerHit,
    classify_code_line,
    scan_code_file,
    iter_code_files,
    main,
    CVES,
    LINE_INDICATORS,
    RULE_FILENAMES,
    _RULE_SPECS,
    PhpInstall,
    PackageInfo,
    StaleProcess,
    STATUS_PATCHED,
    STATUS_PATCHED_BACKPORT,
    STATUS_VULNERABLE,
    STATUS_VULNERABLE_EOL,
    STATUS_UNKNOWN,
)


def _scan(lines, forced_type=None, large_bytes=100_000, burst=3):
    with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as fh:
        fh.write("\n".join(lines) + "\n")
        path = fh.name
    try:
        return scan_file(path, forced_type, large_bytes, burst)
    finally:
        os.unlink(path)


class ParseVersionTests(unittest.TestCase):
    def test_plain(self):
        self.assertEqual(parse_version("8.3.2"), (8, 3, 2))

    def test_php_v_output(self):
        out = "PHP 8.4.26 (cli) (built: Oct  1 2026 10:00:00) (NTS)"
        self.assertEqual(parse_version(out), (8, 4, 26))

    def test_distro_suffix(self):
        self.assertEqual(parse_version("7.4.33-1+deb11u1"), (7, 4, 33))

    def test_none(self):
        self.assertIsNone(parse_version("no version here"))


class AssessTests(unittest.TestCase):
    def test_patched_at_fix(self):
        self.assertEqual(assess((8, 4, 27)).status, STATUS_PATCHED)

    def test_patched_above_fix(self):
        self.assertEqual(assess((8, 4, 30)).status, STATUS_PATCHED)

    def test_vulnerable_below_fix(self):
        v = assess((8, 4, 26))
        self.assertEqual(v.status, STATUS_VULNERABLE)
        self.assertEqual(v.fixed_version, "8.4.27")
        self.assertTrue(v.affected)

    def test_each_supported_branch_fix(self):
        for ver, fixed in [((8, 5, 12), True), ((8, 5, 11), False),
                           ((8, 3, 36), True), ((8, 3, 35), False),
                           ((8, 2, 35), True), ((8, 2, 34), False)]:
            with self.subTest(ver=ver):
                status = assess(ver).status
                self.assertEqual(status == STATUS_PATCHED, fixed)

    def test_eol_branch_affected(self):
        v = assess((8, 1, 20))
        self.assertEqual(v.status, STATUS_VULNERABLE_EOL)
        self.assertTrue(v.affected)

    def test_old_php7_affected(self):
        self.assertEqual(assess((7, 4, 33)).status, STATUS_VULNERABLE_EOL)

    def test_lower_bound_affected(self):
        self.assertTrue(assess((5, 4, 0)).affected)

    def test_future_branch_unknown(self):
        self.assertEqual(assess((8, 6, 0)).status, STATUS_UNKNOWN)

    def test_none_unknown(self):
        self.assertEqual(assess(None).status, STATUS_UNKNOWN)


class ScanLogsTests(unittest.TestCase):
    def test_upload_progress_field_flagged(self):
        findings, _ = _scan([
            'POST /upload body: PHP_SESSION_UPLOAD_PROGRESS=foo',
        ], forced_type="waf")
        ids = {f.indicator_id for f in findings}
        self.assertIn("upload_progress_field", ids)

    def test_php_tag_in_filename_flagged(self):
        findings, _ = _scan([
            'Content-Disposition: form-data; name="x"; filename="<?php system($_GET[0]);"',
        ], forced_type="waf")
        ids = {f.indicator_id for f in findings}
        self.assertIn("php_tag_in_upload", ids)

    def test_serialized_in_body_flagged(self):
        findings, _ = _scan([
            'body: PHP_SESSION_UPLOAD_PROGRESS=x&data=O:4:"Evil":0:{}',
        ], forced_type="waf")
        ids = {f.indicator_id for f in findings}
        self.assertIn("serialized_in_upload", ids)

    def test_error_log_unknown_line0(self):
        findings, _ = _scan([
            "[21-Oct-2026 10:00:00] PHP Fatal error:  Allowed memory ... Unknown on line 0",
        ], forced_type="error")
        ids = {f.indicator_id for f in findings}
        self.assertIn("php_fatal_unknown_line0", ids)

    def test_access_log_large_post_burst(self):
        line = ('203.0.113.9 - - [21/Oct/2026:10:00:00 +0000] '
                '"POST /up HTTP/1.1" 200 250000 "-" "curl"')
        findings, alerts = _scan([line] * 4, forced_type=None)
        self.assertTrue(any(a.ip == "203.0.113.9" for a in alerts))

    def test_small_posts_not_flagged(self):
        line = ('203.0.113.9 - - [21/Oct/2026:10:00:00 +0000] '
                '"POST /up HTTP/1.1" 200 120 "-" "curl"')
        _, alerts = _scan([line] * 10)
        self.assertEqual(alerts, [])

    def test_benign_access_line_clean(self):
        line = ('198.51.100.1 - - [21/Oct/2026:10:00:00 +0000] '
                '"GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla"')
        findings, alerts = _scan([line])
        self.assertEqual(findings, [])
        self.assertEqual(alerts, [])

    def test_guess_log_type(self):
        self.assertEqual(guess_log_type("x PHP_SESSION_UPLOAD_PROGRESS y"), "waf")
        self.assertEqual(guess_log_type("PHP Fatal ... Unknown on line 0"), "error")
        self.assertEqual(
            guess_log_type('1.2.3.4 - - [d] "GET / HTTP/1.1" 200 10'), "access")


class AssessTagTests(unittest.TestCase):
    def test_full_version_tag(self):
        self.assertEqual(assess_tag("8.3.10-fpm-alpine").status, STATUS_VULNERABLE)
        self.assertEqual(assess_tag("8.4.27-apache").status, STATUS_PATCHED)

    def test_eol_branch_tag_affected(self):
        self.assertEqual(assess_tag("8.1").status, STATUS_VULNERABLE_EOL)
        self.assertEqual(assess_tag("7.4-fpm").status, STATUS_VULNERABLE_EOL)

    def test_supported_branch_tag_unknown(self):
        self.assertEqual(assess_tag("8.4").status, STATUS_UNKNOWN)
        self.assertEqual(assess_tag("8.3-fpm").status, STATUS_UNKNOWN)

    def test_non_version_tag_unknown(self):
        self.assertEqual(assess_tag("latest").status, STATUS_UNKNOWN)
        self.assertEqual(assess_tag("fpm-alpine").status, STATUS_UNKNOWN)


class InventoryTests(unittest.TestCase):
    def test_parses_formats(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("web01 8.3.10\nweb02=8.4.27\n# a comment\n\ndb01: 7.4.33\n")
            path = fh.name
        try:
            installs = read_inventory(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(installs), 3)
        by_label = {i.binary: i.verdict for i in installs}
        self.assertTrue(by_label["web01"].affected)
        self.assertEqual(by_label["web02"].status, STATUS_PATCHED)
        self.assertEqual(by_label["db01"].status, STATUS_VULNERABLE_EOL)


class DockerFileTests(unittest.TestCase):
    def test_parses_dockerfile_and_compose(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as fh:
            fh.write("FROM php:8.3.10-fpm\nimage: php:8.4.27-apache\nimage: php:8.1\n")
            path = fh.name
        try:
            hits = scan_docker_files([path])
        finally:
            os.unlink(path)
        tags = [h.image_tag for h in hits]
        self.assertIn("php:8.3.10-fpm", tags)
        self.assertIn("php:8.4.27-apache", tags)
        statuses = {h.image_tag: h.verdict.status for h in hits}
        self.assertEqual(statuses["php:8.3.10-fpm"], STATUS_VULNERABLE)
        self.assertEqual(statuses["php:8.4.27-apache"], STATUS_PATCHED)
        self.assertEqual(statuses["php:8.1"], STATUS_VULNERABLE_EOL)


class SarifTests(unittest.TestCase):
    def test_check_sarif_shape(self):
        installs = [PhpInstall("web01", "8.3.10", assess((8, 3, 10)))]
        doc = check_to_sarif(installs)
        self.assertEqual(doc["version"], "2.1.0")
        self.assertEqual(len(doc["runs"][0]["results"]), 1)
        self.assertEqual(doc["runs"][0]["results"][0]["level"], "error")

    def test_check_sarif_skips_patched(self):
        installs = [PhpInstall("web02", "8.4.27", assess((8, 4, 27)))]
        self.assertEqual(len(check_to_sarif(installs)["runs"][0]["results"]), 0)

    def test_scan_sarif_shape(self):
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as fh:
            fh.write('body PHP_SESSION_UPLOAD_PROGRESS=x\n')
            path = fh.name
        try:
            findings, alerts = scan_file(path, "waf", 100_000, 3)
        finally:
            os.unlink(path)
        doc = scan_to_sarif(findings, alerts)
        self.assertEqual(doc["version"], "2.1.0")
        self.assertGreaterEqual(len(doc["runs"][0]["results"]), 1)


PHP_I_SAMPLE = """\
phpinfo()
memory_limit => 128M => 128M
post_max_size => 8M => 8M
session.upload_progress.cleanup => On => On
session.upload_progress.enabled => On => On
fatal_error_backtraces => On => On
"""


class PostureTests(unittest.TestCase):
    def test_parse_ini_posture(self):
        cfg = parse_ini_posture(PHP_I_SAMPLE)
        self.assertEqual(cfg["memory_limit"], "128M")
        self.assertEqual(cfg["post_max_size"], "8M")
        self.assertEqual(cfg["session.upload_progress.enabled"], "On")
        self.assertEqual(cfg["session.upload_progress.cleanup"], "On")

    def test_parse_uses_local_value_and_ignores_missing(self):
        cfg = parse_ini_posture("memory_limit => -1 => 128M\n")
        self.assertEqual(cfg, {"memory_limit": "-1"})

    def test_parse_empty(self):
        self.assertEqual(parse_ini_posture(""), {})

    def test_notes_only_for_affected(self):
        cfg = parse_ini_posture(PHP_I_SAMPLE)
        bad = PhpInstall("php", "8.5.1", assess((8, 5, 1)), True, cfg)
        good = PhpInstall("php", "8.5.12", assess((8, 5, 12)), True, cfg)
        text = " ".join(posture_notes(bad))
        self.assertIn("memory_limit=128M", text)
        self.assertIn("PARTIAL", text)
        self.assertIn("fatal_error_backtraces", text)  # 8.5 only
        self.assertEqual(posture_notes(good), [])

    def test_backtraces_note_is_8_5_only(self):
        cfg = parse_ini_posture(PHP_I_SAMPLE)
        ins = PhpInstall("php", "8.4.1", assess((8, 4, 1)), True, cfg)
        self.assertNotIn("fatal_error_backtraces", " ".join(posture_notes(ins)))


def _maps_line(path, deleted=True):
    return (f"7f0000000000-7f0000100000 r-xp 00000000 08:01 1234 {path}"
            + (" (deleted)" if deleted else ""))


class StaleProcessTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = self._tmp.name

    def add_proc(self, pid, comm, maps=(), exe=None):
        d = os.path.join(self.root, str(pid))
        os.makedirs(d)
        with open(os.path.join(d, "comm"), "w") as fh:
            fh.write(comm + "\n")
        with open(os.path.join(d, "maps"), "w") as fh:
            fh.write("\n".join(maps) + "\n")
        if exe is not None:
            os.symlink(exe, os.path.join(d, "exe"))

    def test_deleted_library_in_php_fpm(self):
        self.add_proc(10, "php-fpm8.4",
                      [_maps_line("/usr/lib/libphp8.4.so")])
        stale, note = find_stale_php_processes(self.root)
        self.assertIsNone(note)
        self.assertEqual(len(stale), 1)
        self.assertEqual(stale[0].name, "php-fpm8.4")
        self.assertEqual(stale[0].pids, [10])
        self.assertIn("libphp8.4.so", stale[0].reason)

    def test_deleted_binary_in_php_fpm(self):
        try:
            self.add_proc(11, "php-fpm8.4", exe="/usr/sbin/php-fpm8.4 (deleted)")
        except (OSError, NotImplementedError):
            self.skipTest("symlinks not available")
        stale, _ = find_stale_php_processes(self.root)
        self.assertEqual(len(stale), 1)
        self.assertIn("binary replaced", stale[0].reason)
        self.assertIn("/usr/sbin/php-fpm8.4", stale[0].reason)

    def test_workers_are_grouped(self):
        for pid in (21, 20, 22):
            self.add_proc(pid, "php-fpm8.4", [_maps_line("/usr/lib/libphp8.4.so")])
        stale, _ = find_stale_php_processes(self.root)
        self.assertEqual(len(stale), 1)
        self.assertEqual(stale[0].pids, [20, 21, 22])

    def test_mod_php_apache(self):
        self.add_proc(30, "apache2",
                      [_maps_line("/usr/lib/apache2/modules/libphp8.4.so")])
        stale, _ = find_stale_php_processes(self.root)
        self.assertEqual([s.name for s in stale], ["apache2"])

    def test_apache_without_php_is_ignored(self):
        self.add_proc(31, "apache2", [_maps_line("/usr/lib/libssl.so.3")])
        self.assertEqual(find_stale_php_processes(self.root)[0], [])

    def test_unrelated_deleted_library_is_ignored(self):
        self.add_proc(32, "php-fpm8.4", [_maps_line("/usr/lib/libssl.so.3")])
        self.assertEqual(find_stale_php_processes(self.root)[0], [])

    def test_current_php_is_clean(self):
        self.add_proc(33, "php-fpm8.4",
                      [_maps_line("/usr/lib/libphp8.4.so", deleted=False)])
        self.assertEqual(find_stale_php_processes(self.root)[0], [])

    def test_other_processes_and_non_pids_ignored(self):
        self.add_proc(40, "bash", [_maps_line("/usr/lib/libphp8.4.so")])
        os.makedirs(os.path.join(self.root, "self"))
        self.assertEqual(find_stale_php_processes(self.root)[0], [])

    def test_permission_denied_is_reported_not_fatal(self):
        self.add_proc(50, "php-fpm8.4", [_maps_line("/usr/lib/libphp8.4.so")])
        with mock.patch("php2shell_check._stale_reason", side_effect=PermissionError):
            stale, note = find_stale_php_processes(self.root)
        self.assertEqual(stale, [])
        self.assertIn("run as root", note)

    def test_no_proc_filesystem(self):
        stale, note = find_stale_php_processes(os.path.join(self.root, "missing"))
        self.assertEqual(stale, [])
        self.assertIn("/proc", note)

    def test_stale_fails_check_and_is_in_sarif(self):
        ok = PhpInstall("php", "8.4.27", assess((8, 4, 27)))
        sp = StaleProcess("php-fpm8.4", [1, 2], "library replaced on disk (libphp8.4.so)")
        self.assertEqual(check_exit_code([ok], None), 0)
        self.assertEqual(check_exit_code([ok], None, local_stale=True), 1)
        self.assertEqual(check_exit_code([], None, local_stale=True), 1)
        self.assertEqual(check_exit_code([ok], "none", local_stale=True), 0)
        results = check_to_sarif([ok], [sp])["runs"][0]["results"]
        self.assertEqual([r["ruleId"] for r in results], ["php2shell-restart-pending"])


class RulesTests(unittest.TestCase):
    def test_every_indicator_has_a_rule_spec(self):
        for ind in LINE_INDICATORS:
            with self.subTest(indicator=ind.id):
                spec = _RULE_SPECS.get(ind.id)
                self.assertIsNotNone(spec, "add a _RULE_SPECS entry for this indicator")
                self.assertTrue({"modsec", "suricata", "sigma"} & set(spec))

    def test_header_carries_the_caveats(self):
        for text in (render_modsecurity(), render_suricata(), render_sigma()):
            self.assertIn("CVE-2026-109618", text)
            self.assertIn("not a fix", text)
            self.assertIn("64 KB", text)
            self.assertIn("PHP_SESSION_UPLOAD_PROGRESS", text)
            self.assertIn("not validated against a live engine", text)

    def test_modsecurity_detect_only_by_default(self):
        text = render_modsecurity()
        self.assertNotIn("deny,status", text)
        ids = re.findall(r"id:(\d+),", text)
        self.assertEqual(ids, ["99100", "99101", "99102"])
        self.assertIn('SecRule ARGS_NAMES "@rx (?i)PHP_SESSION_UPLOAD_PROGRESS"', text)
        self.assertIn('SecRule FILES "@rx (?i)<\\?(?:php|=)"', text)

    def test_modsecurity_block_only_specific_rules(self):
        text = render_modsecurity(block=True, id_base=77000)
        rules = text.split("SecRule ")[1:]
        denying = [r for r in rules if "deny,status:403" in r]
        self.assertEqual(len(denying), 2)
        self.assertEqual(len(re.findall(r"id:77\d{3},", text)), 3)
        chained = [r for r in rules if r.startswith("ARGS_NAMES") and "chain" in r][0]
        self.assertNotIn("deny", chained)
        self.assertIn("SecRule ARGS", text.split("chain\"")[1])

    def test_suricata_rules_are_well_formed(self):
        for block in (False, True):
            lines = [ln for ln in render_suricata(block=block).splitlines()
                     if ln and not ln.startswith("#")]
            self.assertEqual(len(lines), 4)
            sids = [re.search(r"sid:(\d+);", ln).group(1) for ln in lines]
            self.assertEqual(len(set(sids)), len(sids))
            for ln in lines:
                self.assertRegex(ln, r"^(alert|drop) http any any -> any any \(")
                self.assertTrue(ln.endswith(")"))
                self.assertEqual(ln.count('"') % 2, 0)
                self.assertIn("http.request_body;", ln)
                self.assertIn("flow:established,to_server;", ln)
            self.assertEqual(sum(ln.startswith("drop") for ln in lines),
                             2 if block else 0)
        self.assertIn("detection_filter:track by_src, count 3, seconds 120;",
                      render_suricata())

    def test_sigma_documents(self):
        text = render_sigma()
        self.assertEqual(text, render_sigma())  # deterministic
        docs = [d for d in text.split("---\n")[1:]]
        self.assertEqual(len(docs), len(LINE_INDICATORS))
        ids = [re.search(r"^id: (\S+)$", d, re.M).group(1) for d in docs]
        self.assertEqual(len(set(ids)), len(ids))
        for rid in ids:
            uuid.UUID(rid)
        for d in docs:
            for key in ("title:", "logsource:", "detection:", "condition:", "level:"):
                self.assertIn(key, d)

    @unittest.skipUnless(yaml, "PyYAML not installed")
    def test_sigma_is_valid_yaml(self):
        docs = list(yaml.safe_load_all(render_sigma()))
        self.assertEqual(len(docs), len(LINE_INDICATORS))
        by_title = {d["title"]: d for d in docs}
        d = by_title["PHP2Shell - Serialized PHP data alongside the upload-progress field"]
        self.assertEqual(d["detection"]["condition"], "kw1 and kw2")
        self.assertEqual(d["detection"]["kw2"], ['O:*:"*', 'a:*:{*'])
        self.assertEqual(d["level"], "high")
        self.assertIn("cve.2026-109619", d["tags"])

    def test_cli_rules_stdout_and_output_dir(self):
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            self.assertEqual(main(["rules", "--format", "suricata"]), 0)
        self.assertIn("sid:1000100;", buf.getvalue())
        with tempfile.TemporaryDirectory() as tmp, \
                contextlib.redirect_stdout(io.StringIO()):
            out = os.path.join(tmp, "rules")
            self.assertEqual(main(["rules", "--output", out, "--block"]), 0)
            self.assertEqual(sorted(os.listdir(out)), sorted(RULE_FILENAMES.values()))
            with open(os.path.join(out, "php2shell-modsecurity.conf")) as fh:
                self.assertIn("deny,status:403", fh.read())

    def test_cli_rules_unwritable_output(self):
        with tempfile.NamedTemporaryFile() as fh, \
                contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            # a file where the output directory should be
            self.assertEqual(main(["rules", "--output", fh.name]), 2)


PROBE_SAMPLE = """\
BIN /usr/bin/php
VER PHP 8.4.26 (cli) (built: Oct  1 2026)
INI memory_limit => 128M => 128M
INI session.upload_progress.enabled => On => On
BIN /usr/sbin/php-fpm8.4
VER PHP 8.4.27 (fpm-fcgi) (built: Oct 22 2026)
STALE 812 php-fpm8.4 library replaced on disk (libphp8.4.so)
STALE 811 php-fpm8.4 library replaced on disk (libphp8.4.so)
"""


class SshFleetTests(unittest.TestCase):
    def _hosts_file(self, text):
        fh = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
        fh.write(text)
        fh.close()
        self.addCleanup(os.unlink, fh.name)
        return fh.name

    def test_hosts_file_parsing_and_validation(self):
        path = self._hosts_file(
            "web01\nadmin@web02.example.com  # primary\n# comment\n\n"
            "-oProxyCommand=evil\nweb 03\n10.0.0.5\nfe80::1%eth0\n")
        entries = read_ssh_hosts(path)
        ok = [e for _, e, err in entries if err is None]
        bad = [e for _, e, err in entries if err is not None]
        self.assertEqual(ok, ["web01", "admin@web02.example.com", "10.0.0.5", "fe80::1%eth0"])
        self.assertEqual(bad, ["-oProxyCommand=evil", "web 03"])

    def test_unreadable_hosts_file(self):
        entries = read_ssh_hosts(os.path.join(tempfile.gettempdir(), "nope-php2shell.txt"))
        self.assertIsNotNone(entries[0][2])

    def test_parse_remote_probe(self):
        installs = parse_remote_probe("web01", PROBE_SAMPLE)
        self.assertEqual([i.binary for i in installs],
                         ["web01: /usr/bin/php", "web01: /usr/sbin/php-fpm8.4"])
        self.assertEqual(installs[0].verdict.status, STATUS_VULNERABLE)
        self.assertEqual(installs[1].verdict.status, STATUS_PATCHED)
        self.assertEqual(installs[0].config["memory_limit"], "128M")
        self.assertTrue(installs[0].upload_progress_enabled)
        # restart findings belong to the host and sit on its first record, grouped
        self.assertEqual(len(installs[0].stale), 1)
        self.assertEqual(installs[0].stale[0].pids, [811, 812])
        self.assertEqual(installs[1].stale, [])

    def test_parse_remote_probe_without_php(self):
        installs = parse_remote_probe("db01", "")
        self.assertEqual(len(installs), 1)
        self.assertEqual(installs[0].verdict.status, STATUS_UNKNOWN)
        self.assertEqual(installs[0].binary, "db01")

    def test_parse_remote_probe_stale_without_binary(self):
        installs = parse_remote_probe(
            "db01", "STALE 5 apache2 library replaced on disk (libphp8.4.so)\n")
        self.assertEqual(installs[0].verdict.status, STATUS_UNKNOWN)
        self.assertEqual(installs[0].stale[0].name, "apache2")
        self.assertEqual(check_exit_code(installs, None), 1)

    def test_remote_output_is_sanitized(self):
        installs = parse_remote_probe(
            "h", "BIN /usr/bin/php\x1b[2J\nVER PHP 8.4.27\x1b[31m (cli)\n")
        self.assertNotIn("\x1b", installs[0].binary)
        self.assertNotIn("\x1b", installs[0].raw_version)

    def test_probe_host_runs_ssh_safely(self):
        done = mock.Mock(returncode=0, stdout=PROBE_SAMPLE, stderr="")
        with mock.patch("php2shell_check.subprocess.run", return_value=done) as run:
            installs = probe_host("admin@web01")
        cmd = run.call_args.args[0]
        self.assertIsInstance(cmd, list)
        self.assertNotIn("shell", run.call_args.kwargs)
        self.assertIn("BatchMode=yes", cmd)
        self.assertEqual(cmd[cmd.index("--") + 1], "admin@web01")  # host after `--`
        self.assertEqual(cmd[-2:], ["sh", "-s"])
        self.assertIn("command -v", run.call_args.kwargs["input"])
        self.assertEqual(len(installs), 2)

    def test_probe_host_failures_become_unknown(self):
        failed = mock.Mock(returncode=255, stdout="", stderr="x\nPermission denied (publickey).\n")
        for effect, text in [
            (FileNotFoundError(), "ssh"),
            (subprocess.TimeoutExpired("ssh", 1), "timed out"),
        ]:
            with self.subTest(text=text), \
                    mock.patch("php2shell_check.subprocess.run", side_effect=effect):
                inst = probe_host("web01")[0]
                self.assertEqual(inst.verdict.status, STATUS_UNKNOWN)
                self.assertIn(text, inst.verdict.detail)
        with mock.patch("php2shell_check.subprocess.run", return_value=failed):
            inst = probe_host("web01")[0]
        self.assertIn("Permission denied (publickey)", inst.verdict.detail)

    def test_scan_ssh_hosts_and_cli(self):
        path = self._hosts_file("web01\nweb01\n--bad\nweb02\n")

        def fake_probe(host, timeout=90):
            return parse_remote_probe(host, PROBE_SAMPLE if host == "web01" else "")

        with mock.patch("php2shell_check.probe_host", side_effect=fake_probe) as probe:
            installs = scan_ssh_hosts(path, jobs=4)
            self.assertEqual(probe.call_count, 2)  # duplicate host probed once
        self.assertEqual([i.binary for i in installs],
                         ["web01: /usr/bin/php", "web01: /usr/sbin/php-fpm8.4",
                          path + ":3", "web02"])
        self.assertIn("not a plain host", installs[2].verdict.detail)
        with mock.patch("php2shell_check.probe_host", side_effect=fake_probe), \
                contextlib.redirect_stdout(io.StringIO()) as buf:
            code = main(["check", "--ssh-hosts", path, "--no-color", "--json"])
        self.assertEqual(code, 1)
        payload = json.loads(buf.getvalue())
        self.assertEqual(payload["stale_processes"], [])  # local check is skipped
        self.assertEqual(payload["installs"][0]["stale_processes"][0]["pids"], [811, 812])

    @unittest.skipUnless(os.name == "posix" and shutil.which("sh"), "needs a POSIX sh")
    def test_probe_script_against_fake_proc(self):
        with tempfile.TemporaryDirectory() as tmp:
            for pid, comm, maps in [
                (100, "php-fpm8.4", _maps_line("/usr/lib/libphp8.4.so")),
                (101, "apache2", _maps_line("/usr/lib/libssl.so.3")),
                (102, "bash", _maps_line("/usr/lib/libphp8.4.so")),
                (103, "php-fpm8.4", _maps_line("/usr/lib/libphp8.4.so", deleted=False)),
            ]:
                d = os.path.join(tmp, "proc", str(pid))
                os.makedirs(d)
                with open(os.path.join(d, "comm"), "w") as fh:
                    fh.write(comm + "\n")
                with open(os.path.join(d, "maps"), "w") as fh:
                    fh.write(maps + "\n")
            os.makedirs(os.path.join(tmp, "bin"))
            php = os.path.join(tmp, "bin", "php")
            with open(php, "w") as fh:
                fh.write('#!/bin/sh\ncase "$1" in\n'
                         '  -v) echo "PHP 8.4.26 (cli)" ;;\n'
                         '  -i) echo "memory_limit => 128M => 128M" ;;\nesac\n')
            os.chmod(php, 0o755)
            env = dict(os.environ, PATH=os.path.join(tmp, "bin") + os.pathsep + "/usr/bin:/bin")
            out = subprocess.run(
                ["sh", "-s"], input=build_remote_probe(os.path.join(tmp, "proc")),
                capture_output=True, text=True, env=env, timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        installs = parse_remote_probe("h", out.stdout)
        self.assertEqual(installs[0].verdict.status, STATUS_VULNERABLE)
        self.assertEqual(installs[0].config["memory_limit"], "128M")
        self.assertEqual([(s.name, s.pids) for s in installs[0].stale],
                         [("php-fpm8.4", [100])])

    def test_parse_remote_probe_backport(self):
        out = ("BIN /usr/bin/php\nVER PHP 8.0.30 (cli)\nPKG rpm php-cli 8.0.30-8.el9_8.1\n"
               "CVE CVE-2026-109618\nCVE CVE-2026-109619\n")
        (ins,) = parse_remote_probe("web01", out)
        self.assertEqual(ins.verdict.status, STATUS_PATCHED_BACKPORT)
        self.assertEqual(ins.package.name, "php-cli")

    def test_parse_remote_probe_nochangelog(self):
        out = "BIN /usr/bin/php\nVER PHP 8.2.20 (cli)\nPKG dpkg php8.2-cli 8.2.20-1\nNOCHANGELOG\n"
        (ins,) = parse_remote_probe("web01", out)
        self.assertTrue(ins.verdict.affected)
        self.assertIsNone(ins.package.cves)

    def test_parse_remote_probe_one_cve_is_not_enough(self):
        out = ("BIN /usr/bin/php\nVER PHP 8.2.20 (cli)\nPKG dpkg php8.2-cli 8.2.20-1\n"
               "CVE CVE-2026-109618\n")
        (ins,) = parse_remote_probe("web01", out)
        self.assertTrue(ins.verdict.affected)
        self.assertEqual(ins.package.cves, ["CVE-2026-109618"])

    def test_parse_remote_probe_rejects_untrusted_package_lines(self):
        for pkg in ("PKG dpkg ;rm-rf 8.2.20-1", "PKG apt php8.2-cli 8.2.20-1",
                    "PKG dpkg php8.2-cli", "PKG dpkg"):
            with self.subTest(pkg=pkg):
                out = f"BIN /usr/bin/php\nVER PHP 8.2.20 (cli)\n{pkg}\nCVE CVE-2026-109618\nCVE CVE-2026-109619\n"
                (ins,) = parse_remote_probe("web01", out)
                self.assertIsNone(ins.package)
                self.assertTrue(ins.verdict.affected)

    def test_parse_remote_probe_ignores_unknown_cve_ids(self):
        out = ("BIN /usr/bin/php\nVER PHP 8.2.20 (cli)\nPKG dpkg php8.2-cli 8.2.20-1\n"
               "CVE CVE-2026-109618\nCVE CVE-1999-0001\nCVE CVE-2026-109618\n")
        (ins,) = parse_remote_probe("web01", out)
        self.assertEqual(ins.package.cves, ["CVE-2026-109618"])

    def test_probe_uses_cves_as_single_source(self):
        script = build_remote_probe()
        self.assertIn("|".join(CVES), script)  # no ERE metacharacters to escape
        self.assertNotIn("@CVE_RE@", script)
        self.assertNotIn("@DOC@", script)

    # The only system tools on the probe's PATH, beside the fakes, so the
    # host's own dpkg or rpm never answers for the fake php.
    PROBE_TOOLS = ("sh", "head", "sed", "grep", "cut", "sort", "awk", "readlink", "cat", "gzip")

    def _run_fake_probe(self, changelog, manager="dpkg", tools=PROBE_TOOLS, fakes=None):
        """Run the real sh probe against a fake php 8.2.20 and a fake dpkg or
        rpm whose package changelog is `changelog`. `fakes` adds more shims
        ({name: sh body}). Returns the probe's stdout."""
        with tempfile.TemporaryDirectory() as tmp:
            bindir, sysdir = os.path.join(tmp, "bin"), os.path.join(tmp, "sys")
            for d in (bindir, sysdir, os.path.join(tmp, "proc")):
                os.makedirs(d)
            for t in tools:
                if shutil.which(t):
                    os.symlink(shutil.which(t), os.path.join(sysdir, t))

            def script(name, body):
                path = os.path.join(bindir, name)
                with open(path, "w") as fh:
                    fh.write("#!/bin/sh\n" + body)
                os.chmod(path, 0o755)

            script("php", 'case "$1" in -v) echo "PHP 8.2.20 (cli)" ;; esac\n')
            if manager == "dpkg":
                docdir = os.path.join(tmp, "doc", "php8.2-common")
                os.makedirs(docdir)
                with gzip.open(os.path.join(docdir, "changelog.Debian.gz"), "wt") as fh:
                    fh.write(changelog)
                script("dpkg", 'echo "php8.2-cli: $2"\n')
                script("dpkg-query", 'printf %s "8.2.20-1"\n')
            else:
                with open(os.path.join(tmp, "rpm-changelog"), "w") as fh:
                    fh.write(changelog)
                script("rpm", 'case "$1" in\n'
                              '  -qf) printf %s "php-cli 8.2.20-8.el9_8.1" ;;\n'
                              '  -q) [ "$2" = --changelog ] && [ "$3" = php-cli ] && '
                              f'cat "{tmp}/rpm-changelog" ;;\n'
                              'esac\n')
            for name, body in (fakes or {}).items():
                script(name, body)
            out = subprocess.run(
                [shutil.which("sh"), "-s"],
                input=build_remote_probe(os.path.join(tmp, "proc"), os.path.join(tmp, "doc")),
                capture_output=True, text=True, timeout=30,
                env=dict(os.environ, PATH=bindir + os.pathsep + sysdir))
        self.assertEqual(out.returncode, 0, out.stderr)
        return out.stdout

    @unittest.skipUnless(os.name == "posix" and shutil.which("sh"), "needs POSIX sh")
    def test_probe_script_reads_fake_dpkg_changelog(self):
        out = self._run_fake_probe("php8.2 (8.2.20-1) unstable; urgency=high\n"
                                   "  * Fix CVE-2026-109618 and CVE-2026-109619.\n")
        self.assertIn("PKG dpkg php8.2-cli 8.2.20-1\n", out)
        self.assertIn("CVE CVE-2026-109618\n", out)
        self.assertIn("CVE CVE-2026-109619\n", out)
        (ins,) = parse_remote_probe("h", out)
        self.assertEqual(ins.verdict.status, STATUS_PATCHED_BACKPORT)

    @unittest.skipUnless(os.name == "posix" and shutil.which("sh"), "needs POSIX sh")
    def test_probe_script_reads_fake_rpm_changelog(self):
        out = self._run_fake_probe("* Mon Oct 26 2026 Packager <p@example.org> - 8.2.20-8.el9_8.1\n"
                                   "- Fix CVE-2026-109618\n- Fix CVE-2026-109619\n", manager="rpm")
        self.assertIn("PKG rpm php-cli 8.2.20-8.el9_8.1\n", out)
        self.assertIn("CVE CVE-2026-109618\n", out)
        self.assertIn("CVE CVE-2026-109619\n", out)
        (ins,) = parse_remote_probe("h", out)
        self.assertEqual(ins.verdict.status, STATUS_PATCHED_BACKPORT)

    @unittest.skipUnless(os.name == "posix" and shutil.which("sh"), "needs POSIX sh")
    def test_probe_script_needs_a_digit_boundary_after_the_cve(self):
        # Longer IDs that merely start with ours are other CVEs.
        lookalike = "  * Fix CVE-2026-1096185 and CVE-2026-1096190\n"
        for manager in ("dpkg", "rpm"):
            with self.subTest(manager=manager):
                out = self._run_fake_probe(lookalike, manager=manager)
                self.assertNotIn("CVE CVE-", out)
                self.assertNotIn("NOCHANGELOG", out)
                (ins,) = parse_remote_probe("h", out)
                self.assertTrue(ins.verdict.affected)
                self.assertEqual(ins.package.cves, [])

    @unittest.skipUnless(os.name == "posix" and shutil.which("sh"), "needs POSIX sh")
    def test_probe_script_without_gzip_or_grep_o_says_nochangelog(self):
        # Without these the changelog cannot be searched; that must not read as
        # "the changelog names neither CVE".
        both = "  * Fix CVE-2026-109618 and CVE-2026-109619\n"
        no_grep_o = {"grep": f'case "$1" in -o*) echo "grep: invalid option" >&2; exit 2 ;; esac\n'
                             f'exec {shutil.which("grep")} "$@"\n'}
        for label, kw in [("no gzip", {"tools": [t for t in self.PROBE_TOOLS if t != "gzip"]}),
                          ("dpkg, no grep -o", {"fakes": no_grep_o}),
                          ("rpm, no grep -o", {"fakes": no_grep_o, "manager": "rpm"})]:
            with self.subTest(label):
                out = self._run_fake_probe(both, **kw)
                self.assertIn("NOCHANGELOG", out)
                (ins,) = parse_remote_probe("h", out)
                self.assertTrue(ins.verdict.affected)
                self.assertTrue(any("changelog not available" in n for n in backport_notes(ins)))


class FailOnTests(unittest.TestCase):
    def test_default_keeps_historical_code(self):
        self.assertEqual(exit_code_for(["low"], None, 1), 1)
        self.assertEqual(exit_code_for([], None, 0), 0)

    def test_threshold_matrix(self):
        self.assertEqual(exit_code_for(["medium"], "high", 1), 0)
        self.assertEqual(exit_code_for(["high"], "high", 0), 1)
        self.assertEqual(exit_code_for(["low"], "medium", 1), 0)
        self.assertEqual(exit_code_for(["medium"], "low", 0), 1)
        self.assertEqual(exit_code_for([], "low", 1), 0)

    def test_none_never_fails(self):
        self.assertEqual(exit_code_for(["high"], "none", 1), 0)

    def test_check_exit_codes(self):
        bad = PhpInstall("a", "8.4.26", assess((8, 4, 26)))
        ok = PhpInstall("b", "8.4.27", assess((8, 4, 27)))
        unk = PhpInstall("c", "", assess(None))
        self.assertEqual(check_exit_code([bad], None), 1)
        self.assertEqual(check_exit_code([ok], None), 0)
        self.assertEqual(check_exit_code([unk], None), 2)
        self.assertEqual(check_exit_code([], None), 2)
        self.assertEqual(check_exit_code([unk], "high"), 0)
        self.assertEqual(check_exit_code([unk], "medium"), 1)
        self.assertEqual(check_exit_code([bad], "none"), 0)
        self.assertEqual(check_exit_code([], "high"), 2)
        self.assertEqual(check_exit_code([], "none"), 0)

    def test_cli_fail_on(self):
        # --version path needs no PHP binary
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["check", "--version", "8.4.26", "--no-color"]), 1)
            self.assertEqual(main(["check", "--version", "8.4.26", "--no-color",
                                   "--fail-on", "none"]), 0)
            self.assertEqual(main(["check", "--version", "8.4.27", "--no-color",
                                   "--fail-on", "low"]), 0)


class SessionHandlerTests(unittest.TestCase):
    """CVE-2026-115560: not fixed by the 2026-10-21 releases, so these apply to
    patched installs too."""

    def _install(self, version, upload, handler="php"):
        cfg = {"session.serialize_handler": handler,
               "session.upload_progress.enabled": "On" if upload else "Off"}
        return PhpInstall("php", version, assess(parse_version(version)), upload, cfg)

    def test_posture_parses_serialize_handler(self):
        cfg = parse_ini_posture("session.serialize_handler => php_serialize => php\n")
        self.assertEqual(cfg["session.serialize_handler"], "php_serialize")

    def test_note_applies_to_patched_install(self):
        notes = " ".join(session_handler_notes(self._install("8.4.27", True)))
        self.assertIn("CVE-2026-115560", notes)
        self.assertIn("not fixed by the 2026-10-21", notes)
        self.assertIn("scan-code", notes)

    def test_note_names_nondefault_handler(self):
        notes = " ".join(session_handler_notes(self._install("8.4.27", True, "php_serialize")))
        self.assertIn("session.serialize_handler=php_serialize", notes)
        plain = " ".join(session_handler_notes(self._install("8.4.27", True, "php")))
        self.assertNotIn("serialize_handler=php", plain)

    def test_no_note_when_upload_progress_off_or_unknown(self):
        self.assertEqual(session_handler_notes(self._install("8.4.27", False)), [])
        self.assertEqual(session_handler_notes(PhpInstall("x", "", assess(None))), [])

    def test_note_does_not_change_exit_code(self):
        good = self._install("8.4.27", True, "php_serialize")
        self.assertEqual(check_exit_code([good], None), 0)

    def test_classify_lines(self):
        c = classify_code_line
        self.assertEqual(c("ini_set('session.serialize_handler', 'php');"), "ini_set_php")
        self.assertEqual(c('  ini_set( "session.serialize_handler" , "php" ) ;'), "ini_set_php")
        self.assertEqual(c("ini_set('session.serialize_handler', $h);"), "ini_set_other")
        self.assertEqual(c("ini_set('session.serialize_handler', 'php_serialize');"),
                         "ini_set_other")
        self.assertEqual(c("session.serialize_handler = php_serialize"), "config_nondefault")
        self.assertEqual(c("php_value session.serialize_handler php_binary"),
                         "config_nondefault")
        self.assertIsNone(c("session.serialize_handler = php"))
        self.assertIsNone(c("ini_set('memory_limit', '256M');"))
        self.assertIsNone(c("// serialize_handler is documented here"))

    def test_scan_tree(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "vendor", "x"))
            os.makedirs(os.path.join(d, ".git"))
            with open(os.path.join(d, "vendor", "x", "s.php"), "w") as fh:
                fh.write("<?php\nini_set('session.serialize_handler', 'php');\nsession_start();\n")
            with open(os.path.join(d, "app.php"), "w") as fh:
                fh.write("<?php echo 1;\n")
            with open(os.path.join(d, ".user.ini"), "w") as fh:
                fh.write("session.serialize_handler = php_serialize\n")
            with open(os.path.join(d, ".git", "c.php"), "w") as fh:
                fh.write("ini_set('session.serialize_handler', 'php');\n")
            with open(os.path.join(d, "notes.txt"), "w") as fh:
                fh.write("ini_set('session.serialize_handler', 'php');\n")
            files, errors = iter_code_files([d])
            self.assertEqual(errors, [])
            self.assertEqual(len(files), 3)  # .git and .txt skipped
            kinds = sorted(f.kind for p in files for f in scan_code_file(p))
            self.assertEqual(kinds, ["config_nondefault", "ini_set_php"])

    def test_cli_scan_code(self):
        with tempfile.TemporaryDirectory() as d:
            clean = os.path.join(d, "a.php")
            with open(clean, "w") as fh:
                fh.write("<?php echo 1;\n")
            bad = os.path.join(d, "b.php")
            with open(bad, "w") as fh:
                fh.write("<?php ini_set('session.serialize_handler','php');\n")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                self.assertEqual(main(["scan-code", clean]), 0)
                self.assertEqual(main(["scan-code", d]), 1)
                self.assertEqual(main(["scan-code", d, "--fail-on", "none"]), 0)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                main(["scan-code", d, "--json"])
            data = json.loads(out.getvalue())
            self.assertEqual(data["cve"], "CVE-2026-115560")
            self.assertEqual(data["findings"][0]["kind"], "ini_set_php")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["scan-code"]), 2)
            self.assertEqual(main(["scan-code", "/no/such/path"]), 2)


class BackportTests(unittest.TestCase):
    def _ins(self, ver, cves, name="php8.2-cli"):
        ins = PhpInstall("/usr/bin/php8.2", f"PHP {ver}", assess(parse_version(ver)))
        ins.package = PackageInfo("dpkg", name, ver + "-1", cves)
        return ins

    def test_changelog_cves(self):
        self.assertEqual(changelog_cves("  * Fix CVE-2026-109619 and CVE-2026-109618\n"),
                         ["CVE-2026-109618", "CVE-2026-109619"])
        self.assertEqual(changelog_cves("nothing here"), [])

    def test_changelog_cves_needs_a_digit_boundary(self):
        lookalike = "  * Fix CVE-2026-1096185 and CVE-2026-1096190\n"
        self.assertEqual(changelog_cves(lookalike), [])
        self.assertEqual(changelog_cves("(CVE-2026-109618, CVE-2026-109619)"), CVES)
        self.assertEqual(changelog_cves("CVE-2026-109618CVE-2026-109619"), CVES)
        ins = self._ins("8.2.20", changelog_cves(lookalike))
        apply_backport(ins)
        self.assertTrue(ins.verdict.affected)

    def test_both_cves_backported_is_patched(self):
        ins = self._ins("8.0.30", ["CVE-2026-109618", "CVE-2026-109619"])
        apply_backport(ins)
        self.assertEqual(ins.verdict.status, STATUS_PATCHED_BACKPORT)
        self.assertFalse(ins.verdict.affected)
        self.assertIn("php8.2-cli", ins.verdict.detail)
        self.assertEqual(check_exit_code([ins], None), 0)

    def test_one_cve_stays_affected(self):
        ins = self._ins("8.2.20", ["CVE-2026-109618"])
        apply_backport(ins)
        self.assertTrue(ins.verdict.affected)
        self.assertTrue(any("CVE-2026-109619" in n for n in backport_notes(ins)))

    def test_changelog_missing_stays_affected(self):
        ins = self._ins("8.2.20", None)
        apply_backport(ins)
        self.assertTrue(ins.verdict.affected)
        self.assertTrue(any("changelog not available" in n for n in backport_notes(ins)))

    def test_package_must_be_the_running_build(self):
        # A source build (or COPY --from) over a packaged path: the package's
        # changelog says nothing about the PHP that actually runs.
        mismatch = ["package php8.2-cli 8.2.35-1 does not match running PHP 8.2.20; "
                    "not treated as patched"]
        for cves in (list(CVES), None):
            with self.subTest(cves=cves):
                ins = PhpInstall("/usr/bin/php8.2", "PHP 8.2.20", assess((8, 2, 20)))
                ins.package = PackageInfo("dpkg", "php8.2-cli", "8.2.35-1", cves)
                apply_backport(ins)
                self.assertEqual(ins.verdict.status, STATUS_VULNERABLE)
                self.assertEqual(backport_notes(ins), mismatch)
        out = ("BIN /usr/bin/php\nVER PHP 8.2.20 (cli)\nPKG dpkg php8.2-cli 8.2.35-1\n"
               "CVE CVE-2026-109618\nCVE CVE-2026-109619\n")
        (ins,) = parse_remote_probe("h", out)
        self.assertEqual(ins.verdict.status, STATUS_VULNERABLE)
        self.assertEqual(backport_notes(ins), mismatch)

    def test_vendor_release_and_epoch_forms_match_the_running_version(self):
        for running, version in [((8, 0, 30), "8.0.30-8.el9_8.1"),         # RHEL
                                  ((8, 0, 30), "8.0.30-8.el9_8.1.alma.1"),  # AlmaLinux
                                  ((8, 0, 30), "1:8.0.30-8.el9_8.1"),       # epoch
                                  ((7, 4, 33), "7.4.33-23.el9.remi")]:      # Remi EOL build
            with self.subTest(version=version):
                ins = PhpInstall("/usr/bin/php", "PHP", assess(running))
                ins.package = PackageInfo("rpm", "php-cli", version, list(CVES))
                apply_backport(ins)
                self.assertEqual(ins.verdict.status, STATUS_PATCHED_BACKPORT)
                self.assertEqual(backport_notes(ins), [])

    def test_notes_never_say_missing_nothing(self):
        # Both CVEs named but apply_backport not run: no "missing ;" line.
        ins = self._ins("8.2.20", list(CVES))
        self.assertNotIn("missing ;", " ".join(backport_notes(ins)))

    def test_no_package_no_notes(self):
        ins = PhpInstall("/usr/local/bin/php", "PHP 8.2.20", assess((8, 2, 20)))
        apply_backport(ins)
        self.assertTrue(ins.verdict.affected)
        self.assertEqual(backport_notes(ins), [])

    def test_patched_version_untouched(self):
        ins = self._ins("8.4.27", [])
        apply_backport(ins)
        self.assertEqual(ins.verdict.status, STATUS_PATCHED)
        self.assertEqual(backport_notes(ins), [])

    def test_read_changelog_falls_back_to_common(self):
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "php8.2-common"))
            with gzip.open(os.path.join(root, "php8.2-common", "changelog.Debian.gz"), "wt") as fh:
                fh.write("php8.2 (8.2.20-1) unstable; urgency=high\n"
                         "  * CVE-2026-109618 CVE-2026-109619\n")
            text = read_package_changelog(PackageInfo("dpkg", "php8.2-cli", "x", None), doc_root=root)
            self.assertEqual(changelog_cves(text), ["CVE-2026-109618", "CVE-2026-109619"])
            self.assertIsNone(read_package_changelog(PackageInfo("dpkg", "php9-cli", "x", None), doc_root=root))

    def test_package_for_binary_dpkg_and_rpm(self):
        def fake(cmd, **kw):
            out = {"dpkg": "php8.2-cli:amd64: /usr/bin/php8.2\n",
                   "dpkg-query": "8.2.20-1"}.get(os.path.basename(cmd[0]), "")
            return subprocess.CompletedProcess(cmd, 0 if out else 1, out, "")
        with mock.patch("php2shell_check.shutil.which", side_effect=lambda n: n if n.startswith("dpkg") else None), \
             mock.patch("php2shell_check.subprocess.run", side_effect=fake):
            pkg = package_for_binary("/usr/bin/php8.2")
        self.assertEqual((pkg.manager, pkg.name, pkg.version), ("dpkg", "php8.2-cli", "8.2.20-1"))

        def fake_rpm(cmd, **kw):
            return subprocess.CompletedProcess(cmd, 0, "php-cli 8.0.30-8.el9_8.1", "")
        with mock.patch("php2shell_check.shutil.which", side_effect=lambda n: n if n == "rpm" else None), \
             mock.patch("php2shell_check.subprocess.run", side_effect=fake_rpm):
            pkg = package_for_binary("/usr/bin/php")
        self.assertEqual((pkg.manager, pkg.name, pkg.version), ("rpm", "php-cli", "8.0.30-8.el9_8.1"))

    def test_empty_changelog_is_not_available(self):
        # An empty answer cannot show the CVEs are missing, only that there is nothing to read.
        for out in ("", "\n"):
            with self.subTest(out=out), mock.patch("php2shell_check._run_ok", return_value=out):
                self.assertIsNone(read_package_changelog(PackageInfo("rpm", "php-cli", "x", None)))
        with mock.patch("php2shell_check._run_ok", return_value="- Fix CVE-2026-109618\n"):
            self.assertIn("CVE-2026-109618",
                          read_package_changelog(PackageInfo("rpm", "php-cli", "x", None)))
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "php8.2-cli"))
            with gzip.open(os.path.join(root, "php8.2-cli", "changelog.Debian.gz"), "wt") as fh:
                fh.write("")
            self.assertIsNone(read_package_changelog(PackageInfo("dpkg", "php8.2-cli", "x", None),
                                                     doc_root=root))
        ins = self._inspect_rpm("")
        self.assertIsNone(ins.package.cves)
        self.assertTrue(any("changelog not available" in n for n in backport_notes(ins)))

    def _inspect_rpm(self, rpm_changelog):
        with mock.patch("php2shell_check._run", return_value="PHP 8.0.30 (cli)\n"), \
             mock.patch("php2shell_check.package_for_binary",
                        return_value=PackageInfo("rpm", "php-cli", "8.0.30-8.el9_8.1", None)), \
             mock.patch("php2shell_check._run_ok", return_value=rpm_changelog), \
             mock.patch("php2shell_check.read_ini_posture", return_value={}):
            return inspect_binary("/usr/bin/php")

    def test_package_for_binary_unowned(self):
        with mock.patch("php2shell_check.shutil.which", return_value=None):
            self.assertIsNone(package_for_binary("/usr/local/bin/php"))

    def test_notes_have_no_raw_control_chars(self):
        ins = self._ins("8.2.20", None, name="php\x1b[31m-cli")
        apply_backport(ins)
        self.assertNotIn("\x1b", "".join(backport_notes(ins)))

    def _inspect(self, changelog):
        with mock.patch("php2shell_check._run", return_value="PHP 8.0.30 (cli)\n"), \
             mock.patch("php2shell_check.package_for_binary",
                        return_value=PackageInfo("rpm", "php-cli", "8.0.30-8.el9_8.1", None)), \
             mock.patch("php2shell_check.read_package_changelog", return_value=changelog):
            return inspect_binary("/usr/bin/php")

    def test_inspect_binary_applies_backport(self):
        ins = self._inspect("  * CVE-2026-109618 CVE-2026-109619\n")
        self.assertEqual(ins.verdict.status, STATUS_PATCHED_BACKPORT)
        self.assertEqual(ins.package.cves, ["CVE-2026-109618", "CVE-2026-109619"])
        ins = self._inspect(None)
        self.assertTrue(ins.verdict.affected)
        self.assertIsNone(ins.package.cves)


class DockerProbeTests(unittest.TestCase):
    def _run(self, *results):
        """Put docker on PATH and make subprocess.run return `results` in order."""
        procs = [subprocess.CompletedProcess(["docker"], rc, out, err) for rc, out, err in results]
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(mock.patch("php2shell_check.shutil.which",
                                       side_effect=lambda n: "/usr/bin/docker" if n == "docker" else None))
        return stack.enter_context(mock.patch("php2shell_check.subprocess.run", side_effect=procs))

    def test_probe_image_uses_sh_probe_and_no_network(self):
        run = self._run((0, "BIN /usr/local/sbin/php-fpm\nVER PHP 8.3.10 (fpm-fcgi)\n", ""))
        installs = probe_image("php:8.3.10-fpm")
        cmd = run.call_args.args[0]
        self.assertEqual(cmd[:2], ["docker", "run"])
        self.assertEqual(cmd[cmd.index("--network") + 1], "none")
        self.assertEqual(cmd[cmd.index("--entrypoint") + 1], "sh")
        self.assertEqual(cmd[cmd.index("--cap-drop") + 1], "ALL")
        self.assertEqual(cmd[cmd.index("--security-opt") + 1], "no-new-privileges")
        self.assertEqual(cmd[-2:], ["php:8.3.10-fpm", "-s"])
        self.assertNotIn("shell", run.call_args.kwargs)
        self.assertEqual(run.call_args.kwargs["input"], build_remote_probe())
        self.assertEqual(installs[0].binary, "image php:8.3.10-fpm: /usr/local/sbin/php-fpm")
        self.assertTrue(installs[0].verdict.affected)

    def test_probe_image_distroless_fallback(self):
        run = self._run((127, "", 'exec: "sh": executable file not found in $PATH'),
                        (0, "PHP 8.4.27 (cli) (built: Oct 21 2026)\n", ""))
        installs = probe_image("example/php-distroless:8.4")
        self.assertEqual(len(installs), 1)
        self.assertEqual(installs[0].verdict.status, STATUS_PATCHED)
        cmd = run.call_args_list[1].args[0]
        self.assertEqual(cmd[cmd.index("--entrypoint") + 1], "php")
        self.assertEqual(cmd[cmd.index("--network") + 1], "none")
        self.assertEqual(cmd[cmd.index("--cap-drop") + 1], "ALL")
        self.assertEqual(cmd[cmd.index("--security-opt") + 1], "no-new-privileges")
        self.assertEqual(cmd[-1], "-v")

    def test_probe_image_no_php_is_unknown(self):
        self._run((0, "", ""), (127, "", 'exec: "php": executable file not found in $PATH\n'))
        installs = probe_image("alpine:3.20")
        self.assertEqual(len(installs), 1)
        self.assertEqual(installs[0].verdict.status, STATUS_UNKNOWN)
        self.assertIn("executable file not found", installs[0].verdict.detail)

    def test_php_that_cannot_be_invoked_is_not_no_php(self):
        # 126 is "found but cannot run" (e.g. permission denied): a finding, not a skip.
        denied = 'exec: "php": permission denied\n'
        self._run((0, "", ""), (126, "", denied))
        (ins,) = probe_image("example/php:8.3")
        self.assertEqual(ins.verdict.status, STATUS_UNKNOWN)
        self.assertTrue(ins.verdict.detail.startswith("docker probe failed"), ins.verdict.detail)
        self.assertIn("permission denied", ins.verdict.detail)
        self._run((0, "abc123\tapp\texample/php:8.3\n", ""), (0, "", ""), (126, "", denied))
        hits, _ = scan_running_containers()
        self.assertEqual([h.source for h in hits], ["container app (example/php:8.3)"])
        self.assertIn("permission denied", hits[0].verdict.detail)

    def test_option_like_image_rejected_before_docker(self):
        with mock.patch("php2shell_check.subprocess.run") as run:
            (ins,) = probe_image("--privileged")
            (cont,) = probe_container("--privileged", "web")
        run.assert_not_called()
        self.assertEqual(ins.verdict.status, STATUS_UNKNOWN)
        self.assertEqual(cont.verdict.status, STATUS_UNKNOWN)

    def test_docker_failures_become_unknown(self):
        for effect, text in [(FileNotFoundError(), "docker"),
                             (subprocess.TimeoutExpired("docker", 1), "timed out")]:
            with self.subTest(text=text), \
                    mock.patch("php2shell_check.shutil.which", return_value="/usr/bin/docker"), \
                    mock.patch("php2shell_check.subprocess.run", side_effect=effect):
                (ins,) = probe_image("php:8.3.10")
                self.assertEqual(ins.verdict.status, STATUS_UNKNOWN)
                self.assertIn(text, ins.verdict.detail)

    def test_docker_missing_is_a_note(self):
        with mock.patch("php2shell_check.shutil.which", return_value=None), \
                mock.patch("php2shell_check.subprocess.run") as run:
            hits, note = scan_running_containers()
            self.assertEqual(hits, [])
            self.assertIn("docker", note)
            cwd = os.getcwd()
            with tempfile.TemporaryDirectory() as empty:
                os.chdir(empty)
                try:
                    out = io.StringIO()
                    with contextlib.redirect_stdout(out):
                        code = main(["scan-docker", "--image", "php:8.3"])
                finally:
                    os.chdir(cwd)
        run.assert_not_called()
        self.assertEqual(code, 2)
        self.assertIn("[UNKNOWN]", out.getvalue())
        self.assertIn("docker CLI not found on PATH", out.getvalue())

    def test_official_image_has_no_package_line(self):
        self._run((0, "BIN /usr/local/bin/php\nVER PHP 8.2.20 (cli)\n", ""))
        (ins,) = probe_image("php:8.2.20-cli")
        self.assertIsNone(ins.package)
        self.assertEqual(backport_notes(ins), [])
        self.assertTrue(ins.verdict.affected)

    def test_running_containers_probe_cli_and_fpm(self):
        run = self._run(
            (0, "abc123\tweb\tphp:8.3.10-fpm\n", ""),
            (0, "BIN /usr/local/bin/php\nVER PHP 8.3.10 (cli)\n"
                "BIN /usr/local/sbin/php-fpm\nVER PHP 8.3.10 (fpm-fcgi)\n", ""))
        hits, note = scan_running_containers()
        self.assertIsNone(note)
        ps = run.call_args_list[0].args[0]
        self.assertEqual(ps[-2:], ["--format", "{{.ID}}\t{{.Names}}\t{{.Image}}"])
        exe = run.call_args_list[1].args[0]
        self.assertEqual(exe, ["docker", "exec", "-i", "abc123", "sh", "-s"])
        self.assertEqual(run.call_args_list[1].kwargs["input"], build_remote_probe())
        self.assertEqual(len(hits), 2)
        self.assertEqual({h.source for h in hits}, {"container web (php:8.3.10-fpm)"})
        self.assertTrue(all(h.verdict.affected for h in hits))
        self.assertEqual([h.install.binary for h in hits],
                         ["container web: /usr/local/bin/php", "container web: /usr/local/sbin/php-fpm"])

    def test_running_container_fallback_and_no_php_skipped(self):
        run = self._run((0, "abc123\tapp\tphp-distroless\ndef456\tdb\tpostgres:16\n", ""),
                        (126, "", 'exec: "sh": executable file not found\n'),
                        (0, "PHP 8.4.27 (cli)\n", ""),
                        (0, "", ""),
                        (126, "", 'exec: "php": executable file not found\n'))
        hits, note = scan_running_containers()
        self.assertEqual(run.call_args_list[2].args[0], ["docker", "exec", "abc123", "php", "-v"])
        self.assertEqual([h.source for h in hits], ["container app (php-distroless)"])
        self.assertEqual(hits[0].verdict.status, STATUS_PATCHED)

    def test_running_container_probe_timeout_is_unknown(self):
        ps = subprocess.CompletedProcess(["docker"], 0, "abc123\tweb\tphp:8.3-fpm\n", "")
        with mock.patch("php2shell_check.shutil.which", return_value="/usr/bin/docker"), \
                mock.patch("php2shell_check.subprocess.run",
                           side_effect=[ps, subprocess.TimeoutExpired("docker", 60)]):
            hits, note = scan_running_containers()
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].source, "container web (php:8.3-fpm)")
        self.assertEqual(hits[0].verdict.status, STATUS_UNKNOWN)
        self.assertIn("timed out", hits[0].verdict.detail)

    def test_running_container_exec_failure_is_unknown(self):
        gone = "Error response from daemon: container abc123 is not running\n"
        self._run((0, "abc123\tweb\tphp:8.3-fpm\n", ""), (1, "", gone), (1, "", gone))
        hits, note = scan_running_containers()
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].verdict.status, STATUS_UNKNOWN)
        self.assertIn("is not running", hits[0].verdict.detail)

    def _cli(self, argv, installs):
        out = io.StringIO()
        with mock.patch("php2shell_check.probe_image", return_value=installs) as probe, \
                contextlib.redirect_stdout(out):
            code = main(argv)
        return code, out.getvalue(), probe

    def test_cli_image_json_adds_install_keys(self):
        ins = parse_remote_probe("image php:8.2.20", "BIN /usr/bin/php8.2\nVER PHP 8.2.20 (cli)\n"
                                 "PKG dpkg php8.2-cli 8.2.20-1\nCVE CVE-2026-109618\n"
                                 "STALE 7 php-fpm8.2 binary replaced on disk (/usr/sbin/php-fpm8.2)\n")
        dockerfile = tempfile.NamedTemporaryFile("w", suffix="Dockerfile", delete=False)
        dockerfile.write("FROM php:8.4.27-cli\n")
        dockerfile.close()
        self.addCleanup(os.unlink, dockerfile.name)
        code, out, probe = self._cli(["scan-docker", dockerfile.name, "--image", "php:8.2.20",
                                      "--image", "php:8.4.27", "--json"], ins)
        self.assertEqual([c.args[0] for c in probe.call_args_list], ["php:8.2.20", "php:8.4.27"])
        self.assertEqual(code, 1)
        doc = json.loads(out)
        file_hit, image_hit = doc["hits"][0], doc["hits"][1]
        self.assertEqual(set(file_hit), {"source", "line", "image", "binary", "version",
                                         "status", "affected", "detail"})
        self.assertIsNone(file_hit["binary"])
        self.assertEqual(image_hit["binary"], "image php:8.2.20: /usr/bin/php8.2")
        self.assertEqual(image_hit["package"]["name"], "php8.2-cli")
        self.assertEqual(image_hit["stale_processes"][0]["pids"], [7])
        self.assertTrue(any("CVE-2026-109619" in n for n in image_hit["backport_notes"]))
        self.assertIn("config", image_hit)

    def test_cli_stale_only_fails_and_counts_high(self):
        ins = parse_remote_probe("image x", "BIN /usr/local/bin/php\nVER PHP 8.4.27 (cli)\n"
                                 "STALE 7 php binary replaced on disk (/usr/local/bin/php)\n")
        code, out, _ = self._cli(["scan-docker", "--image", "x"], ins)
        self.assertEqual(code, 1)
        self.assertIn("replaced on disk", out)
        code, _, _ = self._cli(["scan-docker", "--image", "x", "--fail-on", "high"], ins)
        self.assertEqual(code, 1)

    def test_cli_backport_label(self):
        ins = parse_remote_probe("image x", "BIN /usr/bin/php8.2\nVER PHP 8.2.20 (cli)\n"
                                 "PKG dpkg php8.2-cli 8.2.20-1\n"
                                 "CVE CVE-2026-109618\nCVE CVE-2026-109619\n")
        code, out, _ = self._cli(["scan-docker", "--image", "x"], ins)
        self.assertEqual(code, 0)
        self.assertIn("[OK (distro backport)]", out)


class ReportTests(unittest.TestCase):
    def _rows(self):
        bad = PhpInstall('<script>alert(1)</script>"', "PHP 8.3.10", assess((8, 3, 10)))
        ok = PhpInstall("/usr/bin/php", "PHP 8.4.27", assess((8, 4, 27)))
        return rows_from_installs([bad, ok], "ssh")

    def test_markdown_summary_and_rows(self):
        md = render_markdown("PHP2Shell check", self._rows(), "2026-10-30T00:00:00Z")
        self.assertIn("| Status | Target |", md)
        self.assertIn("1 affected", md)
        self.assertIn("1 patched", md)
        self.assertNotIn("—", md)                     # no em dashes
        self.assertLess(md.index("vulnerable"), md.index("| patched"))  # worst first

    def test_reports_have_no_em_dashes_even_from_verdict_text(self):
        rows = rows_from_installs([PhpInstall("php", "PHP 7.4.1", assess((7, 4, 1)))], "ssh")
        self.assertIn("—", rows[0].detail)
        self.assertNotIn("—", render_markdown("t", rows, "now"))
        self.assertNotIn("—", render_html("t", rows, "now"))

    def test_html_css_never_breaks_inside_short_words(self):
        css = render_html("t", self._rows(), "now").lower()
        self.assertNotIn("break-all", css)
        self.assertNotRegex(css, r"overflow-wrap:\s*anywhere")
        self.assertRegex(css, r"th\s*\{[^}]*white-space:\s*nowrap")

    def test_markdown_escapes_pipes(self):
        r = ReportRow("a|b", "local", "8.3.10", "vulnerable", "x", [])
        self.assertIn("a\\|b", render_markdown("t", [r], "now"))

    def test_markdown_notes_in_details_and_escaped(self):
        r = ReportRow("t", "local", "8.3.10", "vulnerable", "d", ["see <b>x</b> | y"])
        md = render_markdown("t", [r], "now")
        self.assertIn("<details>", md)
        self.assertNotIn("<b>x", md)

    def test_html_is_self_contained_and_escaped(self):
        page = render_html("PHP2Shell check", self._rows(), "2026-10-30T00:00:00Z")
        self.assertNotIn("<script>alert(1)", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertNotIn("<script", page.lower())
        self.assertNotRegex(page, r"(src|href)=\"https?://")
        self.assertIn("prefers-color-scheme: dark", page)
        self.assertIn("<title>PHP2Shell report</title>", page)
        self.assertIn("data:image/svg+xml", page)

    def test_rows_from_installs_stale(self):
        ins = PhpInstall("/usr/sbin/php-fpm", "PHP 8.4.27", assess((8, 4, 27)),
                         stale=[StaleProcess("php-fpm", [4], "binary replaced on disk (x)")])
        rows = rows_from_installs([ins], "ssh")
        self.assertEqual(rows[0].status, "restart_needed")
        local = rows_from_installs([], "local",
                                   [StaleProcess("php-fpm", [4], "binary replaced on disk (x)")])
        self.assertEqual([r.status for r in local], ["restart_needed"])
        self.assertEqual(local[0].source, "local")

    def test_rows_from_hits(self):
        ins = PhpInstall("image php:8.2.20: php", "PHP 8.2.20", assess((8, 2, 20)))
        hits = [DockerHit("Dockerfile", 3, "php:8.3", assess_tag("8.3")),
                DockerHit("image php:8.2.20", 0, "php:8.2.20", ins.verdict, install=ins)]
        rows = rows_from_hits(hits)
        self.assertEqual(rows[0].target, "Dockerfile:3 (php:8.3)")
        self.assertEqual(rows[0].source, "dockerfile")
        self.assertEqual(rows[1].source, "image")
        self.assertEqual(rows[1].status, "vulnerable")
        self.assertIn("image php:8.2.20: php", rows[1].target)

    def test_cli_writes_reports_and_keeps_exit_code(self):
        with tempfile.TemporaryDirectory() as d:
            md, ht = os.path.join(d, "r.md"), os.path.join(d, "r.html")
            with contextlib.redirect_stdout(io.StringIO()):
                code = main(["check", "--version", "8.3.10", "--markdown", md, "--html", ht])
            self.assertEqual(code, 1)
            self.assertTrue(os.path.getsize(md) and os.path.getsize(ht))

    def test_cli_reports_leave_json_stdout_alone(self):
        with tempfile.TemporaryDirectory() as d:
            md = os.path.join(d, "r.md")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                main(["check", "--version", "8.3.10", "--json", "--markdown", md])
            self.assertEqual(json.loads(out.getvalue())["installs"][0]["version"], "8.3.10")

    def test_scan_docker_writes_reports(self):
        with tempfile.TemporaryDirectory() as d:
            df, md = os.path.join(d, "Dockerfile"), os.path.join(d, "r.md")
            with open(df, "w") as fh:
                fh.write("FROM php:8.3.10\n")
            with contextlib.redirect_stdout(io.StringIO()):
                code = main(["scan-docker", df, "--markdown", md])
            self.assertEqual(code, 1)
            with open(md, encoding="utf-8") as fh:
                self.assertIn("1 affected", fh.read())

    def test_unwritable_report_exits_2(self):
        with tempfile.TemporaryDirectory() as d:
            bad = os.path.join(d, "missing", "r.md")
            err = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
                code = main(["check", "--version", "8.4.27", "--markdown", bad])
            self.assertEqual(code, 2)
            self.assertIn("r.md", err.getvalue())


class GithubActionTests(unittest.TestCase):
    """action.yml: its inputs, and its run script executed for real under bash
    with fake GITHUB_* files, as the runner would execute the step."""

    REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    @classmethod
    def setUpClass(cls):
        if yaml is None:
            raise unittest.SkipTest("PyYAML not installed")
        with open(os.path.join(cls.REPO, "action.yml"), encoding="utf-8") as fh:
            cls.action = yaml.safe_load(fh)
        cls.scan_step = next(s for s in cls.action["runs"]["steps"] if s.get("id") == "scan")

    def test_declares_inputs_defaults_and_output(self):
        inputs = self.action["inputs"]
        self.assertEqual(inputs["command"]["default"], "scan-docker")
        self.assertEqual(inputs["args"]["default"], "")
        self.assertEqual(inputs["fail-on"]["default"], "")
        self.assertEqual(inputs["python-version"]["default"], "3.13")
        self.assertIn("exit-code", self.action["outputs"])
        self.assertEqual(self.action["runs"]["using"], "composite")

    def test_inputs_reach_the_script_only_through_env(self):
        # `${{ }}` inside run: is the script-injection pattern GitHub warns about.
        self.assertNotIn("${{", self.scan_step["run"])
        self.assertEqual(self.scan_step["env"], {
            "P2S_COMMAND": "${{ inputs.command }}",
            "P2S_ARGS": "${{ inputs.args }}",
            "P2S_FAIL_ON": "${{ inputs.fail-on }}",
            "P2S_PYTHON": "${{ steps.python.outputs.python-path }}",
        })

    def test_setup_python_leaves_the_callers_python_alone(self):
        # Without update-environment: false, setup-python puts its Python first
        # on PATH for every later step of the caller's job.
        setup = next(s for s in self.action["runs"]["steps"]
                     if str(s.get("uses", "")).startswith("actions/setup-python@"))
        self.assertEqual(setup["id"], "python")
        self.assertIs(setup["with"]["update-environment"], False)
        self.assertEqual(setup["with"]["python-version"], "${{ inputs.python-version }}")

    def run_script(self, d, command, args="", fail_on=""):
        """Run the step's script as the runner does (bash -eo pipefail), with
        P2S_PYTHON set to this interpreter (setup-python's python-path output)
        and the GITHUB_* files in `d`. A `python` on PATH that always fails
        proves the script runs the interpreter it was given."""
        bindir = os.path.join(d, "bin")
        os.makedirs(bindir)
        with open(os.path.join(bindir, "python"), "w") as fh:
            fh.write("#!/bin/sh\necho 'wrong python' >&2\nexit 99\n")
        os.chmod(os.path.join(bindir, "python"), 0o755)
        runner_temp = os.path.join(d, "runner-temp")
        os.makedirs(runner_temp)
        script = os.path.join(d, "step.sh")
        with open(script, "w", encoding="utf-8") as fh:
            fh.write(self.scan_step["run"])
        env = dict(os.environ, PATH=bindir + os.pathsep + os.environ["PATH"],
                   GITHUB_ACTION_PATH=self.REPO, RUNNER_TEMP=runner_temp,
                   GITHUB_STEP_SUMMARY=os.path.join(d, "summary.md"),
                   GITHUB_OUTPUT=os.path.join(d, "output.txt"),
                   P2S_COMMAND=command, P2S_ARGS=args, P2S_FAIL_ON=fail_on,
                   P2S_PYTHON=sys.executable)
        proc = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", script],
                              cwd=d, env=env, capture_output=True, text=True, timeout=120)

        def read(name):
            path = os.path.join(d, name)
            if not os.path.exists(path):
                return ""
            with open(path, encoding="utf-8") as fh:
                return fh.read()
        return proc, read("summary.md"), read("output.txt")

    @unittest.skipUnless(os.name == "posix" and shutil.which("bash"), "needs bash")
    def test_check_fails_the_step_and_writes_summary_and_output(self):
        with tempfile.TemporaryDirectory() as d:
            proc, summary, output = self.run_script(d, "check", "--version 8.3.10")
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertEqual(output, "exit-code=1\n")
        self.assertIn("1 affected", summary)

    @unittest.skipUnless(os.name == "posix" and shutil.which("bash"), "needs bash")
    def test_fail_on_none_exits_0(self):
        with tempfile.TemporaryDirectory() as d:
            proc, _, output = self.run_script(d, "check", "--version 8.3.10", fail_on="none")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(output, "exit-code=0\n")

    @unittest.skipUnless(os.name == "posix" and shutil.which("bash"), "needs bash")
    def test_scan_docker_writes_summary_for_a_dockerfile(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "Dockerfile.ci"), "w", encoding="utf-8") as fh:
                fh.write("FROM php:8.3.10-fpm\n")
            proc, summary, output = self.run_script(d, "scan-docker", "Dockerfile.ci")
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertEqual(output, "exit-code=1\n")
        self.assertIn("1 affected", summary)

    @unittest.skipUnless(os.name == "posix" and shutil.which("bash"), "needs bash")
    def test_other_commands_get_no_markdown_flag(self):
        # scan-code has no --markdown; passing one would be a usage error (exit 2).
        with tempfile.TemporaryDirectory() as d:
            proc, summary, output = self.run_script(d, "scan-code", ".", fail_on="none")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(summary, "")
        self.assertEqual(output, "exit-code=0\n")

    @unittest.skipUnless(os.name == "posix" and shutil.which("bash"), "needs bash")
    def test_unknown_command_exits_2_and_writes_no_outputs(self):
        with tempfile.TemporaryDirectory() as d:
            proc, summary, output = self.run_script(d, "scan-everything")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("command must be", proc.stdout)
        self.assertEqual(summary, "")
        self.assertEqual(output, "")


if __name__ == "__main__":
    unittest.main()
