"""Tests for php2shell-check version/verdict logic. Run: python -m pytest, or
   python -m unittest discover tests."""

import contextlib
import io
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tempfile  # noqa: E402

from php2shell_check import (  # noqa: E402
    assess,
    assess_tag,
    parse_version,
    scan_file,
    scan_docker_files,
    read_inventory,
    check_to_sarif,
    scan_to_sarif,
    guess_log_type,
    parse_ini_posture,
    posture_notes,
    exit_code_for,
    check_exit_code,
    find_stale_php_processes,
    main,
    PhpInstall,
    StaleProcess,
    STATUS_PATCHED,
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


if __name__ == "__main__":
    unittest.main()
