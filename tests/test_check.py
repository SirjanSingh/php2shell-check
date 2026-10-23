"""Tests for php2shell-check version/verdict logic. Run: python -m pytest, or
   python -m unittest discover tests."""

import os
import sys
import unittest

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
    PhpInstall,
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


if __name__ == "__main__":
    unittest.main()
