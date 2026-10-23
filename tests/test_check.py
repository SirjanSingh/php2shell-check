"""Tests for php2shell-check version/verdict logic. Run: python -m pytest, or
   python -m unittest discover tests."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tempfile  # noqa: E402

from php2shell_check import (  # noqa: E402
    assess,
    parse_version,
    scan_file,
    guess_log_type,
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


if __name__ == "__main__":
    unittest.main()
