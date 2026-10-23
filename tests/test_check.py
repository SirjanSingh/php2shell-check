"""Tests for php2shell-check version/verdict logic. Run: python -m pytest, or
   python -m unittest discover tests."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from php2shell_check import (  # noqa: E402
    assess,
    parse_version,
    STATUS_PATCHED,
    STATUS_VULNERABLE,
    STATUS_VULNERABLE_EOL,
    STATUS_UNKNOWN,
)


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


if __name__ == "__main__":
    unittest.main()
