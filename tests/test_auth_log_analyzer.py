#!/usr/bin/env python3
"""Tests for auth_log_analyzer.py (stdlib unittest, no pytest needed).

Usage:  python3 tests/run_tests.py
"""

import io
import json
import os
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import auth_log_analyzer as ala  # noqa: E402


def line(time, message, host="webserver", process="sshd[1234]"):
    """One synthetic syslog line: 'Nov 23 HH:MM:SS host process: message'."""
    return f"Nov 23 {time} {host} {process}: {message}"


def failed(time, user, ip, port=52310):
    return line(time, f"Failed password for {user} from {ip} port {port} ssh2")


def failed_invalid(time, user, ip, port=52310):
    return line(
        time,
        f"Failed password for invalid user {user} from {ip} port {port} ssh2",
    )


def accepted(time, user, ip, method="publickey", port=52310):
    return line(
        time,
        f"Accepted {method} for {user} from {ip} port {port} ssh2",
    )


def invalid_user(time, user, ip, port=52310):
    return line(time, f"Invalid user {user} from {ip} port {port}")


def report_for(text, **kwargs):
    """Parse text and analyse it, with a fixed year for determinism."""
    events, total, malformed = ala.parse_log(text, year=2026)
    return ala.analyze_log(events, total, malformed, **kwargs)


def findings_of(report, severity=None):
    if severity is None:
        return report.findings
    return [f for f in report.findings if f.severity == severity]


class TestParsing(unittest.TestCase):
    def test_failed_password(self):
        event = ala.parse_line(failed("10:15:02", "root", "203.0.113.45"), year=2026)
        self.assertIsNotNone(event)
        self.assertEqual(event.kind, "failed_password")
        self.assertEqual(event.user, "root")
        self.assertEqual(event.ip, "203.0.113.45")
        self.assertEqual(event.time, datetime(2026, 11, 23, 10, 15, 2))

    def test_failed_password_for_invalid_user(self):
        event = ala.parse_line(failed_invalid("10:15:02", "testuser", "203.0.113.45"), year=2026)
        self.assertIsNotNone(event)
        self.assertEqual(event.kind, "failed_password")
        self.assertEqual(event.user, "testuser")

    def test_accepted_password(self):
        event = ala.parse_line(accepted("10:15:02", "alice", "192.168.1.10", "password"), year=2026)
        self.assertEqual(event.kind, "accepted")
        self.assertEqual(event.method, "password")
        self.assertEqual(event.user, "alice")

    def test_accepted_publickey(self):
        event = ala.parse_line(accepted("10:15:02", "alice", "192.168.1.10"), year=2026)
        self.assertEqual(event.kind, "accepted")
        self.assertEqual(event.method, "publickey")

    def test_invalid_user(self):
        event = ala.parse_line(invalid_user("10:15:02", "guest", "203.0.113.45"), year=2026)
        self.assertEqual(event.kind, "invalid_user")
        self.assertEqual(event.user, "guest")

    def test_failed_publickey(self):
        text = line("10:15:02", "Failed publickey for alice from 203.0.113.45 port 52310 ssh2")
        event = ala.parse_line(text, year=2026)
        self.assertEqual(event.kind, "failed_publickey")
        self.assertEqual(event.user, "alice")

    def test_connection_closed(self):
        text = line("10:15:02", "Connection closed by 203.0.113.45 port 52310 [preauth]")
        event = ala.parse_line(text, year=2026)
        self.assertEqual(event.kind, "connection_closed")
        self.assertEqual(event.ip, "203.0.113.45")

    def test_disconnected(self):
        text = line("10:15:02", "Disconnected from user alice 192.168.1.10 port 51234")
        event = ala.parse_line(text, year=2026)
        self.assertEqual(event.kind, "disconnected")

    def test_sudo_pam_auth_failure(self):
        text = line(
            "09:15:22",
            "pam_unix(sudo:auth): authentication failure; logname=alice uid=1000 "
            "euid=0 tty=/dev/pts/0 ruser=alice rhost= user=alice",
            process="sudo",
        )
        event = ala.parse_line(text, year=2026)
        self.assertEqual(event.kind, "sudo_failure")
        self.assertEqual(event.user, "alice")

    def test_sudo_not_in_sudoers(self):
        text = line(
            "09:20:11",
            "bob : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/bob ; "
            "USER=root ; COMMAND=/bin/cat /etc/shadow",
            process="sudo",
        )
        event = ala.parse_line(text, year=2026)
        self.assertEqual(event.kind, "sudo_failure")
        self.assertEqual(event.user, "bob")

    def test_pam_sshd_auth_failure(self):
        text = line(
            "10:15:02",
            "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 "
            "tty=ssh ruser= rhost=203.0.113.45 user=root",
        )
        event = ala.parse_line(text, year=2026)
        self.assertEqual(event.kind, "failed_password")
        self.assertEqual(event.ip, "203.0.113.45")
        self.assertEqual(event.user, "root")

    def test_session_open_is_other(self):
        text = line("10:15:02", "pam_unix(sshd:session): session opened for user alice by (uid=0)")
        event = ala.parse_line(text, year=2026)
        self.assertIsNotNone(event)
        self.assertEqual(event.kind, "other")

    def test_malformed_line_returns_none(self):
        self.assertIsNone(ala.parse_line("this is not a log line", year=2026))
        self.assertIsNone(ala.parse_line("Nov 23 10:00:00 webserver", year=2026))
        self.assertIsNone(ala.parse_line("", year=2026))

    def test_bad_month_returns_none(self):
        self.assertIsNone(
            ala.parse_line("Xyz 23 10:15:02 host sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2", year=2026)
        )


class TestBruteForce(unittest.TestCase):
    def test_brute_force_at_threshold(self):
        text = "\n".join(
            failed(f"10:{minute:02d}:00", f"user{minute}", "203.0.113.45")
            for minute in range(0, 25, 5)
        )
        report = report_for(text)
        self.assertIn("203.0.113.45", report.brute_force_ips)
        highs = findings_of(report, "high")
        self.assertTrue(any("Brute-force" in f.message for f in highs))

    def test_below_threshold_no_brute_force(self):
        text = "\n".join(
            failed(f"10:{minute:02d}:00", f"user{minute}", "203.0.113.45")
            for minute in range(0, 20, 5)
        )
        report = report_for(text)
        self.assertEqual(report.brute_force_ips, [])
        self.assertFalse(any("Brute-force" in f.message for f in report.findings))

    def test_window_expiry(self):
        # Five failures, but spread over two hours: no 60-minute window
        # holds all five, so this is not a brute-force attack.
        text = "\n".join(
            failed(f"{hour:02d}:00:00", f"user{hour}", "203.0.113.45")
            for hour in (8, 9, 10, 11, 12)
        )
        report = report_for(text)
        self.assertEqual(report.brute_force_ips, [])

    def test_wider_window_catches_spread_failures(self):
        text = "\n".join(
            failed(f"{hour:02d}:00:00", f"user{hour}", "203.0.113.45")
            for hour in (8, 9, 10, 11, 12)
        )
        report = report_for(text, window_minutes=300)
        self.assertIn("203.0.113.45", report.brute_force_ips)

    def test_threshold_flag_raises_bar(self):
        text = "\n".join(
            failed(f"10:{minute:02d}:00", f"user{minute}", "203.0.113.45")
            for minute in range(0, 25, 5)
        )
        report = report_for(text, threshold=10)
        self.assertEqual(report.brute_force_ips, [])


class TestOtherFindings(unittest.TestCase):
    def test_success_after_failure(self):
        text = "\n".join(
            [
                failed("10:00:00", "admin", "203.0.113.45"),
                failed("10:05:00", "admin", "203.0.113.45"),
                accepted("10:10:00", "admin", "203.0.113.45", "password"),
            ]
        )
        report = report_for(text)
        self.assertTrue(
            any("Successful" in f.message and "compromised" in f.message for f in report.findings)
        )

    def test_accepted_without_failures_is_clean(self):
        text = accepted("10:10:00", "alice", "192.168.1.10")
        report = report_for(text)
        self.assertFalse(any("Successful" in f.message for f in report.findings))
        self.assertTrue(any(f.severity == "info" for f in report.findings))

    def test_success_after_old_failures_not_flagged(self):
        # Failures more than the window before the login do not count.
        text = "\n".join(
            [
                failed("08:00:00", "admin", "203.0.113.45"),
                accepted("10:10:00", "admin", "203.0.113.45", "password"),
            ]
        )
        report = report_for(text)
        self.assertFalse(any("Successful" in f.message for f in report.findings))

    def test_user_enumeration(self):
        text = "\n".join(
            invalid_user(f"10:{minute:02d}:00", user, "203.0.113.45")
            for minute, user in enumerate(
                ["guest", "oracle", "test", "backup", "webadmin"], start=0
            )
        )
        report = report_for(text)
        self.assertTrue(any("enumeration" in f.message for f in report.findings))

    def test_enumeration_below_threshold(self):
        text = "\n".join(
            invalid_user(f"10:{minute:02d}:00", user, "203.0.113.45")
            for minute, user in enumerate(["guest", "oracle", "test", "backup"], start=0)
        )
        report = report_for(text)
        self.assertFalse(any("enumeration" in f.message for f in report.findings))

    def test_root_failed_attempt(self):
        report = report_for(failed("10:00:00", "root", "203.0.113.45"))
        self.assertTrue(any("Root login" in f.message for f in report.findings))

    def test_root_accepted(self):
        report = report_for(accepted("10:00:00", "root", "192.168.1.10", "publickey"))
        self.assertTrue(any("Root login" in f.message for f in report.findings))

    def test_password_accepted_flagged(self):
        report = report_for(accepted("10:00:00", "alice", "192.168.1.10", "password"))
        self.assertTrue(any("Password authentication accepted" in f.message for f in report.findings))

    def test_publickey_only_not_flagged(self):
        report = report_for(accepted("10:00:00", "alice", "192.168.1.10", "publickey"))
        self.assertFalse(any("Password authentication" in f.message for f in report.findings))

    def test_off_hours_login(self):
        report = report_for(accepted("03:12:40", "deploy", "198.51.100.23"))
        self.assertTrue(any("Off-hours" in f.message for f in report.findings))

    def test_daytime_login_not_off_hours(self):
        report = report_for(accepted("10:12:40", "deploy", "198.51.100.23"))
        self.assertFalse(any("Off-hours" in f.message for f in report.findings))

    def test_sudo_failures(self):
        text = "\n".join(
            [
                line(
                    "09:15:22",
                    "pam_unix(sudo:auth): authentication failure; logname=alice "
                    "uid=1000 euid=0 tty=/dev/pts/0 ruser=alice rhost= user=alice",
                    process="sudo",
                ),
                line(
                    "09:20:11",
                    "bob : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/bob ; "
                    "USER=root ; COMMAND=/bin/id",
                    process="sudo",
                ),
            ]
        )
        report = report_for(text)
        self.assertEqual(report.sudo_failures, 2)
        self.assertTrue(any("Sudo authentication" in f.message for f in report.findings))

    def test_password_spraying(self):
        lines = []
        for i, ip in enumerate(["203.0.113.45", "198.51.100.77", "192.0.2.50"]):
            for j in range(2):
                lines.append(failed(f"10:{i * 10 + j * 2:02d}:00", "admin", ip))
        report = report_for("\n".join(lines))
        self.assertTrue(any("spraying" in f.message for f in report.findings))

    def test_spraying_needs_three_ips(self):
        lines = []
        for i, ip in enumerate(["203.0.113.45", "198.51.100.77"]):
            for j in range(3):
                lines.append(failed(f"10:{i * 10 + j * 2:02d}:00", "admin", ip))
        report = report_for("\n".join(lines))
        self.assertFalse(any("spraying" in f.message for f in report.findings))

    def test_clean_log_info_finding(self):
        report = report_for(accepted("10:00:00", "alice", "192.168.1.10"))
        self.assertEqual(report.score, 100)
        self.assertEqual(report.grade, "A")
        self.assertEqual(len(report.findings), 1)
        self.assertEqual(report.findings[0].severity, "info")

    def test_empty_log(self):
        report = report_for("")
        self.assertEqual(report.total_lines, 0)
        self.assertEqual(report.score, 100)
        self.assertEqual(report.grade, "A")
        self.assertTrue(any(f.severity == "info" for f in report.findings))


class TestScoring(unittest.TestCase):
    def test_grade_boundaries(self):
        self.assertEqual(ala.grade_for(100), "A")
        self.assertEqual(ala.grade_for(90), "A")
        self.assertEqual(ala.grade_for(89), "B")
        self.assertEqual(ala.grade_for(80), "B")
        self.assertEqual(ala.grade_for(79), "C")
        self.assertEqual(ala.grade_for(70), "C")
        self.assertEqual(ala.grade_for(69), "D")
        self.assertEqual(ala.grade_for(60), "D")
        self.assertEqual(ala.grade_for(59), "F")
        self.assertEqual(ala.grade_for(0), "F")

    def test_deductions(self):
        # One high (25) and one medium (10): 100 - 35 = 65, grade D.
        text = "\n".join(
            [failed(f"10:{m:02d}:00", f"user{m}", "203.0.113.45") for m in range(0, 25, 5)]
            + [failed("10:30:00", "root", "203.0.113.45")]
        )
        report = report_for(text)
        self.assertEqual(report.score, 65)
        self.assertEqual(report.grade, "D")

    def test_score_floor_zero(self):
        # Many findings at once: the score stops at 0, never negative.
        # Brute force + success-after-failure + spraying (3 high),
        # enumeration + root + password + sudo (4 medium), off-hours (1 low)
        # deduct 25*3 + 10*4 + 3 = 118, so the score floors at 0.
        lines = [
            failed("02:00:00", "admin", "203.0.113.45"),
            failed("02:05:00", "admin", "203.0.113.45"),
            failed("02:10:00", "admin", "198.51.100.77"),
            failed("02:15:00", "admin", "192.0.2.50"),
            failed("02:20:00", "admin", "198.51.100.99"),
            failed("02:25:00", "x1", "203.0.113.45"),
            failed("02:30:00", "x2", "203.0.113.45"),
            failed("02:35:00", "root", "203.0.113.45"),
            invalid_user("02:40:00", "guest", "203.0.113.45"),
            invalid_user("02:41:00", "oracle", "203.0.113.45"),
            invalid_user("02:42:00", "test", "203.0.113.45"),
            invalid_user("02:43:00", "backup", "203.0.113.45"),
            invalid_user("02:44:00", "webadmin", "203.0.113.45"),
            line(
                "02:45:00",
                "pam_unix(sudo:auth): authentication failure; logname=alice "
                "uid=1000 euid=0 tty=/dev/pts/0 ruser=alice rhost= user=alice",
                process="sudo",
            ),
            accepted("02:50:00", "admin", "203.0.113.45", "password"),
        ]
        report = report_for("\n".join(lines))
        self.assertEqual(report.score, 0)
        self.assertEqual(report.grade, "F")

    def test_malformed_lines_skipped_and_counted(self):
        text = "\n".join(
            [
                accepted("10:00:00", "alice", "192.168.1.10"),
                "this is not a log line",
                "Nov 23 10:00:00 webserver",
            ]
        )
        report = report_for(text)
        self.assertEqual(report.total_lines, 3)
        self.assertEqual(report.malformed_lines, 2)
        self.assertEqual(report.parsed_lines, 1)

    def test_top_ips_sorted_by_failed(self):
        text = "\n".join(
            [
                failed("10:00:00", "a", "10.0.0.1"),
                failed("10:01:00", "b", "10.0.0.2"),
                failed("10:02:00", "c", "10.0.0.2"),
                accepted("10:03:00", "alice", "10.0.0.3"),
            ]
        )
        report = report_for(text)
        self.assertEqual(report.top_ips[0]["ip"], "10.0.0.2")
        self.assertEqual(report.top_ips[0]["failed"], 2)


class TestOutputAndCli(unittest.TestCase):
    def test_json_output_shape(self):
        text = "\n".join(
            [failed(f"10:{m:02d}:00", f"user{m}", "203.0.113.45") for m in range(0, 25, 5)]
        )
        report = report_for(text, source="test.log")
        data = report.as_dict()
        self.assertEqual(data["source"], "test.log")
        self.assertIn("counts", data)
        self.assertIn("top_ips", data)
        self.assertIn("score", data)
        self.assertIn("grade", data)
        self.assertIn("findings", data)
        self.assertEqual(data["counts"]["failed_passwords"], 5)
        self.assertEqual(data["counts"]["brute_force_ips"], ["203.0.113.45"])
        self.assertEqual(data["findings"][0]["severity"], "high")
        self.assertIn("fix", data["findings"][0])

    def test_format_report_clean(self):
        report = report_for(accepted("10:00:00", "alice", "192.168.1.10"))
        text = ala.format_report(report)
        self.assertIn("Score: 100/100  Grade: A", text)
        self.assertIn("No failed login attempts", text)

    def test_main_fail_on_high(self):
        text = "\n".join(
            [failed(f"10:{m:02d}:00", f"user{m}", "203.0.113.45") for m in range(0, 25, 5)]
        )
        with redirect_stdout(io.StringIO()):
            self.assertEqual(ala.main(["--log", text, "--fail-on", "high"]), 1)
        with redirect_stdout(io.StringIO()):
            self.assertEqual(ala.main(["--log", text, "--fail-on", "none"]), 0)

    def test_main_fail_on_ignores_lower_severity(self):
        # A medium-only log passes --fail-on high but fails --fail-on medium.
        with redirect_stdout(io.StringIO()):
            self.assertEqual(
                ala.main(["--log", accepted("10:00:00", "alice", "192.168.1.10", "password"), "--fail-on", "high"]),
                0,
            )
        with redirect_stdout(io.StringIO()):
            self.assertEqual(
                ala.main(["--log", accepted("10:00:00", "alice", "192.168.1.10", "password"), "--fail-on", "medium"]),
                1,
            )

    def test_main_json_flag(self):
        out = io.StringIO()
        with redirect_stdout(out):
            code = ala.main(["--log", accepted("10:00:00", "alice", "192.168.1.10"), "--json"])
        self.assertEqual(code, 0)
        data = json.loads(out.getvalue())
        self.assertEqual(data["score"], 100)
        self.assertEqual(data["grade"], "A")

    def test_main_stdin(self):
        old_stdin = sys.stdin
        sys.stdin = io.StringIO(accepted("10:00:00", "alice", "192.168.1.10"))
        try:
            out = io.StringIO()
            with redirect_stdout(out):
                code = ala.main(["-"])
            self.assertEqual(code, 0)
            self.assertIn("Score: 100/100", out.getvalue())
        finally:
            sys.stdin = old_stdin

    def test_main_missing_file_exit_2(self):
        err = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(err):
            code = ala.main(["/nonexistent/auth.log"])
        self.assertEqual(code, 2)
        self.assertIn("could not read", err.getvalue())

    def test_main_log_and_file_together_exit_2(self):
        # argparse's parser.error exits with status 2.
        err = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(err):
            with self.assertRaises(SystemExit) as ctx:
                ala.main(["some.log", "--log", "Nov 23 10:00:00 h sshd[1]: hi"])
        self.assertEqual(ctx.exception.code, 2)

    def test_main_no_input_exit_2(self):
        err = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(err):
            with self.assertRaises(SystemExit) as ctx:
                ala.main([])
        self.assertEqual(ctx.exception.code, 2)

    def test_main_bad_threshold_exit_2(self):
        err = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(err):
            with self.assertRaises(SystemExit) as ctx:
                ala.main(["--log", "x", "--threshold", "0"])
        self.assertEqual(ctx.exception.code, 2)

    def test_main_version(self):
        out = io.StringIO()
        with redirect_stdout(out):
            with self.assertRaises(SystemExit) as ctx:
                ala.main(["--version"])
        self.assertEqual(ctx.exception.code, 0)
        self.assertIn(ala.__version__, out.getvalue())

    def test_sample_log_scores_zero(self):
        # The shipped sample log is a host under active attack.
        sample = os.path.join(ROOT, "examples", "sample-auth.log")
        with open(sample, encoding="utf-8") as handle:
            text = handle.read()
        events, total, malformed = ala.parse_log(text, year=2026)
        report = ala.analyze_log(events, total, malformed)
        self.assertEqual(total, 67)
        self.assertEqual(report.failed_passwords, 15)
        self.assertEqual(report.brute_force_ips, ["203.0.113.45"])
        self.assertEqual(report.score, 0)
        self.assertEqual(report.grade, "F")
        self.assertEqual(len(report.findings), 8)


if __name__ == "__main__":
    unittest.main(verbosity=2)
