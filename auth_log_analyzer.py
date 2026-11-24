#!/usr/bin/env python3
"""Auth Log Analyzer: spot brute-force attacks in a Linux auth log.

A dependency-free Python CLI. It parses syslog-style auth log lines
(sshd, sudo, PAM), detects SSH brute-force attacks, password spraying,
user enumeration, suspicious successful logins, and other signs of a
host under attack, and grades the host's exposure A-F. Every finding
comes with a plain-language fix.

Usage:
    python3 auth_log_analyzer.py /var/log/auth.log
    python3 auth_log_analyzer.py auth.log --threshold 10 --window-minutes 30
    cat auth.log | python3 auth_log_analyzer.py -
    python3 auth_log_analyzer.py --log "Nov 23 10:15:02 host sshd[1234]: Failed password for root from 203.0.113.45 port 22 ssh2"
    python3 auth_log_analyzer.py auth.log --json --fail-on high

Exit codes: 0 = pass, 1 = findings at or above --fail-on, 2 = usage/parse error.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta

__version__ = "1.0.0"
DEFAULT_THRESHOLD = 5
DEFAULT_WINDOW_MINUTES = 60
OFF_HOURS_START = 0
OFF_HOURS_END = 6
ENUMERATION_MIN_USERS = 5
SPRAY_MIN_IPS = 3

SEVERITY_DEDUCTION = {"high": 25, "medium": 10, "low": 3, "info": 0}
SEVERITY_ORDER = {"high": 3, "medium": 2, "low": 1, "info": 0}

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

# Syslog prefix: "Nov 23 10:15:02 hostname sshd[1234]: " (the process
# part may also be "sshd:" without a PID, or "sudo:" / "systemd-logind:").
SYSLOG_RE = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<process>[a-zA-Z0-9_.\-]+)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)

FAILED_PASSWORD_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+ ssh2"
)
FAILED_PUBLICKEY_RE = re.compile(
    r"Failed publickey for (?:invalid user )?(?P<user>\S+) from "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+ ssh2"
)
ACCEPTED_RE = re.compile(
    r"Accepted (?P<method>password|publickey) for (?P<user>\S+) from "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+ ssh2"
)
INVALID_USER_RE = re.compile(
    r"Invalid user (?P<user>\S+) from "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+"
)
CONNECTION_CLOSED_RE = re.compile(
    r"Connection closed by (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+"
)
DISCONNECTED_RE = re.compile(
    r"Disconnected from (?:invalid user \S+ |user \S+ )?(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+"
)
SUDO_AUTH_FAILURE_RE = re.compile(
    r"pam_unix\(sudo:auth\): authentication failure; .* user=(?P<user>\S+)"
)
SUDO_NOT_IN_SUDOERS_RE = re.compile(
    r"(?P<user>\S+) : user NOT in sudoers ; .*"
)
PAM_AUTH_FAILURE_RE = re.compile(
    r"pam_unix\((?P<service>[a-zA-Z0-9_\-]+):auth\): authentication failure;"
    r".* rhost=(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) user=(?P<user>\S+)"
)


@dataclass
class Event:
    """One parsed auth log event."""

    kind: str  # failed_password, failed_publickey, accepted, invalid_user,
    #          connection_closed, disconnected, sudo_failure, not_in_sudoers
    time: datetime
    ip: str | None = None
    user: str | None = None
    method: str | None = None  # "password" or "publickey", for accepted events


@dataclass
class Finding:
    """One problem found, with the fix in plain language."""

    severity: str  # "high" | "medium" | "low" | "info"
    source: str
    message: str
    fix: str

    def as_dict(self) -> dict:
        return {
            "severity": self.severity,
            "source": self.source,
            "message": self.message,
            "fix": self.fix,
        }


@dataclass
class Report:
    """The full result of one log analysis."""

    source: str | None
    total_lines: int = 0
    parsed_lines: int = 0
    malformed_lines: int = 0
    failed_passwords: int = 0
    failed_publickeys: int = 0
    accepted_logins: int = 0
    accepted_passwords: int = 0
    accepted_publickeys: int = 0
    invalid_user_attempts: int = 0
    sudo_failures: int = 0
    unique_ips: int = 0
    brute_force_ips: list[str] = field(default_factory=list)
    top_ips: list[dict] = field(default_factory=list)
    score: int = 100
    grade: str = "A"
    findings: list[Finding] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "source": self.source,
            "counts": {
                "total_lines": self.total_lines,
                "parsed_lines": self.parsed_lines,
                "malformed_lines": self.malformed_lines,
                "failed_passwords": self.failed_passwords,
                "failed_publickeys": self.failed_publickeys,
                "accepted_logins": self.accepted_logins,
                "accepted_passwords": self.accepted_passwords,
                "accepted_publickeys": self.accepted_publickeys,
                "invalid_user_attempts": self.invalid_user_attempts,
                "sudo_failures": self.sudo_failures,
                "unique_ips": self.unique_ips,
                "brute_force_ips": self.brute_force_ips,
            },
            "top_ips": self.top_ips,
            "score": self.score,
            "grade": self.grade,
            "findings": [f.as_dict() for f in self.findings],
        }


def grade_for(score: int) -> str:
    """Convert a 0-100 score to an A-F grade."""
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def parse_line(line: str, year: int | None = None) -> Event | None:
    """Parse one syslog auth log line into an Event, or None.

    Returns None for lines that do not match the syslog prefix at all
    (malformed) and for lines whose message is a kind this tool does
    not track (session open/close notices, "Connection closed" with no
    IP, and similar). Callers count the first kind as malformed; the
    second kind is a recognised line with nothing to record.
    """
    match = SYSLOG_RE.match(line)
    if not match:
        return None
    month = MONTHS.get(match.group("month"))
    if month is None:
        return None
    try:
        day = int(match.group("day"))
        hour, minute, second = (int(part) for part in match.group("time").split(":"))
        stamp = datetime(year or datetime.now().year, month, day, hour, minute, second)
    except ValueError:
        return None
    message = match.group("message")

    if (m := FAILED_PASSWORD_RE.search(message)) is not None:
        return Event("failed_password", stamp, ip=m.group("ip"), user=m.group("user"))
    if (m := FAILED_PUBLICKEY_RE.search(message)) is not None:
        return Event("failed_publickey", stamp, ip=m.group("ip"), user=m.group("user"))
    if (m := ACCEPTED_RE.search(message)) is not None:
        return Event(
            "accepted", stamp, ip=m.group("ip"), user=m.group("user"),
            method=m.group("method"),
        )
    if (m := INVALID_USER_RE.search(message)) is not None:
        return Event("invalid_user", stamp, ip=m.group("ip"), user=m.group("user"))
    if (m := CONNECTION_CLOSED_RE.search(message)) is not None:
        return Event("connection_closed", stamp, ip=m.group("ip"))
    if (m := DISCONNECTED_RE.search(message)) is not None:
        return Event("disconnected", stamp, ip=m.group("ip"))
    if (m := SUDO_AUTH_FAILURE_RE.search(message)) is not None:
        return Event("sudo_failure", stamp, user=m.group("user"))
    if (m := SUDO_NOT_IN_SUDOERS_RE.search(message)) is not None:
        return Event("sudo_failure", stamp, user=m.group("user"))
    if (m := PAM_AUTH_FAILURE_RE.search(message)) is not None:
        return Event(
            "failed_password", stamp, ip=m.group("ip"), user=m.group("user")
        )
    return Event("other", stamp)


def parse_log(text: str, year: int | None = None) -> tuple[list[Event], int, int]:
    """Parse a whole log into events.

    Returns (events, total_lines, malformed_lines). Lines that do not
    match the syslog prefix are skipped and counted as malformed;
    recognised lines with an untracked message are counted as parsed
    but produce no event.
    """
    events: list[Event] = []
    total = 0
    malformed = 0
    for raw in text.splitlines():
        if not raw.strip():
            continue
        total += 1
        event = parse_line(raw, year=year)
        if event is None:
            malformed += 1
            continue
        if event.kind != "other":
            events.append(event)
    return events, total, malformed


def _max_in_window(times: list[datetime], window: timedelta) -> tuple[int, datetime, datetime]:
    """Largest count of times inside any sliding window, with its span.

    ``times`` must be sorted. Returns (count, first, last) of the
    busiest window.
    """
    best = 0
    best_start = best_end = None
    start = 0
    for end, moment in enumerate(times):
        while moment - times[start] > window:
            start += 1
        count = end - start + 1
        if count > best:
            best = count
            best_start, best_end = times[start], moment
    if best_start is None:
        return 0, times[0], times[0]
    return best, best_start, best_end


def analyze_log(
    events: list[Event],
    total_lines: int,
    malformed_lines: int,
    source: str | None = None,
    threshold: int = DEFAULT_THRESHOLD,
    window_minutes: int = DEFAULT_WINDOW_MINUTES,
) -> Report:
    """Grade an auth log from its parsed events.

    This is a pure function of its inputs, so it is easy to test
    offline with synthetic events.
    """
    window = timedelta(minutes=window_minutes)
    findings: list[Finding] = []

    failed = [e for e in events if e.kind == "failed_password"]
    failed_keys = [e for e in events if e.kind == "failed_publickey"]
    accepted = [e for e in events if e.kind == "accepted"]
    invalid = [e for e in events if e.kind == "invalid_user"]
    sudo_failures = [e for e in events if e.kind == "sudo_failure"]

    # Invalid-user lines that also appear as "Failed password for
    # invalid user ..." are counted once, as a failed password; the
    # "Invalid user ..." line itself is the enumeration signal.
    invalid_users = {e.user for e in invalid if e.user}
    failed_by_ip: dict[str, list[Event]] = {}
    for event in failed:
        failed_by_ip.setdefault(event.ip or "", []).append(event)
    accepted_by_ip: dict[str, list[Event]] = {}
    for event in accepted:
        accepted_by_ip.setdefault(event.ip or "", []).append(event)
    failed_ips_by_user: dict[str, set[str]] = {}
    for event in failed:
        if event.user:
            failed_ips_by_user.setdefault(event.user, set()).add(event.ip or "")

    all_ips = {
        e.ip for e in events if e.ip
    }

    # --- Brute force: threshold or more failed passwords from one IP
    # inside the window ---------------------------------------------------
    brute_force_ips: list[str] = []
    for ip in sorted(failed_by_ip):
        times = sorted(e.time for e in failed_by_ip[ip])
        count, start, end = _max_in_window(times, window)
        if count >= threshold:
            brute_force_ips.append(ip)
            findings.append(
                Finding(
                    "high",
                    ip,
                    f"Brute-force attack from {ip}: {count} failed "
                    f"passwords between {start.strftime('%H:%M')} and "
                    f"{end.strftime('%H:%M')} ({window_minutes} minute "
                    "window).",
                    f"Block {ip} at the firewall (fail2ban or an "
                    "iptables rule), check whether any account it tried "
                    "was compromised, and move SSH to key-only "
                    "authentication.",
                )
            )

    # --- Successful login after failures from the same IP ----------------
    # A login that follows failed attempts from the same address may be
    # the attacker getting in, not a user mistyping a password.
    for event in accepted:
        ip = event.ip or ""
        earlier = [
            e for e in failed_by_ip.get(ip, [])
            if timedelta(0) <= event.time - e.time <= window
        ]
        if earlier:
            findings.append(
                Finding(
                    "high",
                    ip,
                    f"Successful {event.method} login for "
                    f"{event.user} from {ip} at "
                    f"{event.time.strftime('%H:%M')} came after "
                    f"{len(earlier)} failed password attempt(s) from "
                    "the same IP in the previous "
                    f"{window_minutes} minutes. This may be a "
                    "compromised account.",
                    f"Treat {event.user}'s account as possibly "
                    "compromised: force a password reset, review what "
                    f"that session did, and revoke any keys or sessions "
                    "created by it.",
                )
            )

    # --- Password spraying: one username, many source IPs ----------------
    for user in sorted(failed_ips_by_user):
        ips = failed_ips_by_user[user]
        total_for_user = sum(
            1 for e in failed if e.user == user
        )
        if len(ips) >= SPRAY_MIN_IPS and total_for_user >= threshold:
            findings.append(
                Finding(
                    "high",
                    user,
                    f"Password spraying against {user}: "
                    f"{total_for_user} failed passwords from "
                    f"{len(ips)} different IPs ({', '.join(sorted(ips))}). "
                    "One password is being tried against one account "
                    "from many addresses.",
                    f"Lock or rotate the {user} account, check it for "
                    "unauthorised changes, and rate-limit logins per "
                    "account as well as per IP.",
                )
            )

    # --- User enumeration: many "Invalid user" attempts -------------------
    if len(invalid_users) >= ENUMERATION_MIN_USERS:
        findings.append(
            Finding(
                "medium",
                "sshd",
                f"User enumeration: {len(invalid)} attempts probed "
                f"{len(invalid_users)} usernames that do not exist "
                f"({', '.join(sorted(invalid_users))}). An attacker is "
                "mapping which accounts exist on this host.",
                "Do not reveal whether a username exists: keep sshd's "
                "default behaviour, disable password authentication, "
                "and block the probing IPs.",
            )
        )

    # --- Root login attempts ----------------------------------------------
    root_failed = [e for e in failed if e.user == "root"]
    root_accepted = [e for e in accepted if e.user == "root"]
    if root_failed or root_accepted:
        findings.append(
            Finding(
                "medium",
                "root",
                f"Root login attempts: {len(root_failed)} failed and "
                f"{len(root_accepted)} accepted. Direct root login is "
                "the first thing an attacker tries.",
                "Set PermitRootLogin no in sshd_config and log in as a "
                "normal user, then use sudo. Rotate the root password "
                "if any root login succeeded.",
            )
        )

    # --- Password authentication accepted ---------------------------------
    password_accepted = [e for e in accepted if e.method == "password"]
    if password_accepted:
        users = sorted({e.user for e in password_accepted})
        findings.append(
            Finding(
                "medium",
                "sshd",
                f"Password authentication accepted {len(password_accepted)} "
                f"time(s) ({', '.join(users)}). Passwords can be "
                "guessed; SSH keys cannot.",
                "Move to key-only authentication: set "
                "PasswordAuthentication no in sshd_config and give "
                "every user an SSH key.",
            )
        )

    # --- Sudo authentication failures --------------------------------------
    if sudo_failures:
        users = sorted({e.user for e in sudo_failures if e.user})
        findings.append(
            Finding(
                "medium",
                "sudo",
                f"Sudo authentication failures: {len(sudo_failures)} "
                f"failed attempt(s)"
                + (f" for {', '.join(users)}" if users else "")
                + ". Somebody is trying to escalate to root.",
                "Check who was at the keyboard for each failure, "
                "review sudoers for accounts that should not have "
                "sudo, and alert on repeated sudo failures.",
            )
        )

    # --- Off-hours logins --------------------------------------------------
    off_hours = [
        e for e in accepted
        if OFF_HOURS_START <= e.time.hour < OFF_HOURS_END
    ]
    if off_hours:
        details = ", ".join(
            f"{e.user} from {e.ip} at {e.time.strftime('%H:%M')}"
            for e in off_hours
        )
        findings.append(
            Finding(
                "low",
                "sshd",
                f"Off-hours logins: {len(off_hours)} accepted login(s) "
                f"between {OFF_HOURS_START:02d}:00 and "
                f"{OFF_HOURS_END:02d}:00 ({details}). Logins at this "
                "hour deserve a second look.",
                "Confirm each off-hours login was expected (on-call "
                "work, a scheduled job, a different timezone). If not, "
                "treat the account as possibly compromised.",
            )
        )

    # --- Clean log: no failed attempts at all ------------------------------
    if not failed and not invalid and not sudo_failures:
        findings.append(
            Finding(
                "info",
                "log",
                "No failed login attempts at all in this log: no failed "
                "passwords, no invalid-user probes, and no sudo "
                "failures. Either the host is quiet, or the log covers "
                "a short period.",
                "Keep watching: a clean log is good news, not a reason "
                "to stop checking. Run this tool on a regular schedule.",
            )
        )

    # --- Per-IP table -------------------------------------------------------
    ip_rows: dict[str, dict] = {}
    for event in events:
        if not event.ip:
            continue
        row = ip_rows.setdefault(
            event.ip,
            {"ip": event.ip, "failed": 0, "accepted": 0, "invalid_users": 0},
        )
        if event.kind == "failed_password":
            row["failed"] += 1
        elif event.kind == "accepted":
            row["accepted"] += 1
        elif event.kind == "invalid_user":
            row["invalid_users"] += 1
    top_ips = sorted(
        ip_rows.values(),
        key=lambda row: (-row["failed"], -row["accepted"], row["ip"]),
    )

    score = 100
    for finding in findings:
        score -= SEVERITY_DEDUCTION[finding.severity]
    score = max(0, score)

    return Report(
        source=source,
        total_lines=total_lines,
        parsed_lines=total_lines - malformed_lines,
        malformed_lines=malformed_lines,
        failed_passwords=len(failed),
        failed_publickeys=len(failed_keys),
        accepted_logins=len(accepted),
        accepted_passwords=len(password_accepted),
        accepted_publickeys=len([e for e in accepted if e.method == "publickey"]),
        invalid_user_attempts=len(invalid),
        sudo_failures=len(sudo_failures),
        unique_ips=len(all_ips),
        brute_force_ips=brute_force_ips,
        top_ips=top_ips,
        score=score,
        grade=grade_for(score),
        findings=findings,
    )


def format_report(report: Report) -> str:
    """Render a report as plain text."""
    lines: list[str] = []
    title = report.source or "Auth log analysis"
    lines.append(f"Auth log report: {title}")
    lines.append(f"Score: {report.score}/100  Grade: {report.grade}")
    lines.append("")
    lines.append("Summary:")
    lines.append(f"  Lines parsed: {report.total_lines}")
    if report.malformed_lines:
        lines.append(f"  Malformed lines skipped: {report.malformed_lines}")
    lines.append(f"  Failed passwords: {report.failed_passwords}")
    lines.append(f"  Failed public keys: {report.failed_publickeys}")
    lines.append(
        f"  Accepted logins: {report.accepted_logins} "
        f"(password: {report.accepted_passwords}, "
        f"publickey: {report.accepted_publickeys})"
    )
    lines.append(f"  Invalid user attempts: {report.invalid_user_attempts}")
    lines.append(f"  Sudo authentication failures: {report.sudo_failures}")
    lines.append(f"  Unique source IPs: {report.unique_ips}")
    lines.append(f"  Brute-force IPs: {len(report.brute_force_ips)}")
    if report.top_ips:
        lines.append("")
        lines.append("Top source IPs by failed passwords:")
        for row in report.top_ips:
            if row["failed"] == 0 and row["accepted"] == 0 and row["invalid_users"] == 0:
                continue
            lines.append(
                f"  {row['ip']:<16} failed: {row['failed']:<3} "
                f"accepted: {row['accepted']:<3} "
                f"invalid users: {row['invalid_users']}"
            )
    if report.findings:
        lines.append("")
        lines.append(f"Findings ({len(report.findings)}):")
        for finding in report.findings:
            lines.append(
                f"  [{finding.severity.upper()}] {finding.source}: "
                f"{finding.message}"
            )
            lines.append(f"        Fix: {finding.fix}")
    else:
        lines.append("")
        lines.append(
            "No findings: no brute force, no spraying, no enumeration, "
            "no root attempts, and no password logins in this log."
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="auth_log_analyzer.py",
        description=(
            "Analyse a Linux auth log (sshd, sudo, PAM), detect "
            "brute-force attacks and suspicious logins, and grade the "
            "host's exposure A-F."
        ),
    )
    parser.add_argument(
        "logfile",
        nargs="?",
        help="Path to the auth log file, e.g. /var/log/auth.log. Use '-' to read from stdin.",
    )
    parser.add_argument(
        "--log",
        metavar="TEXT",
        help="Analyse log text given on the command line instead of a file, e.g. --log 'Nov 23 10:15:02 host sshd[1234]: Failed password for root from 203.0.113.45 port 22 ssh2'. Useful for tests.",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=DEFAULT_THRESHOLD,
        metavar="N",
        help=f"Failed passwords from one IP (or one user) that flag brute force / spraying. Default: {DEFAULT_THRESHOLD}.",
    )
    parser.add_argument(
        "--window-minutes",
        type=int,
        default=DEFAULT_WINDOW_MINUTES,
        metavar="N",
        help=f"Minutes the failed attempts must fall inside to count as an attack. Default: {DEFAULT_WINDOW_MINUTES}.",
    )
    parser.add_argument("--json", action="store_true", help="Print the report as JSON instead of plain text.")
    parser.add_argument(
        "--fail-on",
        choices=["high", "medium", "low", "none"],
        default="none",
        help="Exit 1 when findings at or above this severity are found. Default: none.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)

    try:
        if args.threshold < 1:
            parser.error("--threshold must be at least 1")
        if args.window_minutes < 1:
            parser.error("--window-minutes must be at least 1")
        if args.log is not None:
            if args.logfile is not None:
                parser.error("--log and a log file cannot be used together")
            text = args.log
            source = "inline log text"
        elif args.logfile is not None:
            if args.logfile == "-":
                text = sys.stdin.read()
                source = "stdin"
            else:
                try:
                    with open(args.logfile, encoding="utf-8", errors="replace") as handle:
                        text = handle.read()
                except OSError as exc:
                    raise ValueError(f"could not read {args.logfile} ({exc})") from exc
                source = args.logfile
        else:
            parser.error("Give a log file to analyse, or log text with --log")
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    events, total, malformed = parse_log(text)
    report = analyze_log(
        events,
        total,
        malformed,
        source=source,
        threshold=args.threshold,
        window_minutes=args.window_minutes,
    )

    if args.json:
        print(json.dumps(report.as_dict(), indent=2))
    else:
        print(format_report(report))

    if args.fail_on != "none":
        threshold_order = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[f.severity] >= threshold_order for f in report.findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
