# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | Yes                |
| < 1.0   | No (pre-release)   |

## Reporting a Vulnerability

**Do not open a public GitHub issue for a security problem.**

Email the details to **info@cyberlegends.org** with the subject
`[auth-log-analyzer] Security report`. Include:

- What the issue is and what it affects
- Steps to reproduce it, if you have them
- The version or commit you tested against

You will get an acknowledgement within 7 days, and a fix or a plan for
one within 30 days for confirmed issues. Please do not disclose the
issue publicly until a fix is released.

## What This Tool Does (and Does Not Do)

- Auth Log Analyzer only reads the log file you give it, on your own
  machine. It makes no network calls, never logs in, never submits
  data, and never stores anything.
- It has no dependencies, no network calls, and no telemetry.
- It reads only syslog-style auth log lines (sshd, sudo, PAM) and
  reports counts, source IPs, usernames, and login times from them.
  It does not execute anything from the log, and it cannot see
  attacks that leave no trace in the log.
- A low score is a finding about a host's auth log, not a
  vulnerability in this tool. If a host's log looks wrong, check
  with that host's owner before treating it as a live compromise.
- Auth logs are sensitive: they contain real usernames, IP addresses,
  and login times. Do not paste a real log into a public issue. Redact
  it first, or reproduce the problem with the synthetic log in
  `examples/sample-auth.log`.
