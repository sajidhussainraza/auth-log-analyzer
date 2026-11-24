# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-23

### Added

- Dependency-free Python CLI that parses a Linux auth log
  (syslog-style sshd, sudo, and PAM lines) and grades the host's
  exposure A-F with a 0-100 score.
- Detection of SSH brute-force attacks (a configurable number of
  failed passwords from one IP inside a sliding time window),
  password spraying (one username tried from three or more IPs),
  user enumeration (probing of usernames that do not exist), root
  login attempts, password authentication being accepted, sudo
  authentication failures, and off-hours logins (00:00-06:00).
- A "successful login after failures from the same IP" check that
  flags a login which may be a compromised account, not a mistyped
  password.
- Plain-language findings with a concrete fix for every issue, a
  per-IP table sorted by failed passwords, and a summary of counts.
- A clean-log note (severity `info`, no deduction) when a log has no
  failed attempts at all, so a quiet host is reported, not hidden.
- Input from a log file, from stdin (`-`), or inline with `--log`;
  machine-readable output (`--json`); a CI gate
  (`--fail-on {high,medium,low,none}`, default `none`); a
  configurable threshold (`--threshold`, default 5) and window
  (`--window-minutes`, default 60); and a `--version` flag.
- Exit codes 0 (pass), 1 (findings at or above `--fail-on`),
  2 (usage or file error).
- Malformed lines are skipped and counted, never fatal: a corrupt
  line does not stop the analysis.
- 52 tests (stdlib `unittest`, no pytest needed), including a test
  that the shipped sample log scores 0/100, grade F.
- A synthetic sample log (`examples/sample-auth.log`, 67 lines) with
  real saved text and JSON output, covering a brute-force IP, a
  successful login after failures, password spraying, user
  enumeration, a root attempt, an off-hours login, and sudo failures.
- Full repository standard: README, CONTRIBUTING.md, Code of Conduct,
  Security policy, issue and pull request templates, CI workflow,
  `.gitignore`, `.editorconfig`, and original SVG banner and logo.

### Fixed

- Nothing yet; this is the first release.

## [Unreleased]

- Nothing yet. See the [roadmap](README.md#roadmap) for what is planned.
