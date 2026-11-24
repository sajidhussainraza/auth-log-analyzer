# Contributing to Auth Log Analyzer

Thanks for helping make Auth Log Analyzer better. This is
a small, dependency-free tool, and contributions that keep it that way
are especially welcome.

## Quick steps

1. Fork the repository and clone your fork.
2. Create a branch for your change:
   `git checkout -b fix/describe-the-change`
3. Make the change. Keep the tool Python standard library only; do not
   add third-party dependencies.
4. Add or update tests in `tests/` for any behaviour you change.
5. Run the full suite and make sure all tests pass:
   `python3 tests/run_tests.py`
6. Run a smoke check of the CLI:
   `python3 auth_log_analyzer.py examples/sample-auth.log`
7. Open a pull request describing the change and why it helps. Fill in
   the pull request template.

## What to work on

- A new check for a real auth-log security rule, with tests and a README
  entry in the "What it checks" table.
- Better plain-language wording for a finding or its fix.
- Documentation fixes, typo corrections, and clearer examples.
- Bug reports: include the command you ran, the log lines involved
  (redact real usernames and IP addresses first), and the output you
  got versus what you expected.

## Ground rules

- **No new dependencies.** The whole point of this tool is that it
  runs on a clean machine with only Python 3.10+.
- **No behaviour change without a test.** Every new check or scoring
  change needs a test in `tests/test_auth_log_analyzer.py`.
- **Keep scores honest.** Do not tune deductions to flatter a
  particular site. Deductions are 25 / 10 / 3 per high / medium / low
  finding, and grade bands are A 90+, B 80+, C 70+, D 60+, F below 60.
- **Keep the README truthful.** Document only what the code actually
  does. If you are unsure about a claim, mark it `TODO: verify`
  instead of guessing.
- **Analyse only logs you own or have permission to analyse.** Auth
  logs contain usernames, IP addresses, and login times. Redact them
  before sharing a sample in an issue or a pull request.
- **No secrets, ever.** The tool reads log files locally and makes no
  network calls at all. Never add credentials, tokens, or tracking.
- Follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Reporting a security issue

Do not open a public issue for a security problem. See
[SECURITY.md](SECURITY.md) for how to report it privately.
