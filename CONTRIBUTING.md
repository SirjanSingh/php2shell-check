# Contributing

Thanks for helping improve `php2shell-check`. This is a small, dependency-free
project and we'd like to keep it that way.

## Ground rules

- **Defensive only.** PRs that add remote exploitation, active blackbox probing
  of hosts, or working exploit payloads will be declined. The tool inspects
  systems the operator controls; it does not attack.
- **Standard library only.** No third-party runtime dependencies. Python 3.9+.
- **Every behavior change needs a test.** See `tests/test_check.py`.
- **Cite sources for detection logic.** New log/Docker indicators must link to a
  public vendor/vendor-neutral advisory in the PR, and the indicator should
  carry its `source` in code (see `LINE_INDICATORS`).

## Developing

```bash
git clone https://github.com/SirjanSingh/php2shell-check
cd php2shell-check
python -m unittest discover tests -v
```

Try your change end-to-end:

```bash
python php2shell_check.py check --version 8.3.10
python php2shell_check.py scan-docker Dockerfile
python php2shell_check.py scan-logs /path/to/log
```

## Pull requests

- Keep PRs focused and small.
- Update `README.md` and `CHANGELOG.md` when behavior changes.
- Make sure CI is green (tests on 3.9/3.11/3.13 + CLI smoke test).
