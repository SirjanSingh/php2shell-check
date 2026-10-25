# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.1.0] - 2026-10-26

First release on PyPI (`pipx install php2shell-check`).

### Added
- `check` (detector) and `harden` (preventer) for the PHP2Shell RCE flaws
  CVE-2026-109618 and CVE-2026-109619.
- `check --inventory FILE` — offline fleet check from a list of `label version`
  lines (no network, no SSH).
- `check --sarif` / `scan-logs --sarif` — SARIF 2.1.0 output for GitHub code
  scanning.
- `scan-docker` — assess PHP base-image tags in Dockerfiles/compose files, and
  (with `--running`) read PHP versions from running containers. Branch-only tags
  (e.g. `php:8.1`, `php:8.4`) are classified distinctly from pinned tags.
- `scan-logs` — read-only detection of PHP2Shell exploitation *attempts* in web
  and PHP logs, using vendor-published indicators (each tagged with its source).
- Packaging: `pip`/`pipx` installable with a `php2shell-check` entry point;
  version single-sourced from the module; SPDX license metadata.
- Automated PyPI publishing via Trusted Publishing (`release.yml`) on version
  tags, documented in `RELEASING.md`.
- Community health files, CI (Python 3.9/3.11/3.13 + CLI smoke test + package
  build).
