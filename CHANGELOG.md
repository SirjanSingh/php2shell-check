# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Restart awareness in `check` (Linux): flags `php*` / `mod_php` Apache processes
  whose binary or `libphp` was replaced on disk, i.e. an upgrade that is installed
  but not running. Counts as a failure; reported in human, JSON and SARIF output.
  `--no-restart-check` skips it.
- `rules` — ready-to-paste ModSecurity, Sigma and Suricata rules generated from
  the `scan-logs` indicators. Detect-only by default; `--block` denies/drops only
  the specific high-severity rules. Each file carries the body-inspection-limit
  caveat and its sources.
- `check --ssh-hosts FILE` (`--ssh-jobs N`) — fleet check over `ssh` for hosts you
  hold keys for. Pipes one fixed read-only probe on stdin; key auth only; host
  entries that could be read as ssh options are rejected; remote output is
  sanitised.
- `--fail-on high|medium|low|none` on `check`, `scan-logs` and `scan-docker` to
  choose which findings fail the run. Default exit codes are unchanged.
- Config-posture report for affected installs: `session.upload_progress.*`,
  `post_max_size`, `memory_limit` (and `fatal_error_backtraces` on 8.5) read from
  `php -i`, now including `php-fpm -i`. Shown as temporary exposure reduction only.
- README: copy-paste GitHub Action that gates CI on PHP2Shell.

### Changed
- `check` JSON gains `config`, `stale_processes` and `restart_check_note`;
  existing keys are unchanged.

### Fixed
- README's GitHub Action example used `scan-docker --sarif`, which does not exist.

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
