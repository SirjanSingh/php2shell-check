# Security Policy

## Scope and intent

`php2shell-check` is a **defensive** tool. It inspects the environment it runs in
(local PHP, version strings, Dockerfiles/compose files, your own running
containers, and your own logs) and reports exposure to the PHP2Shell flaws
(CVE-2026-109618 / CVE-2026-109619).

It intentionally does **not** send exploit traffic and has no URL or blackbox
probe mode. If you want to verify a server you operate, run the tool on that
server (or feed it that server's version/logs). The one remote mode is
`check --ssh-hosts`, for machines you already hold SSH keys for: it runs a fixed,
read-only script over `ssh` (key auth only, your `known_hosts` honoured, host
entries that could be read as ssh options rejected) and writes nothing on the
host. Only ever test systems you own or are explicitly authorized to test.

`rules` only prints or writes rule files; it never contacts a host.

## This is not a substitute for patching

Detection is not prevention. Update PHP to a patched release
(8.5.12 / 8.4.27 / 8.3.36 / 8.2.35) regardless of what this tool reports.

## Reporting a vulnerability in this tool

If you find a security issue in `php2shell-check` itself, please open a
[GitHub issue](https://github.com/SirjanSingh/php2shell-check/issues) for low-risk bugs,
or for anything sensitive, use GitHub's private vulnerability reporting on this
repository. Please do not include working exploit payloads for PHP2Shell in
public issues.

## A note on accuracy

The version/fix data reflects the 2026-10-21 PHP release. The log/Docker
indicators are behavioral detection guidance published by security vendors, not
confirmed atomic indicators of compromise. Always confirm against
[php.net](https://www.php.net/) and your own telemetry.
