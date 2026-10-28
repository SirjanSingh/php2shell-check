#!/usr/bin/env bash
#
# One-time maintainer setup for the php2shell-check repo.
#
# Run this from a machine where the GitHub CLI (`gh`) is authenticated with
# repo-admin scope — e.g. your laptop (`gh auth login` first). It is NOT meant
# to run from the cloud session, whose proxy blocks repository-settings writes.
#
# Idempotent: safe to re-run.
set -euo pipefail

REPO="${REPO:-SirjanSingh/php2shell-check}"

echo "==> Setting repository description and topics on $REPO"
gh repo edit "$REPO" \
  --description "Defensive checker, preventer & log scanner for the PHP2Shell RCE flaws (CVE-2026-109618 / CVE-2026-109619). Zero dependencies, stdlib-only, no remote probing." \
  --add-topic php \
  --add-topic security \
  --add-topic cve \
  --add-topic php2shell \
  --add-topic rce \
  --add-topic vulnerability-scanner \
  --add-topic cve-2026-109618 \
  --add-topic cve-2026-109619

echo "==> Creating the 'pypi' Actions environment used by release.yml"
gh api -X PUT "repos/$REPO/environments/pypi" >/dev/null
echo "    done (optional: add required reviewers under Settings -> Environments)"

cat <<'NOTE'

==> MANUAL step on PyPI (cannot be automated with gh):
    1. Sign in / sign up at https://pypi.org
    2. Go to https://pypi.org/manage/account/publishing/ and add a
       pending publisher with EXACTLY:
         PyPI Project Name: php2shell-check
         Owner:             SirjanSingh
         Repository name:   php2shell-check
         Workflow name:     release.yml
         Environment name:  pypi

==> Then cut the first release (publishes to PyPI automatically):
       git tag v0.1.0 && git push origin v0.1.0

    Verify afterwards:
       pipx install php2shell-check && php2shell-check --version
NOTE
