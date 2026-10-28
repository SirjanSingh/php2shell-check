# Releasing to PyPI

Publishing is automated with [PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/)
(OIDC) — no API tokens or secrets are stored in the repo. You do the one-time
setup below once; after that every version tag publishes automatically.

## Fastest path: run the setup script

From a machine where `gh` is authenticated with repo-admin scope (your laptop —
**not** the cloud session, whose proxy blocks settings writes):

```bash
./scripts/finish-setup.sh
```

It sets the repo description + topics, creates the `pypi` Actions environment,
and prints the single PyPI step that must be done by hand (detailed below).

## One-time setup (you must do this in your own PyPI account)

1. Create a PyPI account at https://pypi.org and verify your email.
2. Go to **https://pypi.org/manage/account/publishing/** and add a
   **pending publisher** with exactly:
   - PyPI Project Name: `php2shell-check`
   - Owner: `SirjanSingh`
   - Repository name: `php2shell-check`
   - Workflow name: `release.yml`
   - Environment name: `pypi`
3. In GitHub: **Settings → Environments → New environment** named `pypi`
   (optionally add a required reviewer so a human approves each publish).

> **If the repo is ever renamed:** the PyPI publisher matches the repository name, so a
> rename breaks publishing until the publisher on PyPI is updated (Manage project, Publishing).
> The repo was renamed from `shiny-php` to `php2shell-check` after v0.2.0 shipped; update the
> publisher's repository name before tagging the next release.

That's it — no password or token goes anywhere near the repo.

## Cutting a release

1. Bump the version in **one place**: `__version__` in `php2shell_check.py`
   (`pyproject.toml` reads it automatically). Update `CHANGELOG.md`.
2. Commit, then tag and push:
   ```bash
   git commit -am "Release v0.2.0"
   git tag v0.2.0
   git push origin main --tags
   ```
3. The `release.yml` workflow builds, runs `twine check`, and publishes to PyPI.
4. Verify:
   ```bash
   pipx install php2shell-check        # or: pip install php2shell-check
   php2shell-check --version
   ```

## Testing the build locally first (optional)

```bash
python -m pip install --upgrade build twine
python -m build
python -m twine check dist/*
```

## Why not npm?

This is a Python CLI, so PyPI is its native registry (`pip` / `pipx` read it).
npm hosts Node packages; shipping a Python tool there would require a wrapper
that just shells out to `python`, which adds maintenance for no real benefit.
If a Node-ecosystem distribution is ever needed, open an issue to discuss.
