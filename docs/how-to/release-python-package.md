# Release Python Package

This guide covers the release flow for publishing CASM wheels with bundled Go tools.

## Prerequisites

- GitHub Actions workflow file: `.github/workflows/pypi-release.yml`
- PyPI trusted publisher configured for this repo/workflow
- TestPyPI trusted publisher configured for this repo/workflow

## 1) Validate locally

From the repo root:

```bash
source .venv/bin/activate
python scripts/build_bundled_tools.py --clean-platform-dir
python -m build
python -m twine check dist/*
```

Quick smoke test from the built wheel:

```bash
python3 -m venv /tmp/casm-wheel-smoke/.venv
source /tmp/casm-wheel-smoke/.venv/bin/activate
pip install dist/*.whl
casm --help
```

## 2) Stage on TestPyPI

- Push your branch to GitHub.
- Run the `Build and Publish PyPI` workflow manually (`workflow_dispatch`).
- Confirm the `publish-testpypi` job succeeds.

Install test package from TestPyPI:

```bash
pip install \
  --index-url https://test.pypi.org/simple/ \
  --extra-index-url https://pypi.org/simple \
  g2cv-casm
```

## 3) Publish to PyPI

Tag a release and push the tag:

```bash
git tag vX.Y.Z
git push origin vX.Y.Z
```

The same workflow publishes to production PyPI on `v*` tags.

## Notes

- Linux wheels are tagged `manylinux2014_x86_64` for index compatibility.
- macOS wheels are currently built on `macos-14` (arm64).
- If TestPyPI fails with HTTP 400, check verbose upload logs in `publish-testpypi` first.
