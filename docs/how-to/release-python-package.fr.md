# Publier le package Python

Ce guide decrit le flux de release pour publier les wheels CASM avec les outils Go embarques.

## Prerequis

- Workflow GitHub Actions: `.github/workflows/pypi-release.yml`
- Trusted publisher PyPI configure pour ce repo/workflow
- Trusted publisher TestPyPI configure pour ce repo/workflow

## 1) Validation locale

Depuis la racine du repo:

```bash
source .venv/bin/activate
python scripts/build_bundled_tools.py --clean-platform-dir
python -m build
python -m twine check dist/*
```

Smoke test rapide depuis la wheel construite:

```bash
python3 -m venv /tmp/casm-wheel-smoke/.venv
source /tmp/casm-wheel-smoke/.venv/bin/activate
pip install dist/*.whl
casm --help
```

## 2) Validation sur TestPyPI

- Push de la branche sur GitHub.
- Lancer le workflow `Build and Publish PyPI` en manuel (`workflow_dispatch`).
- Verifier que le job `publish-testpypi` passe.

Installer depuis TestPyPI:

```bash
pip install \
  --index-url https://test.pypi.org/simple/ \
  --extra-index-url https://pypi.org/simple \
  g2cv-casm
```

## 3) Publication sur PyPI

Creer un tag de release puis le pousser:

```bash
git tag vX.Y.Z
git push origin vX.Y.Z
```

Le meme workflow publie sur PyPI quand le tag correspond a `v*`.

## Notes

- Les wheels Linux sont tagues `manylinux2014_x86_64`.
- Les wheels macOS sont actuellement construites sur `macos-14` (arm64).
- En cas d'erreur HTTP 400 sur TestPyPI, verifier d'abord les logs verbeux du job `publish-testpypi`.
