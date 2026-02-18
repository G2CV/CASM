# Tutoriel 1: Hello World (5 min)

> **Prérequis**
> - Terminal macOS/Linux
> - Python 3.11+
> - Go 1.21+

## Objectif

Executer votre premier scan CASM en mode dry-run et inspecter les artefacts generes.

## Étapes

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt -r requirements-dev.txt
# Optionnel (depuis PyPI): python -m pip install g2cv-casm
python -m pip install -e .
make build-hands
make test
casm run probe --scope scopes/scope.example.yaml --dry-run
```

Comportement attendu:

- La commande se termine avec succes.
- Aucun probing réseau n'est exécute (`dry_run=true`).
- Un dossier de run est cree sous `runs/eng-123/<run_id>/`.

Inspecter la sortie:

```bash
ls runs/eng-123
```

Attention: ne desactivez pas les controles ScopeGuard pour les premiers essais.
