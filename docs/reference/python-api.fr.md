# Référence API Python (annotée)

Cette page donne une carte pratique des fonctions Python de production.

## Entrée principale

- `brain/cli/casm.py`: parsing CLI et routage vers les commandes

## Modules core critiques

- `orchestrator.py`: flux probe standard
- `unified.py`: flux unifié probe/http/dns + fusion des artefacts
- `report.py` / `pdf_report.py`: génération de rapports
- `scope.py`: parsing du périmètre + enforcement de politique

## Quand utiliser cette référence

- retrouver rapidement une fonction/méthode
- comprendre les side effects par module
- préparer une modification cross-module

Version détaillée: `reference/python-api.md`
