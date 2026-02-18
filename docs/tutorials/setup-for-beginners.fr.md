# Installation pour debutants absolus

Si c'est votre première exécution de CASM, suivez cette page de haut en bas. Vous devriez obtenir un scan local fonctionnel en quelques minutes.

> **Prérequis**
> - Shell Linux ou macOS
> - Acces Internet pour installer les dependances

## Versions requises

- Python: 3.11 ou plus recent
- Go: 1.21 ou plus recent

Verifier les versions:

```bash
python3 --version
go version
```

## Installation pas a pas

1. Clonez le repository.
2. Créez et activez un environnement virtuel.
3. Installez les dependances Python et l'entree CLI locale `casm`.
4. Compilez les binaires Go utilises par les commandes de scan.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt -r requirements-dev.txt
# Optionnel (depuis PyPI): python -m pip install g2cv-casm
python -m pip install -e .
make build-hands
```

## Verification de l'installation

```bash
casm run probe --scope scopes/scope.example.yaml --dry-run
make test
```

Si ces deux commandes reussissent, votre environnement local est pret.

Si `casm` est introuvable, réactivez le venv puis exécutez:

```bash
python -m pip install g2cv-casm
# ou, depuis le repository source
python -m pip install -e .
```

## Erreurs d'installation frequentes

| Erreur | Cause | Correctif |
|---|---|---|
| `command not found: go` | Go manquant | installer Go 1.21+ puis rouvrir le shell |
| `No module named brain` | venv non actif | `source .venv/bin/activate` |
| `tool_not_found` | binaires non compiles | lancer `make build-hands` |
| échec SSL/TLS à l'installation | proxy/certificats entreprise | configurer proxy et CA pour pip/go |

Astuce: gardez `.venv` actif dans chaque shell où vous lancez CASM.
