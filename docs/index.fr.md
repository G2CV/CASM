# Documentation CASM

CASM (Continuous Attack Surface Monitoring) est un système de sécurité à double runtime:

- Python (`brain/`) orchestre la politique de périmètre, les flux de travail, la normalisation des preuves et la génération de rapports.
- Go (`hands/`) exécute les opérations réseau (probe TCP, vérification HTTP, énumération DNS) de façon sûre et déterministe.

Cette documentation est organisée pour MkDocs et pour les lecteurs qui découvrent le projet.

## Carte de la documentation

- Architecture
  - `docs/architecture/overview.fr.md`
  - `docs/architecture/data-flow.fr.md`
  - `docs/architecture/python-go-bridge.fr.md`
- Tutoriels
  - `docs/tutorials/setup-for-beginners.fr.md`
  - `docs/tutorials/tutorial-1-hello-world.fr.md`
  - `docs/tutorials/tutorial-2-real-use-case.fr.md`
  - `docs/tutorials/tutorial-3-advanced-integration.fr.md`
- Guides pratiques
  - `docs/how-to/add-python-module.fr.md`
  - `docs/how-to/add-go-package.fr.md`
  - `docs/how-to/extend-bridge.fr.md`
  - `docs/how-to/debug-cross-language.fr.md`
  - `docs/how-to/testing.fr.md`
  - `docs/how-to/profile-performance.fr.md`
  - `docs/how-to/contributing.fr.md`
- Référence
  - `docs/reference/component-inventory.fr.md`
  - `docs/reference/data-structures.fr.md`
  - `docs/reference/python-api.fr.md`
  - `docs/reference/go-api.fr.md`
  - `docs/reference/function-catalog.fr.md`
  - `docs/reference/cli.fr.md`
  - `docs/reference/configuration.fr.md`
  - `docs/reference/glossary.fr.md`
- Explications
  - `docs/explanation/design-decisions.fr.md`
  - `docs/explanation/trade-offs.fr.md`
  - `docs/explanation/security-model.fr.md`
  - `docs/explanation/performance.fr.md`

## Parcours recommandé

1. Commencez par les pages d'architecture.
2. Exécutez le Tutoriel 1, puis le Tutoriel 2.
3. Utilisez la référence pendant l'implémentation.
4. Utilisez les pages d'explication pour le contexte et les compromis.

## Informations projet

- Prérequis Python: `>=3.11` (`pyproject.toml`)
- Prérequis Go: `1.21` (`hands/go.mod`)
- Artefacts de sortie principaux:
  - `targets.jsonl`
  - `evidence.jsonl`
  - `results.sarif`
  - `report.md`
  - `report.pdf` (optionnel)

> Astuce: Pour une première prise en main, allez directement sur `docs/tutorials/tutorial-1-hello-world.fr.md`.
