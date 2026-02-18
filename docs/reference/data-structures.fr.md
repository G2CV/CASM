# Référence des structures de données

CASM s'appuie sur quelques objets centraux:

- `Scope`: politique d'autorisation
- `ToolRequest` / `ToolResult`: contrat d'exécution d'un outil
- `Finding`: constat sécurité normalise
- `Evidence`: evenement brut, horodate et exploitable

## Artefacts de run

- `targets.jsonl`: inventaire des cibles
- `evidence.jsonl`: journal d'evenements
- `results.sarif`: constats pour CI/automatisation
- `report.md` / `report.pdf`: vues humaines

## Règles de cohérence

- IDs stables (`target_id`, `attempt_id`, fingerprints)
- URL canonicales pour limiter le bruit de diff
- schéma version explicite dans les sorties

Version détaillée: `reference/data-structures.md`
