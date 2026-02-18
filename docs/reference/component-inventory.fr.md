# Inventaire des composants

Cette page donne une carte rapide du code de production.

## Zones principales

- `brain/cli`: commandes utilisateur (`casm`)
- `brain/core`: logique métier, orchestration, génération de rapports
- `brain/adapters`: pont Python -> binaires Go
- `hands/cmd/*`: outils d'exécution (`probe`, `http_verify`, `dns_enum`)
- `contracts/schemas`: contrats JSON request/response
- `contracts/fixtures`: exemples d'échanges

## Flux type

1. CLI charge un périmètre
2. Core orchestre les étapes
3. Adapters invoquent les outils Go
4. Artefacts écrits dans `runs/<engagement>/<run>/`

## Quand utiliser cette page

- Pour localiser rapidement un module propriétaire
- Pour comprendre qui est responsable d'une fonctionnalité
- Pour préparer une contribution cross-language

Version détaillée: `reference/component-inventory.md`
