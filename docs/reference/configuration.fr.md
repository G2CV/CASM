# Référence de configuration

Le fichier de périmètre contrôle ce que CASM a le droit de faire.

## Fichier principal

- `scopes/scope.yaml`

## Champs importants

- `engagement_id`: identifiant de la campagne
- `allowed_domains`, `allowed_ips`: périmètre autorisé
- `allowed_ports`, `allowed_protocols`: limites techniques
- `seed_targets`: cibles initiales
- `max_rate`, `max_concurrency`: garde-fous de charge
- `per_attempt_timeout_ms`, `tool_timeout_ms`: timeouts
- `http_verify_*`: profil et options de vérification HTTP/TLS
- `dns_enumeration.*`: options DNS passif/actif
- `pdf_branding`, `pdf_diff`: personnalisation des rapports PDF

## Bonne pratique

Toujours commencer en `dry-run`, puis activer l'exécution réelle avec un périmètre minimal.

Version complété: `reference/configuration.md`
