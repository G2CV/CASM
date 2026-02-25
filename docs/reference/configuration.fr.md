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
- `notifications`: publication des résumés d'exécution

## Bloc notifications

`notifications.publishers` accepte une liste d'objets publisher.

Types supportés:

- `webhook`
  - `url` (requis)
  - `timeout_seconds` (optionnel, défaut `10`)
  - `max_retries` (optionnel, défaut `2`)
  - `headers` (optionnel)
- `file`
  - `path` (requis): chemin JSONL pour journaliser les événements

Options d'alerte facultatives dans `notifications.alerts`:

- `min_severity` (défaut `low`)
- `rule_ids` (liste optionnelle)
- `uri_regex` (regex optionnelle)
- `cooldown_minutes` (défaut `0`)
- `max_events` (défaut `50`)
- `include_added` (défaut `true`)
- `include_removed` (défaut `true`)
- `state_path` (défaut `runs/<engagement_id>/alerts_state.json`)

Les erreurs de publication sont journalisées et ne bloquent pas le pipeline de scan.

Exemple:

```yaml
notifications:
  publishers:
    - type: webhook
      url: "https://hooks.slack.com/services/T000/B000/xxxx"
      timeout_seconds: 10
      max_retries: 2
    - type: file
      path: "runs/notifications.jsonl"
  alerts:
    min_severity: "medium"
    cooldown_minutes: 60
    max_events: 25
```

## Bonne pratique

Toujours commencer en `dry-run`, puis activer l'exécution réelle avec un périmètre minimal.

Version complété: `reference/configuration.md`
