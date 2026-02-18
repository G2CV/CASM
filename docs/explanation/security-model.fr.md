# Modèle de sécurité et menaces

## Contrôles de sécurité principaux

- Modèle de périmètre axé sur l'autorisation (domaines/IPs/ports/protocoles).
- Comportement dry-run par défaut.
- Codes de blocage déterministes.
- Gardes-fous de débit et de concurrence.
- Rédaction avant persistance.

## Menaces et mitigations

| Menace | Mitigation |
|---|---|
| Scan hors périmètre accidentel | checks `ScopeGuard` avant invocation outil |
| Charge de scan excessive | `max_rate`, `max_concurrency`, limites de timeout |
| Fuite de secrets dans artefacts | `redaction.py` + persistance de logs rédigés |
| Faux diffs non déterministes | canonical URL + fingerprint stables |
| Propagation crash outil | mapping adapter vers blocked reasons |

## Opérations sensibles

Attention: `http_verify_tls_insecure_skip_verify=true` désactive la validation certificat. À utiliser uniquement en laboratoire contrôlé.

Attention: `check_zone_transfer` pour DNS peut produire un trafic réseau très visible; utilisez-le uniquement avec autorisation explicite.
