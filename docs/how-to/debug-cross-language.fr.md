# Comment debugger les problèmes cross-language

## Symptomes -> causes

| Symptome | Cause probable | Correctif |
|---|---|---|
| `tool_not_found` | binaire absent | lancer `make build-hands` |
| `tool_timeout` | timeout trop bas / cible inaccessible | augmenter timeout, inspecter stderr |
| `invalid_tool_output` | stdout contient un JSON invalide | vérifier que l'outil écrit uniquement du JSON |
| `tool_error` | panic Go ou exit non-zero | lancer l'outil en direct et inspecter les logs |

## Workflow pratique

1. Lancer la commande sur un petit set de cibles.
2. Inspecter le dossier d'exécution (`tool_stderr.log`, `tool_stdout.partial.log`).
3. Rejouer l'outil Go en standalone avec une fixture connue.

```bash
cat contracts/fixtures/http_verify_request.json | hands/bin/http_verify
```

4. Valider la réponse contre le schéma.

## Debug race/concurrence (Go)

```bash
cd hands && go test -race ./...
```
