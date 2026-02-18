# Comment lancer les tests

## Unit + intégration dans le repo

```bash
make test
```

Équivalent:

```bash
python -m pytest brain/tests
cd hands && go test ./...
```

## Test manuel end-to-end

```bash
casm run unified --config scopes/scope.yaml --dry-run=false
casm evidence --path runs/<engagement>/<run>/evidence.jsonl --limit 10
casm diff --old runs/<baseline>/results.sarif --new runs/<current>/results.sarif
```

## Dépannage

- Erreur import Python: activer le virtualenv et réinstaller les dépendances.
- Erreur build Go: vérifier `go version` >= 1.21.
- Flakiness réseau: préférer dry-run ou fixtures localhost pour des tests déterministes.
