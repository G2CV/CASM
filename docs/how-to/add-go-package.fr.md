# Comment ajouter un nouveau package/outil Go

## Objectif

Ajouter un outil d'exécution sous `hands/` compatible avec les contrats CASM.

## Étapes

1. Créer la commande (souvent `hands/cmd/<tool_name>/main.go`).
2. Definir les structs request/response avec tags JSON.
3. Lire une requête sur stdin et écrire une réponse sur stdout.
4. Garder des sorties déterministes (tri stable si besoin).
5. Ajouter des tests dans le package.
6. Ajouter la cible build dans le `Makefile`.
7. Ajouter l'adapter Python dans `brain/adapters`.
8. Brancher la commande dans la CLI.

## Pattern minimal

```go
reader := bufio.NewReader(os.Stdin)
var req ToolRequest
if err := json.NewDecoder(reader).Decode(&req); err != nil {
    // retourner une réponse bloquée invalid_request
}
resp := run(req)
_ = json.NewEncoder(os.Stdout).Encode(resp)
```

Attention: retournez des erreurs JSON structurees; évitez les logs arbitraires sur stdout.
