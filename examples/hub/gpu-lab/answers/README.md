# Example answers

Pass the notebook token as JSON on standard input; it is never stored in a file.

```text
yougori template run ./examples/hub/gpu-lab --inputs answers/private.json --secrets - --yes
```

Secret: `notebook_token` (at least 16 characters).
