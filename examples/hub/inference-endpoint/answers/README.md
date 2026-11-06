# Example answers

A small public safetensors model. Pass the key as JSON on standard input; it is never stored in a file.

```text
yougori template run ./examples/hub/inference-endpoint --inputs answers/private.json --secrets - --yes
```

Secrets: `api_key` (at least 32 characters), and `hf_token` only for gated or private models.
