# Inference Endpoint

One open model behind an OpenAI-compatible endpoint with your own key.

Inference Endpoint serves a Hugging Face model with vLLM on this computer's NVIDIA GPU. It uses the same pinned vLLM image as Yougori's own model runner, refuses requests without your API key, keeps downloaded model files on a volume, and is reachable on this computer only or, if you choose, from anywhere through a quick link or your own domain.

Use `yougori run hf.co/OWNER/MODEL` for a private model on this computer with usage counters and idle unloading ([Model Server](../model-server/README.md) does the same as a template, once the engine can apply it). Use Inference Endpoint when apps elsewhere need a model behind an HTTPS address and a key you control.

```text
yougori template run ./examples/hub/inference-endpoint
```

From the Hub, search for "Inference Endpoint" (or "vllm"), or run `yougori run hub/PUBLISHER/inference-endpoint@1.0.0` with the publisher shown on its Hub page.

## Questions it asks

| Input | Type | Default | Notes |
| --- | --- | --- | --- |
| `model` | text | — | `OWNER/MODEL` with safetensors weights and an architecture vLLM supports |
| `api_key` | secret | — | At least 32 characters; apps send it as `Authorization: Bearer KEY` |
| `hf_token` | secret | none | Only for gated or private models |
| `max_model_len` | choice | 8192 | 4096, 8192, 16384 or 32768 tokens; at most what the model supports |
| `max_concurrent` | choice | 16 | 8, 16, 32 or 64 requests at once |
| `cpu` | number | 8 | 2 to 64 cores |
| `memory_gb` | number | 32 | 8 to 512 GB |
| `storage_gb` | number | 100 | 30 to 4096 whole GB, for the model files and the server image |
| `access` | choice | none | none (only this computer), quick or domain |
| `domain` | domain | — | When `access` is domain |

Example answers without secrets are in [`answers/`](answers).

## What it creates

- A GPU sandbox running `vllm serve MODEL` on port 8000, with your key, your context and concurrency limits, and the cores, memory and disk you chose.
- A volume at `/models` that keeps downloaded weights across restarts and updates.
- A health check on `/health`; the endpoint counts as ready only once vLLM answers there.
- Its address on this computer, and, if you asked, a quick link or your domain in front of it.

## Outputs

| Output | Value |
| --- | --- |
| Endpoint address | Such as `https://NAME.trycloudflare.com` or your domain; on this computer, a local address |
| Sandbox | The sandbox's name, for `yougori logs` |

Your API key is never an output; you chose it.

## Calling it

`POST /v1/chat/completions` and `POST /v1/completions` (streaming supported), `GET /v1/models`, all with `Authorization: Bearer KEY`. The model name is the `OWNER/MODEL` you chose.

## Managing it

Stop and start it from My setups. Changing the model or limits plans the change first and restarts the server; downloaded files stay on the volume. Removing the setup removes the sandbox and keeps the `/models` volume until you delete it separately.

## Known limits

- **NVIDIA GPU on Windows x64 with WSL 2.** Other computers cannot run this template; use `yougori run hf.co/OWNER/MODEL` for processor-only models.
- **Safetensors models only**, with an architecture the pinned vLLM 0.29.0 supports. Code from the model's repository never runs.
- **The model must fit the GPU's memory** at the context length you chose. vLLM stops with an out-of-memory message otherwise; choose a shorter context or a smaller model.
- **First start** downloads the whole model. If that takes longer than the ten-minute health wait, the setup shows the endpoint as starting until vLLM answers.
- **One key.** Change it by updating the setup with a new key; vLLM then restarts.
- **One GPU sandbox on this computer.** It does not spread the model over several computers; use Neo Grid for that.
- **Serverless endpoints on rented GPUs** are available in NeoCloud, not in this template.
- **Quick links** can change after a restart; the address output is refreshed when it does.
- **Health watching is planned.** The service's health path is checked when it starts. Watching it afterwards (Health check) and the Health and logs view are listed as planned in setup and can't be turned on yet; `yougori template status NAME` and `yougori template logs NAME` show the setup's state and activity meanwhile.

## Files

| File | Purpose |
| --- | --- |
| `yougori-template.yaml` | Questions, steps and outputs |
| `yougori.yaml` | The vLLM sandbox and its publication |
| `answers/` | Example answers without secrets |
| `TESTING.md` | What maintainers check before publishing a version |
| `CHANGELOG.md` | Version history |
| `LICENSE` | MIT |
