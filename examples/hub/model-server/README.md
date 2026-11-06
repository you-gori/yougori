# Model Server

Run an open model on this computer with a private API.

Model Server downloads an open model from Hugging Face (`hf.co/OWNER/MODEL`) or Yougori (`yg/PUBLISHER/MODEL`), runs it with Yougori's model runner on this computer's GPU or processor, and gives you a private OpenAI-compatible API with its own key. Before anything is downloaded, Yougori checks the model's files and this computer: an unsupported model or a GPU that is too small stops setup with nothing created.

```text
yougori template run ./examples/hub/model-server
```

From the Hub, search for "Model Server", or run `yougori run hub/PUBLISHER/model-server@1.0.0` with the publisher shown on its Hub page.

## Questions it asks

| Input | Type | Default | Notes |
| --- | --- | --- | --- |
| `model` | text | — | `hf.co/OWNER/MODEL` (GGUF or safetensors) or `yg/PUBLISHER/MODEL` |
| `quantization` | text | picked to fit | GGUF only, such as `Q4_K_M` |
| `gpu` | choice | optional | optional (GPU when available), required, or none (processor only, GGUF models) |
| `memory_gb` | number | 16 | 4 to 256 GB |

Example answers are in [`answers/`](answers).

## What it creates

- A model sandbox running the model with the right runner: llama.cpp for GGUF, Transformers or vLLM for safetensors. Files are checked against their published checksums; code from the model's repository never runs.
- A private API on this computer only (`127.0.0.1`), with its own key kept in this computer's credential store.

## Outputs

| Output | Value |
| --- | --- |
| Model | The model it serves |
| API address | The local address, such as `http://127.0.0.1:8000/v1` |

The key is not an output. `yougori model access NAME` shows it, with the addresses, whenever you need it.

## Calling it

`POST /v1/chat/completions` (streaming supported) and `GET /v1/models`, with the key as a bearer token. `GET /v1/usage` reports requests and tokens. Readiness goes from installing and downloading to verifying, loading and ready; a request before ready gets an error that says so.

## Managing it

From My setups or the CLI:

- `yougori model chat NAME`: chat with it.
- `yougori model usage NAME --days 7`: usage by hour, for up to 90 days.
- `yougori model optimize NAME`: unload after an idle time (10 to 3600 seconds), or pin it so it stays loaded.
- `yougori model stop NAME`: stop the model.
- Share it on Yougori Network, free or paid, with your Yougori account. Shared prompts can be read by the Network and the computer that serves them.

Removing the setup removes the model sandbox, including its downloaded model files; they can be downloaded again.

## Known limits

- **The model cannot be changed after setup.** To run a different model, size or memory, remove the setup and run the template again. Setup refuses a change in place rather than replacing the model halfway.
- **Concurrent callers.** Updated GGUF and vLLM runners generate several requests together (four and eight by default); Transformers models answer one at a time. Up to 128 more wait in arrival order. A full queue returns HTTP 429; waits over five minutes return 504. Allow for waiting plus generation in client timeouts. Restart the model under the updated engine to enable queuing.
- **Request limits**: up to 128 messages and 32,768 characters, `max_tokens` up to 4096, 90 seconds (300 seconds streaming).
- **Local only.** The API listens on this computer. For apps elsewhere, use Neo Grid, Inference Endpoint, or a Yougori Network share.
- **The key cannot be rotated or revoked yet.** Anyone with it can use the model while it runs; stop the model to cut access.
- **Rented GPUs** are not part of this template. To run a model on a rented GPU, rent a pod in NeoCloud and run `yougori model run --neocloud`.
- **GPU support**: NVIDIA GPUs on Windows x64 with WSL 2. On Linux and on computers without a supported GPU, models run on the processor and must be GGUF.
- **Gated or private Hugging Face models** need `yougori model auth login` first.
- **The Health and logs view is planned.** It is listed as planned in setup and can't be turned on yet; `yougori template status NAME` and `yougori template logs NAME` show the setup's state and activity meanwhile.

## Files

| File | Purpose |
| --- | --- |
| `yougori-template.yaml` | Questions, steps and outputs |
| `yougori.yaml` | The model service |
| `answers/` | Example answers |
| `TESTING.md` | What maintainers check before publishing a version |
| `CHANGELOG.md` | Version history |
| `LICENSE` | MIT |
