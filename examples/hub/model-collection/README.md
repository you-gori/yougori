# Model Collection

Several open models on this computer, taking turns on its GPU.

Model Collection runs two or three open models on this computer, each with its own private OpenAI-compatible API. On an NVIDIA GPU, Yougori's model optimizer gives the GPU to the model being asked, frees memory from idle ones, and waits for a reply in progress to finish before switching. You can pin the model you use most so it stays loaded.

```text
yougori template run ./examples/hub/model-collection
```

From the Hub, search for "Model Collection", or run `yougori run hub/PUBLISHER/model-collection@1.0.0` with the publisher shown on its Hub page.

## Questions it asks

| Input | Type | Default | Notes |
| --- | --- | --- | --- |
| `model_one`, `model_two` | text | — | `hf.co/OWNER/MODEL` or `yg/PUBLISHER/MODEL` |
| `quant_one`, `quant_two` | text | picked to fit | GGUF only |
| `third` | yes/no | no | Add a third model |
| `model_three`, `quant_three` | text | — | When `third` is yes |
| `gpu` | choice | optional | optional, required, or none (processor only, GGUF models) |
| `memory_gb` | number | 16 | 4 to 256 GB for each model |

Example answers are in [`answers/`](answers).

## What it creates

One model sandbox per model, each checked before download (unsupported models stop setup with nothing created), with its own private API and key on this computer.

## Outputs

| Output | Value |
| --- | --- |
| First model, Second model, Third model | Each model's local API address |

`yougori model access NAME` shows each model's key and addresses.

## How the GPU is shared

- On an NVIDIA GPU, one model holds the GPU at a time. A request to another model waits until the current reply finishes, then that model is loaded.
- A pinned model stays loaded and blocks the others from the GPU; unpin it to share again.
- An idle time (10 to 3600 seconds) unloads a model after it has been unused that long.
- A request waits at most 30 minutes for the GPU.
- Without a supported GPU, every model runs on the processor and stays loaded, so memory must hold them all.

## Managing it

From My setups or the CLI: `yougori model optimize NAME --pin` or `--unpin`, `--idle SECONDS`, `--on` or `--off`; `yougori model usage NAME`; `yougori model stop NAME`. Removing the setup removes the model sandboxes and their downloaded files.

## Known limits

- **A model cannot be changed after setup.** To run a different model, size or memory, remove the setup and run the template again.
- **Two or three models** in this template. Add more with `yougori run hf.co/OWNER/MODEL`.
- **Concurrent callers per model.** Updated GGUF and vLLM runners generate several requests together; up to 128 more wait and are served in order. A full queue returns HTTP 429; waits over five minutes return 504. Allow for waiting plus generation in client timeouts. Restart models under the updated engine to enable queuing.
- **Pinning and idle times** are set after setup, not in the questions.
- **Each model has its own address and key**; there is no single address that routes by model name. Use Neo Grid for one API over several models.
- **GPU support**: NVIDIA on Windows x64 with WSL 2. Elsewhere the models run on the processor and must be GGUF.
- **The Health and logs view is planned.** It is listed as planned in setup and can't be turned on yet; `yougori template status NAME` and `yougori template logs NAME` show the setup's state and activity meanwhile.

## Files

| File | Purpose |
| --- | --- |
| `yougori-template.yaml` | Questions, steps and outputs |
| `yougori.yaml` | The model services |
| `answers/` | Example answers |
| `TESTING.md` | What maintainers check before publishing a version |
| `CHANGELOG.md` | Version history |
| `LICENSE` | MIT |
