# GPU Lab

A JupyterLab notebook on this computer's NVIDIA GPU, with your work kept safe.

GPU Lab runs JupyterLab on the PyTorch 2.8 image with CUDA 12.8 (the same image Yougori's model runner uses for safetensors models), on this computer's NVIDIA GPU. Your token protects it, and everything under `/workspace` survives restarts and updates.

```text
yougori template run ./examples/hub/gpu-lab
```

From the Hub, search for "GPU Lab" (or "jupyter"), or run `yougori run hub/PUBLISHER/gpu-lab@1.0.0` with the publisher shown on its Hub page.

## Questions it asks

| Input | Type | Default | Notes |
| --- | --- | --- | --- |
| `notebook_token` | secret | — | At least 16 characters; you type it when the notebook opens |
| `cpu` | number | 4 | 2 to 32 cores |
| `memory_gb` | number | 16 | 4 to 256 GB |
| `storage_gb` | number | 60 | 30 to 2048 whole GB |
| `access` | choice | none | none (only this computer), quick or domain |
| `domain` | domain | — | When `access` is domain |

Example answers without secrets are in [`answers/`](answers).

## What it creates

- A GPU sandbox from `pytorch/pytorch:2.8.0-cuda12.8-cudnn9-runtime`, with JupyterLab 4.2.5 installed at setup.
- A volume at `/workspace`, where the notebook opens and where your notebooks and outputs are kept.
- A health check on `/api`; the lab counts as ready once JupyterLab answers.
- Its address on this computer, and, if you asked, a quick link or your domain in front of it.

## Outputs

| Output | Value |
| --- | --- |
| Notebook address | Where you open the lab |
| Sandbox | The sandbox's name, for `yougori logs` and `yougori terminal` |

## Managing it

Stop the lab when you are not using it; the GPU is free for other work and `/workspace` is kept. Packages you install with `pip` in a notebook terminal live in the sandbox, not in `/workspace`; an update to a new template version may need them installed again. Removing the setup removes the sandbox and keeps the `/workspace` volume until you delete it separately.

## Known limits

- **NVIDIA GPU on Windows x64 with WSL 2.** Setup stops before anything is created when this computer has no supported GPU.
- **This computer only.** A lab on a rented GPU is a NeoCloud pod with its own Jupyter link; it is not part of this template, and NeoCloud bills it per second while it runs.
- **No spending budget** applies here, because a local GPU is not billed. A rented pod has its own price check in NeoCloud.
- **One user.** Everyone with the address and token shares the same lab and files.
- **Packages** beyond PyTorch and JupyterLab are installed by you with `pip`.
- **Quick links** can change after a restart; the address output is refreshed when it does.
- **Health watching is planned.** The service's health path is checked when it starts. Watching it afterwards (Health check) and the Health and logs view are listed as planned in setup and can't be turned on yet; `yougori template status NAME` and `yougori template logs NAME` show the setup's state and activity meanwhile.

## Files

| File | Purpose |
| --- | --- |
| `yougori-template.yaml` | Questions, steps and outputs |
| `yougori.yaml` | The lab sandbox and its publication |
| `answers/` | Example answers without secrets |
| `TESTING.md` | What maintainers check before publishing a version |
| `CHANGELOG.md` | Version history |
| `LICENSE` | MIT |
