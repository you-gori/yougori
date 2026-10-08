# Publish from your computer

Yougori stores model pages and routing metadata. Model weights stay in the publisher's
GPU container or its read-only local model folder. No S3 bucket is required.

Sign in once with `yougori login`; the CLI and App share that account.

```powershell
# Open downloads, free chat and API
yougori model run hf.co/OWNER/MODEL --nowfree

# Your local model folder; weights remain closed
yougori model run OWNER/MODEL --folder D:\Models\my-model --nowfree --closed-weights

# Close downloads for the same already-running model container
yougori model run OWNER/MODEL --nowfree --closed-weights

# Reopen downloads without creating another container
yougori model run OWNER/MODEL --nowfree
```

`--closed-weights` offers chat and API inference without weight downloads; it requires
`--now` or `--nowfree`. Sharing offers open weight downloads by default. The former
`--publish` model flag remains an alias for `--closed-weights` so existing commands keep
their behavior. Free versus paid inference is independent of whether downloads are offered. Publish only model files
you are allowed to distribute or serve. The website imports license declarations, languages,
datasets, tags, base models and task/library metadata from README.md and recognizes common
license headers. Unspecified licenses stay unspecified; page settings can override them.

In the App, use Huggingface → Model library → Publish, choose your running container
and select open or closed weights. The model runner also accepts an optional local
model folder and the same closed-weights setting. Local safetensors folders require
config.json and tokenizer files; supported GGUF files use `--quant` when necessary.
Explicit local folders can load their declared AutoConfig and AutoModelForCausalLM classes from verified Python files inside the model container. Remote repository code remains disabled. Incompatible dependency sets still require a dedicated runner.

The website lists pages at `/modellibrary` and publisher controls at `/publish`. Each page
offers chat and an API example. Open pages also provide browser downloads and:

```powershell
yougori model library --mine
yougori model download yg/PUBLISHER/MODEL --output D:\Models\downloaded
```

The general Yougori API key works across all models. Set `model` to the page reference,
with its precision suffix when applicable, or keep using the original network model ID.
Private pages apply wallet permissions to both names. An offline publisher cannot serve
chat, API or downloads. Models shared through different GPUs continue to use provider
selection and failover; a download resumes from its pinned publishing container.

Downloads contain model assets only, excluding container disks, credentials, usage and
conversation history. Files and 8 MiB chunks are checksummed. Scoped direct links expire
within five minutes; closing downloads in the running container immediately rejects old
links. Completed downloads cannot be recalled. Runtime quantization may serve a smaller
precision while the source weight files remain in their original precision.

A new runner is required to serve publisher downloads. Stop and start an older model
with the updated engine; its container and cached weights are kept. The first open
publication computes a file manifest in the background while inference remains available.
A local read-only model mount must not be edited while serving: changed files require a
restart and a new verified version. Only explicitly selected local model code runs inside its isolated model container; remote repository code and pickle weights remain disabled.

GPU administrators and the standard gateway can read inference content. Closed weights
are kept on the publisher's computer, but this is not confidential or hardware-attested
inference. Keep proprietary weights on hardware you control. Production backend changes
and new binaries must be deployed together before these commands are publicly available.

## Source-only folders

The same --folder command accepts model source and tokenizer files without weights. It starts a CPU file publisher without CUDA or ML dependencies. Use --nowfree for open downloads. The page is marked source-only and offers no chat, inference API, paid sharing or recording. Python source, requirements and model configuration are included; credential files, container disks and chat history are excluded. Adding runnable weights creates an inference workload while keeping the previous publisher and its data.

## Download counts and publication records

Library browsing and model cards are public. Sign in with a wallet before downloading files, including through the CLI.

Website and CLI download starts share one counter. Retries and individual chunks do not
increase it; one network counts once per model per UTC day. Redirected transfers cannot be
confirmed as completed. Keyed network hashes expire on the next UTC day, while totals persist.

Publishing and page edits append timestamped records linked by SHA-256 hashes. File names,
sizes and full-file hashes identify the published version. Small README, license, NOTICE and
citation files are kept as text, limited to 64 KiB per file and 128 KiB total per distinct record.
Configuration contributes selected metadata; its raw JSON is not retained as evidence.
Weights, model source code, prompts and responses are never copied into these records.
Identical evidence is stored once. Archived pages retain their publication history.

Owners can export publication records from their model page. Keep an export independently
to compare later hashes. These are publication/attribution records, not proof of copyright
ownership or an independently notarized timestamp. Model cards display untrusted text safely.
