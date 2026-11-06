# G04 real path: the local vLLM call graph and the first profile binding

Written 29 October 2026 by Manager 1's LD1 agent from the checkout at `ae5e5fe` plus
LD1's `load_vllm` change. It is a source record, not an installed-app or hardware result.
Three labels are kept apart throughout: **implemented** (source and offline tests exist),
**integrated on the path** (called on the `run_model` → vLLM path of section 2) and
**validated on hardware** (observed on the GPU below). Nothing in this document is validated
on hardware; GPU-W00 (section 5) is the plan for the first such observation.

## 1. Host and runtime facts

- GPU (Manager 1; combined plan A.11, docs/combined-gpu-memory-and-vm-sandbox-plan.md:1719–1721):
  NVIDIA GeForce RTX 5090 Laptop GPU, 24,463 MiB, driver 617.42, compute capability 12.0.
- Runner provider `yougoriCuda`: the Windows WSL2 CUDA container runtime, crate `yougori-cuda`
  in `runtime/cuda/host` (runtime/cuda/host/src/lib.rs:1), routed by src-tauri/src/runtime/cuda.rs:1–2.
- Images: `TRANSFORMERS_IMAGE` and `LLAMA_CPP_IMAGE` (src-tauri/src/model_runner.rs:93–94);
  the vLLM image `IMAGE` = `docker.io/vllm/vllm-openai@sha256:c2914767…` (model_runner/vllm.rs:3).
- Ledger admission profile `local-single-vllm-v1` (model_runner/optimizer/capacity.rs:27).

## 2. Call graph

Engine side (all paths under src-tauri/src):

1. `yougori model run hf.co/OWNER/MODEL` → automation `run_model` (cli/src/public.rs:1321;
   automation/dispatch.rs:124) → `run_model` (model_runner.rs:72) → `run_model_with_resources` (:210)
   → `run_model_at_revision` (:213).
2. Three branches at :221–223: a folder goes to `local::run` (model_runner/local.rs:65), a `yg/`
   name to `run_registry_model` (:322), everything else to `preflight::preflight_pinned` (:223 →
   preflight.rs:100), one Hugging Face metadata call plus `config.json`. `preflight::inspect`
   (preflight.rs:14) chooses `runner: yougori-vllm, format: vllm` only when the `model_type` is absent
   from the Transformers catalog `architectures-5.18.0.json` and `vllm::inspect` (vllm.rs:6) finds an
   architecture in `architectures-vllm-0.29.0.json` (preflight.rs:27); otherwise the same safetensors
   checkpoint runs on the Transformers runner.
3. `vllm::check_local_hardware` (:258 → vllm.rs:31): one bounded `nvidia-smi` query, memory and
   compute-capability check, `shared_capacity` true only when exactly one GPU line is reported
   (vllm.rs:54–56).
4. Workload environment: `YOUGORI_MODEL`, `YOUGORI_MODEL_REVISION` (:292), `YOUGORI_MODEL_PRECISION`
   (:295), `YOUGORI_MODEL_FORMAT=vllm` (:302), `optimizer::environment` (:304 → optimizer.rs:37: the
   model server source, the GPU helper source, `YOUGORI_GPU_OPTIMIZER=1`, a `gpu-control-*` secret) and,
   for `shared_capacity`, `optimizer::stamp_capacity` (:305 → optimizer.rs:19 → capacity.rs:31:
   `YOUGORI_GPU_CAPACITY_POLICY=local-single-vllm-v1`, `YOUGORI_GPU_CAPACITY_BYTES` from
   `gpuMemoryGbEstimated`).
5. `projects::run_workload` (:311–312 → projects.rs:950): provider `yougoriCuda`, runtime
   `vllm::IMAGE`, `containerCommand` = `server_command()` (:400–405, the compressed model server in
   `YOUGORI_MODEL_SERVER_SOURCE`), a `model-*-models` volume at `/root/.cache/huggingface`.
   The local-folder path builds the same request at local.rs:147 (read-only bind at `/yougori-model`,
   `TRANSFORMERS_IMAGE` or `LLAMA_CPP_IMAGE` only, `optimizer::environment` at :139, no capacity
   stamp) after `run_checked` refused `format == "vllm"` at local.rs:79. The registry path does the
   same at model_runner.rs:378–388 (no vLLM image, no stamp).

Container side (src-tauri/src/model_server.py, lines after LD1's change):

6. `__main__` (:2994) starts `load_model` (:1842; `single_model_load` :715, `timed_load` :701), which
   dispatches on `FORMAT`: `load_gguf` (:1744, llama.cpp), `load_vllm` (:2026), `load_clef` (:1573),
   `load_transformers` (:1493, `checkpoint` :1287 → `verified_snapshot` :1438 → `gpu_before_load` →
   `from_pretrained`).
7. `load_vllm`: exact `VLLM_VERSION` check (:2030–2031); revision check (:2035–2036); then either
   `prepared_vllm_source` (:1973, the process-local source memo) or Hugging Face metadata and
   `config.json`; or, with `YOUGORI_MODEL_PATH`, `local_vllm_source` (:1997 → `verified_snapshot` →
   `registry_snapshot` :1428, the bundled verifier model_runner/registry_snapshot.py); registry check
   against vLLM's `ModelRegistry` or the Kolibri plugin (:2061–2070); `gpu_before_load`
   (gpu_optimizer.py:100, timed as `admission_wait`); `vllm_hardware` (:1870); for Hugging Face,
   `verified_snapshot` and `remember_vllm_source` (:1928); `vllm serve` (:2087–2091); `/health` every
   2 s for up to an hour (:2099–2111).
8. The optimizer protocol, engine side: `optimizer::start` (lib.rs:757 → optimizer.rs:250/:254) runs
   one scheduler loop woken by `wake::Wake` (wake.rs:7; `request_completed` optimizer.rs:27 after
   `/v1/yougori/prepare` and `/v1/yougori/release`) and by `events::run` (:260 → events.rs:214), whose
   long poll is `POST /v1/yougori/optimizer {"action":"watch"}` answered by `gpu_watch`
   (gpu_optimizer.py:223). Each pass: `status_batch::collect` (:320 → status_batch.rs:14) →
   `model_status` (model_runner.rs:655 → `model_request` :599 → `/health`, model_server.py:2823);
   `validate_seen` (:188) and `observe` (:223); `runtime_binding::pass`/`apply` (:342–352); the loading
   guard (:371); for a waiting model `capacity::local_switch` (:404 → capacity.rs:351 → `switch` :271:
   `probe::local` samples the GPU, `Accounting::settle_and_reserve` :103 reserves on the foundation
   `Ledger`, foundation/ledger/mod.rs:1–6) and the fenced controls `control::prepare_switch`/`request`
   (control.rs:360/:288, actions `phase`, `unload`, `grant`, control.rs:15) answered by `gpu_control`
   (gpu_optimizer.py:268); for legacy members `control::switch` (:409 → control.rs:327). Idle residents:
   `idle_expired` (:244) → `Action::Unload` (:414–415), then `capacity::local_release` (:421 →
   capacity.rs:426/:390).
9. Unload, container side: `gpu_unload` (gpu_optimizer.py:199) → `gpu_release_memory` (:177:
   `terminate()` the vLLM process with a 10 s then 5 s grace, drop references, `gc.collect()`,
   `empty_cache()`), status `idle`. A grant sets `GPU_GRANTED` so a loader blocked in
   `gpu_before_load` continues, or starts `load_model` again (:313, :325). Stop from the CLI:
   `yougori model stop ENV` → `stop_model` (dispatch.rs:273 → model_runner.rs:19 → neocloud.rs:156);
   settings: `yougori model optimize ENV [--on|--off] [--pin|--unpin] [--idle SECONDS]` →
   `model_optimizer` (public.rs:1143 → optimizer.rs:66).
10. Runtime binding: `Launch::of` reads `YOUGORI_MODEL_FORMAT=vllm`, the capacity policy and the
    shipped server source (runtime_binding.rs:104–128); the release is pinned from
    `model_memory::profiles::audit::TODAY` (runtime_binding.rs:98; profiles/audit.rs:149); binds and
    unbinds reach `host_evidence::bind_runtime`/`unbind_runtime` (host_evidence/engine.rs:66/:72).

## 3. Plan components on this path today

| Component | Label | Proof |
| --- | --- | --- |
| Host ledger reservation | Integrated on the path for newly created single-GPU vLLM models; not validated on hardware | capacity.rs:1–2, :27, :31, :103; optimizer.rs:305, :404; foundation/ledger/mod.rs:1–6 |
| Host-evidence runtime binding | Integrated on the path | optimizer.rs:342–352; runtime_binding.rs:1–32; host_evidence/engine.rs:66 |
| Measurement workflow | Implemented; reachable only by explicit `yougori model measure` (no automatic enrollment) | public.rs:1180–1184 → dispatch.rs:289 → measurement/workflow.rs:363 → collector.rs:337 (`/v1/diagnostics/timings?journal=1`); model_server.py:99, :147–148 |
| Event-driven admission | Integrated on the path as hints; the one-second reconciliation remains | events.rs:1, :214; optimizer.rs:260; gpu_optimizer.py:223; wake.rs:1–2 |
| Bounded status probes, verified source reuse, runner timings | Integrated on the path | status_batch.rs:14; model_server.py:1928, :1973; :329–339 |

Not reached from this path. model_memory/mod.rs:5–6 states it for the whole tree: "Pure library
code tested against fakes. Runner integration belongs to GPU-W01 onward." Per component:

| Component | Where it is implemented | What the path does instead |
| --- | --- | --- |
| Catalog and importer | manifest/importer.rs:1–3 (`Importer` :417); boundaries/catalog.rs:281 (`ArtifactImporter`); catalog_service.rs:1–5 (`catalog_status`, lib.rs:91) | `download_snapshot` (model_server.py:862) into the cache volume, or the read-only bind; `model_runner.rs` and `local.rs` never name `catalog_service` |
| Sidecar manifest | manifest/mod.rs:1–8 | vLLM reads `config.json` and the safetensors files directly (`--load-format safetensors`) |
| Tiers | tiers/mod.rs:1–8 | one volume (model_runner.rs:311) or one bind (local.rs:147) |
| Transfer executor | executor/mod.rs:1–5; `TransferBackend` executor/backend.rs:196, implemented only by `FakeBackend` (executor/fakes.rs:339), `BytesBackend` (boundaries/fakes.rs:1265) and `EdgeBackend` in the `#[cfg(test)]` scenarios (model_memory/mod.rs:28–29; scenarios.rs:680) | vLLM's own loader moves the bytes |
| Placement and boundaries governors | placement/mod.rs:1–8; boundaries/governor.rs:1–4 | `capacity::Accounting` plus `gpu_before_load` |
| Helper rollout | helpers/mod.rs:1–8 (G08 library) | source injection: `optimizer::source` (optimizer.rs:31), `server_payload` (model_runner.rs:394); docs/gpu-memory/helper-packaging.md |
| Adapter/KV keys | adapters/adapter.rs:1–8; adapters/kv.rs:1–8 | no adapter or prefix-cache flag in the launch (model_server.py:2087–2091) |
| Retention policies | residency/mod.rs:1–2; reclaim/mod.rs:1–4; tiers | idle expiry only (`idle_expired` optimizer.rs:244; `YOUGORI_GPU_IDLE_SECONDS` gpu_optimizer.py:17) and the process-local source memo; no sleep mode for 0.29.0 (backends/capabilities.rs:8–9) |

## 4. The first profile binding

vLLM 0.29.0 (`VLLM_VERSION`, model_server.py:89), on `vllm::IMAGE`, safetensors, original precision
(`YOUGORI_MODEL_PRECISION=auto` for an unpinned Hugging Face run, model_runner.rs:295; the runner
reports `precision` from the checkpoint's `dtype`/`torch_dtype`, :2126), one GPU (`--tensor-parallel-size`
is the visible CUDA device count from `vllm_hardware`, :1872; the ledger profile is stamped only when
`nvidia-smi` lists one GPU, vllm.rs:54–56). The launch, model_server.py:2087–2097:

```text
python -m vllm.entrypoints.cli.main serve <root>
  --served-model-name <MODEL> --host 127.0.0.1 --port <LLAMA.port>
  --model-impl vllm --load-format safetensors
  --max-model-len min(max_position_embeddings or 4096, 32768)
  --tensor-parallel-size <count> --distributed-executor-backend mp
  --gpu-memory-utilization 0.90 --max-num-seqs 1 --enforce-eager
  --generation-config vllm --disable-log-stats
  [--reasoning-parser kolibri1] [--enable-auto-tool-choice --tool-call-parser <TOOL_PARSER>]
  [--kv-cache-dtype fp8   (Kolibri FP8 only)]
env: HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 VLLM_NO_USAGE_STATS=1 VLLM_PLUGINS=... VLLM_API_KEY=...
```

`vllm_hardware` (:1870–1883) admits only CUDA devices of compute capability 7.5 or newer with
(weights/GiB + 2)/0.90 GiB free. The audited record of this launch is `profiles/audit.rs:149–186`
(`ServingAudit::drift` compares it flag by flag with the source). stdout and stderr are discarded (:2100).

The loader is vLLM's own safetensors loader (`--load-format safetensors`). With LD1's change the same
loader serves a verified local root (`local_vllm_source`, section 2 step 7): implemented in Python and
tested offline, not integrated (local.rs:79 still refuses `vllm` for folders; Manager 1 lifts it).

Loader variants. vLLM documents other `--load-format` values: `auto`, `pt`, `npcache`, `dummy`,
`sharded_state`, `gguf`, `mistral`, `bitsandbytes`, `tensorizer`, `runai_streamer`, `fastsafetensors`.
Which of these the 0.29.0 entry point accepts, and which optional packages the pinned image carries
(`tensorizer`, `runai-model-streamer`, `fastsafetensors`, `bitsandbytes`): to check in the pinned image.
Without a new dependency, only a value whose implementation ships in vLLM core and whose package is
already in the image qualifies; `dummy` (random weights, startup-only timing) and `sharded_state`
(a vLLM-written per-rank snapshot) are the candidates to check first. Everything else is a versioned
image change: a loader that needs an extra package, vLLM sleep mode (no sleep rule is recorded for
0.29.0, backends/capabilities.rs:8–9) and the 0.31.0 preload daemon (combined plan line 493: "adding
flags to 0.29.0 is insufficient"). The `--max-num-seqs 1 --enforce-eager` audit is GPU-W01 (plan line 1169).

## 5. GPU-W00 measurement plan (a plan only; nothing was run)

What `yougori model measure` records today (docs/gpu-memory/measurement-workflow.md; combined plan
GPU-W00 at lines 1142–1158): `RunnerTimings` stage records (model_server.py:329–339) and request records flow into
`RunnerJournal` (:99) only when the workload carries `YOUGORI_MEASUREMENT_SESSION` (:147–148);
`measure start` enrolls an idle, updated runner; `collect`/`seal` read
`/v1/diagnostics/timings?journal=1` (collector.rs:337); `export` writes `observations.json` with raw
events and `benchmarkContext: "unavailable"`. Durations are host monotonic time, not CUDA time.

Stage boundaries that exist (`RunnerTimings.STAGES`, :336–339; docs/gpu-memory/runner-timings.md):
`dependencies`, `checkpoint` (Transformers only), `snapshot`, `download`, `weight_verification`,
`weight_hash`, `runtime_artifact` (llama.cpp), `weight_load` (Transformers/CLEF), `admission_wait`,
`engine_start_to_ready` (llama.cpp and vLLM: `Popen` through the first `/health` 200),
`native_ready_wait`, `request_validation`, `model_wait`, `prompt_preparation`, `generation`.
Not observable today: vLLM's internal weight read, KV allocation and warm-up (one `engine_start_to_ready`
span); the unload itself (`gpu_release_memory` has no stage); GPU memory peaks (no device timing).

Model selection. The baseline model must preflight to `runner: yougori-vllm`: its `model_type` absent
from `architectures-5.18.0.json` (`types`) and its architecture present in `architectures-vllm-0.29.0.json`
(preflight.rs:27). `gpt2`, `llama`, `qwen2`, `gemma3` and `smollm3` are in the Transformers catalog and
would not exercise vLLM. Architectures only vLLM knows include `InternLM2ForCausalLM` and
`ExaoneForCausalLM`; whether a small safetensors checkpoint of either exists and preflights as vLLM is
to check with `yougori model preflight hf.co/OWNER/MODEL` before anything is created. The revision is
pinned by preflight at creation (`YOUGORI_MODEL_REVISION`, model_runner.rs:292); the CLI has no revision
flag, so record `revision` from `yougori model status ENV` and keep one environment for the whole series.

Conditions for every run: Automatic GPU memory on (`optimizer.enabled: true` in `model status`); no
other model environment running; the host idle otherwise; the same `nvidia-smi` sample
(`--query-gpu=memory.used,memory.total --format=csv -l 1`) alongside as residency evidence, which is
not a stage; instrumentation unchanged between compared runs.

Load/unload/reload baseline of one small pinned model:

```text
yougori model preflight hf.co/OWNER/MODEL            # runner yougori-vllm, format vllm, gpuMemoryGbEstimated
yougori model run hf.co/OWNER/MODEL --backend cuda --api --port 8000
yougori model status ENV                            # until status ready; record revision, optimizer fields
yougori model measure start ENV                     # idle runner; the cold load above is not in the window
yougori model optimize ENV --idle 10                # idle_expired → unload → status idle
yougori model chat ENV   (or one POST /v1/chat/completions)   # prepare → grant → reload → reply
yougori model status ENV                            # ready again; repeat the unload/reload pair 5 times
yougori model measure seal ENV
yougori model measure export ENV
```

Expected records per reload: `admission_wait`, `snapshot` (a warm `prepared_vllm_source` memo or the
verifier), `engine_start_to_ready`, then the request's `model_wait`, `prompt_preparation`, `generation`.

Two-model switching workload: two vLLM-eligible environments A and B, both ready once, both enrolled
with `measure start`, both `optimize --idle 0` (keep loaded until switching). Today's scheduler keeps one
resident model: a switch phases and unloads every other resident before granting (optimizer.rs:384–409;
control.rs:327–350; capacity.rs:271), so alternating one request to A, then B, then A (five pairs)
yields per switch the unload of the resident (visible as `status idle` and the host `memory.used`
drop) and the waiting model's `admission_wait` + `engine_start_to_ready`. Record `optimizer.waitingFor`
from `model status` while waiting. Seal and export both environments; report A→B and B→A separately.

## 6. Summary by label

- Implemented, not integrated: the local-root vLLM source (`local_vllm_source`); every `model_memory`
  component in section 3's second table; the audited launch record.
- Integrated on the path: everything in section 3's first table and the full call graph of section 2.
- Validated on hardware: nothing here. The first hardware evidence is the section 5 plan.

## 7. Doubts

- Line numbers are from this checkout; `model_server.py` lines after :1997 include LD1's change.
- The loader-variant list is vLLM's documented set as known to the author, not read from the 0.29.0
  image; treat every entry as "to check in the pinned image".
- Candidate baseline models are named by architecture rule only; existence, size and preflight result
  are unverified offline.
