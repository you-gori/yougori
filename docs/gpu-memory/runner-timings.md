# GPU-W00: observations in the Python runner

Implemented 28 October 2026 in `src-tauri/src/model_server.py`. This is the
production-path instrumentation slice of GPU-W00 in the combined GPU/VM plan.
It does not complete GPU-W00, establish a hardware baseline, or change scheduling.

## Available observations

Every `load_model()` call records a load attempt. Authorized inference requests
record a request attempt after endpoint routing, including invalid requests and
failed preparation. All durations use `time.monotonic_ns()` on the host, expressed
in milliseconds. No CUDA synchronization or device timing is introduced.

| Stage | Measured boundary |
| --- | --- |
| `dependencies` | Existing dependency inspection/install function |
| `checkpoint` | Existing checkpoint metadata inspection |
| `snapshot` | Verified snapshot or GGUF acquisition function |
| `download` | Snapshot download function, including retries |
| `weight_verification` | Existing weight identity check, including stamp reuse |
| `weight_hash` | Actual existing file hash function; a false result counts as failure |
| `runtime_artifact` | Pinned llama.cpp artifact lookup/acquisition |
| `weight_load` | Transformers `from_pretrained().eval()` or CLEF release-model loading |
| `admission_wait` | Existing `gpu_before_load()` call |
| `engine_start_to_ready` | llama.cpp/vLLM process creation through successful health polling |
| `native_ready_wait` | Waiting for an externally started native engine's health response |
| `request_validation` | Body read, JSON parsing and request validation |
| `model_wait` | Existing `gpu_enter()` call, including any preparation/wake wait |
| `prompt_preparation` | Existing tokenization/template/context preparation functions |
| `generation` | Existing generation function, including preparation and streaming writes |

Stages are inclusive and may nest: **do not sum stage durations** to obtain total
wall time. A missing stage means it was not observed, not that it took zero time.
Registry verification may occur inside `snapshot` without a separate hash stage.
Stamp reuse can skip hashing; these records alone do not classify a run as cold or
warm. Engine startup includes health polling delays and does not separately measure
process initialization, device transfer or prefill. Native readiness does not claim
to measure the external process's launch.

Each completed record contains `id`, `completionSequence`, `kind`, `outcome`, `elapsedMs`,
`firstOutputMs` and `stages`. Each stage contains `calls`, `failedCalls` and
`elapsedMs`. Outcomes are `ok`, `cancelled`, `busy`, `invalid` or `error`; failures
that the existing runner catches are reflected through its resulting state/meter.
Request elapsed time includes existing completion bookkeeping. It excludes socket
accept, header parsing, authorization, routing failures and server admission
rejections that occur before the handler's inference block.

`firstOutputMs` measures from the request observation start to the first successful
write/flush of nonempty streamed content or a tool-call fragment. Role-only chunks,
empty deltas, terminal chunks and failed writes do not count. This is **first emitted
output**, not exact first-token latency: a streamer may buffer tokens, and a
successful server write does not prove client receipt. Buffered responses retain
`null`. Device prefill, kernel time and exact token-level timing remain unknown.

## Access and retention

`GET /v1/diagnostics/timings` requires both existing credentials:

- The model token in `Authorization: Bearer ...`.
- The engine admin token in `X-Yougori-Admin`.

Without a configured admin token, access is denied. Ordinary model clients cannot
read these records. They are not included in `/health` or `/v1/usage`, and replies
use the existing `Cache-Control: no-store` behavior. No new public UI/CLI endpoint
or credential is introduced. Any future engine adapter must preserve this boundary.

The response reports `clock: "process_monotonic"`, `units: "milliseconds"`,
`instanceId`, `started`, `completed`, `active`, `retained`, `evicted`, `retainedIds`
and `recent`. The in-memory ring retains the last 64 completed attempts. Each new
collector, including initialization after an ordinary process restart, receives a
random 128-bit `instanceId` encoded as 32 lowercase hexadecimal characters. It
stays fixed across snapshots, contains no model/host/user identity and grants no
authority. It is an observation namespace, not a VM generation or attestation.

Records appear in completion order; `id` is allocated in start order. A record's
`completionSequence` is assigned when it enters the ring under the same lock as
the completed counter. Sequences therefore increase from 1 in completion order.
`retainedIds` lists exactly the retained records' start IDs in that order. Active
attempts have counts but no partial records. Each thread owns its current
observation; one lock protects ring snapshots and counters.

A future collector identifies attempts by `(instanceId, id)` and uses
`(instanceId, completionSequence)` as its delivery cursor. For the same instance,
after consuming through completion `C`, a snapshot whose oldest retained
completion exceeds `C + 1` has lost completed records for that collector. Records
at or below `C` are duplicates; the new records are above it. A changed instance
starts a new namespace, never continuity from the old counter. Initial `evicted`
counts describe ring history, not necessarily loss by a collector that already
consumed those records. Older servers missing these fields cannot establish this
continuity and need an explicitly limited fallback.

For example, start ID 1 can remain active while IDs 2 and 3 finish with completion
sequences 1 and 2. When ID 1 finishes into a two-record test ring, the retained IDs
are `[3, 1]` with completion sequences `[2, 3]`. Neither the minimum/maximum start
ID nor a start-ID gap proves a completed attempt was lost.

These additive fields allow loss detection, not recovery of evicted observations.
An interrupted process can lose active attempts and its final uncollected records.
The diagnostics have no durable attempt journal, collector acknowledgment or
shared benchmark identity. Do not turn a retained-ring snapshot into an
all-attempt benchmark denominator or a CORE-08 report without that integration.

Labels and outcomes come from fixed allowlists. No prompts, model responses,
paths, exception messages, model names, keys or request headers are retained by
this collector. Existing separately configured usage/listen behavior is unchanged.

## Verification and handoff

Offline checks passed:

```powershell
python -B -m unittest discover -s src-tauri/src -p model_timing_test.py -v
# 16 tests (including collector restart, out-of-order completion and ring loss)
python -B scripts/model-server.test.py
# 39 tests
python -B -m unittest discover -s src-tauri/src -p model_server_test.py
# 29 tests
python -B -m unittest discover -s src-tauri/src -p gpu_optimizer_test.py
# 24 tests
```

The tests exercise real handler/load/stream paths with fake clocks, stubbed
backends and disposable files: nested timings, bounded retention, concurrent
requests, verification stamp reuse and corruption, external/native readiness,
invalid/busy requests, cancelled writes, first output and access control. No live
engine, app, model download, GPU workload or benchmark was run.

Remaining work belongs to subsequent GPU-W00/integration slices:

1. Adapt these raw observations into the shared CORE-08 report/evidence contracts;
   this collector intentionally does not introduce a second benchmark schema.
2. Join runs with permitted build/hardware/workload identity in the collecting
   engine, without adding content or secrets to telemetry.
3. Add backend-supported prefill/device/wake subdivisions where actual observation
   is possible; preserve unknown values elsewhere.
4. Establish reproducible cold/warm and failure-path hardware baselines and quantify
   instrumentation overhead before making speed or security claims.
5. Rebuild/package through the normal release flow. Source edits do not update an
   installed app or an already running model server.


## Subsequent durable collection integration

The [measurement collection pipeline](measurement-collection.md) adds opt-in,
bounded durable session-window recording, authenticated replay/seal, an owned
host cursor, durable output and a strict CORE-08 adapter. The ring and its legacy
response remain available. Earlier statements above about no durable journal
apply to the original default collector, which remains disk-free.

A new process opening an existing journal exposes it as degraded evidence rather
than resuming or claiming completeness. Exact first-token, queue and response
completion clocks still cannot be inferred from buffered first-output timings.
The adapter preserves successful raw request outcomes with explicit conversion
gaps. Real workload baselines and full successful-serving conversion remain open.

The later single-agent follow-up records explicit wrapper acceptance, generation
admission and response completion instead of inferring them from those older
durations. Completion follows the final successful response flush and excludes
cleanup/usage persistence; final-write disconnects are failures. See the linked
measurement document for exact boundaries and versioned legacy compatibility.
Per-token emission and upstream scheduler/device clocks remain unavailable.
