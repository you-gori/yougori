# Local GPU admission through the shared ledger

Implementation slice: CORE-03, GPU-W02 and GPU-W05, 28 October 2026.
One agent implemented this work. It adopts the existing foundation ledger in the
production optimizer; it does not replace the ledger with separate capacity math.

## Supported profile and behavior

Newly created **local, single-GPU vLLM** models are enrolled after the existing
hardware preflight succeeds. Their workload options contain a versioned admission
profile and a bounded memory demand derived from the model preflight. The demand
is an estimate, not a measured peak. The reservation is at least the bundled
vLLM launch's 90% GPU-memory budget and at least the preflight demand. A separate
256 MiB supervisor reserve remains unavailable to models.

Legacy models, multi-GPU, other model backends, remote providers, native Metal,
and VM-owned model allocations are **not** silently enrolled or presented as
covered. Their existing execution categories remain unchanged. Unsupported or
corrupt advertised profiles fail closed. Enrolled models cannot turn off
Automatic GPU memory and bypass admission; pinning remains available.

Capacity is sampled on the host using bounded direct `nvidia-smi` execution.
Stable machine and GPU identifiers are hashed; raw identifiers are not logged.
The parser requires one GPU, valid memory totals/usage and disabled or unsupported
MIG. Missing used-memory data, topology changes, malformed output, cancellation
or probe failure refuse a new grant. Each child query has a five-second deadline,
bounded output and explicit kill/reap on failure. Windows queries the registry
identity and NVIDIA tool as separate hidden processes, without a shell child.

## Transaction and accounting

The production scheduler serializes these steps with user optimizer configuration:

1. Fence the target's phase and obtain causal unload acknowledgements from the
   old residents. This step cannot grant a target load.
2. Check every persisted old grant intent. A later revision of the **same** runner
   must make the old compare-and-set impossible, and the runner must report no
   active/resident/loading/uncertain state. A replacement runner alone does not
   prove the old process died. Unknown or unavailable intents block admission.
3. Obtain fresh host capacity evidence. Under the shared ledger lock, charge all
   observed used memory as unmanaged usage before retiring this adapter's old
   reservations. Residual allocations remain charged; no guessed managed usage
   is subtracted. Other clients' live reservations on this GPU prevent this
   reclassification until they release them.
4. Atomically reserve a host-level runtime envelope and a model-placement child.
   CORE-03 charges physical memory once; the child is carved from the envelope.
   Existing tenant limits are preserved. The handle is available through
   `model_runner::host_capacity_ledger()` for subsequent production consumers.
5. Conservatively mark both reservations in use, then persist the exact target
   instance/revision intent using the existing synced atomic workload-options
   writer. Only then send the matching grant.

Disk failure, cancellation, transport error and lost acknowledgements do not free
an in-use reservation or erase its durable intent. The next attempt must reconcile
the intent before starting another load. Engine restart reconstructs uncertainty
from workload options and resamples physical usage; it does not deserialize old
ledger IDs into a new ledger. A stopped, missing or replacement runner can require
resuming its environment or recreating it when no lifecycle proof is available.
Idle unloads also reconcile and release reservations without waiting for another
model's demand; they require the same fence and host-evidence checks.

Capacity errors become existing model waiting reasons. The scheduler keeps its
existing oldest-demand selection and one-resident policy; this does not claim
new multi-model placement or fairness. Closed ledger records and queue events are
not drained by this client. Until a shared audit consumer owns their retention,
the adapter refuses new reservations at 4,096 closed records and asks for a new
engine accounting session. Workload grant intents survive that restart.

## Limits and remaining work

This is admission accounting, **not a hardware VRAM quota**. An unmanaged process
can allocate after a sample, and runtime peak estimates can be wrong. Driver OOM
handling remains necessary. The host sample and recorded transition fence are
evidence for this local supported profile, not attestation or proof of hostile
guest honesty. Physical usage left after an unload remains counted conservatively.

CORE-03 is not globally complete: real VM/transfer consumers must adopt the same
host handle, with lifecycle-owned parents, additional resource kinds, explicit
sharing, retention/export of ledger events and finer observed allocation ownership.
Multi-GPU/rank placement and other backends need their own reviewed demand/topology
contracts. This slice keeps the old scheduler's selection policy rather than
introducing a second queue.

The intent writer provides process-crash recovery using synced file contents and
atomic replacement. Filesystem/platform power-loss durability is not established
by the offline tests. Real hardware acceptance, measured performance, installed
application updates and release are separate work.

## Verification

Tests exercise the real ledger: parent/child charging, external pressure, another
client's reservations, preserved tenant limits, cancellation beyond the grant TTL,
stale/replaced device evidence, bounded probe parsing/process cancellation, ordering
of eviction/reservation/persistence/grant, failed storage, lost acknowledgements,
and recovered/orphan intents. A cross-language test runs the actual Python
optimizer and HTTP model handler after the actual Rust ledger transaction; only
hardware evidence, weights and model execution are fixtures. It checks the saved
intent against the grant fence and completes a request after admission.

No live engine, GPU query, model download, provider or installed workload was used
for these checks. Final command results are recorded in the completion entry below.

## Completion evidence — 28 October 2026

- `cargo test --offline --locked --manifest-path src-tauri/Cargo.toml --lib model_runner:: -- --skip swarm::`: **143 passed**, no failures or ignored tests in this filter. This includes 15 additional admission/probe/integration regressions relative to the previous 128-test round.
- `cargo test --offline --locked --manifest-path cli/Cargo.toml --lib skills::`: **11 passed**, including the updated model-optimizer instructions.
- `npm run check:native -- --offline --locked`: **all-target compilation passed**. Seven existing unused measurement API warnings remain; this slice added no new warning category.
- Scoped whitespace, LF and local documentation-link checks passed.

Native gates ran serially in `D:/YougoriBuildCache/target`. An initial compile
failure came from an existing `foundation/text.rs` implementation whose module
declaration was missing; the integration added only `pub mod text;`, preserving
that implementation and its consumers. Final checks use the completed source,
including idle release and conservative replacement-runner handling.

The combined plan and unfinished-work view now record this source delivery and
the remaining profiles/acceptance. No commit, push, installation, live workload,
GPU operation or deployment was performed. The wider application unit suite and
real GPU/VM acceptance are not claimed by the focused test filters above.
