# GPU-W01: bounded concurrent model status collection

The host optimizer now collects independent model health observations with at most
four request futures in flight, instead of waiting for each model serially. Each
running model retains its existing three-second timeout. A completed request frees
its slot immediately, even when an earlier request is still pending.

Results are restored to environment input order before the scheduler consumes
them. Equal-age demand ordering therefore does not depend on response speed.
Paused models remain in the snapshot with unknown health and are never probed.
Failed or timed-out requests also remain unknown. The existing `observe()` logic
still treats an unresponsive, previously resident model as holding GPU memory;
timeout does not become proof that memory is free.

The collector owns its request futures directly, without spawning background
tasks. Scheduler cancellation drops in-flight probes and the remaining input,
returns no partial snapshot, and stops before scheduling from that batch. The
same scheduler awaits every batch, so it does not accumulate overlapping rounds.
Grant and unload operations remain serialized. The one-second reconciliation loop
and runtime authorization are unchanged.

The new helper is `src-tauri/src/model_runner/optimizer/status_batch.rs`; its caller
is the existing optimizer loop. It reuses the repository's futures/Tokio
dependencies and the existing `model_status()` transport, response limit and
credentials. No new endpoint, API schema, public setting or dependency is added.

Six offline Rust tests cover the concurrency cap, progress past a slow first
request, ordering, paused/error/timeout handling through the existing resident
observation logic, cancellation before/during collection and empty batches. Tests
use controlled futures, channels and counters; no engine, GPU or external model
server is run. Correctness checks do not establish a measured workload speedup.

On 28 October 2026, the focused native optimizer suite passed all 11 tests (six
new collector tests and five existing scheduling/residency tests), with no skips
or compiler warnings. `npm run check:native -- --offline --locked` also passed for
all configured native targets on this Windows checkout, with no warnings.

Relevant verification commands use the shared build cache:

```powershell
$env:CARGO_TARGET_DIR='D:/YougoriBuildCache/target'
cargo test --offline --locked --manifest-path src-tauri/Cargo.toml --lib model_runner::optimizer:: -- --skip swarm::
npm run check:native -- --offline --locked
```

Full GPU-W01 acceptance still needs isolated real-workload comparisons. The host's
one-second demand-discovery delay is a separate event-transport integration task;
the runner-side readiness notifications are documented in `runner-wake.md`.
Source changes do not update the installed application or existing workloads.
