# GPU-W01: host wake hints for engine-owned demand

The host scheduler can now react to demand that the engine already knows about,
without always waiting for its next one-second reconciliation poll.

`model_runner::model_request()` signals the optimizer after a POST to
`/v1/yougori/prepare` or `/v1/yougori/release` has received a successful, parsed
response. Connection failures, HTTP errors and response parsing failures do not
signal. The hook runs after the response, so a preparation request has reached the
runner before the host tries to observe it. A successful optimizer-settings change
also signals after its workload options have been saved. Read-only settings queries
do not signal.

The hint does not mean a model is ready or a memory grant is authorized. Even a
200 response describing a model error is only a reason to re-observe state. Every
wake follows the existing authenticated status collection, residency checks,
ordering, unload acknowledgements and private grant path. No request content,
model identity, key or response data is stored in the hint.

## Scheduling and limits

- One process-local Tokio `Notify` serves the existing single host scheduler.
  It stores at most one pending permit; a burst does not allocate an event queue.
- A hint received while the scheduler is working remains pending for its next
  round. Requests and settings do not spawn another scheduler or a probe task.
- Starts of observation rounds are at least 100 ms apart. A long-running round
  incurs no additional rate-limit wait after that gap has elapsed. The existing
  maximum of four simultaneous status requests remains in place.
- With no hint, the existing one-second delay after the preceding round remains
  the reconciliation fallback. Lost notifications therefore do not remove polling.
- Shutdown wins over a pending hint and interrupts both the ordinary wait and
  the rate-limit wait. Collection and control calls keep their separate shutdown
  checks.
- Health reads, chat completions and the scheduler's own phase/unload/grant calls
  do not signal. This avoids polling/control responses creating a feedback loop.

The wake helper lives in `model_runner/optimizer/wake.rs`; its consumers are the
existing `optimizer.rs` loop and settings method. The only change to the shared
`model_runner.rs` entrypoint is the post-response hook. Other sessions' edits in
that file are preserved. No dependency, public endpoint, CLI command, durable event
stream, audit format or shared CORE schema is introduced.

## Verification and remaining scope

Eight offline tests cover preparation/release hints, failures and excluded paths,
10,000-notification coalescing, notification after waiter registration, periodic
reconciliation, rate limiting and cancellation, hints received during work, and
shutdown priority. Dedicated notification tests use a 30-second reconciliation interval and
require immediate readiness or bounded completion, so normal one-second polling
cannot account for their success. They use controlled futures and no live engine.

On 28 October 2026, the focused native optimizer suite passed all 27 tests,
including the eight new wake tests, with no ignored tests or compiler warnings.
The all-target native compile check also passed on Windows without warnings.

```powershell
$env:CARGO_TARGET_DIR='D:/YougoriBuildCache/target'
cargo test --offline --locked --manifest-path src-tauri/Cargo.toml --lib model_runner::optimizer:: -- --skip swarm::
npm run check:native -- --offline --locked
```

This completes the engine-known preparation/release/settings wake path, not all
host demand discovery. Direct API clients that contact the runner without going
through `model_request()` still rely on reconciliation. Chat requests do not acquire
new preparation leases through this change. A runner-to-host event transport for
those requests needs separate protocol, resource-bound and compatibility work.
No production latency gain is claimed without isolated hardware measurements.
The installed app and already-running workloads are not updated by source edits.


The runner-origin transport previously left open by this slice is implemented
in [event-driven admission](event-driven-admission.md): bounded private watches
now supplement these hints in the production scheduler. Periodic reconciliation
remains for recovery, legacy runners and workloads beyond the subscription cap.
Hardware latency acceptance remains separate.
