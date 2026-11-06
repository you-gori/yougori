# GPU-W01: runner events and observation-fenced admission

Direct API requests can now wake the production host optimizer through a private
runner long poll. The daemon still re-observes health and applies its admission
checks; an event is a hint, never a memory reservation or an authorization grant.
Existing one-second reconciliation remains for old/unreachable runners, missed
notifications and models beyond the subscription cap.

## Protocol and runner behavior

The existing authenticated `POST /v1/yougori/optimizer` accepts `action: "watch"`
with `instanceId`, `since` and `waitMs` (0 through 5000). This uses the existing
private GPU control credential, not an ordinary model API key. Its response is a
health-shaped object containing `status` and `optimizer`. Versioned optimizer
snapshots add `controlProtocol: 1`, a random per-process `instanceId` (32 lowercase
hex characters), and a monotonic `sequence` no larger than 2^53 - 1.

Demand, readiness, residency and relevant control transitions advance the revision.
Heartbeat replies and renewal of an already-live lease do not. Watches return on
a revision/instance mismatch or wait expiry; lease expiration is reconciled too.
The runner captures a per-revision event under its state lock, preventing a lost
wake between snapshot and registration. An independent semaphore caps all private
watch requests, including lock waiters, at four. Watch deadlines do not wait forever
to reacquire a lock held by cleanup; busy deadlines return 429. Disconnect checks
run at most 250 ms apart while waiting. Counter exhaustion rotates the instance
before accepting a compare-and-set control.

Versioned phase/unload/grant controls carry `expectedInstanceId` and
`expectedSequence`. The runner reconciles expiring leases before comparing these
under the state lock. Stale observations return 409 without applying the action;
partial or malformed fences return 400. Accepted transitions return their action
flag and a causal `controlAck` with action, instance, expected sequence and the
resulting sequence exactly one greater. The acknowledgement snapshot is captured
without another expiry pass advancing it afterward. Old hosts may send both fences
absent for compatibility; the new host always fences advertised v1 runners.

## Production host integration

`optimizer::start_until` owns both its scheduling loop and `events::run` through
one `tokio::join!`. No subscription or request is detached. The scheduler passes
compact membership/cursor snapshots over a latest-value watch channel after each
health collection. Shutdown or return from the scheduler cancels subscriptions;
dropping the parent future also drops every owned transport.

`optimizer/events.rs` holds at most 128 cursors and four in-flight private watch
requests. Models without valid v1 metadata retain periodic observation. The
subscription subset rotates connections fairly; models beyond 128 retain the
same polling fallback. Paused, stopped, removed, disabled or malformed members
are omitted when the next inventory/health pass reaches the manager, canceling
their in-flight requests. Replacement incarnation tickets prevent a late old
completion from modifying the new member. Membership reconciliation remains
bounded by the existing observation cycle; it is not a separate platform event bus.

Each request asks for up to five seconds and has an eight-second outer deadline.
Failure, timeout, regression or invalid/legacy replies retry after 1, 2, 4, 8, 16
then at most 30 seconds. Successful requests have a minimum 100 ms reconnect gap,
even if a remote server replies immediately. A malformed watch reply never
downgrades that subscription to an unfenced protocol. The latest valid cursor is
kept; only a changed revision or incarnation not already seen by a health poll
notifies the host. Initial snapshots, duplicate replies and ordinary heartbeats
therefore do not cause scheduler polling storms.

The existing `Wake` coalesces notifications into one pending permit and keeps
observation-round starts at least 100 ms apart. Its one-second fallback remains.
Four long polls are separate from the existing maximum of four concurrent health
probes; serialized control requests remain separate too. Runner event bodies do
not enter a durable queue or become CORE-06 audit records.

## Admission and uncertain observations

Before the daemon updates its occupancy history, it validates advertised protocol
metadata through the same parser used by control admission. Once a running/paused
member advertises fencing, malformed/unsupported metadata, an unreachable status,
or a later missing version is unknown. A same-instance sequence regression is also
rejected. It preserves prior occupancy and blocks
new admission even when the earlier snapshot was empty. Removing the environment
from that running/paused inventory ends this in-memory protocol history. Loading
and uncertain-release states also count as occupied when a runner later stops
answering. Genuine legacy runners retain the existing compatibility behavior.

The host serializes settings changes with scheduling through one engine-owned
async mutex. A scheduling pass collects its health observations after acquiring
that mutex, so even legacy control does not use a pre-configuration snapshot.
The mutex remains held through unload/grant or idle unload. A user configuration
change waits at most 20 seconds to acquire it, then holds it through health read,
the remote configuration and persistence,
preventing disable-and-autoload from interleaving between unload proof and grant.
Configuration POST waits are bounded to the same 20-second control timeout.
Read-only settings requests and long polls do not hold this gate.

The updated host only changes settings on v1 runners, with both observation fences;
older runners remain readable and retain their existing scheduler compatibility,
but settings writes explain that the model must be restarted with the updated
engine. Before sending configuration, the host durably saves
`YOUGORI_GPU_CONFIGURATION_PENDING` in the existing workload options. This internal
marker contains only bounded validated revision/state fields, not credentials or
content. Canonical workload validation and atomic persistence apply. Failure to
persist prevents sending the command. No new standalone journal or public option
schema is introduced.

Any timeout, transport error, invalid acknowledgement or caller cancellation leaves
the marker in place. Engine restart reloads it, and marked environments stay in
the observation set even if their saved optimizer flag is disabled. A valid causal
configuration acknowledgement allows committing the desired settings and removing
the marker together. Otherwise a fresh state-lock observation can invalidate the
old command only by advancing its sequence or changing its process incarnation.
Only then is the marker removed; unchanged, regressed, malformed or legacy replies
never clear it. A malformed/sticky legacy marker cannot be overwritten by another
configuration. The waiting model is told that a GPU configuration outcome is
unconfirmed instead of assuming the GPU is free.

Disabled GPU-runner workloads remain observed (CPU/source-only workloads are
excluded). A disabled resident, loading, active or uncertain runner blocks managed
grants even after its pending command has been causally resolved. Its waiting reason
explains that automatic memory management is off and asks the user to re-enable it
or stop the model. Clearing a command marker is never proof of released memory.
Unreadable options for a known GPU model also block admission instead of silently
removing its occupancy history. Stopped/deleted environments leave the running/paused
observation set; retained marker metadata is checked if that environment starts again.

This gate serializes one engine's actions, not arbitrary holders of the private
credential. User-selected unmanaged operation still has its existing semantics.
Observation fences bind one runner process/revision; they are not CORE-04 VM
authorization epochs, model activation identity, GPU capacity leases or exactly-once
delivery. No public API command or runtime category changes here.

## Verification and remaining scope

The host tests use controlled futures/channels, not real models: connection caps
and fair rotation, ownership on shutdown or membership closure, removal/restart,
direct-demand events, heartbeat suppression, health/watch cursor overlap, invalid
reply backoff, deadlines, bounded cursor storage and stale completion rejection.
Additional scheduling regressions cover malformed metadata, downgrade and revision
rollback attempts, disabled occupancy, and conservative occupancy after
loading/uncertain runners stop answering. Configuration fixtures cover marker
serialization through canonical workload options, strict causal invalidation,
malformed/legacy retention and payload minimization.

The coordinating gate also runs the runner's real loopback HTTP/socket fixtures,
control-transition regressions and a cross-language integration fixture that
drives these production adapters against disposable Python servers. See the
gate's reported results; test implementation alone is not a passing result.

No installed engine, real model download, GPU workload or deployment is needed
for these fixtures. Attributable GPU-W01 performance acceptance still requires
authorized isolated workloads and comparable hardware measurements. This work
does not finish the combined plan or its hardware/VM integration packages.


## Cross-language execution fixture

`model_runner/optimizer/protocol_integration.rs` starts the real Python HTTP
handlers in disposable processes through `protocol_fixture.py`. The Rust side
uses the production event manager, control coordinator and response parser;
only model weights/generation and the loopback transport binding are synthetic.
Four scenarios exercise:

1. Direct API demand waking the host before periodic polling, followed by a
   fenced unload/grant that completes chat.
2. Runner replacement between phase and grant.
3. Withdrawal of target demand between phase and grant.
4. A delayed configuration command refused after the resident was unloaded.

The native model-runner test filter therefore requires Python, matching the
repository's offline verification prerequisite. Fixture environments are
allowlisted, caches are disposable, tokens are synthetic, and each owned Python
process is killed/reaped before its cache is removed. No app instance, GPU,
model download, production environment or external service is used.

## Completed gate (28 October 2026)

- `npm run test:model:offline -- --scratch-root D:/YougoriBuildCache/scratch`:
  163 tests across ten suites passed, including 19 private protocol tests.
- `cargo test --offline --locked --manifest-path src-tauri/Cargo.toml --lib model_runner:: -- --skip swarm::`:
  93 tests passed, including all four cross-language scenarios.
- `npm run check:native -- --offline --locked`: all-target compilation passed.

Native gates used `D:/YougoriBuildCache/target`. A pre-existing status fixture
was corrected to advertise `enabled: true` for its healthy managed resident;
disabled occupancy now intentionally blocks admission. No installed app,
workload, commit, push or deployment was changed by these gates.
