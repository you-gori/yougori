# GPU-W01: bounded optimizer control transitions

Scheduler phase, unload and grant requests previously inherited the general model
POST timeout of 1,800 seconds. An unresponsive control endpoint could therefore
stall scheduling and delay engine shutdown. Independent status probes already had
short timeouts; control requests now have their own bounded wait as well.

`model_runner/optimizer/control.rs` implements the existing request sequence:

1. Ask the target model to report the freeing-memory phase. If this request fails,
   times out or is cancelled, stop before unloading any current model.
2. Unload current resident models one at a time. Every response must contain the
   JSON boolean `unloaded: true`. Refusal, missing/malformed acknowledgement,
   transport failure, timeout or cancellation stops the sequence immediately.
3. Grant the target only after every required unload is acknowledged. With no
   residents, the target phase request still precedes the grant.

Each request has a 20-second deadline, covering connection and response handling.
The existing runner allows 10 seconds for native-engine termination and another
5 seconds after killing it; this leaves a small transport margin without reusing
the inference deadline. The deadline bounds the host wait, not the duration of
remote cleanup. Async deadlines and cancellation are cooperative; they cannot
forcibly interrupt synchronous runtime or credential-store work. The same wrapper
bounds idle-unload requests. Ordinary inference
and user-issued configuration methods keep their existing behavior.

Shutdown is checked before polling each request, with cancellation taking priority
when both branches are ready. No request task is detached, and no subsequent
control is sent after the wrapper observes cancellation. Calls remain serial; the
four-way concurrency introduced for status observations never applies to unloads
or grants. Existing private control credentials and runtime transport are reused.

## Uncertain outcomes and reconciliation

A timeout or dropped connection does not prove that the remote operation stopped.
It may have completed before its response was lost or may still be running. This
helper never treats an uncertain unload as freed memory, and it does not grant the
target in that transition. It does not automatically retry a request within the
transition. The scheduler observes current model status again on its next round
and applies its existing residency/loading checks before making another decision.

The Python runner also preserves uncertainty across that next observation. It sets
`releaseUncertain: true` during unloading, retains the native process handle until
exit is confirmed, and keeps `resident: true` after a cleanup exception. Here
`resident` conservatively means memory must still be treated as occupied; it does
not mean the model is ready for inference. The state becomes `error` with a generic
message, and new loading is refused even if automatic memory management is disabled.
Only a successful unload clears the flag; restarting the model environment is the
other recovery route. With automatic management enabled, a later unload attempt
can reconcile a process that exited after the earlier timeout. A failed allocator
cleanup remains uncertain even when model object references have already been
dropped. Unexpected control exceptions return a sanitized 503 response rather than
letting native command arguments appear in an HTTP-server traceback.

The GPU optimizer card gives this optional `releaseUncertain` field priority over
its ordinary Ready/Loading label. It shows "Memory release unconfirmed" and an
instruction to restart the model environment if it does not recover. When a later
response clears the flag, the card returns to the usual state. Older runners that
omit the field retain their existing display behavior.

An acknowledged earlier unload is not rolled back if a later unload fails.
Restoring that model, if subsequently requested, follows the ordinary loader.
Similarly, a failed grant response is not proof that loading never started; a
future round must inspect the runner. Cancellation only drops local request futures
and makes no exactly-once or remote-rollback guarantee.

The internal outcomes are `Cancelled`, `TimedOut` and `Rejected`. They carry no
backend error text, request content or credentials. No new API endpoint, CLI option,
configuration value or dependency is introduced. The one-second host discovery
loop and the runner's grant/eviction checks remain unchanged.

## Verification

Eight new offline Rust tests cover serialized successful switching, phase/grant
failure, strict unload acknowledgement, failure after partial reclamation, timeout
cleanup, in-flight cancellation, cancellation between steps/before the first send,
and switching with no residents. Controlled futures and synthetic responses stand
in for the runtime. No installed engine, model, GPU or external service is used.

On 28 October 2026, the focused native optimizer suite passed all 19 tests,
including the eight new control-transition tests, with no skips or warnings.
Three Python regressions cover native-process exit timeout/retry, allocator cleanup
failure/retry and sanitized control errors. The offline gate passed all 105 tests
across eight suites, including 20 optimizer tests, with no skips.
The all-target native compile check also passed on Windows, without warnings.
All five optimizer-card tests passed, including uncertain-state/recovery and older
runner compatibility. Repository lint, app-only TypeScript and the Vite production
bundle passed. The full `npm run build` remains blocked by pre-existing grid-removal
work: `e2e/grids.spec.ts` lines 14, 15 and 79 import the deleted
`src/api/grids/wire.ts` and `src/api/grid-api.ts`. Those files were left to their
owner, with the failure recorded on the coordination board. The separate app checks
do not make that full build green.

```powershell
$env:CARGO_TARGET_DIR='D:/YougoriBuildCache/target'
cargo test --offline --locked --manifest-path src-tauri/Cargo.toml --lib model_runner::optimizer:: -- --skip swarm::
npm run check:native -- --offline --locked
```

This is a reliability slice of GPU-W01, not its complete acceptance. Isolated
hardware comparisons, host demand event transport and the other backend-specific
optimizations remain open. Source edits reach the installed app and workloads only
through the normal rebuild/deployment flow.
