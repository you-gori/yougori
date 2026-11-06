# Owner measurement workflow

Implemented by one agent on 29 October 2026 as a G01 / S08 integration slice.
This is source implementation, not an installed release or hardware result.

## Commands and scope

```text
yougori model measure start ENV
yougori model measure collect ENV
yougori model measure status ENV
yougori model measure seal ENV
yougori model measure export ENV
yougori model measure abandon ENV
```

All commands accept `--session ID` (32 lowercase hexadecimal characters).
`start` enrolls an idle, updated runner without generating requests, reloading a
model, or changing workload settings. Enrollment refuses while a load or request
is active. Collection is explicit: there is no background collector. The owner
runs their workload between starting and sealing the window. Instrumentation
has overhead and must be held constant in comparisons.

The CLI resolves the environment and calls the `model_measurement` automation
method. Its production adapter uses the existing private model request route,
with both model and admin credentials. No credential is accepted in a command
argument or written into measurement output. The same route carries bounded
owner-only start, seal, release and abandon controls.

`collect` persists validated observations before advancing the saved cursor.
Repeated collection deduplicates overlapping pages. `seal` asks the runner to
close the window and collects through its seal marker. A request in flight, a
page budget, timeout, loss, or restart cannot turn a partial window into a
complete one. Retry collection/sealing using the saved identity and cursor.
`status` reads locally collected progress; it does not poll runner health.

`export` writes a managed `observations.json` and returns its engine-local path.
It supports partial windows. The export's `complete` field means a validated
seal was collected, not that measurements prove a performance or security claim.
It retains raw events and labels missing report context as
`ReportContextUnavailable`, with `benchmarkContext: "unavailable"` and zero
converted reports. No workload, cold/warm start, device, or cache metadata is
invented. Existing context-backed CORE-08 conversion remains available to
callers supplying trusted context; this raw CLI workflow does not claim it.

## Recovery and retention

- Identity is persisted before remote enrollment. A lost response returns
  `startUnconfirmed`; repeating `start` uses the same identity rather than
  silently creating another window. A different active session cannot replace
  the current one. To adopt an already configured
  `YOUGORI_MEASUREMENT_SESSION`, supply its ID explicitly on the first start.
- A per-environment filesystem lock serializes host operations across
  processes. The existing cursor and durable sink retain their own locks,
  checksums, bounded replay and identity checks.
- Runner enrollment resets counters only after durable journal attachment and
  only while no load/request is active. Existing/degraded files cannot be reused
  as new windows. A fresh window gets a fresh observation namespace.
- Starting after a locally completed window releases only the old sealed
  runner copy. The validated host archive remains exportable by session ID.
  Release is idempotent if its response is lost.
- `abandon` attempts collection and asks the runner to stop recording, then
  clears the local current selection. It preserves incomplete evidence and
  never invents a seal. Check `runnerStopped`: if false, the runner may still
  be recording. Retry abandonment with the old ID once reachable and idle.
- Storage is under the engine's `model-measurements/ENV/SESSION/`, with separate
  cursor and output directories. Session IDs and environment names cannot
  traverse paths; unexpected file types and corrupt state are refused.
- At most eight host session directories are retained per environment. Archive
  older session directories yourself when full; preserve the current session,
  `current.json`, and lock files. Runner journal and sink limits still apply;
  saturation is explicit loss/refusal, never silent successful completion.
  Abandoned runner journals are retained as incomplete evidence and continue
  counting against the runner's retention limit.

## Implementation and checks

- [Host workflow](../../src-tauri/src/model_runner/measurement/workflow.rs),
  [durable sink](../../src-tauri/src/model_runner/measurement/sink.rs),
  [Python runner](../../src-tauri/src/model_server.py).
- [Workflow tests](../../src-tauri/src/model_runner/measurement/workflow/tests.rs)
  cover serialization, storage bounds, invalid identities, uncertain starts,
  incomplete export, explicit abandon and sanitized errors.
- [Protocol integration](../../src-tauri/src/model_runner/measurement/protocol_integration.rs)
  exercises real localhost Python HTTP handlers and Rust collection, including
  repeated collection, seal, export, session rotation and runner restart.
  Model loading/inference are disposable synthetic fixtures; no live model,
  GPU, provider, app restart or Swarm operation is performed.
- Python journal tests exercise owner authorization, active-run refusal,
  idempotent enrollment, distinct namespaces, abandonment and storage failure.

Validation: 235 Python tests across all 12 offline model suites, 22 focused CLI
parsing/skills/catalog tests, 194 native model-runner tests and three automation
dispatch contract tests passed. The native suite includes the two new real HTTP
workflow cases. A Windows-only builder warning was corrected afterward; the
final all-target compile passed with three existing report-adapter dead-code
warnings. Unix export-directory sync remains platform-gated and was not executed
on this Windows host. Rustfmt, Python AST, UTF-8/LF, whitespace and local-link
checks also passed. Cargo gates used the shared build cache and were serialized
within this session.

## Still open

G01 still needs trusted workload/start-state metadata and report-context
enrollment, optional UI presentation, prefill/device/scheduler and retained
process wake observations, pre-arrival load attribution and additional backend
profiles. S08 still needs the remaining production report/trust consumers and
release/signature work owned by their respective agents. Hardware acceptance
and performance comparisons are separate gates. Do not reassign this CLI
session lifecycle, raw collection, or export as unimplemented work.
