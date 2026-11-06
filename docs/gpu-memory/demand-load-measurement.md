# Correlated demand-load measurement

Implemented by one agent on 29 October 2026 as another G01 / GPU-W00 slice.
This extends the existing private runner journal and CORE-08 adapter. It adds no
public command, backend dependency or automatic measurement enrollment.

## Observation boundary

During an explicitly recording journal session, `timed_load` retains one bounded
observation: the load attempt ID, its monotonic call-start time, and the timestamp
at successful return with the runner ready. A failed/new load or memory release
invalidates the old observation. A late finish cannot replace a newer attempt.
This is the existing `load_model` wrapper boundary, including its internal waits;
it is not a CUDA event, pure weight-transfer time or retained-process wake.

At actual `gpu_enter` readiness admission, a request can copy this observation
once, only if the entire completed load lies after its accepted boundary and
before generation admission. The request and load use the same runner monotonic
clock. Concurrent waiters can reference the same load ID while retaining separate
request records. The load is shared work: durations across those requests must
not be summed as exclusive resource cost.

The optional `demandLoad` version-1 extension contains only
`source: runner-load-call`, `loadAttemptId`, `startedMs` and `readyMs`.
Times are relative to this request's attempt start. The ID belongs to the same
runner instance/session as its containing journal record; no credentials, model
content, paths or exception strings are included. Existing record/window bounds
apply and only one latest load is held in memory.

Loads that started before request acceptance are deliberately omitted instead of
being retimed to arrival. Incomplete/failed loads, disabled/sealed journals, and
the narrow ready-before-wrapper-return race also yield no completed interval.
Missing data stays unknown. Uninstrumented requests and legacy records retain
their existing shape and conversion behavior.

## Reporting and replay

Python replay and Rust parsing validate the closed schema, source/version,
bounded IDs, request association and `accepted <= start <= ready <= admission`
ordering (or elapsed duration when a failed request was never admitted).

Successful CORE-08 Serving conversion requires exact verified token observations
and trusted caller context stating `NotLoaded` at arrival. The report includes
RequestAccepted, LoadStarted, LoadCompleted, RequestDequeued, token emission and
RequestCompleted, allowing CORE-08 to check the load is inside time to first token.
Ready/asleep context conflicts remain raw with `ServingStartStateMismatch`;
unknown state or incomplete token observations retain their existing gaps. A load
never turns a failed request into a success. Legacy demand records still retain
`DemandWorkBoundaryUnavailable`, preserving durable replay compatibility.

The actual HTTP relay, journal, collector, cursor, report conversion and sealed
sink reopen are exercised together with synthetic loading/inference. The test
changes no installed app and uses no GPU or downloaded model. Other tests cover
concurrent waiters, invalidation during failed release, stale completion, prior
loads, strict malformed input rejection, opt-in behavior and detached snapshots.

## Remaining scope

Backend scheduler, CUDA/device, prefill and retained-process wake clocks remain
open, as do loads already underway at arrival, other output profiles, production
session enrollment/trusted context and hardware qualification. This slice makes
no speedup claim and does not complete all of G01. Subsequent work delivered
[owner CLI session enrollment and raw export](measurement-workflow.md); trusted
report-context enrollment and the remaining backend observations stay open.

## Verification

- Offline Python gate: 228 tests across twelve suites passed, including 35 timing
  tests and 19 journal tests.
- Native model-runner gate: 178 tests passed, including four new demand-report
  cases and the actual HTTP-to-sealed-sink demand-load integration.
- All-target native compile passed (`npm run check:native -- --offline --locked`),
  with seven existing unused measurement-API warnings.
- Scoped Python AST, rustfmt, UTF-8/LF, whitespace and documentation link checks
  passed.

Shared target: `D:/YougoriBuildCache/target`; disposable test scratch under
`D:/YougoriBuildCache/scratch`. No agents, live workloads, installation, commit,
push or release.
