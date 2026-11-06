# Private runner measurement collection

Implemented source slice, 28 October 2026: GPU-W00 and CORE-08 adapter work.
This connects the real Python handler to a Rust collector, durable cursor,
output sink and shared report types. It is an internal explicit-job entrypoint;
there is no automatic benchmark enrollment or new public CLI/UI command.
Real hardware baselines and full successful-serving report conversion remain open.

## Recording and replay

The existing timing ring remains disk-free by default. An explicit model-workload
`YOUGORI_MEASUREMENT_SESSION` value of 32 lowercase hex characters enables a
journal in that workload's existing cache. The opaque session identifier is not
a credential or a claim of VM authority. Recording starts at runner initialization.

Start records precede observed load/request work; terminal records include existing
outcomes, numeric timings and allowlisted stages. Each start, finish and seal is
flushed and fsynced. A session is bounded to 8 MiB, 8,192 events, 8 KiB per record
and 4,096 active observations. At most four session files are admitted in the
cache, with no automatic deletion of earlier evidence. These limits make this a
finite measurement window, not an unlimited multi-day journal.

The existing private `/v1/diagnostics/timings` route supports:

- GET without query: the existing bounded in-memory diagnostics.
- GET with `journal=1&after=N&limit=N`: bounded replay, at most 128 events per page.
- POST with `{"action":"seal","sessionId":"<32-lowercase-hex>"}`: close the
  recording window only when no observations remain active and storage is healthy.

Both the ordinary model token and existing engine-held admin credential are
required for replay and sealing. Query/body shape and counters are bounded;
responses use no-store. Host transport attaches the admin credential to the exact
route including its query and refuses diagnostics collection without it.
A seal stops journal recording for that window; ordinary serving and the diagnostic
ring continue. It does not claim to count later traffic or requests rejected before
the timing instrumentation boundary.

Storage failure, overflow, corruption or incomplete recovery prevents a complete
window verdict. A process opening an existing session never overwrites it or
continues it: the valid prefix is replay-only degraded evidence, and a new explicit
session is needed for a new complete window. Unknown outcomes are not guessed.

## Collection, cursor and output

`model_runner/measurement/mod.rs::collect_model` binds the collector to existing
private `model_request` transport and the durable sink. The job supplies its
session, private storage, cancellation, bounds and caller-owned typed metadata.
It is callable internally and exercised through the cross-language harness; product
command exposure and real-environment benchmark execution are separate tasks.

A collection has a page size of at most 128, at most 64 pages and at most a 60-second
async deadline. It validates session/instance identity, version, clock/units,
sequence, monotonic advertised tail, attempt starts and completions, active counts
and seal proof. Open heads and page caps remain incomplete. It refuses malformed
or legacy replay instead of silently treating a retained ring as a denominator.

A kernel lock owns each engine-private cursor directory. Cursor identity and active
attempts persist by synced atomic replacement. The collector advances only after
the matching durable output acknowledgement, never merely after a fetch.
A lost acknowledgement or crash can replay records; the sink deduplicates by event
identity across different page boundaries and rejects conflicting data, context or
operation IDs. Every raw success, failure and start remains present even when it
cannot become a successful CORE-08 record.

The sink uses a bounded atomic session snapshot with a corruption checksum, synced
before acknowledgement. It rewrites/syncs a duplicate replay too, so an in-memory
copy cannot acknowledge a disappeared output file. Its checksum detects corruption;
it is not an authentication or host-administrator tamper-resistance claim.
The app-facing wrapper runs blocking persistence off the async executor. A write
can finish after cancellation; the cursor is not advanced without its acknowledgement
and replay remains idempotent. Filesystem/power-loss durability still depends on
the storage substrate. This is not an exactly-once delivery guarantee.

## Shared report conversion and limits

The adapter uses existing CORE-08 types, exact checked conversion from decimal
milliseconds to nanoseconds, caller-provided build/workload/execution metadata and
explicit unknown measurements. It rejects unsupported fields, impossible timings,
identity mismatch and invalid report context.

Successful `load_model` call observations map to the existing activation-to-ready
stage interval, using the actual timed-load start and ready return. This does not
measure isolated process initialization or GPU transfer. Request first-output timing
may describe buffered content or tool fragments; it cannot supply exact TokenEmitted
events required for a successful CORE-08 Serving record.
Such successes retain their raw successful outcome and typed conversion gaps.
Eligible failures can be represented without inventing token events. Inclusive
stages are never summed. Unknown cache state, token counts, resources and power
remain unknown.

### Request boundaries (single-agent follow-up)

New accepted request observations contain an optional `boundaries` object:
`{"version":1,"acceptedMs":2,"admittedMs":5,"completedMs":90}`. Values are
milliseconds relative to the same attempt start as `elapsedMs`. Acceptance is
after body/schema validation and before model preparation/wake. Admission is
immediately after the wrapper acquires its exclusive generation lock, before
prompt preparation. Completion is after a successful response and final flush,
before GPU lease release, listening history and usage persistence. The outer
`elapsedMs` remains whole-handler time for compatibility; it is not response latency.
These boundaries measure the wrapper, not a backend scheduler, kernel execution
or receipt by the remote client. Pre-acceptance validation and authentication are
outside the accepted-to-completed interval.

Missing admission/completion is `null`; invalid requests have no boundaries.
Busy/preparation failures do not claim generation admission, and partial or
disconnected responses do not claim successful completion. Both llama.cpp/vLLM
and Transformers now classify failures in the final SSE finish/DONE writes as
cancellation rather than success. Buffered disconnects avoid a second response.

Legacy records without `boundaries` retain explicit unavailable gaps. New fields
are strictly versioned, bounded and ordered in Python journal replay and Rust
conversion; unknown versions and invalid fields fail closed. An older collector
that does not understand the extension also refuses it instead of misreporting it.
The durable sink retains boundaries even when no successful Serving report can
be emitted. Eligible failed reports include only observed acceptance/admission
events, with wrapper queue wait computed from those events. Successful requests
still need exact token events and trusted serving-state metadata for full CORE-08
conversion; chunk timing is never relabelled as token timing.

A sealed raw session can establish its window's attempt accounting; selecting only
convertible reports cannot establish a success denominator. The finite journal,
private storage and existing observation boundary must be stated with any result.

## Offline verification

The Python gate covers real temporary-file and authenticated HTTP journal behavior,
including ring eviction, seal races, recovery, malformed input and storage failure.
Native tests cover strict conversion, collection limits/cancellation, durable cursor
ownership and recovery, sink replay/conflicts and actual Rust/Python execution.
The cross-language fixture uses the production handler, collector, response parser,
cursor, adapter and sink; model execution is a tiny stub with FakeSubstrate metadata.
It counts 71 attempts beyond the 64-record ring, keeps successful conversion gaps,
replays with new page boundaries, tests lost acknowledgement and refuses a restarted
session's completeness. No installed engine, GPU, model download, provider or real
credential is used.

See [offline inventory](offline-tests.md) and the separate
[pinned CPU checkpoint job](cpu-checkpoint-job.md). Numerical checkpoint coverage
is unavailable in the default environment until its pinned dependencies are present.
Final gate results are recorded below after execution.

## Integrated gate result (28 October 2026)

- `npm run test:model:offline -- --scratch-root D:/YougoriBuildCache/scratch`:
  191 tests, twelve suites passed, no skips.
- `cargo test --offline --locked --manifest-path src-tauri/Cargo.toml --lib model_runner:: -- --skip swarm::`:
  125 passed, no failures or ignored tests in this filter, including three new
  measurement Rust/Python scenarios and the earlier admission scenarios.
- `npm run check:native -- --offline --locked`: all-target compilation passed.

Native gates used `D:/YougoriBuildCache/target`. Compilation reports seven
unused-code warnings for internal job constructors/diagnostic API pieces pending
PRODUCT enrollment; this is not a claim of completed CLI/UI job integration.
The source review corrected a sink mutex-guard type mismatch and removed a
redundant adapter return field. Python AST, local document links, LF and scoped
whitespace checks pass. No app rebuild/install, live workload, GPU test, commit,
push or deployment was performed. The separate CPU numerical job remains
unavailable because its five pinned dependencies are absent.

## Request-boundary follow-up verification (28 October 2026)

Worked with one agent only. The same commands above passed after the boundary and
disconnect changes: **199 Python tests across twelve suites**, **128 native
model-runner tests**, and **all-target native compilation**. No skips or ignored
tests occurred in those filters; seven existing unused internal API warnings
remain pending product integration. Packaging-size/round-trip checks also passed
within the native filter. The cross-language fixture now uses the real generation
admission and response path with only preparation/inference stubbed; successful
buffered requests retain boundaries without inventing token events.

Python AST, LF, scoped whitespace and local documentation links were checked.
No shared foundation schema, public command, installed app or real workload was
changed; no commit, push or deployment was performed. These are source and offline
integration results, not GPU performance or real-model numerical acceptance.


## Verified token-emission extension (29 October 2026)

The [token-emission implementation](token-emission-measurement.md) now connects
byte-verified streamed backend tokens to successful CORE-08 Serving reports for
ready-at-arrival requests. It records actual client-flush timestamps, bounds
traces, and retains gaps for unsupported/mismatched output. Earlier notes above
about all successes lacking conversion describe the pre-extension state;
buffered, incomplete and demand-without-backend-boundaries cases still have gaps.
