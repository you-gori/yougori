# GPU-W00 offline regression gate

The GPU-W00 task to inventory Python tests and wire fast regressions into existing
verification is implemented through `package.json`. Both `npm run verify` and
`npm run verify:windows` run `npm run test:model:offline` before their expensive
checks, and a failure stops the verification chain. Python 3.12 must be installed.

The source plan's CI inventory predates the current release policy:
`.git/info/exclude` deliberately keeps `.github/workflows/` local and states that
public releases do not use GitHub Actions. This change preserves that decision;
no Actions workflow is added or enabled. If CI is reintroduced, invoke the same
gate after Python setup, with a job/step timeout of at least 20 minutes.

## Run locally

Python 3.12, standard library only:

```powershell
npm run test:model:offline
```

For the shared Windows checkout, use the existing build scratch directory:

```powershell
npm run test:model:offline -- --scratch-root D:/YougoriBuildCache/scratch
```

The scratch parent must already exist. The gate creates and cleans its own child
directories only. `--list` prints the selected files without executing tests.
There is no dependency installation, model download or installed Yougori invocation.

## Inventory and selection

The gate uses an explicit file list. Adding a file requires reviewing its runtime,
network, dependency and cleanup behavior; broad discovery could run hardware or
optional-dependency tests accidentally. Counts below describe the local verification
on 28 October 2026 and are not hard-coded acceptance thresholds.

| Included file | Tests | Purpose |
| --- | ---: | --- |
| `scripts/test-model-offline.test.py` | 5 | Gate failures, environment filtering, timeout propagation and temporary-cache cleanup |
| `scripts/test-model-checkpoints.test.py` | 13 | Separate pinned CPU job preflight, timeout, cleanup, redaction and false-green rejection |
| `scripts/model-server.test.py` | 39 | Stubbed model startup, auth, request validation, usage, streaming and decision transport |
| `src-tauri/src/model_server_test.py` | 29 | GGUF relay, bounded download records/backpressure, worker cleanup, verification cache and mocked GPU queries |
| `src-tauri/src/model_verification_test.py` | 13 | Stable bounded hashing, Windows metadata semantics, bounded cache hints and concurrent writer recovery |
| `src-tauri/src/model_timing_test.py` | 22 | Bounded timing, request admission/flush boundaries, final-write disconnects, first output and diagnostics authorization |
| `src-tauri/src/model_journal_test.py` | 17 | Durable start/outcome/seal records, versioned request boundaries, authenticated replay, storage failure and conservative recovery |
| `src-tauri/src/model_registry_test.py` | 14 | Bounded manifest validation, complete preflight, artifact integrity, immutable revision and path checks |
| `src-tauri/src/gpu_optimizer_test.py` | 24 | Memory admission, expiry, pinning, request wake-up, uncertain unload/failed-load recovery and control error sanitization |
| `src-tauri/src/gpu_optimizer_protocol_test.py` | 19 | Real HTTP watch/auth/expiry/restart/CAS races, disconnect cleanup and disabled-loader occupancy |
| `src-tauri/src/gpu_optimizer_integration_test.py` | 1 | Two disposable loopback HTTP servers with synthetic weights and stubbed loading |
| `scripts/model-chat-client.test.py` | 3 | Client credential retrieval and streaming with mocked CLI/HTTP calls |

Total: **199 tests, twelve suites, no skips**. Suites use fake models and GPU results;
some exercise real loopback sockets and short-lived Python fixture processes. They
do not connect to the installed engine, start a production model or run a GPU job.
Simulated startup messages describing GPUs/downloads are fixture output.

These suites remain separate:

| Excluded file/category | Reason |
| --- | --- |
| `scripts/model-checkpoint.test.py` | Requires the pinned model runtime dependencies and real tiny CPU checkpoint inference; its dependency-based skips must not pass as coverage in this stdlib gate |
| `scripts/model-decisions.test.py` | Requires PyTorch, Transformers and safetensors for real tiny CLEF inference |
| `scripts/test-macos-model-runtime.py` | Native Mac runtime acceptance has its own manual workflow and built runtime prerequisites |
| CUDA/runtime acceptance and benchmark suites | Require explicit hardware/runtime prerequisites and isolated execution |
| Swarm tests | Outside this model-runner task and absent from the explicit list |

The first two suites now have a [separate pinned CPU job](cpu-checkpoint-job.md),
run with `npm run test:model:checkpoints`. Its numerical coverage is unavailable
until the required interpreter and packages are installed; it fails on missing
dependencies or skipped tests. Its stdlib job regressions are included above.
No new checkpoint numerical-correctness or hardware-performance coverage is claimed.

## Gate behavior

Each suite runs in a fresh Python process with `-I -B`: no user site or inherited
Python import path, and no bytecode output. The child receives only necessary OS
launch variables, disposable home/cache/temp paths, offline Hugging Face settings,
disabled telemetry, empty CUDA device visibility and proxy bypass for fixtures.
Provider credentials and inherited `YOUGORI_*` source/configuration variables are
not copied. Test fixtures may then set their own synthetic configuration.

The parent checks that all listed files exist before starting. A suite must execute
at least one test with no failure, error, skip, expected failure or unexpected
success. A timeout, import error or interpreter startup failure fails the gate;
later passing suites cannot erase it. Remaining suites still run for useful failure
diagnostics. Each child has a 120-second timeout. Output goes directly to the test
log rather than an unbounded parent buffer.

This is a regression harness for reviewed repository tests, not a security sandbox.
Offline environment flags and hidden CUDA devices do not enforce a host network or
device boundary. New fixtures must keep their own resource cleanup and bounded
child-process behavior; a future hardware suite must not enter this gate by merely
renaming a file.

The full command passed locally on Windows with Python 3.12. The full application
verification chains were not run by this session, since those include unrelated
builds and suites; their new model step was run directly. Changes remain uncommitted
for the coordinating session. No application rebuild is needed for this test-only
change. GPU-W00 still needs hardware baselines and the other reporting/probe work.
