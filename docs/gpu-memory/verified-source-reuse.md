# Verified local source reuse and load ownership

Implemented by one agent on 29 October 2026 as the local-source reuse and
per-runner load deduplication parts of G02 / GPU-W01.

## Behavior

After preparing a pinned vLLM checkpoint, the runner may retain one process-local
source description. It binds the model name, immutable revision, cache root and
pinned vLLM version to the snapshot root, verified file identities, configuration
and conservative weight-byte estimate. This is a memo of existing source files;
it does not publish another artifact catalog or persist a new trust authority.

Before retaining it, the runner inventories the actual snapshot and requires
checksums and sizes for every file from that revision's metadata. It validates
weights, configuration, tokenizer files, indexes and any other present artifacts
through the existing bounded hash/stamp verifier. Configuration must still match
the one used by preflight. Missing checksums or unsupported inventory shapes
leave the existing preparation path available, without creating a reuse memo.

On reload, the same files must exist with the same pinned identities. File
membership is checked before and after verification. Changed bytes, missing files
or added files invalidate the memo and refuse that load; they never silently
become a different checkpoint. Identical replacement bytes can be accepted after
verification. A changed model/revision/cache/backend identity selects the normal
preparation path. Configuration returned from the memo is a detached copy.

A successful reuse skips Hub metadata/configuration requests and snapshot
preparation, even when remote access is unavailable. It still checks the installed
runtime version, model architecture, hardware fit and scheduler admission and
starts the same backend with the same arguments. GPU allocations, process state,
weights in VRAM and KV are not retained by this change. `sourceReused` in runner
health describes source preparation only and is reset for every load attempt.

## Bounds and fallback

The source memo is lost on runner restart; fresh processes use normal pinned
preparation. Inventory is capped at 4,096 entries, paths at 1,024 characters and
metadata at 16,384 file entries. Directory symlinks and special files cannot enter
the memo. Normal Hugging Face file symlinks are allowed because their bytes and
sizes are checked. Root configuration comparison reads at most 2 MiB plus one.

An owner may set `YOUGORI_VLLM_SOURCE_REUSE=0` in the workload environment to keep
the original preparation path. It does not disable ordinary weight verification.
No new CLI command, UI setting or backend upgrade is introduced.

The existing file verification stamps remain cache hints in the same filesystem
trust boundary. This is not protection against a privileged writer changing files
between validation and backend reads, or forging the local verification cache.
Catalog leases/immutable handles and broader lifecycle integration remain G04/S02.

## Load ownership

The production `load_model` entry has one owner. Simultaneous duplicate load
notifications return without starting another dependency/download/backend pass,
creating another load timing record, or running another owner's GPU cleanup.
Exceptions release ownership so a later retry can run.

Ownership is released under the existing GPU state lock before publishing load
completion. This prevents a new scheduler grant from being dropped while the
previous load owner is leaving. The existing active-request, pinning, revision,
uncertain-release and host-ledger rules are preserved. This is per-runner
single-flight; it is not cross-container download deduplication.

The load timing wrapper measures the load body through its ready/error return;
final GPU cleanup/publication follows it under the state lock. It does not claim
allocator cleanup duration or device timing.

## Verification and remaining work

Tests use real tiny source files, pinned hashes, actual verification and the
production vLLM startup/reload path with only dependencies, GPU and process/HTTP
execution stubbed. The reload test makes every remote metadata/config/download
call fail after first preparation, checks unchanged process arguments and repeated
admission, then corrupts a tokenizer and verifies no third backend starts.
Other regressions cover metadata gaps, identity changes, membership races,
changed configuration/weights/indexes, verification hints, bounds, duplicate loads
and exception/retry ownership. No model download or real GPU is used.

G02 still includes supported sleep/retained-process integration, representative
concurrency/eager tuning and cross-environment deduplication where applicable.
No startup-latency percentage or hardware performance result is claimed here.

Offline Python gate: 215 tests across twelve suites passed. The final diagnostic
reset was also checked in the 40-test startup/serving suite. All 149 native
model-runner tests passed, including helper packaging/round trips and earlier
HTTP/admission/measurement integration. All-target native compilation passed
with seven existing unused measurement-API warnings. Native gates were serialized
in this session using `D:/YougoriBuildCache/target`. Scratch fixtures used the
shared scratch directory; scoped AST, UTF-8, LF, whitespace and local links passed.

No live engine, GPU, provider, download, commit, push, installation or release was
performed. Other sessions' changes are preserved.
