# Bounded download progress and cleanup

This implements a focused GPU-W00 correctness fixture and download-recovery
improvement under the combined GPU/VM plan. It supports GPU-W11 rollout work;
it does not complete either work package or change the download transport.

`src-tauri/src/model_server.py` now reads worker stdout in records of at most
1,048,576 text characters, including the newline. An oversized or truncated
record, invalid JSON, unexpected event, invalid counter, or I/O/decode failure
ends the attempt with a generic failure event. Raw worker output is not logged.
This is a character bound, not a byte-exact heap budget: Python strings, JSON
objects and the text decoder also have bounded per-record overhead.

Before queue insertion, cached filenames are checked against the requested files,
deduplicated and reduced to their known byte total. Transfer/written counts must
be nonnegative integers at most 2^63 - 1 (booleans and floats are rejected).
Completion roots must be nonempty, contain no NUL and be at most 32,768 characters.
Unused fields are discarded. The queue retains at most 128 normalized records;
it does not retain each worker's entire cached filename list or extra fields.

A full queue applies backpressure instead of dropping progress or completion.
Queue insertion checks a cleanup event every 100ms. Completion, failure and EOF
end the reader after delivery; shutdown can cancel their insertion. Cleanup sets
that event before terminating/reaping the owned worker and joining the reader.
A broken request pipe also enters cleanup and the ordinary retry path. The
worker's stdout read still depends on worker termination/EOF to unblock; this
change does not introduce a subprocess-tree supervisor or a universal hard
deadline for OS process termination.

The existing Xet-to-HTTPS retry, inactivity threshold, success exit-code check,
completed-cache reuse and deletion of only this attempt's partial files remain.
The UI's numeric download fields and credential handling remain compatible.
Workers must emit newline-terminated records; exceptionally large cache records
now fail safely rather than consuming unbounded memory.

## Verification

On 28 October 2026, `model_server_test.py` passed 29 tests, including eight new
tests for normalization, malformed and oversized records, sanitized I/O failures,
terminal delivery under backpressure, cancellation of a full queue, broken stdin
cleanup, and a synthetic malformed worker followed by a successful HTTPS retry
with 1,000 progress records. Existing stall, partial-cache cleanup and completion
boundary tests also pass.

The complete offline model gate passed 113 tests across eight suites, with no
skips. It uses synthetic subprocesses, fake models and loopback HTTP fixtures;
no real model download, GPU, installed app or live engine was exercised. The
installed app needs a separately built release to receive this source change.
