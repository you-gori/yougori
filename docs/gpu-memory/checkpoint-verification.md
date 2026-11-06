# Checkpoint verification and bounded cache recovery

This is a production-runner correctness slice of GPU-W00/GPU-W01 in the combined
GPU-memory and VM-sandbox plan. It hardens the existing pinned SHA-256/Git-blob
verification path without changing checkpoint selection, download transports or
the loader's trust policy.

## Changes

- Hashing validates the expected hex digest and the regular-file type, reads at
  most the initially opened file's size plus one EOF-check byte in chunks of at
  most 4 MiB, and rejects premature EOF or growth. Progress uses that fixed size.
  It compares descriptor and current path identity/metadata before accepting the
  digest, so a visible replacement or mutation during hashing cannot pass.
  Each API's timestamps are compared to its own initial observation: Windows
  Python 3.12 exposes birth time in path `stat().st_ctime` but change time in
  descriptor `fstat().st_ctime`. Device/inode/size/mtime must agree across both.
- The cache stamp includes version 2, device, inode, size, modification time,
  platform `ctime` and expected digest. Legacy stamps cause one fresh verification.
  A cache hit rechecks current metadata after reading its hint; a fresh hash is
  checked against the original stamp again before a hint is published.
- Cache input is bounded to 2 Mi text characters and accepts only known stamp
  shapes. Invalid, oversized, deeply nested or unreadable records cause hashing.
  Output retains at most 1,024 hints and drops older hints when the serialized
  record would exceed the character limit. This is a metadata optimization, so
  dropping a hint only causes another hash.
- Writers use independent create-exclusive temporary files and atomic replacement.
  Concurrent writers can lose each other's hints, but cannot mix partial JSON or
  delete another writer's temporary file. Cache-write failures do not reject a
  successfully verified checkpoint; hash failures still reject it. Failed writes
  clean up only the temporary file this call created.

## Evidence and remaining limits

`src-tauri/src/model_verification_test.py` exercises thirteen offline cases with tiny
temporary files: digest/type rejection, growing files, changed file identities,
post-hash mutation, cache reuse and legacy invalidation, mutation during a cache
hit, missing/nonregular/corrupt files, oversized/malformed/deep cache input, entry
bounds, denied cache writes, temporary-name collision and concurrent writers.
The Windows timestamp difference and descriptor-change refusal also have a
deterministic fixture, so a fast file creation cannot hide the distinction.

This local cache is **not a cryptographic trust boundary** against an actor who
can edit both it and the checkpoint. It does not prevent modification after the
last check and before the backend later opens the file. Filesystem metadata is
not proof of immutability, and file I/O can still block in the operating system.
The plan's immutable artifact/catalog integration and protected publication are
still required for that stronger guarantee. No fsync durability is needed for a
disposable hint; an interrupted cache publication safely triggers rehashing.

Tests use no GPU, downloaded model, installed engine or live workload. No measured
startup speedup or completion of the broader GPU work packages is claimed.
