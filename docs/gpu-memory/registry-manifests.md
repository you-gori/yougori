# Uploaded checkpoint manifest validation

This is a focused GPU-W00/GPU-W03 input-validation slice in the combined plan.
The existing embedded registry helper still verifies authorized uploaded/local
artifacts inside the model mount. Its SHA-256 literal in `model_server.py` is
updated with the exact LF-normalized helper source; packaging must ship both.

Both `YOUGORI_LOCAL_MANIFEST` and `.yougori-verified-files.json` now have an explicit
1 MiB UTF-8 byte limit. File input reads at most that limit plus one byte; the
environment source checks character length before its bounded UTF-8 encoding.
An explicitly present empty environment manifest is invalid rather than silently
falling back to a different source. Malformed JSON, duplicate object keys, invalid
UTF-8, excessive nesting and input read failures produce generic safe errors.

The document must contain exactly `revision` and `files`; each of 1–512 entries
must contain exactly `name`, `size` and `sha256`. Revisions and digests retain the
existing lowercase 40/64 hex grammar. Sizes are nonnegative integers (not booleans)
and individual/aggregate declared sizes cannot exceed 2^63−1 bytes.

Names follow the engine-generated ASCII grammar with a 240-character limit.
Empty, dot, parent, absolute, drive, backslash, NUL and alternate-stream forms are
refused, as are empty path components and trailing-dot aliases. Duplicate names,
resolved paths and duplicate device/inode identities are rejected. Root containment
is checked before inspecting resolved artifacts, and all metadata, paths, regular
file types and sizes are checked before any file is hashed. This avoids spending
time hashing large earlier artifacts when a later entry is already invalid.

Failed explicit revalidation clears the previous verified marker and exposed
snapshot file list. Only complete hash success publishes a verified snapshot.
Normal nested files, empty files and Git-blob/SHA-256 identities remain supported.
`local_checkpoint()` and its explicit `YOUGORI_LOCAL_CODE=1` consent behavior are
unchanged; this work neither grants code execution nor installs packages.

## Verification and limits

`model_registry_test.py` passes 14 offline tests (11 added), using tiny temporary
files, a real local hardlink and synthetic invalid manifests. Cases include both
input sources, exact/oversized byte boundaries, malformed shapes and types,
duplicate keys/names/file identities, path escapes, complete preflight before
hashing, normal nested/Git-blob files, failed revalidation and the embedded digest.

This validation does not make a mutable mount immutable or implement a race-proof
filesystem resolver. File contents and links can still change between preflight,
hashing and later backend access; the shared immutable artifact/lease work remains
necessary. Root symlinks are resolved, not prohibited, and file-identity alias
checks depend on the filesystem supplying a nonzero inode. No GPU, model download,
pip install, live engine, measured speedup or broader work-package completion is
claimed.
