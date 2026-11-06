# Artifact and metadata signing

`yougori-sign` is an opt-in maintainer utility for S08/VM-W45. It signs the same
domain-separated statements the catalog, guest-image and sandbox trust readers
verify, and records which signed components a build ran (CORE-08 signed build
identities). It does not start Yougori, install a trust root, publish a release, or
change an engine setting. Ordinary builds do not include private-key handling.

## Build and key input

```powershell
$env:CARGO_TARGET_DIR='D:/YougoriBuildCache/target'
cargo build --locked --manifest-path engine/Cargo.toml --features release-tools --bin yougori-sign
```

The result is `D:/YougoriBuildCache/target/debug/yougori-sign.exe` on Windows.
Provision an Ed25519 signing key through your existing offline release-key
process. Input must be unencrypted PKCS#8 DER, version 1 or 2, at most 4 KiB.
Version 1 derives its public key; version 2 checks the included public key too.
PEM, raw seeds and non-Ed25519 keys are refused. This utility does not generate
or store private keys; deciding and protecting production keys remains the
release owner's responsibility. Tests use disposable generated keys.

The binary takes exactly `--request PUBLIC_REQUEST.json`. Private bytes enter
through stdin, never command arguments or JSON request files. The Node wrapper
handles binary stdin on Windows and launches without a shell:

```powershell
node scripts/sign-artifacts.mjs --tool D:/YougoriBuildCache/target/debug/yougori-sign.exe --request public-request.json --key-file C:/protected-release-keys/signing.der
```

The key file must already be protected by the owner. The wrapper bounds its read,
passes the bytes only on child stdin, and clears its own input buffer afterward.
Neither program claims to erase every OS/library copy of private material.
Output is one public JSON value; save it as an artifact in the release staging
directory. Failures exit nonzero and do not produce a successful JSON result.
The wrapper suppresses child error output; direct binary errors provide more
specific public refusal reasons without printing the private-key input.

## Public key and artifact trust roots

Public request:

```json
{"operation":"public_key"}
```

The response includes the Ed25519 public key, catalog publisher identity, and
the sandbox metadata key/key ID. The publisher and metadata key ID identify the
same key. To generate a **candidate** artifact-class trust-root document:

```json
{
  "operation":"trust_roots",
  "id":"release-2026",
  "classes":["guest_image","model_helper"],
  "valid_from":"2026-10-29T00:00:00Z",
  "valid_until":"2027-01-01T00:00:00Z"
}
```

Choose the actual classes/windows deliberately. The existing `TrustRoots`
parser checks the generated document. Installing it into the engine is a
separate operator action; this command does not grant its key any live trust.
Use separate offline and online keys for the sandbox metadata roles, as the
existing root schema requires. A single artifact trust-root entry does not
replace that metadata-role root.

## Detached artifact signatures

```json
{"operation":"sign_artifact","class":"guest_image","artifact":"guest-manifest.json"}
```

Artifact paths are resolved relative to the public request file. The utility
opens the file for reading and computes its actual `ContentKey` with a fixed
64 KiB buffer, binding its length, class and signer using `content_statement`.
Input is a regular file; truncation, growth and observed mutation during hashing
are refused. It never substitutes a caller-provided checksum for the input bytes.
Keep release staging stable while signing and distributing; verification hashes
the receiver's actual bytes again.

The response is exactly the existing detached envelope:

```json
{"publisher":"<publisher fingerprint>","signature":"<128 hex characters>"}
```

It can be read directly as `guest_image::ManifestSignature`. For model helpers,
use class `model_helper` and carry the signature with that class's existing
publisher trust claim. Signing a guest manifest binds the build record and boot
artifacts through its existing content references; signing alone does not check
that the manifest/build record forms a bootable release. That validation remains
with the guest-image consumer. The library `SigningKey::sign_manifest` also
supports consumers whose existing policy uses `manifest_statement`; the file
command intentionally uses the content-bound signature described above.

Verification request (embed the public attestation and trusted root document):

```json
{
  "operation":"verify_artifact",
  "class":"guest_image",
  "artifact":"guest-manifest.json",
  "attestation":{"publisher":"<fingerprint>","signature":"<signature hex>"},
  "trust_roots":{"format":1,"keys":["<replace with reviewed root entries>"]},
  "at":"2026-10-29T12:00:00Z"
}
```

```powershell
node scripts/verify-artifacts.mjs --tool D:/YougoriBuildCache/target/debug/yougori-sign.exe --request verify-request.json
```

The verification wrapper passes no private input. The binary rehashes the file
and applies the real key/class/window/revocation checks at the specified time.
Its response says `verification: "artifact_signature"` and records the content
key and length. It does not claim class-specific structural validity, install
authorization or release acceptance.

## Helper bundles

A model helper (G08: `gpu-optimizer`, `clef-adapter`, `publisher-routes`,
`registry-verifier`, `model-server`) reaches a runner as a signed bundle the
engine admits into its catalog's `model_helper` class and serves to opted-in
runners (`yougori catalog model_helpers`). The same tool builds the bundle from
public inputs, without any key:

```json
{"operation":"build_helper_bundle","helper":"gpu-optimizer","version":"1.0.0",
 "abi":{"major":1,"minor":0},
 "runners":[{"backend":"transformers","version":"5.18.0"}],
 "entry":"gpu_optimizer.py",
 "files":[{"path":"gpu_optimizer.py","source":"src/gpu_optimizer.py"}],
 "output":"gpu-optimizer.yghelper"}
```

`abi` is the loader ABI the helper needs (this engine's loader provides 1.0);
`runners` names the exact backend releases the helper supports (`transformers`,
`vllm` or `llama_cpp`), so a runner on another release is never served it; `entry`
must be one of `files`. Paths are relative to the request file; at most 256 files
of 16 MiB each; the whole bundle is bounded by the catalog's helper-bundle limit.
The output reports the bundle's content key and length, which `sign_artifact`
with class `model_helper` then signs:

```bash
node scripts/sign-artifacts.mjs --tool D:/YougoriBuildCache/target/debug/yougori-sign.exe --request build-request.json
node scripts/sign-artifacts.mjs --tool D:/YougoriBuildCache/target/debug/yougori-sign.exe --request sign-request.json --key-file C:/protected-release-keys/helpers.der
```

The engine admits the bundle only with an attestation from a key its trust roots
allow for `model_helper` (`yougori catalog model_helpers --action admit --bundle
PATH --attestation PATH`); the whole file is re-hashed on admission and again each
time it is opened for a runner, and a signature from any other key, a changed
byte or a missing attestation is refused with nothing published. No production
helper-signing key exists in this repository or on any build host; the
acceptance evidence under `docs/gpu-memory/evidence/` was produced with a
disposable test key.

## Signed build identities

`identify_build` records which signed components a build ran as the CORE-08
`SignedBuildIdentity` (`src-tauri/src/foundation/signing/identity.rs`). It reads
public files only and never signs, so run it through the verification wrapper,
which passes no private input. Paths are relative to the request file.

```json
{
  "operation":"identify_build",
  "trust_roots_file":"trust-roots.json",
  "build":{
    "plan":"<plan digest, 64 hex characters>",
    "runner_build_file":"yougori-engine.exe",
    "runner_version":"1.2.0"
  },
  "components":[
    {"class":"guest_image","publisher":"<fingerprint>",
     "artifact":"guest-manifest.json","signature_file":"guest-manifest.sig.json"},
    {"class":"model_helper","publisher":"<fingerprint>",
     "artifact":"helper.bundle","signature_file":"helper.sig.json"}
  ]
}
```

```powershell
node scripts/verify-artifacts.mjs --tool D:/YougoriBuildCache/target/debug/yougori-sign.exe --request identify-build.json | Set-Content -Encoding ascii signed-build.json
```

The record is ASCII. Windows PowerShell's `>` writes UTF-16, which the record reader
refuses.

`build` holds the fields of the report's `BuildIdentity`: `plan`, `runner_version`
(a report label) and either `runner_build` (a digest) or `runner_build_file`, whose
plain SHA-256 is recorded (what `Get-FileHash -Algorithm SHA256` prints, in lower
case). Give exactly one of the two. The trust-root file is read by the engine's own
loader (`TrustRoots::load`), so a file the engine would refuse is refused here.

For each component the utility hashes the actual file as `sign_artifact` does,
builds the content statement the class's verifier checks, and calls
`SignedComponent::check` with the signature from the signature file (the
`sign_artifact` output) at the current system time. Two classes are accepted:
`guest_image` for the feature manifest (`guest_image::signing_statement`) and
`model_helper` for the encoded bundle (`helpers::bundle_statement`). The verifiers of
the other classes check another statement (OCI layers), a metadata chain (runtime
updates) or none yet. A component's `publisher` must equal its signature file's.

The output is exactly the record that `SignedBuildIdentity::from_json` reads, at the
report's schema version (3): the build and, per component, its class, publisher,
statement digest, `checked_at` and `verification`. A refusal is recorded with its
typed outcome (`revoked`, `class_not_allowed`, `bad_signature`, `no_keys_for_class`,
`unknown_publisher`, `not_yet_valid`, `expired`), never dropped, so a successful
command does not mean every component verified: read each outcome. The request is
refused, and nothing is written, when an input gives no statement to check: an
unreadable artifact or signature file, another class, a publisher that differs from
its signature file, no components or more than 256, or the same class and statement
twice (the same bytes listed twice under one class and publisher).

`verify_build` reads a stored record back and verifies each recorded statement again
with `SignedComponent::reverify` under the trust-root file at the current time:

```json
{
  "operation":"verify_build",
  "trust_roots_file":"trust-roots.json",
  "record_file":"signed-build.json",
  "artifact_files":["guest-manifest.json","helper.bundle"],
  "signature_files":["guest-manifest.sig.json","helper.sig.json"]
}
```

Give one artifact and signature file per component, in the record's order, each by
the recorded publisher. The utility hashes the actual artifact and reconstructs its
class/publisher-bound statement before checking its signature. Changed bytes or a
relabeled class refuse the request, even if one key is trusted for both classes.
The result says `verification: "signed_build_reverified"` and lists, per
component, the recorded outcome and time beside the outcome now; `all_verified` is
true only when every component verifies now. A key revoked or expired since the
record was made shows here. `artifact_files_checked: true` records that current
files were read; `build_authenticated: false` makes explicit that the build labels
are unsigned. A completed report can have `all_verified: false`; automation must
check that field before accepting component signatures.

What a record shows: at `checked_at`, under the named trust-root file, whether a key
allowed for the class vouched for exactly those bytes (content key and length) as
that publisher's, and if not, why. What it does not show: that the build ran these
files (the caller lists them), that the trust-root file was the one in force in an
engine, that a guest release is bootable or a helper bundle well formed (their
consumers' checks still apply), anything about the runner build beyond its recorded
digest, or install and release acceptance. The record is not signed: whoever can
edit it can change its build fields or its claimed outcomes. `verify_build`
recomputes the outcomes but cannot detect an edited build.

E03 benchmark runs and E05 release evidence store the record as its own JSON file
beside the run records it describes (for example `signed-build.json` next to an
exported `observations.json`, or in the release evidence folder), with the signature
files, so `verify_build` can be repeated. Do not add it to a `RunRecord`: version-3
run records refuse unknown fields. A reader joins the two with
`SignedBuildIdentity::describes`, which requires `plan`, `runner_build` and
`runner_version` to equal the run record's `build`, so give `identify_build` the same
three values the runner reports.

## Sandbox metadata and threshold signing

Use the existing metadata envelope, including an empty signature list for the
first signer. This example authors targets metadata with no targets:

```json
{
  "operation":"sign_metadata",
  "role":"targets",
  "at":1793232000,
  "document":{
    "signed":{"role":"targets","version":1,"expires":1798761600,"targets":{}},
    "signatures":[]
  }
}
```

The role must match the payload. The existing typed schema, nonzero version,
expiry and root consistency checks run before signing. Supported roles are
`root`, `timestamp`, `snapshot`, `targets` and `revocation`. The latter checks its
issue time instead of an expiry. A signer appends its Ed25519 signature over
`MetadataFile::message(role)` and preserves the signed payload and other
signatures. A repeated signer or more than 64 signatures is refused. Feed the
result as the next signer's `document` for threshold signing; do not edit its
payload between signatures.

To check signatures, use `operation: "verify_metadata"`, `role`, `document`,
`at` (Unix seconds), and `trusted_root` containing the separately trusted typed
`RootMetadata` payload. The utility calls the existing `verify_threshold` with
the real Ed25519 adapter, requires valid production keys and checks expiry. The
result is explicitly `verification: "metadata_threshold_only"`.

That check does **not** bootstrap trust in a root supplied by an attacker, prove
root rotation against a previous root, persist rollback/revocation floors,
verify the timestamp/snapshot/targets chain, or admit an installed release.
Those remain the existing stateful trust client's responsibilities. Do not use
the threshold result as a substitute for that client.

## Bounds and tests

Public request files and stored build identities are limited to 1 MiB, signature
files to 4 KiB. Duplicate JSON keys (including nested metadata), non-string operation
tags, unknown operations/fields and invalid private-key formats are refused. Public
file contents and errors never need a private key in arguments, logs or output. The
verification wrapper passes on a verification report or a build identity record and
refuses any other result.

```powershell
node --test scripts/sign-artifacts.test.mjs
cargo test --locked --manifest-path src-tauri/Cargo.toml --no-default-features --features engine-only,release-tools --lib release_tools::
cargo test --locked --manifest-path src-tauri/Cargo.toml --no-default-features --features engine-only,release-tools --lib foundation::signing::signer::
node scripts/test-artifact-signing.mjs --tool D:/YougoriBuildCache/target/debug/yougori-sign.exe --scratch D:/YougoriBuildCache/scratch/m3
```

These are local cryptographic/interoperability tests with disposable keys and
files. No production key or published artifact is created by them. Packaging,
key custody, actual guest/helper delivery and release/install/rollback acceptance
remain with S08/E05 and the consuming managers.

The native smoke command requires the binary built above and an existing scratch
directory. It generates a disposable key, exercises the real wrappers and binary,
reports eleven checks (including current-file build verification and revocation),
and removes only its own temporary files. A missing binary
or failed check exits nonzero; it never substitutes a mock or silently skips.
