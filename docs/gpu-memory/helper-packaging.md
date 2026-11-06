# GPU-W11: embedded helper packaging bounds

The current source packaging already uses a bounded provisioning path. This
change adds regressions around that path's canonical validator and the complete
embedded helper set; it does not introduce a second set of runtime limits.

## Local creation and refresh

Local Hugging Face, registry and local-folder model launches build OCI workload
options and pass them through `projects::run_workload`. That function deserializes
`CreateEnvironmentRequest` and calls `Options::validate()` before dispatching
environment creation or provisioning. `commands::create_environment` validates
again. `RuntimeManager::save_workload_options` validates before writing options;
`refresh_server` uses that save before updating the stopped workload configuration.
Loading saved options also revalidates them.

The authority for these limits is `cli/src/workload.rs::Options::validate`:

- Each environment value is at most 65,536 UTF-8 bytes, inclusive; at most 512
  ordinary variables are allowed, alongside separately validated secret bindings.
- The complete serialized `Options` JSON is at most 262,144 bytes, inclusive.
  Names, JSON escaping, arguments, secret references, mounts and other fields
  consume this same budget. Summing raw helper lengths alone is insufficient.
- The separate startup command remains below the existing 32 KiB command limit.
  Source is delivered in workload environment values, not that startup string.

These checks reject invalid workload options before guest provisioning or
replacement. They are not a claim of side-effect-free launch preflight: earlier
model setup may already have saved vault references, verified/downloaded cache
files, or updated model metadata. Secret references are checked here; resolving
their protected values and guest-side validation remain the existing runtime's
responsibility.

## Remote delivery is distinct

NeoCloud's `server_source()` is sent in the existing `model/run` RPC and written
to a source file. It does not travel as a 64 KiB environment value. The remote
`runtime/cloud/model.py` checks a separate maximum of 262,144 Python string
characters before writing the server. The packaging regression matches that
character-count contract and verifies the injected GPU, Clef and publisher sources
plus the unmodified main server body. This does not equate remote character limits
with OCI serialized byte limits or change the cloud RPC framing contract.

## Regression coverage

`model_runner/packaging.rs` is compiled only for tests and uses the real current
embedded sources. Seven tests cover:

1. Exact base64/zlib roundtrip for the server, optimizer, Clef, publisher and
   registry helpers, preserving each existing source's newline policy.
2. All five current helpers together with representative model metadata, vault
   references, a bind and a named volume passing the canonical validator.
3. Inclusive 64 KiB values, non-ASCII UTF-8 byte cost, and a one-byte oversize error
   that does not echo helper content or protected references.
4. Inclusive 256 KiB serialized options and rejection one byte above that size,
   while every individual environment value still fits.
5. JSON escape expansion exhausting the aggregate budget even when raw value
   byte lengths do not increase.
6. A non-environment argument sharing and exhausting the same aggregate budget.
7. The current remote source bundle's distinct character bound and exact content.

The existing `only_model_server_commands_are_refreshed` test retains the startup
command check. No hard-coded compressed source sizes or source digests are added;
future source growth is checked using the bytes compiled into that test build.

Focused filter for the coordinating native gate:

```powershell
$env:CARGO_TARGET_DIR='D:/YougoriBuildCache/target'
cargo test --offline --locked --manifest-path src-tauri/Cargo.toml --lib model_runner::packaging:: -- --skip swarm::
```

No live provisioning, cloud RPC, installed engine, model download or GPU run is
part of these tests. The pre-provision call order above was reviewed in source;
the tests exercise the real serializer/validator without creating environments.
Signed helper distribution, ABI migration and release authorization remain the
separate CORE-08/RELEASE work. This closes the packaging regression slice, not
GPU-W11 as a whole.

On 28 October 2026, the parent ran the complete `model_runner::` test filter:
63 tests passed, including all seven packaging cases, the startup-command check
and the embedded registry digest check. No tests were ignored and no warnings
were emitted. The shared Windows build target was used.
The subsequent all-target native compile check also passed without warnings.
