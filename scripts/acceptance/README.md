# Runtime acceptance with a disposable engine

This folder holds what the 27 October 2026 runtime acceptance used: small disposable fixtures, the
in-memory Hub fixture, and the procedure. The results are in
[the evidence record](../../docs/template-platform/inventory-2026-10-26.md#runtime-acceptance-27-october-2026).

A disposable engine runs beside the installed one on the same computer and the same Windows
account. It never reaches the installed engine, its data folder or its sign-ins.

## The `acceptance` build feature

The CLI, the engine library and the headless engine have an `acceptance` Cargo feature. No
release build enables it. With it, three environment variables apply:

| Variable | Effect |
| --- | --- |
| `YOUGORI_ACCEPTANCE_ENDPOINT` | The control pipe (`\\.\pipe\NAME`) or socket the engine listens on and the CLI calls |
| `YOUGORI_ACCEPTANCE_DATA_DIR` | The engine's data folder, an absolute path |
| `YOUGORI_ACCEPTANCE_RUNTIME_DIR` | A runtime folder to run instead of the bundled one, verified against its own checksum lists |

The feature fails closed. A malformed pipe name, the installed engine's own pipe name, or a data
folder given without a pipe name is an error. It never falls back to the installed endpoint.

The engine's single-instance lock and its deployment-secrets vault entries also get a suffix
derived from the data folder. The disposable engine therefore sees none of the installed
engine's vault entries, including its Hub sign-in. Everything it stores carries
`.Yougori.DeploymentSecrets.v1.acceptance.<suffix>` and can be listed and deleted by that name.

The Personal Vault belongs to the Windows account, not to an engine, so a disposable engine never
reaches it: every broker call goes through `vault::broker`, which refuses under this feature, and
the vault's own setup file is read from the acceptance data folder. (Before 27 October 2026 the
disposable engines polled the account's broker for its status every 2 seconds; that read only a
count of waiting requests and changed nothing.)

## Procedure

1. Build into a target directory of its own, never `src-tauri/target`, which the installed
   development engine may be running from:

   ```bash
   export CARGO_TARGET_DIR=/c/tmp/yougori-engine-target
   cargo build --manifest-path engine/Cargo.toml --features acceptance --offline
   cargo build --manifest-path cli/Cargo.toml --features acceptance --offline --bin yougori
   ```

2. Write the variables to a file with an editor, not a shell `echo` or heredoc. A shell can turn
   `\\.\pipe\` into `\.\pipe\`. Also set `USERPROFILE` to a disposable folder, so the CLI's
   `~/.yougori` is the test's own. Set `YOUGORI_NETWORK_URL` to the in-memory Hub, or to an
   address nothing listens on, such as `http://127.0.0.1:9`.

3. Start the engine with those variables, then check its endpoint before anything else:

   ```bash
   yougori app status   # endpoint must be the test pipe and engineOnly true
   ```

4. Run the fixtures with the test CLI. `accept-tiny` has one sandbox, one volume and one secret.
   `accept-wait` has two sandboxes, the second needing a secret, for cut-off and waiting changes.
   `accept-borrower` borrows another setup's sandbox. `accept-tooluser` installs `accept-tool`
   from the Hub. `accept-model` is for a dry run of a local model.

5. For the Hub tool path, start the in-memory Hub from the website checkout:

   ```bash
   yougori tool check scripts/acceptance/fixtures/accept-tool --format json   # its review
   node scripts/acceptance/hub-fixture.mjs PATH/TO/YougoriWebsite 8799 scripts/acceptance/fixtures/accept-tool REVIEW.json
   ```

6. To test a candidate guest agent without rebuilding the appliance, copy the bundled runtime to
   a new folder. Build the agent in the Linux build distribution and replace
   `usr/local/sbin/yougori-agent` inside a copy of `appliance/initramfs-virt`. Then update
   `appliance/SHA256SUMS` and `SHA256SUMS` in that copy and point
   `YOUGORI_ACCEPTANCE_RUNTIME_DIR` at it. The appliance installs the agent from its initramfs at
   every boot. The bundled runtime is only read.

7. Clean up. Quit the engine with `yougori app quit --yes`, using the test variables. Delete the
   vault entries whose target ends in `.acceptance.<suffix>`, and remove the disposable folders.

## Interrupting model migration

`model-migration-recovery.py` uses acceptance builds and a fresh data directory to
exercise real own-volume/catalog migration across process termination. Pass
`--root`, `--engine`, `--cli`, `--runtime` and `--model` (a local Qwen2.5-0.5B folder).
It creates and deletes its own CUDA fixture via the public API, preserves the model
source, and kills only the engine process it launched after observing a boundary
marker. It never uses the installed endpoint or edits platform state.

The acceptance-only `YOUGORI_ACCEPTANCE_MIGRATION_PAUSE` switch accepts
`options-installed`, `runtime-configured` or `catalog-prepared`; the marker is
`<acceptance data>/model-migration/acceptance-pause.json`. A pause expires after
60 seconds. The switch is absent from release builds. After a hard termination,
the harness explicitly requests verified abandoned-runtime recovery before
resuming or rolling back; another live runtime owner is never displaced.
`--reuse-fixture --from-case N` can continue this harness's retained fixture after
a failed attempt. Evidence distinguishes failed attempts from passed cases.

## Rebuilding the appliance into a new folder

`scripts/build-appliance.sh` and `scripts/build-cuda.sh` need `YOUGORI_MUSL_TOOLCHAIN_MANIFEST`.
That is the `native-complete.json` written by building the pinned toolchain from its checksummed
sources, in the Linux build distribution (Ubuntu 22.04 with the packages `build.py` records,
Go 1.27.2 from the pinned archive):

```bash
python3 scripts/vendor-oci-build/build.py --work WORK --output OUT --go /opt/yougori-go1.27.2/go/bin/go --native-only
export YOUGORI_MUSL_TOOLCHAIN_MANIFEST=WORK/native-complete.json
bash scripts/build-appliance.sh REPO NEW_APPLIANCE_FOLDER
bash scripts/build-cuda.sh NEW_CUDA_FOLDER
```

Run them on a copy of the working tree inside the distribution, so nothing is written into the
checkout (`build-appliance.sh` writes a build record under `REPO/build`). On 27 October 2026 the
libraries came out byte for byte as recorded in `build/oci-runtime/build-record.json`; only the
`musl-gcc` wrapper and specs differ, because they name their own folder.

To test the result, copy the bundled runtime to a new folder, put the new `appliance/` files and
the CUDA payload's `yougori-agent`, `yougori-mount-helper`, `yougori-cuda-probe` and `SHA256SUMS`
in it, rewrite the changed lines of its top-level `SHA256SUMS`, and point
`YOUGORI_ACCEPTANCE_RUNTIME_DIR` at it. Use a fresh data folder for a new installation and an
older one for an upgrade: an existing disk keeps the base image it was made on (archived in the
engine's data folder) and boots the new kernel and initramfs.

The development engine in `src-tauri/target` runs its appliance straight from
`src-tauri/resources/runtime`, and the CUDA payload's checksums are compiled into it. Replace those
files only with that engine stopped, and rebuild it afterwards.

## Driving the desktop app's own screens

Build the desktop app with the feature into a target folder of its own (it is also called
`yougori.exe`, like the test CLI), pointed at a Vite server on a spare port and with a debugging
port on its WebView. `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS` is not enough, since Tauri sets its own
browser arguments; set them in the window's configuration instead:

```bash
TAURI_CONFIG='{"build":{"devUrl":"http://127.0.0.1:1424"},"app":{"windows":[{…the main window…,"additionalBrowserArgs":"--remote-debugging-port=9333 --disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection"}]}}' \
  cargo build --manifest-path src-tauri/Cargo.toml --features acceptance
npx vite --host 127.0.0.1 --port 1424 --strictPort
```

Start it with the test variables and `WEBVIEW2_USER_DATA_FOLDER` set to a folder of the test's
own, so it never shares the installed app's WebView data, then drive it with Playwright's
`connectOverCDP`. Its first launch shows the guide; skip it, or set the
`yougori.instructions.seen.v1` local storage item. Stay away from Settings: changing sign-in
startup there writes this Windows account's startup entry.

## What it never does

It never stops, restarts or calls the installed engine, and never reads or changes its data
folder. It never uses the installed engine's sign-ins, never publishes anywhere but the in-memory
Hub, and never changes the bundled runtime. Quitting the disposable engine stops only its own
sandboxes.
