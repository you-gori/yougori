# macOS

## Native model implementation (app acceptance pending)

The source now contains a native llama.cpp b11425 model runtime, compiled with
Metal and Accelerate on Apple Silicon and Accelerate/CPU on Intel. `model compute`
probes the installed binary and actual Metal devices; a hosted Mac without a GPU
selects native CPU. `model run ... --backend auto|metal|cpu` selects compute.
Use a GGUF repository or local GGUF folder. CUDA, Transformers, vLLM, MLX and
Core ML are not provided by this native runtime. This is not full macOS feature
parity or a validated release.

Weights are pinned and SHA-256 verified in a persistent native-models cache on
the selected drive. The native process rechecks them before each load and only
executes the bundled verified runtime. A read-only mount supplies the existing
Linux API frontend, preserving chat, tool calling, usage, recording and publishing.
The private native service binds loopback, uses a separate random key, and gets
a lifetime-scoped guest network grant. The supervised process exits when its
engine-owned pipe closes. No model-repository Python runs on the host.

Apple Metal bounty workers use the same private model frontend, tool readiness
check and isolated agent/test containers. Idle memory release stops both the
frontend and its native process. Grid and bounty registration identify the backend.
The draft app runner uses a 32K context window, matching the Linux GGUF runner,
so bounty rules, tool definitions and source do not compete for only 4K tokens.
The containers still use the x86-64 appliance; ARM64 guest execution and full
VM support remain separate unfinished work. Native process filesystem isolation,
strict unified-memory accounting, model optimizer parity and Mac hardware
acceptance also remain to be completed. Uploaded GGUF publications use the same
native path; other uploaded formats still require their supported backend.

Build with `bash scripts/build-macos-model-runtime.sh`; development engines may
set `YOUGORI_MACOS_MODEL_DIR` to its `build/macos-model/runtime` output. The normal
Mac build includes these binaries and their licenses in desktop and engine bundles.
`python3 scripts/test-macos-model-runtime.py` checks verified tiny-model inference,
authentication and owner-loss cleanup, reporting CPU and Metal results separately.
The dedicated manual GitHub workflow runs this on Apple Silicon and Intel. A CPU
pass does not establish Metal support. GitHub ARM runners cannot validate nested
hardware virtualization, and ad-hoc CI signatures do not establish Gatekeeper or
notarization acceptance.

### Native CI evidence — 2026-10-11

[Run 38146853917](https://github.com/you-gori/yougori/actions/runs/38146853917)
passed on macOS 15.7.9 for both architectures at CI commit
`2f3337f8207be59329f3a2077b220b0f600cfd9c`:

- Apple Silicon: native CPU and Metal inference, using the runner's `MTL0`
  Apple Paravirtual device.
- Intel: native CPU inference with Accelerate; no Metal device was available.
- Both: verified GGUF fixture, wrong-key rejection, token generation, owner-pipe
  loss cleanup, runtime checksums, native binary architecture, valid ad-hoc
  signatures, and dependency checks allowing only macOS system libraries.

The run exposed and corrected the `MTL0` device-name detection and an unintended
Homebrew OpenSSL dependency. The private loopback server now builds without
OpenSSL, OpenMP, built-in subprocess tools or downloaded Web UI assets.

This evidence covers the standalone native inference runtime. Desktop/engine
integration, full grid/bounty workflows, large-model memory behavior, physical
GPU performance and distribution acceptance remain unverified on macOS. The
four-file CI branch is `codex/macos-native-validation-20261011`; the implementation
changes have not been published with it. The repository's original disabled
GitHub Actions setting was restored after the tests.

## Existing guest runtime

Yougori runs on macOS 14 or newer, natively on Apple Silicon and Intel, with nothing
else to install. The app ships its own QEMU, built from pinned sources (see
`scripts/macos-runtime/inputs.json`). It downloads Cloudflare Tunnel, pinned and
checksum-verified, the first time public access is used. Apple Silicon runs the x86-64
appliance through QEMU's software CPU, which is slower; Intel Macs use Apple's
Hypervisor framework for containers and full VMs. GPU/CUDA guests are not available on
macOS.

## Building with GitHub (no Mac needed)

The **macOS app (manual)** workflow builds the Apple Silicon and Intel apps on GitHub's
macOS runners. It never runs on push or pull request; start it from
Actions → macOS app (manual) → Run workflow, or through the release-candidate workflow.
Each run:

1. Builds QEMU and its libraries from the pinned sources. This is cached until those
   inputs change.
2. Runs the disposable guest tests on that runtime, then the app's tests.
3. Builds, signs and notarizes `Yougori.app`, its DMG and the standalone engine archive.

Its artifacts are the DMG, the engine archive and
`yougori-macos-runtime-sources-ARCH.tar`.

Signing needs an Apple Developer Program membership and these repository secrets
(Settings → Secrets and variables → Actions):

| Secret | Where it comes from |
|---|---|
| `APPLE_CERTIFICATE` | A "Developer ID Application" certificate exported with its key as `.p12`, then base64-encoded (`base64 -i cert.p12`, or `[Convert]::ToBase64String([IO.File]::ReadAllBytes("cert.p12"))` in PowerShell). |
| `APPLE_CERTIFICATE_PASSWORD` | The password chosen when exporting that `.p12`. |
| `APPLE_TEAM_ID` | developer.apple.com → Account → Membership details. |
| `APPLE_API_ISSUER`, `APPLE_API_KEY_ID` | App Store Connect → Users and Access → Integrations → App Store Connect API: create a key with the Developer role. |
| `APPLE_API_KEY` | The contents of that key's downloaded `AuthKey_<id>.p8` file. |

Running the workflow with **sign** unchecked produces ad-hoc signed previews for testing.
macOS refuses to open those when they are downloaded; never ask users to disable
Gatekeeper or remove quarantine to install them.

When publishing, pin the Team ID into the installer script with
`node scripts/release-manifest.mjs --apple-team-id TEAMID …`.

## Building on a Mac

1. Install Xcode command-line tools, Node and Rust, then `npm run macos:setup`. This
   installs the build tools meson, ninja and pkgconf from Homebrew; none of them ship.
2. `npm run macos:runtime` builds and signs the bundled QEMU into `build/macos-runtime/`.
3. `npm run macos:test:runtime` runs the disposable guest tests on that runtime.
4. `npm run macos:build` runs the tests and builds the app and DMG.
   - With `YOUGORI_MAC_SIGNING_IDENTITY` and the `APPLE_API_ISSUER`, `APPLE_API_KEY` and
     `APPLE_API_KEY_PATH` notarization variables set, it is a signed, notarized release
     build.
   - Otherwise it is a preview.
5. `npm run engine:package` builds the standalone CLI engine archive.

Development builds started without a bundled runtime fall back to native Homebrew QEMU,
or to a runtime named by `YOUGORI_MACOS_QEMU_DIR`.

## Licenses and sources

The runtime carries each component's license texts in `runtime/qemu/licenses/`, and
`runtime/qemu/SOURCES.json` records every component's version, license, source URL and
SHA-256. QEMU is GPL-2.0, so every macOS release must also publish
`yougori-macos-runtime-sources-ARCH.tar` as its corresponding source. It contains:

- the exact pinned archives
- the meson wraps glib downloaded during its build
- the build and signing scripts

## Release checklist

On each architecture, with a clean account and normal Gatekeeper settings, test:

- **Install and first launch:** downloaded DMG mounting, drag-to-Applications install,
  first launch, CLI linking and permission prompts.
- **Standalone engine:** CLI + engine installation independently of the desktop app,
  including operation without an open window.
- **Runtime:**
  - container start/stop, terminal input/resize and sharing
  - microVM/full VM behavior and network access
  - complete owned-process shutdown
- **Models:** model chat and API access. Track Neocloud tests separately when using a
  paid provider account.
- **Lifecycle:** upgrade, reinstall, login startup, uninstall and preservation of user data.

Record the package SHA-256, macOS version, architecture and results in the release
acceptance record. Unsigned artifacts cannot satisfy these checks.
