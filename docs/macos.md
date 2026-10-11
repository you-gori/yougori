# macOS

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
