# Harness installation repair — 2026-11-04

The reported Shannon import failed on an ordinary Windows installation. Earlier
fixture runs used a newer, separate guest and therefore did not cover that failure.

## Repaired paths

- The normal source-built app loaded an old, checksum-valid guest with an ASCII-only
  OCI importer. Replaced its guest artifacts with the already built guest matching
  all current Go source inputs and dependency hashes. The source importer already
  supports Linux UTF-8 names; host file access rules were not weakened. Restarted
  the ordinary app and restored the existing model. Release preflight now rejects
  guest build records that do not match the checkout source.
- Windows installation now launches the harness immediately, after releasing its
  lock. The inline website instructions explain installation, code approval and
  the command for later use. Existing catalog cards are preserved. Large package
  transfers report progress. No API key needs to be copied.
- Shannon without arguments performs model validation, using a local disposable
  HTTP target. Its real Pi client was sending a provider storage extension and an
  excessive output budget that the real local runner rejects. The configuration
  now uses the local chat contract, 128 output tokens for validation and at most
  4,096 for tasks. Pi uses the same compatible wire settings. Both images were
  rebuilt/published locally; no hosted release was made.
- The website checks that the current VM archive and optional tool archive are
  present with their declared sizes before marking a harness available. The CLI
  checks server readiness and the local VM API before asking for device approval.
  Download checksums and VM extraction checks remain mandatory.

## Checks actually run

| Check | Result and scope |
| --- | --- |
| Exact PowerShell install command for Shannon, ordinary app, existing local Qwen2.5-0.5B-Instruct | Passed: automatic launch, image import including the formerly refused Unicode name, real VM, Temporal worker, real model inference and model-validation completion; no penetration test |
| Windows 5.1 installers | All 21 source launchers installed and their installed version commands ran; repeated installation, separate servers, special-character paths, checksum failures and traversal refusal passed |
| Installed Pi command | Passed device-code approval and inference from the real native VM against an HTTP fixture; request fields/output limit were checked against the local chat contract |
| Python tests | 187 passed |
| Browser | Desktop/mobile accounts, catalog and inline install steps passed; no screenshots |
| Guest source guard / release-preflight tests | 12 passed, including changed source and dependencies |
| Frontend lint and build | Passed; build retains its bundle-size warning |

The live preview was restarted at `http://127.0.0.1:3002`, preserving its database.
The user's installed `solver-shannon` was refreshed. Test guests stopped normally.

Six harnesses currently have published VM packages on this preview: Pi, Plandex,
Strix, Shannon, PentAGI and HexStrike. The other fifteen source profiles now show
as in preparation. Installing their launcher does not establish VM runtime
compatibility; they need published and verified VM artifacts. The earlier actual
client/tool checks for the other five available harnesses remain separate evidence
in `native-harnesses-2026-11-04.md`.

The real Shannon check proves connection and launch, not that a 0.5B model can
perform a useful security assessment. Scans still require an explicitly supplied
target within the VM. This task did not enable external networking or run a scan.

Local logs are under `C:/YougoriBuildCache/scratch/solver/`:
`shannon-user-install-fixed.log`, `harness-windows-final.log`,
`harness-all-tests.log`, `harness-browser-final.log`,
`harness-runtime-guard-tests.log`, `harness-lint.log`, and `harness-ui-build.log`.
