# Installed engine and automatic payments — 2026-11-04

This follows the initial native harness validation. It addresses its two explicit
limitations: the old installed engine and wallet configuration without settlement.

## Installed app and CLI

- Built the CLI from the current source using `node scripts/bundle-cli.mjs --dev`.
- Built the frontend using `npm run build`; built the desktop with
  `cargo build --locked --manifest-path src-tauri/Cargo.toml --bin yougori --features tauri/custom-protocol`.
  The build passed with the six existing engine warnings.
- Gracefully stopped the normal 1.1.1 engine. Its shutdown receipt reports
  `cleanupOutcome=verified`, `engineStopped=true`, `requiresReconciliation=false`.
- Preserved the previous app/CLI in
  `%LOCALAPPDATA%/Yougori/backup-before-vm-20261104/`.
- Installed both current binaries in `%LOCALAPPDATA%/Yougori`, updated user PATH
  ordering using `scripts/install-cli-path.ps1` and refreshed the managed CLI skill.
- Normal installed engine and CLI report **1.2.0**, using the normal user control
  pipe and normal data. No acceptance endpoint was selected.
- A real native Sandbox VM launched with one CPU and 1 GB, executed `uname -a`
  and printed `installed-native-vm-ok`, exit code zero. Stop returned
  `vm_stop=stopped`. No host/container fallback was used.
- Updated the existing CUDA runtime through `yougori gpu setup`; status reports
  `updateAvailable=false`. Restarted the existing Qwen2.5-0.5B model.
- The website on `127.0.0.1:3002` returned a real GPU completion. The disposable
  API key used for the check was revoked immediately.

This is a locally built app, not a published or signed release. It embeds the
frontend but its runtime resources still resolve from this source checkout.
Do not remove the source runtime folder while using this local build. No local
environment data was deleted or converted.

Installed SHA-256:

| Binary | SHA-256 |
| --- | --- |
| App | `7d9a809deddc20ed10c866771af05aa4e8577c16359a5129149473628d395a76` |
| CLI | `984ea185e2828a571c3302943a97ad150cbc65b9a1cf65b945ae5cd63b58d477` |

## Automatic settlement

Implemented invoice ownership/reference binding, seven mainnet validators,
finality checks, persistent retries, exactly-once credit ledger, inline checkout,
admin per-request pricing and shared-gateway credit reservations/refunds. See
[the payment contract](../../docs/payments.md) for exact semantics and limits.

- **157 Python tests passed**, zero failures (full template suite).
- **Browser flow passed**, including inline invoice creation, wallet-approval
  rejection, no accidental credit, invoice cancellation, admin pricing visibility,
  no checkout popup and existing responsive/catalog flows.
- Financial tests cover wrong token/chain/recipient/amount/reference, failed
  receipts, missing finality, reorgs, replay, ownership, wallet changes, stale
  work, restart resumption, concurrent settlement/spending and failed inference
  refunds. HTTP/SQLite and inference use real local servers; chain responses in
  those tests are controlled fixtures, not paid transactions.
- Live read-only probes passed on **all seven mainnets**. Five EVM contracts also
  accepted read-only simulations of the exact invoice transfer calldata, including
  its trailing reference. The probe does not sign or broadcast transactions.
  Solana's USDC mint decimals/mainnet identity and Tron's solidified mainnet block
  were read successfully.
- An initial probe hit public RPC/range errors on Base and Polygon. Base's default
  endpoint now uses PublicNode; the probe queries completed blocks instead of
  racing the latest head across balanced RPC nodes. The successful rerun is
  [payment-network-probe-2026-11-04.json](payment-network-probe-2026-11-04.json).

No real funds were sent, no wallet private keys were accessed and no paid cloud
server was rented. An actual signed-payment-to-credit trial remains unperformed;
the administrator must configure their receiving wallet before accepting payments.
