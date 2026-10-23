# Baseline before the Grid Core work

Taken 18 October 2026, immediately before Phase 1. Nothing was reset, cleaned, committed or
pushed to produce it.

## Preserved state

The working tree held 145 changed or untracked entries, including the audit fixes of 17–18
October. It is archived, verified and restorable at `D:\yougori-archive-2026-10-18`:

- `HEAD.txt` — the commit the tree was based on, `502f789`
- `status.txt` — the 145 entries
- `tracked-changes.patch` — `git diff HEAD --binary`, verified to reverse cleanly against the
  tree, which proves it is exactly the current difference
- `untracked/` — a copy of all 50 untracked paths, 69 files
- `RESTORE.md` — how to put it back

An archive rather than a branch, because this project keeps one branch.

## Test baseline

Measured on this checkout, with the audit fixes in place.

| Suite | Command | Result |
| --- | --- | --- |
| Grid crate | `cargo test --locked` in `grid` | 119 passed, 1 ignored (154 after Phase 1 and 2) |
| Engine library | `cargo test --lib -- --skip swarm` in `src-tauri` | 567 passed, 88 ignored |
| Engine, all targets | `cargo check --all-targets` in `src-tauri` | compiles, tests included |
| CLI | `cargo test --locked` in `cli` | 330 + 164 + 164 + 24 + 6 + 3 passed |
| Frontend types and lint | `npx tsc -b`, `npm run lint` | clean |
| Frontend units | `npx vitest run --dir src` | 609 passed in 108 files |
| Browser flows | `npx playwright test e2e/{desks,neo-grid,swarm-mining}.spec.ts` | 14 passed |
| Website backend | `node --test server/swarm.test.mjs` | 37 passed |
| Website browser flows | Swarm Playwright config | 7 passed |

Two standing exceptions, unchanged by this work:

- The engine's research worker tests compile but are not run, by the owner's rule that no worker
  may be started here.
- The website's `dist` is a symbolic link to a removed folder, so its browser suite needs a build
  into another directory and an environment variable pointing at it.

The plan's command list mentions `go test ./...`. The only Go module in the repository is
`appliance/agent`, so that command applies there and nowhere else.

## What exists today

| Product | Hub | Port | Record | Vault keys |
| --- | --- | ---: | --- | --- |
| Closed Neo Grid | `grid/src/hub.rs` | 7460, tunnel 7461 | `grid/hub.json`, `grid/member.json` | `yougori-grid-hub-key`, `-hub-password`, `-member-token` |
| Sandbox Grid | the same hub | 7463, tunnel 7464 | `grid/desks-hub.json`, `desks-member.json`, `desks.json`, `desk-login.json` | `yougori-desks-*`, plus parking and connector secrets |
| Access Grid | `grid/src/access/hub.rs` | 7465, tunnel 7466 | its own record | `yougori-access-hub-key`, `-hub-seal`, `-device` |
| Swarm Mining | `grid/src/bounty.rs` | 7462 | `bounty/host.json`, `swarm/` | `yougori-bounty-hub-key`, `-hub-password` |

Data folders under the application's data directory: `grid`, `bounty`, `swarm`, `security`,
`operations`, `network`.

Every one of those records and keys needs an owner and a migration step before the core replaces
it. That mapping is in the ADR, and each phase's exit gate restates it for the records it touches.

The table above is this document's own reading of the tree on 18 October 2026, and it is a summary
rather than a specification. The exact on-disk shape of each of those records, the version each is
at, what an older build does with a newer one, the fixture that pins the bytes and the full list of
vault entry names are in [frozen-contracts.md](frozen-contracts.md), which is rendered from the
register in `grid/src/core/compat/frozen.rs` and cannot drift from it. Where the two disagree, that
one is right. `security` and `network` are out of its scope on purpose: neither holds a record a
grid is made of, and nothing in the rollout reads either.

## Rule for every later phase

The products keep working while the core is built. Nothing above is deleted, and no record is
rewritten in place without a verified backup and a tested rollback.
