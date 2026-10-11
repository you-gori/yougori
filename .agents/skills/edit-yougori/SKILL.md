---
name: edit-yougori
description: Change, build and test the Yougori source checkout, including the React desktop UI, the Tauri engine, the Rust CLI, the Go guest agent, the vault, bundled runtimes and the agent skills. Use for code changes, bug fixes, tests and local builds in this repository. Operating environments and models through the CLI is the yougori skill instead.
---

# Edit Yougori

Work from this checkout's root. Run `git status` first: people and other agents may have uncommitted work here. Keep it intact: never stash, reset, clean or revert changes you did not make, and do not commit, push or release unless asked.

## Where things live

| Area | Path | Notes |
|---|---|---|
| Desktop UI | `src/` | React, TypeScript and Vite; Vitest tests sit next to the code (`*.test.ts(x)`) |
| Engine and Tauri commands | `src-tauri/src/` | `commands*.rs` (app commands), `automation/` (CLI requests and the job queue), `runtime/` (container, GPU and VM runtimes, storage), `model_runner/`, `swarm/`, `remote_access/`, `market.rs` |
| Standalone engine | `engine/` | `yougori-engine`: the engine without a display |
| CLI | `cli/src/` | `main.rs` dispatch, `public.rs` public commands, `parse.rs` and `catalog.rs` advanced commands and `schema`, `launcher/` interactive flows, `bounty*.rs` Swarm Mining, `skills.rs` skill install |
| Agent skills | `skills/yougori/SKILL.txt`, `skills/yougori/references/cli.txt`, `skills/model-architecture-support/` | compiled into the CLI; each `# ` section of `cli.txt` becomes one topic reference |
| Guest agent | `appliance/agent/` | Go service inside containers and microVMs |
| Vault and runtimes | `vault/`, `runtime/` | Personal Vault broker; CUDA host, GPU, confidential and security runtimes |
| Scripts and docs | `scripts/`, `docs/` | install, release and compliance tooling (`*.test.mjs`); design notes and reviews |

## Checks

- UI: the focused test (`npx vitest run src/PATH.test.tsx`), then `npm run lint` and `npm run build`.
- CLI: `cargo test --manifest-path cli/Cargo.toml` (narrow with `--lib MODULE::` or `--test command_line`).
- Engine: `cargo test --manifest-path src-tauri/Cargo.toml --lib MODULE::`, then `npm run check:native` (all targets).
- Guest agent: `go test ./...` in `appliance/agent`. Scripts: `node --test scripts/NAME.test.mjs`.
- Everything: `npm run verify`. Runtime and hardware suites (`test:runtime`, `test:workspace`, `cli:test:runtime`) are ignored tests that need real runtimes; run them only when the change needs them.
- Rust builds are large: point `CARGO_TARGET_DIR` at a drive with free space when the system drive is small. Keep LF line endings.

## Rules

- When CLI behaviour changes, update the matching topic section of `skills/yougori/references/cli.txt` in the same change and run `cargo test --manifest-path cli/Cargo.toml --lib skills::`. The tests keep `SKILL.txt` under 5,000 bytes, one `# ` section per topic in order, a `## Troubleshooting` table in each, and exactly two YAML project examples that validate.
- Engine method changes also update `cli/src/catalog.rs` and `cli/src/parse.rs` so `yougori schema` stays truthful.
- Credentials travel through stdin (`--file -`) or protected bindings, never arguments or logs. Tests use disposable data and no real outreach, accounts or payments. No app screenshots or videos in tests.
- `npm run desktop:dev` runs this checkout. The installed app is built from packaged files; editing source does not change it until it is rebuilt and installed. Never claim a rebuild or install that did not happen.

Report the changed files, the checks you ran and any remaining limitation. The Yougori management skill (`~/Yougori/Workspace/skills/yougori/`) covers operating environments through the CLI; this skill covers changing the source.
