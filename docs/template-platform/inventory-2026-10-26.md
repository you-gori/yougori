# Feature and dependency inventory — 26 October 2026 (P01)

This is the P01 inventory the [active plan](../template-platform-implementation-plan.md) asks for (section 3): one table with its six columns, a measured baseline, and a caller rationale for every removal. It describes the working tree as it is today, not the snapshot in the [completion audit](completion-audit-2026-10-26.md).

Tree inspected: HEAD `da2b00c` plus uncommitted work. `git status --porcelain` shows 146 deletions, 112 modifications and 50 untracked paths; `git diff --stat` is 258 files, +10,490 / −41,909. Nothing was committed, built, run or published for this inventory. Only this file was written. Where a claim could not be checked by grep, the row says **unverified**; a wrong Remove here becomes a real deletion in P06.

Decisions use the plan's vocabulary: Keep, Consolidate, Optional-defer, Remove, Preserve-for-compatibility.

## 1. Baseline measurements

All counts are lexical lines (`wc -l`) and include comments. They exclude `target/`, `node_modules/`, `dist/`, `vendor/` (`src-tauri/Cargo.toml` and `engine/Cargo.toml` path `glib` to `../vendor/glib`), `__pycache__/` and the two generated TypeScript files. Methods are given verbatim so the P06 after-measurement is reproducible from the repository root in Git Bash.

### Rust production source

Method: `find CRATE/src -name '*.rs' -not -path '*/tests/*' -exec cat {} + | wc -l`. Note: no crate has a directory named `tests` under `src/`, so this filter only keeps crate-level `tests/` out by scanning `src/` alone. Inline `#[cfg(test)]` modules and files named `tests.rs` / `*_tests.rs` inside `src/` are therefore included; their size is given separately.

| Crate | Lines in src/ | Of which `tests.rs` / `*_tests.rs` files | Files with `#[cfg(test)]` | `[dependencies]` entries |
| --- | ---: | ---: | ---: | ---: |
| setup | 15,868 | 0 | 15 | 5 |
| cli | 61,512 | 999 | 86 | 18 |
| src-tauri | 138,284 | 14,654 | 172 | 41 |
| grid | 75,067 | 15,529 | 59 | 23 |
| vault | 7,115 | 0 | 10 | 16 |
| engine | 9 | 0 | 0 | 1 |

Dependency method: `awk '/^\[dependencies\]/{f=1;next}/^\[/{f=0}f&&/^[a-zA-Z0-9_-]+ *=/' CRATE/Cargo.toml | wc -l` (build- and dev-dependencies not counted). Test-file method: `find CRATE/src -name '*.rs' \( -name tests.rs -o -name '*_tests.rs' -o -name '*_test.rs' \) -exec cat {} + | wc -l`.

### TypeScript

Method: `find src -type f \( -name '*.ts' -o -name '*.tsx' \) -not -path '*/node_modules/*' -exec cat {} + | wc -l` → 37,096, of which `*.test.ts(x)` → 11,199 (same command with `-name '*.test.ts' -o -name '*.test.tsx'`). The generated `src/api/setups/capabilities.generated.ts` is inside this count.

package.json: 15 `dependencies`, 23 `devDependencies` (`node -e` over the parsed file). Individual npm dependency use was not checked (unverified).

### Public concepts, screens and commands

| Measure | Value | Method |
| --- | ---: | --- |
| Public CLI help lines | 97 | `grep -c '^  yougori ' cli/src/public.rs` |
| Help lines by family | model 22, rollout 6, vault 4, run 4, neocloud 4, deployment 3, cp 3; 43 other families with 1–2 lines | `grep '^  yougori ' cli/src/public.rs \| awk '{print $2}' \| sort \| uniq -c` |
| Agent guide sections | 13 | `grep -c '^# ' skills/yougori/references/cli.txt` (1,552 lines) |
| Desktop pages | 5 files in `src/pages` (3 pages: overview, hub, setups; 2 tests) | `ls src/pages` |
| App navigation | `AppPage = "sandboxes" \| "hub" \| "setups"` | `src/components/app-shell.tsx:18` |
| Desktop components | 173 top-level entries in `src/components`; 187 non-test files recursively; 268 files recursively | `ls src/components \| wc -l`; `find src/components -type f -not -name '*.test.*' \| wc -l` |
| Setup builder files | 33 in `src/components/setups` | `find src/components/setups -type f \| wc -l` |
| Tauri commands registered | 262 entries in `generate_handler![]`, of which 16 `setups::commands::*` | awk over `src-tauri/src/lib.rs` |
| Example packages | 14 in `examples/hub` (13 format 2 at 1.0.0, my-api 2.0.0; hello-site is v1) | `ls examples/hub`; `grep -m1 ^format_version: examples/hub/*/yougori-template.yaml` |
| Versions | every crate and package.json: 1.1.2; `setup/src/format.rs:35` `MINIMUM_YOUGORI = "1.2.0"` | `grep -H ^version */Cargo.toml package.json` |

### Build and check duration

`cargo check --manifest-path CRATE/Cargo.toml`, one run each, sequential, on a **warm cache** (cargo itself reported "Finished … in 0.05s / 0.30s / 0.56s", i.e. nothing recompiled). Wall time via `date +%s%N` before and after:

| Crate | Wall time | Exit |
| --- | ---: | ---: |
| setup | 144 ms | 0 |
| cli | 419 ms | 0 |
| src-tauri | 723 ms | 0 |

These numbers only prove the tree checks; a cold-cache or `--release` figure needs a clean target directory and was not taken (the live engine's target directory must not be disturbed). Each crate has its own `target/` (`cargo metadata` → `cli/target` for cli); `CARGO_TARGET_DIR` is unset.

### Bundle size

Not measured. `dist/` exists (3.8 MB, modified 2026-10-25) but predates today's removals and was not rebuilt; `src-tauri/tauri.conf.json` bundles `"targets": "all"`. Record the after-measurement from a fresh `npm run build` in P06/P07, not from this folder.

### Why fewer lines alone do not prove a simpler system

- 4,043 lines were *added* today as shared modules (`cli/src/{activity,storage_prompt,cli_ui,composer,reconcile}.rs`, untracked) so that the 18,653 launcher lines could go; `cli_ui.rs` alone is 3,303 lines and now serves `yougori model`. The net cli reduction is smaller than the deletion count.
- 14,654 of src-tauri's lines and 15,529 of grid's are test files inside `src/`; deleting tests lowers the count without simplifying anything (plan 8: "deleting useful tests" is not reduction).
- The grid crate (75,067) is linked only by src-tauri (27 files use `yougori_grid`) but 53,020 of its lines are `grid/src/core`, of which 9,432 are `core/compat` serving one CLI command. Line counts do not show which 20% of a crate is live.
- The engine still registers 262 commands and dispatches 64 `grid_/desks_/access_/swarm_/bounty_` wire routes (`src-tauri/src/automation/dispatch.rs`); the number of reachable routes, not lines, is the honest complexity measure for P06.

## 2. Removals already made on 2026-10-26 (recorded, not re-litigated)

Evidence: `git status --porcelain` and `git diff --stat` per path; nothing below is committed.

| Removed | Size (diff) | Caller rationale |
| --- | --- | --- |
| `cli/src/launcher/{menu,project,project/cloud,live,live/{databases,folders,two_way},plan,plan/recommend,package,scripts,diagnose,stream,sync,storage,ui,composer,grid_setup}.rs` and `launcher/assets/*` (8 files); `launcher.rs` reduced | 29 files, +34 / −18,653 | The `yougori launch` / `yougori cli` interactive menu and project launcher. Only entry was `main.rs` `launcher::requested`; the only external callers were the three npm scripts `yougori`, `yougori-change`, `yougori-cloud`, removed from `package.json` (−3). Shared plumbing extracted first (see section 1); the engine includes `cli/src/reconcile.rs` by path from `src-tauri/src/setups/folder_sync.rs:16`. |
| `cli/src/grid.rs`, `cli/src/access.rs`, `cli/src/grids/run.rs`, `cli/src/grids/render.rs`, `cli/src/launcher/grid_setup.rs`; 30 `parse.rs` routes; 27 help lines (`access` 14, `grids` 3, `grid` 3, `launch` 2, `join`, `create`, `cli`, `COMPANY`, `Open`) | 7 files +738 / −2,782; `parse.rs`/`public.rs`/`help_coverage.rs`/`main.rs`/`lib.rs` +39 / −190; agent guide +141 / −445 | The four branded command families. Plan section 1 removes the grids as products; their engine entry points stay reachable through templates (`src-tauri/src/setups/grids.rs`, row 6.1). The grids *library* (`cli/src/grids/{mod,alias,answer,fault,words}.rs`) stays because the engine imports `yougori_cli::grids` in 23 places (row 1.6). |
| `cli/src/legacy_notice.rs` | not in HEAD | Was never committed; no caller remains (`rg legacy_notice cli/src` → none). |
| `cli/src/bounty_map.rs` | unchanged vs HEAD | Removed by mistake, restored byte-identical (`git status --porcelain cli/src/bounty_map.rs` is empty). |
| `src-tauri/src/core_vault.rs` (366), `src-tauri/src/grid_hardware.rs` (250) | −616 | Both `#![allow(dead_code)]` with no callers ([removal ledger](removal-ledger.md), "Grid Core migration scaffolding"). `rg 'core_vault|grid_hardware' src-tauri/src` → none. |
| Desktop grid/swarm/access/desks/neocloud pages, components, APIs and libs: `src/pages/{grids,desks,access,neocloud,swarm-mining}-page.tsx`, `src/components/{grid-*,access-*,swarm-*,desk-*,sandbox-grid-admin*,closed-bounty-*,private-bounty-host}.tsx`, `src/api/grids/*`, `src/api/{grid,access,bounty,swarm}-api.ts`, `src/lib/{grid-*,swarm-*,rented-gpu,research-authorisation}.ts` | 121 files in `src/`, +470 / −14,755 | Navigation is `sandboxes \| hub \| setups` (`app-shell.tsx:18`); `app.tsx` lazy-loads only Overview, Hub and Setups. The removal ledger dates the All grids page removal to 2026-10-26; when the remaining `src/` deletions happened is not recorded in this tree (unverified), but none has a caller today. Leftovers are in row 1.5. |
| The four grid packages moved out of `examples/hub` to `setup/tests/fixtures/packages/{access,neo,sandbox,swarm-mining}-grid` | untracked | `cli/src/hub/setups.rs:2066`: "the grids are no longer published as examples, only kept as test packages". `setup/tests/packages.rs:25-30` reads both roots. |
| Docs: `docs/{access-grid,closed-neo-grid,sandbox-grid-enterprise,retrigger-fleet,retrigger-plan}.md`, `docs/grid-core/{baseline,desk-migration}.md` | 11 files +133 / −1,925 | Product documentation for removed products; `docs/hub.md` grew by 112 lines to absorb what still applies. |

## 3. Inventory

Columns are the plan's. "Callers" are grep results from this tree (`rg`/`grep -rn`), with a count and one representative path.

### Priority 1 — unused product pages, launchers, recipe selectors

| Feature/module | Current callers | Retained workflow | Decision | Data/compatibility impact | Verification |
| --- | --- | --- | --- | --- | --- |
| 1.1 Starter-recipe registry: `src/components/setups/recipes.ts` `RECIPES: StarterRecipe[] = []`, `recipeById`, `StarterRecipe`; `template-builder.tsx` `RECIPES.map` (lines 832, 1013), `RecipeChoice` (1010), entry kind `"recipe"` (98, 147, 257, 259, 503-507, 799, 868); `setup-intent.ts:5` `EntryKind "recipe"`; `setup-link.ts:54` `recipeFrom(?recipe\|?template)`; `capability-board.tsx:209,233` `onRecipe`; `src/api/setups/types.ts:115` `RecipeSlug` naming the four grids | 6 files import from `recipes.ts`; every consumer receives an empty array. `findSetupMatches`/`normaliseQuery` in the same file are live: `setup-link.ts`, `setup-suggestions.tsx`, `capability-board.tsx`, `setup-link.test.ts` use them to match capability groups | None for the registry (plan 3: "If unused, remove that registry and its dead UI"); the group search stays for capability selection | **Remove** the registry, `StarterRecipe`, `recipeById`, `RecipeSlug`, `RecipeChoice`, the `"recipe"` entry kind, the "Start with a recipe" source option (147) and the `onRecipe` prop; **Keep** `findSetupMatches` (drop its `recipes` field) | A `?recipe=`/`?template=` link already resolves to `null`; no stored data. The builder's default entry must become capability selection or import (plan P02) | Before: `rg -n 'RECIPES\|StarterRecipe\|recipeById\|RecipeSlug\|"recipe"' src` lists the sites above. After: 0 hits; `npx vitest run src/components/setups` green; `setup-link.test.ts` updated |
| 1.2 `cli/src/launcher/` remainder: `api.rs` 460, `chat.rs` 1,513, `domains.rs` 249, `neocloud.rs` 704, `releases.rs` 77; `cli/src/launcher.rs` 1,390 ("Interactive compute launcher" doc comment is stale) | `main.rs` 10 refs (`launcher::prompt_model` :90, `::requested`/`::run` :163-164, `::command_progress` :212-670, `::CANCELLED` :426). Submodules referenced only inside the folder (`chat::` 5+4, `domains::` 6+3, `api::` 3, `neocloud::` 1 from `chat.rs`, `releases::` 2) | `yougori model run / chat / api` and progress rendering for every top-level command (`command_progress`) | **Consolidate**: rename folder and file (e.g. `model_run`), split `command_progress`/`busy`/`stage` into `cli_ui.rs` where the rest of the UI plumbing went. Not a removal | None on disk | `cargo check --manifest-path cli/Cargo.toml`; `cargo test --manifest-path cli/Cargo.toml -- --skip swarm --skip bounty`; `help_coverage` tests still pass |
| 1.3 `cli/src/launcher_state.rs` (82) — launcher preferences under the user's `.yougori/launch` | `pub mod launcher_state` in `lib.rs:15`; **engine:** `src-tauri/src/commands.rs:1921` and `:2014` call `yougori_cli::launcher_state::forget_environment` when an environment is deleted. (The first draft of this row said 0 callers from a `cli/src`-only grep; the engine is a caller — corrected 2026-10-26 after checking at source.) | Cleaning a deleted environment's leftover launcher settings off existing users' disks | **Preserve-for-compatibility** — the launcher is gone, the files it wrote are not | Removing it breaks the engine build and leaves stale per-environment files | After: `rg launcher_state cli/src src-tauri/src` → `lib.rs` + the two engine callers only |
| 1.4 NeoCloud in the engine: `src-tauri/src/neocloud.rs` 2,248 + `neocloud/{accounts,catalog,contracts,install,pricing,provider_commands,runpod}.rs` 4,201; `rented_gpu.rs` 1,074; `cloud_deployment.rs` 206; `cloud_options.rs` 192 (total 7,921 without `grid_neocloud.rs`) | `neocloud::` 88 refs in 15 files: `lib.rs` registers 31 `neocloud_*`/`runpod_*` commands (lines 852-880) and resumes RunPod at 658; `model_runner.rs` (`run_neocloud_model`, lib.rs:765); `automation/dispatch.rs`; `desks.rs`; `lifecycle.rs`; `shutdown.rs`; `host_terminal.rs`; `models.rs`; Swarm: `swarm/rented.rs` 42, `swarm/mod.rs` 16, `swarm/development.rs` 3, `swarm/model_lifecycle.rs` 2, `bounty.rs` 2. `rented_gpu::` 66 refs, non-Swarm: `grid_neocloud.rs` 24, `desks.rs` 2, `grids.rs` 2, `setups/grids.rs` 1. Desktop: 18 non-test files, incl. `src/components/dialogs/dialogs/create-environment-dialog.tsx:59,270` ("neocloud" environment type on the Sandboxes page), `neocloud-form.tsx`, `neocloud-pod.tsx`, `neocloud-endpoint.tsx`, `cloud-environment-dialog.tsx`, `src/api/{neocloud,runpod,cloud}-api.ts`. CLI: 4 help lines `yougori neocloud providers\|discover\|plan\|create\|inspect\|start\|stop\|delete`, `yougori model run --neocloud`; `parse.rs` 50 mentions | Rented GPU environments as a sandbox type (Compute group: "rented compute"), `yougori model run --neocloud`, Swarm rented workers | **Keep — owner's decision, 2026-10-26.** The owner confirmed `--neocloud` and the rented-GPU sandboxes are very important. Not a removal candidate in any P06 batch; the earlier relayed "no NeoCloud" referred to the grid launcher UI, which is already gone | NeoCloud accounts live in the keyring (`neocloud/accounts.rs`); `rented_gpu.rs` keeps the owed-stop ledger — removing it would strand billable pods that only it can stop | Before: 31 registered commands, 1 UI radio option, 4 help lines. After a product decision: those counts, plus `rg neocloud src src-tauri/src cli/src` |
| 1.4b `src-tauri/src/grid_neocloud.rs` 1,370 — rented GPUs attached to a Neo Grid | `lib.rs` 6 (4 commands `grid_neocloud_status/add/remove/stop_all` :711-714, `manage` :624, `start` :661); `automation/dispatch.rs` 4; `grids.rs` 1; `lifecycle.rs` 1; `shutdown.rs` 1; `swarm/mod.rs` 1; `swarm/rented.rs` 3; `setups/grids.rs` via wire names `grid_neocloud_status`/`grid_neocloud_stop_all`. The desktop caller `grid-neocloud.tsx` is deleted | Only the Neo Grid template's ModelService on rented compute, and Swarm's rented path | **Preserve-for-compatibility** while `swarm/rented.rs` and the Grid handler call it; Remove with row 6.1 if the grid kinds leave the catalogue | Its ledger of rented pods per grid; `stop_all` runs at shutdown (`shutdown.rs`) — removing it without a replacement would leave pods running | `rg 'grid_neocloud' src-tauri/src` before/after; shutdown path test in `shutdown_state_tests` |
| 1.5 Leftovers of the removed desktop grids/Swarm UI: `src/components/use-swarm-actions.ts` (33) + `.test.tsx` (36); `src/components/swarm.css` (141); `src/pages/setups-page.test.tsx:32-37` `vi.mock` of `@/pages/access-page`, `@/pages/swarm-mining-page`, `@/components/grid-timeline` (modules that no longer exist); `src/components/neo-grid.css` (174, `.grid-swarm-*` rules); `src/components/grids.css` (135) | `use-swarm-actions`: 0 importers; `swarm.css`: 0 importers; `neo-grid.css`: imported by `template-builder.tsx:23` and `hub-page.tsx:16`; `grids.css`: `app-shell.tsx`, `setup-detail.tsx`, `template-builder.tsx`, `setups-page.tsx` (it owns `.grid-choice`, still used by the builder) | None for the first three; the builder still uses `.grid-choice` from `grids.css` | **Removed 2026-10-26 (P06 batch 1):** `use-swarm-actions.ts` + test and `swarm.css` — orphaned since `src/pages/swarm-mining-page.tsx` and `src/pages/access-page.tsx` were deleted earlier today (uncommitted, by another agent), which is consistent with the plan's "Removed from current work" (Swarm Mining as a dedicated product section; the engine worker and `yougori start bounty` stay); the five stale `vi.mock` lines were removed in the P02 pass. **Consolidate** `neo-grid.css` + `grids.css` into `setups/setups.css` keeping only selectors the builder/hub page use (which selectors is unverified: needs a per-class grep) | None | `rg -l 'swarm' src --glob '!*.test.*'` → only model/network panels (text), 0 component files; vitest for `setups-page.test.tsx` passes without the mocks |
| 1.6 Grids library `cli/src/grids/{mod 387, alias 995, answer 119, fault 202, words 489, tests 856}.rs` (3,048) and the 12 `grids_*` wire-method schemas in `cli/src/catalog.rs:203-215` | Engine: `yougori_cli::grids` 23 refs in `src-tauri/src/grids/registry.rs` (7), `grids.rs` (6), `grids/tests.rs` (7), `automation/queue.rs` (3) — `registry.rs` matches on `grids::Product`. CLI: `catalog.rs` 6 (`grids_method!` for `grids_realm/people/computers/share/models/desks/credentials/requests/research/connectors/work/log`), `help_coverage.rs` 1, `parse.rs:221` (secret-field list for five `grids_*` methods). Engine `dispatch.rs` still routes all 13 `grids_*` methods; `lib.rs` registers only `grids_rollout` as a Tauri command | The engine's registry of grid instances (needed by row 6.1); the agent-facing method catalogue (`yougori agent discover`) | **Preserve-for-compatibility** now; **Consolidate** in P06: move `Product`, `alias` and `words` to the engine or `setup/` so the engine stops depending on CLI code, and drop the `grids_*` schemas from `catalog.rs` unless a retained workflow calls them (unverified: no CLI command sends them any more; only automation/agents could) | `grids::Product` names the instance folders and keyring entries of existing grids (`default`, `i-xxxxxxxx`) — the alias table must survive wherever it moves | `rg 'yougori_cli::grids' src-tauri/src` → 0 after the move; `cargo test --manifest-path src-tauri/Cargo.toml --lib grids:: -- --skip swarm::` |
| 1.7 Grid Core rollout stage machine: `yougori rollout status\|survey\|rehearse\|observe\|coverage\|advance\|back\|retire\|unretire\|forget` — `cli/src/rollout.rs` 202, 6 help lines, `catalog.rs:214`; `src-tauri/src/rollout.rs` 467; `grid/src/core/compat` 9,432 | `cli/src/main.rs:171-177`; `dispatch.rs:144`; `lib.rs:746`. The desktop panel (`grid-rollout.tsx`, `src/api/grids/rollout.ts`) is deleted, so no UI reads rollout state. `src-tauri/src/rollout.rs` uses `yougori_grid::core::compat` | None: the grids it moves "onto Grid Core" are no longer products, and the removal ledger already marks rehearsal/backup as superseded by `setups/migration.rs` | **Remove** the stage verbs and `core/compat` with them | `rollout.json` stage records on customers' hubs become unread; harmless if no product reads a realm (removal ledger: "no product in this build reads a realm") | `rg grids_rollout cli/src src-tauri/src` → 0; `grid/src/core/compat` gone; help lines 97 → 91 |
| 1.7b Rollout data verbs `yougori rollout backup\|verify\|restore\|read --product neo\|sandbox\|swarm\|access` | Same entry points as 1.7 | Reading or restoring a product record "without the product that wrote it" | **Preserve-for-compatibility** until `setups/migration.rs` (row 6.3) offers `restore` and `read` — it has inventory, backup, verify and rehearsal today; restore/read are not there (unverified beyond its module doc) | Backup stamps under the engine data folder; a user with a stamp needs some tool to restore it | Decide after `migration.rs` gains restore; then the whole of 1.7 goes together |

### Priority 2 — duplicated validation, capability metadata, lifecycle, UI/CLI behaviour

| Feature/module | Current callers | Retained workflow | Decision | Data/compatibility impact | Verification |
| --- | --- | --- | --- | --- | --- |
| 2.1 Capability catalogue: `setup/src/capability.rs` (`registry()`, `descriptors()`, `ALIASES`, `availability()`), generated into `src/api/setups/capabilities.generated.ts`, consumed via `src/api/setups/catalogue.ts`; engine `setup_capabilities` fills availability per host | CLI `cli/src/hub/plan.rs` 10, `cli/src/hub/setups.rs` 8; engine `setups/planning.rs` 5, `commands.rs`, `permissions.rs`, `views.rs`, `local_models.rs`, `share.rs`; UI `capability-board.tsx`, `setup-detail.tsx`, `recipes.ts`, `setups-page.tsx`. Freshness test `setup/tests/contract.rs:127` | Capability selection in UI and CLI (plan P02) | **Keep** — no second hand-written catalogue exists in `src/` or `cli/`. Small **Consolidate**: the group search words are written twice (`cli/src/hub/setups.rs:20-27` `GROUP_WORDS`; `src/api/setups/catalogue.ts:13` `LEADS.words`) and `availability_words/availability_code` (`setups.rs:112-130`) mirror engine strings by convention — move both into `capability.rs` so the generated TS carries them | None | `setup/tests/contract.rs` (`capabilities_generated_ts_is_fresh`) before and after |
| 2.2 Two review shapes: `cli/src/hub/review.rs` `template` (v1, line 167) and `template_v2` (line 21, wraps `yougori_setup::plan::Review`, `setup/src/plan.rs:240`) | v1: `run.rs:257-258` (prepare), `publish.rs:183` (V1 branch), tests `run.rs:2227,2459`. v2: `publish.rs` V2 branch, `cli/tests/hub_contract.rs:103`, `plan::Review` 12 refs in `setups.rs`, engine `planning.rs` 3, `local_models.rs` 3, `share.rs` 2 | v2 review is the one contract (plan P03); v1 review exists only for v1 run/publish | **Preserve-for-compatibility** (v1 shape) tied to row 2.3; **Keep** v2 | The website accepts both shapes (`review_shape_problem`, `review.rs:1671`); published v1 items keep their stored review | Goes when 2.3 goes; `review_shape_problem` test coverage |
| 2.3 v1 template path: `cli/src/hub/run.rs` `prepare`/`prepare_own`/`run` (2,556; `run()` at 1283 branches to `plan::run_v2` at 1333 for format 2), `instances.rs` 801, `lifecycle.rs` 751, `tools.rs` 658; fixtures `examples/hub/hello-site` (v1) and `cli/tests/fixtures/my-api-1.6.0` | `setup/tests/v1.rs:13` (3 tests pass per audit), `run.rs:1926,1930` tests, `cli/tests/hub_contract.rs:5`; `main.rs` via `yougori run hub/…` and `yougori template …` | Existing v1 instances (`~/.yougori/hub/instances/INSTANCE/instance.json`, `~/.yougori/hub/records/INSTANCE.json`) and published v1 items | **Preserve-for-compatibility** (plan P07: "existing supported v1 compatibility, or documented safe handling where support is explicitly retired"). Removal would require a documented recovery/export for v1 instances first (plan P04 last bullet) | Audit: no in-place takeover from CLI-owned My API 1.6.0 to engine-owned v2; those instances are stranded if v1 is retired without an export | `cargo test --manifest-path setup/Cargo.toml --test v1`; cli `run.rs` v1 tests; a documented migration note before any retirement |
| 2.4 Two command families for the same thing: `yougori run hub/PUBLISHER/NAME` (`public.rs:64`) and `yougori template run\|continue\|status\|…` (`public.rs:65-66`, ~25 verbs); `cli/src/hub/mod.rs:1143` rewrites `run … template …` into `template run` | `main.rs` → `hub::` dispatch | One template run/manage family (plan P06: "reconcile the existing template/setup command families; avoid introducing a third") | **Consolidate**: keep `template …` as the family, keep `run hub/…` only as a documented alias (plan: "short aliases only where they provide useful compatibility at low cost") | Scripts and the agent guide name both; `help_coverage` tests enforce documentation | Help line count; `help_coverage` tests; `docs/hub.md` |
| 2.5 `cli/src/legacy_names.rs` (110) | `hub/plan.rs` 3, `public.rs` 2, `skills.rs` 2, `workload.rs` 2 | Old environment names resolving to new ones (what it maps is unverified beyond its callers) | **Keep** | Compatibility of stored names | — |
| 2.6 Three backup implementations: `src-tauri/src/setups/backups.rs` 1,075 (setup volumes), `local_backup.rs` 1,309 (environments, `src/api/local-backup-api.ts`), `backup.rs` 873 (`zstd` archives) | Each registered in `lib.rs`; `setups/mod.rs:68-73` wires `backups::Backups` + `schedules::Scheduler` | Files-and-data group: "supported backup" | **Consolidate** candidate — overlap is unverified (different units: volume vs environment vs archive); do not remove any until P04 decides the one retained backup contract | Existing backups under the data folder in three layouts; retention policies | List of backup commands registered before/after; restore test on a disposable volume |

### Priority 3 — first-party recipe/catalogue infrastructure

| Feature/module | Current callers | Retained workflow | Decision | Data/compatibility impact | Verification |
| --- | --- | --- | --- | --- | --- |
| 3.1 Publication ledger: `docs/template-platform/publication-ledger.md` (83) and `cli/tests/publication_ledger.rs` (182) — the test reads every format 2 package in `examples/hub` and asserts the ledger rows match (`UPDATE_LEDGER=1` rewrites) | Only the test itself (`rg publication-ledger cli src-tauri setup` → the test); the ledger records no completed publication (audit) | None: first-party publication is deferred (plan section 1) | **Remove** the test; archive the ledger under `docs/template-platform/archive/` | None (document) | `cargo test --manifest-path cli/Cargo.toml --test publication_ledger` no longer exists; `ls cli/tests` |
| 3.2 Trusted short names `cli/src/hub/setups.rs:57-63` `TRUSTED_ALIASES`: "my api", "sandbox grid", "neo grid", "access grid", "swarm mining grid" → `hub/yougori/NAME` | `resolve_alias`/`alias_hint` in the same file (6 refs), test at line 1997 | Typing "my api" instead of `hub/yougori/my-api` | **Consolidate**: drop the four grid rows — their packages are not in `examples/hub` and `setup/tests/packages.rs:25-26` says they are "never published"; whether older grid versions exist on the Hub is unverified (needs a website check, not a grep). Keep "my api" only if `hub/yougori/my-api` stays published (unverified here) | A user typing "neo grid" gets a refusal instead of a resolution; no stored data | Test at `setups.rs:1997` updated; `rg 'sandbox-grid\|neo-grid\|access-grid\|swarm-mining-grid' cli/src` → only test fixtures |
| 3.3 Example packages `examples/hub` (14) | Loops over the whole folder: `setup/tests/packages.rs` (goldens in `setup/tests/fixtures/*.plan.json`/`*.review.json`, 47 files), `cli/src/hub/publish.rs:739` (personal-defaults test), `cli/tests/publication_ledger.rs`, `src-tauri/src/setups/permissions.rs:99` (`example(name)`, names used unverified). By name: `hello-site` — `setup/tests/v1.rs:13`, `cli/src/hub/run.rs:1926`, `cli/tests/hub_contract.rs:5`; `host-my-app` — `hub_contract.rs:98`; `my-api` — `run.rs:1930`, `mod.rs:1143` (string only), `scripts/measure-template-platform.mjs`; `ai-workspace` — `scripts/measure-template-platform.mjs`; `backup-workflow` — `adr-0001-format-v2.md` only. `agent-tools`, `app-backend`, `dev-workspace`, `gpu-lab`, `inference-endpoint`, `model-collection`, `model-server`, `operations-dashboard`, `shared-workspace`: no named reference anywhere | Test fixtures for the planner, review and permissions (plan section 10: "may supply internal fixture data") | **Preserve-for-compatibility** as fixtures, and **Consolidate** their location: move all 13 format 2 packages to `setup/tests/fixtures/packages/` next to the four grid packages (`packages.rs` already reads both roots; `YOUGORI_EXAMPLES` overrides). Per package: `hello-site` and `my-api` **Keep** where tests name them; `host-my-app` **Keep** (`hub_contract`); the nine with no named reference are **Optional-defer** — each is only a loop fixture, so retiring any one of them costs its golden files and nothing else | Published versions on the Hub are untouched by moving files (plan: "existing published items … not deleted"). Moving breaks the `examples/hub` path in `publish.rs:739`, `permissions.rs:99`, `hub_contract.rs:96`, `scripts/task-metrics.mjs:170`, `scripts/measure-template-platform.mjs` | `cargo test --manifest-path setup/Cargo.toml --test packages` with goldens; the four tests listed |
| 3.4 Catalogue-era documents and scripts: `docs/template-platform/{catalogue 299, parity-ledger 627, progress 68, task-metrics 38, measured-bounds 108, singleton-ledger 133, reconciliation-ledger 74, handoff 143}.md`; `scripts/task-metrics.mjs` (+ test) and `scripts/measure-template-platform.mjs` (+ test) | `task-metrics.mjs:170` reads `examples/hub/{sandbox-grid,neo-grid,access-grid,swarm-mining-grid}` — paths that no longer exist (stale); `measure-template-platform.mjs` `AREAS` lists deleted files but measures a Git tree, so it may still run (unverified, not run) | Historical evidence only (plan: "historical evidence, not competing plans") | **Optional-defer**: archive the documents; fix or remove `task-metrics.mjs` (it cannot run as written) | None | `node scripts/task-metrics.mjs` fails today on the moved paths (expected) |
| 3.5 Grid test packages `setup/tests/fixtures/packages/{access-grid,neo-grid,sandbox-grid,swarm-mining-grid}` and their goldens (access 3, neo 3, sandbox 4, swarm 1 files) | `setup/tests/packages.rs` (`test_packages()` root), `cli/src/hub/setups.rs:2068` | Proof that a template can still build the six grid kinds (row 6.1) | **Keep** while 6.1 is kept; Remove together with it | None | `cargo test --manifest-path setup/Cargo.toml --test packages` |

### Priority 4 — unused dependencies, helpers, flags, generated artifacts

Method: for each `[dependencies]` entry, `grep -rE "\bNAME::|use NAME\b|NAME!\(" CRATE/src CRATE/tests --include=*.rs | wc -l` with `-` replaced by `_` in NAME (derive macros reached through `use` are counted; a derive used only as `#[derive(NAME::X)]` is covered by `NAME::`).

| Feature/module | Current callers | Retained workflow | Decision | Data/compatibility impact | Verification |
| --- | --- | --- | --- | --- | --- |
| 4.1 cli `notify = "8"` (`cli/Cargo.toml:39`) | 0 uses in `cli/src`, `cli/tests` (`rg '\bnotify::|use notify\b' cli` → none) | None | **Removed 2026-10-26** (no `build.rs`, 0 uses confirmed) | `cli/Cargo.lock` re-resolved without the `notify` tree | `cargo check --manifest-path cli/Cargo.toml --all-targets` clean |
| 4.2 src-tauri `thiserror` | 0 uses (`rg thiserror src-tauri/src` → none; no `derive(Error)`) | None | **Removed 2026-10-26** (0 uses confirmed, no `derive(Error)`) | `src-tauri/Cargo.lock` re-resolved without it | `cargo check --manifest-path src-tauri/Cargo.toml` clean |
| 4.3 Near-zero but live dependencies — src-tauri: `similar` (1: `changes.rs`), `tauri-plugin-dialog` (1: `lib.rs`), `tauri-plugin-clipboard-manager` (1: `lib.rs`), `portable-pty` (2: `host_terminal/`), `scrypt` (2: `remote_access.rs`), `crc32fast` (2: `runtime/branch.rs`), `zstd` (2: `backup.rs`), `iana-time-zone` (3: `market.rs`, `swarm/`), `tokio-rustls` (3), `rcgen` (4: `peer_sharing.rs`, `grid_neocloud.rs`, `grid/instance_tests.rs`), `fatfs` (4: `file_import/drive.rs`), `smoltcp` (5: `runtime/cloud/bridge.rs`, `runtime/fabric/file_service.rs`). cli: `age` (4: `confidential.rs`), `axum` (6: `confidential/runner.rs`, `hub/client.rs`), `semver` (6) | As listed | Each is behind a retained path (terminal, remote access, backups, drive import, confidential runner) | **Keep**. `zstd` and `iana-time-zone` would become removable only if row 2.6 drops `backup.rs` or `market.rs` goes | None | Re-run the dependency grep after P06 removals |
| 4.4 Dead code in `src-tauri/src/runtime/cloud/mod.rs`: `known_hosts` (298), `run_script` (305), `shell_quote` (326), all `pub(crate)` | `known_hosts`/`run_script` are called only from `src-tauri/src/desks/cloud.rs:637,656` inside `async fn join` (622); `shell_quote` only from `run_script` itself (`mod.rs:309`). `model_runner.rs:502` has its own private `shell_quote`. The warning means the `desks::cloud::join` chain is unreachable in the compiled configuration (which caller dropped is unverified — `join` is too generic to grep; it is the Sandbox Grid cloud-desk path) | None found | **Remove** the three functions together with `desks::cloud::join` once row 6.1's WorkspacePool handler is confirmed not to need cloud desks (unverified); or **Consolidate** `shell_quote` with `model_runner.rs:502` if `run_script` stays | None | `cargo check` warning count for `runtime/cloud/mod.rs` → 0 |
| 4.5 Feature flags: src-tauri `desktop` (default) / `engine-only` (`Cargo.toml:14-19`; 4 `cfg(feature = "engine-only")` sites); cli and setup have no `[features]` | `engine/Cargo.toml:15` builds src-tauri with `engine-only` | Headless engine | **Keep** | — | `cargo check --manifest-path engine/Cargo.toml` (not run here) |
| 4.6 Generated artifacts: `src/api/setups/capabilities.generated.ts` (kept, freshness-tested); `src/api/grids/permits.generated.ts` (deleted) and its generator `scripts/grid-core-roles.mjs` (exists; not in `package.json` scripts — but **it has callers**, corrected 2026-10-26: `scripts/grid-client-docs.test.mjs:8,40` imports it and runs `--check`; `compliance/release.json:3129` and `compliance/evidence/application-source.json:4209` list it; `docs/grid-core/progress.md:372` documents it. It generates the now-deleted `src/api/grids/permits.generated.ts` from `grid/src/core/identity.rs`, so the generator, its test and the compliance entries go together, when the grid crate's scope is settled — not before) | None for the generator (unverified beyond grep of `package.json` and the comment) | None | **Remove** `scripts/grid-core-roles.mjs` (+ test if any) | None | `rg grid-core-roles . --glob '!node_modules'` → 0 |
| 4.7 `yougori-cli` legacy binary (`cli/Cargo.toml:14-16`, `src/legacy.rs` = `include!("main.rs")`) | 10 packaging/test files: `scripts/bundle-cli.mjs`, `scripts/desktop-dev.mjs`, `scripts/build-signed-windows.ps1`, `scripts/install-windows.test.mjs`, `scripts/release-manifest.test.mjs`, `scripts/test-linux-installed.sh`, `scripts/verify-macos-bundle.mjs`, agent guide | Installed scripts and skills that call the old binary name | **Preserve-for-compatibility** (2-line file; cost is a second binary in the bundle) | Installers ship two names | Release preflight tests |
| 4.8 npm dependencies (15 + 23) | Not individually checked | — | **Unverified** — measure with `npx depcheck` or a per-package grep in P06 before removing any | — | — |

### Priority 5 — runtime pieces to keep

| Feature/module | Current callers | Retained workflow | Decision | Data/compatibility impact | Verification |
| --- | --- | --- | --- | --- | --- |
| 5.1 Container/microVM/VM runtime: `src-tauri/src/runtime/{mod,workload,vm,vm_memory,vm_security,boot_media,microvm_network,qmp_socket,native_sandbox,appliance*,guest_job,guest_ssh,host_platform,host_relay,remote_bridge,fabric}.rs`, `runtime/cuda.rs` + `gpu.rs` + crate `yougori-cuda-runtime` (16 uses), `projects.rs` 1,006 | `setups/ordinary.rs` `EnvironmentHandler` through `EngineProjects` (`setups/mod.rs:51`); Sandboxes page; `yougori run\|vm\|microvm\|start\|stop\|exec\|logs` | Compute group: sandbox type, CPU/RAM, GPU | **Keep** | Running environments and their disks | Disposable-runtime lifecycle tests (P04) |
| 5.2 Storage: `runtime/{storage,container_storage,storage_reclaim,volumes,named_volumes,snapshot_export,duplication_disk,import_drive}.rs`, `temporary_storage.rs`, `file_import/`, `file_export.rs`, `duplication.rs` 2,466 | `VolumeHandler` (`ordinary.rs`), `yougori volume`, `cp`, `import`, `download` | Files-and-data group: persistent volumes, storage location, folder access | **Keep** (`duplication.rs` also serves NeoCloud duplicates — `cloud-duplicate-dialog.tsx`; keep with 1.4) | Named volumes and snapshots on disk | Volume create/mount/backup tests |
| 5.3 Networking: `hub_tunnel.rs` 195, `remote_access.rs` 1,038, `peer_sharing.rs` 327, `runtime/host_addresses.rs`, `runtime/connection_files.rs`; cli `own_domain.rs`, `tool_public_access.rs`, `tool_sharing.rs` | `PublicationHandler` (`ServicePublication`) and `ConnectionHandler` (`Connection`) in `ordinary.rs`; `yougori ports\|connect\|remote\|deployment` | Websites-and-connections group | **Keep** | Public links, domains, pairing keys | Publication handler tests |
| 5.4 Vault: crate `vault/` 7,115 (`yougori_vault` used by 6 files), `src-tauri/src/{vault,vault_gateway,vault_setup,vault_notifications}.rs`, cli `vault.rs`, `tool_credentials.rs` | `yougori vault` (4 help lines), credential bindings for tools, `setups/permissions.rs` | Access group: scoped credentials, secrets never in exports | **Keep** | Encrypted secrets at rest; keyring entries | Vault tests (`npm run vault:test`) |
| 5.5 Models: `model_runner.rs` 1,213, `models.rs` 888, `model_registry.rs` 247, `market.rs` 1,116, `setups/local_models.rs`, `setups/share.rs`; cli `model_*`, `template_models.rs`, row 1.2 | `ModelServiceHandler` peers (`setups/grids.rs:942`), `yougori model` (22 help lines), `model-workspace.tsx`, `network-panel.tsx` (`market-api.ts`) | Tools-and-models group | **Keep** (`market.rs` is the Yougori Network client the model workspace uses; not grid-only) | Downloaded weights, model keys | `model_runner` tests |
| 5.6 Jobs and artifacts: `setups/jobs.rs`, `setups/job_worker.rs` (+ tests) using `yougori_grid::core` (`grid/src/core/jobs*`, untracked today) | `setups/mod.rs:56`; `JobHandler`, `ArtifactStoreHandler` | Automation group: supported commands, readiness | **Keep** — note this ties the setup engine to the grid crate's `core` even if row 1.7 removes `core/compat` | Job receipts in the setups data folder | `setups/jobs/tests.rs` |
| 5.7 Setup engine core: `setup/` crate; `src-tauri/src/setups/{service,store,journal,permissions,planning,handler,ordinary,package,commands,views,export,folder_sync,telemetry,schedules}.rs`; `src/components/setups/`, `src/api/setups/`; `cli/src/hub/{plan,setups,components,personal,format,scan,refs,pattern,publish,capture}.rs` | Everything above | The product (plan section 2: "do not rebuild these foundations") | **Keep** | The setups registry and journal | Existing pure tests (27 passing per audit) |
| 5.8 Swarm Mining and bounty: `src-tauri/src/swarm/` 9,826, `bounty.rs`, `bounty_project.rs`, `grid/src/bounty*.rs`, cli `bounty*.rs`, `closed_bounty.rs` | Live worker on this machine | Out of this inventory's scope by instruction; never run or tested here | **Keep** (not evaluated) | A running worker | None taken here |

### Priority 6 — compatibility and recovery paths

| Feature/module | Current callers | Retained workflow | Decision | Data/compatibility impact | Verification |
| --- | --- | --- | --- | --- | --- |
| 6.1 Engine grid adapters: `src-tauri/src/grid.rs` 2,326, `deskgrid.rs` 1,614, `accessgrid.rs` 1,432 (+433 tests), `desks.rs` 1,907 + `desks/` 2,899, `grids.rs` 400, `grids/registry.rs` 228, `grid_observe.rs` 430, `setups/grids.rs` 3,403 (six handlers: Grid, ComputePool, ModelService, WorkspacePool, AccessBinding, CredentialBroker — `grids.rs:556-1905`), `setups/adopt.rs`; grid crate 75,067 (27 src-tauri files use `yougori_grid`) | `setups/grids.rs` calls the products by wire name (`grid_create/join/leave/delete/password/plan_add/plan_update/plan_remove/swarm_add/swarm_remove/status`, `desks_create/join/leave/add/remove/delete/person_add/person_remove/member_share/status`, `access_create/signin/signout/manage/delete/status`, `grid_neocloud_status/stop_all`); `automation/dispatch.rs` routes 64 such methods; `grid.rs` is used by 11 other files, `desks` 4, `deskgrid` 5, `accessgrid` 2, `grids` 7; `grid_observe` by `lib.rs:625` and `grids.rs:55-134` only. UI: none (all deleted). CLI: none since today, except through templates | "A template can still build these": the six resource kinds remain in `setup/src/resource.rs` `Kind` and in the capability catalogue; `setup/tests/fixtures/packages/*-grid` plan and review against them | **Preserve-for-compatibility** for existing grids (adopted read-only views, `adopt.rs`) and for the six kinds *as long as they are listed as supported capabilities*. The plan (priority 5: "do not preserve every historical adapter automatically") leaves one product decision this grep cannot make: whether Grid/ComputePool/WorkspacePool/AccessBinding/CredentialBroker stay selectable. If they do not, this row (≈14,500 engine lines plus most of the grid crate outside `core/jobs`) becomes the largest Remove in P06 and needs an export/recovery path for existing grid records first (plan P04 last bullet) | Each product's records under the engine data folder (`default` and `i-xxxxxxxx` instances, fixed ports and keyring names per the [singleton ledger](singleton-ledger.md)); `adopt.rs` reads only file metadata | Before: `setup/tests/packages.rs` grid goldens; `src-tauri/src/grids/tests.rs`; `accessgrid_tests.rs`. After a removal: an exported record for each adopted grid, and `rg 'Kind::Grid\|ComputePool\|WorkspacePool\|AccessBinding\|CredentialBroker' setup/src src-tauri/src` consistent with the catalogue |
| 6.2 `src-tauri/src/grid_observe.rs` 430 — loopback health scrape for grids | `lib.rs:625` (managed state), `grids.rs:55,56,124,130,134` (`grids_realm` verbs); removal ledger: "served, always empty (no realm databases exist)" | None today | **Remove** with row 1.7 (its only readers are the `grids_realm` observe verbs, which no CLI command sends) — unverified whether an external monitoring agent scrapes its port | None | `rg grid_observe src-tauri/src` → 0 |
| 6.3 Migration dry run `src-tauri/src/setups/migration.rs` 969 (+488 tests) — inventory, checksummed backup, verify, rehearsal, read-only on a named folder | `setups/commands.rs` 7 refs (engine commands); no UI panel (removal ledger: not done at M14) | Recovery path for legacy grid records before any adopted product is removed | **Keep**; extend with restore/read so row 1.7b can go | Backups it writes are in a caller-named new folder | `setups/migration/tests.rs` |
| 6.4 v1 instances and published v1 items | Row 2.3 | — | **Preserve-for-compatibility** | As row 2.3 | As row 2.3 |
| 6.5 Setup backups and schedules `setups/backups.rs`, `schedules.rs`; `src/api/setups/backups.ts`, `setup-backups.tsx` | `setups/mod.rs:68-73`; UI | Supported backup/restore (plan P04) | **Keep** (see 2.6 for the two other implementations) | `<data>/setups/backups/<setup>/<volume>/<backup>` with checksums and `backup_keep` retention | Restore test on a disposable volume |
| 6.6 `src-tauri/src/setups/export.rs`, `capture` (`cli/src/hub/capture.rs`) | `template capture\|export` commands; UI | Portable export without secrets (plan P05) | **Keep** | Exported templates must never carry credential values (`scan.rs` refusals) | Export-then-import round trip on a fixture |

## 4. Totals

Rows: 42. By decision (a row with two decisions is counted under the first):

| Decision | Rows |
| --- | ---: |
| Keep | 17 |
| Consolidate | 4 |
| Optional-defer | 1 |
| Remove | 10 |
| Preserve-for-compatibility | 9 |
| Unverified (no decision) | 1 (4.8 npm dependencies) |

Highest-confidence removals (every caller grep returned zero or only the module itself): 4.1 `notify`; 4.2 `thiserror`; 1.5 `use-swarm-actions.ts`, `swarm.css` and the stale `vi.mock` lines (all four done 2026-10-26, P06 batch 1); **not** 1.3 `launcher_state.rs`, which the engine calls — a cli-only grep missed it, which is why every Remove row must grep `src-tauri/src` too; 3.1 `publication_ledger.rs` + ledger; 1.1 the empty starter registry and its dead UI; 4.6 `scripts/grid-core-roles.mjs`.

## 5. Findings that contradict the plan's assumptions

1. **NeoCloud is not Swarm-only — and it stays (owner's decision, 2026-10-26).** The rented-environment type is a radio option in the Sandboxes creation dialog (`dialogs/create-environment-dialog.tsx:59,270`), 18 desktop files and 31 registered engine commands serve it, and `yougori model run --neocloud` depends on it. Removing "NeoCloud except where Swarm needs it" would remove a retained sandbox type; only `grid_neocloud.rs` (row 1.4b) is grid/Swarm-specific.
2. **The grid adapters are not optional by inspection.** Six resource kinds in the shared format and catalogue resolve to them, and the kept test packages exercise them. Whether they stay is a capability-scope decision (P02), not a dead-code finding.
3. **The audit's "no retained starter entries" gap is now a removal, not a restoration** (plan section 3); the UI still carries the recipe entry kind, so the builder does not yet "open on capability selection or import".
4. **Some engine wire methods have no caller left but are still served**: all 13 `grids_*` methods are routed in `dispatch.rs` and advertised in `catalog.rs` although the commands that sent them are gone; `grid_observe` is served to nobody.
5. **Line counts moved, they did not only shrink**: 4,043 lines of extracted CLI plumbing and 3,403 lines of `setups/grids.rs` are new untracked code in the same tree that lost 41,909 lines.

## 6. Not verified here

- Whether `hub/yougori/{sandbox,neo,access,swarm-mining}-grid` or `my-api` have published versions on the Hub (needs the website, not the tree) — affects 3.2.
- Which selectors of `neo-grid.css`/`grids.css` the builder still uses — affects 1.5.
- What dropped the caller of `desks::cloud::join` — affects 4.4.
- Whether `scripts/measure-template-platform.mjs` still runs against the moved paths; `task-metrics.mjs` cannot.
- npm dependency usage (4.8), `cargo check --manifest-path engine/Cargo.toml`, cold-cache build times and bundle size.
- Whether any external agent calls the `grids_*` methods or scrapes `grid_observe` — affects 1.6, 6.2.
- No test suite was run for this inventory; the "27 passing" figure is the audit's.

## Findings from the P02 and P06-batch-1 passes (26 October 2026, later the same day)

- P02 done: the desktop builder opens on "Add capabilities" or an import; the empty starter registry (`recipes.ts`) and its dead picker are gone; the desktop suite is 187/187 with `tsc` and `eslint` clean. "Run a template" had been a dead end (step 1 could never pass with an empty registry).
- `SetupDraft.recipe` is **not** the registry: it is the grid-kind format field the shared generator requires (`setup/src/draft.rs` `draft_needs_recipe`). It was kept, with a conditional "Which kind of grid?" question mirroring the CLI's `Step::GridKind`. The three grid kinds are now written down twice (desktop `GRID_KINDS`, CLI `cli/src/hub/setups.rs` `kinds`); **Consolidate** into the generated catalogue once `setup/` is free (P06).
- Two desktop behaviours lost their UI with the grid pages but keep an API: `setupsApi.reviewJoin` (join a grid with an invitation) and `setupsApi.reviewAdoption` (adopt an older grid as a setup). The CLI keeps `template join` and the `setup migration` commands. **Preserve-for-compatibility** on the engine/CLI side; decide in P04 whether the desktop needs an adoption path for existing grid records (the plan: "an honest recovery/export path when a retired feature can no longer run").
- Engine `ValidateResponse.notes` has two shapes (`Vec<Diagnostic>` for a draft, `Vec<String>` for imports; `src-tauri/src/setups/planning.rs:737`). **Consolidate** in P04.
- P06 batch 1, each verified at source first: removed `src/components/use-swarm-actions.ts` + test and `swarm.css` (0 importers), the `notify` (cli) and `thiserror` (src-tauri) dependencies (0 uses; lockfiles lost only those trees), and `cli/tests/publication_ledger.rs` (no code callers; the ledger document stays as a historical record). **Not** removed, because the first draft of this inventory was wrong about their callers: `cli/src/launcher_state.rs` (the engine calls it) and `scripts/grid-core-roles.mjs` (a test and the compliance manifests reference it). Rule drawn from both: every Remove row must grep `src-tauri/src`, `scripts/` and `compliance/` as well as the crate the file lives in.
- CSS consolidation done (P06 batch 1, desktop): `src/components/neo-grid.css` and `grids.css` deleted; the selectors still used (per-class grep across `src/**/*.ts(x)`, counts recorded in the agent's report) moved into `src/components/setups/setups.css`; `app-shell.tsx:16` and `hub-page.tsx:16` import lines changed. NeoCloud dialogs untouched. Desktop suite 187/187, `tsc` and `eslint` clean.
- **Gap found while integrating:** the Hub-page-versus-files check (a published review that promises less than the files grant is named before anyone agrees) exists only in the CLI since today (`cli/src/hub/plan.rs` `against_the_page`). The desktop runs Hub templates through the engine (`setup_plan`) and gets no such comparison. **Consolidate** in P04/P06: move the comparison into the engine's planning so both doors get it, then the CLI can call the engine's rather than its own.
- Version coherence (P07) resolved locally: every manifest (six `Cargo.toml`, `package.json`, `package-lock.json` root entries, `src-tauri/tauri.conf.json`) is 1.2.0, matching `format::MINIMUM_YOUGORI`; lockfiles re-resolved (own crates only; the removed `notify` tree is the only other change). setup, cli, grid, vault, src-tauri check with zero warnings. Not pushed, not released, no compliance evidence regenerated (that is release-time work).
- **Headless engine crate (`engine/`) does not check**, and this predates today: it builds `src-tauri` with `engine-only` and no default features, where `tauri::WebviewWindow` has no default runtime generic; `src-tauri/src/setups/commands.rs` names `tauri::WebviewWindow` directly in 16 signatures instead of the crate alias `lib.rs:164` (`type WebviewWindow = tauri::WebviewWindow<Rt>`). 17 errors, all in that file; the signatures are unchanged from HEAD and the lock re-resolve touched no dependency. Fix: import the crate alias in commands.rs — one line — once the P03 agent releases the file. P07 must check `engine/` explicitly; nobody had today.
- P05 done (export → import by another person): six leak paths closed in `src-tauri/src/setups/export.rs` (private LAN addresses, live `desk-invite:` invitations, this computer's name, template-authored personal defaults, `.env`/key/token files, fixed wallet values now refuse the export); second copies become `NAME-2`; update `conflicts` now at the top of every CLI result; `cli.txt` Setups topic gained "Sharing a setup without an account". Found and handed to P04: `planning.rs::check` runs only the format check on install, so what export refuses to pass on can still be installed.
- P03 done (Hub tools through the shared path): pinned Hub tools are fetched by the engine through the same digest-verifying `EngineHub` client as components (`src-tauri/src/setups/hub_tools.rs`, new), reviewed like bundled tools (installer addresses, the key as a `hub-INSTANCE-key-NAME` secret, digest and Verified badge, the community warning word for word, a declared-access line), and installed through the one existing custom-tool path; the `ordinary.rs` refusal is gone. Portable tool metadata (`access`, `inputs`, `outputs`) lives in `setup/src/format.rs` with bounds; a declaration grants nothing — authority is the sandbox spec (`ordinary.rs` `environment`/`usable_binding`/`validate`), and a test holds that. Follow-ups: `setup/src/resource.rs` `ToolInstall.digest` so apply is tied to the reviewed digest, not only version plus per-file hashes (doing now); the CLI's own v1 `Tool` (`cli/src/hub/format.rs`) lacks the metadata so `yougori tool check|add|publish` refuse it — **Consolidate** to the shared format (agent running); `server/hub/review.mjs` in the website checkout may need to accept the new `tools[]` keys (not on this machine; P07 website contract item).
- Consolidated (P06): the CLI's own copy of the tool-file rules is gone. `cli/src/hub/format.rs` now parses tool files with `yougori_setup::format::tool` (`ToolFile` = the shared `Tool`); the CLI `Tool` remains only as the installer's view (`From<&ToolFile>`), because the engine's `hub_tools.rs::installer` builds that view by a 15-field literal. `yougori tool check|add` accept and validate `access`/`inputs`/`outputs` with the shared messages, and the tool review shows declared access as "the tool's own word". CLI 729 passed; setup, cli, src-tauri and engine checks at zero warnings. Remaining duplication: `hub_tools.rs:71-89 installer()` = `format.rs From<&ToolFile>` (one line to unify); `format.rs` `metadata`/`hub_text`/`badge_words`/`topic` mirror the shared crate for the v1 template path; `tool_memory()`.
- Behaviour notes from that change (tool check/add): version messages use the shared wording (`1.0 is not a version` rather than quoted); a `yougori-tool.yaml` over 65,536 bytes is refused; NUL bytes are caught per shell line rather than up front.
- Retired (P06): `scripts/task-metrics.mjs` and its test — it measured the four cancelled grid recipes by name and could not run since those packages moved; `docs/template-platform/task-metrics.md` stays as a historical record and says so. The 13 example packages stay where they are as test fixtures (moving them would break four known paths for no product gain).

## P04 done, and the batch's own breakages closed (27 October 2026)

- P04 (shared lifecycle and recovery): the state machine is written down in the agent's report (Creating/Running/Stopped/Updating/Removing/Retained/Removed; operations Planned→Applying→Completed|Failed|AwaitingInput|Unknown, Cancelling→Cancelled). Nine of the eleven required behaviours already held and now have a test each; two were changed: a `continue` after an *unknown* outcome now reconciles first (looks, never acts) and then carries on without creating anything twice; and a setup holding a part whose product is gone (a retired grid) could be neither stopped nor removed — it is now said plainly on the setup page and in every review, the part is skipped and never touched, and the note points at export. Also: `ValidateResponse.notes` is one shape (diagnostics); install planning refuses what export refuses (`install_refused`, same scan and personal-detail rules) so the two doors agree; backup wording says a copy of files, never a database backup. Engine suite 1087 → 1098, zero warnings.
- **CLI/engine mismatches P04 found, not yet fixed (follow-ups):** `template configure` cannot answer a setup waiting for input — the CLI tells people to use it, but it plans a new change and the engine refuses `setup_busy`; the engine's door is `setup_apply` with the waiting operation's id, digest and secrets. `cli/src/hub/setups.rs::retry` refuses an `unknown` outcome locally although the engine now accepts `setup_action retry` for it. The engine never emits `cancelled` on the wire (it maps to `failed` + `operation_cancelled`), so the CLI's cancelled branches are dead but harmless.
- Breakages this batch introduced and closed before stopping: the builder filtered import notes to strings and so dropped every Diagnostic-shaped note after the P04 shape change (`template-builder.tsx:544`, now maps to `message`; desktop 190/190, tsc, eslint clean); five `scripts/launcher-*.test.mjs` required assets that went with the launcher and failed `npm test` before vitest started (removed, backed up).
- Renamed (P06): `cli/src/launcher.rs` + `cli/src/launcher/` → `cli/src/model_run.rs` + `cli/src/model_run/` — it is the interactive model run/chat flow, not a launcher; `launcher_state.rs` keeps its name because the engine calls it. `yougori cli --help` no longer prints the dead launcher page. The CLI's last copies of the v1 metadata rules (licences, badge words, text rules, bounds, `tool_memory`) now come from the shared crate, with the user-facing words pinned by a test; the remaining v1-only differences are commented at their lines in `cli/src/hub/format.rs`.

## Measurements after (27 October 2026, same method as the baseline)

| Measure | Baseline | After | Note |
| --- | --- | --- | --- |
| Rust lines: setup / cli / src-tauri / grid / vault | 15,868 / 61,512 / 138,284 / 75,067 / 7,115 | 16,305 / 61,933 / 139,898 / 75,067 / 7,115 | Up, not down: the baseline already followed the day's big removals (launcher, four families: net −48,404 lines against the last commit). P03–P05 then added the Hub-tool path, export checks, lifecycle tests (`lifecycle_tests.rs`), tool metadata — much of it tests. |
| TypeScript in src/ (of which tests) | 37,096 (11,199) | 36,986 (11,101) | Starter registry, grid stylesheets, orphaned Swarm UI gone; new builder tests added. |
| Dependencies: setup / cli / src-tauri / grid; npm | 5 / 18 / 41 / 23; 15 + 23 | 5 / 17 / 40 / 23; 15 + 23 | `notify`, `thiserror` removed (0 uses). |
| `yougori help` lines | 97 | 97 | The families' 26 lines went before the baseline; `template permissions` and the export loop's wording were added within existing lines. |
| Desktop: pages / components / setups | 5 / 173 / 33 | 5 / 168 / 34 | |
| Guide `# ` sections | 13 | 13 | Four grid sections → one "Grids a template can build" (same count because that one replaced them before the baseline). |
| Versions | 1.1.2 everywhere vs minimum 1.2.0 | 1.2.0 everywhere | Local only; not pushed, not released. |
| Working tree vs last commit | — | 279 files, +10,838 / −48,404; 371 untracked | Nothing committed, at the owner's instruction. |

Honest reading, as the plan asks: this batch simplified the system by removing products, commands, duplicate validators and dead assets, and by making the engine the single implementation behind both doors — not by shrinking the line count of the code that remains, which grew with tests and the three finished workflows.

## Re-audit 27 October 2026

This entry supersedes completion assumptions in earlier checklist rows without deleting their history. The [active plan](../template-platform-implementation-plan.md) now contains only remaining work. Original P01–P07 section references elsewhere in this inventory refer to the previous plan layout.

Source checked in this audit:

- The inventory and baseline/after measurements exist; they are not tasks to create again.
- The empty starter registry and obsolete launcher files are gone. The model interaction code is under cli/src/model_run; grid styles were consolidated into the retained setup stylesheet.
- Hub tools use src-tauri/src/setups/hub_tools.rs and the ordinary shared installer, with reviewed digest binding in ToolInstall. The previous blanket Hub-tool refusal is replaced.
- The CLI tool format delegates to yougori_setup::format::tool. The engine installer view now calls the same From mapping, so the earlier duplicate-mapping follow-up is also finished.
- Export safeguards and lifecycle regression tests are present. Engine lifecycle tests use fake backends; those source checks do not establish actual crash/disk/domain acceptance.
- Validation notes share the diagnostic representation. The desktop consumes their messages.
- Grid-kind choices now come from the shared catalogue; the earlier duplicate GRID_KINDS follow-up is finished. Group search words remain duplicated.
- App/crate metadata is 1.2.0 and setup commands import crate::WebviewWindow. The old version-mismatch and headless alias implementation tasks are removed.
- Recipe publication remains deferred. Existing packages are not new release requirements.

Confirmed unfinished at source:

1. cli/src/hub/setups.rs::configure starts a new change rather than answering the existing waiting operation.
2. The same module's retry still refuses unknown locally despite the engine's reconciliation path.
3. cli/src/hub/plan.rs::against_the_page remains a CLI-only comparison; the desktop engine planning path does not provide the equivalent review comparison.
4. Engine dependencies on CLI grid types and duplicated capability search wording remain. Further removal suggestions require caller and compatibility decisions.
5. Actual export/import, custom-tool/model attachment and lifecycle runtime acceptance, website contracts and final packaging/compliance/bundle evidence remain open.

Fresh checks run for this audit:

| Check | Passed | Failed |
| --- | ---: | ---: |
| setup contract integration suite | 5 | 0 |
| setup planning integration suite | 19 | 0 |
| setup v1 integration suite | 3 | 0 |
| Desktop builder, setup-link and setups-page suites | 61 | 0 |
| Total | 88 | 0 |

Commands:

    cargo test --offline --locked --manifest-path setup/Cargo.toml --test contract --test planning --test v1
    npx --no-install vitest run src/components/setups/template-builder.test.tsx src/components/setups/setup-link.test.ts src/pages/setups-page.test.tsx

Rust used a separate target cache with four jobs, incremental disabled and dev/test debug info disabled. These are focused pure/mocked checks, not the full suites reported earlier, a live engine run, website verification or release certification.

Only the active plan and this evidence entry were changed for this re-audit. No source code was edited, no worker or application was started, and nothing was committed, pushed or published.

## Batch 2: sections 1–3 implemented, website contracts checked (27 October 2026)

This entry records what the [active plan](../template-platform-implementation-plan.md)'s sections 1–3 and 5 asked for and what was done, with the checks run. The plan now lists only what remains (runtime acceptance and release evidence).

### 1A. A change waiting for an answer is answered through `template configure`

- `cli/src/hub/setups.rs::configure` reads the setup's current operation first (`setup_operation`). When it is `awaiting_input`, `answer_waiting` sends the secret value to the engine with `setup_apply` carrying the waiting operation's own id and the digest of the reviewed plan, which the engine's `continue_operation` joins (`resume_waiting`); nothing is planned or created a second time. The ordinary path (`change`) is unchanged for an idle setup.
- The engine's `dto::OperationProgress` gained an optional `planDigest` (additive; `views::progress` fills it) so a terminal that was not there for the review can name the plan. `HandlerError` gained an optional `field`, set by the sandbox secrets step (`ordinary.rs`, `secret_needed`), carried on the diagnostic as `field`, so the CLI asks for exactly that key, refuses an answer that leaves it out before sending anything, and a terminal asks for the value without echo.
- Secret transport is unchanged: `--secrets -` (stdin JSON) or a hidden prompt at a real terminal; never an argument. An input or binding cannot change a change already under way (it would need a new plan); the refusal names the working actions: `yougori template configure INSTANCE --secrets -`, or `yougori call setup_cancel --setup-id ID --operation-id OP --yes` and then configure. `--dry-run` reports what is waited for and sends nothing.
- Wording that pointed at a non-working action (`configure` planning a busy setup) is replaced by `waiting_words`/`settled_words`, shared by `configure`, `continue`, `logs --follow`, `start`/`stop` and `template run`'s `follow_operation`.
- Tests (`cli/src/hub/setups.rs`): supplied answer (one `setup_apply`, no `setup_plan`, the secret in no other call and not in the result), missing or partial answer refused before sending, inputs/bindings refused, dry run, an agreement that cannot be answered from here, a change cancelled meanwhile reported as a cancellation rather than success, and the idle path as before. Engine: `an_operation_waiting_for_a_secret_continues_by_its_id_without_the_plan_in_memory` now continues by the digest the progress names; `a_sandbox_waits_for_its_secret_and_continues_when_given_it` checks the named field.

### 1B. `template continue` after an unknown outcome, and cancellation on the wire

- `retry` no longer refuses `unknown` locally. It asks the engine to reconcile (`setup_action reconcile`, which records what the cut-off step left behind), and only a change that then reads `failed` is retried (`setup_action retry`, same operation id); one found finished returns `continued: false`; one still unknown is reported with its reason and nothing runs. The result carries `reconciled: true` when the check happened.
- The engine never emits a `cancelled` state (`views::operation_state` maps `Cancelled` to `failed`; `operation_error` adds the code `operation_cancelled`). The CLI's dead `"cancelled"` branches are gone; `failed` with that code is said as a cancellation (`wire::cancelled`, exit 130) in `settled_words` and in `follow_operation`; `cancelling` is waited on like `applying`.
- Tests: `continue_after_an_unknown_outcome_has_the_engine_check_first_and_runs_nothing_blindly` (reconcile→retry; reconcile→completed with no retry; still-unknown with no retry; a second continue after completion runs nothing), `a_cancelled_change_arrives_as_failed_with_its_code_and_is_said_as_a_cancellation`. Engine: `l03b_continuing_after_an_unknown_outcome_reconciles_first_and_a_second_continue_does_nothing_twice` (reconcile makes nothing; retry runs only the unfinished step; a second retry is refused `not_retryable` and a second reconcile changes nothing; one creation per resource).

### 2. The Hub page check is one rule at the planning boundary

- The rule is `cli/src/hub/review.rs::page_check` (with `page_lines`, `page_json`, `page_from_json`, `NO_HUB_PAGE`), used by the engine's `planning::plan` for every Hub-sourced plan (`setup_plan`, which the desktop and `template run` share) and by `template plan` when it plans a Hub package locally. The engine's `Hub::fetch` now carries the item's page (`Fetched.page`, from the same `client::obtain` the CLI uses); the plan envelope carries `page: {compared, differs, differences[], reason?}`. A folder, and a setup planned again from its kept package, carry no page.
- The desktop `SetupReview` shows the differences above everything else before the person agrees, and a page that could not be compared says why; a page that matched shows nothing. The CLI's `run_v2` reads the engine's answer (`page_of`) instead of comparing on its own; `against_the_page` is removed. An engine that made no check is reported as "not compared" with an update hint, never as a clean check.
- Coverage: understated grants (`warnings`), changed sandboxes (`environments`), costs, an absent page, a page for another version, a page published without a review, and an honest page: engine `a_hub_page_that_promises_less_than_the_files_is_named_in_the_plan_before_anyone_agrees`; CLI `the_page_check_is_one_rule_with_one_shape_for_every_door`, `a_run_of_a_hub_template_carries_the_engines_page_check_into_its_result`; desktop `setup-views.test.tsx` (two cases). Imports are covered by the published review including each resolved component (`published_review`), and by `hub_contract.rs` F12.

### 3. Consolidation and removal decisions

- Capability search words and availability wording are now one table: `yougori_setup::capability::Group::{key, lead, words, from_word}` and `Availability::{id, words, parse}`; the generated client table (`capabilities.generated.ts`, refreshed with `UPDATE_CONTRACT=1 cargo test --manifest-path setup/Cargo.toml --test contract`) carries `key`, `lead`, `words` per group and `AVAILABILITY_TEXT`. The CLI's `GROUP_WORDS` and the desktop's `LEADS` are gone; `--group` still takes `grid|models|web|people|data|automation` or a group id.
- Rows whose earlier decision changed, with the evidence, are in the [removal ledger](removal-ledger.md#decisions-resolved-27-october-2026): the grids vocabulary stays in `yougori-cli` as the shared library it already is (1.6); the rollout stage machine stays for the documented compatibility window and goes in a planned breaking release, the data verbs stay (1.7, 1.7b, 6.2); `desks::cloud::join` is live, not dead (4.4); the two generator scripts whose inputs were deleted on 26 October are retired with their generated guide (4.6); every npm dependency and every helper script has a caller (4.8).
- Nothing was removed that a retained primitive, an existing record, a documented command or a v1 item depends on.

### 5. Website and user-sharing contracts

- Website source: `C:\Users\Argon\Downloads\YougoriWebsite` (commit f01eee1, five files locally modified; not changed by this batch). `server/hub/review.mjs` keeps a closed, bounded format 2 review: every top-level key `published_review` writes (`format, environments, totals, public, connections, tools, inputs, steps, pcAccess, warnings, requires, resources, capabilities, subtitle, aliases, retention, costs`) is in its `PARTS`; the tool metadata (`access`, `inputs`, `outputs`) sits under `tools[i]` in both the template review and the format 1 tool review, within the website's depth 4 and 4000-character text bounds. Bounds agree: resources 256, dependsOn 32, capabilities 64, aliases 16 of 64 characters, subtitle 120, costs 32, text 4000 (`setup/src/limits.rs`, `review::TEXT_MAX`). Resource kinds, selections (`required|optional|default`) and retention (`keep|ask`) match the shared ids; every capability id matches the website's `^[a-z]+\.[a-z_]+$`. Versions: both refuse a `+` build part and numeric prerelease parts with leading zeros (`refs::parse_version`, `rules.VERSION`). Secret and path scanning use the same token patterns, forbidden names, skipped folders and placeholder rule (`scan.rs`, `scan.mjs`).
- Run: `node --test server/hub.test.mjs` in the website checkout, 37 passed (including immutable versions, resumed multi-part uploads, checksum refusal, format refusal, closed and bounded format 2 reviews, a format 2 tool keeping a tool review's grants). `node scripts/test-hub-contract.mjs C:\Users\Argon\Downloads\YougoriWebsite` ran the CLI's two website-backed contract tests against a disposable in-memory Hub: download, check and review of a seeded item; publishing the CLI's real reviews in both formats and reading them back; 2 passed. No public item was touched; nothing was published anywhere.
- The website carries no first-party recipe promotion (the only product name on its pages is the Neo Grid pricing plan). `docs/hub.md` section 4 now documents `access`, `inputs` and `outputs`.
- Not verified here: that an exported package runs for another person on a real engine. That is runtime acceptance (the plan's remaining section).

### 4. Runtime acceptance: what could be checked, and what blocks the rest

- The CLI built from this tree (`cli/target/debug/yougori.exe`, 1.2.0, protocol 2) against the engine running on this computer: `template list` reads the three v1 instances (`my-api`, `my-api-2`, `my-api-3`) and the adopted Swarm Mining setup; `template capabilities --group web` reports availability from the engine; a disposable fixture (`C:\tmp\yougori-accept\fixture`, one `alpine:3.20` sandbox with one secret) passes `template check` and plans locally (`template plan`: `page` says a folder has no Hub page, `secretsAtRun: [token]`).
- `template run FIXTURE --dry-run --yes` was refused by the running engine: "This template needs Yougori 1.2.0 or newer". The engine running on this computer is the 26 October development build, which reports 1.1.2 and refuses every format 2 template; it also predates every engine change in this batch. The engine's control pipe is one per user, so a second engine cannot run beside it, and no environment variable moves its data folder. Real-runtime acceptance of the implemented tools therefore needs an engine built from this tree, which means stopping the running one, or a second computer. Nothing was stopped, restarted or created here.

### Checks run for this batch

| Check | Command | Result |
| --- | --- | --- |
| Shared crate | `cargo test --manifest-path setup/Cargo.toml --offline` | 163 passed (lib 75, contract 5, draft 15, folder_bindings 13, measured_bounds 7, merge 3, packages 4, planning 19, review_fixes 19, v1 3), 0 failed |
| CLI library | `cargo test --manifest-path cli/Cargo.toml --lib --offline -- --skip swarm --skip bounty` | 573 passed, 0 failed, 1 ignored; 76 filtered (Swarm Mining and bounty, never run) |
| CLI command line | `cargo test --manifest-path cli/Cargo.toml --test command_line --offline` | 25 passed |
| CLI ↔ website contract | `node scripts/test-hub-contract.mjs <website>` | 2 passed against a disposable in-memory Hub |
| Engine | `cargo check --manifest-path src-tauri/Cargo.toml --all-targets --offline` (separate target dir) | 0 warnings |
| Engine setups | `cargo test --manifest-path src-tauri/Cargo.toml --lib --offline -- setups:: --skip swarm:: --skip bounty` | 324 passed, 0 failed |
| Desktop | `npx vitest run --dir src`; `npx tsc -p tsconfig.app.json --noEmit`; `npx eslint . --max-warnings 0` | 830 passed in 134 files; type check clean; lint clean |
| Scripts | `node --test --test-concurrency=2 scripts/*.test.mjs` | pass (after the two orphaned generators were retired; before that, 3 ENOENT failures) |
| Website | `node --test server/hub.test.mjs` | 37 passed |

Rust ran with a separate engine target directory, incremental disabled and dev/test debug info disabled, because the engine running on this computer was built from `src-tauri/target`. One test binary from an earlier run hung on an obsolete fake (`"cancelled"` state) and was stopped; the fake was corrected. Nothing was committed, pushed, published, installed or restarted.

## Follow-up verification after batch 2, 27 October 2026

The latest check confirmed the batch 2 implementation at source and reran focused tests. The active plan now removes the five completed checklist rows and the completed-work paragraphs. Only real-runtime acceptance and release evidence/packaging remain.

Confirmed at source:

- configure detects AwaitingInput and answers the existing operation through answer_waiting; normal idle configuration is preserved.
- retry reconciles unknown outcomes through the engine and retries only the appropriate settled state. Cancellation uses the engine's failed state plus operation_cancelled code.
- planning::plan calls the shared review::page_check; the CLI reads the engine's result and SetupReview shows differences or inability to compare before agreement.
- CLI group matching and availability wording use the shared registry; the desktop consumes generated metadata.
- Remaining keep/defer/removal decisions are documented in the removal ledger, rather than silently marked as deletions.
- Compliance manifests still reference the retired grid-client-docs and grid-core-roles scripts. Regeneration and package verification remain open.

Fresh verification:

| Suite | Passed | Failed |
| --- | ---: | ---: |
| CLI hub::setups:: (including waiting-input, unknown-outcome and cancellation regressions) | 50 | 0 |
| CLI hub::plan:: (including shared page-check and export/import contracts) | 13 | 0 |
| Desktop setup-views | 8 | 0 |
| Website Hub suite | 37 | 0 |
| Total | 108 | 0 |

Commands:

    cargo test --offline --locked --manifest-path cli/Cargo.toml --lib hub::setups:: -- --skip swarm --skip bounty
    cargo test --offline --locked --manifest-path cli/Cargo.toml --lib hub::plan:: -- --skip swarm --skip bounty
    npx --no-install vitest run src/components/setups/setup-views.test.tsx
    node --test server/hub.test.mjs

The website command ran in the existing website checkout. Rust used the separate target cache, four jobs, incremental disabled and dev/test debug info disabled. These checks use test fixtures and mocks; no public packages or accounts were changed. The broader batch 2 engine and cross-repository results above remain reported historical evidence, not rerun results from this follow-up.

The installed-engine version/runtime limitation is the preceding batch's observation, not a fresh live-state assertion. This check did not call, stop or restart the live engine. Runtime acceptance still requires a compatible test engine on an isolated installation or other suitable authorized environment.

Only the active plan and this evidence record were edited. No code, live workload, commit, publication or release was changed.

## Isolated runtime evidence audit, 27 October 2026

This read-only follow-up found newer evidence under the local acceptance workspace (C:/tmp/yougori-accept/evidence) that was not yet reflected in the active plan. It inspected saved JSON result/state fields, scripts, logs and current source. No runtime command, engine restart or test suite was launched by this audit. Another final-check sweep was already producing results.

### Prerequisite resolved

The acceptance feature in the CLI, engine library and headless engine supplies isolated endpoint/data/runtime configuration, lock and deployment-secret namespaces. scripts/acceptance/README.md documents the procedure and disposable fixtures. restart.log records an isolated headless 1.2.0 engine starting successfully. The previous claim that another compatible engine could not run alongside the installed engine is obsolete.

This is evidence that the acceptance route was implemented and used, not proof of every isolation property or of production packaging. Release verification must ensure the feature stays disabled and the tested guest-agent/runtime is the shipped one.

### Completed scenarios removed from the active plan

| Evidence filenames in the acceptance workspace | Observed result and limit |
| --- | --- |
| 02-run-tiny-a.json, 02-run-tiny-b.json, 03-volumes.json | Two v2 CLI runs report ready and separate volumes exist. Host-port isolation is not established by 03-ports.json, which is an empty list. |
| 04-status-stopped.json, 10-status-after-restart.json | Basic stop/start and subsequent running status are evidenced. These alone do not prove an explicit stop remains stopped through restart. |
| 12-check.json, 13-restore-copy.json, 15-restore-orig.json | Backup check reports unchanged content; copy and original restore succeed with checked metadata. Keep any missing restored-byte comparison explicit. |
| 18-logs-final2.json, 21-configure.json | The interrupted-operation sequence reaches completed; answering a waiting operation also reaches completed. Earlier failed attempts are not counted as final passes. |
| 22-apply-stale.json, 23-configure-2.json | Stale apply is refused with revision_conflict and a concurrent configure with setup_busy. |
| 26-stop-borrower.json, 26-owner.json, 29-continue-rm.json, 29-owner.json | Borrower stop/removal completes and the owner is still running. This is not actual model inference/attachment evidence. |
| 30-export.json, 31-run-imported.json, run2/data/setups/registry.json | Real export and import/run to ready in the second isolated profile. Full credential/private-default assertions remain separate. |
| 34-logs.json, 35-logs.json | Hub-tool operation completes; the later changed-tool case fails with tool_unavailable. Do not treat an expected refusal as a failed acceptance scenario or outer ok=true as successful execution. |
| 36-rm-continue.json, 52-retained-status.json, 52-retained-export.json | Interrupted removal completes after reconciliation; another setup is retained and exports successfully. |
| 43-backups-after.json | Three backup copies retained. |
| 47-publish-again.json, 48-hub-run.json | Publication to the disposable Hub succeeds and that downloaded v2 item runs to ready. Nothing here establishes public deployment. |
| 50-v1-continue.json, 50-v1-status.json | The v1 fixture continues and reports ready with its environment running and tool step done. |

### Still partial or missing

- 37-validate.json is draft validation, not a native UI walkthrough.
- 40-model-dry.json is explicitly dryRun=true, not actual inference.
- 51-domain.json is an operation_failed response, not proof another working route survived.
- publish-cut.log records an interrupted upload followed by an upload-not-found response after restarting an in-memory Hub. Later publication succeeded, but persisted partial-upload resume needs its own evidence.
- Full/read-only storage, port/credential isolation, recipient-secret exclusion, stopped-state persistence, legacy unsupported-resource access and cleanup require the precise remaining assertions in the plan.
- The acceptance procedure uses a separate candidate runtime with a rebuilt guest agent. Matching that runtime to shipped artifacts remains a release gate.

### Release evidence at inspection

The final/summary.txt file was being populated by an existing sweep; completed setup, CLI-library and command-line rows had exit 0 when read. It had no final DONE marker at that observation. This audit did not launch duplicate checks or mark the release sweep complete.

The standalone engine test logs also contain successful result summaries, but they are historical execution records and do not replace candidate identity, policy exclusions or packaging checks.

Compliance manifests still list retired grid-client-docs/grid-core-roles scripts. Existing dist output is older than the acceptance work. Runtime acceptance and release completion therefore must not be collapsed into one completed checkbox.

Only the active plan and this inventory entry were edited by this audit. Raw artifacts were read, not rewritten; concurrent implementation and test work were preserved.

## Runtime acceptance, 27 October 2026

The plan's section 1 asked for real-runtime evidence of the generic tools and lifecycle. It was run
on this computer with a disposable engine built from this tree. That engine ran beside the
installed development engine (`src-tauri/target/debug/yougori.exe`, 1.1.2, PID 49568), which was
never stopped or restarted and served its own workloads throughout. The procedure, the fixtures and
the isolation rules are in [`scripts/acceptance/`](../../scripts/acceptance/README.md).

### Isolation

- A new `acceptance` Cargo feature, in the CLI, the engine library and the headless engine and
  never in a release build, gives the disposable engine its own control pipe
  (`YOUGORI_ACCEPTANCE_ENDPOINT`), data folder (`YOUGORI_ACCEPTANCE_DATA_DIR`) and optionally its
  own runtime folder (`YOUGORI_ACCEPTANCE_RUNTIME_DIR`). Its single-instance lock and its
  deployment-secrets vault entries carry a suffix derived from the data folder, so it never sees
  the installed engine's sign-ins and everything it stores is named as its own.
- Builds used `CARGO_TARGET_DIR=/c/tmp/yougori-engine-target`. `USERPROFILE` pointed at a
  disposable folder. The Hub was the website's own server code run in memory
  (`scripts/acceptance/hub-fixture.mjs`), and nothing was published anywhere real.
- A second disposable engine, with its own data folder, profile, vault namespace and no Hub
  sign-in, stood in for another person importing an export.
- The candidate guest agent (below) ran from a copy of the bundled runtime whose initramfs carries
  the agent built from this tree, with that copy's checksum lists regenerated. The bundled runtime
  in `src-tauri/resources/runtime` was only read.
- At the end both engines and the in-memory Hub were stopped, and the eight vault entries the
  disposable engines created were deleted.

**Incident, closed.** A shell turned the second engine's pipe name `\\.\pipe\…` into `\.\pipe\…`.
The first version of the feature treated an invalid name as unset and fell back to the real
endpoint. As a result, three read-only requests reached the installed engine: an engine status,
the setup list, and one Hub read made with its sign-in (`/hub/me`). The same fallback had sent one
engine status there earlier in the run. Nothing was changed. The disposable engine itself refused
to start, because it could not take the installed engine's pipe. The feature now fails closed: a
malformed name, the installed engine's own name, or a data folder given without a name is an
error (`cli/src/wire.rs`, `acceptance_tests`).

**Second gap, closed later the same day.** The Personal Vault belongs to the Windows account, and
the acceptance feature did not isolate it. Every disposable engine asked the account's vault broker
for its status every 2 seconds (`vault_notifications`), and the first disposable desktop app read
the account's vault setup file and asked the broker for its status at startup. The status carries
only request IDs and a count; nothing was written, and the broker refused the unregistered test
build before anything else. Every broker call now goes through `vault::broker`, which refuses under
the feature, and the vault setup file is read from the acceptance data folder.

### What was exercised, and the result

| Plan item | What ran on the real runtime | Result |
| --- | --- | --- |
| Create with required inputs and a secret | `template run` of `accept-tiny` (one sandbox, one volume, one secret) | Created; the sandbox had the input, exactly the secret and no internet, as declared; the secret value was in no setup, plan or journal file |
| Native capability selection | `setup_validate` with a draft of capability choices, as the app's builder sends it, then a run of the files the engine wrote | Ran; the service answered inside its sandbox. The app's UI itself was not driven |
| Custom tool fetch, review, install | `accept-tool` published on the in-memory Hub; `accept-tooluser` planned and applied | The review named the tool, its version, digest, Verified mark and declared access; the tool installed and passed its check |
| Reject changes from the reviewed digest | The cached tool altered after review, with the Hub up and then with it down | Hub up: the changed copy was refused and the reviewed digest fetched again; the altered line never ran. Hub down: the apply failed before creating anything |
| Export and import as another person | `template export`, then the export run on the second engine with that person's own secret | No secret value, host path, account or setup id in the export; it ran with no publisher account |
| Cross-setup borrowing | `accept-borrower` borrowing another setup's sandbox | Attached. Stopping the borrower left the owner running; removing the owner while borrowed was refused; removing the borrower detached and left the owner and its data intact |
| Connections to another setup's sandbox, model attachment | The borrower's connection to the borrowed sandbox; a `model_request` connection | Not delivered by the engine (known limits in `catalogue.md`). Both are now refused at planning, before anything is made. A model dry run reviewed the download and the GPU; no model was served |
| Two copies | Two runs of `accept-tiny` | Distinct sandbox names, volumes and vault entries; each had its own input and secret; ports stay inside each sandbox |
| Restart, explicit stops | `app quit` and start of the disposable engine; `template stop` and `start` | After the fixes: setups read what is there after a restart, start starts, data survives a stop |
| Crash recovery | The disposable engine killed with `taskkill /F` while a step was inside the runtime, then started | Startup recovery found the cut-off step's work and recorded it without doing it twice |
| `template continue` after a cut-off step; a waiting change answered with `template configure --secrets -` | The two-sandbox `accept-wait` cut between its sandboxes, then continued and answered from a fresh terminal | Continued, waited for the secret the crash lost, took it through configure, and the second sandbox had exactly that secret |
| A cancellation from the app read by the CLI | `setup_cancel` (the app's Cancel call) while the CLI followed the run | After the fix: the engine looked at once and ended the change as cancelled; the CLI exited 130 and named the commands to carry on or remove |
| Stale and concurrent changes | A reviewed plan applied after the setup changed; two `configure` at once | `revision_conflict`; the second change refused while the first ran; nothing interleaved |
| Storage failure | Write access to one test setup's backup folder denied, then restored | "Yougori could not prepare a folder for the backup: Access is denied", retried, nothing partial written; the retry after restoring succeeded |
| Publication failures | Publishing the same version twice; an upload cut off by stopping the Hub, then published to a fresh Hub | Same version refused, nothing uploaded. After the fix the cut-off upload was started again and published |
| Hub run with the page check | `template run hub/yougori/accept-tiny@1.0.1` | Downloaded, digest checked, Verified, the Hub page compared with the files and found the same |
| Backup, restore, retention | Backup now, check, restore into a disposable copy, restore over the original; removal without and with `--delete-data` | After the fixes all worked: the copy and the original held exactly the backed-up files; without `--delete-data` the volume and its backups were kept and the setup read retained |
| Domain failure | A run with access domain and no saved domain | Refused before anything was made, naming the command that saves a domain |
| v1 | `template run examples/hub/hello-site` with access none | After the agent fix: the site served and its pip-installed tool passed its check |
| Retained setup inspection and export | `template status` and `template export` of the retained copy | Status readable (after a fix to how kept volumes read); export written with its omissions listed |

### Defects found on the real runtime, and fixed

Each passed its mocked tests before. Each fix has a regression test unless the row says otherwise.

| Defect | Fix |
| --- | --- |
| The CLI's method catalogue lacked `consents` for `setup_apply`, so every format 2 run through the CLI was refused before reaching the engine | `cli/src/catalog.rs`; test `setup_apply_accepts_everything_the_template_commands_send` |
| A volume mounted by name was not a dependency, and `backup_through` made a volume wait for its sandbox: sandboxes were made before their volumes and a removal deleted the volume first, so it never finished | `setup/src/graph.rs` (`mounted_volumes`, `readiness_references`), `setup/src/plan.rs`; the engine reads mounts for setups recorded earlier (`service.rs` `needs`); golden fixtures regenerated; tests in `setup/tests/packages.rs` and `setups/tests.rs` |
| A stop or removal stopped under the old order failed the same way on every retry | Retry recomputes the waits (`service.rs` `teardown_waits`); lifecycle test |
| The project `down` action refused a folder, so removing a setup's last sandbox failed | `src-tauri/src/projects.rs` (runtime-verified; no unit test) |
| After a deletion agreed on removal, a setup still read retained | `ordinary.rs` sandbox removal; test assertion |
| After Yougori closed and opened, setups read running with nothing running, and `template start` did nothing | Start and stop refresh first; idle setups are refreshed after startup recovery; drift wording no longer says "outside Yougori"; lifecycle test |
| The guest file service refuses every path on a mounted volume (`RESOLVE_NO_XDEV`): `yougori cp ENV:/data`, `yougori volume cp` and every setup backup failed with "invalid cross-device link"; restores into volumes were refused the same way | Guest agent `volume_files.go`, used by `remote_files.go` and `file_import.go` only when the engine opts in for its own local transfers; teammates' shares keep the old rule; Go tests. **Ships only with a rebuilt appliance** |
| A restore copied into a folder that did not exist, and its files landed one level too deep | `backups.rs` makes the folder and uses the copied folder by name; the test fake now does what the agent does |
| Crash recovery recorded a sandbox made but never started as done | Run the step again (`ordinary.rs` recover); test updated |
| The CLI said "not submitted" when the engine went away during a change it had accepted | `setups.rs` `engine_lost`, used by both CLI follow loops; test |
| The diagnostic scrubber masked the word after a bare "token", "password" or "secret", garbling messages about secret questions | A bare key masks the next word unless it is a plain sentence word; `password = value` is now masked too, which the old rule missed (`lifecycle.rs`; tests) |
| A cancel that interrupted a step left "outcome unknown" | The runner settles a cancel-interrupted step at once (`service.rs` `run`); test updated |
| `template plan INSTANCE` sent the name as the setup id | Resolve the name and plan a change as `configure` does (`setups.rs`); test |
| A change planned without a name renamed the setup to the template's title | Keep the setup's own name (`planning.rs`); test |
| A connection to a borrowed sandbox was planned and then failed; `model_request` was silently not delivered; a setup holding such a connection could not be removed | Refused at review (`ConnectionHandler::review`); the project builder drops connections it can't deliver and rewrites the file before taking the last sandbox down; test |
| A changed cached tool was refused silently, so an offline failure said only "no saved copy" | The reason is carried on (`hub_tools.rs`, CLI `client::own`) (runtime-verified) |
| The catalogue required `source` for `setup_validate`, refusing the app builder's drafts at the wire | `source?` and `draft?` (`catalog.rs`) (runtime-verified) |
| The builder gave a private-only service an Address output, and the CLI printed unresolved outputs as values | `draft.rs` and `plan.rs`; draft test |
| Every backup asked for now was first recorded as skipped "because the previous one was still running" | The loop takes the due time when it starts the run (`schedules.rs`); test, shown to fail without the fix |
| Publishing through the engine never resumed or restarted an upload: the engine's job label hid the website's words from the resume rules | `publish.rs` `website_words`; test |
| A dry run required secret values | References for every secret question (`plan.rs`); test |
| v1 files into the working directory (`working_dir: /app` with files into `/app`) were refused, so the v1 example never ran | Guest agent takes an empty folder's place (`project_files.go`); Go test. **Ships only with a rebuilt appliance** |
| A retained setup listed its kept volume as missing | Keep the step's observation (`service.rs` `apply_receipt`); test assertion |

### Not exercised here

- The desktop app's own screens. Its engine calls (draft, plan, apply, cancel) were exercised
  through the same wire.
- Provider sign-in sessions, which need real provider accounts.
- A genuinely full or read-only disk; a denied write stood in for it.
- Serving a local model and attaching it: that needs a model download, and attachment is not
  delivered by setups (now refused at planning).
- Linux, macOS and signed builds.

### Observations at the time

All four were followed up the same day; see
[the appliance rebuild and the remaining coverage](#appliance-rebuild-and-the-remaining-coverage-27-october-2026).


- Twice, a step failed seconds after the disposable engine started, with "no such object" and
  "container is still present". Both cleared on `template continue` without anything done twice.
  The runtime may accept work before the appliance is fully ready. Not reproduced on purpose.
- The format 2 review of a Hub tool shows its identity, version, digest, Verified mark and declared
  access, but not its install lines.
- A private publication opens no address on this computer; the service is listed as a sandbox port.
- The waiting-for-an-answer error from `template continue` carries the code `operation_failed`
  rather than one of its own.

## Appliance rebuild and the remaining coverage, 27 October 2026

The plan's first section asked for the appliance to be rebuilt with the guest agent fixes; its
second, for the runtime coverage still open. Both were taken as far as this computer allows
without stopping the installed development engine (`src-tauri/target/debug/yougori.exe`, PID
49568), which runs its appliance straight from `src-tauri/resources/runtime` and was not stopped,
restarted or touched. Nothing was committed, pushed, published or installed.

### The rebuilt appliance and CUDA payload

- **Toolchain.** `YOUGORI_MUSL_TOOLCHAIN_MANIFEST` is the `native-complete.json` written by
  `scripts/vendor-oci-build/build.py --native-only`, which builds the pinned musl, libseccomp and
  btrfs from their checksummed sources. It was built in the `Yougori-Ubuntu-Build` distribution,
  whose `gcc-11`, `libc6`, `libc6-dev`, `libgcc-11-dev` and `linux-libc-dev` versions are the ones
  `build/oci-runtime/build-record.json` records. Every library, `libc.a` included, came out byte for
  byte as recorded; only the `musl-gcc` wrapper and specs differ, because they name their own folder.
  The procedure is now in `scripts/acceptance/README.md`.
- **Builds.** `scripts/build-appliance.sh` and `scripts/build-cuda.sh`, run on a copy of the working
  tree inside the distribution, each into a new folder: 41 seconds and 1 second. The mount helper
  and the CUDA probe are byte-identical to the shipped ones. The guest agent in the initramfs and
  the CUDA payload's agent are the same bytes.
- **Candidate runtime.** `C:\tmp\yougori-candidate-20261027\runtime`: the bundled runtime with the
  four appliance files and the CUDA payload's agent, mount helper, probe and checksum list replaced,
  and the changed lines of the top-level `SHA256SUMS` rewritten. All three checksum lists verify.

| File | SHA-256 |
| --- | --- |
| `appliance/appliance-base.qcow2` (179,638,272 bytes) | `4f92209019584208c8814ca2593cec797f80580fcbc22da19588c0359cd36921` |
| `appliance/vmlinuz-virt` | `17fbd3efd16f2e7cb1b945f06423b37399ba7d5ac8cdd3665e7f13f363500e85` |
| `appliance/initramfs-virt` | `2d1bd704a1a9a471e1f087d978e259d7055a2ac35cf9f922516a9930d865bed5` |
| `cuda/yougori-agent` (and the initramfs agent) | `33c593db4a0639d58932479f4d26b35b94a7ca0e06bf23883c366ec052ce9819` |
| `cuda/yougori-mount-helper` (unchanged) | `eaca353827ed1ac0eb501b9584ed279fca0a256842af14524f3e345358f68811` |
| `cuda/yougori-cuda-probe` (unchanged) | `51d314dd385f3e7e5a032fdb09276e8ba57fd8b517db1135ad4779a22a7db26d` |
| top-level `SHA256SUMS` | `d6f219a9015b585e3ed5781a934c1146967e1d3983b8501f101dbc6f3c7bcb16` |

**Package changes.** Read from each base image's APK database without booting it, 60 packages
in both. Two changed, with the same licences: `ca-certificates` 20260909-r0 → 20261020-r0 (aports
`e78f5987166c6ffbe23f6472e2e8f040298fe2da`) and `linux-virt` 6.18.55-r0 → 6.18.58-r0 (origin
`linux-lts`, aports `5fe63f789de75f6a71001cf2de771f922bedd0d2`). The recorded evidence
(`compliance/evidence/alpine-packages.json`) matches the shipped appliance; the compliance bundle
holds neither new source yet. `scripts/collect-compliance.py` reads only
`src-tauri/resources/runtime`, so the evidence for the new bytes is collected once they are
installed there (see the plan).

### The acceptance steps on the rebuilt appliance

Run on the candidate runtime through `YOUGORI_ACCEPTANCE_RUNTIME_DIR`, since the bundled one can't
be replaced under the installed engine.

| Path | What ran | Result |
| --- | --- | --- |
| A new installation (fresh data folder, final bytes) | `accept-tiny`; `cp ENV:/data`; `volume cp VOLUME:/sub`; backup now; backup check; restore into a copy; restore over the original; `examples/hub/hello-site` with access none | All passed. The copies held exactly the volume's files; the check found 2 files unchanged; the copy and the original held the backed-up files and not the later ones; the v1 site served from `/app`; the guest ran kernel 6.18.58-0-virt |
| An upgrade (the data folder made on the shipped base) | The same steps | All passed. The disk kept its archived base (`a44c81…`) and booted the new kernel and initramfs, which bring the new agent and matching modules; earlier setups' volumes were all still there |
| A sandbox made from the builder kept to this computer | `access: private` fixture, and the desktop builder (below) | Reachable at its 127.0.0.1 port; its Address output named it |
| A change cut off mid-step and carried on at once | `accept-wait` with the test engine killed while its first sandbox was made, then started and carried on straight away, three times | After the fixes below: the first sandbox was made again, the secret given to `continue` reached the second, and nothing ran twice. A container half saved by the old agent was removed and made again |

### Defects found, and fixed

| Defect | Fix |
| --- | --- |
| A format 2 review showed a tool's downloads but not the lines it runs | `plan::Review.installs` (setup crate), printed by the CLI ("Installs:") and the app ("What its tools run"), cleaned of control and invisible characters; golden plans updated; tests in the planner, CLI and app |
| A change waiting for an answer carried the code `operation_failed` | `awaiting_input` (`cli/src/wire.rs`), in the skill's code table; test |
| `template continue --secrets -` read the secret and dropped it, so the change asked again | It answers the waiting change as `configure` does; an input given to `continue` is refused; test |
| `access: private` ("Only this computer") opened nothing on this computer, and no publication reported its address | A private publication publishes the sandbox's port at 127.0.0.1 on a port fixed for the setup and publication (`ordinary::here_port`, 20000–39999); every publication reports `outputs.NAME.url`; the builder gives a private service its Address again; ADR-0002 updated; engine and draft tests; runtime-verified |
| After a hard stop, a sandbox recorded as made had no container: the next change failed with "no such object" | The project apply lets a missing container through to its start, which makes it again from its definition (`projects.rs`); runtime-verified |
| The guest reported a container made before its disk had it; a hard stop then lost it, or kept its record without its storage ("private storage path was redirected" on every later change) | The agent flushes the guest's disk before it reports a container made or reconfigured (`durable`); a container whose writable layer is missing is removed and reported as missing, so it is made again (`errIncompleteContainer`); Go tests; runtime-verified |
| A removal nerdctl reported done could still be listed for a moment ("is still present; deletion did not finish") | The agent reads the list again for up to 3 seconds; Go test |
| A container whose command fails at once read "restarting", so every change to its setup ended "outcome unknown", and the setup could not be removed | Any state with no process to attach is treated as finished, as an exited one was; its internet choice is applied when it runs again; Go test; runtime-verified |
| The Personal Vault was not isolated from disposable engines (see the incident note above) | `vault::broker`; vault setup paths under the acceptance data folder |
| Driving the app: a setup reading running with stopped parts offered Repair, which found nothing, and no Start | Start is offered while any of the setup's own parts reads stopped; lifecycle test |
| Driving the app: "Run it here" in the builder never asked the template's own questions (image, port), so planning refused the unanswered image | Validating a draft returns the questions the template it makes will ask; the builder asks them; engine test |
| Driving the app: the builder's last step did not show the new setup's address | One shared outputs view, used by the list, the detail and the builder |

The deletion race and the half-saved container are the two errors seen "seconds after an engine
start" in the first pass; both came from the hard stop of the guest, not from its start.

### The desktop app's own screens

A disposable desktop build with the acceptance feature ran on a test data folder, pipe and vault
namespace, with its own WebView2 data folder, and was driven through its WebView with Playwright
(procedure in `scripts/acceptance/README.md`). Driven: the first-launch guide; My setups; a setup's
detail, its tabs and its Address; Start from the list and the detail; Repair's review; and the
whole builder: name, capabilities, the generated template, Run it here, storage, the template's
questions, the review ("this computer only, at 127.0.0.1"), Set it up, progress and What is ready,
whose address answered. Not driven: Settings (it writes the account's sign-in startup entry), the
Hub page, and the Personal Vault.

### Still open

- Provider sign-in sessions, which need real provider accounts.
- A genuinely full or read-only disk: mounting a small disposable volume needs an administrator,
  and this session has none.
- Serving a local model; model attachment and connections to another setup's sandbox stay refused
  at planning (`ConnectionHandler::review`) until the owner decides to build them.
- Linux and macOS runtimes, and signed builds.
- Small things seen while driving the app: capability health reads "Not checked yet" after a start
  until the setup is refreshed; a private publication reads running while its sandbox is stopped;
  the review's heading for a private service is "Reachable from outside".

### Checks on the final tree, 27 October 2026

Run one after another on the final working tree (`CARGO_TARGET_DIR` of its own; nothing reached
the installed engine).

| Check | Exit | Time | Result |
| --- | --- | ---: | --- |
| `cargo test` setup crate | 0 | 24 s | 165 passed |
| `cargo test` CLI library (Swarm and bounty skipped) | 0 | 67 s | 580 passed, 1 ignored |
| `cargo test` CLI command line | 0 | 35 s | 25 passed |
| `cargo test` CLI library, `acceptance` feature, `wire::` | 0 | 21 s | 7 passed |
| `cargo check` engine library, all targets | 0 | 123 s | no warnings |
| `cargo check` headless engine, `acceptance` feature | 0 | 80 s | no warnings |
| `cargo check` headless engine, all targets | 0 | 41 s | no warnings |
| `cargo test` engine library | 0 | 158 s | 1195 passed, 90 ignored |
| Guest agent: `go vet`, `go test` (Go 1.27.2) | 0 | 29 s | passed; `gofmt` lists only `container_quota_test.go` and `restart_policy.go`, unformatted at HEAD and not touched |
| `cargo test` vault library | 0 | 20 s | 52 passed, 1 ignored |
| `vitest run --dir src` | 0 | 31 s | 134 files, 831 tests passed |
| `tsc -p tsconfig.app.json --noEmit` | 0 | 6 s | clean |
| `eslint . --max-warnings 0` | 0 | 5 s | clean |
| `node --test scripts/*.test.mjs` | 0 | 29 s | 159 passed, 5 skipped |
| Website `server/hub.test.mjs` | 0 | 2 s | 37 passed |
| `scripts/test-hub-contract.mjs` against the website checkout | 0 | 5 s | 2 passed |

The appliance, the CUDA payload and the release candidate were not built from the checkout
itself here; see the plan for what each needs.

### Installed locally, 27 October 2026

At the owner's request, with no release planned, the rebuilt appliance was installed for local
development. The development engine (PID 49568) was stopped with `yougori app quit`; the four
appliance files, the CUDA payload's agent and checksum list and the top-level `SHA256SUMS` were
copied in (all three checksum lists verify; the previous files are in
`C:\tmp\yougori-runtime-backup-20261027`); the engine (`src-tauri/target`) and the development CLI
(`cli/target`) were rebuilt, 98 s and 49 s, without warnings; and the engine was started again with
`yougori app start` (version 1.2.0, the same pipe).

- The four sandboxes of `my-api-3` that were running were started again and run on kernel
  6.18.58-0-virt. Its GPU sandbox first asked for the CUDA runtime update the new payload needs;
  `yougori gpu setup --yes --storage-drive D:\` installed it, keeping the container disks, and the
  sandbox saw its RTX 5090 again. `my-api` and `my-api-2` read incomplete, as before.
- The acceptance steps (copying out of a volume, `volume cp`, backup, check, restore into a copy and
  over the original, and the v1 example) passed on the bundled runtime with no override, on a
  disposable engine.
- The engine's state before the stop listed 19 `grid` … `grid-19` records, each a container of an
  image named `grid` that failed while provisioning and never existed in the runtime; the audit log
  shows one made through the CLI every few hours since the engine started on 26 October, the first
  as it started. They were not in the state the rebuilt engine loaded, and the audit records no
  deletion; nothing of theirs was kept anywhere. What issues those CLI calls is not known.

