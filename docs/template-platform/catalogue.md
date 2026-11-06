# Template catalogue: per-recipe completion ledger

> **Scope superseded — 26 October 2026:** The user now wants reusable tools for users to build their own templates, with unnecessary product code removed. First-party template creation/completion/publication is deferred for now, including the former 13-package release. Follow the [single active plan](../template-platform-implementation-plan.md). Recipe milestones and publication requirements below are historical, not active assignments.

Plan sections 10–15 and 15.1. Created 26 October 2026 by job J5; maintained by the coordinator from here on. One row per recipe in the complete initial catalogue: 4 grid templates, 8 supporting recipes (My API is an existing item receiving an update) and 11 additional recipes.

**26 October 2026: shrunk to templates.** The four grid templates and the five recipes that needed a grid (AI Team, Build & Test Farm, Data Pipeline, Workshop Lab, Model Evaluation) were removed. Their rows stay below, marked Removed, so the numbering other documents cite still holds. The engine parts they used (grid, pool, model, workspace and credential resource kinds and handlers) stay for any template to use.

## Status words (plan 15.1)

| Status | Meaning here | Evidence required |
| --- | --- | --- |
| Designed | Described; no package, or a package that cannot be honest yet because a capability it needs is Planned. | The named missing capability. |
| Implemented | Package source exists in `examples/hub/<slug>/` (template, project, README with inputs/outputs/known limits, changelog, licence, example answers, maintainer test spec) and passes `setup/tests/packages.rs`: format check, deterministic plan for every example answer file, and a review the website accepts. | Test run on the package. Static evidence only. |
| Validated | The package's runtime acceptance rows (its `TESTING.md` section 3) pass on an isolated supported runtime. | Recorded run per row. |
| Published | The version is on the Hub with its digest. | Hub receipt (plan 26). |
| Verified from download | The published version was downloaded into a fresh folder, its hashes checked, and its runtime acceptance repeated from the download. | Recorded run (plan 26.3). |

**No package is beyond Implemented today.** Handlers now exist for the ordinary kinds, the grid kinds, a model service on this computer and a sandbox share, so those packages plan and apply against the engine's fakes; runtime validation on a real computer (each package's `TESTING.md` section 3) has not been recorded yet. A kind with no handler is still refused at review with "Yougori can't manage … resources on this computer yet. Nothing was changed." Runtime validation starts as the remaining handlers land (M05, M08–M12).

## Summary

| # | Slug | Title | Wave | Status | Platforms | Handler kinds needed |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | `sandbox-grid` | Sandbox Grid | Grid | Removed (26 October 2026); kept as a test package | Windows x64, Linux x64 | grid, compute_pool, workspace_pool, access_binding |
| 2 | `neo-grid` | Neo Grid | Grid | Removed (26 October 2026); kept as a test package | Windows x64, Linux x64 | grid, compute_pool, model_service |
| 3 | `access-grid` | Access Grid | Grid | Removed (26 October 2026); kept as a test package | Windows x64, Linux x64 | grid, access_binding, credential_broker |
| 4 | `swarm-mining-grid` | Swarm Mining Grid | Grid | Removed (26 October 2026); kept as a test package | Windows x64, Linux x64 | grid, compute_pool, worker_group, model_service, environment, artifact_store |
| 5 | `ai-workspace` | AI Workspace | Supporting | Implemented | Windows x64, Linux x64 | environment (+ tool installer) |
| 6 | `ai-team` | AI Team | Supporting | Removed (26 October 2026): needed a grid | Windows x64, Linux x64 | model_service (team), resource bindings |
| 7 | `model-server` | Model Server | Supporting | Implemented; handler landed (model service on this computer, `setups::local_models`) | Windows x64, Linux x64 | model_service |
| 8 | `host-my-app` | Host My App | Supporting | Implemented | Windows x64, Linux x64 | environment, service_publication |
| 9 | `shared-workspace` | Shared Workspace | Supporting | Implemented; handler landed (sandbox share, `setups::share`) | Windows x64, Linux x64 | access_binding (share), resource bindings |
| 10 | `gpu-lab` | GPU Lab | Supporting | Implemented | Windows x64 (NVIDIA) | environment (gpu), service_publication |
| 11 | `inference-endpoint` | Inference Endpoint | Supporting | Implemented | Windows x64 (NVIDIA) | environment (gpu), service_publication |
| 12 | `my-api` | My API | Supporting (update) | Implemented as `2.0.0` (format 2); v1 `1.6.0` stays Published and unchanged | Windows x64, Linux x64 | environment (+ tool installer), connection, service_publication |
| 13 | `dev-workspace` | Dev Workspace | Additional | Implemented | Windows x64, Linux x64 | environment (+ folder bindings and folder sync) |
| 14 | `build-test-farm` | Build & Test Farm | Additional | Removed (26 October 2026): needed a grid | Windows x64, Linux x64 | grid, compute_pool, job, artifact_store |
| 15 | `data-pipeline` | Data Pipeline | Additional | Removed (26 October 2026): needed a grid | Windows x64, Linux x64 | grid, compute_pool, job (three stages in order), artifact_store |
| 16 | `workshop-lab` | Workshop Lab | Additional | Removed (26 October 2026): needed a grid | Windows x64, Linux x64 | grid, compute_pool, workspace_pool, access_binding (reset) |
| 17 | `model-evaluation` | Model Evaluation | Additional | Removed (26 October 2026): needed a grid | Windows x64, Linux x64 | grid, compute_pool, job (dataset + evaluation), artifact_store |
| 18 | `model-collection` | Model Collection | Additional | Implemented; handler landed (model service on this computer, `setups::local_models`) | Windows x64, Linux x64 | model_service |
| 19 | `app-backend` | App Backend | Additional | Implemented | Windows x64, Linux x64 | environment, connection, service_publication |
| 20 | `agent-tools` | Agent Tools | Additional | Implemented for tools, folders and generated instructions; credential binding refused (see below) | Windows x64, Linux x64 | environment (+ tool installer, bundled tool), folder bindings |
| 21 | `operations-dashboard` | Operations Dashboard | Additional | Implemented | Windows x64, Linux x64 | environment, volume |
| 22 | `backup-workflow` | Backup Workflow | Additional | Implemented | Windows x64, Linux x64 | environment, volume (+ schedule and backup), service_publication |
| 23 | `customer-workspaces` | Customer Workspaces | Additional | Designed | — | provisioning API + wake/sleep |

Counts (from the table above, 23 rows): 13 Implemented packages, including My API at `2.0.0`; 9 Removed on 26 October 2026 (rows 1–4, 6 and 14–17); 1 Designed (row 23, Customer Workspaces, which is unfinished programme work rather than a package waiting to be written — see its row); 0 not started. My API's v1 `1.6.0` stays published and unchanged. 0 Validated, 0 Published as v2, 0 Verified from download.

Evidence for every Implemented row: `cargo test --locked --manifest-path setup/Cargo.toml --test packages` passes for the package (run 26 October 2026 on copies of the packages, and in place by job J1, which writes the golden plans and reviews under `setup/tests/fixtures/`). The same test still checks, plans and reviews the four former grid packages, now test packages in `setup/tests/fixtures/packages/`, Swarm Mining Grid included since 27 October 2026: `the_research_package_reviews_only_what_it_was_given_offline_and_as_authorised` asserts what only research promises (no live target, an offline sandbox, the authorisation sent as written, the folder the person chose).

---

## Grid templates

All four were removed on 26 October 2026 and are kept only as test packages for the engine's parts (`setup/tests/fixtures/packages/`). Their earlier details are in the [parity ledger](parity-ledger.md).

### 1. Sandbox Grid (`sandbox-grid`)

Removed on 26 October 2026, when Yougori shrank to templates: a branded grid product is not shipped or published. The engine parts it used stay, so a template can still build one, and the package is kept as a test package for those parts in `setup/tests/fixtures/packages/sandbox-grid/`, never published. Its earlier details are in the [parity ledger](parity-ledger.md).

### 2. Neo Grid (`neo-grid`)

Removed on 26 October 2026, when Yougori shrank to templates: a branded grid product is not shipped or published. The engine parts it used stay, so a template can still build one, and the package is kept as a test package for those parts in `setup/tests/fixtures/packages/neo-grid/`, never published. Its earlier details are in the [parity ledger](parity-ledger.md).

### 3. Access Grid (`access-grid`)

Removed on 26 October 2026, when Yougori shrank to templates: a branded grid product is not shipped or published. The engine parts it used stay, so a template can still build one, and the package is kept as a test package for those parts in `setup/tests/fixtures/packages/access-grid/`, never published. Its earlier details are in the [parity ledger](parity-ledger.md).

### 4. Swarm Mining Grid (`swarm-mining-grid`)

Removed on 26 October 2026, when Yougori shrank to templates: a branded grid product is not shipped or published. The engine parts it used stay, so a template can still build one, and the package is kept as a test package for those parts in `setup/tests/fixtures/packages/swarm-mining-grid/`, never published. Its earlier details are in the [parity ledger](parity-ledger.md).

---

## Supporting recipes

### 5. AI Workspace (`ai-workspace`)

- **Capabilities:** tools.builtin, tools.provider_access, data.volumes, run.health_logs (optional).
- **Owned:** one container sandbox (pinned Ubuntu 24.04) with a `/workspace` volume and the picked built-in tools. **Borrowed:** none.
- **Questions:** tools (codex, claude, gemini, opencode, kilo, ollama, openclaw); per tool with sign-in support: access (subscription, api, both), sign-in source (copy this computer's file, or fresh), API key; cores, memory, disk.
- **Outputs:** sandbox name.
- **Lifecycle:** stop keeps everything; unpicked tools stay installed; remove keeps the `/workspace` volume.
- **Permissions:** sign-in files copied only after the person chooses it, and never in scripted runs; API keys reach the sandbox as environment variables.
- **Tested scenarios:** package, plan and review tests; runtime AW-R01–R08 pending.
- **Known limits:** container only (API keys cannot go to a MicroVM); no host folders; no bundled custom tool; Ollama on the processor; sharing gives teammates control of the whole sandbox.

### 6. AI Team (`ai-team`)

Removed on 26 October 2026, when Yougori shrank to templates: it needed a grid, and the grid templates are no longer shipped. The engine parts it used stay.

### 7. Model Server (`model-server`)

- **Handler landed (J23).** `setups::local_models` runs a model service on this computer through the model runner (`run_model`), stamped with the setup that made it (`YOUGORI_SETUP_STAMP`). Create, observe, stop, start, remove and health work against the runner; a crash mid-create is settled by the stamp without a second model. Runtime acceptance (MS-R01-R08) still pending on a real computer.
- **Capabilities:** models.local, web.service, web.private, run.service, run.health_logs (optional).
- **Owned:** one model service on this computer.
- **Questions:** model, quantization, GPU use, memory.
- **Outputs:** model, local API address.
- **Lifecycle:** remove deletes the model sandbox and its downloaded files.
- **Permissions:** API on 127.0.0.1 only; key in the credential store, shown by `yougori model access`.
- **Tested scenarios:** package, plan and review tests; runtime MS-R01–R08 pending.
- **Known limits:** several generations together on GGUF and vLLM runners (one on Transformers), with up to 128 waiting callers on updated runners (429 when full, 504 after five minutes waiting); `max_tokens` up to 4096; key not rotatable; local only; rented GPUs through `model run --neocloud`; GPU on Windows x64 only.

### 8. Host My App (`host-my-app`)

- **Capabilities:** web.service, web.health (optional), web.private, web.quick_link, web.domain, data.volumes, run.service, run.health_logs (optional).
- **Owned:** app container with a `/data` volume; its publication.
- **Questions:** image, health path, cores, memory, disk, optional `APP_SECRET`, access, domain.
- **Outputs:** app address, sandbox name.
- **Lifecycle:** a new image replaces the container and keeps `/data`; remove keeps the volume.
- **Permissions:** private by default; public only by choice.
- **Tested scenarios:** package, plan and review tests; runtime HA-R01–R08 pending.
- **Known limits:** image only (no build from a source folder); one container; port 8080 inside the container; one secret; no automatic rollback.

### 9. Shared Workspace (`shared-workspace`)

- **Share handler landed (J23).** `setups::share` makes, revokes and reports one sandbox shared with one person through the remote gateway, stamped with the setup that made it. It shares a sandbox this setup makes or borrows; the borrowed sandbox is never started, stopped or removed, and removing the share revokes it so sessions close at once.
- The sandbox the person picks from their own setups arrives as a borrowed resource (the planner's resource-binding resolution), so the engine attaches it, keeps its owning setup from being removed while it is shared, and never creates or changes it. Runtime acceptance (SW-R01-R07) still pending.
- **Capabilities:** people.team, people.invites (optional), data.folders (optional), web.service, web.quick_link, web.domain.
- **Owned:** one person's share. **Borrowed (resource binding):** the sandbox shared.
- **Questions:** username, name, password, permission (view, edit, control), folder, hours, access, domain.
- **Outputs:** share link (private), share page.
- **Lifecycle:** remove or revoke closes the person's sessions at once; the sandbox keeps running.
- **Permissions:** view and edit confined to one folder; control gives terminal, apps and power.
- **Tested scenarios:** package, plan and review tests; runtime SW-R01–R07 pending.
- **Known limits:** one person per setup; expiry not changeable; one gateway for all shares; 12-hour sessions, 15-minute idle; 128 people.

### 10. GPU Lab (`gpu-lab`)

- **Capabilities:** web.service, web.health (optional), web.private, web.quick_link, web.domain, data.volumes, run.service, run.health_logs (optional).
- **Owned:** GPU sandbox (PyTorch 2.8 CUDA 12.8 image plus JupyterLab 4.2.5) with a `/workspace` volume; its publication.
- **Questions:** token, cores, memory, disk, access, domain.
- **Outputs:** notebook address, sandbox name.
- **Lifecycle:** stop frees the GPU and keeps `/workspace`; remove keeps the volume.
- **Permissions:** token required; private by default.
- **Tested scenarios:** package, plan and review tests; runtime GL-R01–R06 pending.
- **Known limits:** NVIDIA on Windows x64 only; local only (rented labs are NeoCloud pods); no spending budget (local GPU unbilled); one shared user.

### 11. Inference Endpoint (`inference-endpoint`)

- **Capabilities:** web.service, web.health (optional), web.private, web.quick_link, web.domain, data.volumes, run.service, run.health_logs (optional).
- **Owned:** GPU sandbox with the pinned vLLM 0.29.0 image and a `/models` volume; its publication.
- **Questions:** model, API key, Hugging Face token, context length, concurrency, cores, memory, disk, access, domain.
- **Outputs:** endpoint address, sandbox name.
- **Lifecycle:** changes restart vLLM and keep `/models`; remove keeps the volume.
- **Permissions:** `/v1` requires the key; private by default.
- **Tested scenarios:** package, plan and review tests; runtime IE-R01–R07 pending.
- **Known limits:** NVIDIA on Windows x64 only; safetensors architectures vLLM supports; one key; serverless endpoints stay in NeoCloud.

### 12. My API (`my-api`)

- **Status:** `2.0.0` (format 2) Implemented (J18). The Hub's `1.6.0` (format 1) stays published and unchanged; its instances keep running pinned to it.
- **Capabilities:** web.service, web.health (optional), web.quick_link, web.domain, data.volumes, data.private_connections, tools.builtin, tools.provider_access, run.service, run.health_logs (optional).
- **Owned:** the `web` sandbox with the `my-api-data` volume and its publication; optional components created only for chosen providers: `paid` (Codex, Anthropic API, Gemini), `local` (Ollama, GPU optional, `my-api-models` volume) and `free` (OpenCode, Kilo), each with a one-way connection from `web`. **Borrowed:** none.
- **Questions:** admin account (create or keep), admin email and password, providers, per-provider access, sign-in source and API keys, gateway scope, bridge secret, site name, access, domain. Wallet and network are chosen on the website after admin sign-in.
- **Outputs:** website address, selected providers.
- **Lifecycle:** stop and remove keep both volumes. A newer website copies the database to `/data/backups` and checks it before upgrading the layout, and refuses to start if it can't.
- **Permissions:** only `web` is published; provider credentials stay in their sandbox; host sign-ins copied only on the person's choice.
- **Plan 14.3 regression requirements:** admin made in setup, kept on update, never by signup; wallet after sign-in; checksum-checked addresses and an optional admin-entered USDT token; manual confirmation with transaction ids, reject, cancel and a cap on open requests; per-user credits and per-model keys and prices; subscription, API or both per adapter; free-only catalogue freshness with visible reasons and per-model timestamps; sign-in failures and throttling update availability without leaking credentials; Admin navigation and fixes. Offline tests cover each.
- **Tested scenarios:** package, plan (three answer files) and review tests; `test_service.py`, `test_prices.py`, `test_tool_models.py`, `models-ui.cjs`, `theme-ui.cjs`; runtime MA-R01–R13 pending.
- **Known limits:** no in-place update from `1.6.0` (the engine has no adoption step for v1 instances; README gives the manual path); selling a model started with `yougori run --template` works for `1.6.0` instances only, because setups don't deliver connections to another setup's model or `model_request`.

---

## Additional recipes

### 13. Dev Workspace (`dev-workspace`) — Implemented

- **Capabilities:** grid.local_only, data.sync, data.folders, data.volumes, tools.builtin (default), web.service (optional), web.quick_link (optional), run.service.
- **Owned:** the `dev` sandbox with the person's project folder synced to `/workspace`, its `storage` volume at `/root`, and its publication when a quick link is chosen. **Borrowed:** none.
- **Questions:** image, coding tools, cores, memory, disk, access. Two folder bindings: `project` (writable, mode sync) and `reference` (optional, read only, mode mount).
- **Outputs:** the project's place in the sandbox, the sandbox name, the app address when published.
- **Lifecycle:** stop stops the sandbox and the syncing, keeping both copies; start syncs once and then keeps syncing; remove deletes the sandbox and its volume and never touches the person's folder.
- **Permissions:** exactly the two folders chosen, with the access each binding declares. The writable one needs an explicit `write_folder:` agreement when the setup is applied, and the step is refused without it. Tools sign in inside the sandbox; no sign-in is copied from this computer.
- **Format support (ADR-0001 section 16):** `pc_access[].binding` and the new `sync:` list; `read_only` and `mode` on a folder binding; the folder is filled in at plan time only and never by an answer.
- **Tested scenarios:** package, plan (two answer files) and review tests; `setup/tests/folder_bindings.rs` (13); the engine's folder sync in `src-tauri/src/setups/folder_sync.rs` (11, including both-sides edits and a kept conflict over real files against a fake sandbox); runtime DW-R01–R14 pending.
- **Known limits:** one sandbox per synced folder; conflicts are resolved by hand (both whole versions kept, no merge); files are copied whole; SQLite databases inside the folder are copied as ordinary files, unlike `yougori launch`'s row-level snapshots; `.env` files sync like any other file (no separate question yet); port 3000 only; one reference folder.

### 14. Build & Test Farm (`build-test-farm`) — Removed

Removed on 26 October 2026, when Yougori shrank to templates: it needed a grid, and the grid templates are no longer shipped. The engine parts it used stay.

### 15. Data Pipeline (`data-pipeline`) — Removed

Removed on 26 October 2026, when Yougori shrank to templates: it needed a grid, and the grid templates are no longer shipped. The engine parts it used stay.

### 16. Workshop Lab (`workshop-lab`) — Removed

Removed on 26 October 2026, when Yougori shrank to templates: it needed a grid, and the grid templates are no longer shipped. The engine parts it used stay.

### 17. Model Evaluation (`model-evaluation`) — Removed

Removed on 26 October 2026, when Yougori shrank to templates: it needed a grid, and the grid templates are no longer shipped. The engine parts it used stay.

### 18. Model Collection (`model-collection`) — Implemented

- **Handler landed (J23).** As Model Server: each model is its own model sandbox on this computer, with its own stamp, API and key. Runtime acceptance (MC-R01-R05) still pending.
- **Capabilities:** models.local, web.service, web.private, run.service, run.health_logs (optional).
- **Owned:** two or three model services on this computer.
- **Questions:** first and second model with sizes, optional third, GPU use, memory per model.
- **Outputs:** each model's local API address.
- **Lifecycle:** remove deletes the model sandboxes and their files.
- **Permissions:** each model's API on 127.0.0.1 with its own key.
- **Tested scenarios:** package, plan and review tests; runtime MC-R01–R05 pending (the switching proof is MC-R01).
- **Known limits:** pinning and idle times set after setup; one address per model; GPU on Windows x64 only.

### 19. App Backend (`app-backend`) — Implemented

- **Capabilities:** web.service, web.health (optional), web.private, web.quick_link, web.domain, data.databases, data.volumes, data.private_connections, run.service, run.health_logs (optional).
- **Owned:** app container, PostgreSQL 16.4, optional Redis 7.4.1, three volumes, one-way connections, publication.
- **Questions:** image, health path, app cores and memory, database password, database disk, Redis, access, domain.
- **Outputs:** app address, app and database sandbox names.
- **Lifecycle:** volumes kept on image updates, on turning Redis off and on remove.
- **Permissions:** database and cache reachable only from the app.
- **Tested scenarios:** package, plan and review tests; runtime AB-R01–R07 pending.
- **Known limits:** no backups; no automatic migrations or rollback; PostgreSQL and Redis only.

### 20. Agent Tools (`agent-tools`) — Implemented, without the credential binding

- **What the package does (J24).** A coding agent in its own sandbox with the chosen built-in
  tools, a synced project folder and an optional read-only reading folder, and `AGENTS.md`
  generated at every start from the grants the setup really has: the tools actually on the path,
  the folders actually mounted or synced, and the real network state. A grant taken away
  disappears from the file at the next start. Undeclared tools and actions are denied
  structurally, not by instruction: the tool is not installed, the folder is not mounted, the
  network is not there. It also carries its own bundled tool (`tools/repo-map`), the supported
  form of a custom tool, since a Hub-published tool is still refused at review.
- **The credential binding was refused, not forgotten (coordinator, J24).** It would need two new
  pieces of attack surface on the two things the Access Grid exists to protect, in an autonomous
  session with no second reviewer: it waits for the owner.
- **The design, so the decision can be made with the analysis done:**
  - The hub already has the right call. `POST /access/v1/use` (`grid/src/access/hub.rs` route
    table, `grid/src/access/hub/requests.rs`) applies the rules, destinations, hourly limits and
    approvals and forwards the request with the credential injected, so the value never reaches
    the caller. Nothing about that needs changing.
  - What is missing is the caller's identity. `shared.caller(bearer)` resolves a bearer token to a
    person's sign-in session, and the only ways to get one are `/signin`, `/resume` and `/sso`.
    A scoped, non-person session is needed: minted for one sandbox, carrying its own identity for
    `policy::Who`, limited to the destinations the setup declared, expiring with the setup, and
    written into the activity log as that sandbox rather than as a person.
  - A sandbox also cannot reach the hub's listener. The engine is the signed-in computer, so the
    second piece is a host-side relay the sandbox reaches on a loopback or connection address,
    which attaches that session; the sandbox holds only an opaque session token. The SG-006 relay
    (`grid/src/relay.rs`) is the Sandbox Grid's TCP desk relay and is not reusable for this.
  - **Not an option:** a binding that copies a credential value into a sandbox. That is the exact
    thing the Access Grid prevents, and it must not be built as a shortcut to this row.
- **Next step:** the owner decides the scoped session and the relay above, with a reviewer. Until
  then the package's Known limits say plainly that scoped credentials cannot reach a sandbox and
  why, and the agent is told it has none.

### 21. Operations Dashboard (`operations-dashboard`) — Implemented

- **Capabilities:** run.service, data.volumes. No web capability and no notification capability: the board is not published and nothing is sent anywhere.
- **Owned:** the `readings` volume and the `board` sandbox (pinned `python:3.13-alpine`, no internet) that serves that folder on a port of this computer. **Borrowed:** none.
- **Questions:** how many readings to keep, the port the board answers on, memory for the board.
- **Outputs:** board sandbox, readings volume.
- **Lifecycle:** stop stops the board; remove keeps both the volume and the readings taken, which are deleted separately.
- **Engine (the capability this row was waiting for):** `setup_telemetry` (`src-tauri/src/setups/telemetry.rs`), a scoped, redacted, read-only reading across setups with bounded retention, reached from the terminal as `yougori setup telemetry`. It replaces nothing: `src-tauri/src/grid_observe.rs` still reads only Grid Core realms, and this does not touch it ([reconciliation R15](reconciliation-ledger.md) stands for that endpoint).
  - **Scoped.** The setups read are exactly the ones `setup_list` returns, and a named setup goes through `setup_get` first, so a setup a caller may not read is refused in the same words. There is no administrator view and no mode that widens what a caller can already see.
  - **Redacted at the source, with nothing to turn off.** Health, states, counts, durations and resource ids only. No setup or template name, question or answer; no secret, credential name or token; no address, link, domain or port; no filesystem path, folder, image or account name; no log line and no refusal sentence — a failed operation carries its code alone. Every id is passed through a last gate that replaces anything which is not a short plain id with `(hidden)`.
  - **Bounded, and the bound is in the answer.** At most 50 setups a page (20 by default) with a cursor for the next; operations finished more than 30 days ago are not counted, and at most 50 per setup.
  - **Nothing is sent anywhere.** The reading is worked out when it is asked for and nothing is stored for it. There is no notification, no destination and no schedule; this recipe does not declare `run.notifications`, so no setup made from it tells anyone anything.
- **Desktop door:** `setup_telemetry` in `src-tauri/src/setups/commands.rs`, written but not yet listed in the Tauri invoke handler (`src-tauri/src/lib.rs`), which is another job's file. The CLI door is complete.
- **Permissions:** no new ones. The board has no internet and no publication.
- **Tested scenarios:** package, plan (two answer files) and review tests; engine tests for the redaction (planted name, path, email, secret binding, address, image and runtime name, none of which reach the reading), the code-not-sentence rule, the 30-day window and the page bound; CLI tests for the views and the usage text. Runtime OD-R01–R12 pending.
- **Known limits:** the board cannot take its own readings — it is a file server with no internet and no access to the engine, so a person runs the command and copies the file in; it is a folder of JSON, not charts, trends or alerting; no per-setup CPU, memory, disk or network figures, because the engine does not observe them; health is only as fresh as the last observation; a removed setup disappears from later readings; container sandboxes only; this is not an audit log.

### 22. Backup Workflow (`backup-workflow`) — Implemented

- **Capabilities:** run.service, data.volumes, run.backups, run.schedule, web.service, web.private, web.quick_link (optional), web.domain (optional), run.health_logs (optional).
- **Owned:** the `app` sandbox with the `app-data` volume, a small `backup` sandbox (pinned Alpine 3.21, no internet) that mounts the same volume and is what Yougori reads and restores through, and the app's publication when one is asked for. **Borrowed:** none.
- **Questions:** image, data path, cores, memory; schedule, time zone, backups to keep, consistency (stop or live), missed-run policy, overlap policy, retries; access, domain, health path.
- **Outputs:** app sandbox, backup sandbox, app address (with a public address).
- **Lifecycle:** stop pauses the schedule and keeps its place; start resumes; remove drops the schedule and keeps both the volume and every backup already taken, which are deleted separately.
- **Format additions (ADR-0001 section 17):** `backup_schedule`, `backup_timezone`, `backup_keep`, `backup_consistency`, `backup_missed`, `backup_overlap`, `backup_retries` and `backup_through` on a `volume`.
- **Engine:** a durable scheduler in the setup registry (`src-tauri/src/setups/schedules.rs`, schema 2) that runs in UTC with a named zone, follows RFC 5545 for the nights the clocks change, and applies the missed-run, overlap and retry policies; the copy and the restore in `src-tauri/src/setups/backups.rs`.
- **Permissions:** no new ones. Backups are kept in Yougori's own data folder; a template never names where they go.
- **Tested scenarios:** package, plan (two answer files) and review tests; 20 engine tests covering the policies, the daylight-saving nights, a restore drill (back up, change, restore, compare) and a tampered backup being refused. Runtime BW-R01–R17 pending.
- **Known limits:** one volume per setup; backups kept on this computer only, with no copy elsewhere, no cloud destination and no encryption at rest, so this is not cross-device disaster recovery and the README says so; container sandboxes only; at most 200,000 files and 200 GB per backup; values in the credential store are never in a backup; the schedule runs only while Yougori runs; the named time zones carry the rules in force when the build was made; no notification when a backup fails.

### 23. Customer Workspaces (`customer-workspaces`) — Designed

- **Missing capability:** a per-customer sandbox lifecycle, an authenticated provisioning API, per-customer accounts, limits, deletion and durable wake and sleep. No claim that this exists today. The Retrigger plan that described them was removed on 26 October 2026: nothing of it was built and nothing referred to it.
- **Reported as unfinished programme work (plan 27.2), not silently omitted.** There is no plan for the lifecycle it needs any more, so this recipe is not deliverable in this wave.
- **Next concrete action:** none until someone decides to plan a per-customer sandbox lifecycle again.

---

## Change log

- 26 October 2026 (shrunk to templates): the four grid templates and the five recipes that needed a grid removed from the catalogue and from `examples/hub`; the grid packages kept as test packages in `setup/tests/fixtures/packages/`; the Retrigger plan removed, so Customer Workspaces has no plan behind it.

- 26 October 2026 (the operations reading): Operations Dashboard Implemented. `setup_telemetry` gives a scoped, redacted, read-only reading across setups with a 30-day window and a 50-setup page, reached as `yougori setup telemetry`; the package is a private board with no internet, no publication and no notifications. Backups gained their doors in the same job: `yougori setup backups`, `… check` and `… restore`, where a restore describes what it would replace and does nothing until it is confirmed.

- 26 October 2026: created (J5). 12 packages Implemented; 9 Designed with missing capabilities named; Swarm Mining Grid not started; My API v2 Designed.
- 26 October 2026 (J18 and the final capability list): My API `2.0.0` Implemented. Every package's capability line follows its template; Planned capabilities are optional and marked. AI Team, Model Server, Shared Workspace and Model Collection carry the runtime gate "needs handler" with what works today.
- 26 October 2026 (folder bindings): Dev Workspace Implemented. An environment reaches a folder the person chooses, mounted or synced, through a folder binding (ADR-0001 section 16); `data.folders` and `data.sync` are Shipped. Agent Tools still lacks only the credential binding.
