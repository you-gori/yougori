# ADR 0002: the engine owns setups

Status: accepted, 26 October 2026 (job J3). Implements milestone M03 of
[the template platform plan](../template-platform-implementation-plan.md), sections 4, 6.1, 6.3–6.5, 8, 19.1–19.2 and 21.4.
Code: `src-tauri/src/setups/`. Shared messages: `setup/src/dto.rs` (job J2).

## The decision

One engine-owned service is the only writer of setup state. The desktop and the CLI read it and
request changes through the same calls, so they never run separate state machines (invariants 2
and 3). The service keeps a versioned registry file, an operation journal inside it, a table of
resource handlers by resource kind, and read-only adopted records for the grids that predate
setups. Nothing in it starts automatically after a restart.

## Ownership

- A setup is identified by `setup-<uuid>`, which the engine reserves when it reviews the plan
  for a new setup. `dto::PlanResponse.setupId` carries it, and the client sends it back in
  `ApplyRequest`. So applying the same create plan twice can't make a second setup
  (`setup_exists`). A resource is identified by its logical ID inside that setup. An operation is
  identified by the ID the client chose for the request. Names and template titles never
  authorise anything (invariant 1).
- Each resource record names its owner. `owner: None` means this setup owns it. A resource with
  an owner is a binding to another setup's resource:
  - Borrowing never calls a handler and never creates anything. An `Action::Attach` step copies
    the owner's runtime ID into the borrowing record and lists the borrower on the owner's record.
  - Stopping the borrowing setup skips the binding. Removing the borrowing setup only detaches it
    (`Action::Detach`, again with no handler).
  - Removing an owner that has borrowers is refused with `resource_in_use` (invariant 6, L09,
    L10). This is checked three times: at review, when the removal is claimed, and right before
    the removal step acts.
  - A new borrower moves the owner's revision on, so a removal reviewed earlier is refused with
    `revision_conflict`.
  - Borrowing from a setup that is in the middle of a change is refused with `owner_busy`.
- Removing a declaration from a template never deletes the resource. Review notes that it is
  kept, with its data (plan 8.1).

## State layout

`<engine data folder>/setups/registry.json` is one JSON document:

| Field | Holds |
| --- | --- |
| `schema` | The stored shape's version, currently 1. |
| `revision` | Moves on with every saved change. |
| `instances` | Per setup: source (pinned `SourceRef` and package digest), format and protocol versions, lock digest, configuration revision, setup revision, public answers, capabilities, realms, storage placement, safe outputs, current operation, lifecycle, health, upgrade history and resources. |
| `operations` | The journal (below). |
| `tombstones` | `setup` and `setup/resource` keys of everything removed, with the generation and the operation that removed it. |

A resource record holds its logical and runtime IDs, kind (`yougori_setup::resource::Kind`),
owner and borrowers, generation, desired and observed state, retained data, cost status, last
observation, drift, and the reference-only specification it was last applied with.

Writes go to a temporary file in the same folder, are flushed to disk and are renamed into
place. On Unix the folder is flushed too. On Windows the rename is retried for a moment if a
scanner or sync tool holds the old file. A failed save says why: the disk is full, another
program is using the file, permissions, or the drive. When the file reaches its size limit,
finished operations are trimmed to their last events, and then to the newest few per setup, so
the change that frees space can still be saved. Tombstones are never trimmed. A file that is damaged, not a regular file, too large, or from a newer schema is refused:
the service reports `registry_unreadable` or `registry_from_newer_version` and never writes over
it. Unknown fields are refused too, so an older engine can't rewrite a newer file and drop what
it doesn't know. Any change to the stored shape bumps `schema`.

The registry never holds a credential value.

- Plans and answers that carry what looks like a credential value (a `password`, `token`,
  `secret` or `api_key` field with a plain string) are refused with `secret_in_plan`, so only
  references reach the file.
- A `secrets` map, and `{{secrets.ID}}` placeholders, hold binding names, so they are allowed.
- A client's `apply:FIELD` reference reaches the planner as the binding name `apply.FIELD`.
  `StepContext::secret` resolves it to the value given with `setup_apply` under `FIELD`.
- Secret values given to `setup_apply` are kept in memory for that operation only. A continue
  merges new values with earlier ones, and they are dropped as soon as the operation finishes,
  however it ends.
- After a restart, a handler that needs a secret reports `needs_input` and the operation waits in
  `awaiting_input` (invariant 7). Applying again with the same operation ID and digest continues
  it, with no reviewed plan needed in memory, and so does `retry`.

Realm data stays in each realm's own store.

## The journal

An operation records:

- its kind (create, update, start, stop, remove or repair)
- the reviewed plan's digest
- the setup revision it was reviewed against and the revision it holds
- its state, ordered steps, cancel request, error and events.

Operation states are those of plan 8.2: planned, awaiting input, applying, cancelling, completed,
failed and unknown. Internally a cancellation finishes as `cancelled`. In the shared messages it
is `failed` with code `operation_cancelled` and `retryable: true`, because `dto::OperationState`
has no cancelled state.

Each step carries an idempotency key scoped to operation, resource and action
(`<operation>/<resource>/<action>`). Handlers put it on what they create, so an effect whose
receipt was lost can be found again.

For each step:

1. Its intent (`applying`, attempt number) is saved before the handler is called.
2. The handler acts.
3. The receipt and the resource's ownership record are saved together in the next commit.

A commit changes a copy of the registry, saves it, and only then publishes it as the readers'
snapshot, so a failed save leaves memory and disk as they were (L04). Readers never wait for a
save. Writers are serialised, and on the async runtime they hand their worker's other tasks
away while they wait for the disk. If the receipt can't be saved after an
effect, the operation shows as unknown in this engine while the disk keeps the intent, and the
next start reconciles it (L03). If a save fails before the next effect, the operation stops as
failed and retryable, and nothing more is done.

Events are bounded to 200 per operation and carry a sequence number. A reader passes a cursor
and receives the events from it, the next cursor, and `truncated: true` when older events were
dropped. A cursor ahead of the operation is refused (L05, L20).

The journal keeps at most 32 finished operations per setup and 512 in total. An operation that
holds a setup, or whose outcome is unknown, is never dropped.

## Concurrency

A setup is claimed by its `current_operation` and its revision, both on disk, so the claim holds
across restarts. Only one engine process ever writes the registry: the engine's single-instance
lock (`instance_lock.rs`) is what keeps a second process away. The desktop and the CLI are
clients of that one engine. Applying a plan:

- with an operation ID that already exists for the same setup and digest joins that operation,
  even when it has finished, so a replay never runs twice
- with the same digest as the operation that is running joins it
- with a different change while the setup is claimed gets `setup_busy`, naming the operation
- reviewed against an older revision gets `revision_conflict`

Inside one engine, checks and claims run under one registry lock (L02).

## Handlers

`ResourceHandler` has:

- `validate` and `plan`, which change nothing
- `observe`, which finds a resource by runtime ID, or by the creating step's label before a
  receipt exists
- `apply` (create, update, start), `health`, `stop` and `remove`
- `detach`, kept for handlers that will issue scoped access for a binding. The engine doesn't
  call it yet, because attaching creates nothing.
- `recover`, which by default reads an observation according to the step's action
- `review`, which checks a declared resource against the rest of its setup before anything runs
  (a credential broker needs an Access Grid this setup makes, say), so a refusal comes at review
  rather than half-way through applying
- `notes` and `change_notes`, plain lines for the review: what removing a grid deletes and when,
  a sign-in left for the person, a sandbox made again from a new image
- `forget_setup`, called once a setup's removal completes, for what a handler keeps outside its
  resources (vault entries)

A handler that doesn't support an operation returns `unsupported_operation`, with no placeholder
success. A kind with no handler is refused at review with `unsupported_resource` (invariant 13).

A panicking handler is treated as an unknown outcome. Outcomes are:

| Outcome | Meaning |
| --- | --- |
| not started | Safe to run again. |
| failed | The handler is sure nothing it didn't report was left behind. |
| unknown | Reconcile before doing anything else. |
| unsupported | This handler can't do it here. |
| needs input | Wait for an answer or secret. |

`handler::fake::FakeHandler` exists for tests only. A kind with no registered handler is refused
plainly.

### Ordinary resources (`setups::ordinary`)

Environments (sandboxes), volumes, service publications and connections are realised by the same
project engine that `yougori template run` ends in: `projects::run_project_action`. That engine
already handles:
- making each sandbox once, under its ownership name
- files and `setup`
- name resolution between sandboxes
- ports, quick links and domains
- connections
- readiness probes
- cancellation

How a setup uses it:
- Each setup has one engine-owned project, `<setups>/projects/<setup-id>/yougori.yaml`, named
  `setup-<first 8 of id>`.
- A step puts its own resource into that project, built from the setup's recorded resources
  (`StepContext.peers`), and lets the project converge. Stable identities make a repeated or
  interrupted step safe.
- The setup's cancellation reaches the project through the operation context.

Sandboxes:
- `observe` and `recover` find a sandbox only by the project engine's ownership stamp
  (`Yougori project <sha256 of the canonical yougori.yaml> / <resource>`), with its ID once
  recorded. A lost receipt is adopted, not recreated; a sandbox that merely has the same name is
  never taken, and the project refuses to use it.
- If the project fails after making a sandbox, the outcome is unknown and settled by looking. If
  nothing was made, the step fails and is retryable.
- Stop and start of a sandbox use `set_environment_status`.
- Removing one releases it from the project, then deletes it. Named volumes, where its data
  lives, are kept, and the record shows the data is retained. When another sandbox of the setup
  is stopped, removal rewrites the project file without converging it and undoes its own effect
  directly (delete, unpublish, `delete_connection`), so a stopped setup stays stopped.
- Health comes from the project's own probes (`project_deployment_status`). A sandbox is ready
  only when its configured health check passed, publicly too when it has an address; a running
  sandbox with no health check is "unknown", never ready.
- An update converges in place: the review names the settings that change. A new image, source
  or GPU makes the project build a new sandbox; the review says so, says the old one is kept
  stopped with what is on its own disk, and, when the sandbox keeps data, that the change is
  forward only (plan 8.5, L16). Changing a sandbox's kind or drive is refused at review.
- Built-in tools (`codex`, `claude`, `gemini`, `ollama`, `opencode`, `kilo`, `openclaw`) are
  installed after the sandbox starts, with the same `install-tools.sh` the terminal stages, run
  detached under `setsid` and polled. Tools bundled in the template folder run their install lines
  the way `yougori run` does (`hub::tools::runner`), then their check, and leave the same
  fingerprint marker. A retry installs only what is missing; nothing is launched; the tools go
  with the sandbox. A failed install on a sandbox this attempt made takes it down again. Hub tools
  are refused at review.
- A tool's sign-in from this computer (`tool_credentials::host_signin`) is copied only when the
  template asks for it and the person agreed when applying (`consents: ["copy_signin:RES/TOOL"]`
  with `setup_apply`, listed by the plan view). It is copied once, when the tool arrives.
- `files:` sources are read from the setup's kept copy of its package
  (`<setups>/projects/<setup-id>/package`), written atomically when the operation is submitted.

Volumes, publications and connections:
- Volumes are named as v1 projects name them (`<project>-<name>`). The runtime makes one when its
  sandbox first starts. Removing the volume resource keeps the data.
- Publications open a quick link or a saved domain. Stopping one closes the address, and starting
  opens it again. `private` publishes the sandbox's port at 127.0.0.1 only, on a port of this
  computer fixed for the setup and publication (20000 to 39999, `ordinary::here_port`); it stays
  with its sandbox. Each reports its address as `outputs.NAME.url`. `none` opens nothing.
- Volumes and connections don't run, so `stoppable()` keeps them out of start and stop.

Secrets: a sandbox binding must be a value given with `setup_apply` (`apply.FIELD`, or the
planner's key for one of the sandbox's own bundled tools); any other stored entry named by a
template is refused at review. Values are stored in the OS credential vault with the existing
deployment-secret functions, under `setup-<id8>-<resource>-<variable>-<hash>`, within the
vault's 80 characters. Each name goes into the setup's ledger (`vault-names`) before its value is
stored. What an attempt stored is forgotten when nothing came of it; a variable an update drops is
forgotten; the ledger is swept when the setup is removed. Keyring and ledger work runs off the
async runtime. A sandbox whose secret wasn't given waits in `awaiting_input` before anything is
made.

Not supported yet, each refused at review: local-network (`lan`) publication; volume size limits
and drive choice; Hub tools.

`EngineProjects` calls the engine through `automation::dispatch` and `projects`. The tests use
`ordinary::fake::FakeProjects`, so no sandbox, port or data folder is touched.

### Neo Grid (`setups::grids`)

The grid handlers call the Neo Grid product's own functions through `automation::dispatch`, so a
grid made from a template is the same grid the product manages, shown as a tab of its setup in My setups:
- `grid` with `mode: create` calls `grid_create`. The company password comes from the apply
  secret, and the reach setting maps to the tunnel: LAN, quick link or saved domain.
- `grid` with `mode: join` calls `grid_join`, with the invitation and password from apply
  secrets.
- Removing a created grid calls `grid_delete("later")`: it is paused for three days, can be
  restored, and is recorded as retained. The review gives the date and what goes then. Removing a
  joined grid calls `grid_leave`.
- A grid keeps running for its computers, so stopping and starting the setup leave it.
- Every handler acts only on what this setup made: the hub, membership, sign-in, plan or person
  whose ID it recorded, or, before a receipt exists, one the product says was made after the step
  began. A join or sign-in with one already here is refused (`already_in_use`) rather than let the
  product quietly replace it; removal leaves alone what isn't the recorded one.
- In-place changes the products don't offer (a grid, a person, credentials, a team) are refused at
  review.
- `compute_pool` has no product object; its availability, idle minutes and hours are applied to
  each model plan, and a pool update applies them again. Its recovery never acts on its own.
- `model_service` uses `grid_plan_add`, `grid_plan_update` and `grid_plan_remove`. A team
  (`spec.team`, `swarm/NAME`) uses `grid_swarm_add` and `grid_swarm_remove`.
- The first app key (`api.first_key`) isn't created during apply. A key is shown once, and setups
  have no private-result channel yet, so the person creates one with
  `yougori grids models add-key`.

When a setup owns a grid's hub or membership, the adopted legacy record for it is hidden from the
list, and the one-grid rule doesn't count it against that setup.

### Sandbox Grid and Access Grid (`setups::grids`)

The same grid handler serves the Sandbox Grid (`desks_*`) and the Access Grid (`access_*`).

Sandbox Grid:
- `grid` create, join and remove call `desks_create`, `desks_join`, `desks_delete("later")` and
  `desks_leave`.
- A person signing in (`member: person`) calls `desk_login`, and `desk_logout` on removal.
  Sign-in with a company account opens a browser, so it is refused.
- A `compute_pool` of `this_computer` sets this computer's share with `desks_member_share`, and
  resets it to the suggested share on removal.
- A `workspace_pool` with one workspace per person is a recorded policy. Each person's workspace
  is ordered with their account, sized from the pool. Shared workspaces, parking, backups, cloud
  fallback and drive choice are refused.
- An `access_binding` person calls `desks_person_add` (their workspace stays when the person is
  removed). SSO, invitations, extra administrators and two-step sign-in are refused for now.

Access Grid:
- An Access Grid is made together with its first administrator, as the product does
  (`access_create`). The grid step reads the administrator's binding from the operation's other
  planned steps (`StepContext.planned`), with the administrator's password from the apply
  secrets. The administrator's own step then only confirms the account, and turns on two-step
  sign-in when `mfa` is set.
- Other people are added with `access_manage personAdd`.
- People sign in with `access_signin` and out with `access_signout`. Computers don't join an
  Access Grid.
- `credential_broker` needs an Access Grid this setup makes. Before any `access_manage` it checks
  that the hub here is that grid, open, and managed by its owner, so nothing is sent as someone
  else signed in here. It adds each credential with `credentialAdd` (its value is an apply secret,
  sealed by the grid) and one `ruleAdd` per path (standing is `allow`). Each carries this step's
  stamp in the product's own `note`: a same-named credential without it refuses the step before
  anything changes, a retry adds only what is missing, and removal deletes only stamped
  credentials (`credentialRemove` takes their rules).

The tests plan and apply the real `neo-grid`, `sandbox-grid` and `access-grid` templates through
the planner and these handlers, against in-memory products (`grids::fake::FakeGrids`).

### Research on a Swarm Mining Grid (`setups::grids::research`)

A research grid (`swarm_mining_grid`) and its one worker (`worker_group`, role `research`) drive
the Swarm Mining product's own closed review through the calls its page and CLI make:
`inspectProject` and `hostSource` to host a review of the folder the person chose,
`localConnect` or `connect` and then `startWorker` for the worker, and `swarm_dispatch` to pause,
resume and delete it. The rules of the review stay in that product.

- **Authorisation as written.** The grid's `research.authorization` is sent exactly as the person
  wrote it; the review shows it, and agreeing to the review is that authorisation. Nothing makes
  one up.
- **No live target.** A review is of source, or of a site or API the worker starts inside its own
  offline sandbox. `target: url` is refused at review, and a joined review whose policy is a live
  service (`scopeMode: external_target`) is refused before its worker starts. The live-target
  capability stays in the private build.
- **A joined review's terms are agreed to by the person.** They are known only once connected, so
  the worker step gives the connection back and waits (`terms_to_accept`, operation
  `awaiting_input`) until the person agrees to exactly those terms: the start of their digest,
  from the window's "Agree to these terms" or as `accept_terms` with `template configure`.
  Findings for a joined project are always read here first.
- **One review per computer**, as the product allows. One already hosted is never taken over or
  deleted; removing a setup deletes only the review it hosted.
- **The worker's model and sandbox** are declared in the template but made by the worker inside
  its own sandboxes, so their handlers keep the record only (`research::made_by_worker`) and the
  review says nothing about them beyond the worker's own note.
- Swarm Mining's own record of its workers is listed beside setups only while it holds a worker
  no setup made.

Tests drive these against an in-memory Swarm Mining (`grids::fake`); no real review, model or
sandbox was run for them.

### Finite jobs and their results (`setups::jobs`)

Two kinds: `job` and `artifact_store`. Everything that decides anything is in
`yougori_grid::core::jobs` — the queue, the fencing, the attempts, the staged and checksummed
artifacts, the retries by side-effect class, the cancel that is a request. The handler is the
setup engine's side of it, and the worker loop (`setups::job_worker`) is the computer's side.

- **A realm per setup.** `EngineJobs` opens one Grid Core realm per setup under
  `<data>/setups/jobs/<setup>.db`, with a key minted on first use and kept in this computer's own
  credential vault under `grid-core.setup-jobs.<setup>`. Two setups never share a queue, a shelf or
  a retention policy, and removing one touches nothing of the other. The realm is made with the
  `Models` capability only, never `Research`, so a job can never reach research scope — and the
  library refuses a generic job in a research realm regardless.
- **Three refusals at review, before anything exists.** A `compute` reference this setup does not
  declare, or that names something other than a `compute_pool`; a pool whose grid is a research
  grid; and a job that may be tried more than once without saying `idempotent: true` or
  `reconcile: manual`. A shell as the job's program, a folder `source`, a `secrets` map and a
  `schedule` are refused at validation, each in words that say what to do instead.
- **Applying.** The setup's queue is opened, the job is sent under the step's own idempotency key
  as its deduplication key, and this computer's worker loop is started. Applying the same step
  again finds the job already admitted rather than queueing a second one. A changed description is
  a new job, not an edit: `plan` answers `Create`, never `Update`.
- **Stop and start.** Stopping closes the queue to new work and stops this computer taking any.
  What is already running finishes; nothing is killed. Starting reopens admission and starts the
  loop again.
- **A stage reads the stage before it.** A job may declare `inputs: [{resource: OTHER_JOB}]`. The
  handler waits for that job to succeed, reads the artifact it handed back, and passes it to this
  job as an input named after the stage that produced it — so nothing a person writes becomes a
  name, let alone a path. The reference is also the dependency, so the plan's order and the
  format's cycle check come from `Spec::references` rather than from anything here. A stage that
  failed, was cancelled or was stopped fails this one, naming which; a stage whose outcome nobody
  knows stops this one without starting it, so a person settles that one first; waiting gives way
  to the step being cancelled, and gives up once the stage before it has had its own time limit
  for every attempt it is allowed plus an hour.
- **Continuing a pipeline after a stage failed.** `plan` reads the recorded job's state: a stage
  that succeeded is `Unchanged`, so no step exists for it and nothing it did outside the grid
  happens twice; a stage that ended without succeeding is sent again as a new job, and the stages
  after it follow. A stage whose outcome is unknown is the one case `plan` refuses to decide, with
  `awaiting_settlement`, because sending it again might repeat what already happened. This is why
  `Observed::Stopped` on a job means "it ended without succeeding" and stopping a *setup* records
  `Observed::Present` instead: stopping a setup must never look like a failed stage.
- **Checkpoints.** A worker sends back a file called `checkpoint` that an attempt left beside its
  result, whichever way that attempt ended, and the library hands it to the next attempt as
  `resume_from`, which the worker writes into the input folder as `checkpoint`. A job that did not
  declare `checkpoint: true` has its checkpoint refused by the library, and that refusal is not an
  error for the attempt.
- **The store's policy is the person's answer.** Applying an `artifact_store` calls
  `Core::set_job_retention` with exactly the declared size and days, so a store that says ten
  gigabytes and seven days sweeps to ten and seven rather than to the grid's own twenty and thirty.
  A declared number outside the library's bounds is refused at validation with the bound named,
  never widened to fit. The sweep still keeps whatever a job still in play needs, and reports that
  it is over its allowance instead of removing it.
- **Removal deletes only what the setup recorded.** The job it sent is asked to stop and its record
  goes; a job this setup never sent is nobody's business of its own. **Artifacts are kept**, and are
  removed only by the library's own retention sweep, which never removes what a job still in play
  needs. Removing the store is the same: the setup stops using it, and nothing it holds is deleted.
- **The worker loop.** A fresh sandbox per attempt through the engine's container runtime, made at
  the start of the attempt and deleted at its end whichever way it ended; the attempt's inputs
  mounted read-only at `/yougori/job/in` and one writable folder at `/yougori/job/out`; the
  declared command as the container's entrypoint, never a line for a shell; no network, no host
  folder and no credential. It heartbeats while the sandbox runs, hears a cancel on the next
  heartbeat and stops its own work, and asks the realm whether it still holds the attempt before it
  sends anything — so a lost lease never writes, and the library's fencing refuses it a second time
  if the loop were ever wrong. A timeout is reported as nothing at all: the attempt lapses and the
  realm settles it as an outcome nobody knows, which is not a failure.
- **Off by default.** No loop runs because the handler exists. A setup that declares a job starts
  one; stopping or removing that setup stops it.

The tests plan and apply the real `build-test-farm`, `data-pipeline` and `model-evaluation`
templates through the planner and these handlers against an in-memory grid (`setups::jobs::tests`),
and the multi-worker build fixture (`setups::job_worker::tests`) drives several loops against a
real realm in a temporary folder with fake sandboxes.

One change outside this module made the pipeline templates expressible: `Spec::references` in
`setup/src/resource.rs` now allows a job's `inputs` to name a `job`, not only a store or a volume.
It is additive — no existing template changes meaning — and the handler still enforces the
narrower rule at review, that a job's input is another job of the same setup and never a store, a
volume or itself.

What this does not do yet, said rather than implied. A job cannot be handed a folder from this
computer, a credential, or a schedule — so per-stage credential grants and a job that calls the
grid's own model service are not built, rather than half-built, and the packages that would want
them say so. One attempt runs on one computer at a time. The deduplication key makes applying a step twice safe inside the grid;
it is not a promise that the job's effects outside it happened exactly once, and the review says so.

## Recovery

On start:

- A step left in `applying` becomes `unknown`, and so does its operation.
- An operation that had started but had no step in flight fails with `engine_interrupted`. Retry
  continues only the steps that didn't finish.
- An operation that never started fails with "nothing was changed".
- A cancel request that was pending completes as cancelled.

Unknown operations are then reconciled in the background by looking (`recover`/`observe`), never
by acting again. A reconciliation registers itself like a runner, so it can't race one, and it
saves a finding only if the step is still the one it looked at:

- An effect that is found is adopted as the receipt.
- An effect that didn't happen leaves the step to run again.
- When the provider can't be asked, the step stays unknown and the setup stays claimed.

Retry is explicit, and is allowed only when nothing has changed the setup since. Steps already
done are never repeated (L08). Nothing restarts by itself, so a stopped workload stays stopped
(plan 8.5).

Drift is found by `refresh`, which observes every owned resource and records the missing or
changed ones, with plain sentences and degraded health. Refresh never recreates anything. A
missing resource is recreated only by a reviewed repair plan, at the next generation (L18).

Removing a resource writes a tombstone with its generation. Removing the last resource of a setup
writes a setup tombstone and drops the setup's record, so removed setups don't count towards the
limit of 256. An old operation ID replays as a join of its finished operation, and a start or
stop sent again after it finished answers with its operation. An old plan under a new ID is
refused with `setup_removed` or `resource_removed`. Removed setups and resources therefore can't
be resurrected, including after a restart (L19).

## Adoption

`adopt::scan` finds the products that predate setups by the existence of their own records under
the engine data folder, using the file names their modules use:

| Product | Records |
| --- | --- |
| Neo Grid | `grid/hub.json`, `grid/member.json` |
| Sandbox Grid | `grid/desks-hub.json`, `grid/desks-member.json`, `grid/desks.json` |
| Access Grid | `grid/access-hub.json`, `grid/access-member.json` |
| Swarm Mining | `bounty/host.json` (the hub), `swarm/workers.json` |

Adoption is read-only, and only file metadata is read. No record is opened, so adoption can never
hold a handle that gets in the way of a product saving its own files, the live Swarm worker above
all. Their contents, which hold keys and certificates, are never read. A scan is reused for three
seconds, so listing and planning don't keep touching the disk.

Adopted setups appear in `setup_list` with:
- `adoptedLegacy: true`, an `adopted-…` ID and no actions
- `stateObserved: false`: their state isn't observed, so the client shows "managed from its own
  page" rather than a state word (invariant 16). The state field says `stopped` only because it
  never implies that something runs or can be started from here.

Every change to them is refused with `legacy_managed`. Nothing here can start Swarm (plan 13.5). A
record that exists but can't be looked at is listed as "(can't be read)", not left out (plan
19.1).

These are temporary legacy views (plan 19.2) with a removal milestone of M14/M15, when each
product's migration lands.

Until multi-instance grids (M06) namespace the hubs' fixed keyring names and listeners
([singleton ledger](singleton-ledger.md) SG-A05, SG-N05, SG-S06, SG-W02), a second hub of a grid
profile on this computer is refused with `unsupported_here`. It counts:
- grids that exist
- grid creates in operations that haven't finished, or whose outcome is unknown
- a second grid of the profile in the same plan
- the legacy products' hubs

It counts per profile what a grid holds on this computer: its hub, this computer's membership,
and a person's sign-in. A grid made here holds its hub and the hub computer's membership (an
Access Grid's, its administrator's sign-in), a join holds the membership, and a person signing in
holds the sign-in. A borrowed grid is not counted, and a grid is never compared with itself.
Review and apply run the same check (`one_grid_per_profile`) before anything is written.

`setup_action adopt` on an adopted Neo, Sandbox or Access Grid hub returns the plan for a new
setup holding it, applied as any reviewed plan. It is bookkeeping only: the grid resource
(`adopted: true`) records the hub ID read from the product's status; nothing is moved,
restarted or re-keyed, and the product's records are not written. Swarm Mining, memberships and
records Yougori can't look at are not adopted.

## Desktop and CLI calls

The nine calls are `setup_capabilities`, `setup_validate`, `setup_plan`, `setup_apply`,
`setup_list`, `setup_get`, `setup_operation`, `setup_cancel` and `setup_action`. One
implementation (`setups::commands`) serves two doors:
- The desktop's Tauri commands, allowed from the main window only, which answer with a `dto`
  message or a `dto::Diagnostic`.
- The CLI's engine methods of the same names, through `automation::dispatch`, plus `setup_export`,
  which writes a reviewed recipe folder (see the built table). Over the wire a refusal travels as
  `YOUGORI_SETUP code retry|final [resource]: sentence`. The queue strips the head into
  `errorDetails`, so a person sees only the sentence. Every such refusal comes before anything was
  changed, so its outcome is `not_started`. An operation that fails after it started reports that
  in its own progress instead.
- Reads (capabilities, validate, plan, list, get, operation) answer at once and never take a
  slot in the job journal, so polling `template logs --follow` can't flood it. Writes are
  journaled.

The headless `yougori-engine` runs the same startup, so the methods work there with no windows.

`setup_validate` and `setup_plan` call the shared planner (`setups::planning`):
- Folder sources are collected as the Hub collects them, and checked with `format::template`.
- Plans come from `plan::plan`, with this computer as `plan::Host`.
- An installed setup is re-planned from the source it was made from.
- The answer is `dto::PlanResponse`, whose digest is the planner's own, plus the engine's step
  list and notes. The engine accepts either digest when applying or continuing.

- `setup_get` returns `SetupDetail` plus recent operations, notes and a readable flag, with each
  resource's own details.
- `setup_action` runs start and stop at once.
- Remove and repair first return the plan to review, then apply it when called with its digest. A
  removal review names outstanding charges per resource (`setups::tests`
  `a_removal_says_plainly_what_may_still_be_charging`, and `a_removal_says_nothing_about_the_charges_
  of_a_part_it_only_borrows`), and a ticked deletion offer deletes exactly that resource's data — a volume
  and its backups, or the grid the setup made — at once (`removing_one_volume_on_its_own_offers_its_
  deletion_the_same_way`, `a_ticked_deletion_deletes_exactly_that_volume_and_all_its_backups`,
  `setups::grids` `a_ticked_deletion_deletes_the_grid_the_setup_made_at_once`).
- A single resource (a part) is started, stopped, removed or detached on its own through
  `PlanIntent::Part`, and the rest of the setup stays up (`setups::tests`
  `one_part_is_stopped_started_and_removed_on_its_own_and_the_setup_stays_up`). Removal and detach of
  a part are reviewed first, like removing the whole setup.
- `refresh`, `reconcile` and `retry` are engine actions.
- `adopt` (see Adoption) and `join` return a plan to review. `join` reads the invitation only to
  tell the grid and its company; the invitation and company password come again as apply secrets.
- `pause_admission`, `release_compute` and `delete_data` return `unsupported_here`.
- Request types refuse unknown fields, so a misspelt `existingSetup` can't plan a new setup.
- `setup_reveal` returns a setup's private one-time outputs (such as a grid's first app key) only on
  demand, through `service.reveal` (`setups::commands` `reveal`); ordinary outputs are filled from the
  products and shown by `setup_get`.

Sources: a Hub source resolves `latest` to a pinned version through the CLI's Hub client and its
cache; an installed setup never follows latest. Format 1 packages are read by the CLI's v1 parser
and planned through `hub::plan::legacy_of`. Builder drafts are generated with `draft::to_package`.
Pinned components resolve through `hub::components::resolve`, the function `template check` uses.
The plan's lock (`lock::Lock`) is kept with the setup and shown by `setup_get`, with the person's
choices (`customization`); planning the same version again must match it. An update to a new
version names what is new, changed, unchanged and no longer declared (kept, never deleted), and
the setup's source and lock move only when it completes.

## Built since this ADR was first written

| Item | Evidence |
| --- | --- |
| Per-part lifecycle | `PlanIntent::Part` starts, stops, removes or detaches one resource on its own; the rest of the setup stays up. `setups::commands` part arm; test `setups::tests` `one_part_is_stopped_started_and_removed_on_its_own_and_the_setup_stays_up`. |
| Reviewed data deletion | `retention.onRemove: ask` offers an unticked deletion; ticking it deletes exactly that volume and its backups, or the grid the setup made, at removal. `service::removal_data` with each handler's `removal_offers` (`handler.rs`, overridden in `grids.rs`); tests `removing_one_volume_on_its_own_offers_its_deletion_the_same_way`, `a_ticked_deletion_deletes_exactly_that_volume_and_all_its_backups`, `grids::a_ticked_deletion_deletes_the_grid_the_setup_made_at_once`. |
| Outstanding-charge lines | A removal review names, per resource, whether it is still charging or unconfirmed. `setups::tests` `a_removal_says_plainly_what_may_still_be_charging`. |
| New-grant conflicts on update | An update to a new version raises a review conflict for each grant or download the new version adds. `setups::planning` `new_grants`; test `a_new_version_that_asks_for_more_says_what_before_anything_changes`. |
| Setup outputs and private reveal | Ordinary outputs are filled from the products and shown by `setup_get`; private one-time outputs (a grid's first app key) are returned on demand by `setup_reveal`/`service::reveal`. |
| Request field checking | Request types refuse unknown fields, so a misspelt `existingSetup` cannot plan a new setup. |
| Export | `setup_export` writes a reviewed recipe folder from the setup's kept package copy and its public answers as defaults, with every secret, sign-in, personal value (invariant 17) and host-folder grant left out and listed; it refuses a non-empty folder and a setup with no kept package. `setups::commands` `setup_export` arm → `export::export` (`export.rs`); tests `export::recipe_carries_safe_answers_as_defaults_and_omits_secrets_and_personal`, `an_export_needs_a_full_path_and_an_empty_folder`. |

## Not built yet

| Item | Status |
| --- | --- |
| Local model and share handlers | A model service outside a grid (this computer) and a share of an existing sandbox to one person are being added as handlers, so an ordinary setup can serve a model or share a sandbox. Until then the model-server/model-collection/ai-team and shared-workspace packages name the missing handler in their Known limits. |
| Grid options | Company sign-in (SSO), invitations, extra administrators, shared workspaces, parking, rented computers in a pool, and changing a grid, person or credential after it was made (update). Each is refused plainly at review, pointing to the Grids page. Research has no handler. |
| Capability host description | `setup_capabilities` and the planner's host are best effort: operating system and architecture, ready runtime providers, the GPU runtime payload, and memory. |
| Parallel steps | Steps run one at a time in dependency order, not in parallel within resource limits (plan 8.3 step 6). |
| Plan contents | Quote, permission and inventory revalidation before apply (plan 8.3 step 4), cost and permission diffs. |
| Backups before an update | Named as a forward-only change in the review; a pre-update backup is not taken automatically yet (`setup_backup_now` takes one on request). |
| Multi-instance grids (M06) | One instance per grid profile until then. |
