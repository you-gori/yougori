# The TypeScript client

Written by `scripts/grid-client-docs.mjs` from `src/api/grids`. Do not edit by hand; change the
code and run `node scripts/grid-client-docs.mjs`.

One client, four grids. `grids.models`, `grids.workspaces`, `grids.credentials` and
`grids.research` speak Grid Core's vocabulary over the engine commands that exist today. The
four product modules keep their own paths, their own types and their own answers, and they now
send through the same one call path, so a request name, a typed refusal and the redaction pass
cover what the pages already do. A page moves to `grids` when its own test moves with it.

Every method below says where it goes: an engine command, another module it wraps, or this
computer. A method that says nothing fails the generator.

## grids.models

Closed Neo Grid.

| Method | What it does | Where it goes |
| --- | --- | --- |
| `status` | The hub this computer runs and this computer's membership, with the tunnel. | `grid_status` |
| `who()` | What the client believes this computer may do here. The engine decides for real. | on this computer |
| `may(action: Action)` | Whether a control is worth offering. Never the decision itself. | on this computer |
| `suggestedAddress()` | This computer's private network address to host on. | `grid_suggested_address` |
| `host(name: string, address: string, password: string, reach: Reach = "network")` | Starts the hub on this computer. | `grid_create` |
| `join(invite: string, password?: string)` | Joins a company hub from an invite code. | `grid_join` |
| `leave()` |  | `grid_leave` |
| `scheduleDeletion(when: DeleteWhen = "later")` | `later` pauses the grid for three days and is restorable, `now` deletes it, `forget` stops waiting for computers that are away. | `grid_delete` |
| `restore()` |  | `grid_restore` |
| `hosts(filter: HostFilter = {}, page: PageRequest = {})` | The computers in this grid, filtered and paged. Asking for no page asks for all of them. | `grid_status` |
| `plans(page: PageRequest = {})` | The model plans in this grid. | `grid_status` |
| `addPlan(plan: NewModelPlan, options?: CallOptions)` | Orders a model across the grid. | `grid_plan_add` |
| `removePlan(planId: string, options?: CallOptions)` |  | `grid_plan_remove` |
| `removeHost(hostId: string)` |  | `grid_member_remove` |
| `drainHost(hostId: string)` | Leaves a computer out: no model and no work until it is brought back. | `grid_member_exclude` |
| `bringHostBack(hostId: string)` |  | `grid_member_include` |
| `rentedGpus()` | The rented NeoCloud GPUs in the grid this computer hosts, with each pod's price and state, and the rented pods that could join. Nothing here rents or starts a pod. | `grid_neocloud_status` |
| `addRentedGpu(environmentId: string)` | Adds a pod already rented in NeoCloud, at most eight to a grid. | `grid_neocloud_add` |
| `removeRentedGpu(environmentId: string)` | Takes a rented GPU out of the grid and stops its pod, which ends its GPU billing. | `grid_neocloud_remove` |
| `stopRentedGpus()` | Stops every rented GPU in the grid. They stay in it, offline, until started in NeoCloud. | `grid_neocloud_stop_all` |
| `harnesses(page: PageRequest = {})` | The teams of models this grid serves as `swarm/NAME`. | `grid_status` |
| `addHarness(harness: NewHarness)` |  | `grid_swarm_add` |
| `removeHarness(harnessId: string)` |  | `grid_swarm_remove` |
| `runHarness(harness: string, prompt: string)` | Runs a team of models once and reports what each one did. The answer is a model's own words and is never shortened or rewritten. | `grid_swarm_run` |
| `changePlan()` | Changes a plan after it was ordered. The command line has this; the desktop does not. | `grid_plan_update` |
| `changePassword()` | Rotates the company password. The command line has this; the desktop does not. | `grid_password` |
| `addKey()` |  | `grid_key_create` |
| `revokeKey()` |  | `grid_key_revoke` |
| `readInvite(code: string)` | The company an invite names, read here so a mistyped code is caught before joining. | on this computer |

## grids.workspaces

Sandbox Grid.

| Method | What it does | Where it goes |
| --- | --- | --- |
| `status` | The hub, this computer's membership, what it hosts, and the person signed in here. | `desks_status` |
| `who()` | What the client believes the person signed in here may do. The hub decides for real. | on this computer |
| `may(action: Action)` | Whether a control is worth offering. Never the decision itself. | on this computer |
| `suggestedAddress()` | This computer's private network address to host on. | `desks_suggested_address` |
| `host(name: string, address: string, password: string, reach: Reach = "network")` | Starts the hub on this computer. | `desks_create` |
| `join(invite: string, password: string, name?: string)` |  | `desks_join` |
| `leave()` |  | `desks_leave` |
| `scheduleDeletion(when: DeleteWhen = "later")` | `later` pauses the grid for three days and is restorable, `now` deletes it, `forget` stops waiting for computers that are away. | `desks_delete` |
| `restore()` |  | `desks_restore` |
| `adoptMembership(membership: unknown)` | A computer the hub itself made takes up a membership that was prepared for it. | `desks_adopt_membership` |
| `hosts(filter: HostFilter = {}, page: PageRequest = {})` | The computers in this grid. Asking for no page asks for all of them. | `desks_status` |
| `removeHost(hostId: string)` |  | `desks_member_remove` |
| `setOffer(hostId: string, offer: Offer)` | What the grid may take from a computer, whether or not its person is using it. | `desks_member_share` |
| `suggestOffer(hostId: string)` | Puts the suggestion back in force. | `desks_member_share` |
| `people(filter: PersonFilter = {}, page: PageRequest = {})` | The people who sign in to open a workspace. | `desks_status` |
| `addPerson(person: { username: string; name: string; password: string; workspace?: { kind?: DeskKind; cpu: number; memoryGb: number; diskGb: number; gpu: boolean } })` | Adds a person and, with `workspace`, orders their first one in the same step. The password is an argument of the engine command and is never written anywhere by this client. | `desks_person_add` |
| `setPersonPassword(principalId: string, password: string)` |  | `desks_person_password` |
| `removePerson(principalId: string)` |  | `desks_person_remove` |
| `list(filter: WorkspaceFilter = {}, page: PageRequest = {})` | The workspaces this grid holds. | `desks_status` |
| `order(workspace: NewWorkspace)` | Orders one. | `desks_add` |
| `assign(workspaceId: string, principalId: string | null, options?: CallOptions)` | Gives one to a person, or takes it back with null. | `desks_assign` |
| `retry(workspaceId: string)` |  | `desks_retry` |
| `remove(workspaceId: string, options?: CallOptions)` |  | `desks_remove` |
| `signIn(invite: string, username: string, password: string, code?: string)` | With two-step sign-in on, the hub asks for the code from the authenticator app until one is given. | `desk_login` |
| `signInSso(invite: string)` | The company's identity provider signs the person in. | `desk_login` |
| `refresh()` |  | `desk_refresh` |
| `signOut()` |  | `desk_logout` |
| `manage(request: { action: string } & Record<string, unknown>)` | The one admin door the Sandbox Grid already has. Its actions keep their exact names, so the same request object works through either surface. | `desks_manage` |
| `readInvite(code: string)` | The company an invite names, read here so a mistyped code is caught before joining. | on this computer |

## grids.credentials

Access Grid.

| Method | What it does | Where it goes |
| --- | --- | --- |
| `status` | The hub, this person's sign-in, and everything they may see. | through `accessApi.status` |
| `who()` | What the client believes the person signed in here may do. The hub decides for real. | on this computer |
| `may(action: Action)` | Whether a control is worth offering. Never the decision itself. | on this computer |
| `suggestedAddress()` | This computer's private network address to host on. | through `accessApi.status` |
| `host(company: string, address: string, admin: { username: string; name: string; password: string }, reach: Reach = "network")` | Starts the hub on this computer, with its first administrator. | through `accessApi.create` |
| `scheduleDeletion(when: DeleteWhen = "later")` | `later` pauses the grid for three days and is restorable, `now` deletes it, `forget` removes it from this computer. | through `accessApi.delete` |
| `restore()` |  | through `accessApi.restore` |
| `signIn(invite: string, username: string, password: string, code?: string)` |  | through `accessApi.signIn` |
| `signInSso(invite: string)` |  | through `accessApi.signInSso` |
| `signOut()` |  | through `accessApi.signOut` |
| `people(page: PageRequest = {})` | The people in this grid. | through `accessApi.status` |
| `list(filter: CredentialFilter = {}, page: PageRequest = {})` | The credentials this grid holds. Never their values. | through `accessApi.status` |
| `add(credential: { name: string; shape: string; field?: string; destinations: string[]; value: string; note?: string; config?: Record<string, string | number> })` | Adds one. The value is handed straight to the hub, which puts it in the vault; it is never written to a log, a prompt or this client's own state. | through `accessApi.manage` |
| `rotate(credentialId: string, value: string)` | Replaces the value behind a credential, leaving every rule in place. | through `accessApi.manage` |
| `retire(credentialId: string)` |  | through `accessApi.manage` |
| `grants(filter: GrantFilter = {}, page: PageRequest = {})` | Who may use a credential, for what. | through `accessApi.status` |
| `allow(grant: { credentialId: string; who: string; methods: string[]; path: string; decision: Grant["decision"]; reveal?: boolean; hours?: number; limit?: number })` |  | through `accessApi.manage` |
| `takeBack(grantId: string)` |  | through `accessApi.manage` |
| `waiting(filter: ApprovalFilter = {}, page: PageRequest = {})` | What waits for an approver. | through `accessApi.status` |
| `decide(approvalId: string, verdict: Verdict)` | Agrees to a request, agrees for a while, or refuses with a reason. | through `accessApi.manage` |
| `history(filter: AuditFilter = {}, page: PageRequest = {})` | What was decided and used, most recent first. | through `accessApi.status` |
| `verifyHistory()` | Whether the history is whole, and where it first breaks if it is not. | through `accessApi.manage` |
| `backup(output: string, passphrase: string)` |  | through `accessApi.backup` |
| `restoreBackup(file: string, passphrase: string, address: string)` |  | through `accessApi.restoreBackup` |
| `account.twoStepStart()` | Begins turning on two-step sign-in, and answers with what to scan. | through `accessApi.account` |
| `account.twoStepConfirm(code: string)` |  | through `accessApi.account` |
| `account.twoStepOff(code: string)` |  | through `accessApi.account` |
| `account.changePassword(password: string, code?: string)` |  | through `accessApi.account` |
| `account.signOutOthers()` | Ends this person's sign-in on every other computer. | through `accessApi.account` |
| `account.forgetDevice(deviceId: string)` |  | through `accessApi.account` |
| `manage(request: { action: string } & Record<string, unknown>)` | The door the Access Grid already has, for an action this profile has not named yet. | through `accessApi.manage` |
| `use()` | Using a credential, checking a request and revealing a value happen on the local wire and have no desktop command at all, so the desktop cannot offer them whatever this says. | `access_use` |
| `check()` |  | `access_check` |
| `reveal()` |  | `access_reveal` |
| `readInvite(code: string)` | The company an invite names. | on this computer |

## grids.research

Swarm Mining and closed bounties.

| Method | What it does | Where it goes |
| --- | --- | --- |
| `prompts()` | This computer's worker prompts. | `swarm_dispatch` |
| `savePrompts(values: Partial<Record<"agents" | "rules" | "liveTask" | "sourceTask" | "chatReply", string>>)` |  | `swarm_dispatch` |
| `resetPrompts()` |  | `swarm_dispatch` |
| `status()` | Every research job on this computer. | `swarm_dispatch` |
| `jobs(filter: ResearchFilter = {}, page: PageRequest = {})` | The research jobs, filtered and paged. Asking for no page asks for all of them. | `swarm_dispatch` |
| `job(jobId: string)` | One job. | `swarm_dispatch` |
| `steps(jobId: string, after = 0)` | Progress since a line you have already seen. A cursor read, not a stream: the engine keeps a ring of lines and this asks for what came after `after`. | `swarm_dispatch` |
| `check(model: string, quant?: string)` | Checks a model and this computer's resources before anything is created. | `swarm_dispatch` |
| `prepare(setup: WorkerSetup)` | Creates a job that joins the public board. | `swarm_dispatch` |
| `pause(jobId: string)` |  | `swarm_dispatch` |
| `resume(jobId: string, budgetMinutes = 30)` |  | `swarm_dispatch` |
| `stop(jobId: string)` | Leaves the bounty it holds, and keeps the job. | `swarm_dispatch` |
| `remove(jobId: string)` |  | `swarm_dispatch` |
| `clearHistory(jobId: string)` | Clears a paused job's activity and attempt count; reports and receipts stay. | `swarm_dispatch` |
| `messages(jobId: string, after = 0, page: PageRequest = {})` | What the job and the person have said to each other. | `swarm_dispatch` |
| `say(jobId: string, content: string)` |  | `swarm_dispatch` |
| `reports(jobId: string, page: PageRequest = {})` | What it wrote up. The document is somebody's findings and is never touched. | `swarm_dispatch` |
| `submitReport(jobId: string, reportId: string)` |  | `swarm_dispatch` |
| `offers(jobId: string)` | The bounties this job is offered, with the terms each one needs. | `swarm_dispatch` |
| `skipOffer(jobId: string, offerId: string)` |  | `swarm_dispatch` |
| `accept(jobId: string, offer: SwarmOffer, budgetMinutes: number, reportPolicy = "review")` | Accepts a bounty. The person must be authorized to test the target, and this is what records that they said so, with the digests of exactly what they agreed to. | `swarm_dispatch` |
| `rentedGpus()` | Jobs whose model runs on a rented NeoCloud GPU, what each GPU costs, and how recent stops went. | `swarm_dispatch` |
| `stopRentedGpu(jobId: string)` | Pauses the job and stops its rented GPU, which ends the GPU's billing. | `swarm_dispatch` |
| `stopRentedGpus()` | Stops every job's rented GPU. | `swarm_dispatch` |
| `board()` | The public bounty board. | `swarm_dispatch` |
| `closed.status()` |  | `bounty_dispatch` |
| `closed.suggestedAddress()` |  | `bounty_suggested_address` |
| `closed.inspect(path: string)` | Reads a project folder or archive and says what it found. | `bounty_dispatch` |
| `closed.publish(request: Record<string, unknown>)` |  | `bounty_dispatch` |
| `closed.connect(invite: string, password: string, name: string)` |  | `bounty_dispatch` |
| `closed.connectHere()` |  | `bounty_dispatch` |
| `closed.discard(ticket: string)` |  | `bounty_dispatch` |
| `closed.begin(preview: PrivatePreview, setup: WorkerSetup, budgetMinutes: number, reportPolicy: string)` | Begins work on a connected closed bounty. | `bounty_dispatch` |
| `closed.start(jobId: string, content: string)` | Works a source given on this computer alone. | `swarm_dispatch` |
| `closed.stop(jobId: string)` |  | `swarm_dispatch` |
| `closed.removeHunter(memberId: string)` |  | `bounty_member_remove` |
| `closed.unpublish()` |  | `bounty_delete` |
| `closed.choosePath` | Asks the desktop for a project folder or archive. One place, so a test can answer instead of opening a window. | on this computer |

## The shared pieces

### Types

The vocabulary: realms, principals, devices, hosts, plans, workspaces, credentials, approvals, research jobs and audit events.

`src/api/grids/types.ts` exports: `RealmKind`, `Capability`, `Profile`, `RealmLifecycle`, `NetworkPolicy`, `Realm`, `Tunnel`, `Reach`, `RealmHub`, `Membership`, `PrincipalKind`, `Role`, `Action`, `Principal`, `Attestation`, `Device`, `Me`, `Resources`, `Commitment`, `HostLoad`, `HostStatus`, `ModelProgress`, `ModelReport`, `PlanTarget`, `ModelPlan`, `NewModelPlan`, `Harness`, `WorkspaceKind`, `WorkspaceAccess`, `WorkspaceState`, `Workspace`, `NewWorkspace`, `Image`, `CredentialShape`, `Credential`, `Grant`, `ApprovalState`, `Verdict`, `Approval`, `WorkKind`, `Stage`, `ResearchJob`, `ResearchStep`, `AuditDecision`, `AuditEvent`, `AuditCheck`, `RealmStatus`, `ModelsStatus`, `WorkspacesStatus`, `CredentialsStatus`, `ResearchStatus`, `Expect`, `CallOptions`.

### Refusals

One class per kind of refusal, each carrying the command and the call's name. The engine's own words are kept exactly.

`src/api/grids/errors.ts` exports: `Failure`, `GridError`, `NotAllowedError`, `CapabilityOffError`, `NeedsApprovalError`, `ConflictError`, `DesktopOnlyError`, `CliOnlyError`, `classify`, `say`.

### Pages and filters

Asking for no page asks for the whole list. Every filter left out narrows nothing.

`src/api/grids/page.ts` exports: `PageRequest`, `Page`, `HostFilter`, `WorkspaceFilter`, `PersonFilter`, `CredentialFilter`, `GrantFilter`, `ApprovalFilter`, `AuditFilter`, `ResearchFilter`, `MOST`, `paginate`, `where`, `mentions`.

### What the client offers

A mirror of the engine's table. It grants nothing; the engine, the hub and Grid Core each check again.

`src/api/grids/permits.ts` exports: `Held`, `capabilityOf`, `CAPABILITY_DOING`, `enabled`, `may`, `guard`, `ROLE_FROM_DESKS`, `ROLE_FROM_ACCESS`, `HOST_ROLES`, `MEMBER_ROLES`.

### Redaction

A second line of defence over answers, not enforcement. Opt-in per field, and it never walks somebody else's document.

`src/api/grids/redact.ts` exports: `REDACTED`, `Leak`, `onLeak`, `safeUrl`, `safePath`, `FieldPolicy`, `scrub`.

### Events and the shared read

One desktop event as an accelerator, with reads as the truth and one shared poller behind every watcher.

`src/api/grids/events.ts` exports: `GRID_EVENT`, `GridEvent`, `EventKind`, `EventFilter`, `deliver`, `subscribe`, `Watch`, `WatchStore`, `watch`, `forgetWatches`.

### The one call path

Request names, optimistic versions, the transport seam and the typed refusal.

`src/api/grids/wire.ts` exports: `Transport`, `setTransport`, `resetTransport`, `requestId`, `CARRIES_REQUEST_ID`, `Call`, `call`, `cliOnly`.

### Mapping tables

Where the four products' words meet Grid Core's, one table per state that differs.

`src/api/grids/compat.ts` exports: `seconds`, `toPlanTarget`, `fromPlanTarget`, `toModelPlan`, `toHostStatus`, `toDeskHostStatus`, `toModelsHub`, `toWorkspacesHub`, `toCredentialsHub`, `toMembership`, `toAssignment`, `toDesksMembership`, `toAccessMembership`, `WORKSPACE_STATE_FROM_DESK`, `DESK_STATE_FROM_WORKSPACE`, `toWorkspace`, `toDeskPrincipal`, `WORKER_STATES_CORE_CANNOT_HOLD`, `STAGE_FROM_WORKER`, `toResearchJob`, `toCredential`, `toGrant`, `toApproval`, `toAuditEvent`, `toAccessPrincipal`, `LegacyRow`, `LEGACY_METHODS`.

## What replaces what

Every method the four product modules export today, and what a page calls once it moves. The
engine command is the same on both sides, so nothing changes on the engine the day a page moves.

| Module | Today | After it moves | Engine command |
| --- | --- | --- | --- |
| `grid-api` | `gridApi.status` | `grids.models.status` | `grid_status` |
| `grid-api` | `gridApi.suggestedAddress` | `grids.models.suggestedAddress` | `grid_suggested_address` |
| `grid-api` | `gridApi.create` | `grids.models.host` | `grid_create` |
| `grid-api` | `gridApi.join` | `grids.models.join` | `grid_join` |
| `grid-api` | `gridApi.leave` | `grids.models.leave` | `grid_leave` |
| `grid-api` | `gridApi.delete` | `grids.models.scheduleDeletion` | `grid_delete` |
| `grid-api` | `gridApi.restore` | `grids.models.restore` | `grid_restore` |
| `grid-api` | `gridApi.addPlan` | `grids.models.addPlan` | `grid_plan_add` |
| `grid-api` | `gridApi.removePlan` | `grids.models.removePlan` | `grid_plan_remove` |
| `grid-api` | `gridApi.removeComputer` | `grids.models.removeHost` | `grid_member_remove` |
| `grid-api` | `gridApi.excludeComputer` | `grids.models.drainHost` | `grid_member_exclude` |
| `grid-api` | `gridApi.includeComputer` | `grids.models.bringHostBack` | `grid_member_include` |
| `grid-api` | `gridApi.rentedGpus` | `grids.models.rentedGpus` | `grid_neocloud_status` |
| `grid-api` | `gridApi.addRentedGpu` | `grids.models.addRentedGpu` | `grid_neocloud_add` |
| `grid-api` | `gridApi.removeRentedGpu` | `grids.models.removeRentedGpu` | `grid_neocloud_remove` |
| `grid-api` | `gridApi.stopRentedGpus` | `grids.models.stopRentedGpus` | `grid_neocloud_stop_all` |
| `grid-api` | `gridApi.addHarness` | `grids.models.addHarness` | `grid_swarm_add` |
| `grid-api` | `gridApi.removeHarness` | `grids.models.removeHarness` | `grid_swarm_remove` |
| `grid-api` | `gridApi.runHarness` | `grids.models.runHarness` | `grid_swarm_run` |
| `desks-api` | `desksApi.status` | `grids.workspaces.status` | `desks_status` |
| `desks-api` | `desksApi.manage` | `grids.workspaces.manage` | `desks_manage` |
| `desks-api` | `desksApi.suggestedAddress` | `grids.workspaces.suggestedAddress` | `desks_suggested_address` |
| `desks-api` | `desksApi.create` | `grids.workspaces.host` | `desks_create` |
| `desks-api` | `desksApi.join` | `grids.workspaces.join` | `desks_join` |
| `desks-api` | `desksApi.leave` | `grids.workspaces.leave` | `desks_leave` |
| `desks-api` | `desksApi.delete` | `grids.workspaces.scheduleDeletion` | `desks_delete` |
| `desks-api` | `desksApi.restore` | `grids.workspaces.restore` | `desks_restore` |
| `desks-api` | `desksApi.removeComputer` | `grids.workspaces.removeHost` | `desks_member_remove` |
| `desks-api` | `desksApi.setComputerShare` | `grids.workspaces.setOffer` | `desks_member_share` |
| `desks-api` | `desksApi.suggestComputerShare` | `grids.workspaces.suggestOffer` | `desks_member_share` |
| `desks-api` | `desksApi.addPerson` | `grids.workspaces.addPerson` | `desks_person_add` |
| `desks-api` | `desksApi.setPersonPassword` | `grids.workspaces.setPersonPassword` | `desks_person_password` |
| `desks-api` | `desksApi.removePerson` | `grids.workspaces.removePerson` | `desks_person_remove` |
| `desks-api` | `desksApi.addDesk` | `grids.workspaces.order` | `desks_add` |
| `desks-api` | `desksApi.assignDesk` | `grids.workspaces.assign` | `desks_assign` |
| `desks-api` | `desksApi.retryDesk` | `grids.workspaces.retry` | `desks_retry` |
| `desks-api` | `desksApi.removeDesk` | `grids.workspaces.remove` | `desks_remove` |
| `desks-api` | `desksApi.login` | `grids.workspaces.signIn` | `desk_login` |
| `desks-api` | `desksApi.loginSso` | `grids.workspaces.signInSso` | `desk_login` |
| `desks-api` | `desksApi.refreshDesk` | `grids.workspaces.refresh` | `desk_refresh` |
| `desks-api` | `desksApi.logout` | `grids.workspaces.signOut` | `desk_logout` |
| `swarm-api` | `swarmApi.workers` | `grids.research.jobs` | `swarm_dispatch` |
| `swarm-api` | `swarmApi.prompts` | `grids.research.prompts` | `swarm_dispatch` |
| `swarm-api` | `swarmApi.savePrompts` | `grids.research.savePrompts` | `swarm_dispatch` |
| `swarm-api` | `swarmApi.resetPrompts` | `grids.research.resetPrompts` | `swarm_dispatch` |
| `swarm-api` | `swarmApi.status` | `grids.research.job` | `swarm_dispatch` |
| `swarm-api` | `swarmApi.activity` | `grids.research.steps` | `swarm_dispatch` |
| `swarm-api` | `swarmApi.doctor` | `grids.research.check` | `swarm_dispatch` |
| `swarm-api` | `swarmApi.prepare` | `grids.research.prepare` | `swarm_dispatch` |
| `swarm-api` | `swarmApi.pause` | `grids.research.pause` | `swarm_dispatch` |
| `swarm-api` | `swarmApi.resume` | `grids.research.resume` | `swarm_dispatch` |
| `swarm-api` | `swarmApi.leave` | `grids.research.stop` | `swarm_dispatch` |
| `swarm-api` | `swarmApi.remove` | `grids.research.remove` | `swarm_dispatch` |
| `swarm-api` | `swarmApi.clearHistory` | `grids.research.clearHistory` | `swarm_dispatch` |
| `swarm-api` | `swarmApi.messages` | `grids.research.messages` | `swarm_dispatch` |
| `swarm-api` | `swarmApi.chat` | `grids.research.say` | `swarm_dispatch` |
| `swarm-api` | `swarmApi.reports` | `grids.research.reports` | `swarm_dispatch` |
| `swarm-api` | `swarmApi.submitReport` | `grids.research.submitReport` | `swarm_dispatch` |
| `swarm-api` | `swarmApi.offers` | `grids.research.offers` | `swarm_dispatch` |
| `swarm-api` | `swarmApi.skipOffer` | `grids.research.skipOffer` | `swarm_dispatch` |
| `swarm-api` | `swarmApi.accept` | `grids.research.accept` | `swarm_dispatch` |
| `swarm-api` | `swarmApi.rentedGpus` | `grids.research.rentedGpus` | `swarm_dispatch` |
| `swarm-api` | `swarmApi.stopRentedGpu` | `grids.research.stopRentedGpu` | `swarm_dispatch` |
| `swarm-api` | `swarmApi.stopRentedGpus` | `grids.research.stopRentedGpus` | `swarm_dispatch` |
| `swarm-api` | `swarmApi.bounties` | `grids.research.board` | `swarm_dispatch` |
| `swarm-api` | `swarmApi.practiceStart` | `grids.research.closed.start` | `swarm_dispatch` |
| `swarm-api` | `swarmApi.practiceStop` | `grids.research.closed.stop` | `swarm_dispatch` |
| `bounty-api` | `bountyApi.inspect` | `grids.research.closed.inspect` | `bounty_dispatch` |
| `bounty-api` | `bountyApi.host` | `grids.research.closed.publish` | `bounty_dispatch` |
| `bounty-api` | `bountyApi.connect` | `grids.research.closed.connect` | `bounty_dispatch` |
| `bounty-api` | `bountyApi.localConnect` | `grids.research.closed.connectHere` | `bounty_dispatch` |
| `bounty-api` | `bountyApi.discard` | `grids.research.closed.discard` | `bounty_dispatch` |
| `bounty-api` | `bountyApi.start` | `grids.research.closed.begin` | `bounty_dispatch` |
| `bounty-api` | `bountyApi.status` | `grids.research.closed.status` | `bounty_dispatch` |
| `bounty-api` | `bountyApi.suggestedAddress` | `grids.research.closed.suggestedAddress` | `bounty_suggested_address` |
| `bounty-api` | `bountyApi.removeMember` | `grids.research.closed.removeHunter` | `bounty_member_remove` |
| `bounty-api` | `bountyApi.remove` | `grids.research.closed.unpublish` | `bounty_delete` |
| `bounty-api` | `bountyApi.choosePath` | `grids.research.closed.choosePath` | `plugin-dialog` |
| `access-api` | `accessApi.status` | `grids.credentials.status` | `access_status` |
| `access-api` | `accessApi.create` | `grids.credentials.host` | `access_create` |
| `access-api` | `accessApi.delete` | `grids.credentials.scheduleDeletion` | `access_delete` |
| `access-api` | `accessApi.restore` | `grids.credentials.restore` | `access_restore` |
| `access-api` | `accessApi.signIn` | `grids.credentials.signIn` | `access_signin` |
| `access-api` | `accessApi.signInSso` | `grids.credentials.signInSso` | `access_signin` |
| `access-api` | `accessApi.signOut` | `grids.credentials.signOut` | `access_signout` |
| `access-api` | `accessApi.manage` | `grids.credentials.manage` | `access_manage` |
| `access-api` | `accessApi.account` | `grids.credentials.account` | `access_account` |
| `access-api` | `accessApi.backup` | `grids.credentials.backup` | `access_backup` |
| `access-api` | `accessApi.restoreBackup` | `grids.credentials.restoreBackup` | `access_restore_backup` |

`src/api/access-api.ts` is not changed by any of this. `grids.credentials` calls it, which is
why that grid's answers are handed to the redaction pass in the profile rather than in the call
path, and why `use`, `check` and `reveal` name the command line: they exist on the local wire
only, with no desktop command at all.
