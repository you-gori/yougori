# Grid Core: the staged plan

How the four products become one backend with four capability profiles and one tab, without
breaking what is shipped. Each phase lands on its own, behind a flag, with the products still
working. The architecture is in [ADR 0001](0001-architecture.md); what is being protected is in
the [threat model](threat-model.md); the starting point is in the [baseline](baseline.md).

## State

| Phase | What it does | State |
| --- | --- | --- |
| 0 | Preserve the working tree, write the architecture, threat model, adapter matrix and baseline | **Done**, 18 October 2026 |
| 1 | The Grid Core: realms, identity, capabilities, work, audit, store | **Done**, first landing |
| 2 | Storage: one database per realm, versioned migrations, the credential storage contract | **Done**, 19 October 2026 |
| 3 | Model serving on the core | **In progress**, core profile and placement seam |
| 4 | Workspaces on the core | |
| 5 | Credential brokering on the core | **In progress**, the broker and schema version 5 |
| 6 | The research realm on the core | **In progress**, the research profile and schema version 6 |
| 7 | One set of engine commands and one CLI group | |
| 8 | One TypeScript API | |
| 9 | One Grids tab and the create wizard | |
| 10 | The adapter framework and connectors, read-only first | |
| 11 | Security verification and threat testing | |
| 12 | Reliability, scale and operations | |
| 13 | Migration and rollout of the four shipped products | |

## Phase 1, as landed

`grid/src/core/` holds, with 17 tests that need no profile:

- **`realm.rs`** — a realm is one trust boundary: its kind (company or research), the capabilities
  its owner turned on, its network policy, its lifecycle and the fingerprint of its key. A company
  realm cannot take on research, and a research realm starts offline.
- **`identity.rs`** — principals, devices with attestation, and eleven roles bound to sixteen
  actions (the eleventh and the sixteenth arrived with Phase 6: a researcher, who does research
  and approves nothing, including their own).
  Approving is its own permission, which an administrator holds so that a realm is never stuck
  with nobody able to decide, and which never lets anyone decide their own request while someone
  else can. A computer that proved nothing about itself is reported unverified, never assumed
  safe. These rules follow the Access Grid's, so the credential profile inherits them unchanged.
- **`capability.rs`** — short-lived permissions signed with the realm's own key, naming the realm,
  capability, principal, device, workload, resource, destination, method, path, size, approval and
  expiry. Every claim is checked again at the moment of use, single-use permissions are spent, and
  a permission from another realm fails on its signature.
- **`work.rs`** — resources, hosts and how a computer was committed, GPU isolation that the
  scheduler must know before sharing a card, leases with generations, and one workload lifecycle
  with the legal transitions written down.
- **`approval.rs`** — someone else must agree to a credential request or research scope while
  anyone else can; where nobody else can, the approval is recorded as self-issued. An approver
  may agree once, or allow the same narrow thing for up to a day, which becomes a standing
  allowance naming who agreed and to what. Requests that need an approver every time are never
  covered by one. Unanswered requests lapse.
- **`audit.rs`** — one event per decision, each sealed with the realm's key over its own fields
  and the seal before it, with verification that names the first event that was altered, removed
  or reordered. Keyed rather than a plain hash chain, so someone who can edit the file cannot
  re-seal what they changed.
- **`store.rs`** — one record per realm, written to a temporary file, flushed and renamed; a
  record from an older build is migrated on a copy with the original kept beside it; a record from
  a newer build is refused rather than guessed at; backups carry no key and restore only with it.

Nothing in the shipped products calls this yet. It is additive, and the four hubs are untouched.

## Phase 2, as landed

A realm now lives in a database of its own. `grid/src/core/store/` holds the shape, the steps
between versions, and the shape a realm travels in; `grid/src/core/credential.rs` holds what a
credential is. Thirty-five tests cover both, still with no profile and no product wiring.

- **One database per realm**, in write-ahead logging mode with every commit flushed. Each change
  is one transaction: a decision and the standing allowance it creates land together or not at
  all. A copy taken mid-flight, journal and all, opens as the last committed state.
- **Versions and steps.** A `migrations` table records every version the database has been
  through. A step and the record of having run it are the same transaction, so a step that fails
  leaves the database at the version it was already at, with the half that had run undone. A
  database from a newer build is refused rather than guessed at.
- **Generations instead of hunting.** Withdrawing trust from an account, a computer or the whole
  realm raises that subject's generation and writes a row saying who did it and when. A permission
  issued under an older generation is refused the next time it is used; nothing has to be found
  and deleted. A permission unknown to the realm is refused outright, which is what makes a
  restore safe.
- **Decisions stand as made.** There is no path in the code that changes or removes one, and the
  database itself refuses an update or a delete. The same guard holds for recorded events, which
  may only be dropped once they have been exported somewhere this computer cannot reach.
- **The chain's own details are kept apart** from the realm's ordinary records: which vault entry
  holds the sealing key, which version of it, where the chain has got to, and how far it has been
  exported. The key is never in the database. Whoever can edit the file can drop the guards; the
  seal is what they cannot forge, and verification names the first event they touched.
- **What survives a restart.** Which single-use permissions have been spent is in the database,
  so restarting no longer hands anyone a second use of one.
- **Administering and approving are separate rows.** An administrator holds the approving
  permissions, each naming the role it came with, so either can be taken back on its own.
- **A record from the first core is brought across** on opening: the database is built from it,
  the history is carried over sealed as it was, and the record is kept beside it under the version
  it was written in. The wrong key, a newer version or a tampered history all stop the migration
  before anything is written.

**The credential storage contract** is in, and nothing more: no broker, no connectors, no UI.

- A credential is a reference. What is stored is the vault entry holding the value, which version
  of it, a fingerprint, the one destination it may be sent to, and who may use it for what. There
  is no column for a value, and a test fails if one is ever added.
- Using one needs both a grant and someone's agreement. Agreeing once is agreeing to one use,
  which is known from the permission that names that agreement, not by changing the decision.
- A credential may be marked as needing an approver every time; no standing allowance covers one.
- Rotation moves which version of the vault entry is current. Retiring takes a credential out of
  use and deletes nothing.

## Phase 6, as landed

The isolated research realm is a core profile at schema version 6, in `grid/src/core/research.rs`,
with twenty-four tests and no worker, container, machine or network connection anywhere in them.
The whole of it is in [progress.md](progress.md); what matters most is said here too, because it
is the one phase where a misreading would be dangerous.

- **A code and trust separation, and nothing else.** Nothing in this profile weakens, bypasses or
  disables any model's safety behaviour. There is no model invocation in it, no prompt, no system
  message and no setting that could become one, and a guard test fails if one ever appears. The
  test proves those words are absent from the profile and its schema; it does not prove a model is
  safe and is not offered as that.
- **Nothing is inherited**, because the two realms are two files holding two keys. A permission
  from one is refused by the other on its signature, both ways.
- **Offline until a destination is explicitly admitted**, one at a time, on somebody else's
  granted decision, with the realm's stated policy kept equal to what is actually admitted. Every
  address that can only ever mean a machine near us is refused: the private, loopback, link-local
  and deprecated site-local ranges on both families, the unspecified addresses `0.0.0.0` and `::`,
  broadcast and multicast, the rest of `0.0.0.0/8`, the deprecated `::a.b.c.d` form, the names that
  only mean a local machine, and plain `http://`. Both doors onto the realm's policy, `Core::set_network` and
  the broker's `Core::set_egress`, ask the same question, because a second way in would be a way
  around it.
- **One approval mechanism.** Admissions, freezing an authorisation and reviewing a finding are
  all `Core::ask` and `Core::decide`, marked so that no standing allowance can cover them. A
  request is decided under the action it was asked for and spent only on that action, so approving
  a credential and approving research stay two permissions and not one.
- **Scanning is recorded, never performed.** There is no scanner here, and the record says who
  looked and what they said.
- **Isolated execution is a seam.** The core writes the plan and holds no process; the four
  enclosure shapes have rows in the adapter matrix in their true state.

## What each later phase must not break

The exit gates from the plan, kept where they can be checked:

**Phase 2, storage.** No destructive migration without a verified backup; a dry-run report before
anything is written; every old record keeps an owner until its profile has moved. *Met for the
core: `Core::rehearse` reports what a migration would bring across and writes nothing, the record
is kept under the version it was written in, and the key and the history are checked before
anything is built. Each product's own records still move in its own phase, and each one ships its
own rehearsal.*

**Phase 3, model serving.** Existing plans migrate without changing where models run. The
OpenAI-compatible API behaves as it does today, streaming included. No prompt or answer is written
to disk unless policy says so. The first core landing now provides the durable model plan and
sticky host assignment profile, model-plan admission as ordinary model work, and plan-constrained
leases. Work that belongs to a plan is placed only on that plan's computers whichever way a
reservation is asked for, so a runner cannot reach a different model's computer by taking the
generic path. The legacy hub and OpenAI-compatible transport remain behind their compatibility
adapter; the Phase 3 exit gate is still open until that adapter is wired and streaming parity is
verified.

**Phase 4, workspaces.** Desks stay usable across the move. A failed computer does not lose who
owns a workspace. A stale assignment cannot reclaim a newer workspace. Dedicating a computer is
explicit, reversible, and never means handing over the person's own files.

**Phase 5, credentials.** No stored secret reaches a workload. Destination, method and path are
checked after approval and immediately before the request is sent. Approval cannot be self-issued
while another approver exists. Revocation stops the next request.

**Phase 6, research.** A token from the research realm is refused by the company realm, and the
reverse. The research realm cannot reach the credential broker, cannot address the company's
computers, and is offline unless its own policy opens it. Changing the source or the scope
invalidates acceptance. A stop reaches the running work and leaves the evidence. *Met for the
core, with one half named rather than claimed: `grid/src/core/research.rs` and schema version 6
hold scopes with limits and an authorisation a second person agreed to, admissions that each name
the one decision that let them in, acquired source with its manifest and its dependencies,
artifacts with insert-only verdicts about them, findings reviewed through the ordinary approval
machinery, and one sealed document that leaves. The stop moves rows and withdraws permissions;
stopping an enclosure is the engine's half of it, and `research::Enclosure` is where that seam is.
This is a containment boundary and nothing else: no setting here reaches how any model behaves,
and a guard test fails if one ever appears. The gate stays open until the product calls any of it.*

**Phase 7 to 9, surfaces.** Old commands keep working as aliases for at least one major release.
The UI never offers a capability the realm has not enabled. Old routes redirect into the one tab.
*Met for the command namespace: `yougori grids ...` is twelve wire methods over all four products,
every shipped word still reaches the handler it reached before, no old command says it is old, and
a command a grid cannot do is refused in words after the grid is found and before one argument of
the command is read. What the CLI offers for a grid is built from what that grid does. The tab and
the TypeScript client are Phases 8 and 9; see [ADR 0002](0002-one-namespace.md).*

**Phase 10, connectors.** Read-only discovery before any mutation, a credential reference rather
than a value, a dry run that shows what would change, and a row in the matrix in its true state.

**Phase 12, reliability, scale and operations.** A published size for every thing a realm holds,
each one a constant the core enforces or warns against rather than a number in a document. No
question about one row answered by reading a whole table, and no whole table read inside a loop
over computers, with a test that counts what the database was asked rather than only checking the
answer. A liveness check that cannot be made expensive by accident and never verifies the history.
Every number a realm reports coming from a named query, with what it does not mean written beside
it. An upgrade that takes a copy first, a restore drill that says what a restore does not bring
back, and one operations document. And it says plainly, in the product and in the document, that
one database per realm on one computer is not high availability. *Met:
[operations.md](operations.md) is the document, schema version 10 is the indexes, and the counted
tests are in `grid/src/core/bench/tests.rs`. What was not done is in that document's last section,
including that no size was measured at its limit. The line that used to stand here, that the
connector seam had no timeout, retry or backoff, was already half wrong when it was written and is
now wrong altogether: every provider call had a timeout all along through `https::call`, and the
seam now carries a budget, a breaker, a cap on concurrent calls, a deadline over a whole operation
and the provider's own throttle.*

**Phase 13, migration and rollout.** The on-disk shape of every record a shipped product writes
frozen in code, with a fixture per record and a test that fails when the bytes change, and a
loader that refuses a record from a newer build rather than reading it and saving it back without
the fields it did not know. An inventory a customer takes of their own deployment, because the
vendor cannot enumerate installations and no stage may depend on knowing that one exists. A
rehearsal that runs the real import and the real rollback against copies and proves the realm
came back table by table. A backup that is read back with the product's own loader before it is
called a backup. Observation mode for every profile, with one place that decides which band a
difference falls into and a placement difference always stopping. A rollback that survives a
restart. And no automatic path that deletes a customer's record, ever. *Met:
[rollout.md](rollout.md) is the runbook, [frozen-contracts.md](frozen-contracts.md) is the
register, and schema version 11 is what makes an import undoable after a restart, which version 12
widened so an import may say that an Access Grid or a bounty host is what it brought across. All
four products have a bridge. What was not done: the research bridge builds a draft scope and cannot
freeze it, because freezing one needs a second person to agree and a bounty host has one
administrator; the credentials bridge carries no credential value, because a realm refuses to hold
one, so every credential arrives unusable until an administrator fills in its vault entry; and
every duration in the runbook is unmeasured, because no deployment exists here.*

## Sizing, honestly

- Phases 2 to 6 are the bulk: each moves a product's lifecycle onto the core with a migration and
  a rollback, and each is a release of its own.
- Phase 10 is open-ended. Four connectors exist and are mock-tested. The rest of the matrix is a
  roadmap, and saying otherwise in the product would be false.
- A multi-node control plane is a separate decision from this consolidation. It stays behind its
  own flag and does not block any phase above.
- Migration touches a released version. Every phase that moves a record ships with a dry run, a
  backup, a rollback and a runbook, or it does not ship.
