# Moving the four shipped products onto Grid Core

The runbook for a company moving its own grids onto Grid Core: the order the four products move
in, what is compared while both paths run, what stops a rollout, how to go back at every stage,
how long the old record is kept, and which parts of this cannot be written until somebody has run
it against a real deployment.

The shapes this rests on are frozen in [frozen-contracts.md](frozen-contracts.md). Where each
phase stands is in [progress.md](progress.md). The desk bridge's own account of what changes is in
[desk-migration.md](desk-migration.md), and this page does not repeat it.

## 1. What this is, and what it is not

It is a sequence an administrator runs on their own hub computer. Every stage is local, every
stage is reversible, and the one verb that deletes anything refuses until a retention has run out.

It is **not** a switch the vendor throws. This software runs on customers' own computers. The only
calls it makes out of a company's network are two HTTPS GETs for static release files, which carry
no identity and no counts, and the Yougori Network and the Swarm website, which know a signed-in
account and its nodes and know nothing about which grids that account runs or how large they are.
Neither is per-grid and neither is complete. Using any of them as a migration inventory would be a
change to what this product sends and a separate decision nobody has taken.

So one rule shapes everything below: **no stage may depend on the vendor knowing that a deployment
exists.** An installation nobody has ever heard of is protected by the version gate in the two
loaders that have one, `hub::read` and `bounty::read`, which is the Closed Neo Grid, the Sandbox
Grid and Swarm Mining, and by nothing else, which is why that gate is stage 0. The Access Grid's
loader has no gate: its record is **Dropped** in the register, so an older build reads a newer one,
loses what it does not know, and nothing in the rollout says so except the rehearsal, which
compares the version it found with the register.

Nothing is uploaded. There is no vendor bucket and there is not going to be one.

## 2. The frozen contracts

Stage 0 is a document and a check, and it is the foundation of the rest.

Every record the four products write is pinned in `grid/src/core/compat/frozen.rs`, with a fixture
per record and a test that fails when the bytes change. `hub::load` and `bounty::load` now read the
record's version before anything else and refuse one written by a newer build, in a sentence that
names the version. Before this, both were a bare `serde_json::from_slice` and no caller anywhere
read `record.version`, so an older build read a newer record, dropped every field it had not heard
of, and saved that back over it.

The Access Grid's loader still is a bare `serde_json::from_slice`, and those files belong to
another part of this work. Its record is **Dropped** in the register, which is exactly what that
word means: an older build reads a newer one and loses what it does not know. Only the rehearsal
notices, by comparing the version it found against the register.

What the gate cannot do is repair a record that has already been read and saved over. It stops the
next read and nothing else. [frozen-contracts.md](frozen-contracts.md) says what else the freeze
does not cover, including that it begins with this build and says nothing about 1.0.20 and earlier.

## 3. Before you start

- **Who runs it.** The administrator at the hub computer. The commands are
  `yougori rollout ...`; nothing in them is reachable from a member computer.
- **Which vault entries must be present.** Every backup manifest lists, by name, the entries its
  records cannot be used without: the hub key, the hub password, the member token, and for a
  Sandbox Grid the parking and connector entries as well. Prove they are present **before** the
  migration rather than discovering their absence afterwards. This crate cannot read the operating
  system's vault, so the manifest names them and the proving is an operator step.
- **Which version is installed.** The same build on the hub and on every member computer, because
  the version gate, where there is one, refuses a record from a newer build and a half-upgraded
  grid is the one way to meet that refusal by accident.
- **Where the files go.** Everything this runbook writes is under the application's `operations`
  folder, beside the products' own: `survey-*.json`, `rehearsal-*.json`, `backups/<stamp>/`,
  `observations/*.jsonl`, `retired/<stamp>/` and `rollout.json`.

## 4. The eight stages

One profile at a time, one stage at a time. `yougori rollout status` says where each profile
stands; `yougori rollout advance --profile P --yes` moves one on and refuses to skip.

| # | Stage | What it changes | How it is undone | For how long |
| --- | --- | --- | --- | --- |
| 0 | freeze | a document, and a version check in `hub::read` and `bounty::read`; the Access Grid's loader has none | nothing to undo; the check only ever refuses | for ever |
| 1 | survey | one file under the operations folder | delete it | for ever |
| 2 | backup | one stamped folder of copies | delete it, once its retention has run out | until the retention runs out |
| 3 | rehearsal | a scratch folder, deleted when it passes | delete it; it is kept only when something failed, so the failure can be read | not applicable |
| 4 | import | **nothing yet: no command in this build performs an import** | the bridge's own roll back, then delete the realm's database and its key from the vault, neither of which any command does | until the cutover |
| 5 | observation | lines in an append-only ledger | stop the comparator; if the pilot is ending, undo the import as well | until the cutover |
| 6 | cutover | which of the two the product reads | point the product back at its hub | ninety days, unless the administrator asked for longer |
| 7 | retire | where the legacy record sits | put it back, which is what `unretire` does | the same |

**What each stage does, in order.**

0. **Freeze.** Install a build that has the version gate. Nothing else.
1. **Survey.** `yougori rollout survey` reads the records this computer holds, counts them and
   writes one file. It sends nothing. It carries no person's name, no email, no model name, no
   bounty title, no address, no hostname, no certificate, no salt, no hash and no absolute path;
   every path in it is the fixed one from the frozen register, which is the same on every
   computer. There is no flag that adds any of these.
2. **Backup.** `yougori rollout backup` copies each product's record into a stamped folder, reads
   every copy back with the loader that wrote it, records a SHA-256 and a byte count for each, and
   **fails the backup** if any of them does not read. It names the vault entries a restore needs.
   It deliberately does not copy a worker's receipts or a published bounty's source: the product
   deletes both on purpose, and copying them into a plain folder for an operator to carry away
   would undo a privacy measure in the name of safety. Then carry the stamped folder off this
   computer, through the application's own encrypted backup. A backup sitting on the computer
   being migrated protects against a bad migration and not against a bad disk.
3. **Rehearsal.** `yougori rollout rehearse` copies every record and every realm database, runs
   each bridge's real import against the copies, verifies the realm's history, rolls the import
   back, and compares the realm table by table and row by row with what it held before. That last
   check is the one worth having: a snapshot leaves out sign-ins, spent permissions, brokered
   uses, withdrawals, what each computer last said about itself and every generation number, so a
   rollback that bumped a generation would pass a snapshot comparison and fail this one. A record
   is copied with the file system; a realm is copied with SQLite's own `VACUUM INTO`, which gives
   one consistent file with no journal beside it and does not stop the live database.
4. **Import.** The bridge writes a realm beside the hub. The hub keeps serving and keeps owning
   everything. Nothing is placed again: every computer keeps the model it had and every desk
   arrives on the computer it is on.

   **No command in this build does this, or takes it back out.** All four imports and their roll
   backs are library functions, and the only thing that runs them is the rehearsal, against
   copies. `yougori rollout advance --profile P --yes` records
   that an administrator considers themselves at this stage; it moves nothing. The verbs that
   would perform the import and undo it, and the realm identifier a status would name as the
   rollback's target, arrive together or not at all.
5. **Observation.** Section 5.
6. **Cutover.** The product reads the realm instead of the hub. This is the only stage that
   changes what the shipped product does, and the whole risk of the rollout is concentrated in it.
   It is reversible because **no bridge ever writes a hub's record**: every function in
   `compat/` takes it by reference, and the comparisons run the hub's own placement on a copy. So
   after a cutover the grid on the hub is still byte for byte the grid it was, and going back is a
   setting rather than a restore.
7. **Retire.** `yougori rollout retire` moves the legacy record into a stamped folder with a
   manifest and a checksum. It is copied, the copy is read back, and only then is the original
   removed; a loader that refuses the copy leaves both files where they are.

   It goes through the stage machine rather than around it: the verb asks `advance` whether this
   profile may reach the retire stage, so a product with no bridge, a profile whose turn it is
   not, and a profile whose old record is still inside its retention are all refused in the stage
   machine's own words. No shipped product is without a bridge today, so in practice it is the
   last two that refuse; the first is kept so that a product added later without one is refused on
   the day it is added. The recorded stage is written only once the file has actually moved, and
   `unretire` puts the stage back with the record. Without that check the one verb that deletes
   a live record obeyed none of the rules the rest of this page describes.

## 5. Observation mode: what is compared

The hub keeps deciding. The core decides the same question beside it. Every answer the two give
differently is written down instead of being applied.

**Nothing is applied, and the comparison never runs in the pilot realm.** `compat::*::roll_back`
refuses once work has been placed from a computer the import brought in, so comparing inside the
pilot realm would quietly destroy the undo that stage 4 depends on. Every comparison builds a
throwaway realm in a scratch folder and deletes it.

**Both sides are asked in the core's vocabulary.** The hub says `ready` and the core says
`assigned`; which is which is the bridge's own documented translation, tested, and not a
disagreement. The hub's answer goes through that translation first and only then is compared, so
what is left is a real difference about the same question.

Six headings, for every profile:

| Heading | What it asks |
| --- | --- |
| plans | what the administrator asked this grid to do |
| assignments | which computer each thing was put on |
| permissions | what each account may do |
| workloads | what is running, and in which state |
| audit events | what each side recorded about it |
| user-visible answers | what somebody asking the product would be told |

**Models profile.** Plans and assignments are compared for real: `compat::neo::compare` runs
`hub::reconcile` on a copy and `model::reconcile` beside it and reports computer by computer, and
the two are already held to each other by seventeen hand-written grids and three thousand
generated from a seed in the test. A plan's model is compared by an eight-character digest of its
name rather than by the name, because a ledger line never carries a name of anything. The other
four headings produce a line each saying they cannot be asked from a record on disk, and why:

- **permissions**: the Closed Neo Grid has no accounts at all. Computers join with the company
  password and no person signs in, so there is nothing on the hub's side to compare.
- **workloads**: the hub keeps its queue, its running requests and its retries in memory and
  writes none of it to the record.
- **audit events**: the hub hands each event to a callback the application owns and keeps none of
  them in its record.
- **user-visible answers**: this needs both paths serving, and the Phase 3 gate is still open. The
  legacy transport stays behind its compatibility adapter until that adapter is wired and
  streaming parity is verified, so **stage 5 for the models profile is not complete until the
  Phase 3 gate closes**, whatever the ledger says about plans and assignments.

**Workspaces profile.** Plans, assignments, permissions and workloads are compared for real;
audit events and user-visible answers say they cannot be. `compat::desks::compare` is heavier than
the model grid's, and four things about it are worth knowing:

- The core's chooser is exercised by the desks that are waiting for a computer. A desk that is
  already on one is chosen again by neither side: the hub's placer skips it and the core refuses
  to place a workspace that is on a computer. Those rows compare the hub's record with the realm's
  own stored placement, so a placement the bridge did not carry across is a difference under
  assignments, and the comparison says in a note that the agreement is about a placement held and
  not about a choice made.

- It needs a database, because the core's chooser reads the store. It builds a throwaway realm per
  comparison, so it runs on a schedule and samples rather than watching.
- It places in the hub's own order, one desk at a time, committing each placement before choosing
  the next, because `desks::place` walks the list and changes it as it goes.
- It writes three things into the scratch realm that the import deliberately does not: each
  computer offers the share bounded by what it has free right now rather than the raw share the
  admin agreed; each desk already on a computer holds a reservation there; and every account is
  allowed to place work. Without all three the two sides are not being asked the same question.
  What a realm that owned these desks should actually grant is a decision for the cutover, and the
  comparison does not pretend to make it.

**Research profile.** Two headings can be asked from a record on a disk and four cannot. What a
bounty host published is put beside what the realm would hold, file by file and computer by
computer, which is what would catch a bridge that lost a digest or a finding. What those lines are
not is two deciders asked the same question: a joined computer chooses its own model and works the
whole source, so the host decides nothing a realm also decides, and the notes say that in those
words. The four that cannot be asked say so and why, including that no worker may be run, started
or tested in this repository at all.

**Credentials profile.** Three headings can be asked and three cannot. The hub's own
`policy::evaluate` and the realm's credential and permission are asked the same question for every
person and every credential, and both answers are put in the same three words: at once, an approver
decides, or nothing. The rules are compared by what they decide and by how many methods they name,
with the path as a digest, because an observation never carries a path. A credential a realm holds
none of produces a line saying the question could not be asked rather than a difference.

Both still produce a line under every one of the six headings, because a ledger that is silent
about a question and a ledger that says the question could not be asked read very differently to
whoever has to decide whether a rollout may go on. Section 7 says what each bridge cannot carry.

### What counts as a difference worth stopping for

Three bands, and the rule for sorting into them is mechanical. It is `observe::judge`, in one
place, and nothing else decides.

**Agrees.** The two sides said the same thing.

**Noted, and the pilot continues.** Two cases only:

- under **permissions**, the core allows a subset of what the hub allowed. Less is the direction a
  migration is allowed to err in. This is where a Sandbox Grid administrator becoming a workspace
  administrator and an operator, rather than the realm's owner, lands;
- under the four headings that are neither assignments nor permissions, a difference where one of
  the bridge's own notes names a word that differs and that word is not an identifier a grid
  minted.

**Stop. End the pilot for that profile and roll the realm back.** Everything else, including:

- **any difference under assignments.** Where a computer, a model or somebody's desk is put is the
  thing the whole migration is about, and a reason to place it differently belongs in the notes an
  operator reads rather than in a decision to carry on without reading them. A difference between
  two identifiers can never be explained away by a note, because a note is a sentence about a
  whole grid and never names one computer;
- under **permissions**, anything the core allows that the hub did not, even when it looks
  harmless;
- a difference nobody meant and nobody wrote a note for. That is the safe direction and it will
  cost false stops; the cost of the other direction is somebody's work.

### When a pilot has actually run

A time-only gate is passed by doing nothing, so the gate is time **and** coverage.
`yougori rollout coverage --profile P` reads the ledger and reports both. It asks for at least
fourteen days, and for the window to have contained something joining, something leaving and
something moving, with no stop outstanding.

Every number there is a proposal. Nothing in this repository has watched a real grid for any
length of time, and whether an ordinary company's fortnight contains all three situations is
exactly the thing that cannot be answered from here. The coverage reading also says what it cannot
see: a computer that joined and left between two passes was never in the ledger at all, because
the ledger holds what each pass looked at and nothing in between.

## 6. Going back, at every stage

The table in section 4 has one row per stage with what undoes it. Three things are worth saying
beyond it.

**Nothing here can be run from a command line yet.** `compat::undo_for` and both `roll_back`
functions are library code; no verb calls either, and no verb performs the import they would undo.
What follows is what the bridges do when something runs them, which today is the rehearsal, on
copies.

**A rollback survives a restart.** What an import created is the only thing that can undo it, and
until this phase it existed only in memory: an import could be taken back out on the day it ran and
never afterwards. It is now written into the realm's own database as part of the import, beside the
event that records it: at schema version 11 for the two grids, and at schema version 12, which
widened the one column that says which bridge ran, for the bounty host and the Access Grid. So the undo travels
with `Core::backup`, it cannot be separated from the realm it describes, and it is still there
after a crash, a restart or a reboot. `compat::undo_for` reads it back, and the database refuses an
edit to it. The row goes when the import is undone; what happened stays in the history.

**What a rollback cannot undo is the history.** `audit_events` refuses an update and refuses a
delete until the events have been exported, so a pilot that goes wrong leaves permanent evidence
that it happened. That is the intent, and whoever starts a pilot should be told before rather than
after.

**The refusals are built into the bridges and are quoted here in the words an operator sees.**
Each names what to do.

| Refusal | What it means |
| --- | --- |
| Somebody is in one of the workspaces this import brought in, so the import cannot be undone | Close the sessions and run it again, or decide the realm is now the grid. |
| Work in this grid was placed from a computer or an account this import brought in, so the import cannot be undone | The realm has started being used. Let the work finish, or decide the realm is now the grid. |
| Somebody has enrolled a computer of their own against an account this import brought in, so the import cannot be undone | A real computer has joined the realm. Taking the account out would leave that computer naming nothing. |
| A credential this import brought in has been used, so the import cannot be undone | The realm has started brokering. Taking the credential out would leave the record of that use naming nothing. |
| This import carried decisions somebody made, and a realm writes a decision once and never withdraws one, so the import cannot be undone | Delete the realm and its key instead. Carrying the Access Grid's log is the one import that cannot be taken back out, which is why it is not the one the rehearsal runs. |
| The scope this import brought in has been frozen, and a frozen scope is what somebody agreed to, so the import cannot be undone | Somebody in the research realm has agreed to this scope. Close it there, or decide the realm is now the grid. |

For a pilot realm that holds nothing but the import, the simplest undo is deleting the realm and
its key. `roll_back` is for a realm that was already in use. For a research realm it is the only
undo that leaves nothing behind, because a research realm closes a scope, withdraws an admission
and disposes of a source and deletes none of them; the rehearsal names those tables before the
trial runs rather than reporting them as a rollback that failed.

## 7. The order the four move in, and what each bridge cannot carry

**Closed Neo Grid, then Sandbox Grid, then Swarm Mining, then Access Grid.** The order is enforced
by `rollout::advance` rather than recommended: a profile cannot reach the import until the one
before it has reached its cutover.

1. **Closed Neo Grid first.** Its bridge is the most finished thing in `compat/`: comparison mode
   exists for placements and for new plans, and agreement is already tested against seventeen
   hand-written grids and three thousand generated ones. Its blast radius is the smallest in the
   product: a wrong placement sends a model to a different computer, which costs a download.
   Nobody's files are involved and weights can be fetched again. It is also the only profile whose
   comparison is a pure function, so observation is cheap enough to run often.
2. **Sandbox Grid second.** The same record type and the same hub implementation, so everything
   learned in (1) applies. The stakes are higher, because a workspace holds somebody's work, but
   its bridge exists, its runbook exists, and the part that would be risky is the part the
   migration deliberately does not touch: a packed desk arrives as a key, a size and a checksum,
   and no byte of anybody's work is read, copied or written.
3. **Swarm Mining third**, and the reason is about this repository rather than about the product:
   the standing rule for this work forbids running, starting or testing a worker here, so its
   observation mode cannot be exercised on this machine at all. Leading with the product whose
   pilot nobody here can watch would be the wrong way round.
4. **Access Grid last.** It is the only one holding credentials and its worst failure is the worst
   of the four: a stored secret reaching a workload, or an approval self-issued while another
   approver existed. It is also the least in need of the core, because it already has its own
   encrypted backup and its own tamper-evident log. Last means it inherits whatever the three
   pilots before it hardened.

This is deliberately not the phase order in [plan.md](plan.md), which puts credentials at 5 and
research at 6. Phase order is about building; this is about moving customers, and those are
different questions.

### Swarm Mining: what the bridge carries, and what it cannot

`grid/src/core/compat/bounty.rs` has the same four operations the other three have: rehearse,
import, roll back and compare. It reads `bounty::Record` by reference and nothing in it starts a
worker, offers work or reaches a network; the only thing it does with the published files is decode
and hash them, through the product's own `bounty_project::snapshot`, so the manifest says what that
component reported rather than what the bridge guessed.

**What it carries.** Each joined computer becomes an account and a computer, and the computers
become hosts that offer nothing, because the host never recorded how large one is. The published
files become a `research::Source` with a manifest of every path, digest and size, under a
`research::Scope` whose name, purpose and authorisation are the bounty's own words. Each finding
becomes a `research::Finding` against that exact source, naming the computer that reported it, with
the model that found it kept beside it and the severity read from the word the worker chose.

**What it cannot.**

1. **The scope arrives a draft, and a draft places nothing.** A frozen scope is one a second person
   agreed to over its digest, and a bounty host has one administrator. So the scope comes across
   unfrozen, the request that would let its source in is written still waiting, and nothing can be
   placed under it until somebody in the research realm decides that request and freezes the scope.
   A migration does not invent the second person.
2. **A research realm is a separate trust boundary with its own key**, and the bridge refuses
   anything else. `Capability::allowed_in` keeps research out of a company realm, the realm's own
   database says the same to anything that opens the file, and `compat::bounty::import` says it in
   words before a row is written. Creating that realm and keeping its key is the application's
   decision and not this crate's.
3. **The worker side is the application's.** `swarm/workers.json`, `swarm/events/` and
   `swarm/receipts/<worker-id>/` are written by the engine, and the receipts hold a project's
   output and test input, which is why the product deletes them with the worker. None of it
   crosses, so no finding rests on an artifact.
4. **The host keeps no review of a finding**, so every finding arrives submitted and unreviewed.
   Accepting or rejecting one is the research realm's own decision.
5. **Its observation mode cannot be exercised here at all.** No worker may be run, started or
   tested in this repository, so this bridge has only ever run against records and fixtures and
   never beside a host that is serving.

**Its undo is deleting the realm, not emptying it.** A research realm closes a scope, withdraws an
admission and disposes of a source, and deletes none of them; a finding stays in the record. The
realm's own triggers say each of those to anything that opens the file. So `roll_back` closes the
scope, withdraws the admission, disposes of the source and takes the computers back off, and leaves
the record where it is. The rehearsal names those tables before the trial runs rather than
reporting them as a rollback that failed. A bounty is brought across into a realm created for it,
so the way to leave nothing behind is to delete that realm and its key, which is what the import
stage's own undo sentence already says.

### The Access Grid: what the bridge carries, and what it cannot

`grid/src/core/compat/access.rs` has the same four operations, reads `access::hub::Record` by
reference and changes nothing in it. Nothing in this phase edits an Access Grid file; those belong
to another part of this work.

**What it carries.** Each person becomes an account with roles, each remembered computer becomes a
computer in the realm, each credential becomes a `core::credential::Credential` naming a vault
entry, a destination, the methods and paths its rules allow and whether every use needs an
approver, and each rule becomes a `core::credential::Grant` for every person it covers. Where the
caller hands in lines of the grid's own activity log, the decisions in them become requests and
decisions in the realm and the rest become events in its history.

**What it cannot.**

1. **No value crosses, and a credential arrives unusable until somebody fills it in.**
   `access::policy::Credential` holds its value sealed with the key in that computer's vault, and
   `core::credential::Credential::is_a_reference` is checked at the realm's door, so nothing with a
   value in it reaches a realm at all. What crosses is the name of a vault entry nobody has written
   and a fingerprint that matches no value, so the broker refuses that credential in words until an
   administrator puts the value in the entry and records what it fingerprints to. That is a
   refusal, never a wrong send. Where this company's secrets should live is a decision, and a
   migration does not make it quietly.
2. **A rule that says ask becomes a credential that asks every time.** The hub decides per rule and
   a realm decides per credential, so one asking rule makes the whole credential ask, and people
   whose own rule allowed them at once now wait for an approver. That is less than the hub allowed,
   which is the direction a migration is allowed to err in, and the rehearsal counts it.
3. **An Access Grid administrator does not become a realm administrator.** They become a credential
   administrator, a credential approver and an auditor, which is everything they could do with
   credentials, rules and the record. Adding and removing accounts is `ManagePeople`, which only a
   realm administrator holds, and that is wider than the Access Grid ever granted.
4. **A credential the hub mints a short-lived one from crosses as what it is, settings and all,**
   because a realm brokers the same three kinds now. What does not cross is one whose settings a
   realm will not hold: a realm checks a token endpoint, a client identifier, a region and a role
   on the way in, and recording one that failed those checks would be writing down a row that
   reads as working and refuses on first use. Those are counted and named in the rehearsal's
   notes, credential by credential and check by check, rather than stopping the whole import.
5. **A credential that travels in the URL arrives unsendable.** The hub puts a query credential's
   value in the URL on nobody's say-so. A realm needs an administrator to allow that credential by
   name, because the copies the service's access log and every proxy in between keep are not the
   grid's to delete. So each one arrives recorded and refused until somebody allows it, which the
   rehearsal counts.
6. **Two-step secrets, remembered sign-in tokens, the identity provider's settings, an hourly limit
   and a rule that lets somebody see a value** have no counterpart in a realm, so none of them
   crosses.
7. **Two tamper-evident logs cannot verify one another.** The hub keeps `access::activity`, sealed
   its own way; the realm keeps `core::audit`, sealed with the realm's key. The lines this bridge
   carries are sealed by the realm as lines it was told, never as events it witnessed, and the
   observation ledger says that under its own audit heading rather than putting the two side by
   side as though either vouched for the other.

**An import that carried a decision cannot be taken back out.** A realm writes a decision once and
never withdraws one, which its own database enforces, so `roll_back` refuses outright rather than
half-undoing. An import handed no lines of the log is the ordinary one and is fully reversible, and
that is the one the rehearsal runs: a rehearsal copies the products' records and the activity log
is a file of its own, which it does not copy.

## 8. Retention, and the read-only tools that never go away

**Nothing legacy is deleted at a cutover.** The record is left exactly where it is and the product
simply stops writing it. At `retire` it moves into a stamped folder with a manifest and a
checksum. It is deleted only when somebody runs `yougori rollout forget --stamp STAMP --yes` and
the retention has run out.

**One product per stamped folder.** The folder's manifest describes one retired record, and
`forget` deletes the whole folder on the one retention that manifest names, so a second record
landing in the same folder would be unreachable by `unretire` and deleted on somebody else's
clock. Retiring into a folder that already holds a record is refused, and the engine gives each
folder a name only one product can take so that nobody meets the refusal.

**The retention is ninety days by default and thirty at the shortest.** `--keep-for-days` sets it
and the manifest records when it expires. `--force` is the only override; whoever uses it is
expected to record why. Ninety days is a proposal: it is not measured, and nobody has reviewed it
against whatever retention obligations a customer has.

**There is no automatic path that deletes a customer's record.** No timer, no cleanup on upgrade,
no cleanup on uninstall, no sweep. `forget` is the only function in this phase that deletes
anything and nothing calls it. The absence of a feature is a promise that is easy to lose, so it is
written down. Two deletions the product already does on purpose are carved out and are not covered
by this promise: a worker's receipts go with the worker, and a published bounty's imported source
is deleted after a day. Both hold somebody's project, which is why they go.

**The reading tools stay.** `hub::read`, `bounty::read`, `access::hub::load` and
`store::legacy::read` stay and stay able to read every frozen version; a test reads every fixture
with the current build. `yougori rollout read --product P [--stamp STAMP]` prints a record's
version, its grid's identifier and its counts without starting a hub, and a test proves it leaves
the folder listing and every file's size exactly as they were. It opens only records under this
computer's own Yougori folder: a record found anywhere else is copied in first, which is one step
and keeps the door from being a way to read any file on the computer.

## 9. What cannot be written here, and must stay marked unmeasured

No customer deployment exists in this repository or on this computer. These are carried as open
questions rather than quietly filled in.

- **How long each stage takes** on a grid with real numbers of computers and desks, and therefore
  whether a cutover fits a maintenance window. Nothing here was timed against anything.
- **Whether taking a consistent copy of a realm under write load contends with its writers.** No
  realm here is under load.
- **Whether fourteen days and the three situations are the right gate.** Until a real grid runs
  it, the three bands are a prediction about differences nobody has seen.
- **Whether ninety days is the right retention.** It is a default this phase proposes.
- **The live view of a Sandbox Grid's computers.** `hub::host_views` is built from presence the hub
  keeps in memory: whether a computer was heard from recently, what it reported, whether somebody
  is using it, whether it is on battery. None of that is in the record, and the hub does not hand
  it out. Until that is wired, observing the workspaces profile from a record on disk proves one
  thing only: that both sides refuse to place a desk on a computer that has said nothing. The
  comparison takes the live views as an argument so that a caller which has them can ask the real
  question; nothing in this repository has them.
- **Whether a member computer that is offline through the whole cutover rejoins cleanly.** That
  needs more than one computer.
- **Whether a Sandbox Grid's parked data is still fetchable after a cutover.** That needs the
  company's bucket and its credential, and nothing here reaches either.
- **Anything about the Access Grid's identity provider.** Those are live tenants.
- **Every connector row.** None is live-tested, none can be from here, and no stage of this
  rollout requires one.
- **The wording of these commands.** It should be settled after somebody has run them once.
