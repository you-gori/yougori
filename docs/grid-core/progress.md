# Grid Core: where each phase stands

One row per phase of the consolidation. This file is the honest record: a phase is only done when
its exit gate is met and its tests prove it, and anything that cannot be done in this repository is
written down here rather than quietly dropped.

The architecture is in [ADR 0001](0001-architecture.md), the staged plan and its exit gates are in
[plan.md](plan.md), what is being protected is in the [threat model](threat-model.md), and the true
state of every integration is in [adapters.md](adapters.md).

## Where this stands, in one paragraph

Every phase from 0 to 13 has been built. The core exists, all four profiles sit on it, there is one
command namespace, one typed client, one Grids area, a connector seam with an honest matrix, a
security pass that found and fixed real defects, an operations document, and the machinery to move
a shipped product across and back again. What has not happened is the move itself: the four hubs
still serve every customer, and no page or command yet reads a realm from the core in anger. Rows 4
to 9 therefore say what landed rather than "done", because their exit gates ask whether the product
uses the core, and today it does not. That is the next and last step, and Phase 13 is the thing
that makes it safe: rehearse on a copy, back up, run both paths in observation mode, enable one
profile, and keep the rollback for the whole retention period.

## Production readiness, since the phases landed

A pass over the gaps each phase wrote down for itself has closed the ones that stood between the
work and a real deployment. The two products that could not migrate now can: the Access Grid and
Swarm Mining bridges are built to the same standard as the model and sandbox bridges, so all four
rehearse, import, roll back and compare. The credential broker now carries the minting kinds the
shipped Access Grid carries, so moving a customer across loses no feature: an OAuth client
credential, a GitHub App key and an AWS signing key are each turned into a short-lived token in
memory, wiped when it is let go, and never written to the database, a log, an audit reason or a
backup. The robustness holes are closed: a stale computer can no longer complete work that moved
on, because advancing work is keyed on the reservation it holds now; an offline research realm's
history no longer grows without bound, because an operator can carry it off in a verified bundle
without weakening the rule that an unexported event is never dropped; a provider call has a timeout
and a circuit breaker; a full disk is refused where it matters with a sentence an operator can act
on; and the health and readiness checks are served on the loopback interface so a monitoring agent
can scrape them. On the frontend, the rollout and migration view now renders in the Grids area, and
the first real page, model serving, reads through the typed client, which is the first step of the
cutover rows 4 to 9 still await.

## State

| Phase | What it does | State |
| --- | --- | --- |
| 0 | Preserve the tree, write the architecture, threat model, adapter matrix and baseline | Done, 18 October 2026 |
| 1 | The Grid Core: realms, identity, capabilities, work, audit | Done, 18 October 2026 |
| 2 | Storage: one database per realm, versioned migrations, the credential storage contract | Done, 19 October 2026 |
| 3 | Model serving on the core, and the legacy hub as a compatibility adapter | Done, 19 October 2026 |
| 4 | Sandbox Grid workspaces on the core | In progress, profile and migration landed 19 October 2026 |
| 5 | Access Grid credential brokering on the core | In progress, broker and migration landed 19 October 2026 |
| 6 | Swarm Mining as an isolated research realm | In progress, the research profile and migration landed 19 October 2026 |
| 7 | One engine command namespace and one CLI | The twelve methods, the one CLI and the alias table landed 19 October 2026; no page has moved yet |
| 8 | One TypeScript API | The client, the shims and the generated guide landed 19 October 2026; the model serving page now reads through the typed client, the first page to move |
| 9 | One Grids tab and the create wizard | The one area, the wizard, the dry run, the realm status, the timeline and the rollout and migration view landed 19 October 2026; each grid is still served by its own hub |
| 10 | The connector interface and the enterprise adapters | The seam, the read-only cloud and storage adapters, the SCIM client, hardware discovery, audit export, connector tasks and the sweeper landed 19 October 2026; nineteen rows are exercised against something on this computer and none against a real system |
| 11 | Security verification and threat testing | The threat model rewritten against the code, the attack tests, the authorisation invariants, the fuzz harnesses and the recovery gaps landed 19 October 2026; five defects found and fixed. A verification pass, not an audit |
| 12 | Reliability, scale and operations | The sizes, the indexes at schema version 10, the targeted queries, the counted benchmarks, health and readiness, the reading, upkeep, the upgrade copy, the restore drill and [operations.md](operations.md) landed 19 October 2026; no size was measured at its limit and nothing about high availability changed |
| 13 | Migration and rollout | The frozen contracts, the version gates, the self-survey, the rehearsal on copies, the per-product backup, observation mode for every profile, the eight stages with a rollback that survives a restart at schema version 11, the retention and the read-only reading tools landed 19 October 2026; the research and credentials bridges landed 19 October 2026 at schema version 12, so all four products rehearse, import, roll back and compare; a research scope arrives a draft, no credential value crosses, and every duration in the runbook is unmeasured |

## Phase 3, as landed

The legacy Neo Grid hub became a compatibility adapter rather than being replaced.
`grid/src/core/compat/neo.rs` translates a hub record into core principals, devices, hosts, model
plans and placements, rehearses the move without writing anything, imports it, and rolls it back
again. Comparison mode runs both placement algorithms over the same grid and reports, computer by
computer, whether they agree, which is the mechanism Phase 13 needs for observation mode.

Agreement is the point, so it is tested twice: a table of seventeen shapes of grid, and three
thousand grids generated from a seed held in the test, with no clock and no random number
generator, so a failure can be reproduced exactly. Where the two algorithms genuinely had to
differ, the difference was closed rather than hidden: picking a computer now takes it off the plan
that had it, a plan left with no computers is removed, tie-breaks follow join order rather than a
random identifier, and a computer that leaves the grid is taken out of every plan that picked it.

Model requests gained the reliability behaviour they lacked: a request whose computer goes quiet
moves to another computer in the same plan and never back to the one that just failed, a request
has a deadline, a person can cancel their own, and a reservation that lapses no longer leaves work
running for ever. The legacy hub's own logic was not touched; it gained visibility and nothing
else, which the parity tests and its own tests both hold to.

## Phase 4, as landed

Sandbox Grid workspaces are a core profile at schema version 4. `grid/src/core/workspace.rs` holds
what a workspace is, and `grid/src/core/store/schema.rs` holds the seven tables that keep it. It is
additive: nothing shipped calls it yet, and the Sandbox Grid hub still owns every desk.

Three properties are the point, and each has a test that fails if it stops being true.

**A person's files are never in the realm's database.** While a workspace runs, its disk is the
sandbox disk on the computer that holds it, named here by whatever that computer calls the sandbox.
While it moves, it is one packed file with the hub or in the company's own bucket, recorded as a
key, a size and a checksum. The test reads the database file and the journal back and finds the
checksum and not what it hashes. The column names of all seven tables are checked against a
forbidden list, and the database refuses a key that is rooted, a drive letter, a backslash or a
step up out of wherever it started.

**A placement that has been left behind can never reclaim a workspace.** Two generations, compared
by equality and never by "at least": a number below is a computer that has been left behind, and a
number above was never issued, because the database refuses to hand a placement number out twice.
The same comparison is made again in SQL inside the statement that writes, and no rows changed is a
refusal that is recorded with words the computer can act on.

**Committing a computer is explicit, reversible, and never means reading somebody's files.** A
pledge records the exact sentence that was agreed and is never edited; withdrawing it writes the
withdrawal beside it. A computer that offers again does not get to change what was agreed. The four
rules that protect the computer's owner are carried from the shipped grid rather than left behind:
a computer going away, on battery, nearly out of disk, or whose person is back when the admin lent
the grid only its idle time all take nothing.

The record move has its dry run, its backup, its rollback and its runbook, in
[desk-migration.md](desk-migration.md). The bridge is `grid/src/core/compat/desks.rs` and it is
built the way the model grid's bridge was. The Phase 4 gate stays open until the product calls any
of this: desks staying usable across the move is a claim about the shipped Sandbox Grid, and
nothing shipped has moved yet.

## Phase 5, as landed

Credential brokering is a core profile at schema versions 5 and 13. The broker is
`grid/src/core/broker.rs`, the vault seam is `grid/src/core/vault.rs`, and what it makes a
short-lived credential from a long-lived one with is `grid/src/core/mint.rs`. It is additive:
nothing shipped calls it yet, and the Access Grid hub still brokers every request a person makes
today.

**The workload never receives the value.** It holds a single-use permission naming a credential, a
place, a method, a path and a size, and asks the broker to send. The broker reads the value, puts
it on the request itself, and hands back the answer. There is no call that returns a value and no
column in any of the three new tables that could hold one, which a test checks by name and by
searching the database file, its journal and a backup for every encoding of the value, and for the
query the request carried, after a successful send.

**A reference is checked at the realm's door, not only at the constructor.** `Credential` has
public fields and derives `Deserialize`, so `Credential::new` is not the only way one can be built.
`Credential::is_a_reference` is the constructor's rules as a method, and `Core::add_credential`
asks it before anything is written. What is written there is repeated by every brokered request's
row, by every backup and by the sentence a vault failure puts in the history, and that history is
insert-only, so a value put where a reference belongs could not be taken back out.

**Everything is checked twice, and the second time is the last thing before the send.** What can
be decided without a value is decided first, so a refusal never reaches a vault at all. The value
is then read on a thread kept for blocking work, because a locked keychain or a prompt in front of
the person at the computer takes unbounded wall time, and an administrator can revoke a computer,
retire the credential or rotate it while it does. `Core::still_clear` re-reads the realm and the
credential and is the statement before `forward::send`, with nothing between them. A test suspends
a vault read until a retirement has been applied and proves no connection is ever made.

Reaching a token endpoint is a second unbounded wait, and it happens between those two rather than
after them, so the last look stays the statement before the send. That also means a token can be
bought and then thrown away unused, when something changed while it was being bought, and a test
proves that is what happens rather than the request going out under the old answer.

**Revocation and rotation bite at the moment of use.** A rotation raises the credential's
generation, and a permission carries the generation it was minted under, so the permission minted
a second earlier is refused by the same mechanism that refuses a suspended account. Nothing has to
be found and deleted.

The wire is the Access Grid's forwarder rather than a second one of Core's own, so TLS, redirects,
path canonicalisation, header hygiene and hiding a value in an answer are decided in one place.
That is a dependency pointing from Core up into a profile, and it is accepted on purpose and
written down in the module: when Grid Core becomes a crate of its own the forwarder moves with it.

One keeper can be opened by this build, the operating system's own vault, through
`src-tauri/src/core_vault.rs` on the `keyring` layer this app already has. The encoding is pinned
rather than assumed: a credential vault is a byte store with a text door beside it, and on Windows
the text door writes UTF-16, so a byte read of an entry written that way is not the value's UTF-8
and would fingerprint to something else on that platform alone. Both ends go through the byte door
and the value is written behind a line that says which encoding it is. Nothing in the test suite
opens the real vault of whoever runs it; what is proved here is the framing, including that the
UTF-16 of the same value is refused rather than taken for it. HashiCorp Vault, Azure Key Vault,
AWS Secrets Manager, Google Secret Manager, CyberArk, BeyondTrust, PKCS#11 modules and TPM-backed
storage are each a named seam that refuses every read, and each has a row in the adapter matrix
saying exactly that.

The store that keeper sits on is now a seam of its own, `core_vault::Store`, so the framing is
proved on both sides without anybody's real vault being touched. `src-tauri/src/core_vault.rs`
holds five tests against a fake that behaves the way each platform's store behaves: a value
written through this code comes back out of it unchanged on Windows, macOS and Linux; an entry
somebody wrote through the text door is refused as damaged rather than taken for the value,
including the UTF-16 Windows hands back for one; a damaged entry, an empty one and a store that
will not answer are each told apart; a value too long for Windows's 2560-byte credential blob is
refused rather than half written; and asking whether the store answers writes nothing. The rule
that no test opens the real Credential Manager or Keychain of whoever runs it has not moved, and
that `keyring` hands back the bytes it was given is still not proved here.

**All seven ways of travelling are brokered, and the three that mint keep their tokens in
memory.** Version 13 adds OAuth 2 client credentials, GitHub App installation tokens and AWS
SigV4, which the shipped Access Grid has carried all along and which the core refused. Each is
written against the shipped `forward::Prepared`, `forward::fetch` and `sigv4::sign` rather than a
second copy of them, so a fix to a signature or to hiding a value in an answer reaches both. What
a minting credential needs besides its value, a token endpoint, a client identifier, a region, a
role, is checked on the way in by `credential::checked_settings` and is names and addresses: a
settings map holding something that reads as a secret is refused by the realm's door and by the
database. A minted token is a secret with an expiry, so it is held in `mint::Cache`, which is
handed to the broker by whoever starts it, is never written anywhere, and overwrites every entry
in place when it is dropped, the way `Held` and `Sealed` do. The key a token is held under carries
the credential's generation and the version of the vault entry it came from, so a rotation makes
the next request mint again rather than anything having to be found and deleted. A token endpoint
is bound by the realm's own outbound rules, asked before any value is read, because that is the
one list that stops every credential at once. A test proves that neither an OAuth client secret
nor the token bought with it reaches the database, its journal, the history or a backup.

**A value travels in the URL only when an administrator said it may.** A query credential's value
ends up in the service's own access log and in every proxy in between, and those copies are not
this grid's to delete. So the decision is recorded on the credential with the name of whoever made
it, through `Core::allow_query_credential`; the broker refuses the send without one, at both
looks, and the refusal says why. The database refuses the half of that decision that names nobody.
An Access Grid brought across by the bridge carries its query credentials and does not carry such
a decision, because the hub needs none, so each arrives recorded and unsendable until somebody
allows it, which the rehearsal's notes say in words.

**A client certificate is gone from `Secret` rather than promised.** A client certificate is not a
value that goes in a header, a parameter or a username: it is a key the outgoing TLS handshake
proves possession of, and the forwarder this grid sends through builds its TLS with no client
authentication. Keeping the word would have been the type promising what the broker cannot do, so
version 13 retires any credential that said it was one and the database refuses another.
`Secret::ServiceAccount` stays, and now travels, because minting is what a service account is for.

**Which destinations the upgrade to version 5 could not carry can be read.** That step copied each
credential's one destination into the new list with `INSERT OR IGNORE`, so an address written by a
build whose only rule was that it began `https://` was dropped rather than aborting the step, and
nothing said which. `Core::destinations_left_out` is that report. It is computed from what the
realm holds now rather than from a record the step did not keep, and that is its honest limit: a
destination an administrator took away afterwards appears too, and the reason tells the two apart
because one of them is an address this grid would refuse today and the other is not.

Forty-one tests cover it, and the rollback the plan asks for is `schema::DOWN5` and
`schema::DOWN13`, each with a test that takes its version back out and puts it back. `DOWN13`
cannot bring everything back and says so: a credential that travels as oauth, github-app or aws is
left with a word a version 12 build will not write, its settings are gone, and a credential that
called itself a client certificate stays retired. The Phase 5 gate stays open until the product
calls any of this.

## Phase 6, as landed

The isolated research realm is a core profile at schema version 6, in `grid/src/core/research.rs`.
It is additive: nothing shipped calls it, and Swarm Mining still owns every bounty worker. No
worker was started to build or test any of it, and nothing in the grid crate can start one.

**It is a code and trust separation, and nothing else.** Nothing here weakens, bypasses or disables
any model's safety behaviour. There is no model invocation in the profile, no prompt, no system
message, no setting that reaches a runtime's behaviour and no column whose contents could become
one. Every control it adds is containment. A guard test reads the profile's own source and the
shape its database takes and fails if such a setting ever appears; what that proves is narrow and
the test says so in its own words: it proves the words are absent, not that a model is safe.

**A research grid inherits nothing, because there is nothing to inherit from.** It is an ordinary
realm created with `RealmKind::Research`, so it is a different file with a different key, its own
people, computers, history and policy, and `Capability::allowed_in` already refuses to put research
and the company's three capabilities in one realm. A permission minted in one is refused by the
other on its signature, in both directions, and both refusals are recorded. A credential cannot be
written into a research grid by any route: the capability refuses it, `Core::add_credential`
refuses it, the broker refuses before it looks at anything, and three triggers refuse the rows.

**Offline by default, and explicitly opened one destination at a time.** A research grid starts
with `NetworkPolicy::offline()`. A destination reaches the realm's policy only through an
`Admission::Destination` written on somebody else's granted decision, and the policy is kept equal
to what is actually admitted: withdrawing one takes it out, one that simply lapses is swept out
where requests are lapsed, and the last one going leaves the grid offline again. A policy with
outbound on and an empty destinations list is refused outright, because `NetworkPolicy::allows`
reads an empty list as anywhere. The Phase 6 gate "cannot address the company's computers" is a
refusal of every address that can only ever mean a machine near us, written down once in
`research::near_us`: the private, loopback and link-local ranges on both families, including
`fe80::/10` and the deprecated `fec0::/10` beside it, the unspecified addresses `0.0.0.0` and `::`,
broadcast and multicast, the rest of
`0.0.0.0/8`, and the deprecated `::a.b.c.d` form, along with the names that only ever mean a
machine on the same network and plain `http://`, with a test named for the gate. `crate::net::private`
is left as it is, because it is the LAN-sharing rule that decides who may join a grid and widening
it would make plain `http://` acceptable to the forwarder for these same addresses. Both doors onto
the realm's policy go through `checked_network`: `Core::set_network` and the broker's
`Core::set_egress`, which would otherwise be a second set of rules for the same question. The limit
is written down rather than implied: the core does no name lookup, so a public name that resolves
inside the company is not caught there, nor is a host written as a bare decimal, and what holds
then is the enclosure's own network filter.

**Agreement is `approval.rs` and nothing else.** Admitting a source, a destination, a repository, a
tool or a person, freezing a scope's authorisation, and reviewing a finding are all ordinary
`Core::ask` requests for `ApproveResearch`, decided by `Core::decide`, every one of them marked
`every_time`, so no standing allowance can ever cover any of them. The action a request was asked
under is read back twice and never taken on anybody's word: `approval::decide` refuses an approver
who names an action other than the request's own, and every place an agreement is spent asks
`Approval::asked_to` first, so an agreement to approve research cannot let a company credential out
and an agreement to approve a credential cannot let anything into a scope. `research_reviews` is a link row
naming the request and holds no verdict of its own. A researcher cannot write an authorisation and
freeze it alone: freezing takes a granted decision over the authorisation's digest from somebody
who is not its author, while anybody else could decide.

**Changing the source or the scope invalidates acceptance.** A frozen scope is replaced by a new
version, never edited, and the database refuses the edit. Revising or halting one closes it, stops
its unfinished work, withdraws its admissions and raises its generation, so every permission it
issued is refused at its next use without anything being hunted down. Every crossing sealed under a
scope or a source that has since changed is marked no longer good, and `Core::notices` is what
somebody carries to the company realm, which sets its own acceptance aside with
`Core::retract_import`. There is no connection between the two realms and there is not meant to be.

**A stop reaches running work and leaves the evidence.** Work that has begun is quarantined rather
than cancelled, because `Stage` refuses to take draining work to cancelled and a stop that cannot
reach what is running is not a stop. The reservation goes back, every artifact, source, finding and
verdict stays where it is, and the person holding the realm's stop switches can pull it as well as
the researcher. What the core does is move rows and withdraw permissions; stopping the enclosure
itself is the engine's half, and the product text should say that rather than implying otherwise.

**Isolated execution is a seam the core holds no implementation of.** `research::Enclosure` has
five operations and `research::Plan` is what the engine builds a container, microVM, virtual
machine or GPU sandbox from: the resources, the GPU isolation, the network, how long, how many
files, how many bytes, how many artifacts, the classification of the material and the source
digest. The four have rows in the adapter matrix in their true state, which is Roadmap, with the
runtime each would be built from named. A card is given to research only where somebody has
recorded how it is isolated and it is good enough for the scope; nothing here attests that, so
`Core::set_gpu_isolation` records who asserted it and the event says so.

**Scanning is recorded, never performed.** There is no scanner in this repository. A verdict about
an artifact is an insert-only row naming the person who recorded it and the tool they are
reporting, the latest one is the state, and nothing crosses unless the last verdict on every
artifact a finding rests on is clean. The product must present this as who looked and what they
said, never as the grid having detected anything.

**The crossing is a document, and its claims are kept small.** It carries no key, no permission and
no source byte, which a test checks by value. Its digest is keyless, so it catches damage and
transcription error and not an adversary, who recomputes it along with the edit; the test proves
exactly that and no more. Its seal is taken with the research realm's key, which the company realm
does not hold and must never be given, so the company realm does not check it and does not pretend
to. What makes an import is a named person in the company realm deciding with a second approver,
written under that realm's own key. The design's earlier idea of carrying sealed audit events was
dropped rather than reworded: a filtered excerpt cannot be verified as a chain by anybody who does
not hold the key, so carrying it would have meant shipping something that looks like proof.

Twenty-four tests cover it, none of which starts a worker, opens a socket or builds anything: the
enclosure is a recording stub that is handed a plan and starts nothing. The portable shape gained
the research vectors as fields that default to empty rather than a version bump, so a backup
carries every scope, admission, source, manifest, dependency, artifact, verdict, finding, review
and crossing, and restores only with the research grid's own key. The rollback the plan asks for is
`schema::DOWN6`, with a test that takes version 6 back out and puts it back. The Phase 6 gate stays
open until the product calls any of this.

## Phase 8, as landed

One client, `src/api/grids`, speaking Grid Core's vocabulary over the engine commands that exist
today: realms, principals, devices, hosts, plans, workspaces, credentials, approvals, research
jobs and audit events. It is additive. No page moved, and no page had to.

Nothing is aliased. The four product modules keep their own paths, their own exported objects and
their own type declarations, because several of those hold what Grid Core has no room for: a
joined computer's model assignment and its progress, a desk that is building or moving, a worker
that is paused. `src/api/grids/compat.ts` holds the conversions instead, one table per state that
differs, and says in each case what is lost. A desk that is building has no core state of its own,
so a workspace also carries the product's own word; four of Swarm Mining's states have no core
stage at all, so those map to null and a page reads the job's own state. The alternative, a type
alias, would have emptied three pages quietly rather than failing a build.

What did change is underneath. Every product module now sends through one call path,
`src/api/grids/wire.ts`, so what the pages already do is covered by the same four things the new
client gets: a memorable name per call that ties several calls in one action together, a typed
refusal that keeps the engine's own sentence, an `ifVersion` carried when a caller says what it
believed it was changing, and the redaction pass. Each module keeps its own sentence for a person
with no desktop app, naming what they were doing.

Redaction is a second line of defence and is written down as one. It replaces a field whose name
says the value is the secret, and reports where it found it rather than throwing; it never touches
the contents of a string, and it does not walk somebody else's document. That matters in two
places the client would otherwise break: a bounty's authorization, scope, objective and service
rules are what somebody reads before they tick "I am authorized to test this target", and a
research report's document is the finding itself.

The Access Grid is wrapped, not changed. `src/api/access-api.ts` belongs to another part of this
work and nothing here edits it, so `grids.credentials` calls that module and never an `access_*`
command string. The consequence is stated in the code: answers that come back that way do not pass
through the shared call path, so the profile hands each one to the redaction pass itself, and a
page that calls `accessApi` directly still bypasses it. `access_use`, `access_check` and
`access_reveal` exist on the local wire with no desktop command at all, so the client names the
command line instead of pretending.

The permission table is generated. `scripts/grid-core-roles.mjs` writes
`src/api/grids/permits.generated.ts` from `grid/src/core/identity.rs`, including the sentence for
each action, and `may` answers no for a suspended account and for a capability a grid never turned
on, exactly as `Principal::may` does. It grants nothing: the desktop command checks the main
window, the hub checks the session, and Grid Core checks its own table again at the moment it acts.

The event stream is the one this repository already has. `src/api/grids/events.ts` defines a
desktop event, `yougori-grids-news`, listened to the way `marketApi.listen` listens for
`yougori-market`. It is an accelerator and never the truth, because the command line cannot
receive a desktop event, the browser fixture has no desktop app, and no product emits this one
yet. Every watcher is served by one shared read per name, with the most eager watcher setting the
pace, and that read carries a first-wait flag and a refresh flag so a spinner always has something
to hang on. The four products' own pollers were left where they are on purpose: all four browser
tests replace methods on the product modules, and moving a page's read onto the shared poller
before its test moves would walk straight past those stubs.

Pages and filters run on this computer, because every status command answers with whole lists.
Asking for no page asks for the whole list, so a method that returned every worker still returns
every worker.

[typescript-api.md](typescript-api.md) is written by `scripts/grid-client-docs.mjs` from the
client itself. Every method has to say where it goes, with one of three tags, and a command it
names has to exist in `src-tauri/src/lib.rs` or `src-tauri/src/automation/dispatch.rs`; a method
that says nothing fails the generator. `scripts/grid-client-docs.test.mjs` re-renders both
generated files and fails when either has drifted.

What Phase 8 does not do, plainly. No engine command reads `ifVersion`, so optimistic concurrency
is carried rather than enforced, and two administrators editing the same plan still race. Refusals
are classified from the sentences the Rust produces today, which is a table that will go wrong the
first time somebody rewords one; a code from the engine is Phase 7's to give. Paging is a shape,
not a saving. The event is inert until a product emits it. The Closed Neo Grid and Swarm Mining
expose no account at all, so for those two the client knows only whether this computer runs the
hub, and it assumes it may act rather than greying out a control the engine would have allowed.
And no page has moved: that is the next step, one page and its test at a time.

## Phase 10, as far as it has landed

The seam is `grid/src/core/connector.rs`: one trait, nine operations, the five that only read
first. It is additive, like everything else in the core, and no shipped product calls it yet.

Three properties are what the seam is for, and each is enforced by the types rather than by a
rule somebody has to remember. No argument of any operation can carry a secret, because every
argument is one of the types in that file and none of them has anywhere to put one; a connector is
given a permission naming a credential, and the one place a value is ever read is a connector's
own construction, which is not an argument of anything. Nothing changes a provider until that
exact plan has been checked, because `validate` is the only thing that returns a `Checked` and
the three operations that change a provider all require one. A connector cannot touch a realm,
because nothing in the seam is given one; a connector hands back what happened and a list of
notes, and the caller decides what the realm records.

The four connectors that exist were wrapped rather than rewritten, in
`grid/src/core/connector/desktop.rs`, so that the only connectors in this repository that have
been exercised against anything keep the behaviour that was exercised. Their own tests still run
against them directly, and the seam's test drives them through all nine operations against the
same loopback servers and asserts the providers see the same requests.

The adapter matrix is no longer written by hand. One table in
`grid/src/core/connector/registry.rs` holds every integration the plan names with its true state
and the evidence for it, [adapters.md](adapters.md) is rendered from that table, and a test fails
when the two stop agreeing. No row is live-tested and none can be here.

### What the second part of Phase 10 added

**Read-only connectors, enforced rather than promised.** `Connector::alters_anything` answers yes
by default, so the four that already existed are untouched by the question being asked. A
read-only connector answers no, and what makes the answer bite is that every plan it makes has
reading steps and nothing else, which `cleared` refuses to carry out. The read-only connectors are
written as if their author had forgotten the rule, and a test drives them that way, because the
point is that the rule does not depend on anybody remembering it. The refusal is one sentence in
one place.

The reason those adapters are read-only is a type and not a policy. `Request` carries a `Subject`
that has to be an email, so the trait models one thing: giving or taking back one named person's
access at one provider. Listing the machines a credential reaches is about nobody, and widening
the trait to invent a person for it would have taken away the thing that stops a connector being
handed somebody it was never told about.

**Eight read-only cloud and storage adapters and one SCIM client**, in
`grid/src/core/connector/cloud.rs` and `scim.rs`, over one wire seam in `wire.rs`. The Amazon
fixtures recompute the Signature Version 4 signature from the canonical request and refuse one
that does not match, so a signing mistake is a failed test. SCIM is the one standard in the phase
that fits the trait without being bent, and it reads the group before it writes to it, so what it
reports as already true is what the server says rather than what it remembers.

**A wire seam that is not a second broker.** `core::broker` is how a workload makes one request
with a credential it never sees, through the Access Grid's forwarder, with a single-use permission
and a ledger row. It presents a credential; it does not sign a request with one or exchange one
for a token, which is what every provider in this phase needs. So connectors take the road the
four that already ship take, `grid/src/https.rs`, and `wire.rs` is the one place on that road
where a value exists. A connector holds a `Box<dyn Wire>`, and `Wire` has no method that returns a
value, so there is nothing it could call to get one. The rate limit, the breaker and the token
cache are on the connection, where a connector cannot reach them.

**Connector tasks, and the hole they fill.** A connector that cannot write to a realm cannot
record a provider it just moved. So the realm writes the row first: schema version 8 holds
`connector_intents` with four triggers and a partial unique index, `Core::open_connector_task`
records what is about to be asked before it is asked, and `Core::settle_connector_task` records how
it ended with every note the connector kept, in one transaction. The worst case becomes a realm
that says it does not know rather than one that believes something false.

**The sweeper, which is where rollback lives.** It mints a fresh permission on every attempt, so
suspension, a withdrawn grant and a retired credential bite at the moment of the attempt. It makes
the plan again and refuses to act on one it cannot reproduce. After three attempts a row says a
person has to look. When the realm has withdrawn the credential it says it can no longer reach the
provider in either direction, rather than reporting a rollback that never happened.

**Hardware discovery, in `grid/src/core/hardware.rs`.** A second seam with two operations, because
a computer reporting on itself has no credential, no destination and no person. A fact that was
not measured is reported as not measured and never as no, which is the rule `identity.rs` already
followed. Every fact carries how it was learned and when. There is a `Probe` trait because the
application this crate is part of already measures some of it and depends on this crate rather
than the other way round, so reading the same hardware twice would be two answers that can
disagree; `src-tauri/src/grid_hardware.rs` is the host side of it and measures nothing new.

**Trust that cannot overstate.** Four rungs, a ceiling at self-reported, and a clamp. Nothing here
mints a key inside a TPM, asks for a quote or checks a manufacturer chain, so nothing here can
produce more; a realm demanding more takes no computer at all and the refusal says so. A
measurement older than a day, a measurement stamped in the future, and a report that does not say
how it was measured all count for nothing.

**Audit export, in `grid/src/core/export.rs`.** A third seam, because a batch of events is not a
person. `render` produces the bytes without sending them, which is why a wire format can be
checked on a computer with no network. Syslog and OpenTelemetry over HTTP are built and exercised
against collectors on this computer; the SIEM webhook, Splunk, Microsoft Sentinel and Elastic
render their envelopes and have never sent one, and their rows say which four questions about
acceptance this repository can never answer.

**The registry split four composite rows**, because a row naming several systems can carry one
state only while all of them are in it, and a test now refuses to let a split row come back.

### What Phase 10 still does not do

The gate stays shut, and for the same reason as before: no profile calls the seam. Nothing in the
four products opens a connector task, runs the sweeper or exports a history, and
`src-tauri/src/grid_hardware.rs` has no caller outside its own tests because nothing in the
application drives a realm yet.

Nothing is live-tested and nothing can be from here. Seventeen things in the plan were judged
buildable without a vendor library and fifteen of them were built; what was refused, and why, is
in each row's evidence. The three largest refusals: SAML needs XML exclusive canonicalisation
before a signature check and hand-rolling one is where signature-wrapping bugs come from; LDAP and
Active Directory would be a client and a fixture that prove only that they agree with each other;
and Google Cloud needs RS256 assertion signing, which `grid/src/jwt.rs` can check but cannot do,
so it is new code nobody has written rather than an existing path pointed somewhere else.

## Phase 7, as landed

One namespace, `grids`, with twelve wire methods and one CLI group over all four products. The
decision and its limits are in [ADR 0002](0002-one-namespace.md); what follows is what is in the
tree.

`cli/src/grids/mod.rs::VERBS` is one table of ninety-odd verbs with, for each, what the grid must
be able to do, whether it writes, what it asks a person to confirm, which words it takes and one
line of help. That table is what the terminal parses with, what `yougori grids NOUN --help`
prints, what `catalog::confirmation_for` reads for a `grids_*` method, what the engine refuses
with and what the launcher's new home-menu entry builds its submenu from. The three places that
used to be able to disagree about a confirmation now read the same row, and a test asserts it.

`cli/src/grids/alias.rs` holds both halves of the migration. `product_call` turns one typed
command into the wire method a product already has, so the new door and the old door are one
behaviour rather than two implementations that look alike. `ALIASES` is the table of what the four
products shipped and what each is now also called; the left-hand column of the test that checks it
is built from `catalog::methods()` rather than from the table, so a product method added later
fails the build until it has a row or a written reason.

The engine side, `src-tauri/src/grids.rs`, is a translator and nothing more. It reads the noun
from the method and the verb from `request.do`, finds the grid from
`src-tauri/src/grids/registry.rs`, refuses in words anything that grid does not do, builds the
product call, validates it against the engine's own contract, and then calls the handler that
exists today. Listing the grids is the one thing no single product can answer, because none of
them knows about the others, so the register answers it: this is the first place in the product
where all four are named together.

What is new that the old doors do not have: one answer shape for every command; capability
validation that happens after the grid is found and before one argument of the command is read; a
machine code travelling in front of the sentence for the queue to strip, which is the arrangement
`YOUGORI_BUSY` already uses; a dry run that is no longer short-circuited to syntax-only; and one
readable name per typed command.

Grid Core's audit gained that name. Schema version 7 adds a nullable `command` column and an index
on it, `Core::during` holds the name for the length of one command so that every event it causes
carries it, and `Core::history_for` and `Core::recorded_for` read everything one command did. The
seal takes the name only when there is one, so an event written by an earlier build seals exactly
the bytes it sealed then and an old chain still verifies; a test proves that, and proves that
adding a name to an old event afterwards is caught.

Four things are worth saying plainly rather than leaving to be discovered. A rehearsal does not
call the product handler, because none of the four hubs has a rollback wrapper; what it does check
is named above. No product hub writes a command's name against an event yet, so an answer from
this door reports no events, says `correlated: false`, and `grids log show --command NAME` refuses
in words rather than answering with the whole record. There is no `grids research start`, and a
test asserts there is not: a worker is started in one place, by `yougori start bounty`. And
publishing a closed bounty keeps `yougori bounty host`, because it carries its source files with
it and no option on this door can hold them.

No desktop command and no page. The twelve methods are on the wire, which is what the CLI and
agents speak; the Grids tab is Phase 9.

## Phase 9, as landed

One area in the app called Grids, in place of the four entries that were there. Each grid keeps
its own name under it, with the line it always had, so the way people already reach the Neo Grid,
the Sandbox Grid, Swarm Mining and the Access Grid is still the way they reach them, and the four
browser tests that click those names pass untouched. An address that named one of them still
works: `?page=grid` and the newer `?grid=neo` both land on it, and `?grid=neo&show=status` lands
on its status.

One create wizard, `src/components/grid-create-wizard.tsx`, asks what the grid is for before it
asks anything else and from then on asks only that purpose's questions. Research clears the other
three when it is picked, which is `Capability::allowed_in` and nothing more. Two answers the
earlier draft had wrong are right here: a desk's kind is derived from a container image and asked
outright otherwise, because `Image` has a `WorkspaceKind` and nothing may guess it; and the cores
and memory a computer gives are asked as the computer's offer, while the disk one desk may fill is
asked as the desk's, because Grid Core's `Quota` holds disk and not cores or memory.

The dry run is the last screen before anything is created. It is seven lines and a list of what
would be made, all of them sentences: where the records are kept, which computer mints and holds
the key, what else is kept beside it, how far the grid can be reached, who administers it, who
approves, and which computers could join. No file, folder, vault entry, realm id or dotted audit
token appears in any of it, and three tests assert that. Each high-impact answer raises its own
sentence with the scope in it, and the grid is not created until every one of them is agreed to.

One status view with the panels that grid's capabilities allow, and no others: computers, work,
model plans, desks, credentials, what waits for an approver, and the history. A panel is rendered
only when the grid has the capability and the person holds the permission; nothing is shown
disabled with a note about a permission somebody does not have. The timeline turns a principal id
into a person's name and a dotted action into a sentence, and the four products' own single words
go through the same door, so one timeline reads as one thing.

What Phase 9 does not do, plainly. No page was rewritten: each of the four grids still has its own
hub and its own page, and the area opens that page unchanged. The wizard creates a grid by calling
the product's own create, so a grid with two purposes starts two hubs today, one for each, and the
sentence it shows says so. A research grid is never created here at all: it hands the authorised
answers to Swarm Mining's own page, which is where a worker is started, and no part of this phase
starts, resumes or touches one. The confirmation is enforced in the browser, where this wizard
lives; enforcing it in the engine needs `grids_create`, which is the phase that moves creation onto
the core. Branding is presentation and nothing else: a company name and a line saying who to ask,
kept on this computer, because there is no brand row in the core's schema and inventing one in a
tab would be the wrong place for a schema step. Tenants are grids, which the core already gives:
one key, one record and one set of people each, and the area's list is the list of them.

## Phase 11, as landed

The threat model was read against the code and rewritten: four of its claims turned out to be about
the hub rather than the core, two described behaviour that does not exist, three assets were not
listed, and the most important adversary was missing. Grid Core authenticates nobody; it takes a
caller's word for `by` and `device_id`, and `Core::allowed` says yes to the literal word `owner`.
That contract is now written down as a boundary rather than left in somebody's head.

Nineteen attack tests landed in `grid/src/core/attack.rs`, five more against the outbound path in
`grid/src/core/broker/tests.rs`, fifteen authorisation invariants in `grid/src/core/invariant.rs`
driven by a seeded generator in `grid/src/core/seed.rs`, seven fuzz harnesses in
`grid/src/core/fuzz.rs`, and six recovery tests in `grid/src/core/recovery.rs`. Fifty-four new
tests pass and one long sweep is ignored on purpose. Every one of them says in its own comment what
a pass proves and what it does not, and where an attack cannot be performed here the test proves
the part that can be checked and the comment says in words what is left unproven.

Five defects were found by tests written in this pass and fixed in it: `Core::accept` acted on a
token's claims before checking its signature and sealed a stranger's text into the history; a
one-use permission could be used twice by two processes because the row count of the one statement
that spends it was discarded; a backup's state was not sealed, so an added administrator survived a
restore with the history still verifying; a restore brought a withdrawn account back at an active
account's generation; and a paused grid still accepted permissions minted after it was paused,
because `Core::accept` never asked whether the grid was serving, which the ignored long invariant
sweep found and shrank to three moves. That last one is the only thing the ignored sweep has ever
found, and it is why it is kept. Schema version 9 adds the rules withdrawal rests on as triggers,
so anything that opens the file is held to them too.

`cargo clippy` on this crate was failing before this phase, on a `never_loop` in
`grid/src/relay.rs` that is deny by default, so the run exited before reporting a single lint
anywhere in `core/`. It was genuinely safe to fix and is fixed. What is still missing is an
enforcement point: no workflow runs clippy for any crate, and none runs `grid`'s own test suite.
Grid Core is compiled in CI because `src-tauri` depends on it, and its three hundred and
seventy-four tests have never run there.

Said once, plainly: **a verification pass written by the people who wrote the code is a
verification pass. It is not an audit.** It tests what they thought to test.
[docs/grid-core/security-review.md](security-review.md) is the full account, including what cannot
be verified here and what a real engagement would have to cover.

## Phase 12, as landed

The valuable half of this phase is the queries. `grid/src/core/store/mod.rs` was read end to end
and every place that read a whole table to answer a question about one row, or read a whole table
inside a loop over computers, was replaced with a targeted query. Schema version 10 adds the
seventeen indexes those queries are asked with, and nothing else: it changes nothing a realm holds.
The full list of what was fixed is the table in [operations.md](operations.md).

Each fix is proved by counting what the database was asked, not by checking the answer came out
the same. `grid/src/core/bench.rs` is a meter over SQLite's own statement trace, which `rusqlite`
already carries behind a feature asked for as a dev-dependency, so a release build does not have
the trace machinery in it. Criterion was considered and declined: every commit in a realm is an
fsync, so a timing harness measures the disk, and a statement count is the same number on a slow
machine as on a fast one. Each benchmark builds the same realm at two sizes and asserts the
statement counts are equal, so none of them can fail because a machine is slow.

What the meter cannot see is said beside every number it reports: it counts rows given back, not
rows read, so a `COUNT(*)` over half a million entries and a single b-tree descent are the same
number to it. Where the cheap shape of a statement is the property, the test asserts on the
statements themselves, which the meter also records.

Measured on this machine, at the published computer limit with fifty thousand reservations and a
realm holding no workspace, no packed copy and no model plan: granting a reservation is sixteen
statements and about 1 500 rows, a reading of that realm is twelve statements and ten rows, and a
sweep with nothing due is two statements. The same reservation, under the code that was there
before, would have been about a thousand statements and about twenty-five million rows; that
second figure is counted from the shape of the old code, not measured beside the new one.

`grid/src/core/limits.rs` holds the published sizes, each with the sentence that says what set it
and each enforced by a named door, in the house wording that puts the number in the refusal. Four
of them warn rather than refuse, and the reason is written down: refusing to record what happened
means refusing whatever caused it, so a realm whose history had grown would stop serving, and an
operator would find out from the outage.

`health.rs` is liveness and readiness, four statements and eight, every one of them a b-tree
descent or a bounded range rather than a count of a table nothing deletes from. Neither verifies the history, and
there is a test whose job is to stop somebody adding that to a probe. `metrics.rs` is one reading
of a realm, with each number's query named and what it does not mean written beside it: computers
heard from recently counts computers that have authenticated, because nothing else writes that
time; model readiness from the database is placement and not whether anything is loaded; and a
count of refusals is capped by how far the trimmed history still reaches. `upkeep.rs` is the slow
work on three cadences, and a realm nobody sweeps still answers every question the same way.

Operations that could be code are code: an upgrade that takes an exact copy first, a sentence per
version saying whether it can be taken back out, a restore drill that reports what a restore does
**not** bring back, and an evidence bundle that carries identifiers and fixed words and leaves the
realm's own words where they are.

**Nothing outside the core calls any of it yet.** No code in `grid/src`, `src-tauri/src` or
`cli/src` opens a realm, constructs `Upkeep`, takes a copy on a schedule or asks for a checkup, so
the cadences, the backup schedule and the warnings at the four unenforced sizes are what a host
should do rather than what any realm on this computer does. Section 12 of
[operations.md](operations.md) carries that beside the other gaps.

Said once, plainly, here and in the document and nowhere contradicted: **one SQLite database per
realm on one computer is not a high-availability design.** There is no replication, no leader
election and no failover, and section 9 of [operations.md](operations.md) says what each of the
four ways out would cost and why active-and-active is not available at any price with a single
sealed history per realm.

## Phase 13, as landed

The foundation is the freeze. Every record the four products write is pinned in
`grid/src/core/compat/frozen.rs` with a fixture per record and a round-trip test, and
[frozen-contracts.md](frozen-contracts.md) is rendered from that register the way the adapter
matrix is rendered from the connector registry. The bytes cannot see one kind of change, a new
optional field that is skipped when it is empty, so `crate::hub` and `crate::bounty` each gained an
exhaustive destructuring test that stops compiling when a field is added. Those two name every
type either record is made of, down through the desks, the people and the enterprise settings,
with `bounty::Record::coordination` the one exception and named as one: it carries
`skip_serializing`, so none of it is in the record. What the freeze does not cover is in the
document's last section, including that it begins with this build and says nothing about 1.0.20
and earlier.

Two loaders gained a version check they never had, which is three of the four products; the
Access Grid's loader has none, its record is **Dropped** in the register, and nothing in the
rollout says so except the rehearsal. `hub::load` and `bounty::load` were a bare
`serde_json::from_slice` and no caller anywhere read `record.version`, so an older build read a
newer record, dropped every field it did not know, and saved that back over it. Both now refuse a
record from a newer build in a sentence that names the version, compared as a `u64` so that a
version of 256 does not narrow to 0 and fall through to "damaged". It cannot repair a record that
has already been saved over; it stops the next read, which is why it is stage 0 and why no later
stage depends on anybody knowing that a deployment exists.

**Nobody can enumerate deployments, so the inventory is one a customer takes of their own.**
`yougori rollout survey` reads this computer's records, counts them and writes one file. It sends
nothing and carries no name, email, model name, bounty title, address, hostname, certificate, salt,
hash or absolute path; a test checks the written bytes against the secrets in the fixtures it was
built from. The only true enumeration anywhere is a hub's own list of its members, because they
enrolled, and that is exactly the list a migration needs.

**A rehearsal runs the real thing on copies.** Records are copied with the file system and realms
with SQLite's own `VACUUM INTO`; each bridge's import runs against the copies, the history is
verified, the import is rolled back, and the realm is compared with what it held before table by
table and row by row. A snapshot would not have done: it carries no sign-ins, spent permissions,
brokered uses, withdrawals, host conditions or generation numbers, so a rollback that bumped a
generation would pass a snapshot comparison and fail this one.

**A backup is read back before it is called one.** Every copied record is reloaded with the loader
that wrote it and the backup fails if one does not read. The manifest names the vault entries a
restore cannot do without, as names and never values, and a realm's entry is read off the copy
itself rather than off the register, because the register leaves the realm's own identifier as a
placeholder and nobody can prove a placeholder present in a vault. Two of Swarm Mining's files are deliberately
not copied: a worker's receipts and a published bounty's imported source both hold somebody's
project, which is why the product deletes them, and copying them into a plain folder for an
operator to carry away would undo a privacy measure in the name of safety.

**Observation mode is general.** `compat::neo::compare` was the only comparison; now every profile
answers the same six headings and a profile that cannot be observed says so under each of them
rather than producing nothing. `compat::desks::compare` is new and is the harder half: the core's
chooser reads the store, so it builds a throwaway realm per comparison, places in the hub's own
order one desk at a time, and writes into the scratch realm the three things the import
deliberately does not. A desk that is already on a computer is chosen again by neither side, so
that row is compared against the realm's own stored placement rather than against the hub's field
copied back, and a note says the agreement is about a placement held and not about a choice made.
Seven shapes of grid are tested and the two sides agree on all of them.
Which band a difference falls into is `observe::judge`, in one place: a placement difference always
stops, a narrower permission is a note, a difference one of the bridge's own notes explains is a
note, and everything else stops.

**A rollback now survives a restart.** `Imported` and `DesksImported` existed only in memory, so an
import could be taken back out on the day it ran and never afterwards. Schema version 11 keeps what
an import created in the realm itself, beside the event that records it, so the undo travels with a
backup, cannot be separated from the realm, and is refused an edit by the database. The row goes
when the import is undone; the history keeps both events and is never rewritten.

**No command performs an import or takes one back out.** That holds for all four products,
including the two with bridges: `compat::neo::import`, `compat::desks::import`, both `roll_back`
functions and `compat::undo_for` are library code, and the only thing that runs them is the
rehearsal, against copies. `yougori rollout advance --profile models --yes` records that an
administrator considers themselves at the import stage and moves nothing, and both sentences the
engine prints for that stage say so. The verb that would perform the import, the verb that would
undo it, and the realm identifier a status would name as the undo's target arrive together or not
at all; the always-null field that named it has been taken out until then.

**The verb that moves a live record aside goes through the stage machine.** `rollout retire` asks
`advance` whether the profile may reach the retire stage, so a product with no bridge, a profile
whose turn it is not and a profile still inside its retention are refused in the stage machine's
own words; the stage is recorded only once the file has moved, and `unretire` puts the stage back
with the record. The first of those three no longer refuses any shipped product, because all four
have a bridge; it is kept, and `why_no_bridge` reads the frozen register rather than naming a
product, so a product added later without one is refused with its own sentence on the day it is
added. One product per stamped folder, because the folder's manifest describes one record and
`forget` deletes the whole folder on the one retention it names.

**Nothing deletes a customer's record on a timer.** No sweep, no cleanup on upgrade, none on
uninstall. `forget` is the only function in the phase that deletes anything, nothing calls it, and
it refuses until the retention has run out: ninety days by default and thirty at the shortest, both
of them proposals nobody has measured or reviewed against a customer's obligations.

**All four products have a bridge, and what each one cannot carry is said everywhere it matters.**
`compat::bounty` and `compat::access` joined `compat::neo` and `compat::desks` on 19 October 2026,
each with the same four operations: rehearse, import, roll back and compare. Schema version 12
widened the one column that says which bridge an import came from, so an import can still be undone
after a restart whichever of the four ran it. The rehearsal now runs a real import and a real
rollback for every product rather than for two.

What neither of the two new ones can carry is in `missing()` in each module, in each module's own
header, and in [rollout.md](rollout.md) section 7, and the two sentences that matter most are
these. A bounty's authorisation becomes a research scope that arrives **a draft**, because freezing
one needs an approver who is not its author and a bounty host has one administrator; a draft places
nothing, so the realm is honest and inert until somebody in it decides that themselves. And **no
Access Grid credential value crosses**: the record holds each one sealed with the key in that
computer's vault, a realm refuses to hold a value at all, and what arrives is the name of a vault
entry nobody has written and a fingerprint that matches no value, so the broker refuses that
credential in words until an administrator puts the value there. Two further things are refusals
rather than silences: a research import is undone by deleting the realm it created, because a
research realm closes and disposes of its record and never deletes it; and an Access Grid import
that carried a decision out of the hub's own log cannot be taken back out at all, because a realm
writes a decision once and never withdraws one.

The runbook is [rollout.md](rollout.md), and its last section is the list of things that cannot be
written from here: every duration, whether a fortnight contains what the coverage gate asks for,
whether ninety days is right, whether a copy of a realm under write load contends with its writers,
and the live view of a Sandbox Grid's computers, which the hub keeps in memory and does not hand
out. Until that last one is wired, observing the workspaces profile from a record on disk proves
one thing only: that both sides refuse to place a desk on a computer that has said nothing.

## The robustness pass, 19 October 2026

Seven things each phase had written down in its own "not done" list, closed or proved already
closed. Nothing here is a feature; every one of them is something a production deployment would
have hit.

**A connector's notes were unbounded, and worse than unbounded.** Each connector kept a
`Vec<Note>` that nothing ever drained and handed back a *copy*, so a connector nobody asked grew
for as long as the process ran, and a sweeper working through a hundred tasks sealed the first
task's notes into the realm's history a hundred times. The second is the worse of the two: a
history that says something happened a hundred times when it happened once is a history an
operator will believe. `connector::Notes` is now the one note book for all three connectors; it
holds 512 and taking them empties it. Past the cap the oldest go, and the first note handed over
says how many went and what to do differently, because a history missing part of a run and not
saying so is worse than a short one.

**A long-offline realm's chain can now be bounded without weakening the trim rule.** `Store::trim`
drops events only as far as `exported_to`, and a research realm is built to reach nothing, so it
can never export and nothing is ever dropped. An unexported event is still never dropped and the
database still refuses to drop one. What an operator is given instead is `export::Bundle`:
`Core::write_history_out` verifies the chain, writes everything that has not left this computer
into one file and reads it back seal by seal before calling it written, and **marks nothing**,
because a file beside the realm is not a copy of anything. `Core::carried_out` is the second step,
and it is keyed on the file rather than on a number: a number is something somebody can type, and
the marker is the one thing between an event and the delete guard. A bundle from another realm,
one that was edited, one that was truncated, one claiming to reach past what the realm wrote and
one handed back twice are each refused in words.

**`Core::advance` is keyed on the reservation.** It took a workload identifier, looked up whatever
reservation the work held *now*, and asked for a live one only before `Preparing` and `Running`.
So a computer that went quiet, had its work given to a second computer and then woke up could walk
that second computer's work from leased to preparing to running to completed, and the person
waiting would be told their request had finished by a computer that never produced the answer.
It is now keyed on the reservation the way `give_back` already was, every step needs a reservation
that is neither given back nor run out, and a reservation the work no longer holds is refused
without a row being written, because a realm should not write a row every time a computer that was
left behind knocks. `a_computer_that_woke_up_late_cannot_move_on_work_that_went_to_another_computer`
fails without the guard; twenty-three call sites moved.

**The disk is watched in the three places it matters.** Starting a realm and taking a copy both
refuse outright when there is measurably not enough room, and `Core::ready` warns below a gigabyte
and says plainly below 256 MB what is about to happen. The write path does not ask: a check per
transaction is a syscall per audited action for a condition that changes over hours, and SQLite
already refuses a write it cannot make. On Windows the number is measured, and everywhere else
`room::free` answers that it does not know and every caller treats that as permission to carry on.
Why it is not measured elsewhere is in the module: there is no free-space call in the standard
library or in any crate this one already depends on, and the POSIX one needs a `statvfs` whose
layout differs between Linux, macOS and the BSDs, where a wrong guess is not a wrong number but
undefined behaviour.

**Phase 12's connector note was half stale.** It said there was "no timeout, retry, backoff,
provider-throttle handling, circuit breaker or cap on concurrent provider calls". Read against the
code: every provider call already had a timeout, ten seconds to connect and a minute for an
answer, through `https::call`; a token bucket and a breaker already existed in
`connector/limits.rs` and were already wired into `wire::Keyed`; and `may_retry` and `backoff`
were written and tested. Three things were genuinely missing and are now closed. Nothing anywhere
read a provider's own throttle, and worse, a 429 reached `breaker.succeeded()` through the branch
that treats anything under 500 as "the provider answered", so being throttled *forgot* every
refusal before it. Nothing capped concurrent calls, so a hundred callers could each take a token
inside the same second and all wait on the provider together. And the four connectors that ship,
the only ones in this repository ever pointed at anything, had none of it in front of them at all:
no budget, no breaker, no cap, and no deadline over an operation that is a sign-in followed by two
or three more calls each with its own minute. All four now carry the same restraint, with
`desktop::WHOLE_OPERATION` at two minutes over the lot; a deadline on something that was going to
change the provider comes back as `PartlyDone`, which `may_retry` refuses to repeat, so a lost
answer cannot become a second change. Both runbooks were corrected.

**Health and a reading are served, and the decision is written down.** Nothing in `grid/src/core`
binds a port and that has not changed. What changed is that the engine decided what to do with the
values: `src-tauri/src/grid_observe.rs` reads every realm on this computer, `yougori grids health`
answers from it, and `yougori grids observe` serves `/healthz` and `/metrics` on `127.0.0.1` with
a bearer token the engine makes at random and hands back once. Three things about it are
deliberate. Every realm is opened **read-only**, because `Core::open` migrates and a health
endpoint that brought a customer's realm forward because a monitoring agent scraped it would be
among the worst bugs this product could ship; `health::checkup`, `health::readiness` and
`metrics::reading_over` were split out to take a `Store` rather than a `Core` for exactly that, and
each still costs the number of statements the operations document says it does, because the
lifecycle and whether the realm does research are passed in rather than read again. No key is
needed and none is read, so a realm whose key has been lost is still one this can report on. And
the listener is off until somebody turns it on, because a desktop application that opens a port
nobody asked for has made a decision for its owner. The two verbs are answered by the engine's own
register rather than by a product, because a checkup comes from a realm's database and because an
operator has to be answered on a computer where a product is in trouble. The twelve wire methods
are still twelve.

**Clippy was already clean, and still is.** Phase 11 fixed the `never_loop` in `grid/src/relay.rs`
and said so in the security review; the note that it still fails was stale. `cargo clippy --locked
--all-targets` on `grid` exits zero with 54 warnings, none of them deny-level and none in `core/`.
The `poll_write` that lint was about is unchanged and the relay's own tests pass.

**`Core::record()` is gone.** A whole-realm read behind a getter's name that panicked when the
database would not answer, with sixty-nine test call sites. Both halves were wrong: a scan behind
a name like a getter is how a scan ends up on somebody's request path, and a getter that panics is
how a realm whose disk has gone takes the process with it. Every call site uses `snapshot()`,
which is named for what it is and reports trouble, and `snapshot`'s own comment now says why the
other one is not there.

## What cannot be done in this repository, and why

This is stated once here so no phase has to pretend otherwise.

**Live enterprise systems.** The plan names roughly a hundred integrations: Citrix DaaS and Virtual
Apps and Desktops, Omnissa Horizon, Windows 365, Azure Virtual Desktop, vSphere, Entra ID, Okta,
Auth0, CyberArk, BeyondTrust, the AWS, Azure and Google clouds, their storage services, and the
SIEM exports. Each needs a tenant, a vendor SDK and credentials. None of those exist here, and a
standing rule for this work forbids reaching a live target at all. What can honestly be built is
the connector contract, the fixture-backed adapters, and a matrix that says which is which. An
adapter that has never spoken to the real system is marked mock-tested or interface only, and the
product says the same thing.

**Hardware that is not in this computer.** Attestation, TPM state, Secure Boot, BitLocker and
FileVault, NVIDIA MIG and vGPU partitioning, AMD ROCm and Intel GPU discovery can be read where the
machine has them and stubbed where it does not. A stub reports unverified rather than assuming the
answer, which is already the rule in `identity.rs`.

**Swarm Mining must not be run here.** A live worker would be disrupted. The research realm is
therefore built and tested without starting a worker: the realm, its isolation, its approvals and
its transfer rules are all testable on their own, and they are what Phase 6 proves.

**Penetration testing against third parties.** Phase 11's threat testing is done against this
software on this machine. Nothing is aimed at anyone else's system.

## Standing rules that shape the work

- Nothing is committed and nothing is pushed until the owner says so.
- One branch, `main`, and no worktrees left holding branches.
- No capability that weakens, bypasses or disables a model's safety behaviour will be built, in the
  research realm or anywhere else. The owner's plan says this and the architecture agrees with it.
- No prompt, answer, credential or personal file is written to a realm database.
