# Grid Core: running one

What a grid is made of, how large it is supported to get, what it can say about itself, how to
upgrade it, how to keep it, how to get it back, and what to do when something is wrong.

This is the operations document for Grid Core specifically. The architecture is in
[ADR 0001](0001-architecture.md), the staged plan in [plan.md](plan.md), what is being protected in
the [threat model](threat-model.md), and the state of every integration in
[adapters.md](adapters.md).

Two things are said here before anything else, because everything below depends on them.

**One SQLite database per realm on one computer is not a high-availability design.** There is no
replication, no leader election, no failover and no second copy of a realm serving at the same
time. Section 9 says exactly what that means and what would have to change. Nothing in the product
claims otherwise.

**The sizes in section 1 are design bounds, not a service level.** Section 2 says what was actually
measured, on what, and what the measurement does not show.

---

## 1. Supported sizes

One realm, one database, one computer. The numbers are in code, in
`grid/src/core/limits.rs`, and each one names the door that enforces it. A number only in a
document is a number nobody keeps.

| Thing | Limit | Enforced by | Why it is there |
| --- | ---: | --- | --- |
| People and services | 512 | `Core::add_principal` refuses | Parity with the shipped Sandbox Grid (`desks::MAX_PEOPLE`). The desks bridge cannot bring across more people than the hub holds, so a larger number here is one nothing can reach |
| Computers enrolled | 1 024 | `Core::enrol_device` refuses | Two per person: a laptop and a desktop, which is the shape the product assumes |
| Computers offering resources | 512 | `Core::offer_host` refuses | One host row per computer that offers. This is the number every placement decision walks, so it is the number section 2 measures at |
| Model plans | 32 | `Core::add_model_plan` refuses (`model::MAX_PLANS`) | Reconciling rewrites the whole profile when anything moves |
| Workspaces | 256 | `Core::order_workspace` refuses (`workspace::MAX_WORKSPACES`) | Parity with `desks::MAX_DESKS` |
| Work in flight at once | 4 096 | `Core::submit` refuses | The set the sweep walks. It is walked through an index, but it is still the per-second budget |
| Credentials | 1 024 | `Core::add_credential` refuses | A credential hub of that size is realistic, and `UNIQUE (realm_id, name)` means each was deliberately named |
| Grants of a credential to a person | 16 384 | `Core::allow_credential` refuses | Credentials times the people likely to hold any one of them |
| Requests open at once | 1 024 | `Core::ask` refuses | A request lapses after fifteen minutes unless the caller asked for longer, so this is a rate as much as a size |
| Research scopes | 64 | `Core::add_scope` refuses (`research::MAX_SCOPES`) | Already in the research profile |
| Standing allowances live | 4 096 | Warned, not refused | An allowance is created by a decision somebody already made. Refusing to write it would lose the decision |
| Events in the history | 200 000 | Warned, not refused | See below |
| Reservations written | 200 000 | Warned, not refused | Reservations are never deleted, only released: they are the record of what work has been tried on. The work in flight accounts for 12 288 of these; the rest is finished work, which nothing deletes and nothing bounds, and 200 000 is a judgement about roughly 50 000 finished pieces of work rather than a derivation |
| Brokered requests written | 500 000 | Warned, not refused | `credential_uses` takes one row per brokered request and the database refuses to delete one |

**Why four of them warn rather than refuse.** Refusing to record what happened means refusing
whatever caused it. A realm that stopped serving because its history had grown would turn a tidying
problem into an outage, and an operator would find out from the outage. `Core::ready` reports
Degraded with a sentence naming the export instead, which is the thing that has to happen for the
history to be trimmed at all. **Nothing outside the core calls `Core::ready` today**, so the
warning is a check somebody has to run rather than one anything runs; section 12 says so with the
rest of that gap.

**What nothing bounds.** Placements accumulate for the life of a workspace, because a placement
number is monotone and never reused. A workspace placed a thousand times is a workspace that has
been failing to settle, and that is worth noticing rather than capping.

---

## 2. What was measured, on what, and what it does not show

### The instrument

There is no benchmark framework in this repository and none was added. What varies in this code is
the number of statements the database is asked and the number of rows those statements give back,
not nanoseconds: every commit is an fsync (`PRAGMA synchronous = FULL`), so a timing harness on
this storage measures the disk far more than the code, and a number that moves with the disk
cannot be asserted on a slow machine without being either meaningless or flaky.

So the instrument is SQLite's own statement trace, which `rusqlite` already exposes behind its
`trace` feature. It is asked for as a dev-dependency, so a release build does not carry the trace
machinery at all. `grid/src/core/bench.rs` is the meter; the tests are in
`grid/src/core/bench/tests.rs`. Each one builds the same realm at two sizes and asserts the
statement count is **equal**, which is a property that holds on any machine.

**What the meter cannot see, which decides what every row figure below means.** The row count is
of rows *given back*, not rows read. SQLite reports one row for a `COUNT(*)` however much of the
table it added up, so a statement that walks half a million index entries and a statement that
makes one b-tree descent are the same number here. A low row count therefore proves the work did
not carry a table back into memory, which is what the code before this phase did; it does not
prove which index a query used, and nothing in this crate asserts a query plan. Where the cheap
shape of a statement is the property, the test asserts on the statements themselves, which the
meter also records: a `SELECT COUNT(*) FROM audit_events` coming back onto a path is invisible to
the counters and plain in the text.

Where a wall time appears below it was printed, never asserted. No test in the ordinary suite
fails because a machine is slow.

### What the tests assert

| Test | What it asserts |
| --- | --- |
| `one_reservation_costs_the_same_number_of_queries_whatever_the_grid_holds` | Granting one reservation costs the same number of statements at 2 computers with 20 reservations and at 16 computers with 4 000, and reads under 400 rows at the larger size |
| `a_question_about_one_computer_never_reads_every_reservation` | `free_on` is 2 statements and at most 2 rows in a realm holding 2 000 reservations |
| `deciding_a_request_does_not_read_every_account_in_the_grid` | Deciding costs the same statements with 4 people and with 202 |
| `whether_anybody_else_could_agree_is_the_same_answer_the_people_in_the_grid_give` | The query that replaced reading every account gives the same answer as reading every account, including that a suspended approver does not count and a realm administrator does |
| `recording_what_happened_costs_the_same_statements_whatever_the_history_holds` | Writing one event costs the same statements with 20 events behind it and with 820. Both sizes are under `audit::KEEP`, so this is the ordinary write and not the trim |
| `the_sweep_gives_back_only_the_reservations_that_have_run_out` | A sweep of a realm holding 300 reservations and one holding 3 000 each give back the five that were due, in the same number of rows, under 50 |
| `the_health_check_touches_a_handful_of_rows_and_never_reads_the_history` | Liveness is 4 statements and at most 4 rows |
| `a_reading_costs_the_same_whatever_the_grid_holds` | A reading costs the same statements at 2 computers and at 16, and reads under 200 rows at 4 000 reservations. The realm it measures holds no workspace, no packed copy and no model plan |
| `a_reading_does_not_carry_back_a_row_for_every_packed_copy_ever_made` | A reading is the same statements and the **same rows** with 2 packed copies waiting and with 400, which is the one statement in a reading whose cost used to grow with what the realm had done |
| `a_grid_refuses_the_row_after_its_limit_and_says_which_number_it_reached` | Each enforced limit refuses the row after it, with the number in the sentence |
| `a_health_check_never_verifies_the_history` | Readiness is eight statements and at most eight rows, which is the number section 4 carries |
| `readiness_never_counts_the_three_tables_it_warns_about` | No statement a readiness check runs is a count over the history, the brokered request ledger or the reservations |
| `a_reading_counts_the_queue_the_reservations_and_the_computers` | A reading is twelve statements in a realm without the research profile, which is the number section 5 carries |
| `a_history_past_what_it_keeps_is_still_trimmed_without_counting_it_every_time` | Taking the count off the write path did not stop the history being trimmed, nothing unexported is dropped, and recording one thing in a realm that never exports runs no count over the history |

### What was actually run

`cargo test -p yougori-grid --lib -- --ignored --nocapture grid_core_load_shape`, on the
development machine this was written on: Windows 11, an ordinary desktop SSD, a debug build.
19 October 2026.

The block below is **reformatted for width from that run, not pasted from it.** The statement and
row counts are as printed. The times are rounded. The counts line takes four numbers out of the
`Counts` struct the test prints in full, and the sweep line is printed with a reservation count
beside it that is left out here.

```
built 512 computers and 50000 reservations in 3.4s
one reservation:                16 statements,  1540 rows,  11.4 ms
one reading:                    12 statements,    10 rows,   2.0 ms
one sweep:                       2 statements,     0 rows,  69 microseconds
one reconcile with no plans:     4 statements,  1024 rows,   4.1 ms
one snapshot of the whole realm:                            230 ms
counts: 512 computers, 501 workloads, 50 001 reservations, 1 028 events
```

The statement and row counts are the same on every run and on every machine. The times are not:
two runs on this machine gave 230 and 272 milliseconds for the snapshot. That is the whole reason
the assertions are on counts.

**What this shows.** Granting a reservation in a realm at the published computer limit, holding
fifty thousand reservations, is sixteen statements. The rows it reads are the computers and their
owners, which it has to look at, and not the reservations, which it used to read once per computer:
the cost grows with how many computers are in the realm and no longer with how much the realm has
ever done. A reading of this realm is twelve statements and ten rows, plus one row per model plan
in a realm that has any, because every number in it is a count or an aggregate written against the
version 10 indexes. A sweep with nothing due is two statements.

**What this does not show.**

- It is a debug build on one machine. A release build is faster and a slower disk is slower. No
  number here is a service level.
- It says nothing about how many disk pages a statement touched, or about how many rows SQLite
  read, only how many rows came back. A count returns one row whatever it counted.
- The realm it was taken on holds no workspace, no packed copy and no model plan, so the ten-row
  figure says nothing about what those add. What the reading costs as packed copies accumulate is
  measured separately, by `a_reading_does_not_carry_back_a_row_for_every_packed_copy_ever_made`.
- It was measured at the computer limit with fifty thousand reservations, not at the two hundred
  thousand the limits table warns at.
- The one remaining linear cost is deliberate: a placement decision reads every computer in the
  realm, because it has to consider each one. At 512 computers that is about 1 500 rows.
- `snapshot` is still the whole realm and takes a quarter of a second at this size. That is what a
  portable backup costs, and it is why nothing on a request path calls it.
- No model was loaded, no workspace was built, no provider was reached and no worker was run.
  Model streaming, image pull and sandbox creation are not in this crate and were not measured;
  the core never sees a prompt, a token or an answer.

### The comparison, which is arithmetic rather than a measurement

The code before this phase read every reservation in the realm once, and then read every
reservation again inside the loop over computers, once per computer. At 512 computers and 50 001
reservations that is about 1 026 statements and about 25 million lease rows materialised for one
reservation. That figure is counted from the shape of the code that was there, not measured: the
old path was replaced rather than benchmarked beside the new one.

---

## 3. The queries that were fixed

Every one of these was a whole table read to answer a question about one row, or a whole table read
inside a loop over computers. Each is now a targeted query, and schema version 10 adds the indexes
they are asked with.

| Was | Is |
| --- | --- |
| `free_on` read every reservation in the realm | `Store::reserved_on`, one query for one computer |
| Placement called `free_on` once per computer | `Core::free_everywhere`, one pass over computers and live reservations |
| Placement asked `device()` once per computer | `Store::active_devices`, one query |
| Workspace placement asked `standing_pledge()` and `condition()` once per computer | `Store::standing_pledges` and `Store::conditions`, one query each |
| `tried` read every reservation in the realm | `Store::leases_tried`, one query, one row per reservation on that work so the retry budget is unchanged |
| `unfinished_on` read every workload and filtered in Rust | SQL, through `workloads_by_device` |
| `expire` read every workload including finished ones | `Store::unfinished_before`, through `workloads_by_deadline` |
| `decide` read every account, and one more query per account | `Store::another_holder_of`, one query, with the join to `principals` that keeps suspended approvers out |
| `standing` read every allowance | `Store::allowance_for`, through `allowances_by_holder` |
| `agreement_for` read every request the realm has ever held | `Store::standing_requests_about`, through `requests_by_resource` |
| `order_workspace` read every workspace to compare its length | `Store::workspace_count` |
| `workspaces_of` read every workspace and filtered by owner | `Store::workspaces_owned_by`, through `workspaces_by_owner` |
| The next placement number read every placement to take the largest | `Store::last_placement_number`, through the existing descending index |
| `stuck_parcels` read every packed copy ever written | `Store::stuck_artifacts`, through `workspace_artifacts_waiting` |
| A reading built every stuck packed copy to take the length of the list | `Store::count_stuck_artifacts`, the same question counted in the database, through the same index |
| Readiness read fourteen counts to use two of them | `Store::ever_written`, one statement and two b-tree descents: the largest row identifier of the ledger and of the reservations, which for insert-only tables is how many rows each has been given |
| `offer_host` and `report_condition` read every computer to find one | `Store::host_of_device`, through `hosts_by_device` |
| `revoke_device` read every reservation in the realm | `Store::leases_on`, per computer, through `leases_by_host` |
| `trim` ran `SELECT COUNT(*) FROM audit_events` on every audited action | Index seeks: the smallest sequence, the one just written, and the export marker. The count runs only when there is exported history to drop, so a realm that never exports never pays for one |
| `history_shape` counted the whole history to say how long it is | The span between the smallest and largest sequence, two b-tree descents, because sequences are dense and only a prefix is ever dropped |
| Undoing an import read every workload, computer or workspace | `Store::work_from`, `any_other_device_of`, `holds_any_host_or_plan`, `holds_any_workspace_or_image` |
| Closing a research scope read every workload | `Store::unfinished_noted` |
| Reconciling model plans rewrote the whole profile on every computer check-in | It writes only when something moved |

**Where `snapshot()` is still called, and why.** Two places, and both are correct.
`Core::backup` takes the whole realm, because a backup is the whole realm. `Core::record` is the
same thing behind a name that reads like a getter, kept for callers written against the first core;
nothing outside the tests calls it and nothing new should. `Core::export_workspaces` does not call
it, and it is the model the rest follow: five targeted reads into a record.

**What was considered and not done.** Coalescing model reconciliation into the background would
take it off the request path, and it was rejected: it delays where a model lands by however long
the pass waits, and the Phase 3 parity claim rests on tests that compare this core's placement with
the shipped hub's computer by computer. Making the write conditional gets most of the benefit and
changes no placement at all.

---

## 4. Health and readiness

`grid/src/core/health.rs`. Two checks, deliberately kept apart.

**`Core::healthy()`** is liveness. Four statements, each a single row: does the database answer,
what shape is it at, what is the realm doing, and where did the history get to. A realm with no
computers in it is alive, and that answer is correct.

**`Core::ready(now)`** is readiness. Eight statements: the four liveness ones, then one that is
`Host::takes_work` and `Device::active` written in SQL, then three that read the sizes of the
things nothing deletes from, so an operator hears about the history, the brokered request ledger,
the reservations and the live allowances from a check rather than from a full disk.

Every one of the eight is a b-tree descent or a bounded range, and none of them is a count with no
`WHERE`. That is deliberate and it is the difference between a check and a scan: the three sizes
this reports are the three the limits table warns at 200 000, 200 000 and 500 000, and counting
them would mean walking about a million index entries every time an operator asked. The history's
length is the span between its smallest and largest sequence; the ledger and the reservations are
each a largest row identifier, which for a table nothing deletes from is how many rows it has been
given; the live allowances are a count through `allowances_by_expiry`, which visits live rows only.
`readiness_never_counts_the_three_tables_it_warns_about` is the test that holds this, and it
asserts on the statements rather than on the counters, because a count is invisible to those.

Readiness still costs more than liveness, so `healthy` is the one to put behind a probe that runs
every second.

**Neither verifies the history.** `Core::verify_audit` reads every event and re-seals each one,
which is a whole-table read plus one HMAC per event. Putting that behind a probe that runs every
second is the obvious wrong move, and
`a_health_check_never_verifies_the_history` is the test that stops somebody making it. Verify the
history deliberately: in a restore drill, after a crash, or when somebody suspects something.

A probe never runs `PRAGMA wal_checkpoint`, which blocks the writer.

**Who serves them.** `yougori grids health` answers from the engine, reading every realm on this
computer read-only; `--full` adds the reading. `yougori grids observe` starts a listener on
`127.0.0.1` that answers `/healthz` and `/metrics`, and hands back a bearer token once. `/healthz`
is 503 when any realm is down and 200 otherwise, degraded included: a grid that is answering is
answering, and paging somebody at three in the morning for a warning is how warnings get turned
off. A computer that holds no realm at all is serving, because today that is every computer.

---

## 5. The reading, and where each number comes from

`grid/src/core/metrics.rs`. `Core::reading(now)` is twelve statements in a realm without the
research profile and thirteen in one that has it, because `research_shape` is one more count.
Every one of them is a count or an aggregate written against the version 10 indexes, and all but
one gives back a single row; the exception is the grouped statement behind model readiness, which
gives back a row per model plan and is capped by `model::MAX_PLANS`.

That says the statements and the rows handed back do not grow with what the realm holds. It does
not say the time does not: the time a count takes grows with the table it counts, and nothing here
has measured one at the sizes section 1 warns at.

| Number | Where it comes from | What it does not mean |
| --- | --- | --- |
| Queue depth, by stage | `SELECT stage, COUNT(*) FROM workloads WHERE stage IN (…) GROUP BY stage`, through `workloads_by_stage` | Nothing about whether the work is progressing, only where it is |
| Oldest reservation age, live reservations | `MIN(granted_at)` over `leases_live_by_expiry` | The oldest, not the average. An average would need a scan and an operator acts on the oldest |
| Computers offering, taking work, heard from recently | Three counts over `hosts`, `devices` and the join between them | **Heard from recently counts computers that have authenticated.** Nothing else writes `last_seen_at`. A computer that is on and idle and never authenticates is not counted, and a realm no profile authenticates against reports nought |
| Model readiness | `model_plans LEFT JOIN model_assignments`, grouped | This is **placement**: which plan the realm put on which computer. Whether a model is loaded changes every few seconds and writing that into a realm database would turn it into a telemetry store. The `reported` field is `None` until something tells the realm, and `None` is not nought |
| Workspace failures, waiting, attempts, rebuilds | Two counts over `workspaces` through `workspaces_by_state`, plus two sums over the table | Attempts and rebuilds are totals for the life of the realm, not rates. **Waiting answers the window that was asked for, not the cut one.** How far the history reaches cuts the refusal count below, because that count comes out of the chain; nothing trims `workspaces`, so cutting this one would turn a young realm, a trim, or the hour after a desks migration into a pile of workspaces that look as though they had waited |
| Stuck packed copies | `COUNT(*) FROM workspace_artifacts WHERE …`, through `workspace_artifacts_waiting`, with the same day `Artifact::stuck` uses | The data is safe; what is wrong is that no computer has had room |
| Approval latency | `MIN(requested_at)` over waiting requests, and `AVG(decided_at - requested_at)` over decisions in the window | The average is over the window, and the window is capped by the history |
| Credential failures | `COUNT(*) FROM audit_events WHERE at > ? AND capability = 'credentials' AND decision = 'refused'`, through `audit_events_by_time` | **Capped by how far the history reaches.** The chain is trimmed once exported, so a window longer than the chain holds would report fewer refusals than happened. `Reading::reaches` says where the cap is and the window is cut to it |
| Credentials due to rotate | `COUNT(*) FROM credentials WHERE retired_at IS NULL AND rotate_by <= ?` | Due, not overdue in any policy sense |
| Brokered requests held | `COUNT(*) FROM credential_uses` | The ledger's size. The database refuses to delete a row from it |
| Research findings | Three counts over `research_scopes` and `research_findings` | Nought in a realm that does no research. A research realm is a `Core` of its own with its own database and its reading is never joined to the company's |
| Counts of everything | One statement of fourteen sub-counts | Sizes, not health. This is the one statement in a reading whose time grows with the realm: a `COUNT(*)` with no `WHERE` walks the whole b-tree, which is why readiness does not use it |

A reading carries no name, no path, no prompt and no value.
`a_reading_carries_no_name_no_path_and_no_value` builds a realm whose person, credential and
destination are known strings and asserts none of them is in the serialised reading.

**Nothing in Grid Core binds a port.** A reading is a value the product serialises. Whether there
is an endpoint is a decision for whatever opens the realm, not for the core.

---

## 6. Upkeep: what runs when

`grid/src/core/upkeep.rs`. `Upkeep::tick(&mut core, now)` with no clock of its own: the caller
supplies the time, as everywhere else in the core, and nothing constructs `Upkeep` outside its own
tests yet. The cadences below say what a host should do, not what any realm on this computer does.

| Every | What | Why that cadence |
| --- | --- | --- |
| second | Reservations that ran out, and work past its deadline | A reservation that has run out is holding room on a computer that could be taking other work. Both are index range scans |
| minute | Requests nobody answered, sign-ins whose permission ran out | Neither weakens anything by waiting a minute: an expired request is already refused, and so is a lapsed sign-in's permission |
| hour | Permissions that expired a day ago, and trimming the history | Pure tidying. The history is trimmed only as far as it has been exported |

Each piece is independent: one that fails records a sentence and the others still run.

**What breaks if upkeep never runs.** Nothing about correctness. A realm nobody sweeps answers
every question the same way: a reservation that has run out holds no room whether or not anything
has marked it released, and work on it is refused either way.
`nothing_in_a_pass_is_on_anybody_s_request_path` is that test. What a realm nobody sweeps does
accumulate is rows that say nothing, and `Core::ready` is what says so.

---

## 7. Upgrades

Migration is already safe step by step: each step and the record of having run it are one
transaction, so a step that fails leaves the realm at the version it was at
(`a_step_that_fails_leaves_the_grid_at_the_version_it_was_at`). A realm written by a newer build is
refused rather than opened.

**Before an upgrade.** `Core::upgrade_with_a_copy(folder, now)` takes an exact copy of the
database first and then migrates, returning where the copy went and which versions it ran. The
copy is for the case a transaction cannot help with: a step that runs perfectly and turns out to
have been the wrong idea.

**Taking a version back out.** `Core::how_to_undo(version)` answers in a sentence, read out of the
code rather than out of a list somebody keeps up to date by hand. Versions 5 to 11 were written
with a way back. Versions 2, 3 and 4 were not: for those the copy is the only way back, and
`how_to_undo` says exactly that.

Rolling back is rehearsable rather than a one-way door: opening the realm with this build
afterwards runs the step again.

**Outside this crate.** The installer has to compare the schema version before it replaces the
binary. `migrate` can only refuse after the user has already upgraded, and nothing in `grid/` can
make that happen earlier.

---

## 8. Backups, restore and disaster recovery

### The key comes first

**The realm's key is never in a backup, and a restore is refused without it.** The backup holds
the name of the vault entry (`KeyReference::for_realm`) and a check value, not the key. So the
whole schedule below is worth nothing unless that vault entry is backed up separately, out of
band, by the operator. That is the first line of this section rather than a footnote.

### What a backup actually contains

Both kinds are readable by anyone who can read the folder they are in.

- The **exact copy** (`Core::copy_to`, SQLite's `VACUUM INTO`) is a byte-for-byte realm database.
  Everything the realm holds is in it, in plain SQLite.
- The **portable backup** (`Core::backup`) is JSON holding the whole record: people with their
  names and addresses, computers, credentials by name, destination and vault reference, workspaces,
  and the sealed history. The key seals it for integrity and authenticity. **It does not encrypt
  it.**

Neither holds a prompt, an answer, a file from anybody's computer or a credential's value. Where
backups are written is as sensitive as where the realm lives.

### The schedule

| When | What | What it survives | What it does not |
| --- | ---: | --- | --- |
| Hourly | `Core::copy_to`, exact | A crash, a bad write, a deleted row | A bad migration: it is the same shape, so it migrates the same way. Losing the computer, if it sits beside the original |
| Daily | `Core::backup`, portable | A bad migration, because the portable shape is version tolerant | Nothing version tolerance cannot carry |
| Weekly | Keep a daily | A bad restore nobody noticed for a week | |

Keep 24 hourly, 14 daily, 8 weekly. `VACUUM INTO` holds a read lock while it runs, and on a realm
near the published sizes the single writer waits for it, so the hourly copy belongs in the upkeep
pass that already owns the connection rather than on anybody's request path.

**Nothing in this repository runs that schedule.** `Core::copy_to` is called by
`upgrade_with_a_copy`, by the core's own tests, and by nothing else; taking the copies is a job
for whatever opens the realm, and nothing opens one yet.

One more thing a copy does and does not do. `VACUUM INTO` has to write, so the connection that
takes a copy is read-write, and when it is the last connection to a realm in write-ahead logging
SQLite check-points on close: frames a crashed writer left in the journal are folded into the main
file and the two files beside it go. The copy holds exactly what the realm held, at the same
version, with nothing migrated. The realm's own bytes may move; no row does.

### The restore drill

`Core::rehearse_restore(folder, backup, key, now)` restores into a folder of its own, verifies the
history, runs the realm's own storage check, and reports the counts.
`Core::restore` already refuses a path that exists, so a drill cannot land on a live realm.

The valuable part of the report is **what a restore does not bring back**, and all three are
deliberate:

1. **Sign-ins.** A record carries no permissions, so a restored realm holding sign-ins would hand
   somebody a workspace on the strength of a permission that does not exist.
2. **Every permission the realm ever issued.** A restored realm has no record of issuing them, so
   each is refused the next time it is used.
3. **What every computer last said about itself.** Every computer must report its condition again
   before a workspace can be placed on it.

A drill that does not say those out loud teaches the wrong lesson about what a backup is.

Cadence: monthly, scripted, on the hourly copy. Quarterly, by hand, on the daily portable backup
with the key fetched from the vault exactly as it would be in an incident, because fetching the key
is the step that fails in real incidents and the only one a scripted drill never exercises.

### Disaster recovery

**Recovery point.** Up to one hour once something takes the hourly copy, and whatever left the
machine last until then, because nothing takes it yet. If that copy sits beside the original
then losing the computer loses both, and the recovery point is whatever left the machine last.
Copying backups off the machine is the operator's job; the product must say so rather than let a
copy beside the original look like safety.

**Recovery time.** Restoring the portable shape replays the record row by row through the ordinary
writers, most of which commit on their own, on a connection that flushes every commit. At the
published sizes that is a large number of separate transactions and it is the slowest path in the
design. It was not measured and it is not claimed. The exact copy restores in the time it takes to
copy a file, which is the path to use when the shape has not changed.

**Losing the computer entirely.** There is no automatic failover. Someone puts the realm's file or
its backup on another computer, fetches the key from the vault, and opens it. Every computer then
has to come back, report its condition and be given work again.

---

## 9. High availability: what this is not

**One SQLite database per realm on one computer is not a high-availability design.** Said plainly,
because the rest of this document would otherwise read like one.

What the code actually is:

- One connection, held in `Store`. There is no pool and there is one writer.
- A ten second busy timeout is the whole of the contention handling.
- The realm's key is in memory while the realm is open, so a second instance means a second copy of
  the key in a second process.
- Appending an event reads the chain's end, seals over it and writes, in one transaction. A sealed
  chain is inherently serial.
- Nothing in `grid/src/core/` binds a port. There is no leader election, no replication and no
  fencing.

What would have to change, in increasing order of cost.

1. **A single writer, stated.** Keep SQLite, make one process the only writer, give readers
   read-only connections. This buys concurrent reads. **It is not high availability**; it only
   stops a lock error being a surprise.
2. **A replicated log.** The history is already a sealed, ordered log, so shipping it to a second
   machine and replaying it looks attractive. It does not work as written: the history records
   decisions, not rows, so replaying it cannot rebuild a realm. Either the history grows a change
   payload, which changes what the threat model says goes into it, or this option is off.
3. **File-level replication.** Shipping the write-ahead log. Every commit is flushed, so the log is
   consistent at every commit and this is the cheapest real standby. It is still active and
   passive with a manual failover, and it needs the journal files, which are outside anything the
   core manages today.
4. **PostgreSQL.** ADR 0001 already decided this is the answer for a multi-node control plane,
   behind its own flag, reading the same portable shape. This is why every `Store` method returns
   plain types over `Result<_, String>` rather than database types: that signature is what makes a
   second implementation possible.

**Active and active is not available at any price with this storage.** The history is a single
sealed sequence per realm, and two writers cannot both be at its end. Multi-writer high
availability needs either one history per writer, which changes what a history proves, or consensus
over its end, which is a different product.

---

## 10. Incidents

**Severity.** S1: the realm cannot be opened, or its history does not verify. S2: no computer can
take work, or a workspace's only copy was on a computer that is gone. S3: a limit has been
reached. S4: a number is outside its band.

**The first five minutes, in order.** `Core::healthy()`. Then `Core::ready(now)`, and read its
notes: they are sentences, not codes. Then `Core::reading(now)`. Then
`Core::evidence(since, now)` if somebody else has to look at it.

**What an evidence bundle carries.** The checkup, the reading, every version the realm's database
has been through, what happened since a sequence the engineer names, and the identifiers of packed
copies nobody has taken. What happened is carried **without the words**: an action is a fixed word
this code wrote, such as `work.queued`, and the reason is left out, because some reasons are words
a person typed, such as the name somebody was added under or the place a credential may be sent.
Those belong in the realm's sealed history, which stays on the realm's computer. There is no
prompt, no file, no path, no owner name and no secret in an evidence bundle.

### Runbooks

Each opens with the first thing to run.

**The realm will not open.** `Core::healthy()`. If the shape is newer than this build, the realm
was opened by a newer Yougori: install that version or restore the copy taken before the upgrade.
If the file does not answer at all, the file or its journal is damaged: restore the most recent
hourly copy, then the daily backup if the copy will not open either.

**The shape is newer than this build.** Nothing can be done to the realm from here, and nothing
should be: a newer shape is refused rather than opened, deliberately. Install the newer build, or
restore the copy taken before the upgrade.

**A migration failed half way.** It did not. Each step and its record are one transaction, so the
realm is at the version it was at. `Core::history()` says which versions ran. Whatever stopped the
step is still there; the error names it.

**The queue is not draining.** `Core::reading(now).queue`. Work queued and nothing leased means
placement is finding no computer: `Core::ready(now)` says whether any computer can take work at
all. Work leased and nothing running means computers are taking reservations and not starting.

**Every computer is refusing work.** `Core::ready(now)`. Each computer is either draining,
committed to nothing, or belongs to a computer taken out of the grid. For workspaces specifically
there are four more reasons, all of them the computer owner's protection: going away, on battery,
nearly out of disk, or its person is using it when the grid was lent only its idle time.

**A workspace has waited an hour for a computer.** `Core::reading(now).workspaces`. The count of
workspaces waiting since before the window is the number. Why no computer will take it is in the
sentence `place_workspace` refuses with.

**A packed copy has been stuck for a day.** `Core::stuck_parcels(now)`. The data is safe; no
computer has had room for it. Add room or commit another computer.

**Approvals are not being answered.** `Core::reading(now).approvals`. If the oldest wait is near
fifteen minutes the requests are lapsing before anybody sees them. Check that somebody other than
the requester holds the approving permission and is not suspended: a realm whose only approver is
suspended cannot approve anything, and that is the rule working rather than a fault.

**A credential request is being refused.** The refusal names which rule refused it. The counted
refusals are in `Core::reading(now).credentials.refused_in_window`, and that count is capped by how
far the history still reaches.

**A brokered request has been open too long.** `Store::open_uses` lists them, and the broker's own
reaper closes them. A request open far past its limit means the broker stopped between opening the
record and closing it.

**The history does not verify.** S1. `Core::verify_audit()` names the event. Do not write to the
realm. Take an exact copy first, then compare against the most recent backup and against whatever
was exported off the computer: only a copy that left the computer settles where the history really
ended.

**The database file is growing.** `Core::reading(now)` gives the counts.
`audit_events_never_exported` growing means nothing is carrying the history off this computer, and
nothing is dropped past the export mark. Export, then let upkeep trim.

**The realm can reach nothing, so it can never export.** An authorised research realm is built to
reach nothing, so every sink refuses, the marker never moves and its chain grows for as long as it
runs. The answer is not a looser trim: an unexported event is still never dropped, and the
database still refuses to drop one. It is two steps the operator takes.

1. `Core::write_history_out(by, to, now)` verifies the chain, writes every event that has not left
   this computer into one file, and reads the file back event for event and seal for seal before
   calling it written. It marks nothing. A file on the same disk as the realm is not a second copy
   of anything, and one disk failure would lose both.
2. The operator carries that file somewhere else. Then `Core::carried_out(by, from, now)` reads
   the file they actually have, checks it belongs to this realm, checks every seal in it under the
   realm's key, and checks that its last event is the event this realm holds at that number with
   the same seal. Only then does the marker move, and only as far as the bundle reaches.

The second step is keyed on the file rather than on a number, and that is the point of it. The
marker is the one thing standing between an event and the delete guard letting it go, so a number
somebody typed must not be able to move it. A bundle from another realm, one that was edited, one
that was truncated, one that claims to reach past what this realm has written and one handed back
twice are each refused, in words. `Core::exported` is still there for a sink that confirmed.

**The write-ahead log will not check-point.** Something is holding a read open. Closing the realm
check-points and truncates. Never run a check-point from a probe.

**The disk is filling.** Every commit is flushed and the journal is beside the file, so a full disk
is the most common real failure for this storage shape. `Core::ready(now)` now says so: it asks the
operating system how much room is left where the realm is, warns below a gigabyte and says plainly
below 256 MB that the realm will stop being able to record what it decides, and then refuse
whatever caused it. Starting a realm and taking a copy both refuse outright when there is
measurably not enough room, because an operator told at that moment can choose another disk and
has lost nothing. The ordinary write path does not ask: a check per transaction would be a syscall
per audited action for a condition that changes over hours, and SQLite already refuses a write it
cannot make.

**On Windows the number is measured; everywhere else it is not.** `grid/src/core/store/room.rs`
asks the operating system on Windows, which is the platform this ships on. There is no free-space
call in the standard library and none in any crate this one already depends on, and the POSIX one
needs a `statvfs` whose layout differs between Linux, macOS and the BSDs, which would be guessing
at a C structure on platforms nobody here builds for. So elsewhere it answers that it does not
know, every caller treats not knowing as permission to carry on, and no note claims the disk is
fine. A host that can measure it on another platform should refuse before it opens the realm.

**A computer was lost with workspaces on it.** `Core::host_lost`. Every workspace it held keeps its
owner, its image and its trail. One whose data can still be found waits for a computer; one whose
data was only ever there has failed, and the record says exactly that rather than implying it can
be recovered.

**A restore brought back less than expected.** Read the three things a restore does not bring back
in section 8. If what is missing is not one of those three, compare the drill report's counts
against the backup.

**A provider is refusing.** Connector work is recorded before a connector is asked, so a task left
open is a task to look at rather than a change nobody knows about. What is in front of a provider
is in `grid/src/core/connector/limits.rs` and is the same for every connector: a token bucket of
thirty with five a second, a breaker that stops sending after five refusals in a row and stays
shut for a minute, a cap of four requests in the air at once, and the provider's own throttle.
A connection that is refusing without reaching anybody says which of those it is, in the refusal.

**A provider is throttling.** A 429, or a 503 that carries a `Retry-After`, stops that connection
at once for as long as the provider asked for, up to five minutes. One throttle is enough: unlike
a refusal, a throttle is the provider saying in terms that it is shedding requests, and inside a
customer's tenant that shedding is applied to everything their own people are doing too. A
provider asking for longer than five minutes gets five minutes and then an operator.

**A connector operation is hanging.** Every call has a timeout, and has had all along: the two
HTTP clients wait ten seconds to connect and a minute for an answer. What was missing was a
deadline over a whole operation, because one operation against a desktop provider is a sign-in and
then two or three more calls, each with its own minute. `desktop::WHOLE_OPERATION` is two minutes
over the lot. A deadline on something that was going to change the provider comes back as
`PartlyDone`, which `limits::may_retry` refuses to repeat, so a lost answer cannot become a second
change; a deadline on a read is an ordinary refusal and may be repeated.

---

## 11. What is never collected

No prompt, no answer, no file from anybody's computer, no credential value, no owner name and no
absolute user path. Not in a reading, not in an evidence bundle, not in the history and not in a
backup. The tests that hold this are
`a_reading_carries_no_name_no_path_and_no_value`,
`an_evidence_bundle_carries_identifiers_and_counts_and_nothing_anybody_would_mind_sharing`,
`a_credential_is_a_reference_and_never_a_value` and
`nothing_that_is_inside_a_workspace_is_ever_in_the_realms_database`.

---

## 12. What this phase did not do

- **Almost nothing outside the core calls any of this.** The one thing that now does is the
  checkup: `src-tauri/src/grid_observe.rs` reads every realm on this computer and answers
  `yougori grids health`, and `yougori grids observe` serves `/healthz` and `/metrics` to a
  monitoring agent on the loopback interface. Everything else is still unasked. No code opens a
  realm to serve a product request, constructs `Upkeep` or takes a copy on a schedule, so the
  cadences in section 6 and the schedule in section 8 still say what a host should do rather than
  what any realm does today.
- **Nothing serving a checkup opens a realm the way a writer would.** `Core::open` migrates, which
  is a write, so a health endpoint that opened realms the ordinary way would bring a customer's
  realm forward because a monitoring agent scraped it. `health::checkup`, `health::readiness` and
  `metrics::reading_over` therefore take a `Store` rather than a `Core`, and the engine opens each
  realm through `Store::open_for_reading`, which the operating system itself refuses to let write.
  `looking_at_a_realm_never_writes_to_it` compares the realm's bytes before and after.
- **No size here was measured at its limit.** The load shape ran at 512 computers and 50 000
  reservations. The limits table warns at 200 000 reservations and 500 000 brokered requests, and
  neither was built.
- **No high availability was built, and none is claimed.** Section 9.
- **No endpoint in the core, and that has not changed.** Nothing in `grid/src/core` binds a port;
  a `Checkup` and a `Reading` are still values. What changed is that the engine decided what to do
  with them. The endpoint is off until `yougori grids observe` turns it on, it binds `127.0.0.1`
  and nothing else, and it wants a bearer token the engine makes at random and hands back once:
  the token is never written to a file, never logged, never in an audit reason and never in a
  command line, and it goes away when the endpoint stops. That is the same guarantee the engine's
  own control door has, which is a named pipe or a socket only this user may open, carried onto a
  port that has no such thing of its own.
- **Connector reliability is no longer a gap.** The seam carries a budget, a breaker, a cap on
  concurrent calls, a timeout on every call, a deadline over a whole operation and the provider's
  own throttle, and the four connectors that ship are held to all of them. See section 10.
- **No off-machine backup.** Copying backups somewhere else, and backing up the vault entry that
  holds the realm's key, are the operator's, and the code cannot enforce either.
- **Nothing is live-tested.** Every number above was taken against fixtures on this computer.
  No provider, no collector and no tenant anywhere has ever been reached from this repository.
- **Nothing was measured against a model, a GPU, a provider or a worker.** Model streaming, image
  pull, sandbox creation and research scheduling are outside this crate, and Swarm Mining is never
  run here.
- **The restore time at the published sizes was not measured.** It is the slowest path in the
  design and it is named rather than claimed.
