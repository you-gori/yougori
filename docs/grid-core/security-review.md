# Grid Core security review

What was tested, what passed, what is an assumption, what cannot be verified in this repository,
and what a real engagement would have to cover. Written during Phase 11, 19 October 2026, against
the core as it stood that day.

Read this with [threat-model.md](threat-model.md), which now says for every claim which part of
the tree it is about and how far it is held up.

**This is a verification pass, not an audit.** It was written by the people who wrote the code,
it tested what they thought to test, and it is worth exactly what that is worth. A third party
with no stake in the answer has not looked at any of it.

## What was done

Five things, in this order, because each one found work for the next.

1. The threat model was read against the code and rewritten. Four of its claims were about a
   component that is not the core, two described behaviour that does not exist, one adversary was
   missing altogether, and three assets were not listed.
2. Nineteen attack tests were written in `grid/src/core/attack.rs`, covering the twelve families
   the phase names, plus five more against the outbound path in `grid/src/core/broker/tests.rs`.
   Every one performs the attack and asserts it fails. Every one says in its own comment what a
   pass proves and what it does not.
3. Fifteen authorisation invariants were written as sentences that are either true or false of
   any reachable state, in `grid/src/core/invariant.rs`, and checked over runs produced by a
   seeded generator in `grid/src/core/seed.rs`.
4. Seven seeded fuzz harnesses were written in `grid/src/core/fuzz.rs`.
5. Six recovery tests were written in `grid/src/core/recovery.rs`, against the gaps left by the
   dozen recovery scenarios the suite already covered.

Five defects were found and fixed along the way, and are described below with what each one
actually allowed.

## The numbers

| Crate | Gate | Before | After |
| --- | --- | --- | --- |
| grid | `cargo test --locked` | 320 passed, 2 ignored | 374 passed, 3 ignored |
| grid | `cargo clippy --locked --all-targets` | **failed**, before reporting a single lint | clean: no errors, 35 warnings in the library, none in `core/` |
| cli | `cargo test --locked` | 729 passed | 729 passed |
| src-tauri | `cargo check --locked --all-targets` | clean | clean |

Fifty-four new tests pass and one more is ignored on purpose. The two ignored tests that were
already there are unchanged: a live Cloudflare tunnel, and the adapter-matrix rewriter that
writes to the repository.

The new ignored one is `every_invariant_over_a_long_sweep`: two hundred generated runs of forty
calls with all fifteen invariants checked after every move. It passes, and it takes about ninety
seconds, which is longer than the whole of the rest of this crate's suite, so it is ignored rather
than made a gate. Every realm it makes is a SQLite file with `synchronous = FULL`, so each move is
at least one flush to disk. The committed version of each invariant runs six runs of twenty-two
moves, which is twelve seconds for the whole file.

## The attacks, and what each one is worth

All nineteen are in `grid/src/core/attack.rs`. The file's own header states the limit that
applies to every one of them: a pass proves a property of this code, on this computer, under a
clock the test supplies, with the realm called directly in one thread. **The core authenticates
nobody**, so every test assumes the one thing the core does not do.

| Family | Test | What a pass proves | What it does not |
| --- | --- | --- | --- |
| Realm crossing | `two_realms_on_one_computer_share_no_door_no_key_and_no_file` | A research realm refuses every company door on the realm's own capability; two realms are two files; neither opens with the other's key; neither file holds the other's realm id | Process separation. Both keys live in one operating system vault under one user |
| Token forgery | `a_token_edited_or_signed_with_a_guessed_key_is_refused_and_spends_nothing` | Ten claim fields are each inside the signature; sixty-four wrong keys all fail and none marks the permission spent | That HMAC-SHA256 is unforgeable, which is the `hmac` and `sha2` crates' business |
| Token forgery | `an_unsigned_token_never_reaches_the_database_or_the_history` | A forged token carrying ten kilobytes of a stranger's text writes one refusal event naming nobody, and no byte of the text reaches any row | That every other path filters caller text; each has its own test |
| Token forgery | `a_token_that_is_not_a_token_is_refused_and_never_a_crash` | Nine shapes including a four-megabyte input are each refused with a sentence | Anything about inputs this list did not reach |
| Token replay | `a_one_use_permission_survives_no_restart_and_no_second_handle` | Spending is in the database, so a restart and a second process both refuse the second use, and the database refuses to unspend it | Serializability. One thread, one chosen order |
| Revocation races | `nothing_revives_a_permission_a_withdrawal_killed` | A withdrawal in the same instant kills a permission; bringing an account back does not revive what it held; pausing refuses a held permission and reopening does not bring it back | That a withdrawal reaches an open connection or a running process |
| Approval bypass | `an_agreement_cannot_be_stretched_widened_or_decided_twice` | The ceiling holds at both ends; an allowance covers one method, one path, one person and one window; a decision cannot be made twice, in Rust or in the file | That twenty-four hours is the right ceiling, or that one person cannot hold two accounts |
| Audit tampering | `an_altered_event_names_itself_whichever_field_was_touched` | Eight fields each break verification; dropping the guard and recomputing a plain hash chain does not repair it, because the seal is keyed | Detection without the key. An attacker who holds it is out of scope by design |
| Audit tampering | `a_history_cut_off_at_either_end_is_caught_only_so_far` | A run deleted off the end is caught, because the chain no longer ends where the realm recorded it ending | Removal from the front, which is what trimming does, and removal by anybody who also edits `audit_chain`. The test performs that second case rather than describing it |
| Audit tampering | `nothing_a_stranger_sends_becomes_a_field_of_the_history` | A reason is stripped of control characters and cut to five hundred; a reason shaped like a value is withheld; the database refuses an identifier that is a sentence | That an identifier names something real. The bound is on length |
| Backup tampering | `a_backup_edited_after_it_was_taken_is_refused_whichever_part_was_edited` | An added administrator, a removed seal, a swapped header, a newer version and each of the three header fields that travel beside the record are refused; a history edited before the backup passes the seal and fails verification | Anything against somebody who holds the realm key |
| Backup tampering | `a_restored_realm_honours_no_permission_it_handed_out_before_the_backup` | A backup carries no permissions, so every one handed out before it is unknown afterwards | That a restore is safe in every other way |
| Credential leakage | `no_shape_of_a_secret_reaches_a_file_an_error_or_a_printout` | Four shapes of secret reach no file, no journal, no backup, no error message and no printout | That a secret never reaches this process's memory. The broker reads one on purpose |
| Credential leakage | `what_a_workload_gets_is_a_permission_and_it_names_one_destination` | A workload gets one-use claims naming one credential, place, method, path and size, with no vault name and no fingerprint in them | That a broker honours it, which the broker's own tests cover |
| Prompt leakage | `no_table_in_a_realm_has_a_column_that_could_hold_a_prompt_or_a_desks_contents` | No column in any of the realm's tables could hold a prompt, an answer or a desk's contents | Anything about a model's behaviour. This is a storage property |
| Prompt leakage | `a_computer_that_gives_work_back_never_chooses_the_words` | The words sealed into the history when work comes back are a closed set fixed in this crate | That every path uses a closed set. Several take free text and are bounded instead |
| Host impersonation | `a_computer_cannot_speak_for_another_or_rewrite_what_it_committed_to` | A computer cannot report on, adopt or park a workspace that is not its own, cannot offer more than it has, and cannot rewrite its commitment by offering again or by editing the file | **That the computer identifier was authenticated.** The core takes it as text |
| Worker escape | `a_permission_reaches_only_what_it_names_and_an_artifact_key_is_never_a_place_on_a_computer` | A permission for one piece of work is refused for another; one for a model is refused by the workspace door; seven path shapes are refused by Rust and again by the database | **Container, microVM or VM escape.** See below |
| Worker escape | `a_research_realm_has_no_door_to_a_credential_whatever_role_is_granted` | Every role in the realm in one pair of hands opens no credential door; the database refuses a credential row in a research realm outright | Containment of a research workload at run time |
| Network pivoting | `an_offline_realm_allows_nothing_and_a_credential_names_one_place` | An offline realm allows nothing including the empty destination; a listed realm allows only what is listed; a credential refuses plain HTTP, a bare host and a URL with a password in it; a research realm starts offline | That a workload obeys any of it. Nothing in the core enforces a network rule on a process |

### Worker escape, in plain words

The test above proves what this repository can prove, which is that a workload cannot reach
another realm's resources **through the realm's own doors**, and that an artifact key can never
be a place on a computer.

What remains unproven is the thing the words "worker escape" usually mean. Escaping a container,
a microVM or a virtual machine is a property of a hypervisor and a kernel, not of this code. Grid
Core holds a kind and an opaque reference to where a workspace was placed, and nothing else;
there is no boundary here to attack. Proving containment would mean starting real sandboxes on
this computer and attacking them, which this work does not do and was not asked to do. Nothing in
that test should be read as evidence that a compromised workload cannot reach the host it runs
on.

### The outbound path

The old plan for this phase said Grid Core had no network surface. That was wrong by the time it
was written: `grid/src/core/broker.rs` is the core's outbound path, and it was the largest
untested attack surface in the phase. Five tests were added in `grid/src/core/broker/tests.rs`,
all against servers bound to 127.0.0.1:

- `a_redirect_is_answered_and_never_followed`: a service that answers with a redirect does not
  get the credential sent a second time anywhere. The place the redirect pointed at is never
  connected to.
- `a_place_taken_away_while_the_value_is_being_read_stops_the_request`: the race the last look
  exists for. Everything was in order when the request was cleared and is not by the time the
  value is in hand.
- `egress_turned_off_while_the_value_is_being_read_stops_the_request`: the same for the realm's
  own outbound switch.
- `a_workload_cannot_set_the_header_its_credential_travels_in`: dropped on the way in, refused
  at the last look if anything puts one back.
- `a_credential_that_travels_in_a_query_is_not_doubled_by_the_workloads_own`: the parameter the
  workload set is replaced, not added beside, so the service sees one value and it is the grid's.

None of these proves anything about a real provider. Both ends of every one of them are this
computer.

## The invariants

Fifteen sentences, each either true or false of any state a realm can reach, in
`grid/src/core/invariant.rs`. Each has its own test and its own seed.

1. No permission is accepted whose account, computer or grid was already withdrawn.
2. A one-use permission is accepted at most once in the life of a realm.
3. A permission minted in another realm is never accepted here.
4. Every call that changed the realm left one more event behind it.
5. The history verifies in every state a run can reach, and names the edit when there is one.
6. No generation and no policy version ever falls.
7. A decision, once written, is never written again.
8. Nobody is the only approver of their own request while another exists.
9. A realm holds only the capabilities its kind allows.
10. Every role a person holds is a row that names where it came from.
11. Work is running only under a reservation that has not been given back.
12. No computer ever holds more than it offered.
13. Work that has finished never moves again.
14. Every standing allowance names a decision that exists.
15. A permission the grid still remembers names a policy version the grid has been at.

The generator is a seeded splitmix64 held in the test, as `compat/tests.rs` has used since the
placement comparison was written. No clock and no random number generator, so a failure is a seed
and a round number and running those two numbers again gives exactly the failure reported. No
property-testing crate was added, for a reason worth keeping: `grid` has one dev-dependency
today, and this repository tracks the source of every crate it ships for licence compliance, so a
dozen transitive crates for a test-only convenience is a dozen compliance rows. What a
property-testing crate would genuinely give and a seed does not is automatic shrinking to a
minimal counterexample; `seed::shrink` is a truncating substitute and saying that plainly is
better than implying the two are the same.

Two honesty measures are in the file itself, because a suite of invariants can be green by never
getting anywhere:

The long sweep earns its place: it found the fifth defect below, which six runs of twenty-two
moves never reached, and the truncating shrinker cut the failing run to three moves.

- `generated_runs_reach_the_states_these_invariants_are_about` fails unless twelve runs produce
  people, minted permissions, **accepted** permissions, refusals, permissions offered from a
  second realm, a run where the file was edited behind the realm's back, events and decided
  requests. It caught a real problem: before it, the generator almost never reached a state where
  a permission could be minted at all, so two of the invariants were passing vacuously.
- `the_generator_gives_the_same_run_for_the_same_seed_and_a_different_one_otherwise` fails if the
  generator stops generating.

**What a pass proves:** the invariant held across the runs named in each test, which are real
sequences of `Core` calls including restarts, a restore from a backup, and an edit made to the
file behind the realm's back. **What it does not prove:** that the invariant holds in every
reachable state. The state space is unbounded; a seed covers a sample. Nothing here is a proof,
and the word is not used.

## The fuzzing

Seven seeded harnesses in `grid/src/core/fuzz.rs`: capability tokens, damaged database files,
connector input, bytes from outside fed to the four doors that take them, model plans, artifact
keys, and the migration steps.

**What is lost against coverage-guided fuzzing, said plainly:** coverage. `cargo-fuzz` is not
installed, installing it needs crates.io, and libFuzzer needs a nightly toolchain, which this
computer does not have. These harnesses explore a seeded sample of the input space and reach no
coverage target. Every harness asserts no panic, prints its seed and round on failure, and every
one that reads a refusal asserts it says something a person can act on. Three of them also assert
that the generator has not stopped exercising anything: F3 fails unless it saw a setting taken, a setting
refused and a generated person accepted, F5 unless at least one plan was accepted, and F6 unless it
saw both a stored key and a refused one. Of the rest, F1 asserts that every mutation it made is refused, which is the
whole of what it is for; F2 and F4 assert only that nothing panicked and that what came back was
an answer or an error a person can read, so a generator that stopped reaching anything interesting
would still pass them; and F7 is not generated at all, because it walks the schema versions in
order and has no seed to print.

F3 is the one that had to be fixed rather than described. Its accepting branch was reached nought
times in four hundred rounds for its committed seed, because `Settings::with` takes a name of
letters, digits, dashes and underscores and the generator drew from an alphabet of thirty-seven
characters of which nine qualify. It now offers names a connector is really pointed at as well as
noise, and it asserts both counts.

## Dependency audit and static analysis

What this computer can actually run, offline:

| Tool | Available | Result |
| --- | --- | --- |
| `cargo clippy --locked --all-targets` | yes | **Was failing before this pass** on a `clippy::never_loop` in `grid/src/relay.rs`, a correctness lint and therefore deny by default, so the run exited before reporting a single lint anywhere in `core/`. Fixed in this pass and still clean on 19 October 2026 after the robustness pass: exits zero, 54 warnings across the library and its tests, none of them deny-level and none in `core/` |
| `cargo test --locked` | yes | 374 pass, 3 ignored when this was written; 477 pass and 6 are ignored on 19 October 2026 |
| `cargo tree --duplicates` | yes | Seven crates are linked at two versions: `base64`, `block-buffer`, `cpufeatures`, `crypto-common`, `digest`, `getrandom`, `sha1`. All of them are hashing or encoding utilities pulled in twice by `tokio-tungstenite 0.30` and `rcgen`, which depend on the newer RustCrypto line while the rest of the tree is on the older one. One TLS stack only: `rustls` on `ring`, with no `native-tls` and no `openssl` anywhere |
| `cargo fmt --check` | yes | Nothing security-relevant; mentioned so nobody counts it twice |
| `cargo deny` | **no** | Not installed. Installing needs crates.io. Its licence, bans and sources checks would work offline once it existed; advisories would not |
| `cargo audit` | **no** | Not installed, and `~/.cargo/advisory-db` does not exist. The advisory database is a network fetch |
| `cargo miri` | **no** | A rustup shim with no component in any installed toolchain, and it would not run against `rusqlite`'s bundled C SQLite in any case |
| `npm audit` | **not offline** | It posts the dependency tree to the registry. It already runs in CI |

### The clippy blocker, and why fixing it was safe

`grid/src/relay.rs`, in `poll_write` on the relayed stream. Every arm of the match inside the
`loop` returned, so the body could never reach its end and the loop could never go round.
`never_loop` is in clippy's correctness group, which is deny by default, so the whole run exited
non-zero before reaching anything in `core/`. A reviewer who ran clippy and saw it fail would
have concluded Grid Core was unlinted, and they would have been right.

The fix is to drop the `loop`, which is exactly equivalent: a write either gets its place in the
queue, finds the queue gone, or waits to be polled again, and all three return. The read loop
above it is a real loop and is untouched. This was genuinely safe to fix, and the comment in its
place now says why there is no loop there, so nobody puts one back.

### Where static analysis is not enforced

No workflow in `.github/workflows/` runs `cargo clippy` or `cargo fmt` for any crate, and none
runs `grid`'s own test suite. Grid Core is compiled on every CI run, because `src-tauri` depends
on it and CI checks `src-tauri`, but the three hundred and seventy-four tests in this crate have
never run in CI. That is the single biggest gap in this section and it is a workflow change, not
a code change. Until it is made, everything in this document is a local result.

### What these tools do not catch

Clippy catches nothing about authorisation, nothing about the audit chain and nothing about
whether a secret reaches a log. `cargo deny` would catch a known advisory in a dependency, not a
logic flaw in this code. `npm audit` covers roughly a thousand development dependencies, almost
all of which are build and test tooling that never ships inside the bundle; an advisory there is
a build-chain risk, not a product vulnerability, and a report that does not say which is doing
nobody any favours.

## Recovery

Already covered before this pass, and named here so nobody writes them twice: power loss with a
torn journal, a change that never committed, a migration step that fails, restart with the right
key and the wrong one, a database from a newer build, backup and restore, host loss with and
without somebody signed in, a restored realm handing nobody a live workspace, a reservation that
lapses, and a brokered request left open by a hub that stopped. Twelve scenarios across
`core/tests.rs`, `workspace/tests.rs` and `broker/tests.rs`.

What was missing, and is now in `grid/src/core/recovery.rs`:

| Gap | Test | What it shows |
| --- | --- | --- |
| Nothing could ask a realm what was wrong with it | `a_realm_can_be_asked_what_is_wrong_with_it_without_opening_anything_else` | `Core::check_storage` combines SQLite's own integrity check, its reference check and the history, and names the table when a reference is broken. Nothing anywhere called either pragma before |
| Two writers on one realm | `two_handles_on_one_realm_never_interleave_a_change` | The second writer waits for a three-hundred-millisecond hold, released from another thread, and then succeeds; the history verifies and has no gap. One chosen interleaving, not serializability, and a hold that outlasts the ten-second busy timeout is refused with a sentence rather than waited out, which this does not spend ten seconds proving |
| Power cut at the first version | `a_power_cut_at_the_first_version_leaves_a_realm_that_still_opens` | The table that records versions is created outside a transaction, because it is what records transactions. A realm left in exactly that state opens and finishes the job |
| Key rotation | `a_realm_key_is_asked_for_and_never_kept_and_there_is_no_way_to_rotate_one` | The honest one. There is no way to rotate a realm key, and the test says so rather than pretending otherwise |
| A computer that stopped answering | `a_realm_that_lost_a_computer_stops_placing_on_it_and_gets_its_reservation_back` | `host_lost` is the workspace answer and does not touch a reservation; what gives a reservation back is the reservation running out and `expire` noticing. A realm nobody calls `expire` on holds it until somebody does |
| A realm carried to another computer | `a_realm_carried_to_another_computer_is_the_realm_it_was` | The same identity, the same people, every event with the same seal |
| A damaged file | `a_damaged_database_is_reported_rather_than_read_half_way` (in `fuzz.rs`) | Overwriting a run of bytes or cutting the file short gives an answer or an error a person can act on, never a panic, and never a partial record returned as if it were whole |

### Key rotation does not exist, and that is a gap

`Chain::verify` takes one key and every event in a realm is sealed under it, so changing the key
would break every earlier seal. A realm whose key is believed to have leaked has one answer
today: take a backup, make a new realm, and carry across by hand, which stops every permission
and every sign-in it had handed out. Adding rotation needs a table of key versions, a key version
on each event, and a verify that takes several keys. That is production work this phase did not
do, and it is the largest named gap left behind.

### Network partition is not the core's

The core has no socket, no listener and no clock of its own: every method takes the time as an
argument. Partition, slow reads, TLS downgrade and certificate pinning all belong to
`grid/src/net.rs`, `hub.rs`, `tunnel.rs` and `relay.rs`, which are not built on the core.

## Defects found, and what was done about them

Five, each found by a test written in this pass and each fixed in the same pass. None of them was
reachable by an outsider on its own, because the core is behind whatever authenticates its caller.
Three of them mattered: a stranger's text reaching the sealed history, a one-use permission usable
twice, and a backup whose state nothing sealed.

**1. `Core::accept` acted on a token before checking its signature.** It called `Authority::peek`,
which verifies nothing, and on a stale hit wrote the token's `principal_id`, `device_id` and
`workload_id` straight into the sealed history. Those fields are not filtered the way a free-text
reason is, so anybody who could reach the door could seal attacker-chosen text of any length into
the realm's permanent record, one row per attempt. Fixed by adding `Authority::verified`, which
is the signature half of `accept` lifted out, and calling it first; a token that does not verify
now writes one refusal event naming `unknown` and nothing else. Covered by
`an_unsigned_token_never_reaches_the_database_or_the_history`, and a schema trigger bounds the
length of every identifier in the history as a second line.

**2. A one-use permission could be used twice by two processes.** `Store::spend_capability` ran
`UPDATE capabilities SET spent_at = ... WHERE spent_at IS NULL`, which is the one atomic statement
that settles the race, and threw away the row count. Two handles on one realm could both read the
permission as unspent, both pass the check, and both be told yes. The broker path happened to be
saved by a unique index on its own record of open requests; the workspace path had nothing. Fixed
by returning the row count and treating nought as already used. Covered by
`a_one_use_permission_survives_no_restart_and_no_second_handle`, and by the invariant.

**3. A backup's state was not sealed.** The history in a backup was sealed event by event; the
state beside it was not. Adding a realm administrator to a backup file and leaving the history
alone passed the restore with the history still verifying, which is a privilege escalation from
write access to one file. Fixed by sealing the record with the realm's key, exactly as each event
is sealed, and checking it in `store::restore` before anything is written. A missing seal is a
refusal rather than a pass, so deleting the field does not close the door. Covered by
`a_backup_edited_after_it_was_taken_is_refused_whichever_part_was_edited`.

**4. A restore brought a withdrawn account back at an active account's generation.** The portable
record carries no generation numbers, so a suspended account or a revoked computer came back at
generation one. Found by the invariant "no generation and no policy version ever falls", which
failed on the restore move. Not exploitable today, because a backup carries no permissions either
and a suspended account is refused on its own suspension before any generation is compared. Fixed
anyway, because the safety of withdrawal rests on generations and a realm where the record and
the generation disagree is one nobody should have to reason about. If a record is ever made to
carry permissions, the generations have to come with it, and the threat model says so.

**5. A paused grid still accepted permissions minted after it was paused.** `Core::accept` never
asked whether the grid was serving. `use_workspace` and the broker both ask before they call it,
so the two doors a product actually uses were covered, but the generic one was not, and a profile
written later that forgot to ask would have accepted permissions in a grid somebody had stopped.
Pausing raises the policy version, so everything minted before the pause was already refused; what
got through was a permission minted after it. Found by the long invariant sweep, which shrank the
failing run to three moves: pause, mint, accept. Fixed by asking the question in `Core::accept`,
read from the database rather than from the copy the handle opened with, so a grid another process
paused is paused here too.

Two smaller things were closed while passing:

- The schema took an artifact key with a tab or a newline in it, which Rust had always refused, so
  a second process writing to the file was held to a looser rule than this code. A trigger at
  schema version 9 closes it, including an embedded nought byte, which SQLite reads as the end of
  a text value and so no pattern match would have caught.
- The generations withdrawal depends on could be lowered by anything that opened the file with
  another tool. Four triggers at schema version 9 say they only rise, as `workspaces` has said
  since version 4, plus one that a used permission stays used and two that a withdrawal is never
  rewritten or unrecorded.

## Assumptions

Things believed to be true that nothing here checks. Each one is a question for a real
engagement.

- **The embedding process authenticates its caller.** This is the big one. The core takes `by`,
  `device_id` and `principal_id` as text, and `Core::allowed` returns yes for the literal word
  `owner` without looking anything up. Every attack test in this pass calls the core directly and
  so assumes this.
- **The operating system vault keeps a key.** Nothing in `grid` reads or writes one; that is
  `src-tauri`'s. "Keyed from the OS vault" is untestable in this crate.
- **HMAC-SHA256 and the random number generator are sound.** Taken on the strength of the `hmac`
  and `sha2` crates and the operating system's own generator. There is no entropy test worth
  writing; one that counted the bits of a thousand tokens would pass for a broken generator.
- **The comparisons meant to be constant-time are.** The signature comparison and the hash
  comparison are written to fold over the whole length rather than returning early. Proving the
  property needs statistical timing measurement on a quiet machine with a predictable scheduler,
  and on this one it would prove nothing. The intent is stated; the property is not claimed.
- **The hub's transport claims.** Certificate pinning, the shape of a sign-in refusal, and what a
  tunnel carries. All of it is in the hub and none of it is built on the core.
- **A host reports its own size and its own attestation honestly.** `Attestation::verified` reads
  what a computer says about itself, and the code already says unverified rather than assuming.
- **A sandbox contains what runs in it.** See worker escape above.

## What cannot be verified in this repository, and why

Stated here rather than worked around.

1. **Penetration testing against anyone else's systems.** Forbidden, and there is nothing to test
   against: no tenant, no vendor SDK and no credential exists in this repository.
2. **A live target of any kind.** Every test in this pass that uses a socket binds 127.0.0.1.
   Nothing reaches an address that is not this computer's own.
3. **Container, microVM or VM escape.** Not provable by a Rust test. It is a property of a
   hypervisor and a kernel, the sandboxes are built by `src-tauri` against Docker, WSL, Hyper-V
   and QEMU, and running them would start real workloads on this machine.
4. **A model's behaviour.** Refusals, jailbreaks, prompt injection, exfiltration through a model.
   The core never sees a prompt, and nothing in this work attempts to change how any model
   behaves. The nearest thing here is a storage property: no table in a realm has a column that
   could hold a prompt.
5. **Anything needing a live tenant.** The four desktop connectors are exercised against loopback
   servers that imitate published management APIs. Mock-tested is not tenant-tested, and the
   adapter matrix says so for every row.
6. **Hardware attestation.** TPM, Secure Boot, measured boot, BitLocker. This computer's answer
   is one data point and the code already reports unverified rather than assuming.
7. **Timing side channels.** See the assumptions above.
8. **Coverage-guided fuzzing.** No `cargo-fuzz`, no nightly toolchain, no network to get either.
9. **Memory safety beyond the compiler.** No miri component, and it would not run against
   bundled C SQLite anyway.
10. **Real power loss.** A real cut can tear a sector inside a committed frame. No test on an
    ordinary file system can produce one reliably; the corruption harness is the closest honest
    approximation.
11. **Multi-node behaviour and clock skew.** The core has no clock; every method takes the time
    as an argument. Skew between two computers needs two computers.
12. **An attacker who already holds a realm key, or administrator rights on the hub computer.**
    Out of scope in the threat model, and deliberately left there rather than quietly defended
    against.
13. **Swarm Mining, bounty workers and the practice flow.** Not run, not tested, not touched. The
    research realm is tested as a realm, with its isolation, approvals and transfer rules, and no
    worker was ever started.

## What a real engagement would have to cover

In the order somebody should spend money on it.

1. **The authentication boundary around the core.** Everything in this document assumes it. A
   review of how each product's hub turns a request into a `by` and a `device_id`, and whether
   caller-supplied text can ever become either, is worth more than everything below it.
2. **Sandbox containment.** Container, microVM and VM escape against the images and the
   configurations this product actually ships, on the three platforms it ships on. This cannot be
   done here at all.
3. **The hub's transport.** Certificate pinning end to end, the sign-in path and whether repeated
   wrong attempts are bounded, tunnel and relay behaviour under a hostile peer, and resource
   exhaustion against a published hub.
4. **The operating system vault integration.** Where a realm key and a credential value actually
   live on Windows, macOS and Linux, what reads them, and what a crash dump contains.
5. **Connector behaviour against real tenants.** Everything in the adapter matrix is mock-tested.
   What a provider does with a request the broker builds is unknown until somebody sends one.
6. **Cryptographic review.** The token format, the chain seal, the backup seal and the
   fingerprint, looked at by somebody who does that for a living rather than by the people who
   wrote them.
7. **Dependency advisories.** `cargo audit` and `cargo deny` against a current advisory database,
   which needs a network this work did not have.
8. **Key rotation**, once it exists, and a recovery drill for a realm whose key has leaked.
9. **Coverage-guided fuzzing** of the token parser, the migration path and the connector input,
   with libFuzzer and a corpus, on a machine that can install it.
10. **A read of this document by somebody with no stake in it.** The failure mode of a
    verification pass written by the authors is that it tests what they already believed. The
    only fix for that is a different pair of eyes.
