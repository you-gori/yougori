# Grid Core threat model

What the core must hold true, who it is held against, and what it does not claim. Written with
[ADR 0001](0001-architecture.md).

Rewritten on 19 October 2026, during the security verification pass, against the core as it
actually is rather than as it was at the end of Phase 0. Every claim below now says which part of
the tree it is about and whether it is tested, enforced by the database, an assumption, or not
implemented. Where the old document claimed something the code does not do, the claim has been
corrected rather than quietly dropped. [security-review.md](security-review.md) says what was
tested, what passed, and what nobody here can test at all.

## What is being protected

| Asset | Where it lives | Worst outcome if lost |
| --- | --- | --- |
| Company credentials | Sealed in the credential profile's store, keyed from the OS vault | An outsider acts as the company against its own providers |
| A realm's identity key | OS vault, TPM or HSM | Anyone can impersonate the hub and collect enrolments |
| Device tokens | Each computer's OS vault | A removed computer keeps working the grid |
| People's sign-in material | Only ever a hash on the hub; a derived key in transit | Accounts taken over |
| Workspace data | The host computer's disk, and a bucket while a workspace moves | A person's work is read or lost |
| Model weights and prompts | Host disk; prompts not retained unless policy says so | Confidential prompts disclosed |
| Research artefacts | The research realm's own store | Unreviewed material spreads into the company realm |
| The audit chain | Each realm's own store, exportable | Nobody can say what happened |
| The realm's database and its journal | `<realm>.db` and `<realm>.db-wal` on the host disk | Everything in the realm, read or altered, by anyone who holds the file |
| The record left beside a migrated realm | `<realm>.v{N}.backup`, written by `Core::database_for` and never removed | A full copy of the realm, including its sealed history, left on disk indefinitely |
| The realm key while the realm is open | `Core.key`, a `String` held for the whole open life of the realm | A crash dump or a core file carries the key that signs permissions and seals the history |

## Who it is held against

1. **An outsider on the network.** Can reach a published hub address. No password, no token.
2. **A removed or revoked computer.** Held valid credentials until a moment ago.
3. **A person inside the company.** Has a real account; should reach only what their role allows.
4. **A compromised workload.** Code running inside a workspace, a model runtime or a research
   runtime. Assume it is fully controlled by an attacker.
5. **A curious administrator.** Legitimate power; should not be able to act unobserved, or approve
   their own sensitive requests.
6. **A dishonest publisher of research source.** Supplies material intended to break out of the
   research realm.
7. **A caller of the library that passes something a stranger chose.** This is the one the old
   document left out, and it is the most important. **Grid Core authenticates nobody.**
   `Core::authenticate(device_id, secret, now)` exists and no other method in the core calls it.
   `Core::enrol_device`, `Core::offer_host`, `Core::report_workspace`, `Core::adopt_workspace`,
   `Core::park_workspace` and `Core::report_condition` all take a device identifier as plain text
   and act on it; `Core::allowed` returns `Ok(())` for the literal word `owner` without looking
   anything up. The design is sound only because the embedding process is expected to
   authenticate first and never to pass caller-supplied text as `by` or `device_id`. That
   contract is the boundary, and it belongs here rather than in somebody's head.

Not in scope: an attacker with administrator rights on the hub computer itself, a hostile OS or
hypervisor, physical access, or an attacker who already holds a realm's key. Those defeat any
user-space design and the product should say so rather than imply otherwise.

## Claims

Each row says which part of the tree the claim is about and how far it is held up. The four
states are **tested** (a test fails when it stops being true), **enforced** (the database or the
type system refuses it, with a test over that), **assumed** (believed, with the reason it cannot
be tested here) and **not implemented** (the claim describes something that does not exist).

### Enrolment and transport: all of this is the hub, not the core

Grid Core has no listener, no TLS and no certificate handling. Every claim in this group is about
`grid/src/net.rs`, `hub.rs`, `tunnel.rs` and `relay.rs`, which are not built on the core.

| Claim | About | State |
| --- | --- | --- |
| A client pins the hub's certificate from the invitation before it sends anything | hub (`net.rs`) | **assumed for the pinning decision itself.** What is tested is that identities load into TLS with stable fingerprints and that certificates round-trip and normalise (`net.rs` tests), and the end-to-end tests do connect to a hub over its own TLS on loopback. This pass did not walk the pinning path line by line and does not claim to have |
| A wrong password is refused without saying which part was wrong | hub (`member.rs`) | **assumed.** Not verified in this pass |
| Repeated wrong attempts from one address are locked out | hub | **assumed, and probably false.** This pass searched `net.rs`, `hub.rs` and `member.rs` and found no per-address lockout; the `MAX_ATTEMPTS` in `hub.rs` is a job retry count, not a sign-in one. Treat the claim as unsupported until somebody points at the code |
| A tunnel or relay carries the grid's own encrypted traffic only | hub (`tunnel.rs`, `relay.rs`) | **assumed.** The design is a pinned TLS session inside WebSocket frames, and the relay's own `Debug` deliberately prints no bytes, but this pass did not test it |
| A request body that never arrives does not hold a connection slot indefinitely | hub (`net.rs`) | **enforced in code**: a thirty-second timeout and a size limit around the body read. No test found for it in this pass |

### Identity and authorisation, in the core

| Claim | About | State |
| --- | --- | --- |
| A capability token is bound to its realm, principal, device, workload and expiry, and is refused outside any of them | core | tested (`a_permission_is_bound_to_its_work_its_computer_and_its_destination`, `a_token_edited_or_signed_with_a_guessed_key_is_refused_and_spends_nothing`) |
| A token minted in the research realm is refused by the primary realm, and the reverse | core | tested (`two_realms_on_one_computer_share_no_door_no_key_and_no_file`, and as an invariant over generated runs) |
| Nothing a token says is acted on before its signature is checked | core | tested (`an_unsigned_token_never_reaches_the_database_or_the_history`). Added in this pass; before it, the claims were read with `Authority::peek`, which checks nothing, and written into the sealed history |
| Revocation takes effect on the next request | core | tested (`nothing_revives_a_permission_a_withdrawal_killed`) |
| A grid that is paused answers but serves nothing, including permissions minted after it was paused | core | tested (`nothing_revives_a_permission_a_withdrawal_killed`, `a_paused_grid_serves_nobody_who_is_already_in_a_desk` in the workspace profile). `Core::accept` did not ask this until the security pass; the two doors a product uses asked it first, and the generic one did not |
| Revocation reaches a connection that is already open | hub | **not the core's.** The core has no connections. A brokered request already on the wire is not recalled either, and `a_place_taken_away_while_the_value_is_being_read_stops_the_request` shows where the line is: between the vault and the send, not after it |
| A one-use permission is used once, across a restart and across two processes holding the same file | core | tested (`a_one_use_permission_survives_no_restart_and_no_second_handle`) and enforced (`capability_spending_is_final`). The second-process half was not true until this pass: the row count of the one statement that spends a permission was being discarded |
| A generation never falls, so a withdrawal cannot be undone by lowering one | core | enforced by the database at schema version 9, and checked as an invariant over generated runs |
| A person cannot approve their own credential request or their own research scope while another qualified approver exists | core | tested (`roles_are_separate_and_nobody_approves_their_own`, and as an invariant) |
| A decision is written once and never changed | core | enforced (`decisions_never_change`, `decisions_never_vanish`) and tested |
| Every mutation names a principal, a device, a realm and a policy version | core | **partly true.** An event carries a realm, a principal and a policy version always; a device and a workload are optional and most writers leave them unset. There is no profile field. Restated here rather than left as written |

### Workloads and resources, in the core

| Claim | About | State |
| --- | --- | --- |
| Work runs only under an unexpired lease | core | tested (`work_cannot_run_on_a_reservation_that_has_expired`, and as an invariant) |
| An expired lease cannot be resumed | core | enforced by `Stage::may_become`, and checked as an invariant: work that has finished holds no reservation and never moves again |
| A host's offered share bounds what runs on it | core | tested (`a_computer_offers_only_what_it_has_and_a_draining_one_takes_nothing`, and as an invariant) |
| A workload names its network policy and data classification before it starts | nothing | **not implemented.** `work::Workload` has neither field. The network policy is on the realm and the access class is on the workspace, which is where the rules are actually read |
| Cancellation reaches the running work, not only the record of it | runtime (`src-tauri`) | **not the core's.** `Core::cancel_work` moves a stage and gives a reservation back. Reaching a process is the runtime's |

### Credentials, in the core and its broker

| Claim | About | State |
| --- | --- | --- |
| A workload receives a capability, never a stored secret value | core | tested four ways, including `what_a_workload_gets_is_a_permission_and_it_names_one_destination` |
| The broker re-checks destination, method, path and size immediately before it acts, after any approval | core (`broker::still_clear`) | tested, including three races: a place taken away, egress switched off, and an agreement that simply ran out, each while the value is being read. The third needs the clock to move, so the last look is taken at the instant the request was asked at plus the time actually spent waiting, measured monotonically |
| A workload cannot set the header its credential travels in | core and forwarder | tested (`a_workload_cannot_set_the_header_its_credential_travels_in`) |
| A redirect is not followed | forwarder | tested (`a_redirect_is_answered_and_never_followed`), over a loopback server |
| No secret this grid holds appears in anything this grid writes: not a log, a trace, a command argument, a record, a backup, an audit reason or a diagnostic export | core | tested (`no_shape_of_a_secret_reaches_a_file_an_error_or_a_printout`, `nothing_about_the_value_reaches_the_database_the_history_or_a_backup`). The one deliberate exception stands: a credential that travels as a query parameter is a value in a URL, and the service's own access log and every proxy in between will keep a copy. The grid keeps that query out of everything it writes; it cannot keep it out of theirs |
| The answer that comes back has the value hidden in three encodings | forwarder | tested. A service that re-encodes it some other way, splits it across two chunks of a streamed body, or returns a different secret of its own, is not covered by that and cannot be |
| The research realm cannot call the broker at all | core | tested (`a_research_realm_reaches_no_credential_and_no_permission_crosses_between_realms`, `a_research_realm_has_no_door_to_a_credential_whatever_role_is_granted`). Worth one qualification: the capability is asked first by `add_credential`, `use_credential` and `clear_to_send`. `allow_credential`, `rotate_credential` and `retire_credential` do not ask it; what stops them in a research realm is that no credential row can exist there, which the database refuses outright |

### Research containment, in the core

| Claim | About | State |
| --- | --- | --- |
| Offline by default; outbound network is denied unless the realm's policy opens it | core | tested (`an_offline_realm_allows_nothing_and_a_credential_names_one_place`, `a_research_grid_is_offline_until_a_destination_is_admitted_and_an_empty_list_is_refused`) |
| Source is accepted only with a signed authorisation record and an immutable scope version; changing either invalidates acceptance | core | tested (`changing_the_source_or_the_scope_invalidates_acceptance`, `nobody_writes_their_own_authorisation_and_freezes_it_alone`, `a_source_that_changed_after_it_was_acquired_is_quarantined`) and enforced by `research_scopes_freeze_once` |
| Artefacts are bounded, checksummed and retained under a stated policy | core | tested (`work_is_held_to_its_scopes_limits`, `artifacts_and_sources_are_kept_for_a_stated_time_and_let_go_of_with_a_reason`) |
| A stop reaches the running work and leaves the evidence intact | core, for the record; runtime, for the process | **half.** The realm's half is tested (`a_stop_reaches_running_work_and_leaves_the_evidence`, and `the_enclosure_is_handed_the_plan_and_the_core_starts_nothing` for where the line is). Reaching the process is the runtime's and no test in this crate can show it |

### Audit, in the core

| Claim | About | State |
| --- | --- | --- |
| Every state change produces one event, hash-chained to the one before it | core | tested, and checked as an invariant: the history has no gap in its sequence numbers in any state a generated run reaches |
| A modified event, or one removed from the middle, is detectable on verification | core | tested, field by field (`an_altered_event_names_itself_whichever_field_was_touched`), including after the guards are dropped and a plain hash chain is recomputed over the result. Removal from an end is weaker and `a_history_cut_off_at_either_end_is_caught_only_so_far` says how far it goes: a run deleted off the end is caught, because the chain no longer ends where `audit_chain` records it ending; a run deleted off the front is not caught at all, because that is what trimming an exported front legitimately does; and somebody who edits `audit_chain` in the same file defeats both. Only a copy that left this computer settles an end |
| Nothing a caller sends becomes an unfiltered field of the history | core | tested (`nothing_a_stranger_sends_becomes_a_field_of_the_history`) and enforced (`audit_events_identifiers_are_identifiers`). Two layers: `Entry::because` strips control characters and cuts to five hundred, and `Entry::safe` withholds a reason shaped like a value |
| Export is complete enough for the customer's own retention, and carries no secret values | core (`core::export`) | **part.** Syslog and OTLP are tested against collectors on this computer that keep whatever they are handed, with the tests reading those bytes back apart into fields. The four vendor envelopes are rendered and asserted on their bytes alone, and nothing has ever sent one anywhere: `Vendor::deliver` refuses and names why. What none of it shows is that any real collector accepts the shape. "No secret values" rests on the row above rather than on a test here: what an export carries are event fields, and `Entry::because` and `Entry::safe` are what keep a value out of them. No test in `core::export` searches a rendered batch for one |
| A change and the event that records it land together or not at all | core | **not implemented.** Each `Store` method opens its own transaction and a `Core` method is a sequence of them, so a process that dies between two of them can leave a change with no event. See the weak points below |

## Weak points we accept and must state

The first five were here before and are still true. The rest were found by this pass.

- **Local hash chain is not an external archive.** Until a deployment exports to storage the hub
  cannot reach, an attacker with the hub computer can rewrite history.
- **An end of the history can be cut off by whoever holds the file.** A seal cannot be forged
  without the realm key, but the record of where the chain ends is `audit_chain.head_sequence` and
  `head_seal`, plain columns in the same database, and `exported_to`, which the delete guard
  consults, is another. Somebody who raises the watermark, deletes a run and moves the head to
  match leaves a shorter genuine chain that verifies. Verification now compares the chain against
  the recorded head, which catches a tool that touched only `audit_events`; it cannot catch one
  that touched both. An export to storage this computer cannot reach is the only answer.
- **Attestation is only as good as the hardware.** Where TPM or Secure Boot is unavailable the
  product must say the host is unverified rather than treat it as trusted. Held in code by
  `what_a_computer_proved_about_itself_is_never_overstated`.
- **Connectors inherit their provider's model.** Yougori brokers and observes; it does not replace
  a provider's own identity, licensing or session policy, and must not imply that it does.
- **Mock-tested is not tenant-tested.** Every connector states which it is. Held in code by
  `State::may_change_a_tenant` and `no_integration_claims_more_than_this_repository_can_show`.
- **A credential's fingerprint is a plain hash of the value.** It has to be computable by an
  administrator's tool that holds the value and by the grid, which never does, so it is neither
  salted nor keyed. It is there to tell one credential from another and to notice that a value
  changed. Somebody holding a backup can test guesses against it, which matters for a credential
  that is a chosen password and not for one that is a random key.
- **Zeroing covers only what this code owns.** The broker overwrites the value and the request it
  built when a request ends. The HTTP library's own header buffer, the TLS record, the kernel's
  socket buffer and anything the operating system paged to disk are copies nobody here can reach,
  so a crash dump taken mid-request contains the value.
- **A person who can see a screen can photograph it.** Restricted workspaces bound channels, not
  physics.
- **A change and its event are two transactions.** `Core::decide` runs three writes, each in its
  own transaction. A process that dies between the second and the third leaves a decided request
  with no event. The same shape is in `revoke_device`, `suspend_principal`, `open_workspace` and
  `use_credential`. Closing it means giving every `Store` write a variant that takes a
  transaction, which is a refactor of `store/mod.rs` and its own piece of work.
- **A migrated realm leaves a full copy on disk.** `Core::database_for` renames the old record to
  `<realm>.v{N}.backup` and nothing ever removes it. It is not encrypted and it holds the whole
  realm, including its sealed history.
- **The history is bounded at twenty thousand events.** Beyond that the front is dropped, but only
  once it has been exported. A realm nobody ever exports from keeps every event it has written,
  for ever, and "nobody can say what happened" is bounded by an export that may never have
  happened.
- **Every refused permission writes an event, from a caller the core never authenticated.** One
  sealed row per forged token, and `Store::trim` drops events only as far as the export watermark,
  so unexported refusals accumulate without bound. The fix in this pass stopped a stranger's text
  reaching the fields of those rows; it did not stop the rows.
- **Two realms on one computer share one operating system vault and one operating system user.**
  Realm separation is a database and key claim, not a process claim. A process that can read one
  vault entry can read the other.
- **A realm key cannot be rotated.** `Chain::verify` takes one key and every event is sealed under
  it, so changing the key would break every earlier seal. A realm whose key is believed to have
  leaked has one answer today: take a backup, make a new realm, and carry across by hand, which
  stops every permission and every sign-in it had handed out.
- **A restore does not carry generation numbers across.** The portable record holds no
  generations, and this is safe only because it holds no permissions either, so a restored realm
  refuses everything it handed out before. A withdrawn account or computer is brought back at a
  generation above the one it started at, which this pass added; before it, a suspended account
  came back at the generation an active one starts at. If a record is ever made to carry
  permissions, the generations have to come with it.
- **A connector is a new outbound surface.** A connector holds a keyring handle, reaches one
  HTTPS address, and is handed a ticket of claims rather than a bearer string. None of that was
  in this document before, and all of it is covered by the connector seam's own tests against
  loopback servers.

## What this model does not do

It does not describe any way to influence how a model behaves about a task. The research realm is
a containment boundary: approvals, offline defaults, bounded artefacts and audit. Where a model
declines work, that decision stands, and no feature will be built to work around it.
