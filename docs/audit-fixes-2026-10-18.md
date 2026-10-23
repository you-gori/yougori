# Audit fixes — 18 October 2026

What was done about the two audits of 17 October: [Swarm Mining](swarm-bug-audit-2026-10-17.md) (56 findings) and [Neo Grid, Sandbox Grid and sandboxes](neo-grid-bug-audit-2026-10-17.md) (55 findings).

Each finding was first re-checked against the current working tree, since the Sandbox Grid had changed a great deal since the audits. **18 were already fixed by that later work; 93 were still present.** All 93 are now fixed.

| Area | Findings | Already fixed | Fixed now | Remaining |
| --- | ---: | ---: | ---: | ---: |
| Neo Grid, NG-001–025 | 25 | 0 | 25 | 0 |
| Sandbox Grid, SG-001–021 | 21 | 16 | 5 | 0 |
| Sandboxes, SB-001–009 | 9 | 2 | 7 | 0 |
| Swarm Mining, SW-001–056 | 56 | 0 | 56 | 0 |

## Neo Grid

- **Work authorization (NG-001, NG-002).** `work()` no longer trusts the models a computer offers. `assigned_models()` resolves what that computer may serve from the durable record on every poll and every wake: its assigned plan's model only, nothing while it is left out or no longer capable, and an error once it is no longer a member. A pending long poll therefore stops serving the moment its membership or assignment changes.
- **Key lifecycle and limits (NG-003, NG-005, NG-006).** A chat request re-checks its API key after the body arrives, so a key revoked mid-upload queues nothing. Replies still streaming back now count against their key (`Live::relaying`, released by a guard whatever happens) and appear in status as `queue.streaming`. A swarm harness takes one of its key's places per call instead of checking once and fanning out freely.
- **Request bodies (NG-004).** `net::json_body` has a 30-second deadline, so a client cannot hold a connection permit by trickling a body.
- **Plan updates (NG-007).** Every field of a plan update is validated before any of it is applied; a refused update changes nothing, live or saved.
- **Leaving (NG-008).** A computer that leaves by itself goes through the same cleanup as an admin removal: plans that picked it forget it, and plans left without computers go.
- **Durability (NG-009).** A failed save restores the dirty marker and records `grid.save.failed`, so the next flush or sweep tries again rather than losing the change.
- **Harness contract (NG-010, NG-011, NG-012).** Tools and non-text `response_format` are refused rather than silently dropped; the caller's `max_tokens` applies to the final answer. The workers' combined results are bounded (`COMBINE_LIMIT`) and a job too large for a computer to receive is refused with its size, instead of becoming an interrupted answer. A request carrying images runs as a mixture, where every model sees the original messages, rather than through the plan path that flattens to text.
- **Streaming lifetime (NG-022).** A relayed reply has one generation-length window overall and a 60-second limit on a blocked downstream send.
- **Model lifecycle (NG-013–NG-020).** A failed hub restore is retried after 30 seconds instead of latching for the process. Preparation is cancelled when its assignment changes, and a half-made environment is marked so. Each preparation carries a generation, so an old one cannot clear a newer one's handle. Deletion waits for the model to be genuinely free (a failed health check counts as busy) and keeps waiting, logging, rather than abandoning the weights. A stop-only retirement checks the environment has not been given back. `parked` is cleared by a start that actually succeeded. The grid's own request is no longer read as its person using the computer.
- **Activity (NG-021).** A logind session whose details cannot be read now yields `Unknown`, which withholds work, instead of "nobody is here".
- **Interface (NG-023, NG-024, NG-025).** `GridRun` resolves to whether the change went through, so a failed submission keeps the form. `usePolled` ignores answers from superseded reads. Invites are decoded as UTF-8, so a company name outside ASCII survives.

## Sandbox Grid

- **Account enumeration (SG-004).** The decoy salt for an unknown username is derived from a secret only the hub holds, so it can no longer be computed from public information.
- **Disk accounting (SG-011).** A desk is placed when it fits what is free now and all desks together stay within the share; free space is no longer counted against the share twice. The suggested share is judged on the disk as it was before the grid's own desks filled it.
- **Cancellation (SG-019).** A build task cancelled by leaving the grid marks a sandbox it had begun as failed, where it can be deleted, instead of leaving it provisioning.
- **Persistence (SG-020).** A failed write of `desks.json` is recorded and retried at the next check-in, and a lost or damaged file is rebuilt from the sandboxes' own desk tags.
- **Desks open from anywhere (SG-006).** A desk is still shared on its host's private address, and a person on the company network still reaches it directly. From anywhere else the session now goes through the hub, which the admin can already publish: each host keeps two connections waiting at the hub (`/grid/v1/desks/relay/host`), a person's computer asks for one of its desks (`/grid/v1/desks/relay/open?desk=…`), and the hub joins the two and copies bytes. The desk's own TLS, pinned to the certificate in its invitation, is negotiated end to end inside that connection, so the hub carries a session it cannot read, exactly as a Cloudflare tunnel only relays the grid's own encrypted traffic. The hub checks the person still owns that desk, that it is ready and that its computer is online, before handing anything over. The person's computer tries the direct address first and falls back by itself, so nothing changes on the company network. New module `grid/src/relay.rs`; `member::Membership::hold_desk_relay`, `member::DeskSession::open_desk` and `desk_request`; `desks::keep_desk_relays` on the host.

## Sandboxes

- **Editor safety (SB-001, SB-002).** Each save stages into a file of its own, created exclusively, decodes beside it and moves it over the original in one step. A failed decode or an interrupted save leaves the original untouched, and no unrelated file can be destroyed.
- **Encoding (SB-003).** A file that is not UTF-8 is refused by the editor rather than silently rewritten.
- **Concurrent edits (SB-004).** A save carries the text as it was read; the guest checks the file is unchanged before replacing it.
- **Deletion (SB-005).** Transfers and guest jobs are cancelled only after the lock is held and every precondition has passed, so a refused deletion no longer interrupts work.
- **Sharing (SB-008, SB-009).** Shared sandboxes are refreshed eight at a time, so unreachable ones no longer delay the rest. An interrupted upload can be retried: the person is asked whether to replace the partial file.

## Swarm Mining

- **Build (SW-001).** The native test target compiles again; the stale practice test was rewritten against the current target and its receipt checks.
- **Private hub and coordinator (SW-002, SW-003, SW-006, SW-011, SW-012, SW-013, SW-021, SW-049).** TLS handshakes have a deadline, so idle connections cannot fill the slots. Report answers name their evidence instead of carrying it twice. The receipt cap no longer blocks controls. Response bodies have a deadline. Leave ends the session. Presence follows the session's real state and freshness. Re-accepting the same terms keeps the conversation. A worker's name and model reach the host's roster.
- **Host lifecycle (SW-005, SW-016, SW-017, SW-018, SW-019, SW-020).** A failed resume is retried; abandoned import snapshots are pruned after a day; a failed preview or start gives its membership and credential back; a ticket is claimed before anything is awaited; hosting that succeeds reports the live bounty even when its local worker fails; deletion reports what it could not remove.
- **Worker (SW-007, SW-008, SW-009, SW-015, SW-054, SW-055).** A rebuilt workspace is stated plainly in the agent's memory. A recorded environment that no longer exists is forgotten so a resume rebuilds it. Chat inference happens only where the worker may work. Deleting a worker removes its receipts and its in-memory activity. A membership ended remotely clears the worker's policy, source and guidance.
- **Tasks and transport (SW-041, SW-042, SW-043).** A file's whole path identifies its task, so deep paths are no longer confused. Output is clipped by the size it will be sent at, escaping included. Blocked or interrupted attempts are retried rather than counted as covered.
- **Target and sandbox (SW-010, SW-024, SW-044, SW-045, SW-046, SW-047).** A zombie process is no longer mistaken for a running service. Scripts keep their executable bit. The target log is bounded and read from its tail. A failed bootstrap closes the agent's network. Cancelling preparation stops a private worker's model. Deleting a private worker re-reads its row after the gate, so a late sandbox is not orphaned.
- **Practice (SW-026, SW-027, SW-028, SW-029, SW-031, SW-048).** The 30-minute budget is a wall clock covering waits, busy retries and a long answer. A full request journal still allows one closing turn. The synchronous path registers with the usual stop control. Measurements travel with every ending. The console, the module and the guide describe the current Northstar Ledger exercise. The CLI waits past the practice budget.
- **Import boundary (SW-025, SW-050, SW-051).** The review lists every included and excluded path. Empty files are ordinary source. Credential files and private keys are refused by the engine for every hosting route, so the older CLI path cannot share what the desktop importer rejects.
- **Website (SW-004, SW-022, SW-034, SW-035, SW-036, SW-037, SW-038, SW-039, SW-052, SW-056).** Choosing new files marks the upload as due again. A blank optional deadline means "not given". Shared events are trimmed to what every worker can record. A repeated upload whose snapshot was deleted stores it again. A message is returned by its own ID. A conversation request that outlives its view is discarded. Expired budgets stop occupying capacity. Offers consider every open bounty, newest first. Account mutations re-check the admin session after the body arrives. Report lists are paginated.
- **Tests (SW-030, SW-053).** The desktop Swarm browser tests match the current dialogs (the project-first closed-bounty flow, the third authorization tick); the website's owner-approval journey uses the ordinary publisher promise, which is what its production-mode server accepts. The model-tools test no longer expects one machine's core count.

## Checks after the fixes

| Check | Result |
| --- | --- |
| `cargo test --locked` (grid) | 118 passed, 1 ignored |
| `cargo test --lib -- --skip swarm` (engine) | 567 passed, 88 ignored |
| `cargo check --all-targets` (engine) | clean, including the test target |
| `cargo test --locked` (CLI) | 330 + 164 + 24 + 6 + 3 passed |
| `npx tsc -b`, `npm run lint` | clean |
| `npx vitest run --dir src` | 609 passed in 108 files |
| `npx playwright test e2e/{desks,neo-grid,swarm-mining}.spec.ts` | 14 passed |
| Website `node --test server/swarm.test.mjs` | 37 passed |
| Website `npx tsc --noEmit`, Swarm Playwright | clean; 7 passed |

The Swarm worker tests in the engine are skipped by the standing rule not to run Swarm Mining; they compile. No worker, practice run or live target was started.

## Still not established

- No real sandbox, GPU, VM, two-computer desk move, S3 bucket, cloud provider, identity provider or provider API was exercised. The fixes above are source changes with unit, library and browser coverage.
- SG-006 remains a limitation, now described rather than promised.
- The audits' own untested boundaries (load, partitions, power loss, payments) are unchanged.
