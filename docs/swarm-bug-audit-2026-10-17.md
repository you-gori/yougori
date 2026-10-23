# Swarm Mining bug audit — 17 October 2026

Read-only review of the current desktop, CLI, private/LAN coordinator, worker harness, practice target, and website/backend checkouts. **No fixes were made.** This document consolidates the earlier 33 findings and adds 23 findings from deeper inspection and local probes.

## Result and scope

**56 findings: 7 High, 42 Medium, 7 Low.** These include product defects, operational limitations, and defects in the tests/documentation. Severity describes impact, not how thoroughly the issue was reproduced. No Critical issue was established by this review.

| Severity | IDs |
| --- | --- |
| High | SW-001, SW-002, SW-003, SW-004, SW-034, SW-051, SW-052 |
| Medium | SW-005–SW-030, SW-035, SW-037–SW-048, SW-050, SW-054, SW-056 |
| Low | SW-031–SW-033, SW-036, SW-049, SW-053, SW-055 |

Evidence labels:

- **Reproduced:** an existing test or a local probe exhibited the described failure. The entry identifies whether this used the real HTTP handler, an extracted helper, or a mocked boundary. It does not imply a complete desktop-to-model run.
- **Source-traced:** the relevant branches and state transitions establish a defect or limitation, but its full runtime scenario was not reproduced.
- **Reproduced boundary + source trace:** the problematic input/output or helper behavior was reproduced; its downstream effect follows from the inspected integration code.

24 findings have reproduction evidence at one of those levels; 32 are source-traced. Hypotheses needing more evidence are listed separately and are not included in the 56.

### Checkouts

| Label used below | Location | HEAD at inspection |
| --- | --- | --- |
| Desktop | `C:\Users\Argon\Desktop\yougori` | `502f78914382ed768a6f71f4b38cc72184f9dbde` |
| Website | `C:\Users\Argon\Downloads\YougoriWebsite` | `1fb5a27319a07c131441b6e38f21a9feea0bfc33` |

Both checkouts contained substantial pre-existing uncommitted changes. Findings refer to those working-tree files, not just the commits above. Paths below are relative to the labeled checkout; line numbers identify the inspected version. This is a deep Swarm review, not a claim that every unrelated subsystem in Yougori or the deployed production service has been audited.

### Most consequential failures

1. The native test target cannot compile after the practice redesign (SW-001).
2. Valid evidence or channel data can exceed smaller downstream limits and stop workers (SW-002, SW-034, SW-042).
3. Unauthenticated idle connections can occupy every private-hub connection slot (SW-003).
4. A publisher can select new files but publish the previous source; retrying an older upload can also return a deleted snapshot (SW-004, SW-035).
5. The older CLI folder importer includes credential files that the newer importer rejects (SW-051).
6. A pending account-admin mutation can finish after its session has been revoked (SW-052).

## Detailed findings

### SW-001 — Native test target references a removed practice oracle

**High · Reproduced · Build/test defect**

- **Location:** Desktop `src-tauri/src/swarm/practice.rs:619`, `:620`.
- **Trigger/evidence:** `cargo check --locked --manifest-path src-tauri/Cargo.toml --all-targets` fails with two `E0425` errors for `bounty_practice::oracle`.
- **Cause:** the practice implementation changed, but the native test still invokes the old flag-only oracle. Its surrounding login-service assumptions are also stale.
- **Impact:** all-target native validation is blocked, including reliable execution of the relevant native test suite. This does **not** establish that a non-test release build fails.

### SW-002 — A valid private report becomes too large for its tool response

**High · Reproduced boundary + source trace · Private reports**

- **Location:** Desktop `grid/src/bounty_coordination.rs:329`, `src-tauri/src/swarm/guest.rs:1445`.
- **Trigger/evidence:** the coordinator dispatch probe accepted a 26,000-byte evidence file, encoded as 34,668 base64 characters. The resulting report response was 70,417 bytes, exceeding the native 65,536-byte tool-response limit.
- **Cause:** report evidence is included both in the report document and the expanded report response.
- **Impact:** the report can already be stored when delivery to OpenCode fails. The worker can fail despite a successful coordinator mutation, leaving an ambiguous result and unreliable retries. The probe exercised dispatch with stubbed surrounding services, not a live model.

### SW-003 — Idle TLS connections exhaust all private-hub slots

**High · Reproduced · Private/LAN availability**

- **Location:** Desktop `grid/src/bounty.rs:374`, `:421`.
- **Trigger/evidence:** against an ephemeral loopback hub using the actual grid library, 64 TCP connections that did not finish TLS consumed the available permits. A legitimate join worked before the connections, failed while they were held, and worked after they closed.
- **Cause:** a connection permit is acquired before TLS negotiation; the handshake has no deadline that releases it.
- **Impact:** a network-reachable client does not need a bounty password to deny access to legitimate participants. No external host was tested.

### SW-004 — Selecting replacement files can still publish the previous upload

**High · Source-traced · Website publishing**

- **Location:** Website `src/swarm/BountyWizard.tsx:362`, `:626`, `:955`, `:962`.
- **Trigger:** upload project A, choose project B without changing the revision text, then publish.
- **Cause:** `uploaded` checks only whether the stored source revision equals the draft revision. Changing either file picker does not invalidate that state. Publishing skips `uploadFiles()` when it remains true.
- **Impact:** the selected replacement can be silently ignored and agents receive the previous source. This is distinct from the server-side upload retry defect in SW-035. No browser reproduction of this exact replacement sequence was completed.

### SW-005 — A failed private-host restore cannot recover in the same process

**Medium · Source-traced · Host startup/recovery**

- **Location:** Desktop `src-tauri/src/bounty.rs:41`, `:57`, `:108`.
- **Trigger:** restart with a saved host, then encounter a temporary vault or bind failure during restoration.
- **Cause:** the loaded flag is set before restoration finishes. The error is logged, the live host remains absent, and the existing `host.json` also prevents creating another host.
- **Impact:** correcting the temporary problem does not cause ordinary status/loading calls to retry. The user is left needing a restart or explicit host cleanup instead of normal recovery.

### SW-006 — Reaching the receipt cap blocks coordinator controls

**Medium · Reproduced · Private coordination capacity**

- **Location:** Desktop `grid/src/bounty_coordination.rs:101`.
- **Trigger/evidence:** populate the coordinator's 20,000 receipt slots, then send otherwise valid control/renewal/submission requests. The dispatch probe returns `coordination_full` before their route logic runs.
- **Cause:** the global receipt-cap guard precedes route dispatch, including operations that do not need another durable receipt.
- **Impact:** remote pause, stop, leave, renewal, and submission can fail at capacity. Native local cancellation still works; this finding does not mean the participant loses every way to stop local execution.

### SW-007 — Resuming a private worker rebuilds its mutable project but keeps its journal

**Medium · Source-traced · Worker resume**

- **Location:** Desktop `src-tauri/src/swarm/closed.rs:132`, `src-tauri/src/swarm/runner.rs:97`, `src-tauri/src/swarm/guest.rs:1286`.
- **Trigger:** create regression scripts, generated fixtures, or other investigation state in the build directory, pause, then resume a private worker.
- **Cause:** resume enters `preparing_bounty`; project preparation reconstructs the mutable build directory from the accepted snapshot. The investigation journal is retained.
- **Impact:** recorded progress can refer to scripts or state that no longer exist, and completed tasks may not be repeated to reconstruct them. A clean restart and a continuation are not represented consistently.

### SW-008 — Private retry does not recover stale model or agent environment IDs

**Medium · Source-traced · Worker recovery**

- **Location:** Desktop `src-tauri/src/swarm/closed.rs:132`, `src-tauri/src/swarm/mod.rs:1384`, `src-tauri/src/swarm/model_lifecycle.rs:598`, `src-tauri/src/swarm/guest.rs:1672`.
- **Trigger:** a saved private worker still has IDs for a deleted model environment or a deleted agent environment with the current harness version; retry/resume it.
- **Cause:** setup selection tests whether the IDs are present, rather than whether their environments exist. The fuller preparation recovery path is skipped; readiness/environment lookup then fails again.
- **Impact:** retry can repeatedly fail instead of recreating the missing resource. Missing test sandboxes have a separate recreation path and are not included in this claim.

### SW-009 — Private chat inference runs before remote execution authorization is checked

**Medium · Source-traced · Pause/budget behavior**

- **Location:** Desktop `src-tauri/src/swarm/runner.rs:109`, `:125`, `:491`, `:495`.
- **Trigger:** a remotely paused or budget-expired worker receives a new participant message while its supervisor loop remains connected.
- **Cause:** `handle_human()` runs before the membership/authorization gate and can load the model and issue a completion request.
- **Impact:** model work can continue despite the paused/budget state and the code's stated intention not to generate while paused. This concerns chat inference, not a demonstrated bypass allowing sandbox investigation tools. A local pause also cancels the runner and is a different path.

### SW-010 — A zombie target process can be mistaken for a running service

**Medium · Reproduced boundary + source trace · Target supervisor**

- **Location:** Desktop `src-tauri/src/swarm/target.rs:283`, `:288`, `:297`.
- **Trigger/evidence:** an owned-child WSL probe produced a process in state `Z` with the same `/proc` birth marker. The supervisor's exact `born()` helper still regarded its identity as present.
- **Cause:** restart detection compares process start time but does not reject zombie state.
- **Impact:** when the target remains an unreaped zombie, health checking fails without restarting it. This requires the zombie condition; it is not a claim that every ordinary exit produces this failure.

### SW-011 — Private coordinator response bodies lack an overall read deadline

**Medium · Source-traced · Network failure handling**

- **Location:** Desktop `grid/src/bounty.rs:674`, `grid/src/net.rs:266`.
- **Trigger:** a private hub completes connection and response headers but then stalls its response body.
- **Cause:** the body uses a size-limited `collect().await`; the connection/header timeout does not cover this collection.
- **Impact:** a request can remain pending indefinitely even though it has a byte cap, stalling the operation until another cancellation or connection failure intervenes. Slow-body behavior was not exercised against a live multi-machine hub.

### SW-012 — Private Leave retains membership and credentials

**Medium · Source-traced · Private worker lifecycle**

- **Location:** Desktop `grid/src/bounty_coordination.rs:164`, `src-tauri/src/swarm/closed.rs:148`, `:191`.
- **Trigger:** choose Leave for a private worker.
- **Cause:** the coordinator maps the action to a paused session, while native membership removal and credential deletion happen in Delete, not Leave.
- **Impact:** leaving does not fully detach the participant or revoke its access as the action name implies. The local worker stops, but its membership remains available until separately removed.

### SW-013 — Private host presence reports preview/paused workers as running

**Medium · Source-traced · Host dashboard correctness**

- **Location:** Desktop `grid/src/bounty_coordination.rs:431`, `grid/src/bounty.rs:356`.
- **Trigger:** join only to preview a private bounty, pause a managed worker, or leave a previously seen worker offline.
- **Cause:** managed coordination initializes presence as running and subsequent traffic mostly updates `seen`; the working count does not use freshness to exclude stale entries.
- **Impact:** the host can show workers as working even though they have not begun, are paused, or are no longer online. Presence and actual execution state are different sources of truth.

### SW-014 — CLI and desktop host views read different finding stores

**Medium · Source-traced · CLI/desktop parity**

- **Location:** Desktop `cli/src/closed_bounty.rs:252`, `src/components/private-bounty-host.tsx:23`.
- **Trigger:** use the CLI to inspect findings created by managed workers, or the desktop view to inspect legacy findings.
- **Cause:** the CLI view reads the legacy findings collection; the desktop host view reads managed reports.
- **Impact:** switching interfaces can make existing findings appear absent. This is a visibility mismatch, not evidence that the underlying reports were deleted.

### SW-015 — Worker deletion leaves persisted execution receipts behind

**Medium · Source-traced · Storage/privacy cleanup**

- **Location:** Desktop `src-tauri/src/swarm/runner.rs:759`, `src-tauri/src/swarm/mod.rs:713`.
- **Trigger:** run experiments that save request/response receipts, then delete the worker.
- **Cause:** deletion removes event data and credentials but does not remove `swarm/receipts/<worker>`.
- **Impact:** potentially sensitive project output and test input remain on disk, and repeated worker lifecycles accumulate unused receipt data. This is local retention, not a demonstrated disclosure to another account.

### SW-016 — Abandoned source inspections accumulate full snapshots on disk

**Medium · Source-traced · Import storage lifecycle**

- **Location:** Desktop `src-tauri/src/bounty.rs:148`, `:153`, `:172`.
- **Trigger:** repeatedly inspect folders/files and cancel or replace the selection without successfully hosting it.
- **Cause:** each inspection creates a UUID-named JSON snapshot containing base64 source. Only the selected snapshot is removed after successful hosting; no expiry or aggregate cleanup was found.
- **Impact:** discarded imports retain source material and consume storage beyond the limit of any single project.

### SW-017 — A failed preview can leak a joined membership and vault credential

**Medium · Source-traced · Private join rollback**

- **Location:** Desktop `src-tauri/src/bounty.rs:206`, `:212`.
- **Trigger:** joining succeeds, but fetching the policy fails before the preview ticket is completed; alternatively, the app exits with pending preview tickets.
- **Cause:** error cleanup does not roll back all completed join/credential steps. Pending ticket cleanup information exists only in memory.
- **Impact:** unused memberships and credentials remain, and a restart loses the ticket bookkeeping needed for normal cleanup.

### SW-018 — Concurrent starts can consume the same private join ticket twice

**Medium · Source-traced · Join/start race**

- **Location:** Desktop `src-tauri/src/bounty.rs:189`, `:195`.
- **Trigger:** two overlapping `startWorker` calls use the same preview ticket.
- **Cause:** each call clones the ticket before awaiting preparation; removal occurs afterward rather than atomically claiming it first.
- **Impact:** two local workers can share one coordinator identity, conflicting over its messages, leases, and state. The interleaving was traced, not reproduced with two actual model preparations.

### SW-019 — Hosting can succeed while the UI receives a creation failure

**Medium · Source-traced · Partial-success handling**

- **Location:** Desktop `src-tauri/src/bounty.rs:168`, `:172`.
- **Trigger:** host creation completes, but the automatic local preview/join fails.
- **Cause:** the combined operation propagates the later error without distinguishing the already-live host from the failed join.
- **Impact:** the user sees failure, retries, and then receives an already-hosting error. A host can be live even though its creation dialog reported an unsuccessful operation.

### SW-020 — Host deletion reports success despite ignored storage/credential errors

**Medium · Source-traced · Host cleanup**

- **Location:** Desktop `src-tauri/src/bounty.rs:238`, `:249`.
- **Trigger:** deleting the host encounters a filesystem or vault removal error.
- **Cause:** removal results are discarded and the response still reports `deleted: true`.
- **Impact:** host data or credentials can survive a supposedly successful deletion; remaining host files can also obstruct subsequent creation. Failure injection was not performed on the user's real vault or host files.

### SW-021 — Reaccepting the same private policy clears the conversation

**Medium · Reproduced · Private conversation persistence**

- **Location:** Desktop `grid/src/bounty_coordination.rs:116`, `:129`.
- **Trigger/evidence:** in the dispatch probe, accept a policy, add a message, and accept the same policy with a new idempotency key. The session's message count becomes zero.
- **Cause:** acceptance replaces the session with a fresh `messages: Vec::new()`.
- **Impact:** an otherwise valid repeat acceptance discards the private conversation. A replay with the identical key is a different, cached path.

### SW-022 — Leaving the optional submission deadline blank prevents publication

**Medium · Reproduced · Website form/API contract**

- **Location:** Website `src/swarm/api.ts:71`, `server/swarm/validation.mjs:73`.
- **Trigger/evidence:** leave the optional field blank; the form payload sends `submissionDeadline: ''`, which validation rejects as a timestamp.
- **Cause:** the backend defaults to `closesAt` only for null/missing values through `??`, while the UI represents blank as an empty string.
- **Impact:** an advertised optional field must be manually filled to pass the backend contract.

### SW-023 — Website character limits do not match native command byte limits

**Medium · Reproduced boundary + source trace · Cross-runtime validation**

- **Location:** Website `server/swarm/validation.mjs:87`; Desktop `grid/src/bounty_project.rs:44`.
- **Trigger/evidence:** a setup command containing `"é".repeat(5000)` passes the website's 8,000-character limit but occupies 10,000 UTF-8 bytes and fails the native 8,000-byte limit.
- **Cause:** JavaScript string length and Rust byte length are treated as equivalent limits.
- **Impact:** a publisher can create a valid website recipe that workers reject. The limits need a common unit; this finding does not assert that all non-ASCII commands fail.

### SW-024 — Importing source loses executable permissions

**Medium · Source-traced · Project materialization**

- **Location:** Desktop `grid/src/bounty_project.rs:116`, `src-tauri/src/swarm/guest.rs:1314`.
- **Trigger:** import a project whose recipe executes a checked-in script directly, such as `./start.sh` or `./gradlew`.
- **Cause:** the snapshot has no executable-mode metadata and materialization makes files mode `0644`.
- **Impact:** a command that works in the original checkout fails with a permission error unless setup explicitly restores permission or uses an interpreter. This is especially relevant to enterprise folder imports.

### SW-025 — Import review silently shows only the first 100 files/exclusions

**Medium · Source-traced · Source review UI contract**

- **Location:** Desktop `src-tauri/src/bounty_project.rs:173`.
- **Trigger:** inspect an import with more than 100 included or excluded paths.
- **Cause:** the review response truncates the lists even though up to 4,000 source files are supported; it supplies no usable continuation or explicit list-truncation indicator.
- **Impact:** the publisher cannot fully review what will be shared or what was omitted through that flow. The aggregate count alone does not expose the hidden paths.

### SW-026 — Practice's 30-minute limit is checked only between turns

**Medium · Source-traced · Practice budget enforcement**

- **Location:** Desktop `src-tauri/src/swarm/practice.rs:24`, `:157`; `cli/src/bounty_practice.rs:260`.
- **Trigger:** a turn begins near the time limit and then spends a long period waiting for generation, busy retries, readiness, or a participant hold.
- **Cause:** elapsed-time enforcement is at the loop boundary rather than a deadline covering those awaited operations.
- **Impact:** practice can continue beyond its advertised 30-minute budget. Cancellation exists, but there is no demonstrated strict wall-clock limit for an entire practice run.

### SW-027 — The last allowed practice request can prevent reporting its result

**Medium · Source-traced · Practice result handling**

- **Location:** Desktop `src-tauri/src/swarm/practice.rs:157`, `cli/src/practice/evidence.rs`.
- **Trigger:** the 192nd allowed HTTP request produces the evidence needed for a finding, and the model needs another turn to inspect it and call `report_finding`.
- **Cause:** `target.journal.full()` ends the loop before that next model turn.
- **Impact:** a successful final observation can be counted as budget exhaustion without letting the model submit it. A report in the same tool-call batch can still succeed; the defect is the missing final review/report opportunity.

### SW-028 — Synchronous practice bypasses the registered cancellation/session mechanism

**Medium · Source-traced · Practice RPC lifecycle**

- **Location:** Desktop `src-tauri/src/swarm/practice.rs:63`, `:69`, `src-tauri/src/swarm/mod.rs:905`.
- **Trigger:** invoke the low-level synchronous `practice` action, then use the ordinary practice-stop controls or start a background practice session.
- **Cause:** the synchronous path creates its own cancellation token instead of registering a practice activity with the shared controller.
- **Impact:** the usual `practiceStop` mechanism cannot reliably target that run, and it can overlap the background practice path. The normal interactive CLI uses the background flow; the finding is specifically about the still-exposed synchronous interface.

### SW-029 — Practice metrics are omitted from CLI and cancellation outcomes

**Medium · Source-traced · Practice observability**

- **Location:** Desktop `cli/src/bounty_practice.rs:323`, `:400`, `src-tauri/src/swarm/practice.rs:100`.
- **Trigger:** consume the final CLI JSON result, or stop a background practice and inspect its outcome.
- **Cause:** the CLI result construction does not carry through the richer metrics. The background cancellation outcome also lacks the metrics included on the successful completion path.
- **Impact:** callers lose request counts, coverage/receipt details, and other measurements needed to compare practice runs. This concerns outcome serialization; intermediate activity can still contain useful information.

### SW-030 — Three browser test failures leave important journeys unverified

**Medium · Reproduced · Test/integration configuration defects**

- **Location:** Desktop `e2e/swarm-mining.spec.ts:83`, `:101`; Website `tests/swarm.spec.ts:1100`.
- **Trigger/evidence:** desktop Swarm Playwright: 3 passed, 2 failed. Website Swarm Playwright: 4 passed, 1 failed, 2 skipped. The website failure repeated in isolation.
- **Cause:** the desktop failures use stale form/consent expectations. The website owner-approval journey receives HTTP 409 because its synthetic commitment path is disabled under the test configuration.
- **Impact:** these suites are not a green regression gate for the new flows. The failed assertions alone do **not** prove three corresponding production UI defects. The two skipped website journeys were not validated.

### SW-031 — Practice help still describes the removed login/flag exercise

**Low · Source-traced · Documentation/console**

- **Location:** Desktop `cli/src/bounty_console.rs:257`, `skills/yougori/references/cli.txt:1379`.
- **Trigger:** open the practice console or consult its CLI reference.
- **Cause:** labels and instructions still refer to `acme-login`, its login-service workflow, and flag-only qualification rather than the current Northstar Ledger exercise and receipt-based finding checks.
- **Impact:** users and agents receive inaccurate instructions about the target, available workflow, and success conditions.

### SW-032 — Polling either preserves obsolete errors or erases actionable ones

**Low · Source-traced · Desktop feedback**

- **Location:** Desktop `src/components/private-bounty-host.tsx:13`, `src/components/swarm-worker-detail.tsx:27`.
- **Trigger:** a host poll fails and later succeeds; separately, a worker action fails just before the next successful background poll.
- **Cause:** host polling does not clear its old error after recovery, whereas worker polling clears the same error state used by user actions.
- **Impact:** the host can look broken after recovery, while an action failure can disappear within roughly three seconds before the user can read or act on it.

### SW-033 — A source file contains an invalid UTF-8 separator byte

**Low · Reproduced · Desktop text encoding**

- **Location:** Desktop `src/pages/swarm-mining-page.tsx:49`.
- **Trigger/evidence:** byte inspection found a standalone `0xB7` at byte offset 2710 in the join separator. It is not a valid UTF-8 encoding of the intended character.
- **Cause:** a text edit introduced an incompatible byte encoding.
- **Impact:** tools/rendering that decode UTF-8 can show a replacement glyph. TypeScript compilation still passed, so compilation alone does not catch it.

### SW-034 — A valid shared attempt event can stop every native worker that reads it

**High · Reproduced boundary + source trace · Public agent coordination**

- **Location:** Website `server/swarm/index.mjs:843`, `:850`, `:853`; Desktop `src-tauri/src/swarm/memory.rs:66`.
- **Trigger/evidence:** the actual local HTTP API accepted an attempt containing 8,000 CJK characters in observations and 4,000 each in expected/limitations. Fetching its channel event yielded 48,652 serialized bytes. The exact native memory-record helper rejected it with `Channel event exceeds its memory limit`.
- **Cause:** the server validates text lengths but can emit an event larger than the native 32,768-byte journal-record limit.
- **Impact:** the offending event cannot be recorded, the synchronization cursor cannot progress past it, and workers reading the same channel can repeatedly fail. HTTP acceptance and native rejection were tested separately; a live multi-model swarm was not run.

### SW-035 — Upload retries can return a snapshot that has already been deleted

**Medium · Reproduced · Website upload idempotency**

- **Location:** Website `server/swarm/index.mjs:60`, `:529`, `:536`, `:540`, `src/swarm/api.ts:232`.
- **Trigger/evidence:** upload A to an unpublished draft, replace it with B, then upload A again using its original content-derived idempotency key. The actual HTTP handler returns 200 with A's original source identity, but that source no longer exists and the draft still points to B.
- **Cause:** replacing an unpublished source deletes it, while its cached idempotent upload response remains. The client deterministically reuses the key for identical upload content.
- **Impact:** a successful retry can falsely report that the requested source is selected, leading to stale upload status, missing-source lookups, or publication of the wrong current snapshot. This is separate from the file-picker state bug in SW-004.

### SW-036 — Messages after the first page receive an empty acknowledgement

**Low · Reproduced · Website chat API**

- **Location:** Website `server/swarm/index.mjs:151`, `:397`, `:750`.
- **Trigger/evidence:** seed 100 synthetic conversation messages, then post a human message and an agent reply through the actual HTTP handlers. Both returned HTTP 200 with `{}`; the stored count reached 102.
- **Cause:** after insertion, each route searches the first 100 messages for the newly inserted ID. It is no longer in that page, so `message` is undefined and disappears during JSON serialization.
- **Impact:** callers do not receive the promised message object. Messages are still stored and cursor-based polling can retrieve them; no message-loss or UI-crash claim is made here.

### SW-037 — Switching workers can mix their conversation caches

**Medium · Reproduced helper · Website conversation state**

- **Location:** Website `src/swarm/use-conversation.ts:8`, `:14`, `:18`, `:27`.
- **Trigger/evidence:** a deferred request for worker A resolves after the hook switches to worker B. A probe running the actual transpiled hook with mocked React/resource boundaries put A's message into B's shared cache and made the next B request use A's cursor (`after=500`).
- **Cause:** the asynchronous callback mutates `state.current` after awaiting without checking that the ref still belongs to its captured worker. The outer resource generation guard cannot undo that shared-ref mutation.
- **Impact:** the view can display one owned worker's conversation in another and skip earlier messages belonging to the new worker. This was not a cross-account authorization bypass or a full browser reproduction.

### SW-038 — Expired work budgets continue occupying bounty capacity

**Medium · Reproduced · Capacity/lifecycle limitation**

- **Location:** Website `server/swarm/index.mjs:337`, `:357`, `:359`, `:737`.
- **Trigger/evidence:** accept a one-minute budget on a capacity-one bounty, advance the fixture clock by 61 seconds, then try to enroll a second participant. The first worker loses execution authorization, while the second receives no offer and acceptance returns capacity HTTP 409.
- **Cause:** capacity counts active/paused membership rows without considering their expired budget; no automatic expiry/reclamation was found.
- **Impact:** unavailable workers can keep a bounty full until their membership is explicitly ended or the bounty lifecycle changes. Reserving paused participants may be intentional, but the lack of expired-budget reclamation is an operational limitation rather than an authorization bypass.

### SW-039 — Older ineligible bounties can hide every eligible offer

**Medium · Reproduced · Offer discovery**

- **Location:** Website `server/swarm/index.mjs:332`, `:338`.
- **Trigger/evidence:** seed more than 100 older open but ineligible records and create a later bounty the participant can accept. The actual offers endpoint omits the later bounty, while direct acceptance succeeds.
- **Cause:** SQL selects the oldest 100 open records before checking authorization, schedule, approval, and capacity. There is no pagination to reach later records.
- **Impact:** workers can appear to have no available work despite eligible bounties existing. Ineligible old records consume discovery slots.

### SW-040 — Source validation accepts paths that cannot be materialized

**Medium · Reproduced boundary + source trace · Source manifest integrity**

- **Location:** Desktop `grid/src/bounty_project.rs:68`, `:91`, `src-tauri/src/swarm/guest.rs:1300`; Website `server/swarm/validation.mjs:91`, `server/swarm/index.mjs:515`.
- **Trigger/evidence:** submit both regular file `node` and file `node/child`, or a filename with a single 260-byte component. The website accepted both manifests; the actual grid snapshot validator also accepted the file/parent collision.
- **Cause:** validation checks path syntax and duplicate full names, but not file-versus-directory prefix conflicts or the sandbox filesystem's per-component limit.
- **Impact:** accepted source cannot be reconstructed normally in the Linux sandbox. The validators were exercised; a full worker preparation of these snapshots was not run.

### SW-041 — Long source paths collide in task identity

**Medium · Reproduced helper · Task coverage**

- **Location:** Desktop `src-tauri/src/swarm/runner.rs:320`, `:331`.
- **Trigger/evidence:** use two distinct valid paths formed by `"segment/".repeat(30)` plus `a.rs` and `b.rs`. Both pass the real grid path validator. The extracted native `next_task()` returns the same 240-character component for both; recording the first source-review attempt makes it advance to another category instead of reviewing the other file.
- **Cause:** a truncated display string is also used as the component's deduplication identity.
- **Impact:** different files are treated as already covered, and the component may not even identify the complete filename. This probe used valid paths with no empty path segments.

### SW-042 — Escaped command output can exceed the tool transport cap

**Medium · Reproduced boundary + source trace · Experiment output**

- **Location:** Desktop `src-tauri/src/swarm/guest.rs:1445`, `:1540`, `src-tauri/src/swarm/runner.rs:888`.
- **Trigger/evidence:** JSON-serializing stdout and stderr containing 24,000 quote characters each produced 96,038 bytes even though each raw stream fit its 24,000-byte clip. The tool transport rejects responses above 65,536 bytes.
- **Cause:** clipping raw output does not bound escaped JSON size or the complete result envelope.
- **Impact:** an otherwise completed local check can fail when its result is sent back to the agent. The size mismatch was reproduced with serialization, not a live container command. SW-002 involves different report expansion logic; this is the experiment-output path.

### SW-043 — Blocked and interrupted attempts are treated as completed coverage

**Medium · Reproduced helper · Task retry logic**

- **Location:** Desktop `src-tauri/src/swarm/runner.rs:190`, `:327`.
- **Trigger/evidence:** feed the exact `next_task()` helper nonhistorical blocked results for all seven categories of a file. It returns no task. Adding a peer observation that resolves the blocker does not change that result.
- **Cause:** deduplication tests component/category/conditions and event type, but not outcome or whether later peer evidence changes the reason to retry.
- **Impact:** failed setup or interrupted work can exhaust the worker's apparent coverage and leave it waiting despite newly usable evidence. New participant guidance changes the condition key and can permit retries; there is no equivalent automatic reconsideration for the reproduced peer-update case.

### SW-044 — Target logs have no size bound, and error handling reads the entire log

**Medium · Source-traced · Sandbox storage and memory**

- **Location:** Desktop `src-tauri/src/swarm/target.rs:289`, `:292`, `:303`.
- **Trigger:** a long-lived target writes large amounts of stdout/stderr, then fails its health check.
- **Cause:** both streams go into one file without rotation or a per-log cap. Failure diagnostics call `read()` on the full file before selecting its last 6,000 characters.
- **Impact:** logs can consume the sandbox's disk allowance and then create a large memory allocation during diagnostics. The container quota still provides an outer storage bound. No disk-filling stress test was performed.

### SW-045 — Failed agent bootstrap leaves the agent's network enabled

**Medium · Source-traced · Setup cleanup**

- **Location:** Desktop `src-tauri/src/swarm/guest.rs:580`, `:655`, `:686`, `:1595`; `src-tauri/src/swarm/mod.rs:781`.
- **Trigger:** OpenCode installation, provider setup, or tool bootstrap fails after agent-network access is enabled.
- **Cause:** network closure is on the successful path. The launch-error cleanup aborts agent execution/PTY and the test environment, but does not close that agent network or remove the allocated agent container.
- **Impact:** a failed preparation can leave a running, network-enabled resource behind. Initial bootstrap does not yet contain the imported project, so this is not evidence of a demonstrated project-code escape or external attack.

### SW-046 — Cancel Preparation can leave a private worker's model loading

**Medium · Source-traced · Model resource cleanup**

- **Location:** Desktop `src-tauri/src/swarm/mod.rs:938`, `:1297`, `src-tauri/src/swarm/model_lifecycle.rs:211`, `:480`.
- **Trigger:** cancel preparation of a private worker while its model is downloading/loading.
- **Cause:** private workers already have a `server_id` containing their member ID. Cancellation sets state to paused, but cleanup eligibility only recognizes a paused setup worker when `server_id` is absent; the initial-setup classification makes the same assumption.
- **Impact:** cancellation can stop sandbox preparation without stopping the unused model download/load, consuming resources after the UI says preparation was cancelled. This was source-traced; no GPU/download cancellation experiment was run.

### SW-047 — Deleting a private worker during environment creation can orphan a sandbox

**Medium · Source-traced race · Resource lifecycle**

- **Location:** Desktop `src-tauri/src/swarm/closed.rs:153`, `:164`, `:187`, `src-tauri/src/swarm/guest.rs:472`, `:490`.
- **Trigger:** private Delete advances the generation and waits for the execution gate while an environment creation is finishing.
- **Cause:** late creation can add its environment ID to the current worker row, then stop it because its generation is stale. Delete continues using the earlier worker snapshot instead of rereading the row after the gate, so it misses that late resource and then removes the row.
- **Impact:** a stopped owned sandbox can remain without its worker record. The public deletion path has a reread; this finding concerns the private path. The interleaving was traced but not scheduled in a live runtime test.

### SW-048 — Synchronous practice allows 30 minutes but its CLI RPC times out at 15

**Medium · Source-traced · Low-level CLI/API contract**

- **Location:** Desktop `cli/src/client.rs:176`, `cli/src/bounty_practice.rs:260`, `src-tauri/src/swarm/practice.rs:157`.
- **Trigger:** call the synchronous `swarm_dispatch` practice action and let it run for more than 900 seconds.
- **Cause:** the CLI client's special timeout is 900 seconds; the practice budget is 1,800 seconds, before the additional overruns in SW-026.
- **Impact:** the client can time out before a valid run returns. The ordinary `bounty practice` command uses background polling, so this does not imply that every CLI practice run has a 15-minute limit.

### SW-049 — Private host roster does not adopt the configured worker name/model

**Low · Source-traced · Host usability**

- **Location:** Desktop `src-tauri/src/bounty.rs:170`, `:183`, `:192`, `grid/src/bounty_coordination.rs:431`, `grid/src/bounty.rs:542`.
- **Trigger:** host locally, configure/rename the worker, and inspect the private host member roster.
- **Cause:** membership is created with a preliminary name such as `Host worker`; managed worker startup/heartbeats do not update that member record with the final name and model. The older heartbeat path that carries model metadata is different.
- **Impact:** multiple workers are hard to identify and the host can lack model information even though it was provided during setup.

### SW-050 — The older CLI importer generates empty files that the host rejects

**Medium · Reproduced boundary + source trace · CLI folder hosting**

- **Location:** Desktop `cli/src/closed_bounty.rs:115`, `:123`, `src-tauri/src/bounty.rs:90`.
- **Trigger/evidence:** run the actual extracted folder importer on a fixture with an empty `empty.py` or `__init__.py`. It emits a valid empty base64 string; native `read_files()` rejects empty `data` as missing.
- **Cause:** an empty file and an absent content field are conflated at the older hosting boundary.
- **Impact:** ordinary projects containing legitimate zero-byte files cannot be hosted through that CLI path. The newer desktop snapshot importer handles empty files differently and is not included in this claim.

### SW-051 — The older CLI importer shares credential files rejected by the newer importer

**High · Reproduced boundary + source trace · Source confidentiality**

- **Location:** Desktop `cli/src/closed_bounty.rs:105`, `:115`, `src-tauri/src/bounty.rs:99`, `src-tauri/src/bounty_project.rs:24`, `:53`.
- **Trigger/evidence:** the actual extracted CLI importer included synthetic `credentials.json` and `key.pem`, including a dummy private-key marker, in its source payload. It filters hidden/build names, not the newer credential-file/content exclusions.
- **Cause:** the older CLI upload reaches `bounty_host` and grid snapshot validation without going through the new desktop importer's secret rejection.
- **Impact:** a folder that is rejected or filtered by the newer flow can share secrets with bounty participants through the older CLI flow. Only fake fixture data was used; no real credential was read, uploaded, or disclosed. This is an import-boundary inconsistency, not a claim that arbitrary secret detection can be perfect.

### SW-052 — Pending account-admin mutations survive session revocation

**High · Reproduced · Website authorization race**

- **Location:** Website `server/swarm/moderation.mjs:44`, `:48`, `:54`.
- **Trigger/evidence:** begin an authenticated loopback request to `/api/swarm/admin/accounts/limit`, pause its body, revoke the synthetic admin session, then finish the body. The handler returned HTTP 200 and applied limit 17; a fresh admin request using that session returned 401.
- **Cause:** account-limit and account-access changes check admin authorization before awaiting `readJson()` and do not recheck it after the await. Other moderation mutations do perform a fresh check.
- **Impact:** revocation does not prevent an already-pending account mutation from committing; the same ordering exists on the account ban/restore path. This requires a previously valid admin session and does not grant a non-admin admin privileges. No real accounts or production settings were changed.

### SW-053 — The model-tool test assumes a host-specific CPU fallback

**Low · Reproduced · Test portability**

- **Location:** Desktop `scripts/swarm-model-tools.test.py:212`, `src-tauri/src/model_server.py:884`, `:887`.
- **Trigger/evidence:** `python scripts/swarm-model-tools.test.py` ran seven tests: six passed, one failed. With an invalid thread setting, the helper fell back to this host's CPU count, 24, while the test unconditionally expected the string `2`.
- **Cause:** the fallback assertion neither mocks CPU count nor derives its expectation from the host. The explicit two-thread allocation assertions earlier in the same test passed.
- **Impact:** the suite produces a machine-dependent failure. This is not evidence that the runtime ignores a valid CPU allocation or that its tool-calling protocol is broken.

### SW-054 — Remotely ended public membership leaves a waiting worker with stale policy

**Medium · Source-traced · Public worker state transition**

- **Location:** Desktop `src-tauri/src/swarm/runner.rs:110`, `src-tauri/src/swarm/practice.rs:36`; Website `server/swarm/index.mjs:650`.
- **Trigger:** membership ends through a remote lifecycle action, or a stopped worker later resumes after its membership ended remotely.
- **Cause:** the no-membership branch sets `ready_waiting` but does not clear the worker's accepted policy/source/guidance. Practice's waiting predicate requires the policy to be null.
- **Impact:** the UI can show a worker waiting for offers while practice rejects it as ineligible and old bounty context remains. The native local Leave path does clear this data; the finding concerns remote transitions and their recovery.

### SW-055 — Deleted workers remain in the in-memory activity map

**Low · Source-traced · Memory/privacy cleanup**

- **Location:** Desktop `src-tauri/src/swarm/activity.rs:29`, `:35`, `src-tauri/src/swarm/mod.rs:713`.
- **Trigger:** repeatedly create, use, and delete workers during one engine session.
- **Cause:** activity is kept in a static map by worker ID. The 5,000-event bound applies per worker; worker deletion does not remove its map entry.
- **Impact:** practice request/response text and activity remain in memory until process restart, and the number of retained worker histories can grow beyond the simultaneous-worker limit. No heap-growth benchmark was run.

### SW-056 — Public report lists silently hide reports beyond the newest 100

**Medium · Source-traced · Report discoverability**

- **Location:** Website `server/swarm/index.mjs:320`, `:401`; Desktop `src-tauri/src/swarm/mod.rs:1154`.
- **Trigger:** a participant or worker accumulates more than 100 reports, including drafts awaiting review.
- **Cause:** both worker detail and the participant report list use `ORDER BY sequence DESC LIMIT 100` without exposing a pagination cursor.
- **Impact:** older drafts/findings disappear from normal lists and cannot be reached through pagination. Direct retrieval remains possible if the report ID is already known; this is not report deletion. The private coordinator's separate report collection is not the affected path.

## Validation performed

The first table records checks completed in the earlier audit and retained here; they were not all rerun during this continuation. The second table records deeper checks from this continuation. Passing focused tests does not cancel failures elsewhere or establish complete end-to-end readiness.

### Earlier audit checks

| Check | Result | Interpretation |
| --- | --- | --- |
| `cargo check --locked --manifest-path src-tauri/Cargo.toml --all-targets` | Failed: two `E0425` errors | SW-001; native test coverage is blocked |
| `cargo test --locked --manifest-path grid/Cargo.toml bounty -- --nocapture` | 9 passed | Existing grid bounty tests |
| `cargo test --locked --manifest-path cli/Cargo.toml bounty_practice -- --nocapture` | 6 passed | CLI practice unit coverage |
| `npx vitest run src/components/closed-bounty-dialog.test.tsx src/api/swarm-api.test.ts` | 3 tests passed, 2 files | Focused desktop UI/API coverage |
| `python scripts/swarm-target.test.py` | 4 passed, 1 skipped | Linux-only case skipped on Windows |
| `npm run lint` | Passed | Desktop lint |
| `npx tsc -b --pretty false` | Passed | Desktop TypeScript |
| Website `node --test server/swarm.test.mjs` | 37 passed | Existing backend suite |
| Website runtime-contract test | 1 passed | Separate contract check; 38 backend/contract tests combined |
| Desktop Swarm Playwright | 3 passed, 2 failed | Stale expectations described in SW-030 |
| Website Swarm Playwright | 4 passed, 1 failed, 2 skipped | Owner-approval configuration failure; repeated in isolation |
| Swarm-scoped `git diff --check` in both checkouts | Passed | Whitespace verification, not behavior verification |
| Private coordinator dispatch probes | Reproduced oversized report, receipt-cap controls, conversation reset | Exact dispatch exercised with surrounding clock/token/hash stubs |
| Ephemeral private hub using the real grid library | Reproduced 64-connection exhaustion and recovery | Local loopback only |
| Northstar Ledger vulnerable/fixed control fixture | Own export 200 in both; direct foreign access 403 in both; vulnerable source-edit path 200 with cross-tenant proof; fixed control 403 without that proof | Supports the practice fixture's intended challenge, not a product vulnerability finding |
| WSL child-process and byte-inspection probes | Zombie birth marker retained; invalid UTF-8 byte confirmed | SW-010 and SW-033 |

### Deeper continuation checks

| Check | Result | Coverage/limits |
| --- | --- | --- |
| `cargo test --locked --manifest-path cli/Cargo.toml --test bounty_command_line` | 6 passed | Command parsing/offline behavior; no live engine/model |
| `python scripts/swarm-model-tools.test.py` | 6 passed, 1 failed | Host-dependent fallback assertion, SW-053 |
| Actual website handlers through ephemeral loopback HTTP and disposable in-memory SQLite | Reproduced SW-034–SW-036, SW-038–SW-040, SW-052 | Synthetic users, synthetic source, controllable fixture clock; seeded catalogs for size/capacity cases |
| Actual `useConversation` hook, transpiled and exercised with deferred requests and mocked hook/resource boundaries | Reproduced SW-037 | Demonstrates ref/cursor contamination; not a full browser run |
| Rust probe using actual grid library, native memory helper, extracted `next_task()`, and extracted older CLI importer | Reproduced SW-034, SW-040, SW-041, SW-043, SW-050, SW-051 at the stated boundaries | Disposable programs; no repository test/source edits |
| Valid-path collision recheck | Both full paths valid; identical 240-character component; next category chosen after only one source-review result | Confirms SW-041 without relying on invalid path syntax |
| Serialized output-size probe | 96,038 bytes from individually clipped streams | SW-042; no live container needed to establish the size mismatch |

Selected measured outputs from the continuation:

```text
Shared event serialized size: 48,652 bytes
Native event record rejection: Channel event exceeds its memory limit
Upload A -> B -> A: replayedOriginal=true, replayedSourceExists=false, currentIsB=true
Conversation after first 100 entries: human POST={}, agent POST={}, stored messages=102
Offer catalog test: offerVisible=false, directAcceptanceSucceeded=true
Long-path task test: validPaths=true, sameComponent=true, componentLength=240
Command stdout/stderr serialization: 96,038 bytes
Admin request after revocation: pending request=200, applied limit=17, fresh request=401
```

The temporary probes reused actual handlers/helpers where practical. They are evidence at those boundaries, not substitutes for a full desktop, model, target, and multi-worker integration run. No real production targets, accounts, payment flows, or credentials were modified.

## Coverage and remaining uncertainty

| Area | Inspected/exercised | Still missing |
| --- | --- | --- |
| Desktop closed-bounty flow | Form/API contract, import review, hosting, preview tickets, local/LAN choices, polling, error paths | Complete new-user journey with a real model and large enterprise project |
| Public website/backend | Publishing/upload lifecycle, validation, source identity, enrollment/offers, capacity, messages, shared events, reports, moderation authorization | Production deployment validation; the skipped browser journeys; large-scale sustained use |
| Private/LAN hub | TLS admission, membership, coordination, control, receipts, messages, reports, persistence callers | Sustained multi-PC LAN/VPN operation, network partitions, power-loss recovery |
| Worker/OpenCode harness | Preparation, target setup, tools/transport limits, task selection, cancellation, resume/delete races, model lifecycle | Real model discovery, fresh OpenCode install failure injection, GPU stress, long model runs; no claim about latest upstream harness compatibility |
| Practice | Native/CLI contracts, target fixture and fixed control, receipt budget, cancellation and metrics paths | Native test suite currently blocked; full live-model success-rate evaluation across models |
| Security boundaries | Source filtering inconsistencies, authorization timing, event/transport limits, private-hub availability | A complete penetration test of the app, OS isolation, vault, dependency supply chain, and deployed infrastructure |
| Resource/storage cleanup | Imported snapshots, receipts, model cancellation, late sandbox creation, activity retention | Real disk-full/vault-failure injection and memory/storage growth benchmarks |
| Payments/awards | Relevant report/membership transitions reviewed | No real payment or external award settlement was exercised; this is not a payment audit |

### Follow-up concerns not counted as confirmed bugs

1. **Evidence authenticity versus integrity.** Some report attachments are model-authored base64 rather than automatically bound to native execution receipts. A digest proves content integrity, not that a claimed experiment happened. The existing validation/provenance guarantees need a dedicated adversarial review before calling this a proven exploit.
2. **Private coordinator scaling.** Reads clone coordinator history, and many writes serialize it synchronously, including frequent lifecycle operations. Large histories may increase latency and memory, but no benchmark establishes the operational threshold.
3. **Power-loss durability.** Atomic replacement does not by itself demonstrate persistence across sudden power loss. Host/member/coordinator recovery and partial write failures need fault-injection tests.
4. **Full model/runtime behavior.** Static state-machine findings involving GPU/model loading, process teardown, and environment creation need deterministic live integration tests once the native test compilation blocker is removed.

### Items deliberately not counted

- The planted Northstar Ledger tenant-isolation flaw is the practice exercise, not a vulnerability in the Swarm product. The fixed-control comparison is included above as validation of that exercise.
- The earlier screenshot's vertically wrapped authorization checkbox was already changed before this audit; it is not listed as a newly confirmed open bug.
- A suspected closed-dialog import-state leak was rejected after tracing the parent unmount/reset behavior.
- A private worker does have a `server_id` from creation; findings that depend on that value use the actual private member-ID behavior.
- Passing unit tests, HTTP probes, or TypeScript checks are not presented as proof that an enterprise can complete every Swarm workflow today.

## Change record

This report is the only intended repository addition from this read-only continuation. Existing source edits, deleted files, untracked implementation files, and generated build output predated the report and were preserved. No fixes, commits, installation, publication, or deployment were performed.

A content-hash comparison covered 1,726 existing desktop checkout files and 401 website files captured before the deeper probes. All reviewed Swarm files and all captured website files were unchanged. Two unrelated desktop files, `e2e/desks.spec.ts` and `src/components/grid-desks.tsx`, changed during the audit through activity outside these audit writes; they were left untouched. The report is the only new existing source/document file identified by the comparison after excluding generated/build directories.

The list is the complete set of findings established by this audit, not a guarantee that the system contains no additional bugs. Source-traced races and failure paths should be reproduced in isolated integration tests before changes are declared validated.
