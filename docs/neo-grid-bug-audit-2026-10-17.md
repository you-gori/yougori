# Neo Grid, sandboxes, and Sandbox Grid bug audit — 17 October 2026

## Combined audit

Expanded to include local sandbox lifecycle, sandbox file editing and sharing, and Sandbox Grid hosting, placement, people, desks, recovery, and UI integration. **55 findings in total: 7 High, 47 Medium, 1 Low. No application fixes were made.**

| Area | Findings | High | Medium | Low |
| --- | ---: | ---: | ---: | ---: |
| Original Neo Grid review, NG-001–NG-025 | 25 | 2 | 22 | 1 |
| Sandbox Grid addition, SG-001–SG-021 | 21 | 3 | 18 | 0 |
| Sandbox addition, SB-001–SB-009 | 9 | 2 | 7 | 0 |
| **Total** | **55** | **7** | **47** | **1** |

The addition contributes **30 findings**, with **17 locally reproduced at the stated handler/helper boundary and 13 source-traced**. Across both phases, 32 findings have reproduction evidence and 23 are source-traced. Shared defects already covered by an NG ID are cross-referenced, not counted again.

The most urgent new issues are the restart path that treats restored desks as removed, the failure path that can delete an existing desk's data, unchanged access grants after reassignment/removal, and unsafe sandbox editor saves. Reproductions used disposable data; no real sandbox was stopped, deleted, modified, or exposed.

The original Neo Grid section is retained below. The [Sandbox Grid findings](#sandbox-grid-findings) and [sandbox findings](#sandbox-findings) follow it, with additional verification and scope limits.

## Original Neo Grid review

Read-only review of the current Neo Grid implementation: private hub, LAN and tunnel transport, membership, scheduling, model lifecycle, API request routing, model-team harnesses, CLI, and desktop UI. **No application fixes were made.** This report is separate from the [Swarm Mining audit](swarm-bug-audit-2026-10-17.md).

## Neo Grid result and scope

**25 findings: 2 High, 22 Medium, 1 Low.** These include correctness defects, security boundary failures, and operational limitations. No Critical finding was established. Severity describes impact, independently of the strength of reproduction evidence.

| Severity | IDs |
| --- | --- |
| High | NG-001, NG-002 |
| Medium | NG-003–NG-024 |
| Low | NG-025 |

**15 findings have local reproduction evidence; 10 are source-traced.** The reproduction labels below distinguish real hub requests from harness/helper probes. Passing those probes does not mean a complete desktop-to-GPU integration scenario was run.

- **Reproduced:** an actual local handler, module, or extracted UI helper exhibited the failure. Each entry identifies the boundary exercised.
- **Reproduced boundary + source trace:** a problematic input/output was reproduced, and the downstream consequence follows from inspected integration code.
- **Source-traced:** the inspected state transitions establish the defect or limitation, but the complete runtime scenario was not reproduced.

### Checkout and boundaries

| Item | Inspected version |
| --- | --- |
| Checkout | `C:\Users\Argon\Desktop\yougori` |
| HEAD | `502f78914382ed768a6f71f4b38cc72184f9dbde` |
| Working tree | Substantial pre-existing uncommitted changes; findings describe the working tree, not only HEAD |
| Core | `grid/src/hub.rs`, `member.rs`, `harness.rs`, `net.rs`, `tunnel.rs`, `activity.rs`, `policy.rs`, `schedule.rs`, and supporting authentication/persistence code |
| Desktop/native | `src-tauri/src/grid.rs`, shared tunnel/model lifecycle integration, `src/api/grid-api.ts`, Neo Grid page, dialogs, swarm controls, and shared status polling |
| CLI | Grid commands, launcher flow, argument/schema integration, and automation dispatch/queue behavior |

Neo Grid's model-team harnesses are distinct from Swarm Mining bounty workers. The public **Join Yougori grid** path delegates to the separate Network product; this audit does not establish correctness of that entire marketplace/backend. Sandbox Grid desks have a separate lifecycle and were outside the original phase; they are covered in the addition below. No production service or external company's grid was tested.

### Highest-priority problems

1. Assignment/exclusion is not enforced when a member takes a job, and a pending member poll can survive removal (NG-001, NG-002).
2. Both streaming and swarm fan-out bypass the advertised per-key request accounting (NG-005, NG-006).
3. Valid harness settings can generate a job larger than workers can receive, after substantial work has already completed (NG-011).
4. Model preparation, reassignment, deletion, and restart handling have cancellation and state races (NG-014–NG-020).
5. Failed operations can change state or erase the user's form, and late status replies can restore obsolete UI state (NG-007, NG-023, NG-024).

## Detailed findings

### NG-001 — An excluded, unassigned member can take model work

**High · Reproduced · Job authorization**

- **Location:** `grid/src/hub.rs:1040`, `:1506`, `:1534`.
- **Trigger/evidence:** the loopback probe created a normal serving member and a second member marked incapable, excluded, and unassigned. The second member supplied the model name in its work request, received the synthetic prompt, and returned an answer that the caller accepted with HTTP 200.
- **Cause:** `work()` trusts the client's model list. `take()` matches that list against the queued model and retry exclusions; it does not check the member's current assignment, exclusion, or capability in the durable record.
- **Impact:** a member token permits reading prompts and supplying results outside that computer's assignment. This requires an existing member credential; it is not an unauthenticated outsider attack. Normal desktop workers voluntarily follow their assignments, but the hub does not enforce that boundary. This contradicts the documented instruction to assign plans only to computers trusted with that data.
- **Observed result:** `assigned=false`, `excluded=true`, `receivedPrompt=true`, `callerStatus=200`.

### NG-002 — A removed member's pending poll can receive a new prompt

**High · Reproduced · Membership revocation**

- **Location:** `grid/src/hub.rs:1212`, `:1516`, `:1534`, `:1740`.
- **Trigger/evidence:** start an authenticated long poll, remove that member, then enqueue a request. The pending poll received the new synthetic prompt. A fresh request using the same membership was correctly rejected.
- **Cause:** membership is checked before entering the long-poll handler. Waking and retrying `take()` does not revalidate it. Removing the member cleans up jobs already associated with it but does not invalidate the outstanding poll.
- **Impact:** removal does not immediately stop prompt disclosure through already-open polls. The probe established disclosure; it does not claim that a removed member can submit a new authenticated response successfully.
- **Observed result:** `freshRequestRejected=true` while the pending poll returned the prompt queued after removal.

### NG-003 — Key revocation does not fence requests still uploading their body

**Medium · Reproduced · API key lifecycle**

- **Location:** `grid/src/hub.rs:1100`, `:1783`, `:1786`, `:1824`.
- **Trigger/evidence:** send valid authorization headers and part of a JSON body, revoke the API key, then finish the body. The request subsequently entered the queue, reached a worker, and completed with HTTP 200. A fresh request with that key returned 401.
- **Cause:** `key_of()` runs before awaiting the body. The captured key ID is used to enqueue work without another validity check.
- **Impact:** revocation stops fresh authentication but does not prevent a request that has not yet supplied its complete workload from starting work afterward. This is narrower than a general revoked-key bypass: the connection must have authenticated before revocation. It also differs from merely allowing an already-running generation to finish.

### NG-004 — Incomplete unauthenticated JSON bodies hold connections without a deadline

**Medium · Reproduced boundary + source trace · Hub availability**

- **Location:** `grid/src/net.rs:298`; `grid/src/hub.rs:60`, `:1130`, `:1159`, `:1190`, `:1282`.
- **Trigger/evidence:** a local TLS client sent the headers and only part of a join body, held it for 32 seconds, and then finished it. The hub still processed it and returned the expected 403 for invalid synthetic proof.
- **Cause:** the hub has a 10-second TLS handshake deadline and a 30-second HTTP header deadline, but `json_body()` has only a byte limit. Its body collection has no time limit, including before join authentication.
- **Impact:** clients can retain connection permits while supplying no complete authenticated request. Each listener has 2,048 permits; filling them can deny legitimate access through that listener. The probe demonstrated retention beyond the header deadline, **not** a full 2,048-connection exhaustion test. Actual full-exhaustion impact remains source-traced.

### NG-005 — Streaming responses disappear from concurrency accounting before completion

**Medium · Reproduced · Request limits and status**

- **Location:** `grid/src/hub.rs:1669`, `:1685`, `:1820`.
- **Trigger/evidence:** using the actual loopback hub and synthetic response streams, one API key accumulated 33 still-open response bodies despite the configured 32-request limit. The hub reported zero waiting and zero running jobs.
- **Cause:** receiving a member's response headers removes the job from `live.running`. Body relay continues afterward, while the key limit and queue status count only waiting/running entries.
- **Impact:** active responses escape the advertised per-key limit, monitoring understates work in progress, and a key can accumulate more live relays than its limit. The probe used protocol-level synthetic members, not 33 simultaneous GPU generations.
- **Observed result:** `openResponses=33`, `configuredPerKeyLimit=32`, `queue={waiting:0,running:0}`.

### NG-006 — Swarm fan-out can exceed the per-key request limit

**Medium · Reproduced · Harness admission control**

- **Location:** `grid/src/hub.rs:1868`, `:1871`, `:1909`.
- **Trigger/evidence:** a 31-task mixture queued 31 jobs. A second call using the same key passed the outer check and queued another 31, giving 62 waiting jobs under one key.
- **Cause:** the outer swarm route checks the current count once without reserving capacity. Each `HubAsk::ask()` then checks only the global queue limit, not that key's remaining allowance.
- **Impact:** a key can occupy more than its documented share and crowd out other applications. This is distinct from NG-005: it occurs before any response begins streaming.
- **Observed result:** `queued=62`, `limit=32`.

### NG-007 — An invalid plan update partially changes live state

**Medium · Reproduced · Configuration atomicity**

- **Location:** `grid/src/hub.rs:810`.
- **Trigger/evidence:** update a plan from model A to B while supplying an invalid percentage of zero. The call returned `--percent must be 1–100`, but the live plan named B. The saved record initially still named A; creating an unrelated API key then persisted B too.
- **Cause:** individual fields mutate the live plan before later fields are validated. The saved `previous` record is only used by `commit()`, which is never reached when early validation returns an error.
- **Impact:** an operation reported as rejected can silently change model selection and later become durable through another operation. Live assignments and saved settings can disagree in the meantime.

### NG-008 — Self-leave retains plans pointing at departed computers

**Medium · Reproduced · Membership and plan cleanup**

- **Location:** `grid/src/hub.rs:1057`, `:1724`.
- **Trigger/evidence:** assign a plan to one explicitly picked member, then have that member leave through its member endpoint. The record had zero members but retained the plan and the departed member ID.
- **Cause:** admin removal removes picked-member references and drops empty picked-computer plans. Self-leave removes the member and reconciles assignments without the same cleanup.
- **Impact:** stale plans remain visible and consume the 32-plan allowance until manually removed. Repeated joins/leaves can accumulate unusable plans; the probe reproduced one cycle, not saturation of all 32 slots.
- **Observed result:** `members=0`, `retainedPlans=1`, with the old member ID still in the plan's target.

### NG-009 — A failed persistence flush discards the retry marker

**Medium · Reproduced · Durability and recovery**

- **Location:** `grid/src/hub.rs:1113`, `:2046`.
- **Trigger/evidence:** a heartbeat changed a disposable member record and marked it dirty. The probe temporarily made the fixture's record path unwritable as a file, called `flush()`, restored the original path, and called `flush()` again. The disk still held the previous value while memory held the new one.
- **Cause:** both explicit flush and the periodic saver clear `dirty` before saving, ignore save errors, and do not restore the marker on failure.
- **Impact:** a transient persistence failure can lose updates on restart and a later flush alone does not recover them. An unrelated subsequent mutation can mask the issue by setting the marker again. Only disposable fixture data was altered for this fault injection.

### NG-010 — Swarm calls silently discard generation, structured-output, and tool options

**Medium · Reproduced · API compatibility**

- **Location:** `grid/src/hub.rs:1919`; `grid/src/harness.rs:270`, `:443`, `:466`.
- **Trigger/evidence:** an actual HTTP swarm call requested `max_tokens: 1`, JSON-object response format, and a tool definition. Its three forwarded plan/worker/final requests used token limits 1,200, 2,048, and 4,096; none forwarded response format or tools. The endpoint accepted a non-JSON final text answer with HTTP 200.
- **Cause:** the swarm entry point retains only `messages` and the streaming choice. Harness stages construct their own request options, including the final answer.
- **Impact:** clients cannot rely on the requested final-output format, tools, or output cap. Internal workers may reasonably need separate budgets, but silently ignoring the caller's final-output contract makes the advertised compatible endpoint unreliable. Unsupported options are not rejected or explained.

### NG-011 — Supported harness settings generate jobs larger than workers can receive

**Medium · Reproduced boundary + source trace · Payload limits**

- **Location:** `grid/src/harness.rs:26`, `:30`, `:350`, `:415`; `grid/src/hub.rs:1874`; `grid/src/member.rs:113`.
- **Trigger/evidence:** run the actual planning harness with three rounds of 32 tasks and synthetic worker answers of 12,000 ASCII characters. It constructed a 1,154,104-byte model request, exceeding the member exchange limit of 1,048,576 bytes even before the job envelope is added.
- **Cause:** aggregation limits each answer individually in characters, but does not limit the combined serialized job. Internally generated requests bypass the HTTP entry-point request-size check. Workers cap their entire received response at 1 MiB.
- **Impact:** a large planning run can finish many worker tasks and then become undeliverable when the lead must combine their results. The worker reports an interrupted hub response rather than a useful context-size error. The probe used the real harness with a synthetic `Ask` implementation; actual model generation and the final worker rejection were not run end to end.

### NG-012 — The planning strategy accepts mixed image/text input but drops the image

**Medium · Reproduced · Harness input preservation**

- **Location:** `grid/src/harness.rs:177`, `:350`, `:388`, `:422`.
- **Trigger/evidence:** the actual harness accepted a user message containing text and a synthetic image URL. All model requests in the planning run omitted the image.
- **Cause:** the plan path flattens messages using `request_text()`, which retains only string content or text fields from content parts, and builds every stage from that flattened string.
- **Impact:** a request to inspect an image can return an apparently successful answer from models that never received it. This finding is specific to the planning path. The mixture path retains the original messages when text is also present; it should not be described as dropping all images in the same way.

### NG-013 — A transient host restore failure is latched for the process lifetime

**Medium · Source-traced · Startup recovery**

- **Location:** `src-tauri/src/grid.rs:249`, `:255`, `:1009`.
- **Trigger:** restart with a saved hub while a temporary bind or credential-vault problem prevents `Hub::start()` from succeeding.
- **Cause:** `ensure_loaded()` sets `loaded=true` before restoration. Later calls return immediately. The existing hub settings file also prevents creating a replacement hub.
- **Impact:** correcting the temporary problem does not make ordinary status/loading operations recover the hub. The user needs a process restart or explicit hub cleanup. The UI does expose a hub error; this is a recovery failure, not an assertion that the failure is hidden.

### NG-014 — Exclusion or reassignment does not cancel preparation already in progress

**Medium · Source-traced · Download and model lifecycle**

- **Location:** `src-tauri/src/grid.rs:432`, `:444`, `:455`, `:734`, `:748`; `docs/closed-neo-grid.md:73`.
- **Trigger:** exclude a computer, remove its plan, or change its model while the old model is downloading or starting.
- **Cause:** the assignment handler clears the preparation handle without aborting or cancelling the task. Preparation continues and only checks the new assignment after `run_model_with_resources()` returns.
- **Impact:** downloads and startup can continue consuming bandwidth, disk, and runtime resources after the model is no longer wanted. Cleanup is deferred until preparation finishes, and can never be reached if preparation stalls. The documented promise that exclusion stops an in-progress download is not implemented by this path.

### NG-015 — An old preparation task can erase the handle for a newer one

**Medium · Source-traced · Reassignment race**

- **Location:** `src-tauri/src/grid.rs:452`, `:455`, `:625`, `:748`.
- **Trigger:** preparation A is running, assignment changes to B, B starts preparing, then A completes first.
- **Cause:** every preparation completion unconditionally clears `inner.work.preparing` before checking whether it still belongs to the current assignment. The field may already refer to B.
- **Impact:** the next tick can start another B preparation while the first is still active. Ownership and preparation status become unreliable, and unnecessary startup/download work can be scheduled. No live GPU timing reproduction was performed; the finding follows the asynchronous handle replacement directly.

### NG-016 — Deletion interprets a failed health check as no request in flight

**Medium · Source-traced · Safe model retirement**

- **Location:** `src-tauri/src/grid.rs:529`, `:539`, `:544`, `:565`.
- **Trigger:** retire a grid-created model while it is answering a request, and have its health check time out or fail.
- **Cause:** the failed check becomes `None`, and `in_flight(None)` is false. Deletion immediately leaves the wait loop and proceeds to stop/delete the environment if it has not been reassigned.
- **Impact:** a transient monitoring failure can interrupt an active request and remove the environment, despite the retirement code's promise to wait for in-flight work. The separate stop-only `quiet()` check correctly treats missing health as uncertainty; the deletion path does not.

### NG-017 — Cleanup is permanently abandoned when a retired model stays busy too long

**Medium · Source-traced · Resource cleanup**

- **Location:** `src-tauri/src/grid.rs:49`, `:539`, `:553`, `:753`.
- **Trigger:** a retired grid-created model continues reporting active work throughout 20 cleanup checks, roughly ten minutes when checks return promptly.
- **Cause:** `spawn_delete()` logs that the model was kept and returns. The assignment has already relinquished the environment ID, and there is no retained retirement queue to revisit it after the request finishes.
- **Impact:** the model environment and downloaded weights can remain orphaned indefinitely, requiring manual cleanup. The defect is abandonment after the bounded wait, not the decision to preserve a model while it is busy.

### NG-018 — A delayed retirement stop can stop an environment that was reassigned

**Medium · Source-traced · Reassignment race**

- **Location:** `src-tauri/src/grid.rs:522`, `:557`, `:575`.
- **Trigger:** an old assignment schedules stop-only retirement; while its asynchronous health check is pending, the same environment is reused by a new assignment. The old health check indicates that it is quiet.
- **Cause:** `spawn_power(..., false)` proceeds to stop the environment without checking whether it is now the current assigned environment. The deletion path has a reassignment guard, but the stop-only path does not.
- **Impact:** an obsolete retirement task can stop the newly selected model, leaving the current grid worker unavailable. This requires the described timing and a quiet health result; ordinary reassignment does not always trigger it.

### NG-019 — Restart state is cleared before the restart succeeds

**Medium · Source-traced · Schedule resume**

- **Location:** `src-tauri/src/grid.rs:575`, `:699`, `:704`; `src-tauri/src/model_runner/neocloud.rs:69`.
- **Trigger:** a grid-managed model is parked outside its schedule. When the schedule opens, its start attempt fails before changing the environment's `Stopped` state, for example while resolving runtime workload options.
- **Cause:** the grid immediately persists `parked=false` when scheduling the asynchronous start. The result is only logged. Subsequent retries require `parked=true` or an environment state of `Error`.
- **Impact:** the stopped model can be treated as manually stopped and receive no automatic retry even after the transient problem clears. Failures that do set the environment to `Error` follow a different retry path; this finding concerns those that leave it `Stopped`.

### NG-020 — A grid's own running request is mistaken for personal model use

**Medium · Source-traced · Availability and idle policy**

- **Location:** `src-tauri/src/grid.rs:654`, `:668`, `:679`, `:711`; `grid/src/hub.rs:598`.
- **Trigger:** a grid request is still generating when a health poll observes an active optimizer request, with a nonzero idle threshold configured.
- **Cause:** any active or pending optimizer work makes `person_using` true. The exception based on the grid's last job applies only to the idle-time branch, and the worker's current `busy` state is read afterward.
- **Impact:** the grid closes the serving gate and reports `person_active` for its own work. With no other available member, new callers can receive HTTP 503 instead of queueing behind a legitimately busy grid worker. The current generation may finish; this is an availability/reporting defect, not an assertion that every active answer is cancelled. `idle_after=0` bypasses this condition.

### NG-021 — Linux session-detail failures can bypass the idle requirement

**Medium · Source-traced · Activity detection**

- **Location:** `grid/src/activity.rs:59`, `:64`, `:73`, `:105`; `grid/src/policy.rs:101`.
- **Trigger:** `loginctl list-sessions` succeeds and identifies local sessions, but `loginctl show-session` fails for the relevant active session or all returned sessions.
- **Cause:** failed detail reads are silently skipped. An empty remaining list becomes `Activity::Nobody`, which permits serving, instead of `Activity::Unknown`, which would withhold work under a nonzero idle threshold.
- **Impact:** the grid can use a person's computer despite being unable to establish that it is idle. This differs from total `list-sessions` failure, which already returns `Unknown` correctly. The Linux command sequence was inspected, not executed on this Windows host.

### NG-022 — Streaming relay has no overall or downstream-stall deadline

**Medium · Source-traced · Streaming lifecycle**

- **Location:** `grid/src/hub.rs:1669`, `:1689`, `:1698`, `:1889`, `:2015`; `grid/src/member.rs:318`.
- **Trigger:** a protocol-level member repeatedly provides small response frames before each per-frame deadline, or the downstream caller stops consuming while keeping its connection open.
- **Cause:** the relay timeout restarts for each incoming frame. Sending a frame into the bounded relay channel has no timeout. The job has already left `live.running`, so the normal running-job sweeper no longer governs it. Harness body collection also has no independent overall deadline.
- **Impact:** hub tasks and connections can outlive the intended generation window, especially under downstream backpressure. This is a lifetime/cancellation defect separate from NG-005's incorrect counts. The normal member client applies its own approximately 31-minute response-upload wait, which limits some ordinary paths; it does not supply a hub-side total deadline for arbitrary protocol clients or a blocked downstream send. No 30-minute live timeout test was performed.

### NG-023 — Failed plan and harness creation clears the form

**Medium · Reproduced boundary + source trace · UI error handling**

- **Location:** `src/pages/neocloud-page.tsx:93`, `:206`; `src/components/grid-swarm.tsx:103`.
- **Trigger/evidence:** an extracted probe of the actual `run()` helper made the operation reject. The helper reported an error but fulfilled its returned promise, so the caller's `.then()` reset still executed.
- **Cause:** `run()` catches errors without returning a failure result or rethrowing. Both creation forms clear inputs in an unconditional success continuation. The early return when already busy also fulfills normally.
- **Impact:** a failed or skipped submission erases the model/selected-computer fields or harness name/worker selection, making retry harder and suggesting completion. This was reproduced at the helper boundary, not through a full browser/native failure scenario.
- **Observed result:** `errorReported=true`, `thenResetRan=true`.

### NG-024 — Late status replies overwrite newer grid state

**Medium · Reproduced boundary + source trace · UI polling**

- **Location:** `src/components/workspace-actions.tsx:23`.
- **Trigger/evidence:** the actual extracted polling helper received overlapping refreshes. The newer one returned a deleted/absent hub; the older one then returned the pre-deletion hub. The final visible state was the old hub.
- **Cause:** interval and manual refreshes can overlap. Results are applied in completion order with no request generation or cancellation guard.
- **Impact:** actions such as deletion, exclusion, or joining can appear to reverse temporarily, and controls can operate against obsolete IDs. Errors can also be cleared by older responses. This shared hook affects other workspaces too; it is counted once here for its Neo Grid effect. The reproduction used mocked React state functions and controlled promises.
- **Observed result:** `lastVisibleHub=deleted-hub` after a newer response had already reported no hub.

### NG-025 — Invite preview corrupts non-ASCII company names

**Low · Reproduced · Internationalization**

- **Location:** `src/api/grid-api.ts:196`, `:201`.
- **Trigger/evidence:** the actual transpiled TypeScript module decoded an invite whose UTF-8 company name was `Żółć 東京`. The preview returned mojibake beginning `Å»Ã³...`.
- **Cause:** `atob()` produces a binary byte string, which is passed directly to `JSON.parse()` without decoding UTF-8.
- **Impact:** valid international company names display incorrectly during joining. The native parser receives the original invite code; this probe does not establish that joining itself fails.

## Verification performed

| Check | Result | What it establishes |
| --- | --- | --- |
| `cargo test --locked --manifest-path grid/Cargo.toml --lib` | 67 passed, 1 ignored | Existing core grid tests, including local transport, scheduling, harness, and shared hub coverage. Counts include adjacent bounty/desks tests. |
| `npx vitest run src/api/grid-api.test.ts src/lib/grid-status.test.ts` | 6 passed in 2 files | Existing API/status helper cases. |
| `npx playwright test e2e/neo-grid.spec.ts` | 5 passed | Browser UI flows with a mocked grid API. These are not native/GPU integration tests. |
| `cargo test --locked --manifest-path cli/Cargo.toml grid -- --nocapture` | 15 passed across test binaries | Filtered CLI/launcher/command-line cases; counts include duplicated launcher tests across binaries. |
| `cargo check --locked --manifest-path src-tauri/Cargo.toml --all-targets` | Failed: two `E0425` errors | `src-tauri/src/swarm/practice.rs:619` and `:620` reference removed `bounty_practice::oracle`. Already recorded as SW-001, not counted again here. This does not establish that a non-test release build fails. |
| Disposable Rust probe 1 | 7 asserted reproductions passed | NG-001, NG-002, NG-003, NG-005, NG-007, NG-008, NG-009 against the actual grid library. |
| Disposable Rust probe 2 | 5 asserted reproductions passed | Actual hub probes for NG-004, NG-006, NG-010; actual harness with synthetic answers for NG-011 and NG-012. |
| JavaScript module/helper probes | 3 asserted reproductions passed | NG-023, NG-024, NG-025. |

Probe hubs used ephemeral loopback ports, disposable settings, synthetic credentials, and synthetic prompts. No real account, production key, or model workload was used. Rust probes were compiled against this checkout's built grid library. Playwright used its isolated port 1422 fixture with screenshots, video, and traces disabled.

Temporary reproduction sources/results are in `C:\Users\Argon\AppData\Local\Temp\yougori-neogrid-audit-du2ns1w6` (`probe.rs`, `probe2.rs`, `results.txt`, `results2.txt`, `ui-results.jsonl`). These are temporary audit artifacts, not permanent regression tests. This report is the deliverable; application source and existing tests were not edited to fix the findings.

A final SHA-256 comparison against the audit's starting snapshot found all 1,715 baselined files unchanged and none missing. The only new non-ignored checkout file was this report. Build/cache/test-output directories were excluded from that source comparison.

## Coverage gaps and uncounted follow-ups

- Native all-target compilation is blocked by SW-001. Consequently the native lifecycle findings were traced in source rather than reproduced through a complete running desktop/model stack.
- No live GPU downloads, model cancellation, environment deletion, macOS/Linux session commands, or multi-machine LAN partition scenarios were exercised.
- The external Cloudflare quick-tunnel test remained ignored. Local pinned TLS and simulated tunnel tests passed; public tunnel establishment, real network partitions, and production reconnect behavior remain unverified.
- Hub JSON-body retention was demonstrated with one slow connection. Listener saturation, large-grid load, and prolonged stream backpressure were not load-tested.
- Status for a published tunnel appears to depend on URL/process state rather than a fresh end-to-end reachability check. Whether the UI can remain connected during specific network partitions needs a controlled integration test; it is not included in the 25.
- `tick()` carries a membership snapshot across asynchronous activity/health checks before its later membership-change guard. A concurrent leave/rejoin may permit stale worker state changes; an integration race reproduction is needed before assigning a separate finding.
- If deleting the hub settings file fails after `grid_delete()` has dropped the running hub, the process can retain an offline saved configuration. This recovery path deserves fault-injection testing; it is not counted as another confirmed finding here.
- Password/invite flows, certificate pinning, schedule parsing, and CLI routing were reviewed, but this is not a cryptographic proof or an exhaustive audit of the OS credential vault, model runtime, public Network marketplace, or Sandbox Grid desks.

## Hypotheses checked and ruled out

- **“The hub has no TLS handshake timeout.”** False for this Neo Grid hub: TLS has a 10-second deadline and HTTP headers have a 30-second deadline. NG-004 concerns the later JSON body stage. Do not copy the separate Swarm private-hub handshake defect into this report.
- **“CLI `grid run-swarm` is cut off by the normal short request timeout.”** The command uses the automation queue rather than the immediate status path; the initially suspected direct timeout does not establish a bug.
- **“The CLI audit journal necessarily persists raw swarm prompts.”** The inspected journal uses an allowlist of metadata and does not write raw request arguments/results. That claim was not established.
- **“All image input is discarded by every harness strategy.”** The mixture strategy retains original message objects. NG-012 is scoped to the plan strategy's text flattening.
- **“Passing UI tests proves real grid operations work.”** The five browser tests replace the grid API. Their success does not resolve the native lifecycle or authorization findings.

The list records the bugs and limitations supported by this review. It is not a guarantee that no other defects exist; the untested boundaries above remain explicit.

## Sandbox Grid findings

### SG-001 — Restart treats restored desks as deleted before reading the hub's orders

**High · Reproduced boundary + source trace · Startup and data preservation**

- **Location:** `src-tauri/src/deskgrid.rs:54`, `:68`, `:123`, `:200`, `:225`, `:235`; `src-tauri/src/desks.rs:106`, `:244`, `:259`.
- **Trigger/evidence:** restart a computer that has saved Sandbox Grid membership and hosted desks. An extracted probe of the actual partition expression put one restored desk into the deletion list when orders were empty: `restoredDesks=1`, `deletionCandidates=1`.
- **Cause:** current orders exist only in memory and start empty. The first tick calls `reconcile()` before its first hub check-in. Reconciliation interprets every hosted desk absent from that list as explicitly removed, removes its tracking record, and schedules sandbox stop/deletion.
- **Impact:** a normal engine restart can delete desk sandboxes and their data before the hub has confirmed their assignments, including when the hub is temporarily unreachable. The later check-in can still return the original assignments, causing rebuilds or races with deletion. No actual sandbox deletion was performed in the audit; the destructive consequence is traced to the native deletion call.

### SG-002 — A temporary desk failure is converted into a data-deletion order

**High · Reproduced boundary + source trace · Failure recovery**

- **Location:** `src-tauri/src/desks.rs:243`, `:309`, `:318`, `:324`; `grid/src/desks.rs:420`, `:447`.
- **Trigger/evidence:** a real loopback hub received a `failed` report for an existing desk, simulating a temporary sharing failure. It retained the desk record in `failed` state but returned zero orders for that host.
- **Cause:** the native host reports a stopped/error environment or inability to mint a share as a desk failure. `orders_for()` includes only Building/Ready desks. Native reconciliation uses absence from orders as the instruction to delete the sandbox and its data, without distinguishing a failure from an admin removal.
- **Impact:** a temporary missing LAN address, share-capacity failure, or runtime error can escalate into destruction of an existing desk. The core state transition was reproduced; the native deletion branch was inspected rather than executed.
- **Observed result:** `deskStillInHub=true`, `orders=0` after the failure report.

### SG-003 — Reassignment, account removal, and password changes leave issued desk access valid

**High · Reproduced boundary + source trace · Access revocation**

- **Location:** `grid/src/hub.rs:896`, `:908`, `:945`; `grid/src/desks.rs:447`; `src-tauri/src/desks.rs:313`; `src-tauri/src/peer_sharing.rs:43`, `:126`.
- **Trigger/evidence:** person A received a desk invitation, then the admin assigned that desk to B. The real hub returned exactly the same invitation to B and did not request rotation from the host. Removing B left the host order present, with an empty person name and no rotation request.
- **Cause:** person/assignment mutations change ownership metadata but do not invalidate the live invitation or revoke its host share. The host renews by age; it does not associate the share with a person ID or assignment generation. The LAN share authenticates its bearer token independently of the person's hub account/password.
- **Impact:** someone holding the old invitation can retain control of the desk after losing its assignment or account. A password reset also does not end issued bearer access. Standard invitations last 24 hours and are normally rotated with two hours remaining; actual remaining access depends on that renewal and host availability. This is not a claim that removed accounts can perform a fresh password login. The probe verified unchanged capabilities/orders; continued native share access follows the separate bearer authorization path.

### SG-004 — Public salt responses reveal whether a username exists

**Medium · Reproduced · Account enumeration**

- **Location:** `grid/src/hub.rs:1273`, `:1440`; `grid/src/desks.rs:302`.
- **Trigger/evidence:** an unauthenticated loopback client fetched the public grid salt and requested the salts for two synthetic usernames. Comparing each with `decoy_salt(public_grid_salt, username)` correctly identified the existing and nonexistent accounts without guessing passwords.
- **Cause:** the supposedly indistinguishable decoy is derived entirely from public information. Real account salts are random, so equality with the publicly computable decoy distinguishes missing accounts.
- **Impact:** a reachable hub discloses account existence despite its generic login errors. Salt lookups also do not count as failed password attempts. Only the two synthetic names were queried; no real account enumeration was performed.

### SG-005 — Retrying a failed build reuses a permanently cached failure

**Medium · Source-traced · Retry behavior**

- **Location:** `src-tauri/src/desks.rs:214`, `:255`, `:275`; `grid/src/hub.rs:957`.
- **Trigger:** desk creation fails before an entry is added to `inner.hosted`; the admin fixes the cause and retries on the same host.
- **Cause:** the host caches the failure by desk ID and returns it before considering another build. The cleanup that removes a cached failure runs only for dropped **hosted** desks. A build that never became hosted is absent from that cleanup. Hub retry preserves the desk ID; that ID reuse was separately confirmed against the real hub.
- **Impact:** Retry can immediately report the old failure without attempting the corrected operation. Rejoining/restarting or moving to another host may clear or avoid the cache, but ordinary retry does not.

### SG-006 — A public grid tunnel does not make desk access reachable from outside the LAN

**Medium · Source-traced · Remote access contract**

- **Location:** `src-tauri/src/deskgrid.rs:174`; `src-tauri/src/desks.rs:224`, `:399`; `src-tauri/src/peer_sharing.rs:29`, `:119`; `src/pages/desks-page.tsx:188`.
- **Trigger:** host a Sandbox Grid with an internet tunnel, then sign into a desk from a computer without a route to the desk host's private LAN/VPN address.
- **Cause:** the tunnel transports hub traffic only. `mint_share()` always creates a direct LAN share on a private address and random port. Importing that invitation connects directly to the private address; there is no desk data connection through the grid tunnel.
- **Impact:** hub login can work while opening/importing the desk fails, contrary to the page's “open theirs from anywhere” promise. A separately configured VPN can make it work. The audit did not test a live external tunnel; this is the source-established transport mismatch.

### SG-007 — Placement exceeds the host's hard limit of 32 live shares

**Medium · Reproduced boundary + source trace · Capacity planning**

- **Location:** `grid/src/desks.rs:354`, `:390`; `src-tauri/src/peer_sharing.rs:121`, `:123`; `src-tauri/src/desks.rs:224`.
- **Trigger/evidence:** the loopback hub placed 40 resource-fitting desks on a synthetic host and returned all 40 as orders. The native sharing service permits at most 32 live shares per computer, including non-desk shares.
- **Cause:** placement accounts for CPU, RAM, disk, and GPU availability but not the sharing service's admission limit. Each running desk mints a share, even when currently unassigned to a person.
- **Impact:** valid placements can build sandboxes that can never be made accessible on that host. The resulting share failures also encounter SG-002's destructive failure handling. The 40 placements were reproduced; no 40 real sandboxes were provisioned.

### SG-008 — Desk login is a snapshot with no refresh or invitation renewal

**Medium · Source-traced · Client lifecycle**

- **Location:** `src-tauri/src/desks.rs:377`, `:386`, `:428`; `src-tauri/src/peer_sharing.rs:192`.
- **Trigger:** sign in before a desk is ready, have another desk assigned afterward, or keep using a desk while the host rotates its share.
- **Cause:** the login stores the desk list and imported credentials once. `desk_status()` returns the saved object; no polling/login refresh updates assignments or imports replacement invitations. Generic shared-environment refresh can report a failed old invitation but cannot discover the new one.
- **Impact:** readiness and desk lists remain stale, and normal invitation rotation interrupts existing access until the person signs in again. This is separate from SG-003: rotation does eventually revoke the old share, but clients do not follow it automatically.

### SG-009 — Switching desk accounts leaves the previous account's imported environments behind

**Medium · Source-traced · Local session cleanup**

- **Location:** `src-tauri/src/desks.rs:392`, `:394`, `:428`, `:439`.
- **Trigger:** sign in as A, then sign in as B without first signing A out; finally sign out of B.
- **Cause:** the second login imports/reuses B's desks and replaces `inner.login`. It removes older entries only when replacing the same desk with a different address. It does not remove A's desks that are absent from B's response. Logout subsequently knows only B's current desk list.
- **Impact:** A's shared nodes and saved invitation credentials can remain after the UI says B is signed out. Remote grants were originally authorized; the defect is incomplete local account switching/logout, not a fresh bypass of the server password check.

### SG-010 — Real hosts always report that they are not on battery

**Medium · Source-traced · Power policy**

- **Location:** `src-tauri/src/desks.rs:131`, `:154`; `grid/src/desks.rs:344`.
- **Trigger:** contribute a laptop running on battery.
- **Cause:** the scheduler correctly rejects `on_battery=true`, but the actual desktop capacity adapter hardcodes `on_battery: false` instead of obtaining power state.
- **Impact:** the documented battery exclusion works in synthetic scheduler tests but not through this native reporting path. A laptop can receive new desk workloads while on battery.

### SG-011 — Disk placement double-counts space already consumed by existing desks

**Medium · Reproduced · Resource accounting**

- **Location:** `grid/src/desks.rs:238`, `:354`.
- **Trigger/evidence:** the actual placement helper was given a 100 GB configured disk share, a hosted 20 GB desk, 80 GB currently free, and a new 70 GB desk. It refused placement although total promised desk space would be 90 GB and the new desk fits the 80 GB free.
- **Cause:** the total configured share is first capped to current free space, and then all existing desk allocations are subtracted again. Current free space already excludes the bytes those desks have physically consumed.
- **Impact:** desks can wait indefinitely despite sufficient share and free disk. The suggested share also shrinks with reported free space, making the same accounting increasingly conservative as data accumulates. The probe used the real helper with explicit capacities, not physical disk allocation.

### SG-012 — A full VM desk defaults to a microVM-only image identifier

**Medium · Reproduced boundary + source trace · VM creation**

- **Location:** `grid/src/desks.rs:46`; `src-tauri/src/desks.rs:165`; `src-tauri/src/commands.rs:1325`; `src-tauri/src/runtime/vm.rs:453`.
- **Trigger/evidence:** `DeskSpec::checked(DeskKind::Vm, ..., "")` returned `builtin:alpine` in the actual library probe.
- **Cause:** full VMs and microVMs share that default, but full VM provisioning treats the source as a filesystem path and requires an existing bootable ISO or virtual disk. Only the microVM provisioner handles `builtin:alpine` specially.
- **Impact:** the default full VM desk order is accepted by the hub and fails when a host tries to build it. No VM was launched to demonstrate this validation mismatch.

### SG-013 — VM image paths containing spaces are rejected as invalid image references

**Medium · Reproduced · VM input validation**

- **Location:** `grid/src/desks.rs:78`.
- **Trigger/evidence:** the actual validator rejected `C:/Synthetic Images/test.iso` for a VM desk.
- **Cause:** one image validator rejects all whitespace for both OCI references and boot-media filesystem paths.
- **Impact:** ordinary quoted Windows/Linux paths containing spaces cannot be submitted, even though VM provisioning accepts a path string. This is independent of whether the selected media exists on the eventual host; distributing custom media across hosts is an additional unverified workflow.

### SG-014 — Fractional disk sizes pass desk validation but fail native creation

**Medium · Reproduced boundary + source trace · Resource validation**

- **Location:** `grid/src/desks.rs:75`; `src-tauri/src/desks.rs:173`; `src-tauri/src/commands.rs:1216`; `src-tauri/src/runtime/storage.rs:42`.
- **Trigger/evidence:** the actual desk validator accepted `disk_gb=1.5`; an extracted copy of the actual native `storage_bytes()` function rejected it.
- **Cause:** the hub checks a numeric range but not integrality, while native storage requires a whole number of GB.
- **Impact:** CLI/API orders can be saved and placed even though every host will reject creation. The desktop's integer step avoids common submissions but does not make the accepted API contract valid.

### SG-015 — Valid international desk names exceed the native environment name limit

**Medium · Reproduced boundary + source trace · Naming**

- **Location:** `grid/src/desks.rs:293`; `src-tauri/src/desks.rs:174`; `src-tauri/src/commands.rs:1204`.
- **Trigger/evidence:** the actual desk-name validator accepted 30 CJK characters. After the native ` — desk` suffix, the environment name measured 99 UTF-8 bytes, above the native 80-byte limit.
- **Cause:** the hub limits printable characters; native creation limits bytes, with an additional generated suffix.
- **Impact:** accepted desk names can consistently fail on the worker. This is a creation failure, distinct from NG-025's invite-preview display corruption.

### SG-016 — “Add person and desk” can fail after permanently creating the person

**Medium · Reproduced boundary + source trace · Multi-step creation**

- **Location:** `src-tauri/src/desks.rs:472`; `grid/src/hub.rs:877`, `:923`.
- **Trigger/evidence:** the probe executed the same two real hub operations used by native `person_add()`. A 64-character display name created the person, then the generated `name's desk` failed the 64-character desk-name check. The person remained saved.
- **Cause:** the first operation commits before the second is validated/executed, with no rollback or partial-success result. Desk capacity limits can trigger the same partial outcome.
- **Impact:** the UI receives an error for the combined operation, but retrying it fails because the username already exists. The resulting person has no desk. This probe exercised the hub composition, not Tauri UI invocation.

### SG-017 — A desk whose sandbox was created but failed to start loses its sandbox tracking

**Medium · Source-traced · Build cleanup**

- **Location:** `src-tauri/src/desks.rs:193`, `:199`, `:201`, `:208`.
- **Trigger:** sandbox creation succeeds, but the subsequent start call fails, for example because of temporary resource admission or runtime startup failure.
- **Cause:** the environment ID is only placed into `inner.hosted` if the entire creation-plus-start operation succeeds. On start failure it stores only an error by desk ID and neither records the created environment nor rolls it back.
- **Impact:** an existing sandbox can be left outside desk tracking. Retry then encounters the cached failure or a duplicate environment name, and removing the desk cannot find that untracked environment for cleanup.

### SG-018 — Failed desk deletion is forgotten instead of retried

**Medium · Source-traced · Cleanup durability**

- **Location:** `src-tauri/src/desks.rs:244`, `:249`, `:259`.
- **Trigger:** the hub removes a hosted desk, but stopping or deleting its sandbox fails, for example because another lifecycle operation holds its lock.
- **Cause:** the host first removes and persists the desk's tracking entry, then starts an untracked asynchronous deletion. Failure is recorded in the audit log only; no retained cleanup item schedules another attempt.
- **Impact:** removed desks can leave running/stopped sandboxes and disk allocations behind. Later empty order lists cannot retry them because they are no longer in `inner.hosted`.

### SG-019 — Leaving during desk creation can strand an undeletable Provisioning node

**Medium · Source-traced · Cancellation**

- **Location:** `src-tauri/src/desks.rs:199`, `:345`, `:352`; `src-tauri/src/commands/vm_creation.rs:6`; `src-tauri/src/commands.rs:1785`.
- **Trigger:** leave the Sandbox Grid after creation has persisted the sandbox's Provisioning node but before provisioning completes.
- **Cause:** `stop_hosting()` aborts the build task. Creation records the pending node before awaiting runtime work, and task abortion skips its finalization. There is no cancellation cleanup in the desk task.
- **Impact:** the current process can retain a Provisioning node that cannot be started or deleted through ordinary lifecycle commands. Restart recovery changes interrupted creation into Error, after which cleanup is possible. Runtime provisioning may also leave partial resources; that part was not measured.

### SG-020 — Hosted-desk persistence failures silently orphan ownership records

**Medium · Source-traced · Persistence**

- **Location:** `src-tauri/src/desks.rs:106`, `:121`, `:211`.
- **Trigger:** a desk builds successfully but its `desks.json` update fails, or that tracking file is unreadable/malformed at the next startup.
- **Cause:** `persist_hosted()` discards write/removal failures, and loading substitutes an empty list on read/parse failure. It does not reconstruct ownership from the sandbox's desk tag or surface an error.
- **Impact:** the hub may consider a desk ready while the restarted host has forgotten the existing sandbox. Attempts to create it again can fail on its existing name, leaving data stranded in an untracked sandbox. This finding does not claim that the persistence failure itself deletes those files.

### SG-021 — One unreachable desk can block a person's entire login

**Medium · Source-traced · Multi-desk availability**

- **Location:** `grid/src/hub.rs:1484`, `:1493`; `src-tauri/src/desks.rs:394`, `:413`, `:429`.
- **Trigger:** a person has several desks; the first one requiring import has a still-valid invitation but its host is offline, while another desk is reachable.
- **Cause:** the hub includes invitations for Ready desks without requiring their hosts to be online. Native login imports desks sequentially and propagates any import error before saving the login or processing later desks.
- **Impact:** one unavailable host prevents opening independent available desks through that login. Imports completed before a later failure can also remain as local nodes even though the overall login returned an error. A per-desk degraded result is not returned.

## Sandbox findings

### SB-001 — Saving a file overwrites and deletes a pre-existing sibling staging file

**High · Reproduced · Sandbox file editor**

- **Location:** `src/api/guest-files-api.ts:59`, `:64`, `:69`.
- **Trigger/evidence:** a disposable directory contained `project.txt` and an independent `project.txt.yougori-save`. Calling the actual transpiled `guestFilesApi.write()` replaced the project and removed the independent sibling file.
- **Cause:** every save uses the deterministic sibling name, unconditionally truncates it, and deletes it after decoding. There is no exclusive creation, unique name, or ownership check. Separate editor windows also share that staging path.
- **Impact:** a normal save can destroy unrelated data with the reserved-looking suffix; overlapping saves can corrupt each other's staging. The test executed generated commands using Git Bash solely inside a new temporary fixture directory. It did not access a real guest or user document. This is a guest data-safety defect, not a host escape.

### SB-002 — A failed final decode truncates the original file despite reporting a save error

**High · Reproduced · Sandbox file editor atomicity**

- **Location:** `src/api/guest-files-api.ts:69`.
- **Trigger/evidence:** after the real save helper staged data, the disposable test replaced that staging content with invalid base64 before the final command. The save rejected, but the original file had already been truncated to zero bytes.
- **Cause:** `base64 -d < temporary > original` opens/truncates the original before decoding succeeds. This is not an atomic replacement. A damaged staging file, overlapping save, decoder failure, or interrupted write can therefore damage the original.
- **Impact:** the UI correctly reports failure, but the previous file contents are not preserved. The exact zero-byte outcome was reproduced with fault-injected staging corruption; disk-full and process-interruption variants were source-traced, not separately tested.

### SB-003 — Non-UTF-8 text is silently changed when opened and saved

**Medium · Reproduced · File encoding**

- **Location:** `src/api/guest-files-api.ts:22`, `:27`, `:59`.
- **Trigger/evidence:** the real module opened a temporary file containing bytes `63 61 66 E9`, inserted a replacement character without an error, and saved that character as UTF-8 after a small edit.
- **Cause:** decoding uses UTF-8 with `fatal:false`; only NUL bytes trigger the binary-file guard. Invalid sequences are silently replaced and the editor does not retain original encoding/bytes.
- **Impact:** editing legacy-encoded files can irreversibly replace characters without warning. The separate remote-file editor uses strict UTF-8 decoding; this finding concerns the ordinary sandbox editor.

### SB-004 — A stale editor buffer silently overwrites external changes

**Medium · Reproduced · Concurrent file editing**

- **Location:** `src/components/guest-files.tsx:38`, `:59`; `src/api/guest-files-api.ts:59`.
- **Trigger/evidence:** the test opened a temporary file through the real API, changed it externally, then saved an edit based on the old text. The external update was replaced successfully without conflict detection.
- **Cause:** the UI remembers the original text only for dirty-state display. Save passes only the new contents; neither the API nor its guest commands compare current contents, modification time, or a revision token before writing.
- **Impact:** edits from an agent, terminal, another window, or another collaborator can be lost even when saves do not overlap. This is distinct from SB-001's shared staging-file collision.

### SB-005 — A rejected sandbox deletion can still cancel its jobs and transfers

**Medium · Source-traced · Lifecycle side effects**

- **Location:** `src-tauri/src/commands.rs:1757`, `:1764`, `:1775`, `:1785`.
- **Trigger:** request deletion while another lifecycle/network operation holds the environment lock, or while another later deletion precondition will reject the request.
- **Cause:** deletion cancels file transfers and registered guest executions before acquiring the lifecycle lock or validating those later preconditions.
- **Impact:** the environment remains after deletion returns an error, but its work may already be interrupted. The power-state command explicitly validates before comparable cancellation; deletion does not maintain that behavior. No real running workload was cancelled during the audit.

### SB-006 — Oversized LAN-share results return an error body with HTTP success

**Medium · Reproduced · Sharing protocol**

- **Location:** `src-tauri/src/peer_sharing.rs:35`, `:53`, `:55`.
- **Trigger/evidence:** a local probe ran the extracted actual TLS share server and HTTP reader with a synthetic handler returning more than 8 MiB. It received HTTP 200 with `{"error":"Result exceeds 8 MiB"}`.
- **Cause:** the server chooses status from the successful handler result, then substitutes a size-error body without changing that status. The client treats a successful HTTP status as a successful result.
- **Impact:** callers may receive an apparent success containing the wrong response shape instead of the operation's size error. The probe exercised the actual transport helpers with a fake operation, not a live sandbox command.

### SB-007 — Steady requests prevent expired share listeners from cleaning up

**Medium · Reproduced · Share expiry and capacity**

- **Location:** `src-tauri/src/peer_sharing.rs:46`, `:60`, `:123`, `:130`.
- **Trigger/evidence:** an extracted actual share server expired after one second while a loopback client kept sending requests. It was still running 32 seconds after expiry, beyond the cleanup interval. The 191 post-expiry requests were correctly rejected.
- **Cause:** the 30-second sleep is created anew on every `select!` iteration. Accepting a request or collecting a finished client cancels and restarts that sleep.
- **Impact:** an expired listener can continue occupying its live share slot indefinitely while traffic keeps arriving; expiry cleanup of its owned terminal sessions is delayed too. This does **not** bypass the per-request expiry check. The test demonstrated one retained listener, not exhaustion of all 32 share slots.

### SB-008 — Unreachable shared sandboxes delay status refresh for every later sandbox

**Medium · Source-traced · Status availability**

- **Location:** `src-tauri/src/peer_sharing.rs:36`, `:192`.
- **Trigger:** several imported shared environments are unreachable and appear before a healthy one in the refresh list.
- **Cause:** the background refresher awaits each inspect request sequentially, each with an approximately eight-second request timeout, then waits another ten seconds before starting the next round. There is no per-environment schedule or bounded concurrent batch.
- **Impact:** 32 unreachable predecessors can delay the next healthy status update by roughly 256 seconds plus the polling pause and connection overhead. Even a small number of dead shares makes power/error status noticeably stale. This delay is source-derived, not a multi-minute load benchmark.

### SB-009 — An interrupted remote upload cannot be retried under the same filename in the UI

**Medium · Source-traced · File transfer recovery**

- **Location:** `src/components/remote-workspace.tsx:81`, `:84`, `:88`; `src-tauri/src/remote_access/files.rs:186`.
- **Trigger:** upload a file to a shared sandbox/folder, then lose connectivity or close the view after the destination has been created but before all chunks are written.
- **Cause:** the UI creates the final filename first and deliberately retains uploaded chunks on cancellation. Every retry again requests exclusive creation of that filename; it has no resume/overwrite decision. The remote file view offers no remove/rename action to clear that partial destination.
- **Impact:** retrying the same upload fails because the file already exists. Recovery requires an owner/terminal/CLI operation or a different filename. The original local upload file remains intact; the issue concerns the incomplete remote destination and UI recovery.

## Shared findings that also affect Sandbox Grid

These extend the applicability of existing findings and are not additional entries in the total:

| Existing finding | Additional affected path |
| --- | --- |
| NG-004, incomplete unauthenticated body retention | Sandbox Grid uses the same hub JSON-body reader, including person salt/login routes. |
| NG-009, lost dirty marker after failed persistence | Sandbox Grid hub records and heartbeat mutations use the same `Hub::flush()` and sweep. |
| NG-013, failed restore latched for the process | `src-tauri/src/deskgrid.rs:123` similarly sets `loaded` before starting its saved hub. |
| NG-021, Linux activity-detail failure treated as nobody present | Desk capacity uses the same activity provider; this affects shares configured as idle-only. |
| NG-023, error converted into fulfilled promise then form cleared | `src/pages/desks-page.tsx:167` and `src/components/grid-desks.tsx:46` repeat the failed-operation/reset pattern. |
| NG-024, stale overlapping status responses | Sandbox Grid uses the same `usePolled()` hook in `workspace-actions.tsx`. |
| NG-025, non-UTF-8 invite preview decoding | `src/api/desks-api.ts:162` repeats the direct `JSON.parse(atob(...))` decoding for desk invites. |

## Additional checks and coverage

| Check | Result | Limit |
| --- | --- | --- |
| `cargo test --locked --manifest-path grid/Cargo.toml --lib desks` | 8 passed | Includes the real local hub/person/desk flow; does not run native sandbox provisioning. |
| Focused Vitest sandbox UI checks | Initially 18 passed in 4 files; expanded run 24 passed in 5 files | Counts overlap, so do not add them. Expanded run covered guest file API, remote workspace, creation dialog, guest workspace, and environment list. |
| `npx playwright test e2e/desks.spec.ts` | 3 passed | Host/share/person, member join, and desk login/logout use mocked engine APIs. A nonfatal startup 404 was printed; all three tests completed. |
| `cargo check --locked --manifest-path src-tauri/Cargo.toml --lib` | Passed, with the existing unused-assignment warning in Swarm practice | Confirms the non-test native library compiles. The previously established all-target/test compile blocker SW-001 remains outside these successful checks. |
| `cargo test --locked --manifest-path cli/Cargo.toml desks` | Command succeeded, **0 matching tests** | Not evidence of desk CLI behavior coverage. |
| Disposable grid probes | Assertions passed | Real hub mutation/auth/placement calls; source helper probes for validation and startup partitioning. |
| Extracted LAN-share transport probes | 2 passed | Actual server/TLS/HTTP-reader code with synthetic operations; no Tauri runtime or real sandbox. |
| Sandbox editor shell probes | 4 passed | Actual transpiled file API, generated commands executed by Git Bash in a newly created temporary directory. |

The expanded Vitest command was:

```text
npx vitest run src/api/guest-files-api.test.ts src/components/remote-workspace.test.tsx src/components/dialogs/create-environment-dialog.test.tsx src/components/guest-workspace.test.tsx src/components/environment-list.test.tsx
```

Temporary probe sources and results are in `C:\Users\Argon\AppData\Local\Temp\yougori-sandbox-audit-e7wo_001`: `probe.rs`, `probe_more.rs`, `sharing_probe.rs`, and their JSONL results. The file-editor fixture files remain under that temporary audit directory. No regression tests or application changes were committed or added to the checkout.

### What this extension reviewed

- Sandbox creation/provisioning records, resource validation/admission, start/stop/delete sequencing, relevant storage and recovery paths, file editing/import interfaces, and LAN/remote sharing.
- Sandbox Grid membership restoration, host check-ins, resource shares, placement, desk orders, build/error/retry/delete behavior, persistence, person authentication, reassignment, invitation generation, client login/logout, and UI call chains.
- Existing safety controls relevant to these paths, including duplicate-name checks, pinned share TLS, share capability checks, bounded HTTP framing, resource reservations, managed-path validation, and lifecycle locks. Their presence does not establish complete isolation correctness.

### Remaining limitations and rejected hypotheses

- No real user sandbox, GPU container, VM, microVM, account, share, or saved credential was altered. Full restart/deletion/data-loss scenarios were established through source and disposable helper/hub probes rather than run on real workloads.
- No kernel/hypervisor escape, arbitrary host compromise, or cross-sandbox escape was established. This is not an independent audit of QEMU, WSL, OCI runtimes, operating systems, bundled binaries, or every guest-agent endpoint. Native AppContainer/Computer Branch creation is currently rejected by the normal create command and was not exercised as an active product path.
- Real LAN partitions, a remote desk across the public tunnel, OS-vault failures, power-state detection on hardware, and end-to-end long-running invitation renewal still need integration coverage.
- The suspected duplicate-name creation race was ruled out at the persistence boundary: `create_on_graph()` checks the name again inside `store.mutate()` before provisioning starts.
- The LAN share expiry problem does not allow authorized operations after expiry: the local probe confirmed rejection of those requests. The retained listener/cleanup issue is what SB-007 reports.
- Full VM maximum-memory startup and shared host resource admission use different quantities in some paths. This deserves a targeted multi-VM admission test; no separate defect is counted without establishing the actual physical/allocation outcome.
- Missing persisted desk metadata, concurrent leave/check-in, and custom VM media distribution have further combinations that were not fully reproduced. Findings above state the specific supported failure rather than treating all combinations as confirmed.

A SHA-256 comparison against the extension's 1,716-file starting snapshot found only this Markdown audit changed, with no missing or new non-ignored checkout files. Build/cache/test output directories were excluded. No application fixes were made.
