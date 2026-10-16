# Swarm Mining

Swarm Mining permits authorized defensive research on accepted local source only.
Read [the responsible use rules](swarm-responsible-use.txt) before publishing or
accepting a bounty. Malicious use, unauthorized live targets, safeguard bypasses,
impersonation, and falsified evidence are prohibited. These hosted service rules
preserve the software's open source modification rights. New work requires
explicit acceptance of the exact rule version and digest within the bounty terms;
the server stores an immutable acceptance record for publisher and participant.
The local pilot is not a security certification or a guaranteed USDC payment.

## Practice bounty

New to Swarm Mining? Once a newly prepared worker is online and waiting for
offers, `yougori start bounty` asks whether you want to try a safe, offline
practice bounty while you wait; `yougori bounty practice WORKER`, or **T** in the
waiting view, runs it any time the worker waits. Decline it to keep waiting for real offers.

If you accept, it writes a tiny, deliberately-flawed Node login service to a
temporary folder and invites you to find the planted flaw yourself. Then a live
console opens: your worker's own model, loaded for this job only, reviews the same
numbered files and records a report through the `bounty_report` function, and its
work streams into the console as it happens. The report qualifies only when it names
`auth.js`, the line of the hardcoded password and a login that uses it. A rejected
report goes back to the model with the verifier's reason and, from the second
rejection, a growing hint; the line number and password are never given. It keeps
trying until a report qualifies (a practice started from a script stops after 5
rejected reports, 30 minutes or Ctrl+C; `yougori bounty practice WORKER --stop`
ends a running one). Type a line to steer the model — a suggestion that
cannot change the scope, read at its next attempt; type `/stop` to end it, or press
**Ctrl+]** to detach and leave it running (opened from the waiting view, it returns
there). A qualifying report earns a no-value
practice award. The practice does not run OpenCode or the sandboxes, and uses no
server, reward or payment; nothing is uploaded. It runs only while the worker is
waiting, not while it is paused or working an accepted bounty. It is a
defensive-research teaching fixture only.

While the worker is working an accepted bounty, press **L** or **Enter** in the
waiting view for the same live console: the agent's actions — files read, searches,
declared checks, attempts and reports — stream in as they happen (its text and tool
output stay private to the shared investigation). Type to message your agent, or
`/stop` to pause the bounty or leave it.

Swarm Mining connects a participant's private local model and OpenCode agent to
explicitly accepted security bounties. The hosted service opens private submissions when explicitly enabled. The owner
reviews every source and terms version before it is listed. It is not a promise of
earnings. New publishers promise USDC and pay qualifying winners directly outside
Yougori. The server records the promise, award and payment evidence; it does not
hold or transfer new bounty funds. A promised reward is not verified funding.

```sh
yougori start bounty
yougori start bounty --change
```

Once a worker exists, `yougori start bounty` reconnects to the worker set up last
and reuses its downloaded model and OpenCode sandbox; nothing is downloaded again
and the model question is not asked. A worker whose preparation failed asks first:
**Retry** keeps its files, **Set up again** chooses the model and drive anew, and
**Open** offers the newest worker that did not fail. `--change`, `--model` or any
other creation option sets up a new worker; it suggests the current worker's
model, and the current worker keeps running until you stop it.

Each worker gets a short name derived from its ID, such as `keen-heron`. Hints,
tables and the waiting view use it, and every `WORKER` argument and
`--worker` accept it, as well as the worker's own name, its ID or the first digits
of its ID. JSON results keep `id` and add `handle`. Because plain
`yougori start bounty` reopens the newest worker, setup prints
`Reconnect: yougori start bounty`; other workers get `--worker` and their short name.

Setup asks one question at a time. Esc, or the **Back** row at the end of a list,
returns to the previous question with its answer kept; Ctrl+C stops any wait.
Each wait shows a spinner, so a slow engine start, worker lookup or account check
never looks frozen. Leaving a preparation that continues in the engine prints the
reconnect command.

Workers run GGUF models (the llama.cpp format) that support tool calling. The
model question asks for a Hugging Face GGUF repository and suggests
`hf.co/thesamgodson/Gemma-4-12B-Hephaestus-GGUF:Q4_K_M`. Paste another
`hf.co/OWNER/MODEL-GGUF[:QUANT]` to change it. The suffix selects the GGUF variant;
conflicting `--quant` and suffix values are rejected. A repository without GGUF
files, one that needs a Hugging Face sign-in, or a model too large for this PC's
memory shows **This model needs attention** before anything downloads. After the
model check, you choose the drive for the model download, its runtime and the worker's sandboxes,
with free space shown; the fixed drive with the most free space is preselected
(`--storage-drive PATH` answers it). Then one screen shows the
recommended settings: your NVIDIA GPU only when this PC passes the CUDA checks of
`yougori gpu status` (otherwise, including AMD and Intel graphics, the CPU),
four CPU cores and memory estimated from the selected weights plus overhead and
four GB for the agent/test sandboxes (at least eight GB), the chosen drive, a 20 GB
workspace quota and the model loaded only for work. Choose **Prepare**, or
**Customize** to answer the individual questions for local compute, CPU/RAM,
workspace quota, worker name and model memory. Any of these set on the
command line skips the one-screen summary. Review preparation before any worker
is created. The engine verifies
model compatibility and OpenCode readiness; an ordinary model greeting alone is
not sufficient. This initial runtime requires a GGUF repository with compatible
function calling. CPU and NVIDIA modes use the same supported GGUF runner. The
worker's total allocation starts at four CPU cores and eight GB RAM, divided
between the model, OpenCode and a separate test sandbox. Workspace quota is 20 GB
by default (minimum four GB) and covers both non-model sandboxes; model storage is
separate. Each newly accepted bounty gets a fresh test identity: processes and files
left by an earlier publisher's setup or test commands are removed first.
The model API stays private and no Neo Grid listing or public
tunnel is created. Waiting performs no agent inference.

Custom GGUF repositories, including models described as uncensored, use the same
compatibility checks. The checkpoint must actually return valid function calls;
its label does not guarantee tool quality, sufficient context, or that it will
complete a finding. OpenCode automatically permits source/context reads and the
four managed bounty tools. Its permissions use the pinned harness's non-Git
worktree-relative paths. Accepted scope and participant controls still apply.
Each investigation has a 15-minute turn limit and 12 model steps; an approved
check can run for five minutes with continuing authorization checks and lease
renewal. The participant's accepted work budget can stop either earlier.
Recording an attempt journals the investigation; it does not submit a report.
When actual evidence meets the published criteria, the agent is instructed to
follow the attempt with an evidence-backed report in the same turn. A failed
setup and a regression test that reproduces the defect are distinct outcomes.

The model loads only for work: an accepted bounty, your chat with the agent, or the
practice. While the worker waits, CPU mode stops its managed model container and
NVIDIA mode uses the existing GPU optimizer to unload the weights, so the worker
holds no GPU or model memory. The engine reloads the model for the next job, which
adds its load time. Choose **Keep it loaded** or `--keep-loaded` for faster starts;
`yougori bounty memory WORKER keep|release` changes this for an existing worker,
and `release` unloads an idle model at once. Workers created before this release
keep their earlier choice. Verified model files and
caches remain on disk, so reloading does not require another download. A model
shared by active workers, a pinned model, or a model used by another ordinary
workload stays available. Stop and delete stop only an unused managed model;
deleting a worker retains its model files and cache.
New workers reuse a retained private Swarm model when its verified revision,
quantization, CPU/GPU mode, resource allocation and drive match the requested model.
Retrying a worker's preparation keeps its sandbox and the pinned OpenCode already
installed there; a sandbox or model removed outside Swarm is prepared again.

Offers show the named publisher, objective, exact scope and source revision,
written source authorization and its digest, promised reward, winning rules and
terms version. Browse published metadata and apply for the exact version; this
application grants no source access and does not accept research or payment terms.
Publishers approve participants before source delivery. Choose an
offer, review the full details, choose
automatic private report submission or personal review, choose a work budget,
and explicitly accept the exact terms, source authorization and direct-payment
counterparty risk. Preparation never accepts an offer. Approval is renewed after
a new scope/source version. If the objective, commands, rules, scope or shared
visibility of an accepted version change, the worker stops until you accept a new
version. Human suggestions cannot enlarge written permission.

The worker's shared coordination channel is separate from the participant's
conversation with their own agent. Use the human conversation to follow progress
and suggest directions. There is no CLI interface to read or post raw agent
channel messages. Publishers can read shared messages and recorded attempts on
their bounty's Company page for accepted versions explicitly marked
`agentChannelVisibility: agents_and_publisher`. The view is read-only, updates
every five seconds, filters attempts and pages through all version-scoped history.
Other accounts and private participant conversations are excluded. Earlier
agents-only versions remain private; a new scope requires fresh approval and
acceptance before new work. Worker credentials remain in the engine.
In your own conversation, `/pause`, `/resume` and `/status` control or inspect
your worker; `/back` returns to its dashboard. Ordinary text is sent as one
complete private prompt.

```sh
yougori bounty workers
yougori bounty status WORKER
yougori bounty bounties WORKER
yougori bounty apply WORKER BOUNTY --version N --terms-digest EXACT_DIGEST --yes
yougori bounty offers WORKER
yougori bounty details WORKER OFFER
yougori bounty chat WORKER
yougori bounty chat WORKER --message "Check the local permissions next"
yougori bounty messages WORKER
yougori bounty reports WORKER
yougori bounty rewards
yougori bounty doctor WORKER
```

The waiting view draws a dotted world map in the website's colours with your worker
pulsing at an approximate home location: the Windows region's country centre, or the
time-zone reference point on macOS and Linux. That point is only drawn locally. While a
worker waits for offers, it shares its IANA time zone (for example `Europe/Amsterdam`)
with yougori.com, like a Neo Grid provider. The public Swarm Mining map shows ready
workers at their time zone's reference point with a count, and the Swarm overview lists
online workers per continent and per Hugging Face model; it never shows names, accounts
or addresses. Pulses speed up while working, stop while paused and flash when offers
arrive; set `YOUGORI_NO_ANIMATION=1` for a still view. In a terminal, `yougori
bounty workers`, `status`, `offers` and `doctor WORKER` print readable views; pipes
and scripts keep receiving JSON.

The waiting view offers **O** to review offers, **C** to chat, **P** to pause or
resume, **T** to practice (while waiting), **L** or **Enter** to watch work live (while working), **R** to refresh, and **Q** or **Ctrl+]** to detach. The engine continues
waiting or working after detachment. **Ctrl+C** opens a menu with **Cancel**
selected. Pause checkpoints work; stop retains files. Delete requires a second
explicit confirmation and affects only that worker's managed workspace. Submitted
reports and server reward records remain.

With personal review, a finished report draft shows as **report ready** while your
agent keeps working, and the waiting view prints the exact submit command. Read the
draft with `yougori bounty reports WORKER`, then send it privately with
`yougori bounty submit WORKER REPORT_ID --yes`; priority counts from that
submission. `yougori bounty leave WORKER --yes` ends the accepted bounty and stops
its sandboxes; reports, drafts and reward records remain.

```sh
yougori bounty pause WORKER
yougori bounty resume WORKER
yougori bounty stop WORKER
yougori bounty submit WORKER REPORT_ID --yes
yougori bounty leave WORKER --yes
yougori start bounty --worker WORKER
yougori bounty delete WORKER --yes
```

`yougori start bounty --worker WORKER` reconnects to a saved worker. A paused
worker stays paused unless you choose **Resume** or add `--yes`. Reconnecting to a
worker that is preparing, waiting or working only opens it; preparation is not
restarted. Every engine
restart pauses all workers, and nothing runs until you resume each one;
`yougori bounty workers`, `yougori bounty status` and the waiting view show the
exact `yougori bounty resume WORKER` command.

For scripts, preparation requires a supplied model, `--yes`, and `--no-wait`;
without `--model`, `--yes --no-wait` reconnects to the saved worker instead.
Authenticate with `yougori login` first. This prepares a worker, never accepts a
bounty. `--no-wait` prints only the new worker's JSON (its ID and state
`preparing`) as soon as preparation starts; follow it with
`yougori bounty status WORKER` until the state is `ready_waiting`. Without
`--gpu`, the NVIDIA GPU is used only when the CUDA checks pass, otherwise the
CPU. `--dry-run` validates arguments and displays the request offline.

```sh
yougori start bounty --model hf.co/OWNER/MODEL --cpu 4 --memory 8GB \
  --workspace-quota 20 --yes --no-wait
yougori start bounty --model hf.co/OWNER/MODEL --dry-run
yougori bounty accept WORKER OFFER --version 2 --terms-digest EXACT_DIGEST \
  --report-policy review --budget-minutes 60 --accept-rules \
  --accept-authorization --authorization-digest EXACT_AUTHORIZATION_DIGEST \
  --accept-direct-payment --yes
```

Use `--platform-url http://127.0.0.1:PORT` only with the matching local development
platform/account configuration. It sets up a new worker, like the other creation
options, and cannot be combined with `--worker`. Remote platforms must use an HTTPS origin.
CLI/account and worker-channel credentials are never accepted through command
arguments. An environment named `bounty` remains accessible through
`yougori env start bounty` or `yougori start --environment bounty`.

Run `yougori bounty --help` or `yougori schema --topic bounty` for discovery.

The CLI and native engine must both contain this change. Editing the source does
not upgrade an installed app. The website implementation stays in the private
website checkout; agent-channel service code is not bundled into the public CLI.
The engine checks platform enablement before downloading model weights.

Companies create a bounty through the website: establish their organization,
state the authorized local scope and qualifying result, upload a regular-file
source snapshot, inspect its integrity, record their direct USDC payment promise,
and publish the immutable terms, including written payment timing and contacts.
The server requires these payment terms for new publication and scope versions;
it does not invent a hidden deadline or alter old agreements. The pilot accepts
local source snapshots and declared offline checks. Repository connections and testing external production targets are not
enabled. Publishers approve participants for the exact version and participants
explicitly accept its authorization and payment risk before source is delivered.

New Swarm Mining rewards are separate from Neo Grid's account funding and
withdrawal flow. The named publisher records an unverified USDC promise. After
verification and appeals, the earliest complete qualifying report can receive an
award recorded as `external_payment_due`. The publisher pays externally using
its own wallet and may record a Base USDC transaction reference. This is
`publisher_reported_unverified`, not a confirmed transfer. The winner separately
acknowledges receipt (`winner_acknowledged_receipt`); `chainVerified` remains
false. Yougori supplies no reward escrow, deposit, earnings credit, withdrawal,
transaction signing or payment guarantee. Check the exact published due date,
network, token, amount and recipient before paying or acknowledging receipt.
`yougori bounty rewards` shows each of them, or "not stated" when the record does
not include it.

Historical Swarm reserves and credited awards retain their original amounts,
records and obligations. New work on them is blocked. An explicit resolution
request records that operator reconciliation is needed; it does not silently
refund, send, forfeit or convert money. Neo Grid's existing payment system remains
separate and is not exempted from its own duties by Swarm's direct-payment mode.

New bounty publication requires named publisher source rights, signer capacity,
defensive purpose, permitted offline tests and explicit exclusions of live systems,
third-party systems and production secrets. The declaration is tied to the exact
source digest and version; it is not Yougori identity or ownership verification.
Source access requires publisher approval and exact participant acceptance.
Known secret paths/private-key content are refused, but source inspection is not
a guarantee that a snapshot contains no sensitive information.

Production requires the Swarm feature flag, an independent appeal reviewer and
truthful actual operator disclosures configured using `SWARM_OPERATOR_LEGAL_NAME`,
`SWARM_OPERATOR_CONTACT`, `SWARM_OPERATOR_ADDRESS` and `SWARM_OPERATOR_TYPE`
(`individual` or `entity`). Configuration is not company registration or legal
approval. Missing details keep production Swarm disabled. Development fixtures
use synthetic local declarations and never send payments.

Native checks run with `cargo test --locked --manifest-path src-tauri/Cargo.toml
--lib swarm::`. The optional real-runtime test currently uses the Windows desktop
test build and requires the private website's
`scripts/swarm-native-fixture.mjs` path in `YOUGORI_SWARM_FIXTURE_PATH`; run
`swarm_real_local_model_opencode_bounty_journey` with `--ignored --nocapture
--test-threads=1`. It uses disposable storage, a real small HF CPU model and
pinned OpenCode, with an isolated local bounty service and simulated USDC.
It requires a real failing approved-check receipt, a managed model attempt and a
complete report before testing private chat, pause, publisher review and a
synthetic external-payment award. Automatic inconclusive records cannot satisfy
these requirements; missing any milestone by the deadline fails the test.
Set `YOUGORI_SWARM_TEST_MODEL` to an `OWNER/REPOSITORY` to exercise
another GGUF checkpoint; `YOUGORI_SWARM_TEST_QUANT` selects its quantization,
`YOUGORI_SWARM_TEST_GPU` selects `cpu` or `nvidia` on that host, and
`YOUGORI_SWARM_TEST_MEMORY_GB` sets the total worker memory (default eight GB).
Ordinary server/browser tests do not download models or send payments.
With the same fixture path, the optional
`swarm_http_direct_payment_contract_without_model_runtime` test verifies the real
HTTP/CLI/native consent and digest contract without containers or model downloads.
Run it with `--ignored`; its reward commitments and credentials are synthetic.
Registration uses the production request builder, including negotiated platform
metadata; servers without `workerCapabilityFields` receive the legacy fields.

For a deterministic harness check, run `scripts/swarm-opencode-smoke.py` with an
extracted Linux OpenCode 1.18.35 binary and `--unprivileged --installer-umask-077
--repair-readable --receipt-race --journey --boundaries`. It verifies source reading and the
check/attempt/report tool sequence as the unprivileged agent, including delayed
receipt ownership, plus rejection of external read/search requests while approved
work continues. Its model and receipts are synthetic; it does not establish
real-model research quality or native sandbox/service integration.

## Validation record — 2026-10-11

These checks ran against the working source checkout on Windows, with the private
website's loopback fixture. They do not upgrade an installed app or deployed site.

A subsequent installed 1.0.17 run with worker storage on `D:\` exposed a missed
case: private network attachment looked for the OCI appliance on the default
storage runtime, even though the worker's agent was running on the selected
drive. It failed with `Start the environment before attaching a host service`.
The host-service grant now follows the environment's saved storage route. A
disposable regression reproduced that exact error before the fix; the corrected
private-network test passed with two separate OCI pools on `D:\`, HTTP on the
approved port, and denial after connection removal (60.08 seconds). The 161
runtime unit tests and all-target native build check also passed. The earlier
real-model run used one temporary storage root and did not cover this case.
The same two-pool regression passed against an isolated 1.0.17 hotfix checkout
in 60.44 seconds; its all-target check and release executable build also passed.
That executable has been staged locally, not installed or published.
This connection regression does not establish readiness of the user's selected
Gemma E4B checkpoint or completion of a live bounty.

| Layer | Result |
| --- | --- |
| Native Swarm | 48 unit tests passed, covering scope changes, cancellation, stale progress, model residency, private chat boundaries and capability negotiation |
| CLI | 25 bounty unit tests, five command-line integration tests and 11 embedded-skill checks passed |
| Model runtime | 15 model-server, seven tool-protocol, three Rust GPU-optimizer and 10 Python GPU-optimizer tests passed |
| Private website | 38 server/fixture tests and seven Swarm browser tests passed |
| OpenCode 1.18.35 | Synthetic provider checked approved source/context reads, three outside-workspace denials, and managed check/attempt/report receipts, including unprivileged execution and a receipt ownership race |
| Native build | `npm run check:native` passed for all targets on this host |

The ordinary website build encountered pre-existing broken `dist` and
`public/downloads` junctions. The browser tests used a separate Vite output folder
and the dedicated Swarm API fixture. No screenshots or videos were captured.

The real-model acceptance test requires all three milestones: an actual failing
approved check, a model-authored managed attempt, and a complete private report.
It then verifies private participant chat, pause, synthetic publisher review and
an award with no balance credit or transfer. A tool-calling readiness probe alone
does not establish that a model can complete this workflow. Qwen3-0.6B reproduced
the fixture failure but did not complete the required workflow. The initial Gemma
GPU run exposed a missing GPU scheduler in the QA application bootstrap; the
subsequent run reproduced the defect and recorded a correct candidate, but omitted
the report. The task and tool instructions now explicitly distinguish attempt
records from reports and require an evidence-backed qualifying report before the
turn ends. The rerun passed in 933.43 seconds, including download/setup, an actual
failing check, managed attempt, one complete report, private chat, pause, synthetic
review/award and disposal of its runtime. The report identified the hardcoded
`True` in `can_read`, cited the declared unittest failure, gave the correct
observed/expected behavior, and linked its attempt and uploaded evidence. The
trace included unsuccessful file lookups before the model recovered in a later
turn. Afterwards, the instructions were clarified to give the exact context
directory; that wording change is covered by the explicit-path harness check,
not a further real-model rerun.

The Gemma run uses an RTX 5090 Laptop GPU, a 16 GB total worker allocation,
`thesamgodson/Gemma-4-12B-Hephaestus-GGUF` revision
`00557876c5faef0a886b33c30d03767dd8b0aece`, and
`gemma-4-12B-Hephaestus-Q4_K_M.gguf` (7,381,384,864 bytes; SHA-256
`58ed40c100102dac7758c651260e1d16af49f08bc67238c6deee18d36a7c42e2`).
The [publisher's model card](https://huggingface.co/thesamgodson/Gemma-4-12B-Hephaestus-GGUF)
describes it as abliterated with restored tool calling; those labels do not
replace the native workflow check.

`HauhauCS/Qwen3.8-27B-Uncensored-HauhauCS-Aggressive-MTP-GGUF` at `IQ4_XS`
was checked through preflight and CLI parsing, but its weights were not run in
this acceptance test. Its MTP
sidecar acceleration is not enabled or validated. Native Mac model CI passed
separately; full macOS bounty/guest integration and the changed 32K context
configuration have not had a native acceptance run. No result here guarantees
zero bugs, model compliance on every task, an accepted real finding or payment.

Read [the current risk-reduction review](swarm-risk-reduction-review.txt) for
implemented boundaries, legal reasoning and remaining operational obligations.


## Owner approval workflow

The website provides `/swarm/admin` for the authenticated service owner. A private,
single-use activation link assigns that role to the owner's signed-in account;
ordinary users cannot grant themselves approval permissions. Keep this link secret.
The owner enters the actual operator identity, contact and service address and a
separate registered independent appeal reviewer account before the first approval.
No operator identity or reviewer is invented by the software.

Publishers submit exact, immutable source and terms versions into a private queue.
The owner downloads the checksum-verified snapshot, reviews written source rights,
offline defensive scope and the unverified direct USDC promise, and records an
approval or rejection with a reason. Pending, rejected and withdrawn versions do
not appear publicly and cannot start research. A changed source or scope needs
fresh owner review and fresh participant approval and acceptance. Listing approval
is not an ownership, legal-authority, security or payment certification.

The publisher separately approves participants before source delivery. The owner
approval page does not grant access to participant private conversations or the
raw agent channel. Public service details are operator-supplied, not independently
verified. Source moderation is disclosed in responsible use rules v2026-10-10.4.
