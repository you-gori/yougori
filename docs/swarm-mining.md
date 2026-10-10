# Swarm Mining

Swarm Mining permits authorized defensive research on accepted local source only.
Read [the responsible use rules](swarm-responsible-use.txt) before publishing or
accepting a bounty. Malicious use, unauthorized live targets, safeguard bypasses,
impersonation, and falsified evidence are prohibited. These hosted service rules
preserve the software's open source modification rights. New work requires
explicit acceptance of the exact rule version and digest within the bounty terms;
the server stores an immutable acceptance record for publisher and participant.
The local pilot is not a security certification or a guaranteed USDC payment.

Swarm Mining connects a participant's private local model and OpenCode agent to
explicitly accepted security bounties. The hosted service opens private submissions when explicitly enabled. The owner
reviews every source and terms version before it is listed. It is not a promise of
earnings. New publishers promise USDC and pay qualifying winners directly outside
Yougori. The server records the promise, award and payment evidence; it does not
hold or transfer new bounty funds. A promised reward is not verified funding.

```sh
yougori start bounty
```

Paste `hf.co/OWNER/MODEL` first. The wizard then asks for local compute, CPU/RAM,
storage, workspace quota, a worker name, and whether to retain model memory while
waiting. Review preparation before any worker is created. The engine verifies
model compatibility and OpenCode readiness; an ordinary model greeting alone is
not sufficient. This initial runtime requires a GGUF repository with compatible
function calling. CPU and NVIDIA modes use the same supported GGUF runner. The
worker's total allocation starts at four CPU cores and eight GB RAM, divided
between the model, OpenCode and a separate test sandbox. Workspace quota starts
at four GB and covers both non-model sandboxes; model storage is separate.
The model API stays private and no Neo Grid listing or public
tunnel is created. Waiting performs no agent inference.

Choose **Release model memory while waiting** or `--release-memory` to release
idle model memory. CPU mode stops its managed model container; NVIDIA mode uses
the existing GPU optimizer to unload idle weights. The engine reloads the model
when you accept work or send your own agent a prompt. Verified model files and
caches remain on disk, so reloading does not require another download. A model
shared by active workers, a pinned model, or a model used by another ordinary
workload stays available. Stop and delete stop only an unused managed model;
deleting a worker retains its model files and cache.
New workers reuse a retained private Swarm model when its verified revision,
quantization, CPU/GPU mode and resource allocation match the requested model.

Offers show the named publisher, objective, exact scope and source revision,
written source authorization and its digest, promised reward, winning rules and
terms version. Browse published metadata and apply for the exact version; this
application grants no source access and does not accept research or payment terms.
Publishers approve participants before source delivery. Choose an
offer, review the full details, choose
automatic private report submission or personal review, choose a work budget,
and explicitly accept the exact terms, source authorization and direct-payment
counterparty risk. Preparation never accepts an offer. Approval is renewed after
a new scope/source version. Human suggestions cannot enlarge written permission.

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
yougori bounty reports WORKER
yougori bounty rewards
yougori bounty doctor WORKER
```

The waiting view offers **O** to review offers, **C** to chat, **P** to pause or
resume, **R** to refresh, and **Q** or **Ctrl+]** to detach. The engine continues
waiting or working after detachment. **Ctrl+C** opens a menu with **Cancel**
selected. Pause checkpoints work; stop retains files. Delete requires a second
explicit confirmation and affects only that worker's managed workspace. Submitted
reports and server reward records remain.

```sh
yougori bounty pause WORKER
yougori bounty resume WORKER
yougori bounty stop WORKER
yougori start bounty --worker WORKER
yougori bounty delete WORKER --yes
```

For scripts, preparation requires a supplied model, `--yes`, and `--no-wait`.
Authenticate with `yougori login` first. This prepares a worker, never accepts a
bounty. `--dry-run` validates arguments and displays the request offline.

```sh
yougori start bounty --model hf.co/OWNER/MODEL --cpu 4 --memory 8GB \
  --gpu nvidia --workspace-quota 20 --yes --no-wait
yougori start bounty --model hf.co/OWNER/MODEL --dry-run
yougori bounty accept WORKER OFFER --version 2 --terms-digest EXACT_DIGEST \
  --report-policy review --budget-minutes 60 --accept-rules \
  --accept-authorization --authorization-digest EXACT_AUTHORIZATION_DIGEST \
  --accept-direct-payment --yes
```

Use `--platform-url http://127.0.0.1:PORT` only with the matching local development
platform/account configuration. Remote platforms must use an HTTPS origin.
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
--lib swarm::`. The optional real-runtime test requires the private website's
`scripts/swarm-native-fixture.mjs` path in `YOUGORI_SWARM_FIXTURE_PATH`; run
`swarm_real_local_model_opencode_bounty_journey` with `--ignored --nocapture
--test-threads=1`. It uses disposable storage, a real small HF CPU model and
pinned OpenCode, with an isolated local bounty service and simulated USDC.
Ordinary server/browser tests do not download models or send payments.
With the same fixture path, the optional
`swarm_http_direct_payment_contract_without_model_runtime` test verifies the real
HTTP/CLI/native consent and digest contract without containers or model downloads.
Run it with `--ignored`; its reward commitments and credentials are synthetic.

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
