# Inference Solver — preview

A separate Yougori Hub template. My API is unchanged. The main page shows harnesses, models
and sandboxes side by side, followed by usage and administrator controls; personal API keys
are a dropdown beside the main page's title. The administrator chooses which of the three
comes first and which harnesses are offered. Sandboxes join the page only when a computer
offers them, or someone already has one.
Visitors can browse harnesses and models immediately. Sign-in is only needed for
personal keys, usage, administrator controls, and access to inference. The public
catalog excludes saved server addresses, connection names, and credentials.
The design uses elements of prompx.com: a pale blue page, light Hanken Grotesk,
two-tone headings, pill buttons ending in an arrow circle, light blue highlights, flat
square panels and light/dark themes. The Harnesses column holds one card, Yougori, which
holds every harness: its page shows the one command that starts them and lists each harness
with what it asks, and each harness keeps its own page, without popups. Models have their own
pages and can be filtered as censored or uncensored: detected
from the model name, and an administrator can set the label on the model's page.
Hanken Grotesk (SIL Open Font License) is bundled in `site/fonts`.

## Run the website on its server

From the repository root, with Python 3.12 or newer:

```powershell
python -I -B examples/hub/inference-solver/site/server.py --data "$env:LOCALAPPDATA\Yougori\inference-solver-preview" --bootstrap
```

Choose an administrator email and a password of at least 12 characters in the
terminal, then open **http://127.0.0.1:3000**. On later runs, omit `--bootstrap`.
An existing administrator is never overwritten. Use a separate data directory
for each service. Stop this preview with Ctrl+C.

Choose account access with `--account-mode public` (open signup) or
`--account-mode private` (invitation-only, the default). This choice is independent
of hosting: either mode can run locally or use a public URL. For example, add
`--account-mode public` to try public signup on localhost. The template asks the
same question during setup and passes it through `ACCOUNT_MODE`.

Admin is one column of sections, each with its name and one line on the left and its
controls on the right: **Local GPUs**, **Rent a cloud GPU**, **Model servers**, **Sandboxes**,
**Main page and harnesses**, **Website identity**, **People**, **Model pricing**, **Media pricing
and storage**, **Crypto payments** and **Compute activity**. Nothing is folded away: optional
settings are tick boxes, or a mode, that switch their fields on. Local GPUs starts with the
models computers run for the website (Hugging Face repositories, at most 20): each computer that
connects chooses 1 to 3 of them, Yougori installs them there, and each loads on its GPU while it
is used and unloads after 5 minutes without requests. A computer's model joins the catalog only
while it is on this list; with none listed, computers can lend only Sandbox VMs. Each listed
model shows how many connected computers run it now. Adding a model checks it first
(`model_check.py`, the engine's own rules): public, an architecture Yougori's runtimes serve (the
engine's Transformers and vLLM lists), no repository code, not a model that ships its own
megakernel program (its base model is named instead when Yougori runs that), with the GPU memory
it needs (weights x 1.2 + 2 GB, as the engine estimates) and the GPU generation its number
formats need (bf16 Ampere, FP8 Ada, FP4 Blackwell). The model's row says so, with how many
connected computers have a GPU for it; `yougori inference connect` marks the models this
computer's GPU cannot run, and Rent a cloud GPU marks the GPUs that cannot run the model typed. Then comes every
command a GPU computer runs, in order, each with its own Copy button: install or update Yougori
(yougori.com's install command for Windows or Linux, which also starts it), `yougori app start`
(the connector needs Yougori running and never starts it) and `yougori inference connect URL`.
**Copy all for Windows** and **Copy all for Linux** copy only the commands, with only that
system's install command, and **Post on X** opens X with one post for both: each install command
under its system's name, then the start and connect commands under "Both:", ready to send. **Ask each computer for its code** (on by default): unticked, a computer that runs the commands joins at once, without a code, and serves only the listed models (it sees the requests it serves); the code box and the contributor password are then hidden. It approves the code a connecting computer shows in place (an administrator who opens
`#contribute` lands there). On desktop the left edge is a
camera-style ruler, as in the PrompX harness: tick lines, a mark per section and a thumb; drag it
to scroll, click a mark to jump, hover for names. It replaces the page's scrollbar. Without Yougori on the website's server (every hosted
inference), the website server's own controls are not shown and Rent a cloud GPU rents directly
(below). With it, Admin uses Yougori on the website's server, never an engine on a
visitor's computer. Existing
local models are discovered automatically; selecting **Add to inference** obtains
their connection internally. **Load and connect model** starts a selected Hugging
Face repository through Yougori. Model URLs and keys are not entered in this UI.

The server detects its installed Yougori CLI; `SOLVER_YOUGORI` can specify its path.
`SOLVER_COMPUTE=0` disables the controller for a website-only preview. The engine's
provider account and model credentials stay on that server. Public deployments
need a trusted, administrator-operated backend with Yougori installed. The current
Python-only sandbox manifest does **not** install a nested Yougori engine or grant
the website control over its host; without a backend, rental controls explicitly
remain unavailable. Existing template model attachments still work independently.

Cloud rental currently supports **RunPod**, through Yougori's implemented provider
adapter. The admin connects the provider account once if needed, fetches live GPU
offers, selects a model, and approves the displayed maximum hourly compute price.
Offers expire after two minutes and Yougori rechecks stock and price before buying.
The job appears immediately, records the rented environment before model setup,
and automatically publishes its models after connection. Quotes include the
selected 1–8 GPUs and temporary/persistent storage sizes; incompatible models
are refused before purchase.
Storage and other provider charges are separate. Stop controls act only on rentals
created here; stopping can leave storage charges. Ambiguous purchases are not
retried, and interrupted operations stay visible for inspection.

Optional contributors run `yougori inference connect URL`, which starts Yougori if needed
(CLI 1.2.2 and older need `yougori app start` first), reads the website's list of models for
computers (`GET /api/compute/models`: the administrator's list and `most`, 3) and asks what the
computer does: run models on its GPU, run Sandbox VMs on the PC, or both. A computer running
models chooses 1 to 3 of the listed ones; Yougori installs the ones it lacks (each loads on the
GPU while it is used and unloads after 5 minutes without requests) and reuses a model the
computer already has. Without a listed model, a computer can lend only Sandbox VMs. The next
`connect` offers to continue with the same choices or change them; a model dropped is deleted
from the computer if Yougori installed it for the website. Scripts give `--models REPO,REPO
--sandbox none|CPU,GB,VMS`, or reuse the last choices. The first time, the contributor enters a
short computer code on `/#contribute`. The CLI passes the answers to the connector
(`compute_node.py --models ENVIRONMENTS --sandbox none|CPU,GB,VMS --release ENVIRONMENTS`); on
Ctrl+C the connector stops the models it ran only for the website. An admin approves
it, or a signed-in member supplies the optional contributor password. Contributors
cannot rent servers or receive host-management commands. Their connector makes outbound
HTTPS requests, relays inference only to their selected Yougori loopback APIs, and
keeps model credentials on their computer. Owners may separately contribute bounded
Sandbox VM resources; only those guests receive grid commands. Closing the connector makes the node
offline; the admin can revoke it immediately. A locally hosted preview must be
published over HTTPS before computers outside that host can contribute.

## Website-hosted instances (yougori.com)

The Yougori website's **Create inference** flow hosts one instance per company on its own
server, at `https://NAME.yougori.com`. `site/managed.py` starts the instance as a plain process
on a loopback port; the website proxies that address to it without buffering, restarts it if it
stops, resumes it after a website restart and stops accepting new instances at the server's
capacity. The process gets its instance folder (`provision.json`, `data/`) and nothing of the
website: no engine, no provider account, no website secret. Over https the cookies are Secure,
browser requests must come from the instance's own origin, and the sign-in and code limits use
the client address the proxy reports, so one visitor cannot lock out the others behind it.

Harness VM images live outside the template releases, in the server's image folder: each
release's `site/vm-images` links to it (or `SOLVER_VM_IMAGES` names it), so every hosted
inference offers every published harness. The Yougori harness's images are in its `yougori`
folder: the base image in each variant, a pack per harness and the `image.json` that lists them
(`scripts/build-vm-images.py yougori`). Each inference hands out only the packs of the harnesses
it offers.

Compute comes from the administrator's computers (`yougori inference connect URL` on each
computer with a GPU) and from GPUs the website rents itself. Rent a cloud GPU takes the
administrator's own RunPod and Vast.ai API keys (checked against the provider, saved on the
website's server, never shown again; `rentals.py`, `neocloud.py`), lists both providers' GPUs
that are available now with their hourly prices, and rents one for a public Hugging Face text
model after checking it: an architecture the pinned runtime serves (`vllm_architectures.json`,
the engine's list for vLLM 0.29.0), no repository code, and weights that fit the GPU's memory and
the disk. The GPU runs that runtime (its CUDA 12.9 build, by digest) and fetches its agent from
the website with its own credential (`rental_agent.py`); the agent starts the model on the
GPU's loopback and serves requests over outbound connections, as a connected computer does, so
nothing listens on the GPU's public addresses. The model joins the catalog when it serves. A
rental is made once per request and never retried; one whose model cannot start is deleted so
it stops charging; one the provider ends leaves the catalog; **Stop and delete** ends the
charges. Renting needs the website's public https address.
`python -I -B tests/test_managed.py` checks the address, origin, cookie and attempt-limit rules.

## Website-created development instances

The separate Yougori website's **Create inference** flow can launch this site in
its own Sandbox VM on the development host. `site/hosted.py` consumes a private
per-instance configuration and the onboarding administrator's password hash.
Internal/public account access is fixed for that instance. Its unique owner-token
`.localhost` origin accepts host-only session cookies, using the engine's explicit
`sandbox publish --application true` mode. The original preview mode is unchanged.

The VM receives no host engine socket, host folders or outbound routes. Local
contributors use the authenticated relay; cloud rental and automatic payment
settlement are not connected in this mode. The website's production server cannot
enable this development provisioner. VM limits remain enforced: 3 GB RAM, one CPU,
1 GB workspace and 8 MiB of total responses. There is no idle or absolute time limit; the owner stops it explicitly.
This is a local acceptance path, not always-on production hosting.

SQLite runs on the guest's private disk. After each successful write, `Store`
atomically snapshots it into this VM's staged workspace before acknowledging the
change. Snapshot failure refuses further database work and makes health fail.
The host can restore this retained data into a fresh VM after proving the previous
VM stopped. Run `python -I -B tests/test_hosted.py` to check imported credentials,
snapshot durability and failure handling. The website repository also contains
`scripts/test-inference-hosting.mjs` for real multi-VM acceptance.

Hosted instances receive a manifest of publisher-verified harness images. Large,
hash-pinned archives download from the development host's read-only artifact
endpoint, outside the VM website's response budget. No tenant database or keys
are exposed there. The launcher allows this additional loopback destination only
for public package bytes; authentication and inference stay on its configured VM
origin. Missing packages remain unavailable. Refresh the instance after publishing
new images. The PowerShell command and Python launcher explicitly pin
`TOKEN.localhost` connections to loopback while retaining the HTTP Host identity.
`tests/test_hosted_downloads.py` checks that transport boundary, and
`tests/runtime_hosted_downloads.py` checks complete downloads and a real portable
Windows installation against a running instance without changing the user's PATH.

## Run the template

This source change requires an engine built from the same checkout. An older
1.2.0 binary may still refuse format-2 `model_request` connections.

```powershell
yougori template check examples/hub/inference-solver --format text
yougori template run examples/hub/inference-solver
```

The CLI creates the admin, asks for the website name and publication mode, and
offers an optional local model with quantization, GPU selection and memory budget.
If selected, the shared model runner downloads and starts it, and the template's
receiver discovers its catalog over a private one-way port-8000 connection.
Retries reuse that connection. The model key travels in a temporary file and is
never an output of the setup. Removing the connection first closes network access,
then removes the website's endpoint and saved key; a stopped receiver must be
started to finish that cleanup.

The website currently uses a Python service environment and a persistent volume.
It is not a dedicated VM sandbox. The local model uses Yougori's existing model
runner. The optional Admin rental flow requires a fresh quote and cost approval.
Quick links and saved domains
use Yougori's existing publication system, not managed Cloudflare for SaaS.

## What works in this preview

- CLI-created administrator and two account modes: public email/password signup,
  or private invitation-only registration. Both sign new members in automatically.
  Private mode rejects the signup API as well as hiding its button. Signup never grants admin
  access, and duplicate accounts cannot replace existing accounts. Passwords need
  at least 12 characters; account endpoints share an attempt limit and require
  same-origin requests. Email verification, password reset and customer payments
  are not implemented.
- Personal API keys stored as hashes, shown once, restricted to specific model names
  or all models; immediate admission refusal after revocation.
- Up to ten connected model servers, automatic catalog refresh, and truthful
  unavailable/stale states. This is not a guarantee of ten resident models per GPU.
- One name per model, however many contributing computers or model servers serve it
  (`site/routing.py`). A conversation stays on the one that served its previous turn while
  it has a free slot, so its repeated history is already in that server's KV cache;
  otherwise the least busy one serves it. Clients can name their conversation with an
  `X-Session-ID` header or OpenAI's `prompt_cache_key` (Codex sends it); Claude Code's
  `metadata.user_id` and the opening of the conversation work the same way. A server that
  cannot take a request is skipped before anything reaches the caller and tried last for
  30 seconds; a refused request (400) is tried on the other servers of that name, since
  they can differ in context length, and is the answer only when all of them refuse. Admin
  **Usage** shows requests per computer and the live routing.
- A harness's tools are never dropped without a word. When all servers of a model refuse a
  request that asks for a reply over 4,096 tokens, it is sent again with 4,096 and its tools,
  unless Yougori's model server named another limit. Two refusals are not resent: a request
  Yougori's model server refuses for its size (more tools, tool definitions, messages,
  characters or bytes than it takes), and a conversation too long for the context. The
  harness gets the refusal. A size refusal of a request with tools also says how many tool
  definitions and bytes it sent. Any other refusal may mean that the model's server calls no
  tools, so the request is sent once more as plain chat: no tools, earlier tool calls and
  results written into the conversation as text, the model told that no tools are available
  and that nothing it writes runs, and, on a contributed computer, the oldest turns dropped
  when the chat outgrows the context. A chat with no user message goes with its instructions
  as the user's message. A refusal reaches the harness in the model server's own words.
- `/v1/models` and streaming/non-streaming `/v1/chat/completions`, including
  streamed tool-call deltas. The model server always streams to the relay; a caller who
  did not ask for a stream gets the completion assembled from it, so a long answer is cut
  off only when the model stalls for two minutes, not after a fixed time. The relay accepts
  up to 32 simultaneous upstream requests; further requests get retryable 429 responses.
  Backend capacity and queue behavior still determine actual serving concurrency.
- Private request counts, reported token usage and duration. Prompts, completions
  and raw provider errors are not stored in the usage log. Missing token counts
  remain unknown rather than estimated for billing.
- JSON output: a request's `response_format` (`json_object`, or `json_schema` with a schema) goes
  only to a replica whose server enforces it. Yougori's vLLM and llama.cpp launches say so in
  their catalog (`capabilities.structuredOutput`) and health, and the connector reports it; a
  server connected by address that lists no capabilities is not refused. A model with no replica
  that enforces it refuses such requests rather than answering in prose, model pages and the
  catalog show "JSON output", and the Responses adapter maps `text.format`.
- Media models: a model whose Yougori server generates images, video, speech or sound (its
  catalog names the task) is listed with that task and takes jobs, not chat. The website
  serves the model server's own routes (`/v1/jobs`, `/v1/jobs/ID?wait=`, `/v1/jobs/ID/result`,
  `/v1/files/ID`, cancel, delete, uploads) and OpenAI's `images/generations`, `audio/speech` and
  `videos` shapes, so a client written for one Yougori model works unchanged. A job goes to one
  replica like a chat request; when it ends its files are copied to the website, the job is
  recorded as a request by what it made (images, seconds of output) and charged at the model's
  per-image and per-second prices (Admin → Media pricing), and the model server's copy is
  removed. Outputs stay for the retention and storage cap the administrator sets. Connected
  computers relay jobs and files through the connector (`yougori inference connect`); a
  connector from an earlier release is not sent media jobs. Model pages show a Try it box for
  signed-in members (`site/media.py`, `tests/test_media.py`).
- Cached input: the prompt tokens a model server reused from its cache, as it reports them
  (vLLM's `prompt_tokens_details.cached_tokens`, llama.cpp's `timings.cache_n`). Each model
  has a cached-input price beside its input and output prices; without one, cached tokens
  cost the input price. Usage lists them per request, model pages show the 24-hour share
  once five requests reported it, and Messages, Responses and Gemini clients receive them
  in their own usage fields.
- Contributing computers receive requests over one long-lived stream from the website and
  acknowledge each one, so a request starts without a polling delay; a computer that does
  not acknowledge within eight seconds loses the request to another server. A connector
  serves eight requests at once across every model it shares, and the website routes by
  that. Run one connector per computer: a second one started with the same credential
  replaces the first, which stops and says so. Connectors from earlier releases keep
  polling, and the new connector polls websites that have no stream, or that refuse it.
- Administrator server-side compute management, invitations, request totals, connection
  status, audit events, and editable name, tagline and colour style.
- Colour styles: the administrator picks Navy (the default), Nord, Solarized, Catppuccin,
  Rose Pine or Gruvbox under Website identity, for every visitor. The page arrives with it
  (`data-palette` on `<html>`, set by the server), and each person can still switch light
  and dark. Each style uses its palette's official colours, light and dark; `style.css` names
  the sources and the few colours moved just far enough for 4.5:1 text contrast.
- Main page and harnesses: an administrator's first sign-in opens **Set up your inference**
  instead of the main page, with every harness ticked and Harnesses first. The same choices
  stay in Admin under **Main page and harnesses**. The chosen column comes first on the main
  page, which opens at the site's own address. Yougori has no box of its own: it is offered
  while any harness inside it is. A hidden harness leaves the pages, and its setup ZIP,
  install script, VM image and code sign-in are refused; `/api/harnesses` still lists it,
  unavailable with the reason, so `yougori inference run` explains it. Harnesses added to the
  catalogue later are offered until the administrator hides them.
- Yougori, our own harness (the Rust crate `harness/`), holds its own agent and all 21
  harnesses: the coding harnesses' real engines behind its screen, and the five security
  harnesses' own terminal clients in a pane of that screen. Each harness also has a
  server-bound setup ZIP with source, pinned tool versions and this website's address; it
  contains no account credentials. See [the launcher](site/harnesses/README.md).
- Run `yougori inference run --server URL` (the website shows it with `yougori` as the
  harness). It asks which harness, which model, that harness's own questions (a security
  harness: what to test, permission, what is off limits, how far it may go, a test login, the
  source code and a focus), the folder copied in, what the VM reaches (not for a security
  harness) and CPU and memory, then starts the harness inside the Yougori harness, in a Sandbox
  VM from the Yougori images. Yougori manages a pinned private Python runtime on Windows and
  keeps host-side client code bundled in the CLI. Repeat the same command next time; no
  separate solver command, remote install script, or PATH entry is needed.
  `yougori inference install HARNESS --server URL` prepares the images a run starts the
  harness from: the Yougori base image and the harness's pack. A harness is available only when
  its pack and base image are published.
- First-use browser code sign-in: the CLI generates its credential, displays a
  short code, and resumes after the signed-in user approves the named harness.
  No manual API-key creation or copying. Codes expire after ten minutes, approval
  is single-use, credentials stay per-server/per-harness, and access can be revoked.
  This is a service-specific device flow inspired by
  [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628), not a general OAuth server.
- Yougori's page groups the harnesses inside it by category, Coding then Cyber Coding, one
  row each with what it asks and a Copy command button. Their labels and colors live in
  `site/categories.json`; harness membership is in `harnesses.json`. Cyber Coding groups the
  cybersecurity harnesses; model refusal behavior still depends on the chosen model. Each
  harness's own page shows its command, what Yougori asks, first-use sign-in, requirements
  and source download.
- Blue terminal presentation and an enforced network boundary. Harnesses run in Yougori
  Sandbox VMs; an owner-only publication and host relay forward only model API requests to
  this website. The real API key stays outside the VM. Workspaces are staged copies. By
  default the VM reaches only this website. A coding harness may also be given sites
  (HTTPS through the launcher), targets (Yougori's filter holds the VM to those hosts) or the
  public internet (never this computer or its network). A security harness reaches only its
  target and this website.
- Stateless Responses, Messages and Gemini text/function adapters reuse the
  Chat Completions gateway's authorization, model scopes and usage accounting.
  Their SSE output is buffered until completion; it is not native token streaming.
  Media, provider-hosted tools and stored responses are not emulated.

The data volume contains upstream model credentials. Treat the volume, its copies,
and administrator access as secrets. This preview does not encrypt those upstream
credentials at rest or claim a vault integration. Passwords use scrypt. Browser
mutations require same-origin checks and CSRF tokens; published sessions use
Secure cookies. The current sign-in throttle uses the direct peer address, so
users behind the same reverse proxy share its limit.

## Editing and verification

Read [.agents/skills/edit-inference-solver/SKILL.md](.agents/skills/edit-inference-solver/SKILL.md)
before editing the template. UI changes live in `site/index.html`, `style.css`,
and `app.js`; there is no frontend build step.

```powershell
python -I -B examples/hub/inference-solver/tests/test_service.py
python -I -B examples/hub/inference-solver/tests/test_harnesses.py
node examples/hub/inference-solver/tests/browser.mjs
node examples/hub/inference-solver/tests/private_accounts.mjs
node examples/hub/inference-solver/tests/device_browser.mjs
python -I -B examples/hub/inference-solver/tests/test_device_auth.py
python -I -B examples/hub/inference-solver/tests/test_media.py
# Windows integration, with the checksum-pinned official Python ZIP already downloaded:
python -I -B examples/hub/inference-solver/tests/windows_installer.py --runtime-zip PATH/TO/python-3.14.10-embed-amd64.zip --run-client
# Opt-in: downloads/builds a real client image and uses a disposable model fixture.
python -I -B examples/hub/inference-solver/tests/runtime_harnesses.py codex --root PATH/TO/TEST-CACHE
```

The HTTP checks use disposable SQLite data and an actual local HTTP upstream
fixture. They do not benchmark a GPU or establish production provider compatibility.
Browser checks use the repository's Playwright installation and do not record images.

Validation on 2026-11-02: 395 engine setup tests, 179 setup-library/planning tests,
11 CLI skill tests, six real HTTP/database scenarios, and the browser workflow
passed. `npm run check:native` passed with six existing warnings outside these
changes. Both new editing skills passed their format check. The website was also
visually reviewed. Automatic model attachment has engine/receiver tests but has
**not yet been exercised as a real sandbox + GPU setup**. That original check did
not replace the installed app/CLI; the subsequent installation is recorded below.

Still required for the full product: automatic controller attachment to sandbox-hosted websites,
GPU placement and cost policies, additional NeoCloud providers, AWS/Cloudflare SaaS
hosting and domain lifecycle. No public launch or claim of full production readiness
is made by this preview. Invoice settlement is described in [docs/payments.md](docs/payments.md).

Compute checks: `python -I -B tests/test_compute.py` exercises real website HTTP,
SQLite, contribution streaming and enrollment; provider adapter tests substitute
only the CLI transport and do not incur charges. `node tests/browser.mjs` checks the
one-column Admin, its tick boxes, colour styles, responsive layout and absence of a connection popup.
These checks do not claim a completed paid cloud deployment.

Harness validation is recorded separately in
[tests/evidence/harness-runtime-2026-11-02.md](tests/evidence/harness-runtime-2026-11-02.md).
These are actual third-party clients using a disposable model fixture. They prove
connection and network enforcement, not the tool-use quality of a real model.
The current native Sandbox VM checks and infrastructure results are in
[tests/evidence/native-harnesses-2026-11-04.md](tests/evidence/native-harnesses-2026-11-04.md).

## Current infrastructure controls

**Sandboxes**, immediately beside Models, lists each PC's owner-contributed CPU
cores, RAM and VM slots, including what is still free. Launch, guest commands and
stop are inline on that page; there is no separate setup to create. Capacity counts
other users' sandboxes without exposing their private guests. Admin has a simple
enable switch, server contribution limits and public/private contributor admission
with an optional join password, plus receiving-wallet settings for seven networks.
Contributors explicitly select
resources in `yougori inference connect URL`; neither the website nor guests get host file access.
VMs run until stopped, without a fixed idle or absolute time limit. Disconnecting
stops the connector's VMs; owner revocation and engine-death cleanup remain active.

Cloud quotes support 1–8 GPUs and temporary/persistent volume sizing. Displayed
GPU prices are totals for the selected count; rental uses the approved fresh quote.
Account balance and current hourly spend come from the connected RunPod account.
No paid rental was performed in the isolated checks. Multiple GPUs do not by
themselves establish tensor-parallel compatibility for a selected model/backend.

Wallet settings now support automatic invoice settlement on all seven networks,
an idempotent dollar-balance ledger and separate input, cached-input and output prices per million tokens.
Checkout is inline under Usage; full behavior, finality and RPC configuration are
in [docs/payments.md](docs/payments.md). No real funds were transferred in testing.

Admin can invite additional administrators or promote existing members under
**People and administrators**. Public signup always creates a member. The server
prevents removal of the last administrator even during concurrent changes.

Admin **Usage** is a control panel with CPU, RAM, GPU utilization and temperature
charts, GPU memory/power, disk and workload readings, users online, active requests,
model token totals, revenue, top-ups and cloud account spending. Hardware samples
are bounded to one hour; API totals cover 24 hours. Online means a visible browser
heartbeat in 90 seconds, and API activity means a request in five minutes. Missing
sensors are unavailable, not zero. Engine refresh failure does not reuse old host
metrics as live samples. Remote cloud temperatures need a contributing node with
sensor support; RunPod spending is from the latest Admin account check.

In the Yougori desktop, **Hub → Create my inference** preselects this bundled template
in the existing review/setup flow. It does not automatically rent or launch anything.
Verification: [control-panel evidence](tests/evidence/control-panel-2026-11-04.md).

On 2026-11-04 the local installed app and CLI were updated together from 1.1.1 to
the current 1.2.0 source build. A VM launch, guest command and stop passed through
the normal installed engine. This is a local source build, not a published release;
its runtime resources still come from this source checkout. An unsupported engine
cannot launch a VM, and no host/container fallback is provided.

`tests/test_infrastructure.py` covers real website HTTP and authorization with
an isolated transport for engine calls. `tests/runtime_grid.py` additionally
passed a real HTTP-to-connector-to-VM launch, guest command, stop and reconciliation.
HexStrike, Plandex, Strix, PentAGI and Shannon have passed native VM checks.
Shannon's check starts its Temporal worker and validates the model connection;
it does not run a full penetration test.
These checks use real clients and a disposable model fixture, not a model-quality
benchmark or an external penetration test. Earlier container evidence does not
establish native VM compatibility for the other catalog entries.
