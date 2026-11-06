# Inference Solver harness launcher

On Windows, use the website's **Install CLI** command. For example, replacing
`https://solver.example` with your website:

```powershell
powershell -NoProfile -c "irm 'https://solver.example/install/codex.ps1' | iex"
```

Installation starts the harness immediately in the same terminal. Keep it open,
follow the displayed website link, and approve the code. No separate run command
or manually copied API key is needed. On later visits, open PowerShell and run:

```powershell
solver-codex
solver-codex models
solver-codex login
solver-codex --workspace C:\path\to\project
solver-codex --help
```

Each ready harness has its own `solver-NAME` command and `/install/NAME.ps1` URL.
The per-user installer includes a private, checksum-pinned Python 3.14.10 runtime;
no global Python installation is needed. Yougori with working Sandbox VM support
is required. First launch imports the image prepared by the website administrator.
The installer checks the source ZIP's SHA-256, rejects redirects and unsafe ZIP
paths, and activates the new command after validating it. Re-run it to update.
An existing command connected to a different server is preserved; the additional
server gets a command with a short suffix. The install directory is normally
`%LOCALAPPDATA%\InferenceSolver\cli`. The existing API-key profile stays separate.
`INFERENCE_SOLVER_HOME` selects another install directory; setting
`INFERENCE_SOLVER_NO_PATH=1` leaves persistent PATH unchanged (portable mode).
Automated packaging can set `INFERENCE_SOLVER_NO_LAUNCH=1` to skip the initial
launch; normal users do not need this option. Contributor `solver-node` installation
remains separate and does not auto-start a contribution.
These checks provide download integrity, not an independent publisher signature.

For the source ZIP on Windows/Linux, install Python 3.12+ and Yougori with Sandbox VM support.
The macOS VM backend is not supported by this launcher.
The official tools are installed into dedicated images, not into your normal CLI
profiles. Installers download packages before a session starts. Before each session,
`yougori inference run` asks what the VM may use: a project folder (staged as a
copy), what it can reach (only the originating Inference Solver API, sites you
choose, or the whole internet as well) and its CPU and memory. `--workspace`,
`--internet inference|sites|full` (with `--sites github.com,pypi.org` for sites),
`--cpu` and `--memory` answer those questions, and `--yes` keeps the defaults for
the rest. Chosen sites need no network card: the harness's HTTPS goes through a
proxy in the VM (`vm_tunnel.py`) over the owner channel, and the launcher opens a
tunnel only to a chosen site (or its subdomains) on port 443 at a public address.

For a source installation, extract this folder and run:

```
python solver.py list
python solver.py install pi
python solver.py models
python solver.py run pi --workspace /path/to/project
```

Replace `pi` with the harness you downloaded. The website address is already in
`connection.json`. First launch generates its own credential and shows an
eight-character code. Open the printed website link; sign in, enter the code and
approve the named harness. The same terminal continues automatically. No manual
API-key creation or copying is required. Each server/harness has its own credential,
saved in an owner-only local folder. Use `login` to reconnect.
Codes expire after ten minutes; denial and
revocation refuse access. You can revoke a connection from the website's API keys.
The server stores only credential and code hashes. Keys are never in downloads,
image layers, command arguments or harness environments. A harness gets only a
nonsecret local relay token. The selected workspace is staged as a copy in the VM; review and promote approved
changes with Yougori before they reach the original folder. Omit
`--workspace` for an empty disposable workspace. Session home directories are
ephemeral. No host home, SSH agent, provider account or Docker socket is shared.

`models` lists the server's current authenticated model catalog. Select with
`--model MODEL_ID`, or use the interactive picker. There is no external-provider
fallback. Client context/output budgets are configuration defaults, not discovered
model capabilities; use a model that supports the task's context and tool calls.

The boundary is a Yougori Sandbox VM without host folder mounts. By default it has
no external network interface; with `--internet full` the engine attaches an
outgoing-only NAT network card (no incoming access), and model requests still use
the relay below. The VM's loopback API exchanges allowlisted inference requests
through an owner-only Yougori publication. The host relay forwards only model API
paths to the fixed service origin; it refuses redirects, proxy CONNECT, arbitrary
URLs and account/admin routes. Its real service key stays outside the guest.
Beyond the sites or the whole internet allowed for a session, external browsing,
git fetch, package downloads and telemetry are unavailable at runtime. Prepare dependencies before building the VM image.

Chromatic terminal accents are remapped to blue in a real PTY. Neutral text,
backgrounds, input, resize events and terminal controls are preserved. Native themes are
used where configured. Licenses and notices remain with the packaged sources.
The multi-service adapters patch pinned upstream source to use the single VM and
fixed model relay; they are not unmodified vendor distributions.

Responses and Messages adapters support stateless text and function tools. Their
SSE output is buffered until the upstream completion ends. Native reasoning,
media, hosted provider tools and stored responses are not emulated. Unsupported
features fail with an error. A compatible model must still support tool calling.
Gemini's generateContent adapter has the same text/function and buffering limits.
Codex gets a custom catalog containing only the models available to your key.
The Gemini and Claude clients may still display their own vendor model shortcuts;
selecting them cannot reach that vendor and this server refuses unknown model IDs.

Grok's pinned executable supports Linux amd64 guests only. Other builds
are refused explicitly. Older runtime evidence used Docker Desktop and does not establish native VM
compatibility. Pi has separately passed a real Yougori VM inference check on
Windows; other native checks are recorded as they finish.
Top-level tools and Git revisions are pinned; transitive package dependencies
are resolved during installation.

SWE-agent uses its local execution backend inside the VM. PentestGPT
uses its maintained interactive `pentestgpt-legacy` client, with reasoning,
parsing and generation all set to the selected server model. It is not its
separate autonomous CTF/Docker deployment. Open Interpreter and PentestGPT also
accept `--print "prompt"` through a small adapter using their own Python clients.
DeepSeek accepts the same flag to use its official headless profile.

For SWE-agent, select a Git project with its `.git` directory inside the shared
folder. Existing edits are preserved; the launcher does not reset the project.
Without a workspace, SWE-agent gets an empty disposable Git repository. It asks
for a task interactively; headless runs require `--problem_statement.text "task"`.

`list` distinguishes installable profiles from unfinished multi-service adapters.
A profile is not a claim that every upstream release was tested on every host.
Only the real-runtime results recorded in the template's tests/evidence apply.

HexStrike includes its pinned HTTP/MCP server and a terminal companion that
uses only the selected server model. Its MCP file tool has passed a native VM
round trip. Optional external scanners are reported as unavailable when absent.
Plandex includes its real CLI, local server and PostgreSQL. All agent roles use
the selected model. Its context budget defaults to 32,768 tokens and must be at
least 16,384; choose a model that supports it. `--print "task"` runs a headless plan.

Strix uses the pinned agent SDK's local execution client inside the outer VM,
with its Caido sidecar on loopback. Its actual guest command and tool-result
round trip have passed. No second container runtime is involved.

PentAGI includes PostgreSQL/pgvector, its server and a terminal client. Its pinned
execution adapter runs commands and transfers files inside the same outer VM,
with one flow per session. `--print "task"` runs a headless flow. Guest execution,
file write/read and the result's return to the model have passed.

Shannon opens a `shannon>` prompt and stays in the prepared VM. Use `check` for
model validation, `shell` to start a service inside the VM, `scan URL` to run a task
against that service, `logs` for worker details, and `exit` to stop the VM. Select
a project with `solver-shannon --workspace "C:\path\to\project"` before scanning.
Starting the command never starts a scan automatically. The terminal shell also
runs inside the VM. Repeated actions in this open session do not copy the tool
package again; after exiting, a new VM still needs its own tool preparation.

Shannon's real worker and private Temporal service have passed native VM model
validation. For a one-shot check, `solver-shannon -- --validate-model` checks
only the chosen model using a disposable loopback target and then exits. Scans require
`--target http://127.0.0.1:PORT` and a target running inside that VM; the external
network restriction also applies to cybersecurity harnesses.
Canonical reports are written under `.shannon/runs` in the staged workspace.
Internal worker logs go to `~/shannon-worker.log` inside the VM; `logs` displays
them. `--verbose` streams them during a one-shot run. Failures retain their nonzero
exit codes; quiet output does not turn an unsuccessful task into a success.
The runtime check does not establish a complete end-to-end penetration test.
Shannon uses the local chat-completions contract: no provider storage/reasoning
extensions, a 128-token connection check, and at most 4,096 output tokens for a task.

Larger harnesses use a separate checksum-verified tool package. The launcher
downloads it from this website, transfers it through the private VM connection,
and starts the tool only after verification and bounded extraction. The image
itself pins the expected package hash. This does not grant external guest access.
Publisher builds use `scripts/build-vm-images.py --split-tools`. `--reuse-tools`
is only for runtime-Python edits against an existing image with identical tool
pins; installer, OS or dependency changes require a full build.
The catalog only marks a harness available when its current VM image and any
separate tool archive exist with the declared sizes. Client-side checksums remain
mandatory. The CLI checks this availability and the local VM runtime before login.
An administrator must publish missing images; a source profile alone is not ready.

Sources: [OpenCode](https://opencode.ai/docs/providers/),
[Codex](https://developers.openai.com/codex/config-file/config-reference),
[Claude](https://code.claude.com/docs/en/llm-gateway),
[Pi](https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/models.md),
[Qwen](https://qwenlm.github.io/qwen-code-docs/en/users/configuration/auth/),
[Aider](https://aider.chat/docs/config/options.html),
[Cline](https://docs.cline.bot/cli/cli-reference),
[Goose](https://goose-docs.ai/docs/getting-started/providers/).
