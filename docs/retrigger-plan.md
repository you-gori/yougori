# Retrigger — one sandbox per signup (plan)

Status: plan only, nothing implemented. Written 2026-10-14 against `main` at `1e717d8`.

## 1. What it is

A developer is building their own product (an iOS app, a SaaS, anything) that lets
*their* users drive an AI harness with *their own* account or subscription. Harnesses
are the AI tools Yougori already installs:

- Codex
- Claude Code
- Gemini CLI
- OpenCode
- Kilo Code
- Ollama
- OpenClaw

Retrigger is the piece of Yougori that makes this work:

1. A user signs up in the developer's product. The developer's backend calls
   Retrigger, or Retrigger receives the signup event. Retrigger creates a small,
   isolated sandbox for that user.
2. The product asks the user which harness they use: "Codex, Claude Code, Gemini,
   OpenCode…?". The list comes from Retrigger, so the product never hardcodes it. The
   answer goes to Retrigger, which activates that harness in the user's sandbox and
   sizes the sandbox for it.
3. Retrigger starts the harness's own sign-in inside the sandbox and returns what the
   product must show:
   - a link and a code (Codex);
   - a link only (Ollama cloud);
   - a link to a sign-in terminal (every other harness).

   The user signs in. Retrigger detects success and tells the product.
4. From then on the product sends prompts for that user. Retrigger runs them with that
   harness in that user's sandbox and streams the output back.

In the desktop app, Retrigger is a page that works like a database: apps on the
left, one row per user with their sandbox, harness, sign-in state and activity, plus
the API keys, webhook and endpoint for each app. Every app action has a matching
`yougori retrigger …` command, as the CLI parity rule requires.

```
iOS app ──► developer backend ──► Retrigger endpoint (HTTPS, saved domain)
   ▲                                   │
   │ harness list, link + code,        ├─ registry: apps, users, keys, webhooks
   │ sign-in link, streamed output     ├─ provisioner: one microVM per user, sized per harness
   │                                   ├─ harness adapters: activate, sign in, run, detect expiry
   └──── (optional) direct, with a ────┤─ runs: each harness's headless mode in the sandbox
         short-lived user token        └─ webhooks ──► developer backend
```

## 2. Terms that shape the design

These are not optional; the design below is built around them. Each vendor's rules
also apply when its account is used *inside another harness*, for example a Claude or
ChatGPT login inside OpenCode.

**Anthropic, Claude Code** ([legal and compliance](https://code.claude.com/docs/en/legal-and-compliance)):
- Running Claude Code for other people in hosted sandboxes requires the developer to
  accept Anthropic's Commercial Terms.
- The binary must be unmodified, with none of its sign-in methods removed.
- Each end user signs in with their own plan or their own API key. The developer may
  not pay for, resell or intermediate that usage.
- "Developers may not collect, store, or intermediate Claude.ai credentials or session
  tokens — sign-in to a Claude account must complete through Anthropic's own flow."
  Anthropic explicitly still allows an end user to sign in to the unmodified binary on
  a hosting platform.
- Anthropic does not permit routing requests through Free, Pro or Max plan
  credentials from third-party apps. So Claude models inside OpenCode, Kilo Code or
  OpenClaw need the user's own Anthropic API key, not a Claude plan sign-in.
- The product may say it "runs Claude Code" in plain text, but not use the name or logo
  in its own branding.
- Pro and Max limits assume ordinary, individual use.

**OpenAI, Codex** ([Codex authentication](https://learn.chatgpt.com/docs/auth)):
- `codex login --device-auth` prints a link and a one-time code. This is the
  "open this link, enter this code" flow.
- Users must first turn on device code login in ChatGPT's security settings, or a
  workspace admin must allow it.
- OpenAI says to treat `auth.json` like a password and not to expose Codex execution
  in untrusted environments. Its auth page has no rule on hosted third-party use;
  check OpenAI's terms before launch.

**Google (Gemini CLI), Ollama, and the open-source harnesses (OpenCode, Kilo Code,
OpenClaw)**:
- Not reviewed yet.
- Phase 5 includes a terms check per vendor and per sign-in type: Google personal
  account versus API key, Ollama cloud account, and every provider those harnesses can
  sign in to.
- Until a harness's review is done, the GUI marks it "terms not reviewed".

**Design consequences, for every harness**:
- The developer's product never asks for harness credentials and never sees sign-in
  codes that the user pastes. Paste-back sign-ins happen in a terminal attached to the
  real harness in the user's own sandbox (section 8). Only codes the vendor *shows* the
  user for another device, such as Codex's device code, are relayed.
- Harnesses are installed and run unmodified, from their official installers.
- Retrigger never reads, copies or exports credential files. The existing "copy this
  computer's sign-in" import is blocked for Retrigger sandboxes.
- Enabling a harness for an app may require a one-time acknowledgement of that
  vendor's conditions (Claude Code: always). Acknowledgements are stored with a date.

None of this is legal advice. Review before any public launch, as with the Swarm legal
reviews.

## 3. What exists today

| Area | Today | Gap |
|---|---|---|
| Harness sandboxes | CLI-only logic in `cli/src/container_tools.rs:622-735`. Tool list hardcoded in 4 places (`container_tools.rs:10`, `src/lib/terminal-installers.ts`, `workspace/installers.rs:36`, `tool_credentials.rs:18`) | Port to the engine; one harness registry |
| Install | `src-tauri/src/workspace/install-tools.sh` installs each tool's latest release, unpinned; Gemini and Kilo get a private Node 22 each | Pinned versions, preinstalled in one base image |
| Sign-in | Nothing automated. Only file import from the host (`cli/src/tool_credentials.rs`) | Device code, link and sign-in terminal |
| MicroVM boot | Each new microVM pulls `ubuntu:24.04@sha256:534b…` from Docker Hub (`workload_options.go:191-216`). No cache, template or warm pool | Docker Hub anonymous pull limits break at scale; needs a local base |
| Creation | Serialized engine-wide by `feature:run_workload` (`automation/coordinator.rs:82-127`) | Retrigger needs its own lock key |
| RAM | Fixed per sandbox at boot. Built-in microVM floor 0.5 GB (`runtime/vm_memory.rs:5`) | Per-harness measured sizes |
| CPU | Every running microVM reserves ≥ 1 whole host CPU (`commands/resource_admission.rs:94`, `cpu.preferred.round().max(1.0)`), against the host's logical CPU count (`scheduler.rs:9-13`) | A 16-thread host runs at most 16 sandboxes, however small. Needs CPU sharing for Retrigger sandboxes |
| Idle | No idle stop for environments. Pause keeps RAM | Idle stop and wake on demand |
| Ownership | `Environment` has no owner, tag or label (`models.rs:151-194`) | Owner field |
| Long commands | `execute_guest_job` + `guest_execution_output` with cursors; one job per sandbox; holds one of 32 queue slots for the whole run | Runs need their own lane |
| Public API | Engine is pipe-only by design. Sharing gateway is hand-written HTTP/1.1 with `Connection: close`, no streaming (`remote_access.rs:638-788`) | New separate gateway on axum (already a dependency), with streaming |
| Tunnels | One cloudflared per hostname → loopback port; saved domains; global quick-tunnel cooldown (`workspace/cloudflare.rs`) | One tunnel for the whole endpoint; saved domain in production |
| Webhooks | No outbound notification code. Closest patterns: Swarm `agent_once`, `market::sync_one` | Signed webhook outbox |
| State | JSON files, atomic writes (`store.rs:236`), per-feature folders | `retrigger/` folder |
| GUI | No router; header features are dialogs (`src/components/app-shell.tsx:40-53`). Best table to copy: `src/components/environment-list.tsx` | New Retrigger view |

## 4. Harnesses

### 4.1 The harness registry

Each harness is defined once, as a manifest the engine reads. The four hardcoded tool
lists above are generated from it or checked against it. Built-in manifests ship for
all seven harnesses. A later phase lets a developer add a custom harness manifest for
any CLI agent not on the list.

```jsonc
{
  "id": "opencode", "name": "OpenCode", "version": "1.x.y",       // pinned
  "install": "harnesses/opencode.sh",          // runs once, in the base image build
  "signIn": [
    { "method": "terminal", "command": ["opencode", "auth", "login"] }
  ],
  "signedIn": ["sh", "-c", "test -s ~/.local/share/opencode/auth.json"],  // existence only, never read
  "signOut": ["opencode", "auth", "logout"],
  "run": {
    "new":    ["opencode", "run", "--format", "json"],
    "resume": ["opencode", "run", "--format", "json", "--session", "{session}"],
    "prompt": "stdin",                         // stdin | file:{path} | arg
    "output": "jsonl",                         // jsonl | ndjson | text
    "session": "$.sessionID",                  // where the resumable session ID appears
    "autonomy": { "readOnly": [...], "workspaceWrite": [...], "full": [...] }
  },
  "services": [],                              // background processes started on wake
  "authError": ["401", "not logged in", "re-authenticate"],   // patterns that mean "sign in again"
  "size": { "memoryGb": 1.0, "notes": "measured 2026-10-xx" },
  "terms": { "reviewed": false, "acknowledgement": null },
  "userHint": "Choose a provider and sign in. For Claude models use your own Anthropic API key."
}
```

### 4.2 The seven built-in harnesses

Commands marked † are to be confirmed in the Phase 0 spike against the pinned
versions. Sizes are starting estimates; the spike replaces them with measured values.

| Harness | Sign-in in the sandbox | Headless run | Output | Starting size |
|---|---|---|---|---|
| Codex | **Link + code**: `codex login --device-auth`. Fallback: terminal | `codex exec --json -` / `codex exec resume {session} --json -` | JSONL | 0.75 GB |
| Claude Code | **Terminal**: Claude Code's own login (`claude auth login`† or `/login`). Or own API key in the same terminal | `claude -p --output-format stream-json --verbose` / `--resume {session}` | JSONL | 1 GB |
| Gemini CLI | **Terminal**: Google sign-in with `NO_BROWSER=true` (shows a link, user pastes a code)†. Or own Gemini API key | `gemini -p … --output-format stream-json`† / resume† | JSONL | 1 GB |
| OpenCode | **Terminal**: `opencode auth login` (provider picker; some providers show device codes inside it). Or provider API keys | `opencode run --format json`† / `--session {session}` | JSON events | 1 GB |
| Kilo Code | **Terminal**: Kilo's own sign-in or provider keys† | `kilo run …`† (headless mode) | JSON or text† | 1 GB |
| Ollama | **None** for local models. **Link** for Ollama cloud models: `ollama signin` prints a link to connect the sandbox† | HTTP `POST /api/chat` to `127.0.0.1:11434` inside the sandbox via `curl -N` | NDJSON | 1 GB with cloud models; model size + 1 GB for local CPU models |
| OpenClaw | **Terminal**: `openclaw onboard` (its own account and provider setup) | `openclaw agent --message … --json`†; its gateway runs as a service | JSON† | 1.5–2 GB |

**Sign-in methods** (section 8):
- `deviceCode`: Retrigger reads the link and code the harness prints and returns both.
- `link`: Retrigger returns only a link.
- `terminal`: Retrigger returns a link to a short-lived sign-in terminal attached to
  the harness.
- `none`: nothing to do.

`terminal` is generic, so any harness with an interactive sign-in works without
harness-specific parsing.

**Services**: Ollama needs `ollama serve`, and OpenClaw its gateway. They start when the
sandbox wakes and stop with it; their memory counts toward the harness size.

**Ollama models**:
- Local models are gigabytes each. Downloaded per user, they would make sandboxes
  large.
- Default: Ollama cloud models only.
- Local models need an explicit per-app setting with a model allowlist and a larger
  size.
- Later: one shared, read-only model disk attached to every Ollama sandbox, so a model
  is stored once.

## 5. Data model

**App**: one developer product connected to Retrigger.

```jsonc
{
  "id": "app-7f3c…", "name": "My Harness", "createdAt": "…", "enabled": true,
  "harnesses": ["codex", "claude", "gemini", "opencode", "kilo", "ollama", "openclaw"],
  "acknowledgements": { "claude": "2026-10-…" },
  "sandbox": { "isolation": "microVm", "sizing": "auto",   // auto = per-harness measured size
               "overrides": { "openclaw": { "memoryGb": 2 } } },
  "ollama": { "localModels": false, "allow": [] },
  "limits": { "maxUsers": 500, "maxRunning": null /* derived from host */,
              "signupsPerHour": 100, "idleStopMinutes": 15,
              "runMaxMinutes": 30, "runsPerUserPerMinute": 10 },
  "autonomy": "workspaceWrite",          // readOnly | workspaceWrite | full
  "keys": [{ "id": "key-…", "prefix": "rt_live_ab12", "sha256": "…",
             "createdAt": "…", "lastUsedAt": "…", "revokedAt": null }],
  "webhook": { "url": "https://api.example.com/yougori", "events": ["*"],
               "secretRef": "Yougori.Retrigger.v1/app-7f3c…/webhook" }
}
```

**User (member)**: one end user of that app, and their sandbox.

```jsonc
{
  "id": "usr-91ab…", "appId": "app-7f3c…",
  "externalId": "u_12345",               // the developer's own opaque user ID; unique per app
  "createdAt": "…", "lastActiveAt": "…",
  "environmentId": "env-…",
  "phase": "active",                     // state machine below
  "harness": "codex",                    // null until the user chooses
  "signIn": { "codex": { "state": "signedIn", "updatedAt": "…" } },  // per harness, so switching back needs no new sign-in
  "error": null,                         // { code, message, retryable, at }
  "runs": { "total": 42, "lastAt": "…" } // counters only: prompts and output are never stored
}
```

**Environment owner field (engine change).** Add an optional `owner` field to
`Environment` (serde default, so old state still loads):

```jsonc
"owner": { "kind": "retrigger", "appId": "app-…", "memberId": "usr-…" }
```

It is used to:
- hide these sandboxes from the overview graph;
- apply the CPU sharing in section 6;
- block sharing, PC folders, connections, publications and credential import;
- reconcile the registry with environments.

Descriptions alone can't do this: they can't be edited and a snapshot restore can reset
them.

**Storage** (data folder, atomic writes with `store::write_atomic`):

| Path | Contents |
|---|---|
| `retrigger/apps.json` | Apps with key hashes; no plaintext secrets |
| `retrigger/members/<appId>.json` | Users of one app |
| `retrigger/outbox/` | Pending webhook deliveries, so they survive restarts |
| `retrigger/activity/<appId>.jsonl` | Bounded activity log: IDs and states only, rotated |
| `retrigger/bases/<version>/` | Base image disk and manifest (section 7) |
| `retrigger/harnesses/` | Custom harness manifests (later phase) |
| keyring `Yougori.Retrigger.v1` | Webhook signing secrets |

API keys are 256-bit random secrets, so a SHA-256 hash with constant-time comparison is
enough. scrypt is for human passwords.

### User state machine

```
            POST /users
                │
             queued ──► creating ──► ready ──► activating(harness) ──► needsSignIn ◄──┐
                            │                         │                     │          │
                            ▼                         ▼                     ▼          │ expired /
                         failed ◄─────────────────────┴──────────────── signingIn      │ signed out
                       (retryable)                                          │          │
                                                                            ▼          │
                                                                         active ───────┘
  any ──► deleting ──► (removed)      harness "none" (local Ollama): activating ──► active
```

Sandbox power (running, stopped, starting) is tracked separately from the phase. An
`active` user's sandbox is usually stopped and woken on demand.

## 6. Small sandboxes

**Goal**: the smallest sandbox that still runs the chosen harness reliably. Sizes are
measured per harness, not guessed.

**How sizes are set**:
- The Phase 0 spike runs a standard task in each harness: read a file, edit it, run a
  command, answer.
- It starts at the 0.5 GB microVM floor and steps up 0.25 GB at a time until the task
  passes 5 times in a row.
- The harness size is that value plus 25% headroom, rounded up to 0.25 GB. It is stored
  in the harness manifest with the measurement date.
- Per-app overrides exist for heavier use, such as builds or big repos.

**Lifecycle sizing**:
- At signup the sandbox is *created* at the floor size and left stopped: disk and
  record only, seconds, no RAM.
- When the user picks a harness, Retrigger sets that harness's size before the first
  start. RAM is fixed at boot, so changing it while stopped costs nothing.
- Switching harness later resizes on the next start.

**CPU sharing (engine change)**:
- Each sandbox gets 1 vCPU.
- Today admission reserves a whole host CPU per running microVM, which caps a 16-thread
  host at 16 sandboxes.
- Harnesses spend most of their time waiting on remote models. So Retrigger-owned
  sandboxes are admitted with a CPU weight: default 0.25, so four sandboxes per host
  thread.
- Each QEMU process gets a host-side CPU cap so one user can't starve the others:
  Windows job object CPU rate control, or Linux cgroup `cpu.max`.
- The weight is a per-app setting.
- The change is limited to Retrigger-owned environments in `resource_admission.rs`;
  everything else is unchanged.

**Disk**:
- One shared, read-only base holds every harness (section 7).
- Each user has an overlay with only their own changes, typically under 0.5 GB.
- The virtual disk is 8 GB, because the base counts inside it.

**Isolation**: one microVM per user by default. Each sandbox holds a different person's
sign-ins, so users must never share a kernel. Containers stay available per app, with a
warning that they are for single-tenant testing only.

**Idle stop and wake**:
- A supervisor stops sandboxes idle longer than `idleStopMinutes` (default 15). Idle
  means no run, no sign-in in progress and no open terminal. It stops rather than
  pauses, because pause keeps the RAM.
- Any API call that needs the sandbox wakes it first and starts the harness's services.
- Target cold start is under 10 s; measure it in the spike.

**Capacity**:
- `maxRunning` defaults to whichever runs out first: the RAM budget divided by
  harness sizes, or the CPU budget divided by the CPU weight.
- The RAM budget is total − max(10%, 1 GB) − 0.375 GB (`scheduler.rs:9-13`).
- Example, a 16-thread, 64 GB host:
  - RAM budget ~57 GB, which runs ~50 one-GB sandboxes at once.
  - CPU allows 64 at weight 0.25.
  - So RAM decides: ~50 running, and thousands registered.
  - Without the CPU change, the same host stops at 16.
- When full, the supervisor stops the least recently active idle sandbox. If none is
  idle, the API returns `503 capacity_full` with `Retry-After`, and a `capacity.full`
  webhook fires.

**Scale ceiling for v1**: about 1,000 users per engine. Every environment sits in
`platform-state.json` (32 MiB cap) and in the state pushed to the app after each change.
Measure in the Phase 4 load test before raising it.

**Beyond one machine**: production does not run on one big host, and never on one VM
per user. Sleeping users move to object storage, and awake sandboxes are packed onto a
fleet of nodes from many providers, with a lease ("a month per signup") per user. The
economics, architecture and phases are in [retrigger-fleet.md](retrigger-fleet.md).
Capacity figures in this section are per node.

## 7. Fast creation: the Retrigger base image

Without a base image, each signup downloads Ubuntu from Docker Hub inside a new microVM.
That takes minutes, and it hits Docker Hub's anonymous pull limit after about a hundred
signups per IP every few hours. This is required before real users.

**Contents**:
- The pinned Ubuntu image.
- One shared Node 22, for the harnesses that need it, instead of a private Node per
  tool.
- All seven harnesses at pinned versions, from their official installers, unmodified.
- Ollama CPU-only: its CUDA libraries are removed, because microVMs have no GPU, which
  saves about 1–2 GB.
- A non-root user `rt` (Claude Code refuses `--dangerously-skip-permissions` as root),
  `/workspace` owned by `rt`, and `tool-env.sh`.
- Package caches cleaned.

**Versions**: pinned in `retrigger-base.lock` (harness → version + checksum). The size
target is measured in the spike.

Installed but unused harnesses cost only shared disk, once. They don't change a user's
RAM or their own disk.

**Build (once per base version)**:
1. Create a builder microVM from the built-in Alpine base.
2. Pull the image once.
3. Run each harness's install script, then check each one's `--version`.
4. Stop the builder.
5. Its `system.qcow2` becomes the read-only `retrigger/bases/<version>/system.qcow2`,
   with a manifest of versions, image digest and build date.

**Per user**: `qemu-img create -f qcow2 -b <base> -F qcow2 environments/<id>/system.qcow2`
plus the saved workload. No pull and no install, so choosing a harness only activates
it. A custom harness that is not in the base installs at choice time.

**Fallback if the combined base is too big**: per-harness bases. The sandbox is
created from a minimal base at signup and re-created from the harness's base when the
user chooses. That is instant, because the sandbox holds nothing yet.

**Engine changes**:
- `create_environment` (`commands.rs:1192`; disk setup `vm.rs:695-710`) accepts an
  alternate backing base.
- The guest agent must start the workload from a locally present image without
  pulling (`workload_options.go:191-216`). If it always pulls, add a "use local if
  present" path. That needs a guest binary rebuild in the WSL build distro.

**Lifecycle**:
- Bases are refcounted; a base is never deleted while a user's disk uses it.
- New bases apply to new users. Existing users keep theirs, and harnesses that update
  themselves do so in place.
- Settings → Base images shows each version with its user count, plus Build new and
  Remove unused.

**Creation lock**: Retrigger creation uses `create:<name>` and `environment:<id>` locks,
not `feature:run_workload`. Signups then don't queue behind each other or behind the
developer's own `yougori run`. A per-app semaphore caps parallel creations (default 4).

## 8. Sign-in

Sign-in sessions live only in memory. Links, codes and terminal bytes are never written
to disk, the activity log or the audit log. After an engine restart, a sign-in in
progress goes back to `needsSignIn`.

### 8.1 `deviceCode` (Codex) and `link` (Ollama cloud)

1. Wake the sandbox.
2. Start the harness's sign-in command as user `rt` through the Retrigger exec lane
   (section 9.3).
3. Read output with cursors and strip ANSI. Extract the first `https://` link, and for
   `deviceCode` the one-time code. The exact formats are captured in the spike and kept
   as test fixtures.
4. Return `{ method, url, code?, expiresAt }` to the caller, and send
   `user.sign_in_started` with the same fields to the webhook.
5. When the command exits 0, run the manifest's `signedIn` check. Then set
   `signIn.<harness> = signedIn` and `phase = active`, and send `user.signed_in`.
6. Errors:
   - Device code turned off in ChatGPT → `device_code_disabled`, with the fix in the
     message.
   - Expired → `expired`.
   - Anything else → `failed`, retryable.
7. If a later run's output matches the manifest's `authError` patterns, the user moves
   to `needsSignIn` and Retrigger sends `user.sign_in_expired`.

### 8.2 `terminal` (Claude Code, Gemini CLI, OpenCode, Kilo Code, OpenClaw; fallback for all)

These harnesses show a link, the user signs in on the vendor's site, and then pastes a
code or key back into the harness. Vendors (Anthropic explicitly) require that this
completes through their own flow, without the developer handling the code. So:

1. `POST /users/{id}/sign-in` returns:
   ```json
   { "method": "terminal", "url": "https://<endpoint>/s/<one-time-token>", "expiresAt": "…" }
   ```
   The token is 256-bit, single-use and valid for 15 minutes.
2. The product opens that URL in a system browser sheet (`ASWebAuthenticationSession`
   or `SFSafariViewController` on iOS).
3. The page is a minimal terminal (xterm.js, already a GUI dependency) connected over a
   WebSocket to a PTY in the user's sandbox. The PTY runs the manifest's sign-in
   command, unmodified, as user `rt`.
4. The user follows the harness's own prompts: open the vendor link, sign in, paste
   the code, or choose a provider and paste their own API key. Retrigger carries
   terminal bytes only. It never parses, logs or stores them.
5. The terminal is limited to that one command. It closes when the command exits, the
   token expires, or 15 minutes pass. It is not a general shell.
6. Success is checked with the manifest's `signedIn` check: the harness's own status
   command, or a `test -s` existence check that never reads the file.
7. The page then says "Signed in. You can return to the app". It can optionally
   redirect to an app-registered callback such as `myapp://retrigger/done`.

### 8.3 Text for the developer's product

`GET /v1/harnesses` returns each offered harness with its name, sign-in method and a
`userHint`. This lets the product build its picker and instructions from the API.
Examples:

- **Codex**: "Open the link and enter code ABCD-1234. If it says device sign-in is off,
  turn on device code login in ChatGPT → Settings → Security."
- **Claude Code**: "Sign in to Claude Code with your own Claude account. Your sign-in
  stays in your private sandbox."
- **OpenCode, Kilo Code, OpenClaw**: "Choose a provider and sign in. For Claude models,
  use your own Anthropic API key."
- **Ollama**: "Connect your Ollama account to use cloud models."

The product must not present any of these as "Sign in with <vendor>" for its own
accounts.

## 9. Runs (using the user's account)

### 9.1 Commands

- Each harness's `run` manifest gives the commands (table in section 4.2).
- The prompt is written to a 0600 file in the sandbox and passed by stdin or file,
  never in argv. This avoids quoting problems, the 32 KiB command limit and
  process-list leaks.
- Ollama runs are `curl -N` to the sandbox's own API, with the request body in a file.
- Autonomy (`readOnly`, `workspaceWrite` (default), `full`) maps to each harness's own
  flags in its manifest. For example:
  - Codex: `--sandbox read-only`, `--full-auto`,
    `--dangerously-bypass-approvals-and-sandbox`.
  - Claude Code: `--permission-mode plan`, `--permission-mode acceptEdits`,
    `--dangerously-skip-permissions`.
  - At `full`, the microVM is the boundary.

### 9.2 Output

- Retrigger reads output with cursors, buffers partial lines, and forwards each line as
  a server-sent event (SSE).
- Event types:
  - `event`: the harness's own line, unchanged;
  - `session`: the resumable session ID, extracted with the manifest's `session` path;
  - `done`: exit code and duration;
  - `error`.
- Harnesses with `text` output send `chunk` events instead.
- A normalized event set (`text`, `toolUse`, `usage`) across harnesses comes later.
  Raw passthrough ships first.
- Output is not stored. The guest keeps the last 512 KiB per stream for 30 minutes, so a
  dropped stream can resume with `GET /runs/{id}/events?after=<cursor>`.
- Activity records only metadata: run ID, user, harness, start, end, exit code, byte
  counts.

### 9.3 Engine lane

`execute_guest_job` holds one of the engine's 32 regular queue slots for the whole run.
Twenty users running prompts would starve the developer's own work. Retrigger instead
gets an internal path to start, poll and cancel guest async execution directly:
- the same guest agent calls, outside the general queue;
- its own cap (default `maxRunning`);
- still one run per sandbox (`execution:<id>` lock). A second run for the same user gets
  `409 run_in_progress`.

Sign-in commands use the same lane.

Limits: `runMaxMinutes` (default 30), prompt ≤ 256 KiB, `runsPerUserPerMinute`.
`POST /runs/{id}/cancel` calls `cancel_guest_execution`.

## 10. Public API

Served by a new Retrigger gateway: axum, loopback only, its own port. It is not the
remote-sharing gateway, which stays as reviewed. One cloudflared tunnel exposes it:
- **Production**: a saved domain such as `api.example.com`.
- **Testing**: a quick link, with the warning that it changes on restart and shares the
  global quick-tunnel cooldown.

Unlike remote sharing, the endpoint restarts with the engine if it was on, because the
developer's product depends on it. This is a setting, on by default.

**Auth**:
- Secret key `rt_live_<prefix>_<secret>`: server-to-server, scoped to one app, held only
  by the developer's backend.
- User token `rt_ut_…`: minted by the backend for one user, valid ≤ 1 h, scoped to that
  user's harness choice, sign-in and runs. The iOS app can call Retrigger directly
  without ever holding the secret key.
- No cookies. CORS denied, except for the sign-in page's own same-origin WebSocket.

**Endpoints (`/v1`)**:

| Method | Path | Key | Result |
|---|---|---|---|
| GET | `/harnesses` | secret, user | Offered harnesses: id, name, sign-in method, `userHint` |
| POST | `/users` `{externalId, harness?}` | secret | `201` user, or `200` same user (idempotent on `externalId`); honours `Idempotency-Key` |
| GET | `/users?status=&cursor=` | secret | Page of users |
| GET | `/users/{id}`, `/users/by-external/{externalId}` | secret, user | User |
| DELETE | `/users/{id}` | secret | `202`; sandbox and data deleted |
| POST | `/users/{id}/harness` `{harness}` | secret, user | `202`; activates and sizes |
| POST | `/users/{id}/sign-in` | secret, user | `deviceCode`, `link`, `terminal` or `none` object (section 8) |
| GET | `/users/{id}/sign-in` | secret, user | `{state, method, url?, code?, expiresAt?}` |
| DELETE | `/users/{id}/sign-in` | secret, user | Signs out (the harness's own logout) |
| POST | `/users/{id}/start`, `/stop` | secret | Power |
| POST | `/users/{id}/tokens` | secret | `{token, expiresAt}` user token |
| POST | `/users/{id}/runs` `{prompt, sessionId?, model?}` | secret, user | SSE stream, or `202 {runId}` without `Accept: text/event-stream` |
| GET | `/runs/{id}/events?after=` | secret, user | SSE resume |
| POST | `/runs/{id}/cancel` | secret, user | Cancel |
| GET | `/health` | none | `{ok, version}` |

**Errors**: `{"error":{"code":"capacity_full","message":"…","retryable":true}}`. Codes:
- `unauthorized`, `forbidden`, `not_found`, `conflict`, `run_in_progress`
- `harness_not_offered`, `not_signed_in`, `device_code_disabled`, `sign_in_expired`
- `capacity_full`, `user_limit_reached`, `rate_limited`, `sandbox_failed`, `engine_busy`

**Limits**:
- Request body ≤ 256 KiB.
- Per key: 120 requests/min.
- Per app: `signupsPerHour`, so a mass-signup attack on the product can't fill the host.
- Per user: `runsPerUserPerMinute`.
- Concurrent SSE streams ≤ `maxRunning`.

**Webhooks out**:
- Events:
  - `user.created`, `user.sandbox_ready`, `user.harness_ready`
  - `user.sign_in_started` (includes the link and code for `deviceCode` and `link`),
    `user.signed_in`, `user.sign_in_expired`
  - `user.failed`, `user.deleted`
  - `run.completed`, `run.failed`
  - `capacity.full`
- Signing: `Yougori-Signature: t=<unix>,v1=<hex HMAC-SHA256(secret, "<t>.<body>")>` and
  `Yougori-Event-Id` for deduplication. Receivers reject timestamps more than 5 minutes
  old.
- Delivery:
  - HTTPS only, no redirects, 10 s timeout.
  - SSRF guard: refuse loopback, private, link-local and metadata addresses after DNS
    resolution. `http://localhost` is allowed only behind a per-app "development"
    switch.
- Retries from the persisted outbox: 1 min, 5 min, 30 min, 2 h, 6 h, 12 h, then marked
  failed. The GUI shows each delivery with Resend.

**Signup sources (later, optional)**: presets that accept a signup event directly, for
developers without backend logic:
- Supabase database webhook on `auth.users` insert, verified by a shared-secret header
- Clerk `user.created`, verified with Svix signatures
- Firebase Auth through a Cloud Function that calls `POST /users`

**End-to-end flow (iOS)**:

```
1. User signs up        app → backend → POST /v1/users {externalId}             → sandbox created (stopped, floor size)
2. "Which do you use?"  app → backend → GET /v1/harnesses                        → picker built from the list
                        app → backend → POST /v1/users/{id}/harness {opencode}   → activated, sized
3. Sign in              app → backend → POST /v1/users/{id}/sign-in              → {method, url, code?}
                        Codex: app shows "Open link, enter ABCD-1234"
                        others: app opens the sign-in terminal link in a browser sheet
                        backend receives user.signed_in → pushes to the app
4. Use it               backend → POST /v1/users/{id}/tokens → app holds rt_ut_…
                        app → POST /v1/users/{id}/runs {prompt} (SSE)            → streamed harness events
```

## 11. Desktop GUI

A **Retrigger** header button, text only like Neo Grid and Settings. It is registered in
`src/components/app-shell.tsx:40-53` and opens a full-window view over the overview, with
Back and Esc to return. A "database" with hundreds of rows needs more room than a dialog
gives. There are no icons: text buttons and segmented controls, as in
`environment-list.tsx`.

**Top bar**:
- App picker
- New app
- Live line: `12 running of 50 · 340 users · 3.1 GB disk · Endpoint: api.example.com (on)`

**Users** (segmented tab; default). A table cloned from `EnvironmentList`:

| User | Harness | Sign-in | Sandbox | Size | Last active | Created |
|---|---|---|---|---|---|---|
| u_12345 | Codex | Signed in | Stopped | 0.75 GB | 4 min ago | 2 Oct |
| u_12346 | OpenCode | Signing in · 11 min left | Running | 1 GB | now | 2 Oct |
| u_12347 | Ollama | Not needed | Running | 1 GB | now | 3 Oct |
| u_12348 | Not chosen | — | Stopped | 0.5 GB | — | today |

- Search (`/`), segments (All, Active, Signing in, Failed, Not chosen), a harness
  filter, sort, density.
- Bulk Stop and bulk Delete.
- Row actions: Start/Stop, Open terminal (owner shell, for support), Restart sign-in,
  Change harness, Retry (failed), Delete (`AlertDialog`).
- The expanded row shows: sandbox ID and name, base version, harness version, sign-in
  state per harness, last 20 runs (metadata), and the last error with Retry.
- Codex rows that are signing in show the code, so the developer can help a user on a
  call. Terminal sign-ins show only "Signing in".
- "Add test user" creates a user exactly as a signup would, so the whole flow can be
  tried before the product exists.

**Activity**: a live list of user, run and webhook delivery events (status, HTTP code,
attempt, Resend).

**Connect**:
- Endpoint:
  - pick a saved domain or a quick link, then Start/Stop;
  - status;
  - Test, which calls `/health` through the public URL.
- API keys:
  - Create shows the key once, with Copy and a once-only note (the vault key pattern in
    `personal-vault.tsx:92-110`).
  - The list shows prefix, created, last used and Revoke.
- Webhook: URL, events, the signing secret (shown once; Rotate), and Send test event.
- Code samples (segmented: curl, Node, Swift) with the endpoint filled in and the key as
  a placeholder.

**Settings**:
- Harnesses offered. Each shows its version, size, sign-in method and terms status.
  Claude Code opens the acknowledgement from section 2.
- Sizing: Auto (measured per harness) or overrides per harness; isolation (container
  shows the single-tenant warning); CPU weight.
- Ollama: cloud only, or local models with an allowlist.
- Idle stop: 5 min, 15 min, 1 h, never.
- Max users, max running, signups per hour, run limits, autonomy.
- Base images: versions, users per version, Build new, Remove unused.
- Delete app: removes every user's sandbox; type the app name to confirm.

**Overview integration**:
- Retrigger sandboxes are hidden from the graph.
- The List view gets a "Retrigger" type filter, off by default.
- The engine refuses share, mount, connection, publish and credential import on them.

**Files**:
- `src/api/retrigger-api.ts`, with browser-adapter fixtures
- `src/types/retrigger.ts`
- `src/components/retrigger/` (view, users table, connect, settings, activity, plus a
  `.css` per the house convention)
- live updates through a new `yougori-retrigger` event, so the platform-state event
  stays slim

## 12. CLI

Same engine methods, same data. Follows the CLI UX rules: a spinner on every wait, Back
on setup questions, Ctrl+C always works, memorable names.

```
yougori retrigger                                   interactive menu
yougori retrigger app create NAME [--harnesses codex,claude,...] [--isolation microvm|container]
yougori retrigger app list | inspect APP | update APP [...] | rm APP --yes
yougori retrigger harnesses [APP]                   built-in harnesses, versions, sizes, sign-in methods
yougori retrigger key create APP | key list APP | key revoke KEY_ID --yes
yougori retrigger webhook set APP --url URL [--events ...] | test APP | rotate APP --yes
yougori retrigger endpoint start [--domain HOST | --quick] | stop | status
yougori retrigger users APP [--status active|signing-in|failed|unchosen] [--harness ID]
yougori retrigger user add APP EXTERNAL_ID [--harness ID]        (same as a signup)
yougori retrigger user inspect|start|stop|terminal|sign-in|sign-out|retry APP USER
yougori retrigger user harness APP USER ID
yougori retrigger user rm APP USER --yes
yougori retrigger run APP USER "prompt" [--session ID]           (streams; JSON when piped)
yougori retrigger activity APP [--follow]
yougori retrigger base status | build | prune --yes
```

**Engine methods** (catalog, dispatch and contract tests, per `dispatch.rs:906-992`):

| Group | Methods |
|---|---|
| Apps | `retrigger_app_create`, `_list`, `_get`, `_update`, `_delete` |
| Harnesses | `retrigger_harness_list` |
| Keys | `retrigger_key_create`, `_list`, `_revoke` |
| Webhooks | `retrigger_webhook_set`, `_test`, `_rotate` |
| Endpoint | `retrigger_endpoint_start`, `_stop`, `_status` |
| Users | `retrigger_user_create`, `_list`, `_get`, `_delete`, `_start`, `_stop`, `_set_harness`, `_retry` |
| Sign-in | `retrigger_sign_in_start`, `_status`, `_sign_out` |
| Runs | `retrigger_run_start`, `_read`, `_cancel` |
| Activity | `retrigger_activity` |
| Base | `retrigger_base_status`, `_build`, `_prune` |

Every method also needs:
- a topic in `discovery.rs`;
- HELP and `skills/yougori/references/cli.txt` entries (`help_coverage.rs`);
- a check of whether it bypasses the queue (reads and run polling do).

Secrets are outputs only (key, webhook secret) and are printed once. Nothing secret is
ever accepted in argv.

## 13. Engine module layout

```
src-tauri/src/retrigger/
  mod.rs          manager (managed state like RemoteAccess), load, start supervisor
  model.rs        App, Member, Key, Webhook, phases; pure transition functions
  store.rs        apps.json, members/<app>.json, outbox, activity (atomic, bounded)
  harness.rs      manifest type, loader, validation; built-in manifests via include_str!
  harnesses/      codex.json, claude.json, gemini.json, opencode.json, kilo.json, ollama.json,
                  openclaw.json and their install scripts (*.sh)
  provision.rs    create from base, size per harness, start/stop/delete, wake, services,
                  idle stop, capacity + LRU, reconcile
  base.rs         base build, manifest, refcount, prune
  signin.rs       in-memory sessions; deviceCode/link parser; sign-in terminal sessions
  runs.rs         Retrigger exec lane, line splitter, session extraction, SSE fan-out, cancel
  gateway.rs      axum router, keys and user tokens, rate limits, SSE, sign-in page + WebSocket
  webhooks.rs     signer, outbox worker, SSRF guard
  commands.rs     tauri commands + dispatch functions
  tests.rs
src-tauri/src/retrigger/signin-page.html     sign-in terminal page (embedded)
```

**Harness registry as the single source**: the CLI `TOOLS` list, the GUI
`terminal-installers.ts`, the engine allowlist and `tool_credentials.rs` names are
checked against the built-in manifests by a test, the way `container_tools.rs:749-756`
already checks the GUI list.

**Hooks into existing code**:
- `models.rs`: `Environment.owner`.
- `commands.rs` / `vm.rs`: the alternate base disk.
- `commands/resource_admission.rs`: CPU weight for Retrigger-owned sandboxes.
- Runtime: per-QEMU host CPU cap.
- `remote_access.rs`, `workspace.rs` (publish), `cli/src/tool_credentials.rs`,
  share/mount paths: refuse Retrigger-owned sandboxes.
- `lib.rs`: manage the state and start the supervisor next to the other loops
  (`lib.rs:609-635`).
- `security::committed`: `retrigger.*` audit events with IDs only.
- Guest agent: start from a local image without pulling (if needed); guest firewall
  rules (section 14).
- Gateway: call `Control::handle` (widen it from `pub(super)`) with
  `security::acting_as("retrigger", …)` for lifecycle actions, so locks, the journal and
  state pushes still apply. Only runs and sign-in use the direct lane.

**Reconcile** (at start and every 5 min):
- A Retrigger-owned environment with no user is shown under Settings as "Orphaned
  sandboxes", with Delete.
- A user whose environment is gone moves to `failed (sandbox_missing)`, with Recreate.

## 14. Security

- **Cross-user isolation**:
  - a microVM per user;
  - no PC folders, connections, shares or publications;
  - no credential import;
  - harnesses run as non-root `rt` inside the hardened workload container (dropped
    capabilities, seccomp, `no-new-privileges`, 4096 process limit);
  - host CPU caps per sandbox.
- **Host reachability**: QEMU user networking lets a guest reach the host's loopback
  services through 10.0.2.2. These include the Retrigger gateway, the sharing gateway
  and the developer's own dev servers. Retrigger sandboxes get firewall rules in the
  microVM's Alpine layer, outside the workload container. They drop 10.0.2.2 except
  DNS, plus RFC 1918, link-local and metadata ranges. Add this to
  `docs/sandbox-security-review.txt` and test it.
- **Optional strict internet**, per app: a DNS allowlist built from the offered
  harnesses' vendor domains plus GitHub, npm and PyPI. Without it, user code can reach
  the internet from the host's IP, and the developer is responsible for that traffic.
- **API**: hashed keys, constant-time compare, immediate revoke, per-key and per-user
  rate limits, idempotency, body caps, loopback bind, no browser origins except the
  sign-in page.
- **Sign-in page**: single-use 256-bit token, 15-minute life, one PTY bound to one user
  and one command. Strict CSP, no third-party scripts, xterm.js bundled.
- **Secrets**:
  - The webhook secret is kept in the keyring. A headless Linux engine needs Secret
    Service; decide a fallback in Phase 5.
  - Codes and terminal bytes are never logged.
  - Prompts and outputs are never stored.
  - The audit log records IDs and states only.
- **Data deletion**: `DELETE /users/{id}` removes the disk and the record. Docs tell
  developers to send opaque IDs, not emails, as `externalId`.
- **Cloudflare**: as with sharing, Cloudflare terminates TLS and can see traffic. Say so
  in the docs.

## 15. Phases

Each phase ends with something usable and tested. Phases 1–3 work for a handful of
users on one machine.

Phases 4 and 5 below are the single-machine versions. In the fleet design they become
Phases 4–8 of [retrigger-fleet.md](retrigger-fleet.md#8-changes-to-the-main-plans-phases):
- node mode and object storage;
- scheduler and multiple nodes;
- autoscaler and providers;
- leases and plans;
- hardening.

Read Phases 4 and 5 here for their content; the fleet document gives the order.

**Phase 0 — spikes (1–2 days)**. Run all seven harnesses in a current microVM sandbox:
1. **Sign-in**, per harness: the exact command and whether it needs a PTY; the printed
   link, code and expiry formats; how success shows; a status or check command; the
   expired-auth error text; the logout command. Codex: the error shown when device code
   is disabled. Ollama: the `ollama signin` output.
2. **Headless run**, per harness: the non-interactive command, stdin or file prompt
   input, output format, where the session ID appears, resume flags, and autonomy flags
   as user `rt`. Kilo Code and OpenClaw have the least known headless modes; record
   what works.
3. **Size**, per harness: the measurement procedure from section 6, starting at the
   0.5 GB floor. Measure the cold start to a ready harness, including services.
4. **Base image**: the total size with all seven, Ollama without CUDA libraries.
   Whether a stopped microVM's `system.qcow2` can back new overlays. Whether the agent
   starts the workload without pulling (`workload_options.go`).
5. **CPU**: confirm the 1-CPU admission cap in practice. Test the Windows job object
   CPU rate on a QEMU process.
6. **Guest reachability**: confirm a guest reaches host loopback via 10.0.2.2 today.

Output: `docs/retrigger-spike.txt` with captured, redacted outputs. These become the
seven manifests and the test fixtures.

**Phase 1 — engine core, all harnesses, desktop view (local only)**
- `Environment.owner`, the `retrigger/` module, the store, the state machine, and the
  harness registry with the seven manifests.
- Provisioning on the current path (pull plus pinned installs) with the Retrigger
  creation lock and per-harness sizing.
- Activation; `deviceCode`, `link`, `none` and terminal sign-in, with the terminal shown
  inside the desktop app (not public yet); services; idle stop and wake.
- Catalog methods; CLI `app`, `harnesses`, `user`, `users` and `activity`; GUI Users,
  Activity and Settings with "Add test user".

Done when, for each of the seven harnesses, "Add test user" → choose the harness → sign
in with a real account (Ollama local: none) shows "Signed in", then idle stop → wake
keeps the sign-in. Checked from both the GUI and the CLI.

**Phase 2 — public endpoint, keys, webhooks**
- The axum gateway, endpoint start/stop on a saved domain or quick link, auto-restart,
  secret keys.
- `/harnesses`, `/users`, `/harness` and `/sign-in`, plus start/stop/delete.
- The public sign-in terminal page; the webhook outbox with signing, retries and SSRF
  guard.
- GUI Connect tab; CLI `key`, `webhook`, `endpoint`.
- `examples/retrigger/`: a small Node backend and a SwiftUI sample with a harness
  picker, the code screen and the terminal sign-in in `ASWebAuthenticationSession`.

Done when a curl script against the public URL completes signup → harness → sign-in →
`user.signed_in` webhook, and an iPhone signs in to Codex (code) and Claude Code
(terminal) through the sample.

**Phase 3 — runs for every harness**
- The Retrigger exec lane, `/runs` with SSE, resume, cancel, sessions, user tokens and
  limits.
- Raw passthrough for every harness, plus session extraction per manifest.
- CLI `retrigger run`; run metadata in the GUI.

Done when an iPhone streams an answer from each of the seven harnesses through a user
token, continues the conversation where the harness supports it, and resumes a dropped
stream.

**Phase 4 — scale**
- The base image with all harnesses (build, overlays, refcount, prune, GUI Base
  images) and parallel creation.
- CPU weight and host CPU caps; capacity, LRU stop and `capacity_full`; reconcile and
  orphans.
- Load test: 200 signups in a burst, then 25 concurrent runs across mixed harnesses.
  Record creation time, cold start per harness, RAM per sandbox, state file size and
  app responsiveness.

Done when a signup is ready in under 5 s without network pulls and the numbers are in
`docs/retrigger-load-test.txt`.

**Phase 5 — hardening, terms, release**
- Guest firewall rules, optional strict internet, and a security review section.
- A terms review per harness and sign-in type, plus the acknowledgement flows.
- Standalone engine on a Linux server (KVM) as the recommended production host, with a
  keyring fallback.
- Custom harness manifests: a developer adds any CLI agent by describing its install,
  sign-in and run commands; validated, then built into a new base.
- Normalized run events across harnesses.
- A shared read-only Ollama model disk.
- Signup-source presets (Supabase, Clerk, Firebase).
- User docs `docs/retrigger.md`, skill and `cli.txt` updates, release through the normal
  runbook.

## 16. Testing

- **Unit**:
  - state transitions;
  - manifest validation;
  - `deviceCode` and `link` parsers on captured fixtures for each harness;
  - line splitter across chunk boundaries and session extraction per manifest;
  - key hashing; webhook signature against fixed vectors;
  - SSRF guard (IPv4, IPv6, DNS rebinding);
  - rate limiter; capacity, CPU weight and LRU choice; idempotent create.
- **Engine integration**: gateway over real HTTP, like `remote_access/tests.rs:242`
  (auth, scopes, errors, SSE and resume). Webhook delivery against a local receiver,
  with retry and restart persistence.
- **Contract**: the existing catalog, dispatch, help coverage, schema size and topic
  tests cover the new methods. A new test checks the four tool lists against the
  harness registry.
- **CLI**: the interactive `yougori retrigger` menu through the ConPTY harness (pywinpty
  + pyte; answer DA1).
- **GUI**: vitest component tests for every table state and the once-only key reveal,
  with a mocked API. Playwright with browser-adapter fixtures (an app with users in
  every state and harness), and "Retrigger" added to the header-button loop in
  `e2e/app.spec.ts:12`.
- **Real**:
  - an end-to-end script per harness with real test accounts;
  - an iPhone run of the sample app;
  - the Phase 4 load test;
  - the guest-to-host reachability test before and after the firewall rules.

## 17. Decisions needed (recommendation first)

1. **Name**: `Retrigger` / `yougori retrigger`, as you said. Rename now if you meant
   "Trigger"; it touches every method name.
2. **Paste-back sign-ins** (Claude Code, Gemini CLI, OpenCode, Kilo Code, OpenClaw): the
   sign-in terminal page (recommended; the only shape that fits Anthropic's terms) rather
   than a code field in the app.
3. **Production host**: a Linux server running the standalone engine (recommended for
   24/7 uptime) versus this Windows PC. This changes Phase 5's priority.
4. **What users get beyond prompts**: prompts only in v1 (recommended), or also files
   and a terminal in the app.
5. **GUI shape**: full-window view from a header button (recommended) versus a large
   dialog like the other features.
6. **Ollama**: cloud models only by default (recommended; keeps sandboxes at ~1 GB), or
   local models allowed per app.
7. **Fleet decisions**: who runs the control plane, the default lease, the first
   providers and object storage. See
   [retrigger-fleet.md, section 11](retrigger-fleet.md#11-decisions).
