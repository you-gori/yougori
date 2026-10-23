# Yougori from the CLI — command list and build status

Goal: someone runs one install command, gets `yougori` in their terminal, and can do everything the desktop app does without opening it — create environments and Hugging Face models, move files in and out of any environment, share volumes, open ports, publish to the local network or a public domain, share environments, and reach the Personal Vault. Projects carry their own Yougori files, and agents read a preferences file that suggests the user's usual choices but always asks first.

## Status

The interactive CLI offers **Open terminal here** under **Manage an environment**. Containers, GPU containers and built-in microVMs also offer to start and open their terminal after creation. The guest shell uses the current console; `exit` or Ctrl+] returns to the menu and leaves the environment running. Stopped or paused guests require a start choice, while busy or failed guests are left alone. Full VMs use their environment console window instead.

The command catalog and backend dispatch cover the desktop commands, with deliberate desktop-only exceptions described below. This is source-level coverage, not a claim that every provider, guest type, installer, and hardware path has passed an end-to-end test. What still needs a running engine or real hardware is at the end of this section.

**Current CLI-only limits**
- Personal Vault item entry and approval still open the focused desktop window. `vault status` and `vault mcp` work from a terminal, but the full vault workflow cannot be completed without Desktop under the current approval design.
- Guest application windows and the dashboard require Desktop. The CLI can request those windows but the standalone engine has no display.
- Copying files **out of a full VM** is not implemented in the desktop or CLI file service. Use the VM's own SSH file transfer. Copying files *into* full VMs uses an imported-files drive.
- The friendly `neocloud` commands cover provider discovery, price comparison, creation and lifecycle actions. Price comparison ranks only explicit live USD hourly quotes and reports missing provider CLIs, unsupported integrations, unpriced offers and other currencies separately. Actual provisioning and billing behavior still require tests against each configured provider account.

**Audit on 2026-09-26**
- The current source advertises 147 backend methods. The desktop-command contract test passes, and all CLI unit/command tests pass. An isolated real transport test passed across disposable containers, sharing, private connections, terminal access, snapshots, backup, a microVM and a full VM. GPU, provider-account billing, and non-Windows installers remain unverified on real hardware.
- The engine currently running on this development PC was built before the control pipe was renamed. Its bundled CLI can reach it; a CLI built from current source cannot. Exit that old headless engine normally, then restart from current sources before interpreting a failed live `app status` as a new-engine defect. Development startup now rebuilds the bundled CLI before registering it on PATH; release packaging bundles the CLI before checking release evidence.

**Phase 1 — commands and two-way sync**
- Engine-owned shared state: saved domains (`savedDomains`, moved from the app's browser storage on first start) and model chat history (one file per model under `model-chats/`, moved from browser storage on first open). The app updates live when the CLI changes either.
- Checking: `status`, `ps --type`, `top`, `ports list --all`, `volume ls`, `domain list`, `model usage|access|history`, `cloud show`, `lan list`, `vault status`, `doctor`; tables in a terminal, JSON when piped, `--format` to choose.
- Files: `cp` into (optionally `ENV:/folder`), out of (`ENV:/path PC_FOLDER`, never overwriting) and between environments; `ls`; `volume cp` both ways through a running environment that mounts the volume; `drives`.
- Domains: `domain list|add|remember|remove`, `--domain` on `ports publish` and `remote start` for any app port. `domain remember ENV --port N --yes` copies a node's remembered tunnel into reusable saved setups without exposing its token.
- Models: `model chat` continues the app's conversation and settings (`--new`, `/new`), `model history|usage|access`.
- Friendly verbs for every former call-only method: `rename`, `env startup|install-skills`, `storage`, `cloud …`, `lan …`, `project …`, `agent setup`.

**Phase 2 — approvals**: vault decisions stay in the focused app window, as the security model requires. `vault approve|add|open` bring that window forward from the CLI; `vault status` reports only a running flag and a waiting count. Tokens still arrive via `--file`.

**Phase 3 — install and upkeep**: `scripts/install/install.ps1` and `install.sh`; `doctor`; `app autostart` with a background-engine mode; `update` (SHA-256 plus same-publisher signature on Windows); `uninstall` (keeps data).

**Phase 4 — project files**: `init` (yougori.yaml, `.yougoriignore`, `.yougori/PREFERENCES.md`, `.gitignore` entries), `.yougoriignore` applied by the engine to every copy from the PC (CLI and drag-and-drop), `prefs path|show|remember|forget`, and the agent skill's ask-first rules.

**Phase 5 — volumes, standalone engine, cloud lookups**
- Volumes: the guest agent lists named volumes with the containers using them and removes unused ones (`/v1/volumes/action`). `volume ls [--scan] [--size]`, `volume rm`, `volume prune [--yes]`, and a Volumes section in Settings. Removal is refused while any environment or container mounts the volume. The appliance and GPU payloads were rebuilt with Go 1.26.
- Standalone engine: `engine/` builds `yougori-engine`, the same engine without WebView, windows or tray (Tauri's windowless runtime), so it needs no display. The CLI starts it when the desktop app is missing (or with `app start --engine`). `npm run engine:package` makes the engine-only archive; the command-line installers install it by default; `update` updates it.
- Cloud lookups: `cloud options KIND` (regions, images, machine types, subnets, security groups, key pairs, resource groups, local SSH public keys) through the signed-in provider CLI, read-only. The app's deploy dialog shows them as suggestions.

**Needs you or real hardware**
- Publish on yougori.com (private website repo). `npm run release:manifest -- --base-url https://yougori.com/releases/VERSION windows-x86_64=SIGNED_SETUP.exe windows-x86_64-engine=artifacts/engine/….zip …` writes `artifacts/website/` (`releases/latest.json`, `install.ps1` pinned to the signer read from the signed installer, `install.sh`). Upload the assets to that base URL and copy the folder to the site.
- Sign releases (`YOUGORI_SIGN_CERT_SHA1`); no code-signing certificate is installed on this PC. `npm run engine:package` signs the engine when it is set.
- Try on real machines: the macOS and Linux installers and engines, `update --yes`, and copying out of a cloud server and a shared environment.
- GPU runtimes installed before this change keep their old agent until GPU setup runs again, so `volume rm` skips GPU volumes on them.

## One engine, two front ends

Project launcher links are development previews. The shared proxy prevents browser and CDN caching on local, LAN, temporary-link and saved-domain responses, and removes GET/HEAD cache validators so old cached assets receive a fresh response after restart. The same proxy is used for cloud project launches. No project-specific Vite configuration is required. After updating an older launcher, relaunch the project and hard-refresh any browser that already cached its assets; already-running launchers keep their bundled helpers until the next launch.

The app and the CLI are two windows onto the same engine and the same data. Whatever is created, changed or deleted in one appears in the other, and both can be used at once.

- Both call the same engine, so environments, connections, ports, publications, shares, snapshots, backups, saved domains and model conversations are shared.
- A CLI change is pushed to the open app immediately (`yougori-platform-state`, `yougori-model-chat-history`); the app also refreshes every 2 seconds.
- The engine runs one operation at a time for conflicting changes.
- Display-only state (graph layout, view mode, tour progress) stays in the app.

The standalone engine (`yougori-engine`) is the same engine built without the desktop runtime. It uses the same data folder and control pipe, and only one engine runs at a time. It has no dashboard: `app show` hands its environments to the desktop app when nothing is running, and otherwise says what to stop. Guest, app and service windows and Personal Vault approvals need the desktop app.

Rule for new features: anything a user creates or chooses is stored by the engine, never only in the app, and every app action gets a matching CLI command in the same change. The engine's contract test fails when an app command has no CLI entry, unless it is deliberately app-only (vault management, Market sign-in in the app, streaming chat channels, one-time migrations).

## Command list

`yougori help` prints everything; `yougori schema METHOD` gives exact parameters.

For agents, `yougori agent inventory` returns a finite, secret-free JSON capability map across local, shared, cloud and provider-managed environments. It identifies exact IDs, current resource allocations, guest-command and file-transfer readiness, and where a full VM needs guest SSH or a shared node needs a grant. `yougori run` finishes with JSON when stdout is piped (use `-d` explicitly in scripts), and `yougori logs ENV` returns one JSON `logs` field; neither command mixes streamed text into machine-readable output. `-it` still requires a terminal. Agents can then upload with `cp`, run with `exec`, inspect the guest exit code and logs, and stop compute when authorized work is finished.

For Neocloud, agents should offer a local functional trial first. `neocloud plan` returns `localTrial.runArgs` only when the provider's image is a runnable OCI image; otherwise it explicitly requires an equivalent local image. A GPU workload needs an NVIDIA GPU container for a meaningful GPU trial. After reviewing trial logs and command results, the agent can compare live provider prices and present the options. Cloud creation is a separate billable choice, creates a fresh resource, and requires selected-file transfer plus a second check in the cloud. A local workload failure should be fixed before paying for cloud compute; a local capacity limit is a reason to consider cloud.

### Install, health and upkeep
| Command | What it does |
|---|---|
| `irm https://yougori.com/install.ps1 \| iex`, `curl -fsSL https://yougori.com/install.sh \| sh` | Verified install for this user, `yougori` on PATH, then `doctor`; installs only the engine and CLI by default; download the desktop app separately |
| `app start [--engine] \| status \| show \| quit` | Start/stop the background engine (`--engine`: the standalone one), open the dashboard |
| `app autostart on [--dashboard] \| off \| status` | Start the engine at login (background by default) |
| `doctor` | Engine, runtimes, GPU, disk, PATH and start-at-login, with fixes |
| `update --check \| --yes`, `uninstall --yes` | Signed updates; removal that keeps data |
| `init` | Project files (section below) |

### Check everything
| Command | What it shows |
|---|---|
| `status` | Engine, environments by type, published links, sharing, saved domains, connections, jobs |
| `ps [--type container\|gpu\|model\|microvm\|vm\|cloud\|shared\|app]` | Every environment of every type |
| `top [--once]` | Live CPU, memory, storage and network |
| `inspect ENV`, `logs ENV`, `env console ENV` | One environment in detail |
| `ports list ENV \| --all`, `connection list`, `share list ENV` | Ports, links, connections, PC folders |
| `remote list`, `lan list` | People and networks with access |
| `volume ls \| inspect`, `domain list`, `snapshot list`, `backup list` | Storage and publishing resources |
| `model status \| usage \| access \| history ENV` | Models |
| `cloud show ENV`, `vault status`, `gpu status`, `storage location`, `jobs list` | Everything else |

### Environments
`run`, `create`, `start`, `stop`, `restart`, `rm ENV --yes`, `exec`, `rename`, `pull`, `images`, `image rm`; `vm run`, `microvm run`; `env pause|open|resources|storage|internet|gpu|reset|recover|startup|install-skills`; `changes ENV`; `env duplicate` via `call duplicate_local_environment|duplicate_environment`.

### Files and volumes
| Command | What it does |
|---|---|
| `cp PC_PATH... ENV[:/folder]` | Into local containers, microVMs, full VMs and connected cloud servers (a drive for full VMs; a folder choice for containers and microVMs). Importing into a remote shared environment is not supported. |
| `cp ENV:/path PC_FOLDER` | Out of containers, microVMs, cloud servers and shared environments; never overwrites. Full VMs need guest SSH transfer. |
| `cp ENV_A:/path ENV_B[:/folder]` | Between environments |
| `ls ENV [PATH]` | Browse folders |
| `share add \| list \| remove` | Live PC folder mounts |
| `volume ls [--scan] [--size] \| inspect \| cp` | Named volumes, sizes and users, including ones left by deleted environments; copies go through a running environment that mounts them |
| `volume rm NAME --yes \| prune [--yes]` | Delete unused volumes and their data (refused while mounted) |
| `drives list \| attach \| detach` | A VM's imported-files drives |
| `connection create --permissions volumes --volume NAME` | Share a volume between environments |

### Ports, local network, public access and domains
`ports list|add|remove|publish|unpublish`; `ports publish ENV --port N --kind local|cloudflare`; `ports publish ENV --port N --domain HOST`; `domain list|add|remember|remove` (new token via `--file -`, or `domain remember ENV --port N --yes` for an already remembered token).

### Sharing
`remote create|list|start [--domain HOST]|stop|update|revoke|remove|connect|files|download`; `lan share|list|revoke|import`.

### Hugging Face models
`model run hf.co/OWNER/MODEL [--api --port N]`, `model chat ENV [--new]`, `model history|status|api|access|usage ENV`.

### Cloud servers
`cloud scan|test|add|configure|connect|disconnect|show|auth|options|deploy|power|delete`. `cloud options KIND --provider P --account A [--region R]` looks up values for the deploy request.

`neocloud providers|list|discover|prices|compare|quote|plan|create|inspect|start|stop|delete|recover` covers provider-CLI-backed resources. `neocloud prices --product gpu --hours 8 --min-vram-gb 24 --max-hourly 2 --format table` checks configured provider CLIs in parallel and ranks only explicit live USD hourly compute prices. `neocloud quote --provider vast --offer 123 --hours 8` focuses on one exact offer without creating it. `neocloud plan --file request.json` validates a provider request (`{"request":{...}}`) without creating a resource or claiming account/price readiness. The report keeps unavailable, unpriced, differently denominated, and unsupported providers visible without treating them as free or cheaper. `--location` supplies a Civo region or Nebius project ID; it is not a global geographic filter. Cost estimates omit storage, network, taxes and charges that may continue after stopping. `create`, `start`, and `delete` require `--yes`; deletion also requires the exact resource name.

### Projects, snapshots, backups, GPU
`up|apply|down [-f yougori.yaml]`, `import compose.yaml`, `project list|inspect`; `snapshot …`; `backup …`; `gpu status|setup|test`.

### Personal Vault
`vault mcp`, `vault status`, `vault open|approve|add` (brings the app forward; the person decides there).

### Agents and the rest
`skills print|install`, `agent setup`, `env skills ENV`, `terminal …`, `microvm apps|open`, `window …`, `market discovery|login|status|logout`, `settings get|set`, `jobs …`, `prefs …`, `schema`, `call`.

## Yougori project files

| File | Purpose | Commit it? |
|---|---|---|
| `yougori.yaml` | Declares environments, ports, volumes, connections, publishing | Yes |
| `.yougoriignore` | Gitignore syntax; what copies from this folder leave behind | Yes |
| `.yougori/PREFERENCES.md` | Project-level preferences for agents | If the team agrees |
| `.yougori/local.yaml` | Personal overrides | No (added to `.gitignore`) |
| `.yougori/state.json` | Machine-specific IDs | No (added to `.gitignore`) |

`yougori init` never overwrites existing files, and points to `yougori import` when a Compose file exists. The `.yougoriignore` template leaves out version control, dependencies, build output, logs, and secrets (`.env`, `.env.*`, `*.pem`, `*.key`, `*.p12`).

## The preferences file (agent harness)

1. Agents read `~/.yougori/PREFERENCES.md`, then `.yougori/PREFERENCES.md` (`yougori prefs show`); the project file wins.
2. Preferences only suggest: "You usually publish with a Quick link — use that again, or crm.prompx.com?"
3. Always ask before acting. Ask every time for anything billable, public, destructive, involving credentials, PC folder access or Full control sharing.
4. After the user confirms a choice they want remembered: `yougori prefs remember KEY VALUE [--project]`, which records a count and date.
5. Secrets are refused.

## Decisions taken

- Windows first; macOS and Linux installers are written but unverified.
- The command-line installers install the standalone engine and CLI by default. Download the desktop app separately. The existing `YOUGORI_ENGINE_ONLY=0` override explicitly selects the desktop bundle when needed.
- Preferences are saved only when the user confirms "remember this".
- `.yougoriignore` excludes `.env` and key files by default.
