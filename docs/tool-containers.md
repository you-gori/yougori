# Tool shortcuts in your terminal

```powershell
yougori codex
yougori claude
yougori gemini
yougori opencode
yougori kilo
yougori ollama
yougori openclaw
```

The first command creates a sandbox, installs the selected tool, and starts it in
the terminal where you ran the command. Later calls reuse the tool's sandbox and
installed binary. Files in `/workspace` and tool sign-in stay in that sandbox. The
desktop terminal view does not open.
Before creating a sandbox for any tool, Yougori asks you to choose CPU cores and
RAM using the same arrow-key sliders as the main CLI. You can also type a number
and press Enter to confirm. Defaults are 2 CPU cores and 4 GB RAM, capped by the
computer's capacity; storage defaults to 20 GB. The choices appear before creation
and installation. `--cpu` and `--memory` skip their respective sliders; supplying
both skips the resource prompt. Reconnecting reuses the saved resources without
prompting or resizing. Use `--new` to choose resources for a fresh sandbox.
Cancelling this prompt creates nothing, and `--dry-run` never prompts.

Every wait shows a spinner: starting Yougori, loading your sandboxes, starting a
stopped sandbox and creating a new one. Ctrl+C stops waiting and ends the command;
work Yougori already started keeps going, so check it with `yougori ps`. Keys
typed while waiting are dropped and never answer a later question.

Each question after the first offers Back: press Esc or choose the Back row, and
the earlier question appears again with your last answer selected. Ollama's GPU
question and the CPU and memory sliders form one group; the sign-in, public link
and `--share` questions after installation form another. Going back never undoes
what an answer already did: a copied sign-in stays copied, and a link or teammate
access that was created stays. Asking about a public link again then defaults to
keeping the link you have.

## One microVM per sandbox

Each new sandbox is its own microVM: it boots its own kernel with minimal virtual
hardware, and the tool runs there in a hardened container from Ubuntu 24.04
pinned by digest (`ubuntu:24.04@sha256:534baea6…30eb55`, the 2026-09-17 build),
not a moving tag. Sandboxes therefore never share a kernel with each other: code
that escapes one tool's container still has to break out of its microVM before it
can reach another sandbox, its PC folders or its imported sign-ins. The
hypervisor, host kernel and computer remain trusted, so this is a stronger
boundary, not an absolute one. The first start boots the microVM and downloads the
pinned image inside it, so it takes longer than a container.

`--isolation container` opts out. The sandbox is then a container in Yougori's
shared VM, which shares that VM's kernel with your other containers.
`--isolation microvm` is accepted and is the default.

| | microVM (default) | container (`--isolation container`) |
|---|---|---|
| Kernel | its own | shared with your other containers |
| GPU (`--gpu nvidia`, Ollama's GPU answer) | not available | available |
| PC folders at creation (`--mount`) | not available yet | available |
| Copy this computer's sign-in | asked on every launch | asked on every launch |
| `yougori exec` and `cp`, folders shared with teammates | the tool's container | the tool's container |
| PC folders added later (`yougori share add`), connection folders | mounted in the tool's container | mounted in the tool's container |
| Public project link, `--share`, Ctrl+C stop menu | available | available |

Options that need a container fail with a message that names
`--isolation container`; Yougori never switches to a container on its own. Reuse
matches isolation: `yougori codex` reuses a microVM sandbox and
`yougori codex --isolation container` reuses a container sandbox. Existing
sandboxes keep their isolation and are never converted. If the tool already has a
container sandbox, the first microVM launch creates a new sandbox and prints how to
reconnect to the container. In a microVM, `yougori exec`, copied sign-ins,
`yougori cp` in both directions and folders you share with teammates use the
tool's container, where its terminal runs, not the microVM's own minimal guest.
PC folders you add with `yougori share add` and folders from connections are
mounted there too, under `/yougori/shared`.

Tool setup shows an animated loading bar and elapsed time. Package-manager and
download logs stay offscreen. Yougori verifies success and closes the separate
setup terminal before showing sharing prompts or opening the tool; no Enter is
needed to advance after setup. Keys typed while setup is running do not answer
later prompts. If setup fails, a bounded error summary appears. Ctrl+C still
opens the sandbox stop menu during setup.

`yougori ollama` asks "Want a GPU container for Ollama?" GPUs need container
isolation, and the question says so: "Yes, give Ollama a GPU" creates or reuses
an NVIDIA GPU container, which shares Yougori's VM kernel with your other
containers. "Use a CPU microVM" runs models on the CPU in a microVM (with
`--isolation container`, a CPU container). Yougori reuses only a matching managed
Ollama sandbox; switching modes creates/reuses another sandbox and preserves the
previous one. `--isolation microvm`, `--isolation container --gpu nvidia` or
`--environment` skips the question and keeps that choice.

Ollama starts its model API on port 11434 in a separate quiet terminal. Startup
uses an animated loading bar, then verifies the API and opens an "Ollama ready"
menu: Run a model, Open sandbox shell, Refresh models, or Back to my terminal.
It reuses a responding server instead of starting a duplicate. Normal server logs,
key generation and GPU discovery do not fill the host terminal. No model is downloaded
until you choose one. Returning keeps the model server and sandbox running; Ctrl+C
still opens the sandbox stop choices. Custom tool arguments keep their normal behavior.

OpenClaw starts interactive `onboard`; complete its
own account setup and permissions there. Other shortcuts start the tool's usual
interactive interface.

Every interactive launch, including reconnects and `--share`, asks by the tool's
name, for example "Use your Claude Code sign-in from this computer?" "No, sign in
inside the sandbox" is selected by default and keeps the sandbox's current
sign-in. "Yes, copy it into this sandbox" copies only the selected tool's
supported credential files and replaces matching files in the sandbox. Credentials
are transferred as files, never printed or put in shell arguments, and installed
with owner-only file permissions. Host originals stay unchanged; this is a copy,
not ongoing synchronization. MicroVM and container sandboxes work the same: the
files land in the tool's own home directory. Ctrl+C while copying cancels the
transfer, removes the staged copy and opens the stop menu; Cancel there asks
again. If a copy fails, Yougori shows why and continues, so you can sign in
inside the tool.

File imports support Codex, Claude Code, Gemini CLI, OpenCode, Kilo Code, and
Ollama's cloud identity. OS keychains, VS Code extension storage, environment-only
API keys, and OpenClaw's database credential store are not imported. OpenClaw is
still asked, but explains why and offers only No; sign in during its onboarding.
Missing or expired credentials fall back to the tool's normal sign-in. Custom
provider configuration is not copied. Local Ollama models do not require
authentication.

Anyone controlling the sandbox, including existing recipients and teammates added
with `--share`, can use or read imported credentials and consume that account's
credits. The credential prompt explains this before anything is copied.

```powershell
yougori codex --new --memory 8GB
yougori claude --name writing
yougori codex --isolation container
yougori kilo --isolation container --mount ./site:/workspace/site
yougori gemini --environment EXISTING_SANDBOX
yougori codex -- --help
yougori ollama -- run MODEL
yougori openclaw -- gateway run
yougori kilo --dry-run
```

Creation options (`--image`, `--cpu`, `--memory`, `--storage`, `--storage-drive`,
`--gpu nvidia`, and `--mount`) need a new sandbox; `--gpu nvidia` and `--mount`
also need `--isolation container`. MicroVM sandboxes need at least 6 GB of storage.
`--image` changes the image the tool runs in for either isolation. Tools default to
CPU microVMs; Ollama uses the GPU choice above. PC folders are not shared by
default. `--environment` explicitly installs/runs the tool in a chosen local
container or microVM with Yougori's built-in guest instead. Put tool arguments
after `--`. `--dry-run` reports the `isolation` it would use (`null` with
`--environment`, which keeps that sandbox's isolation).

Ctrl+] closes this terminal session and returns to your host terminal. The
sandbox, files and sign-in remain; the attached program can stop when its
terminal closes. Exiting the tool also returns to the host terminal. Before the
tool opens, Yougori prints the shortest reconnect command: `Reconnect: yougori
codex` when the plain shortcut reuses this sandbox, otherwise `yougori codex
--environment NAME` with the sandbox's name (its ID only when another sandbox
answers to the same name). `yougori stop ENV` stops the sandbox.
Once the sandbox is in use, Ctrl+C opens Yougori's arrow-key menu with Cancel
selected by default. Cancel returns to the same session, question or wait without
sending Ctrl+C to the tool. Stop sandbox disconnects everyone and keeps the
sandbox and its data. Stop and delete first stops the sandbox, then permanently
removes it and its managed data. Each action requires Enter; repeated Ctrl+C or
Escape presses cannot confirm it. The menu works the same for microVM and
container sandboxes, including during installation and the sign-in, public link
and sharing questions. While a public link or teammate access is being created,
the menu opens as soon as that finishes; a second Ctrl+C quits at once. Remote/SSH
shells keep their usual guest interrupt behavior.
Noninteractive calls require `--dry-run`, which validates without creating,
installing or starting anything. `yougori TOOL --help` lists all options.

## Give your project a public link

Every tool shortcut asks "Want your project on the internet right away?" after
installation. "Not yet, let's build first" continues with existing access settings.
Choose "Yes, let's give it a link" to select an application port, then a temporary
quick HTTPS link or one of your saved domains. The default project port is 3000;
choose the port your website will actually listen on. This is separate from Ollama's
model API on port 11434 inside the sandbox. The website can call that internal API.
Domains already used by another service are disabled and their routes are preserved.
Create a domain setup in Yougori's Public access setups first if none are listed.

Yougori creates the tunnel immediately, prints the full URL and asks you to copy it
before continuing into the tool. The link starts serving the website or HTTP API
as soon as it listens on the selected port inside the sandbox; a tunnel URL alone
does not mean the project is already running. Keep the owner computer and Yougori
running. Anyone with the link can reach the selected service. Quick links can change
after a restart. `yougori ports list ENV` shows publications; disconnect an exact
route with `yougori ports unpublish PUBLICATION_ID --yes`.

These prompts use the same CLI styling and Ctrl+C stop choices as sharing. Cancelling
before publication creates no link. Cancelling after creation leaves the confirmed
publication available while the sandbox runs. `--dry-run` never prompts or publishes.
The public project link and `--share` teammate connection links are separate flows:
public access publishes the selected service; teammate links open authenticated shells.

## Share a tool sandbox

```powershell
yougori codex --share
yougori claude --share
yougori opencode --share
```

The tool commands and sharing flow use Yougori's existing animated wordmark,
colors, progress display, masked password inputs and arrow-key menus.

`--share` works with every tool shortcut and with `--new`, `--name`, or
`--environment`. Yougori installs/checks the tool first, offers credential import
and project public access, then asks how many
teammates to add, their individual usernames and passwords, and an access expiry
(24 hours, 7 days, or 1 hour). Back keeps the answers already given; a password
you go back to is typed again. It uses the existing password-protected sharing
gateway. Each teammate gets their own grant and link with control of this sandbox,
its files and any tool sign-in or connections available inside it.

Before opening the tool, Yougori prints connection commands for PowerShell 7 and
macOS/Linux, including each teammate's password. Copy the appropriate command
and choose Open tool to launch it. Passwords are hidden while entered and are
not saved by the CLI, although copies made while creating invites can remain in
its memory until it exits. The gateway stores only salted verifiers. Printed
commands can remain in terminal scrollback; commands used by recipients can also
appear in shell history and process arguments. Recipients can leave the password
out of the command (`yougori connect LINK USERNAME`) and type it privately.

```powershell
yougori connect 'https://example.com/share/share-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' 'alice' 'your-share-password'
```

The recipient connects directly to a shell in the same sandbox in their current
terminal and runs `codex` (or the other installed tool) there. Each connection has
its own terminal session; everyone uses the same sandbox files and tool sign-in.
Use separate quoted arguments; credentials are not part of the HTTPS URL.
The owner must keep their computer, Yougori, sandbox and gateway running.

Updated clients and engines carry terminal input and output through a persistent
binary stream, including the sandbox agent when it supports streaming. Keyboard
input and output run independently. Older engines, guest agents, LAN invitations
and SSH cloud environments use independent read/write polling as a compatibility
path. Update both teammates' engines/CLIs and the sandbox guest agent for the full
streaming path; updating only the CLI still improves keyboard handling.

Streams enforce the existing recipient permissions, target and terminal ownership.
Revocation, expiry and engine shutdown close access. Queues and recent output are
bounded. If a connection drops, Yougori reports it and never automatically resends
uncertain keyboard input. Reconnecting opens a new shell in the existing sandbox;
it does not resume the previous terminal session.

For optional diagnostics, set `YOUGORI_TERMINAL_TRACE=1` before connecting. After
a normal terminal exit, the CLI prints stream-opening duration, attached duration
and input/output byte counts. Terminal contents and credentials are not recorded.
Quick tunnel links can change after the gateway restarts; fetch current links
with `yougori remote list`. Closing the owner's tool terminal leaves grants and
the running sandbox available until expiry or revocation.

```powershell
yougori remote list
yougori remote revoke SHARE_ID --yes
```

If account creation or gateway startup fails, Yougori reports completed recipient
IDs and stops before opening the tool. Inspect these before retrying, so an
ambiguous failed request cannot silently create duplicate grants. Cancelling
before final confirmation creates no recipients. Cancelling after the commands
are printed leaves the confirmed shares available.
Choosing Cancel from the Ctrl+C stop menu returns to the current sharing step
and retains teammates already entered; choosing Stop or Stop and delete ends
the flow after the selected lifecycle action.
