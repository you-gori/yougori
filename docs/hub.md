# Yougori Hub: templates and tools

The Hub is where people share whole Yougori setups (templates) and tools for sandboxes.
Anyone with a Yougori account can publish. Everything on the Hub is public and open source,
and free: templates and tools cannot be sold. Other people find them on
https://yougori.com/hub, read every file, and run them with one command:

```text
yougori run hub/PUBLISHER/NAME
```

Nothing on the Hub is checked by Yougori. Only templates and tools uploaded by the Yougori
owner account carry the **Verified** badge. Every other page, and every run, shows the same
warning:

> Not checked by Yougori. Community templates can contain harmful code, including viruses.
> Read the files first and run only what you trust.

This file is the reference for the template and tool formats, the commands, the Hub API and the
behaviour every part must keep. The website code lives in the private website repository
(`server/hub/`, `src/hub/`); the CLI code in `cli/src/hub/`.

## 1. Words

| Word | Meaning |
|---|---|
| Template | A folder that describes a whole setup: `yougori-template.yaml` + a normal `yougori.yaml` project + the app's files. |
| Tool | A folder with `yougori-tool.yaml`: how to install, check, sign in to and open one program inside a sandbox. |
| Item | A template or tool on the Hub, addressed as `PUBLISHER/NAME`. |
| Version | One immutable upload of an item, labelled with a semantic version such as `1.2.0`. |
| Instance | One running copy of a template on a computer. It has its own name, so two copies never collide. |
| Clone | A different computer that ran or downloaded an item: the CLI counts each computer once per item with its install id (`~/.yougori/hub/install-id`), and only when the website answered; browser downloads count once per address. |
| Publisher | The account's public name. It is shared with the model library (`yg/PUBLISHER/...`). |
| Owner | The Yougori owner account (the account that already moderates Swarm Mining). Its uploads are the only Verified ones. |

## 2. Addresses

- Hub item: `PUBLISHER/NAME`. Both parts: lowercase letters, digits, `-` or `_`, starting with a
  letter or digit, at most 64 characters.
- CLI reference: `hub/PUBLISHER/NAME`, optionally `@VERSION` (`hub/acme/my-api@1.2.0`).
  The CLI also accepts the page address: `https://yougori.com/hub/PUBLISHER/NAME`
  (and `yougori.com/hub/...`). `yougori run` leaves anything with a `:` after `hub/` to images
  (`hub/library/nginx:1.27`, `hub/a/b@sha256:…`), and `hub/x` alone is an image too.
- File paths inside an item (the CLI and the website apply the same rule, `checkPath`):
  relative, `/` between folders, no leading or trailing `/`; at most 512 characters in all and
  255 per name, counted in UTF-16 units as JavaScript counts them; no empty, `.` or `..` part; none
  of `\ : * ? " < > |`, no control character (U+0000 to U+001F, U+007F), no bidi control (U+061C,
  U+200E, U+200F, U+202A to U+202E, U+2066 to U+2069) and no invisible character (U+200B to
  U+200D, U+2060 to U+2064, U+FEFF); no name ending in a dot or a space; no Windows device name
  in any letter case, with or without an extension (CON, PRN, AUX, NUL, CONIN$, CONOUT$, COM0 to
  COM9, LPT0 to LPT9, COM¹ COM² COM³ LPT¹ LPT² LPT³). Two paths that are the same after NFC
  normalisation and lowercasing are the same file (as on Windows and macOS), and a file may not
  have the name of a folder (`app` beside `app/server.js`). A version that breaks the rule cannot
  be published; a downloaded one is refused with "this version has a file name Yougori cannot
  store on this computer (PATH)".
- Web pages: `/hub` (explore), `/hub/PUBLISHER` (publisher), `/hub/PUBLISHER/NAME` (item),
  `/hub/publish` (how to publish, your items), `/hub/admin` (owner only).
- Reserved publisher names (only the owner may use them): `hub`, `publish`, `admin`, `api`,
  `new`, `explore`, `search`, `settings`, `help`, `about`, `docs`, `account`, `login`, `signin`,
  `signup`, `tools`, `templates`, `trending`, `reports`, `yg`, and any name whose look-alike form
  (lowercase; `0→o 1→l 3→e 4→a 5→s 7→t 8→b`; `-` `_` removed) contains `yougori`, `official` or
  `verified`. A new publisher name whose look-alike form equals an existing publisher's is
  refused ("too similar to an existing publisher").

## 3. Template format

A template folder contains:

- `yougori-template.yaml` (required): what the Hub and the CLI need to know.
- `yougori.yaml` (required, or the file named by `project:`): a normal Yougori project. It is
  parsed with the exact same strict rules as `yougori up`.
- `README.md` (recommended): shown on the Hub page.
- `LICENSE` (recommended): the open-source licence text.
- Any app files the project copies in with `files:`.
- Bundled tools, each in its own folder with a `yougori-tool.yaml`.

### 3.1 `yougori-template.yaml`

```yaml
kind: template            # optional; template is the default
name: my-api              # Hub name (see Addresses)
title: My API             # optional, at most 80 characters; defaults to the name
summary: A private model API website built from four Yougori sandboxes.   # required, at most 200
version: 1.0.0            # required: MAJOR.MINOR.PATCH, optional -prerelease
license: MIT              # required: an SPDX id from the open-source list below
topics: [ai, api, website]  # optional, at most 10, lowercase words with dashes
project: yougori.yaml     # optional, default yougori.yaml
changelog: First release. # optional, at most 4000 characters; shown under Versions

requires:                 # all optional
  yougori: 1.1.0          # minimum Yougori CLI version
  gpu: optional           # none (default) | optional | required
  platforms: [windows-x86_64, linux-x86_64]   # empty = every platform

inputs:                   # questions asked when someone runs the template
  - id: access            # [a-z][a-z0-9_]{0,31}, unique
    question: Where should the website be reachable?
    type: choice          # choice | text | number | secret | domain | yesno
    choices:
      - {value: quick, label: Quick link, hint: Free HTTPS link from Cloudflare. It can change after a restart.}
      - {value: domain, label: My own domain, hint: A domain you saved with yougori domain add.}
      - {value: none, label: Only this computer}
    default: quick
  - id: domain
    question: Which saved domain?
    type: domain
    when: {access: domain}   # asked only when another answer matches
  - id: admin_email
    question: Admin email for the website
    type: text
    pattern: "^[^@\\s]+@[^@\\s]+$"
    hint: Used to sign in to the admin page.
  - id: openai_key
    question: OpenAI API key (optional)
    type: secret
    required: false

tools:                    # environment name in yougori.yaml -> tools installed in it
  paid: [codex, claude, gemini]
  free: [opencode, kilo]
  local: [ollama]
  web: [tools/gateway]    # a bundled tool folder, or hub/PUBLISHER/NAME[@VERSION]

public:                   # internet access, set up after the environments start
  - environment: web
    port: 3000
    access: "{{inputs.access}}"   # quick | domain | none, literally or from an answer
    domain: "{{inputs.domain}}"   # required when access is domain

steps:                    # what a person does afterwards; shown at the end and in status
  - title: Sign in to Codex, Claude Code and Gemini
    detail: Each opens in this terminal. Sign in, then press Ctrl+] to come back.
    command: yougori codex --environment {{env.paid}}

outputs:                  # shown at the end of a run and in status
  - label: Website
    value: "{{public.web}}"
```

Rules:

- `inputs[].type`:
  - `choice` needs 2–12 `choices` (`value` slug, `label` at most 60, optional `hint` at most 160).
  - `text` (at most 500 characters, optional `pattern`), `number` (optional `min`, `max`),
    `yesno` (answers `yes` or `no`), `domain` (a saved domain name; the CLI lists saved domains).
  - `secret` answers are never written to disk, logs or the Hub. The CLI stores each one as a
    deployment secret named `hub-INSTANCE-ID` and the project refers to it as
    `{{secrets.ID}}` in `secrets:` (for example `secrets: {OPENAI_API_KEY: "{{secrets.openai_key}}"}`).
  - `required` defaults to true; `default` must be a valid answer; `when` names one earlier
    input and the answer that makes this question appear.
- `title`, `summary` and `changelog` are counted in UTF-16 units, trimmed, and must be plain:
  no control characters (the changelog may have tabs and line breaks), no bidi or invisible
  characters, no more than 2 combining marks in a row. Title and summary may not contain the word
  verified (in any case, as a whole word) or check marks (U+2713, U+2714, U+2611, U+2705,
  U+1F5F8), and the title not the word official: "Only Yougori shows the Verified badge; leave that
  word and check marks out." Without a title, the name is the title and follows the same rule.
- Placeholders are replaced inside string values only, after the YAML is parsed, so an answer can
  never change the structure of the file:
  - `{{inputs.ID}}` (not allowed for secret inputs), `{{secrets.ID}}` (only in `secrets:` values),
  - `{{instance}}` (the instance name), `{{env.NAME}}` (the environment's sandbox in this instance:
    `INSTANCE-NAME`, or the new name the engine gave it when an update replaced it),
  - `{{public.NAME}}` (the environment's public address; only in `outputs`).
  Unknown placeholders are errors at `template check` time. Steps and outputs may show answers to
  ordinary inputs (that is what they are for), never a secret: `{{secrets.ID}}` and secret input ids
  are refused there. No placeholder may choose a path on this computer: `files` sources, PC
  folders (`bind: true` volumes, `pc_access`) and a VM's `source` are fixed paths inside the
  template folder, and the run checks them again after filling in the answers, before it stores a
  secret or writes a file.
- `ports` lists container ports only (`ports: [3000]`). `check` and `publish` refuse a fixed host
  port (`"8080:3000"`): a second copy of the template could never start. A template uploaded
  without the CLI that has one still runs: every port opens inside its sandbox only, and the run
  says so above the review.
- A tool from the Hub must name its version at `check` and `publish` (`hub/acme/aider@1.0.0`), so
  everyone who runs the template installs the same files. A tool that signs in with an API key
  needs a sandbox that can receive it (a container, or a microVM with an image).
- `tools` keys must be environment names in the project. Built-in tool names: `codex`, `claude`,
  `gemini`, `ollama`, `opencode`, `kilo`, `openclaw`. Anything else is a relative path to a bundled
  tool folder or a `hub/PUBLISHER/NAME[@VERSION]` tool reference.
- `public[].environment` must exist in the project and `port` must be one of its `ports` targets.
- The project's own `project:` name is ignored: each instance uses the instance name.
- A template may not use `pc_access`, writable PC folders (`bind: true` volumes) or
  `permissions.pc` unless the runner accepts it separately (see Running).

### 3.2 Open-source licences accepted

`MIT`, `MIT-0`, `Apache-2.0`, `BSD-2-Clause`, `BSD-3-Clause`, `ISC`, `0BSD`, `Unlicense`,
`CC0-1.0`, `Zlib`, `BSL-1.0`, `MPL-2.0`, `EPL-2.0`, `EUPL-1.2`, `Artistic-2.0`,
`LGPL-2.1-only`, `LGPL-2.1-or-later`, `LGPL-3.0-only`, `LGPL-3.0-or-later`,
`GPL-2.0-only`, `GPL-2.0-or-later`, `GPL-3.0-only`, `GPL-3.0-or-later`,
`AGPL-3.0-only`, `AGPL-3.0-or-later`.

## 4. Tool format: `yougori-tool.yaml`

```yaml
kind: tool
name: aider
title: Aider
summary: AI pair programming in your terminal.
version: 1.0.0
license: Apache-2.0
topics: [coding, ai]
command: aider                  # the program; opened in a terminal for the person
install:                        # shell lines run in the sandbox, in order, stopping at the first failure
  - python3 -m pip install --user --break-system-packages aider-chat==0.86.1
check: aider --version          # must succeed after installing
signin:                         # optional
  method: browser               # none | browser | device | api-key
  command: aider --login        # browser/device: opened in a terminal for the person
  variable: OPENAI_API_KEY      # api-key: the environment variable the key goes into
needs:                          # optional
  gpu: none                     # none | optional | required
  memory: 4GB
  internet: true
service:                        # optional long-running server inside the sandbox
  command: aider --serve --port 8080
  port: 8080
```

- `command` and `check` are single shell lines (at most 4096 characters); `install` has at most
  32 lines. They run as the sandbox user with `$HOME/.local/bin` on `PATH`.
- A line that downloads (`curl`, `wget`, `http://`, `https://`, `pip install`, `npm install`,
  `apt-get`) is listed on the review screen with the address it fetches from.
- API keys are asked with a hidden prompt (or read from stdin in scripts), stored as a deployment
  secret and passed to the tool as the named variable. They are never part of the tool or template.

## 5. Command line

All commands print text in a terminal and JSON when piped or with `--format json`.
Every wait shows a spinner, every question offers Back, and Ctrl+C always stops.

### 5.1 Running

```text
yougori run hub/PUBLISHER/NAME[@VERSION] [--name INSTANCE] [--input ID=VALUE]... [--inputs FILE]
                                         [--secrets -] [--yes] [--allow-pc-access] [--dry-run]
yougori template run hub/PUBLISHER/NAME[@VERSION] | ./FOLDER   (same options)
yougori template continue INSTANCE [--yes] [--input ID=VALUE]... [--inputs FILE] [--secrets -]
                                   [--allow-pc-access]
yougori template status [INSTANCE]
yougori template list
yougori template update INSTANCE [--yes] [--allow-pc-access] [--input ID=VALUE]... [--secrets -]
yougori template down INSTANCE
yougori template rm INSTANCE --yes [--delete-data]
```

A run goes: download → verify → requirements → review → questions → create → tools → public
access → steps and outputs.

1. **Download and verify.** The CLI fetches the version's files straight from the website,
   checks every SHA-256 and the version digest, and keeps a copy in
   `~/.yougori/hub/cache/PUBLISHER/NAME/VERSION`. Only when the website cannot be reached at all
   (no connection, a timeout) does a copy already on this computer run, with a notice; it then
   counts as a community item, since nothing can confirm its badge. An error answer (even 5xx), a
   removed item (410) or a version that does not exist never falls back to a saved copy. A saved
   copy reused online takes its Verified badge and kind from the page, never from the list saved
   beside it. If the copy cannot be saved (a full disk, another run saving the same version), the
   run goes on with the checked download and says so.
2. **Requirements.** Yougori version, platform and GPU are checked before anything is created.
   A missing GPU offers: run without it (only when `gpu: optional`), or cancel.
3. **Review.** Built on this computer from the files themselves, never from the Hub page:
   sandboxes and isolation, total CPU, memory, disk and GPU, public links, internet, PC folders,
   connections, tools with their sources and the addresses their installers download from, and
   the questions it will ask. Unverified items show the warning above the review. Nothing is
   created until the person chooses **Run it**; scripts must pass `--yes`. PC access needs its own
   yes (`--allow-pc-access` in scripts). If the Hub page's summary differs from the files, the CLI
   says so.
4. **Questions.** Asked one at a time with Back. Scripts pass `--input ID=VALUE`, `--inputs FILE`
   (JSON object; secrets are refused there) and `--secrets -` (JSON object on stdin).
5. **Create.** The project is filled in and checked first; secrets are stored only after that.
   The instance folder `~/.yougori/hub/instances/INSTANCE` gets a copy of the files and a
   generated `yougori.yaml` (project name = instance). The CLI then runs the same reconciliation
   as `yougori up` and records each sandbox's ID and real name (including what a failed attempt
   made). Every port opens inside its sandbox only. Instance names: the template name, or `--name`.
   If an instance of the same template exists, a person chooses Open (or Continue) the existing
   one / Create another (`NAME-2`); scripts are told its `template continue` command, or pass
   another `--name`.
6. **Tools.** Built-in tools are installed with the same quiet installer as `yougori codex` when a
   person is at the terminal; in scripts they become steps. Custom tools install through their
   `install` lines and must pass `check`.
7. **Public access.** Quick links and saved domains are set up exactly like `yougori ports publish`.
   A publication is reused only when it already serves the port that way: a Cloudflare quick link,
   or for a domain exactly `https://DOMAIN`; a loopback publication never counts.
8. **Clone count.** A run of a Hub item adds this computer once to the item's clones. It comes last,
   waits five seconds at most, and never stops a run; `counted` is recorded only when the website
   answered.
9. **End.** Outputs (addresses) and the steps that need a person, then
   `Status: yougori template status INSTANCE`.

If a part fails, everything already created stays, the instance is marked incomplete, and the
message names the part, the fix and the two commands `yougori template continue INSTANCE` and
`yougori template rm INSTANCE --yes`. Ctrl+C stops at once and prints the same two (or, when the
command had not created anything yet, says so).

`template continue INSTANCE` carries an instance on from its own record: the same source and
version and exactly the same files (a Hub instance uses its checked copy, so it keeps working
after the item left the Hub; a folder instance refuses when its folder changed and points to
`update`), its stored answers, and only the questions it has no answer for. It runs only the parts
that did not finish, makes again sandboxes deleted elsewhere (with their tools and public access),
starts a stopped instance, and finishes an update that stopped. A ready instance just shows its
status. Scripts pass `--yes`.

Only one command changes an instance at a time (`~/.yougori/hub/locks/INSTANCE.lock`); another one
says so and changes nothing. A run that stopped without saying so (its window was closed) is still
`creating` with nobody holding it: it reads, and is saved, as `incomplete`.

`status` shows each sandbox, public addresses (refreshed by the rule of step 7), steps, the
template version, whether a newer version exists (asked for five seconds at most), and a notice if
the item was removed from the Hub (with the reason). `status` and `list` say `ready`, `incomplete`,
`creating` or `stopped`.

`update` moves to the newest version (a folder instance: to the folder as it is now) and shows what
it changes: new sandboxes; a new image, type or GPU, which replaces the sandbox (the engine keeps
the old one, stopped, with its data, and the tools are installed again in the new one); public
links; tools; questions; PC access (its own yes) and download addresses. It asks only questions
without an answer, offers to run without the GPU when the new version allows it, backs up files
you changed in the instance folder to `~/.yougori/hub/backups/INSTANCE/`, and applies the version.
The version it moves to is recorded apart from the instance's own (`updating`) until every part
finished; `continue` finishes an update that stopped. Tools of the template's own are installed
again; built-in ones are kept. Public links, tools, steps and outputs the new version no longer
lists are dropped. A stopped instance is started for the update and stopped again.

`rm` lists what it removes: every sandbox the instance made, including ones an update replaced and
ones a newer version no longer lists, its stored secrets and its folder; named volumes are kept
unless `--delete-data`. When the instance's record is missing or cannot be read, it finds the
sandboxes by the instance's folder and their names. The engine keeps its record of the project
folder (there is no engine call to forget one); a new instance with the same name reuses it.

### 5.2 Making and publishing

```text
yougori template new [NAME]                 Starts a template folder
yougori template check [FOLDER]             Validates it and shows its review
yougori template capture ENV... [--output FOLDER]   Turns running environments into a template
yougori template publish [FOLDER] [--yes]   Uploads a new version to the Hub
yougori template download REF [FOLDER]      Saves a version's files
yougori template info REF                   Shows the item, its counts and its review
yougori template search [WORDS] [--sort popular|trending|stars|new|updated] [--kind template|tool]
yougori template fork REF [--name NAME]     Copies an item into your publisher name
yougori template star|unstar REF
yougori template report REF --reason harmful|stolen|abuse|other [--details TEXT]
yougori template delete REF --yes           Removes your own item from the Hub
```

- `capture` copies settings only. It never copies disks, sign-ins, environment variable values,
  credentials or data. Values become secret inputs; PC folders are left out. Everything it left
  out is listed in the output and in the generated README.
- `publish` needs `yougori login`. It runs `check`, scans for secrets, shows the name, version,
  licence, file count and size, and says that the upload is public and open source. Versions can
  never be replaced: publish a higher version instead. Before anything is sent it checks what the
  website and the engine would refuse: the marker file must say `name:` and `version:` on exactly
  one top-level line each (and `kind:`, if present, must match), the manifest must be at most
  64 KiB and the review at most 128 KiB as JSON and of the shape in section 7, and the whole
  upload description must fit one 1 MiB request to the engine; a refusal names the largest part.
- An upload that stops (a lost connection, Ctrl+C, a failure on the website) is kept in
  `~/.yougori/hub/uploads/PUBLISHER/NAME@VERSION.json` (upload id, item, version, kind, digest and
  what arrived). Publishing the same files again within the 24 hours the website keeps an
  unfinished upload carries it on: files that arrived are skipped, a file sent partly continues
  from the byte the website names ("Send PATH from byte N"), failures on the way are tried again
  twice, and an upload the website no longer has is started once more. Each new upload counts
  toward the day's 20.
- The credential scan (the same on the website, `server/hub/scan.mjs`) reads every file: UTF-8
  text (without its byte-order mark); UTF-16 text with a byte-order mark, or recognised by its zero
  bytes over the first 4 KiB (mostly zero odd bytes: little-endian; mostly zero even bytes:
  big-endian); and every other file byte by byte, since the keys searched for are plain ASCII.
  Findings in a binary file name the file but no line. It refuses:
  - files inside `.git`, `node_modules`, `.venv`, `venv`, `__pycache__` or `.ssh`; key files
    (`id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519`, `*.p12`, `*.pfx`, `*.kdbx`); credential files
    (`.credentials.json`, `.git-credentials`, `.netrc`, `_netrc`, `.pypirc`, `auth.json` under
    `.codex`, `.opencode`, `opencode`, `kilo` or `.kilo`);
  - `.env` and every `.env.*` file except `.env.example`, `.env.sample`, `.env.template` and
    `.env.defaults`. Those may hold values, except that a secret-like variable must be empty or a
    placeholder: "Leave DB_PASSWORD empty in .env.example (line 3), or write a placeholder such as
    your-key-here." A variable is secret-like when its name, split on `_` and `-`, has a part equal
    (in any case) to KEY, KEYS, TOKEN, TOKENS, SECRET, SECRETS, PASSWORD, PASSWORDS, PASSWD, PASS,
    PWD, CREDENTIAL, CREDENTIALS or PRIVATE, or when it contains PASSWORD, SECRET, TOKEN or APIKEY
    anywhere (AUTH alone is not). A line is `[export ]NAME=VALUE`; the value is cut at the first
    whitespace followed by `#`, trimmed, and unquoted when it is wrapped in matching quotes;
  - an `.npmrc` line `_authToken=…` with a value that is not `${VARIABLE}`;
  - a private key: a `-----BEGIN … PRIVATE KEY-----` header followed by key material (optional
    whitespace, then 40 base64 characters `[A-Za-z0-9+/=]`, or `Proc-Type:`); a header alone, in
    code that reads keys or in documentation, is fine;
  - API keys and tokens, each at a word boundary: OpenAI and Anthropic `sk-` (20 or more of
    `[A-Za-z0-9_-]`), GitHub `ghp_` `gho_` `ghu_` `ghs_` `ghr_` (exactly 36 letters and digits),
    `github_pat_` (50 or more), AWS `AKIA`/`ASIA` (exactly 16 capitals and digits), Slack `xoxb-`
    `xoxa-` `xoxp-` `xoxr-` `xoxs-` (10 or more), Google `AIza` (35, then a word boundary), Hugging
    Face `hf_` (30 or more letters and digits, then a word boundary), Stripe `sk_live_` and
    `rk_live_` (20 or more) and Yougori `ygs_`/`ygw_` (30 or more).
  A match is not a key when it is an obvious placeholder, matching
  `(?:x{6,}|\*{6,}|0{12,}|your|example|placeholder|replace|redacted|dummy|change-?me|<|\$\{)`
  in any case (`sk-your-key-here`, `change-me`). The key patterns run on example environment
  files too. Wallet addresses (`0x` + 40 hex at word boundaries) are allowed but noted on the
  review. Messages never repeat the secret.
- Skipped when collecting a folder: `.git`, `node_modules`, `.venv`, `venv`, `__pycache__`,
  `target`, `dist`, `.DS_Store`, `Thumbs.db`, and anything in `.yougoriignore`. Links are not
  followed. Limits: 1000 files, 5 MiB per file, 25 MiB per version.

### 5.3 Tools

```text
yougori tool new [NAME]                       Starts a tool folder
yougori tool check [FOLDER]                   Validates it
yougori tool add FOLDER | hub/PUBLISHER/NAME[@VERSION]   Saves it on this computer
yougori tool list                             Built-in and added tools
yougori tool remove NAME --yes
yougori tool install NAME --environment ENV   Installs it into a sandbox and runs its check
yougori tool open NAME --environment ENV      Installs if needed, then opens it in this terminal
yougori tool publish [FOLDER] [--yes]         Uploads it to the Hub
```

Added tools live in `~/.yougori/tools/NAME`. Built-in tools keep their own shortcuts
(`yougori codex`, …); `tool open codex --environment ENV` does the same as
`yougori codex --environment ENV`.

`tool add hub/PUBLISHER/NAME` downloads and checks the tool, shows its review (install lines,
download addresses, check, command, sign-in; the community warning above it when it is not
Verified) and asks before saving it; scripts pass `--yes` after reading the review with
`template info`. The first `tool add` of an item counts this computer as a clone. `tool install`
of a community tool says once more that its install lines are not checked (a `warning` in JSON).

A sandbox remembers which version of a tool it installed
(`$HOME/.local/share/yougori/tools/NAME` holds a SHA-256 of the tool's name, version, install
lines and check). An install is skipped only when that matches and the check passes, so a new
version of a tool (in a template update too) is installed again even though the old one's check
still passes.

### 5.4 The desktop app

The app's sidebar has a **Hub** section with three views:

- **Explore**: search, sort (most cloned, trending, stars, newest, updated), templates or tools,
  Verified only. An item shows the same warning, README, files, "What it creates" and versions as
  the website. Reads go through the engine's website proxy (`model_registry_request` with
  `/hub/…` paths), which also signs starring in with the account.
- **On this computer**: every instance, read from `~/.yougori/hub/instances/*/instance.json`
  (engine command `hub_instances`), with its state, public addresses, outputs, steps, and what
  failed and the exact command to continue.
- **Publish**: choose a template or tool folder.

Run, Add tool, Publish, Status, Continue, Update and Remove open a console window with the
bundled CLI (engine command `open_hub_console`), so a person sees exactly the review, questions
and confirmations of section 5.1 and decides there. The engine accepts only these argument lists,
checked before anything starts: `run hub/P/N[@V]`, `template run hub/P/N[@V]`,
`tool add hub/P/N[@V]`, `template|tool publish FOLDER` (an existing absolute folder without quotes
or `%`), `template status|update INSTANCE`, `template continue INSTANCE` (action `continue`),
`template rm INSTANCE --yes` (after a confirmation in the app). The console sets
`YOUGORI_HUB_CONSOLE=1`; the CLI then waits for Enter (or Ctrl+C) before the window closes, after
a success and after an error alike.

The app's Continue button runs `next` from `instance.json` (`failed.next` when present, which is
the same command). While a command holds an instance, the CLI rewrites `updatedAt` in
`instance.json` every 30 seconds. An instance whose `state` is `creating` with an `updatedAt` older
than 120 seconds is a run that stopped without saying so: the app shows it as "Not finished"
("The run stopped before it finished.") with the Continue button.

`instance.json` (schema 1, written atomically by the CLI, never containing answers or secrets;
`inputs` lists only the ids of the questions answered):

```json
{"schema": 1, "name": "my-api", "ref": "acme/my-api", "source": "hub", "folder": null,
 "kind": "template", "title": "My API", "version": "1.0.1", "digest": "…", "verified": false,
 "state": "ready", "failed": null, "createdAt": 0, "updatedAt": 0,
 "environments": {"web": "env-…"}, "public": {"web": "https://…"},
 "steps": [{"title": "…", "detail": "…", "command": "…"}], "outputs": [{"label": "…", "value": "…"}],
 "inputs": ["access", "openai_key"], "next": "yougori template continue my-api"}
```

`state` is `creating`, `ready`, `incomplete` or `stopped`; `failed` is null or
`{"part", "message", "next"}` with `part` one of `environments`, `tools`, `public` or `update`.
`next` is always there, also while `creating`.

## 6. Hub API (website)

All JSON. Errors: `{"error": "plain sentence", "code": "machine_code"}` with a 4xx/5xx status.
Public reads need no sign-in. Writes need a website session (cookie, same origin) or a client
session (`Authorization: Bearer ygs_…`). Every route is also served under
`/api/market/registry/hub/…`, which is how the CLI's signed-in requests reach it through the engine.

### 6.1 Reading

| Route | Answer |
|---|---|
| `GET /api/hub/items?q=&kind=&topic=&sort=&verified=1&publisher=&page=` | `{items: [Summary], total, page, pageSize}`; sort `popular` (default, clones), `trending` (clones in the last 7 days), `stars`, `new`, `updated` |
| `GET /api/hub/items/:pub/:name?version=` | `{item: Detail}` |
| `GET /api/hub/items/:pub/:name/files?version=&path=` | without `path`: `{files: [File]}`; with `path`: `{path, bytes, sha256, text: true, content}` or `{…, text: false}` |
| `GET /api/hub/items/:pub/:name/bundle?version=` | `Bundle` (used by the CLI; not counted) |
| `GET /api/hub/items/:pub/:name/archive?version=` | `.tar.gz` of the version for browsers; counts a clone |
| `GET /api/hub/items/:pub/:name/forks` | `{items: [Summary]}` |
| `GET /api/hub/publishers/:pub` | `{publisher: {name, verified, joinedAt, items, clones, stars}, items: [Summary]}` |
| `GET /api/hub/stats` | `{items, templates, tools, publishers, clones, topics: [{topic, items}]}` |
| `POST /api/hub/items/:pub/:name/clones` | body `{version, install}` (install: 16–128 characters `[A-Za-z0-9_-]`); `{clones}` |

`Summary`:

```json
{"ref": "acme/my-api", "publisher": "acme", "name": "my-api", "kind": "template",
 "title": "My API", "summary": "…", "topics": ["ai"], "license": "MIT",
 "verified": false, "latestVersion": "1.0.1", "createdAt": 1760000000, "updatedAt": 1760100000,
 "counts": {"clones": 12, "clonesWeek": 3, "stars": 4, "forks": 1, "versions": 2},
 "forkedFrom": null}
```

`Detail` = `Summary` plus:

```json
{"state": "active", "removed": null, "starred": false, "mine": false,
 "forkedFrom": {"ref": "other/my-api", "available": true},
 "versions": [{"version": "1.0.1", "createdAt": 0, "digest": "…", "verified": false,
               "fileCount": 12, "bytes": 34567, "clones": 3, "changelog": "…"}],
 "version": {"version": "1.0.1", "createdAt": 0, "digest": "…", "verified": false,
             "fileCount": 12, "bytes": 34567, "readme": "markdown or null", "changelog": "…",
             "files": [{"path": "yougori.yaml", "bytes": 512, "sha256": "…", "text": true}],
             "manifest": {}, "review": {}, "notices": ["Contains a wallet address in app/config.js"]}}
```

A removed or deleted item answers `200` with `state` `removed` or `deleted`,
`removed: {reason, message, at}`, empty `versions`, and `version: null`; its files, bundle and
archive answer `410`. Items of banned accounts behave as removed (`reason: publisher_banned`)
until the account is restored.

`Bundle`:

```json
{"ref": "acme/my-api", "publisher": "acme", "name": "my-api", "kind": "template",
 "version": "1.0.1", "digest": "…", "verified": false, "createdAt": 0,
 "files": [{"path": "yougori.yaml", "sha256": "…", "bytes": 512, "content": "base64"}]}
```

The digest is the SHA-256 of the lines `SHA256  PATH\n` (two spaces, like `sha256sum`) for every
file, sorted by path as bytes.

### 6.2 Writing (signed in)

| Route | Body → answer |
|---|---|
| `GET /api/hub/me` | `{publisher: name|null, owner: bool, items: [Summary], starred: [Summary]}` |
| `POST /api/hub/uploads` | `Upload` → `{upload: {id, expiresAt, maxBatchBytes}}` |
| `POST /api/hub/uploads/:id/files` | `{files: [{path, content, offset?}]}` (base64, at most 600 KB of JSON per request) → `{received, remaining}` |
| `POST /api/hub/uploads/:id/finish` | `{}` → `{item: Detail}` |
| `POST /api/hub/items/:pub/:name/star` | `{starred: true|false}` → `{starred, stars}` |
| `POST /api/hub/items/:pub/:name/fork` | `{name?}` → `{item: Detail}` |
| `POST /api/hub/items/:pub/:name/report` | `{reason: harmful|stolen|abuse|other, details?}` → `{reported: true}` |
| `POST /api/hub/items/:pub/:name/delete` | `{confirm: "pub/name"}` → `{deleted: true}` |

`Upload`:

```json
{"kind": "template", "publisher": "acme", "name": "my-api", "version": "1.0.1",
 "title": "My API", "summary": "…", "license": "MIT", "topics": ["ai"], "changelog": "…",
 "manifest": {}, "review": {},
 "files": [{"path": "yougori.yaml", "bytes": 512, "sha256": "…"}]}
```

A file arrives whole (`offset` 0 with all its bytes) or in consecutive parts: the first with
`offset` 0, each next one starting where the last ended. A part that does not continue is refused
with `offset_mismatch` ("Send PATH from byte N"); size and SHA-256 are checked when the last part
arrives (`checksum_mismatch`). Small files share a request; large ones are split, so no request
passes the 1 MiB the engine forwards. The engine passes on only the error's sentence, so the CLI
recognises these by their wording, which a website test keeps: "Send PATH from byte N",
"This upload does not exist…", "This upload expired…", "This upload is already published." and
"… not arrived yet …".

`manifest` is the parsed `yougori-template.yaml` (or `yougori-tool.yaml`) as JSON; `review` is the
review the CLI computed (section 7). The website's own folder upload sends the fields it can read
from the file's top-level lines and no review; its "What it creates" tab then says so. The first upload claims the publisher name if the account has
none; the account's existing name must be used otherwise.

### 6.3 Owner

| Route | Answer |
|---|---|
| `GET /api/hub/admin/reports?state=open|closed` | `{reports: [{id, item: Summary, reason, details, reporter, createdAt, state}]}` |
| `POST /api/hub/admin/items/:pub/:name/remove` | `{reason: harmful|stolen|abuse|illegal|other, note?}` → `{removed: true}` |
| `POST /api/hub/admin/items/:pub/:name/restore` | `{}` → `{restored: true}` |
| `POST /api/hub/admin/reports/:id/close` | `{}` → `{closed: true}` |

### 6.4 Limits

- 1000 files, 5 MiB per file, 25 MiB per version; paths follow the rule in section 2 (at most 512
  characters and 255 per name, UTF-16 units; no forbidden, control, bidi or invisible characters;
  no Windows device names; no two names one computer stores as the same file; no file named like
  a folder).
- Text, trimmed and counted in UTF-16 units: title at most 80, summary at most 200 (both one line),
  changelog at most 4000 and report details at most 2000 (tabs and line breaks allowed); none may
  hold control, bidi or invisible characters or more than 2 combining marks in a row.
- Manifest at most 64 KiB and review at most 128 KiB as JSON; the review must have the shape of
  section 7 (lists of objects for `environments`, `public`, `connections`, `tools`, `inputs` and
  `pcAccess`; lists of text for `steps` and `warnings`; objects for `totals`, `requires` and
  `needs`; an object or null for `service`; values nested at most four deep; every text at most
  4000 characters without control or bidi characters).
- Versions: semantic versions `MAJOR.MINOR.PATCH[-PRERELEASE]`, each number at most 9 digits
  without leading zeros, numeric prerelease parts without leading zeros (`1.0.0-rc.01` is refused),
  no build part, at most 64 characters.
- 100 items per publisher, 200 versions per item, 20 uploads per account per day.
- A new version must be higher than the item's latest version.
- Uploads expire after 24 hours if not finished.
- 120 stars, 20 reports and 20 forks per account per hour; 60 clone counts per address per hour.

## 7. Review

Computed by the CLI from the files (and shown by the website as the publisher's CLI sent it).
Every text in it is made plain first (control characters other than tab and line breaks, bidi and
invisible characters are left out; a text longer than 4000 characters is cut with "…"), so a
review always has the shape the website accepts. `format` is 1. A run compares the page's review
with its own only when both have the same format, and only in the parts that decide what a
template does to a computer (`environments`, `totals`, `public`, `pcAccess`, each tool's name,
source, environment, downloads, commands, check and command, `inputs`, `warnings`, and a tool's
`needs` and `service`); a page without a review, or with one in another format, is not compared.

```json
{"format": 1,
 "environments": [{"name": "web", "type": "container", "image": "node:24", "cpu": 2,
                   "memoryGb": 4, "storageGb": 20, "gpu": false, "internet": true,
                   "ports": [3000], "tools": ["codex"], "secrets": ["OPENAI_API_KEY"],
                   "pcAccess": [], "writablePcFolders": false}],
 "totals": {"environments": 4, "cpu": 8, "memoryGb": 16, "storageGb": 80, "gpu": "optional"},
 "public": [{"environment": "web", "port": 3000, "access": "quick"}],
 "connections": [{"from": "web", "to": "paid"}],
 "tools": [{"name": "codex", "source": "built-in", "environment": "paid"},
           {"name": "gateway", "source": "bundled", "environment": "web",
            "downloads": ["https://registry.npmjs.org"], "commands": ["npm install -g …"]}],
 "inputs": [{"id": "access", "question": "…", "type": "choice", "secret": false}],
 "steps": ["Sign in to Codex, Claude Code and Gemini"],
 "pcAccess": [],
 "warnings": ["Installs software from https://…"],
 "requires": {"yougori": "1.1.0", "gpu": "optional", "platforms": []}}
```

## 8. Scenarios

These scenarios guide the implementation and its automated checks. Runtime tests against real
containers, GPU hardware and Cloudflare accounts remain separate from the unit and browser suites.

**Creating**
1. An agent builds a setup from a prompt: it writes the template folder, `template check` passes,
   `template run ./folder` runs it locally (not counted), and it is published only when asked.
2. `capture` of a hand-built setup with signed-in tools and a `.env` file leaves sign-ins and values
   out, lists them, and turns values into secret inputs.
3. A setup with a PC folder: `capture` leaves it out and says so; publishing never includes it.
4. A real API key in a file: `check` and `publish` refuse, naming the file and line.
5. `node_modules`, `.git` and build output are skipped; limits are enforced with a plain message.
6. A new version that adds a sandbox, public link, tool or PC access: `update` shows it and needs a
   new yes.
7. The publisher deletes an item: new runs are refused with the reason; running instances keep
   working; forks stay; the name cannot be reused.
8. Republishing the same version, or a lower one, is refused: versions never change.
9. Forks keep a link to the original; the licence carries over; a fork is never Verified unless
   the owner made it; a fork of a deleted item still runs and says the original is gone.
10. First publish claims the publisher name; a reserved or look-alike name is refused.

**Custom tools**
11. A tool that is not built in: `tool new` → `tool check` → `tool add` → `tool install`/`open`.
12. A tool installed from a script on the internet: allowed, and its address is shown on review.
13. API-key sign-in: hidden prompt or stdin; stored as a deployment secret; never in files.
14. A tool that needs a GPU on a computer without one: stopped at requirements with choices.
15. A tool name that clashes with a built-in tool or a Yougori command: refused for `tool add`.
16. An installer that fails or a `check` that fails: the message names the tool, the sandbox and
    how to look inside (`yougori terminal ENV`), and running again retries only that tool.
17. A template's tool from the Hub that was removed: the run stops at requirements and names it.

**Running**
18. Not enough memory or disk for every sandbox: totals are shown before anything is created.
19. Ctrl+C partway: stops at once; what exists is kept; the message shows
    `yougori template continue INSTANCE` and how to remove it.
20. One sandbox fails: the others stay; status names the failed part; `template continue` retries
    only what did not finish.
21. Running the same template twice: Open (or Continue) the existing one / Create another; scripts
    are told the `template continue` command, or pass another `--name`.
22. No Cloudflare account: Quick link is the default; Own domain lists saved domains or says how to
    add one.
23. Quick links can change after a restart: status shows the current address; the run says quick
    links are not for production.
24. An agent runs a template unattended: `--yes`, `--input`, `--inputs`, `--secrets -`; steps that
    need a person are reported, not waited on.
25. Yougori too old: "This template needs Yougori 1.3.0 or newer. Update with yougori update."
26. Website unreachable: a version already on this computer runs with a notice; otherwise a plain
    error that says nothing was changed.
27. The runner edited files in the instance folder, then updates: changed files are backed up
    first and listed.
28. `rm` lists what it removes; data in named volumes is kept unless `--delete-data`.
29. A downloaded file whose hash does not match: refused, nothing created, cache entry dropped.
30. A template removed for harmful code: new runs refused; `status` of existing instances shows
    the notice and how to remove it.

**Hub**
31. Every unverified page shows the warning above the README; only owner uploads show Verified;
    a README cannot fake the badge or hide the warning.
32. Clones count each computer once per item (the CLI's install id; per address for browser
    downloads, at most 5 new clones of an item per address a day); trending uses the last 7 days.
33. Stars need sign-in; one per account; unstar works.
34. Report: one open report per account per item; the owner sees reports, removes or restores
    items, and closes reports.
35. A banned account's items disappear from lists and pages say why; they return if the account
    is restored.
36. Search by words, topic, kind, Verified only; sort by most cloned, trending, stars, newest,
    recently updated; pagination.
37. Files tab shows every file; text files are shown with line numbers, others say they are
    binary; README rendering never runs scripts or loads remote images.
38. A wallet address in a template's files is noted on the review ("this template's files contain
    a wallet address"), because Hub templates are free and never pay their creator.

**Recovery and cleanup**
39. Changing or removing a public entry closes its previous Cloudflare route before applying the
    project. This includes disabling public access, changing ports, switching quick/custom mode
    and changing domains. Unrelated ports and local bridges remain available.
40. If unpublishing fails, the old address stays in the instance record for the next `continue`;
    an already-removed route can be retried safely after a lost response.
41. Quick mode accepts only a working quick-tunnel HTTPS address. A custom domain, stopped route,
    malformed address or publication without the requested HTTPS URL cannot count as ready.
42. A missing public route makes status incomplete and removes stale links and executable steps.
    `continue` checks live routes before deciding that an instance is already ready.
43. A failed vault deletion makes removal fail visibly. The record and folder remain available
    for retry; named volumes remain unless `--delete-data` was requested.
44. Update answers are checked against the fully rendered project before the update is saved or
    obsolete files are removed. An invalid resource size or path leaves the previous version intact.
45. An upload's open-source license must match the single top-level `license:` declaration in its
    template or tool file. Missing, duplicate or different declarations cannot become listings.

## 9. Checking the implementation

From the app checkout:

```text
cargo test --manifest-path cli/Cargo.toml --lib hub::
cargo test --manifest-path cli/Cargo.toml --lib skills::
npx vitest run src/api/hub-api.test.ts src/pages/hub-page.test.tsx src/components/hub-readme.test.tsx
node scripts/test-hub-contract.mjs PATH/TO/YougoriWebsite
```

The contract runner uses the website's actual API, a disposable in-memory database and a local
HTTP listener. It verifies download integrity, the CLI's review, pinned versions, search and clone
counting, then closes the listener. No live accounts, workloads or Cloudflare tunnels are used.
In the website checkout, run `node --test server/hub.test.mjs` and
`npx playwright test tests/hub.spec.ts` for publishing, moderation and browser flows.

The Hub is the setup-sharing framework. It does not itself implement the example model marketplace's
provider adapters, subscription model discovery, metering, wallet payments, credit balances or
editable model pricing. Those belong to an application's template and must be implemented and
tested there. Cloudflare publication tunnels traffic to the running Yougori sandbox; it does not
move the application onto Cloudflare compute. `yougori run hub/PUBLISHER/NAME` runs an explicit
published template; a natural-language prompt still needs an agent to author or select it.
