# The Yougori harness

Our own terminal agent. It runs inside a Yougori Sandbox VM, and it holds every inference harness:
the person picks a harness, then a model from their inference, then answers that harness's own
questions, and works in one Yougori screen whichever harness they chose.

```
yougori inference run --server https://argon.yougori.com
◇  Which harness?   Strix (security)
◇  Which model?     unsloth/gemma-4-26B-A4B-it-GGUF
◇  What should it test? ...
```

## Why Rust (decided 12 Nov 2026, and kept)

- Same language, libraries and release pipeline as the `yougori` CLI (crossterm, reqwest, tokio).
- One small binary (about 10 MB) that starts in tens of milliseconds inside the VM; nothing to
  download at run time.
- Every model request goes to one OpenAI-compatible relay (`http://127.0.0.1:8080/v1`), so one
  streaming client replaces a whole provider layer.
- ratatui, crossterm, pulldown-cmark and syntect give a full-screen interface of the quality of
  the best terminal agents, and redraw only what changed, which matters because the VM's screen
  reaches the person's terminal through the launcher's polling relay.

TypeScript on Bun would mean a 100-200 MB binary, a new toolchain, and a drift toward a fork of
another product; Python's interfaces redraw too heavily for the relay.

## How it fits together

```
host: yougori inference run  ->  questions (harness, model, its own, folder, reach, size), Start
      solver.py run yougori --harness NAME / vm_host.py  ->  Sandbox VM: the Yougori base image,
                                                            then NAME's pack through the VM's
                                                            private control connection
VM:   vm_guest.py -> runtime.py run yougori -> profiles.headless() writes engine.json
      yougori-harness --spec engine.json
          screen (src/ui)  <-- Event / Command (src/protocol.rs) -->  engine (src/engines)
              native: our own agent (src/native)          yougori
              acp:    an ACP agent over stdio             opencode, kilo, gemini, qwen, deepseek,
                                                          goose, openhands, cline, grok
                      or one of our Python ACP bridges    aider, interpreter, swe, plandex
              codex-app-server / claude-stream-json / pi-rpc    codex, claude, pi
          terminal pane (src/ui): the harness's own client  strix, shannon, pentagi, pentestgpt,
                                                          hexstrike
```

Security harnesses keep their own engines and their own terminal clients, which run in the
screen's terminal pane. The Yougori screen frames them (harness, model, what the VM reaches, the
palette), and the spec gives them the setup answers through their own options (`ADAPTERS.md`).
Their VM reaches only the target and this inference.

- **`src/protocol.rs`** is the one event model: messages, reasoning, tool calls with diffs and
  terminal output, permission requests, questions, plans and to-dos, subagents (`parent`),
  security findings and reports, progress, usage, modes, slash commands, errors. It follows ACP,
  so ACP agents map one to one.
- **`src/spec.rs`** is `engine.json`: which protocol, the engine's command and whole
  environment, the model and this inference's models, services to start first, MCP servers,
  setup answers and reach. Per-harness knowledge (config files, the headless command) stays in
  `examples/hub/inference-solver/site/harnesses/profiles.py` (`headless()`).
- **Reach** (`spec.reach`, from the VM's `SOLVER_REACH`) is what the VM reaches besides the
  inference: `inference`, `sites`, `targets` or `full`. Yougori enforces it outside the VM; the
  spec only tells the engine. Our own agent offers webfetch only when the reach allows it.
- **Secrets** (a test login's password) never go into the spec, arguments, logs or reports: the
  VM passes them to this process as `YOUGORI_SECRET_<ID>`, the spec's `secret_env` maps them into
  the engine's environment, and the screen masks their values.
- **Models.** The model switcher lists `spec.models`. Engines that switch in place (`live`) get
  `SetModel`; the rest restart through `spec.respec` with the new model.
- **Our own agent** (`src/native`): streaming tool calls, a step limit, a stuck-loop guard,
  retries, cancel, automatic compaction for 32K windows; tools bash, read, write, edit, glob,
  grep, list, webfetch (when reach allows), todowrite, task (one level of subagents), question;
  allow / ask / deny permissions by tool and pattern; profiles as files; sessions in SQLite;
  AGENTS.md; an MCP client.
- **Images.** One base image, in three variants (base, postgres for Plandex and PentAGI, chromium
  for Shannon), holds the runtime and this binary. Each harness's engine is a pack the launcher
  downloads, checks and delivers into the VM; Yougori's own agent needs none
  (`site/harnesses/Containerfile.yougori`, `scripts/build-vm-images.py yougori`).

## Running it

Inside a VM Yougori starts it. To see the screen without a model:

```
cargo run -- --script tests/scripts/tour.jsonl
```

Build and test with a separate target folder, never the running engine's:

```
CARGO_TARGET_DIR=/d/tmp/yougori-harness-target cargo test < /dev/null
```

The VM build is Linux x86-64 (built in the `Yougori-Release-Build` WSL distro).
`scripts/build-vm-images.py yougori --output DIR --binary PATH` puts it into the base image.

## Notices

No prompt, tool text or source code of another harness is copied: our own agent's prompts and tool
descriptions are our own words, and the adapters and bridges follow published protocols and APIs.
`NOTICE.md` lists the projects whose work they follow, with their licences. Proprietary harnesses'
prompts are never copied; their real engines are hosted as they are. AGPL harnesses run as separate
programs with their source offered (Shannon), or are used unmodified (Open Interpreter, `NOTICE.md`).
