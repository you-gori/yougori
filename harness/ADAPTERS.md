# Engine adapters: what was verified

Every harness keeps its real engine; the Yougori harness drives it headless through the protocol
it speaks (`src/engines`) from the spec `profiles.headless()` writes. This file records, for each
pinned harness, the command, the protocol, how the model reaches the relay, how models switch,
how permissions and cancel work, and the evidence.

## How it was verified (12 Nov 2026)

1. **Pinned source.** Research clones checked against the pins (tag = pin for every one below);
   ACP schemas from `@agentclientprotocol/sdk` 0.14.1, 0.16.1, 0.21.0 and 1.4.0 (`npm pack`, read
   only); Codex's protocol from `codex app-server generate-json-schema` run on the pinned binary;
   Claude Code's control messages from the MIT Claude Agent SDK for Python (commit 3cf3446).
   Paths below are relative to `D:/tmp/harness-feasibility-2026-11-11/src/`.
2. **Protocol probes.** Each engine ran inside its own image (`localhost/inference-solver-vm-NAME`)
   in the WSL distro `Yougori-Harness-Builder`, `buildah run --network none --user 1000:1000`, with
   a scripted model server on 127.0.0.1:8080 (OpenAI chat completions, Responses, Anthropic
   Messages and Gemini). A Python client drove initialize, a session, a plain turn, a shell turn,
   a file-writing turn, a permission dismissed, a model switch and a cancelled turn, first from
   `configure()`'s settings and then from `headless()`'s spec. Transcripts: `/tmp/yh-out` in that
   distro (`NAME-acp.jsonl`, `NAME-line.jsonl`, `NAME-fakemodel.log`).
3. **The adapters themselves.** The crate's Linux test binary, built in `Yougori-Release-Build`,
   ran `engines::acp::tests::real_engine_from_spec` inside every image against the real engine
   from its `headless()` spec: Ready, three turns (text, a shell command, a file write; permissions
   answered), a live model switch where offered, a turn cancelled after 4 s, shutdown.
   **12 of 12 passed** (`/tmp/yh-out/NAME-real.log`). The fake server's model log shows each
   switched turn reaching the relay with the new model.

No container was left behind; the engines never ran on the Windows host.

## Summary

| Harness | Command (from `headless()`) | Protocol | Model switch | Permissions | Cancel |
|---|---|---|---|---|---|
| OpenCode 1.19.5 | `opencode acp --pure` | ACP 1 (SDK 0.21.0) | live: config option `model`, value `solver/<m>` | its rules (default allow): `once`/`always`/`reject` | `session/cancel` → `cancelled` |
| Kilo 7.8.18 | `kilo acp --pure` | ACP 1 (SDK 0.21.0) | live: config option `model`, `solver/<m>` | its rules (bash asks) | → `cancelled` |
| Gemini CLI 0.66.0 | `gemini --acp --model <m>` | ACP 1 (SDK 0.16.1) | live: `session/set_model` with our id | `proceed_once`/`proceed_always`/`cancel` | → `cancelled` |
| Qwen Code 0.26.6 | `qwen --acp --model <m>` | ACP 1 (SDK 0.14.1) | live: config option `model`, `<m>(openai)` | `proceed_once`/`proceed_once_and_switch_to_default`/`cancel` | → `cancelled` |
| DeepSeek dsh 0.2.1-rc.5 | `dsh acp --patch …/solver.acp.patch.yml` | ACP 1 (SDK 1.4.0) | live: config option `model`, `["solver","<m>"]` | only for sandbox escapes: `allow-once`/`reject-once` | → `cancelled` |
| Goose 1.57.0 | `goose acp` | ACP 1 (Rust crate 2.2.0) | restart (its model list holds only the current model of ours) | mode `auto` (default) never asks; `approve`/`smart_approve` ask | → `cancelled` |
| OpenHands 1.16.0 | `openhands acp` | ACP 1 (Python `agent-client-protocol` 0.8.1) | restart (`set_session_model` is a no-op) | mode `always-ask`: `accept`/`reject`/`always_proceed`/`risk_based` | pauses; prompt ends after the model call in flight; reported cancelled |
| Cline 3.0.74 | `cline --acp --config ~/.cline` | ACP 1 (SDK 0.16.1) | live: `session/set_model` with our id (selected at start) | every tool asks unless auto-approve | → `cancelled` |
| Grok 1.0.70 | `grok agent --model solver --no-leader stdio` | ACP 1 | restart (`set_model` refuses ids it does not list; ours is `solver`) | `allow-once`/`allow-edits-session`/`reject-once` | → `cancelled` |
| Codex 0.166.0 | `codex app-server -c sandbox_mode="danger-full-access"` | Codex app-server (JSON-RPC, no `jsonrpc` member) | live: `turn/start` `model` (this turn and after) | modes ask/auto/full-access; `accept`/`acceptForSession`/`decline`/`cancel` | `turn/interrupt` → turn `interrupted` |
| Claude Code 2.1.316 | `claude -p --input-format stream-json --output-format stream-json --verbose --include-partial-messages --permission-prompt-tool stdio --model <m> --setting-sources user` | stream-json + control protocol | live: control `set_model` | `can_use_tool` → allow (with `updatedPermissions` for always) / deny (+`interrupt` when dismissed) | control `interrupt` |
| Pi 0.73.1 | `pi --mode rpc --provider solver --model <m>` | Pi RPC (JSON lines) | live: `set_model {provider, modelId}` | none (Pi asks nothing); extension dialogs become questions | `abort` → `stopReason: aborted` |
| Aider 0.86.2, Open Interpreter 0.4.3, SWE-agent 3ea751c, Plandex 2.2.1 | `/opt/solver/tool/bin/python /opt/solver/bridges/NAME_acp.py --model <m> … -- <configure()'s arguments>` | ACP 1 through our bridge (`bridges/acp.py`) | live (Plandex: from its next step) | their own: Aider's confirmations, Open Interpreter's code blocks, Plandex's pending changes; SWE-agent asks nothing | interrupts the work as Ctrl+C does (Plandex: stops the plan through its server) → `cancelled` |
| Strix, Shannon, PentAGI, PentestGPT, HexStrike | `configure()`'s command, with the setup answers in its own options | `terminal` (their own terminal clients in the screen's pane) | restart | their own | their own |

`yougori` is our own engine (`native`, profile `yougori`). Aider, Open Interpreter, SWE-agent and
Plandex speak no protocol of their own: our Python bridges (`bridges/NAME_acp.py`) run their real
engines in their own venv and speak ACP for them. The five security harnesses keep their own
terminal clients, shown in the screen's terminal pane.

## Per harness

### OpenCode 1.19.5 (`opencode-ref/opencode`, tag v1.19.5 = 810c0eba1a73)
- Command `opencode acp --pure` (`packages/opencode/src/cli/cmd/acp.ts:9-18`). `--model` is
  rejected by the ACP command (`src/index.ts:116`); the model comes from the config.
- Relay: `configure()`'s `OPENCODE_CONFIG`/`OPENCODE_CONFIG_CONTENT` (provider `solver`,
  `@ai-sdk/openai-compatible`, base URL the relay, limits 32,768/4,096), models fetch and
  autoupdate off. Probe: `usage_update.size` 32768, every request at the relay.
- `initialize`: `authMethods [opencode-login]`, no auth needed (`src/acp/service.ts:94-146`).
  `session/new` returns `configOptions` `model` and `mode` (`build`, `plan`), no `modes`
  (`service.ts:199-206`). The adapter takes modes from the `mode` option.
- Switch: `session/set_config_option` (`service.ts:409-466`); probe: next turns at the new model.
- Tools: bash output arrives as text content with `rawOutput.metadata.exit`; the adapter shows it
  as a terminal with the exit code. Edits carry `diff` content only with old/new strings.
- Permissions: `once`/`always`/`reject` (`src/acp/permission.ts:20-24`); defaults allow almost
  everything (`src/agent/agent.ts:119-135`), so few requests. Cancel: `service.ts:357-360`,
  probe `stopReason: cancelled`.

### Kilo 7.8.18 (`kilo-inv/repo`, tag v7.8.18 = b8176153)
- Command `kilo acp --pure` (`packages/opencode/src/cli/cmd/acp.ts:9-18`); OpenCode's ACP code
  with Kilo's agents. Relay as OpenCode (`KILO_*`).
- Probe: config options `model` (`solver/<m>`) and `mode` (`code`, `ask`, `debug`,
  `orchestrator`, `plan`); switch takes effect next turn; cancel → `cancelled`.

### Gemini CLI 0.66.0 (`gemini-inv/repo`, tag v0.66.0 = 97041320)
- Command `gemini --acp --model <m>` (`packages/cli/src/config/config.ts:363-371`; `--model`
  applies per session, `config.ts:288-292`).
- Relay: `configure()`'s `GEMINI_API_KEY` + `GOOGLE_GEMINI_BASE_URL` (the relay translates the
  Gemini API) and `settings.json` (`selectedType gemini-api-key`, folder trust off, web tools
  excluded). `session/new` needs no `authenticate`.
- `session/new` returns `modes` (`default`, `autoEdit`, `yolo`, `plan`) and `models` (Gemini's
  own list). `session/set_model` takes any id without checking (bundle `gemini-22EOGL6O.js`
  around `setModel`); probe: after `set_model` with our id the requests carried it. So the
  adapter selects through `session/set_model` with this inference's ids.
- Files: Gemini checks a file it is about to create through `fs/read_text_file`; its SDK rejects
  an error response with a plain object (`@agentclientprotocol/sdk` 0.16.1 `dist/acp.js:868`)
  whose message its check (`gemini-22EOGL6O.js:16303-16311`) cannot read, so every new file
  failed when the client offered file access (probe). The adapter offers file access to every
  agent except Gemini, which keeps its own (same file system). Probe after the change: the write
  asks permission with a `diff` and succeeds.
- Permissions: `proceed_once` (allow_once), `proceed_always` (allow_always), `cancel`
  (reject_once). Cancel → `cancelled`.

### Qwen Code 0.26.6 (`qwen-inv/repo`, tag v0.26.6 = 042c023b)
- Command `qwen --acp --model <m>` (`packages/cli/src/config/config.ts:658-664`).
- Relay: `settings.json` `modelProviders.openai` (base URL the relay, `envKey SOLVER_API_KEY`),
  `selectedType openai`; `authMethods [openai]`, no `authenticate` needed (probe).
- `session/new` returns `models`, `modes` (`plan`, `default`, `auto-edit`, `auto`, `yolo`) and
  `configOptions` (`mode`, `model` with values `<m>(openai)`, `workflow_mode`,
  `reasoning_effort`). The adapter switches with the config option, which does not persist;
  `session/set_model` would also save the model as the default (`acpAgent.ts:6997-7013`).
- Permissions in the default `auto` mode (its classifier is unavailable offline, so it asks):
  `proceed_once`, `proceed_once_and_switch_to_default`, `cancel`. Writes go through
  `fs/write_text_file` and the call ends with a `diff`. It also sends `craft/drainMidTurnQueue`
  and `qwen/notify/...` requests; the adapter answers method-not-found and the turn goes on.

### DeepSeek dsh 0.2.1-rc.5 (`deepseek-inv/deepseek-harness`, tag dsh-v0.2.1-rc.5 = b830ec95)
- Command `dsh acp --patch <patch>` (`apps/cli/src/args.ts:206-207`, `--patch` on any profile
  `args.ts:170`). ACP sessions take provider and model from the patch's own `acp` row, not from
  `agent-default-model` (`packages/acp/acp/src/index.ts:448-460`), so `headless()` writes
  `.dsh/solver.acp.patch.yml` = `configure()`'s rows + `{id: acp, config: {provider: solver,
  model: <m>}}`; `DSH_TELEMETRY_DISABLED=1`.
- `initialize`: `authMethods []`. `session/new`: `configOptions` `model` grouped, values
  `["solver","<m>"]` (`model-control.ts:158-219`); switch via `set_config_option`
  (`model-control.ts:103-134`), next turn at the new model (probe).
- Tools run in dsh (kind `other`, text results). Permissions only for sandbox escapes
  (`index.ts:159-177`). Cancel → `cancelled` (probe).

### Goose 1.57.0 (`goose-inv/goose`, tag v1.57.0 = 30bba951)
- Command `goose acp` (`crates/goose-cli/src/cli.rs:833-848`). Relay: `GOOSE_PROVIDER=openai`,
  `OPENAI_HOST`, `OPENAI_BASE_PATH`, `GOOSE_MODEL` (env beats config,
  `crates/goose/src/config/base.rs:84-86`).
- `session/new`: `modes` `auto`, `approve`, `smart_approve`, `chat` and `configOptions` incl.
  `model`, whose values are Goose's provider inventory plus the current model only (probe), so
  the adapter cannot select this inference's other models: restart.
- Permissions only in `approve`/`smart_approve` (`server.rs:1300-1318`), options
  `allow_once`/`allow_always`/`reject_once`/`reject_always` (`server.rs:1475-1488`).
  Cancel → `cancelled` (probe). It fetches models.dev at start and fails quietly offline.

### OpenHands 1.16.0 (`openhands-inv/OpenHands-CLI`, tag 1.16.0 = 2963442d; SDK 1.21.0)
- Command `openhands acp` (`openhands_cli/argparsers/acp_parser.py:11-49`). In ACP mode it
  ignores `LLM_*` and `--override-with-envs` (`entrypoint.py:112` vs `152-159`) and refuses a
  session without `agent_settings.json` (`acp_impl/agent/local_agent.py:68-77`, probe:
  `-32000`). `headless()` writes that file with OpenHands' own code
  (`get_default_cli_agent(LLM(model="openai/<m>", base_url=relay))`, as its tests do,
  `tests/conftest.py:62-102`), drops `LLM_*`, sets `OPENHANDS_SUPPRESS_BANNER=1`.
- Modes `always-ask`, `always-approve`, `llm-approve`; one permission per batch
  (`acp_impl/confirmation.py:53-74,160-171`). No model switch (`base_agent.py:331-349`): restart.
- Cancel pauses the conversation but the prompt returns `end_turn` after the model call in
  flight ends (`base_agent.py:405-428`; probe: 60 s with a slow model); the adapter reports the
  turn cancelled. Banners and login messages on stdout are skipped as non-JSON lines.

### Cline 3.0.74 (`cline-inv/repo` + `cline-verify/repo`, tag cli-v3.0.74 = 071e1b25)
- Command `cline --acp --config ~/.cline` (`apps/cli/src/commands/program.ts:71-75`).
  `-P/-m/-k` are ignored in ACP mode (`main.ts:809-818`). `headless()` runs `cline auth
  --provider openai --baseurl <relay> --apikey solver-local-relay --modelid <m>` as the terminal
  client does (it saves provider `openai-compatible` with the model, probe), then
  `CLINE_PROVIDER=openai-compatible`, `CLINE_API_KEY`, `CLINE_MODEL`.
- `session/new` still names its default `gpt-4o` (probe); `session/set_model` takes any id and
  the next turns use it (probe), so the adapter selects the chosen model at start and switches
  live. Modes `plan`/`act`. Cancel → `cancelled`.

### Grok 1.0.70 (binary `grok-1.0.70-linux-x86_64`, sha256 pinned in packages.json)
- Closed source; verified by probe only. `grok help agent`: `agent stdio` runs the agent over
  stdio (options before the subcommand). It speaks ACP: `authMethods [xai.api_key, grok.com]`
  (not needed: `config.toml` names the relay model `solver`), `session/new` `models`
  (`currentModelId solver`) and a `model` config option.
- `set_model`/`set_config_option` with another id: `unknown model id` (probe), so restart; the
  respec writes a new `config.toml`. It sends `_x.ai/*` notifications (ignored) and made one
  request with its own `grok-4.6` model (a session summary), which the relay refuses harmlessly.
- File writes go through `fs/read_text_file`/`fs/write_text_file` with a `diff` and permission
  options `allow-once`, `allow-edits-session`, `reject-once`. Cancel → `cancelled`.

### Codex 0.166.0 (`codex-inv/repo`, tag rust-v0.166.0 = 6ff1e1ca; schema from the binary)
- Command `codex app-server -c sandbox_mode="danger-full-access"`. Messages are JSON-RPC without
  the `jsonrpc` member (`JSONRPCRequest.json`). `initialize` → `initialized` → `thread/start
  {cwd, model, approvalPolicy: "untrusted"}` → `turn/start {threadId, input, model?,
  approvalPolicy?, sandboxPolicy?}`; overrides apply "for this turn and subsequent turns"
  (`TurnStartParams` descriptions).
- Relay: `configure()`'s `config.toml` (provider `solver`, `wire_api = "responses"`, model
  catalog). Sandbox: in the container the bundled bubblewrap could not run and sandboxed
  commands failed with no command items (probe), so the VM is the boundary and the approval
  policy decides what is asked; `approval_policy = "untrusted"` is refused in `config.toml`
  ("no longer supported", probe) but accepted per thread.
- Items: `agentMessage`, `reasoning` (raw `textDelta` or `summaryTextDelta`), `commandExecution`
  (the inner command from `commandActions`, output deltas, exit code), `fileChange` (diff shown
  from the file and the patch, then from disk), `mcpToolCall`, plan updates, token usage.
- Approvals: `item/commandExecution/requestApproval`, `item/fileChange/requestApproval` →
  `accept`/`acceptForSession`/`decline`, dismissed → `cancel`; `item/permissions/requestApproval`
  → the requested profile for the turn or session; `item/tool/requestUserInput` and MCP
  elicitations → questions. Probe: accept runs the command, decline reports it rejected.
- Model: `turn/start model` (probe: the switched turns used it). Cancel: `turn/interrupt` →
  `turn/completed` status `interrupted` (probe).

### Claude Code 2.1.316 (npm package; protocol from the Claude Agent SDK for Python)
- Command as in the table (flags as the SDK passes them,
  `_internal/transport/subprocess_cli.py:509-728`; `--permission-prompt-tool stdio`,
  `types.py:2300-2317`). Relay: `configure()`'s `ANTHROPIC_BASE_URL`, `ANTHROPIC_API_KEY`,
  default-model variables and `settings.json`.
- `initialize` control request (`_internal/query.py:351-369`); its answer carries
  `claude_code_version` and the commands (probe). Each turn: a `user` message, `stream_event`
  deltas, whole `assistant` messages, `user` tool results with `tool_use_result`, a `result`.
- Permissions: `can_use_tool` (`query.py:610-668`) with `permission_suggestions`; answers
  `{behavior: allow, updatedInput}` (+ `updatedPermissions` for "don't ask again") or
  `{behavior: deny, message}` (+ `interrupt: true` when dismissed). AskUserQuestion arrives as
  `can_use_tool` and is answered with `updatedInput.answers` {question: label}
  (`sdk-tools.d.ts:1139,2686`; probe: the engine read the answer back).
- `set_model`, `set_permission_mode` (modes `default`, `acceptEdits`, `plan`,
  `bypassPermissions`), `interrupt` (`query.py:823-845`); probe: interrupt answered
  `still_queued: []`, the turn ended. TodoWrite shows as the plan; subagent messages carry
  `parent_tool_use_id`.

### Pi 0.73.1 (`pi-inv/repo`, tag v0.73.1 = 781152fc)
- Command `pi --mode rpc --provider solver --model <m>` (`packages/coding-agent/docs/rpc.md:7-17`).
  Relay: `configure()`'s `models.json` provider `solver` and `settings.json`.
- Commands with `id` → `response` (`rpc.md:19-36`); events `agent_start` … `agent_end`,
  `message_update` deltas, `tool_execution_*` (`rpc.md:740-982`); edit arguments
  `{path, edits:[{oldText,newText}]}` (`src/core/tools/edit.ts:31-52`).
- `set_model {provider, modelId}` (`rpc.md:216-233`; probe: next turn at the new model),
  `abort` (`rpc.md:123-135`; probe: `stopReason: aborted`), `get_session_stats` for the context
  in use. Extension dialogs (`select`, `confirm`, `input`, `editor`) become questions
  (`rpc.md:984-1175`).

### Coding bridges: Aider 0.86.2, Open Interpreter 0.4.3, SWE-agent 3ea751c, Plandex 2.2.1
- Each bridge (`bridges/NAME_acp.py`, with `support_acp.py`) runs the real engine in the harness's
  own venv and speaks ACP for it through `bridges/acp.py`. The engine's work runs on the main
  thread, so a cancel interrupts it as Ctrl+C does in the harness's own terminal; a cancel that
  arrives while the turn's job is still queued stops it before it runs. The protocol owns stdout;
  whatever the engine prints goes to stderr.
- Aider runs in the bridge's process (`aider.main.main(..., return_coder=True)` with an
  `InputOutput` of ours): replies stream as messages, its confirmations ask with its own options,
  every file it writes is an edit with its diff, shell commands it suggests run in their own process
  group as terminal tool calls. Its chat modes (code, ask, architect, context) are the modes, its
  slash commands the available commands.
- Open Interpreter: each prompt is `interpreter.chat(stream=True)`; each code block is a tool call
  with its output, and its confirmation (auto_run off) a permission request ("don't ask again"
  turns auto_run on, the `auto` mode). A cancel uses its own stop.
- SWE-agent: each prompt is one run, built by SWE-agent's own parser from `configure()`'s
  arguments, with the statement set on the parsed config (so a prompt such as `--help` or one with
  blank lines reaches it whole). The setup answer `issue` starts the first statement and stays until
  a run has worked on it. The final patch comes as diffs and is saved with the trajectory under
  `reports/swe-agent/` in the workspace.
- Plandex: its PostgreSQL, server and model proxy start as `plandex_cli.py` starts them; each prompt
  is `plandex tell` (`chat` in the chat mode) with the prompt in a private file, and `/continue`
  runs `continue --skip-menu`. Pending changes come as diffs and are applied only after a yes. A
  model switch during a step applies from the next step.
- Verified (12 Nov) in each harness's image with no network and a scripted model: a scenario run per
  bridge (turns, permissions, diffs, modes, a live switch, cancels), and
  `engines::acp::tests::real_engine_from_spec` for all four. After the review fixes,
  `test_bridges.py` (39) and `test_bridge_acp.py` (6) passed in the images.

### Security harnesses: Strix, Shannon, PentAGI, PentestGPT, HexStrike
- `profiles._security` starts the harness's own terminal client in the pane and gives it the setup
  answers through its own options: Strix gets `--target=` for each target (and the source folder)
  and `--instruction=` with the brief; Shannon `--target=` for each target, `--config=` with the off
  limits and focus, and `SOLVER_REACH`; PentAGI `--task=` with the brief; HexStrike `--task=` and
  `SOLVER_REACH`. PentestGPT takes its task only as the answer to its first question, so the brief
  is shown first, on one line, to paste there.
- For the practice app the spec starts `practice_app.py` first as a service, and the harness tests
  `http://127.0.0.1:8000`. Any other target starts nothing without the permission yes. The test
  login's password reaches the client only as `YOUGORI_SECRET_LOGIN_PASSWORD`, through `secret_env`.

## For the screen and the other engineers

- `Ready.model_switch` is what the engine can do, not only what the profile says: live needs the
  profile's `live` and a way to select every model of this inference.
- The adapters end every turn with `TurnEnd` (cancelled turns as `Cancelled` even when the
  engine says otherwise), answer open permissions and questions themselves when a turn ends or is
  cancelled, and queue prompts sent during a turn. An ACP turn whose cancel the agent has not
  answered within 30 s ends as `Cancelled` with a warning notice, and the agent's late answer is
  ignored (`acp.rs`, `CANCEL_LIMIT`).
- `Shutdown` closes stdin, waits a second, then stops the process group (SIGTERM, 3 s, SIGKILL)
  and sends `Exit { code: Some(0) }`. A crash sends `TurnEnd { Error }` then `Exit` with the
  exit code and the last stderr lines; logs are `state_dir/<harness>.stderr.log`.
- Services start in order, each ready when its `ready_url` answers, and stop in reverse order
  when the engine handle drops, each fully before the next (ports are free for a restart).
- Bridges: `bridges/acp.py` (`Bridge`) is the agent side of ACP with Yougori's extensions
  (`_yougori/finding|report|progress|usage|notice`, `_yougori/question`); `bridges/support_acp.py`
  holds what the coding bridges share. `profiles.practice_target(spec)` is the shared practice-app
  helper for security entries.
