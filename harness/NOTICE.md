# Notices

The Yougori harness is AGPL-3.0-only. This file lists the outside work it follows or calls, with
each licence. No prompt, tool text or source code of another harness is copied into it.

## Our own agent and the screen (src/native, src/ui)

Written for this crate. The agent's prompts (`src/native/profiles/*.md`, the summary and `/init`
prompts), its tool descriptions and the screen's words are our own. The agent speaks MCP to the
servers a spec names, from the protocol's published message formats (method and field names,
which are needed for interoperability). The crates the binary is built from (`Cargo.lock`) are
used under their own licences.

## Engine adapters (src/engines: acp, codex, claude, pi, process, services)

No source code, prompt or user-facing text was copied into the adapters. They speak the
following protocols, implemented from their published message formats (field names, method names
and enum values, which are needed for interoperability):

- **Agent Client Protocol** (protocol version 1), schema from `@agentclientprotocol/sdk` 0.14.1,
  0.16.1, 0.21.0 and 1.4.0 (`schema/schema.json`). Apache License 2.0, Copyright Zed Industries,
  Inc. and contributors. Used by `src/engines/acp.rs`, `src/engines/acp/terminals.rs` and
  `examples/hub/inference-solver/site/harnesses/bridges/acp.py`.
- **Codex app-server protocol** at Codex 0.166.0, from the JSON schema the pinned binary prints
  (`codex app-server generate-json-schema`). Codex is Apache License 2.0, Copyright 2025 OpenAI.
  Used by `src/engines/codex.rs`.
- **Claude Agent SDK for Python** (github.com/anthropics/claude-agent-sdk-python, commit
  3cf3446), the control message shapes of Claude Code's stream-json mode (`initialize`,
  `can_use_tool`, `interrupt`, `set_model`, `set_permission_mode`). MIT License, Copyright (c)
  2025 Anthropic, PBC. Used by `src/engines/claude.rs`. Claude Code itself is proprietary: none
  of its text is part of the harness; it runs as its own program.
- **Pi RPC mode** at 0.73.1 (`packages/coding-agent/docs/rpc.md`). MIT License, Copyright (c)
  2025 Mario Zechner. Used by `src/engines/pi.rs`.

The harnesses these adapters start (OpenCode, Kilo, Gemini CLI, Qwen Code, DeepSeek dsh, Goose,
OpenHands, Cline, Grok, Codex, Claude Code, Pi) are separate programs installed in the Sandbox VM
under their own licences; the adapters exchange messages with them over pipes. The five security
harnesses (Strix, Shannon, PentAGI, PentestGPT, HexStrike) run their own terminal clients in the
screen's terminal pane (`src/ui/pane.rs`), also as separate programs under their own licences.

## Coding bridges (examples/hub/inference-solver/site/harnesses/bridges: aider_acp, interpreter_acp, swe_acp, plandex_acp, support_acp)

No source code, prompt or user-facing text of these harnesses is copied into the bridges. Each
bridge calls its harness's public Python API, or runs its own CLI and server, in the harness's own
venv inside the Sandbox VM; the text the screen shows (replies, questions, command and mode
descriptions) is the harness's own, passed through at run time. The bridges are part of the
inference-solver template (MIT, `examples/hub/inference-solver/LICENSE`).

- **Aider** 0.86.2 (`aider-chat`, github.com/Aider-AI/aider). Apache License 2.0. `aider_acp.py`
  imports it in its process (`aider.main`, `Coder`, `InputOutput`, `Commands`), gives it an
  `InputOutput` subclass, observes `Model.send_completion`'s stream and, for the session, runs
  the shell commands aider asks for in place of its `run_cmd`.
- **Open Interpreter** 0.4.3 (`open-interpreter`). GNU Affero General Public License v3, checked
  at the pin: the wheel's `LICENSE` is the AGPL-3.0 text (sha256 `490a8e3e…c812`) and its metadata
  says AGPL. `interpreter_acp.py` is our own file; it imports Open Interpreter as a library, so
  while it runs, the bridge and Open Interpreter are one program, and that program is covered by
  the AGPL-3.0 (the bridge's own MIT licence is compatible with it). What this means: Open
  Interpreter is used unmodified; the bridge reaches people only as its source file, beside Open
  Interpreter's published package in the harness pack, so whoever receives the pack has the
  complete source of the program it runs (Open Interpreter's at the pin in `packages.json`, and
  the bridge itself) under the AGPL-3.0's terms; any future change to Open Interpreter itself
  would have to be offered under the AGPL-3.0, including to people using it over a network
  (section 13). Shannon, the other AGPL harness, stays a separate program.
- **SWE-agent** at commit 3ea751c (sweagent 1.1.0) with SWE-ReX 1.4.0. MIT License, Copyright (c)
  2024 John Yang, Carlos E. Jimenez, Alexander Wettig, Shunyu Yao, Karthik Narasimhan, Ofir
  Press. `swe_acp.py` uses its run API (`RunSingle`, `BasicCLI`, `AbstractAgentHook`).
- **Plandex** 2.2.1 (commit e2d77207). MIT License, Copyright (c) 2025 PlandexAI Inc.
  `plandex_acp.py` runs Plandex's CLI and server as separate programs and reads its server's HTTP
  API as its CLI does (the plan stream and its message types, plan state, diffs, branches), from
  their published source; `plandex_cli.py`'s model proxy is reused.
