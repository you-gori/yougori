# AI Workspace

Your AI coding tools in one sandbox, signed in your way.

AI Workspace makes one container sandbox and installs the AI tools you pick: Codex, Claude Code, Gemini CLI, OpenCode, Kilo Code, Ollama and OpenClaw. For each tool that supports it, you choose how it reaches its models: your own account (a subscription sign-in), an API key, or both. Your files live in `/workspace`, which survives restarts and updates.

```text
yougori template run ./examples/hub/ai-workspace
```

From the Hub, search for "AI Workspace", or run `yougori run hub/PUBLISHER/ai-workspace@1.0.0` with the publisher shown on its Hub page.

## Questions it asks

Only the questions for the tools you pick are asked. An API key is asked only when you choose "An API key" or "Both" for that tool.

| Input | When | Type | Default | Notes |
| --- | --- | --- | --- | --- |
| `tools` | always | multiple choice | Codex | codex, claude, gemini, opencode, kilo, ollama, openclaw |
| `TOOL_access` | that tool picked (codex, claude, gemini, opencode, kilo) | choice | subscription | subscription, api or both |
| `TOOL_signin_source` | subscription or both | choice | new | computer (copy only that tool's sign-in file from this computer) or new (sign in fresh) |
| `TOOL_api_key` | api or both | secret | — | Given to the sandbox as `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `OPENCODE_API_KEY` or `KILO_API_KEY` |
| `cpu` | always | number | 2 | 0.5 to 32 cores |
| `memory_gb` | always | number | 4 | 1 to 64 GB |
| `storage_gb` | always | number | 20 | 6 to 512 whole GB |

Ollama and OpenClaw have no sign-in question: Ollama needs none, and OpenClaw signs in during its own setup.

Example answers without secrets are in [`answers/`](answers).

## What it creates

- One container sandbox (Ubuntu 24.04, pinned) with the cores, memory and disk you chose and internet access, so the tools can reach their providers.
- A persistent `/workspace` volume, where terminals open.
- The tools you picked, installed with the same installer as the `yougori codex`, `yougori claude` and other shortcuts.
- For subscription sign-in: a separate sign-in window per tool, labelled with the tool. Choosing "Copy my sign-in from this computer" copies only that tool's own sign-in file, and only after you choose it.
- For API keys: each key stays in this computer's credential store and reaches the sandbox as an environment variable.

## Outputs

| Output | Value |
| --- | --- |
| Sandbox | The sandbox's name, for `yougori TOOL --environment NAME` and `yougori terminal NAME` |

## Using it

Each picked tool has a step with its command, such as `yougori codex --environment NAME`. Opening a tool this way uses this sandbox; it does not create another one. Ollama starts its server inside the sandbox when you open it; then `ollama pull` and `ollama run` work in its terminal.

## Managing it

Stop and start it from My setups. Changing which tools are picked plans the change first; a tool you unpick stays installed until you remove it from the sandbox yourself. Removing the setup removes the sandbox and keeps the `/workspace` volume; deleting that data is a separate step that names it first.

## Known limits

- **Container only.** For a MicroVM sandbox, use the `yougori TOOL --isolation microvm` shortcut. API keys can only be given to containers.
- **No folders from this computer.** The template never chooses a folder on your computer. Copy files in with `yougori copy`, or clone your repository inside the sandbox.
- **Your own tools** are added with `yougori tool add` after setup; a bundled or Hub tool in a template is always installed, so this template includes none.
- **Ollama runs on the processor here.** For GPU models, run one with `yougori run hf.co/OWNER/MODEL`.
- **OpenClaw** keeps its gateway running only while `openclaw gateway run` runs in a terminal.
- **Sign-in status** comes from each tool: an opened sign-in window does not mean you are signed in. Scripted runs (`--yes`) never copy sign-ins from this computer; they leave a step to sign in later.
- **Sharing** happens from a terminal (Ctrl+G, Share this environment). A teammate with control can use everything in the sandbox, including your signed-in tools and API keys.
- **Provider terms**: whether a subscription allows a given use is between you and the provider.
- **The Health and logs view is planned.** It is listed as planned in setup and can't be turned on yet; `yougori template status NAME` and `yougori template logs NAME` show the setup's state and activity meanwhile.
- **Platforms**: Windows x64 and Linux x64 builds. OpenClaw installs on x64 and ARM64 only.

## Files

| File | Purpose |
| --- | --- |
| `yougori-template.yaml` | Questions, tools, sign-in options, steps and outputs |
| `yougori.yaml` | The sandbox |
| `answers/` | Example answers without secrets |
| `TESTING.md` | What maintainers check before publishing a version |
| `CHANGELOG.md` | Version history |
| `LICENSE` | MIT |
