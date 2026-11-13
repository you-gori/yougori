"""Per-harness settings. Only an isolated loopback relay is a model provider.

Nothing reads the host's provider profiles or subscription credentials. The
networkless Yougori VM enforces isolation even if a project changes settings.
"""
import json
import os
from pathlib import Path
import re
import subprocess

BASE = "http://127.0.0.1:8080/v1"
LOCAL_KEY = "solver-local-relay"  # Not a service credential; the relay holds that.
BLUE = "#5297ff"
# Relative to the workspace, where the security harnesses start: their results come back to the
# person's folder only after their review.
PENTESTGPT_LOGS = "reports/pentestgpt"
# The window and the longest reply a harness plans for when the catalog says nothing of its model:
# the window Yougori's model servers serve (src-tauri/src/model_runner/engine_backends.py starts
# llama.cpp with -c 32768, and model_server.py context_window() holds Transformers models to it) and
# the longest reply the website passes on (site/gateway.py REPLY_TOKENS; model_server.py refuses
# more). Each harness is told its own model's window and reply budget (limits()), so it asks no more
# and compacts its conversation in time.
CONTEXT_WINDOW = 32768
REPLY_TOKENS = 4096
# Where a catalog entry gives its model's window and longest reply, by the names model servers use.
WINDOW_FIELDS = ("context_length", "context_window", "max_model_len", "max_context_length")
REPLY_FIELDS = ("max_completion_tokens", "max_output_tokens")
# The longest window Shannon's and Plandex's launchers take (shannon_cli.py, plandex_cli.py).
LAUNCHER_WINDOW = 131072
# A model the catalog no longer lists: it went away after the VM started.
UNAVAILABLE = "The model %s is not available on this server right now. Choose another model, or start again when it is back."
# What Yougori's setup package adds to every VM's copy of the workspace (appliance/agent/setupkit,
# which the engine runs at each launch; vm_host.py SETUP_FILES names the same five). Git in the VM
# leaves them out (git_ignored), so no harness counts them among its changes. When the session ends
# (the harness exits, or the launcher ends it with /finish before it stops the VM), vm_guest.py takes
# the ones the package added out of the copy, so the person's review does not list them. The ones
# the person's folder already held stay: the launcher names them (/start "setup_in_folder").
SETUP_FILES = ("yougori.py", "node_modules/yougori/index.mjs", "node_modules/yougori/index.d.ts",
               "node_modules/yougori/package.json", ".agents/skills/yougori-setup/SKILL.md")
# The window Gemini CLI 0.66.0 gives a model (packages/core/src/core/tokenLimits.ts): these two by
# name, any other GEMINI_WINDOW. It compresses the chat at GEMINI_SHARE of that window
# (DEFAULT_COMPRESSION_TOKEN_THRESHOLD) unless model.compressionThreshold sets another share.
GEMINI_WINDOW = 1048576
GEMINI_WINDOWS = {"gemma-4-31b-it": 256000, "gemma-4-26b-a4b-it": 256000}
GEMINI_SHARE = 0.5


def write(root, name, value):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value if isinstance(value, str) else json.dumps(value, indent=2), encoding="utf-8")
    return str(path)


def git_ignored(root, patterns):
    """Adds `patterns` to git's own ignore file in the harness's home (XDG_CONFIG_HOME/git/ignore,
    which git reads for every repository), each once, keeping what is there. Nothing is written in
    the workspace, so nothing of it reaches the person's review."""
    path = Path(root) / ".config/git/ignore"
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        lines = []
    added = [pattern for pattern in patterns if pattern not in lines]
    if added:
        path.write_text("".join(line + "\n" for line in lines + added), encoding="utf-8")
    return str(path)


def offline_skills(root):
    """OpenHands clones its public skills from GitHub at every start and prints an ERROR when the
    clone fails, as it always does in a VM that reaches only the inference. A local repository with
    no skills answers that clone (git's url.insteadOf, set in the environment), so OpenHands starts
    cleanly with none. Without git nothing is set and OpenHands reports as before."""
    mirror = root / ".openhands/offline-skills"
    if not (mirror / ".git").is_dir():
        (mirror / "skills").mkdir(parents=True, exist_ok=True)
        # OpenHands warns when the clone has no skills folder; git keeps a folder only with a file.
        (mirror / "skills/.keep").write_text("", encoding="utf-8")
        who = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(root), "GIT_CONFIG_NOSYSTEM": "1",
               "GIT_AUTHOR_NAME": "Yougori", "GIT_AUTHOR_EMAIL": "solver@localhost",
               "GIT_COMMITTER_NAME": "Yougori", "GIT_COMMITTER_EMAIL": "solver@localhost"}
        for step in (["init", "-q", "-b", "main"], ["add", "-A"], ["commit", "-q", "-m", "No public skills offline"]):
            try:
                done = subprocess.run(["git", *step], cwd=mirror, env=who, capture_output=True, timeout=30)
            except (OSError, subprocess.SubprocessError):
                return {}
            if done.returncode:
                return {}
    return {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "url." + mirror.as_uri() + ".insteadOf",
            "GIT_CONFIG_VALUE_0": "https://github.com/OpenHands/extensions"}


def environment(root):
    """A harness's whole environment before its own settings: a fresh home and only the relay.
    Yougori never passes through host env or provider credentials."""
    root = Path(root)
    return {"PATH": "/opt/solver/tool/node_modules/.bin:/opt/solver/tool/bin:/usr/local/bin:/usr/bin:/bin",
            "HOME": str(root), "XDG_CONFIG_HOME": str(root / ".config"), "XDG_DATA_HOME": str(root / ".local/share"),
            "TERM": "xterm-256color", "COLORTERM": "truecolor", "LANG": "C.UTF-8",
            "SOLVER_API_KEY": LOCAL_KEY, "OPENAI_API_KEY": LOCAL_KEY, "OPENAI_BASE_URL": BASE,
            "OPENAI_API_BASE": BASE, "DO_NOT_TRACK": "1", "NO_ANALYTICS": "1",
            "LITELLM_LOCAL_MODEL_COST_MAP": "True"}


def catalog_ids(model, catalog):
    """The catalog's model ids. Refuses `model` when the catalog does not list it: it went away after
    the VM started, or this server never had it."""
    ids = [item["id"] for item in catalog]
    if model not in ids:
        raise ValueError(UNAVAILABLE % model)
    return ids


def limits(model, catalog):
    """The window and the reply budget of `model`, in tokens. The window is what its catalog entry
    gives (256 to 1,048,576 tokens), else CONTEXT_WINDOW. The reply budget is what the entry gives, at
    most REPLY_TOKENS, which the website passes on, and at most a quarter of the window, so a reply
    always leaves the conversation room."""
    entry = next((item for item in catalog if item.get("id") == model), {})
    window = next((value for value in map(entry.get, WINDOW_FIELDS) if type(value) is int and 256 <= value <= 1048576),
                  CONTEXT_WINDOW)
    reply = next((value for value in map(entry.get, REPLY_FIELDS) if type(value) is int and value > 0), REPLY_TOKENS)
    return window, min(reply, REPLY_TOKENS, window // 4)


def cline_limits(config, window, reply):
    """Cline's auth command saves the relay's provider (in `config`'s data/settings/providers.json)
    without a window, which Cline then takes for 128,000 tokens, and Cline asks 8,192 tokens of reply.
    The relay's entry gets this model's window and reply budget instead (its contextWindow and
    maxTokens). Settings of another shape are left as they are. Whether anything changed."""
    path = Path(config) / "data/settings/providers.json"
    try:
        stored = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    entries = stored.get("providers") if isinstance(stored, dict) else None
    changed = False
    for entry in entries.values() if isinstance(entries, dict) else ():
        settings = entry.get("settings") if isinstance(entry, dict) else None
        if isinstance(settings, dict) and isinstance(settings.get("baseUrl"), str) and settings["baseUrl"].rstrip("/") == BASE:
            settings.update(contextWindow=window, maxTokens=reply)
            changed = True
    if changed:
        written = path.with_name(path.name + ".partial")
        descriptor = os.open(written, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(stored, stream, indent=2)
        os.replace(written, path)
    return changed


def configure(harness, model, catalog, root):
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    env = environment(root)
    ids = catalog_ids(model, catalog)
    # The chosen model's window and reply budget, and each listed model's for the harnesses that
    # list them all.
    window, reply = limits(model, catalog)
    sized = {mid: limits(mid, catalog) for mid in ids}
    git_ignored(root, ["/" + name for name in SETUP_FILES])
    quote = json.dumps
    if harness in ("strix", "pentagi"):
        # Their adapters run only in a Yougori VM that holds them: their own image, or the Yougori
        # harness's shared base image (harness-name `yougori`), where this names the pack delivered.
        env["SOLVER_HARNESS"] = harness
    if harness == "pentagi":
        # Every one of its agents asks this model's reply budget, not its provider's 16,384 tokens.
        return ["python3", "/opt/solver/pentagi_cli.py", "--model", model, "--max-output", str(reply)], env
    if harness == "shannon":
        # Its launcher's own window (the models.json it writes for Shannon's agents) and reply budget.
        return ["python3", "/opt/solver/shannon_cli.py", "--model", model, "--context-budget", str(min(window, LAUNCHER_WINDOW)),
                "--max-output", str(reply)], env
    if harness == "plandex":
        return ["python3", "/opt/solver/plandex_cli.py", "--solver-model", model,
                "--context-budget", str(min(window, LAUNCHER_WINDOW))], env
    if harness == "strix":
        env.update(STRIX_LLM="openai/"+model,STRIX_API_TYPE="chat_completions",STRIX_RUNTIME_BACKEND="yougori_vm",
                   STRIX_TELEMETRY="false",OPENAI_AGENTS_DISABLE_TRACING="1",STRIX_REASONING_EFFORT="none")
        # Strix takes a model LiteLLM does not know for a 200,000-token window and holds back 20,000
        # tokens of it before it compacts (strix/config/settings.py, llm/compaction.py). Told the
        # window, it holds back the reply budget twice over and asks no longer summary than the budget.
        env.update(STRIX_CONTEXT_FALLBACK_TOKENS=str(window), STRIX_CONTEXT_BUFFER_TOKENS=str(2 * reply),
                   STRIX_CONTEXT_SUMMARY_TOKENS=str(reply))
        return ["/opt/solver/tool/bin/python", "/opt/solver/strix_cli.py"], env
    if harness == "hexstrike":
        return ["/opt/solver/tool/bin/python", "/opt/solver/hexstrike_cli.py", "--model", model], env
    if harness == "deepseek":
        env["DSH_HOME"] = str(root / ".dsh")
        env["NARB_DISABLE_NATIVE_CACHE"] = "1"
        # Without a window and a reply length dsh takes 262,144 and 32,768 for a model its catalog
        # does not know (its route's defaultContextWindow and defaultMaxTokens). A model's own
        # maxTokens is also its requests' reply length (docs/config-catalog.md, PiAiModelProfile).
        path = write(root, ".dsh/solver.patch.yml", [
            {"id": "agent-default-model", "config": {"provider": "solver", "model": model}},
            {"id": "deepseek-account", "disabled": True},
            {"id": "llm-pi-ai", "config": {"providers": {"solver": {"apiKeyEnv": "SOLVER_API_KEY",
                "displayName": "Inference Solver", "api": "openai-completions", "baseURL": BASE,
                "models": [{"id": mid, "contextWindow": sized[mid][0], "maxTokens": sized[mid][1]} for mid in ids]}}}}
        ])
        return ["dsh", "tui", "--patch", path], env
    if harness in ("opencode", "kilo"):
        name = harness
        config = {"enabled_providers": ["solver"], "model": "solver/" + model, "small_model": "solver/" + model,
                  "autoupdate": False, "share": "disabled", "plugin": [],
                  "provider": {"solver": {"npm": "@ai-sdk/openai-compatible", "name": "Inference Solver",
                    "options": {"baseURL": BASE, "apiKey": LOCAL_KEY},
                    # Each model's window and reply budget, as for Pi: the harness compacts the
                    # conversation before it outgrows them.
                    "models": {mid: {"name": mid, "limit": {"context": sized[mid][0], "output": sized[mid][1]}} for mid in ids}}}}
        path = write(root, f".config/{name}/{name}.json", config)
        env[name.upper() + "_CONFIG"] = path
        env[name.upper() + "_CONFIG_CONTENT"] = json.dumps(config)
        env[name.upper() + "_DISABLE_MODELS_FETCH"] = "true"
        env[name.upper() + "_DISABLE_AUTOUPDATE"] = "true"
        env[name.upper() + "_DISABLE_PROJECT_CONFIG"] = "true"
        return [name, "--pure", "--model", "solver/" + model], env
    if harness == "codex":
        env["CODEX_HOME"] = str(root / ".codex")
        # context_window as in Codex's own catalog (models-manager/models.json): without it Codex
        # knows no window and never compacts before the server refuses the conversation.
        catalog_path = write(root, ".codex/solver-models.json", {"models": [{
            "slug": mid, "display_name": mid, "description": "Inference Solver model", "visibility": "list",
            "supported_in_api": True, "priority": index, "supported_reasoning_levels": [],
            "shell_type": "unified_exec", "support_verbosity": False, "default_reasoning_summary": "none",
            "truncation_policy": {"mode": "tokens", "limit": 10000}, "experimental_supported_tools": [],
            "input_modalities": ["text"], "supports_search_tool": False, "tool_mode": "direct",
            "context_window": sized[mid][0],
            "base_instructions": "You are a coding assistant. Work with the user's project using the provided tools."
        } for index, mid in enumerate(ids)]})
        write(root, ".codex/config.toml", f'''model = {quote(model)}
model_provider = "solver"
web_search = "disabled"
model_catalog_json = {quote(catalog_path)}
[model_providers.solver]
name = "Inference Solver"
base_url = {quote(BASE)}
env_key = "SOLVER_API_KEY"
wire_api = "responses"
requires_openai_auth = false
[analytics]
enabled = false
[feedback]
enabled = false
''')
        # Codex's terminal screen starts a shared background server and records it with `ps`, which
        # this image does not have, so it exited before showing anything; one-shot `exec` does not
        # use the server. --no-daemon is a top-level option, so it also goes before `exec`.
        return ["codex", "--model", model, "--no-daemon"], env
    if harness == "claude":
        env.update({"CLAUDE_CONFIG_DIR": str(root / ".claude"), "ANTHROPIC_API_KEY": LOCAL_KEY,
                    "ANTHROPIC_BASE_URL": BASE[:-3], "ANTHROPIC_MODEL": model,
                    "ANTHROPIC_DEFAULT_HAIKU_MODEL": model, "ANTHROPIC_DEFAULT_SONNET_MODEL": model,
                    "ANTHROPIC_DEFAULT_OPUS_MODEL": model, "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
                    "DISABLE_AUTOUPDATER": "1", "DISABLE_TELEMETRY": "1", "DISABLE_ERROR_REPORTING": "1"})
        env["MAX_THINKING_TOKENS"] = "0"
        # Claude Code asks 32,000 tokens of reply of a model it does not know, and takes a model id
        # that does not start with claude- for a 200,000-token window, which it compacts at
        # (code.claude.com/docs/en/model-config, "Correct the window for a gateway or custom model
        # ID"). It gets this model's reply budget and window.
        env["CLAUDE_CODE_MAX_OUTPUT_TOKENS"] = str(reply)
        env["CLAUDE_CODE_MAX_CONTEXT_TOKENS"] = str(window)
        write(root, ".claude/settings.json", {"model": model, "env": {k: v for k, v in env.items() if k.startswith("ANTHROPIC_")}})
        return ["claude", "--model", model, "--setting-sources", "user"], env
    if harness == "pi":
        env["PI_CODING_AGENT_DIR"] = str(root / ".pi/agent")
        write(root, ".pi/agent/models.json", {"providers": {"solver": {"baseUrl": BASE,
              "api": "openai-completions", "apiKey": LOCAL_KEY, "models": [{"id": mid,
                "contextWindow": sized[mid][0], "maxTokens": sized[mid][1],
                "compat": {"supportsStore": False, "supportsDeveloperRole": False,
                           "supportsReasoningEffort": False, "supportsLongCacheRetention": False,
                           "maxTokensField": "max_tokens"}} for mid in ids]}}})
        write(root, ".pi/agent/settings.json", {"defaultProvider": "solver", "defaultModel": model})
        return ["pi", "--provider", "solver", "--model", model], env
    if harness == "qwen":
        # Without contextWindowSize Qwen Code gives a model it does not know a 200,000-token window
        # (16,700 tokens showed as 8%), and compacts too late.
        write(root, ".qwen/settings.json", {"modelProviders": {"openai": [{"id": mid, "name": mid,
             "baseUrl": BASE, "envKey": "SOLVER_API_KEY", "generationConfig": {"contextWindowSize": sized[mid][0]}} for mid in ids]},
             "security": {"auth": {"selectedType": "openai"}}, "model": {"name": model},
             "telemetry": {"enabled": False}, "general": {"enableAutoUpdate": False}})
        env["OPENAI_MODEL"] = model
        return ["qwen", "--model", model], env
    if harness == "gemini":
        env.update({"GEMINI_API_KEY": LOCAL_KEY, "GOOGLE_GEMINI_BASE_URL": BASE[:-3],
                    "GOOGLE_GENAI_API_VERSION": "v1beta", "GEMINI_TELEMETRY_ENABLED": "false"})
        # Folder trust asked on every start (each start has a fresh home) and restarted Gemini after
        # the answer, losing what was typed. The one-shot runs pass --skip-trust; the VM is the boundary.
        # Gemini CLI compresses the chat at a share of the window it knows for the model (tokenLimit:
        # 1,048,576 for any it does not know), which no option sets; the share is chosen so that it
        # compresses at half of this model's window, as its default does at half of its own, and
        # never later than its default.
        share = min(GEMINI_SHARE, window * GEMINI_SHARE / GEMINI_WINDOWS.get(model, GEMINI_WINDOW))
        write(root, ".gemini/settings.json", {"security": {"auth": {"selectedType": "gemini-api-key"}, "folderTrust": {"enabled": False}},
            "model": {"name": model, "compressionThreshold": share},
            "telemetry": {"enabled": False}, "general": {"enableAutoUpdate": False},
            "tools": {"exclude": ["google_web_search", "web_fetch"]}})
        return ["gemini", "--model", model], env
    if harness == "aider":
        # Aider's own files stay in its home, never in the workspace, so the person's review lists
        # only what Aider changed (it listed its chat history and its tags cache): its chat and input
        # history by its own options, and its repo map's tags cache by AIDER_START and the bridge,
        # as Aider has no option for that. Git in the VM ignores .aider*, which Aider checks, so it
        # adds nothing to the project's .gitignore for them either.
        own = root / AIDER_FILES
        config = {"model": "openai/" + model, "weak-model": "openai/" + model,
                  "editor-model": "openai/" + model, "openai-api-base": BASE, "analytics": False,
                  "check-update": False, "show-release-notes": False, "auto-commits": False,
                  "chat-history-file": str(own / "chat.history.md"), "input-history-file": str(own / "input.history"),
                  "user-input-color": BLUE, "tool-output-color": BLUE, "tool-error-color": BLUE,
                  "tool-warning-color": BLUE, "assistant-output-color": BLUE}
        git_ignored(root, ["/.aider*"])
        env["SOLVER_AIDER_FILES"] = str(own)
        # JSON is a YAML subset, avoiding interpolation of IDs or credentials.
        path = write(root, ".aider.conf.yml", config)
        # Aider fetches LiteLLM's model list from GitHub unless its day-old cache holds entries, and
        # prints the failure in a VM that reaches only the inference. A fresh cache naming this
        # server's models (each one's window and reply budget, as for OpenCode) answers instead.
        write(root, ".aider/caches/model_prices_and_context_window.json",
              {"openai/" + mid: {"max_input_tokens": sized[mid][0], "max_output_tokens": sized[mid][1], "litellm_provider": "openai",
                                 "mode": "chat"} for mid in ids})
        return [BRIDGE_PYTHON, "-I", "-c", AIDER_START, "--config", path, "--model", "openai/" + model], env
    if harness == "interpreter":
        # Open Interpreter takes a model LiteLLM does not know for an 8,000-token window; it gets this
        # model's window and reply budget (its bridge reads the same two options).
        return ["interpreter", "--offline", "--disable_telemetry", "--model", "openai/" + model, "--api_base", BASE,
                "--context_window", str(window), "--max_tokens", str(reply)], env
    if harness == "openhands":
        env.update({"LLM_API_KEY": LOCAL_KEY, "LLM_MODEL": "openai/" + model, "LLM_BASE_URL": BASE,
                    "DO_NOT_TRACK": "1", "LITELLM_LOCAL_MODEL_COST_MAP": "True"})
        write(root, ".openhands/cli_config.json", {"critic_enabled": False})
        env.update(offline_skills(root))
        return ["openhands", "--override-with-envs"], env
    if harness == "pentestgpt":
        env.update({"OLLAMA_BASE_URL": BASE, "OLLAMA_API_KEY": LOCAL_KEY, "LANGFUSE_ENABLED": "false"})
        # Its session log and transcript go to the workspace (it starts there), so they come back to
        # the person's folder after their review; it saves sessions in the workspace's test_history.
        # It starts through PENTESTGPT_WINDOW, which gives it this model's window. Python's -I keeps
        # the workspace off its import path, so a project file named like a module it imports never
        # runs in that module's place.
        return ["/opt/solver/tool/bin/python", "-I", "-c", PENTESTGPT_WINDOW, str(window), "--reasoning-model", "ollama:" + model,
                "--parsing-model", "ollama:" + model, "--generation-model", "ollama:" + model,
                "--base-url", BASE, "--log-dir", PENTESTGPT_LOGS], env
    if harness == "swe":
        env["SWE_AGENT_CONFIG_ROOT"] = "/opt/solver/source"
        env["PIP_NO_INDEX"] = "1"
        blank = write(root, ".swe/empty.env", "")
        # The window, as the bridge gives it: SWE-agent stops with exit_context instead of a refusal.
        return ["sweagent", "run", "--config", "/opt/solver/source/config/default.yaml",
                "--agent.model.name", "openai/" + model, "--agent.model.api_base", BASE,
                "--agent.model.max_input_tokens", str(window),
                "--agent.model.api_key", "$SOLVER_API_KEY", "--agent.model.per_instance_cost_limit", "0",
                "--agent.model.retry.retries", "3", "--agent.model.retry.min_wait", "1", "--agent.model.retry.max_wait", "8",
                "--agent.model.per_instance_call_limit", "50", "--env.deployment.type", "local",
                "--env.repo.type", "preexisting", "--env.repo.repo_name", "workspace", "--env.repo.reset", "false",
                "--agent.tools.reset_commands", '["cd /workspace"]',
                "--env.post_startup_commands", '["cd /workspace"]', "--env_var_path", blank,
                "--output_dir", str(root / ".swe/output")], env
    if harness == "goose":
        # Goose gives a model it does not know 128,000 tokens of window, and one its catalog knows that
        # model's own reply length; both are this model's (env beats config, config/base.rs).
        sizes = {"GOOSE_CONTEXT_LIMIT": window, "GOOSE_MAX_TOKENS": reply}
        # Goose asks whether to share usage data at the first start of every fresh home, before
        # the session, unless telemetry is already decided: off, as nothing leaves the VM anyway.
        env.update({"GOOSE_PROVIDER": "openai", "GOOSE_MODEL": model, "OPENAI_HOST": BASE[:-3],
                    "OPENAI_BASE_PATH": "v1/chat/completions", "GOOSE_DISABLE_SESSION_NAMING": "true",
                    "GOOSE_TELEMETRY_OFF": "1", **{name: str(value) for name, value in sizes.items()}})
        write(root, ".config/goose/config.yaml", {"GOOSE_PROVIDER": "openai", "GOOSE_MODEL": model,
              "OPENAI_HOST": BASE[:-3], "OPENAI_BASE_PATH": "v1/chat/completions", "extensions": {},
              "GOOSE_TELEMETRY_ENABLED": False, **sizes})
        return ["goose"], env
    if harness == "grok":
        # Without context_window Grok takes 200,000 tokens for a model it does not know; it compacts
        # within the window (its user guide, Custom models).
        write(root, ".grok/config.toml", f'''[model.solver]
model = {quote(model)}
base_url = {quote(BASE)}
name = "Inference Solver"
env_key = "SOLVER_API_KEY"
max_completion_tokens = {reply}
context_window = {window}
[models]
default = "solver"
''')
        return ["grok", "--model", "solver"], env
    if harness == "cline":
        # Cline's auth command writes its own schema; only the nonsecret relay
        # token is passed to it. The real service credential is never here.
        env["CLINE_TELEMETRY_DISABLED"] = "1"
        return ["/opt/solver/tool/node_modules/cline/bin/cline", "--config", str(root / ".cline"), "--provider", "openai", "--model", model], env
    raise ValueError("This harness does not yet have a validated isolated launch profile.")


# The Yougori harness (harness/, `yougori-harness --spec engine.json`) shows one screen for every
# harness and drives each one's real engine headless through the protocol it speaks. headless()
# builds that engine.json (harness/src/spec.rs) from the same settings configure() writes for the
# harness's own terminal client. harness/ADAPTERS.md holds what was verified for each harness.

NAMES = {"yougori": "Yougori", "opencode": "OpenCode", "kilo": "Kilo", "codex": "Codex", "pi": "Pi", "qwen": "Qwen Code",
         "cline": "Cline", "claude": "Claude Code", "gemini": "Gemini CLI", "goose": "Goose", "deepseek": "DeepSeek",
         "openhands": "OpenHands", "grok": "Grok", "aider": "Aider", "interpreter": "Open Interpreter", "swe": "SWE-agent",
         "plandex": "Plandex", "strix": "Strix", "shannon": "Shannon", "pentagi": "PentAGI", "pentestgpt": "PentestGPT",
         "hexstrike": "HexStrike"}
SECURITY = {"strix", "shannon", "pentagi", "pentestgpt", "hexstrike"}
RESPEC = ["python3", "/opt/solver/runtime.py", "engine"]
# The screen's switch command (its /harness): runtime.py switch, given the request on stdin.
SWITCH = ["python3", "/opt/solver/runtime.py", "switch"]
# Passed on from the VM so a harness reaches the chosen sites through the VM's proxy.
PASSED_ON = ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy", "SOLVER_EMPTY_WORKSPACE")
PRACTICE_URL = "http://127.0.0.1:8000"
PRACTICE_SERVICE = {"name": "practice-app", "argv": ["python3", "/opt/solver/practice_app.py", "--port", "8000"],
                    "ready_url": PRACTICE_URL + "/", "ready_seconds": 30}
# OpenHands reads its model only from agent_settings.json in its ACP mode; its own code writes it.
# The window and the reply length are the model's (the last two arguments): OpenHands asks a model
# LiteLLM knows for its own reply length (64,000 tokens for some), more than the relay takes.
OPENHANDS_SETTINGS = ("import sys; from openhands.sdk import LLM; from openhands_cli.utils import get_default_cli_agent; "
                      "llm = LLM(model=sys.argv[1], api_key=sys.argv[2], base_url=sys.argv[3], usage_id='agent', "
                      "max_input_tokens=int(sys.argv[5]), max_output_tokens=int(sys.argv[6])); "
                      "agent = get_default_cli_agent(llm=llm); "
                      "open(sys.argv[4], 'w', encoding='utf-8').write(agent.model_dump_json(context={'expose_secrets': True}))")
# PentestGPT's legacy client gives every ollama: model a 128,000-token window, which no option
# changes, and trims each conversation to it (pentestgpt_legacy/llm/registry.py resolve,
# llm/client.py _trim). This starts it with the model's window (its first argument), then its own
# arguments; the window reaches its model lookup (llm/factory.py), its prompts are untouched.
PENTESTGPT_WINDOW = ("import dataclasses, sys; from pentestgpt_legacy.llm import factory; "
                     "window = int(sys.argv.pop(1)); found = factory.resolve; "
                     "sized = lambda spec: dataclasses.replace(spec, context_window=window) "
                     "if spec is not None and spec.provider == 'ollama' else spec; "
                     "factory.resolve = lambda name: sized(found(name)); "
                     "from pentestgpt_legacy.main import main; sys.argv[0] = 'pentestgpt-legacy'; sys.exit(main())")
# Where Aider keeps its own files (its histories, its repo map's tags cache): in the harness's home.
AIDER_FILES = ".aider"
# Starts Aider as its `aider` command does, with its repo map's tags cache in SOLVER_AIDER_FILES, not
# beside the project: Aider 0.86.2 joins RepoMap.TAGS_CACHE_DIR to the project's folder, and has no
# option for it; an absolute folder wins the join. The Aider bridge does the same (bridges/aider_acp.py).
AIDER_START = ("import os, sys; from aider.repomap import RepoMap; "
               "RepoMap.TAGS_CACHE_DIR = os.path.join(os.environ['SOLVER_AIDER_FILES'], os.path.basename(RepoMap.TAGS_CACHE_DIR)); "
               "from aider.main import main; sys.argv[0] = 'aider'; sys.exit(main())")


def reach_of(text):
    """The reach the person chose (SOLVER_REACH): what the VM reaches besides the inference."""
    try:
        value = json.loads(text) if text else {}
    except ValueError:
        value = {}
    if not isinstance(value, dict):
        value = {}
    mode = value.get("mode") if value.get("mode") in ("inference", "sites", "targets", "full") else "inference"
    strings = lambda key: [item for item in value.get(key) or [] if isinstance(item, str)][:256]
    return {"mode": mode, "sites": strings("sites"), "targets": strings("targets")}


def practice_target(spec):
    """A security harness pointed at the practice app: start the app first and test it at its
    loopback address. Shared by every security harness's entry, the bridges' included."""
    answers = spec.setdefault("answers", {})
    if isinstance(answers, dict) and answers.get("target") == "practice":
        spec["services"] = [dict(PRACTICE_SERVICE)] + [s for s in spec.get("services", []) if s.get("name") != "practice-app"]
        answers["target"] = PRACTICE_URL
        answers["practice"] = True
    return spec


# The security harnesses' setup answers (site/harnesses.json) reach the VM in answers.json: target
# ("practice" or the addresses given), permission, off_limits, depth, login_user, source and focus.
# The test login's password is never among them: the VM holds it as YOUGORI_SECRET_LOGIN_PASSWORD,
# and the harness gets that one variable through the spec's secret_env, so it is never in
# arguments, files, logs or reports.
LOGIN_PASSWORD = "YOUGORI_SECRET_LOGIN_PASSWORD"
DEPTHS = {"look": ("Look only", "Observe and map, change nothing."),
          "safe": ("Test safely", "Test without harming data or service."),
          "full": ("Full exploitation", "Confirm each finding, still only within the targets and the off-limits list.")}
# The permission question's refusal (site/harnesses.json): a target other than the practice app
# starts nothing without the person's yes, whoever wrote the answers.
PERMISSION_REFUSAL = "Yougori tests only targets you own or have written permission to test. Nothing was started."


def _words(value):
    """An answer as one line of plain text ("" for anything but text)."""
    return " ".join(value.split()) if isinstance(value, str) else ""


def _items(value):
    """A list answer's items, each one line; a text answer is split at its commas."""
    if isinstance(value, str):
        value = value.split(",")
    if not isinstance(value, list):
        return []
    items = []
    for item in map(_words, value):
        if item and item not in items:
            items.append(item)
    return items


def _sentence(text):
    return text if text.endswith((".", "!", "?")) else text + "."


def _practice(answers):
    """Whether the answers choose the practice app inside the VM."""
    return answers.get("target") == "practice" or answers.get("practice") is True


def setup_targets(answers):
    """What a security harness tests: the practice app's address, or the addresses the person gave
    (each as given, once); empty when the answers name no target."""
    if not isinstance(answers, dict):
        return []
    if _practice(answers):
        return [PRACTICE_URL]
    return _items(answers.get("target"))


def _brief(answers, off_limits=None, focus=None, targets=True):
    """The setup brief's lines; `off_limits` and `focus` replace the answers' own (for a harness
    whose own settings already say the rest). Without `targets` the addresses are left out, for a
    harness that takes each one through its own option."""
    tested = setup_targets(answers)
    if not tested:
        return []
    one = len(tested) == 1
    if _practice(answers):
        where = ("Test only this target: %s, the practice app inside this VM." % PRACTICE_URL if targets
                 else "The target is the practice app inside this VM.")
        lines = [where + " It is deliberately vulnerable and made for this test."]
    else:
        lines = ["Test only %s: %s." % ("this target" if one else "these targets", ", ".join(tested))] if targets else []
        if answers.get("permission") is True:
            lines.append("The person running this test owns %s or has written permission to test %s."
                         % (("this target", "it") if one else ("these targets", "them")))
    off_limits = _items(answers.get("off_limits")) if off_limits is None else off_limits
    if off_limits:
        lines.append("Off limits, never touch: %s." % ", ".join(off_limits))
    label, words = DEPTHS.get(answers.get("depth"), DEPTHS["safe"])
    lines.append("How far it may go: %s. %s" % (label, words))
    focus = _words(answers.get("focus")) if focus is None else focus
    if focus:
        lines.append(_sentence("Focus: " + focus))
    user = _words(answers.get("login_user"))
    if user:
        lines.append(_sentence("Test login: user " + user) + " Its password is in the environment variable %s; use it "
                     "from there and never write it into files, logs or reports." % LOGIN_PASSWORD)
    source = _words(answers.get("source"))
    if source:
        lines.append("Source code: %s, a copy of the project in this VM." % source)
    return lines


def setup_brief(answers, one_line=False):
    """The person's setup answers in plain words, for a security harness to start from: what it
    tests (the practice app's address for the practice app), what is off limits, how far it may
    go, the focus, the test login's user (its password only by the name of the variable holding
    it) and the source code. "" without a target. One line for a client that asks in one line."""
    return (" " if one_line else "\n").join(_brief(answers))


# Shannon refuses its config file when a text in it has one of these (its config-parser.ts), as
# the text goes into its agents' prompts.
SHANNON_REFUSES = re.compile(r"\.\./|[<>]|javascript:|data:|file:", re.IGNORECASE)
SHANNON_HOST = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
SHANNON_WORDS = 1000  # its rules_of_engagement's longest


def _shannon_rule(item, description):
    """One off-limits or focus item as a rule of Shannon's config: a URL path or a host name; None
    for anything else, which only words can say."""
    if item.startswith("/") and not any(c.isspace() for c in item) and len(item) <= 1000:
        return {"description": description, "type": "url_path", "value": item}
    host = item.lower().rstrip(".")
    if len(host) <= 253 and SHANNON_HOST.fullmatch(host):
        return {"description": description, "type": "domain", "value": host}
    return None


def shannon_config(answers):
    """Shannon's own config file (the fields of its pinned config-schema.json) from the setup
    answers: off-limits paths and hosts as rules.avoid, a focus that is one path or host as
    rules.focus, Look only as exploit "false" (its analysis without the exploitation phase), and the
    rest of the brief in words as rules_of_engagement, which Shannon puts into every prompt. The
    targets are not in the words: each one reaches Shannon through its --target, and an address
    such as http://metadata:8000 holds "data:", which Shannon refuses in its settings. No
    authentication section: it needs the password in the file, where it never goes."""
    avoid, unruled = [], []
    for item in _items(answers.get("off_limits")):
        rule = _shannon_rule(item, "Off limits")
        if rule is None or len(avoid) == 50:
            unruled.append(item)
        elif all((r["type"], r["value"]) != (rule["type"], rule["value"]) for r in avoid):
            avoid.append(rule)
    focus = _words(answers.get("focus"))
    focus_rule = _shannon_rule(focus, "Focus") if focus else None
    if focus_rule and any((r["type"], r["value"]) == (focus_rule["type"], focus_rule["value"]) for r in avoid):
        focus_rule = None  # Shannon refuses a rule that is both; off limits wins.
    # Only the person's own words can hold what Shannon refuses: the brief's own words never do.
    for name, texts in (("off-limits list", _items(answers.get("off_limits"))), ("focus", [focus]),
                        ("login", [_words(answers.get("login_user"))]), ("source code folder", [_words(answers.get("source"))])):
        found = next((match for match in map(SHANNON_REFUSES.search, texts) if match), None)
        if found:
            raise ValueError('Shannon refuses ../, <, >, javascript:, data: and file: in its settings, and the %s has '
                             '"%s". Write it another way and start again.' % (name, found.group(0)))
    words = "\n".join(_brief(answers, unruled, "" if focus_rule else focus, targets=False))
    found = SHANNON_REFUSES.search(words)
    if found:
        raise ValueError('Shannon refuses ../, <, >, javascript:, data: and file: in its settings, and its setup has '
                         '"%s". Change the answers and start again.' % found.group(0))
    if len(words) > SHANNON_WORDS:
        raise ValueError("Shannon takes at most %d characters of setup in words and these answers need %d. Shorten the "
                         "off-limits list (paths and host names do not count) or the focus, and start again."
                         % (SHANNON_WORDS, len(words)))
    config = {"rules_of_engagement": words}
    rules = {name: value for name, value in (("avoid", avoid), ("focus", [focus_rule] if focus_rule else [])) if value}
    if rules:
        config["rules"] = rules
    if answers.get("depth") == "look":
        config["exploit"] = "false"
    return config


def shannon_url(target):
    """Shannon tests web addresses: a target given as a host (and port) becomes one, https for no
    port or 443, http otherwise."""
    if "://" in target:
        return target
    host, colon, port = target.rpartition(":")
    if not colon:
        host, port = target, ""
    if port in ("", "443"):
        return "https://" + host
    return "http://" + host + ("" if port == "80" else ":" + port)


def _yougori(spec, model, catalog, root, run):
    git_ignored(root, ["/" + name for name in SETUP_FILES])
    spec.update(protocol="native", profile="yougori", model_switch="live", env=environment(root),
                state_dir=str(Path(root) / ".yougori/state"))


def _acp(command, switch):
    """An ACP agent: its terminal client's settings, started in its ACP mode."""
    def entry(spec, model, catalog, root, run):
        argv, env = configure(spec["harness"], model, catalog, root)
        spec.update(protocol="acp", argv=command(argv, model, root), env=env, model_switch=switch)
    return entry


def _codex(spec, model, catalog, root, run):
    _, env = configure("codex", model, catalog, root)
    # The VM is the boundary: Codex's own sandbox (bubblewrap, which cannot always start in the
    # VM) is not used. How much it asks is the screen's mode, set per thread and turn.
    spec.update(protocol="codex-app-server", env=env, model_switch="live",
                argv=["codex", "app-server", "-c", 'sandbox_mode="danger-full-access"'])


def _claude(spec, model, catalog, root, run):
    _, env = configure("claude", model, catalog, root)
    spec.update(protocol="claude-stream-json", env=env, model_switch="live",
                argv=["claude", "-p", "--input-format", "stream-json", "--output-format", "stream-json", "--verbose",
                      "--include-partial-messages", "--permission-prompt-tool", "stdio", "--model", model,
                      "--setting-sources", "user"])


def _pi(spec, model, catalog, root, run):
    _, env = configure("pi", model, catalog, root)
    spec.update(protocol="pi-rpc", argv=["pi", "--mode", "rpc", "--provider", "solver", "--model", model], env=env,
                model_switch="live")


def _deepseek(spec, model, catalog, root, run):
    argv, env = configure("deepseek", model, catalog, root)
    # dsh's ACP sessions take their provider and model from the patch's `acp` row, not from
    # `agent-default-model`; write() stored the rows as JSON, which YAML reads.
    rows = json.loads(Path(argv[-1]).read_text(encoding="utf-8"))
    rows.append({"id": "acp", "config": {"provider": "solver", "model": model}})
    path = write(Path(root), ".dsh/solver.acp.patch.yml", rows)
    env["DSH_TELEMETRY_DISABLED"] = "1"
    spec.update(protocol="acp", argv=["dsh", "acp", "--patch", path], env=env, model_switch="live")


def _openhands(spec, model, catalog, root, run):
    _, env = configure("openhands", model, catalog, root)
    settings = Path(root) / ".openhands/agent_settings.json"
    settings.parent.mkdir(parents=True, exist_ok=True)
    window, reply = limits(model, catalog)
    try:
        # It runs in the workspace, as the session does. As for PentestGPT, -I keeps the workspace off
        # its import path: a project's own openhands package never replaces OpenHands's.
        done = run(["/opt/solver/tool/bin/python", "-I", "-c", OPENHANDS_SETTINGS, "openai/" + model, LOCAL_KEY, BASE,
                    str(settings), str(window), str(reply)], env=env, capture_output=True, text=True, timeout=180)
    except (OSError, subprocess.SubprocessError) as error:
        raise ValueError("OpenHands could not write its settings: %s" % error)
    if done.returncode:
        raise ValueError("OpenHands could not write its settings: " + (done.stderr or "").strip()[-600:])
    # In its ACP mode OpenHands ignores the LLM_ variables (and says so on every start).
    for name in ("LLM_API_KEY", "LLM_MODEL", "LLM_BASE_URL"):
        env.pop(name, None)
    env["OPENHANDS_SUPPRESS_BANNER"] = "1"
    spec.update(protocol="acp", argv=["openhands", "acp"], env=env, model_switch="restart")


def _cline(spec, model, catalog, root, run):
    argv, env = configure("cline", model, catalog, root)
    # As for its terminal client: Cline's auth command writes its own provider settings
    # (provider openai-compatible) with only the nonsecret relay token.
    try:
        done = run([argv[0], "auth", "--provider", "openai", "--baseurl", BASE, "--apikey", LOCAL_KEY, "--modelid", model],
                   env=env, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError) as error:
        raise ValueError("Cline could not save its provider: %s" % error)
    if done.returncode:
        raise ValueError("Cline could not save its provider: " + (done.stderr or done.stdout or "").strip()[-600:])
    cline_limits(Path(root) / ".cline", *limits(model, catalog))
    env.update({"CLINE_PROVIDER": "openai-compatible", "CLINE_API_KEY": LOCAL_KEY, "CLINE_MODEL": model})
    spec.update(protocol="acp", argv=[argv[0], "--acp", "--config", str(Path(root) / ".cline")], env=env, model_switch="live")


def _terminal(spec, model, catalog, root, run):
    """The harness's own terminal client, shown in the screen's terminal pane."""
    argv, env = configure(spec["harness"], model, catalog, root)
    spec.update(protocol="terminal", argv=argv, env=env, model_switch="restart")


def _security(adapt):
    """A security harness's own terminal client, given the person's setup answers through its own
    options: `adapt` adds them. Without a target in the answers it starts as its terminal client.
    A target other than the practice app starts nothing without the person's yes to the permission
    question, whoever wrote the answers."""
    def entry(spec, model, catalog, root, run):
        _terminal(spec, model, catalog, root, run)
        practice_target(spec)
        answers = spec["answers"]
        if not setup_targets(answers):
            return
        if not _practice(answers) and answers.get("permission") is not True:
            raise ValueError(PERMISSION_REFUSAL)
        if _words(answers.get("login_user")):
            spec["secret_env"][LOGIN_PASSWORD] = "login_password"
        adapt(spec, answers, Path(root))
    return entry


def strix_target(target):
    """A target as Strix's --target takes it: a web address or a host as given, and a host with a
    port (which Strix does not read without a dot in the name) as a web address."""
    if "://" in target or ":" not in target:
        return target
    return shannon_url(target)


def _strix(spec, answers, root):
    # Its own --target for each target and the source code (a local directory, which Strix reads as
    # white-box), its own --instruction with the brief; interactive as its terminal client. It keeps
    # its runs in the home, and each run's report comes to the workspace's reports/strix
    # (strix_cli.py).
    spec["argv"] += ["--target=" + target for target in dict.fromkeys(map(strix_target, setup_targets(answers)))]
    if _words(answers.get("source")):
        spec["argv"].append("--target=" + _words(answers["source"]))
    spec["argv"].append("--instruction=" + setup_brief(answers))


def _reach(spec):
    """Tells the harness's launcher what the VM reaches besides the inference (SOLVER_REACH)."""
    spec["env"]["SOLVER_REACH"] = json.dumps(spec["reach"], separators=(",", ":"))


def _shannon(spec, answers, root):
    # Each target through its --target (shannon_cli scans them in turn, then stays open), focus and
    # off limits in its own config file, and the reach, so a target outside the VM that the VM
    # reaches is allowed. Its runs go to the workspace's .shannon/runs.
    targets = []
    for target in map(shannon_url, setup_targets(answers)):
        if target not in targets:
            targets.append(target)
    path = write(root, ".shannon/yougori-config.yaml", shannon_config(answers))
    spec["argv"] += ["--target=" + target for target in targets] + ["--config=" + path]
    _reach(spec)


def _pentagi(spec, answers, root):
    # Its flow starts with the brief; its questions are answered in its terminal as before, and the
    # flow's messages, their results and its write-ups are saved to the workspace's reports/pentagi.
    spec["argv"].append("--task=" + setup_brief(answers))


def _hexstrike(spec, answers, root):
    # The brief is its first turn, then the person goes on in its terminal; the session's transcript
    # is saved to the workspace's reports/hexstrike. With the reach, its instructions say what the VM
    # reaches, so a target outside it is not called unreachable.
    spec["argv"].append("--task=" + setup_brief(answers))
    _reach(spec)


# PentestGPT's legacy client takes its task only as the answer to its first question (a one-line
# prompt on its terminal) and has no option for it, so the brief is shown first, on one line, for
# the person to paste there.
SHOW_FIRST = 'printf "%s\\n\\n" "$1"; shift; exec "$@"'


def _pentestgpt(spec, answers, root):
    shown = "PentestGPT asks for the task first. Paste this line as its answer:\n" + setup_brief(answers, one_line=True)
    spec["argv"] = ["/bin/sh", "-c", SHOW_FIRST, "pentestgpt", shown, *spec["argv"]]


# Our ACP bridges (bridges/NAME_acp.py) drive the real engines of the harnesses that speak no
# protocol of their own, in the harness's own venv. The bridge takes this inference's models and
# window, then after `--` the arguments configure() gives the harness's terminal client (its
# settings and the relay model); Plandex's bridge starts its server and CLI itself.
BRIDGES = "/opt/solver/bridges"
BRIDGE_PYTHON = "/opt/solver/tool/bin/python"


def _bridge(harness):
    def entry(spec, model, catalog, root, run):
        argv, env = configure(harness, model, catalog, root)
        # Aider's own options, after AIDER_START: the bridge starts Aider in its own process.
        own = {"swe": argv[2:], "plandex": [], "aider": argv[4:]}.get(harness, argv[1:])
        spec.update(protocol="acp", env=env, model_switch="live", argv=[
            BRIDGE_PYTHON, "%s/%s_acp.py" % (BRIDGES, harness), "--model", model, "--models", json.dumps(spec["models"]),
            "--context-window", str(spec["context_window"]), "--max-output", str(spec["max_output"]), "--", *own])
    return entry


HEADLESS = {
    "yougori": _yougori,
    "opencode": _acp(lambda argv, model, root: ["opencode", "acp", "--pure"], "live"),
    "kilo": _acp(lambda argv, model, root: ["kilo", "acp", "--pure"], "live"),
    "qwen": _acp(lambda argv, model, root: ["qwen", "--acp", "--model", model], "live"),
    "gemini": _acp(lambda argv, model, root: ["gemini", "--acp", "--model", model], "live"),
    "goose": _acp(lambda argv, model, root: ["goose", "acp"], "restart"),
    "grok": _acp(lambda argv, model, root: ["grok", "agent", "--model", "solver", "--no-leader", "stdio"], "restart"),
    "deepseek": _deepseek,
    "openhands": _openhands,
    "cline": _cline,
    "codex": _codex,
    "claude": _claude,
    "pi": _pi,
    "aider": _bridge("aider"),
    "interpreter": _bridge("interpreter"),
    "swe": _bridge("swe"),
    "plandex": _bridge("plandex"),
    "strix": _security(_strix),
    "shannon": _security(_shannon),
    "pentagi": _security(_pentagi),
    "pentestgpt": _security(_pentestgpt),
    "hexstrike": _security(_hexstrike),
}


def headless(harness, model, catalog, root, answers=None, cwd=None, reach=None, run=subprocess.run):
    """The engine spec (engine.json) for `harness` on `model`: protocol, command and whole
    environment, this inference's models, the setup answers and reach. Writes the harness's
    settings under `root` as configure() does."""
    entry = HEADLESS.get(harness)
    if entry is None:
        raise ValueError("%s cannot run in the Yougori harness yet: it has no headless profile." % NAMES.get(harness, harness))
    ids = catalog_ids(model, catalog)
    window, reply = limits(model, catalog)
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    spec = {"harness": harness, "name": NAMES.get(harness, harness), "category": "security" if harness in SECURITY else "coding",
            "protocol": "", "argv": [], "env": {}, "secret_env": {}, "cwd": str(cwd or os.getcwd()), "model": model,
            "models": ids, "model_switch": "restart", "respec": RESPEC + [harness], "profile": None, "mcp": [],
            "services": [], "context_window": window, "max_output": reply, "base_url": BASE, "api_key": LOCAL_KEY,
            "answers": dict(answers) if isinstance(answers, dict) else {},
            "reach": reach if isinstance(reach, dict) else reach_of(os.environ.get("SOLVER_REACH")),
            "state_dir": str(root / ".yougori")}
    entry(spec, model, catalog, root, run)
    for name in PASSED_ON:
        if os.environ.get(name):
            spec["env"][name] = os.environ[name]
    if harness in SECURITY:
        practice_target(spec)
    return spec
