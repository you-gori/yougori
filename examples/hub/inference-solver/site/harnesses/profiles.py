"""Per-harness settings. Only an isolated loopback relay is a model provider.

Nothing reads the host's provider profiles or subscription credentials. The
networkless Yougori VM enforces isolation even if a project changes settings.
"""
import json
import os
from pathlib import Path

BASE = "http://127.0.0.1:8080/v1"
LOCAL_KEY = "solver-local-relay"  # Not a service credential; the relay holds that.
BLUE = "#5297ff"


def write(root, name, value):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value if isinstance(value, str) else json.dumps(value, indent=2), encoding="utf-8")
    return str(path)


def configure(harness, model, catalog, root):
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    # Fresh home: Yougori never passes through host env or provider credentials.
    env = {"PATH": "/opt/solver/tool/node_modules/.bin:/opt/solver/tool/bin:/usr/local/bin:/usr/bin:/bin",
           "HOME": str(root), "XDG_CONFIG_HOME": str(root / ".config"), "XDG_DATA_HOME": str(root / ".local/share"),
           "TERM": "xterm-256color", "COLORTERM": "truecolor", "LANG": "C.UTF-8",
           "SOLVER_API_KEY": LOCAL_KEY, "OPENAI_API_KEY": LOCAL_KEY, "OPENAI_BASE_URL": BASE,
           "OPENAI_API_BASE": BASE, "DO_NOT_TRACK": "1", "NO_ANALYTICS": "1",
           "LITELLM_LOCAL_MODEL_COST_MAP": "True"}
    ids = [item["id"] for item in catalog]
    if model not in ids:
        raise ValueError("Choose a model from this server's live catalog.")
    quote = json.dumps
    if harness == "pentagi":
        return ["python3", "/opt/solver/pentagi_cli.py", "--model", model], env
    if harness == "shannon":
        return ["python3", "/opt/solver/shannon_cli.py", "--model", model], env
    if harness == "plandex":
        return ["python3", "/opt/solver/plandex_cli.py", "--solver-model", model], env
    if harness == "strix":
        env.update(STRIX_LLM="openai/"+model,STRIX_API_TYPE="chat_completions",STRIX_RUNTIME_BACKEND="yougori_vm",
                   STRIX_TELEMETRY="false",OPENAI_AGENTS_DISABLE_TRACING="1",STRIX_REASONING_EFFORT="none")
        return ["/opt/solver/tool/bin/python", "/opt/solver/strix_cli.py"], env
    if harness == "hexstrike":
        return ["/opt/solver/tool/bin/python", "/opt/solver/hexstrike_cli.py", "--model", model], env
    if harness == "deepseek":
        env["DSH_HOME"] = str(root / ".dsh")
        env["NARB_DISABLE_NATIVE_CACHE"] = "1"
        path = write(root, ".dsh/solver.patch.yml", [
            {"id": "agent-default-model", "config": {"provider": "solver", "model": model}},
            {"id": "deepseek-account", "disabled": True},
            {"id": "llm-pi-ai", "config": {"providers": {"solver": {"apiKeyEnv": "SOLVER_API_KEY",
                "displayName": "Inference Solver", "api": "openai-completions", "baseURL": BASE,
                "models": [{"id": mid} for mid in ids]}}}}
        ])
        return ["dsh", "tui", "--patch", path], env
    if harness in ("opencode", "kilo"):
        name = harness
        config = {"enabled_providers": ["solver"], "model": "solver/" + model, "small_model": "solver/" + model,
                  "autoupdate": False, "share": "disabled", "plugin": [],
                  "provider": {"solver": {"npm": "@ai-sdk/openai-compatible", "name": "Inference Solver",
                    "options": {"baseURL": BASE, "apiKey": LOCAL_KEY},
                    "models": {mid: {"name": mid} for mid in ids}}}}
        path = write(root, f".config/{name}/{name}.json", config)
        env[name.upper() + "_CONFIG"] = path
        env[name.upper() + "_CONFIG_CONTENT"] = json.dumps(config)
        env[name.upper() + "_DISABLE_MODELS_FETCH"] = "true"
        env[name.upper() + "_DISABLE_AUTOUPDATE"] = "true"
        env[name.upper() + "_DISABLE_PROJECT_CONFIG"] = "true"
        return [name, "--pure", "--model", "solver/" + model], env
    if harness == "codex":
        env["CODEX_HOME"] = str(root / ".codex")
        catalog_path = write(root, ".codex/solver-models.json", {"models": [{
            "slug": mid, "display_name": mid, "description": "Inference Solver model", "visibility": "list",
            "supported_in_api": True, "priority": index, "supported_reasoning_levels": [],
            "shell_type": "unified_exec", "support_verbosity": False, "default_reasoning_summary": "none",
            "truncation_policy": {"mode": "tokens", "limit": 10000}, "experimental_supported_tools": [],
            "input_modalities": ["text"], "supports_search_tool": False, "tool_mode": "direct",
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
        return ["codex", "--model", model], env
    if harness == "claude":
        env.update({"CLAUDE_CONFIG_DIR": str(root / ".claude"), "ANTHROPIC_API_KEY": LOCAL_KEY,
                    "ANTHROPIC_BASE_URL": BASE[:-3], "ANTHROPIC_MODEL": model,
                    "ANTHROPIC_DEFAULT_HAIKU_MODEL": model, "ANTHROPIC_DEFAULT_SONNET_MODEL": model,
                    "ANTHROPIC_DEFAULT_OPUS_MODEL": model, "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
                    "DISABLE_AUTOUPDATER": "1", "DISABLE_TELEMETRY": "1", "DISABLE_ERROR_REPORTING": "1"})
        env["MAX_THINKING_TOKENS"] = "0"
        write(root, ".claude/settings.json", {"model": model, "env": {k: v for k, v in env.items() if k.startswith("ANTHROPIC_")}})
        return ["claude", "--model", model, "--setting-sources", "user"], env
    if harness == "pi":
        env["PI_CODING_AGENT_DIR"] = str(root / ".pi/agent")
        write(root, ".pi/agent/models.json", {"providers": {"solver": {"baseUrl": BASE,
              "api": "openai-completions", "apiKey": LOCAL_KEY, "models": [{"id": mid,
                "contextWindow": 32768, "maxTokens": 4096,
                "compat": {"supportsStore": False, "supportsDeveloperRole": False,
                           "supportsReasoningEffort": False, "supportsLongCacheRetention": False,
                           "maxTokensField": "max_tokens"}} for mid in ids]}}})
        write(root, ".pi/agent/settings.json", {"defaultProvider": "solver", "defaultModel": model})
        return ["pi", "--provider", "solver", "--model", model], env
    if harness == "qwen":
        write(root, ".qwen/settings.json", {"modelProviders": {"openai": [{"id": mid, "name": mid,
             "baseUrl": BASE, "envKey": "SOLVER_API_KEY"} for mid in ids]},
             "security": {"auth": {"selectedType": "openai"}}, "model": {"name": model},
             "telemetry": {"enabled": False}, "general": {"enableAutoUpdate": False}})
        env["OPENAI_MODEL"] = model
        return ["qwen", "--model", model], env
    if harness == "gemini":
        env.update({"GEMINI_API_KEY": LOCAL_KEY, "GOOGLE_GEMINI_BASE_URL": BASE[:-3],
                    "GOOGLE_GENAI_API_VERSION": "v1beta", "GEMINI_TELEMETRY_ENABLED": "false"})
        write(root, ".gemini/settings.json", {"security": {"auth": {"selectedType": "gemini-api-key"}},
            "model": {"name": model}, "telemetry": {"enabled": False}, "general": {"enableAutoUpdate": False},
            "tools": {"exclude": ["google_web_search", "web_fetch"]}})
        return ["gemini", "--model", model], env
    if harness == "aider":
        config = {"model": "openai/" + model, "weak-model": "openai/" + model,
                  "editor-model": "openai/" + model, "openai-api-base": BASE, "analytics": False,
                  "check-update": False, "show-release-notes": False, "auto-commits": False,
                  "user-input-color": BLUE, "tool-output-color": BLUE, "tool-error-color": BLUE,
                  "tool-warning-color": BLUE, "assistant-output-color": BLUE}
        # JSON is a YAML subset, avoiding interpolation of IDs or credentials.
        path = write(root, ".aider.conf.yml", config)
        return ["aider", "--config", path, "--model", "openai/" + model], env
    if harness == "interpreter":
        return ["interpreter", "--offline", "--disable_telemetry", "--model", "openai/" + model, "--api_base", BASE], env
    if harness == "openhands":
        env.update({"LLM_API_KEY": LOCAL_KEY, "LLM_MODEL": "openai/" + model, "LLM_BASE_URL": BASE,
                    "DO_NOT_TRACK": "1", "LITELLM_LOCAL_MODEL_COST_MAP": "True"})
        write(root, ".openhands/cli_config.json", {"critic_enabled": False})
        return ["openhands", "--override-with-envs"], env
    if harness == "pentestgpt":
        env.update({"OLLAMA_BASE_URL": BASE, "OLLAMA_API_KEY": LOCAL_KEY, "LANGFUSE_ENABLED": "false"})
        return ["pentestgpt-legacy", "--reasoning-model", "ollama:" + model,
                "--parsing-model", "ollama:" + model, "--generation-model", "ollama:" + model,
                "--base-url", BASE, "--log-dir", str(root / ".pentestgpt/logs")], env
    if harness == "swe":
        env["SWE_AGENT_CONFIG_ROOT"] = "/opt/solver/source"
        env["PIP_NO_INDEX"] = "1"
        blank = write(root, ".swe/empty.env", "")
        return ["sweagent", "run", "--config", "/opt/solver/source/config/default.yaml",
                "--agent.model.name", "openai/" + model, "--agent.model.api_base", BASE,
                "--agent.model.api_key", "$SOLVER_API_KEY", "--agent.model.per_instance_cost_limit", "0",
                "--agent.model.retry.retries", "3", "--agent.model.retry.min_wait", "1", "--agent.model.retry.max_wait", "8",
                "--agent.model.per_instance_call_limit", "50", "--env.deployment.type", "local",
                "--env.repo.type", "preexisting", "--env.repo.repo_name", "workspace", "--env.repo.reset", "false",
                "--agent.tools.reset_commands", '["cd /workspace"]',
                "--env.post_startup_commands", '["cd /workspace"]', "--env_var_path", blank,
                "--output_dir", str(root / ".swe/output")], env
    if harness == "goose":
        env.update({"GOOSE_PROVIDER": "openai", "GOOSE_MODEL": model, "OPENAI_HOST": BASE[:-3],
                    "OPENAI_BASE_PATH": "v1/chat/completions", "GOOSE_DISABLE_SESSION_NAMING": "true"})
        write(root, ".config/goose/config.yaml", {"GOOSE_PROVIDER": "openai", "GOOSE_MODEL": model,
              "OPENAI_HOST": BASE[:-3], "OPENAI_BASE_PATH": "v1/chat/completions", "extensions": {}})
        return ["goose"], env
    if harness == "grok":
        write(root, ".grok/config.toml", f'''[model.solver]
model = {quote(model)}
base_url = {quote(BASE)}
name = "Inference Solver"
env_key = "SOLVER_API_KEY"
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
