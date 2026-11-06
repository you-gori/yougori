"""Private provider bridge: API credentials remain in this sandbox, never in the website."""
import json
import math
import os
import secrets
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from transport import Failure, request
from http_limits import Server, exit_on_stop
import tool_models

PROVIDERS = {
    "openai": ("https://api.openai.com/v1", "OPENAI_API_KEY"),
    "anthropic": ("https://api.anthropic.com/v1", "ANTHROPIC_API_KEY"),
    "google": ("https://generativelanguage.googleapis.com/v1beta/openai", "GEMINI_API_KEY"),
    "kilo": ("https://api.kilo.ai/api/gateway", "KILO_API_KEY"),
    "opencode": ("https://opencode.ai/inference/openai/v1", "OPENCODE_API_KEY"),
}


# Only the paid models documented for Chat Completions. Other OpenCode families use
# Responses, Messages, Gemini or System One. Reviewed 2026-10-24:
# https://opencode.ai/v2/docs/console/models/
OPENCODE_CHAT_MODELS = {
    "qwen3.8-max", "deepseek-v4.1-flash", "deepseek-v4-pro", "minimax-m3", "minimax-m2.7",
    "minimax-m2.5", "glm-5.3-flash", "glm-5.3", "glm-5.2", "glm-5.1", "glm-5",
    "kimi-k2.5", "kimi-k2.6", "kimi-k2.7-code", "kimi-k3", "mistral-large-4",
}


def selected(tool):
    # Older instances have no selection setting. Preserve their existing providers.
    return "SELECTED_PROVIDERS" not in os.environ or tool in os.environ["SELECTED_PROVIDERS"].split(",")


def api_enabled(provider):
    tool = {"openai": "codex", "anthropic": "claude", "google": "gemini"}.get(provider, provider)
    if not selected(tool):
        return False
    if provider == "anthropic":
        return True  # API key only; this template does not offer Claude Code.
    if provider == "kilo" and os.environ.get("KILO_SCOPE", "free") == "free":
        return True  # Anonymous, zero-price models only.
    if provider == "opencode" and os.environ.get("OPENCODE_SCOPE", "free") != "all":
        return False  # The upstream's free chat tier requires its own client.
    return os.environ.get(tool.upper() + "_ACCESS", "api") in ("api", "both")


def headers(provider):
    key = os.environ.get(PROVIDERS[provider][1], "").strip()
    if provider == "anthropic":
        return {"x-api-key": key, "anthropic-version": "2023-06-01"}
    return {"Authorization": "Bearer " + key} if key else {}


def free_model(item):
    pricing = item.get("pricing")
    if not isinstance(pricing, dict) or not {"prompt", "completion"} <= pricing.keys():
        return False
    try:
        return all(not isinstance(value, bool) and math.isfinite(float(value)) and float(value) == 0 for value in pricing.values())
    except (TypeError, ValueError):
        return False


def catalogue(mode):
    models, status, throttled = [], {}, []
    names = ("openai", "anthropic", "google") if mode == "paid" else ("kilo", "opencode")
    for provider in names:
        if not selected({"openai": "codex", "anthropic": "claude", "google": "gemini"}.get(provider, provider)):
            status[provider] = "Not selected during setup."
            continue
        if not api_enabled(provider):
            status[provider] = "Not selected for the website API; subscription access uses its coding-tool terminal."
            continue
        free_only = provider == "kilo" and os.environ.get("KILO_SCOPE", "free") != "all"
        if provider == "kilo" and not free_only and not os.environ.get("KILO_API_KEY", "").strip():
            status[provider] = "Paid gateway models require a Kilo API key."
            continue
        if provider != "kilo" and not os.environ.get(PROVIDERS[provider][1], "").strip():
            status[provider] = "API key not configured"
            continue
        try:
            path, pages = "/models", 0
            while path:
                url = "https://opencode.ai/inference/v1/models" if provider == "opencode" else PROVIDERS[provider][0] + path
                result = request(url, headers=headers(provider), timeout=12)
                rows = result.get("data")
                if not isinstance(rows, list) or len(rows) > 20000:
                    raise Failure(502, "Invalid model catalogue")
                for item in rows:
                    if not isinstance(item, dict) or not isinstance(item.get("id"), str):
                        continue
                    if free_only and not free_model(item):
                        continue
                    name = item["id"]
                    # These OpenCode families use Responses or Messages, not this bridge's
                    # text Chat Completions adapter. Free models remain client-only.
                    if provider == "opencode" and name not in OPENCODE_CHAT_MODELS:
                        continue
                    if provider == "openai" and not name.startswith(("gpt-", "chatgpt-", "o1", "o3", "o4")):
                        continue
                    if provider == "openai" and any(part in name for part in ("image", "realtime", "audio", "transcribe", "tts")):
                        continue
                    models.append({"id": provider + "/" + name, "provider": provider,
                                   "upstream": name, "free": provider == "kilo" and free_model(item)})
                pages += 1
                if result.get("has_more"):
                    if pages >= 20 or not isinstance(result.get("last_id"), str):
                        raise Failure(502, "Incomplete model catalogue")
                    path = "/models?limit=1000&after_id=" + quote(result["last_id"], safe="")
                else:
                    path = None
            status[provider] = "Connected"
        except Failure as error:
            models = [model for model in models if model["provider"] != provider]
            status[provider] = str(error)
            if error.code == "rate_limit":
                # Throttled, not gone: the website keeps this provider's last models listed.
                throttled.append(provider)
    if mode == "free" and selected("opencode") and os.environ.get("OPENCODE_SCOPE", "free") != "all":
        status["opencode"] = "Free chat models require the OpenCode client; use its terminal. Not exported as an API."
    return {"object": "list", "data": models, "status": status, "throttled": throttled}


def completion(mode, data):
    if (not isinstance(data, dict) or not isinstance(data.get("model"), str) or
        not isinstance(data.get("messages"), list) or not data["messages"] or
        any(not isinstance(message, dict) or not isinstance(message.get("content"), str) or
            message.get("role") not in ("system", "developer", "user", "assistant") for message in data["messages"])):
        raise Failure(400, "Send a model and text messages.")
    model = next((item for item in catalogue(mode)["data"] if item["id"] == data.get("model")), None)
    if model is None:
        raise Failure(404, "Model is unavailable; refresh the catalogue.", "model_unavailable")
    if data.get("_yougori_free_only") and not model["free"]:
        raise Failure(409, "This model is no longer free. Refresh the catalogue and set a selling price.", "no_longer_free")
    provider, name = model["provider"], model["upstream"]
    # Rechecking the free catalogue before every call prevents a formerly-free model
    # from silently becoming a paid fallback. No provider fallback is performed.
    payload = {**data, "model": name, "stream": False}
    payload.pop("_yougori_free_only", None)
    limit = payload.pop("max_completion_tokens", payload.pop("max_tokens", 1024))
    if provider == "anthropic":
        systems = [message["content"] for message in data["messages"] if message["role"] in ("system", "developer")]
        payload = {"model": name, "max_tokens": limit,
                   "messages": [message for message in data["messages"] if message["role"] in ("user", "assistant")]}
        if systems:
            payload["system"] = "\n\n".join(systems)
        raw = request(PROVIDERS[provider][0] + "/messages", payload, headers(provider), timeout=180)
        usage = raw.get("usage", {})
        return {"id": raw.get("id", "chatcmpl-" + secrets.token_hex(8)), "object": "chat.completion", "created": int(time.time()),
                "model": model["id"], "choices": [{"index": 0, "message": {"role": "assistant", "content": "".join(
                    block.get("text", "") for block in raw.get("content", []) if block.get("type") == "text")},
                    "finish_reason": "length" if raw.get("stop_reason") == "max_tokens" else "stop"}],
                "usage": {"prompt_tokens": sum(usage.get(key, 0) for key in ("input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens")),
                          "completion_tokens": usage.get("output_tokens", 0)}}
    payload["max_completion_tokens" if provider == "openai" else "max_tokens"] = limit
    answer = request(PROVIDERS[provider][0] + "/chat/completions", payload, headers(provider), timeout=180)
    answer["model"] = model["id"]
    return answer


def snapshot(mode):
    # Tool sign-in checks cannot delay the independent provider API requests.
    with ThreadPoolExecutor(max_workers=2) as pool:
        api = pool.submit(catalogue, mode)
        clients = pool.submit(tool_models.catalogue, mode)
        result, tools = api.result(), clients.result()
    result["toolModels"] = tools["toolModels"]
    result["status"].update(tools["status"])
    return result


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(300)

    def log_message(self, *args):
        pass

    def send(self, status, value):
        data = json.dumps(value, allow_nan=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def authorized(self):
        key = os.environ.get("BRIDGE_KEY", "")
        return bool(key) and secrets.compare_digest(self.headers.get("Authorization", ""), "Bearer " + key)

    def do_GET(self):
        if self.path == "/health":
            return self.send(200, {"ok": True})
        if not self.authorized():
            return self.send(401, {"error": "Bridge authentication required"})
        if self.path not in ("/models", "/v1/models"):
            return self.send(404, {"error": "Not found"})
        self.send(200, snapshot(self.server.mode))

    def do_POST(self):
        if not self.authorized():
            return self.send(401, {"error": "Bridge authentication required"})
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if self.headers.get("Transfer-Encoding") or self.path != "/v1/chat/completions" or not 0 < size <= 131072:
                raise Failure(400, "Invalid request")
            data = json.loads(self.rfile.read(size))
            self.send(200, completion(self.server.mode, data))
        except Failure as error:
            self.send(error.status, {"error": {"message": str(error), "code": error.code}})
        except (ValueError, TypeError, KeyError, AttributeError):
            self.send(502, {"error": "Invalid request or provider response"})


if __name__ == "__main__":
    if len(os.environ.get("BRIDGE_KEY", "")) < 16:
        raise SystemExit("Set BRIDGE_KEY to at least 16 characters through a Hub secret.")
    exit_on_stop()
    server = Server(("0.0.0.0", int(os.environ.get("BRIDGE_PORT", "8080"))), Handler)
    server.mode = os.environ.get("BRIDGE_MODE", "paid")
    server.serve_forever()
