"""Yougori model gateway: one hosted model, reached from inside this setup only.

The setup's other sandboxes call this gateway as an OpenAI-compatible API, at
http://model_gateway:8080/v1. It holds the provider's key itself, so they never see it, and it
keeps to what the template said:

* FREE_ONLY=yes: a request for a model the provider charges for is refused (402,
  "no_longer_free"), and the price is looked at again every ten minutes, so a model that starts
  costing money is refused from then on.
* BUDGET_USD=N: what this calendar month's requests cost is added up from the usage the provider
  reports, and a request that could take the month past N is refused (402, "budget_reached")
  before it is sent, so the limit is never passed.
* MODEL=ID: only that model is used; a request that names another is refused.

What it has spent, and what it refused, is kept in /data/usage.json, which survives restarts.
Nothing a request carries is kept. Standard library only.
"""
import datetime
import http.server
import json
import os
import threading
import time
import urllib.error
import urllib.request

PROVIDERS = {
    "openrouter": "https://openrouter.ai/api/v1",
    "openai": "https://api.openai.com/v1",
    "anthropic": "https://api.anthropic.com/v1",
    "gemini": "https://generativelanguage.googleapis.com/v1beta/openai",
    "groq": "https://api.groq.com/openai/v1",
    "mistral": "https://api.mistral.ai/v1",
    "deepseek": "https://api.deepseek.com/v1",
    "together": "https://api.together.xyz/v1",
}

PROVIDER = os.environ.get("PROVIDER", "openrouter").strip().lower()
UPSTREAM = (os.environ.get("BASE_URL", "").strip() or PROVIDERS.get(PROVIDER, "")).rstrip("/")
KEY = os.environ.get("UPSTREAM_KEY", "")
MODEL = os.environ.get("MODEL", "").strip()
FREE_ONLY = os.environ.get("FREE_ONLY", "no").strip().lower() in ("yes", "true", "1")
BUDGET = float(os.environ.get("BUDGET_USD", "0") or 0)
# Dollars per million tokens, "PROMPT,COMPLETION", for a provider that publishes no price list.
PRICES = os.environ.get("PRICES", "").strip()
STATE = os.environ.get("STATE", "/data/usage.json")
PORT = int(os.environ.get("PORT", "8080"))
LARGEST_BODY = 8 * 1024 * 1024
# A request that does not say how long its answer may be is counted as this long when it is
# checked against the budget.
ASSUMED_ANSWER_TOKENS = 4096
CATALOGUE_FOR = 600

lock = threading.Lock()


def this_month():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m")


def load():
    try:
        with open(STATE, encoding="utf-8") as file:
            state = json.load(file)
    except (OSError, ValueError):
        state = {}
    if state.get("month") != this_month():
        state = {"month": this_month(), "spentUsd": 0.0, "requests": 0, "refused": 0, "unpriced": 0}
    return state


def save(state):
    folder = os.path.dirname(STATE) or "."
    os.makedirs(folder, exist_ok=True)
    staged = STATE + ".new"
    with open(staged, "w", encoding="utf-8") as file:
        json.dump(state, file)
    os.replace(staged, STATE)


state = load()
catalogue = {"at": 0.0, "prices": {}}


def prices():
    """Each model's price as the provider lists it: dollars per token, (prompt, completion)."""
    if time.time() - catalogue["at"] < CATALOGUE_FOR:
        return catalogue["prices"]
    found = {}
    try:
        request = urllib.request.Request(UPSTREAM + "/models", headers={"Authorization": "Bearer " + KEY})
        with urllib.request.urlopen(request, timeout=20) as answer:
            listed = json.load(answer)
        for model in listed.get("data", []):
            pricing = model.get("pricing") or {}
            if "prompt" in pricing and "completion" in pricing:
                found[model.get("id", "")] = (float(pricing["prompt"]), float(pricing["completion"]))
    except (OSError, ValueError, urllib.error.URLError):
        return catalogue["prices"]
    catalogue["at"] = time.time()
    catalogue["prices"] = found
    return found


def price_of(model):
    listed = prices().get(model)
    if listed is not None:
        return listed
    if PRICES:
        prompt, completion = (float(part) / 1_000_000 for part in PRICES.split(",", 1))
        return (prompt, completion)
    return None


def is_free(model):
    price = price_of(model)
    return price is not None and price[0] == 0 and price[1] == 0


def refuse(handler, status, code, message):
    with lock:
        state["refused"] = state.get("refused", 0) + 1
        save(state)
    body = json.dumps({"error": {"message": message, "type": code, "code": code}}).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def record(model, usage):
    """Adds what one answer cost, from the usage the provider reported."""
    if not isinstance(usage, dict):
        return
    cost = usage.get("cost")
    if not isinstance(cost, (int, float)):
        price = price_of(model)
        if price is None:
            with lock:
                state["unpriced"] = state.get("unpriced", 0) + 1
            return
        cost = usage.get("prompt_tokens", 0) * price[0] + usage.get("completion_tokens", 0) * price[1]
    with lock:
        if state.get("month") != this_month():
            state.update(load())
        state["spentUsd"] = round(state.get("spentUsd", 0.0) + float(cost), 6)
        save(state)


class Gateway(http.server.BaseHTTPRequestHandler):
    server_version = "YougoriModelGateway/1"

    def log_message(self, format, *args):
        # The path and status only: never a request's text.
        print("%s %s" % (self.command, self.path.split("?")[0]), flush=True)

    def answer(self, status, value):
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/yougori/health":
            return self.answer(200, {"ok": bool(UPSTREAM and KEY)})
        if path == "/yougori/usage":
            with lock:
                if state.get("month") != this_month():
                    state.update(load())
                shown = dict(state, budgetUsd=BUDGET, freeOnly=FREE_ONLY, model=MODEL, provider=PROVIDER)
            return self.answer(200, shown)
        if path == "/v1/models":
            ids = [MODEL] if MODEL else sorted(prices())
            if FREE_ONLY:
                ids = [model for model in ids if is_free(model)]
            return self.answer(200, {"object": "list", "data": [{"id": model, "object": "model"} for model in ids]})
        return self.answer(404, {"error": {"message": "Nothing is here.", "code": "not_found"}})

    def do_POST(self):
        path = self.path.split("?")[0]
        if not path.startswith("/v1/"):
            return self.answer(404, {"error": {"message": "Nothing is here.", "code": "not_found"}})
        length = int(self.headers.get("Content-Length") or 0)
        if length > LARGEST_BODY:
            return refuse(self, 413, "too_large", "This request is larger than the gateway takes.")
        raw = self.rfile.read(length)
        try:
            body = json.loads(raw or b"{}")
        except ValueError:
            return refuse(self, 400, "invalid_request", "The request is not JSON.")
        model = body.get("model") or MODEL
        if MODEL and model != MODEL:
            return refuse(self, 403, "model_not_allowed", "This setup uses %s only." % MODEL)
        body["model"] = model
        if FREE_ONLY and not is_free(model):
            return refuse(self, 402, "no_longer_free", "%s costs money, and this setup uses free models only." % model)
        if BUDGET > 0:
            price = price_of(model)
            if price is None:
                return refuse(self, 402, "price_unknown", "The price of %s isn't known, so this setup can't keep to its budget. Set PRICES." % model)
            most = body.get("max_tokens") or body.get("max_completion_tokens") or ASSUMED_ANSWER_TOKENS
            estimate = (len(raw) / 3.0) * price[0] + float(most) * price[1]
            with lock:
                spent = state.get("spentUsd", 0.0) if state.get("month") == this_month() else 0.0
            if spent + estimate > BUDGET:
                return refuse(self, 402, "budget_reached", "This request could take this month past its budget of $%.2f ($%.4f spent)." % (BUDGET, spent))
        stream = bool(body.get("stream"))
        if stream:
            options = body.get("stream_options") or {}
            options["include_usage"] = True
            body["stream_options"] = options
        if PROVIDER == "openrouter":
            body["usage"] = {"include": True}
        request = urllib.request.Request(UPSTREAM + path[len("/v1"):], data=json.dumps(body).encode(), method="POST", headers={"Authorization": "Bearer " + KEY, "Content-Type": "application/json"})
        with lock:
            state["requests"] = state.get("requests", 0) + 1
        try:
            answer = urllib.request.urlopen(request, timeout=600)
        except urllib.error.HTTPError as error:
            text = error.read()
            self.send_response(error.code)
            self.send_header("Content-Type", error.headers.get("Content-Type", "application/json"))
            self.send_header("Content-Length", str(len(text)))
            self.end_headers()
            self.wfile.write(text)
            return
        except (OSError, urllib.error.URLError) as error:
            return refuse(self, 502, "upstream_unreachable", "The provider couldn't be reached: %s" % error)
        with answer:
            if stream:
                self.send_response(answer.status)
                self.send_header("Content-Type", answer.headers.get("Content-Type", "text/event-stream"))
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                usage = None
                for line in answer:
                    self.wfile.write(line)
                    self.wfile.flush()
                    text = line.decode("utf-8", "replace").strip()
                    if text.startswith("data:") and '"usage"' in text:
                        try:
                            usage = json.loads(text[5:].strip()).get("usage") or usage
                        except ValueError:
                            pass
                record(model, usage)
                return
            text = answer.read()
            self.send_response(answer.status)
            self.send_header("Content-Type", answer.headers.get("Content-Type", "application/json"))
            self.send_header("Content-Length", str(len(text)))
            self.end_headers()
            self.wfile.write(text)
            try:
                record(model, json.loads(text).get("usage"))
            except ValueError:
                pass


if __name__ == "__main__":
    save(state)
    http.server.ThreadingHTTPServer(("0.0.0.0", PORT), Gateway).serve_forever()
