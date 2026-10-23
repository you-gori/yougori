"""Development-only, fixed-provider model relay. Keys arrive via protected env bindings."""
import hmac
import json
import os
import threading
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


def provider_url(value):
    parsed = urllib.parse.urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or parsed.path.rstrip("/") != "/v1"):
        raise ValueError("The provider must be an HTTPS /v1 endpoint without credentials")
    return value.rstrip("/") + "/chat/completions"


class Relay(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, model, base_url, provider_key, local_key, context=65536):
        self.model = model
        self.url = provider_url(base_url)
        self.provider_key = provider_key
        self.local_key = local_key
        self.context = context
        self.slot = threading.Lock()
        self.opener = urllib.request.build_opener(NoRedirects)
        super().__init__(address, Handler)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def send(self, value, status=200):
        data = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def authorized(self):
        if hmac.compare_digest(self.headers.get("Authorization", ""), "Bearer " + self.server.local_key):
            return True
        self.send({"error": {"message": "Invalid private relay credential"}}, 401)
        return False

    def do_GET(self):
        if not self.authorized():
            return
        if self.path == "/health":
            return self.send({"status": "ready", "model": self.server.model, "context": self.server.context,
                "developmentApi": True, "optimizer": {"supported": False, "enabled": False,
                    "active": int(self.server.slot.locked()), "pending": 0, "loading": False, "pinned": False}})
        if self.path == "/v1/models":
            return self.send({"object": "list", "data": [{"id": self.server.model, "object": "model"}]})
        self.send({"error": {"message": "Endpoint not found"}}, 404)

    def do_POST(self):
        if not self.authorized():
            return
        if self.path != "/v1/chat/completions":
            return self.send({"error": {"message": "Endpoint not found"}}, 404)
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 1048576:
                return self.send({"error": {"message": "Conversation exceeds relay bounds"}}, 413)
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict) or body.get("model", self.server.model) != self.server.model:
                raise ValueError("Use this worker's configured model")
            tokens = body.get("max_tokens", 2048)
            if type(tokens) is not int or not 1 <= tokens <= 8192:
                raise ValueError("Development output must be between 1 and 8192 tokens")
            if not isinstance(body.get("messages"), list):
                raise ValueError("A conversation is required")
            body["model"] = self.server.model
            body["max_tokens"] = tokens
        except (ValueError, TypeError):
            return self.send({"error": {"message": "Invalid bounded model request"}}, 400)
        if not self.server.slot.acquire(blocking=False):
            return self.send({"error": {"message": "Model busy; retry shortly"}}, 429)
        started = False
        try:
            request = urllib.request.Request(self.server.url, data=json.dumps(body).encode(), headers={
                "Authorization": "Bearer " + self.server.provider_key, "Content-Type": "application/json",
                "User-Agent": "Yougori/1.1 (development model relay)"})
            with self.server.opener.open(request, timeout=330) as upstream:
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream" if body.get("stream") else "application/json")
                self.send_header("Connection", "close")
                self.end_headers()
                started = True
                total = 0
                while chunk := upstream.read1(65536):
                    total += len(chunk)
                    if total > 16 * 1024 * 1024:
                        break
                    self.wfile.write(chunk)
                    self.wfile.flush()
                self.close_connection = True
        except urllib.error.HTTPError as error:
            # Never echo provider bodies: they can contain request data or credentials.
            message = {401: "Provider rejected the API key", 402: "Provider account has insufficient credit",
                       403: "Provider denied the request", 429: "Provider rate limit reached; retry shortly"}.get(
                           error.code, "Provider could not complete this model request")
            self.send({"error": {"message": message}}, error.code if 400 <= error.code <= 599 else 502)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            if not started:
                self.send({"error": {"message": "Provider connection failed"}}, 502)
            self.close_connection = True
        finally:
            self.server.slot.release()


if __name__ == "__main__":
    Relay(("0.0.0.0", 8000), os.environ["YOUGORI_MODEL"], os.environ["YOUGORI_API_BASE_URL"],
          os.environ["YOUGORI_API_KEY"], os.environ["YOUGORI_MODEL_TOKEN"]).serve_forever()
