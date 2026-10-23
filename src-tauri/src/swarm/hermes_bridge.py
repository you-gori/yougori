"""Private Yougori supervisor transport around the pinned Hermes AIAgent.

Each turn uses a fresh process. Abort kills that process, closes inference, and
cannot transfer a stale tool to another lease. This server never controls model
residency. No Hermes CLI, shell, plugins, MCP, or user configuration is exposed.
"""
import argparse
import base64
import contextlib
import hmac
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from hermes_tools import DEFINITIONS, ManagedTools

REVISION = "4d04303818b61bf3aa09278af48356315515965b"


class LiveParts:
    """Bounded text deltas; one stable part per response/channel, never per token."""
    def __init__(self, emit):
        self.emit = emit
        self.parts = {}
        self.last_text = ""

    def delta(self, text, kind="text"):
        if text is None:
            self.close()
            return
        if not text:
            return
        part = self.parts.setdefault(kind, {"id": uuid.uuid4().hex, "type": kind, "text": ""})
        addition = str(text)[:max(0, 65536 - len(part["text"]))]
        if addition:
            part["text"] += addition
            self.emit({"delta": {"id": part["id"], "type": kind, "text": addition}})

    def close(self):
        for part in self.parts.values():
            self.emit({"part": {**part, "time": {"end": int(time.time() * 1000)}}})
            if part["type"] == "text":
                self.last_text = part["text"]
        self.parts.clear()

    def tool_finished(self):
        self.close()
        self.last_text = ""

    def finish(self, final_text=""):
        streamed = self.parts.get("text", {}).get("text", self.last_text)
        # A provider may fall back to a non-streaming response. Preserve it,
        # but never append the final response a second time after streaming it.
        if final_text and not streamed:
            self.delta(str(final_text))
        self.close()


def run_turn(config, root, session, prompt, emit, probe=False):
    # Bind before importing any runtime/config/plugin module. This API is pinned
    # with Hermes; safe mode prevents discovery of ambient plugins and MCP.
    from agent.safe_worker_policy import _bind_safe_worker_policy
    _bind_safe_worker_policy(safe_mode=True, ignore_user_config=True, config={
        "model": {"default": config["model"], "provider": "custom", "base_url": config["baseUrl"],
                  "context_length": config.get("context", 32768)},
        "auxiliary": {"title_generation": {"enabled": False}, "compression": {
            "provider": "custom", "model": config["model"], "base_url": config["baseUrl"],
            "api_key": config["apiKey"], "timeout": config.get("requestTimeoutSeconds", 330)}},
        "compression": {"enabled": True, "threshold": 0.75, "protect_last_n": 4},
        "memory": {"memory_enabled": False, "user_profile_enabled": False},
        "tools": {"tool_search": {"enabled": "off"}},
        "providers": {"custom": {"request_timeout_seconds": config.get("requestTimeoutSeconds", 330),
                                  "stale_timeout_seconds": config.get("requestTimeoutSeconds", 330)}},
        # The native owner recovers a crashed local model. Hand failures back
        # immediately instead of waiting through Hermes' hosted-provider retries.
        "agent": {"max_turns": 32, "api_max_retries": 1, "auto_recovery_cycles": 0},
        "display": {"tool_progress": "none"}})
    from run_agent import AIAgent
    from agent import agent_init, model_metadata
    # Upstream's 64K floor budgets for its general-purpose tool/prompt surface.
    # Swarm has ten bounded tools, an explicit short system prompt and fresh
    # turns. Adapt that sizing heuristic, never inflate the reported context or
    # change the model's KV allocation. Native scope/budget enforcement is intact.
    agent_init.MINIMUM_CONTEXT_LENGTH = 8192
    model_metadata.MINIMUM_CONTEXT_LENGTH = 8192
    import model_tools  # Complete built-in discovery before registering the bounded tools.
    ManagedTools(root, session).register()

    live = LiveParts(emit)

    def finished(call_id, name, args, result):
        live.tool_finished()
        from agent.display import _detect_tool_failure
        failed = _detect_tool_failure(name, result)[0]
        emit({"part": {"id": str(call_id), "type": "tool", "tool": name,
              "state": {"status": "error" if failed else "completed", "input": args, "output": str(result)[:16000]}}})

    agent = AIAgent(model=config["model"], provider="custom", api_mode="chat_completions",
                    base_url=config["baseUrl"], api_key=config["apiKey"],
                    enabled_toolsets=["yougori_swarm"], max_iterations=32,
                    max_tokens=config["maxTokens"], quiet_mode=True, session_id=session,
                    skip_context_files=True, skip_memory=True, skip_background_review=True,
                    load_soul_identity=False, fallback_model={}, cwd=str(root),
                    tool_complete_callback=finished, stream_delta_callback=live.delta,
                    reasoning_callback=lambda text: live.delta(text, "reasoning"),
                    run_budget_seconds=890)
    # Fail closed if upstream ever expands this toolset implicitly.
    actual = {tool["function"]["name"] for tool in agent.tools}
    if actual != set(DEFINITIONS):
        raise RuntimeError("Hermes managed tool allowlist mismatch")
    if agent.context_compressor.context_length != config.get("context", 32768):
        raise RuntimeError("Hermes context differs from the model's actual window")
    emit({"ready": True, "tools": sorted(actual)})
    try:
        if probe:
            return
        result = agent.run_conversation(prompt, system_message=config["prompt"])
        live.finish(result.get("final_response") or "")
        failed = result.get("error") or result.get("failed") or result.get("interrupted")
        emit({"done": True, "info": {"error": {"name": "APIError"}} if failed else {}})
    finally:
        live.close()
        agent.release_clients()


def child(args):
    config = json.loads(Path(args.config).read_text(encoding="utf-8"))
    prompt = json.loads(sys.stdin.readline())["prompt"]
    output = sys.stdout
    lock = threading.Lock()

    def emit(value):
        with lock:
            output.write(json.dumps(value) + "\n")
            output.flush()

    # SDK startup notices must never corrupt the supervisor event stream.
    with contextlib.redirect_stdout(sys.stderr):
        try:
            run_turn(config, Path(args.root), args.session, prompt, emit, probe=args.probe)
        except Exception as error:
            name = type(error).__name__
            classification = {"AuthenticationError": "ProviderAuthError", "NotFoundError": "ProviderModelNotFoundError"}.get(name, "APIError")
            emit({"done": True, "info": {"error": {"name": classification, "data": {"class": name}}}})
            # Class only: provider exceptions can contain credentials or private prompts.
            print(f"Hermes turn failed ({name})", file=sys.stderr)


class Session:
    def __init__(self):
        self.lock = threading.Lock()
        self.process = None
        self.aborted = False
        self.started = False
        self.parts = []
        self.home = None

    def record(self, event):
        part = event.get("part") or event.get("delta")
        if not part:
            return
        with self.lock:
            for index, previous in enumerate(self.parts):
                if previous["id"] == part["id"]:
                    self.parts[index] = ({**previous, "text": (previous.get("text", "") + part["text"])[:65536]}
                                         if "delta" in event else part)
                    return
            if len(self.parts) < 128:
                self.parts.append(part)

    def abort(self):
        with self.lock:
            self.aborted = True
            process = self.process
            if process and process.poll() is None:
                # The child may exit between poll() and the signal.
                with contextlib.suppress(ProcessLookupError):
                    if os.name == "posix":
                        os.killpg(process.pid, signal.SIGKILL)
                    else:
                        process.kill()
        if process:
            process.wait(timeout=5)


class Bridge(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, args):
        self.args = args
        self.config = json.loads(Path(args.config).read_text(encoding="utf-8"))
        self.password = os.environ["YOUGORI_HARNESS_PASSWORD"]
        self.sessions = {}
        self.lock = threading.Lock()
        probe = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--child", "--probe",
            "--root", args.root, "--config", args.config, "--session", "ses_probe"],
            input=json.dumps({"prompt": ""}) + "\n", capture_output=True,
            text=True, encoding="utf-8", timeout=75)
        events = [json.loads(line) for line in probe.stdout.splitlines()]
        if probe.returncode or not any(event.get("ready") for event in events):
            raise RuntimeError("Pinned Hermes initialization failed")
        super().__init__(("127.0.0.1", args.port), Handler)

    def close_sessions(self):
        with self.lock:
            sessions = list(self.sessions.values())
            self.sessions.clear()
        for session in sessions:
            session.abort()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def send(self, value, status=200):
        data = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        self.dispatch()

    def do_POST(self):
        self.dispatch()

    def do_DELETE(self):
        self.dispatch()

    def dispatch(self):
        expected = "Basic " + base64.b64encode(("yougori:" + self.server.password).encode()).decode()
        if not hmac.compare_digest(self.headers.get("Authorization", ""), expected):
            return self.send({}, 401)
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 <= length <= 1048576:
                return self.send({}, 413)
            body = json.loads(self.rfile.read(length)) if length else {}
            path = self.path.split("?", 1)[0]
            if path == "/global/health" and self.command == "GET":
                return self.send({"healthy": True, "harness": "hermes", "version": REVISION})
            if path == "/config/providers" and self.command == "GET":
                return self.send({"providers": [{"id": "yougori", "models": {self.server.config["model"]: {}}}]})
            if path == "/tools" and self.command == "GET":
                return self.send([{"id": name} for name in DEFINITIONS])
            if path == "/session" and self.command == "POST":
                with self.server.lock:
                    if len(self.server.sessions) >= 4:
                        return self.send({}, 409)
                    identity = "ses_" + uuid.uuid4().hex
                    self.server.sessions[identity] = Session()
                return self.send({"id": identity})
            match = re.fullmatch(r"/session/([A-Za-z0-9_-]{1,128})(/message|/abort)?", path)
            if not match:
                return self.send({}, 404)
            identity, action = match.groups()
            with self.server.lock:
                session = self.server.sessions.get(identity)
            if session is None:
                return self.send({}, 404)
            if (action == "/abort" and self.command == "POST") or (not action and self.command == "DELETE"):
                session.abort()
                if self.command == "DELETE":
                    with self.server.lock:
                        self.server.sessions.pop(identity, None)
                return self.send(True)
            if action == "/message" and self.command == "GET":
                with session.lock:
                    parts = list(session.parts)
                return self.send([{"info": {"role": "assistant"}, "parts": parts}])
            if action == "/message" and self.command == "POST":
                return self.turn(identity, session, body)
            return self.send({}, 405)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            self.send({"error": "Invalid managed harness operation"}, 400)

    def turn(self, identity, session, body):
        prompt = "\n".join(part["text"] for part in body["parts"] if part["type"] == "text")
        args = self.server.args
        with session.lock:
            if session.started or session.aborted:
                return self.send({}, 409)
            session.started = True
        process = None
        result = {"info": {"error": {"name": "APIError"}}}
        try:
            with session.lock:
                # Abort may arrive after claiming this turn and before spawning it.
                if session.aborted:
                    return self.send(result)
                session.home = tempfile.TemporaryDirectory(prefix="yougori-hermes-turn-")
                environment = {**os.environ, "HERMES_HOME": session.home.name}
                process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--child",
                    "--root", args.root, "--config", args.config, "--session", identity],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                    text=True, encoding="utf-8", env=environment, start_new_session=os.name == "posix")
                session.process = process
            process.stdin.write(json.dumps({"prompt": prompt}) + "\n")
            process.stdin.close()
            for line in process.stdout:
                if len(line) > 262144:
                    raise ValueError("Oversized Hermes event")
                event = json.loads(line)
                session.record(event)
                if event.get("done"):
                    result = {"info": event["info"]}
            process.wait(timeout=5)
        finally:
            try:
                session.abort()
            finally:
                if process:
                    for pipe in (process.stdin, process.stdout):
                        if pipe:
                            with contextlib.suppress(OSError):
                                pipe.close()
                if session.home:
                    session.home.cleanup()
        return self.send(result)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default="/srv/yougori-swarm")
    parser.add_argument("--config", default="/etc/yougori-hermes/config.json")
    parser.add_argument("--port", type=int, default=4096)
    parser.add_argument("--child", action="store_true")
    parser.add_argument("--probe", action="store_true")
    parser.add_argument("--session")
    args = parser.parse_args()
    if args.child:
        child(args)
    else:
        server = Bridge(args)
        def stop(*_):
            server.close_sessions()
            raise SystemExit(0)
        signal.signal(signal.SIGTERM, stop)
        if hasattr(signal, "SIGHUP"):
            signal.signal(signal.SIGHUP, stop)
        try:
            server.serve_forever(poll_interval=0.2)
        finally:
            server.close_sessions()
            server.server_close()


if __name__ == "__main__":
    main()
