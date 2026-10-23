"""Run with the pinned Hermes venv Python. Only disposable loopback fixtures.

Exercises actual AIAgent inference, managed tool receipts, path denial, HTTP
authentication, abort during inference, and a fresh session after cancellation.
"""
import argparse
import base64
import concurrent.futures
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SWARM = Path(__file__).resolve().parents[1] / "src-tauri/src/swarm"
sys.path.insert(0, str(SWARM))
from hermes_bridge import Bridge, REVISION
from hermes_tools import DEFINITIONS, ManagedTools


class Provider(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        assert self.headers.get("Authorization") == "Bearer fixture-key"
        if self.path != "/v1/chat/completions":
            self.send_error(404)
            return
        self.server.requests.append(body)
        self.server.called.set()
        if self.server.fail:
            self.send_error(503, "Synthetic model offline")
            return
        if self.server.block:
            self.server.release.wait(30)
        assert "OUTSIDE_PRIVATE_CANARY" not in json.dumps(body)
        if body.get("tools"):
            assert {t["function"]["name"] for t in body["tools"]} == set(DEFINITIONS)
        receipts = [m for m in body["messages"] if m["role"] == "tool"]
        for receipt, (_, _, marker) in zip(receipts, [] if self.server.pressure else self.server.calls):
            assert marker in str(receipt["content"]), receipt
        index = len(receipts)
        if not body.get("tools"):
            assert self.server.pressure, "Unexpected auxiliary inference"
            self.server.compressions += 1
            message, finish = {"role": "assistant", "content": "Fixture tool receipts checked. Continue the approved investigation."}, "stop"
        elif self.server.pressure and self.server.pressure_calls < 8:
            self.server.pressure_calls += 1
            message = {"role": "assistant", "content": (f"Inspection record {self.server.pressure_calls}. " * 500), "tool_calls": [{
                "id": f"pressure_{self.server.pressure_calls}", "type": "function",
                "function": {"name": "bounty_share", "arguments": json.dumps({"kind": "read", "content": f"fixture-{self.server.pressure_calls}"})}}]}
            finish = "tool_calls"
        elif index < len(self.server.calls):
            name, args, _ = self.server.calls[index]
            message = {"role": "assistant", "content": None, "tool_calls": [{
                "id": f"call_{index}", "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}]}
            finish = "tool_calls"
        else:
            message, finish = {"role": "assistant", "content": "Fixture completed"}, "stop"
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream" if body.get("stream") else "application/json")
            self.end_headers()
            if body.get("stream"):
                delta = dict(message)
                for call in delta.get("tool_calls", []):
                    call["index"] = 0
                chunks = [(delta, None), ({}, finish)]
                if self.server.live:
                    chunks = [({"role":"assistant", "reasoning_content":"Checking fixture"}, None),
                              ({"content":"Fixture "}, None), ({"content":"completed"}, None), ({}, finish)]
                for chunk_index, (part, reason) in enumerate(chunks):
                    event = {"id": "chatcmpl-fixture", "object": "chat.completion.chunk", "created": 1,
                             "model": "fixture", "choices": [{"index": 0, "delta": part, "finish_reason": reason}]}
                    if reason:
                        event["usage"] = {"prompt_tokens": max(100, len(json.dumps(body["messages"])) // 4),
                                          "completion_tokens": 20, "total_tokens": max(100, len(json.dumps(body["messages"])) // 4) + 20}
                    self.wfile.write(("data: " + json.dumps(event) + "\n\n").encode())
                    self.wfile.flush()
                    if self.server.live and chunk_index == 1:
                        self.server.live_started.set()
                        self.server.live_release.wait(30)
                self.wfile.write(b"data: [DONE]\n\n")
            else:
                self.wfile.write(json.dumps({"id": "chatcmpl-fixture", "object": "chat.completion", "created": 1,
                    "model": "fixture", "choices": [{"index": 0, "message": message, "finish_reason": finish}],
                    "usage": {"prompt_tokens": max(100, len(json.dumps(body["messages"])) // 4),
                              "completion_tokens": 20, "total_tokens": max(100, len(json.dumps(body["messages"])) // 4) + 20}}).encode())
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass


def main():
    with tempfile.TemporaryDirectory(prefix="yougori-hermes-smoke-") as temporary:
        root = Path(temporary)
        for directory in ["project", ".yougori/bounty", "spool", "home"]:
            (root / directory).mkdir(parents=True)
        (root / "project/example.py").write_text("fixture_source = True\n")
        (root / "secret.txt").write_text("OUTSIDE_PRIVATE_CANARY")
        os.environ["HERMES_HOME"] = str(root / "home")
        os.environ["YOUGORI_HARNESS_PASSWORD"] = "fixture-owner"
        provider = ThreadingHTTPServer(("127.0.0.1", 0), Provider)
        provider.requests, provider.calls = [], []
        provider.pressure, provider.pressure_calls, provider.compressions = False, 0, 0
        provider.called, provider.release = threading.Event(), threading.Event()
        provider.block = False
        provider.fail = False
        provider.live = False
        provider.live_started, provider.live_release = threading.Event(), threading.Event()
        threading.Thread(target=provider.serve_forever, daemon=True).start()
        config = root / "config.json"
        config.write_text(json.dumps({"model": "fixture", "baseUrl": f"http://127.0.0.1:{provider.server_port}/v1",
            "apiKey": "fixture-key", "maxTokens": 4096, "prompt": "Use only the approved fixture tools."}))
        bridge = Bridge(argparse.Namespace(root=str(root), config=str(config), port=0))
        threading.Thread(target=bridge.serve_forever, daemon=True).start()
        owner_done = threading.Event()
        handled = []

        def owner():
            while not owner_done.wait(0.02):
                for request in (root / "spool").glob("*.request"):
                    value = json.loads(request.read_text())
                    assert value["context"] == {"bountyId": "fixture", "termsVersion": 1, "leaseId": "lease", "generation": 7}
                    handled.append(value["action"])
                    receipt = {"receipt": "receipt_" + value["action"]}
                    if provider.pressure:
                        receipt["records"] = [f"fixture-{len(handled)}-{i:06d}-" + str(i * 178923) for i in range(1500)]
                    request.with_suffix(".response").write_text(json.dumps(receipt))
                    request.unlink()

        threading.Thread(target=owner, daemon=True).start()

        def api(path, body=None, method=None, authorized=True):
            request = urllib.request.Request(f"http://127.0.0.1:{bridge.server_port}{path}",
                data=json.dumps(body).encode() if body is not None else None,
                method=method, headers={"Authorization": "Basic " + base64.b64encode(b"yougori:fixture-owner").decode()} if authorized else {})
            with urllib.request.urlopen(request, timeout=90) as response:
                return json.load(response)

        def session():
            identity = api("/session", {})["id"]
            (root / ".yougori/bounty" / f"session-{identity}.json").write_text(json.dumps({
                "policy": {"bountyId": "fixture", "termsVersion": 1}, "task": {"leaseId": "lease", "generation": 7}}))
            return identity

        message = {"parts": [{"type": "text", "text": "Investigate the fixture."}]}
        try:
            assert api("/global/health")["version"] == REVISION
            try:
                api("/global/health", authorized=False)
                raise AssertionError("Unauthenticated harness access")
            except urllib.error.HTTPError as error:
                assert error.code == 401
            # Deny traversal, supervisor bindings, and symlink escapes independently of the LLM.
            managed = ManagedTools(root, "ses_fixture")
            assert managed.checked_path("project/session-handler.py") == root / "project/session-handler.py"
            spill = root / "home/cache/spillover/fixture.txt"
            spill.parent.mkdir(parents=True)
            spill.write_text("own tool receipt")
            assert managed.local("read", {"filePath": str(spill)}) == "own tool receipt"
            (root / "home/config.json").write_text("private config")
            for forbidden in ["secret.txt", "project/../secret.txt", ".yougori/bounty/session-private.json"]:
                try:
                    managed.checked_path(forbidden)
                    raise AssertionError("Accepted forbidden path")
                except PermissionError:
                    pass
            try:
                managed.checked_path(str(root / "home/config.json"))
                raise AssertionError("Accepted Hermes private configuration")
            except PermissionError:
                pass
            if os.name == "posix":
                (root / "project/escape").symlink_to(root / "secret.txt")
                try:
                    managed.checked_path("project/escape")
                    raise AssertionError("Accepted symlink escape")
                except PermissionError:
                    pass
            evidence = [{"name": "fixture.txt", "contentBase64": "Zml4dHVyZQ=="}]
            provider.calls = [
                ("read", {"filePath": "project/example.py"}, "fixture_source"),
                ("read", {"filePath": str(root / "secret.txt")}, "outside accepted"),
                ("glob", {"pattern": "*.py"}, "example.py"),
                ("grep", {"pattern": "fixture_source"}, "example.py"),
                ("bounty_check", {"index": 1}, "receipt_check"),
                ("bounty_http", {"method": "GET", "path": "/health"}, "receipt_http"),
                ("bounty_experiment", {"language": "python", "hypothesis": "fixture", "code": "print(1)"}, "receipt_experiment"),
                ("bounty_share", {"kind": "read"}, "receipt_share"),
                ("bounty_reply", {"content": "fixture"}, "receipt_reply"),
                ("bounty_attempt", {"outcome": "candidate", "observations": "fixture", "expected": "fixture", "limitations": "synthetic", "evidence": evidence}, "receipt_attempt"),
                ("bounty_report", {**dict.fromkeys(["title", "component", "reproduction", "observed", "expected", "impact", "limitations"], "fixture"), "evidence": evidence}, "receipt_report")]
            identity = session()
            result = api(f"/session/{identity}/message", message)
            assert not result["info"].get("error"), result
            assert len(provider.requests) == len(provider.calls) + 1
            assert handled == [name.removeprefix("bounty_") for name, _, _ in provider.calls if name.startswith("bounty_")]
            actions = api(f"/session/{identity}/message")[0]["parts"]
            assert any(p.get("tool") == "read" and p["state"]["status"] == "error" for p in actions)
            api(f"/session/{identity}", method="DELETE")
            # Drive the real Hermes compressor through the same private provider,
            # then prove normal tool-calling continues with the compacted history.
            provider.pressure, provider.calls = True, []
            identity = session()
            result = api(f"/session/{identity}/message", message)
            assert not result["info"].get("error"), result
            assert provider.compressions > 0, "Context pressure did not invoke the private compressor"
            assert provider.pressure_calls == 8
            api(f"/session/{identity}", method="DELETE")
            provider.pressure = False
            # Hold the SSE connection open after partial text. Both reasoning and
            # text must be readable before the turn finishes, with no duplicate
            # final response or one row per token.
            provider.live = True
            identity = session()
            with concurrent.futures.ThreadPoolExecutor() as pool:
                pending = pool.submit(api, f"/session/{identity}/message", message)
                try:
                    assert provider.live_started.wait(30), "Provider did not stream"
                    deadline = time.monotonic() + 10
                    while time.monotonic() < deadline:
                        parts = api(f"/session/{identity}/message")[0]["parts"]
                        if any(p.get("text") == "Fixture " for p in parts):
                            break
                        time.sleep(0.05)
                    assert not pending.done(), "Turn finished before the live assertion"
                    partial = next(p for p in parts if p.get("text") == "Fixture ")
                    assert "end" not in partial.get("time", {})
                    assert any(p.get("type") == "reasoning" and p.get("text") == "Checking fixture" for p in parts)
                finally:
                    provider.live_release.set()
                assert not pending.result(timeout=30)["info"].get("error")
            parts = api(f"/session/{identity}/message")[0]["parts"]
            texts = [p for p in parts if p["type"] == "text"]
            assert len(texts) == 1, texts
            assert texts[0]["id"] == partial["id"]
            assert texts[0]["text"] == "Fixture completed" and texts[0]["time"]["end"]
            provider.live = False
            api(f"/session/{identity}", method="DELETE")
            # A crashed local provider returns promptly to the native recovery
            # loop instead of sleeping through Hermes' hosted-provider cycles.
            provider.fail = True
            identity = session()
            started = time.monotonic()
            assert api(f"/session/{identity}/message", message)["info"].get("error")
            assert time.monotonic() - started < 15, "Provider failure did not return promptly"
            api(f"/session/{identity}", method="DELETE")
            provider.fail = False
            # Stop while the provider is blocked, then run a fresh real Hermes turn.
            provider.calls, provider.block = [], True
            provider.called.clear()
            identity = session()
            with concurrent.futures.ThreadPoolExecutor() as pool:
                pending = pool.submit(api, f"/session/{identity}/message", message)
                assert provider.called.wait(30), "Hermes did not issue inference"
                started = time.monotonic()
                api(f"/session/{identity}/abort", {})
                assert time.monotonic() - started < 5
                assert pending.result(timeout=5)["info"]["error"]
            provider.block = False
            provider.release.set()
            api(f"/session/{identity}", method="DELETE")
            identity = session()
            assert not api(f"/session/{identity}/message", message)["info"].get("error")
            print("PASS: pinned Hermes live text/reasoning before completion, seven receipt tools, scoped reads/searches, authentication, private context compression, abort and fresh resume")
        finally:
            owner_done.set()
            provider.release.set()
            provider.live_release.set()
            bridge.close_sessions()
            bridge.shutdown()
            bridge.server_close()
            provider.shutdown()
            provider.server_close()


if __name__ == "__main__":
    main()
