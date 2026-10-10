"""Exercise pinned OpenCode with a synthetic local provider and managed spool.

Pass an extracted Linux OpenCode binary. All state is in a temporary folder;
no user credentials, GPU, model downloads, or Yougori workloads are touched.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import urllib.request
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Provider(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        if self.headers.get("Authorization") != "Bearer synthetic-local-key":
            self.send_error(401)
            return
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.server.requests.append(body)
        print(json.dumps({"providerRequest":len(self.server.requests),"toolNames":[t["function"]["name"] for t in body.get("tools",[])]}),flush=True)
        tools = {t["function"]["name"] for t in body.get("tools", [])}
        assert tools <= {"bounty_reply", "read", "glob", "grep"}, tools
        repeated = any(m["role"] == "tool" for m in body.get("messages", []))
        if not repeated and "bounty_reply" in tools:
            delta = {"tool_calls": [{"index": 0, "id": "call_fixture", "type": "function",
                     "function": {"name": "bounty_reply", "arguments": '{"content":"Managed tool reached the owner"}'}}]}
            finish = "tool_calls"
        else:
            delta, finish = {"content": "Fixture completed"}, "stop"
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Connection", "close")
        self.end_headers()
        events = [
            {"id": "chatcmpl-fixture", "object": "chat.completion.chunk", "created": 1,
             "model": "fixture", "choices": [{"index": 0, "delta": delta, "finish_reason": None}]},
            {"id": "chatcmpl-fixture", "object": "chat.completion.chunk", "created": 1,
             "model": "fixture", "choices": [{"index": 0, "delta": {}, "finish_reason": finish}],
             "usage": {"prompt_tokens": 64, "completion_tokens": 32, "total_tokens": 96}},
        ]
        for event in events:
            self.wfile.write(("data: " + json.dumps(event) + "\n\n").encode())
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()
        self.close_connection = True


def run(binary, unprivileged=False, installer_umask_077=False, repair_readable=False, receipt_race=False):
    if unprivileged and (os.name != "posix" or os.geteuid() != 0):
        raise RuntimeError("--unprivileged requires a disposable Linux process launched as root; no system users are changed")
    repo = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="yougori-opencode-smoke-") as temp:
        root = Path(temp)
        home, config, workspace = root / "home", root / "config", root / "workspace"
        for path in [home, config / "tools", workspace / "spool", workspace / "project"]:
            path.mkdir(parents=True)
        tools = (repo / "src-tauri/src/swarm/tools.ts").read_text().replace("/srv/yougori-swarm", str(workspace))
        (config / "tools/bounty.ts").write_text(tools)
        (workspace / "AGENTS.md").write_text("Use only the approved local fixture and managed bounty tools.")
        (workspace / ".yougori/bounty").mkdir(parents=True)
        (workspace / ".yougori/bounty/CONTEXT.json").write_text(json.dumps({"policy":{"bountyId":"bounty_fixture","termsVersion":1},"task":{"leaseId":"lease_fixture","generation":1}}))
        provider = ThreadingHTTPServer(("127.0.0.1", 0), Provider)
        provider.requests = []
        thread = threading.Thread(target=provider.serve_forever, daemon=True)
        thread.start()
        environment = {k: v for k, v in os.environ.items() if not any(s in k.upper() for s in ["API_KEY", "TOKEN", "PASSWORD"])}
        environment.update(HOME=str(home), XDG_CONFIG_HOME=str(home / ".config"),
                           XDG_CACHE_HOME=str(home / ".cache"), XDG_DATA_HOME=str(home / ".local/share"),
                           OPENCODE_CONFIG_DIR=str(config), OPENCODE_DISABLE_PROJECT_CONFIG="true",
                           OPENCODE_DISABLE_CLAUDE_CODE="true", OPENCODE_DISABLE_AUTOUPDATE="true",
                           OPENCODE_DISABLE_MODELS_FETCH="true", OPENCODE_SERVER_PASSWORD="fixture-owner-password")
        install_options = {"umask": 0o077} if installer_umask_077 else {}
        subprocess.run(["npm", "install", "--save-exact", "--ignore-scripts", "--no-audit", "--no-fund", "--prefix", str(config),
                        "@opencode-ai/plugin@1.18.35"], env=environment, check=True, capture_output=True, **install_options)
        model = {
            "$schema": "https://opencode.ai/config.json", "model": "yougori/fixture", "small_model": "yougori/fixture",
            "enabled_providers": ["yougori"], "share": "disabled", "autoupdate": False,
            "snapshot": False, "lsp": False, "formatter": False, "mcp": {}, "plugin": [],
            "default_agent": "swarm", "agent": {"swarm": {"description": "Fixture", "mode": "primary", "steps": 4}},
            "permission": {"*": "deny", "read": {"*":"deny",str(workspace/"project")+"/**":"allow",str(workspace/".yougori/bounty")+"/**":"allow"}, "glob": "allow", "grep": "allow", "bounty_reply": "allow"},
            "provider": {"yougori": {"npm": "@ai-sdk/openai-compatible", "name": "Private fixture",
                "options": {"baseURL": f"http://127.0.0.1:{provider.server_address[1]}/v1", "apiKey": "synthetic-local-key"},
                "models": {"fixture": {"name": "fixture", "tool_call": True,
                    "limit": {"context": 4096, "output": 512}, "modalities": {"input": ["text"], "output": ["text"]}}}}},
        }
        managed_file = root / "managed-opencode.json"
        managed_file.write_text(json.dumps(model))
        managed_file.chmod(0o444)
        environment["OPENCODE_CONFIG"] = str(managed_file)
        child_identity = {}
        if unprivileged:
            # Match the managed guest: protected root-owned code/config/source,
            # one agent-readable config file, and writable agent home + spool.
            root.chmod(0o755)
            for path in root.rglob("*"):
                if path.is_symlink():
                    continue
                if installer_umask_077 and path.is_relative_to(config):
                    continue
                path.chmod(0o755 if path.is_dir() else 0o644)
            for path in [home, *home.rglob("*")]:
                if not path.is_symlink():
                    os.chown(path, 65534, 65534)
            os.chown(workspace / "spool", 65534, 65534)
            (workspace / "spool").chmod(0o700)
            (config / "tools/bounty.ts").chmod(0o444)
            (workspace / "AGENTS.md").chmod(0o444)
            os.chown(managed_file, 0, 65534)
            managed_file.chmod(0o640)
            child_identity = {"user": 65534, "group": 65534, "extra_groups": []}
            if installer_umask_077:
                # Native sync and async commands both use 077. Trusted
                # context ancestors need traversal independently of file mode.
                for path in [workspace / ".yougori", workspace / ".yougori/bounty"]:
                    path.chmod(0o700)
                (workspace / ".yougori/bounty/CONTEXT.json").chmod(0o444)
            if repair_readable:
                for path in config.rglob("*"):
                    if not path.is_symlink():
                        mode = path.stat().st_mode & 0o777
                        path.chmod(mode | (0o555 if path.is_dir() or mode & 0o111 else 0o444))
                for path in [workspace / ".yougori", workspace / ".yougori/bounty", config, config / "tools"]:
                    path.chmod(0o755)
            if installer_umask_077:
                for path in [config / "package.json", config / "node_modules/@opencode-ai/plugin/package.json"]:
                    details = path.stat()
                    print(json.dumps({"fixtureMode":oct(details.st_mode & 0o777), "uid":details.st_uid,
                                      "gid":details.st_gid, "path":str(path.relative_to(root))}), flush=True)
        # Allocate an unused loopback port; the subprocess has no public host binding.
        import socket
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        log = open(root / "server.log", "w+")
        process = subprocess.Popen([str(binary), "serve", "--hostname", "127.0.0.1", "--port", str(port)],
                                   cwd=workspace, env=environment, stdout=log, stderr=log, **child_identity)
        auth = "Basic " + base64.b64encode(b"opencode:fixture-owner-password").decode()
        local = urllib.request.build_opener(urllib.request.ProxyHandler({}))

        def api(path, body=None):
            data = None if body is None else json.dumps(body).encode()
            request = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data,
                      headers={"Authorization": auth, "Content-Type": "application/json", "x-opencode-directory": str(workspace)})
            try:
                with local.open(request, timeout=15 if path=="/global/health" else 90) as response:
                    return json.load(response)
            except urllib.error.HTTPError as error:
                # This fixture contains only synthetic credentials. Capture
                # the initialization cause rather than repeating a bare 500.
                body = error.read().decode(errors="replace")[:4000]
                log.flush()
                log.seek(0)
                details = log.read()[-6000:]
                raise RuntimeError(f"Fixture {path} failed: HTTP {error.code}: {body}\n{details}") from error

        try:
            deadline = time.monotonic() + 60
            while True:
                try:
                    health = api("/global/health")
                    assert health["healthy"] and health["version"] == "1.18.35"
                    print("Pinned OpenCode health passed",flush=True)
                    break
                except Exception:
                    if time.monotonic() > deadline or process.poll() is not None:
                        log.seek(0)
                        raise RuntimeError("OpenCode startup failed: " + log.read()[-8000:])
                    time.sleep(.2)
            providers = api("/config/providers")
            assert len(providers["providers"]) == 1 and providers["providers"][0]["id"] == "yougori"
            assert "fixture" in providers["providers"][0]["models"]
            print("Private provider configuration passed",flush=True)
            tool_list=api("/experimental/tool?provider=yougori&model=fixture")
            assert any(t.get("id")=="bounty_reply" for t in tool_list), tool_list
            print("Managed tool initialization passed",flush=True)
            session = api("/session", {"title": "Managed worker fixture"})
            session_file = workspace / f".yougori/bounty/session-{session['id']}.json"
            session_file.write_text((workspace / ".yougori/bounty/CONTEXT.json").read_text())
            session_file.chmod(0o444)
            # Rotating global task context must not rebind this older session.
            (workspace / ".yougori/bounty/CONTEXT.json").write_text(json.dumps({"policy":{"bountyId":"OTHER","termsVersion":2},"task":{"leaseId":"OTHER","generation":2}}))
            result, errors = [], []
            def message():
                try:
                    result.append(api(f"/session/{session['id']}/message", {"agent": "swarm",
                        "model": {"providerID": "yougori", "modelID": "fixture"},
                        "parts": [{"type": "text", "text": "Use bounty_reply once to report the fixture, then stop."}]}))
                except Exception as error:
                    errors.append(str(error))
            turn = threading.Thread(target=message, daemon=True)
            turn.start()
            seen = []
            deadline = time.monotonic() + 60
            while turn.is_alive() and time.monotonic() < deadline:
                for request_path in (workspace / "spool").glob("*.request"):
                    value = json.loads(request_path.read_text())
                    assert value["action"] == "reply" and value["params"]["content"] == "Managed tool reached the owner"
                    assert value["context"] == {"bountyId":"bounty_fixture","termsVersion":1,"leaseId":"lease_fixture","generation":1}
                    response_path = request_path.with_suffix(".response")
                    if receipt_race:
                        pending_response = request_path.with_suffix(".receipt-pending")
                        pending_response.write_text(json.dumps({"saved": True}))
                        pending_response.chmod(0o600)
                        os.replace(pending_response, response_path)
                        def publish(path=response_path):
                            time.sleep(.4)
                            os.chown(path, 65534, 65534)
                        threading.Thread(target=publish, daemon=True).start()
                    else:
                        response_path.write_text(json.dumps({"saved": True}))
                    request_path.unlink()
                    seen.append(value)
                time.sleep(.05)
            turn.join(1)
            assert not turn.is_alive(), "Bounded fixture turn did not finish"
            assert not errors, errors
            assert seen, "OpenCode did not invoke the managed tool"
            assert len(provider.requests) >= 2, "Tool result did not reach the local model"
            assert any(m["role"] == "tool" for m in provider.requests[-1]["messages"])
            assert not list((workspace / "spool").glob("*.response")), "Consumed tool response was retained"
            assert not list((workspace / "spool").glob("*.ack")), "Consumed tool acknowledgment was retained"
            print(json.dumps({"passed": True, "version": "1.18.35", "modelRequests": len(provider.requests),
                              "managedTools": len(seen), "privateProvider": True, "receiptCleanup": True,
                              "unprivileged": unprivileged, "installerUmask077": installer_umask_077,
                              "readableRepair": repair_readable, "receiptRace": receipt_race}))
        finally:
            process.terminate()
            try:
                process.wait(5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(5)
            provider.shutdown()
            provider.server_close()
            thread.join(2)
            log.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("--unprivileged", action="store_true", help="Run OpenCode as UID/GID 65534 with protected root-owned worker files")
    parser.add_argument("--installer-umask-077", action="store_true", help="Reproduce the native asynchronous root installer umask")
    parser.add_argument("--repair-readable", action="store_true", help="Apply the managed guest's readable root-owned dependency/context repair")
    parser.add_argument("--receipt-race", action="store_true", help="Publish a root-owned0600 receipt before transferring it to the agent")
    arguments = parser.parse_args()
    if (arguments.repair_readable or arguments.receipt_race) and not arguments.unprivileged:
        parser.error("Readable repair and receipt race fixtures require --unprivileged")
    run(arguments.binary.resolve(), arguments.unprivileged, arguments.installer_umask_077,
        arguments.repair_readable, arguments.receipt_race)
