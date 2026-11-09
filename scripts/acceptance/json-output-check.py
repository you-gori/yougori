"""JSON output (OpenAI's response_format) on a disposable acceptance engine, end to end.

Checks, with real models on this computer's GPU:

1. A vLLM launch holds replies to a JSON schema and to any JSON object, buffered and streamed;
   its health lists structuredOutput and /v1/models says so.
2. A GGUF (llama.cpp) launch does the same.
3. A megakernel launch (the owner's kernel) refuses response_format with the typed code
   yougori_structured_output instead of answering in prose, when --reuse names a model saved
   with that launch; the check then switches it to the speculative vLLM launch.
4. `yougori model chat ENV --json SCHEMA.json` (the scripted CLI chat) returns a reply in the
   schema's shape.
5. The inference template (examples/hub/inference-solver), run in this process on a disposable
   data folder with both model APIs connected, shows the models as JSON-capable and passes a
   JSON request and a Responses-API text.format request through to them.

Every request and reply is kept as evidence under ROOT/evidence. Nothing here touches the
installed engine: the acceptance engine has its own pipe, data folder and home.

Run (after building the engine and CLI with --features acceptance into their own target dir):
  python -I -B scripts/acceptance/json-output-check.py --root D:/tmp/yg-json --engine ENGINE.exe
    --cli CLI.exe --runtime %LOCALAPPDATA%/Yougori/runtime [--reuse Qwen3-0.6B --existing-root]
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

spec = importlib.util.spec_from_file_location("migration", Path(__file__).with_name("model-migration-recovery.py"))
migration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(migration)

SCHEMA = {"type": "object", "properties": {"city": {"type": "string"}, "country": {"type": "string"}},
          "required": ["city", "country"], "additionalProperties": False}
FORMAT = {"type": "json_schema", "json_schema": {"name": "capital", "schema": SCHEMA, "strict": True}}
QUESTION = "Which city is the capital of France? Answer with the city and its country."
TEMPLATE = Path(__file__).resolve().parents[2] / "examples" / "hub" / "inference-solver"


def parsed(content):
    """The JSON a reply holds, or a failure that keeps the reply."""
    try:
        return json.loads(content)
    except ValueError as error:
        raise AssertionError(f"The reply is not JSON ({error}): {content[:300]!r}") from None


class Check(migration.Run):
    def __init__(self, args):
        args.model = Path(__file__).parent  # the base harness hashes a model folder; none is used here
        args.from_case = 0
        super().__init__(args)
        self.args = args
        self.environments = {}  # label -> {"id", "name", "port", "key"}
        self.kept = set()

    def result(self, method, params, label=None):
        return self.call(method, params, label)["result"]

    def http(self, port, key, path, body=None, label=None, stream=False):
        request = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=None if body is None else json.dumps(body).encode(),
                                         headers={"Content-Type": "application/json", "Authorization": "Bearer " + key})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        record = {"path": path, "body": body}
        try:
            with opener.open(request, timeout=600) as response:
                if stream:
                    text, usage, finish = [], None, None
                    for line in response:
                        if not line.startswith(b"data:"):
                            continue
                        value = line[5:].strip()
                        if value == b"[DONE]":
                            break
                        event = json.loads(value)
                        if "error" in event:
                            raise RuntimeError(str(event["error"]))
                        usage = event.get("usage") or usage
                        for choice in event.get("choices", []):
                            text.append(choice.get("delta", {}).get("content") or "")
                            finish = choice.get("finish_reason") or finish
                    record.update(status=response.status, content="".join(text), usage=usage, finish=finish)
                else:
                    record.update(status=response.status, reply=json.loads(response.read()))
        except urllib.error.HTTPError as error:
            record.update(status=error.code, error=json.loads(error.read(65536) or b"{}"))
        if label:
            self.write(label, record)
        return record

    def wait_ready(self, environment_id, limit=1800):
        deadline, previous = time.monotonic() + limit, None
        while time.monotonic() < deadline:
            reply = self.call("model_status", {"environmentId": environment_id}, None, checked=False)
            health = reply.get("result") if reply.get("ok") else {"status": "server-starting", "reply": reply}
            if health.get("status") != previous:
                self.write("model-state", health)
                previous = health.get("status")
            if health.get("status") == "ready":
                return health
            if health.get("status") == "error":
                raise RuntimeError("The model failed to load; see the model-state evidence")
            time.sleep(2)
        raise TimeoutError("The model did not become ready in time")

    def api(self, environment_id, port):
        """The model's local API: the port it already serves on, or `port` once turned on."""
        access = self.result("model_api_status", {"environmentId": environment_id})
        if not access.get("apiUrl"):
            access = self.result("model_api", {"environmentId": environment_id, "port": port})
        served = int(access["apiUrl"].rsplit(":", 1)[1].split("/", 1)[0])
        return served, access["apiKey"]

    def existing(self, name):
        state = self.result("get_platform_state", {}, "platform-state")
        found = [e for e in state["environments"] if e["name"] == name]
        assert found, f"No environment named {name} in this data folder"
        return found[0]

    def create(self, label, model, port, quant=None, runner=None):
        resources = {"storageDrive": self.args.storage_drive}
        if runner:
            resources["runner"] = runner
        params = {"model": model, "port": port, "resources": resources}
        if quant:
            params["quant"] = quant
        submitted = self.command("call", "run_model", "--yes", "--no-wait", "--file", "-", params=params, label=f"{label}-submitted")
        job, deadline = submitted["result"]["jobId"], time.monotonic() + 5400
        while time.monotonic() < deadline:
            status = self.result("jobs_get", {"jobId": job, "wait": 1000})
            if status["status"] == "complete":
                created = status["result"]
                self.write(f"{label}-created", created)
                return created["id"], created["apiKey"]
            if status["status"] in ("failed", "cancelled", "interrupted"):
                self.write(f"{label}-creation-failed", status)
                raise RuntimeError(f"Creating {model} failed; see the evidence")
            time.sleep(1)
        raise TimeoutError("Model creation exceeded 90 minutes")

    def expect_json(self, label, port, key, environment_id, name):
        """The positive checks of one launch that enforces JSON output."""
        health = self.result("model_status", {"environmentId": environment_id}, f"{label}-health")
        fact = health["capabilities"]["structuredOutput"]
        assert fact["supported"] is True, fact
        listing = self.http(port, key, "/v1/models", label=f"{label}-models")
        assert listing["reply"]["data"][0]["capabilities"] == {"structuredOutput": True}, listing
        messages = [{"role": "user", "content": QUESTION}]
        buffered = self.http(port, key, "/v1/chat/completions", {"messages": messages, "max_tokens": 128, "temperature": 0, "response_format": FORMAT}, f"{label}-schema-buffered")
        assert buffered["status"] == 200, buffered
        answer = parsed(buffered["reply"]["choices"][0]["message"]["content"])
        assert set(answer) == {"city", "country"} and "Paris" in answer["city"], answer
        streamed = self.http(port, key, "/v1/chat/completions", {"messages": messages, "max_tokens": 128, "temperature": 0, "stream": True, "response_format": FORMAT}, f"{label}-schema-streamed", stream=True)
        assert streamed["status"] == 200 and streamed["finish"] == "stop", streamed
        assert set(parsed(streamed["content"])) == {"city", "country"}, streamed["content"]
        loose = self.http(port, key, "/v1/chat/completions", {"messages": [{"role": "user", "content": "Name two colours. Reply as a JSON object with a key named colours holding a list."}],
                                                              "max_tokens": 128, "temperature": 0, "response_format": {"type": "json_object"}}, f"{label}-object")
        assert loose["status"] == 200 and isinstance(parsed(loose["reply"]["choices"][0]["message"]["content"]), dict), loose
        refused = self.http(port, key, "/v1/chat/completions", {"messages": messages, "response_format": {"type": "xml"}}, f"{label}-bad-format")
        assert refused["status"] == 400 and refused["error"]["error"]["code"] == "yougori_structured_output", refused
        self.cli_chat(label, name)

    def cli_chat(self, label, name):
        """`yougori model chat NAME --json SCHEMA.json` with one piped prompt."""
        schema = self.root / "capital.json"
        schema.write_text(json.dumps(SCHEMA), encoding="utf-8")
        result = subprocess.run([str(self.cli), "model", "chat", name, "--new", "--json", str(schema)], input=QUESTION + "\n",
                                env=self.env, cwd=self.root, capture_output=True, text=True, encoding="utf-8", timeout=600,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        body = json.loads(result.stdout) if result.stdout.strip().startswith("{") else {"stdout": result.stdout}
        self.write(f"{label}-cli-chat", {"exit": result.returncode, "reply": body, "stderr": result.stderr[-2000:]})
        assert result.returncode == 0 and body.get("ok") and body["result"]["outcome"] == "succeeded", body
        reply = body["result"]["messages"][-1]["content"]
        assert set(parsed(reply)) == {"city", "country"}, reply

    def expect_refusal(self, label, port, key, environment_id):
        """A launch that cannot enforce JSON says so with its code, before generating."""
        health = self.result("model_status", {"environmentId": environment_id}, f"{label}-health")
        assert health["capabilities"]["structuredOutput"]["supported"] is False, health["capabilities"]
        refused = self.http(port, key, "/v1/chat/completions", {"messages": [{"role": "user", "content": QUESTION}], "max_tokens": 64, "response_format": FORMAT}, f"{label}-refused")
        assert refused["status"] == 400 and refused["error"]["error"]["code"] == "yougori_structured_output", refused
        listing = self.http(port, key, "/v1/models", label=f"{label}-models")
        assert listing["reply"]["data"][0]["capabilities"] == {"structuredOutput": False}, listing

    def restart(self, environment_id, launch):
        self.result("model_optimizer", {"environmentId": environment_id, "launch": launch}, f"launch-{launch}-saved")
        self.result("stop_model", {"environmentId": environment_id}, f"launch-{launch}-stop")
        time.sleep(3)
        self.result("start_model", {"environmentId": environment_id}, f"launch-{launch}-start")
        return self.wait_ready(environment_id)

    def vllm(self):
        port = self.args.port
        if self.args.reuse:
            env = self.existing(self.args.reuse)
            self.kept.add(env["id"])
            if env["status"] != "running":
                self.result("start_model", {"environmentId": env["id"]}, "vllm-start")
            health = self.wait_ready(env["id"])
            port, key = self.api(env["id"], port)
            if health.get("launch") == "megakernel" and health.get("runner") == "megakernel":
                self.expect_refusal("megakernel", port, key, env["id"])
                health = self.restart(env["id"], "speculative")
            name, environment_id = env["name"], env["id"]
        else:
            environment_id, key = self.create("vllm", self.args.vllm_repository, port, runner="vllm")
            health = self.wait_ready(environment_id)
            name = self.existing_name(environment_id)
        assert health.get("runner") == "vllm", health.get("runner")
        self.write("vllm-launch", {"launch": health.get("launch"), "runner": health.get("runner"), "gpu": health.get("gpu")})
        self.expect_json("vllm", port, key, environment_id, name)
        self.environments["vllm"] = {"id": environment_id, "name": name, "port": port, "key": key}

    def gguf(self):
        port = self.args.port + 1
        environment_id, key = self.create("gguf", self.args.gguf_repository, port, quant=self.args.quant)
        health = self.wait_ready(environment_id)
        self.write("gguf-launch", {"launch": health.get("launch"), "runner": health.get("runner"), "gpu": health.get("gpu"), "quant": health.get("quant")})
        name = self.existing_name(environment_id)
        self.expect_json("gguf", port, key, environment_id, name)
        self.environments["gguf"] = {"id": environment_id, "name": name, "port": port, "key": key}

    def existing_name(self, environment_id):
        state = self.result("get_platform_state", {})
        return next(e["name"] for e in state["environments"] if e["id"] == environment_id)

    def template(self):
        """The inference template in this process: both model APIs connected, JSON routed through."""
        sys.path.insert(0, str(TEMPLATE / "site"))
        from server import Service, Server  # noqa: E402
        import http.client
        folder = tempfile.mkdtemp(prefix="yg-json-template-", dir=str(self.root))
        service = Service(folder, {"email": "admin@example.invalid", "password": "disposable-admin-password"}, account_mode="public")
        web = Server(("127.0.0.1", 0), service)
        thread = threading.Thread(target=web.serve_forever, daemon=True)
        thread.start()
        try:
            def call(path, body=None, session=None, key=None):
                headers = {"Origin": f"http://127.0.0.1:{web.server_port}", "Content-Type": "application/json"}
                if session:
                    headers.update({"Cookie": session[0], "X-CSRF-Token": session[1]})
                if key:
                    headers["Authorization"] = "Bearer " + key
                connection = http.client.HTTPConnection("127.0.0.1", web.server_port, timeout=600)
                try:
                    connection.request("GET" if body is None else "POST", path, body=None if body is None else json.dumps(body), headers=headers)
                    response = connection.getresponse()
                    raw = response.read().decode()
                    return response.status, json.loads(raw) if response.getheader("Content-Type", "").startswith("application/json") else raw, dict(response.getheaders())
                finally:
                    connection.close()
            status, _, headers = call("/api/login", {"email": "admin@example.invalid", "password": "disposable-admin-password"})
            assert status == 200, status
            cookie = headers["Set-Cookie"].split(";")[0]
            session = (cookie, call("/api/session", session=(cookie, ""))[1]["user"]["csrf"])
            for label, item in self.environments.items():
                status, body, _ = call("/api/admin/endpoints", {"name": label, "url": f"http://127.0.0.1:{item['port']}/v1", "key": item["key"], "place": "local"}, session)
                assert status == 201, body
            catalog = {m["id"]: m for m in call("/api/models")[1]["models"]}
            self.write("template-catalog", [{k: v for k, v in m.items() if k in ("id", "state", "features", "replicas")} for m in catalog.values()])
            assert all(catalog[m]["features"] == {"json": True} for m in catalog), catalog
            status, created, _ = call("/api/keys", {"label": "json-check", "scopes": ["*"]}, session)
            assert status == 201, created
            key = created["key"]
            for model in catalog:
                status, body, _ = call("/v1/chat/completions", {"model": model, "messages": [{"role": "user", "content": QUESTION}], "max_tokens": 128, "temperature": 0, "response_format": FORMAT}, key=key)
                self.write(f"template-chat-{model.replace('/', '_')}", {"status": status, "body": body})
                assert status == 200, body
                assert set(parsed(body["choices"][0]["message"]["content"])) == {"city", "country"}, body
                status, body, _ = call("/v1/responses", {"model": model, "input": QUESTION, "max_output_tokens": 128, "temperature": 0,
                                                         "text": {"format": {"type": "json_schema", "name": "capital", "schema": SCHEMA, "strict": True}}}, key=key)
                self.write(f"template-responses-{model.replace('/', '_')}", {"status": status, "body": body})
                assert status == 200, body
                text = next(part["text"] for item in body["output"] if item.get("type") == "message" for part in item["content"] if part.get("type") == "output_text")
                assert set(parsed(text)) == {"city", "country"}, text
        finally:
            service.stopped.set()
            web.shutdown()
            web.server_close()
            thread.join(5)

    def run(self):
        self.start()
        self.vllm()
        self.gguf()
        self.template()
        self.write("complete", {"environments": {label: {k: v for k, v in item.items() if k != "key"} for label, item in self.environments.items()}})

    def clean(self):
        if self.process is None or self.process.poll() is not None:
            return
        for label, item in self.environments.items():
            self.call("stop_model", {"environmentId": item["id"]}, f"cleanup-{label}-stop", checked=False)
            if item["id"] not in self.kept and not self.args.keep:
                self.call("delete_environment", {"environmentId": item["id"]}, f"cleanup-{label}-delete", checked=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    for name in ("root", "engine", "cli", "runtime"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--vllm-repository", default="Qwen/Qwen3-0.6B", help="a safetensors repository served with --runner vllm")
    parser.add_argument("--gguf-repository", default="hf.co/unsloth/Qwen3-0.6B-GGUF")
    parser.add_argument("--quant", default="Q4_K_M")
    parser.add_argument("--reuse", help="the name of an existing vLLM model environment in the root's data folder")
    parser.add_argument("--existing-root", action="store_true", help="continue evidence in an existing root")
    parser.add_argument("--port", type=int, default=18895, help="the vLLM model's API port; the GGUF model takes the next")
    parser.add_argument("--storage-drive", default="D:\\")
    parser.add_argument("--keep", action="store_true", help="keep the model environments for another run")
    args = parser.parse_args()
    args.reuse_fixture = args.existing_root or bool(args.reuse)
    check = Check(args)
    try:
        check.run()
    except BaseException as error:
        check.write("FAILED", {"type": type(error).__name__, "error": str(error)[:4000]})
        raise
    finally:
        check.clean()
        check.stop()


if __name__ == "__main__":
    main()
