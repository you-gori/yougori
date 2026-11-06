"""Catalog downloads, network allowlist, per-tool profiles and protocol contracts."""
import io
import base64
import hashlib
import json
import re
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_service import Flow
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "site/harnesses"))
from blue import Blue
import profiles
import relay
import harness_download
import protocols
import google_protocol


class Harnesses(unittest.TestCase):
    def test_blue_handles_fragmented_colors_without_dropping_controls(self):
        blue = Blue()
        self.assertEqual(blue.feed(b"hi\x1b[38;2;"), b"hi")
        self.assertEqual(blue.feed(b"255;0;0mred\x1b[0m\x1b[2J"), b"\x1b[38;2;82;151;255mred\x1b[0m\x1b[2J")
        self.assertEqual(Blue().feed(b"\x1b[1;31mred\x1b[39m"), b"\x1b[1;38;2;82;151;255mred\x1b[39m")
        self.assertEqual(Blue().feed(b"\x1b[48;2;31;32;33mbackground"), b"\x1b[48;2;31;32;33mbackground")
        self.assertEqual(Blue().feed(b"\x1b[97;44mwhite on blue\x1b[38;2;180;180;180mgray"), b"\x1b[97;44mwhite on blue\x1b[38;2;180;180;180mgray")

    def test_relay_only_allows_model_api_not_arbitrary_network_or_admin(self):
        for target in ("/v1/chat/completions", "/v1/responses", "/v1/messages"):
            self.assertTrue(relay.allowed("POST", target))
        self.assertTrue(relay.allowed("GET", "/v1/models"))
        for method, target in [("CONNECT", "example.com:443"), ("GET", "https://example.com/v1/models"),
                               ("POST", "/api/admin/endpoints"), ("POST", "/v1/../api/keys"),
                               ("GET", "//evil/v1/models"), ("GET", "/v1/models?url=https://evil"),
                               ("POST", "/v1/models\r\nHost: evil")]:
            self.assertFalse(relay.allowed(method, target), (method, target))

    def test_profiles_are_isolated_and_use_only_the_loopback_relay(self):
        specs = harness_download.catalog()
        with tempfile.TemporaryDirectory() as folder:
            for name, spec in specs.items():
                if spec.get("blocked"):
                    continue
                root = Path(folder) / name
                argv, env = profiles.configure(name, "source:model", [{"id": "source:model"}], root)
                self.assertTrue(argv)
                self.assertEqual(env["OPENAI_BASE_URL"], profiles.BASE)
                self.assertEqual(env["OPENAI_API_KEY"], profiles.LOCAL_KEY)
                self.assertEqual(env["HOME"], str(root))
                self.assertNotIn("AWS_ACCESS_KEY_ID", env)
                self.assertNotIn("SSH_AUTH_SOCK", env)
                with self.assertRaises(ValueError):
                    profiles.configure(name, "not-from-this-server", [], root)

    def test_download_pins_server_and_never_includes_local_state(self):
        self.assertEqual(harness_download.bundle("pi", "https://solver.example"), harness_download.bundle("pi", "https://solver.example"))
        with zipfile.ZipFile(io.BytesIO(harness_download.bundle("pi", "https://solver.example"))) as archive:
            names = archive.namelist()
            self.assertEqual(set(names), {"inference-solver/" + name for name in (*harness_download.FILES, "connection.json")})
            config = json.loads(archive.read("inference-solver/connection.json"))
            self.assertEqual(config, {"server": "https://solver.example", "harness": "pi"})
        with self.assertRaises(ValueError):
            harness_download.bundle("../api-key", "https://solver.example")

    def test_install_script_binds_exact_archive_and_refuses_injected_origins(self):
        script = harness_download.powershell("codex", "https://solver.example").decode()
        encoded = re.search(r"FromBase64String\('([A-Za-z0-9+/=]+)'\)", script)[1]
        config = json.loads(base64.b64decode(encoded))
        self.assertEqual(config["harness"], "codex")
        self.assertEqual(config["server"], "https://solver.example")
        self.assertEqual(config["sha256"], hashlib.sha256(harness_download.bundle("codex", config["server"])).hexdigest())
        for value in ("https://host';Write-Host evil", "https://host/?x=1", "https://user:pass@host", "http://remote.example", "https://host:0", "https://host:99999", "https://host#evil"):
            with self.assertRaises(ValueError):
                harness_download.powershell("pi", value)
        specs=harness_download.catalog()
        specs['pentagi']={**specs['pentagi'],'blocked':'Awaiting validation'}
        with patch.object(harness_download,'catalog',return_value=specs), self.assertRaises(ValueError):
            harness_download.powershell("pentagi", "https://solver.example")

    def test_protocol_tool_roundtrip_and_sse_completion(self):
        data = {"model": "model", "input": [{"type": "function_call", "call_id": "call1", "name": "read", "arguments": "{}"},
                     {"type": "function_call_output", "call_id": "call1", "output": "contents"}]}
        transformed = protocols.from_responses(data)
        self.assertEqual(transformed["messages"][1], {"role": "tool", "tool_call_id": "call1", "content": "contents"})
        raw = {"choices": [{"message": {"tool_calls": [{"id": "call2", "function": {"name": "read", "arguments": '{"file":"test"}'}}]},
                            "finish_reason": "tool_calls"}], "usage": {"prompt_tokens": 5, "completion_tokens": 3}}
        for kind in ("responses", "messages"):
            value = protocols.response_value(raw, "model", kind)
            events = list(protocols.events(value, kind))
            self.assertEqual(events[-1][0], "response.completed" if kind == "responses" else "message_stop")
        with self.assertRaises(ValueError):
            protocols.from_responses({"previous_response_id": "other-user-response"})

    def test_namespaced_tools_preserve_identity_across_turns(self):
        data = {"model": "m", "input": [], "tools": [{"type": "namespace", "name": "functions", "tools": [
            {"type": "function", "name": "read", "parameters": {"type": "object", "properties": {}}}]}]}
        tools, names = protocols.response_tools(data)
        identity = tools[0]["function"]["name"]
        self.assertEqual(names[identity], {"name": "read", "namespace": "functions"})
        data["input"] = [{"type": "function_call", "namespace": "functions", "name": "read", "arguments": "{}", "call_id": "c"},
                         {"type": "function_call_output", "call_id": "c", "output": "file contents"}]
        transformed = protocols.from_responses(data)
        self.assertEqual(transformed["messages"][0]["tool_calls"][0]["function"]["name"], identity)
        self.assertEqual(transformed["messages"][1]["tool_call_id"], "c")

    def test_gemini_function_history_and_forbidden_routes(self):
        payload = google_protocol.convert({"contents": [
            {"role": "model", "parts": [{"functionCall": {"name": "read", "args": {"file": "a"}}}]},
            {"role": "user", "parts": [{"functionResponse": {"name": "read", "response": {"output": "hello"}}}]}]}, "source:model")
        self.assertEqual(payload["messages"][0]["tool_calls"][0]["id"], payload["messages"][1]["tool_call_id"])
        path = "/v1beta/models/source%3Amodel:streamGenerateContent?alt=sse"
        self.assertTrue(relay.allowed("POST", path))
        self.assertEqual(google_protocol.route(path), ("source:model", True))
        for suffix in ("?key=secret", "?url=https://evil", "#evil"):
            self.assertFalse(relay.allowed("POST", path.split("?")[0] + suffix))
            self.assertIsNone(google_protocol.route(path.split("?")[0] + suffix))
        with self.assertRaises(ValueError):
            google_protocol.convert({"tools": [{"googleSearch": {}}]}, "m")

    def test_adapters_use_the_same_auth_scope_and_upstream(self):
        fixture = Flow()
        fixture.setUp()
        try:
            fixture.endpoint()
            model = "test/one"
            key = fixture.key([model])["key"]
            for path, data, terminal in [
                ("/v1/responses", {"model": model, "input": "hello"}, "response.completed"),
                ("/v1/messages", {"model": model, "max_tokens": 32, "messages": [{"role": "user", "content": "hello"}]}, "message_stop")]:
                self.assertEqual(fixture.call(path, data)[0], 401)
                status, result, _ = fixture.call(path, data, key=key)
                self.assertEqual(status, 200, result)
                self.assertEqual(result["model"], model)
                status, stream, _ = fixture.call(path, {**data, "stream": True}, key=key)
                self.assertEqual(status, 200)
                self.assertIn("event: " + terminal, stream)
                self.assertEqual(fixture.call(path, {**data, "model": "test/two"}, key=key)[0], 403)
            self.assertEqual(len(fixture.model.calls), 4)
            self.assertTrue(all(call["model"] == "test/one" for call in fixture.model.calls))
            path = "/v1beta/models/" + model + ":streamGenerateContent?alt=sse"
            data = {"contents": [{"role": "user", "parts": [{"text": "hello"}]}]}
            self.assertEqual(fixture.call(path, data)[0], 401)
            status, stream, _ = fixture.call(path, data, key=key)
            self.assertEqual(status, 200)
            self.assertIn('"text": "hello"', stream)
            self.assertEqual(fixture.call(path.replace("test/one", "test/two"), data, key=key)[0], 403)
            for path, data in [("/v1/responses", {"input": [None]}), ("/v1/messages", {"messages": [None]}),
                               (path, {"contents": [None]})]:
                self.assertEqual(fixture.call(path, {"model": model, **data}, key=key)[0], 400)
        finally:
            fixture.tearDown()


if __name__ == "__main__":
    unittest.main(verbosity=2)
