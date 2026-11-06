import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "site"))
import tool_models as tools
from transport import Failure


class Session:
    def __init__(self, replies=(), output=""):
        self.replies = iter(replies)
        self.text = output
        self.sent = []

    def __enter__(self): return self
    def __exit__(self, *args): pass
    def send(self, data): self.sent.append(data)
    def output(self, **kwargs): return self.text
    def receive(self, accepts):
        for reply in self.replies:
            if accepts(reply): return reply
        raise AssertionError("No matching reply")


def cli_rows(*items):
    return "\n".join("opencode/" + item["id"] + "\n" + json.dumps({"providerID": "opencode", **item}, indent=2) for item in items) + "\n"


class ToolModelsTests(unittest.TestCase):
    def test_codex_pages_only_for_signed_in_subscription_and_never_starts_turn(self):
        session = Session([
            {"id": 0, "result": {}}, {"id": 1, "result": {"account": {"type": "chatgpt", "email": "private@example.invalid"}}},
            {"id": 2, "result": {"data": [{"model": "first", "displayName": "First"}, {"model": "hidden", "hidden": True}], "nextCursor": "next"}},
            {"id": 3, "result": {"data": [{"model": "second"}], "nextCursor": None}},
        ])
        with patch.object(tools, "Process", return_value=session):
            result = tools.codex_models()
        self.assertEqual([row["model"] for row in result], ["first", "second"])
        self.assertNotIn("private", json.dumps(result))
        self.assertEqual([row["method"] for row in session.sent], ["initialize", "initialized", "account/read", "model/list", "model/list"])
        self.assertFalse(session.sent[-1]["params"]["includeHidden"])
        self.assertEqual(session.sent[-1]["params"]["cursor"], "next")

    def test_codex_signed_out_or_api_account_does_not_advertise_subscription(self):
        for account in (None, {"type": "apiKey"}):
            session = Session([{"id": 0, "result": {}}, {"id": 1, "result": {"account": account}}])
            with patch.object(tools, "Process", return_value=session), self.assertRaises(Failure):
                tools.codex_models()
            self.assertNotIn("model/list", [row["method"] for row in session.sent])

    def test_codex_repeating_cursor_fails_closed(self):
        session = Session([{"id": 0, "result": {}}, {"id": 1, "result": {"account": {"type": "chatgpt"}}},
                           {"id": 2, "result": {"data": [], "nextCursor": "same"}},
                           {"id": 3, "result": {"data": [], "nextCursor": "same"}}])
        with patch.object(tools, "Process", return_value=session), self.assertRaises(Failure): tools.codex_models()

    def test_claude_code_is_never_started(self):
        # Older installs may still carry a Claude subscription choice; it must do nothing.
        self.assertFalse(hasattr(tools, "claude_models"))
        with patch.dict(os.environ, {"SELECTED_PROVIDERS": "claude", "CLAUDE_ACCESS": "subscription"}), \
             patch.object(tools, "Process") as process:
            self.assertEqual(tools.catalogue("paid"), {"toolModels": [], "status": {}})
        process.assert_not_called()

    def test_free_filter_uses_all_prices_and_tracks_rotating_names(self):
        zero = {"input": 0, "output": 0, "cache": {"read": 0, "write": 0}}
        for cost in (None, {}, {"input": 0}, {"input": 0, "output": True}, {"input": 0, "output": "nan"},
                     {"input": 0, "output": 0, "cache": {"write": .1}}, {"input": 0, "output": None}):
            self.assertFalse(tools.zero_cost(cost))
        first = cli_rows({"id": "old-free", "cost": zero}, {"id": "paid-free-name", "cost": {"input": 1, "output": 0}},
                         {"id": "unknown-free"}, {"id": "retired", "cost": zero, "status": "deprecated"})
        second = cli_rows({"id": "new-name", "cost": zero}, {"id": "old-free", "cost": {"input": 0, "output": 1}})
        with patch.object(tools, "command", side_effect=[first, second]) as command:
            self.assertEqual([m["model"] for m in tools.gateway_models("opencode", True)], ["old-free"])
            self.assertEqual([m["model"] for m in tools.gateway_models("opencode", True)], ["new-name"])
        self.assertIn("--refresh", command.call_args.args[0])
        self.assertIn("--pure", command.call_args.args[0])

    def test_selection_and_discovery_failure_do_not_leak_old_or_other_models(self):
        with patch.dict(os.environ, {"SELECTED_PROVIDERS": "codex", "CODEX_ACCESS": "subscription"}), \
             patch.object(tools, "codex_models", side_effect=Failure(401, "Finish sign-in")):
            result = tools.catalogue("paid")
        self.assertEqual(result["toolModels"], [])
        self.assertEqual(result["status"], {"codex-tool": "Finish sign-in"})

    def test_process_timeout_and_output_limit_clean_up_child(self):
        for code, limit in (("import time;time.sleep(10)", .1), ("print('x'*3000000)", 5)):
            with self.assertRaises(Failure):
                with tools.Process([sys.executable, "-c", code], timeout=limit) as process:
                    process.output()
            self.assertIsNotNone(process.child.poll())
            self.assertFalse(process.reader.is_alive())


if __name__ == "__main__": unittest.main()
