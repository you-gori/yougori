"""bridges/acp.py: the agent side of ACP for Yougori's bridges, driven by a client over pipes."""
import json
import os
from pathlib import Path
import queue
import signal
import subprocess
import sys
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "site/harnesses"))
from bridges.acp import Bridge, Cancelled


class Client:
    """The client's end: writes requests to the bridge, reads what it sends back. `serve` runs the
    bridge on the client's thread (Bridge.run by default)."""

    def __init__(self, bridge_factory, serve=None):
        to_bridge_r, self.to_bridge = os.pipe()
        self.from_bridge, from_bridge_w = os.pipe()
        self.bridge = bridge_factory(os.fdopen(to_bridge_r, "rb"), os.fdopen(from_bridge_w, "wb"))
        self.reader = os.fdopen(self.from_bridge, "rb")
        self.writer = os.fdopen(self.to_bridge, "wb")
        self.lines = queue.Queue()
        self.reading = threading.Thread(target=self._read, daemon=True)
        self.reading.start()
        self.thread = threading.Thread(target=serve or self.bridge.run, daemon=True)
        self.thread.start()
        self.ids = 0

    def _read(self):
        for line in iter(self.reader.readline, b""):
            self.lines.put(line)
        self.lines.put(b"")

    def send(self, value):
        self.writer.write((json.dumps(value) + "\n").encode())
        self.writer.flush()

    def recv(self, timeout=10):
        try:
            line = self.lines.get(timeout=timeout)
        except queue.Empty:
            raise AssertionError("the bridge sent nothing for %d s" % timeout) from None
        assert line, "the bridge closed its output"
        return json.loads(line)

    def request(self, method, params):
        self.ids += 1
        self.send({"jsonrpc": "2.0", "id": self.ids, "method": method, "params": params})
        return self.ids

    def until_response(self, request_id, seen=None):
        while True:
            message = self.recv()
            if message.get("id") == request_id and "method" not in message:
                return message
            if seen is not None:
                seen.append(message)

    def close(self):
        self.writer.close()
        self.thread.join(timeout=10)
        self.bridge._in.close()
        self.bridge._out.close()
        self.reading.join(timeout=10)
        self.reader.close()


class Probe(Bridge):
    def __init__(self, stdin, stdout):
        super().__init__("Probe", "1.0", title="Probe Bridge", models=["m1", "m2"], stdin=stdin, stdout=stdout,
                         modes=[{"id": "ask", "name": "Ask"}, {"id": "auto", "name": "Auto"}])
        self.answers = []

    def prompt(self, text, blocks):
        if text == "fail":
            raise RuntimeError("the scanner crashed")
        if text == "wait":
            self.message("waiting")
            self.cancel_event.wait(10)
            return "end_turn"
        self.thought("Planning.")
        self.message("Hello")
        self.tool_call("t1", "Write notes.txt", kind="edit", status="pending", raw_input={"path": "notes.txt"},
                       content=[self.diff("notes.txt", None, "hi\n")], parent="task-1")
        chosen = self.ask_permission("t1", "Write notes.txt")
        self.answers.append(chosen)
        self.tool_update("t1", status="completed" if chosen == "allow" else "failed")
        self.answers.append(self.question("Which target?", ["a", "b"], allow_text=True))
        self.plan([{"content": "Scan", "status": "in_progress", "priority": "high"}])
        self.finding("f1", "Open redirect", severity="medium", target="/go", evidence="Location: //evil")
        self.progress("scan", "Scanning", done=1, total=3)
        self.usage(context_tokens=900, context_window=32768)
        self.context(900, 32768)
        return "end_turn"


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.client = Client(lambda r, w: Probe(r, w))

    def tearDown(self):
        self.client.close()

    def handshake(self):
        client = self.client
        init = client.until_response(client.request("initialize", {"protocolVersion": 1, "clientCapabilities": {}}))
        self.assertEqual(init["result"]["protocolVersion"], 1)
        self.assertEqual(init["result"]["agentInfo"], {"name": "Probe", "title": "Probe Bridge", "version": "1.0"})
        session = client.until_response(client.request("session/new", {"cwd": "/workspace", "mcpServers": []}))["result"]
        self.assertTrue(session["sessionId"].startswith("probe-"))
        self.assertEqual(session["models"]["currentModelId"], "m1")
        self.assertEqual(session["modes"]["currentModeId"], "ask")
        self.assertEqual(client.bridge.cwd, "/workspace")
        return session["sessionId"]

    def test_a_turn_reports_and_asks_through_the_client(self):
        client = self.client
        session = self.handshake()
        prompt = client.request("session/prompt", {"sessionId": session, "prompt": [{"type": "text", "text": "go"}]})
        updates = []
        while True:
            message = client.recv()
            if message.get("method") == "session/request_permission":
                self.assertEqual(message["params"]["toolCall"], {"toolCallId": "t1", "title": "Write notes.txt"})
                self.assertEqual([o["kind"] for o in message["params"]["options"]], ["allow_once", "allow_always", "reject_once"])
                client.send({"jsonrpc": "2.0", "id": message["id"], "result": {"outcome": {"outcome": "selected", "optionId": "allow"}}})
            elif message.get("method") == "_yougori/question":
                self.assertEqual(message["params"], {"question": "Which target?", "choices": ["a", "b"], "multiple": False, "allow_text": True})
                client.send({"jsonrpc": "2.0", "id": message["id"], "result": {"answer": ["b"]}})
            elif message.get("id") == prompt:
                self.assertEqual(message["result"], {"stopReason": "end_turn"})
                break
            else:
                updates.append(message)
        kinds = [m["params"]["update"]["sessionUpdate"] if m["method"] == "session/update" else m["method"] for m in updates]
        self.assertEqual(kinds, ["agent_thought_chunk", "agent_message_chunk", "tool_call", "tool_call_update", "plan",
                                 "_yougori/finding", "_yougori/progress", "_yougori/usage", "usage_update"])
        call = updates[2]["params"]["update"]
        self.assertEqual(call["content"], [{"type": "diff", "path": "notes.txt", "oldText": None, "newText": "hi\n"}])
        self.assertEqual(call["_meta"], {"yougori": {"parent": "task-1"}})
        self.assertEqual(updates[5]["params"], {"id": "f1", "title": "Open redirect", "severity": "medium", "target": "/go", "evidence": "Location: //evil"})
        self.assertEqual(client.bridge.answers, ["allow", ["b"]])

    def test_cancel_errors_models_and_unknown_methods(self):
        client = self.client
        session = self.handshake()
        prompt = client.request("session/prompt", {"sessionId": session, "prompt": [{"type": "text", "text": "wait"}]})
        self.assertEqual(client.recv()["params"]["update"]["content"]["text"], "waiting")
        busy = client.until_response(client.request("session/prompt", {"sessionId": session, "prompt": [{"type": "text", "text": "x"}]}))
        self.assertIn("already running", busy["error"]["message"])
        client.send({"jsonrpc": "2.0", "method": "session/cancel", "params": {"sessionId": session}})
        self.assertEqual(client.until_response(prompt)["result"], {"stopReason": "cancelled"})
        failed = client.until_response(client.request("session/prompt", {"sessionId": session, "prompt": [{"type": "text", "text": "fail"}]}))
        self.assertEqual(failed["error"]["message"], "the scanner crashed")
        self.assertEqual(client.until_response(client.request("session/set_model", {"sessionId": session, "modelId": "m2"}))["result"], {})
        self.assertEqual(client.bridge.model, "m2")
        seen = []
        client.until_response(client.request("session/set_mode", {"sessionId": session, "modeId": "auto"}), seen)
        self.assertEqual(seen[0]["params"]["update"], {"sessionUpdate": "current_mode_update", "currentModeId": "auto"})
        unknown = client.until_response(client.request("session/fork", {}))
        self.assertEqual(unknown["error"]["code"], -32601)
        client.send({"jsonrpc": "2.0", "method": "_vendor/anything", "params": {}})
        self.assertEqual(client.until_response(client.request("authenticate", {"methodId": "x"}))["result"], {})

    def test_a_dismissed_or_cancelled_ask_reads_as_such(self):
        client = self.client
        session = self.handshake()
        bridge = client.bridge
        bridge.session = session
        result = {}

        def ask():
            result["first"] = bridge.ask_permission("t9", "Run nmap")
            try:
                bridge.question("Go on?")
            except Cancelled:
                result["second"] = "cancelled"
        worker = threading.Thread(target=ask)
        worker.start()
        asked = client.recv()
        client.send({"jsonrpc": "2.0", "id": asked["id"], "result": {"outcome": {"outcome": "cancelled"}}})
        asked = client.recv()
        self.assertEqual(asked["method"], "_yougori/question")
        bridge.cancel_event.set()
        client.send({"jsonrpc": "2.0", "id": asked["id"], "result": {"answer": None}})
        worker.join(timeout=10)
        self.assertEqual(result, {"first": None, "second": "cancelled"})


class Ending(Bridge):
    """Turns that end in whatever their text names."""

    def __init__(self, stdin, stdout):
        super().__init__("Ending", "1.0", title="Ending Bridge", stdin=stdin, stdout=stdout)

    def prompt(self, text, blocks):
        if text == "exit":
            raise SystemExit(0)
        if text == "exit with a message":
            raise SystemExit("usage: tool [options]")
        if text == "interrupt":
            raise KeyboardInterrupt
        return "end_turn"


class Lingering(Ending):
    """A turn whose thread goes on a moment after its answer went out, as a busy machine runs it."""

    def _prompt(self, *args):
        super()._prompt(*args)
        threading.Event().wait(0.2)


class TurnTests(unittest.TestCase):
    def start(self, factory, serve=None):
        client = Client(factory, serve)
        self.addCleanup(client.close)
        client.until_response(client.request("initialize", {"protocolVersion": 1}))
        session = client.until_response(client.request("session/new", {"cwd": os.getcwd(), "mcpServers": []}))
        return client, session["result"]["sessionId"]

    def test_the_next_prompt_may_follow_the_answer_at_once(self):
        # The screen sends a queued prompt the moment the last answer arrives; the turn that answered
        # is over even while its thread is still finishing.
        client, session = self.start(lambda r, w: Lingering(r, w))
        for _ in range(5):
            prompt = client.request("session/prompt", {"sessionId": session, "prompt": [{"type": "text", "text": "go"}]})
            self.assertEqual(client.until_response(prompt), {"jsonrpc": "2.0", "id": prompt, "result": {"stopReason": "end_turn"}})

    def test_every_prompt_gets_one_answer_whatever_ends_it(self):
        client, session = self.start(lambda r, w: Ending(r, w))
        answers = {}
        for text in ("exit", "exit with a message", "interrupt", "fine"):
            prompt = client.request("session/prompt", {"sessionId": session, "prompt": [{"type": "text", "text": text}]})
            answers[text] = client.until_response(prompt)
        self.assertEqual(answers["exit"]["error"]["message"], "Ending Bridge exited during the turn (exit code 0).")
        self.assertEqual(answers["exit with a message"]["error"]["message"],
                         "Ending Bridge exited during the turn: usage: tool [options]")
        self.assertEqual(answers["interrupt"]["error"]["message"], "Ending Bridge was interrupted.")
        self.assertEqual(answers["fine"]["result"], {"stopReason": "end_turn"})

    @unittest.skipUnless(hasattr(signal, "pthread_sigmask") and os.path.exists("/proc/self/status"),
                         "signal masks as Linux shows them")
    def test_commands_a_turn_starts_can_be_interrupted_and_stopped(self):
        # The bridges read the protocol on a thread that keeps SIGINT and SIGTERM blocked (as
        # support_acp.serve does); a command a turn starts must not inherit that.
        masks = []

        class Runs(Bridge):
            def prompt(self, text, blocks):
                status = subprocess.run(["sh", "-c", "grep '^SigBlk' /proc/self/status"], capture_output=True, text=True,
                                        stdin=subprocess.DEVNULL, check=True).stdout
                masks.append(int(status.split()[1], 16))
                return "end_turn"

        holder = {}

        def blocked_reader():
            signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
            holder["bridge"].run()

        def factory(r, w):
            holder["bridge"] = Runs("Runs", "1.0", stdin=r, stdout=w)
            return holder["bridge"]

        client, session = self.start(factory, serve=blocked_reader)
        prompt = client.request("session/prompt", {"sessionId": session, "prompt": [{"type": "text", "text": "go"}]})
        self.assertEqual(client.until_response(prompt)["result"], {"stopReason": "end_turn"})
        blocked = 1 << (signal.SIGINT - 1) | 1 << (signal.SIGTERM - 1)
        self.assertEqual(masks[0] & blocked, 0, "SigBlk %x" % masks[0])


if __name__ == "__main__":
    unittest.main()
