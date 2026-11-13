"""The ACP bridges for Aider, Open Interpreter, SWE-agent and Plandex (site/harnesses/bridges/*_acp.py)
with their engines faked, and their headless() entries. No harness is installed here: the real
engines run only in their VM images (see harness/ADAPTERS.md). Each bridge is driven over pipes by a
small ACP client, as the Yougori screen drives it."""
import json
import os
import queue
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import types
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "site/harnesses"))
import profiles  # noqa: E402
from bridges import aider_acp, interpreter_acp, plandex_acp, swe_acp  # noqa: E402
from bridges import support_acp as support  # noqa: E402

CATALOG = [{"id": "qwen3-coder"}, {"id": "gemma-4"}]


def args(*engine, model="m1", models=("m1", "m2")):
    return support.arguments(["--model", model, "--models", json.dumps(list(models)), "--", *engine], "test")


class Client:
    """The screen's end of a bridge on pipes: collects what the bridge sends and answers its
    permission requests and questions with the policy set."""

    def __init__(self):
        to_bridge_r, to_bridge_w = os.pipe()
        from_bridge_r, from_bridge_w = os.pipe()
        self.bridge_in = os.fdopen(to_bridge_r, "rb")
        self.bridge_out = os.fdopen(from_bridge_w, "wb", buffering=0)
        self.writer = os.fdopen(to_bridge_w, "wb")
        self.reader = os.fdopen(from_bridge_r, "rb")
        self.messages = queue.Queue()
        self.seen = []
        self.permission = ["allow"]
        self.answer = None
        self.asked = []
        self.ids = 0
        threading.Thread(target=self._read, daemon=True).start()

    def attach(self, bridge):
        self.bridge = bridge
        self.thread = threading.Thread(target=bridge.run, daemon=True)
        self.thread.start()
        return bridge

    def _read(self):
        for line in iter(self.reader.readline, b""):
            message = json.loads(line)
            if message.get("method") == "session/request_permission":
                self.asked.append(message["params"])
                policy = self.permission.pop(0) if len(self.permission) > 1 else self.permission[0]
                options = message["params"]["options"]
                kinds = {"allow": "allow_once", "always": "allow_always", "reject": "reject_once"}
                choice = next((o["optionId"] for o in options if o["optionId"] == policy), None) or next(
                    (o["optionId"] for o in options if o["kind"] == kinds.get(policy)), None)
                outcome = {"outcome": "selected", "optionId": choice} if choice and policy != "dismiss" else {"outcome": "cancelled"}
                self.send({"jsonrpc": "2.0", "id": message["id"], "result": {"outcome": outcome}})
            elif message.get("method") == "_yougori/question":
                self.asked.append(message["params"])
                self.send({"jsonrpc": "2.0", "id": message["id"], "result": {"answer": self.answer}})
            self.seen.append(message)
            self.messages.put(message)

    def send(self, value):
        self.writer.write((json.dumps(value) + "\n").encode())
        self.writer.flush()

    def request(self, method, params):
        self.ids += 1
        self.send({"jsonrpc": "2.0", "id": self.ids, "method": method, "params": params})
        return self.ids

    def until(self, request_id, timeout=20):
        while True:
            message = self.messages.get(timeout=timeout)
            if message.get("id") == request_id and "method" not in message:
                return message

    def session(self, cwd):
        self.until(self.request("initialize", {"protocolVersion": 1}))
        return self.until(self.request("session/new", {"cwd": str(cwd), "mcpServers": []}))["result"]

    def prompt(self, session, text, timeout=20):
        return self.until(self.request("session/prompt", {"sessionId": session["sessionId"],
                                                           "prompt": [{"type": "text", "text": text}]}), timeout)

    def updates(self, kind=None):
        found = [m["params"]["update"] for m in self.seen if m.get("method") == "session/update"]
        return [u for u in found if kind is None or u["sessionUpdate"] == kind]

    def wait(self, check, timeout=10):
        """Waits until what the bridge sent satisfies `check` (its writer thread sends in order)."""
        pause = threading.Event()
        for _ in range(int(timeout * 20)):
            if check():
                return True
            pause.wait(0.05)
        return False

    def notices(self):
        return [m["params"] for m in self.seen if m.get("method") == "_yougori/notice"]

    def text(self):
        return "".join(u["content"]["text"] for u in self.updates("agent_message_chunk"))

    def close(self):
        self.writer.close()
        self.thread.join(timeout=10)


class Served:
    """A MainThread serving its jobs on a thread of the test (signals stay the test's)."""

    def __enter__(self):
        self.previous = signal.getsignal(signal.SIGINT)
        self.main = support.MainThread()
        self.thread = threading.Thread(target=self.main.serve, daemon=True)
        self.thread.start()
        return self.main

    def __exit__(self, *exc):
        self.main.stop()
        self.thread.join(timeout=10)
        signal.signal(signal.SIGINT, self.previous)


def done_job(result=None):
    job = support.Job(lambda: None, ())
    job.result = result
    job.done.set()
    return job


class Support(unittest.TestCase):
    def test_options_split_into_the_bridges_and_the_engines(self):
        parsed = support.arguments(["--model", "m2", "--models", '["m1", "m2", 3]', "--context-window", "8192", "--",
                                    "--config", "/c.yml", "--model", "openai/m2"], "x")
        self.assertEqual((parsed.model, parsed.models, parsed.context_window, parsed.max_output), ("m2", ["m1", "m2"], 8192, 4096))
        self.assertEqual(parsed.engine, ["--config", "/c.yml", "--model", "openai/m2"])
        self.assertEqual(support.arguments(["--model", "x"], "x").models, ["x"])

    def test_answers_and_file_texts(self):
        home = Path(tempfile.mkdtemp())
        self.assertEqual(support.answers(str(home)), {})
        (home / ".yougori").mkdir()
        (home / ".yougori/answers.json").write_text('{"issue": "Fix it"}', encoding="utf-8")
        self.assertEqual(support.answers(str(home)), {"issue": "Fix it"})
        (home / "a.txt").write_bytes(b"one\ntwo\n")
        (home / "b.bin").write_bytes(b"\x00\x01binary")
        self.assertEqual(support.read_text(str(home / "a.txt")), "one\ntwo\n")
        self.assertIsNone(support.read_text(str(home / "b.bin")))
        self.assertIsNone(support.read_text(str(home / "missing")))
        self.assertIsNone(support.read_text(str(home / "a.txt"), limit=3))

    def test_main_thread_runs_jobs_and_interrupts_only_the_job_asked(self):
        with Served() as main:
            self.assertEqual(main.call(lambda a, b: a + b, 2, 3), 5)
            with self.assertRaisesRegex(ValueError, "boom"):
                main.call(lambda: (_ for _ in ()).throw(ValueError("boom")))
            started, release = threading.Event(), threading.Event()
            job = main.submit(lambda: (started.set(), release.wait(5)))
            started.wait(5)
            self.assertIs(main.current, job)
            self.assertFalse(main.interrupt(only=done_job()), "another job is not interrupted")
            release.set()
            job.done.wait(5)
        # The handler raises only for an interrupt that was asked for, once, and only inside a
        # job's own code: never in the bookkeeping that ends a job (its caller would wait for ever).
        previous = signal.getsignal(signal.SIGINT)
        try:
            handler = support.MainThread()
            handler._in_job = True
            handler._on_interrupt(signal.SIGINT, None)
            handler._armed = True
            with self.assertRaises(KeyboardInterrupt):
                handler._on_interrupt(signal.SIGINT, None)
            handler._on_interrupt(signal.SIGINT, None)
            handler._armed, handler._in_job = True, False
            handler._on_interrupt(signal.SIGINT, None)
        finally:
            signal.signal(signal.SIGINT, previous)

    def test_an_interrupt_handled_as_a_job_returns_still_ends_it(self):
        # A cancel at the very end of a turn: interrupt() arms as the job's code returns, and the
        # signal is handled a moment later, wherever the main thread then is. The job must end
        # (its caller waits for it) and the thread serve on.
        for moment, expected in (("_in_job", KeyboardInterrupt), ("_job", "done")):
            with self.subTest(handled_just_before_setting=moment):
                class Late(support.MainThread):
                    def __setattr__(self, name, value):
                        if name == moment and value in (False, None) and getattr(self, "_armed", False):
                            self._on_interrupt(signal.SIGINT, None)
                        super().__setattr__(name, value)
                previous = signal.getsignal(signal.SIGINT)
                main = Late()
                thread = threading.Thread(target=main.serve, daemon=True)
                thread.start()
                try:
                    def job():
                        main._armed = True
                        return "done"
                    ran = main.submit(job)
                    self.assertTrue(ran.done.wait(5), "the job ended")
                    if expected is KeyboardInterrupt:
                        with self.assertRaises(KeyboardInterrupt):
                            ran.outcome()
                    else:
                        self.assertEqual(ran.outcome(), expected)
                    self.assertEqual(main.call(lambda: "next"), "next", "the thread serves on")
                finally:
                    main.stop()
                    thread.join(5)
                    signal.signal(signal.SIGINT, previous)

    def test_a_job_interrupted_while_it_waits_never_runs(self):
        with Served() as main:
            started, release = threading.Event(), threading.Event()
            running = main.submit(lambda: (started.set(), release.wait(5)))
            self.assertTrue(started.wait(5))
            ran = []
            waiting = main.submit(ran.append, "ran")
            self.assertTrue(main.interrupt(only=waiting), "the job waiting behind another is dropped")
            self.assertFalse(main.interrupt(only=waiting), "once")
            self.assertFalse(running.interrupted, "the job running goes on")
            release.set()
            self.assertTrue(waiting.done.wait(5))
            with self.assertRaises(KeyboardInterrupt):
                waiting.outcome()
            self.assertEqual(ran, [])
            self.assertEqual(main.call(lambda: "next"), "next", "the jobs after it run")
            self.assertFalse(main.interrupt(only=running), "a job that ended is not interrupted")

    def test_messages_keep_their_order_and_the_bridge_hears_the_client_leave(self):
        client = Client()

        class Probe(support.QueuedBridge):
            gone = threading.Event()

            def prompt(self, text, blocks):
                for i in range(200):
                    self.message("%d " % i)
                return "end_turn"

            def closing(self):
                self.gone.set()
        bridge = client.attach(Probe("Probe", "1", client.bridge_in, stdout=client.bridge_out))
        session = client.session(tempfile.mkdtemp())
        self.assertEqual(client.prompt(session, "go")["result"], {"stopReason": "end_turn"})
        self.assertEqual(client.text(), "".join("%d " % i for i in range(200)))
        client.close()
        self.assertTrue(bridge.gone.wait(5))
        self.assertTrue(bridge.cancel_event.is_set())
        bridge.flush()

    @unittest.skipIf(os.name == "nt", "process groups are POSIX")
    def test_a_process_group_is_stopped_whole(self):
        process = subprocess.Popen(["sh", "-c", "sleep 30 & sleep 30; wait"], start_new_session=True)
        support.remember_group(process.pid)
        support.stop_group(process, grace=2)
        self.assertIsNotNone(process.poll())


# A fake aider: just what the bridge touches of its pinned 0.86.2 API.

class FakeInputOutput:
    def __init__(self, pretty=True, yes=None, input_history_file=None, chat_history_file=None, **kwargs):
        self.pretty, self.yes, self.kwargs = pretty, yes, kwargs
        self.never_prompts = set()
        self.num_user_asks = self.num_error_outputs = 0
        self.dry_run = False
        self.history = []

    def append_chat_history(self, text, linebreak=False, blockquote=False, strip=True):
        self.history.append(text)

    def tool_output(self, *messages, log_only=False, bold=False):
        self.history.append(" ".join(messages))

    def tool_warning(self, message="", strip=True):
        self.history.append(message)

    def write_text(self, filename, content, max_retries=5, initial_delay=0.1):
        if not self.dry_run:
            Path(filename).write_text(content, encoding="utf-8")


class FakeGroup:
    def __init__(self, show=True):
        self.show_group, self.preference = show, None


class SwitchCoder(Exception):
    def __init__(self, placeholder=None, **kwargs):
        self.kwargs, self.placeholder = kwargs, placeholder


class FakeModel:
    reasoning_tag = None
    info = {"max_input_tokens": 32768}

    def __init__(self, name, weak_model=None, editor_model=None, **kwargs):
        self.name, self.edit_format = name, "whole"

    def send_completion(self, messages, functions, stream, temperature=None):
        chunks = [types.SimpleNamespace(choices=[types.SimpleNamespace(delta=types.SimpleNamespace(
            reasoning_content=r, content=c))], usage=None) for r, c in (("Thinking. ", None), (None, "Hello "), (None, "there."))]
        chunks[-1].usage = types.SimpleNamespace(prompt_tokens=900, completion_tokens=12)
        return "hash", iter(chunks)

    def token_count(self, value):
        return 7


class FakeCoder:
    created = []

    def __init__(self, main_model, io, edit_format="whole"):
        self.main_model, self.io, self.edit_format = main_model, io, edit_format
        self.root = os.getcwd()
        self.last_keyboard_interrupt = None
        self.announced = 0

    @classmethod
    def create(cls, io=None, from_coder=None, main_model=None, edit_format=None, summarize_from_coder=True, **kwargs):
        coder = cls(main_model or from_coder.main_model, io or from_coder.io, edit_format or from_coder.edit_format)
        cls.created.append((coder.main_model.name, coder.edit_format, summarize_from_coder))
        return coder

    def show_announcements(self):
        self.announced += 1
        self.io.tool_output("Model: %s with %s edit format" % (self.main_model.name, self.edit_format))

    def run(self, with_message=None, preproc=True):
        if with_message == "/ask":
            raise SwitchCoder(edit_format="ask", summarize_from_coder=False)
        if with_message == "write":
            target = Path(self.root) / "made.py"
            if self.io.confirm_ask("Create new file?", subject="made.py"):
                target.touch()
                self.io.write_text(target, "print('made')\n")
            return
        if with_message == "/run":
            code, output = sys.modules["aider.commands"].run_cmd("echo bridge-ok", cwd=self.root)
            self.io.tool_output("exit %s" % code)
            return
        _, stream = self.main_model.send_completion([], None, True)
        for _ in stream:
            pass
        self.io.tool_output("Tokens: 900 sent, 12 received.")


def fake_aider(coder_holder):
    """sys.modules entries standing in for aider (a fresh set per test)."""
    main = types.ModuleType("aider.main")
    main.InputOutput = FakeInputOutput
    repomap = types.ModuleType("aider.repomap")

    class RepoMap:
        TAGS_CACHE_DIR = ".aider.tags.cache.v4"
    repomap.RepoMap, main.tags_at_start = RepoMap, []

    def run_main(argv, return_coder=False):
        # Where its repo map keeps its tags cache, as aider starts.
        main.tags_at_start.append(RepoMap.TAGS_CACHE_DIR)
        io = main.InputOutput(False, True, None, None, fancy_input=True)
        coder = FakeCoder(FakeModel(argv[argv.index("--model") + 1]), io)
        coder_holder.append(coder)
        return coder
    main.main = run_main
    coders = types.ModuleType("aider.coders")
    coders.Coder = FakeCoder
    commands = types.ModuleType("aider.commands")
    commands.SwitchCoder = SwitchCoder
    commands.run_cmd = None
    models = types.ModuleType("aider.models")
    models.Model = FakeModel
    base_coder = types.ModuleType("aider.coders.base_coder")
    base_coder.run_cmd = None
    tags = types.ModuleType("aider.reasoning_tags")
    tags.REASONING_START, tags.REASONING_END = "--------------\n► **THINKING**", "------------\n► **ANSWER**"
    package = types.ModuleType("aider")
    return {"aider": package, "aider.main": main, "aider.coders": coders, "aider.commands": commands, "aider.models": models,
            "aider.coders.base_coder": base_coder, "aider.reasoning_tags": tags, "aider.repomap": repomap}


class FakeCommands:
    def cmd_add(self, args):
        "Add files to the chat so aider can edit them or review them in detail"

    def cmd_ask(self, args):
        """Ask questions about the code base without editing any files. If no prompt provided, switches to ask mode."""

    def cmd_code(self, args):
        """Ask for changes to your code. If no prompt provided, switches to code mode."""

    def cmd_exit(self, args):
        "Exit the application"

    def cmd_voice(self, args):
        "Record and transcribe voice input"


class Aider(unittest.TestCase):
    def setUp(self):
        self.work = Path(tempfile.mkdtemp())
        self.cwd = os.getcwd()
        self.coders = []
        FakeCoder.created = []
        self.modules = mock.patch.dict(sys.modules, fake_aider(self.coders))
        self.modules.start()
        original = FakeModel.send_completion
        self.addCleanup(setattr, FakeModel, "send_completion", original)

    def tearDown(self):
        os.chdir(self.cwd)
        self.modules.stop()

    def start(self, client, main):
        bridge = client.attach(aider_acp.AiderBridge(args("--config", "/c.yml", "--model", "openai/m1"), client.bridge_in, main,
                                                     commands=FakeCommands, stdout=client.bridge_out))
        bridge.describe_modes(FakeCommands)
        session = client.session(self.work)
        bridge.startup.done.wait(10)
        return bridge, session

    def test_streams_tags_and_chunks(self):
        splitter = aider_acp.TagSplitter("think")
        pieces = []
        for text in ("Hi <th", "ink>why", "</thi", "nk> so <b>"):
            pieces += splitter.feed(text)
        pieces += splitter.flush()
        self.assertEqual(pieces, [("message", "Hi "), ("thought", "why"), ("message", " so <b>")])
        chunk = types.SimpleNamespace(choices=[types.SimpleNamespace(delta=types.SimpleNamespace(reasoning_content="r", content="c"))])
        self.assertEqual(aider_acp.deltas(chunk, aider_acp.TagSplitter(None)), [("thought", "r"), ("message", "c")])
        self.assertEqual(aider_acp.mode_of(types.SimpleNamespace(edit_format="diff")), "code")
        self.assertEqual(aider_acp.mode_of(types.SimpleNamespace(edit_format="architect")), "architect")

    def test_aider_starts_with_its_tags_cache_where_the_profile_keeps_its_files(self):
        """Aider's repo map kept its tags cache beside the project, where the person's review listed
        it (profiles.AIDER_FILES); without the profile's folder, where Aider puts it."""
        files = str(self.work / "home/.aider")
        with mock.patch.dict(os.environ, {"SOLVER_AIDER_FILES": files}), Served() as main:
            self.start(Client(), main)
        self.assertEqual(sys.modules["aider.main"].tags_at_start, [os.path.join(files, ".aider.tags.cache.v4")])
        with mock.patch.dict(sys.modules, fake_aider([])), mock.patch.dict(os.environ, {"SOLVER_AIDER_FILES": ""}), Served() as main:
            self.start(Client(), main)
            self.assertEqual(sys.modules["aider.main"].tags_at_start, [".aider.tags.cache.v4"])

    def test_a_session_starts_aider_streams_its_reply_and_switches_modes_and_models(self):
        client = Client()
        with Served() as main:
            bridge, session = self.start(client, main)
            coder = self.coders[0]
            self.assertIsInstance(coder.io, FakeInputOutput)
            self.assertIsNone(coder.io.yes, "the person answers, not return_coder's yes")
            self.assertFalse(coder.io.kwargs.get("fancy_input"))
            self.assertEqual(session["modes"]["currentModeId"], "code")
            self.assertEqual(session["modes"]["availableModes"][1]["description"], "Ask questions about the code base without editing any files.")
            commands = client.updates("available_commands_update")[0]["availableCommands"]
            self.assertEqual([c["name"] for c in commands], ["add", "ask", "code"], "exit and voice are not offered")
            self.assertEqual(client.prompt(session, "hello")["result"], {"stopReason": "end_turn"})
            self.assertEqual(client.text(), "Hello there.")
            self.assertEqual([u["content"]["text"] for u in client.updates("agent_thought_chunk")], ["Thinking. "])
            usage = [m["params"] for m in client.seen if m.get("method") == "_yougori/usage"][-1]
            self.assertEqual(usage, {"context_tokens": 912, "context_window": 32768, "input_tokens": 900, "output_tokens": 12})
            self.assertFalse(any("Tokens:" in n["text"] for n in client.notices()), "the usage line is the status line's")
            # /ask switches the coder as aider's main loop does, and the mode follows.
            self.assertEqual(client.prompt(session, "/ask")["result"], {"stopReason": "end_turn"})
            self.assertEqual(bridge.coder.edit_format, "ask")
            self.assertEqual(client.updates("current_mode_update")[-1]["currentModeId"], "ask")
            # The screen's model and mode, applied as /model and /chat-mode apply them.
            client.until(client.request("session/set_model", {"sessionId": session["sessionId"], "modelId": "m2"}))
            client.until(client.request("session/set_mode", {"sessionId": session["sessionId"], "modeId": "code"}))
            self.assertEqual(client.prompt(session, "hello")["result"], {"stopReason": "end_turn"})
            self.assertEqual((bridge.coder.main_model.name, bridge.coder.edit_format), ("openai/m2", "whole"))
            client.close()

    def test_writes_are_edits_with_diffs_and_confirmations_are_permissions(self):
        client = Client()
        with Served() as main:
            bridge, session = self.start(client, main)
            self.assertEqual(client.prompt(session, "write")["result"], {"stopReason": "end_turn"})
            asked = client.asked[-1]
            self.assertEqual(asked["toolCall"]["title"], "Create new file? made.py")
            self.assertEqual([o["optionId"] for o in asked["options"]], ["yes", "no"])
            edits = [u for u in client.updates("tool_call") if u["kind"] == "edit" and u["status"] == "completed"]
            self.assertEqual(edits[-1]["title"], "Create made.py")
            self.assertEqual(edits[-1]["content"], [{"type": "diff", "path": str(self.work / "made.py"), "oldText": None,
                                                      "newText": "print('made')\n"}])
            # Declined: nothing written.
            (self.work / "made.py").unlink()
            client.permission = ["reject"]
            client.prompt(session, "write")
            self.assertFalse((self.work / "made.py").exists())
            client.close()

    def test_confirmation_answers_follow_aider(self):
        bridge = types.SimpleNamespace(confirm=mock.Mock(), note=lambda text: None)
        io = aider_acp.make_io(FakeInputOutput, bridge)(True, True, None, None)
        bridge.confirm.return_value = "all"
        group = FakeGroup()
        self.assertTrue(io.confirm_ask("Add file to the chat?", subject="a.py", group=group))
        self.assertEqual(group.preference, "all")
        self.assertTrue(io.confirm_ask("Add file to the chat?", subject="b.py", group=group), "the group's answer stands")
        self.assertEqual(bridge.confirm.call_count, 1)
        bridge.confirm.return_value = "dont"
        self.assertFalse(io.confirm_ask("Add URL to the chat?", subject="https://x", allow_never=True))
        self.assertFalse(io.confirm_ask("Add URL to the chat?", subject="https://x", allow_never=True))
        self.assertEqual(bridge.confirm.call_count, 2, "don't ask again is kept")
        bridge.confirm.return_value = "all"
        self.assertFalse(io.confirm_ask("Run shell commands?", subject="ls", explicit_yes_required=True),
                         "an explicit yes is needed for commands")

    def test_shell_commands_run_in_a_group_of_their_own_as_terminal_calls(self):
        client = Client()
        with Served() as main:
            bridge, session = self.start(client, main)
            self.assertEqual(client.prompt(session, "/run")["result"], {"stopReason": "end_turn"})
            call = [u for u in client.updates("tool_call") if u["kind"] == "execute"][-1]
            self.assertEqual((call["title"], call["rawInput"]), ("echo bridge-ok", {"command": "echo bridge-ok"}))
            final = [u for u in client.updates("tool_call_update") if u.get("toolCallId") == call["toolCallId"]][-1]
            self.assertEqual((final["status"], final["rawOutput"]), ("completed", {"exit_code": 0}))
            self.assertIn("bridge-ok", final["content"][0]["content"]["text"])
            self.assertIn("exit 0", "\n".join(n["text"] for n in client.notices()))
            client.close()

    def test_refused_commands_and_exit(self):
        client = Client()
        with Served() as main:
            bridge, session = self.start(client, main)
            self.assertEqual(client.prompt(session, "/model gpt-4")["result"], {"stopReason": "end_turn"})
            self.assertIn("model switcher", client.notices()[-1]["text"])
            with mock.patch.object(bridge, "leave") as leave:
                client.prompt(session, "/exit")
            leave.assert_called_once()
            client.close()

    def test_a_cancel_while_aider_starts_leaves_its_start_alone(self):
        fake_main = sys.modules["aider.main"]
        original, release = fake_main.main, threading.Event()

        def slow_start(argv, return_coder=False):
            release.wait(10)  # aider's imports, its Git setup and its questions
            return original(argv, return_coder)
        fake_main.main = slow_start
        client = Client()
        with Served() as main, mock.patch.object(support, "exit_now") as exit_now:
            bridge = client.attach(aider_acp.AiderBridge(args("--config", "/c.yml", "--model", "openai/m1"), client.bridge_in,
                                                         main, commands=FakeCommands, stdout=client.bridge_out))
            session = client.session(self.work)
            prompt = client.request("session/prompt", {"sessionId": session["sessionId"],
                                                       "prompt": [{"type": "text", "text": "hello"}]})
            client.send({"jsonrpc": "2.0", "method": "session/cancel", "params": {"sessionId": session["sessionId"]}})
            self.assertEqual(client.until(prompt)["result"], {"stopReason": "cancelled"})
            self.assertFalse(bridge.startup.interrupted, "aider's start goes on")
            release.set()
            self.assertTrue(bridge.startup.done.wait(10))
            exit_now.assert_not_called()
            self.assertIsNotNone(bridge.coder)
            self.assertEqual(client.prompt(session, "hello")["result"], {"stopReason": "end_turn"})
            self.assertEqual(client.text(), "Hello there.")
            client.close()

    def test_a_cancel_while_the_turn_waits_on_the_main_thread_stops_it(self):
        client = Client()
        ran = []
        original = FakeCoder.run
        self.addCleanup(setattr, FakeCoder, "run", original)
        FakeCoder.run = lambda coder, with_message=None, preproc=True: (ran.append(with_message),
                                                                        original(coder, with_message, preproc))[1]
        with Served() as main:
            bridge, session = self.start(client, main)
            # A slow job ahead of the turn (a mode switch summarizing the chat with a model call).
            started, release = threading.Event(), threading.Event()
            main.submit(lambda: (started.set(), release.wait(10)))
            self.assertTrue(started.wait(5))
            prompt = client.request("session/prompt", {"sessionId": session["sessionId"],
                                                       "prompt": [{"type": "text", "text": "hello"}]})
            self.assertTrue(client.wait(lambda: bridge.turn_job is not None))
            client.send({"jsonrpc": "2.0", "method": "session/cancel", "params": {"sessionId": session["sessionId"]}})
            self.assertTrue(client.wait(lambda: bridge.turn_job.interrupted))
            release.set()
            self.assertEqual(client.until(prompt)["result"], {"stopReason": "cancelled"})
            self.assertEqual((ran, client.text()), ([], ""), "nothing of the cancelled turn ran")
            self.assertEqual(client.prompt(session, "hello")["result"], {"stopReason": "end_turn"})
            self.assertEqual(ran, ["hello"])
            client.close()


# A fake Open Interpreter: the LMC chunks its chat(stream=True) yields at 0.4.3.

class FakeInterpreter:
    def __init__(self, script):
        self.script, self.messages, self.auto_run = script, [], False
        self.stop_event = threading.Event()
        self.closed = False
        self.llm = types.SimpleNamespace(model="openai/m1", context_window=32768)
        self.system_message = "You are Open Interpreter."
        self.computer = types.SimpleNamespace(terminal=types.SimpleNamespace(_active_languages={}))

    def chat(self, message, display=True, stream=False):
        self.messages.append({"role": "user", "type": "message", "content": message})

        def chunks():
            try:
                for chunk in self.script:
                    if chunk.get("type") == "confirmation" and self.auto_run:
                        continue
                    yield chunk
            except GeneratorExit:
                self.closed = True
                raise
        return chunks()


CODE_TURN = [
    {"role": "assistant", "type": "message", "start": True},
    {"role": "assistant", "type": "message", "content": "I will count."},
    {"role": "assistant", "type": "message", "end": True},
    {"role": "assistant", "type": "code", "format": "python", "start": True},
    {"role": "assistant", "type": "code", "format": "python", "content": "print(6 * 7)"},
    {"role": "assistant", "type": "code", "format": "python", "end": True},
    {"role": "computer", "type": "confirmation", "format": "execution", "content": {"type": "code", "format": "python",
                                                                                     "content": "print(6 * 7)"}},
    {"role": "computer", "type": "console", "start": True},
    {"role": "computer", "type": "console", "format": "active_line", "content": 1},
    {"role": "computer", "type": "console", "format": "output", "content": "42\n"},
    {"role": "computer", "type": "console", "format": "active_line", "content": None},
    {"role": "computer", "type": "console", "end": True},
    {"role": "assistant", "type": "message", "content": "It is 42."},
]


class Interpreter(unittest.TestCase):
    def start(self, client, main, script):
        bridge = client.attach(interpreter_acp.InterpreterBridge(
            args("--offline", "--disable_telemetry", "--model", "openai/m1", "--api_base", "http://127.0.0.1:8080/v1"),
            client.bridge_in, main, stdout=client.bridge_out))
        with mock.patch.object(bridge, "_setup", lambda: None):
            session = client.session(tempfile.mkdtemp())
        bridge.oi = FakeInterpreter(script)
        bridge.setup = done_job()
        return bridge, session

    def test_options_are_its_terminal_clients(self):
        self.assertEqual(interpreter_acp.engine_options(["--offline", "--disable_telemetry", "--model", "openai/x",
                                                         "--api_base", "http://h/v1"]),
                         {"offline": True, "disable_telemetry": True, "model": "openai/x", "api_base": "http://h/v1"})

    def test_code_is_a_tool_call_asked_before_it_runs(self):
        client = Client()
        with Served() as main:
            bridge, session = self.start(client, main, CODE_TURN)
            self.assertEqual(session["modes"]["currentModeId"], "ask")
            self.assertEqual(client.prompt(session, "count")["result"], {"stopReason": "end_turn"})
            self.assertEqual(client.text(), "I will count.It is 42.")
            asked = client.asked[-1]
            self.assertEqual(asked["toolCall"]["title"], "Run this python code?")
            self.assertEqual(asked["toolCall"]["rawInput"], {"command": "print(6 * 7)", "language": "python"})
            self.assertEqual([o["optionId"] for o in asked["options"]], ["run", "always", "decline"])
            tool = asked["toolCall"]["toolCallId"]
            final = [u for u in client.updates("tool_call_update") if u["toolCallId"] == tool and u.get("status")][-1]
            self.assertEqual(final["status"], "completed")
            self.assertEqual(final["content"][0]["content"]["text"], "42\n")
            titled = [u for u in client.updates("tool_call_update") if u["toolCallId"] == tool and u.get("title")]
            self.assertEqual(titled[0]["title"], "Run python: print(6 * 7)")
            client.close()

    def test_declined_code_is_not_run_and_always_turns_auto_run_on(self):
        client = Client()
        with Served() as main:
            bridge, session = self.start(client, main, CODE_TURN)
            client.permission = ["reject"]
            self.assertEqual(client.prompt(session, "count")["result"], {"stopReason": "end_turn"})
            self.assertEqual(bridge.oi.messages[-1], {"role": "user", "type": "message", "content": interpreter_acp.DECLINED})
            self.assertTrue(bridge.oi.closed, "Open Interpreter's generator is closed, as its terminal does")
            self.assertNotIn("It is 42.", client.text())
            client.permission = ["always"]
            client.prompt(session, "count")
            self.assertTrue(bridge.oi.auto_run)
            self.assertEqual(client.updates("current_mode_update")[-1]["currentModeId"], "auto")
            before = len(client.asked)
            client.prompt(session, "count")
            self.assertEqual(len(client.asked), before, "auto run does not ask")
            client.close()

    def test_magic_commands_and_models(self):
        client = Client()
        magic = types.ModuleType("interpreter.terminal_interface.magic_commands")
        magic.handle_magic_command = lambda oi, command: print("handled", command)
        with Served() as main, mock.patch.dict(sys.modules, {"interpreter": types.ModuleType("interpreter"),
                                                             "interpreter.terminal_interface": types.ModuleType("x"),
                                                             "interpreter.terminal_interface.magic_commands": magic}):
            bridge, session = self.start(client, main, [])
            client.prompt(session, "/tokens hello")
            self.assertEqual(client.notices()[-1]["text"], "handled %tokens hello")
            client.until(client.request("session/set_model", {"sessionId": session["sessionId"], "modelId": "m2"}))
            client.prompt(session, "hi")
            self.assertEqual(bridge.oi.llm.model, "openai/m2")
            client.close()


class Swe(unittest.TestCase):
    def setUp(self):
        # The harness's home, as profiles.environment() sets it in the VM: a session's git rules go
        # there, never into the home of whoever runs these tests.
        self.config = tempfile.mkdtemp()
        environment = mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": self.config})
        environment.start()
        self.addCleanup(environment.stop)

    def test_arguments_patches_and_actions(self):
        self.assertEqual(swe_acp.override(["--a", "1", "--b", "2"], "--b", "3"), ["--a", "1", "--b", "3"])
        self.assertEqual(swe_acp.override(["--a", "1"], "--c", "x"), ["--a", "1", "--c", "x"])
        patch = ("diff --git a/new.txt b/new.txt\nnew file mode 100644\n--- /dev/null\n+++ b/new.txt\n@@ -0,0 +1 @@\n+x\n"
                 "diff --git a/old.py b/old.py\ndeleted file mode 100644\n--- a/old.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-y\n")
        self.assertEqual(swe_acp.patch_files(patch), [("new.txt", False), ("old.py", True)])
        step = types.SimpleNamespace(tool_calls=[{"function": {"name": "str_replace_editor",
                                                                "arguments": '{"command": "create", "path": "/r/a.py"}'}}],
                                     action="str_replace_editor create /r/a.py")
        self.assertEqual(swe_acp.tool_of(step), ("str_replace_editor", {"command": "create", "path": "/r/a.py"}))
        step = types.SimpleNamespace(tool_calls=None, action="ls -la")
        self.assertEqual(swe_acp.tool_of(step), ("bash", {"command": "ls -la"}))

    def test_the_repository_is_the_workspace(self):
        empty = tempfile.mkdtemp()
        root = swe_acp.prepare_repository(empty)
        self.assertTrue(os.path.samefile(root, empty))
        self.assertIn("Initialize temporary workspace", swe_acp.git(empty, "log", "--oneline").stdout)
        exclude = Path(root, ".git/info/exclude").read_bytes()
        swe_acp.keep_reports_out(root)
        swe_acp.keep_reports_out(root)
        # In the home's git rules, so the workspace's .git, which the person reviews, is unchanged.
        self.assertEqual(Path(self.config, "git/ignore").read_text(encoding="utf-8").splitlines(), ["/reports/swe-agent/"])
        self.assertEqual(Path(root, ".git/info/exclude").read_bytes(), exclude)
        busy = tempfile.mkdtemp()
        Path(busy, "notes.txt").write_text("mine", encoding="utf-8")
        with mock.patch.dict(os.environ, {"SOLVER_EMPTY_WORKSPACE": ""}):
            with self.assertRaisesRegex(RuntimeError, "Git repository"):
                swe_acp.prepare_repository(busy)

    def test_steps_are_reported_and_the_patch_is_saved(self):
        client = Client()
        root = tempfile.mkdtemp()
        with Served() as main, mock.patch.object(swe_acp, "preload", lambda: None):
            bridge = client.attach(swe_acp.SweBridge(args(), client.bridge_in, main, stdout=client.bridge_out))
            client.session(root)
            root = bridge.root
            hook = swe_acp.make_hook(object, bridge)()
            hook.on_init(agent=None)
            bridge.call_limit = 50
            hook.on_tools_installation_started()
            hook.on_setup_attempt()
            hook.on_step_start()
            path = os.path.join(root, "fix.py")
            step = types.SimpleNamespace(thinking_blocks=[{"thinking": "Plan it."}], thought="I create the fix.",
                                         action="str_replace_editor create " + path, observation="File created.",
                                         tool_calls=[{"function": {"name": "str_replace_editor", "arguments": json.dumps(
                                             {"command": "create", "path": path, "file_text": "x = 1\n"})}}])
            hook.on_actions_generated(step=step)
            hook.on_action_started(step=step)
            Path(path).write_bytes(b"x = 1\n")
            hook.on_action_executed(step=step)
            hook.on_step_done(step=step, info={"model_stats": {"tokens_sent": 1500, "tokens_received": 40}})
            command = types.SimpleNamespace(thinking_blocks=None, thought="", action="python fix.py", observation="\r\nok\r\n",
                                            tool_calls=[{"function": {"name": "bash", "arguments": '{"command": "python fix.py"}'}}])
            hook.on_actions_generated(step=command)
            hook.on_action_started(step=command)
            hook.on_action_executed(step=command)
            self.assertTrue(client.wait(lambda: len([u for u in client.updates("tool_call_update")
                                                     if u.get("status") == "completed"]) == 2))
            calls = client.updates("tool_call")
            self.assertEqual([(c["title"], c["kind"]) for c in calls], [("Create fix.py", "edit"), ("python fix.py", "execute")])
            done = [u for u in client.updates("tool_call_update") if u.get("status") == "completed"]
            self.assertEqual(done[0]["content"][0], {"type": "diff", "path": path, "oldText": None, "newText": "x = 1\n"})
            self.assertEqual(done[1]["content"][0]["content"]["text"], "ok")
            self.assertEqual(client.text(), "I create the fix.\n\n")
            self.assertEqual(client.updates("agent_thought_chunk")[0]["content"]["text"], "Plan it.\n")
            progress = [(m["params"]["id"], m["params"]["finished"]) for m in client.seen if m.get("method") == "_yougori/progress"]
            self.assertEqual(progress, [("swe-run-0-setup", False), ("swe-run-0-setup", True), ("swe-run-0-steps", False)])
            # The run's end: the patch as diffs, a report in the workspace, the turn's stop reason.
            output = tempfile.mkdtemp()
            config = types.SimpleNamespace(output_dir=output)
            os.makedirs(os.path.join(output, "run-1"))
            Path(output, "run-1", "run-1.traj").write_text("{}", encoding="utf-8")
            patch = "diff --git a/fix.py b/fix.py\nnew file mode 100644\n--- /dev/null\n+++ b/fix.py\n@@ -0,0 +1 @@\n+x = 1\n"
            reason = bridge.finish(config, "run-1", {"exit_status": "submitted (exit_cost)", "submission": patch,
                                                     "model_stats": {"api_calls": 3}}, 5)
            self.assertEqual(reason, "end_turn")
            self.assertTrue(client.wait(lambda: any(m.get("method") == "_yougori/report" for m in client.seen)))
            report = [m["params"] for m in client.seen if m.get("method") == "_yougori/report"][-1]
            self.assertTrue(report["path"].endswith(os.path.join("reports", "swe-agent", "run-1", "summary.md")))
            self.assertTrue(Path(root, "reports/swe-agent/run-1/run-1.patch").is_file())
            self.assertTrue(Path(root, "reports/swe-agent/run-1/run-1.traj").is_file())
            self.assertEqual(client.updates("tool_call")[-1]["title"], "Patch: 1 file changed")
            self.assertEqual(bridge.finish(config, "run-2", {"exit_status": "exit_cost"}, 1), "max_turn_requests")
            self.assertEqual(bridge.finish(config, "run-3", {"exit_status": "exit_context"}, 1), "max_tokens")
            client.close()

    def issue_home(self):
        home = Path(tempfile.mkdtemp())
        (home / ".yougori").mkdir()
        (home / ".yougori/answers.json").write_text('{"issue": "Login fails with a plus sign"}', encoding="utf-8")
        return home

    def test_the_setup_issue_starts_the_first_run(self):
        client = Client()
        config = types.SimpleNamespace(output_dir=tempfile.mkdtemp())
        with Served() as main, mock.patch.dict(os.environ, {"HOME": str(self.issue_home())}), \
                mock.patch.object(swe_acp, "preload", lambda: None):
            bridge = client.attach(swe_acp.SweBridge(args(), client.bridge_in, main, stdout=client.bridge_out))
            session = client.session(tempfile.mkdtemp())
            self.assertIn("Login fails with a plus sign", client.notices()[0]["text"])
            runs = []

            def run(statement):
                runs.append(statement)
                return bridge.finish(config, "run-%d" % len(runs), {"exit_status": "submitted"}, 1)
            with mock.patch.object(bridge, "_run", run):
                client.prompt(session, "Also add a test.")
                client.prompt(session, "Next issue.")
            self.assertEqual(runs, ["Login fails with a plus sign\n\nAlso add a test.", "Next issue."])
            client.close()

    def test_the_setup_issue_stays_until_a_run_works_on_it(self):
        client = Client()
        config = types.SimpleNamespace(output_dir=tempfile.mkdtemp())
        outcomes = iter([RuntimeError("the model server went away"), KeyboardInterrupt(), "exit_api", "submitted (exit_cost)",
                         "submitted"])
        with Served() as main, mock.patch.dict(os.environ, {"HOME": str(self.issue_home())}), \
                mock.patch.object(swe_acp, "preload", lambda: None):
            bridge = client.attach(swe_acp.SweBridge(args(), client.bridge_in, main, stdout=client.bridge_out))
            session = client.session(tempfile.mkdtemp())
            runs = []

            def run(statement):
                runs.append(statement)
                outcome = next(outcomes)
                if isinstance(outcome, BaseException):
                    raise outcome
                return bridge.finish(config, "run-%d" % len(runs), {"exit_status": outcome}, 1)
            with mock.patch.object(bridge, "_run", run):
                failed = client.prompt(session, "Go.")
                cancelled = client.prompt(session, "Try again.")
                broke = client.prompt(session, "Once more.")
                worked = client.prompt(session, "And again.")
                client.prompt(session, "Next issue.")
            self.assertEqual(failed["error"]["message"], "the model server went away")
            self.assertEqual(cancelled["result"], {"stopReason": "cancelled"})
            self.assertEqual((broke["result"], worked["result"]), ({"stopReason": "end_turn"}, {"stopReason": "end_turn"}))
            issue = "Login fails with a plus sign\n\n"
            self.assertEqual(runs, [issue + "Go.", issue + "Try again.", issue + "Once more.", issue + "And again.", "Next issue."],
                             "a failed, cancelled or broken run leaves the issue for the next")
            client.close()

    def test_the_statement_never_goes_through_swe_agents_command_line(self):
        # SWE-agent's first parser (BasicCLI.get_config in sweagent/run/common.py at 3ea751c) reads
        # "--help", "-hi, ..." or "--print_config" as its own options and exits; its settings parser
        # cuts a value joined with '=' at the first line. The statement goes on the parsed config.
        given = []

        class BasicCLI:
            def __init__(self, config_type, help_text=None):
                self.config_type = config_type

            def get_config(self, args):
                given.append(list(args))
                return types.SimpleNamespace(agent=types.SimpleNamespace(model=None), problem_statement="parsed")

        class TextProblemStatement:
            def __init__(self, text, id):
                self.text, self.id = text, id
        modules = {"sweagent": types.ModuleType("sweagent"), "sweagent.run": types.ModuleType("sweagent.run"),
                   "sweagent.run.common": types.ModuleType("sweagent.run.common"),
                   "sweagent.run.run_single": types.ModuleType("sweagent.run.run_single"),
                   "sweagent.agent": types.ModuleType("sweagent.agent"),
                   "sweagent.agent.problem_statement": types.ModuleType("sweagent.agent.problem_statement")}
        modules["sweagent.run.common"].BasicCLI = BasicCLI
        modules["sweagent.run.run_single"].RunSingleConfig = object
        modules["sweagent.agent.problem_statement"].TextProblemStatement = TextProblemStatement
        engine = ["--config", "/opt/solver/source/config/default.yaml", "--agent.model.name", "openai/m1",
                  "--problem_statement.text", "from the profile", "--problem_statement.id=x", "--output_dir", "/o"]
        bridge = types.SimpleNamespace(args=args(*engine), model="m2", root="/work space")
        statements = ("--help", "-hi, the login page fails with a plus sign in the email", "--print_config",
                      "Login fails with a plus sign\n\nAlso add a test.", "- add a test\n- update the docs", "x" * 200000)
        with mock.patch.dict(sys.modules, modules):
            for statement in statements:
                config = swe_acp.SweBridge.configuration(bridge, statement, "run-7")
                self.assertEqual((config.problem_statement.text, config.problem_statement.id), (statement, "run-7"))
        for argv in given:
            self.assertFalse([a for a in argv if a.startswith("--problem_statement")], argv)
            self.assertFalse(set(statements) & set(argv))
            self.assertEqual(argv[:2], ["--config", "/opt/solver/source/config/default.yaml"])
            self.assertEqual(argv[argv.index("--agent.model.name") + 1], "openai/m2")
            self.assertEqual(argv[argv.index("--env.repo.repo_name") + 1], "work space")
            self.assertEqual(argv[argv.index("--agent.tools.reset_commands") + 1], "[\"cd '/work space'\"]")
        self.assertEqual(swe_acp.without_statement(["--problem_statement.text", "a", "--x", "1", "--problem_statement.id=b"]),
                         ["--x", "1"])

    def test_an_exit_in_swe_agent_ends_the_turn_with_an_error(self):
        client = Client()
        with Served() as main, mock.patch.object(swe_acp, "preload", lambda: None):
            bridge = client.attach(swe_acp.SweBridge(args(), client.bridge_in, main, stdout=client.bridge_out))
            session = client.session(tempfile.mkdtemp())
            with mock.patch.object(bridge, "_run", lambda statement: sys.exit(0)):
                failed = client.prompt(session, "--help")
            self.assertIn("SWE-agent stopped (exit code 0)", failed["error"]["message"])
            with mock.patch.object(bridge, "_run", lambda statement: "end_turn"):
                self.assertEqual(client.prompt(session, "Fix it.")["result"], {"stopReason": "end_turn"})
            client.close()

    def test_a_cancel_while_the_run_waits_behind_swe_agents_import_stops_it(self):
        client = Client()
        importing, release = threading.Event(), threading.Event()

        def slow_preload():
            importing.set()
            release.wait(10)
        with Served() as main, mock.patch.object(swe_acp, "preload", slow_preload):
            bridge = client.attach(swe_acp.SweBridge(args(), client.bridge_in, main, stdout=client.bridge_out))
            session = client.session(tempfile.mkdtemp())
            self.assertTrue(importing.wait(5))
            preload = main.current
            runs = []
            with mock.patch.object(bridge, "_run", lambda statement: runs.append(statement) or "end_turn"):
                prompt = client.request("session/prompt", {"sessionId": session["sessionId"],
                                                           "prompt": [{"type": "text", "text": "Fix it."}]})
                self.assertTrue(client.wait(lambda: bridge.turn_job is not None))
                client.send({"jsonrpc": "2.0", "method": "session/cancel", "params": {"sessionId": session["sessionId"]}})
                self.assertTrue(client.wait(lambda: bridge.turn_job.interrupted))
                self.assertFalse(preload.interrupted, "SWE-agent's import goes on")
                release.set()
                self.assertEqual(client.until(prompt)["result"], {"stopReason": "cancelled"})
                self.assertEqual(runs, [], "the cancelled run never started")
                self.assertEqual(client.prompt(session, "Fix it.")["result"], {"stopReason": "end_turn"})
                self.assertEqual(runs, ["Fix it."])
            client.close()


class Plandex(unittest.TestCase):
    def make(self, client):
        bridge = client.attach(plandex_acp.PlandexBridge(args(), client.bridge_in, stdout=client.bridge_out))
        bridge.workspace = tempfile.mkdtemp()
        bridge.session = "plandex-test"
        return bridge

    def test_terminal_text_and_reply_markup(self):
        self.assertEqual(plandex_acp.plain(b"\x1b[31mred\x1b[0m line\r\nover\rwritten\n"), "red line\nwritten\n")
        self.assertEqual(plandex_acp.markdown('Done.\n- a.go:\n<PlandexBlock lang="go" path="a.go">\npackage a\n</PlandexBlock>\n'
                                              "<PlandexFinish/>"), "Done.\n- a.go:\n```go\npackage a\n```")
        self.assertEqual(plandex_acp.YES_NO.search("Commit Plandex updates now? (y)es | (n)o> ").group(1), "Commit Plandex updates now?")
        select = plandex_acp.SELECT.search("? What do you want to do?  [Use arrows to move, type to filter]")
        self.assertEqual(select.group(1), "What do you want to do?")

    def test_the_stream_becomes_messages_and_progress(self):
        client = Client()
        bridge = self.make(client)
        for chunk in ('{"type": "reply", "replyChunk": "Plan:\\n<Plan"}', '{"type": "reply", "replyChunk": "dexFinish/> next"}',
                      '{"type": "buildInfo", "buildInfo": {"path": "a.go", "numTokens": 12}}',
                      '{"type": "loadContext", "loadContextFiles": ["a.go", "b.go"]}',
                      '{"type": "describing"}',
                      '{"type": "reply", "replyChunk": "More."}'):
            self.assertFalse(bridge.stream_message(chunk.encode()))
        self.assertTrue(bridge.stream_message(b'{"type": "error", "error": {"msg": "model refused"}}'))
        self.assertTrue(bridge.stream_message(b'{"type": "finished"}'))
        self.assertFalse(bridge.stream_message(b"heartbeat"))
        self.assertTrue(client.wait(lambda: len(client.notices()) == 1))
        self.assertEqual(client.text(), "Plan:\n next\n\nMore.")
        progress = [m["params"] for m in client.seen if m.get("method") == "_yougori/progress"]
        self.assertEqual(progress[0], {"id": "plandex-0-build-a.go", "label": "Building a.go", "finished": False, "done": 12,
                                       "unit": "tokens"})
        # Processing ends when the next reply streams; the build stays open for the command's end.
        self.assertEqual([(p["id"], p["finished"]) for p in progress[1:]],
                         [("plandex-0-processing", False), ("plandex-0-processing", True)])
        self.assertEqual(list(bridge.stages), ["build-a.go"])
        self.assertEqual(client.updates("tool_call")[0]["title"], "Load context: a.go, b.go")
        self.assertEqual(client.notices()[-1], {"text": "Plandex: model refused", "level": "error"})

    def test_each_command_has_its_own_progress_finished_when_it_ends_well(self):
        client = Client()
        bridge = self.make(client)
        bridge.keep_transcript = lambda *details: None
        codes = iter([0, 1])

        class FakeTerminal:
            def __init__(self, argv, cwd, environment, on_screen=None, on_prompt=None):
                self.process = mock.Mock(poll=lambda: 0)
                self.screen, self.nudged = False, None

            def wait(self, cancel, on_cancel):
                bridge.stream_message(b'{"type": "describing"}')
                return next(codes)

            def close(self):
                pass

            def text(self):
                return ""

        with mock.patch.object(plandex_acp, "Terminal", FakeTerminal):
            self.assertEqual(bridge.in_terminal(["tell", "one"]), (0, ""))
            self.assertEqual(bridge.in_terminal(["tell", "two"]), (1, ""))

        def progress():
            return [(m["params"]["id"], m["params"]["finished"]) for m in client.seen if m.get("method") == "_yougori/progress"]
        self.assertTrue(client.wait(lambda: len(progress()) >= 3))
        # The failed command's stage is left open: the screen shows it stopped when the turn ends.
        self.assertEqual(progress(), [("plandex-1-processing", False), ("plandex-1-processing", True),
                                      ("plandex-2-processing", False)])
        self.assertEqual(bridge.stages, {})

    def test_changes_are_applied_only_when_the_person_says_so(self):
        client = Client()
        bridge = self.make(client)
        target = os.path.join(bridge.workspace, "a.txt")
        ran = []
        bridge.pending = lambda: ([(target, None, "new\n")], "npm test\n")
        bridge.in_terminal = lambda command, watch=True: (ran.append(command), (0, "Applied"))[1]
        bridge.run_cli = lambda command, timeout=600: (ran.append(command), (0, "Rejected"))[1]
        bridge.cancel_event.clear()
        client.permission = ["apply-run"]
        self.assertEqual(bridge.review(), "end_turn")
        self.assertEqual(ran[-1], ["apply", "--auto-exec"])
        options = [o["optionId"] for o in client.asked[-1]["options"]]
        self.assertEqual(options, ["apply", "apply-run", "later", "reject"])
        client.permission = ["apply"]
        bridge.review()
        self.assertEqual(ran[-1], ["apply", "--no-exec"])
        client.permission = ["reject"]
        bridge.review()
        self.assertEqual(ran[-1], ["reject", "--all"])
        count = len(ran)
        client.permission = ["dismiss"]
        bridge.review()
        self.assertEqual(len(ran), count, "dismissed: the changes stay pending")
        self.assertTrue(client.wait(lambda: len([u for u in client.updates("tool_call_update") if u.get("title")]) == 2))
        titles = [u.get("title") for u in client.updates("tool_call_update") if u.get("title")]
        self.assertEqual(titles[-2:], ["Apply Plandex's changes to 1 file (rejected)", "Apply Plandex's changes to 1 file (kept pending)"])
        # /diff shows them without asking; nothing runs.
        asked = len(client.asked)
        self.assertEqual(bridge.review(ask=False, explicit=True), "end_turn")
        self.assertTrue(client.wait(lambda: len(client.updates("tool_call")) == 5))
        shown = client.updates("tool_call")[-1]
        self.assertEqual((shown["title"], shown["kind"], shown["status"]),
                         ("Plandex's pending changes (1 file, not applied)", "read", "completed"))
        self.assertEqual(shown["content"][0], {"type": "diff", "path": target, "oldText": None, "newText": "new\n"})
        self.assertEqual((len(client.asked), len(ran)), (asked, count))

    def started(self, client):
        """A bridge whose Plandex has started on m1 (no services: they are faked)."""
        bridge = self.make(client)
        bridge.auth = {"token": "t", "orgId": "o", "orgName": "Inference Solver"}
        bridge.proxy = types.SimpleNamespace(model="m1")
        bridge.applied = "m1"
        bridge.ready.set()
        return bridge

    def test_models_switch_in_place(self):
        client = Client()
        bridge = self.started(client)
        with mock.patch.object(plandex_acp.plandex_cli, "request") as request:
            bridge.set_model("m2")
        sent = request.call_args[0][1]
        self.assertEqual(sent["models"][0]["providers"][0]["modelName"], "m2")
        self.assertEqual(set(sent["modelPacks"][0]) - {"name", "description"}, set(plandex_acp.ROLES))
        self.assertEqual((bridge.proxy.model, bridge.model, bridge.applied), ("m2", "m2", "m2"))
        headers = bridge.headers()
        self.assertTrue(headers["Authorization"].startswith("Bearer "))

    def test_a_model_chosen_during_a_step_waits_for_the_next(self):
        # Plandex's server keeps the model a step started with, and the proxy serves only the one it
        # is on: switching the proxy in the middle of a step would refuse the rest of the step.
        client = Client()
        bridge = self.started(client)
        in_step, go_on = threading.Event(), threading.Event()
        models = []

        def step(command):
            models.append(bridge.proxy.model)
            in_step.set()
            go_on.wait(10)
            models.append(bridge.proxy.model)
            return 0, ""
        bridge.step = step
        bridge.review = lambda: "end_turn"

        def prompt(text):
            return client.request("session/prompt", {"sessionId": "plandex-test", "prompt": [{"type": "text", "text": text}]})
        with mock.patch.object(plandex_acp.plandex_cli, "request") as request:
            first = prompt("Add a test.")
            self.assertTrue(in_step.wait(10))
            switched = client.until(client.request("session/set_model", {"sessionId": "plandex-test", "modelId": "m2"}))
            self.assertEqual(switched["result"], {})
            go_on.set()
            self.assertEqual(client.until(first)["result"], {"stopReason": "end_turn"})
            self.assertEqual(models, ["m1", "m1"], "the step ends on the model it started with")
            self.assertEqual((bridge.proxy.model, bridge.model, request.call_count), ("m1", "m2", 0))
            self.assertTrue(client.wait(lambda: any("next message uses m2" in n["text"] for n in client.notices())))
            # The next turn takes it before its first command.
            self.assertEqual(client.until(prompt("And the docs."))["result"], {"stopReason": "end_turn"})
            self.assertEqual(models[2:], ["m2", "m2"])
            self.assertEqual(request.call_count, 1)
            self.assertEqual(request.call_args[0][1]["models"][0]["providers"][0]["modelName"], "m2")
            # A switch while no turn runs is made at once.
            client.until(client.request("session/set_model", {"sessionId": "plandex-test", "modelId": "m1"}))
            self.assertEqual((bridge.proxy.model, request.call_count), ("m1", 2))

    def test_a_prompt_reaches_plandex_in_a_file_of_its_own(self):
        # As an argument, "- add tests" reads as Plandex's options, and a pasted log over 128 KiB is
        # more than one argument may be.
        client = Client()
        bridge = self.started(client)
        seen = []

        def step(command):
            path = command[-1]
            with open(path, encoding="utf-8", newline="") as stream:
                seen.append((command[:-1], stream.read(), path))
            return 0, ""
        bridge.step = step
        bridge.review = lambda: "end_turn"
        log = "".join("line %d of the build log\n" % i for i in range(9000))
        self.assertGreater(len(log.encode()), 200 * 1024)
        for text in ("- add tests\n- update the docs", log):
            self.assertEqual(bridge.prompt(text, []), "end_turn")
        bridge.mode = "chat"
        self.assertEqual(bridge.prompt("--help me read this", []), "end_turn")
        self.assertEqual([s[0] for s in seen], [["tell", "--skip-menu", "--file"]] * 2 + [["chat", "--file"]])
        self.assertEqual([s[1] for s in seen], ["- add tests\n- update the docs", log.strip(), "--help me read this"])
        self.assertFalse(any(os.path.exists(s[2]) for s in seen), "each file goes when its step ends")

    def test_continue_leaves_plandex_s_changes_menu_to_the_bridge(self):
        client = Client()
        bridge = self.started(client)
        ran = []
        bridge.step = lambda command: (ran.append(command), (0, ""))[1]
        bridge.review = lambda: ran.append("review") or "end_turn"
        self.assertEqual(bridge.prompt("/continue", []), "end_turn")
        bridge.mode = "chat"
        self.assertEqual(bridge.prompt("/continue", []), "end_turn")
        self.assertEqual(ran, [["continue", "--skip-menu"], "review", ["continue", "--skip-menu", "--chat"]])

    def test_plandex_s_changes_menu_is_left_with_enter(self):
        menu = ("\x1b[1;92m1 file has pending changes\x1b[0m\n- a.go\n\n(a)  apply  Apply all pending changes\n"
                "\x1b[1;95mPress a hotkey,\x1b[0m \x1b[1;97m↓\x1b[0m \x1b[1;95mto select, or\x1b[0m \x1b[1;97menter\x1b[0m "
                "\x1b[1;95mto exit menu/keep iterating>\x1b[0m")
        terminal = object.__new__(plandex_acp.Terminal)
        terminal.output, terminal.seen, terminal.lock = bytearray(menu.encode()), 0, threading.Lock()
        asked, written = [], []
        terminal.on_prompt = lambda *details: asked.append(details)
        terminal.write = written.append
        terminal._prompts()
        self.assertEqual((written, asked), ([b"\r"], []))
        terminal._prompts()
        self.assertEqual(written, [b"\r"], "each menu is answered once")

    @unittest.skipUnless(os.name != "nt" and shutil.which("setsid"), "terminals of their own are POSIX (setsid -c)")
    def test_a_command_waiting_in_the_changes_menu_ends(self):
        script = ("printf '\\033[1;95mPress a hotkey,\\033[0m \\342\\206\\223 to select, or enter to exit menu/keep "
                  "iterating>'; read -r key; echo left-the-menu")
        terminal = plandex_acp.Terminal(["sh", "-c", script], tempfile.mkdtemp(), dict(os.environ), on_prompt=lambda *a: None)
        guard = threading.Timer(20, terminal.stop)
        guard.start()
        try:
            code = terminal.wait()
        finally:
            guard.cancel()
            terminal.close()
        self.assertEqual(code, 0)
        self.assertIn("left-the-menu", terminal.text())

    def test_plandex_s_project_folder_goes_unless_the_workspace_had_it(self):
        # `plandex new` writes .plandex-dev-v2 into the workspace; it points at a plan in a database
        # that goes with the VM, so it must not stay behind for the person to review.
        for had in (False, True):
            with self.subTest(had=had):
                bridge = self.make(Client())
                workspace = bridge.workspace
                if had:
                    os.makedirs(os.path.join(workspace, plandex_acp.PROJECT))
                bridge.commands = lambda commands: None
                with mock.patch.object(plandex_acp.threading, "Thread"), mock.patch("os.chdir"):
                    bridge.new_session(workspace, [])
                os.makedirs(os.path.join(workspace, plandex_acp.PROJECT), exist_ok=True)
                with open(os.path.join(workspace, plandex_acp.PROJECT, "projects-v2.json"), "w") as stream:
                    stream.write("{}")
                bridge.stop_services()
                self.assertEqual(os.path.isdir(os.path.join(workspace, plandex_acp.PROJECT)), had)

    def test_plandex_s_project_folder_goes_before_its_services_are_stopped(self):
        # The harness gives a bridge 3 s after SIGTERM before SIGKILL; stopping Plandex's services
        # may take longer (8 s each), so the folder must already be gone when they are stopped.
        bridge = self.make(Client())
        workspace = bridge.workspace
        bridge.commands = lambda commands: None
        with mock.patch.object(plandex_acp.threading, "Thread"), mock.patch("os.chdir"):
            bridge.new_session(workspace, [])
        os.makedirs(os.path.join(workspace, plandex_acp.PROJECT))
        seen = []

        class Service:
            def poll(self):
                seen.append(os.path.isdir(os.path.join(workspace, plandex_acp.PROJECT)))
                raise KeyboardInterrupt  # the SIGKILL, as far as this bridge can tell
        bridge.processes = [("server", Service())]
        with self.assertRaises(KeyboardInterrupt):
            bridge.stop_services()
        self.assertEqual(seen, [False])

    @unittest.skipUnless(hasattr(signal, "pthread_sigmask") and os.path.exists("/proc/self/status"),
                         "signal masks as Linux shows them")
    def test_plandex_s_services_can_be_interrupted_and_stopped(self):
        # new_session runs on the protocol's reader, which keeps SIGINT and SIGTERM blocked.
        client = Client()
        bridge = self.make(client)
        masks = []

        def start_services():
            status = subprocess.run(["sh", "-c", "grep '^SigBlk' /proc/self/status"], capture_output=True, text=True,
                                    stdin=subprocess.DEVNULL, check=True).stdout
            masks.append(int(status.split()[1], 16))
        bridge.start_services = start_services
        bridge.new_plan = lambda: None

        def reader():
            support.quiet_signals()
            starter = threading.Thread(target=bridge._start)
            starter.start()
            starter.join(10)
        thread = threading.Thread(target=reader)
        thread.start()
        thread.join(15)
        self.assertTrue(bridge.ready.is_set())
        blocked = 1 << (signal.SIGINT - 1) | 1 << (signal.SIGTERM - 1)
        self.assertEqual(len(masks), 1)
        self.assertEqual(masks[0] & blocked, 0, "SigBlk %x" % masks[0])


class HeadlessEntries(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp())
        self.work = Path(tempfile.mkdtemp())

    def test_each_bridge_is_an_acp_engine_in_its_harness_venv(self):
        for harness in ("aider", "interpreter", "swe", "plandex"):
            with self.subTest(harness=harness):
                spec = profiles.headless(harness, "qwen3-coder", CATALOG, self.home, {}, cwd=self.work)
                argv = spec["argv"]
                self.assertEqual((spec["protocol"], spec["model_switch"]), ("acp", "live"))
                self.assertEqual(argv[:2], [profiles.BRIDGE_PYTHON, "/opt/solver/bridges/%s_acp.py" % harness])
                self.assertEqual(argv[2:10], ["--model", "qwen3-coder", "--models", '["qwen3-coder", "gemma-4"]',
                                              "--context-window", "32768", "--max-output", "4096"])
                own, env = profiles.configure(harness, "qwen3-coder", CATALOG, self.home)
                engine = argv[argv.index("--") + 1:]
                self.assertEqual(engine, {"swe": own[2:], "plandex": [], "aider": own[4:]}.get(harness, own[1:]))
                self.assertEqual(spec["env"], env)
                self.assertEqual(spec["respec"], ["python3", "/opt/solver/runtime.py", "engine", harness])
                self.assertTrue(Path(__file__).resolve().parents[1].joinpath("site/harnesses/bridges/%s_acp.py" % harness).is_file())
                parsed = support.arguments(argv[2:], harness)
                self.assertEqual((parsed.model, parsed.models, parsed.engine), ("qwen3-coder", ["qwen3-coder", "gemma-4"], engine))

    def test_the_protocol_names_the_harnesses_it_bridges(self):
        """bridges/acp.py once named Strix, Shannon and PentAGI as bridges too: the security
        harnesses run their own terminal clients in the screen's terminal pane."""
        from bridges import acp
        folder = Path(__file__).resolve().parents[1] / "site/harnesses/bridges"
        bridged = {path.name.removesuffix("_acp.py") for path in folder.glob("*_acp.py")} - {"support"}
        self.assertEqual(bridged, {"aider", "interpreter", "swe", "plandex"})
        named = {harness for harness, title in profiles.NAMES.items()
                 if harness != "yougori" and re.search(r"\b%s\b" % re.escape(title), acp.__doc__)}
        self.assertEqual(named, bridged)
        for harness in profiles.SECURITY:
            spec = profiles.headless(harness, "qwen3-coder", CATALOG, self.home, {}, cwd=self.work)
            self.assertEqual(spec["protocol"], "terminal", harness)


if __name__ == "__main__":
    unittest.main()
