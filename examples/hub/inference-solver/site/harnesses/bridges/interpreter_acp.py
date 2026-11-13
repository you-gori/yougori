"""Open Interpreter (open-interpreter 0.4.3) behind the Yougori screen, over ACP.

This file is our own program; it imports Open Interpreter (AGPL-3.0) as a library in its own
process (see harness/NOTICE.md). The interpreter is set up as its terminal client sets it up: its
default profile, then the options configure() gives it (offline, no telemetry, the relay model and
base URL), with this inference's window. Each prompt is interpreter.chat(stream=True): its message
chunks become messages, each code block a tool call whose code streams in and whose console output
follows, and its confirmation step (auto_run off) a permission request; "don't ask again" turns
auto_run on, which is also the session's "auto" mode. Its % commands are the available commands
(typed with /). A cancel uses Open Interpreter's own stop (its stop_event, which also interrupts
the Python kernel), interrupts a running shell command, and, when the model is still thinking,
interrupts the call the way Ctrl+C does. The work runs on the main thread.
"""
import contextlib
import io
import itertools
import os
import sys
import threading
import time
import traceback

_HERE = os.path.dirname(os.path.abspath(__file__))
if __package__ in (None, ""):
    sys.path[:] = [p for p in sys.path if os.path.abspath(p or os.curdir) != _HERE]
    sys.path.append(os.path.dirname(_HERE))

from bridges import support_acp as support  # noqa: E402
from bridges.acp import Cancelled  # noqa: E402

MODES = [{"id": "ask", "name": "Ask", "description": "Approve each code block before it runs."},
         {"id": "auto", "name": "Auto run", "description": "Run code without asking (auto_run)."}]
# Open Interpreter's % commands that make sense in the screen (typed as /name).
MAGIC = {"help": (None, "Open Interpreter's help"), "reset": (None, "Start a new conversation"),
         "undo": (None, "Remove the last message and its reply"),
         "tokens": ("prompt", "Count the conversation's tokens (and a prompt's)"),
         "info": (None, "Show the session's settings"), "verbose": ("true or false", "Detailed output on or off"),
         "auto_run": ("true or false", "Run code without asking, or ask first"),
         "save_message": ("file.json", "Save the conversation to a JSON file"),
         "load_message": ("file.json", "Load a conversation from a JSON file"),
         "markdown": ("file.md", "Export the conversation as Markdown"),
         "jupyter": (None, "Export the conversation as a Jupyter notebook")}
DECLINED = "I have declined to run this code."
OUTPUT_LIMIT = 64 * 1024
GRACE = 1.5


def version():
    try:
        from importlib.metadata import version as installed
        return installed("open-interpreter")
    except Exception:
        return "0.4.3"


def engine_options(argv):
    """configure()'s interpreter options, read as its terminal client reads them."""
    options = {"offline": False, "disable_telemetry": False, "model": None, "api_base": None}
    i = 0
    while i < len(argv):
        name = argv[i].lstrip("-").replace("-", "_")
        if name in ("offline", "disable_telemetry"):
            options[name] = True
        elif name in ("model", "api_base", "context_window", "max_tokens") and i + 1 < len(argv):
            options[name] = argv[i + 1]
            i += 1
        else:
            sys.stderr.write("Open Interpreter bridge: ignoring option %s\n" % argv[i])
        i += 1
    return options


class InterpreterBridge(support.QueuedBridge):
    def __init__(self, args, stdin, main, **options):
        super().__init__("Open Interpreter", version(), stdin, title="Open Interpreter", models=args.models,
                         model=args.model, modes=[dict(m) for m in MODES], mode="ask", **options)
        self.args, self.main = args, main
        self.options = engine_options(args.engine)
        self.oi = None
        self.ids = itertools.count(1)
        self.lock = threading.Lock()
        self.turn_open = False
        self.pending_model = None
        self.turn_job = None

    def new_session(self, cwd, mcp_servers):
        if os.path.isdir(cwd):
            os.chdir(cwd)
        self.commands([{"name": name, "description": description, **({"hint": hint} if hint else {})}
                       for name, (hint, description) in MAGIC.items()])
        self.setup = self.main.submit(self._setup)

    def _setup(self):
        """The interpreter as its terminal client sets it up (on the main thread)."""
        try:
            from interpreter import interpreter
            from interpreter.terminal_interface.profiles.profiles import profile
            oi = profile(interpreter, "default.yaml")
            oi.offline = bool(self.options["offline"])
            oi.disable_telemetry = bool(self.options["disable_telemetry"])
            oi.llm.model = self.options["model"] or "openai/" + self.args.model
            oi.llm.api_base = self.options["api_base"] or os.environ.get("OPENAI_API_BASE")
            oi.llm.api_key = os.environ.get("OPENAI_API_KEY")
            oi.llm.context_window = int(self.options.get("context_window") or self.args.context_window)
            oi.llm.max_tokens = int(self.options.get("max_tokens") or self.args.max_output)
            oi.auto_run = False
            oi.stop_event = threading.Event()
            self.oi = oi
            self.apply_pending()
            return oi
        except BaseException as error:
            traceback.print_exc()
            support.exit_now(self, 1, "Open Interpreter could not start: %s" % (error,))

    # Turns.

    def prompt(self, text, blocks):
        while not self.setup.done.wait(0.2):
            if self.cancel_event.is_set():
                return "cancelled"
        self.turn_job = job = self.main.submit(self._run_turn, text)
        if self.cancel_event.is_set():
            # Cancelled before this job was the turn's (cancelled() saw the last one).
            self.main.interrupt(only=job)
        job.done.wait()
        try:
            return job.outcome()
        except (KeyboardInterrupt, SystemExit):
            if self.cancel_event.is_set():
                return "cancelled"
            raise RuntimeError("Open Interpreter stopped the turn.")

    def _run_turn(self, text):
        if self.cancel_event.is_set():
            # Cancelled before its turn on the main thread came: nothing of it runs.
            return "cancelled"
        oi = self.oi
        self.apply_pending()
        oi.stop_event.clear()
        self.turn_open = True
        try:
            if text.startswith("/") and text[1:].split(" ")[0] in MAGIC:
                self.magic("%" + text[1:])
                return "end_turn"
            return self.chat(text)
        except (KeyboardInterrupt, SystemExit):
            # Ctrl+C in Open Interpreter: while the model streams it exits (SystemExit), else it
            # stops the code; either way this turn ends here.
            if self.cancel_event.is_set():
                return "cancelled"
            raise
        finally:
            self.turn_open = False
            self.report_usage()

    def chat(self, text):
        oi = self.oi
        stream = oi.chat(text, display=False, stream=True)
        state = {"code": None, "output": "", "shown": 0.0, "language": None, "started": False, "running": None}
        try:
            for chunk in stream:
                if self.cancel_event.is_set():
                    break
                if self.chunk(chunk, state) == "declined":
                    oi.messages.append({"role": "user", "type": "message", "content": DECLINED})
                    break
        finally:
            stream.close()
            if self.cancel_event.is_set() and state["running"]:
                self.reset_language(state["running"])
            if state["code"] is not None and state["started"]:
                self.finish_code(state, "failed" if self.cancel_event.is_set() else "completed")
        return "cancelled" if self.cancel_event.is_set() else "end_turn"

    def reset_language(self, name):
        """A shell-like language stopped in the middle of a command is in an unknown state: it is
        ended, and the next code in it starts a fresh one (the Python kernel keeps its state)."""
        terminal = self.oi.computer.terminal
        language = terminal._active_languages.get(name)
        if language is None or not hasattr(language, "process"):
            return
        try:
            language.terminate()
        except Exception:
            traceback.print_exc()
        terminal._active_languages.pop(name, None)

    def chunk(self, chunk, state):
        role, kind, fmt = chunk.get("role"), chunk.get("type"), chunk.get("format")
        content = chunk.get("content")
        if role == "assistant" and kind == "message":
            if isinstance(content, str) and content:
                self.message(content)
        elif role == "assistant" and kind == "code":
            if chunk.get("start"):
                state.update(code=self.next_id(), source="", language=fmt or "code", started=False, output="")
                self.tool_call(state["code"], "Write %s code" % state["language"], kind="execute", status="pending",
                               raw_input={"language": state["language"]})
            elif isinstance(content, str) and state["code"]:
                state["source"] += content
                if time.monotonic() - state["shown"] > 0.25:
                    state["shown"] = time.monotonic()
                    self.tool_update(state["code"], content=[self.text(fenced(state["language"], state["source"]))])
            elif chunk.get("end") and state["code"]:
                self.code_ready(state)
        elif role == "computer" and kind == "confirmation":
            details = content if isinstance(content, dict) else {}
            if state["code"] is None:
                state.update(code=self.next_id(), source=details.get("content", ""), language=details.get("format", "code"),
                             started=False, output="")
                self.code_ready(state)
            return self.confirm(state, details)
        elif role == "computer" and kind == "console":
            if state["code"] is None:
                state.update(code=self.next_id(), source="", language="code", started=False, output="")
                self.tool_call(state["code"], "Code output", kind="execute", status="in_progress")
            if not state["started"]:
                state["started"] = True
                state["running"] = state["language"]
                self.tool_update(state["code"], status="in_progress")
            if fmt == "output" and isinstance(content, str):
                state["output"] += content
                self.show_output(state)
            elif fmt == "active_line" and content is None and chunk.get("end") is None:
                self.show_output(state, force=True)
            elif chunk.get("end"):
                self.finish_code(state, "completed")
        elif role == "computer" and (kind == "image" or fmt in ("html", "javascript")):
            if state["code"] is not None:
                state["output"] += "\n[%s output: %s]\n" % (kind, fmt)
                self.show_output(state, force=True)
        elif kind == "review" and isinstance(content, str) and content:
            self.notice(content)
        return None

    def code_ready(self, state):
        source = state.get("source", "")
        first = support.first_line(source, 80) or "code"
        self.change_tool(state["code"], title="Run %s: %s" % (state["language"], first),
                         raw_input={"command": source, "language": state["language"]},
                         content=[self.text(fenced(state["language"], source))])

    def confirm(self, state, details):
        """Open Interpreter's confirmation (auto_run off) as a permission request."""
        source = details.get("content", state.get("source", ""))
        options = [{"optionId": "run", "name": "Run", "kind": "allow_once"},
                   {"optionId": "always", "name": "Run, and stop asking (auto run)", "kind": "allow_always"},
                   {"optionId": "decline", "name": "Don't run", "kind": "reject_once"}]
        title = "Run this %s code?" % state["language"]
        try:
            choice = self.ask_permission(state["code"], title, options=options,
                                         raw_input={"command": source, "language": state["language"]})
        except (Cancelled, ConnectionError):
            self.tool_update(state["code"], status="failed")
            state["code"] = None
            raise KeyboardInterrupt
        except (RuntimeError, TimeoutError):
            choice = None
        if choice == "always":
            self.oi.auto_run = True
            self.mode = "auto"
            self._update({"sessionUpdate": "current_mode_update", "currentModeId": "auto"})
        if choice in ("run", "always"):
            return None
        self.tool_update(state["code"], status="failed", content=[self.text(fenced(state["language"], source)),
                                                                   self.text("Not run.")])
        state["code"] = None
        return "declined"

    def show_output(self, state, force=False):
        if force or time.monotonic() - state["shown"] > 0.25:
            state["shown"] = time.monotonic()
            self.tool_update(state["code"], content=[self.text(tail(state["output"]))])

    def finish_code(self, state, status):
        if state["code"] is None:
            return
        self.tool_update(state["code"], status=status, content=[self.text(tail(state["output"]) or "(no output)")])
        state.update(code=None, started=False, output="", running=None)

    def magic(self, command):
        """One of Open Interpreter's % commands; what it prints is the notice."""
        from interpreter.terminal_interface.magic_commands import handle_magic_command
        printed = io.StringIO()
        with contextlib.redirect_stdout(printed):
            handle_magic_command(self.oi, command)
        text = printed.getvalue().strip()
        if text:
            self.notice(text)
        if command.split(" ")[0] == "%auto_run":
            mode = "auto" if self.oi.auto_run else "ask"
            if mode != self.mode:
                self.mode = mode
                self._update({"sessionUpdate": "current_mode_update", "currentModeId": mode})

    def report_usage(self):
        """The conversation's size in tokens, counted with Open Interpreter's own tokenizer helper."""
        oi = self.oi
        try:
            from interpreter.terminal_interface.utils.count_tokens import count_tokens
            texts = [oi.system_message] + [m.get("content") for m in oi.messages if isinstance(m.get("content"), str)]
            printed = io.StringIO()
            with contextlib.redirect_stdout(printed):
                tokens = sum(count_tokens(text, model="gpt-4") for text in texts if text)
        except Exception:
            return
        if tokens:
            self.usage(context_tokens=int(tokens), context_window=int(oi.llm.context_window or self.args.context_window))

    # Models, modes, cancel.

    def set_model(self, model):
        self.model = model
        self.pending_model = model
        if not self.turn_open:
            self.main.submit(self.apply_pending)

    def apply_pending(self):
        model, self.pending_model = self.pending_model, None
        if model and self.oi is not None:
            self.oi.llm.model = "openai/" + model

    def set_mode(self, mode):
        if mode not in ("ask", "auto"):
            raise ValueError("Open Interpreter has no %s mode." % mode)
        self.mode = mode
        if self.oi is not None:
            self.oi.auto_run = mode == "auto"

    def cancelled(self):
        oi = self.oi
        if oi is None:
            return
        oi.stop_event.set()
        self.stop_code()
        job = self.turn_job
        if job is not None and not job.done.is_set():
            threading.Thread(target=self._interrupt_later, args=(job,), daemon=True).start()

    def _interrupt_later(self, job):
        # The same turn still busy after the grace period (the model has sent nothing yet, or a
        # command ignores the stop): interrupt it, as Ctrl+C does.
        if not job.done.wait(GRACE):
            self.main.interrupt(only=job)

    def stop_code(self):
        """Interrupts the command a shell-like language is running (its process's children)."""
        try:
            languages = list(self.oi.computer.terminal._active_languages.values())
        except Exception:
            return
        for language in languages:
            process = getattr(language, "process", None)
            if process is not None and process.poll() is None:
                support.interrupt_tree(process.pid)

    def closing(self):
        self.cancelled()

    def change_tool(self, tool_id, title=None, raw_input=None, content=None, status=None):
        """A tool call update that also carries the input (rawInput), once the code is complete."""
        update = {"sessionUpdate": "tool_call_update", "toolCallId": tool_id}
        for key, value in (("title", title), ("rawInput", raw_input), ("content", content), ("status", status)):
            if value is not None:
                update[key] = value
        self._update(update)

    def next_id(self):
        return "oi-code-%d" % next(self.ids)


def fenced(language, source):
    return "```%s\n%s\n```" % (language or "", source.rstrip("\n"))


def tail(text):
    return text[-OUTPUT_LIMIT:]


def stop_on_exit(bridge):
    def stop():
        oi = bridge.oi
        if oi is not None:
            try:
                oi.computer.terminate()
            except Exception:
                traceback.print_exc()
    support.on_exit(stop)


def main(argv=None):
    args = support.arguments(sys.argv[1:] if argv is None else argv, "Open Interpreter over ACP for the Yougori harness.")
    stdin = support.prepare()
    engine = support.MainThread()
    bridge = InterpreterBridge(args, stdin, engine)
    stop_on_exit(bridge)
    support.serve(bridge, engine)


if __name__ == "__main__":
    main()
