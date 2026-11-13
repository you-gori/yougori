"""Aider (aider-chat 0.86.2) behind the Yougori screen, over ACP.

Aider runs in this process the way its own terminal client sets it up: aider.main.main() with the
arguments configure() gives it (its configuration file and the relay model) and return_coder=True,
with an InputOutput of ours. Through that InputOutput its replies stream as messages (reasoning as
thoughts), its confirmations ask the person as permission requests, its tool output, warnings and
errors become notices, and every file it writes is an edit with its diff. Shell commands it
suggests run, once allowed, in a process group of their own and show as terminal tool calls. Its
chat modes (code, ask, architect, context) are the session's modes and its slash commands the
available commands; this inference's models switch in place. The work runs on the main thread, so
a cancel interrupts it the way Ctrl+C does in aider's own terminal.
"""
import functools
import itertools
import os
import re
import signal
import subprocess
import sys
import threading
import time
import traceback

_HERE = os.path.dirname(os.path.abspath(__file__))
if __package__ in (None, ""):
    # Run as a script: the folder holding `bridges` goes last, and this folder goes, so nothing of
    # ours shadows aider's own modules.
    sys.path[:] = [p for p in sys.path if os.path.abspath(p or os.curdir) != _HERE]
    sys.path.append(os.path.dirname(_HERE))

from bridges import support_acp as support  # noqa: E402
from bridges.acp import Cancelled  # noqa: E402

MODES = ("code", "ask", "architect", "context")
# Commands the screen does instead (models, input, exit) or that need what the VM has not
# (a clipboard, a microphone, an editor, a browser, package downloads for /help questions).
HIDDEN = {"exit", "quit", "model", "editor-model", "weak-model", "models", "voice", "paste", "copy", "copy-context",
          "editor", "edit", "multiline-mode", "report", "help"}
REFUSED = {"/model": "Choose another model with the screen's model switcher: it lists this inference's models.",
           "/editor-model": "Aider uses the model chosen in the screen for every role.",
           "/weak-model": "Aider uses the model chosen in the screen for every role.",
           "/editor": "Type the message in the Yougori screen: it is the editor here.",
           "/edit": "Type the message in the Yougori screen: it is the editor here."}
HINTS = {"add": "files", "drop": "files", "read-only": "files", "lint": "files", "ask": "question",
         "code": "request", "architect": "request", "context": "request", "run": "shell command",
         "test": "test command", "git": "git arguments", "web": "URL", "commit": "message", "load": "file",
         "save": "file", "chat-mode": "code, ask, architect or context", "think-tokens": "token budget",
         "reasoning-effort": "level"}
USAGE_LINE = re.compile(r"^Tokens: .+ sent.* received\.")
KILL_HINT = "^C again to exit"
OUTPUT_LIMIT = 64 * 1024


def version():
    try:
        from importlib.metadata import version as installed
        return installed("aider-chat")
    except Exception:
        return "0.86.2"


class TagSplitter:
    """Splits streamed text into reasoning and reply where the model writes its reasoning inline
    between <tag> and </tag> (aider's reasoning_tag model setting)."""

    def __init__(self, tag):
        self.open, self.close = ("<%s>" % tag, "</%s>" % tag) if tag else (None, None)
        self.inside = False
        self.pending = ""

    def feed(self, text):
        if not self.open:
            return [("message", text)] if text else []
        out = []
        text = self.pending + text
        self.pending = ""
        while text:
            marker = self.close if self.inside else self.open
            at = text.find(marker)
            if at >= 0:
                if at:
                    out.append(("thought" if self.inside else "message", text[:at]))
                text = text[at + len(marker):]
                self.inside = not self.inside
                continue
            # Keep a tail that could be the start of the marker for the next chunk.
            keep = 0
            for size in range(min(len(marker) - 1, len(text)), 0, -1):
                if marker.startswith(text[-size:]):
                    keep = size
                    break
            body, self.pending = (text[:-keep], text[-keep:]) if keep else (text, "")
            if body:
                out.append(("thought" if self.inside else "message", body))
            break
        return out

    def flush(self):
        pending, self.pending = self.pending, ""
        return [("thought" if self.inside else "message", pending)] if pending else []


def deltas(chunk, splitter):
    """(kind, text) pieces of one streamed completion chunk."""
    choices = getattr(chunk, "choices", None) or []
    if not choices:
        return []
    delta = getattr(choices[0], "delta", None)
    if delta is None:
        return []
    out = []
    reasoning = getattr(delta, "reasoning_content", None) or getattr(delta, "reasoning", None)
    if isinstance(reasoning, str) and reasoning:
        out.append(("thought", reasoning))
    content = getattr(delta, "content", None)
    if isinstance(content, str) and content:
        out.extend(splitter.feed(content))
    return out


class ObservedStream:
    """A completion stream as aider reads it, observed on the way: its reasoning and reply reach
    the screen chunk by chunk, and its token counts the status line when it ends."""

    def __init__(self, completion, bridge, model, messages):
        self._completion, self._bridge, self._model, self._messages = completion, bridge, model, messages

    def __getattr__(self, name):
        return getattr(self._completion, name)

    def __iter__(self):
        splitter = TagSplitter(getattr(self._model, "reasoning_tag", None))
        reply, usage = [], None
        self._bridge.stream_started()
        try:
            for chunk in self._completion:
                usage = getattr(chunk, "usage", None) or usage
                for kind, text in deltas(chunk, splitter):
                    self._bridge.stream_piece(kind, text)
                    reply.append(text)
                yield chunk
            for kind, text in splitter.flush():
                self._bridge.stream_piece(kind, text)
        finally:
            self._bridge.stream_ended(self._model, self._messages, "".join(reply), usage)


class QuietStdout:
    """sys.stdout for aider: what it prints goes to the log (stderr), except the reply it echoes
    while streaming, which the screen already shows."""

    def __init__(self, target, bridge):
        self._target, self._bridge = target, bridge

    def write(self, text):
        if self._bridge.streaming:
            return len(text)
        return self._target.write(text)

    def flush(self):
        self._target.flush()

    def __getattr__(self, name):
        return getattr(self._target, name)


def make_io(base, bridge):
    """aider's InputOutput with the screen behind it."""

    class BridgeIO(base):
        def __init__(self, pretty=True, yes=None, *args, **kwargs):
            # Plain output and no prompt_toolkit input: nothing here reads a terminal. `yes` is
            # dropped: return_coder would answer every confirmation with yes; the person answers.
            kwargs["fancy_input"] = False
            super().__init__(False, None, *args, **kwargs)
            self.yes = None

        # Output.

        def tool_output(self, *messages, log_only=False, bold=False):
            super().tool_output(*messages, log_only=True, bold=bold)
            if log_only:
                return
            bridge.note(" ".join(str(m) for m in messages))

        def tool_warning(self, message="", strip=True):
            self._record(message, strip)
            text = str(message).strip()
            if text and KILL_HINT not in text:
                bridge.warn(text, "warn")

        def tool_error(self, message="", strip=True):
            self.num_error_outputs += 1
            self._record(message, strip)
            text = str(message).strip()
            if text:
                bridge.warn(text, "error")

        def _record(self, message, strip):
            text = str(message)
            if not text.strip():
                return
            for line in text.splitlines() or [text]:
                self.append_chat_history(line, linebreak=True, blockquote=True, strip=strip)

        def assistant_output(self, message, pretty=None):
            # A reply that did not stream (a model without streaming).
            if not message:
                return self.tool_warning("The model sent an empty reply.")
            bridge.whole_reply(str(message))

        def print(self, message=""):
            bridge.note(str(message))

        def rule(self):
            pass

        def display_user_input(self, inp):
            pass

        def ring_bell(self):
            self.bell_on_next_input = False

        def offer_url(self, url, prompt="Open URL for more info?", allow_never=True):
            bridge.note(url)
            return False

        def get_input(self, *args, **kwargs):
            raise EOFError

        def toggle_multiline_mode(self):
            pass

        # Files: every write is an edit with its diff.

        def write_text(self, filename, content, max_retries=5, initial_delay=0.1):
            path = os.path.abspath(str(filename))
            old = support.read_text(path) if os.path.exists(path) else None
            super().write_text(filename, content, max_retries, initial_delay)
            bridge.edited(path, old, content, applied=not self.dry_run)

        # Asking the person.

        def confirm_ask(self, question, default="y", subject=None, explicit_yes_required=False, group=None,
                        allow_never=False):
            self.num_user_asks += 1
            question_id = (question, subject)
            if question_id in self.never_prompts:
                return False
            if group and not group.show_group:
                group = None
            if group:
                allow_never = True
            if group and group.preference:
                is_yes = group.preference == "all" and not explicit_yes_required
                self.append_chat_history("%s %s" % (question.strip(), group.preference), linebreak=True,
                                         blockquote=True)
                return is_yes
            answer = bridge.confirm(question, subject, explicit_yes_required, group is not None, allow_never)
            self.append_chat_history("%s %s" % (question.strip(), answer), linebreak=True, blockquote=True)
            if answer == "dont":
                self.never_prompts.add(question_id)
                return False
            if group:
                if answer == "all" and not explicit_yes_required:
                    group.preference = "all"
                elif answer == "skip":
                    group.preference = "skip"
            return answer in ("yes", "all") if not explicit_yes_required else answer == "yes"

        def prompt_ask(self, question, default="", subject=None):
            self.num_user_asks += 1
            if subject:
                bridge.note(str(subject))
            answer = bridge.ask(question, default)
            self.append_chat_history("%s %s" % (question.strip(), answer.strip()), linebreak=True, blockquote=True)
            return answer

    return BridgeIO


class AiderBridge(support.QueuedBridge):
    def __init__(self, args, stdin, main, commands=None, **options):
        super().__init__("Aider", version(), stdin, title="Aider", models=args.models, model=args.model,
                         modes=[{"id": m, "name": m.capitalize()} for m in MODES], mode="code", **options)
        self.args, self.main = args, main
        self.coder = self.io = self.startup = None
        self.pending_model = self.pending_mode = None
        self.turn_open = self.streaming = False
        self.lock = threading.RLock()
        self.notes = []
        self.ids = itertools.count(1)
        self.running = {}
        self.created = set()
        self.shell = None
        self.spoke = False
        self.commands_class = commands
        self.turn_job = None

    # The session.

    def describe_modes(self, commands_class):
        """Each mode's description is aider's own help for its command."""
        for mode in self.modes:
            method = getattr(commands_class, "cmd_" + mode["id"], None)
            doc = support.first_line(getattr(method, "__doc__", "") or "")
            if doc:
                mode["description"] = doc.split(". ")[0].rstrip(".") + "."

    def command_list(self):
        found = []
        cls = self.commands_class
        for attr in sorted(dir(cls)):
            if not attr.startswith("cmd_"):
                continue
            name = attr[4:].replace("_", "-")
            if name in HIDDEN:
                continue
            doc = support.first_line(getattr(getattr(cls, attr), "__doc__", "") or "")
            entry = {"name": name, "description": doc}
            if HINTS.get(name):
                entry["hint"] = HINTS[name]
            found.append(entry)
        return found

    def new_session(self, cwd, mcp_servers):
        if os.path.isdir(cwd):
            os.chdir(cwd)
        if self.commands_class is not None:
            self.commands(self.command_list())
        if self.startup is None:
            self.startup = self.main.submit(self._start)

    def _start(self):
        """Aider's own start-up (on the main thread): its questions come as permission requests."""
        try:
            import aider.main as aider_main
            from aider.coders import Coder
            tags_cache_home()
            aider_main.InputOutput = make_io(aider_main.InputOutput, self)
            hook = sys.excepthook
            try:
                coder = aider_main.main(list(self.args.engine), return_coder=True)
            finally:
                sys.excepthook = hook
            if not isinstance(coder, Coder):
                self.flush_notes()
                support.exit_now(self, 1, "Aider did not start (exit %r); its messages above say why." % (coder,))
            install_hooks(self)
            with self.lock:
                self.coder, self.io = coder, coder.io
            coder.show_announcements()
            self.flush_notes()
            self.report_mode()
            self.apply_pending()
            return coder
        except KeyboardInterrupt:
            support.exit_now(self, 1, "Aider's start was interrupted.")
        except SystemExit as stop:
            self.flush_notes()
            support.exit_now(self, stop.code if isinstance(stop.code, int) and stop.code else 1, "Aider stopped while starting.")
        except Exception as error:
            traceback.print_exc()
            self.flush_notes()
            support.exit_now(self, 1, "Aider could not start: %s" % (error,))

    def prompt(self, text, blocks):
        while not self.startup.done.wait(0.2):
            if self.cancel_event.is_set():
                return "cancelled"
        word = text.strip().split()[0] if text.strip() else ""
        if word in REFUSED:
            self.notice(REFUSED[word], "warn")
            return "end_turn"
        if word in ("/exit", "/quit"):
            self.leave()
            return "end_turn"
        self.turn_job = job = self.main.submit(self._run_turn, text)
        if self.cancel_event.is_set():
            # Cancelled before this job was the turn's (cancelled() saw the last one).
            self.main.interrupt(only=job)
        job.done.wait()
        try:
            return job.outcome()
        except KeyboardInterrupt:
            return "cancelled"

    def _run_turn(self, text):
        if self.cancel_event.is_set():
            # Cancelled before its turn on the main thread came: nothing of it runs.
            return "cancelled"
        from aider.commands import SwitchCoder
        self.apply_pending()
        coder = self.coder
        # Aider exits on a second Ctrl+C within two seconds; a cancel from the screen never is one.
        coder.last_keyboard_interrupt = None
        self.turn_open, self.spoke = True, False
        try:
            try:
                coder.run(with_message=text)
            except SwitchCoder as switch:
                self.switch(switch)
            return "cancelled" if self.cancel_event.is_set() else "end_turn"
        except KeyboardInterrupt:
            return "cancelled"
        except SystemExit:
            self.leave()
            return "end_turn"
        finally:
            self.turn_open = self.streaming = False
            if self.coder is not None:
                self.coder.last_keyboard_interrupt = None
            self.shell = None
            self.flush_notes()
            self.report_mode()

    def leave(self):
        """Aider was asked to exit: the turn ends, then the bridge does."""
        threading.Timer(0.3, self.main.stop).start()

    def switch(self, switch):
        """aider's SwitchCoder, handled as its main loop does."""
        from aider.coders import Coder
        kwargs = dict(io=self.io, from_coder=self.coder)
        kwargs.update(switch.kwargs)
        show = kwargs.pop("show_announcements", True)
        with self.lock:
            self.coder = Coder.create(**kwargs)
        if show is not False:
            self.coder.show_announcements()

    def report_mode(self):
        coder = self.coder
        if coder is None:
            return
        mode = mode_of(coder)
        if mode and mode != self.mode and self.pending_mode is None:
            self.mode = mode
            self._update({"sessionUpdate": "current_mode_update", "currentModeId": mode})

    def set_model(self, model):
        self.model = model
        self.pending_model = model
        if not self.turn_open:
            self.main.submit(self.apply_pending)

    def set_mode(self, mode):
        if mode not in MODES:
            raise ValueError("Aider has no %s mode." % mode)
        self.mode = mode
        self.pending_mode = mode
        if not self.turn_open:
            self.main.submit(self.apply_pending)

    def apply_pending(self):
        """A model or mode chosen in the screen, applied as aider's /model and /chat-mode do."""
        try:
            self._apply_pending()
        except KeyboardInterrupt:
            raise
        except Exception as error:
            traceback.print_exc()
            self.flush_notes()
            self.notice("Aider could not switch: %s" % (error,), "error")

    def _apply_pending(self):
        from aider import models
        from aider.coders import Coder
        if self.coder is None:
            return
        model, self.pending_model = self.pending_model, None
        if model and self.coder.main_model.name != "openai/" + model:
            coder = self.coder
            name = "openai/" + model
            main_model = models.Model(name, weak_model=name, editor_model=name)
            edit_format = coder.edit_format
            if edit_format == coder.main_model.edit_format:
                edit_format = main_model.edit_format
            with self.lock:
                self.coder = Coder.create(io=self.io, from_coder=coder, main_model=main_model, edit_format=edit_format)
        mode, self.pending_mode = self.pending_mode, None
        if mode and mode_of(self.coder) != mode:
            coder = self.coder
            if mode == "code":
                edit_format, summarize = coder.main_model.edit_format, False
            elif mode == "ask":
                edit_format, summarize = "ask", False
            else:
                edit_format, summarize = mode, True
            with self.lock:
                self.coder = Coder.create(io=self.io, from_coder=coder, edit_format=edit_format,
                                          summarize_from_coder=summarize)
            self.coder.show_announcements()
            self.flush_notes()

    def cancelled(self):
        # Only the turn's own job: aider's start-up (which a first prompt may still be waiting for)
        # goes on, and that wait ends by itself on the cancel.
        job = self.turn_job
        if job is not None:
            self.main.interrupt(only=job)
        self.stop_commands()

    def closing(self):
        # The client is gone: whatever aider is doing stops, its start-up included.
        self.main.interrupt()
        self.stop_commands()

    # Reporting.

    def next_id(self, kind):
        return "aider-%s-%d" % (kind, next(self.ids))

    def note(self, text):
        with self.lock:
            text = text.rstrip()
            if USAGE_LINE.match(text.strip()):
                return
            if text.startswith("Applied edit to ") or text.startswith("Did not apply edit to "):
                return
            if not text.strip():
                if self.notes and self.notes[-1]:
                    self.notes.append("")
                return
            self.notes.append(text)

    def flush_notes(self):
        with self.lock:
            notes, self.notes = self.notes, []
        while notes and not notes[-1]:
            notes.pop()
        if notes:
            self.notice("\n".join(notes))

    def warn(self, text, level):
        self.flush_notes()
        self.notice(text, level)

    def stream_started(self):
        self.flush_notes()
        if self.spoke:
            # A second reply in one turn (the architect's editor, a reflection): keep them apart.
            self.message("\n\n")
        self.streaming = True

    def stream_piece(self, kind, text):
        if kind == "thought":
            self.thought(text)
        else:
            self.message(text)
            self.spoke = True

    def stream_ended(self, model, messages, reply, usage):
        self.streaming = False
        sent = getattr(usage, "prompt_tokens", None)
        received = getattr(usage, "completion_tokens", None)
        try:
            if not isinstance(sent, int):
                sent = model.token_count(messages)
            if not isinstance(received, int):
                received = model.token_count(reply) if reply else 0
        except Exception:
            return
        window = (getattr(model, "info", None) or {}).get("max_input_tokens") or self.args.context_window
        used = int(sent or 0) + int(received or 0)
        self.usage(context_tokens=used, context_window=int(window), input_tokens=int(sent or 0),
                   output_tokens=int(received or 0))

    def whole_reply(self, text):
        self.flush_notes()
        from aider.reasoning_tags import REASONING_END, REASONING_START
        if REASONING_START in text and REASONING_END in text:
            before, rest = text.split(REASONING_START, 1)
            thought, after = rest.split(REASONING_END, 1)
            if thought.strip():
                self.thought(thought.strip())
            text = (before + after).strip()
        if text:
            if self.spoke:
                self.message("\n\n")
            self.message(text)
            self.spoke = True

    def edited(self, path, old, new, applied=True):
        self.flush_notes()
        root = getattr(self.coder, "root", None) or os.getcwd()
        relative = os.path.relpath(path, root) if path.startswith(os.path.abspath(root)) else path
        tool = self.next_id("edit")
        if path in self.created and not old:
            # Aider makes the file empty when it is allowed to create it, just before writing it.
            old = None
        self.created.discard(path)
        title = ("Edit %s" if old is not None else "Create %s") % relative
        if not applied:
            title += " (dry run: not written)"
        self.tool_call(tool, title, kind="edit", status="completed" if applied else "failed",
                       raw_input={"path": path}, content=[self.diff(path, old, new)], locations=[{"path": path}])

    def confirm(self, question, subject, explicit_yes_required, grouped, allow_never):
        """One of aider's confirmations, asked through the screen: yes, all, no, skip or dont."""
        self.flush_notes()
        subject = (subject or "").strip()
        root = getattr(self.coder, "root", None) or os.getcwd()
        lines = [line for line in subject.splitlines() if line.strip() and not line.strip().startswith("#")]
        kind, raw, path = "other", None, None
        if question.startswith("Run shell command"):
            kind, raw = "execute", {"command": subject}
        elif question.startswith(("Create new file", "Allow edits to file", "Add file to the chat")) and subject:
            kind = "read" if question.startswith("Add file") else "edit"
            path = os.path.join(root, subject)
            raw = {"path": path}
        elif question.startswith("Add URL to the chat") and subject:
            kind, raw = "fetch", {"url": subject}
        title = question.strip()
        if subject:
            title = "%s %s" % (title, subject if "\n" not in subject else "%s (+%d more)" % (lines[0] if lines else "",
                                                                                     max(len(lines) - 1, 0)))
        tool = self.next_id("ask")
        self.tool_call(tool, title, kind=kind, status="pending", raw_input=raw, locations=[{"path": path}] if path else None)
        options = [{"optionId": "yes", "name": "Yes", "kind": "allow_once"}]
        if grouped and not explicit_yes_required:
            options.append({"optionId": "all", "name": "Yes to all", "kind": "allow_always"})
        options.append({"optionId": "no", "name": "No", "kind": "reject_once"})
        if grouped:
            options.append({"optionId": "skip", "name": "Skip all", "kind": "reject_always"})
        if allow_never:
            options.append({"optionId": "dont", "name": "No, and don't ask again", "kind": "reject_always"})
        try:
            choice = self.ask_permission(tool, title, options=options, raw_input=raw)
        except Cancelled:
            self.tool_update(tool, status="failed")
            raise KeyboardInterrupt
        except ConnectionError:
            self.tool_update(tool, status="failed")
            raise KeyboardInterrupt
        except (RuntimeError, TimeoutError):
            choice = None
        answer = choice if choice in ("yes", "all", "no", "skip", "dont") else "no"
        allowed = answer in ("yes", "all")
        if allowed and path and question.startswith("Create new file"):
            self.created.add(os.path.abspath(path))
        if kind == "execute" and allowed:
            self.shell = {"id": tool, "commands": [line.strip() for line in lines]}
            self.tool_update(tool, status="in_progress" if len(lines) == 1 else "completed")
        else:
            self.tool_update(tool, status="completed" if allowed else "failed")
        return answer

    def ask(self, question, default):
        self.flush_notes()
        try:
            answer = self.question(question, allow_text=True)
        except Cancelled:
            raise KeyboardInterrupt
        except ConnectionError:
            raise KeyboardInterrupt
        except (RuntimeError, TimeoutError):
            answer = None
        if not answer:
            return default
        return str(answer[0])

    # Shell commands aider runs.

    def run_command(self, command, verbose=False, error_print=None, cwd=None):
        """aider.run_cmd for the bridge: the same shell and merged output, in a process group of its
        own (stopped with the turn), shown as a terminal tool call."""
        with self.lock:
            # Aider announces the command just before; the tool call shows it.
            if self.notes and self.notes[-1].strip() == "Running " + command.strip():
                self.notes.pop()
        self.flush_notes()
        shell = self.shell
        if shell and len(shell["commands"]) == 1 and shell["commands"][0] == command.strip():
            tool = shell["id"]
            self.shell = None
            self.tool_update(tool, status="in_progress")
        else:
            tool = self.next_id("run")
            self.tool_call(tool, command, kind="execute", status="in_progress", raw_input={"command": command})
        try:
            process = subprocess.Popen(command, shell=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, cwd=cwd, start_new_session=True)
        except OSError as error:
            message = "Could not run %s: %s" % (command, error)
            (error_print or print)(message)
            self.tool_update(tool, status="failed", content=[self.text(message)], raw_output={"exit_code": 1})
            return 1, message
        support.remember_group(process.pid)
        with self.lock:
            self.running[process.pid] = process
        output = bytearray()
        shown = 0.0
        try:
            while True:
                block = os.read(process.stdout.fileno(), 65536)
                if not block:
                    break
                output += block
                if time.monotonic() - shown > 0.3:
                    shown = time.monotonic()
                    self.tool_update(tool, content=[self.text(tail(output))])
            code = process.wait()
        except KeyboardInterrupt:
            support.stop_group(process)
            self.tool_update(tool, status="failed", content=[self.text(tail(output) + "\n^C")],
                             raw_output={"exit_code": process.returncode})
            raise
        finally:
            process.stdout.close()
            support.forget_group(process.pid)
            with self.lock:
                self.running.pop(process.pid, None)
        text = output.decode("utf-8", errors="replace")
        self.tool_update(tool, status="completed" if code == 0 else "failed", content=[self.text(tail(output))],
                         raw_output={"exit_code": code})
        return code, text

    def stop_commands(self):
        with self.lock:
            running = list(self.running.values())
        for process in running:
            support.signal_group(process.pid, signal.SIGINT)


def tail(output):
    data = bytes(output[-OUTPUT_LIMIT:])
    return data.decode("utf-8", errors="replace")


def mode_of(coder):
    edit_format = getattr(coder, "edit_format", None)
    if edit_format in ("ask", "architect", "context"):
        return edit_format
    if edit_format == "help":
        return None
    return "code"


def tags_cache_home():
    """Aider's repo map keeps its tags cache beside the project, where the person's review listed it,
    and Aider 0.86.2 has no option for that. With the folder the profile gives Aider's own files
    (SOLVER_AIDER_FILES) the cache goes there, as profiles.AIDER_START does for Aider's own client:
    RepoMap joins its folder to the project's, and an absolute folder wins the join."""
    files = os.environ.get("SOLVER_AIDER_FILES")
    if files:
        from aider.repomap import RepoMap
        RepoMap.TAGS_CACHE_DIR = os.path.join(files, os.path.basename(RepoMap.TAGS_CACHE_DIR))


def install_hooks(bridge):
    """Once: the model's streams are observed, and the shell commands aider runs go through the
    bridge (aider.run_cmd, as base_coder and commands imported it)."""
    import aider.coders.base_coder as base_coder
    import aider.commands as commands
    import aider.models as models
    if getattr(models.Model.send_completion, "_yougori", False):
        return
    original = models.Model.send_completion

    def send_completion(model, messages, functions, stream, temperature=None):
        hashed, completion = original(model, messages, functions, stream, temperature)
        if stream and bridge.turn_open:
            completion = ObservedStream(completion, bridge, model, messages)
        return hashed, completion

    send_completion._yougori = True
    models.Model.send_completion = send_completion
    runner = functools.partial(AiderBridge.run_command, bridge)
    base_coder.run_cmd = runner
    commands.run_cmd = runner


def main(argv=None):
    args = support.arguments(sys.argv[1:] if argv is None else argv, "Aider over ACP for the Yougori harness.")
    stdin = support.prepare()
    engine = support.MainThread()
    from aider.commands import Commands
    bridge = AiderBridge(args, stdin, engine, commands=Commands)
    bridge.describe_modes(Commands)
    sys.stdout = QuietStdout(sys.stdout, bridge)
    support.serve(bridge, engine)


if __name__ == "__main__":
    main()
