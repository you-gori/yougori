"""The agent side of the Agent Client Protocol (ACP, protocol version 1) for Yougori's bridges.

A bridge runs a coding harness that speaks no protocol of its own behind the Yougori harness's
screen: Aider, Open Interpreter, SWE-agent and Plandex, each in bridges/NAME_acp.py. The security
harnesses have no bridge: their own terminal clients run in the screen's terminal pane. A bridge
subclasses Bridge (or passes callables), and inside prompt() reports what the harness does:
message and thought chunks, tool calls and their updates, plans, and Yougori's own findings,
reports, progress and usage. It asks the person through ask_permission() and question(), which
wait for the answer.

JSON-RPC 2.0 over stdio, one message per line, standard library only. The protocol owns this
process's stdout: Bridge moves anything else the harness prints to stderr (the screen's log).
"""
import itertools
import json
import os
import signal
import sys
import threading
import traceback
import uuid

PROTOCOL_VERSION = 1
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

ALLOW_ONCE = {"optionId": "allow", "name": "Yes", "kind": "allow_once"}
ALLOW_ALWAYS = {"optionId": "always", "name": "Yes, and don't ask again", "kind": "allow_always"}
REJECT_ONCE = {"optionId": "reject", "name": "No", "kind": "reject_once"}
STOP_REASONS = ("end_turn", "max_tokens", "max_turn_requests", "refusal", "cancelled")
TOOL_KINDS = ("read", "edit", "delete", "move", "search", "execute", "think", "fetch", "switch_mode", "other")
SEVERITIES = ("critical", "high", "medium", "low", "info")


class Cancelled(Exception):
    """Raised by ask_permission() and question() once the turn is cancelled."""


def unblock_signals():
    """Lets the calling thread take SIGINT and SIGTERM again. A thread starts with the signal mask
    of the thread that started it, and a process with that of the thread that started it, which it
    keeps through exec and passes on to what it runs. A thread that starts commands must not hand on
    the mask of the protocol's threads (support_acp.quiet_signals): nothing could interrupt or stop
    those commands. POSIX; a no-op elsewhere."""
    if hasattr(signal, "pthread_sigmask"):
        signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGINT, signal.SIGTERM})


class Bridge:
    """Serves one ACP client on stdio. Override prompt() (and, if needed, new_session(),
    set_model(), set_mode() and cancelled()), then call run()."""

    def __init__(self, name, version, title=None, models=None, model=None, modes=None, mode=None,
                 stdin=None, stdout=None, claim_stdout=True):
        self.name, self.version, self.title = name, version, title or name
        self.models = list(models or [])
        self.model = model or (self.models[0] if self.models else None)
        self.modes = list(modes or [])
        self.mode = mode or (self.modes[0]["id"] if self.modes else None)
        if stdout is None:
            if claim_stdout:
                # The harness's own prints go to stderr; the protocol keeps the real stdout.
                protocol = os.dup(1)
                os.dup2(2, 1)
                sys.stdout = sys.stderr
                stdout = os.fdopen(protocol, "wb", buffering=0)
            else:
                stdout = sys.stdout.buffer
        self._in = stdin if stdin is not None else sys.stdin.buffer
        self._out = stdout
        self._write_lock = threading.Lock()
        self._ids = itertools.count(1)
        self._waiting = {}
        self._waiting_lock = threading.Lock()
        self.session = None
        self.cwd = None
        self.mcp_servers = []
        self._turn = None
        # A turn runs from its prompt until just before its answer goes out, not for as long as its
        # thread lives: a client may send the next prompt the moment it reads the answer.
        self._turn_running = False
        self._turn_lock = threading.Lock()
        self.cancel_event = threading.Event()

    # The harness's part.

    def new_session(self, cwd, mcp_servers):
        """A session starts in `cwd` with these MCP servers (ACP's shapes)."""

    def prompt(self, text, blocks):
        """Runs one turn for the person's `text` (all of `blocks` for images and resources).
        Returns a stop reason ("end_turn" by default); raise to end the turn with an error."""
        raise NotImplementedError

    def set_model(self, model):
        """The person chose another of this inference's models."""
        self.model = model

    def set_mode(self, mode):
        self.mode = mode

    def cancelled(self):
        """The person stopped the turn: end it soon (prompt() sees self.cancel_event set)."""

    # Reporting, from inside prompt().

    def message(self, text, parent=None):
        self._update(dict(sessionUpdate="agent_message_chunk", content={"type": "text", "text": text}), parent)

    def thought(self, text, parent=None):
        self._update(dict(sessionUpdate="agent_thought_chunk", content={"type": "text", "text": text}), parent)

    def tool_call(self, tool_id, title, kind="other", status="in_progress", raw_input=None, content=None,
                  locations=None, parent=None):
        update = {"sessionUpdate": "tool_call", "toolCallId": tool_id, "title": title,
                  "kind": kind if kind in TOOL_KINDS else "other", "status": status}
        if raw_input is not None:
            update["rawInput"] = raw_input
        if content:
            update["content"] = content
        if locations:
            update["locations"] = locations
        self._update(update, parent)

    def tool_update(self, tool_id, status=None, title=None, content=None, raw_output=None, locations=None):
        update = {"sessionUpdate": "tool_call_update", "toolCallId": tool_id}
        for key, value in (("status", status), ("title", title), ("content", content), ("rawOutput", raw_output),
                           ("locations", locations)):
            if value is not None:
                update[key] = value
        self._update(update)

    def plan(self, entries):
        """`entries`: [{"content", "status": pending|in_progress|completed, "priority": high|medium|low}]."""
        self._update({"sessionUpdate": "plan", "entries": [
            {"content": e["content"], "status": e.get("status", "pending"), "priority": e.get("priority", "medium")}
            for e in entries]})

    def commands(self, commands):
        """Slash commands the harness takes: [{"name", "description", "hint"?}]."""
        self._update({"sessionUpdate": "available_commands_update", "availableCommands": [
            dict({"name": c["name"], "description": c.get("description", "")},
                 **({"input": {"hint": c["hint"]}} if c.get("hint") else {})) for c in commands]})

    def context(self, used, size):
        """Tokens in the context window now, of its size."""
        self._update({"sessionUpdate": "usage_update", "used": int(used), "size": int(size)})

    def finding(self, finding_id, title, severity="info", target=None, description="", evidence=None, details=None):
        """A security finding (Yougori's _yougori/finding)."""
        value = {"id": finding_id, "title": title, "severity": severity if severity in SEVERITIES else "info"}
        for key, item in (("target", target), ("evidence", evidence), ("details", details)):
            if item is not None:
                value[key] = item
        if description:
            value["description"] = description
        self.notify("_yougori/finding", value)

    def report(self, title, path=None, summary=None):
        self.notify("_yougori/report", {k: v for k, v in (("title", title), ("path", path), ("summary", summary)) if v is not None})

    def progress(self, progress_id, label, done=None, total=None, unit=None, finished=False):
        value = {"id": progress_id, "label": label, "finished": bool(finished)}
        for key, item in (("done", done), ("total", total), ("unit", unit)):
            if item is not None:
                value[key] = item
        self.notify("_yougori/progress", value)

    def usage(self, context_tokens=None, context_window=None, input_tokens=None, output_tokens=None):
        self.notify("_yougori/usage", {k: v for k, v in (("context_tokens", context_tokens), ("context_window", context_window),
                    ("input_tokens", input_tokens), ("output_tokens", output_tokens)) if v is not None})

    def notice(self, text, level="info"):
        self.notify("_yougori/notice", {"text": text, "level": level})

    # Asking the person, from inside prompt(); both wait for the answer.

    def ask_permission(self, tool_id, title=None, options=(ALLOW_ONCE, ALLOW_ALWAYS, REJECT_ONCE), raw_input=None,
                       content=None):
        """The option id the person chose, or None when they dismissed it. Raises Cancelled once
        the turn is cancelled."""
        tool = {"toolCallId": tool_id}
        if title:
            tool["title"] = title
        if raw_input is not None:
            tool["rawInput"] = raw_input
        if content:
            tool["content"] = content
        result = self.request("session/request_permission", {"sessionId": self.session, "toolCall": tool, "options": list(options)})
        outcome = (result or {}).get("outcome") or {}
        if outcome.get("outcome") == "selected":
            return outcome.get("optionId")
        if self.cancel_event.is_set():
            raise Cancelled()
        return None

    def question(self, question, choices=(), multiple=False, allow_text=False):
        """The person's answer (a list of strings), or None when they dismissed it."""
        result = self.request("_yougori/question", {"question": question, "choices": list(choices), "multiple": bool(multiple),
                                                    "allow_text": bool(allow_text)})
        answer = (result or {}).get("answer")
        if answer is None and self.cancel_event.is_set():
            raise Cancelled()
        return answer

    # Content for tool calls.

    @staticmethod
    def text(text):
        return {"type": "content", "content": {"type": "text", "text": text}}

    @staticmethod
    def diff(path, old, new):
        """A file change; `old` None for a new file."""
        return {"type": "diff", "path": path, "oldText": old, "newText": new}

    # The connection.

    def send(self, value):
        line = (json.dumps(value, ensure_ascii=False) + "\n").encode("utf-8")
        with self._write_lock:
            self._out.write(line)
            self._out.flush()

    def notify(self, method, params):
        self.send({"jsonrpc": "2.0", "method": method, "params": params})

    def request(self, method, params, timeout=None):
        """Sends a request to the client and waits for its result (an error raises RuntimeError)."""
        request_id = "b%d" % next(self._ids)
        waiter = {"event": threading.Event(), "reply": None}
        with self._waiting_lock:
            self._waiting[request_id] = waiter
        try:
            self.send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
            if not waiter["event"].wait(timeout):
                raise TimeoutError("%s got no answer" % method)
        finally:
            with self._waiting_lock:
                self._waiting.pop(request_id, None)
        reply = waiter["reply"]
        if reply is None:
            raise ConnectionError("the client went away")
        if "error" in reply:
            raise RuntimeError(reply["error"].get("message", "the client refused %s" % method))
        return reply.get("result")

    def _update(self, update, parent=None):
        if parent:
            update["_meta"] = {"yougori": {"parent": parent}}
        self.notify("session/update", {"sessionId": self.session, "update": update})

    def _respond(self, request_id, result=None, error=None):
        reply = {"jsonrpc": "2.0", "id": request_id}
        if error is not None:
            reply["error"] = {"code": error[0], "message": error[1]}
        else:
            reply["result"] = result if result is not None else {}
        self.send(reply)

    def run(self):
        """Serves the client until it closes stdin; returns the exit code."""
        for raw in iter(self._in.readline, b""):
            raw = raw.strip()
            if not raw:
                continue
            try:
                message = json.loads(raw)
            except ValueError:
                self.send({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}})
                continue
            if not isinstance(message, dict):
                continue
            if "method" in message:
                self._dispatch(message)
            elif "id" in message:
                with self._waiting_lock:
                    waiter = self._waiting.get(message["id"])
                if waiter:
                    waiter["reply"] = message
                    waiter["event"].set()
        # The client is gone: wake anything still waiting, end a running turn.
        self.cancel_event.set()
        with self._waiting_lock:
            for waiter in self._waiting.values():
                waiter["event"].set()
        turn = self._turn
        if turn is not None:
            turn.join(timeout=10)
        return 0

    def _dispatch(self, message):
        method, params, request_id = message["method"], message.get("params") or {}, message.get("id")
        is_request = "id" in message
        try:
            if method == "initialize":
                result = {"protocolVersion": PROTOCOL_VERSION,
                          "agentCapabilities": {"loadSession": False,
                                                "promptCapabilities": {"image": False, "audio": False, "embeddedContext": True},
                                                "mcpCapabilities": {"http": False, "sse": False}},
                          "authMethods": [], "agentInfo": {"name": self.name, "title": self.title, "version": self.version}}
            elif method == "authenticate":
                result = {}
            elif method == "session/new":
                if not isinstance(params.get("cwd"), str):
                    return self._respond(request_id, error=(INVALID_PARAMS, "session/new needs a cwd."))
                self.session = "%s-%s" % (self.name.lower().replace(" ", "-"), uuid.uuid4().hex[:12])
                self.cwd, self.mcp_servers = params["cwd"], params.get("mcpServers") or []
                self.new_session(self.cwd, self.mcp_servers)
                result = {"sessionId": self.session}
                if self.models:
                    result["models"] = {"currentModelId": self.model,
                                        "availableModels": [{"modelId": m, "name": m} for m in self.models]}
                if self.modes:
                    result["modes"] = {"currentModeId": self.mode, "availableModes": self.modes}
            elif method == "session/prompt":
                return self._start_prompt(request_id, params)
            elif method == "session/cancel":
                self.cancel_event.set()
                self.cancelled()
                return
            elif method == "session/set_model":
                self.set_model(params.get("modelId"))
                result = {}
            elif method == "session/set_mode":
                self.set_mode(params.get("modeId"))
                self._update({"sessionUpdate": "current_mode_update", "currentModeId": self.mode})
                result = {}
            else:
                if is_request:
                    self._respond(request_id, error=(METHOD_NOT_FOUND, "Method not found: " + method))
                return
        except Exception as error:  # A harness hook failed: the client hears why.
            traceback.print_exc(file=sys.stderr)
            if is_request:
                self._respond(request_id, error=(INTERNAL_ERROR, str(error) or type(error).__name__))
            return
        if is_request:
            self._respond(request_id, result)

    def _start_prompt(self, request_id, params):
        with self._turn_lock:
            if self._turn_running:
                return self._respond(request_id, error=(INVALID_PARAMS, "A turn is already running."))
            self._turn_running = True
            self.cancel_event.clear()
            blocks = params.get("prompt") or []
            text = "".join(b.get("text", "") for b in blocks if isinstance(b, dict) and b.get("type") == "text")
            self._turn = threading.Thread(target=self._prompt, args=(request_id, text, blocks), daemon=True)
            try:
                self._turn.start()
            except BaseException:
                self._turn_running = False
                raise

    def _prompt(self, request_id, text, blocks):
        """One turn on its own thread. Whatever ends it (a stop reason, an error, an exit or an
        interrupt the harness let through), the prompt gets exactly one answer."""
        result = error = None
        try:
            unblock_signals()
            reason = self.prompt(text, blocks) or "end_turn"
            if self.cancel_event.is_set():
                reason = "cancelled"
            result = {"stopReason": reason if reason in STOP_REASONS else "end_turn"}
        except Cancelled:
            result = {"stopReason": "cancelled"}
        except BaseException as failure:
            if self.cancel_event.is_set():
                result = {"stopReason": "cancelled"}
            else:
                traceback.print_exc(file=sys.stderr)
                error = (INTERNAL_ERROR, self._describe(failure))
        with self._turn_lock:
            self._turn_running = False
        self._respond(request_id, result, error)

    def _describe(self, failure):
        """What the client hears about a turn that ended in an exception."""
        if isinstance(failure, SystemExit):
            if failure.code is None or isinstance(failure.code, int):
                return "%s exited during the turn (exit code %d)." % (self.title, failure.code or 0)
            return "%s exited during the turn: %s" % (self.title, failure.code)
        if isinstance(failure, KeyboardInterrupt):
            return "%s was interrupted." % self.title
        return str(failure) or type(failure).__name__
