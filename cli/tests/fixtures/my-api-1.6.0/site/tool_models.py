"""Read coding-tool model pickers without starting a conversation or inference.

These are client catalogues, not models exported by the shared website API.
Only normalized model metadata leaves this sandbox; account details never do.
"""
import json
import math
import os
import queue
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from transport import Failure

LIMIT = 2 * 1024 * 1024


class Process:
    """Bound both output and total runtime, including JSONL control sessions."""
    def __init__(self, args, subscription=False, timeout=25):
        env = os.environ.copy()
        env["PATH"] = os.pathsep.join((os.path.expanduser("~/.local/share/yougori/bin"),
                                      os.path.expanduser("~/.local/bin"), env.get("PATH", "")))
        env["NO_COLOR"] = "1"
        if subscription:
            for key in ("OPENAI_API_KEY", "OPENAI_BASE_URL"):
                env.pop(key, None)
        executable = shutil.which(args[0], path=env["PATH"])
        if not executable:
            raise Failure(503, "Tool is still being installed; discovery will retry automatically.")
        self.folder = tempfile.TemporaryDirectory(prefix="yougori-models-")
        self.deadline = time.monotonic() + timeout
        self.lines = queue.Queue()
        try:
            self.child = subprocess.Popen([executable, *args[1:]], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                          stderr=subprocess.DEVNULL, cwd=self.folder.name, env=env,
                                          start_new_session=os.name != "nt")
        except OSError:
            self.folder.cleanup()
            raise Failure(503, "Could not start model discovery; it will retry automatically.") from None
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self):
        size = 0
        try:
            while True:
                line = self.child.stdout.readline(LIMIT + 1)
                if not line:
                    break
                size += len(line)
                if size > LIMIT:
                    self.lines.put(Failure(502, "Tool model catalogue was too large."))
                    return
                self.lines.put(line)
        finally:
            self.lines.put(None)

    def line(self):
        try:
            line = self.lines.get(timeout=max(0, self.deadline - time.monotonic()))
        except queue.Empty:
            raise Failure(503, "Tool model discovery timed out; it will retry automatically.") from None
        if isinstance(line, Exception):
            raise line
        return line

    def send(self, message):
        try:
            self.child.stdin.write(json.dumps(message).encode() + b"\n")
            self.child.stdin.flush()
        except (OSError, ValueError):
            raise Failure(503, "Tool model discovery disconnected.") from None

    def receive(self, accepts):
        while True:
            line = self.line()
            if line is None:
                raise Failure(503, "Tool model discovery ended before returning its catalogue.")
            try:
                value = json.loads(line)
            except (ValueError, UnicodeError):
                continue
            if isinstance(value, dict) and accepts(value):
                return value

    def output(self, allowed_codes=(0,)):
        self.child.stdin.close()
        lines = []
        while True:
            line = self.line()
            if line is None:
                break
            lines.append(line)
        try:
            code = self.child.wait(timeout=max(.01, self.deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            raise Failure(503, "Tool model discovery timed out.") from None
        if code not in allowed_codes:
            raise Failure(503, "Tool could not list models. Check its sign-in; discovery will retry.")
        return b"".join(lines).decode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        try:
            if os.name != "nt":
                os.killpg(self.child.pid, signal.SIGKILL)
            elif self.child.poll() is None:
                self.child.kill()
        except ProcessLookupError:
            pass
        self.child.wait()
        self.reader.join(timeout=2)
        self.child.stdout.close()
        self.child.stdin.close()
        self.folder.cleanup()


def command(args, subscription=False):
    with Process(args, subscription) as process:
        return process.output()


def entry(tool, identifier, label=None, free=False):
    if not isinstance(identifier, str) or not identifier.strip() or len(identifier) > 200:
        raise Failure(502, "Tool returned an invalid model identifier.")
    return {"id": tool + "/" + identifier, "tool": tool, "model": identifier,
            "label": label[:200] if isinstance(label, str) else identifier, "free": free,
            "access": "coding-tool"}


def codex_models():
    with Process(["codex", "app-server"], subscription=True) as process:
        def rpc(identifier, method, params):
            process.send({"id": identifier, "method": method, "params": params})
            reply = process.receive(lambda row: row.get("id") == identifier)
            if "error" in reply or not isinstance(reply.get("result"), dict):
                raise Failure(503, "Codex could not read its model catalogue. Check its sign-in.")
            return reply["result"]

        rpc(0, "initialize", {"clientInfo": {"name": "yougori_hub", "version": "1.5.0"}})
        process.send({"method": "initialized", "params": {}})
        account = rpc(1, "account/read", {"refreshToken": False}).get("account")
        if not isinstance(account, dict) or not str(account.get("type", "")).lower().startswith("chatgpt"):
            raise Failure(401, "Finish signing in to Codex; models will appear automatically.")
        models, cursor, seen = [], None, set()
        for page in range(20):
            result = rpc(page + 2, "model/list", {"limit": 100, "includeHidden": False, "cursor": cursor})
            if not isinstance(result.get("data"), list):
                raise Failure(502, "Codex returned an invalid model catalogue.")
            for row in result["data"]:
                if isinstance(row, dict) and not row.get("hidden"):
                    models.append(entry("codex", row.get("model", row.get("id")), row.get("displayName")))
            cursor = result.get("nextCursor")
            if not cursor:
                return models
            if not isinstance(cursor, str) or cursor in seen:
                break
            seen.add(cursor)
        raise Failure(502, "Codex returned an incomplete model catalogue.")


def zero_cost(cost):
    if not isinstance(cost, dict) or not {"input", "output"} <= cost.keys():
        return False
    def zero(value):
        if isinstance(value, dict):
            return all(zero(v) for v in value.values())
        return not isinstance(value, bool) and math.isfinite(float(value)) and float(value) == 0
    try:
        return all(zero(value) for value in cost.values())
    except (TypeError, ValueError):
        return False


def gateway_models(tool, free_only):
    raw = command([tool, "models", tool, "--verbose", "--refresh", "--pure"])
    decoder, rows, offset = json.JSONDecoder(), [], 0
    # CLI output is a provider/id line followed by a pretty-printed JSON object.
    while offset < len(raw):
        end = raw.find("\n", offset)
        if end < 0:
            break
        label = raw[offset:end].strip()
        offset = end + 1
        if not label:
            continue
        if not label.startswith(tool + "/"):
            raise Failure(502, "Tool returned an invalid model catalogue.")
        while offset < len(raw) and raw[offset].isspace():
            offset += 1
        row, offset = decoder.raw_decode(raw, offset)
        if not isinstance(row, dict) or row.get("providerID") != tool or label != tool + "/" + str(row.get("id")):
            raise Failure(502, "Tool returned an invalid model catalogue.")
        free = zero_cost(row.get("cost"))
        if row.get("status") != "deprecated" and (not free_only or free):
            rows.append(entry(tool, row["id"], row.get("name"), free))
    return rows


def catalogue(mode):
    models, statuses = [], {}
    selected = os.environ.get("SELECTED_PROVIDERS", "").split(",")
    tools = ("codex",) if mode == "paid" else ("opencode", "kilo")
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = {}
        for tool in tools:
            free_only = os.environ.get(tool.upper() + "_SCOPE", "free") != "all"
            access = os.environ.get(tool.upper() + "_ACCESS", "api")
            if tool not in selected or (access not in ("subscription", "both") and not (tool == "opencode" and free_only)):
                continue
            future = pool.submit(codex_models) if tool == "codex" else pool.submit(gateway_models, tool, free_only)
            futures[future] = tool
        for future in as_completed(futures):
            tool = futures[future]
            try:
                rows = future.result()
                models.extend(rows)
                statuses[tool + "-tool"] = f"{len(rows)} models in {tool}; available in its coding-tool terminal."
            except Failure as error:
                statuses[tool + "-tool"] = str(error)
            except (ValueError, TypeError, KeyError, AttributeError, OSError):
                statuses[tool + "-tool"] = "Tool returned an invalid catalogue; discovery will retry automatically."
    models.sort(key=lambda model: model["id"])
    return {"toolModels": models, "status": statuses}
