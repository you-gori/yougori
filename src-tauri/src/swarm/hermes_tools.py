"""Bounded Swarm tools for Hermes. Privileged actions remain native receipts."""
import fnmatch
import itertools
import json
import os
from pathlib import Path
import re
import stat
import time
import uuid


def string(limit, minimum=0):
    return {"type": "string", "minLength": minimum, "maxLength": limit}


def enum(*values):
    return {"type": "string", "enum": list(values)}


def obj(properties, required=None):
    return {"type": "object", "properties": properties,
            "required": list(properties) if required is None else required,
            "additionalProperties": False}


EVIDENCE = {"type": "array", "maxItems": 4, "items": obj({
    "name": string(160, 1), "contentBase64": string(49152, 1)})}
DEFINITIONS = {
    "bounty_attempt": ("Record an evidenced completed attempt. No checks may run after it. For a verified candidate, next use bounty_report with the returned attempt ID.", obj({
        "outcome": enum("not_reproduced", "candidate", "inconclusive", "blocked", "interrupted"),
        "observations": string(8000, 1), "expected": string(4000),
        "limitations": string(4000), "evidence": EVIDENCE})),
    "bounty_report": ("Submit a private evidence-backed finding under the accepted report policy.", obj({
        "title": string(200, 1), "component": string(400, 1), "reproduction": string(12000, 1),
        "observed": string(8000, 1), "expected": string(8000, 1), "impact": string(8000, 1),
        "limitations": string(4000), "evidence": {**EVIDENCE, "minItems": 1},
        "attemptIds": {"type": "array", "maxItems": 32, "items": string(100)}},
        ["title", "component", "reproduction", "observed", "expected", "impact", "limitations", "evidence"])),
    "bounty_reply": ("Check private-reply routing. The supervisor answers humans separately; investigation prose is never delivered to them.", obj({
        "content": string(8192, 1), "replyTo": string(100)}, ["content"])),
    "bounty_check": ("Run an approved command in the separate test sandbox: 0 setup, 1 tests.", obj({
        "index": {"type": "integer", "minimum": 0, "maximum": 1}})),
    "bounty_http": ("Probe only the accepted target using relative paths. Use distinct session names per test account, anonymous for no cookies. Redirects are not followed. Cite the actual receipt.", obj({
        "method": enum("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"),
        "path": string(4096, 1), "headers": {"type": "object", "additionalProperties": {"type": "string"}},
        "body": string(8000), "session": {"type": "string", "pattern": "^[A-Za-z0-9_-]{1,48}$"},
        "resetSession": {"type": "boolean"}}, ["method", "path"])),
    "bounty_experiment": ("Run a bounded reproduction in the separate test sandbox, max 120 seconds. Only the accepted target is reachable. Explain test-copy modifications and cite actual receipts.", obj({
        "language": enum("python", "javascript"), "hypothesis": string(1000, 1), "code": string(16000, 1)})),
    "bounty_share": ("Read or share concise team observations. Never share private messages, secrets or hidden reasoning. Independently verify peer claims.", obj({
        "kind": enum("read", "observation", "blocked", "hypothesis", "verify"), "content": string(4000)}, ["kind"])),
    "read": ("Read a bounded source/context file, or this turn's saved tool output at the exact spillover path returned by Hermes. Other paths are denied.", obj({
        "filePath": string(4096, 1), "offset": {"type": "integer", "minimum": 1},
        "limit": {"type": "integer", "minimum": 1, "maximum": 500}}, ["filePath"])),
    "glob": ("List at most 200 matching files in the accepted source or bounty context.", obj({
        "pattern": string(200, 1), "path": string(4096)}, ["pattern"])),
    "grep": ("Find a literal text pattern in at most 200 accepted source/context files. No regular expressions.", obj({
        "pattern": string(200, 1), "path": string(4096), "include": string(200)}, ["pattern"])),
}


def validate(value, schema):
    """Validate the small JSON Schema subset used by these fixed tools."""
    kind = schema["type"]
    if not {"object": isinstance(value, dict), "array": isinstance(value, list),
            "string": isinstance(value, str), "integer": type(value) is int,
            "boolean": type(value) is bool}[kind]:
        raise ValueError(f"Expected {kind}")
    if "enum" in schema and value not in schema["enum"]:
        raise ValueError("Invalid enum value")
    if kind in ("string", "array"):
        suffix = "Length" if kind == "string" else "Items"
        if not schema.get("min" + suffix, 0) <= len(value) <= schema.get("max" + suffix, 65536):
            raise ValueError("Value exceeds tool bounds")
    if kind == "string" and "pattern" in schema and not re.fullmatch(schema["pattern"], value):
        raise ValueError("Invalid string format")
    if kind == "integer" and not schema.get("minimum", 0) <= value <= schema.get("maximum", 1000000):
        raise ValueError("Integer exceeds tool bounds")
    if kind == "array":
        for item in value:
            validate(item, schema["items"])
    if kind == "object":
        if any(key not in value for key in schema.get("required", [])):
            raise ValueError("Missing required tool argument")
        properties = schema.get("properties", {})
        for key, item in value.items():
            rule = properties.get(key, schema.get("additionalProperties", False))
            if rule is False:
                raise ValueError("Unknown tool argument")
            validate(item, rule)


def bounded_results(items):
    """Keep complete JSON entries inside the tool-output budget, including escapes."""
    encoded = []
    size = 2  # Array brackets.
    for item in items:
        entry = json.dumps(item)
        addition = len(entry) + (2 if encoded else 0)
        if size + addition > 16000:
            break
        encoded.append(entry)
        size += addition
    return "[" + ", ".join(encoded) + "]"


class ManagedTools:
    def __init__(self, root, session):
        self.root = Path(root).resolve()
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", session):
            raise ValueError("Invalid managed session")
        self.session = session

    def checked_path(self, value):
        path = Path(value)
        path = (path if path.is_absolute() else self.root / path).resolve()
        allowed = [self.root / "project", self.root / ".yougori" / "bounty"]
        # Hermes bounds large results by saving them in this fresh turn's home.
        # No other turn's files, runtime logs, config or credentials are readable.
        if os.environ.get("HERMES_HOME"):
            allowed.append(Path(os.environ["HERMES_HOME"]).resolve() / "cache" / "spillover")
        if not any(path == base or base in path.parents for base in allowed):
            raise PermissionError("Path outside accepted source and bounty context")
        # Session bindings are supervisor metadata, not research context.
        if path.parent == self.root / ".yougori" / "bounty" and path.name.startswith("session-"):
            raise PermissionError("Private supervisor session binding")
        return path

    def local(self, name, args):
        path = self.checked_path(args.get("filePath") or args.get("path") or "project")
        if name == "read":
            if not path.is_file() or path.stat().st_size > 8 * 1024 * 1024:
                raise ValueError("Not a bounded source file")
            start = args.get("offset", 1) - 1
            # Seek by line before bounding the returned page. The file-size
            # check above bounds even a giant single line, without hiding later lines.
            with path.open("r", encoding="utf-8", errors="replace") as source:
                lines = itertools.islice(source, start, start + args.get("limit", 200))
                return "\n".join(line.rstrip("\r\n") for line in lines)[:16000]
        result = []
        inspected = 0
        entries = [(path.parent, [], [path.name])] if path.is_file() else os.walk(path, followlinks=False)
        for directory, dirs, files in entries:
            dirs[:] = [d for d in dirs if not Path(directory, d).is_symlink()]
            for filename in files:
                inspected += 1
                if inspected > 10000 or len(result) >= 200:
                    return bounded_results(result)
                candidate = Path(directory, filename)
                try:
                    candidate = self.checked_path(str(candidate))
                except PermissionError:
                    continue
                relative = str(candidate.relative_to(self.root) if self.root in candidate.parents else candidate).replace("\\", "/")
                pattern = args["pattern"] if name == "glob" else args.get("include", "*")
                if not (fnmatch.fnmatch(relative, pattern) or fnmatch.fnmatch(filename, pattern)):
                    continue
                if name == "glob":
                    result.append(relative)
                elif candidate.is_file() and candidate.stat().st_size <= 1024 * 1024:
                    with candidate.open("r", encoding="utf-8", errors="replace") as source:
                        for index, line in enumerate(source, 1):
                            if args["pattern"] in line:
                                line = line.rstrip("\r\n")
                                result.append(f"{relative}:{index}: {line[:400]}")
                                if len(result) >= 200:
                                    break
        return bounded_results(result)

    def request(self, action, params):
        binding = self.root / ".yougori" / "bounty" / f"session-{self.session}.json"
        accepted = json.loads(binding.read_text(encoding="utf-8"))
        policy, task = accepted.get("policy", {}), accepted.get("task", {})
        context = {"bountyId": policy.get("bountyId"), "termsVersion": policy.get("termsVersion"),
                   "leaseId": task.get("leaseId"), "generation": task.get("generation")}
        if not all(context[k] for k in ("bountyId", "termsVersion", "leaseId")) or type(context["generation"]) is not int:
            raise ValueError("No current accepted bounty and task lease")
        identity = str(uuid.uuid4())
        payload = json.dumps({"id": identity, "action": action, "params": params, "context": context}).encode()
        if len(payload) > 65536:
            raise ValueError("Tool request exceeds 64 KiB")
        spool = self.root / "spool"
        pending = spool / f"{identity}.pending"
        fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(payload)
        pending.rename(spool / f"{identity}.request")
        reply = spool / f"{identity}.response"
        deadline = time.monotonic() + 360
        while time.monotonic() < deadline:
            try:
                info = reply.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_size > 65536:
                    raise ValueError("Invalid tool response")
                result = reply.read_text(encoding="utf-8")
                ack = spool / f"{identity}.ack"
                try:
                    fd = os.open(ack, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(fd, "w") as output:
                        output.write(identity)
                    reply.unlink(missing_ok=True)
                    ack.unlink(missing_ok=True)
                except OSError:
                    pass  # Owner reclaims the durable acknowledgment.
                return result
            except (FileNotFoundError, PermissionError):
                time.sleep(0.2)
        raise TimeoutError(f"Tool receipt pending: {identity}. Do not create a duplicate submission.")

    def handler(self, name):
        def execute(args, **_):
            validate(args, DEFINITIONS[name][1])
            return self.request(name.removeprefix("bounty_"), args) if name.startswith("bounty_") else self.local(name, args)
        return execute

    def register(self):
        from tools.registry import registry
        for name, (description, schema) in DEFINITIONS.items():
            registry.register(name=name, toolset="yougori_swarm",
                              schema={"name": name, "description": description, "parameters": schema},
                              handler=self.handler(name), override=True)
