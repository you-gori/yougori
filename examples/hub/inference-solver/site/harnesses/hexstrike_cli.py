"""Terminal companion for the official HexStrike MCP server, inside a Sandbox VM."""
import argparse
import asyncio
import base64
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import socket
import sys
import time
import urllib.error
import urllib.request

# Relative to the workspace, where this terminal starts: the session's transcript comes back to
# the person's folder only after their review.
REPORTS = Path("reports/hexstrike")
MODES = ("inference", "sites", "targets", "full")
# HexStrike lists 150 tools (130 KiB of definitions): more than any Yougori model server takes, so
# every request was refused. The model is offered its web-testing tools alone, in this order, each
# with the programs its server runs for it (none: HexStrike's own Python), and only those this VM
# can run (runs()): a tool whose program is missing fails when it is called. api_fuzzer runs ffuf
# when it is given no endpoints, and comprehensive_api_audit always gives it none.
WEB_TOOLS = (
    ("http_framework_test", ()), ("http_repeater", ()), ("http_intruder", ()), ("http_set_scope", ()),
    ("http_set_rules", ()), ("execute_command", ()),
    ("nmap_scan", ("nmap",)), ("httpx_probe", ("httpx",)), ("nuclei_scan", ("nuclei",)), ("nikto_scan", ("nikto",)),
    ("sqlmap_scan", ("sqlmap",)), ("gobuster_scan", ("gobuster",)), ("ffuf_scan", ("ffuf",)),
    ("feroxbuster_scan", ("feroxbuster",)), ("dirsearch_scan", ("dirsearch",)), ("dalfox_xss_scan", ("dalfox",)),
    ("wafw00f_scan", ("wafw00f",)), ("katana_crawl", ("katana",)), ("arjun_scan", ("arjun",)), ("wpscan_analyze", ("wpscan",)),
    ("browser_agent_inspect", ("chromedriver",)), ("burpsuite_alternative_scan", ("chromedriver",)),
    ("api_schema_analyzer", ("curl",)), ("api_fuzzer", ("curl", "ffuf")), ("graphql_scanner", ("curl",)),
    ("jwt_analyzer", ("curl",)), ("ai_test_payload", ("curl",)), ("comprehensive_api_audit", ("curl", "ffuf")),
    ("generate_payload", ()), ("ai_generate_payload", ()), ("detect_technologies_ai", ()),
    ("execute_python_script", ()), ("create_vulnerability_report", ()), ("server_health", ()),
)
# Programs that share their name with a command HexStrike's own requirements install, first on this
# VM's PATH. Python's httpx installs an httpx command. It takes none of the options of
# ProjectDiscovery's httpx, the compiled program httpx_probe runs ("httpx -l TARGET -t THREADS"),
# and fails every time.
SHADOWED = frozenset({"httpx"})
# The strictest limits of Yougori's model server (src-tauri/src/model_server.py validate_chat,
# without its agent limits): at most 32 tools, 16 KiB each and 48 KiB in all, as JSON.
MOST_TOOLS, MOST_TOOL_BYTES, MOST_TOOLS_BYTES = 32, 16384, 49152


def runs(program):
    """Whether HexStrike's server, which runs each program by its name on this VM's PATH, finds
    `program` there. For a program of SHADOWED, only when the one it finds is not a Python script."""
    found = shutil.which(program)
    if found is None or program not in SHADOWED:
        return found is not None
    try:
        with open(found, "rb") as stream:
            start = stream.read(512)
    except OSError:
        return False
    # pip writes a command as a script that names its Python on the first line, or on the second
    # after #!/bin/sh when the path is long.
    return not (start.startswith(b"#!") and b"python" in start)


def offered(listed, has=None):
    """The tools the model is offered, from HexStrike's own as its MCP server lists them: those of
    WEB_TOOLS whose programs this VM runs (`has`, runs() by default, says so of each), in
    WEB_TOOLS's order, each described as HexStrike describes it, while they fit Yougori's
    strictest model server as it measures them."""
    has = has or runs
    by_name = {tool.name: tool for tool in listed}
    chosen = []
    for name, programs in WEB_TOOLS:
        tool = by_name.get(name)
        if tool is None or not all(has(program) for program in programs) or len(chosen) == MOST_TOOLS:
            continue
        entry = {"type": "function", "function": {"name": name, "description": (tool.description or "")[:3000], "parameters": tool.inputSchema}}
        if len(json.dumps(entry["function"])) <= MOST_TOOL_BYTES and len(json.dumps(chosen + [entry])) <= MOST_TOOLS_BYTES:
            chosen.append(entry)
    return chosen


def reach(environment=None):
    """What this VM reaches besides the inference, as the person chose it (SOLVER_REACH, which the
    Yougori harness passes on): its mode, sites and targets; None when it was not passed on."""
    environment = os.environ if environment is None else environment
    try:
        value = json.loads(environment.get("SOLVER_REACH") or "null")
    except ValueError:
        return None
    if not isinstance(value, dict) or value.get("mode") not in MODES:
        return None
    def listed(key):
        items = value.get(key)
        return [item for item in items if isinstance(item, str) and item] if isinstance(items, list) else []
    return value["mode"], listed("sites"), listed("targets")


def system_message(environment=None):
    """The companion's instructions: the tools only on the targets the person named and on this VM,
    and what the VM reaches as the person chose it. The network is said to be unavailable only when
    the VM reaches no target, and nothing is said of it when the reach is not known."""
    words = ["You are the HexStrike terminal companion. Use the available tools only on the targets the person "
             "named and on this VM."]
    chosen = reach(environment)
    if chosen:
        mode, sites, targets = chosen
        over_https = "the sites " + ", ".join(sites) + " over HTTPS"
        if mode == "full":
            words.append("This VM reaches the internet.")
        elif mode == "targets":
            if targets:  # without them which targets it reaches is not known
                words.append("Besides the model, this VM reaches only " + ", ".join(targets)
                             + (" and " + over_https if sites else "") + ".")
        elif sites:
            words.append("External networking is unavailable, apart from " + over_https + ".")
        else:
            words.append("External networking is unavailable.")
    words.append("Never claim a tool ran if it returned an error.")
    return " ".join(words)


class Refused(Exception):
    """The inference did not answer a model call; its words say why (a request too large for the
    model's server, for example)."""


def refused_words(error):
    """What an HTTP error from the inference says, as one line: its error message, else its status."""
    try:
        detail = json.loads(error.read(65536))["error"]
        words = " ".join(str(detail["message"] if isinstance(detail, dict) else detail).split())
    except (OSError, ValueError, KeyError, TypeError):
        words = ""
    return words or "The inference answered HTTP %d." % error.code


def completion(model, messages, tools):
    request = urllib.request.Request("http://127.0.0.1:8080/v1/chat/completions",
        data=json.dumps({"model":model,"messages":messages,"tools":tools,"stream":False}).encode(),
        headers={"Authorization":"Bearer solver-local-relay","Content-Type":"application/json"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request,timeout=180) as response:
            raw = response.read(4*1024*1024+1)
    except urllib.error.HTTPError as error:
        raise Refused(refused_words(error)) from None
    if len(raw)>4*1024*1024:
        raise ValueError("Model response exceeded the size limit.")
    return json.loads(raw)["choices"][0]["message"]


def hidden_values(environment=None):
    """The secret setup answers this terminal holds (a test login's password): never saved."""
    environment = os.environ if environment is None else environment
    return [value for name, value in environment.items() if name.startswith("YOUGORI_SECRET_") and value]


# Hiding secrets. pentagi_cli.py holds the same code, and a test checks that the two agree.
HIDDEN = "[hidden]"
# A run of base64, standard or URL-safe, such as an HTTP Basic authorization's credentials.
BASE64 = re.compile(r"[A-Za-z0-9+/_-]{8,}={0,2}")
# What some JSON encoder writes as an escape besides control characters and non-ASCII text: PHP
# escapes /, Go < > &, Jinja's tojson also ', .NET also + and `.
JSON_ESCAPED = frozenset('"\\/<>&\'+`')
SHORT_ESCAPES = {'"': '\\"', '\\': '\\\\', '/': '\\/', '\b': '\\b', '\f': '\\f', '\n': '\\n', '\r': '\\r', '\t': '\\t'}


def _in_json(c):
    """Every way a JSON encoder writes the character `c` inside a string: as itself where JSON lets
    it, as a short escape, or as a \\u escape in either case (a surrogate pair beyond the BMP)."""
    if c.isascii() and c.isprintable() and c not in JSON_ESCAPED:
        return {c}
    ways = set() if c in '"\\' or ord(c) < 0x20 else {c}
    if c in SHORT_ESCAPES:
        ways.add(SHORT_ESCAPES[c])
    units = c.encode("utf-16-be")
    escape = "".join("\\u%02x%02x" % (units[i], units[i + 1]) for i in range(0, len(units), 2))
    return ways | {escape, escape.upper().replace("\\U", "\\u")}


def _nested(text):
    """`text` written into a JSON string once more inside the VM: by Python's json, with and without
    \\u escapes for non-ASCII text (pydantic writes as the latter), or by Go's, which escapes <, >
    and & too."""
    plain = json.dumps(text, ensure_ascii=False)[1:-1]
    return {json.dumps(text)[1:-1], plain, re.sub("[<>&\u2028\u2029]", lambda c: "\\u%04x" % ord(c.group(0)), plain)}


def secret_pattern(values):
    """Each secret value as typed and inside a JSON string as any encoder writes it, nested up to
    three deep (a target's JSON answer in a tool's output, in the tool's JSON result, saved as JSON
    once more); None without a value. A character's ways at one depth are prefix-free (each decodes
    to it alone), so a match never backtracks."""
    choices = []
    for value in sorted(set(filter(None, values)), key=lambda value: (-len(value), value)):
        levels = [[{c} for c in value], [_in_json(c) for c in value]]
        for _ in range(2):
            levels.append([{again for way in ways for again in _nested(way)} for ways in levels[-1]])
        for level in reversed(levels):
            choice = "".join(re.escape(next(iter(ways))) if len(ways) == 1 else
                             "(?:" + "|".join(re.escape(way) for way in sorted(ways, key=lambda way: (-len(way), way))) + ")"
                             for ways in level)
            if choice not in choices:
                choices.append(choice)
    return re.compile("|".join(choices)) if choices else None


def _percent(text, keep, space, lower=False):
    """`text` percent-encoded: ASCII letters, digits and `keep` stay, a space is `space`, every other
    character is its UTF-8 bytes as %XX."""
    digits = "%%%02x" if lower else "%%%02X"
    return "".join(space if c == " " else c if c.isascii() and (c.isalnum() or c in keep)
                   else "".join(digits % byte for byte in c.encode("utf-8")) for c in text)


def secret_forms(values):
    """Each secret value percent-encoded in a URL or a form body, as the screen hides it too
    (harness/src/ui/mask.rs), longest first so that a form holding another is hidden whole."""
    forms = set()
    for value in filter(None, values):
        forms.update(_percent(value, "-._~", space, lower) for space in ("%20", "+") for lower in (False, True))
        forms.add(_percent(value, "-._~!'()*", "%20"))  # JavaScript's encodeURIComponent
        forms.add(_percent(value, "-._~/", "%20"))  # Python's quote()
        forms.add(_percent(value, "*-._", "+"))  # a form body as browsers and Java write it
    return sorted(forms, key=lambda form: (-len(form), form))


def _secret_bytes(values):
    """Each secret's bytes as an HTTP Basic authorization carries them (UTF-8, or Latin-1 as Python's
    requests writes them); a value under 4 bytes could turn up by chance in decoded text."""
    found = set()
    for value in filter(None, values):
        for encoding in ("utf-8", "latin-1"):
            try:
                data = value.encode(encoding)
            except UnicodeEncodeError:
                continue
            if len(data) >= 4:
                found.add(data)
    return found


def _base64_holds(run, secrets):
    """Whether a base64 run decodes, from any of its first four characters, to bytes holding a secret."""
    run = run.rstrip("=").replace("-", "+").replace("_", "/")
    for start in range(4):
        piece = run[start:]
        if len(piece) % 4 == 1:
            piece = piece[:-1]  # a lone last character holds no whole byte
        try:
            data = base64.b64decode(piece + "=" * (-len(piece) % 4))
        except ValueError:
            continue
        if any(secret in data for secret in secrets):
            return True
    return False


class Mask:
    """Hides secret values in text: as typed, in JSON (secret_pattern), percent-encoded
    (secret_forms) and in a base64 run."""
    def __init__(self, values):
        values = [value for value in values if value]
        self.pattern = secret_pattern(values)
        self.forms = secret_forms(values)
        self.raw = _secret_bytes(values)

    def __call__(self, text):
        if self.pattern is not None:
            text = self.pattern.sub(HIDDEN, text)
        for form in self.forms:
            if form in text:
                text = text.replace(form, HIDDEN)
        if self.raw:
            text = BASE64.sub(lambda run: HIDDEN if _base64_holds(run.group(0), self.raw) else run.group(0), text)
        return text


def fenced(text):
    """Text in a Markdown code block whose fence no run of backticks inside it can close."""
    fence = "`" * max(3, max((len(run) for run in re.findall(r"`+", text)), default=0) + 1)
    return fence + "\n" + text.rstrip("\n") + "\n" + fence + "\n"


class Transcript:
    """The session as the terminal shows it, with the tools run and their results, in
    reports/hexstrike. A secret value never reaches the file, in any form Mask hides; if the file
    cannot be written the session goes on and the terminal says so once."""
    def __init__(self, folder, hidden):
        self.mask, self.failed = Mask(hidden), False
        self.path = Path(folder) / ("session-" + time.strftime("%Y%m%d-%H%M%S") + ".md")
        self.write("# HexStrike session\n")

    def write(self, text):
        if self.failed:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as stream:
                stream.write(self.mask(text))
        except OSError as error:
            self.failed = True
            print("The session goes on, but its transcript could not be saved: " + str(error), flush=True)

    def person(self, text):
        self.write("\n## Person\n\n" + text.strip() + "\n")

    def reply(self, text):
        self.write("\n## HexStrike\n\n" + text.strip() + "\n")

    def tool(self, name, arguments, result):
        # Hidden before the cut, so a secret that crosses it leaves no part behind.
        result = self.mask(result)
        self.write("\n### Tool " + name + "\n\nArguments:\n\n" + fenced(json.dumps(arguments, indent=1, ensure_ascii=False))
                   + "\nResult:\n\n" + fenced(result[:8000] + ("\n[cut at 8,000 characters]" if len(result) > 8000 else "")))

    def note(self, text):
        self.write("\n" + text + "\n")


async def chat(args):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    source = Path("/opt/solver/source")
    with (Path.home()/"hexstrike-server.log").open("w") as log, (Path.home()/"hexstrike-mcp.log").open("w") as mcp_log:
        # Started in the home folder: the server writes hexstrike.log where it starts, and the
        # workspace holds only what the person reviews.
        server = subprocess.Popen([sys.executable,str(source/"hexstrike_server.py"),"--port","8888"],stdout=log,stderr=log,cwd=Path.home())
        try:
            for _ in range(60):
                if server.poll() is not None:
                    raise ValueError("HexStrike server stopped. See ~/hexstrike-server.log inside the VM.")
                try:
                    with socket.create_connection(("127.0.0.1",8888),timeout=1):
                        break
                except OSError: time.sleep(.25)
            else: raise ValueError("HexStrike did not become ready.")
            params = StdioServerParameters(command=sys.executable,args=[str(source/"hexstrike_mcp.py"),"--server","http://127.0.0.1:8888"],env=dict(os.environ))
            # Its MCP client logs to a file too: those lines would draw over the person's screen.
            async with stdio_client(params, errlog=mcp_log) as (read,write):
                async with ClientSession(read,write) as session:
                    await session.initialize()
                    listed = await session.list_tools()
                    tools = offered(listed.tools)
                    names = {tool["function"]["name"] for tool in tools}
                    if args.list_tools:
                        print("\n".join(tool["function"]["name"] for tool in tools)); return
                    if not tools:
                        raise ValueError("This HexStrike lists none of the web-testing tools this terminal offers. Update Yougori.")
                    messages = [{"role":"system","content":system_message()}]
                    print("HexStrike · Inference Solver · /exit to leave",flush=True)
                    transcript = None if args.prompt else Transcript(Path.cwd()/REPORTS, hidden_values())
                    # A secret a tool echoes (a test login's password) reaches neither the model nor the screen.
                    mask = transcript.mask if transcript else Mask(hidden_values())
                    if transcript:
                        print("The session is saved to " + str(REPORTS/transcript.path.name) + " in the workspace.",flush=True)
                    first = (args.task or "").strip()
                    while True:
                        if first:
                            # The task given at the start is the first turn; the person goes on here.
                            prompt, first = first, ""
                            print("hexstrike > " + prompt,flush=True)
                        else:
                            prompt = args.prompt or await asyncio.to_thread(input,"hexstrike > ")
                        if prompt.strip() in ("/exit","/quit"): return
                        if transcript: transcript.person(prompt)
                        turn = len(messages)
                        messages.append({"role":"user","content":prompt})
                        for _ in range(24):
                            try:
                                reply = await asyncio.to_thread(completion,args.model,messages,tools)
                            except Refused as refusal:
                                # The turn is taken back, so the conversation stays one the model takes.
                                del messages[turn:]
                                print("The model could not answer: " + mask(str(refusal)),flush=True)
                                if transcript: transcript.note("The model could not answer: " + str(refusal))
                                break
                            messages.append(reply)
                            if reply.get("content"):
                                print(mask(reply["content"]),flush=True)
                                if transcript: transcript.reply(reply["content"])
                            calls = reply.get("tool_calls") or []
                            if not calls: break
                            if len(calls)>8: raise ValueError("Too many tool calls in one response.")
                            for call in calls:
                                name = call["function"]["name"]
                                if name not in names: raise ValueError("The model requested a tool it was not offered: " + name[:80])
                                arguments = json.loads(call["function"]["arguments"])
                                print("Running " + name,flush=True)
                                result = await asyncio.wait_for(session.call_tool(name,arguments),timeout=120)
                                # Hidden before the cut, so a secret that crosses it leaves no part behind.
                                content = mask(result.model_dump_json())
                                messages.append({"role":"tool","tool_call_id":call["id"],"content":content[:48000]})
                                if transcript: transcript.tool(name, arguments, content)
                        else:
                            print("Stopped after 24 tool rounds. Enter another instruction to continue.",flush=True)
                            if transcript: transcript.note("Stopped after 24 tool rounds.")
                        if args.prompt: return
        finally:
            server.terminate()
            try: server.wait(timeout=5)
            except subprocess.TimeoutExpired: server.kill(); server.wait()


def parse(argv=None):
    parser = argparse.ArgumentParser(description="HexStrike MCP terminal, using only Inference Solver.")
    parser.add_argument("--model",required=True)
    first = parser.add_mutually_exclusive_group()
    first.add_argument("--print",dest="prompt",help="Run one instruction and leave")
    first.add_argument("--task",help="The first instruction; the session then goes on in this terminal and its "
                       "transcript is saved in reports/hexstrike in the workspace")
    parser.add_argument("--list-tools",action="store_true",help="List the HexStrike tools the model is offered in this VM")
    args = parser.parse_args(argv)
    if args.task is not None and not args.task.strip():
        parser.error("--task needs an instruction.")
    return args


if __name__ == "__main__":
    asyncio.run(chat(parse()))
