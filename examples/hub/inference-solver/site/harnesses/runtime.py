"""Runs inside the image, with a fresh writable home and no network devices."""
import json
import os
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import blue
from profiles import (cline_limits, configure, headless, limits, reach_of, setup_targets, BASE, LOCAL_KEY, PERMISSION_REFUSAL,
                      SECURITY, SWITCH)

HOME = "/home/node"
# The Yougori harness binary: in the image, or in the tool archive.
HARNESS_BINARIES = ("/usr/local/bin/yougori-harness", "/opt/solver/bin/yougori-harness")
# What the Yougori harness itself gets from the VM: the engine's environment is in its spec. The
# switch token is the screen's alone: it gives it only to its switch command.
HARNESS_ENV = ("PATH", "HOME", "TERM", "COLORTERM", "NO_COLOR", "LANG", "YOUGORI_SWITCH_TOKEN")
# The VM's guest (vm_guest.py), which takes the screen's switch requests on the loopback.
GUEST = "http://127.0.0.1:8090"
SWITCH_HEADER = "X-Yougori-Switch"
# How long a switch may wait for the launcher, which may download a pack of up to 512 MiB.
SWITCH_SECONDS = 3 * 3600
OLDER = "This Yougori cannot switch harnesses here. Update Yougori: yougori update"
PENTESTGPT_INTERACTIVE = ("PentestGPT runs only in its own interactive terminal, which asks for the task first. "
                          "Start it without --print: yougori inference run pentestgpt --server URL")
# DeepSeek started alone, from its own image, without a task. `yougori inference run` passes
# nothing after -- and starts DeepSeek inside the Yougori harness, where it keeps a conversation.
DEEPSEEK_ONE_TASK = ('DeepSeek runs one task at a time in this terminal. Give the task after -- --print: '
                     'python solver.py run deepseek -- --print "your task". '
                     'For a conversation, use yougori inference run deepseek --server URL.')


def claim_terminal():
    if os.isatty(0):
        import fcntl
        import termios
        # vm_guest starts this process as its own session leader with a private
        # PTY slave. Claim it so resize/signals propagate to the tool's PTY.
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)


def wait_for_catalog():
    # No third-party process starts until the loopback relay is usable.
    catalog = None
    for _ in range(30):
        try:
            with urllib.request.urlopen(BASE + "/models", timeout=5) as response:
                catalog = json.load(response)["data"]
            break
        except (OSError, ValueError, KeyError):
            time.sleep(.3)
    if catalog is None:
        raise ValueError("Inference Solver is unreachable. The harness was not launched.")
    return catalog


def state(home=None):
    return Path(home or HOME) / ".yougori"


def answers(home=None):
    """The chosen harness's setup answers, written by the launcher (none for many harnesses)."""
    try:
        value = json.loads((state(home) / "answers.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def reach(home=None):
    """SOLVER_REACH from the VM, else the reach of the spec already written (a respec runs in the
    engine's environment, which does not carry it)."""
    if os.environ.get("SOLVER_REACH"):
        return reach_of(os.environ["SOLVER_REACH"])
    try:
        return reach_of(json.dumps(json.loads((state(home) / "engine.json").read_text(encoding="utf-8")).get("reach")))
    except (OSError, ValueError, AttributeError):
        return reach_of(None)


def write_spec(spec, home=None):
    folder = state(home)
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / "engine.json"
    temporary = folder / "engine.json.tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(spec, stream, indent=1)
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)
    return path


def save_answers(value, home=None):
    """The harness's setup answers, for the respecs after a switch (owner-only, whole or not at all)."""
    folder = state(home)
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = folder / ".answers.json.partial"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(value, stream)
    os.replace(temporary, folder / "answers.json")


def session(home=None):
    """What the launcher told this session about switching harness (vm_guest writes session.json):
    the harnesses it may switch to, the VM's base and memory and the inference's address; {} when it
    told nothing."""
    try:
        value = json.loads((state(home) / "session.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(value, dict) or not isinstance(value.get("harnesses"), list):
        return {}
    return {name: value[name] for name in ("harnesses", "vm_base", "vm_memory", "server") if name in value}


def with_session(spec, home=None):
    """`spec` with what the screen needs to switch harness (its /harness): the session's fields and
    the switch command. Without them the screen says switching needs a newer Yougori."""
    fields = session(home)
    if fields:
        spec.update(fields)
        spec["switch"] = list(SWITCH)
    return spec


def harness_environment():
    """Only what the screen needs, and the secret setup answers it maps into the engine."""
    keep = {name: os.environ[name] for name in HARNESS_ENV if os.environ.get(name)}
    keep.update({name: value for name, value in os.environ.items() if name.startswith("YOUGORI_SECRET_")})
    return keep


def run_yougori():
    """The Yougori harness: the chosen harness's engine behind one screen."""
    claim_terminal()
    catalog = wait_for_catalog()
    harness = os.environ.get("SOLVER_HARNESS") or "yougori"
    spec = with_session(headless(harness, os.environ["SOLVER_MODEL"], catalog, HOME, answers(), reach=reach()))
    path = write_spec(spec)
    binary = next((b for b in HARNESS_BINARIES if os.access(b, os.X_OK)), None)
    if binary is None:
        raise ValueError("The Yougori harness is not installed in this VM.")
    os.execve(binary, [binary, "--spec", str(path)], harness_environment())


def engine(harness, model):
    """A fresh spec for another model (the screen's respec), printed as JSON."""
    spec = with_session(headless(harness, model, wait_for_catalog(), HOME, answers(), reach=reach()))
    sys.stdout.write(json.dumps(spec))
    sys.stdout.flush()


def guest(path, data, token, timeout=30):
    """A switch request to this VM's guest on the loopback, with the screen's token; never through
    a proxy (the sites' proxy may be in this environment). Its reply, or its refusal's words."""
    request = urllib.request.Request(GUEST + path, data=json.dumps(data).encode(), method="POST",
                                     headers={"Content-Type": "application/json", SWITCH_HEADER: token})
    try:
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=timeout) as response:
            value = json.loads(response.read(65536))
    except urllib.error.HTTPError as error:
        try:
            said = json.loads(error.read(4096)).get("error")
        except (OSError, ValueError, AttributeError):
            said = None
        raise ValueError(said if isinstance(said, str) and said else "The VM did not take the harness switch.") from None
    if not isinstance(value, dict):
        raise ValueError("The VM did not take the harness switch.")
    return value


def say(**value):
    """One line for the screen (stderr): {"progress": TEXT}, or {"error": TEXT, "kept": BOOL}."""
    sys.stderr.write(json.dumps(value) + "\n")
    sys.stderr.flush()


def switched_spec(harness, model, chosen, home=None):
    """The spec for `harness` after a switch, with its answers kept for the respecs that follow."""
    save_answers(chosen, home)
    spec = with_session(headless(harness, model, wait_for_catalog(), HOME, chosen, reach=reach(home)), home)
    write_spec(spec, home)
    return spec


def switch(home=None, stdin=None, stdout=None, poll=0.3, cancelled=None):
    """The screen's switch command (its /harness), per harness/README.md: the request on stdin
    ({"harness", "model", "answers", "mode": "in-place"|"new-vm"}, for a new VM also "targets",
    "memory" and "secrets"), progress and the reason it failed on stderr, then on stdout the new
    harness's spec (in place, its pack delivered by the launcher) or {"new_vm": true} (the launcher
    starts another VM once the screen exits 75). SIGTERM cancels (`cancelled`: an event set instead,
    for tests). The exit code."""
    stdin, stdout = stdin or sys.stdin, stdout or sys.stdout
    try:
        request = json.loads(stdin.read(262144))
    except ValueError:
        request = None
    if (not isinstance(request, dict) or not isinstance(request.get("harness"), str) or not isinstance(request.get("model"), str)
            or request.get("mode") not in ("in-place", "new-vm") or not isinstance(request.get("answers", {}), dict)):
        say(error="The harness switch was not understood.", kept=True)
        return 1
    harness, model, mode, chosen = request["harness"], request["model"], request["mode"], request.get("answers", {})
    if mode == "in-place" and harness == "yougori":
        # Yougori's own agent needs no pack, and nothing from the launcher.
        stdout.write(json.dumps(switched_spec("yougori", model, {}, home)))
        stdout.flush()
        return 0
    token = os.environ.get("YOUGORI_SWITCH_TOKEN")
    if not token or not session(home):
        say(error=OLDER, kept=True)
        return 1
    if (harness in SECURITY and setup_targets(chosen) and chosen.get("target") != "practice"
            and chosen.get("permission") is not True):
        say(error=PERMISSION_REFUSAL, kept=True)
        return 1
    if cancelled is None:
        cancelled = threading.Event()
        signal.signal(signal.SIGTERM, lambda *_: cancelled.set())
    try:
        identity = guest("/switch", request, token)["id"]
    except (OSError, ValueError, KeyError, TypeError) as error:
        say(error=str(error) or "The VM did not take the harness switch.", kept=True)
        return 1
    shown, failures, deadline = None, 0, time.monotonic() + SWITCH_SECONDS
    while True:
        if cancelled.is_set() or time.monotonic() > deadline:
            reason = "Cancelled." if cancelled.is_set() else "The switch took too long."
            kept = True
            try:
                guest("/switch/cancel", {"id": identity}, token)
                # The launcher ends the switch at its next step: whether the harness before is kept.
                end = time.monotonic() + 15
                while time.monotonic() < end:
                    status = guest("/switch/status", {"id": identity}, token)
                    if status.get("state") == "failed":
                        kept = status.get("kept") is not False
                        break
                    time.sleep(poll)
            except (OSError, ValueError):
                pass
            say(error=reason, kept=kept)
            return 130 if cancelled.is_set() else 1
        try:
            status = guest("/switch/status", {"id": identity}, token)
            failures = 0
        except (OSError, ValueError) as error:
            failures += 1
            if failures >= 20:
                say(error=str(error) or "The VM stopped answering about the switch.", kept=False)
                return 1
            time.sleep(poll)
            continue
        progress = status.get("progress")
        if isinstance(progress, str) and progress and progress != shown:
            shown = progress
            say(progress=progress)
        if status.get("state") == "done":
            try:
                spec = switched_spec(harness, model, chosen, home)
            except ValueError as error:
                say(error=str(error), kept=False)
                return 1
            stdout.write(json.dumps(spec))
            stdout.flush()
            return 0
        if status.get("state") == "accepted":
            stdout.write(json.dumps({"new_vm": True}))
            stdout.flush()
            return 0
        if status.get("state") == "failed":
            reason = status.get("reason")
            say(error=reason if isinstance(reason, str) and reason else "The harness could not be switched.",
                kept=status.get("kept") is not False)
            return 1
        time.sleep(poll)


def run(harness):
    claim_terminal()
    catalog = wait_for_catalog()
    model = os.environ["SOLVER_MODEL"]
    argv, environment = configure(harness, model, catalog, "/home/node")
    # Chosen sites: vm_guest points HTTPS at its proxy; the model relay stays direct (NO_PROXY).
    for name in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy"):
        if os.environ.get(name):
            environment[name] = os.environ[name]
    if os.environ.get('SOLVER_EMPTY_WORKSPACE') == '1':
        environment['SOLVER_EMPTY_WORKSPACE'] = '1'
    if harness == "swe" and os.environ.get("SOLVER_EMPTY_WORKSPACE") == "1":
        subprocess.run(["git", "init", os.getcwd()], env=environment, check=True, capture_output=True)
        subprocess.run(["git", "-C", os.getcwd(), "-c", "user.name=Workspace", "-c", "user.email=workspace@localhost",
                        "commit", "--allow-empty", "-m", "Initialize temporary workspace"], env=environment, check=True, capture_output=True)
    arguments = sys.argv[3:]
    if harness == "deepseek" and arguments[:1] == ["--print"]:
        argv[1] = "headless"
        arguments = arguments[1:]
    elif harness == "deepseek":
        # The pinned dsh ships no terminal screen (its profiles are headless, web, sdk, sdk-minimal
        # and acp), so its interactive start ended in a stack trace about a missing "tui" profile.
        raise ValueError(DEEPSEEK_ONE_TASK)
    if harness == "interpreter" and arguments[:1] == ["--print"]:
        if len(arguments) != 2:
            raise ValueError("Use --print followed by one quoted prompt.")
        program = ("from interpreter import interpreter; import os,sys; "
                   "interpreter.llm.model='openai/'+sys.argv[1]; "
                   "interpreter.llm.api_base=os.environ['OPENAI_BASE_URL']; "
                   "interpreter.llm.api_key=os.environ['OPENAI_API_KEY']; "
                   "interpreter.offline=True; interpreter.telemetry=False; "
                   "interpreter.chat(sys.argv[2],display=True)")
        argv = ["/opt/solver/tool/bin/python", "-c", program, model, arguments[1]]
        arguments = []
    if harness == "pentestgpt" and "--print" in arguments:
        # Its legacy client works only interactively; a one-shot prompt would reach the model
        # without PentestGPT's own workflow and prove nothing about the harness.
        raise ValueError(PENTESTGPT_INTERACTIVE)
    if harness == "cline":
        subprocess.run([argv[0], "auth", "--provider", "openai", "--baseurl", BASE, "--apikey", LOCAL_KEY,
                        "--modelid", model], env=environment, check=True)
        # As in the Yougori harness (profiles._cline): the saved provider gets the model's window.
        cline_limits(Path(HOME) / ".cline", *limits(model, catalog))
    # Arguments may select a prompt or tool mode; the network boundary remains
    # enforced even if a tool lets its user pick a different provider.
    return blue.run(argv + arguments, environment)


if __name__ == "__main__":
    try:
        if sys.argv[1] == "relay":
            raise ValueError("The relay runs outside the VM.")
        elif sys.argv[1] == "run" and sys.argv[2] == "yougori":
            run_yougori()
        elif sys.argv[1] == "run":
            sys.exit(run(sys.argv[2]))
        elif sys.argv[1] == "engine":
            engine(sys.argv[2], sys.argv[3])
        elif sys.argv[1] == "switch":
            sys.exit(switch())
        else:
            raise ValueError("Unknown runtime action.")
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        sys.exit(str(error))
