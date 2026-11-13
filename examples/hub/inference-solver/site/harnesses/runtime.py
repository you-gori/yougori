"""Runs inside the image, with a fresh writable home and no network devices."""
import json
import os
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

import blue
from profiles import cline_limits, configure, headless, limits, reach_of, BASE, LOCAL_KEY

HOME = "/home/node"
# The Yougori harness binary: in the image, or in the tool archive.
HARNESS_BINARIES = ("/usr/local/bin/yougori-harness", "/opt/solver/bin/yougori-harness")
# What the Yougori harness itself gets from the VM: the engine's environment is in its spec.
HARNESS_ENV = ("PATH", "HOME", "TERM", "COLORTERM", "NO_COLOR", "LANG")
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
    spec = headless(harness, os.environ["SOLVER_MODEL"], catalog, HOME, answers(), reach=reach())
    path = write_spec(spec)
    binary = next((b for b in HARNESS_BINARIES if os.access(b, os.X_OK)), None)
    if binary is None:
        raise ValueError("The Yougori harness is not installed in this VM.")
    os.execve(binary, [binary, "--spec", str(path)], harness_environment())


def engine(harness, model):
    """A fresh spec for another model (the screen's respec), printed as JSON."""
    spec = headless(harness, model, wait_for_catalog(), HOME, answers(), reach=reach())
    sys.stdout.write(json.dumps(spec))
    sys.stdout.flush()


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
        else:
            raise ValueError("Unknown runtime action.")
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        sys.exit(str(error))
