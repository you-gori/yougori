"""Runs inside the image, with a fresh writable home and no network devices."""
import json
import os
import subprocess
import sys
import threading
import time
import urllib.request

import blue
from profiles import configure, BASE, LOCAL_KEY

def run(harness):
    if os.isatty(0):
        import fcntl
        import termios
        # vm_guest starts this process as its own session leader with a private
        # PTY slave. Claim it so resize/signals propagate to the tool's PTY.
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)
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
    if harness == "pentestgpt" and arguments[:1] == ["--print"]:
        if len(arguments) != 2:
            raise ValueError("Use --print followed by one quoted prompt.")
        program = ("from pentestgpt_legacy.llm.factory import get_client; import sys; "
                   "print(get_client('ollama:'+sys.argv[1]).send_new_message(sys.argv[2])[0])")
        argv = ["/opt/solver/tool/bin/python", "-c", program, model, arguments[1]]
        arguments = []
    if harness == "cline":
        subprocess.run([argv[0], "auth", "--provider", "openai", "--baseurl", BASE, "--apikey", LOCAL_KEY,
                        "--modelid", model], env=environment, check=True)
    # Arguments may select a prompt or tool mode; the network boundary remains
    # enforced even if a tool lets its user pick a different provider.
    return blue.run(argv + arguments, environment)


if __name__ == "__main__":
    try:
        if sys.argv[1] == "relay":
            raise ValueError("The relay runs outside the VM.")
        elif sys.argv[1] == "run":
            sys.exit(run(sys.argv[2]))
        else:
            raise ValueError("Unknown runtime action.")
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        sys.exit(str(error))
