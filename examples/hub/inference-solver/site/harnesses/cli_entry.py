"""Installed Windows command. Its bundled connection chooses the server/tool."""
import json
from pathlib import Path
import runpy
import re
import sys

here = Path(__file__).resolve().parent
connection = json.loads((here / "connection.json").read_text(encoding="utf-8"))
harness = connection["harness"]
if len(sys.argv) < 2 or not re.fullmatch("solver-" + re.escape(harness) + r"(?:-[a-f0-9]{8})?", sys.argv[1]):
    sys.exit("This command does not match its installed harness.")
arguments = sys.argv[2:]
command = sys.argv[1]
if arguments in (["--help"], ["-h"]):
    print(f"{command} - Inference Solver CLI\nServer: {connection['server']}\n")
    print(f"  {command}                         Start the harness\n"
          f"  {command} models                  List your available models\n"
          f"  {command} login                   Sign in through your browser\n"
          f"  {command} --workspace PATH        Stage a copy of a project\n"
          f"  {command} --model MODEL_ID        Select a server model\n"
          f"  {command} --no-tty -- TOOL_ARGS   Run a headless command in the VM\n"
          f"  {command} --key-stdin             Replace the key through stdin\n\n"
          "First use shows a code to enter on the website. Approve it there;\n"
          "the CLI connects automatically. No API key needs to be copied.\n"
          "Yougori with Sandbox VM support is required. First launch imports\n"
          "the VM image. External runtime network access is blocked.\n"
          "Re-run the website's install command to update this CLI.")
    if harness == 'shannon':
        print('\nShannon opens a command prompt inside its VM. Use check, shell,\n'
              'scan URL, logs, help or exit. Tasks reuse that prepared VM until exit.\n'
              'For a one-shot connection check: '+command+' -- --validate-model')
    sys.exit(0)
if arguments == ["--version"]:
    spec = json.loads((here / "packages.json").read_text())[harness]
    print(f"{command}: configured {spec['version']}\nServer: {connection['server']}")
    sys.exit(0)
action = arguments[0] if arguments[:1] in (["models"], ["login"]) else "run"
if action in ("models", "login"):
    arguments = arguments[1:]
sys.argv = [command, action, harness, *arguments]
runpy.run_path(str(here / "solver.py"), run_name="__main__")
