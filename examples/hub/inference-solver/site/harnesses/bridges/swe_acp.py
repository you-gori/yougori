"""SWE-agent (commit 3ea751c, sweagent 1.1.0) behind the Yougori screen, over ACP.

Each prompt is one SWE-agent run, configured as its own CLI configures one: RunSingleConfig from
the arguments configure() gives `sweagent run` (its default config, the relay model, the local
deployment), parsed by SWE-agent's own parser, with the workspace as the repository and the prompt
as the problem statement (the setup answer `issue`, when there is one, with the prompt added to it,
until a run has worked on the issue). An agent hook reports every step: the model's message as a message (its
thinking blocks as thoughts), the action as a tool call (bash a terminal, the file editor an edit
with its diff), the observation as the tool's output, and the step count as progress. The final
patch comes as diffs and is saved with SWE-agent's trajectory and a summary under
reports/swe-agent/ in the workspace (left out of the repository's own changes). A cancel
interrupts the run the way Ctrl+C does and closes its shell. An empty workspace becomes a Git
repository first, as for SWE-agent's terminal client.
"""
import datetime
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time
import traceback
import uuid

_HERE = os.path.dirname(os.path.abspath(__file__))
if __package__ in (None, ""):
    sys.path[:] = [p for p in sys.path if os.path.abspath(p or os.curdir) != _HERE]
    sys.path.append(os.path.dirname(_HERE))

from bridges import support_acp as support  # noqa: E402

REPORTS = os.path.join("reports", "swe-agent")
TRAJECTORY_LIMIT = 20 * 1024 * 1024
OUTPUT_LIMIT = 64 * 1024
STOPS = {"exit_cost": "max_turn_requests", "exit_total_execution_time": "max_turn_requests", "exit_context": "max_tokens"}
QUIET = {"exit_command", "exit_forfeit", "submitted"}
# Exit statuses of a run that broke down (the model's server, its environment, an error) rather
# than worked on the issue until it stopped.
BROKEN = {"exit_api", "exit_environment_error", "exit_error"}


def version():
    try:
        from importlib.metadata import version as installed
        return installed("sweagent")
    except Exception:
        return "1.1.0"


def override(args, name, value):
    """configure()'s `sweagent run` arguments with `--name value` set (replaced, or added)."""
    out, i, found = [], 0, False
    while i < len(args):
        if args[i] == name and i + 1 < len(args):
            out += [name, value]
            found = True
            i += 2
            continue
        out.append(args[i])
        i += 1
    if not found:
        out += [name, value]
    return out


def without_statement(args):
    """configure()'s `sweagent run` arguments without any problem statement option: the bridge sets
    the statement on the parsed configuration (see SweBridge.configuration)."""
    out, i = [], 0
    while i < len(args):
        if args[i].startswith("--problem_statement."):
            i += 1 if "=" in args[i] else 2
            continue
        out.append(args[i])
        i += 1
    return out


def git(cwd, *args, check=True):
    environment = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    return subprocess.run(["git", "-C", cwd, *args], capture_output=True, text=True, check=check, env=environment,
                          stdin=subprocess.DEVNULL)


def repository_root(cwd):
    try:
        done = git(cwd, "rev-parse", "--show-toplevel", check=False)
    except OSError:
        return None
    return done.stdout.strip() if done.returncode == 0 and done.stdout.strip() else None


def prepare_repository(cwd):
    """The workspace as SWE-agent's repository: an empty one becomes one (as runtime.py does for
    the terminal client). Returns the repository's root."""
    root = repository_root(cwd)
    if root:
        return root
    entries = [e for e in os.listdir(cwd) if e not in (".", "..")]
    if entries and os.environ.get("SOLVER_EMPTY_WORKSPACE") != "1":
        raise RuntimeError("SWE-agent works in a Git repository, and this folder is not one. Start it again on a "
                           "folder that is a Git repository, or on an empty folder.")
    git(cwd, "init")
    git(cwd, "-c", "user.name=Workspace", "-c", "user.email=workspace@localhost", "commit", "--allow-empty", "-m",
        "Initialize temporary workspace")
    return repository_root(cwd) or cwd


def keep_reports_out(root):
    """The reports folder stays out of the patches SWE-agent makes (`git add -A`): a rule in git's own
    ignore file in the harness's home (XDG_CONFIG_HOME/git/ignore, where profiles.py keeps Yougori's
    setup files out too), so nothing in the workspace changes and the person's review does not list
    .git/info/exclude. Without XDG_CONFIG_HOME, which a Yougori VM always sets, the repository's
    local exclude file."""
    try:
        if os.environ.get("XDG_CONFIG_HOME"):
            path = os.path.join(os.environ["XDG_CONFIG_HOME"], "git", "ignore")
        else:
            done = git(root, "rev-parse", "--git-path", "info/exclude", check=False)
            path = done.stdout.strip()
            if done.returncode or not path:
                return
            path = path if os.path.isabs(path) else os.path.join(root, path)
        rule = "/" + REPORTS.replace(os.sep, "/") + "/"
        existing = ""
        if os.path.exists(path):
            with open(path, encoding="utf-8") as stream:
                existing = stream.read()
        if rule not in existing.splitlines():
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "a", encoding="utf-8") as stream:
                stream.write(("" if not existing or existing.endswith("\n") else "\n") + rule + "\n")
    except OSError:
        traceback.print_exc()


def patch_files(patch):
    """(path, deleted) for each file a unified git patch changes."""
    files = {}
    for block in re.split(r"^(?=diff --git )", patch, flags=re.M):
        match = re.match(r"diff --git a/(.+?) b/(.+?)$", block, re.M)
        if match:
            files[match.group(2)] = bool(re.search(r"^deleted file mode", block, re.M))
    return list(files.items())


def tool_of(step):
    """(name, arguments) of a step's action."""
    calls = step.tool_calls or []
    if calls:
        function = calls[0].get("function") or {}
        arguments = function.get("arguments") or {}
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments)
            except ValueError:
                arguments = {"command": arguments}
        return function.get("name") or "", arguments if isinstance(arguments, dict) else {}
    action = (step.action or "").strip()
    name = action.split()[0] if action else ""
    if name == "str_replace_editor":
        parts = shlex.split(action, posix=True) if action.count('"') % 2 == 0 else action.split()
        return name, {"command": parts[1] if len(parts) > 1 else "", "path": parts[2] if len(parts) > 2 else ""}
    return ("bash" if name not in ("submit", "exit") else name), {"command": action}


def make_hook(base, bridge):
    """SWE-agent's agent hook, reporting to the screen."""

    class ScreenHook(base):
        def on_init(self, *, agent):
            self.agent = agent
            self.steps = 0
            self.sent = 0
            self.tool = None
            self.before = None
            self.path = None
            # Each run's progress lines are its own (the screen updates a line by its id).
            self.key = "swe-run-%d" % bridge.runs

        def on_tools_installation_started(self):
            bridge.progress(self.key + "-setup", "Setting up SWE-agent's tools")

        def on_setup_attempt(self):
            # Called once its tools are installed (its combined hook does not pass on_setup_done on).
            bridge.progress(self.key + "-setup", "SWE-agent's tools are ready", finished=True)

        def on_step_start(self):
            self.steps += 1
            limit = bridge.call_limit or None
            bridge.progress(self.key + "-steps", "Step %d" % self.steps, done=self.steps, total=limit, unit="steps")

        def on_actions_generated(self, *, step):
            for block in step.thinking_blocks or []:
                thinking = block.get("thinking") if isinstance(block, dict) else None
                if thinking:
                    bridge.thought(thinking + "\n")
            if step.thought and step.thought.strip():
                bridge.message(step.thought.strip() + "\n\n")
            name, arguments = tool_of(step)
            self.tool = bridge.next_id()
            self.path = None
            kind, title, raw = "other", support.first_line(step.action, 160) or name, {"command": step.action}
            if name == "bash":
                command = arguments.get("command") or step.action
                kind, title, raw = "execute", support.first_line(command, 160), {"command": command}
            elif name == "str_replace_editor":
                command, path = arguments.get("command", ""), arguments.get("path", "")
                self.path = path if path and os.path.isabs(path) else None
                relative = bridge.relative(path)
                kind = "read" if command == "view" else "edit"
                title = {"view": "View %s", "create": "Create %s", "str_replace": "Edit %s", "insert": "Edit %s",
                         "undo_edit": "Undo the last edit of %s"}.get(command, "%s " + command) % relative
                raw = dict(arguments)
            elif name == "submit":
                title = "Submit"
            bridge.tool_call(self.tool, title, kind=kind, status="pending", raw_input=raw,
                             locations=[{"path": self.path}] if self.path else None)

        def on_action_started(self, *, step):
            if self.tool:
                self.before = support.read_text(self.path) if self.path and os.path.isfile(self.path) else None
                bridge.tool_update(self.tool, status="in_progress")

        def on_action_executed(self, *, step):
            if not self.tool:
                return
            observation = clean(step.observation).strip("\n")
            content = []
            if self.path:
                after = support.read_text(self.path) if os.path.isfile(self.path) else None
                if after is not None and after != self.before:
                    content.append(bridge.diff(self.path, self.before, after))
            content.append(bridge.text(observation[-OUTPUT_LIMIT:] if observation else "(no output)"))
            bridge.tool_update(self.tool, status="completed", content=content)
            self.tool = None

        def on_step_done(self, *, step, info):
            if self.tool:
                # The step ended without running its action (exit, a blocked or malformed action).
                bridge.tool_update(self.tool, status="failed", content=[bridge.text(step.observation or "Not run.")])
                self.tool = None
            stats = info.get("model_stats") or {}
            sent = int(stats.get("tokens_sent") or 0)
            if sent:
                last = sent - self.sent
                self.sent = sent
                bridge.usage(context_tokens=last or None, context_window=bridge.args.context_window, input_tokens=sent,
                             output_tokens=int(stats.get("tokens_received") or 0))

        def abandon(self):
            """The run was stopped in the middle of an action."""
            if self.tool:
                bridge.tool_update(self.tool, status="failed", content=[bridge.text("Stopped.")])
                self.tool = None

        def on_run_done(self, *, trajectory, info):
            bridge.progress(self.key + "-steps", "Done after %d steps" % self.steps, done=self.steps,
                            total=bridge.call_limit or None, unit="steps", finished=True)

    return ScreenHook


class SweBridge(support.QueuedBridge):
    def __init__(self, args, stdin, main, **options):
        super().__init__("SWE-agent", version(), stdin, title="SWE-agent", models=args.models, model=args.model, **options)
        self.args, self.main = args, main
        self.root = None
        self.problem = None
        self.issue = (support.answers().get("issue") or "").strip()
        # The issue goes with each prompt until a run has worked on it: a run that failed, broke
        # down or was cancelled leaves it for the next one.
        self.issue_used = False
        # The exit status of the run that finished last (None until one does).
        self.status = None
        self.runs = 0
        self.turn_job = None
        self.call_limit = 0
        self.ids = 0
        self.lock = threading.Lock()

    def new_session(self, cwd, mcp_servers):
        if os.path.isdir(cwd):
            os.chdir(cwd)
        try:
            self.root = prepare_repository(cwd)
            keep_reports_out(self.root)
        except (RuntimeError, OSError, subprocess.CalledProcessError) as error:
            self.problem = str(getattr(error, "stderr", None) or error).strip()
            self.notice(self.problem, "error")
            return
        # SWE-agent's imports take a while: done now, before the first prompt needs them.
        self.main.submit(preload)
        if self.issue:
            self.notice("SWE-agent will work on the issue from the setup:\n%s\n\nSend a message to start; what you write "
                        "is added to the issue." % self.issue)

    def relative(self, path):
        if path and self.root:
            try:
                inside = os.path.relpath(path, self.root)
            except ValueError:
                inside = ".."
            if not inside.startswith(".."):
                return inside.replace(os.sep, "/")
        return path or "file"

    def next_id(self):
        with self.lock:
            self.ids += 1
            return "swe-%d" % self.ids

    def prompt(self, text, blocks):
        if self.problem:
            raise RuntimeError(self.problem)
        statement = text.strip()
        with_issue = bool(self.issue) and not self.issue_used
        if with_issue:
            statement = self.issue if not statement else "%s\n\n%s" % (self.issue, statement)
        if not statement:
            self.notice("Describe the issue SWE-agent should fix.", "warn")
            return "end_turn"
        self.runs += 1
        self.status = None
        self.turn_job = job = self.main.submit(self._run, statement)
        if self.cancel_event.is_set():
            # Cancelled before this job was the turn's (cancelled() saw the last one).
            self.main.interrupt(only=job)
        job.done.wait()
        try:
            reason = job.outcome()
        except KeyboardInterrupt:
            return "cancelled"
        except SystemExit as stop:
            # SWE-agent ends its own command line with exit() (its help, a printed config); here
            # that ends the turn, never the turn's thread without an answer.
            raise RuntimeError("SWE-agent stopped (exit code %s) before its run ended; what it printed is in the log."
                               % (stop.code if stop.code is not None else 0)) from None
        status = (self.status or "").split(" ")[0]
        if with_issue and self.status is not None and status not in BROKEN and not self.cancel_event.is_set():
            self.issue_used = True
        return reason

    def _run(self, statement):
        """One SWE-agent run (on the main thread)."""
        if self.cancel_event.is_set():
            # Cancelled before its turn on the main thread came: nothing of it runs.
            return "cancelled"
        os.environ.setdefault("SWE_AGENT_LOG_STREAM_LEVEL", "WARNING")
        from sweagent.agent.hooks.abstract import AbstractAgentHook
        from sweagent.run.run_single import RunSingle
        run_id = "run-%s-%s" % (datetime.datetime.now().strftime("%Y%m%d-%H%M%S"), uuid.uuid4().hex[:4])
        config = self.configuration(statement, run_id)
        self.call_limit = int(getattr(config.agent.model, "per_instance_call_limit", 0) or 0)
        clear_previous_run(config)
        run = RunSingle.from_config(config)
        hook = make_hook(AbstractAgentHook, self)()
        run.agent.add_hook(hook)
        started = time.monotonic()
        try:
            run.run()
        except KeyboardInterrupt:
            # The run's step line stays unfinished: the screen shows it stopped when the turn ends.
            hook.abandon()
            self.close_environment(run)
            raise
        except BaseException:
            self.close_environment(run)
            raise
        info = run.agent.info if hasattr(run.agent, "info") else {}
        return self.finish(config, run_id, info, time.monotonic() - started)

    def configuration(self, statement, run_id):
        """The run's RunSingleConfig, as `sweagent run` makes it from configure()'s arguments with
        this session's model, window and repository, and the statement as the text problem
        statement that `--problem_statement.text` and `--problem_statement.id` make. The statement
        goes on the parsed configuration, never through SWE-agent's command line: there, text such
        as "--help" or "-hi, the login fails" reads as SWE-agent's own option (it prints its help
        and exits), and a value joined with '=' is cut at its first line."""
        from sweagent.agent.problem_statement import TextProblemStatement
        from sweagent.run.common import BasicCLI
        from sweagent.run.run_single import RunSingleConfig
        root = self.root
        args = without_statement(self.args.engine)
        args = override(args, "--agent.model.name", "openai/" + self.model)
        args = override(args, "--agent.model.max_input_tokens", str(self.args.context_window))
        args = override(args, "--env.repo.repo_name", root.strip("/"))
        args = override(args, "--agent.tools.reset_commands", json.dumps(["cd " + shlex.quote(root)]))
        args = override(args, "--env.post_startup_commands", json.dumps(["cd " + shlex.quote(root)]))
        config = BasicCLI(RunSingleConfig, help_text="SWE-agent").get_config(args)
        config.problem_statement = TextProblemStatement(text=statement, id=run_id)
        return config

    def close_environment(self, run):
        try:
            run.env.close()
        except BaseException:
            traceback.print_exc()

    def finish(self, config, run_id, info, seconds):
        """The run's patch as diffs, its report saved in the workspace, its outcome as the turn's."""
        status = str(info.get("exit_status") or "")
        self.status = status
        patch = info.get("submission") or ""
        files = patch_files(patch) if patch else []
        if files:
            content = []
            for path, deleted in files:
                absolute = os.path.join(self.root, path)
                old = self.original(path)
                new = "" if deleted else (support.read_text(absolute) or "")
                content.append(self.diff(absolute, old, new))
            self.tool_call(self.next_id(), "Patch: %d file%s changed" % (len(files), "" if len(files) == 1 else "s"),
                           kind="edit", status="completed", content=content,
                           locations=[{"path": os.path.join(self.root, p)} for p, _ in files])
        report = self.save_report(config, run_id, info, status, patch, files, seconds)
        changed = "%d file%s changed." % (len(files), "" if len(files) == 1 else "s") if files else "No patch."
        summary = "Exit status: %s. %s" % (status or "unknown", changed)
        if report:
            self.report("SWE-agent run %s" % run_id, path=report, summary=summary)
        base = status.split(" ")[0] if status else ""
        if base.startswith("exit_") and base not in QUIET and base not in STOPS:
            self.notice("SWE-agent stopped: %s." % status, "error")
        elif "(" in status:
            self.notice("SWE-agent ended with %s." % status, "warn")
        return STOPS.get(base, "end_turn")

    def original(self, path):
        try:
            done = git(self.root, "show", "HEAD:" + path, check=False)
        except OSError:
            return None
        return done.stdout if done.returncode == 0 else None

    def save_report(self, config, run_id, info, status, patch, files, seconds):
        folder = os.path.join(self.root, REPORTS, run_id)
        try:
            os.makedirs(folder, exist_ok=True)
            source = os.path.join(str(config.output_dir), run_id)
            trajectory = os.path.join(source, run_id + ".traj")
            if os.path.isfile(trajectory) and os.path.getsize(trajectory) <= TRAJECTORY_LIMIT:
                shutil.copy2(trajectory, os.path.join(folder, run_id + ".traj"))
            if patch:
                with open(os.path.join(folder, run_id + ".patch"), "w", encoding="utf-8") as stream:
                    stream.write(patch)
            stats = info.get("model_stats") or {}
            lines = ["# SWE-agent run %s" % run_id, "",
                     "- Model: %s" % self.model,
                     "- Exit status: %s" % (status or "unknown"),
                     "- Steps (model calls): %s" % stats.get("api_calls", "unknown"),
                     "- Tokens sent / received: %s / %s" % (stats.get("tokens_sent", 0), stats.get("tokens_received", 0)),
                     "- Time: %d s" % seconds, ""]
            if files:
                lines += ["## Files changed", ""] + ["- %s%s" % (p, " (deleted)" if d else "") for p, d in files] + [""]
                lines += ["The patch is %s.patch beside this file; the changes are also in the folder itself." % run_id, ""]
            else:
                lines += ["No patch was submitted.", ""]
            lines += ["SWE-agent's trajectory is %s.traj beside this file (when it was not too large)." % run_id, ""]
            path = os.path.join(folder, "summary.md")
            with open(path, "w", encoding="utf-8") as stream:
                stream.write("\n".join(lines))
            return path
        except OSError as error:
            self.notice("The run's report could not be saved: %s" % error, "warn")
            return None

    def cancelled(self):
        # Only the turn's own job: the import of SWE-agent done ahead of the first run goes on.
        job = self.turn_job
        if job is not None:
            self.main.interrupt(only=job)

    def closing(self):
        # The client is gone: whatever runs stops.
        self.main.interrupt()


def clear_previous_run(config):
    """SWE-agent installs its tool bundles into /root/tools for its one run per machine (as its CLI
    runs); the next run of this session installs them again, so the last run's copies, and its
    submission file, go first."""
    for bundle in getattr(config.agent.tools, "bundles", None) or []:
        name = os.path.basename(str(getattr(bundle, "path", "")).rstrip("/"))
        if name:
            shutil.rmtree(os.path.join("/root/tools", name), ignore_errors=True)
    try:
        os.remove("/root/model.patch")
    except OSError:
        pass


def clean(text):
    return (text or "").replace("\r\n", "\n").replace("\r", "\n")


def preload():
    os.environ.setdefault("SWE_AGENT_LOG_STREAM_LEVEL", "WARNING")
    try:
        import sweagent.run.run_single  # noqa: F401
    except Exception:
        traceback.print_exc()


def main(argv=None):
    args = support.arguments(sys.argv[1:] if argv is None else argv, "SWE-agent over ACP for the Yougori harness.")
    stdin = support.prepare()
    engine = support.MainThread()
    bridge = SweBridge(args, stdin, engine)
    support.serve(bridge, engine)


if __name__ == "__main__":
    main()
