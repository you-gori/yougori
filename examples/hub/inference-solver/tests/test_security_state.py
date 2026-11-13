"""Where Shannon and Strix keep their state in the VM, and what they need there: Shannon's checkpoint
commits a git identity of Yougori's (matrix-M2 defect 2: every commit failed, "Author identity
unknown", and the scan ended GIT_CHECKPOINT_FAILED) and its model's window and reply budget; Strix
its run state outside the workspace, whose files offer no shared memory maps (matrix-M2 defect 3:
agents.db, SQLite in WAL mode, failed with "disk I/O error" before the first turn), while each run's
report still comes back through the review. A temporary home and workspace, the real git and
Strix's modules faked as they are in the pinned strix-agent 1.7.0; no harness engine runs.

Run: python -I -m unittest discover -s examples/hub/inference-solver/tests -p test_security_state.py
"""
import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "site/harnesses"))
import shannon_cli  # noqa: E402
import strix_cli  # noqa: E402

RUN = "127-0-0-1-8000_144f"


def folder(test):
    """A temporary folder removed after the test."""
    path = Path(tempfile.mkdtemp())
    test.addCleanup(shutil.rmtree, path, ignore_errors=True)
    return path


def scan(**given):
    """Shannon's options for one scan, as shannon_cli's parser gives them."""
    options = {"model": "qwen3-coder", "target": "http://127.0.0.1:8000", "validate_model": False, "config": None,
               "context_budget": 32768, "max_output": 4096, "verbose": False}
    return argparse.Namespace(**{**options, **given})


class Shannon(unittest.TestCase):
    def git(self, repository, environment, *args):
        """git as Shannon's worker runs it in the VM: no system or user settings, and never a guessed
        identity (user.useConfigOnly), so only what the environment gives can sign a commit."""
        clean = {name: value for name, value in environment.items() if name in ("PATH", "SYSTEMROOT") or name.startswith("GIT_")}
        clean.update(HOME=str(folder(self)), GIT_CONFIG_NOSYSTEM="1")
        return subprocess.run(["git", "-c", "user.useConfigOnly=true", "-C", str(repository), *args], env=clean,
                              capture_output=True, text=True, timeout=60)

    def test_the_checkpoint_commits_are_yougoris_and_never_the_persons(self):
        if shutil.which("git") is None:
            self.skipTest("git is not installed")
        home, workspace = folder(self), folder(self)
        person = {"PATH": os.environ.get("PATH", ""), "GIT_AUTHOR_NAME": "Person", "GIT_AUTHOR_EMAIL": "person@example.invalid",
                  "GIT_COMMITTER_NAME": "Person", "GIT_COMMITTER_EMAIL": "person@example.invalid"}
        with patch.dict(os.environ, person, clear=True):
            environment = shannon_cli.worker_environment(scan(), home, home / "shannon-models.json", workspace)
        self.assertEqual({name: environment[name] for name in shannon_cli.GIT_IDENTITY}, shannon_cli.GIT_IDENTITY)
        self.assertNotIn("Person", json.dumps(environment))
        self.assertEqual(environment["SHANNON_SOLVER_MODELS"], str(home / "shannon-models.json"))
        self.assertEqual(environment["GIT_CEILING_DIRECTORIES"], str(workspace / ".shannon"))
        # Shannon's own steps (initDeliverableGit, createGitCheckpoint) in its deliverables folder.
        deliverables = folder(self)
        self.assertEqual(self.git(deliverables, environment, "init", "-q").returncode, 0)
        unknown = self.git(deliverables, {"PATH": environment["PATH"]}, "commit", "-q", "--allow-empty", "-m", "Initial deliverables checkpoint")
        self.assertNotEqual(unknown.returncode, 0, "without an identity, as in the VM")
        for message in ("Initial deliverables checkpoint", "Checkpoint: pre-recon (attempt 1)"):
            done = self.git(deliverables, environment, "commit", "-q", "--allow-empty", "-m", message)
            self.assertEqual(done.returncode, 0, done.stderr)
        log = self.git(deliverables, environment, "log", "--format=%an <%ae> %cn <%ce>").stdout.splitlines()
        self.assertEqual(log, ["Yougori <yougori@localhost> Yougori <yougori@localhost>"] * 2)

    def test_its_agents_get_the_models_window_and_reply_budget(self):
        model, = shannon_cli.models_config(scan(context_budget=16384, max_output=2048))["providers"]["solver"]["models"]
        self.assertEqual((model["id"], model["contextWindow"], model["maxTokens"]), ("qwen3-coder", 16384, 2048))
        # Never more than a quarter of the window, and a short answer for a connection check.
        self.assertEqual(shannon_cli.models_config(scan(context_budget=8192))["providers"]["solver"]["models"][0]["maxTokens"], 2048)
        self.assertEqual(shannon_cli.models_config(scan(validate_model=True))["providers"]["solver"]["models"][0]["maxTokens"], 128)
        with patch.object(shannon_cli, "session", return_value=0), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(shannon_cli.main(["--model", "m", "--context-budget", "16384", "--max-output", "2048"]), 0)
            for wrong in ("0", "16385"):
                with self.assertRaisesRegex(ValueError, "reply length"):
                    shannon_cli.main(["--model", "m", "--context-budget", "16384", "--max-output", wrong])

    def test_a_hangup_ends_it_as_ctrl_c_does(self):
        """A session that the launcher ends hangs Shannon up (vm_guest /finish). Python's default for
        a hangup or SIGTERM ends the program at once, before its worker stops."""
        names = [name for name in ("SIGHUP", "SIGTERM") if hasattr(signal, name)]
        for name in names:
            self.addCleanup(signal.signal, getattr(signal, name), signal.getsignal(getattr(signal, name)))
        shannon_cli.hang_up_cleanly()
        for name in names:
            with self.subTest(signal=name), self.assertRaises(KeyboardInterrupt):
                signal.getsignal(getattr(signal, name))(getattr(signal, name), None)


def files(root):
    return sorted(path.relative_to(root).as_posix() for path in Path(root).rglob("*") if path.is_file())


class ShannonDeliverables(unittest.TestCase):
    """Shannon's deliverables repository came back through the person's review once its commits
    worked: runs/fake-m2/shannon/review.json listed 20 .shannon/deliverables/.git files beside the
    report, and promoting them left a broken repository. Shannon's own git steps, as its worker runs
    them (activities.ts initDeliverableGit, git-manager.ts createGitCheckpoint and commitGitSuccess),
    with the real git."""

    def setUp(self):
        if shutil.which("git") is None:
            self.skipTest("git is not installed")
        self.home, self.work = folder(self), folder(self)
        self.deliverables = self.work / ".shannon/deliverables"
        self.repository = self.home / shannon_cli.DELIVERABLES_GIT
        base = {name: os.environ[name] for name in ("PATH", "SYSTEMROOT") if name in os.environ}
        with patch.dict(os.environ, {**base, "HOME": str(self.home), "GIT_CONFIG_NOSYSTEM": "1"}, clear=True):
            self.environment = shannon_cli.worker_environment(scan(), self.home, self.home / "shannon-models.json", self.work)

    def shannon(self, *args, environment=None):
        """git as Shannon runs it: `cd ${sourceDir} && git ...` in the deliverables folder."""
        return subprocess.run(["git", *args], cwd=self.deliverables, env=environment or self.environment,
                              capture_output=True, text=True, timeout=60)

    def agent(self, name):
        """One agent's steps: Shannon's repository unless .git is there, a checkpoint, its deliverable
        and its success commit."""
        self.deliverables.mkdir(parents=True, exist_ok=True)
        if not os.path.lexists(self.deliverables / ".git"):
            for step in (["init"], ["commit", "--allow-empty", "-m", "Initial deliverables checkpoint"]):
                self.assertEqual(self.shannon(*step).returncode, 0)
        steps = (["rev-parse", "--git-dir"], ["commit", "-m", "Checkpoint: %s (attempt 1)" % name, "--allow-empty"])
        for step in steps:
            done = self.shannon(*step)
            self.assertEqual(done.returncode, 0, done.stderr)
        (self.deliverables / (name + "_deliverable.md")).write_text("# " + name + "\n", encoding="utf-8")
        for step in (["add", "-A", "--", name + "_deliverable.md"], ["commit", "-m", name + ": completed successfully", "--allow-empty"]):
            done = self.shannon(*step)
            self.assertEqual(done.returncode, 0, done.stderr)

    def history(self):
        done = subprocess.run(["git", "--git-dir", str(self.repository), "log", "--format=%an %s"], env=self.environment,
                              capture_output=True, text=True, timeout=60)
        self.assertEqual(done.returncode, 0, done.stderr)
        return done.stdout.splitlines()

    def test_its_repository_stays_in_the_home_and_only_the_deliverables_come_back(self):
        with shannon_cli.deliverables_git(self.work, self.home, self.environment):
            self.assertTrue(shannon_cli.points_to(self.deliverables / ".git", self.repository))
            self.agent("recon")
        self.assertEqual(files(self.work), [".shannon/deliverables/recon_deliverable.md"])
        self.assertEqual(self.history(), ["Yougori recon: completed successfully", "Yougori Checkpoint: recon (attempt 1)",
                                          "Yougori Initial deliverables checkpoint"])
        # The next scan of the session goes on in the same repository.
        with shannon_cli.deliverables_git(self.work, self.home, self.environment):
            self.agent("vuln")
        self.assertEqual(files(self.work), [".shannon/deliverables/recon_deliverable.md", ".shannon/deliverables/vuln_deliverable.md"])
        self.assertEqual(len(self.history()), 5)

    def test_it_goes_however_the_worker_ends(self):
        with self.assertRaises(KeyboardInterrupt), shannon_cli.deliverables_git(self.work, self.home, self.environment):
            self.agent("recon")
            raise KeyboardInterrupt  # The session was hung up (hang_up_cleanly).
        self.assertEqual(files(self.work), [".shannon/deliverables/recon_deliverable.md"])

    def test_a_git_file_an_earlier_session_left_is_used_and_stays_as_it_was(self):
        self.deliverables.mkdir(parents=True)
        left = ("gitdir: " + self.repository.as_posix() + "\n").encode()
        (self.deliverables / ".git").write_bytes(left)
        with shannon_cli.deliverables_git(self.work, self.home, self.environment):
            self.agent("recon")  # This VM's home has no such repository yet: it is made.
        self.assertEqual((self.deliverables / ".git").read_bytes(), left)
        self.assertEqual(files(self.work), [".shannon/deliverables/.git", ".shannon/deliverables/recon_deliverable.md"])

    def test_a_git_of_the_folders_own_stays_and_never_leads_to_the_persons_repository(self):
        """The person's project is a git repository, and an earlier review brought back a broken
        deliverables repository (its folders without files were not copied)."""
        person = {**self.environment, "GIT_AUTHOR_NAME": "Person", "GIT_COMMITTER_NAME": "Person"}
        for step in (["init", "-q"], ["commit", "-q", "--allow-empty", "-m", "The person's project"]):
            self.assertEqual(subprocess.run(["git", *step], cwd=self.work, env=person, capture_output=True, timeout=60).returncode, 0)
        broken = self.deliverables / ".git"
        (broken / "objects/ab").mkdir(parents=True)
        (broken / "HEAD").write_text("ref: refs/heads/master\n", encoding="utf-8")
        (broken / "objects/ab/cdef").write_bytes(b"x")
        before = {name: (self.work / name).read_bytes() for name in files(self.work) if not name.startswith(".git/")}
        with shannon_cli.deliverables_git(self.work, self.home, self.environment):
            # No repository for Shannon, so it skips its checkpoints; never the person's.
            self.assertNotEqual(self.shannon("rev-parse", "--git-dir").returncode, 0)
            self.assertNotEqual(self.shannon("commit", "--allow-empty", "-m", "Checkpoint: recon (attempt 1)").returncode, 0)
        self.assertEqual({name: (self.work / name).read_bytes() for name in files(self.work) if not name.startswith(".git/")}, before)
        project = subprocess.run(["git", "log", "--format=%s"], cwd=self.work, env=person, capture_output=True, text=True, timeout=60)
        self.assertEqual(project.stdout.splitlines(), ["The person's project"])
        # Without the worker's ceiling git took the person's repository for Shannon's.
        alone = {name: value for name, value in self.environment.items() if name != "GIT_CEILING_DIRECTORIES"}
        found = self.shannon("rev-parse", "--git-dir", environment=alone)
        self.assertEqual(Path(found.stdout.strip()).resolve(), (self.work / ".git").resolve())

    def test_a_scan_holds_the_git_file_only_while_its_worker_runs(self):
        """run_once, with Temporal and the worker faked: the .git file points to the home while the
        worker runs, and is gone once it has stopped, however it stopped."""
        seen = []

        def worker(command, environment, source, log_path, verbose=False):
            seen.append((shannon_cli.points_to(self.deliverables / ".git", self.home / shannon_cli.DELIVERABLES_GIT),
                         environment["GIT_CEILING_DIRECTORIES"]))
            if len(seen) == 2:
                raise KeyboardInterrupt  # Hung up while the worker runs.
            return 0
        real = subprocess.Popen

        class Temporal:
            def poll(self):
                return None

            def terminate(self):
                pass

            def wait(self, timeout=None):
                return 0

        def popen(argv, *options, **keywords):
            return Temporal() if str(argv[0]).endswith("temporal") else real(argv, *options, **keywords)
        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(self.work)
        ceiling = str(Path.cwd() / ".shannon")
        with patch.dict(os.environ, {"HOME": str(self.home), "USERPROFILE": str(self.home), "GIT_CONFIG_NOSYSTEM": "1"}), \
                patch.object(shannon_cli.Path, "symlink_to", lambda *_, **__: None), \
                patch.object(shannon_cli.subprocess, "Popen", popen), patch.object(shannon_cli, "worker", worker), \
                patch.object(shannon_cli.socket, "create_connection", return_value=contextlib.nullcontext()), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(shannon_cli.run_once(scan()), 0)
            self.assertFalse(os.path.lexists(self.deliverables / ".git"))
            with self.assertRaises(KeyboardInterrupt):
                shannon_cli.run_once(scan())
        self.assertEqual(seen, [(True, ceiling)] * 2)
        self.assertFalse(os.path.lexists(self.deliverables / ".git"))


def shannon_browser_config(workspace):
    """What Shannon's worker writes into the workspace as a scan starts (playwright-config-writer.ts
    at the pinned commit): nothing when the workspace has a playwright-cli config, else the stealth
    script and the config that names it by its absolute path."""
    config = Path(workspace) / ".playwright/cli.config.json"
    if os.path.exists(config):
        return
    script = Path(workspace) / ".playwright/scripts/stealth.js"
    script.parent.mkdir(parents=True, exist_ok=True)
    script.write_text("delete Object.getPrototypeOf(navigator).webdriver;\n", encoding="utf-8")
    config.write_text(json.dumps({"browser": {"browserName": "chromium", "launchOptions": {"headless": True},
                                              "initScript": [str(script)]}}, indent=2), encoding="utf-8")


class ShannonBrowserConfig(unittest.TestCase):
    """Round 2: .playwright/cli.config.json and .playwright/scripts/stealth.js, which Shannon's worker
    writes for playwright-cli, came back through the person's review beside the report."""

    def setUp(self):
        self.work = folder(self)

    def test_what_it_wrote_leaves_once_the_worker_has_stopped(self):
        for scan_number in (1, 2):  # Each scan of the session writes them again.
            with self.subTest(scan=scan_number), shannon_cli.playwright_config(self.work):
                shannon_browser_config(self.work)
                self.assertEqual(files(self.work), [".playwright/cli.config.json", ".playwright/scripts/stealth.js"])
            self.assertEqual(files(self.work), [])
            self.assertFalse(os.path.lexists(self.work / ".playwright"))

    def test_the_page_snapshots_the_agents_took_go_too_unless_the_workspace_had_that_folder(self):
        # Round 5: playwright-cli writes each snapshot into .playwright-cli/ in its working folder.
        with shannon_cli.playwright_config(self.work):
            shannon_browser_config(self.work)
            (self.work / ".playwright-cli").mkdir()
            (self.work / ".playwright-cli/page-2026-11-13T15-00-05-725Z.yml").write_text("- heading\n", encoding="utf-8")
        self.assertEqual(files(self.work), [])
        self.assertFalse(os.path.lexists(self.work / ".playwright-cli"))
        (self.work / ".playwright-cli").mkdir()
        (self.work / ".playwright-cli/kept.yml").write_text("the project's\n", encoding="utf-8")
        with shannon_cli.playwright_config(self.work):
            (self.work / ".playwright-cli/page-1.yml").write_text("- heading\n", encoding="utf-8")
        self.assertEqual(files(self.work), [".playwright-cli/kept.yml", ".playwright-cli/page-1.yml"])

    def test_its_browser_starts_without_chromiums_own_sandbox(self):
        # Round 5: the VM has no user namespaces and no setuid helper, so with Chromium's sandbox every
        # `playwright-cli open` failed ("No usable sandbox!"); 0.1.1 reads PLAYWRIGHT_MCP_SANDBOX.
        environment = shannon_cli.worker_environment(scan(), self.work, self.work / "shannon-models.json", self.work)
        self.assertEqual(environment["PLAYWRIGHT_MCP_SANDBOX"], "false")
        self.assertEqual(environment["PLAYWRIGHT_MCP_EXECUTABLE_PATH"], "/usr/bin/chromium")

    def test_it_goes_however_the_worker_ends(self):
        with self.assertRaises(KeyboardInterrupt), shannon_cli.playwright_config(self.work):
            shannon_browser_config(self.work)
            raise KeyboardInterrupt  # The session was hung up (hang_up_cleanly).
        self.assertFalse(os.path.lexists(self.work / ".playwright"))

    def test_a_config_of_the_workspaces_own_stays_and_shannon_writes_none(self):
        own = {".playwright/cli.config.json": '{"browser": {"browserName": "firefox"}}',
               ".playwright/scripts/stealth.js": "// the project's own\n"}
        for name, text in own.items():
            (self.work / name).parent.mkdir(parents=True, exist_ok=True)
            (self.work / name).write_text(text, encoding="utf-8")
        with shannon_cli.playwright_config(self.work):
            shannon_browser_config(self.work)
        self.assertEqual({name: (self.work / name).read_text(encoding="utf-8") for name in files(self.work)}, own)

    def test_only_what_it_wrote_goes(self):
        # The project has a .playwright folder of its own; Shannon writes its config into it.
        (self.work / ".playwright").mkdir()
        (self.work / ".playwright/login.spec.ts").write_text("test('login', () => {});\n", encoding="utf-8")
        with shannon_cli.playwright_config(self.work):
            shannon_browser_config(self.work)
            (self.work / ".playwright/scripts/notes.txt").write_text("the agent's\n", encoding="utf-8")
        self.assertEqual(files(self.work), [".playwright/login.spec.ts", ".playwright/scripts/notes.txt"])
        # A config that names another script is not Shannon's: it stays, and so does that script.
        other = folder(self)
        with shannon_cli.playwright_config(other):
            (other / ".playwright/scripts").mkdir(parents=True)
            (other / ".playwright/scripts/stealth.js").write_text("// mine\n", encoding="utf-8")
            (other / ".playwright/cli.config.json").write_text(json.dumps({"browser": {"initScript": ["/elsewhere/mine.js"]}}),
                                                               encoding="utf-8")
        self.assertEqual(files(other), [".playwright/cli.config.json", ".playwright/scripts/stealth.js"])

    def test_a_scan_takes_them_out_once_its_worker_has_stopped(self):
        """run_once, with Temporal and the worker faked: the worker writes the config as Shannon's
        does, and the workspace holds only its report afterwards, however the worker stopped."""
        home = folder(self)
        seen = []

        def worker(command, environment, source, log_path, verbose=False):
            shannon_browser_config(Path.cwd())
            seen.append(files(Path.cwd()))
            if len(seen) == 2:
                raise KeyboardInterrupt  # Hung up while the worker runs.
            return 0
        real = subprocess.Popen

        class Temporal:
            def poll(self):
                return None

            def terminate(self):
                pass

            def wait(self, timeout=None):
                return 0

        def popen(argv, *options, **keywords):
            return Temporal() if str(argv[0]).endswith("temporal") else real(argv, *options, **keywords)
        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(self.work)
        with patch.dict(os.environ, {"HOME": str(home), "USERPROFILE": str(home), "GIT_CONFIG_NOSYSTEM": "1"}), \
                patch.object(shannon_cli.Path, "symlink_to", lambda *_, **__: None), \
                patch.object(shannon_cli.subprocess, "Popen", popen), patch.object(shannon_cli, "worker", worker), \
                patch.object(shannon_cli.socket, "create_connection", return_value=contextlib.nullcontext()), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(shannon_cli.run_once(scan()), 0)
            self.assertFalse(os.path.lexists(self.work / ".playwright"))
            with self.assertRaises(KeyboardInterrupt):
                shannon_cli.run_once(scan())
        self.assertEqual(len(seen), 2)
        self.assertTrue(all({".playwright/cli.config.json", ".playwright/scripts/stealth.js"} <= set(held) for held in seen))
        self.assertFalse(os.path.lexists(self.work / ".playwright"))


class FakeStrix:
    """Strix's modules as the pinned strix-agent 1.7.0 has them, for what strix_cli uses: the run
    folder helpers (strix/core/paths.py, verbatim), a report state that saves each run's files there
    (strix/report/state.py), and a scan that saves as Strix does: as it starts, at a finding, at its
    end. `scan` runs as Strix's main."""

    def __init__(self, scan):
        self.modules = {name: types.ModuleType(name) for name in (
            "strix", "strix.core", "strix.core.paths", "strix.report", "strix.report.state", "strix.runtime",
            "strix.runtime.backends", "strix.runtime.session_manager", "strix.interface", "strix.interface.scan_setup",
            "strix.interface.main")}
        paths = self.modules["strix.core.paths"]
        exec('from pathlib import Path\n'
             'RUNS_DIR_NAME = "strix_runs"\n'
             'RUNTIME_STATE_DIR_NAME = ".state"\n'
             'def run_dir_for(run_name, *, cwd=None):\n'
             '    base = cwd or Path.cwd()\n'
             '    return base / RUNS_DIR_NAME / run_name\n'
             'def runtime_state_dir(run_dir):\n'
             '    return run_dir / RUNTIME_STATE_DIR_NAME\n'
             'def runs_base_dir(*, cwd=None):\n'
             '    base = cwd or Path.cwd()\n'
             '    return base / RUNS_DIR_NAME\n', paths.__dict__)

        class ReportState:
            def __init__(self, run_name):
                self.run_name, self.final_scan_result = run_name, None

            def get_run_dir(self):
                run_dir = paths.run_dir_for(self.run_name)
                run_dir.mkdir(parents=True, exist_ok=True)
                return run_dir

            def save_run_data(self, mark_complete=False, status=None):
                run_dir = self.get_run_dir()
                (run_dir / "run.json").write_text(json.dumps({"run_name": self.run_name, "status": status or
                                                              ("completed" if mark_complete else "running")}), encoding="utf-8")
                if self.final_scan_result:
                    (run_dir / "penetration_test_report.md").write_text(self.final_scan_result, encoding="utf-8")
        self.modules["strix.report.state"].ReportState = ReportState
        self.modules["strix.runtime.backends"].register_backend = lambda name, backend: None
        entry = self.modules["strix.interface.main"]
        entry.main = lambda: scan(ReportState, paths)
        self.saved = ReportState.save_run_data

    def __enter__(self):
        self.patched = patch.dict(sys.modules, self.modules)
        self.patched.__enter__()
        return self

    def __exit__(self, *error):
        self.patched.__exit__(*error)


class Sidecar:
    """Caido, the proxy Strix starts beside it, as a process that is up at once."""

    def __init__(self, *_, **__):
        self.stopped = False

    def poll(self):
        return None

    def terminate(self):
        self.stopped = True

    def wait(self, timeout=None):
        return 0


class Strix(unittest.TestCase):
    def setUp(self):
        self.home, self.work = folder(self), folder(self)
        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(self.work)

    def start(self, scan, *arguments, empty=False):
        """strix_cli's main in this VM (the Yougori harness starts it in the workspace) with Strix's
        modules faked; what it printed."""
        environment = {"HOME": str(self.home), "USERPROFILE": str(self.home), "SOLVER_HARNESS": "strix"}
        if empty:
            environment["SOLVER_EMPTY_WORKSPACE"] = "1"
        printed = io.StringIO()
        with FakeStrix(scan) as fake, patch.object(strix_cli, "allowed_here", return_value=True), \
                patch.object(strix_cli.subprocess, "Popen", Sidecar), \
                patch.object(strix_cli.socket, "create_connection", return_value=contextlib.nullcontext()), \
                patch.dict(os.environ, environment), patch.object(sys, "argv", ["strix_cli.py", *arguments]), \
                contextlib.redirect_stdout(printed):
            try:
                strix_cli.main()
            finally:
                self.assertIs(fake.modules["strix.report.state"].ReportState.save_run_data.__wrapped__, fake.saved)
        return printed.getvalue()

    def files(self, root):
        return sorted(path.relative_to(root).as_posix() for path in Path(root).rglob("*") if path.is_file())

    def test_its_state_stays_in_the_home_and_each_runs_report_comes_to_the_workspace(self):
        seen = []

        def scan(ReportState, paths):
            state = ReportState(RUN)
            state.save_run_data()
            run_dir = state.get_run_dir()
            database = paths.runtime_state_dir(run_dir) / "agents.db"
            database.parent.mkdir(parents=True)
            database.write_bytes(b"SQLite format 3\0")
            (paths.runtime_state_dir(run_dir) / "agents.db-wal").write_bytes(b"")
            # The first save is in the workspace already, before the scan goes on.
            seen.append(self.files(self.work))
            (run_dir / "strix.log").write_text("scan started\n", encoding="utf-8")
            state.final_scan_result = "# Security Penetration Test Report\n"
            state.save_run_data(mark_complete=True)
        printed = self.start(scan, "--target=http://127.0.0.1:8000")
        runs = self.home / strix_cli.RUNS / "strix_runs"
        self.assertEqual(self.files(runs), [RUN + "/.state/agents.db", RUN + "/.state/agents.db-wal", RUN + "/penetration_test_report.md",
                                            RUN + "/run.json", RUN + "/strix.log"])
        report = "reports/strix/" + RUN
        self.assertEqual(seen, [[report + "/run.json"]])
        self.assertEqual(self.files(self.work), [report + "/penetration_test_report.md", report + "/run.json", report + "/strix.log"])
        self.assertEqual(json.loads((self.work / report / "run.json").read_text(encoding="utf-8"))["status"], "completed")
        self.assertIn("Strix's report is in reports/strix in the workspace. It comes back to your folder after your review.", printed)

    def test_what_it_saved_comes_back_when_it_is_stopped(self):
        def scan(ReportState, paths):
            state = ReportState(RUN)
            state.final_scan_result = "# Findings so far\n"
            state.save_run_data()
            # Stopped (its SIGHUP and SIGTERM handler): it saves as interrupted and leaves.
            state.save_run_data(status="interrupted")
            raise SystemExit(1)
        with self.assertRaises(SystemExit):
            self.start(scan)
        report = self.work / "reports/strix" / RUN
        self.assertEqual(json.loads((report / "run.json").read_text(encoding="utf-8"))["status"], "interrupted")
        self.assertEqual((report / "penetration_test_report.md").read_text(encoding="utf-8"), "# Findings so far\n")
        self.assertFalse((self.work / "strix_runs").exists())

    def test_without_a_folder_nothing_is_said_of_one(self):
        def scan(ReportState, paths):
            ReportState(RUN).save_run_data(mark_complete=True)
        self.assertNotIn("reports/strix", self.start(scan, empty=True))

    def test_a_file_goes_again_only_once_it_changed_and_the_state_never(self):
        runs, target = folder(self), folder(self)
        (runs / "one/.state").mkdir(parents=True)
        (runs / "one/.state/agents.db").write_bytes(b"state")
        (runs / "one/report.md").write_text("first", encoding="utf-8")
        (runs / "two").mkdir()
        (runs / "two/run.json").write_text("{}", encoding="utf-8")
        reports = strix_cli.Reports(runs, target)
        copied = []
        original = shutil.copyfile
        with patch.object(strix_cli.shutil, "copyfile", side_effect=lambda source, destination: copied.append(Path(source).name) or
                          original(source, destination)):
            reports.copy()
            reports.copy()
            self.assertEqual(sorted(copied), ["report.md", "run.json"])
            (runs / "one/report.md").write_text("second, longer", encoding="utf-8")
            reports.copy()
        self.assertEqual(sorted(copied), ["report.md", "report.md", "run.json"])
        self.assertEqual(self.files(target), ["one/report.md", "two/run.json"])
        self.assertEqual((target / "one/report.md").read_text(encoding="utf-8"), "second, longer")
        strix_cli.Reports(folder(self) / "missing", target).copy()  # No runs yet: nothing to do.

    def test_its_runs_folder_is_the_homes_whatever_folder_it_works_in(self):
        with FakeStrix(lambda *_: None) as fake:
            runs = strix_cli.keep_runs(self.home / "strix")
            paths = fake.modules["strix.core.paths"]
            self.assertEqual(paths.run_dir_for(RUN), self.home / "strix/strix_runs" / RUN)
            self.assertEqual(paths.runs_base_dir(), runs)
            self.assertEqual(paths.run_dir_for(RUN, cwd=self.work), runs / RUN)


if __name__ == "__main__":
    unittest.main(verbosity=2)
