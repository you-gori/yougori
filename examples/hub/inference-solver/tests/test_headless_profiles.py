"""profiles.headless(): the engine spec the Yougori harness starts each harness from, and the
runtime's `run yougori` and `engine` actions. A temporary home, no network, no harness installed."""
import contextlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "site/harnesses"))
import profiles
import runtime
import solver
import vm_host

CATALOG = [{"id": "qwen3-coder"}, {"id": "gemma-4"}]
PROTOCOLS = {"native", "acp", "codex-app-server", "claude-stream-json", "pi-rpc", "terminal"}
EXPECTED = {
    "yougori": ("native", None, "live"),
    "opencode": ("acp", ["opencode", "acp", "--pure"], "live"),
    "kilo": ("acp", ["kilo", "acp", "--pure"], "live"),
    "qwen": ("acp", ["qwen", "--acp", "--model", "qwen3-coder"], "live"),
    "gemini": ("acp", ["gemini", "--acp", "--model", "qwen3-coder"], "live"),
    "goose": ("acp", ["goose", "acp"], "restart"),
    "grok": ("acp", ["grok", "agent", "--model", "solver", "--no-leader", "stdio"], "restart"),
    "deepseek": ("acp", None, "live"),
    "openhands": ("acp", ["openhands", "acp"], "restart"),
    "cline": ("acp", None, "live"),
    "codex": ("codex-app-server", ["codex", "app-server", "-c", 'sandbox_mode="danger-full-access"'], "live"),
    "claude": ("claude-stream-json", None, "live"),
    "pi": ("pi-rpc", ["pi", "--mode", "rpc", "--provider", "solver", "--model", "qwen3-coder"], "live"),
    "strix": ("terminal", None, "restart"),
    "shannon": ("terminal", None, "restart"),
    "pentagi": ("terminal", None, "restart"),
    "pentestgpt": ("terminal", None, "restart"),
    "hexstrike": ("terminal", None, "restart"),
}


class Ran:
    """Stands in for subprocess.run: records commands, succeeds (or fails when told)."""

    def __init__(self, returncode=0, stderr=""):
        self.calls, self.returncode, self.stderr = [], returncode, stderr

    def __call__(self, argv, **options):
        self.calls.append((argv, options))
        return subprocess.CompletedProcess(argv, self.returncode, stdout="", stderr=self.stderr)


class Headless(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp())
        self.work = Path(tempfile.mkdtemp())
        self.clean = patch.dict(os.environ, {}, clear=False)
        self.clean.start()
        for name in profiles.PASSED_ON + ("SOLVER_REACH",):
            os.environ.pop(name, None)

    def tearDown(self):
        self.clean.stop()

    def spec(self, harness, answers=None, run=None, **options):
        return profiles.headless(harness, "qwen3-coder", CATALOG, self.home, answers or {}, cwd=self.work, run=run or Ran(), **options)

    def test_every_entry_is_a_complete_spec_for_its_protocol(self):
        for harness, (protocol, argv, switch) in EXPECTED.items():
            with self.subTest(harness=harness):
                spec = self.spec(harness)
                json.loads(json.dumps(spec))
                self.assertIn(spec["protocol"], PROTOCOLS)
                self.assertEqual((spec["protocol"], spec["model_switch"]), (protocol, switch))
                if argv is not None:
                    self.assertEqual(spec["argv"], argv)
                if protocol != "native":
                    self.assertTrue(spec["argv"], "every engine has a command")
                self.assertEqual(spec["harness"], harness)
                self.assertEqual(spec["name"], profiles.NAMES[harness])
                self.assertEqual(spec["category"], "security" if harness in profiles.SECURITY else "coding")
                self.assertEqual((spec["model"], spec["models"]), ("qwen3-coder", ["qwen3-coder", "gemma-4"]))
                self.assertEqual(spec["respec"], ["python3", "/opt/solver/runtime.py", "engine", harness])
                self.assertEqual((spec["context_window"], spec["max_output"]), (32768, 4096))
                self.assertEqual((spec["base_url"], spec["api_key"]), (profiles.BASE, profiles.LOCAL_KEY))
                self.assertEqual(spec["cwd"], str(self.work))
                self.assertEqual(spec["reach"], {"mode": "inference", "sites": [], "targets": []})
                self.assertEqual(spec["secret_env"], {})
                env = spec["env"]
                self.assertEqual(env["HOME"], str(self.home))
                self.assertIn("/opt/solver/tool/bin", env["PATH"].split(":"))
                self.assertIn("/usr/local/bin", env["PATH"].split(":"))
                # Only the loopback relay is a provider; no host credentials pass through.
                for name, value in env.items():
                    self.assertFalse(value.startswith("sk-"), name)
                self.assertTrue(spec["state_dir"].startswith(str(self.home)))

    def test_our_own_engine_keeps_its_state_and_switches_in_place(self):
        spec = self.spec("yougori")
        self.assertEqual((spec["protocol"], spec["profile"], spec["argv"]), ("native", "yougori", []))
        self.assertEqual(spec["state_dir"], str(self.home / ".yougori/state"))
        self.assertEqual(spec["env"]["LANG"], "C.UTF-8")
        self.assertEqual(spec["env"]["TERM"], "xterm-256color")

    def test_terminal_harnesses_start_exactly_as_their_terminal_clients(self):
        for harness in sorted(profiles.SECURITY):
            with self.subTest(harness=harness):
                spec = self.spec(harness)
                argv, env = profiles.configure(harness, "qwen3-coder", CATALOG, self.home)
                self.assertEqual((spec["argv"], spec["env"]), (argv, env))

    def test_dsh_sessions_take_the_model_from_their_own_acp_row(self):
        spec = self.spec("deepseek")
        self.assertEqual(spec["argv"][:3], ["dsh", "acp", "--patch"])
        rows = json.loads(Path(spec["argv"][3]).read_text(encoding="utf-8"))
        self.assertIn({"id": "acp", "config": {"provider": "solver", "model": "qwen3-coder"}}, rows)
        self.assertIn({"id": "deepseek-account", "disabled": True}, rows)
        self.assertEqual(spec["env"]["DSH_TELEMETRY_DISABLED"], "1")
        # The terminal client's own patch is unchanged.
        self.assertNotIn("acp", [row["id"] for row in json.loads((self.home / ".dsh/solver.patch.yml").read_text(encoding="utf-8"))])

    def test_openhands_writes_its_settings_with_its_own_code(self):
        ran = Ran()
        spec = self.spec("openhands", run=ran)
        (argv, options), = ran.calls
        self.assertEqual(argv[:3], ["/opt/solver/tool/bin/python", "-I", "-c"])
        self.assertEqual(argv[4:7], ["openai/qwen3-coder", profiles.LOCAL_KEY, profiles.BASE])
        self.assertEqual(argv[7], str(self.home / ".openhands/agent_settings.json"))
        self.assertEqual(options["env"]["HOME"], str(self.home))
        self.assertNotIn("LLM_MODEL", spec["env"])
        self.assertEqual(spec["env"]["OPENHANDS_SUPPRESS_BANNER"], "1")
        with self.assertRaisesRegex(ValueError, "OpenHands could not write its settings: no module"):
            self.spec("openhands", run=Ran(returncode=1, stderr="no module"))

    def test_cline_saves_the_relay_provider_and_names_it_in_acp_mode(self):
        ran = Ran()
        spec = self.spec("cline", run=ran)
        (argv, _), = ran.calls
        self.assertEqual(argv[1:], ["auth", "--provider", "openai", "--baseurl", profiles.BASE, "--apikey", profiles.LOCAL_KEY,
                                    "--modelid", "qwen3-coder"])
        self.assertEqual(spec["argv"][1:], ["--acp", "--config", str(self.home / ".cline")])
        self.assertEqual((spec["env"]["CLINE_PROVIDER"], spec["env"]["CLINE_MODEL"]), ("openai-compatible", "qwen3-coder"))

    def test_the_practice_app_starts_first_and_becomes_the_target(self):
        for harness in ("pentestgpt", "hexstrike"):
            with self.subTest(harness=harness):
                spec = self.spec(harness, {"target": "practice", "depth": "safe"})
                self.assertEqual(spec["services"][0], profiles.PRACTICE_SERVICE)
                self.assertEqual(spec["answers"], {"target": "http://127.0.0.1:8000", "practice": True, "depth": "safe"})
        # An outside target needs the permission answer; with it, no practice app is added.
        spec = self.spec("hexstrike", {"target": "https://shop.example.test", "permission": True})
        self.assertEqual((spec["services"], spec["answers"]["target"]), ([], "https://shop.example.test"))
        # The shared helper keeps a harness's own services after the app, once.
        shared = {"answers": {"target": "practice"}, "services": [{"name": "server", "argv": ["x"]}]}
        profiles.practice_target(profiles.practice_target(shared))
        self.assertEqual([s["name"] for s in shared["services"]], ["practice-app", "server"])
        coding = self.spec("opencode", {"target": "practice"})
        self.assertEqual((coding["services"], coding["answers"]), ([], {"target": "practice"}))

    def test_reach_and_proxies_come_from_the_vm(self):
        os.environ["SOLVER_REACH"] = json.dumps({"mode": "sites", "sites": ["https://docs.rs", 3], "targets": []})
        os.environ["HTTPS_PROXY"] = "http://127.0.0.1:8091"
        os.environ["NO_PROXY"] = "127.0.0.1,localhost"
        spec = self.spec("yougori")
        self.assertEqual(spec["reach"], {"mode": "sites", "sites": ["https://docs.rs"], "targets": []})
        self.assertEqual((spec["env"]["HTTPS_PROXY"], spec["env"]["NO_PROXY"]), ("http://127.0.0.1:8091", "127.0.0.1,localhost"))
        self.assertEqual(profiles.reach_of("not json")["mode"], "inference")
        self.assertEqual(profiles.reach_of('{"mode": "everything"}')["mode"], "inference")
        given = self.spec("opencode", reach={"mode": "full", "sites": [], "targets": []})
        self.assertEqual(given["reach"]["mode"], "full")

    def test_a_harness_without_an_entry_or_a_model_outside_the_catalog_is_refused(self):
        # Every catalogue harness has an entry now (the bridges added aider, interpreter, swe and plandex).
        with self.assertRaisesRegex(ValueError, "not-a-harness cannot run in the Yougori harness yet"):
            self.spec("not-a-harness")
        with self.assertRaisesRegex(ValueError, r"^The model other is not available on this server right now\."):
            profiles.headless("opencode", "other", CATALOG, self.home, {}, cwd=self.work)

    def test_configure_is_unchanged_for_the_terminal_clients(self):
        argv, env = profiles.configure("opencode", "qwen3-coder", CATALOG, self.home)
        self.assertEqual(argv, ["opencode", "--pure", "--model", "solver/qwen3-coder"])
        self.assertEqual(env["OPENCODE_DISABLE_MODELS_FETCH"], "true")
        self.assertEqual({k: env[k] for k in profiles.environment(self.home)}, profiles.environment(self.home))


class Runtime(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp())
        self.clean = patch.dict(os.environ, {}, clear=False)
        self.clean.start()
        os.environ.pop("SOLVER_REACH", None)

    def tearDown(self):
        self.clean.stop()

    def test_answers_and_reach_are_read_when_present(self):
        self.assertEqual(runtime.answers(self.home), {})
        (self.home / ".yougori").mkdir()
        (self.home / ".yougori/answers.json").write_text('{"target": "practice"}', encoding="utf-8")
        self.assertEqual(runtime.answers(self.home), {"target": "practice"})
        self.assertEqual(runtime.reach(self.home)["mode"], "inference")
        runtime.write_spec({"harness": "x", "reach": {"mode": "targets", "targets": ["10.0.0.5:443"]}}, self.home)
        self.assertEqual(runtime.reach(self.home), {"mode": "targets", "sites": [], "targets": ["10.0.0.5:443"]})
        os.environ["SOLVER_REACH"] = '{"mode": "full"}'
        self.assertEqual(runtime.reach(self.home)["mode"], "full")

    @unittest.skipIf(os.name == "nt", "file modes are POSIX")
    def test_the_spec_is_private(self):
        path = runtime.write_spec({"harness": "x"}, self.home)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_the_harness_gets_only_the_screen_variables_and_the_secrets(self):
        os.environ.update({"PATH": "/usr/bin", "HOME": "/home/node", "TERM": "xterm", "SOLVER_MODEL": "m",
                           "YOUGORI_SECRET_PASSWORD": "pw", "HTTPS_PROXY": "http://p", "NO_COLOR": "1"})
        env = runtime.harness_environment()
        self.assertEqual(env.get("YOUGORI_SECRET_PASSWORD"), "pw")
        self.assertNotIn("SOLVER_MODEL", env)
        self.assertNotIn("HTTPS_PROXY", env)
        self.assertEqual(env["TERM"], "xterm")
        # The guest says when the person's terminal shows no colour; the harness's screen must hear it.
        self.assertEqual(env["NO_COLOR"], "1")

    def test_engine_prints_a_fresh_spec_for_another_model(self):
        printed = []
        with patch.object(runtime, "HOME", str(self.home)), \
             patch.object(runtime, "wait_for_catalog", return_value=CATALOG), \
             patch.object(runtime.sys.stdout, "write", printed.append):
            runtime.engine("pi", "gemma-4")
        spec = json.loads("".join(printed))
        self.assertEqual((spec["harness"], spec["model"], spec["protocol"]), ("pi", "gemma-4", "pi-rpc"))
        self.assertIn("gemma-4", spec["argv"])

    def test_deepseek_alone_names_commands_that_take_its_task(self):
        """DeepSeek started alone told people to run `yougori inference run deepseek -- --print`,
        which the command refuses: it takes HARNESS and --server URL and passes nothing after --
        (cli/src/inference.rs, options and permissions)."""
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        root = Path(folder.name)

        def start(*arguments):
            """`runtime.py run deepseek ARGUMENTS` in the VM: what it starts, its settings in `root`."""
            with patch.object(runtime, "claim_terminal"), patch.object(runtime, "wait_for_catalog", return_value=CATALOG), \
                    patch.object(runtime, "configure", side_effect=lambda h, m, c, r: profiles.configure(h, m, c, root / "home")), \
                    patch.object(runtime.blue, "run", return_value=0) as started, patch.dict(os.environ, {"SOLVER_MODEL": "qwen3-coder"}), \
                    patch.object(runtime.sys, "argv", ["runtime.py", "run", "deepseek", *arguments]):
                self.assertEqual(runtime.run("deepseek"), 0)
            return started.call_args[0][0]
        with self.assertRaises(ValueError) as refused:
            start()
        self.assertEqual(str(refused.exception), runtime.DEEPSEEK_ONE_TASK)
        for message in (runtime.DEEPSEEK_ONE_TASK, runtime.PENTESTGPT_INTERACTIVE):
            command, = re.findall(r"yougori inference run [^.]+", message)
            self.assertEqual(command.split()[4:], ["--server", "URL"], message)
        # The source setup's command, as named, takes the task through the launcher (the website
        # from the downloaded folder's connection.json) to DeepSeek's headless profile in the VM.
        argv = shlex.split(re.search(r'python solver\.py run deepseek -- --print "[^"]+"', runtime.DEEPSEEK_ONE_TASK)[0])
        setup, keys = root / "setup", root / "keys"
        (keys / "deepseek").mkdir(parents=True)
        (keys / "deepseek/api-key").write_text("is_test-key")
        setup.mkdir()
        (setup / "connection.json").write_text(json.dumps({"server": "http://127.0.0.1:9", "harness": "deepseek"}))
        launched = []
        with patch.object(sys, "argv", argv[1:]), patch.object(solver, "HERE", setup), patch.object(solver, "profile", lambda server: keys), \
                patch.object(solver, "private_folder", lambda path: path.mkdir(parents=True, exist_ok=True)), \
                patch.object(vm_host, "preflight", lambda name, server, held=False: None), \
                patch.object(solver, "models", lambda server, key: [{"id": "qwen3-coder"}]), \
                patch.object(solver, "launch", lambda *given, **options: launched.append(given) or 0), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(solver.main(), 0)
        (harness, _, _, model, _, arguments, *_), = launched
        self.assertEqual((harness, model, arguments), ("deepseek", "qwen3-coder", ["--print", "your task"]))
        command = start(*arguments)
        self.assertEqual((command[:2], command[-1]), (["dsh", "headless"], "your task"))


if __name__ == "__main__":
    unittest.main()
