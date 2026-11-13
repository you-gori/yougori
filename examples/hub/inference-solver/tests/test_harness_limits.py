"""What each harness is told of its model's limits (profiles.py): the window and the reply budget
the catalog gives the chosen model, else the window Yougori's model servers serve and the longest
reply the website's relay passes on. And that Yougori's setup files stay out of git's view in the VM,
so no harness counts them among its changes, and out of the copy of the folder once the session
has ended (vm_guest.py), so the person's review lists only what the harness changed. A temporary
home and workspace and the real git; no harness runs.

Run: python -I -m unittest discover -s examples/hub/inference-solver/tests -p test_harness_limits.py
"""
import base64
import http.client
from http.server import ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import tomllib
import types
import unittest
from unittest.mock import patch
import warnings

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS.parent / "site"))
sys.path.insert(0, str(TESTS.parent / "site/harnesses"))
# vm_guest runs in the Linux VM; its terminal modules are not needed for what these tests check.
for linux_only in ("fcntl", "pty", "termios"):
    sys.modules.setdefault(linux_only, types.ModuleType(linux_only))
import gateway  # noqa: E402
import profiles  # noqa: E402
import runtime  # noqa: E402
import vm_guest  # noqa: E402
import vm_host  # noqa: E402
from bridges import aider_acp, swe_acp  # noqa: E402
from test_routing import yougori_model_server  # noqa: E402

# Two models the catalog does not size (Gemini CLI knows the second by name) and one it does.
CATALOG = [{"id": "qwen3-coder"}, {"id": "gemma-4-26b-a4b-it"},
           {"id": "sized", "context_length": 65536, "max_completion_tokens": 2048}]
SIZES = {"qwen3-coder": (32768, 4096), "gemma-4-26b-a4b-it": (32768, 4096), "sized": (65536, 2048)}
SETUP_PACKAGE = TESTS.parents[3] / "appliance/agent/setupkit/install.go"


class Ran:
    """Stands in for subprocess.run where a harness's own code writes its settings: records each
    command and runs `then` on it."""

    def __init__(self, then=None):
        self.calls, self.then = [], then

    def __call__(self, argv, **options):
        self.calls.append(argv)
        if self.then:
            self.then(argv)
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")


class Limits(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.home, True)
        self.clean = patch.dict(os.environ, {}, clear=False)
        self.clean.start()
        self.addCleanup(self.clean.stop)
        for name in profiles.PASSED_ON + ("SOLVER_REACH",):
            os.environ.pop(name, None)

    def read(self, name):
        return (self.home / name).read_text(encoding="utf-8")

    def test_the_defaults_are_those_of_the_relay_and_of_yougoris_model_server(self):
        self.assertEqual(profiles.REPLY_TOKENS, gateway.REPLY_TOKENS)
        server = yougori_model_server()
        body = {"model": "test/one", "messages": [{"role": "user", "content": "hi"}]}
        server.validate_chat({**body, "max_completion_tokens": profiles.REPLY_TOKENS})
        with self.assertRaises(server.RequestLimit):
            server.validate_chat({**body, "max_completion_tokens": profiles.REPLY_TOKENS + 1})
        backends = (TESTS.parents[3] / "src-tauri/src/model_runner/engine_backends.py").read_text(encoding="utf-8")
        # llama.cpp's window as the engine starts it when the owner chose none (model optimize --context).
        self.assertIn('"-c", str(window)', backends)
        self.assertIn('return %d' % profiles.CONTEXT_WINDOW, backends.split("def llama_window(", 1)[1].split("\ndef ", 1)[0])

    def test_a_models_window_and_reply_budget_are_what_its_catalog_entry_gives(self):
        self.assertEqual(profiles.limits("qwen3-coder", CATALOG), (32768, 4096))
        self.assertEqual(profiles.limits("sized", CATALOG), (65536, 2048))
        for name in profiles.WINDOW_FIELDS:
            self.assertEqual(profiles.limits("m", [{"id": "m", name: 131072}]), (131072, 4096), name)
        for name in profiles.REPLY_FIELDS:
            self.assertEqual(profiles.limits("m", [{"id": "m", name: 1000}]), (32768, 1000), name)
        # Never more reply than the relay passes on, nor more than a quarter of the window.
        self.assertEqual(profiles.limits("m", [{"id": "m", "max_completion_tokens": 32768}]), (32768, 4096))
        self.assertEqual(profiles.limits("m", [{"id": "m", "context_length": 8192}]), (8192, 2048))
        # What is not a window in tokens is no window.
        for wrong in (100, 2097152, "65536", 65536.0, True, None):
            self.assertEqual(profiles.limits("m", [{"id": "m", "context_length": wrong}]), (32768, 4096), repr(wrong))
        for wrong in (0, -5, "2048", 2048.0, True):
            self.assertEqual(profiles.limits("m", [{"id": "m", "max_output_tokens": wrong}]), (32768, 4096), repr(wrong))

    def test_each_harness_is_told_its_models_window_and_reply_budget(self):
        for model, (window, reply) in SIZES.items():
            with self.subTest(model=model):
                self.check_told(model, window, reply)

    def check_told(self, model, window, reply):
        home = self.home / model.replace("/", "-")
        read = lambda name: (home / name).read_text(encoding="utf-8")
        configure = lambda harness: profiles.configure(harness, model, CATALOG, home)
        listed = lambda entry: SIZES[entry]
        # dsh asked max_completion_tokens 32768 and planned for 262,144 tokens.
        argv, _ = configure("deepseek")
        rows = json.loads(Path(argv[-1]).read_text(encoding="utf-8"))
        models = next(row for row in rows if row["id"] == "llm-pi-ai")["config"]["providers"]["solver"]["models"]
        self.assertEqual(models, [{"id": item["id"], "contextWindow": SIZES[item["id"]][0], "maxTokens": SIZES[item["id"]][1]}
                                  for item in CATALOG])
        spec = profiles.headless("deepseek", model, CATALOG, home, run=Ran())
        rows = json.loads(Path(spec["argv"][-1]).read_text(encoding="utf-8"))
        self.assertEqual(next(row for row in rows if row["id"] == "llm-pi-ai")["config"]["providers"]["solver"]["models"], models)
        for harness in ("opencode", "kilo"):
            configure(harness)
            told = json.loads(read(f".config/{harness}/{harness}.json"))["provider"]["solver"]["models"]
            self.assertEqual({mid: (entry["limit"]["context"], entry["limit"]["output"]) for mid, entry in told.items()},
                             {mid: listed(mid) for mid in SIZES}, harness)
        configure("codex")
        self.assertEqual({entry["slug"]: entry["context_window"] for entry in json.loads(read(".codex/solver-models.json"))["models"]},
                         {mid: listed(mid)[0] for mid in SIZES})
        # Claude Code asked 32,000 of a model it does not know and planned for 200,000.
        _, env = configure("claude")
        told = (env["CLAUDE_CODE_MAX_OUTPUT_TOKENS"], env["CLAUDE_CODE_MAX_CONTEXT_TOKENS"])
        self.assertEqual(told, (str(reply), str(window)))
        env = profiles.headless("claude", model, CATALOG, home, run=Ran())["env"]
        self.assertEqual((env["CLAUDE_CODE_MAX_OUTPUT_TOKENS"], env["CLAUDE_CODE_MAX_CONTEXT_TOKENS"]), told)
        configure("pi")
        self.assertEqual({entry["id"]: (entry["contextWindow"], entry["maxTokens"])
                          for entry in json.loads(read(".pi/agent/models.json"))["providers"]["solver"]["models"]},
                         {mid: listed(mid) for mid in SIZES})
        # Qwen Code planned for 200,000 tokens (16,700 tokens showed as 8%).
        configure("qwen")
        self.assertEqual({entry["id"]: entry["generationConfig"] for entry in json.loads(read(".qwen/settings.json"))["modelProviders"]["openai"]},
                         {mid: {"contextWindowSize": listed(mid)[0]} for mid in SIZES})
        configure("aider")
        cache = json.loads(read(".aider/caches/model_prices_and_context_window.json"))
        self.assertEqual({key: (entry["max_input_tokens"], entry["max_output_tokens"]) for key, entry in cache.items()},
                         {"openai/" + mid: listed(mid) for mid in SIZES})
        argv, _ = configure("interpreter")
        self.assertEqual(argv[-4:], ["--context_window", str(window), "--max_tokens", str(reply)])
        bridge = profiles.headless("interpreter", model, CATALOG, home, run=Ran())["argv"]
        self.assertEqual(bridge[bridge.index("--context-window") + 1:bridge.index("--max-output") + 2],
                         [str(window), "--max-output", str(reply)])
        self.assertEqual(bridge[-4:], argv[-4:], "the bridge reads the terminal client's own options")
        argv, _ = configure("swe")
        self.assertEqual(argv[argv.index("--agent.model.max_input_tokens") + 1], str(window))
        # Goose planned for 128,000 tokens.
        _, env = configure("goose")
        self.assertEqual((env["GOOSE_CONTEXT_LIMIT"], env["GOOSE_MAX_TOKENS"]), (str(window), str(reply)))
        config = json.loads(read(".config/goose/config.yaml"))  # JSON, which YAML reads
        self.assertEqual((config["GOOSE_CONTEXT_LIMIT"], config["GOOSE_MAX_TOKENS"]), (window, reply))
        configure("grok")
        solver = tomllib.loads(read(".grok/config.toml"))["model"]["solver"]
        self.assertEqual((solver["max_completion_tokens"], solver["context_window"]), (reply, window))
        _, env = configure("strix")
        self.assertEqual((env["STRIX_CONTEXT_FALLBACK_TOKENS"], env["STRIX_CONTEXT_BUFFER_TOKENS"], env["STRIX_CONTEXT_SUMMARY_TOKENS"]),
                         (str(window), str(2 * reply), str(reply)))
        argv, _ = configure("shannon")
        self.assertEqual(argv[4:], ["--context-budget", str(window), "--max-output", str(reply)])
        argv, _ = configure("plandex")
        self.assertEqual(argv[4:], ["--context-budget", str(window)])
        # PentAGI's custom provider asked 16,384 tokens of reply for every agent.
        argv, _ = configure("pentagi")
        self.assertEqual(argv[4:], ["--max-output", str(reply)])
        argv, _ = configure("pentestgpt")
        self.assertEqual(argv[:5], ["/opt/solver/tool/bin/python", "-I", "-c", profiles.PENTESTGPT_WINDOW, str(window)])
        self.assertEqual(self.openhands_llm(model, home)[-2:], (window, reply))
        self.assertEqual(self.cline_settings(model, home)[:2], (window, reply))
        # Gemini CLI compresses at half of the window it knows for the model.
        configure("gemini")
        share = json.loads(read(".gemini/settings.json"))["model"]["compressionThreshold"]
        known = 256000 if model == "gemma-4-26b-a4b-it" else 1048576
        self.assertAlmostEqual(share * known, window / 2)
        for harness in profiles.HEADLESS:
            spec = profiles.headless(harness, model, CATALOG, home, run=Ran())
            self.assertEqual((spec["context_window"], spec["max_output"]), (window, reply), harness)

    def test_a_window_beyond_what_a_launcher_or_gemini_takes_is_held_to_it(self):
        catalog = [{"id": "gemma-4-26b-a4b-it", "context_length": 1048576}]
        for harness in ("shannon", "plandex"):
            argv, _ = profiles.configure(harness, "gemma-4-26b-a4b-it", catalog, self.home)
            self.assertEqual(argv[argv.index("--context-budget") + 1], str(profiles.LAUNCHER_WINDOW), harness)
        profiles.configure("gemini", "gemma-4-26b-a4b-it", catalog, self.home)
        self.assertEqual(json.loads(self.read(".gemini/settings.json"))["model"]["compressionThreshold"], profiles.GEMINI_SHARE,
                         "never later than Gemini CLI's own default")

    def openhands_llm(self, model, home):
        """What OpenHands's own LLM gets from the settings script headless() runs (its SDK faked):
        model, key, base URL, window and reply budget."""
        ran = Ran()
        profiles.headless("openhands", model, CATALOG, home, run=ran)
        (argv,) = ran.calls
        self.assertEqual(argv[:4], ["/opt/solver/tool/bin/python", "-I", "-c", profiles.OPENHANDS_SETTINGS])

        class Agent:
            def __init__(self, llm):
                self.llm = llm

            def model_dump_json(self, context):
                return json.dumps(self.llm)

        sdk, cli = types.ModuleType("openhands.sdk"), types.ModuleType("openhands_cli.utils")
        sdk.LLM = lambda **options: options
        cli.get_default_cli_agent = lambda llm: Agent(llm)
        with patch.dict(sys.modules, {"openhands": types.ModuleType("openhands"), "openhands.sdk": sdk,
                                      "openhands_cli": types.ModuleType("openhands_cli"), "openhands_cli.utils": cli}), \
                patch.object(sys, "argv", ["-c", *argv[4:]]), warnings.catch_warnings():
            # The one-line script leaves its file to be closed when it ends, as `python -c` does.
            warnings.simplefilter("ignore", ResourceWarning)
            exec(profiles.OPENHANDS_SETTINGS, {})
        llm = json.loads(Path(argv[7]).read_text(encoding="utf-8"))
        self.assertEqual({key: llm[key] for key in ("model", "api_key", "base_url", "usage_id")},
                         {"model": "openai/" + model, "api_key": profiles.LOCAL_KEY, "base_url": profiles.BASE, "usage_id": "agent"})
        return llm["model"], llm["max_input_tokens"], llm["max_output_tokens"]

    def cline_settings(self, model, home):
        """The relay's provider as Cline saved it (its auth command, faked as Cline 3.0.74 writes
        data/settings/providers.json), once the Yougori harness has started it."""
        def auth(argv):
            path = Path(argv[argv.index("--config") + 1] if "--config" in argv else home / ".cline") / "data/settings/providers.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({"version": 1, "lastUsedProvider": "openai-compatible", "modes": {}, "providers": {
                "openai-compatible": {"settings": {"provider": "openai-compatible", "apiKey": profiles.LOCAL_KEY,
                                                   "model": model, "baseUrl": profiles.BASE},
                                      "updatedAt": "2026-11-13T04:00:00.000Z", "tokenSource": "manual"}}}), encoding="utf-8")
        profiles.headless("cline", model, CATALOG, home, run=Ran(auth))
        stored = json.loads((home / ".cline/data/settings/providers.json").read_text(encoding="utf-8"))
        settings = stored["providers"]["openai-compatible"]["settings"]
        return settings["contextWindow"], settings["maxTokens"], stored

    def test_cline_keeps_what_its_auth_saved_and_gets_the_window_only_on_the_relays_entry(self):
        config = self.home / ".cline"
        path = config / "data/settings/providers.json"
        self.assertFalse(profiles.cline_limits(config, 65536, 2048), "nothing saved yet")
        path.parent.mkdir(parents=True)
        saved = {"version": 1, "lastUsedProvider": "openai-compatible", "modes": {}, "providers": {
            "openai-compatible": {"settings": {"provider": "openai-compatible", "model": "sized", "baseUrl": profiles.BASE + "/"},
                                  "updatedAt": "2026-11-13T04:00:00.000Z", "tokenSource": "manual"},
            "anthropic": {"settings": {"provider": "anthropic", "baseUrl": "https://api.anthropic.com"},
                          "updatedAt": "2026-11-13T04:00:00.000Z", "tokenSource": "manual"}}}
        path.write_text(json.dumps(saved), encoding="utf-8")
        self.assertTrue(profiles.cline_limits(config, 65536, 2048))
        stored = json.loads(path.read_text(encoding="utf-8"))
        saved["providers"]["openai-compatible"]["settings"].update(contextWindow=65536, maxTokens=2048)
        self.assertEqual(stored, saved)
        self.assertEqual(sorted(p.name for p in path.parent.iterdir()), ["providers.json"])
        if os.name != "nt":
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        for other in ("not json", json.dumps([1]), json.dumps({"providers": [1]}), json.dumps({"providers": {"x": {"settings": 1}}})):
            path.write_text(other, encoding="utf-8")
            self.assertFalse(profiles.cline_limits(config, 65536, 2048))
            self.assertEqual(path.read_text(encoding="utf-8"), other)
        # Its terminal client (runtime.py run cline) gets the same.
        with patch.object(runtime, "HOME", str(self.home)), patch.object(runtime, "claim_terminal"), \
                patch.object(runtime, "wait_for_catalog", return_value=CATALOG), \
                patch.object(runtime.subprocess, "run", side_effect=lambda argv, **_: path.write_text(json.dumps(
                    {"version": 1, "modes": {}, "providers": {"openai-compatible": {"settings": {"baseUrl": profiles.BASE}}}}),
                    encoding="utf-8")), \
                patch.object(runtime.blue, "run", return_value=0), patch.dict(os.environ, {"SOLVER_MODEL": "sized"}), \
                patch.object(runtime.sys, "argv", ["runtime.py", "run", "cline"]), \
                patch.object(runtime, "configure", side_effect=lambda h, m, c, r: profiles.configure(h, m, c, self.home)):
            self.assertEqual(runtime.run("cline"), 0)
        self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["providers"]["openai-compatible"]["settings"],
                         {"baseUrl": profiles.BASE, "contextWindow": 65536, "maxTokens": 2048})

    def test_pentestgpt_starts_with_its_models_window(self):
        """PentestGPT's legacy client trims every conversation to the 128,000 tokens it gives any
        ollama: model. PENTESTGPT_WINDOW starts it (its modules faked as they are at the pinned
        commit) with the model's window, its own arguments unchanged."""
        seen = []
        package, llm = types.ModuleType("pentestgpt_legacy"), types.ModuleType("pentestgpt_legacy.llm")
        factory, main = types.ModuleType("pentestgpt_legacy.llm.factory"), types.ModuleType("pentestgpt_legacy.main")
        exec("import dataclasses\n"
             "@dataclasses.dataclass(frozen=True)\n"
             "class ModelSpec:\n"
             "    id: str\n    provider: str\n    api_id: str\n    context_window: int\n"
             "def resolve(name):\n"
             "    if name.startswith('ollama:'):\n"
             "        return ModelSpec(id=name, provider='ollama', api_id=name[7:], context_window=128_000)\n"
             "    if name == 'gpt-5.5':\n"
             "        return ModelSpec(id=name, provider='openai', api_id=name, context_window=400_000)\n"
             "    return None\n"
             "def get_client(name):\n"
             "    return resolve(name)\n", factory.__dict__)
        llm.factory, package.llm = factory, llm

        def run():
            seen.append((list(sys.argv), [getattr(factory.get_client(name), "context_window", None)
                                          for name in ("ollama:sized", "gpt-5.5", "unknown")]))
        main.main = run
        argv, _ = profiles.configure("pentestgpt", "sized", CATALOG, self.home)
        self.assertEqual(argv[1:3], ["-I", "-c"], "the workspace stays off its import path")
        with patch.dict(sys.modules, {"pentestgpt_legacy": package, "pentestgpt_legacy.llm": llm,
                                      "pentestgpt_legacy.llm.factory": factory, "pentestgpt_legacy.main": main}), \
                patch.object(sys, "argv", ["-c", *argv[4:]]), self.assertRaises(SystemExit) as ended:
            exec(argv[3], {})
        self.assertIn(ended.exception.code, (None, 0))
        self.assertEqual(seen, [(["pentestgpt-legacy", *argv[5:]], [65536, 400_000, None])])
        self.assertEqual(argv[argv.index("--reasoning-model") + 1], "ollama:sized")

    def test_a_project_file_named_like_a_module_never_runs_in_its_place(self):
        """PentestGPT and OpenHands's settings script start as `python -c` in the workspace, which
        put the person's folder first on the import path: a project's dataclasses.py ran in place of
        the module that PENTESTGPT_WINDOW imports first. Each starts with the options its profile
        gives, run here by this Python, in a folder holding such a file."""
        project = self.home / "project"
        project.mkdir()
        (project / "dataclasses.py").write_text("raise SystemExit('the project file ran')\n", encoding="utf-8")
        ran = Ran()
        profiles.headless("openhands", "sized", CATALOG, self.home / "openhands", run=ran)
        started = {"pentestgpt": profiles.configure("pentestgpt", "sized", CATALOG, self.home)[0], "openhands": ran.calls[0]}
        for harness, argv in started.items():
            with self.subTest(harness=harness):
                options = argv[1:argv.index("-c")]
                done = subprocess.run([sys.executable, *options, "-c", "import dataclasses, sys; print(dataclasses.__file__)"],
                                      cwd=project, capture_output=True, text=True, timeout=60)
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertNotEqual(Path(done.stdout.strip()).parent.resolve(), project.resolve())


class Unavailable(unittest.TestCase):
    """A model that left the catalog after the VM started was refused as if never chosen: "Choose a
    model from this server's live catalog." (runs/matrix-try4/aider)."""

    def test_the_refusal_names_the_model_and_says_it_is_not_available_now(self):
        home = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, home, True)
        said = "The model gone/model-7B is not available on this server right now."
        for call in (lambda: profiles.configure("pi", "gone/model-7B", CATALOG, home),
                     lambda: profiles.headless("opencode", "gone/model-7B", CATALOG, home, run=Ran())):
            with self.assertRaises(ValueError) as refused:
                call()
            self.assertTrue(str(refused.exception).startswith(said), str(refused.exception))
            self.assertNotIn("live catalog", str(refused.exception))
        # runtime.py prints what it refuses and nothing else (sys.exit with the words).
        with patch.object(runtime, "HOME", str(home)), patch.object(runtime, "claim_terminal"), \
                patch.object(runtime, "wait_for_catalog", return_value=CATALOG), patch.dict(os.environ, {"SOLVER_MODEL": "gone/model-7B"}), \
                patch.object(runtime, "write_spec") as written, self.assertRaises(ValueError) as refused:
            runtime.run_yougori()
        self.assertTrue(str(refused.exception).startswith(said))
        written.assert_not_called()


class SetupFiles(unittest.TestCase):
    """The five files Yougori's setup package adds to every VM's workspace were listed in every review
    and in SWE-agent's patch as its changes."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        self.home, self.work = self.root / "home", self.root / "workspace"
        self.work.mkdir()
        self.clean = patch.dict(os.environ, {}, clear=False)
        self.clean.start()
        self.addCleanup(self.clean.stop)
        for name in profiles.PASSED_ON + ("SOLVER_REACH", "XDG_CONFIG_HOME"):
            os.environ.pop(name, None)

    def git(self, *args, env=None):
        """git in the workspace as a harness in the VM runs it: the harness's home, no system settings."""
        clean = {name: value for name, value in os.environ.items() if not name.startswith("GIT_")}
        clean.update(env or {}, GIT_CONFIG_NOSYSTEM="1", GIT_AUTHOR_NAME="Person", GIT_AUTHOR_EMAIL="person@example.invalid",
                     GIT_COMMITTER_NAME="Person", GIT_COMMITTER_EMAIL="person@example.invalid")
        done = subprocess.run(["git", "-C", str(self.work), *args], env=clean, capture_output=True, text=True, timeout=60)
        self.assertEqual(done.returncode, 0, done.stderr)
        return done.stdout

    def setup_package(self):
        """Writes the setup package's files into the workspace, as `setup init` does at each launch."""
        for name in profiles.SETUP_FILES:
            (self.work / name).parent.mkdir(parents=True, exist_ok=True)
            (self.work / name).write_text("// Yougori setup package: " + name + "\n", encoding="utf-8")

    def files(self):
        return sorted(path.relative_to(self.work).as_posix() for path in self.work.rglob("*")
                      if path.is_file() and ".git" not in path.relative_to(self.work).parts)

    def test_the_names_are_those_the_setup_package_writes_and_the_launcher_knows(self):
        written = re.findall(r'"sdk/[^"]+":\s*"([^"]+)"|"SKILL\.md":\s*"([^"]+)"', SETUP_PACKAGE.read_text(encoding="utf-8"))
        self.assertEqual(set(profiles.SETUP_FILES), {first or second for first, second in written})
        self.assertEqual(set(profiles.SETUP_FILES), vm_host.SETUP_FILES)
        self.assertEqual(vm_guest.SETUP_FILES, profiles.SETUP_FILES)

    def test_every_harness_has_git_leave_the_setup_files_out_and_writes_nothing_in_the_workspace(self):
        expected = ["/" + name for name in profiles.SETUP_FILES]
        for harness in profiles.HEADLESS:
            with self.subTest(harness=harness):
                spec = profiles.headless(harness, "qwen3-coder", CATALOG, self.home, cwd=self.work, run=Ran())
                self.assertEqual(spec["env"]["XDG_CONFIG_HOME"], str(self.home / ".config"))
                rules = (self.home / ".config/git/ignore").read_text(encoding="utf-8").splitlines()
                if harness == "aider":
                    expected = expected + ["/.aider*"]  # Aider's own files' names (test_aiders_own_files_stay_in_its_home).
                self.assertEqual(rules, expected, "each once, however often the spec is written")
                self.assertEqual(list(self.work.iterdir()), [])
        # The terminal clients' settings (runtime.py run) too.
        terminal = self.root / "terminal-home"
        profiles.configure("aider", "qwen3-coder", CATALOG, terminal)
        self.assertEqual((terminal / ".config/git/ignore").read_text(encoding="utf-8").splitlines(),
                         ["/" + name for name in profiles.SETUP_FILES] + ["/.aider*"])

    def test_a_harness_sees_its_own_changes_and_not_the_setup_files(self):
        self.git("init", "-q")
        (self.work / "app.py").write_text("print('app')\n", encoding="utf-8")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "The person's project")
        self.setup_package()
        (self.work / "fix.py").write_text("print('fixed')\n", encoding="utf-8")
        (self.work / "app.py").write_text("print('changed')\n", encoding="utf-8")
        # Without the harness's home git sees all five, as SWE-agent's `git add -A` did.
        bare = {"HOME": str(self.root / "elsewhere"), "XDG_CONFIG_HOME": str(self.root / "elsewhere/.config")}
        self.assertEqual(len(self.git("status", "--porcelain", "--untracked-files=all", env=bare).splitlines()), 7)
        profiles.headless("swe", "qwen3-coder", CATALOG, self.home, cwd=self.work, run=Ran())
        home = {"HOME": str(self.home), "XDG_CONFIG_HOME": str(self.home / ".config")}
        self.assertEqual(sorted(self.git("status", "--porcelain", "--untracked-files=all", env=home).splitlines()), [" M app.py", "?? fix.py"])
        self.git("add", "-A", env=home)
        self.assertEqual(self.git("diff", "--cached", "--name-only", env=home).split(), ["app.py", "fix.py"])
        # A project's own yougori.py, tracked, still shows its changes.
        self.git("add", "-f", "yougori.py", env=home)
        self.git("commit", "-q", "-m", "Its own yougori.py", env=home)
        (self.work / "yougori.py").write_text("print('mine')\n", encoding="utf-8")
        self.assertIn(" M yougori.py", self.git("status", "--porcelain", env=home).splitlines())

    def test_swe_agents_reports_stay_out_beside_them_and_the_repository_is_untouched(self):
        self.git("init", "-q")
        exclude = (self.work / ".git/info/exclude").read_bytes()
        profiles.headless("swe", "qwen3-coder", CATALOG, self.home, cwd=self.work, run=Ran())
        with patch.dict(os.environ, {"XDG_CONFIG_HOME": str(self.home / ".config")}):
            swe_acp.keep_reports_out(str(self.work))
            swe_acp.keep_reports_out(str(self.work))
        rules = (self.home / ".config/git/ignore").read_text(encoding="utf-8").splitlines()
        self.assertEqual(rules, ["/" + name for name in profiles.SETUP_FILES] + ["/reports/swe-agent/"])
        self.assertEqual((self.work / ".git/info/exclude").read_bytes(), exclude, "the review lists no .git/info/exclude")
        (self.work / "reports/swe-agent").mkdir(parents=True)
        (self.work / "reports/swe-agent/summary.md").write_text("# Run\n", encoding="utf-8")
        self.setup_package()
        home = {"HOME": str(self.home), "XDG_CONFIG_HOME": str(self.home / ".config")}
        self.assertEqual(self.git("status", "--porcelain", "--untracked-files=all", env=home), "")
        # Outside a Yougori VM (no XDG_CONFIG_HOME) the repository's own exclude file, as before.
        swe_acp.keep_reports_out(str(self.work))
        self.assertIn("/reports/swe-agent/", (self.work / ".git/info/exclude").read_text(encoding="utf-8").splitlines())

    def test_aiders_own_files_stay_in_its_home(self):
        """After an Aider session the review listed Aider's chat history, its repo map's tags cache
        (.aider.tags.cache.v4: an SQLite file and its -shm and -wal) and the .gitignore Aider wrote for
        them (runs/r2/aider). Aider keeps them in its home now: its histories by its own options, its
        tags cache where AIDER_START and the bridge point Aider's RepoMap; and git, which Aider asks,
        ignores .aider*, so Aider adds nothing to the project's .gitignore for them."""
        argv, env = profiles.configure("aider", "qwen3-coder", CATALOG, self.home)
        own = self.home / profiles.AIDER_FILES
        config = json.loads(Path(argv[argv.index("--config") + 1]).read_text(encoding="utf-8"))
        self.assertEqual((config["chat-history-file"], config["input-history-file"]),
                         (str(own / "chat.history.md"), str(own / "input.history")))
        self.assertEqual(env["SOLVER_AIDER_FILES"], str(own))
        # Its own client starts as the `aider` command does, with the tags cache moved (aider faked).
        self.assertEqual(argv[:4], [profiles.BRIDGE_PYTHON, "-I", "-c", profiles.AIDER_START])

        class RepoMap:
            TAGS_CACHE_DIR = ".aider.tags.cache.v4"
        repomap, main, seen = types.ModuleType("aider.repomap"), types.ModuleType("aider.main"), []
        repomap.RepoMap = RepoMap
        main.main = lambda: seen.append((list(sys.argv), RepoMap.TAGS_CACHE_DIR)) or 0
        aider = {"aider": types.ModuleType("aider"), "aider.repomap": repomap, "aider.main": main}
        with patch.dict(sys.modules, aider), patch.dict(os.environ, env), patch.object(sys, "argv", ["-c", *argv[4:]]), \
                self.assertRaises(SystemExit) as ended:
            exec(argv[3], {})
        self.assertIn(ended.exception.code, (None, 0))
        cache = str(own / ".aider.tags.cache.v4")
        self.assertEqual(seen, [(["aider", *argv[4:]], cache)])
        # Aider joins it to the project's folder (repomap.py: Path(self.root) / self.TAGS_CACHE_DIR).
        self.assertEqual(self.work / RepoMap.TAGS_CACHE_DIR, Path(cache))
        # The bridge does the same in its own process, however often; nothing without the profile's folder.
        RepoMap.TAGS_CACHE_DIR = ".aider.tags.cache.v4"
        with patch.dict(sys.modules, aider):
            with patch.dict(os.environ, env):
                aider_acp.tags_cache_home()
                aider_acp.tags_cache_home()
            self.assertEqual(RepoMap.TAGS_CACHE_DIR, cache)
            RepoMap.TAGS_CACHE_DIR = ".aider.tags.cache.v4"
            with patch.dict(os.environ, {"SOLVER_AIDER_FILES": ""}):
                aider_acp.tags_cache_home()
            self.assertEqual(RepoMap.TAGS_CACHE_DIR, ".aider.tags.cache.v4")
        for path in (config["chat-history-file"], config["input-history-file"], cache):
            self.assertNotIn(self.work.resolve(), Path(path).resolve().parents)
        # Aider adds .aider* to the project's .gitignore unless git ignores .aider (main.py
        # check_gitignore: repo.ignored), even in a repository it creates; git in the VM does.
        self.git("init", "-q")
        home = {"HOME": str(self.home), "XDG_CONFIG_HOME": str(self.home / ".config")}
        self.assertEqual(self.git("check-ignore", ".aider", env=home).strip(), ".aider")

    def test_after_the_session_the_copy_holds_only_the_project_and_what_the_harness_changed(self):
        """The review listed SMOKE_OK.txt and the five setup files (runs/real-1/yougori)."""
        (self.work / "app.py").write_text("print('app')\n", encoding="utf-8")
        (self.work / "node_modules/left-pad").mkdir(parents=True)
        (self.work / "node_modules/left-pad/index.js").write_text("module.exports = 1\n", encoding="utf-8")
        self.setup_package()
        found = vm_guest.setup_files(self.work)
        self.assertEqual(sorted(found), sorted(profiles.SETUP_FILES))
        # The harness made one file, and changed one of Yougori's, which is then its change.
        (self.work / "SMOKE_OK.txt").write_text("SMOKE_OK", encoding="utf-8")
        (self.work / "node_modules/yougori/index.mjs").write_text("export const mine = 1\n", encoding="utf-8")
        removed = vm_guest.tidy_setup(self.work, found)
        self.assertEqual(sorted(removed), sorted(set(profiles.SETUP_FILES) - {"node_modules/yougori/index.mjs"}))
        self.assertEqual(self.files(), ["SMOKE_OK.txt", "app.py", "node_modules/left-pad/index.js", "node_modules/yougori/index.mjs"])
        self.assertFalse((self.work / ".agents").exists(), "the folders the setup package made, once empty")
        self.assertTrue((self.work / "node_modules/left-pad").is_dir())
        # Nothing found, nothing done; a second tidy finds nothing more.
        self.assertEqual(vm_guest.tidy_setup(self.work, {}), [])
        self.assertEqual(vm_guest.tidy_setup(self.work, found), [])

    def test_a_projects_own_tracked_copy_of_a_setup_file_stays(self):
        self.setup_package()
        self.git("init", "-q")
        self.git("add", "-f", "yougori.py")
        self.git("commit", "-q", "-m", "A setup author's project")
        found = vm_guest.setup_files(self.work)
        self.assertEqual(vm_guest.tracked(self.work, sorted(found)), {"yougori.py"})
        self.assertNotIn("yougori.py", vm_guest.tidy_setup(self.work, found))
        self.assertEqual(self.files(), ["yougori.py"])
        # Without a repository nothing counts as tracked.
        self.assertEqual(vm_guest.tracked(self.root / "elsewhere", ["yougori.py"]), set())

    def start(self, data):
        """A session started through the guest's own /start (State.start) on this copy of the folder,
        its terminal and harness process faked. Returns the guest and what ends the harness."""
        (self.root / "image").mkdir(exist_ok=True)
        (self.root / "image/harness-name").write_text("pi\n", encoding="utf-8")
        state = vm_guest.State(self.root / "image", self.home)
        quits = threading.Event()
        self.addCleanup(quits.set)

        class Harness:
            pid = 4321

            def __init__(self, *_, **__):
                pass

            def wait(self):
                quits.wait(30)
                return 0
        terminal = types.SimpleNamespace(openpty=os.pipe)
        with patch.object(vm_guest, "WORKSPACE", self.work), patch.object(vm_guest, "pty", terminal), \
                patch.object(vm_guest, "fcntl", types.SimpleNamespace(ioctl=lambda *_: None)), \
                patch.object(vm_guest, "termios", types.SimpleNamespace(TIOCSWINSZ=0)), \
                patch.object(vm_guest.subprocess, "Popen", Harness):
            state.start({"model": "m", "workspace": True, **data})
        self.addCleanup(os.close, state.master)
        return state, quits

    def ended(self, state, quits):
        quits.set()
        with state.lock:
            self.assertTrue(state.lock.wait_for(lambda: state.exit_code is not None, timeout=30))

    def test_setup_files_the_persons_folder_already_held_stay_in_the_copy(self):
        """The folder already held the five files with the package's content (promoted from an
        earlier review that listed them as added, or a setup author's own), untracked. The tidy took
        them out, so the review listed five deletions and the launcher kept the copy for a session
        that changed nothing. The launcher names them now (/start "setup_in_folder")."""
        self.setup_package()  # The person's folder holds them, and so does its copy.
        baseline = {name: (self.work / name).read_bytes() for name in self.files()}
        state, quits = self.start({"setup_in_folder": sorted(profiles.SETUP_FILES)})
        self.assertEqual(state.setup, {})
        self.ended(state, quits)
        self.assertEqual({name: (self.work / name).read_bytes() for name in self.files()}, baseline)

    def test_only_what_the_setup_package_added_leaves_the_copy(self):
        (self.work / "yougori.py").write_text("// Yougori setup package: yougori.py\n", encoding="utf-8")
        self.setup_package()  # It adds the other four, and leaves the folder's own yougori.py.
        state, quits = self.start({"setup_in_folder": ["yougori.py", "not/a/setup/file.txt"]})
        self.assertEqual(sorted(state.setup), sorted(set(profiles.SETUP_FILES) - {"yougori.py"}))
        self.ended(state, quits)
        self.assertEqual(self.files(), ["yougori.py"])
        self.assertFalse((self.work / "node_modules").exists())

    def test_a_launcher_that_names_none_has_every_setup_file_tidied(self):
        self.setup_package()
        state, quits = self.start({})
        self.assertEqual(sorted(state.setup), sorted(profiles.SETUP_FILES))
        self.ended(state, quits)
        self.assertEqual(self.files(), [])

    def test_a_list_of_setup_files_that_is_not_one_is_refused(self):
        for said in ("yougori.py", {"yougori.py": True}, [1], ["yougori.py"] * 65, None):
            with self.subTest(said=said), self.assertRaises(vm_guest.Refusal) as refused:
                vm_guest.kept_setup({"setup_in_folder": said})
            self.assertEqual(str(refused.exception), "The launcher's list of setup files is not valid.")
        self.assertEqual(vm_guest.kept_setup({"setup_in_folder": ["yougori.py", "app.py"]}), {"yougori.py"})
        self.assertEqual(vm_guest.kept_setup({}), set())
        # Refused before anything starts.
        (self.root / "image").mkdir(exist_ok=True)
        (self.root / "image/harness-name").write_text("pi\n", encoding="utf-8")
        state = vm_guest.State(self.root / "image", self.home)
        with self.assertRaises(vm_guest.Refusal):
            state.start({"model": "m", "workspace": True, "setup_in_folder": "yougori.py"})
        self.assertFalse(state.started)

    def guest(self, process):
        """The VM's guest with a session whose harness is `process`, on a copy of the folder holding
        the setup package."""
        self.setup_package()
        (self.root / "image").mkdir(exist_ok=True)
        state = vm_guest.State(self.root / "image", self.home)
        state.process, state.started = process, True
        state.workspace, state.setup = self.work, vm_guest.setup_files(self.work)
        return state

    def test_the_exit_is_given_once_the_copy_is_tidied(self):
        class Ended:
            pid = 4321

            def wait(self):
                return 3
        state = self.guest(Ended())
        self.assertIsNone(state.exit_code)
        state.ended()
        self.assertEqual(state.exit_code, 3)
        self.assertEqual(self.files(), [])
        # /poll gives it to the launcher with the last of the output.
        server = ThreadingHTTPServer(("127.0.0.1", 0), vm_guest.Control)
        server.state = state
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        state.output.extend(b"x" * 65536 + b"bye")
        first = self.post(server, "/poll")
        self.assertEqual((len(base64.b64decode(first["output"])), first["exit"]), (65536, None))
        self.assertEqual(self.post(server, "/poll"), {"output": base64.b64encode(b"bye").decode(), "requests": [], "tunnels": [], "exit": 3})
        self.assertEqual(self.post(server, "/finish"), {"exit": 3}, "a session that ended is not signalled")

    def post(self, server, path):
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=30)
        try:
            connection.request("POST", path, body=b"{}", headers={"Content-Type": "application/json"})
            return json.loads(connection.getresponse().read())
        finally:
            connection.close()

    def test_a_session_the_launcher_ends_is_hung_up_then_tidied(self):
        """Ctrl+] ended the session from the launcher, which stopped the VM with the setup files
        still in the copy."""
        quits = threading.Event()

        class Running:
            pid = 4321

            def wait(self):
                quits.wait(30)
                return 129
        signals = types.SimpleNamespace(SIGHUP=1, SIGTERM=15, SIGKILL=9)
        sent = []

        def killpg(pid, number):
            sent.append((pid, number))
            if number == signals.SIGTERM:
                quits.set()  # This harness saves its work on SIGTERM and ends.
        state = self.guest(Running())
        threading.Thread(target=state.ended, daemon=True).start()
        with patch.object(vm_guest, "signal", signals), patch.object(vm_guest.os, "killpg", killpg, create=True):
            self.assertEqual(state.finish(seconds=1.5), 129)
        self.assertEqual(sent, [(4321, 1), (4321, 15)])
        self.assertEqual(self.files(), [])
        # A harness that outlasts every signal: the launcher stops the VM anyway.
        gone = threading.Event()
        self.addCleanup(gone.set)
        still = self.guest(type("Stuck", (), {"pid": 99, "wait": lambda self: gone.wait(30) and 137})())
        threading.Thread(target=still.ended, daemon=True).start()
        sent.clear()
        with patch.object(vm_guest, "signal", signals), patch.object(vm_guest.os, "killpg", lambda pid, number: sent.append(number), create=True):
            self.assertIsNone(still.finish(seconds=.05))
        self.assertEqual(sent, [1, 15, 9])
        self.assertIsNone(vm_guest.State(self.root / "image", self.home).finish(), "no session, nothing to end")


if __name__ == "__main__":
    unittest.main(verbosity=2)
