"""How the Yougori harness's setup answers travel from `yougori inference run` to the harness in
its VM: the answers file to the launcher, secret answers only in environments and the /start
request, the answers file inside the VM written owner-only outside the workspace, the practice app
allowed and targets outside the VM passed on to a Yougori that holds the VM to them. How the
session's model requests travel back out through the relay, several at once."""
import base64
import contextlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import patch
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "site/harnesses"))
# vm_guest runs in the Linux VM; its terminal modules are not needed for what these tests check.
for linux_only in ("fcntl", "pty", "termios"):
    sys.modules.setdefault(linux_only, types.ModuleType(linux_only))
import profiles
import solver
import vm_guest
import vm_host

SERVER = "http://127.0.0.1:9"
SECRET = "correct horse battery"
# `yougori inference run`, whose words the launcher's refusals use; absent where only the template is.
FOLDERS = Path(__file__).resolve().parents
CLI = FOLDERS[4] / "cli/src/inference.rs" if len(FOLDERS) > 4 else None


class Launcher(unittest.TestCase):
    """solver.py: `run yougori --harness NAME` with the answers file and YOUGORI_SECRET_<ID>."""

    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        self.answers = self.root / "answers.json"
        self.answers.write_text(json.dumps({"target": "practice", "depth": "safe", "login_user": "test@example.com"}))

    def main(self, *argv, environment=None, key=True, catalog=({"id": "m"},), refuse=None):
        """Runs solver.main with the engine, the website and the VM replaced; returns the
        launcher's exit code, what launch was given and what it printed. `refuse`: the website's
        reason the harness cannot start."""
        if key:
            for name in ("strix", "opencode"):
                (self.root / name).mkdir(exist_ok=True)
                (self.root / name / "api-key").write_text("is_test-key")
        # Kept on the test, so a refused run shows that nothing was checked, signed in or started.
        self.launched = launched = {}

        def launch(*positional, **keywords):
            launched.update(positional=positional, keywords=keywords, environment=dict(os.environ))
            return 0

        def run_session(name, server, key_file, model, workspace, interactive=True, **keywords):
            # A run of the Yougori harness, kept as launch() would have been given it: the harness
            # held is the image's, and run_session passes no tool arguments on.
            launched.update(positional=(name, server, key_file, model, workspace, [], interactive),
                            keywords={**keywords, "harness": name}, environment=dict(os.environ), session=True)
            return 0

        def preflight(name, server, held=False):
            launched.setdefault("preflight", []).append((name, held))
            if refuse:
                raise ValueError(refuse)
        variables = {"YOUGORI_SECRET_LOGIN_PASSWORD": SECRET, **(environment or {})}
        printed = io.StringIO()
        with patch.object(sys, "argv", ["solver.py", *argv]), patch.dict(os.environ, variables), \
                patch.object(solver, "profile", lambda server: self.root), \
                patch.object(solver, "private_folder", lambda path: path.mkdir(parents=True, exist_ok=True)), \
                patch.object(vm_host, "preflight", preflight), \
                patch.object(solver, "models", lambda server, key: list(catalog)), patch.object(solver, "launch", launch), \
                patch.object(solver, "run_session", run_session), contextlib.redirect_stdout(printed):
            code = solver.main()
        return code, launched, printed.getvalue()

    def test_run_yougori_carries_the_answers_and_secrets_to_the_vm(self):
        code, launched, _ = self.main("run", "yougori", "--server", SERVER, "--harness", "strix", "--model", "m",
                                   "--answers-file", str(self.answers), "--no-tty")
        self.assertEqual(code, 0)
        self.assertEqual(launched["positional"][0], "strix")  # the image and key of the harness held
        keywords = launched["keywords"]
        self.assertEqual(keywords["harness"], "strix")
        self.assertEqual(keywords["answers"], {"target": "practice", "depth": "safe", "login_user": "test@example.com"})
        self.assertEqual(keywords["secrets"], {"login_password": SECRET})
        self.assertIsNone(keywords["targets"])
        # Its screen may switch to the harnesses this launcher knows (/harness), in this VM or a new one.
        self.assertTrue(launched["session"])
        self.assertTrue({"yougori", "opencode", "strix", "shannon"} <= keywords["known"])
        # Nothing this launcher starts inherits the secret, and no argument holds it.
        self.assertNotIn("YOUGORI_SECRET_LOGIN_PASSWORD", launched["environment"])
        self.assertNotIn(SECRET, json.dumps(launched["positional"], default=str))

    def test_targets_are_checked_and_passed_on(self):
        _, launched, _ = self.main("run", "yougori", "--server", SERVER, "--harness", "opencode", "--model", "m",
                                "--answers-file", str(self.answers), "--internet", "targets",
                                "--targets", "Staging.Example.com:443,10.0.0.5,staging.example.com:443")
        self.assertEqual(launched["keywords"]["targets"], ["staging.example.com:443", "10.0.0.5"])
        self.assertEqual(solver.target_list("targets", "jenkins:8080"), ["jenkins:8080"])
        for bad in ("localhost:3000", "127.0.0.1", "169.254.169.254:80", "224.0.0.1", "jenkins", "x.com:0", "x.com:99999",
                    "::1", "x.com:１２", "a..b"):
            with self.assertRaises(ValueError, msg=bad):
                solver.target_list("targets", bad)
        with self.assertRaises(ValueError):
            solver.target_list("inference", "staging.example.com:443")
        with self.assertRaises(ValueError):
            solver.target_list("targets", "")
        self.assertEqual(solver.site_list("targets", "github.com"), ["github.com"])
        self.assertIsNone(solver.site_list("targets", None))

    def test_a_security_harness_reaches_only_its_target(self):
        """As `yougori inference run` holds it (cli/src/inference.rs: plan_for, resolve_reach)."""
        def run(answers, *options, held=True):
            self.answers.write_text(json.dumps(answers))
            command = ["run", "yougori", "--harness", "strix", "--answers-file", str(self.answers)] if held else ["run", "strix"]
            return self.main(*command, "--server", SERVER, "--model", "m", "--no-tty", *options)

        def refused(answers, *options, held=True):
            with self.assertRaises(ValueError, msg=options) as refusal:
                run(answers, *options, held=held)
            self.assertEqual(self.launched, {}, options)  # nothing was checked, signed in or started
            return str(refusal.exception)
        practice = {"target": "practice", "depth": "safe"}
        address = {"target": ["https://Staging.example.com/login", "10.0.0.5:8080"], "permission": True}
        for answers in (practice, address):
            for options in (["--sites", "github.com"], ["--internet", "sites", "--sites", "github.com"], ["--internet", "full"],
                            ["--internet", "targets", "--sites", "github.com"], ["--sites", ""]):
                self.assertEqual(refused(answers, *options), solver.security_reach("strix"))
        self.assertEqual(solver.security_reach("strix"), "Strix reaches only its target and this inference: it takes no "
                         "--sites, no --targets and no --internet sites or full. The target question names what it tests.")
        # The practice app inside the VM needs only the inference.
        self.assertEqual(refused(practice, "--internet", "targets"),
                         "--internet targets needs a target outside the VM: answer the target question with an address.")
        self.assertEqual(refused(practice, "--targets", "staging.example.com:443"), "Strix reaches only its target and this "
                         "inference: staging.example.com:443 is not its target. The target question names what it tests.")
        keywords = run(practice)[1]["keywords"]
        self.assertEqual((keywords["internet"], keywords["sites"], keywords["targets"]), (False, None, None))
        # Addresses: the VM reaches the target's hosts; --targets may name them again, or fewer, never another.
        _, launched, printed = run(address)
        self.assertEqual((launched["keywords"]["targets"], launched["keywords"]["internet"]),
                         (["staging.example.com:443", "10.0.0.5:8080"], False))
        self.assertIn("reaches this inference and the chosen targets: staging.example.com:443, 10.0.0.5:8080", printed)
        self.assertEqual(run(address, "--internet", "targets")[1]["keywords"]["targets"], ["staging.example.com:443", "10.0.0.5:8080"])
        self.assertEqual(run(address, "--internet", "targets", "--targets", "10.0.0.5:8080")[1]["keywords"]["targets"], ["10.0.0.5:8080"])
        for other in ("evil.example.com:443", "staging.example.com", "10.0.0.5", "staging.example.com:443,10.0.0.6:8080"):
            self.assertIn(" is not its target.", refused(address, "--internet", "targets", "--targets", other))
        self.assertEqual(refused(address, "--internet", "inference"), "--internet inference leaves Strix's target out of reach: "
                         "leave it out, and Strix reaches the target and this inference.")
        # A target answer is checked as the target question checks it.
        self.assertIn("is this computer", refused({"target": ["localhost:3000"], "permission": True}))
        self.assertEqual(refused({"target": True}), "The answers file has an invalid answer target.")
        # Started alone it has no target question: --targets names its target, and nothing else is taken.
        self.assertEqual(run({}, "--internet", "targets", "--targets", "staging.example.com:443", held=False)[1]["keywords"]["targets"],
                         ["staging.example.com:443"])
        for options in (["--internet", "full"], ["--internet", "sites", "--sites", "github.com"],
                        ["--internet", "targets", "--targets", "staging.example.com:443", "--sites", "github.com"]):
            self.assertEqual(refused({}, *options, held=False), "Strix reaches only its target and this inference: it takes no "
                             "--sites and no --internet sites or full. Name its target with --internet targets --targets HOST:PORT.")
        # Every security harness is held so; another harness still reaches what it is given.
        for harness in sorted(solver.SECURITY):
            with self.assertRaises(ValueError, msg=harness) as refusal:
                solver.held_to_target(harness, "full", None, None, {})
            self.assertTrue(str(refusal.exception).startswith(solver.NAMES[harness] + " reaches only its target"))
        _, launched, _ = self.main("run", "yougori", "--server", SERVER, "--harness", "opencode", "--model", "m", "--no-tty",
                                   "--internet", "full")
        self.assertIs(launched["keywords"]["internet"], True)

    @unittest.skipUnless(CLI and CLI.is_file(), "the CLI's source beside the template")
    def test_the_launcher_refuses_in_the_words_of_the_command(self):
        source = CLI.read_text(encoding="utf-8")
        for said in (solver.security_reach("strix").replace("Strix", "{}"),
                     "--internet targets needs a target outside the VM: answer the target question with an address.",
                     "--internet inference leaves {}'s target out of reach: leave it out, and {} reaches the target and this inference."):
            self.assertIn('"' + said + '"', source)

    def test_the_answers_file_holds_answers_only(self):
        for bad in ([1, 2], {"Bad-Id": "x"}, {"x": {"nested": True}}, {"x": 7}, {"x": "\0"}, {"x": ["a", 1]}):
            self.answers.write_text(json.dumps(bad))
            with self.assertRaises(ValueError, msg=bad):
                solver.answer_file(self.answers)
        self.answers.write_text("x" * (solver.ANSWERS_BYTES + 1))
        with self.assertRaises(ValueError):
            solver.answer_file(self.answers)
        with self.assertRaises(ValueError):
            solver.answer_file(self.root / "missing.json")
        self.assertEqual(solver.answer_file(None), {})

    def test_secret_answers_come_only_from_the_environment(self):
        environment = {"YOUGORI_SECRET_LOGIN_PASSWORD": SECRET, "PATH": "/bin"}
        variables = solver.take_secrets(environment)
        self.assertEqual(environment, {"PATH": "/bin"})
        self.assertEqual(solver.secret_answers(variables), {"login_password": SECRET})
        for name, value in (("YOUGORI_SECRET_BAD-NAME", "x"), ("YOUGORI_SECRET_LOGIN_PASSWORD", "two\nlines"),
                            ("YOUGORI_SECRET_LOGIN_PASSWORD", "")):
            with self.assertRaises(ValueError) as refused:
                solver.secret_answers({name: value})
            self.assertNotIn("two", str(refused.exception))
        # --answers-file and --harness belong to the Yougori harness.
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            self.main("run", "strix", "--server", SERVER, "--answers-file", str(self.answers))

    def test_an_existing_harness_starts_as_before(self):
        code, launched, _ = self.main("run", "strix", "--server", SERVER, "--model", "m", "--no-tty", "--", "--print", "hi")
        self.assertEqual(code, 0)
        self.assertEqual(launched["positional"][0], "strix")
        self.assertEqual(launched["positional"][5], ["--print", "hi"])
        keywords = launched["keywords"]
        self.assertNotIn("harness", keywords)
        self.assertEqual((keywords["internet"], keywords["sites"], keywords["targets"]), (False, None, None))

    def test_run_yougori_checks_and_starts_the_harness_inside_the_yougori_harness(self):
        code, launched, printed = self.main("run", "yougori", "--server", SERVER, "--harness", "strix", "--model", "m",
                                            "--answers-file", str(self.answers), "--no-tty", catalog=({"id": "m"}, {"id": "n"}))
        self.assertEqual(code, 0)
        self.assertEqual(launched["preflight"], [("strix", True)])
        # Its base and pack are kept once for every harness Yougori holds; the key stays the harness's own.
        self.assertEqual(launched["keywords"]["images"], self.root / "yougori")
        self.assertEqual(launched["positional"][2], self.root / "strix" / "api-key")
        # The model was chosen already: no numbered list before the harness's screen.
        self.assertNotIn("1. m", printed)
        # A harness started from its own image is checked as before, and the list printed for choosing.
        code, launched, printed = self.main("run", "strix", "--server", SERVER, "--model", "m", "--no-tty",
                                            catalog=({"id": "m"}, {"id": "n"}))
        self.assertEqual((code, launched["preflight"]), (0, [("strix", False)]))
        self.assertNotIn("images", launched["keywords"])
        self.assertIn("1. m\n2. n", printed)

    def test_install_yougori_prepares_the_yougori_harness_images(self):
        installed = []
        with patch.object(vm_host, "install_yougori", lambda held, server, root: installed.append((held, server, root))), \
                patch.object(vm_host, "install", lambda name, server, root: installed.append(("own", name, root))):
            self.assertEqual(self.main("install", "yougori", "--server", SERVER, "--harness", "plandex")[0], 0)
            self.assertEqual(self.main("install", "plandex", "--server", SERVER)[0], 0)
        self.assertEqual(installed, [("plandex", SERVER, self.root / "yougori"), ("own", "plandex", self.root / "plandex")])

    def test_install_checks_the_harness_on_the_website_first_as_run_does(self):
        installed = []
        with patch.object(vm_host, "install_yougori", lambda held, server, root: installed.append(("yougori", held))), \
                patch.object(vm_host, "install", lambda name, server, root: installed.append(("own", name))):
            # Inside the Yougori harness (its `held`), or from the harness's own image.
            self.assertEqual(self.main("install", "yougori", "--server", SERVER, "--harness", "plandex")[1]["preflight"],
                             [("plandex", True)])
            self.assertEqual(self.main("install", "plandex", "--server", SERVER)[1]["preflight"], [("plandex", False)])
            # The website's reason comes first, and nothing is downloaded.
            unpublished = "The administrator has not published this harness's Sandbox VM image yet."
            for command in (["install", "yougori", "--harness", "plandex"], ["install", "plandex"]):
                with self.assertRaises(ValueError) as refused:
                    self.main(*command, "--server", SERVER, refuse=unpublished)
                self.assertEqual(str(refused.exception), unpublished)
        self.assertEqual(installed, [("yougori", "plandex"), ("own", "plandex")])

    def test_a_model_the_website_no_longer_lists_is_named_and_the_launch_reads_the_catalog_again(self):
        gone = "unsloth/gemma-4-26B-A4B-it-GGUF"
        with self.assertRaises(ValueError) as refused:
            self.main("run", "yougori", "--server", SERVER, "--harness", "strix", "--model", gone,
                      "--answers-file", str(self.answers), "--no-tty")
        self.assertEqual(str(refused.exception), "The model " + gone + " is not available on this server right now. Choose "
                         "another model, or start again when it is back.")
        self.assertNotIn("positional", self.launched)  # nothing started
        # The words the VM uses when it finds the same.
        self.assertEqual(str(refused.exception), profiles.UNAVAILABLE % gone)
        # Listed: the launch gets the live catalog to read again, with this server and key, before the VM starts.
        for command in (["run", "yougori", "--harness", "strix", "--answers-file", str(self.answers)], ["run", "strix"]):
            _, launched, _ = self.main(*command, "--server", SERVER, "--model", "m", "--no-tty", catalog=({"id": "m"}, {"id": "n"}))
            self.assertEqual(launched["keywords"]["catalog"](SERVER, "is_test-key"), [{"id": "m"}, {"id": "n"}])

    def test_the_launcher_ends_on_ctrl_c_with_no_traceback(self):
        for raised, ended in ((KeyboardInterrupt(), 130), (ValueError("Choose a harness."), "Choose a harness."),
                              (OSError("refused"), solver.TROUBLE)):
            with patch.object(solver, "main", side_effect=raised):
                self.assertEqual(solver.run(), ended)
        with patch.object(solver, "main", return_value=0):
            self.assertEqual(solver.run(), 0)

    def test_run_yougori_takes_no_tool_arguments(self):
        for extra in (["--", "--print", "hi"], ["--modle", "m"], ["stray"]):
            with self.assertRaises(ValueError, msg=extra) as refused:
                self.main("run", "yougori", "--server", SERVER, "--harness", "strix", "--model", "m", *extra)
            self.assertIn("yougori takes no tool arguments or other options", str(refused.exception))
        code, launched, _ = self.main("run", "yougori", "--server", SERVER, "--harness", "strix", "--model", "m", "--no-tty", "--")
        self.assertEqual((code, launched["positional"][5]), (0, []))

    def test_the_answers_file_the_command_wrote_goes_once_read(self):
        stage = self.root / "client-stage"
        stage.mkdir()
        written = stage / "answers.json"
        written.write_text(json.dumps({"target": "practice"}))
        with patch.object(solver, "HERE", stage):
            self.assertEqual(solver.answer_file(written), {"target": "practice"})
            self.assertFalse(written.exists())
            # The person's own file elsewhere stays, and so does a file of another name beside the launcher.
            self.assertEqual(solver.answer_file(self.answers)["target"], "practice")
            other = stage / "my-answers.json"
            other.write_text("{}")
            solver.answer_file(other)
            self.assertTrue(self.answers.exists() and other.exists())
            # A file that is not valid stays for the command to remove when it ends.
            written.write_text("[1]")
            with self.assertRaises(ValueError):
                solver.answer_file(written)
            self.assertTrue(written.exists())
            # As `yougori inference run` starts the launcher.
            written.write_text(json.dumps({"target": "practice"}))
            code, launched, _ = self.main("run", "yougori", "--server", SERVER, "--harness", "strix", "--model", "m",
                                          "--answers-file", str(written), "--no-tty")
        self.assertEqual((code, launched["keywords"]["answers"], written.exists()), (0, {"target": "practice"}, False))

    def test_model_ids_are_plain_text(self):
        class Opener:
            def __init__(self, body):
                self.body = body

            def open(self, request, timeout):
                return io.BytesIO(self.body)

        def models(*ids):
            body = json.dumps({"data": [{"id": value} for value in ids]}).encode()
            with patch.object(solver, "transport_opener", lambda: Opener(body)):
                return [entry["id"] for entry in solver.models(SERVER, "is_test-key")]
        good = ("unsloth/gemma-4-26B-A4B-it-GGUF", "Qwen/Qwen3-8B:Q4_K_M", "模型", "m" * 1024)
        self.assertEqual(models(*good), list(good))
        for bad in ("", "m" * 1025, "a\x1b[2Jb", "a\nb", "a\x00b", "a\x7fb", "a\x9bb", 7, None):
            with self.assertRaises(ValueError, msg=repr(bad)) as refused:
                models("fine", bad)
            self.assertEqual(str(refused.exception), "Invalid model catalog.")

    def test_models_json_signs_in_and_prints_only_the_models(self):
        def login(server, name, key_file, open_browser):
            print("\nSign in to Inference Solver\nOpen: " + server + "/#connect\nEnter code: ABCD-EFGH\n")
            key_file.write_text("is_new-key")
            return "is_new-key"
        said = io.StringIO()
        with patch.object(solver.device_login, "login", login), contextlib.redirect_stderr(said):
            code, launched, printed = self.main("models", "strix", "--server", SERVER, "--json", key=False,
                                                catalog=({"id": "unsloth/gemma-4-26B-A4B-it-GGUF"}, {"id": "Qwen/Qwen3-8B"}))
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(printed), {"models": ["unsloth/gemma-4-26B-A4B-it-GGUF", "Qwen/Qwen3-8B"]})
        self.assertIn("Enter code: ABCD-EFGH", said.getvalue())
        # `yougori inference run` starts every harness inside the Yougori harness: that is what is checked.
        self.assertEqual(launched["preflight"], [("strix", True)])
        # The harness cannot start here: the website's reason, as JSON.
        out = io.StringIO()
        refused = ValueError("The administrator of this inference has not offered this harness.")
        with patch.object(vm_host, "preflight", side_effect=refused), contextlib.redirect_stdout(out):
            with patch.object(solver, "profile", lambda server: self.root), patch.object(solver, "private_folder", lambda path: None), \
                    patch.object(sys, "argv", ["solver.py", "models", "strix", "--server", SERVER, "--json"]):
                code = solver.main()
        self.assertEqual((code, json.loads(out.getvalue())), (1, {"error": str(refused)}))


class Guest(BaseHTTPRequestHandler):
    """A VM guest: new (takes a Yougori harness session) or older (ignores it), or refusing. Its
    harness asks the model `requests` at once, then ends once each has its whole answer."""

    def log_message(self, *_):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.server.bodies.append((self.path, body))
        status, reply = 200, {}
        if self.path == "/start":
            status, reply = self.server.start
        elif self.path == "/poll":
            asked, self.server.requests = self.server.requests, []
            self.server.asked.update(request["id"] for request in asked)
            waiting = asked or self.server.asked - self.server.answered
            if waiting and not asked:
                time.sleep(.02)
            reply = {"output": "", "requests": asked, "tunnels": [], "exit": None if waiting else 0}
        elif self.path == "/response" and body.get("done"):
            self.server.answered.add(body["id"])
        raw = json.dumps(reply).encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class Host(unittest.TestCase):
    """vm_host.launch: the /start request of a Yougori harness session."""

    def setUp(self):
        self.guest = ThreadingHTTPServer(("127.0.0.1", 0), Guest)
        self.guest.bodies, self.guest.requests, self.guest.asked, self.guest.answered = [], [], set(), set()
        self.guest.start = (200, {"started": True, "tunnels": True, "yougori": True})
        threading.Thread(target=self.guest.serve_forever, daemon=True).start()
        self.addCleanup(self.guest.server_close)
        self.addCleanup(self.guest.shutdown)
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.key_file = Path(folder.name) / "api-key"
        self.key_file.write_text("is_test-key")
        self.engine = []

    def call(self, action, **params):
        self.engine.append(action)
        if action == "launch":
            return {"sandbox": "exe-" + "a" * 32}
        if action == "publish":
            return {"url": "http://abc123.localhost:%d/" % self.guest.server_port}
        return {}

    def launch(self, server=SERVER, **keywords):
        with patch.object(vm_host, "install", lambda name, server, root: "sha256:" + "b" * 64), \
                patch.object(vm_host, "install_yougori", lambda held, server, root: ("sha256:" + "b" * 64, {"harness": held}, 4)), \
                patch.object(vm_host, "call", self.call), patch.object(vm_host, "tidy", lambda sandbox, folder: False), \
                patch.object(vm_host, "prepare_tool", lambda control, root, declaration=None: None), \
                contextlib.redirect_stdout(io.StringIO()):
            return vm_host.launch("strix", server, self.key_file, "m", None, [], False, **keywords)

    def test_a_model_the_website_no_longer_lists_is_refused_before_the_vm_starts(self):
        read = []

        def catalog(server, secret):
            read.append((server, secret))
            return [{"id": "another"}]
        with self.assertRaises(ValueError) as refused:
            self.launch(harness="strix", answers={}, secrets={}, catalog=catalog)
        self.assertEqual(str(refused.exception), "The model m is not available on this server right now. Choose another model, "
                         "or start again when it is back.")
        self.assertEqual(read, [(SERVER, "is_test-key")])
        self.assertNotIn("launch", self.engine)
        self.assertEqual(self.guest.bodies, [])
        # A model id is named as plain words.
        self.assertTrue(vm_host.unavailable("a\x1b[2Jb\n").startswith("The model a[2Jb is not available"))
        # Still listed: the VM starts.
        self.assertEqual(self.launch(harness="strix", answers={}, secrets={}, catalog=lambda server, secret: [{"id": "m"}]), 0)
        self.assertIn("launch", self.engine)

    def test_five_model_requests_at_once_each_get_their_answer(self):
        """As Shannon's five agents ask at once: the fifth waits for a place, and the session goes on."""
        website = Website()
        self.addCleanup(website.close)
        self.guest.requests = [model_request(str(number)) for number in range(5)]
        answering = threading.Timer(.5, website.answer_all)
        answering.start()
        self.addCleanup(answering.cancel)
        self.assertEqual(self.launch(website.url()), 0)
        self.assertEqual(sorted(website.seen()), ["0", "1", "2", "3", "4"])
        statuses = [body["status"] for path, body in self.guest.bodies if path == "/response" and "status" in body]
        self.assertEqual(statuses, [200] * 5)

    def test_a_practice_target_starts_with_its_answers(self):
        answers = {"target": "practice", "depth": "safe"}
        self.assertEqual(self.launch(harness="strix", answers=answers, secrets={"login_password": SECRET}), 0)
        start = next(body for path, body in self.guest.bodies if path == "/start")
        self.assertEqual(start["harness"], "strix")
        self.assertEqual(start["answers"], answers)
        self.assertEqual(start["secrets"], {"login_password": SECRET})
        self.assertEqual(start["reach"], {"mode": "inference", "sites": [], "targets": []})
        # The VM stopped at the end, as every run's VM does.
        self.assertIn("stop", self.engine)

    def test_a_target_outside_the_vm_starts_with_the_vm_held_to_it(self):
        engine, launched = self.call, {}

        def call(action, **params):
            if action == "capabilities":
                self.engine.append(action)
                return {"gpu": {"available": False}, "targets": {"available": True, "gpu": False}}
            if action == "launch":
                launched.update(params)
                held = [{"host": "staging.example.com", "addresses": ["93.184.216.34"], "ports": [443]}]
                return {**engine(action, **params), "reach": {"targets": held}}
            return engine(action, **params)
        self.call = call
        # The name is not looked up here: test_vm_targets checks what the launcher refuses.
        with patch.object(vm_host, "check_targets", lambda targets: list(targets)):
            self.assertEqual(self.launch(harness="strix", answers={"target": ["https://staging.example.com"], "permission": True},
                                         targets=["staging.example.com:443"]), 0)
        self.assertEqual((launched["targets"], "internet" in launched), (["staging.example.com:443"], False))
        start = next(body for path, body in self.guest.bodies if path == "/start")
        self.assertEqual(start["reach"], {"mode": "targets", "sites": [], "targets": ["staging.example.com:443"]})
        self.assertEqual(self.engine[:2], ["capabilities", "launch"])
        self.assertIn("stop", self.engine)

    def test_an_older_image_runs_its_harness_only_without_answers(self):
        self.guest.start = (200, {"started": True, "tunnels": True})
        with self.assertRaises(ValueError) as older:
            self.launch(harness="strix", answers={"target": "practice"}, secrets={})
        self.assertIn("older than the Yougori harness", str(older.exception))
        self.assertIn("stop", self.engine)
        # A harness with nothing to ask starts in its own screen, as it always has.
        self.guest.bodies.clear()
        self.assertEqual(self.launch(harness="strix", answers={}, secrets={}), 0)
        self.assertIn("/poll", [path for path, _ in self.guest.bodies])

    def test_a_refusal_stops_at_once(self):
        self.guest.start = (409, {"error": "This VM was made for another harness. Start the harness again."})
        with self.assertRaises(vm_host.Refused) as refused:
            self.launch(harness="strix", answers={}, secrets={})
        self.assertEqual(str(refused.exception), "This VM was made for another harness. Start the harness again.")
        self.assertEqual([path for path, _ in self.guest.bodies], ["/start"])

    def test_an_existing_harness_sends_no_session(self):
        self.assertEqual(self.launch(), 0)
        start = next(body for path, body in self.guest.bodies if path == "/start")
        self.assertFalse({"harness", "answers", "secrets", "reach"} & set(start))
        self.assertEqual(vm_host.reach(sites=["github.com"]), {"mode": "sites", "sites": ["github.com"], "targets": []})
        self.assertEqual(vm_host.reach(internet=True)["mode"], "full")
        self.assertEqual(vm_host.reach(targets=["a.example.com:443"])["mode"], "targets")


class Answering(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        name = json.loads(self.rfile.read(int(self.headers["Content-Length"])))["name"]
        with self.server.lock:
            self.server.arrived.append(name)
            answer = self.server.answers.setdefault(name, threading.Event())
            if self.server.open:
                answer.set()
        answer.wait(20)
        raw = json.dumps({"answer": name}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class Website(ThreadingHTTPServer):
    """The inference website: each model request is held until the test lets it answer."""

    def __init__(self):
        super().__init__(("127.0.0.1", 0), Answering)
        self.lock, self.arrived, self.answers, self.open = threading.Lock(), [], {}, False
        threading.Thread(target=self.serve_forever, daemon=True).start()

    def url(self):
        return "http://127.0.0.1:%d" % self.server_port

    def seen(self, count=0):
        """The requests that reached it, once there are `count`."""
        deadline = time.monotonic() + 20
        while True:
            with self.lock:
                if len(self.arrived) >= count or time.monotonic() > deadline:
                    return list(self.arrived)
            time.sleep(.01)

    def answer(self, *names):
        with self.lock:
            for name in names:
                self.answers.setdefault(name, threading.Event()).set()

    def answer_all(self):
        with self.lock:
            self.open = True
            for answer in self.answers.values():
                answer.set()

    def close(self):
        self.answer_all()
        self.shutdown()
        self.server_close()


def model_request(name):
    """A model request as the VM's guest passes one on."""
    return {"id": uuid.uuid4().hex, "method": "POST", "path": "/v1/chat/completions",
            "body": base64.b64encode(json.dumps({"name": name}).encode()).decode()}


class VM:
    """The VM's side of the relay: what each request's client was sent, and the requests it no
    longer waits for (their client left), which it answers 410."""

    def __init__(self):
        self.lock = threading.Condition()
        self.replies, self.gone = {}, set()

    def post(self, path, data):
        with self.lock:
            if path != "/response" or data["id"] in self.gone:
                raise vm_host.Ended("The VM no longer waits for this.")
            self.replies.setdefault(data["id"], []).append({key: value for key, value in data.items() if key != "id"})
            self.lock.notify_all()
        return {}

    def finished(self, identity):
        with self.lock:
            return self.lock.wait_for(lambda: any(part.get("done") for part in self.replies.get(identity, [])), 20)


class Relay(unittest.TestCase):
    """vm_host.Relay: the session's model requests, four at once as the VM's guest lets a harness
    have them, the next ones waiting their turn; beyond those, 429; the session goes on."""

    def setUp(self):
        self.website, self.vm, self.done = Website(), VM(), threading.Event()
        self.addCleanup(self.website.close)
        self.relay = vm_host.Relay(self.vm, self.website.url(), "is_test-key", self.done)

    def ask(self, name):
        request = model_request(name)
        self.relay.take(request)
        return request["id"]

    def settled(self):
        deadline = time.monotonic() + 20
        while any(worker.is_alive() for worker in self.relay.workers) and time.monotonic() < deadline:
            time.sleep(.01)

    def test_a_fifth_request_waits_for_a_place_and_the_session_goes_on(self):
        first = [self.ask(name) for name in "abcd"]
        self.assertEqual(sorted(self.website.seen(4)), list("abcd"))
        # The guest freed a place while the request here was still finishing.
        fifth = self.ask("e")
        time.sleep(.3)
        self.assertEqual(len(self.website.seen()), 4)
        self.website.answer("a")
        self.assertTrue(self.vm.finished(first[0]))
        self.assertIn("e", self.website.seen(5))
        self.website.answer("b", "c", "d", "e")
        for identity in [*first, fifth]:
            self.assertTrue(self.vm.finished(identity))
            self.assertEqual(self.vm.replies[identity][0], {"status": 200, "content_type": "application/json"})
        self.assertFalse(self.relay.failed.is_set())

    def test_requests_beyond_those_waiting_are_answered_429(self):
        held = [self.ask(name) for name in "abcdefgh"]  # four under way, four waiting
        self.assertEqual(len(self.website.seen(4)), 4)
        extra = self.ask("i")
        self.assertTrue(self.vm.finished(extra))
        status, data, end = self.vm.replies[extra]
        self.assertEqual((status, end), ({"status": 429, "content_type": "application/json"}, {"done": True}))
        self.assertEqual(json.loads(base64.b64decode(data["data"]))["error"]["message"], vm_host.RELAY_BUSY)
        self.website.answer(*"abcdefgh")
        for identity in held:
            self.assertTrue(self.vm.finished(identity))
        self.assertNotIn("i", self.website.seen())
        self.assertFalse(self.relay.failed.is_set())

    def test_a_request_the_vm_no_longer_waits_for_ends_quietly_and_frees_its_place(self):
        gone = self.ask("a")
        self.website.seen(1)
        self.vm.gone.add(gone)  # its client left
        self.website.answer("a")
        self.settled()
        # Its place is free again: the next four reach the website at once.
        after = [self.ask(name) for name in "bcde"]
        self.assertEqual(sorted(self.website.seen(5)), list("abcde"))
        self.website.answer(*"bcde")
        for identity in after:
            self.assertTrue(self.vm.finished(identity))
        self.assertNotIn(gone, self.vm.replies)
        self.assertFalse(self.relay.failed.is_set())

    def test_a_request_the_vm_s_guest_let_go_ends_quietly(self):
        """Against the VM's own guest (vm_guest), which answers 410 for a request its client left."""
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        (Path(folder.name) / "home").mkdir()
        guest = ThreadingHTTPServer(("127.0.0.1", 0), vm_guest.Control)
        guest.state = vm_guest.State(Path(folder.name), Path(folder.name) / "home")
        threading.Thread(target=guest.serve_forever, daemon=True).start()
        self.addCleanup(guest.server_close)
        self.addCleanup(guest.shutdown)
        control = vm_host.Control("http://abc123.localhost:%d/" % guest.server_port)
        with self.assertRaises(vm_host.Ended):
            control.post("/response", {"id": uuid.uuid4().hex, "done": True})
        self.relay = vm_host.Relay(control, self.website.url(), "is_test-key", self.done)
        self.ask("a")
        self.website.answer("a")
        self.assertEqual(self.website.seen(1), ["a"])
        self.settled()
        self.assertFalse(self.relay.failed.is_set())

    def test_after_the_session_a_request_under_way_ends_quietly(self):
        identity = self.ask("a")
        self.website.seen(1)
        self.done.set()
        self.website.answer("a")
        self.settled()
        self.assertNotIn(identity, self.vm.replies)
        self.assertFalse(self.relay.failed.is_set())

    def test_anything_but_a_request_ends_the_session_however_full_the_relay_is(self):
        for bad in (None, [], {}, {"id": "abc"}, {"id": 7}, {"id": int("1" * 32)}, {"id": "A" * 32}, {"id": "a" * 33}):
            with self.assertRaises(ValueError, msg=bad) as refused:
                self.relay.take(bad)
            self.assertEqual(str(refused.exception), "Invalid VM relay request.")
        # Full, the relay still tells a request (answered 429) from anything else (refused).
        held = [self.ask(name) for name in "abcdefgh"]
        self.website.seen(4)
        with self.assertRaises(ValueError):
            self.relay.take({"id": "not a request id"})
        extra = self.ask("i")
        self.assertTrue(self.vm.finished(extra))
        self.assertEqual(self.vm.replies[extra][0]["status"], 429)
        self.website.answer(*"abcdefgh")
        for identity in held:
            self.assertTrue(self.vm.finished(identity))


class InsideTheVm(unittest.TestCase):
    """vm_guest.harness_session: what runtime.py gets for `run yougori`."""

    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.home = Path(folder.name)

    def start(self, **data):
        environment = {"SOLVER_MODEL": "m"}
        body = {"harness": "strix", "answers": {"target": "practice", "focus": "Login and payments"},
                "secrets": {"login_password": SECRET}, "reach": {"mode": "inference", "sites": [], "targets": []}, **data}
        return vm_guest.harness_session(body, "strix", environment, self.home), environment

    def test_answers_go_to_the_home_and_secrets_only_to_the_environment(self):
        command, environment = self.start()
        self.assertEqual(command, ["run", "yougori"])
        written = self.home / ".yougori" / "answers.json"
        self.assertEqual(json.loads(written.read_text()), {"target": "practice", "focus": "Login and payments"})
        self.assertNotIn(SECRET, written.read_text())
        self.assertEqual(environment["SOLVER_HARNESS"], "strix")
        self.assertEqual(json.loads(environment["SOLVER_REACH"]), {"mode": "inference", "sites": [], "targets": []})
        self.assertEqual(environment["YOUGORI_SECRET_LOGIN_PASSWORD"], SECRET)
        self.assertEqual(environment["SOLVER_MODEL"], "m")
        if os.name == "posix":
            self.assertEqual(written.stat().st_mode & 0o777, 0o600)
            self.assertEqual((self.home / ".yougori").stat().st_mode & 0o777, 0o700)
        self.assertEqual(list((self.home / ".yougori").iterdir()), [written])

    def test_what_the_launcher_sent_is_checked(self):
        for data in ({"harness": "opencode"}, {"answers": {"Bad": "x"}}, {"answers": {"x": {"a": 1}}}, {"answers": []},
                     {"secrets": {"login_password": "two\nlines"}}, {"secrets": {"login_password": ""}},
                     {"secrets": {"login_password": 7}}, {"reach": {"mode": "everywhere"}},
                     {"reach": {"mode": "targets", "targets": ["https://staging.example.com/path"]}}):
            with self.assertRaises(vm_guest.Refusal, msg=data) as refused:
                self.start(**data)
            self.assertNotIn(SECRET, str(refused.exception))
        self.assertFalse((self.home / ".yougori" / "answers.json").exists())
        _, environment = self.start(reach={"mode": "targets", "sites": [], "targets": ["staging.example.com:443"]})
        self.assertEqual(json.loads(environment["SOLVER_REACH"])["targets"], ["staging.example.com:443"])


if __name__ == "__main__":
    unittest.main()
