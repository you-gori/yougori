"""The security harnesses' setup answers: the plain setup brief profiles.py makes from them, how
each launcher takes it (its own options, from headless()), where each one's results go, and that
a test login's password never reaches arguments, files or reports. A temporary home and
workspace, no network; no harness engine runs."""
import asyncio
import base64
import contextlib
import io
import json
import os
import shutil
from pathlib import Path
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch
import urllib.error
from urllib.parse import parse_qs, quote, quote_plus, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "site/harnesses"))
import hexstrike_cli
import pentagi_cli
import profiles
import runtime
import shannon_cli
import strix_cli

CATALOG = [{"id": "qwen3-coder"}, {"id": "gemma-4"}]
# A stand-in for the test login's password the VM holds as YOUGORI_SECRET_LOGIN_PASSWORD.
PASSWORD = "correct horse battery"
# One with what JSON escapes (" and \), what Go escapes (<, > and &), a slash, a space and
# non-ASCII text: the CLI accepts any printable characters.
TRICKY = 'Tr0ub"le\\dor/<&> é'
VARIABLE = "YOUGORI_SECRET_LOGIN_PASSWORD"
# The names of the 150 tools the pinned HexStrike's MCP server lists (packages.json, commit
# d689933ff579), in its order.
HEXSTRIKE_TOOLS = [
    'nmap_scan', 'gobuster_scan', 'nuclei_scan', 'prowler_scan', 'trivy_scan', 'scout_suite_assessment',
    'cloudmapper_analysis', 'pacu_exploitation', 'kube_hunter_scan', 'kube_bench_cis',
    'docker_bench_security_scan', 'clair_vulnerability_scan', 'falco_runtime_monitoring',
    'checkov_iac_scan', 'terrascan_iac_scan', 'create_file', 'modify_file', 'delete_file', 'list_files',
    'generate_payload', 'install_python_package', 'execute_python_script', 'dirb_scan', 'nikto_scan',
    'sqlmap_scan', 'metasploit_run', 'hydra_attack', 'john_crack', 'wpscan_analyze', 'enum4linux_scan',
    'ffuf_scan', 'netexec_scan', 'amass_scan', 'hashcat_crack', 'subfinder_scan', 'smbmap_scan',
    'rustscan_fast_scan', 'masscan_high_speed', 'nmap_advanced_scan', 'autorecon_comprehensive',
    'enum4linux_ng_advanced', 'rpcclient_enumeration', 'nbtscan_netbios', 'arp_scan_discovery',
    'responder_credential_harvest', 'volatility_analyze', 'msfvenom_generate', 'gdb_analyze',
    'radare2_analyze', 'binwalk_analyze', 'ropgadget_search', 'checksec_analyze', 'xxd_hexdump',
    'strings_extract', 'objdump_analyze', 'ghidra_analysis', 'pwntools_exploit', 'one_gadget_search',
    'libc_database_lookup', 'gdb_peda_debug', 'angr_symbolic_execution', 'ropper_gadget_search',
    'pwninit_setup', 'feroxbuster_scan', 'dotdotpwn_scan', 'xsser_scan', 'wfuzz_scan', 'dirsearch_scan',
    'katana_crawl', 'gau_discovery', 'waybackurls_discovery', 'arjun_parameter_discovery',
    'paramspider_mining', 'x8_parameter_discovery', 'jaeles_vulnerability_scan', 'dalfox_xss_scan',
    'httpx_probe', 'anew_data_processing', 'qsreplace_parameter_replacement', 'uro_url_filtering',
    'ai_generate_payload', 'ai_test_payload', 'ai_generate_attack_suite', 'api_fuzzer', 'graphql_scanner',
    'jwt_analyzer', 'api_schema_analyzer', 'comprehensive_api_audit', 'volatility3_analyze',
    'foremost_carving', 'steghide_analysis', 'exiftool_extract', 'hashpump_attack', 'hakrawler_crawl',
    'paramspider_discovery', 'burpsuite_scan', 'zap_scan', 'arjun_scan', 'wafw00f_scan', 'fierce_scan',
    'dnsenum_scan', 'autorecon_scan', 'server_health', 'get_cache_stats', 'clear_cache', 'get_telemetry',
    'list_active_processes', 'get_process_status', 'terminate_process', 'pause_process', 'resume_process',
    'get_process_dashboard', 'execute_command', 'monitor_cve_feeds', 'generate_exploit_from_cve',
    'discover_attack_chains', 'research_zero_day_opportunities', 'correlate_threat_intelligence',
    'advanced_payload_generation', 'vulnerability_intelligence_dashboard', 'threat_hunting_assistant',
    'get_live_dashboard', 'create_vulnerability_report', 'format_tool_output_visual',
    'create_scan_summary', 'display_system_metrics', 'analyze_target_intelligence',
    'select_optimal_tools_ai', 'optimize_tool_parameters_ai', 'create_attack_chain_ai',
    'intelligent_smart_scan', 'detect_technologies_ai', 'ai_reconnaissance_workflow',
    'ai_vulnerability_assessment', 'bugbounty_reconnaissance_workflow', 'bugbounty_vulnerability_hunting',
    'bugbounty_business_logic_testing', 'bugbounty_osint_gathering', 'bugbounty_file_upload_testing',
    'bugbounty_comprehensive_assessment', 'bugbounty_authentication_bypass_testing', 'http_framework_test',
    'browser_agent_inspect', 'http_set_rules', 'http_set_scope', 'http_repeater', 'http_intruder',
    'burpsuite_alternative_scan', 'error_handling_statistics', 'test_error_recovery',
]
# The commands pip wrote in the pinned HexStrike's own environment (/opt/solver/tool/bin in its pack),
# which comes first on its VM's PATH: pip's own and those of HexStrike's requirements.
HEXSTRIKE_COMMANDS = ("pip", "pip3", "pip3.12", "httpx", "flask", "mcp", "uvicorn", "dotenv", "idna", "jsonschema",
                      "normalizer", "wsdump", "cffi-gen-src", "mitmproxy", "mitmdump", "mitmweb")
# The start of a compiled Linux program, as curl and ProjectDiscovery's httpx are.
COMPILED = b"\x7fELF\x02\x01\x01\x00" + bytes(56)


def escaped(text, times=1, **options):
    """`text` inside a JSON string, escaped `times` times."""
    for _ in range(times):
        text = json.dumps(text, **options)[1:-1]
    return text


def encodings(secret):
    """The ways a tool's output and a saved tool result can carry a secret: as typed, in a JSON
    string once, twice and three times (with and without \\u escapes), URL-encoded, and in an HTTP
    Basic authorization."""
    forms = {secret, quote(secret, safe=""), quote_plus(secret, safe=""), quote(secret)}
    for times in (1, 2, 3):
        forms |= {escaped(secret, times), escaped(secret, times, ensure_ascii=False)}
    forms.add(base64.b64encode(("test@example.com:" + secret).encode()).decode())
    return forms


def tool_output(secret):
    """What a HexStrike tool returns when its output echoes a login: the password as typed, in a
    target's JSON answer (Python's and Go's), in a form body and in curl's Basic authorization, as
    the MCP result's JSON the terminal keeps (the tool's JSON text inside it)."""
    go = escaped(secret, ensure_ascii=False).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    stdout = ("login ok as test@example.com password=" + secret + "\n"
              '{"user": "test@example.com", "password": "' + escaped(secret) + '"}\n'
              '{"password":"' + go + '"}\n'
              "> POST /login email=test%40example.com&password=" + quote_plus(secret) + "\n"
              "> Authorization: Basic " + base64.b64encode(("test@example.com:" + secret).encode()).decode() + "\n")
    text = json.dumps({"stdout": stdout, "return_code": 0}, ensure_ascii=False)
    return json.dumps({"meta": None, "content": [{"type": "text", "text": text}], "isError": False}, ensure_ascii=False)


def assert_hidden(test, text, secret):
    """No encoding of `secret` (nor its first five characters) is in `text`."""
    for form in encodings(secret):
        test.assertNotIn(form, text)
    test.assertNotIn(secret[:5], text)
# As `yougori inference run` writes them (cli/src/inference.rs answers_json): no password.
ANSWERS = {"target": ["https://staging.example.com", "10.0.0.5:8080", "intranet:8080"], "permission": True,
           "off_limits": ["/billing", "payments.example.com"], "depth": "full", "login_user": "test@example.com",
           "source": "/run/yougori/workspace", "focus": "Login and payments"}


def clean_environment():
    for name in profiles.PASSED_ON + ("SOLVER_REACH", VARIABLE, "SOLVER_HARNESS"):
        os.environ.pop(name, None)


def folder(test):
    """A temporary folder removed after the test."""
    path = Path(tempfile.mkdtemp())
    test.addCleanup(shutil.rmtree, path, ignore_errors=True)
    return path


class Brief(unittest.TestCase):
    def test_every_depth_is_said_in_plain_words(self):
        words = {"look": "How far it may go: Look only. Observe and map, change nothing.",
                 "safe": "How far it may go: Test safely. Test without harming data or service.",
                 "full": "How far it may go: Full exploitation. Confirm each finding, still only within the targets "
                         "and the off-limits list."}
        for depth, line in words.items():
            with self.subTest(depth=depth):
                self.assertIn(line, profiles.setup_brief({"target": "https://shop.example.test", "depth": depth}).splitlines())
        # A missing or unknown depth is the question's default, Test safely.
        for answers in ({"target": "https://shop.example.test"}, {"target": "https://shop.example.test", "depth": "all"}):
            self.assertIn(words["safe"], profiles.setup_brief(answers).splitlines())

    def test_the_practice_app_is_tested_at_its_address_inside_the_vm(self):
        expected = ("Test only this target: http://127.0.0.1:8000, the practice app inside this VM. It is deliberately "
                    "vulnerable and made for this test.")
        brief = profiles.setup_brief({"target": "practice", "depth": "safe"})
        self.assertEqual(brief.splitlines()[0], expected)
        self.assertNotIn("permission", brief)
        # The same brief once practice_target() has put the address in (as headless() does).
        spec = profiles.practice_target({"answers": {"target": "practice", "depth": "safe"}})
        self.assertEqual(profiles.setup_brief(spec["answers"]), brief)
        self.assertEqual(profiles.setup_targets(spec["answers"]), [profiles.PRACTICE_URL])

    def test_several_targets_and_every_answer(self):
        lines = profiles.setup_brief(ANSWERS).splitlines()
        self.assertEqual(lines, [
            "Test only these targets: https://staging.example.com, 10.0.0.5:8080, intranet:8080.",
            "The person running this test owns these targets or has written permission to test them.",
            "Off limits, never touch: /billing, payments.example.com.",
            "How far it may go: Full exploitation. Confirm each finding, still only within the targets and the "
            "off-limits list.",
            "Focus: Login and payments.",
            "Test login: user test@example.com. Its password is in the environment variable "
            "YOUGORI_SECRET_LOGIN_PASSWORD; use it from there and never write it into files, logs or reports.",
            "Source code: /run/yougori/workspace, a copy of the project in this VM.",
        ])
        one = profiles.setup_brief({"target": ["10.0.0.5"], "permission": True})
        self.assertIn("Test only this target: 10.0.0.5.", one)
        self.assertIn("owns this target or has written permission to test it.", one)
        # One line for a client that asks in one line; nothing without a target.
        self.assertNotIn("\n", profiles.setup_brief(ANSWERS, one_line=True))
        self.assertEqual((profiles.setup_brief({}), profiles.setup_brief({"depth": "full"})), ("", ""))
        self.assertEqual(profiles.setup_targets(None), [])

    def test_the_password_is_never_in_the_brief(self):
        careless = dict(ANSWERS, login_password=PASSWORD, focus="Login and payments")
        for one_line in (False, True):
            self.assertNotIn(PASSWORD, profiles.setup_brief(careless, one_line))
        self.assertNotIn(PASSWORD, json.dumps(profiles.shannon_config(careless)))


class Launchers(unittest.TestCase):
    def setUp(self):
        self.home = folder(self)
        self.work = folder(self)
        self.clean = patch.dict(os.environ, {}, clear=False)
        self.clean.start()
        clean_environment()

    def tearDown(self):
        self.clean.stop()

    def spec(self, harness, answers, reach=None):
        return profiles.headless(harness, "qwen3-coder", CATALOG, self.home, answers, cwd=self.work, reach=reach)

    def own(self, harness):
        return profiles.configure(harness, "qwen3-coder", CATALOG, folder(self))[0]

    def test_strix_takes_its_own_target_for_each_target_and_the_brief_as_its_instruction(self):
        spec = self.spec("strix", ANSWERS)
        self.assertEqual(spec["argv"], self.own("strix") + [
            "--target=https://staging.example.com", "--target=http://10.0.0.5:8080", "--target=http://intranet:8080",
            "--target=/run/yougori/workspace", "--instruction=" + profiles.setup_brief(ANSWERS)])
        self.assertEqual(spec["env"]["SOLVER_HARNESS"], "strix")
        self.assertEqual(spec["secret_env"], {VARIABLE: "login_password"})
        practice = self.spec("strix", {"target": "practice", "depth": "look"})
        self.assertIn("--target=http://127.0.0.1:8000", practice["argv"])
        self.assertEqual(practice["services"][0], profiles.PRACTICE_SERVICE)
        self.assertEqual(practice["secret_env"], {})

    def test_a_target_with_a_port_reaches_strix_as_a_web_address(self):
        for given, taken in {"https://a.example.com/app": "https://a.example.com/app", "10.0.0.5": "10.0.0.5",
                             "staging.example.com": "staging.example.com", "10.0.0.5:8080": "http://10.0.0.5:8080",
                             "intranet:8080": "http://intranet:8080",
                             "staging.example.com:443": "https://staging.example.com"}.items():
            self.assertEqual(profiles.strix_target(given), taken)

    def test_shannon_takes_its_targets_its_own_config_file_and_the_reach(self):
        reach = {"mode": "targets", "sites": [], "targets": ["staging.example.com:443", "10.0.0.5:8080", "intranet:8080"]}
        spec = self.spec("shannon", ANSWERS, reach)
        config = self.home / ".shannon/yougori-config.yaml"
        self.assertEqual(spec["argv"], self.own("shannon") + [
            "--target=https://staging.example.com", "--target=http://10.0.0.5:8080", "--target=http://intranet:8080",
            "--config=" + str(config)])
        self.assertEqual(json.loads(spec["env"]["SOLVER_REACH"]), reach)
        settings = json.loads(config.read_text(encoding="utf-8"))
        self.assertEqual(settings["rules"]["avoid"], [{"description": "Off limits", "type": "url_path", "value": "/billing"},
                                                      {"description": "Off limits", "type": "domain", "value": "payments.example.com"}])
        self.assertNotIn("exploit", settings)
        words = settings["rules_of_engagement"]
        self.assertLessEqual(len(words), profiles.SHANNON_WORDS)
        self.assertIn("How far it may go: Full exploitation.", words)
        self.assertIn("Focus: Login and payments.", words)
        self.assertNotIn("Off limits", words, "paths and hosts are its own rules")
        self.assertNotIn("authentication", settings, "it would need the password in the file")
        # The config file is in the VM's home, never in the workspace that comes back.
        self.assertEqual(list(self.work.iterdir()), [])
        look = profiles.shannon_config(dict(ANSWERS, depth="look", focus="/api"))
        self.assertEqual((look["exploit"], look["rules"]["focus"]), ("false", [{"description": "Focus", "type": "url_path", "value": "/api"}]))

    def test_shannon_refuses_answers_its_own_config_parser_would_refuse(self):
        for answer, value, named in (("off_limits", ["the <admin> area"], 'off-limits list has "<"'),
                                     ("focus", "uploads with data: links", 'focus has "data:"'),
                                     ("login_user", "file:admin", 'login has "file:"'),
                                     ("source", "/run/yougori/../etc", 'source code folder has "../"')):
            with self.subTest(answer=answer), self.assertRaisesRegex(ValueError, "Shannon refuses .* the " + named):
                self.spec("shannon", dict(ANSWERS, **{answer: value}))
        with self.assertRaisesRegex(ValueError, "Shorten the off-limits list .* or the focus"):
            self.spec("shannon", dict(ANSWERS, focus="x" * 900))
        self.assertFalse((self.home / ".shannon").exists(), "nothing is written for answers it refuses")

    def test_shannon_takes_a_target_whose_host_ends_in_data_or_file(self):
        # Its config parser refuses "data:" and "file:" in its settings: a target reaches it only
        # through --target, which it reads as an address.
        reach = {"mode": "targets", "sites": [], "targets": ["metadata:8000", "bigdata:8080", "profile:8443"]}
        targets = ["http://metadata:8000", "bigdata:8080", "profile:8443"]
        spec = self.spec("shannon", dict(ANSWERS, target=targets), reach)
        self.assertEqual([a for a in spec["argv"] if a.startswith("--target=")],
                         ["--target=http://metadata:8000", "--target=http://bigdata:8080", "--target=http://profile:8443"])
        words = json.loads((self.home / ".shannon/yougori-config.yaml").read_text(encoding="utf-8"))["rules_of_engagement"]
        self.assertNotRegex(words, profiles.SHANNON_REFUSES)
        self.assertNotIn("metadata", words)
        self.assertIn("The person running this test owns these targets or has written permission to test them.", words)
        self.assertIn("How far it may go: Full exploitation.", words)
        practice = profiles.shannon_config({"target": "practice", "depth": "safe"})["rules_of_engagement"]
        self.assertEqual(practice.splitlines()[0], "The target is the practice app inside this VM. It is deliberately "
                                                   "vulnerable and made for this test.")
        # The other harnesses' brief still names every target.
        self.assertIn("Test only these targets: http://metadata:8000, bigdata:8080, profile:8443.",
                      profiles.setup_brief(dict(ANSWERS, target=targets)))

    def test_pentagi_and_hexstrike_start_with_the_brief_as_their_task(self):
        for harness in ("pentagi", "hexstrike"):
            with self.subTest(harness=harness):
                spec = self.spec(harness, ANSWERS)
                self.assertEqual(spec["argv"], self.own(harness) + ["--task=" + profiles.setup_brief(ANSWERS)])
                self.assertEqual(spec["secret_env"], {VARIABLE: "login_password"})
        self.assertEqual(self.spec("pentagi", ANSWERS)["env"]["SOLVER_HARNESS"], "pentagi")
        self.assertNotIn("SOLVER_HARNESS", self.spec("hexstrike", ANSWERS)["env"])

    def test_pentestgpt_shows_the_brief_on_one_line_to_paste_at_its_first_question(self):
        spec = self.spec("pentestgpt", ANSWERS)
        self.assertEqual(spec["argv"][:4], ["/bin/sh", "-c", profiles.SHOW_FIRST, "pentestgpt"])
        self.assertEqual(spec["argv"][4].splitlines(), ["PentestGPT asks for the task first. Paste this line as its answer:",
                                                        profiles.setup_brief(ANSWERS, one_line=True)])
        self.assertEqual(spec["argv"][5:], self.own("pentestgpt"))

    def test_without_a_target_each_starts_as_its_terminal_client(self):
        for harness in sorted(profiles.SECURITY):
            with self.subTest(harness=harness):
                spec = self.spec(harness, {"depth": "full", "login_user": "test@example.com"})
                self.assertEqual(spec["argv"], self.own(harness))
                self.assertEqual(spec["secret_env"], {})

    def test_a_target_starts_nothing_without_the_yes_to_the_permission_question(self):
        # solver.py run yougori --answers-file takes answers from anyone, not only from the CLI,
        # which asks the question and always writes its yes.
        refusal, = {question["refusal"] for harness in json.loads((Path(profiles.__file__).parents[1] / "harnesses.json")
                                                                  .read_text(encoding="utf-8"))
                    for question in harness.get("questions", []) if question["id"] == "permission"}
        self.assertEqual(profiles.PERMISSION_REFUSAL, refusal)
        for harness in sorted(profiles.SECURITY):
            for answers in ({"target": ["https://shop.example.com"]}, {"target": "https://shop.example.com", "permission": False},
                            {"target": "https://shop.example.com", "permission": "yes"}):
                with self.subTest(harness=harness, answers=answers):
                    with self.assertRaises(ValueError) as refused:
                        self.spec(harness, dict(answers, login_user="test@example.com"))
                    self.assertEqual(str(refused.exception), refusal)
        self.assertFalse((self.home / ".shannon").exists(), "a refused run writes no settings")
        # The practice app inside the VM needs no permission; the CLI does not ask for it.
        for harness in sorted(profiles.SECURITY):
            with self.subTest(harness=harness, target="practice"):
                practice = self.spec(harness, {"target": "practice"})
                self.assertIn(profiles.PRACTICE_URL, " ".join(practice["argv"]))
                self.assertEqual(practice["services"][0], profiles.PRACTICE_SERVICE)

    def test_hexstrike_and_shannon_are_told_what_the_vm_reaches(self):
        reach = {"mode": "targets", "sites": ["pypi.org"], "targets": ["staging.example.com:443"]}
        for harness in ("hexstrike", "shannon"):
            with self.subTest(harness=harness):
                self.assertEqual(json.loads(self.spec(harness, ANSWERS, reach)["env"]["SOLVER_REACH"]), reach)
                # Without a target it starts exactly as its terminal client, whose instructions then
                # say nothing of the network.
                self.assertNotIn("SOLVER_REACH", self.spec(harness, {}, reach)["env"])
        for harness in ("strix", "pentagi", "pentestgpt"):
            self.assertNotIn("SOLVER_REACH", self.spec(harness, ANSWERS, reach)["env"])

    def test_the_password_reaches_each_harness_only_as_an_environment_variable(self):
        os.environ[VARIABLE] = PASSWORD  # As the VM holds it; headless() must not copy it anywhere.
        for harness in sorted(profiles.SECURITY):
            with self.subTest(harness=harness):
                spec = self.spec(harness, ANSWERS, {"mode": "targets", "sites": [], "targets": ["10.0.0.5:8080"]})
                self.assertEqual(spec["secret_env"], {VARIABLE: "login_password"})
                self.assertNotIn(PASSWORD, json.dumps(spec))
        for folder in (self.home, self.work):
            for path in folder.rglob("*"):
                if path.is_file():
                    self.assertNotIn(PASSWORD.encode(), path.read_bytes(), str(path))


class Results(unittest.TestCase):
    """Each harness's results land in the workspace (its cwd), so they come back to the person's
    folder only after their review: reports/strix (Strix's runs, copied there from its home without
    their state), Shannon's .shannon/runs (its own place), reports/pentagi, reports/hexstrike and
    PentestGPT's --log-dir reports/pentestgpt."""

    def setUp(self):
        self.home = folder(self)
        self.work = folder(self)
        self.clean = patch.dict(os.environ, {}, clear=False)
        self.clean.start()
        clean_environment()

    def tearDown(self):
        self.clean.stop()

    def test_every_harness_starts_in_the_workspace_and_saves_there(self):
        for harness in sorted(profiles.SECURITY):
            spec = profiles.headless(harness, "qwen3-coder", CATALOG, self.home, ANSWERS, cwd=self.work)
            self.assertEqual(spec["cwd"], str(self.work))
        argv = profiles.configure("pentestgpt", "qwen3-coder", CATALOG, self.home)[0]
        self.assertEqual(argv[argv.index("--log-dir") + 1], "reports/pentestgpt")
        for folder in (Path(profiles.PENTESTGPT_LOGS), pentagi_cli.REPORTS, hexstrike_cli.REPORTS):
            self.assertFalse(folder.is_absolute())
            self.assertEqual(folder.parts[0], "reports")
        self.assertIn("Reports go to .shannon/runs in the workspace.", shannon_cli.help_text())

    def test_pentagi_saves_the_flow_with_secrets_hidden(self):
        report = pentagi_cli.Report(self.work / pentagi_cli.REPORTS, 7, profiles.setup_brief(ANSWERS), [PASSWORD])
        report.message("Signed in as test@example.com with " + PASSWORD)
        report.reply("Go on with " + PASSWORD)
        with contextlib.redirect_stdout(io.StringIO()) as shown:
            report.end("finished")
        saved, = (self.work / "reports/pentagi").iterdir()
        text = saved.read_text(encoding="utf-8")
        self.assertTrue(saved.name.startswith("flow-7-") and saved.name.endswith(".md"))
        self.assertNotIn(PASSWORD, text)
        self.assertIn("with [hidden]", text)
        self.assertIn(profiles.setup_brief(ANSWERS), text)
        self.assertIn("The flow finished.", text)
        self.assertIn("reports/pentagi/" + saved.name, shown.getvalue().replace("\\", "/"))
        self.assertEqual(pentagi_cli.hidden_values({VARIABLE: PASSWORD, "HOME": "/home/node", "YOUGORI_SECRET_X": ""}), [PASSWORD])

    def test_a_report_that_cannot_be_written_is_said_once_and_the_flow_goes_on(self):
        blocked = self.work / "reports"
        blocked.write_text("a file where the folder would be", encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()) as shown:
            report = pentagi_cli.Report(blocked / "pentagi", 3, "task", [])
            report.message("one")
            report.end("finished")
            transcript = hexstrike_cli.Transcript(blocked / "hexstrike", [])
            transcript.reply("two")
        self.assertTrue(report.failed and transcript.failed)
        self.assertEqual(shown.getvalue().count("could not be saved"), 2)

    def test_hexstrike_saves_the_session_with_secrets_hidden(self):
        transcript = hexstrike_cli.Transcript(self.work / hexstrike_cli.REPORTS, [PASSWORD])
        transcript.person(profiles.setup_brief(ANSWERS))
        transcript.reply("Signed in with " + PASSWORD)
        transcript.tool("server_health", {"note": PASSWORD}, "status ``` fine")
        saved, = (self.work / "reports/hexstrike").iterdir()
        text = saved.read_text(encoding="utf-8")
        self.assertNotIn(PASSWORD, text)
        self.assertIn("````\nstatus ``` fine\n````", text)
        self.assertIn("### Tool server_health", text)

    def test_every_form_of_a_secret_is_hidden_in_a_hexstrike_tool_result(self):
        transcript = hexstrike_cli.Transcript(self.work / hexstrike_cli.REPORTS, [TRICKY])
        transcript.tool("execute_command", {"command": "curl -v -u test@example.com:" + TRICKY + " http://127.0.0.1:8000/login"},
                        tool_output(TRICKY))
        transcript.reply("Signed in with " + escaped(TRICKY, 2))
        saved, = (self.work / "reports/hexstrike").iterdir()
        text = saved.read_text(encoding="utf-8")
        assert_hidden(self, text, TRICKY)
        self.assertGreaterEqual(text.count("[hidden]"), 7)
        self.assertIn("login ok as test@example.com password=", text)
        self.assertIn("Authorization: Basic [hidden]", text)

    def test_a_secret_that_crosses_a_cut_leaves_no_part_behind(self):
        transcript = hexstrike_cli.Transcript(self.work / hexstrike_cli.REPORTS, [TRICKY])
        transcript.tool("server_health", {}, "x" * 7995 + TRICKY + "y" * 100)
        report = pentagi_cli.Report(self.work / pentagi_cli.REPORTS, 7, "task", [TRICKY])
        report.message("x" * (pentagi_cli.MESSAGE_LIMIT - 5) + TRICKY)
        for folder in ("reports/hexstrike", "reports/pentagi"):
            saved, = (self.work / folder).iterdir()
            text = saved.read_text(encoding="utf-8")
            assert_hidden(self, text, TRICKY)
            self.assertIn("[cut at ", text)

    def test_pentagi_hides_every_form_of_a_secret_in_its_messages(self):
        report = pentagi_cli.Report(self.work / pentagi_cli.REPORTS, 7, "task", [TRICKY])
        report.message(json.loads(tool_output(TRICKY))["content"][0]["text"])
        report.reply("Use " + quote(TRICKY, safe=""))
        with contextlib.redirect_stdout(io.StringIO()):
            report.end("finished")
        saved, = (self.work / "reports/pentagi").iterdir()
        assert_hidden(self, saved.read_text(encoding="utf-8"), TRICKY)

    def test_the_two_launchers_hide_alike_and_leave_other_text_alone(self):
        for secret in (TRICKY, PASSWORD, "pässwörd", "a/b", "emoji \U0001F600 pass"):
            self.assertEqual(hexstrike_cli.secret_forms([secret]), pentagi_cli.secret_forms([secret]))
            self.assertEqual(hexstrike_cli.secret_pattern([secret]).pattern, pentagi_cli.secret_pattern([secret]).pattern)
            for text in (tool_output(secret), "plain " + secret, escaped(secret, 3)):
                self.assertEqual(hexstrike_cli.Mask([secret])(text), pentagi_cli.Mask([secret])(text))
                self.assertNotIn(secret, pentagi_cli.Mask([secret])(text))
        mask = hexstrike_cli.Mask([TRICKY])
        other = ("Authorization: Basic " + base64.b64encode(b"test@example.com:other-password").decode()
                 + " configuration_value-check 8000/tcp open [hidden] Tr0ub le dor")
        self.assertEqual(mask(other), other)
        self.assertEqual(hexstrike_cli.Mask([])("password=" + TRICKY), "password=" + TRICKY)
        self.assertIsNone(hexstrike_cli.secret_pattern([]))
        # Each percent-encoded form at most once, longest first, so one holding another is hidden whole.
        forms = hexstrike_cli.secret_forms([TRICKY])
        self.assertEqual(forms, sorted(set(forms), key=lambda form: (-len(form), form)))

    def test_json_as_any_encoder_writes_it_is_hidden(self):
        mask = hexstrike_cli.Mask([TRICKY])
        jinja = escaped(TRICKY).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026").replace("'", "\\u0027")
        dotnet = (escaped(TRICKY).replace("<", "\\u003C").replace(">", "\\u003E").replace("&", "\\u0026")
                  .replace("\\u00e9", "\\u00E9"))
        php = escaped(TRICKY).replace("/", "\\/")
        go = escaped(TRICKY, ensure_ascii=False).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
        for written in (jinja, dotnet, php, go, escaped(go), escaped(escaped(php), ensure_ascii=False), escaped(dotnet, 2)):
            with self.subTest(written=written):
                self.assertEqual(mask('{"password": "' + written + '"}'), '{"password": "[hidden]"}')
        # A long secret of nothing but escaped characters is matched without backtracking.
        long = '\\"/<' * 1000
        started = time.monotonic()
        self.assertEqual(hexstrike_cli.Mask([long])("x" + escaped(long, 2) + "\\" * 5000), "x[hidden]" + "\\" * 5000)
        self.assertLess(time.monotonic() - started, 30)


class FakeServer:
    """HexStrike's server as the terminal starts it: like the real one, it writes hexstrike.log in
    the folder it starts in."""
    def __init__(self, *_, cwd=None, **__):
        self.stopped = False
        (Path(cwd or os.getcwd()) / "hexstrike.log").write_text("HexStrike started\n", encoding="utf-8")

    def poll(self):
        return None

    def terminate(self):
        self.stopped = True

    def wait(self, timeout=None):
        return 0

    def kill(self):
        self.stopped = True


def pip_command(module, python=b"/opt/solver/tool/bin/python3"):
    """A command as pip writes it in an environment: a script that runs `module`'s main with the
    environment's Python. A Python path too long for the first line goes on the second, after
    #!/bin/sh."""
    shebang = b"#!" + python if len(python) < 126 else b"#!/bin/sh\n'''exec' \"" + python + b"\" \"$0\" \"$@\"\n' '''"
    return (shebang + b"\n# -*- coding: utf-8 -*-\nimport re\nimport sys\nfrom " + module.encode() + b" import main\n"
            b"if __name__ == '__main__':\n    sys.argv[0] = re.sub(r'(-script\\.pyw|\\.exe)?$', '', sys.argv[0])\n"
            b"    sys.exit(main())\n")


def hexstrike_path(root, programs=("curl",), ahead=()):
    """shutil.which as it answers in HexStrike's VM, the VM's folders in `root`. In its PATH's order:
    the compiled programs `ahead`, HexStrike's own environment (HEXSTRIKE_COMMANDS, scripts as pip
    writes them), then the system's compiled `programs` (curl alone in the VM as built)."""
    folders = []
    for name, files in (("ahead", {program: COMPILED for program in ahead}),
                        ("opt/solver/tool/bin", {command: pip_command(command.replace("-", "_")) for command in HEXSTRIKE_COMMANDS}),
                        ("usr/bin", {program: COMPILED for program in programs})):
        path = Path(root) / name
        path.mkdir(parents=True)
        for file, data in files.items():
            (path / file).write_bytes(data)
        folders.append(path)
    return lambda program: next((str(path / program) for path in folders if (path / program).is_file()), None)


def fake_mcp(calls, result='{"status": "fine"}', names=("server_health",)):
    """A stand-in for the mcp package: the tools `names` (HexStrike's own names), whose calls are
    recorded; `result` is the JSON of a result as the terminal keeps it."""
    class Session:
        def __init__(self, *_):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            return False

        async def initialize(self):
            pass

        async def list_tools(self):
            return types.SimpleNamespace(tools=[types.SimpleNamespace(name=name, description=name + " as HexStrike describes it.",
                                                                      inputSchema={"type": "object"}) for name in names])

        async def call_tool(self, name, arguments):
            calls.append((name, arguments))
            return types.SimpleNamespace(model_dump_json=lambda: result)

    @contextlib.asynccontextmanager
    async def stdio_client(_, errlog=None):
        # HexStrike's MCP client logs to ~/hexstrike-mcp.log: on stderr its lines drew over the screen.
        if not str(getattr(errlog, "name", "")).endswith("hexstrike-mcp.log"):
            raise AssertionError("stdio_client must log to ~/hexstrike-mcp.log, not %r" % (errlog,))
        yield None, None

    package, client, stdio = (types.ModuleType(name) for name in ("mcp", "mcp.client", "mcp.client.stdio"))
    package.ClientSession, package.StdioServerParameters = Session, lambda **_: None
    stdio.stdio_client = stdio_client
    return {"mcp": package, "mcp.client": client, "mcp.client.stdio": stdio}


class LauncherOptions(unittest.TestCase):
    def setUp(self):
        self.clean = patch.dict(os.environ, {}, clear=False)
        self.clean.start()
        clean_environment()
        self.root = folder(self)
        self.was = os.getcwd()
        os.chdir(self.root)

    def tearDown(self):
        os.chdir(self.was)
        self.clean.stop()

    def test_pentagi_and_hexstrike_take_a_task_or_one_print_prompt(self):
        for launcher in (pentagi_cli, hexstrike_cli):
            with self.subTest(launcher=launcher.__name__):
                self.assertEqual(launcher.parse(["--model", "m", "--task", "Test only this target."]).task, "Test only this target.")
                self.assertEqual(launcher.parse(["--model", "m", "--print", "hi"]).prompt, "hi")
                for wrong in (["--model", "m", "--task", "a", "--print", "b"], ["--model", "m", "--task", "  "]):
                    with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
                        launcher.parse(wrong)

    def run_hexstrike(self, task, replies, result='{"status": "fine"}', names=("server_health",), inputs=("/exit",), offered=None):
        """hexstrike_cli's chat with --task in a workspace, its server and model faked (a reply that
        is an exception is raised by the model call; `offered` collects the tools each call got):
        the messages each model call got, the tool calls, how often the person was asked, the
        screen and the saved transcript."""
        workspace = self.root / "workspace"
        workspace.mkdir()
        os.chdir(workspace)
        replies, sent, tools = iter(replies), [], []

        def completion(model, messages, given):
            sent.append([dict(message) for message in messages])
            if offered is not None:
                offered.append([tool["function"]["name"] for tool in given])
            reply = next(replies)
            if isinstance(reply, BaseException):
                raise reply
            return reply

        with patch.dict(sys.modules, fake_mcp(tools, result, names)), \
             patch.object(hexstrike_cli, "completion", completion), \
             patch.object(hexstrike_cli.subprocess, "Popen", FakeServer), \
             patch.object(hexstrike_cli.socket, "create_connection", return_value=contextlib.nullcontext()), \
             patch.object(hexstrike_cli.Path, "home", return_value=self.root), \
             patch.object(hexstrike_cli.shutil, "which", lambda program: None), \
             patch("builtins.input", side_effect=list(inputs)) as asked, \
             contextlib.redirect_stdout(io.StringIO()) as shown:
            asyncio.run(hexstrike_cli.chat(hexstrike_cli.parse(["--model", "m", "--task", task])))
        saved, = (workspace / "reports/hexstrike").iterdir()
        return sent, tools, asked.call_count, shown.getvalue(), saved.read_text(encoding="utf-8")

    def test_hexstrike_takes_the_task_as_its_first_turn_then_goes_on_interactively(self):
        os.environ[VARIABLE] = PASSWORD
        task = profiles.setup_brief(ANSWERS)
        sent, tools, asked, shown, text = self.run_hexstrike(task, [
            {"role": "assistant", "content": "Checking.", "tool_calls": [{"id": "1", "function": {"name": "server_health", "arguments": "{}"}}]},
            {"role": "assistant", "content": "Done; signed in with " + PASSWORD},
        ])
        self.assertEqual(sent[0][1], {"role": "user", "content": task})
        self.assertEqual(tools, [("server_health", {})])
        self.assertEqual(asked, 1, "after the task the person goes on in the terminal")
        self.assertIn("hexstrike > " + task.splitlines()[0], shown)
        self.assertIn(task, text)
        self.assertIn("Done; signed in with [hidden]", text)
        self.assertNotIn(PASSWORD, text)
        self.assertNotIn(PASSWORD, shown)

    def test_hexstrike_tells_the_model_what_the_vm_reaches_and_hides_what_a_tool_echoes(self):
        # As headless() gives it for an outside target the VM's card is opened to.
        reach = {"mode": "targets", "sites": [], "targets": ["staging.example.com:443"]}
        spec = profiles.headless("hexstrike", "qwen3-coder", CATALOG, folder(self), dict(ANSWERS, target=["https://staging.example.com"]),
                                 cwd=self.root, reach=reach)
        os.environ.update(SOLVER_REACH=spec["env"]["SOLVER_REACH"], **{VARIABLE: TRICKY})
        echoed = tool_output(TRICKY)
        sent, _, _, shown, text = self.run_hexstrike(spec["argv"][-1][len("--task="):], [
            {"role": "assistant", "content": "Signing in.", "tool_calls": [{"id": "1", "function": {"name": "server_health", "arguments": "{}"}}]},
            {"role": "assistant", "content": "Signed in."},
        ], echoed)
        system = sent[0][0]
        self.assertEqual(system["role"], "system")
        self.assertNotIn("External networking is unavailable", system["content"])
        self.assertIn("this VM reaches only staging.example.com:443.", system["content"])
        self.assertIn("Test only this target: https://staging.example.com.", sent[0][1]["content"])
        # The secret a tool echoed reaches neither the model, nor the screen, nor the transcript.
        tool_message = sent[1][-1]
        self.assertEqual(tool_message["role"], "tool")
        self.assertIn("[hidden]", tool_message["content"])
        for seen in (json.dumps(sent), shown, text):
            assert_hidden(self, seen, TRICKY)

    def test_hexstrike_says_what_the_vm_reaches(self):
        def said(reach):
            return hexstrike_cli.system_message({"SOLVER_REACH": reach if isinstance(reach, str) else json.dumps(reach)})
        outside = said({"mode": "targets", "sites": [], "targets": ["staging.example.com:443", "10.0.0.5"]})
        self.assertEqual(outside, "You are the HexStrike terminal companion. Use the available tools only on the targets the "
                                  "person named and on this VM. Besides the model, this VM reaches only "
                                  "staging.example.com:443, 10.0.0.5. Never claim a tool ran if it returned an error.")
        self.assertIn("reaches only 10.0.0.5:8080 and the sites pypi.org over HTTPS.",
                      said({"mode": "targets", "sites": ["pypi.org"], "targets": ["10.0.0.5:8080"]}))
        full = said({"mode": "full", "sites": [], "targets": []})
        self.assertIn("This VM reaches the internet.", full)
        self.assertNotIn("unavailable", full)
        self.assertIn("External networking is unavailable.", said({"mode": "inference", "sites": [], "targets": []}))
        self.assertIn("External networking is unavailable, apart from the sites pypi.org, docs.python.org over HTTPS.",
                      said({"mode": "sites", "sites": ["pypi.org", "docs.python.org"], "targets": []}))
        # Not passed on (an older launcher) or not readable: nothing is said about the network.
        for unknown in ("", "not json", {"mode": "everything"}, ["targets"], {"mode": "targets", "targets": "10.0.0.5"}):
            with self.subTest(reach=unknown):
                text = said(unknown)
                if not isinstance(unknown, dict) or unknown.get("mode") != "targets":
                    self.assertNotIn("reaches", text)
                self.assertNotIn("unavailable", text)
                self.assertNotIn("10.0.0.5", text)
        self.assertEqual(hexstrike_cli.system_message({}), said(""))

    def test_hexstrike_offers_its_own_web_tools_within_the_strictest_model_server_limits(self):
        """HexStrike lists 150 tools (130 KiB), which every Yougori model server refused, and the site
        then sent the request on without them: the model saw no tool and made up their results."""
        def listed(description, schema):
            return [types.SimpleNamespace(name=name, description=description, inputSchema={"type": "object", "description": "s" * schema})
                    for name in HEXSTRIKE_TOOLS]

        def measured(tools):
            # As src-tauri/src/model_server.py validate_chat measures them.
            return len(tools), len(json.dumps(tools)), max(len(json.dumps(tool["function"])) for tool in tools)

        names = [name for name, _ in hexstrike_cli.WEB_TOOLS]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(set(names) - set(HEXSTRIKE_TOOLS), set(), "only HexStrike's own tools")
        everything = listed("d" * 400, 500)
        self.assertGreater(len(json.dumps([{"type": "function", "function": {"name": t.name, "description": t.description,
                                                                                "parameters": t.inputSchema}} for t in everything])), 48 * 1024)
        # The VM as built: HexStrike's own environment first on PATH, then the system's curl. The tools whose
        # programs are missing stay out, api_fuzzer and comprehensive_api_audit too, since they find endpoints
        # with ffuf. So does httpx_probe: the httpx on PATH is Python's command, not ProjectDiscovery's program.
        with patch.object(hexstrike_cli.shutil, "which", hexstrike_path(folder(self))):
            here = hexstrike_cli.offered(everything)
        self.assertEqual([tool["function"]["name"] for tool in here], [
            "http_framework_test", "http_repeater", "http_intruder", "http_set_scope", "http_set_rules", "execute_command",
            "api_schema_analyzer", "graphql_scanner", "jwt_analyzer", "ai_test_payload", "generate_payload", "ai_generate_payload",
            "detect_technologies_ai", "execute_python_script", "create_vulnerability_report", "server_health"])
        with patch.object(hexstrike_cli.shutil, "which", hexstrike_path(folder(self), ("curl", "ffuf"))):
            with_ffuf = hexstrike_cli.offered(everything)
        self.assertEqual({tool["function"]["name"] for tool in with_ffuf} - {tool["function"]["name"] for tool in here},
                         {"ffuf_scan", "api_fuzzer", "comprehensive_api_audit"})
        # With every program, as many as the strictest model server takes, in HexStrike's own words.
        for description, schema in (("d" * 400, 500), ("d" * 2900, 1500), ("d" * 3500, 12000)):
            with self.subTest(description=len(description), schema=schema):
                tools = hexstrike_cli.offered(listed(description, schema), lambda program: "/usr/bin/" + program)
                count, size, largest = measured(tools)
                self.assertTrue(0 < count <= 32 and size <= 48 * 1024 and largest <= 16 * 1024, (count, size, largest))
                self.assertEqual([tool["function"]["name"] for tool in tools], names[:count])
                self.assertEqual({tool["function"]["description"] for tool in tools}, {description[:3000]})
        # A tool over 16 KiB alone is left out, and the next one still fits.
        big = listed("d" * 100, 100)
        big[HEXSTRIKE_TOOLS.index("http_repeater")].inputSchema = {"type": "object", "description": "s" * 17000}
        chosen = [tool["function"]["name"] for tool in hexstrike_cli.offered(big, lambda program: None)]
        self.assertEqual(chosen[:2], ["http_framework_test", "http_intruder"])

    def test_hexstrike_offers_httpx_probe_only_with_projectdiscoverys_httpx(self):
        """Python's httpx, one of HexStrike's own requirements, puts an httpx command of its own first on
        the VM's PATH. httpx_probe was offered, and every call of it failed: that command takes none of
        the options of ProjectDiscovery's httpx, which httpx_probe runs."""
        listed = [types.SimpleNamespace(name=name, description="d", inputSchema={"type": "object"}) for name in HEXSTRIKE_TOOLS]
        with patch.object(hexstrike_cli.shutil, "which", hexstrike_path(folder(self))):
            # Only httpx is told apart from a Python command; another found on PATH counts.
            self.assertEqual({program: hexstrike_cli.runs(program) for program in ("httpx", "curl", "mitmproxy", "nmap")},
                             {"httpx": False, "curl": True, "mitmproxy": True, "nmap": False})
        # ProjectDiscovery's httpx ahead of HexStrike's own environment on PATH: httpx_probe is offered.
        with patch.object(hexstrike_cli.shutil, "which", hexstrike_path(folder(self), ahead=("httpx",))):
            self.assertIn("httpx_probe", [tool["function"]["name"] for tool in hexstrike_cli.offered(listed)])
        # Python's command as pip writes it for a long path does not count, nor one gone when it is read.
        root = folder(self)
        (root / "httpx").write_bytes(pip_command("httpx", b"/opt/" + b"p" * 140 + b"/bin/python3"))
        for found in (root / "httpx", root / "gone"):
            with self.subTest(found=found.name), patch.object(hexstrike_cli.shutil, "which", lambda program: str(found)):
                self.assertFalse(hexstrike_cli.runs("httpx"))

    def test_hexstrike_asks_the_model_with_only_the_web_tools_this_vm_runs(self):
        offered = []
        sent, tools, _, _, _ = self.run_hexstrike("Test the app.", [
            {"role": "assistant", "content": "Fetching.", "tool_calls": [{"id": "1", "function": {"name": "http_framework_test", "arguments": "{}"}}]},
            {"role": "assistant", "content": "Done."}], names=("server_health", "nmap_scan", "create_file", "http_framework_test"), offered=offered)
        self.assertEqual(offered, [["http_framework_test", "server_health"]] * 2)
        self.assertEqual(tools, [("http_framework_test", {})])
        with patch.object(hexstrike_cli.shutil, "which", lambda program: None), contextlib.redirect_stdout(io.StringIO()) as shown, \
                patch.dict(sys.modules, fake_mcp([], names=("nmap_scan", "http_repeater"))), \
                patch.object(hexstrike_cli.subprocess, "Popen", FakeServer), patch.object(hexstrike_cli.Path, "home", return_value=self.root), \
                patch.object(hexstrike_cli.socket, "create_connection", return_value=contextlib.nullcontext()):
            asyncio.run(hexstrike_cli.chat(hexstrike_cli.parse(["--model", "m", "--list-tools"])))
        self.assertEqual(shown.getvalue(), "http_repeater\n")

    def test_hexstrike_starts_its_server_in_the_home_folder_so_its_log_stays_out_of_the_review(self):
        """HexStrike's server writes hexstrike.log where it starts: started in the workspace, the log
        came back in every review."""
        self.run_hexstrike("Test the app.", [{"role": "assistant", "content": "Done."}])
        self.assertEqual([path.name for path in (self.root / "workspace").iterdir()], ["reports"])
        self.assertTrue((self.root / "hexstrike.log").is_file())

    def test_hexstrike_shows_why_the_model_could_not_answer_and_goes_on(self):
        refusal = hexstrike_cli.Refused("Conversation exceeds 32,768 characters; start a new chat")
        sent, _, asked, shown, text = self.run_hexstrike("Test the app.", [refusal, {"role": "assistant", "content": "Here again."}],
                                                         inputs=("Try once more", "/exit"))
        self.assertIn("The model could not answer: Conversation exceeds 32,768 characters; start a new chat", shown)
        self.assertIn("The model could not answer: Conversation exceeds 32,768 characters; start a new chat", text)
        self.assertEqual(asked, 2, "the person goes on after the refusal")
        # The refused turn is taken back: the next call holds the instructions and the new turn only.
        self.assertEqual([message["role"] for message in sent[1]], ["system", "user"])
        self.assertEqual(sent[1][1]["content"], "Try once more")

    def test_hexstrike_reads_the_words_of_a_refused_model_call(self):
        def opener(status, body):
            def refuse(request, timeout):
                raise urllib.error.HTTPError(request.full_url, status, "Refused", {}, io.BytesIO(body))
            return types.SimpleNamespace(open=refuse)

        for status, body, words in (
                (400, b'{"error": {"message": "Agent tools require the GGUF or vLLM runner and 1 to 32 function definitions.\\nThis request sent 150."}}',
                 "Agent tools require the GGUF or vLLM runner and 1 to 32 function definitions. This request sent 150."),
                (429, b'{"error": {"message": "This service is at capacity. Retry shortly."}}', "This service is at capacity. Retry shortly."),
                (502, b"<html>gateway</html>", "The inference answered HTTP 502.")):
            with self.subTest(status=status), patch.object(hexstrike_cli.urllib.request, "build_opener", lambda *_: opener(status, body)):
                with self.assertRaises(hexstrike_cli.Refused) as refused:
                    hexstrike_cli.completion("m", [{"role": "user", "content": "hi"}], [])
                self.assertEqual(str(refused.exception), words)

    def test_strix_runs_on_its_own_image_and_on_the_shared_base_holding_its_pack(self):
        marker = self.root / "harness-name"
        cases = [("strix", {}, True), ("yougori", {"SOLVER_HARNESS": "strix"}, True),
                 ("yougori", {"SOLVER_HARNESS": "pentagi"}, False), ("yougori", {}, False),
                 ("opencode", {"SOLVER_HARNESS": "strix"}, False)]
        for image, environment, allowed in cases:
            with self.subTest(image=image, environment=environment):
                marker.write_text(image + "\n", encoding="utf-8")
                self.assertIs(strix_cli.allowed_here(marker, environment, "linux"), allowed)
        self.assertFalse(strix_cli.allowed_here(marker, {"SOLVER_HARNESS": "strix"}, "win32"))
        self.assertFalse(strix_cli.allowed_here(self.root / "missing", {"SOLVER_HARNESS": "strix"}, "linux"))

    def test_shannon_scans_each_target_in_turn_then_stays_open(self):
        targets = ["http://127.0.0.1:8000", "http://localhost:8001"]
        with patch.object(shannon_cli, "run_once", return_value=0) as scan, \
             patch.object(shannon_cli, "session", return_value=0) as stay, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(shannon_cli.main(["--model", "m", "--target", targets[0], "--target", targets[1],
                                               "--target", targets[0], "--config", "c.yaml"]), 0)
        self.assertEqual([call.args[0].target for call in scan.call_args_list], targets)
        self.assertTrue(all(not call.args[0].validate_model and call.args[0].config == Path("c.yaml") for call in scan.call_args_list))
        self.assertEqual(stay.call_args.kwargs, {"greet": False})

    def test_shannon_checks_every_target_before_the_first_scan(self):
        with patch.object(shannon_cli, "run_once") as scan, contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(ValueError, "must run inside this VM"):
                shannon_cli.main(["--model", "m", "--target", "http://127.0.0.1:8000", "--target", "https://outside.example.com"])
            os.environ["SOLVER_EMPTY_WORKSPACE"] = "1"
            with patch.object(shannon_cli, "session", return_value=0) as stay:
                shannon_cli.main(["--model", "m", "--target", "http://127.0.0.1:8000"])
            stay.assert_called_once()
        scan.assert_not_called()

    def test_shannon_takes_a_target_outside_the_vm_only_when_the_vm_reaches_it(self):
        os.environ["SOLVER_REACH"] = json.dumps({"mode": "targets", "targets": ["staging.example.com:443", "10.0.0.5"]})
        for allowed in ("https://staging.example.com/app", "http://10.0.0.5:8080", "http://127.0.0.1:8000"):
            self.assertEqual(shannon_cli.target_url(allowed), allowed)
        for refused in ("https://other.example.com", "http://staging.example.com", "https://user:pw@staging.example.com"):
            with self.assertRaisesRegex(ValueError, "reaches only the inference and staging.example.com:443, 10.0.0.5"):
                shannon_cli.target_url(refused)
        os.environ["SOLVER_REACH"] = json.dumps({"mode": "full"})
        self.assertEqual(shannon_cli.target_url("https://anything.example.org"), "https://anything.example.org")
        with self.assertRaisesRegex(ValueError, "without a login"):
            shannon_cli.target_url("ftp://anything.example.org")

    def test_shannon_model_check_runs_once_without_a_target(self):
        with patch.object(shannon_cli, "run_once", return_value=0) as check:
            self.assertEqual(shannon_cli.main(["--model", "m", "--validate-model"]), 0)
        self.assertIsNone(check.call_args.args[0].target)
        self.assertTrue(check.call_args.args[0].validate_model)


class PrintPath(unittest.TestCase):
    def setUp(self):
        self.clean = patch.dict(os.environ, {"SOLVER_MODEL": "qwen3-coder"}, clear=False)
        self.clean.start()

    def tearDown(self):
        self.clean.stop()

    def run_harness(self, harness, *arguments):
        ran = []
        with patch.object(runtime, "claim_terminal"), patch.object(runtime, "wait_for_catalog", return_value=CATALOG), \
             patch.object(runtime, "configure", return_value=([harness + "-client"], {"HOME": "/home/node"})), \
             patch.object(runtime.blue, "run", side_effect=lambda argv, env: ran.append(argv) or 0), \
             patch.object(runtime.sys, "argv", ["runtime.py", "run", harness, *arguments]):
            runtime.run(harness)
        return ran

    def test_pentestgpt_has_no_one_shot_shortcut(self):
        with self.assertRaises(ValueError) as refused:
            self.run_harness("pentestgpt", "--print", "Say OK.")
        self.assertEqual(str(refused.exception), runtime.PENTESTGPT_INTERACTIVE)
        self.assertIn("without --print", runtime.PENTESTGPT_INTERACTIVE)
        # Its interactive client starts as before.
        self.assertEqual(self.run_harness("pentestgpt"), [["pentestgpt-client"]])

    def test_the_other_print_paths_are_unchanged(self):
        argv, = self.run_harness("interpreter", "--print", "Say OK.")
        self.assertEqual((argv[0], argv[1], argv[-2:]), ("/opt/solver/tool/bin/python", "-c", ["qwen3-coder", "Say OK."]))
        self.assertEqual(self.run_harness("strix", "--print", "Say OK."), [["strix-client", "--print", "Say OK."]])


class FakeFlow:
    """PentAGI's REST API for flow 7, in memory: its messages, filtered as the pinned server filters
    them (filters[] on id, with > or in; oldest first; a page at most), and its status. `statuses`
    are what the status reads return (the last one repeats); `then` holds changes PentAGI's workers
    make right after a given status read, before the next read."""
    def __init__(self, messages, statuses):
        self.messages = [dict(message) for message in messages]
        self.statuses, self.reads, self.then, self.updates, self.queries = list(statuses), 0, {}, [], []

    def request(self, path, data=None, method=None):
        if path == "/flows/7":
            status = self.statuses[min(self.reads, len(self.statuses) - 1)]
            self.reads += 1
            self.then.pop(self.reads, lambda flow: None)(self)
            return {"id": 7, "status": status}
        address = urlsplit(path)
        assert address.path == "/flows/7/msglogs/", path
        query = parse_qs(address.query)
        assert (query["page"], query["type"], json.loads(query["sort[]"][0])) == (["1"], ["filter"], {"prop": "id", "order": "ascending"})
        condition, = (json.loads(item) for item in query["filters[]"])
        self.queries.append(condition)
        test = {">": lambda key: key > condition["value"], "in": lambda key: key in condition["value"]}[condition["operator"]]
        found = sorted((dict(message) for message in self.messages if test(message["id"])), key=lambda message: message["id"])
        return {"msglogs": found[:int(query["pageSize"][0])], "total": len(found)}

    def update(self, data):
        self.updates.append(data)

    def result(self, key, text):
        next(message for message in self.messages if message["id"] == key)["result"] = text


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def pause(self, seconds):
        self.now += seconds


TASK = "Test only this target: http://127.0.0.1:8000, the practice app inside this VM."
WRITE_UP = "Write-up: one finding, a reflected XSS on /search."


class PentagiFlow(unittest.TestCase):
    """pentagi_cli.follow(): what the terminal shows and saves of a flow, and when it asks."""

    def setUp(self):
        self.work = folder(self)
        self.clock = FakeClock()

    def follow(self, flow, replies=(), one_shot=False):
        """Follows `flow`; returns what follow() returned (or raised), the screen and the saved report,
        and for each time the person was asked, what the screen showed by then."""
        report = None if one_shot else pentagi_cli.Report(self.work / pentagi_cli.REPORTS, 7, TASK, [TRICKY])
        replies, asked = list(replies), []

        def ask(prompt):
            asked.append(shown.getvalue())
            return replies.pop(0)

        with contextlib.redirect_stdout(io.StringIO()) as shown:
            try:
                outcome = pentagi_cli.follow(flow.request, flow.update, 7, report, one_shot, ask, self.clock, self.clock.pause,
                                             report.mask if report else pentagi_cli.Mask([TRICKY]))
            except ValueError as error:
                outcome = error
        saved = "" if one_shot else next((self.work / "reports/pentagi").iterdir()).read_text(encoding="utf-8")
        return outcome, shown.getvalue(), saved, asked

    def task_flow(self):
        """A task whose tool's result comes after its message, and whose end PentAGI writes as
        PentAGI does: the flow waits (the task is done) before the task's report is stored, and a
        subtask's report, which is not the write-up, comes first."""
        flow = FakeFlow([{"id": 1, "type": "input", "message": TASK},
                         {"id": 2, "type": "terminal", "message": "Scan the practice app's ports", "result": "", "task_id": 1,
                          "subtask_id": 1}], ["running", "waiting"])
        flow.then = {1: lambda flow: flow.result(2, "8000/tcp open"),
                     2: lambda flow: flow.messages.append({"id": 3, "type": "report", "message": "Scan the ports", "result": "",
                                                           "task_id": 1, "subtask_id": 1}),
                     3: lambda flow: flow.messages.append({"id": 4, "type": "report", "message": "Test the practice app",
                                                           "result": WRITE_UP, "task_id": 1})}
        return flow

    def test_the_write_up_is_shown_and_saved_before_the_person_is_asked(self):
        outcome, shown, saved, asked = self.follow(self.task_flow(), ["/exit"])
        self.assertEqual(outcome, 0)
        self.assertEqual(len(asked), 1)
        self.assertIn(WRITE_UP, asked[0], "the task's report came before the question")
        self.assertIn('Result of "Scan the practice app\'s ports":\n\n8000/tcp open', asked[0])
        order = [saved.index(text) for text in ("## Task", "Scan the practice app's ports", "8000/tcp open", "Scan the ports",
                                                WRITE_UP, "## End", "The flow was stopped from this terminal.")]
        self.assertEqual(order, sorted(order))
        self.assertEqual(saved.count(TASK), 1, "its own input is not shown again")

    def test_one_print_returns_only_after_the_write_up(self):
        outcome, shown, _, asked = self.follow(self.task_flow(), one_shot=True)
        self.assertEqual((outcome, asked), (0, []))
        self.assertIn(WRITE_UP, shown)

    def test_a_question_is_shown_and_a_reply_still_waiting_to_be_taken_asks_nothing(self):
        flow = FakeFlow([{"id": 1, "type": "input", "message": TASK},
                         {"id": 2, "type": "ask", "message": "Which login page should I use?",
                          "result": "function ask successfully processed arguments", "task_id": 1, "subtask_id": 1}],
                        ["waiting", "waiting", "waiting", "running", "waiting"])
        # The flow takes the reply a moment later; the next task's report comes after it waits again.
        flow.then = {5: lambda flow: flow.messages.append({"id": 3, "type": "input", "message": "/login"}),
                     6: lambda flow: flow.messages.append({"id": 4, "type": "report", "message": "Test the login",
                                                           "result": WRITE_UP, "task_id": 2})}
        outcome, shown, saved, asked = self.follow(flow, ["/login", "/exit"])
        self.assertEqual(outcome, 0)
        self.assertEqual(flow.updates, [{"action": "input", "input": "/login"}])
        self.assertEqual(len(asked), 2)
        self.assertIn("Which login page should I use?", asked[0])
        self.assertNotIn(WRITE_UP, asked[0])
        self.assertIn(WRITE_UP, asked[1])
        self.assertNotIn("function ask successfully processed arguments", shown + saved)
        self.assertIn("**Reply:** /login", saved)

    def test_a_flow_that_ends_without_a_write_up_ends_after_a_short_wait(self):
        outcome, _, saved, asked = self.follow(FakeFlow([{"id": 1, "type": "input", "message": TASK}], ["finished"]))
        self.assertEqual((outcome, asked), (0, []))
        self.assertGreaterEqual(self.clock.now, pentagi_cli.SETTLE_SECONDS)
        self.assertLess(self.clock.now, pentagi_cli.SETTLE_SECONDS + 2)
        self.assertTrue(saved.endswith("## End\n\nThe flow finished.\n"))

    def test_a_failed_flow_saves_why_before_it_ends(self):
        flow = FakeFlow([{"id": 1, "type": "input", "message": TASK}], ["failed"])
        flow.then = {1: lambda flow: flow.messages.append({"id": 2, "type": "report", "message": "The task could not start: no model",
                                                           "result": TASK})}
        outcome, _, saved, _ = self.follow(flow)
        self.assertIsInstance(outcome, ValueError)
        self.assertIn("failed flow", str(outcome))
        self.assertLess(saved.index("The task could not start: no model"), saved.index("The flow failed."))

    def test_a_result_that_never_comes_is_asked_for_until_it_is_too_late(self):
        flow = FakeFlow([{"id": 1, "type": "input", "message": TASK},
                         {"id": 2, "type": "terminal", "message": "A command that hangs", "result": ""}], ["running"])
        outcome, _, saved, _ = self.follow(flow)
        self.assertIsInstance(outcome, ValueError)
        self.assertIn("one-hour limit", str(outcome))
        asked_at = [index for index, condition in enumerate(flow.queries) if condition["operator"] == "in"]
        self.assertEqual({tuple(flow.queries[index]["value"]) for index in asked_at}, {(2,)})
        # One message read a second: asked for during LATER_SECONDS, then no more.
        self.assertLess(abs(len(asked_at) - pentagi_cli.LATER_SECONDS), 5)
        self.assertTrue(saved.endswith("The flow reached this session’s one-hour limit.\n"))

    def test_secrets_are_hidden_on_the_screen_and_in_the_report(self):
        flow = FakeFlow([{"id": 1, "type": "input", "message": TASK},
                         {"id": 2, "type": "terminal", "message": "Sign in", "result": tool_output(TRICKY)},
                         {"id": 3, "type": "report", "message": "Signed in", "result": "Used " + escaped(TRICKY, 2), "task_id": 1}],
                        ["waiting"])
        _, shown, saved, _ = self.follow(flow, ["/exit"])
        for seen in (shown, saved):
            assert_hidden(self, seen, TRICKY)
        self.assertIn("Used [hidden]", saved)


if __name__ == "__main__":
    unittest.main()
