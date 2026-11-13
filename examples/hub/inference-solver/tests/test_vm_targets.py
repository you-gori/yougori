"""Targets outside the VM: the launcher checks them on this computer (never this computer or a
name leading to it or to a private address not named itself; a web address as its host and
port), refuses a Yougori that cannot hold the VM to them, passes them to the engine and the VM,
tells the person what the VM reaches (and what full internet reaches on this Yougori), and stops
a VM the engine did not hold to them. Inside the VM, targets beside chosen sites go straight
out, and a target sharing a site's name keeps that site on the proxy. The engine's own filter
is tested in Rust (sandbox/qemu_host/network_filter_tests.rs, network_names_tests.rs,
sandbox_vm/engine/network.rs)."""
import contextlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import patch
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "site/harnesses"))
# vm_guest runs in the Linux VM; its terminal modules are not needed for what these tests check.
for linux_only in ("fcntl", "pty", "termios"):
    sys.modules.setdefault(linux_only, types.ModuleType(linux_only))
import solver
import vm_guest
import vm_host
import vm_tunnel

OWN = {"127.0.0.1", "192.168.1.10"}
NAMES = {"staging.mycompany.com": ["93.184.216.34"], "intranet.mycompany.com": ["10.9.9.9"],
         "mypc.lan": ["192.168.1.10"], "rebind.example.com": ["93.184.216.35", "192.168.1.50"],
         "gateway.example.com": ["10.0.2.2"], "meta.example.com": ["169.254.169.254"]}


def resolve(host):
    if host not in NAMES:
        raise OSError("No such host is known.")
    return NAMES[host]


CHECK_TARGETS = vm_host.check_targets


def check(*targets):
    return CHECK_TARGETS(list(targets), resolve=resolve, own=OWN)


class Checks(unittest.TestCase):
    def test_named_hosts_and_addresses_pass_as_given(self):
        targets = ["staging.mycompany.com:443", "192.168.1.50:8080", "10.1.2.3", "intranet.mycompany.com:443", "10.9.9.9:443"]
        self.assertEqual(check(*targets), targets)

    def test_this_computer_is_refused_plainly(self):
        for target, said in (("localhost:8080", "localhost is this computer"),
                             ("192.168.1.10:8080", "192.168.1.10 is an address of this computer"),
                             ("127.0.0.1", "is an address of this computer"),
                             ("mypc.lan:3389", "mypc.lan leads to this computer (192.168.1.10)"),
                             ("10.0.2.2:8080", "in the VM's own network"),
                             ("gateway.example.com", "leads to 10.0.2.2, which is in the VM's own network")):
            with self.assertRaises(ValueError) as refused:
                check(target)
            self.assertIn(said, str(refused.exception))
            self.assertIn("never reaches this computer" if "computer" in said else "Name another address",
                          str(refused.exception))
        with self.assertRaises(ValueError) as refused:
            vm_host.check_targets([vm_host.socket.gethostname() + ":80"], resolve=resolve, own=OWN)
        self.assertIn("is this computer", str(refused.exception))

    def test_a_name_never_opens_a_private_network_by_itself(self):
        with self.assertRaises(ValueError) as refused:
            check("rebind.example.com:443")
        self.assertEqual(str(refused.exception), "rebind.example.com leads to 192.168.1.50, an address on a private network. "
                                                 "Name 192.168.1.50:443 too to let the VM reach it.")
        self.assertEqual(check("rebind.example.com:443", "192.168.1.50:443"), ["rebind.example.com:443", "192.168.1.50:443"])
        with self.assertRaises(ValueError) as refused:
            check("meta.example.com")
        self.assertIn("an address a VM never reaches", str(refused.exception))

    def test_the_launcher_says_plainly_that_localhost_is_this_computer(self):
        for target in ("localhost:3000", "app.localhost:8080", "127.0.0.1", "127.1.2.3:22"):
            with self.assertRaises(ValueError) as refused:
                solver.target_host(target)
            self.assertEqual(str(refused.exception), target + " is this computer. " + vm_host.THIS_COMPUTER)
        with self.assertRaises(ValueError) as refused:
            solver.target_host("0.0.0.0")
        self.assertIn("not an address of a computer to test", str(refused.exception))

    def test_a_name_this_computer_cannot_find_is_refused(self):
        with self.assertRaises(ValueError) as refused:
            check("missing.mycompany.com:443")
        self.assertIn("could not be found from this computer", str(refused.exception))

    def test_this_computer_is_known_by_more_than_its_loopback(self):
        own = vm_host.this_computer()
        self.assertIn("127.0.0.1", own)
        self.assertTrue(all(vm_host.ipaddress.ip_address(address).version == 4 for address in own))

    def test_what_the_person_is_told(self):
        # A host named by its name: its addresses may serve other sites, which the filter
        # refuses by the site each HTTPS and HTTP connection asks for; other protocols name none.
        self.assertEqual(vm_host.reaches(targets=["staging.mycompany.com:443"]),
                         "It reaches only this inference and staging.mycompany.com:443. Yougori checks the site each "
                         "HTTPS and HTTP connection asks for, so other sites sharing a named host's addresses are refused; "
                         "other kinds of connection there, such as SSH, reach whatever answers on the chosen ports.")
        # Addresses named themselves are reached as they are.
        self.assertEqual(vm_host.reaches(targets=["192.168.1.50:8080", "10.1.2.3"], sites=["github.com"]),
                         "It reaches only this inference and 192.168.1.50:8080, 10.1.2.3 (every port), and github.com "
                         "through Yougori's relay.")
        self.assertEqual(vm_host.reaches(), "It reaches only this inference: Yougori relays its model requests.")

    def test_full_internet_is_promised_public_only_when_this_yougori_filters_it(self):
        filtered = vm_host.reaches(internet=True, filtered=True)
        self.assertIn("It can reach the public internet, never this computer or its network", filtered)
        older = vm_host.reaches(internet=True)
        self.assertNotIn("never this computer", older)
        self.assertIn("also this computer's own services and its network", older)
        self.assertIn("yougori update", older)

    def test_a_web_address_given_as_a_target_is_taken_as_its_host_and_port(self):
        for given, taken in (("https://staging.mycompany.com", "staging.mycompany.com:443"),
                             ("http://192.168.1.50:8080/app?x=1", "192.168.1.50:8080"),
                             ("HTTP://Staging.MyCompany.com./", "staging.mycompany.com:80"),
                             ("https://staging.mycompany.com:8443/login", "staging.mycompany.com:8443")):
            self.assertEqual(solver.target_host(given), taken)
        self.assertEqual(solver.target_list("targets", "https://a.example.com,a.example.com:443,http://a.example.com"),
                         ["a.example.com:443", "a.example.com:80"])
        for given, said in (("ftp://files.mycompany.com", "is not an http or https address"),
                            ("https://user:pw@staging.mycompany.com", "Give the login in its own question"),
                            ("https://[::1]:8080/", "IPv6 addresses are not taken"),
                            ("https://staging.mycompany.com:99999/", "is not a web address"),
                            ("http://localhost:3000", "is this computer"),
                            ("https://", "needs a host name")):
            with self.assertRaises(ValueError, msg=given) as refused:
                solver.target_host(given)
            self.assertIn(said, str(refused.exception))

    def test_launch_parameters_hold_the_card_to_the_targets(self):
        params = vm_host.launch_params("pi", "sha256:" + "a" * 64, None, targets=["staging.mycompany.com:443"])
        self.assertEqual(params["targets"], ["staging.mycompany.com:443"])
        self.assertNotIn("internet", params)
        self.assertNotIn("targets", vm_host.launch_params("pi", "sha256:" + "a" * 64, None))


class Engine(unittest.TestCase):
    def test_a_yougori_without_targets_is_refused_before_anything_starts(self):
        for answer in ({"gpu": {"available": False}}, {"targets": True}, {"targets": {"available": False}}, ValueError("unknown action")):
            def call(action, **params):
                if isinstance(answer, Exception):
                    raise answer
                return answer
            with patch.object(vm_host, "call", call), self.assertRaises(ValueError) as refused:
                vm_host.hold_targets()
            self.assertIn("cannot hold a VM to chosen targets yet", str(refused.exception))
        with patch.object(vm_host, "call", lambda action, **params: {"targets": {"available": True}}):
            vm_host.hold_targets()


class Guest(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.server.bodies.append((self.path, body))
        reply = self.server.start if self.path == "/start" else {"output": "", "requests": [], "tunnels": [], "exit": 0}
        raw = json.dumps(reply).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


HELD = [{"host": "staging.mycompany.com", "addresses": ["93.184.216.34"], "ports": [443]}]


class Launch(unittest.TestCase):
    def setUp(self):
        self.guest = ThreadingHTTPServer(("127.0.0.1", 0), Guest)
        self.guest.bodies = []
        self.guest.start = {"started": True, "tunnels": True, "yougori": True, "targets": True}
        threading.Thread(target=self.guest.serve_forever, daemon=True).start()
        self.addCleanup(self.guest.server_close)
        self.addCleanup(self.guest.shutdown)
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.key_file = Path(folder.name) / "api-key"
        self.key_file.write_text("is_test-key")
        self.engine = []
        self.launched = {}
        self.held = HELD
        self.capable = True

    def call(self, action, **params):
        self.engine.append(action)
        if action == "capabilities":
            return {"targets": {"available": True}} if self.capable else {"gpu": {"available": False}}
        if action == "launch":
            self.launched = params
            return {"sandbox": "exe-" + "a" * 32, **({"reach": {"targets": self.held}} if self.held else {})}
        if action == "publish":
            return {"url": "http://abc123.localhost:%d/" % self.guest.server_port}
        return {}

    def launch(self, **keywords):
        printed = io.StringIO()
        with patch.object(vm_host, "install", lambda name, server, root: "sha256:" + "b" * 64), \
                patch.object(vm_host, "install_yougori", lambda held, server, root: ("sha256:" + "b" * 64, {"harness": held}, 4)), \
                patch.object(vm_host, "call", self.call), patch.object(vm_host, "tidy", lambda sandbox, folder: False), \
                patch.object(vm_host, "prepare_tool", lambda control, root, declaration=None: None), \
                patch.object(vm_host, "check_targets", lambda targets: check(*targets)), contextlib.redirect_stdout(printed):
            code = vm_host.launch("strix", "http://127.0.0.1:9", self.key_file, "m", None, [], False, **keywords)
        return code, printed.getvalue()

    def test_targets_go_to_the_engine_and_the_vm_and_the_person_is_told(self):
        code, printed = self.launch(targets=["staging.mycompany.com:443"])
        self.assertEqual(code, 0)
        self.assertIn("It reaches only this inference and staging.mycompany.com:443.", printed)
        self.assertEqual(self.launched["targets"], ["staging.mycompany.com:443"])
        self.assertNotIn("internet", self.launched)
        start = next(body for path, body in self.guest.bodies if path == "/start")
        self.assertEqual(start["targets"], ["staging.mycompany.com:443"])
        self.assertEqual(self.engine[0], "capabilities")
        self.assertIn("stop", self.engine)

    def test_nothing_starts_for_a_target_that_is_this_computer_or_on_an_older_yougori(self):
        with self.assertRaises(ValueError) as refused:
            self.launch(targets=["192.168.1.10:8080"])
        self.assertIn("is an address of this computer", str(refused.exception))
        self.capable = False
        with self.assertRaises(ValueError) as refused:
            self.launch(targets=["staging.mycompany.com:443"])
        self.assertIn("cannot hold a VM to chosen targets yet", str(refused.exception))
        self.assertNotIn("launch", self.engine)
        with self.assertRaises(ValueError):
            self.launch(targets=["staging.mycompany.com:443"], internet=True)

    def test_a_command_line_older_than_targets_starts_nothing(self):
        engine = self.call

        def older(action, **params):
            if action == "launch":
                self.engine.append(action)
                raise ValueError("Unknown parameter 'targets' for sandbox_vm")
            return engine(action, **params)
        self.call = older
        with self.assertRaises(ValueError) as refused:
            self.launch(targets=["staging.mycompany.com:443"])
        self.assertIn("cannot hold a VM to chosen targets yet", str(refused.exception))
        self.assertNotIn("stop", self.engine)

    def test_a_vm_the_engine_did_not_hold_to_the_targets_is_stopped(self):
        self.held = None
        with self.assertRaises(ValueError) as refused:
            self.launch(targets=["staging.mycompany.com:443"])
        self.assertIn("did not hold the VM to the chosen targets", str(refused.exception))
        self.assertEqual(self.engine[-1], "stop")
        self.assertEqual(self.guest.bodies, [])

    def test_full_internet_starts_and_says_what_this_yougori_holds_it_to(self):
        code, printed = self.launch(internet=True)
        self.assertEqual((code, self.launched.get("internet")), (0, True))
        self.assertIn("It can reach the public internet, never this computer or its network", printed)
        # An older Yougori gives the VM QEMU's plain network: it starts, and the person is told.
        self.capable = False
        code, printed = self.launch(internet=True)
        self.assertEqual(code, 0)
        self.assertNotIn("never this computer", printed)
        self.assertIn("also this computer's own services and its network", printed)

    def test_targets_through_the_command_line_run_on_an_image_older_than_the_yougori_harness(self):
        # `yougori inference run` always starts `run yougori --harness NAME`: with nothing asked
        # (a coding harness), an older image runs the harness's own screen, held to the targets
        # by Yougori's filter whatever the image.
        self.guest.start = {"started": True, "tunnels": True}
        code, _ = self.launch(targets=["staging.mycompany.com:443"], harness="strix", answers={}, secrets={})
        self.assertEqual(code, 0)
        self.assertIn("/poll", [path for path, _ in self.guest.bodies])
        with self.assertRaises(ValueError) as older:
            self.launch(targets=["staging.mycompany.com:443"], harness="strix", answers={"target": "x"}, secrets={})
        self.assertIn("older than the Yougori harness", str(older.exception))

    def test_sites_and_targets_together_need_an_image_that_keeps_targets_off_the_proxy(self):
        code, printed = self.launch(targets=["staging.mycompany.com:443"], sites=["github.com"])
        self.assertEqual(code, 0)
        self.assertIn("staging.mycompany.com:443, and github.com through Yougori's relay", printed)
        start = next(body for path, body in self.guest.bodies if path == "/start")
        self.assertEqual((start["sites"], start["targets"]), (["github.com"], ["staging.mycompany.com:443"]))
        self.guest.start = {"started": True, "tunnels": True, "yougori": True}
        with self.assertRaises(ValueError) as refused:
            self.launch(targets=["staging.mycompany.com:443"], sites=["github.com"])
        self.assertIn("cannot combine chosen sites with targets yet", str(refused.exception))
        self.assertEqual(self.engine[-1], "stop")
        # Targets alone need nothing of the image: its network card is the engine's.
        self.assertEqual(self.launch(targets=["staging.mycompany.com:443"])[0], 0)


class GuestSide(unittest.TestCase):
    def test_targets_bypass_the_sites_proxy(self):
        self.assertEqual(vm_guest.target_hosts({"targets": ["staging.mycompany.com:443", "10.1.2.3", "staging.mycompany.com:8443"]}),
                         ["staging.mycompany.com", "10.1.2.3"])
        self.assertEqual(vm_guest.target_hosts({}), [])
        for bad in (["https://staging.mycompany.com"], "staging.mycompany.com:443", [1], ["a"] * 65):
            with self.assertRaises(vm_guest.Refusal):
                vm_guest.target_hosts({"targets": bad})

    def test_a_target_that_shares_a_name_with_a_chosen_site_stays_on_the_proxy(self):
        sites = vm_tunnel.sites(["github.com", "staging.mycompany.com", "example.org"])
        data = {"targets": ["github.com:22", "mycompany.com:443", "api.example.org:8080", "10.1.2.3", "jenkins.lan.net:8080"]}
        bypass = vm_guest.proxy_bypass(sites, data)
        self.assertEqual(bypass, ["127.0.0.1", "localhost", "10.1.2.3", "jenkins.lan.net"])
        # What curl, Python and Go do with that NO_PROXY: the sites (and their subdomains) keep
        # going to the proxy, so the launcher still opens them.
        no_proxy = {"no": ",".join(bypass)}
        for host in ("github.com", "api.github.com", "staging.mycompany.com", "mycompany.com", "www.example.org"):
            self.assertFalse(urllib.request.proxy_bypass_environment(host, no_proxy), host)
        for host in ("10.1.2.3", "jenkins.lan.net", "localhost"):
            self.assertTrue(urllib.request.proxy_bypass_environment(host, no_proxy), host)


class TargetServer(BaseHTTPRequestHandler):
    """A target outside the VM: it notes each request as it arrived and answers it."""
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def do_GET(self):
        self.server.seen.append((self.requestline, dict(self.headers.items())))
        body = b"target says hello"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class InVmProxy(unittest.TestCase):
    """The VM's proxy beside chosen sites: a target goes straight out on the card on its own
    ports (CONNECT, or a plain request as the target takes it); a site still goes through the
    launcher; nothing else, and no port outside 1 to 65535."""

    def setUp(self):
        self.target = ThreadingHTTPServer(("127.0.0.1", 0), TargetServer)
        self.target.seen = []
        threading.Thread(target=self.target.serve_forever, daemon=True).start()
        self.addCleanup(self.target.server_close)
        self.addCleanup(self.target.shutdown)
        self.port = self.target.server_port
        self.tunnels = vm_tunnel.GuestTunnels(["github.com"], threading.Condition(),
                                              vm_tunnel.target_ports(["127.0.0.1:%d" % self.port]))
        self.proxy = vm_tunnel.serve_proxy(self.tunnels, port=0)
        self.addCleanup(self.proxy.server_close)
        self.addCleanup(self.proxy.shutdown)

    def exchange(self, request, wait_for_close=True):
        with socket.create_connection(("127.0.0.1", self.proxy.server_port), timeout=10) as connection:
            connection.sendall(request)
            received = b""
            while wait_for_close and (block := connection.recv(65536)):
                received += block
            return received

    def test_connect_to_a_target_goes_straight_out(self):
        with socket.create_connection(("127.0.0.1", self.proxy.server_port), timeout=10) as connection:
            connection.sendall(b"CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n" % self.port)
            reply = b""
            while b"\r\n\r\n" not in reply:
                reply += connection.recv(4096)
            self.assertTrue(reply.startswith(b"HTTP/1.0 200"), reply)
            connection.sendall(b"GET /through HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            answer = b""
            while block := connection.recv(65536):
                answer += block
        self.assertTrue(answer.endswith(b"target says hello"), answer)
        self.assertEqual(self.target.seen[0][0], "GET /through HTTP/1.1")

    def test_a_plain_request_to_a_target_reaches_it_as_the_target_takes_it(self):
        answer = self.exchange(b"GET http://127.0.0.1:%d/path?q=1 HTTP/1.1\r\nHost: other.example\r\n"
                               b"Proxy-Connection: keep-alive\r\nAccept: */*\r\n\r\n" % self.port)
        self.assertTrue(answer.endswith(b"target says hello"), answer)
        line, headers = self.target.seen[0]
        self.assertEqual(line, "GET /path?q=1 HTTP/1.1")
        # The address's host, never the client's other one; none of the proxy's own fields.
        self.assertEqual(headers["Host"], "127.0.0.1:%d" % self.port)
        self.assertEqual(headers["Connection"], "close")
        self.assertNotIn("Proxy-Connection", headers)
        self.assertEqual(headers["Accept"], "*/*")

    def test_a_site_still_goes_through_the_launcher_and_nothing_else_is_reached(self):
        replies = []
        opened = threading.Thread(target=lambda: replies.append(self.exchange(b"CONNECT github.com:443 HTTP/1.1\r\n\r\n")))
        opened.start()
        deadline = time.monotonic() + 10
        while not self.tunnels.events and time.monotonic() < deadline:
            time.sleep(0.02)
        with self.tunnels.lock:
            event = self.tunnels.events.popleft()
        self.assertEqual((event["open"], event["port"]), ("github.com", 443))
        self.tunnels.from_host({"tunnel": event["tunnel"], "error": "The launcher refused it in this test."})
        opened.join(10)
        self.assertTrue(replies[0].startswith(b"HTTP/1.0 502"), replies)
        for request in (b"CONNECT other.example:443 HTTP/1.1\r\n\r\n",
                        b"CONNECT 127.0.0.1:%d HTTP/1.1\r\n\r\n" % (self.port + 1 if self.port < 65535 else 1),
                        b"CONNECT 127.0.0.1:99999 HTTP/1.1\r\n\r\n",
                        b"CONNECT 127.0.0.1:0 HTTP/1.1\r\n\r\n"):
            self.assertTrue(self.exchange(request).startswith(b"HTTP/1.0 403"), request)
        self.assertTrue(self.exchange(b"GET http://other.example/ HTTP/1.1\r\n\r\n").startswith(b"HTTP/1.0 405"))
        self.assertEqual(self.target.seen, [])


if __name__ == "__main__":
    unittest.main()
