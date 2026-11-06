"""Chosen-site tunnels: the VM's proxy and the launcher's half, end to end over a stand-in for
the owner channel (the launcher's poll loop and its /tunnel messages)."""
from pathlib import Path
import socket
import sys
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "site/harnesses"))
import vm_tunnel


class Names(unittest.TestCase):
    def test_sites_are_names_and_cover_their_subdomains_only(self):
        self.assertEqual(vm_tunnel.sites(["GitHub.com", " pypi.org. ", "github.com"]), ["github.com", "pypi.org"])
        for bad in (["localhost"], ["10.0.0.1"], ["-a.com"], ["a..com"], [], ["a.com"] * 65):
            with self.assertRaises(ValueError):
                vm_tunnel.sites(bad)
        self.assertTrue(vm_tunnel.allowed(["github.com"], "api.github.com"))
        self.assertTrue(vm_tunnel.allowed(["github.com"], "GitHub.com."))
        self.assertFalse(vm_tunnel.allowed(["github.com"], "evilgithub.com"))
        self.assertFalse(vm_tunnel.allowed(["github.com"], "github.com.evil.org"))

    def test_the_launcher_never_connects_to_this_computer_or_its_network(self):
        with self.assertRaises(ValueError):
            vm_tunnel.public_connection("localhost", 443, timeout=2)


class EndToEnd(unittest.TestCase):
    def setUp(self):
        # The "site": an echo server; the launcher's connector reaches it for any chosen name.
        self.site = socket.create_server(("127.0.0.1", 0))
        threading.Thread(target=self.echo, daemon=True).start()
        self.connected = []

        def connect(host, port):
            self.connected.append((host, port))
            return socket.create_connection(self.site.getsockname(), timeout=5)

        self.lock = threading.Condition()
        self.guest = vm_tunnel.GuestTunnels(["example.com"], self.lock)
        self.proxy = vm_tunnel.serve_proxy(self.guest, port=0)

        def post(message):
            if not self.guest.from_host(message):
                raise ValueError("Tunnel ended.")

        self.host = vm_tunnel.HostTunnels(post, ["example.com"], connect=connect)
        self.stopped = threading.Event()
        threading.Thread(target=self.poll, daemon=True).start()

    def tearDown(self):
        self.stopped.set()
        with self.lock:
            self.lock.notify_all()
        self.host.close_all()
        self.proxy.shutdown()
        self.proxy.server_close()
        self.site.close()

    def echo(self):
        while True:
            try:
                peer, _ = self.site.accept()
            except OSError:
                return
            def serve(connection=peer):
                with connection:
                    while data := connection.recv(65536):
                        connection.sendall(data)
            threading.Thread(target=serve, daemon=True).start()

    def poll(self):
        # The launcher's loop: each poll takes the VM's tunnel messages and hands them over.
        while not self.stopped.is_set():
            with self.lock:
                self.lock.wait_for(lambda: self.guest.events or self.stopped.is_set(), timeout=1)
                events = self.guest.take()
            for event in events:
                self.host.handle(event)

    def connect_through_proxy(self, target):
        client = socket.create_connection(self.proxy.server_address, timeout=10)
        client.sendall(("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n" % (target, target)).encode())
        head = b""
        while b"\r\n\r\n" not in head:
            block = client.recv(4096)
            if not block:
                break
            head += block
        return client, head.split(b"\r\n", 1)[0].decode()

    def test_a_chosen_site_carries_bytes_both_ways(self):
        client, status = self.connect_through_proxy("example.com:443")
        with client:
            self.assertIn(" 200 ", status + " ")
            payload = bytes(range(256)) * 2048  # 512 KiB: several tunnel messages each way
            threading.Thread(target=client.sendall, args=(payload,), daemon=True).start()
            received = b""
            while len(received) < len(payload):
                block = client.recv(65536)
                if not block:
                    break
                received += block
            self.assertEqual(received, payload)
        self.assertEqual(self.connected, [("example.com", 443)])

    def test_other_sites_and_ports_are_refused_before_anything_connects(self):
        for target in ("other.org:443", "example.com:22", "127.0.0.1:443"):
            client, status = self.connect_through_proxy(target)
            client.close()
            self.assertIn(" 403 ", status + " ", target)
        self.assertEqual(self.connected, [])

    def test_the_launcher_refuses_a_site_the_session_did_not_choose(self):
        # Even if the VM asks (its own check bypassed), the host does not connect.
        replies = []
        host = vm_tunnel.HostTunnels(replies.append, ["example.com"], connect=lambda *a: self.fail("connected"))
        host.handle({"tunnel": "a" * 32, "open": "evil.org", "port": 443})
        for _ in range(50):
            if replies:
                break
            threading.Event().wait(0.05)
        self.assertEqual(replies[0]["tunnel"], "a" * 32)
        self.assertIn("not chosen", replies[0]["error"])
        with self.assertRaises(ValueError):
            host.handle({"tunnel": "not-an-id", "open": "example.com", "port": 443})


if __name__ == "__main__":
    unittest.main()
