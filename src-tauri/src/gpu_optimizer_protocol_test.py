"""Real loopback runner protocol; synthetic residency, no GPU or model downloads."""
import http.client
import importlib.util
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch


class OptimizerProtocolTests(unittest.TestCase):
    def setUp(self):
        scratch = "D:/YougoriBuildCache/scratch"
        self.folder = tempfile.TemporaryDirectory(dir=scratch if os.path.isdir(scratch) else None)
        self.environment = patch.dict(os.environ, {
            "YOUGORI_MODEL": "fixture/protocol", "YOUGORI_MODEL_TOKEN": "fixture-model-token",
            "YOUGORI_GPU_CONTROL_TOKEN": "fixture-control-token", "YOUGORI_GPU_OPTIMIZER": "1",
            "YOUGORI_MODEL_FORMAT": "safetensors", "HF_HOME": self.folder.name,
        })
        self.environment.start()
        self.model = self.module()
        self.model.STATE.update(status="ready", weightsVerified=True, precision="original", error=None)
        self.model.NETWORK = object()
        self.model.TORCH = self.model.ENGINE_PROCESS = None
        self.server = self.model.Server(("127.0.0.1", 0), self.model.Handler)
        self.server_thread = threading.Thread(target=self.server.serve_forever,
                                              kwargs={"poll_interval": .01}, daemon=True)
        self.server_thread.start()
        self.threads, self.sockets = [], []

    def module(self):
        spec = importlib.util.spec_from_file_location("fixture_runner", Path(__file__).with_name("model_server.py"))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def tearDown(self):
        for connection in self.sockets:
            connection.close()
        with self.model.GPU_LOCK:
            self.model.STATE["status"] = "error"
            self.model.gpu_publish(force=True)
        for thread in self.threads:
            thread.join(6)
        self.server.shutdown()
        self.server.server_close()
        self.server_thread.join(2)
        self.environment.stop()
        self.folder.cleanup()

    def request(self, path, body=None, private=True, authorized=True):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=7)
        try:
            headers = {"Content-Type": "application/json"}
            if authorized:
                headers["Authorization"] = "Bearer fixture-model-token"
            if private:
                headers["X-Yougori-GPU-Control"] = "fixture-control-token"
            connection.request("GET" if body is None else "POST", path,
                               None if body is None else json.dumps(body), headers)
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def control(self, action, snapshot=None, **values):
        snapshot = snapshot or self.model.gpu_snapshot()
        return {"action": action, "expectedInstanceId": snapshot["instanceId"],
                "expectedSequence": snapshot["sequence"], **values}

    def watch(self, snapshot=None, wait_ms=5000):
        snapshot = snapshot or self.model.gpu_snapshot()
        return {"action": "watch", "instanceId": snapshot["instanceId"],
                "since": snapshot["sequence"], "waitMs": wait_ms}

    def wait_for(self, condition, timeout=2):
        deadline = time.monotonic() + timeout
        while not condition() and time.monotonic() < deadline:
            time.sleep(.005)
        self.assertTrue(condition(), "fixture condition did not become true")

    def background(self, body):
        results = []

        def run():
            try:
                results.append(self.request("/v1/yougori/optimizer", body))
            except Exception as error:
                results.append(error)

        thread = threading.Thread(target=run, daemon=True)
        self.threads.append(thread)
        thread.start()
        return thread, results

    def test_watch_requires_both_credentials_and_valid_bounded_cursor(self):
        body = self.watch(wait_ms=0)
        self.assertEqual(self.request("/v1/yougori/optimizer", body, authorized=False)[0], 401)
        self.assertEqual(self.request("/v1/yougori/optimizer", body, private=False)[0], 403)
        for field, values in {"instanceId": [None, "x", "A" * 32],
                              "since": [-1, True, 2**53, "0"],
                              "waitMs": [-1, True, 5001, "1"]}.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    self.assertEqual(self.request("/v1/yougori/optimizer", {**body, field: value})[0], 400)
        self.assertEqual(self.model.GPU_WATCHERS, 0)

    def test_watch_heartbeat_and_lease_renewal_do_not_advance_revision(self):
        self.model.gpu_prepare("fixture_lease_key_123")
        snapshot = self.model.gpu_snapshot()
        self.model.gpu_prepare("fixture_lease_key_123")
        for _ in range(3):
            self.assertEqual(self.model.gpu_snapshot()["sequence"], snapshot["sequence"])
        code, value = self.request("/v1/yougori/optimizer", self.watch(snapshot, wait_ms=50))
        self.assertEqual(code, 200)
        self.assertEqual(value["optimizer"]["sequence"], snapshot["sequence"])
        self.assertEqual(value["optimizer"]["instanceId"], snapshot["instanceId"])

    def test_external_prepare_wakes_long_poll_without_host_interception(self):
        self.assertTrue(self.model.gpu_unload())
        before = self.model.gpu_snapshot()
        thread, replies = self.background(self.watch(before))
        self.wait_for(lambda: self.model.GPU_WATCHERS == 1)
        self.assertEqual(self.request("/v1/yougori/prepare", {"lease": "fixture_external_123"}, private=False)[0], 200)
        thread.join(2)
        self.assertFalse(thread.is_alive())
        code, value = replies[0]
        self.assertEqual(code, 200)
        self.assertEqual(value["status"], "queued")
        self.assertEqual(value["optimizer"]["pending"], 1)
        self.assertGreater(value["optimizer"]["sequence"], before["sequence"])

    def test_watch_restart_and_future_cursor_return_current_snapshot_immediately(self):
        before = self.model.gpu_snapshot()
        other = self.module()
        other.STATE.update(status="idle", weightsVerified=True)
        after = other.gpu_watch(self.watch(before))
        self.assertNotEqual(after["optimizer"]["instanceId"], before["instanceId"])
        body = self.watch(before)
        body["since"] += 10
        code, value = self.request("/v1/yougori/optimizer", body)
        self.assertEqual(code, 200)
        self.assertEqual(value["optimizer"]["sequence"], before["sequence"])

    def test_restart_rejects_previous_instance_control_without_side_effect(self):
        command = self.control("unload")
        other = self.module()
        other.STATE.update(status="ready", weightsVerified=True)
        other.NETWORK = object()
        with self.assertRaises(other.GPUControlConflict):
            other.gpu_control(command)
        self.assertIsNotNone(other.NETWORK)
        self.assertEqual(other.STATE["status"], "ready")

    def test_watch_capacity_leaves_control_requests_available(self):
        body = self.watch()
        watches = [self.background(body) for _ in range(4)]
        self.wait_for(lambda: self.model.GPU_WATCHERS == 4)
        self.assertEqual(self.request("/v1/yougori/optimizer", body)[0], 429)
        self.assertEqual(self.request("/health")[0], 200)
        self.model.gpu_prepare("fixture_wake_all_123")
        for thread, results in watches:
            thread.join(2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(results[0][0], 200)
        self.assertEqual(self.model.GPU_WATCHERS, 0)

    def test_disconnected_watch_releases_capacity_promptly(self):
        body = json.dumps(self.watch()).encode()
        connection = socket.create_connection(("127.0.0.1", self.server.server_port), timeout=2)
        self.sockets.append(connection)
        connection.sendall(b"POST /v1/yougori/optimizer HTTP/1.1\r\nHost: localhost\r\n"
                           b"Authorization: Bearer fixture-model-token\r\n"
                           b"X-Yougori-GPU-Control: fixture-control-token\r\nContent-Length: "
                           + str(len(body)).encode() + b"\r\n\r\n" + body)
        self.wait_for(lambda: self.model.GPU_WATCHERS == 1)
        connection.shutdown(socket.SHUT_RDWR)
        connection.close()
        self.wait_for(lambda: self.model.GPU_WATCHERS == 0)

    def test_watch_deadline_does_not_wait_for_busy_native_cleanup_lock(self):
        snapshot = self.model.gpu_snapshot()
        entered, release = threading.Event(), threading.Event()

        def hold():
            with self.model.GPU_LOCK:
                entered.set()
                release.wait(3)

        holder = threading.Thread(target=hold, daemon=True)
        holder.start()
        self.assertTrue(entered.wait(1))
        try:
            code, _ = self.request("/v1/yougori/optimizer", self.watch(snapshot, wait_ms=50))
            self.assertEqual(code, 429)
            self.assertEqual(self.model.GPU_WATCHERS, 0)
            self.assertTrue(holder.is_alive(), "fixture did not retain cleanup lock")
        finally:
            release.set()
            holder.join(2)

    def test_lease_expiry_wakes_watch_and_invalidates_prior_control_fence(self):
        self.assertTrue(self.model.gpu_unload())
        self.model.gpu_prepare("fixture_expiring_123")
        before = self.model.gpu_snapshot()
        with self.model.GPU_LOCK:
            self.model.GPU_LEASES["fixture_expiring_123"] = time.monotonic() + .05
        code, value = self.request("/v1/yougori/optimizer", self.watch(before))
        self.assertEqual(code, 200)
        self.assertEqual(value["status"], "idle")
        self.assertEqual(value["optimizer"]["pending"], 0)
        self.assertGreater(value["optimizer"]["sequence"], before["sequence"])
        self.assertEqual(self.request("/v1/yougori/optimizer", self.control("grant", before))[0], 409)
        self.assertFalse(self.model.GPU_GRANTED.is_set())

    def test_control_expires_leases_before_comparing_its_fence(self):
        self.assertTrue(self.model.gpu_unload())
        self.model.gpu_prepare("fixture_expired_cas_123")
        command = self.control("grant")
        with self.model.GPU_LOCK:
            self.model.GPU_LEASES["fixture_expired_cas_123"] = time.monotonic() - 1
        with patch.object(self.model, "load_model") as load:
            self.assertEqual(self.request("/v1/yougori/optimizer", command)[0], 409)
            load.assert_not_called()
        self.assertEqual(self.model.GPU_LEASES, {})
        self.assertFalse(self.model.GPU_GRANTED.is_set())

    def test_health_expiry_publishes_one_consistent_state_and_revision(self):
        self.assertTrue(self.model.gpu_unload())
        self.model.gpu_prepare("fixture_expired_health_123")
        before = self.model.gpu_snapshot()
        with self.model.GPU_LOCK:
            self.model.GPU_LEASES["fixture_expired_health_123"] = time.monotonic() - 1
        code, health = self.request("/health")
        self.assertEqual(code, 200)
        self.assertEqual(health["status"], "idle")
        self.assertEqual(health["optimizer"]["pending"], 0)
        self.assertFalse(health["optimizer"]["loading"])
        self.assertEqual(health["optimizer"]["instanceId"], before["instanceId"])
        self.assertGreater(health["optimizer"]["sequence"], before["sequence"])

    def test_ready_and_failed_load_publish_to_private_watchers(self):
        for status in ("ready", "error"):
            with self.subTest(status=status):
                with self.model.GPU_LOCK:
                    self.model.GPU_LOADING = True
                    self.model.STATE.update(status="loading", error=None)
                    self.model.gpu_publish()
                thread, replies = self.background(self.watch())
                self.wait_for(lambda: self.model.GPU_WATCHERS == 1)
                with self.model.GPU_LOCK:
                    self.model.STATE["status"] = status
                    self.model.gpu_after_load()
                thread.join(2)
                self.assertFalse(thread.is_alive())
                self.assertEqual(replies[0][0], 200)
                self.assertEqual(replies[0][1]["status"], status)
                self.assertFalse(replies[0][1]["optimizer"]["loading"])

    def test_disabled_loader_publishes_ownership_before_backend_allocation(self):
        with self.model.GPU_LOCK:
            self.model.GPU_ENABLED = False
            self.model.GPU_LOADING = False
            self.model.STATE.update(status="idle", error=None)
            self.model.NETWORK = None
            self.model.gpu_publish()
        before = self.model.gpu_snapshot()
        with patch.object(self.model.GPU_GRANTED, "wait", side_effect=AssertionError("disabled runner waited for grant")):
            self.model.gpu_before_load()
        code, health = self.request("/health")
        self.assertEqual(code, 200)
        self.assertEqual(health["status"], "loading")
        self.assertFalse(health["optimizer"]["enabled"])
        self.assertTrue(health["optimizer"]["loading"])
        self.assertGreater(health["optimizer"]["sequence"], before["sequence"])
        # Only after the ownership observation do synthetic backend allocations occur.
        self.model.NETWORK = object()
        with self.model.GPU_LOCK:
            self.model.STATE["status"] = "ready"
            self.model.gpu_after_load()
        after = self.model.gpu_snapshot()
        self.assertFalse(after["loading"])
        self.assertTrue(after["resident"])
        self.assertFalse(after["enabled"])

    def test_failed_unload_publishes_uncertainty_without_success_ack(self):
        before = self.model.gpu_snapshot()
        thread, replies = self.background(self.watch(before))
        self.wait_for(lambda: self.model.GPU_WATCHERS == 1)
        with patch.object(self.model, "gpu_release_memory", side_effect=RuntimeError("PRIVATE")):
            code, value = self.request("/v1/yougori/optimizer", self.control("unload", before))
        self.assertEqual(code, 503)
        self.assertNotIn("controlAck", value)
        self.assertNotIn("PRIVATE", json.dumps(value))
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(replies[0][0], 200)
        self.assertTrue(replies[0][1]["optimizer"]["releaseUncertain"])
        self.assertTrue(replies[0][1]["optimizer"]["resident"])
        self.assertEqual(replies[0][1]["status"], "error")

    def test_phase_unload_and_grant_acknowledge_exactly_one_revision(self):
        before = self.model.gpu_snapshot()
        code, unloaded = self.request("/v1/yougori/optimizer", self.control("unload", before))
        self.assertEqual(code, 200)
        self.assertTrue(unloaded["unloaded"])
        self.assertEqual(unloaded["controlAck"], {"action": "unload", "instanceId": before["instanceId"],
                                                "expectedSequence": before["sequence"], "sequence": before["sequence"] + 1})
        self.model.gpu_prepare("fixture_grant_key_123")
        for _ in range(2):
            before = self.model.gpu_snapshot()
            code, phased = self.request("/v1/yougori/optimizer", self.control("phase", before, phase="freeing_memory"))
            self.assertEqual(code, 200)
            self.assertTrue(phased["phased"])
            self.assertEqual(phased["optimizer"]["sequence"], before["sequence"] + 1)
            self.assertEqual(phased["controlAck"]["sequence"], phased["optimizer"]["sequence"])
        with patch.object(self.model, "load_model") as load:
            code, granted = self.request("/v1/yougori/optimizer", self.control("grant", phased["optimizer"]))
            self.assertEqual(code, 200)
            self.assertTrue(granted["granted"])
            self.assertEqual(granted["optimizer"]["sequence"], phased["optimizer"]["sequence"] + 1)
            self.assertEqual(granted["controlAck"]["sequence"], granted["optimizer"]["sequence"])
            self.wait_for(lambda: load.call_count == 1)

    def test_concurrent_duplicate_grants_have_only_one_effect(self):
        self.assertTrue(self.model.gpu_unload())
        self.model.gpu_prepare("fixture_concurrent_123")
        body = self.control("grant")
        with patch.object(self.model, "load_model") as load:
            workers = [self.background(body) for _ in range(2)]
            for thread, _ in workers:
                thread.join(2)
                self.assertFalse(thread.is_alive())
            self.assertEqual(sorted(result[0][0] for _, result in workers), [200, 409])
            self.wait_for(lambda: load.call_count == 1)

    def test_stale_or_partial_fence_cannot_unload_or_publish_ack(self):
        body = self.control("unload")
        self.model.gpu_prepare("fixture_protected_123")
        code, value = self.request("/v1/yougori/optimizer", body)
        self.assertEqual(code, 409)
        self.assertNotIn("controlAck", value)
        self.assertIsNotNone(self.model.NETWORK)
        del body["expectedSequence"]
        self.assertEqual(self.request("/v1/yougori/optimizer", body)[0], 400)
        self.assertIsNotNone(self.model.NETWORK)

    def test_fresh_fence_without_demand_cannot_start_loading(self):
        self.assertTrue(self.model.gpu_unload())
        with patch.object(self.model, "load_model") as load:
            code, value = self.request("/v1/yougori/optimizer", self.control("grant"))
            self.assertEqual(code, 409)
            self.assertNotIn("controlAck", value)
            load.assert_not_called()
        self.assertFalse(self.model.GPU_GRANTED.is_set())

    def test_release_activity_and_configuration_publish_state_changes(self):
        start = self.model.gpu_snapshot()
        self.model.gpu_prepare("fixture_release_key_123")
        prepared = self.model.gpu_snapshot()
        self.assertGreater(prepared["sequence"], start["sequence"])
        self.request("/v1/yougori/release", {"lease": "fixture_release_key_123"}, private=False)
        released = self.model.gpu_snapshot()
        self.assertGreater(released["sequence"], prepared["sequence"])
        self.assertTrue(self.model.gpu_enter(None))
        active = self.model.gpu_snapshot()
        self.model.gpu_leave()
        idle = self.model.gpu_snapshot()
        self.assertGreater(idle["sequence"], active["sequence"])
        code, configured = self.request("/v1/yougori/optimizer", self.control("configure", idle, enabled=True, pinned=True))
        self.assertEqual(code, 200)
        self.assertTrue(configured["optimizer"]["pinned"])
        self.assertEqual(configured["optimizer"]["sequence"], idle["sequence"] + 1)


if __name__ == "__main__":
    unittest.main()
