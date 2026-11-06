"""Exercise demand, leases and safe eviction without GPU/model downloads."""
import os
import io
import json
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import Mock, patch

cache = tempfile.TemporaryDirectory()
os.environ.update(YOUGORI_MODEL="test/model", YOUGORI_MODEL_TOKEN="test-token", HF_HOME=cache.name)
import model_server as model


class OptimizerTests(unittest.TestCase):
    def setUp(self):
        model.GPU_ENABLED = True
        model.GPU_PINNED = model.GPU_LOADING = model.GPU_INITIAL = model.GPU_WAITING_FOR_GRANT = False
        model.GPU_GRANTED.clear()
        model.GPU_ACTIVE = 0
        model.GPU_RELEASE_UNCERTAIN = False
        model.GPU_IDLE_SECONDS = 0
        model.GPU_WAITING_SINCE = None
        model.GPU_LEASES.clear()
        model.GPU_GRANTED.clear()
        model.STATE.update(status="ready", weightsVerified=True, precision="original", error=None)
        model.NETWORK = object()
        model.TORCH = model.ENGINE_PROCESS = None

    @contextmanager
    def waiting_requests(self, count=1, use_reconciliation=False):
        """Real condition waiters; a 30s wait makes notification tests independent of polling."""
        model.STATE["status"] = "loading"
        model.GPU_LOADING = True
        entered, repeated = threading.Event(), threading.Event()
        seen, results, calls, pairs, threads = set(), [], [], [], []
        original_wait = model.GPU_CHANGED.wait
        def wait(timeout):
            # Called with GPU_LOCK held; seeing entered then taking the same lock
            # guarantees the worker has atomically registered its condition wait.
            seen.add(threading.get_ident())
            calls.append(timeout)
            if len(seen) == count: entered.set()
            if len(calls) > count: repeated.set()
            return original_wait(timeout if use_reconciliation else 30)
        def run(connection):
            try:
                results.append(model.gpu_enter(SimpleNamespace(connection=connection)))
            except BaseException as error:
                results.append(error)
        with patch.object(model.GPU_CHANGED, "wait", side_effect=wait):
            try:
                for _ in range(count):
                    pair = socket.socketpair()
                    pairs.append(pair)
                    thread = threading.Thread(target=run, args=(pair[0],), daemon=True)
                    threads.append(thread)
                    thread.start()
                self.assertTrue(entered.wait(2), "requests did not enter their condition wait")
                yield SimpleNamespace(threads=threads, results=results, calls=calls,
                                      peers=[pair[1] for pair in pairs], repeated=repeated)
            finally:
                with model.GPU_LOCK:
                    model.STATE["status"] = "error"
                    model.GPU_CHANGED.notify_all()
                for thread in threads: thread.join(2)
                for pair in pairs:
                    for connection in pair: connection.close()
                self.assertFalse(any(thread.is_alive() for thread in threads))

    def test_load_completion_notifies_all_waiters_and_protects_active_requests(self):
        with self.waiting_requests(3) as pending:
            with model.GPU_LOCK:
                self.assertEqual(len(model.GPU_LEASES), 3)
                model.STATE["status"] = "ready"
                model.gpu_after_load()
            for thread in pending.threads: thread.join(2)
            self.assertEqual(pending.results, [True] * 3)
            self.assertEqual(model.GPU_ACTIVE, 3)
            self.assertEqual(model.GPU_LEASES, {})
            self.assertFalse(model.gpu_unload())
            for _ in range(3): model.gpu_leave()
            self.assertEqual(model.GPU_ACTIVE, 0)

    def test_failed_load_notifies_waiters_without_admitting_them(self):
        with self.waiting_requests() as pending:
            with model.GPU_LOCK:
                model.STATE["status"] = "error"
                model.gpu_after_load()
            pending.threads[0].join(2)
            self.assertEqual(pending.results, [False])
            self.assertEqual(model.GPU_ACTIVE, 0)
            self.assertEqual(model.GPU_LEASES, {})

    def test_disabling_optimizer_notifies_waiters_without_duplicate_loading(self):
        with self.waiting_requests() as pending, patch.object(model, "load_model") as load:
            model.gpu_control({"action": "configure", "enabled": False})
            pending.threads[0].join(2)
            self.assertEqual(pending.results, [False])
            self.assertEqual(model.GPU_LEASES, {})
            load.assert_not_called()  # The existing loader still owns GPU_LOADING.

    def test_spurious_notification_rechecks_state_and_does_not_grant_memory(self):
        with self.waiting_requests() as pending:
            with model.GPU_LOCK:
                model.GPU_CHANGED.notify_all()
            self.assertTrue(pending.repeated.wait(2))
            self.assertEqual(pending.results, [])
            self.assertEqual(model.GPU_ACTIVE, 0)
            self.assertFalse(model.GPU_GRANTED.is_set())
            with model.GPU_LOCK:
                model.STATE["status"] = "ready"
                model.gpu_after_load()
            pending.threads[0].join(2)
            self.assertEqual(pending.results, [True])
            model.gpu_leave()

    def test_missed_notification_is_recovered_by_bounded_reconciliation(self):
        with self.waiting_requests(use_reconciliation=True) as pending:
            with model.GPU_LOCK:
                model.STATE["status"] = "ready"  # Deliberately omit the completion notification.
            pending.threads[0].join(2)
            self.assertEqual(pending.results, [True])
            self.assertTrue(all(0 < timeout <= .25 for timeout in pending.calls))
            model.gpu_leave()

    def test_disconnected_waiter_releases_its_lease_without_notification(self):
        with self.waiting_requests(use_reconciliation=True) as pending:
            pending.peers[0].close()
            pending.threads[0].join(2)
            self.assertEqual(pending.results, [False])
            self.assertEqual(model.GPU_LEASES, {})
            self.assertEqual(model.GPU_ACTIVE, 0)

    def test_deadline_remains_bounded_after_notifications(self):
        with self.waiting_requests() as pending:
            expired = time.monotonic() + 1801
            with patch.object(model.time, "monotonic", return_value=expired):
                with model.GPU_LOCK:
                    model.GPU_CHANGED.notify_all()
                pending.threads[0].join(2)
            self.assertEqual(pending.results, [False])
            self.assertEqual(model.GPU_LEASES, {})

    def test_ready_model_does_not_wait_for_a_notification(self):
        with patch.object(model.GPU_CHANGED, "wait") as wait:
            self.assertTrue(model.gpu_enter(SimpleNamespace()))
            wait.assert_not_called()
            self.assertEqual(model.GPU_ACTIVE, 1)
            model.gpu_leave()

    def test_failed_native_unload_retains_process_and_blocks_new_load_until_reconciled(self):
        process = Mock()
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired("private-native-key", 10),
                                    subprocess.TimeoutExpired("private-native-key", 5)]
        model.ENGINE_PROCESS = process
        with self.assertRaises(subprocess.TimeoutExpired):
            model.gpu_unload()
        self.assertIs(model.ENGINE_PROCESS, process)
        self.assertTrue(model.gpu_snapshot()["resident"])
        self.assertTrue(model.gpu_snapshot()["releaseUncertain"])
        self.assertEqual(model.STATE["status"], "error")
        self.assertNotIn("private-native-key", model.STATE["error"])
        self.assertTrue(model.GENERATION.acquire(blocking=False))
        model.GENERATION.release()
        with self.assertRaisesRegex(RuntimeError, "release is unconfirmed"):
            model.gpu_before_load()
        process.wait.side_effect = None
        process.wait.return_value = 0
        self.assertTrue(model.gpu_unload())
        self.assertIsNone(model.ENGINE_PROCESS)
        self.assertFalse(model.gpu_snapshot()["resident"])
        self.assertFalse(model.gpu_snapshot()["releaseUncertain"])

    def test_allocator_cleanup_failure_remains_resident_even_without_model_references(self):
        empty = Mock(side_effect=RuntimeError("fixture allocator error"))
        model.TORCH = SimpleNamespace(cuda=SimpleNamespace(is_available=lambda: False, empty_cache=empty))
        with self.assertRaises(RuntimeError):
            model.gpu_unload()
        self.assertIsNone(model.NETWORK)
        self.assertIsNone(model.ENGINE_PROCESS)
        self.assertTrue(model.gpu_snapshot()["resident"])
        with patch.object(model, "GPU_ENABLED", False):
            with self.assertRaisesRegex(RuntimeError, "release is unconfirmed"):
                model.gpu_before_load()
        empty.side_effect = None
        self.assertTrue(model.gpu_unload())
        self.assertFalse(model.gpu_snapshot()["releaseUncertain"])
        self.assertEqual(model.STATE["status"], "idle")

    def test_unexpected_control_errors_do_not_echo_native_process_arguments(self):
        body = json.dumps({"action": "unload"}).encode()
        handler = SimpleNamespace(path="/v1/yougori/optimizer", rfile=io.BytesIO(body), reply=Mock(),
                                  headers={"Content-Length": str(len(body)), "X-Yougori-GPU-Control": "fixture-control"})
        with patch.dict(os.environ, {"YOUGORI_GPU_CONTROL_TOKEN": "fixture-control"}), \
                patch.object(model, "gpu_unload", side_effect=subprocess.TimeoutExpired(["engine", "private-native-key"], 5)):
            self.assertTrue(model.gpu_route(handler))
        code, response = handler.reply.call_args.args
        self.assertEqual(code, 503)
        self.assertNotIn("private-native-key", json.dumps(response))

    def test_keep_loaded_setting_survives_pin_changes_and_still_allows_switching(self):
        result = model.gpu_control({"action":"configure", "enabled":True, "idleTimeoutSeconds":0})
        self.assertEqual(result["optimizer"]["idleTimeoutSeconds"], 0)
        model.gpu_control({"action":"configure", "enabled":True, "pinned":True})
        self.assertEqual(model.GPU_IDLE_SECONDS, 0)
        self.assertFalse(model.gpu_unload())
        model.gpu_control({"action":"configure", "enabled":True, "pinned":False})
        self.assertTrue(model.gpu_unload())

    def test_explicit_idle_timeout_validation(self):
        for timeout in (-1, 1, 9, 3601, True, 10.5):
            with self.assertRaises(ValueError):
                model.gpu_control({"action":"configure", "enabled":True, "idleTimeoutSeconds":timeout})
        model.gpu_control({"action":"configure", "enabled":True, "idleTimeoutSeconds":120})
        model.gpu_control({"action":"configure", "enabled":True, "pinned":True})
        self.assertEqual(model.GPU_IDLE_SECONDS, 120)

    def test_idle_unloads_weights_then_new_demand_is_queued(self):
        self.assertTrue(model.gpu_unload())
        self.assertIsNone(model.NETWORK)
        self.assertEqual(model.STATE["status"], "idle")
        result = model.gpu_prepare("synthetic_lease_123")
        self.assertEqual(result["state"], "queued")
        self.assertEqual(result["optimizer"]["pending"], 1)

    def test_active_pinned_leased_and_generation_locked_are_never_evicted(self):
        for attribute in ("GPU_ACTIVE", "GPU_PINNED", "GPU_LOADING"):
            setattr(model, attribute, 1)
            self.assertFalse(model.gpu_unload())
            setattr(model, attribute, 0)
        model.gpu_prepare("synthetic_lease_123")
        self.assertFalse(model.gpu_unload())
        model.GPU_LEASES.clear()
        model.GENERATION.acquire()
        try: self.assertFalse(model.gpu_unload())
        finally: model.GENERATION.release()

    def test_abandoned_lease_expires_and_frees_residency(self):
        model.gpu_prepare("synthetic_lease_123")
        model.GPU_LEASES["synthetic_lease_123"] = time.monotonic() - 1
        self.assertTrue(model.gpu_unload())

    def test_loading_requires_grant_and_preserves_quantized_identity(self):
        model.STATE.update(status="queued", precision="4bit")
        thread = threading.Thread(target=model.gpu_before_load)
        thread.start()
        time.sleep(.03)
        self.assertTrue(thread.is_alive())
        with patch.object(model.threading.Thread, "start") as extra_loader:
            model.gpu_control({"action":"grant"})
            extra_loader.assert_not_called()
        thread.join(1)
        self.assertFalse(thread.is_alive())
        self.assertEqual(model.STATE["status"], "loading")
        self.assertEqual(os.environ["YOUGORI_MODEL_PRECISION"], "4bit")

    def test_disabling_resumes_waiting_loader_without_starting_duplicate(self):
        model.STATE.update(status="queued", precision="4bit")
        thread = threading.Thread(target=model.gpu_before_load)
        thread.start()
        time.sleep(.03)
        self.assertTrue(thread.is_alive())
        with patch.object(model.threading.Thread, "start") as extra_loader:
            model.gpu_control({"action":"configure", "enabled":False})
            extra_loader.assert_not_called()
        thread.join(1)
        self.assertFalse(thread.is_alive())
        self.assertFalse(model.GPU_WAITING_FOR_GRANT)

    def test_failed_load_drops_partial_weights_and_clears_the_allocation_cache(self):
        from types import SimpleNamespace
        empty = __import__("unittest.mock", fromlist=["Mock"]).Mock()
        model.TORCH = SimpleNamespace(cuda=SimpleNamespace(empty_cache=empty))
        model.STATE["status"] = "error"
        model.GPU_LOADING = True
        model.gpu_after_load()
        self.assertIsNone(model.NETWORK)
        self.assertFalse(model.GPU_LOADING)
        empty.assert_called_once()

    def test_failed_load_allocator_cleanup_retains_residency_until_successful_retry(self):
        empty = Mock(side_effect=RuntimeError("private allocator detail"))
        model.TORCH = SimpleNamespace(cuda=SimpleNamespace(is_available=lambda: False, empty_cache=empty))
        model.STATE.update(status="error", error="load failed")
        model.GPU_LOADING = True
        model.gpu_after_load()
        self.assertFalse(model.GPU_LOADING)
        self.assertIsNone(model.NETWORK)
        self.assertTrue(model.gpu_snapshot()["resident"])
        self.assertTrue(model.gpu_snapshot()["releaseUncertain"])
        self.assertNotIn("private allocator detail", model.STATE["error"])
        for enabled in (True, False):
            with patch.object(model, "GPU_ENABLED", enabled):
                with self.assertRaisesRegex(RuntimeError, "release is unconfirmed"):
                    model.gpu_before_load()
        empty.side_effect = None
        self.assertTrue(model.gpu_unload())
        self.assertFalse(model.gpu_snapshot()["resident"])
        self.assertFalse(model.gpu_snapshot()["releaseUncertain"])

    def test_failed_native_load_stops_owned_engine_and_preserves_load_error(self):
        process = Mock()
        process.poll.return_value = None
        process.wait.return_value = 0
        model.ENGINE_PROCESS = process
        model.STATE.update(status="error", error="model did not become ready")
        model.GPU_LOADING = True
        model.gpu_after_load()
        process.terminate.assert_called_once()
        process.wait.assert_called_once_with(timeout=10)
        self.assertIsNone(model.ENGINE_PROCESS)
        self.assertFalse(model.gpu_snapshot()["resident"])
        self.assertFalse(model.GPU_LOADING)
        self.assertEqual(model.STATE["status"], "error")
        self.assertEqual(model.STATE["error"], "model did not become ready")

    def test_failed_native_load_cleanup_timeout_notifies_waiter_and_retains_process(self):
        process = Mock()
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired("private argv", 10),
                                   subprocess.TimeoutExpired("private argv", 5)]
        model.ENGINE_PROCESS = process
        with self.waiting_requests() as pending:
            with model.GPU_LOCK:
                model.STATE["status"] = "error"
                model.gpu_after_load()
            pending.threads[0].join(2)
            self.assertEqual(pending.results, [False])
            self.assertFalse(model.GPU_LOADING)
            self.assertTrue(model.gpu_snapshot()["resident"])
            self.assertIs(model.ENGINE_PROCESS, process)
            self.assertNotIn("private argv", model.STATE["error"])
        # Reconciliation sees the eventual exit without signalling a stale PID.
        process.poll.return_value = 1
        process.terminate.reset_mock()
        process.wait.reset_mock()
        self.assertTrue(model.gpu_unload())
        process.terminate.assert_not_called()
        process.wait.assert_not_called()
        self.assertIsNone(model.ENGINE_PROCESS)
        self.assertFalse(model.gpu_snapshot()["releaseUncertain"])

    def test_failed_load_cannot_claim_release_while_generation_is_busy(self):
        for active in (False, True):
            with self.subTest(active=active):
                model.NETWORK = object()
                original = model.NETWORK
                model.STATE.update(status="error", error="load failed")
                model.GPU_LOADING = True
                model.GPU_ACTIVE = int(active)
                if not active:
                    model.GENERATION.acquire()
                try:
                    model.gpu_after_load()
                    self.assertIs(model.NETWORK, original)
                    self.assertTrue(model.gpu_snapshot()["releaseUncertain"])
                    self.assertTrue(model.gpu_snapshot()["resident"])
                    self.assertFalse(model.GPU_LOADING)
                finally:
                    model.GPU_ACTIVE = 0
                    if not active:
                        model.GENERATION.release()
                self.assertTrue(model.gpu_unload())
                self.assertFalse(model.gpu_snapshot()["releaseUncertain"])

    def test_public_prepare_cannot_grant_memory_and_queue_is_bounded(self):
        model.STATE["status"] = "idle"
        for index in range(32): model.gpu_prepare("synthetic_lease_%03d" % index)
        self.assertFalse(model.GPU_GRANTED.is_set())
        with self.assertRaises(ValueError): model.gpu_prepare("synthetic_lease_extra")

    def test_release_clears_cublas_workspaces_after_dropping_weights_and_before_returning_segments(self):
        order = Mock()
        order.clear.side_effect = lambda: self.assertIsNone(model.NETWORK, "references are dropped first")
        model.TORCH = SimpleNamespace(_C=SimpleNamespace(_cuda_clearCublasWorkspaces=order.clear),
                                      cuda=SimpleNamespace(is_available=lambda: False, empty_cache=order.empty))
        with patch.object(model.gc, "collect", order.collect):
            self.assertTrue(model.gpu_unload())
        self.assertEqual([entry[0] for entry in order.mock_calls], ["collect", "clear", "empty"])
        self.assertEqual(model.STATE["status"], "idle")
        self.assertFalse(model.gpu_snapshot()["releaseUncertain"])
        # A failed load releases through the same path.
        order.reset_mock()
        model.NETWORK = object()
        model.STATE["status"] = "error"
        model.GPU_LOADING = True
        model.gpu_after_load()
        self.assertEqual([entry[0] for entry in order.mock_calls], ["clear", "empty"])
        self.assertFalse(model.gpu_snapshot()["releaseUncertain"])

    def test_release_without_the_private_cublas_api_still_releases(self):
        missing = SimpleNamespace(), None, SimpleNamespace(_cuda_clearCublasWorkspaces=Mock(side_effect=RuntimeError("fixture")))
        for private in missing:
            with self.subTest(private=private):
                model.NETWORK = object()
                model.STATE["status"] = "ready"
                empty = Mock()
                cuda = SimpleNamespace(is_available=lambda: False, empty_cache=empty)
                model.TORCH = SimpleNamespace(cuda=cuda) if private is None else SimpleNamespace(_C=private, cuda=cuda)
                self.assertTrue(model.gpu_unload())
                empty.assert_called_once()
                self.assertIsNone(model.NETWORK)
                self.assertEqual(model.STATE["status"], "idle")
                self.assertFalse(model.gpu_snapshot()["resident"])
                self.assertFalse(model.gpu_snapshot()["releaseUncertain"])

    def test_snapshot_reports_reserved_bytes_as_an_observation_only(self):
        self.assertIsNone(model.gpu_snapshot()["reservedBytes"])  # TORCH unset
        allocated, reserved = [8519680, 0], [987758592, 2097152]
        cuda = SimpleNamespace(is_available=lambda: True, device_count=lambda: 2,
                               memory_allocated=lambda i: allocated[i], memory_reserved=lambda i: reserved[i])
        model.TORCH = SimpleNamespace(cuda=cuda)
        snapshot = model.gpu_snapshot()
        self.assertEqual(snapshot["allocatedBytes"], 8519680)
        self.assertEqual(snapshot["reservedBytes"], 989855744)
        self.assertTrue(snapshot["resident"])
        model.STATE["status"] = "idle"
        before = model.gpu_snapshot()  # its refresh publishes the idle state first
        reserved[0] = 0
        after = model.gpu_snapshot()
        # Held segments never make a released model resident, uncertain or a new revision.
        self.assertFalse(before["resident"]); self.assertFalse(before["releaseUncertain"])
        self.assertEqual(before["reservedBytes"], 989855744); self.assertEqual(after["reservedBytes"], 2097152)
        self.assertEqual(before["sequence"], after["sequence"])
        self.assertEqual(before["instanceId"], after["instanceId"])
        del cuda.memory_reserved
        self.assertEqual(model.gpu_snapshot()["allocatedBytes"], 8519680)
        self.assertIsNone(model.gpu_snapshot()["reservedBytes"])
        # The allocator's peak since the last unload is an observation too (GPU-W00), absent
        # when the runtime cannot report it, and reset by a release, never by a snapshot.
        self.assertIsNone(model.gpu_snapshot()["peakAllocatedBytes"])
        peaks, resets = [10718458880, 0], []
        cuda.max_memory_allocated = lambda i: peaks[i]
        cuda.reset_peak_memory_stats = lambda: resets.append(True)
        cuda.empty_cache = lambda: None
        self.assertEqual(model.gpu_snapshot()["peakAllocatedBytes"], 10718458880)
        self.assertEqual(resets, [])
        with patch.object(model, "gpu_clear_cublas_workspaces", return_value=True):
            model.gpu_release_memory()
        self.assertEqual(resets, [True])
        cuda.is_available = lambda: False
        self.assertIsNone(model.gpu_snapshot()["allocatedBytes"])
        self.assertIsNone(model.gpu_snapshot()["reservedBytes"])
        self.assertIsNone(model.gpu_snapshot()["peakAllocatedBytes"])


GIB = 2 ** 30
TRANSFORMERS_GRANT = {"YOUGORI_GPU_CAPACITY_POLICY": "local-single-transformers-v1",
                      "YOUGORI_GPU_CAPACITY_BYTES": str(3 * GIB), "YOUGORI_GPU_CAPACITY_CONTEXT": "12288",
                      "YOUGORI_MODEL_PRECISION": "auto"}


class TransformersGrantTests(unittest.TestCase):
    """The engine's local-single-transformers-v1 profile: the runner holds itself to its grant (G03)."""

    def setUp(self):
        self.fraction = Mock()
        self.torch = SimpleNamespace(cuda=SimpleNamespace(mem_get_info=lambda index: (20 * GIB, 24 * GIB),
                                                          set_per_process_memory_fraction=self.fraction))
        for patcher in (patch.object(model, "GPU_CAPACITY", None), patch.object(model, "GPU_CAPACITY_CONTEXT", None),
                        patch.object(model, "TORCH", None), patch.dict(os.environ, TRANSFORMERS_GRANT)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_the_grant_caps_the_allocator_of_the_one_device_at_original_precision(self):
        self.assertEqual(model.gpu_cap_memory(self.torch, 1), 3 * GIB)
        self.fraction.assert_called_once_with(3 / 24, 0)
        self.assertEqual(os.environ["YOUGORI_MODEL_PRECISION"], "original")
        self.assertEqual(model.gpu_snapshot()["capacityBytes"], 3 * GIB)
        # The grant's context is the runner's context window from here on (G03): a longer
        # conversation is refused or truncated by fit() instead of running past the grant.
        self.assertEqual(model.gpu_snapshot()["capacityContext"], 12288)
        with patch.object(model, "NETWORK", SimpleNamespace(config=SimpleNamespace(max_position_embeddings=32768))):
            self.assertEqual(model.context_window(), 12288)
            with patch.object(model, "GPU_CAPACITY_CONTEXT", 40000):
                self.assertEqual(model.context_window(), 32768, "the model's own window when the grant covers more")
            with patch.object(model, "GPU_CAPACITY_CONTEXT", None):
                self.assertEqual(model.context_window(), 32768)
            with self.assertRaisesRegex(ValueError, "12288-token context window"):
                model.fit([{"role": "user", "content": "long"}], 64, False, model.context_window(), lambda messages: (messages, 12300))
        # A demand above the device caps the whole device, never more.
        self.fraction.reset_mock()
        os.environ["YOUGORI_GPU_CAPACITY_BYTES"] = str(30 * GIB)
        self.assertEqual(model.gpu_cap_memory(self.torch, 1), 24 * GIB)
        self.fraction.assert_called_once_with(1.0, 0)
        self.assertEqual(model.gpu_snapshot()["capacityBytes"], 24 * GIB)

    def test_without_the_transformers_profile_nothing_changes(self):
        for policy in (None, "local-single-vllm-v1", "local-single-transformers-v2"):
            with self.subTest(policy=policy), patch.dict(os.environ):
                os.environ.pop("YOUGORI_GPU_CAPACITY_POLICY")
                if policy is not None:
                    os.environ["YOUGORI_GPU_CAPACITY_POLICY"] = policy
                self.assertIsNone(model.gpu_cap_memory(self.torch, 2))
                self.fraction.assert_not_called()
                self.assertEqual(os.environ["YOUGORI_MODEL_PRECISION"], "auto")
                self.assertIsNone(model.gpu_snapshot()["capacityBytes"])
                self.assertIsNone(model.gpu_snapshot()["capacityContext"])

    def test_a_malformed_grant_or_another_gpu_count_fails_closed_before_loading(self):
        for value, count in (("0", 1), ("-1", 1), ("1.5", 1), ("", 1), ("\uff13", 1), (str(2 ** 50 + 1), 1),
                             (str(3 * GIB), 2), (str(3 * GIB), 0)):
            with self.subTest(value=value, count=count), patch.dict(os.environ, YOUGORI_GPU_CAPACITY_BYTES=value):
                with self.assertRaises(RuntimeError):
                    model.gpu_cap_memory(self.torch, count)
                self.fraction.assert_not_called()
                self.assertEqual(os.environ["YOUGORI_MODEL_PRECISION"], "auto")
                self.assertIsNone(model.gpu_snapshot()["capacityBytes"])
        # A grant without the context it covers, or with a malformed one, is not read as
        # unbounded: an environment stamped by another engine build is recreated instead.
        for context in (None, "", "0", "-1", "1.5", "\uff13", str(2 ** 20 + 1)):
            with self.subTest(context=context), patch.dict(os.environ):
                os.environ.pop("YOUGORI_GPU_CAPACITY_CONTEXT")
                if context is not None:
                    os.environ["YOUGORI_GPU_CAPACITY_CONTEXT"] = context
                with self.assertRaises(RuntimeError):
                    model.gpu_cap_memory(self.torch, 1)
                self.fraction.assert_not_called()
                self.assertEqual(os.environ["YOUGORI_MODEL_PRECISION"], "auto")
                self.assertIsNone(model.gpu_snapshot()["capacityBytes"])
                self.assertIsNone(model.gpu_snapshot()["capacityContext"])

    def test_a_runtime_that_cannot_cap_its_allocator_fails_instead_of_loading_uncapped(self):
        def refuse(fraction, device):
            raise RuntimeError("native detail " + os.environ["YOUGORI_GPU_CAPACITY_BYTES"])
        for cuda in (SimpleNamespace(mem_get_info=lambda index: (20 * GIB, 24 * GIB)),
                     SimpleNamespace(mem_get_info=lambda index: (20 * GIB, 24 * GIB), set_per_process_memory_fraction=refuse),
                     SimpleNamespace(mem_get_info=lambda index: (0, 0), set_per_process_memory_fraction=self.fraction)):
            with self.subTest(cuda=cuda):
                with self.assertRaises(RuntimeError) as refused:
                    model.gpu_cap_memory(SimpleNamespace(cuda=cuda), 1)
                self.assertIn("cannot hold the model to its GPU grant", str(refused.exception))
                self.assertNotIn("native detail", str(refused.exception))
                self.assertEqual(os.environ["YOUGORI_MODEL_PRECISION"], "auto")
                self.assertIsNone(model.gpu_snapshot()["capacityBytes"])


if __name__ == "__main__": unittest.main()
