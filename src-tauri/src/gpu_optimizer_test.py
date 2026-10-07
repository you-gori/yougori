"""Exercise demand, leases and safe eviction without GPU/model downloads."""
import os
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

cache = tempfile.TemporaryDirectory()
os.environ.update(YOUGORI_MODEL="test/model", YOUGORI_MODEL_TOKEN="test-token", HF_HOME=cache.name)
import model_server as model


class OptimizerTests(unittest.TestCase):
    def setUp(self):
        model.GPU_ENABLED = True
        model.GPU_PINNED = model.GPU_LOADING = model.GPU_INITIAL = False
        model.GPU_ACTIVE = 0
        model.GPU_WAITING_SINCE = None
        model.GPU_LEASES.clear()
        model.GPU_GRANTED.clear()
        model.STATE.update(status="ready", weightsVerified=True, precision="original", error=None)
        model.NETWORK = object()
        model.TORCH = model.ENGINE_PROCESS = None

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
        with patch.object(model.threading.Thread, "start"):
            model.gpu_control({"action":"grant"})
        thread.join(1)
        self.assertFalse(thread.is_alive())
        self.assertEqual(model.STATE["status"], "loading")
        self.assertEqual(os.environ["YOUGORI_MODEL_PRECISION"], "4bit")

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

    def test_public_prepare_cannot_grant_memory_and_queue_is_bounded(self):
        model.STATE["status"] = "idle"
        for index in range(32): model.gpu_prepare("synthetic_lease_%03d" % index)
        self.assertFalse(model.GPU_GRANTED.is_set())
        with self.assertRaises(ValueError): model.gpu_prepare("synthetic_lease_extra")


if __name__ == "__main__": unittest.main()
