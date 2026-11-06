"""GPU-W00 observations through the real runner, using fake clocks and backends."""
import hashlib
import importlib.util
import io
import json
import os
import socket
from pathlib import Path
import tempfile
import threading
import unittest
from contextlib import ExitStack, nullcontext
from types import SimpleNamespace
from unittest.mock import Mock, patch


cache = tempfile.TemporaryDirectory(prefix="yougori-timing-test-")
with patch.dict(os.environ, {
    "YOUGORI_MODEL": "fixture/model", "YOUGORI_MODEL_TOKEN": "fixture-model-key",
    "YOUGORI_MODEL_ADMIN_TOKEN": "fixture-admin-key", "YOUGORI_MODEL_FORMAT": "gguf",
    "YOUGORI_GPU_OPTIMIZER": "0", "HF_HOME": cache.name,
}):
    spec = importlib.util.spec_from_file_location("timing_model_server", Path(__file__).with_name("model_server.py"))
    model = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(model)


def tearDownModule():
    cache.cleanup()


class Clock:
    def __init__(self):
        self.now = 0

    def __call__(self):
        return self.now

    def advance(self, milliseconds):
        self.now += milliseconds * 1_000_000


class TimingTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.timings = model.RunnerTimings(self.clock)
        self.patcher = patch.object(model, "RUNNER_TIMINGS", self.timings)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def test_nested_stages_have_inclusive_host_time_without_invented_device_metrics(self):
        with patch.object(model.time, "time", side_effect=AssertionError("wall clock used")):
            with self.timings.run("load") as run:
                with self.timings.stage("snapshot"):
                    self.clock.advance(2)
                    for _ in range(2):
                        with self.timings.stage("weight_hash"):
                            self.clock.advance(3)
                self.clock.advance(5)
                run["outcome"] = "ok"
        row = self.timings.snapshot()["recent"][0]
        self.assertEqual(row["elapsedMs"], 13)
        self.assertEqual(row["stages"]["snapshot"], {"calls": 1, "failedCalls": 0, "elapsedMs": 8})
        self.assertEqual(row["stages"]["weight_hash"], {"calls": 2, "failedCalls": 0, "elapsedMs": 6})
        self.assertIsNone(row["firstOutputMs"])
        self.assertNotIn("prefill", row["stages"])

    def test_failure_records_are_bounded_and_do_not_retain_exception_text(self):
        timings = model.RunnerTimings(self.clock, limit=2)
        for _ in range(3):
            with self.assertRaisesRegex(RuntimeError, "private"):
                with timings.run("load"):
                    with timings.stage("snapshot"):
                        self.clock.advance(4)
                        raise RuntimeError("private-prompt /private/path token-secret")
        result = timings.snapshot()
        self.assertEqual((result["started"], result["completed"], result["active"], result["evicted"]), (3, 3, 0, 1))
        self.assertEqual([r["id"] for r in result["recent"]], [2, 3])
        self.assertTrue(all(r["outcome"] == "error" for r in result["recent"]))
        self.assertEqual(result["recent"][0]["stages"]["snapshot"]["failedCalls"], 1)
        self.assertNotIn("private", json.dumps(result))
        result["recent"][0]["stages"]["snapshot"]["calls"] = 100
        self.assertEqual(timings.snapshot()["recent"][0]["stages"]["snapshot"]["calls"], 1)

    def test_labels_and_history_limit_cannot_accept_arbitrary_values(self):
        for limit in (0, -1, True, 257, 1.5):
            with self.assertRaises(ValueError):
                model.RunnerTimings(limit=limit)
        with self.assertRaises(ValueError):
            with self.timings.run("private/prompt"):
                pass
        with self.assertRaises(ValueError):
            with self.timings.stage("token-secret"):
                pass
        self.assertEqual(self.timings.snapshot()["started"], 0)

    def test_instance_namespace_changes_on_recreation_not_on_snapshot(self):
        before = self.timings.snapshot()
        self.assertRegex(before["instanceId"], r"^[a-f0-9]{32}$")
        self.assertEqual(before["retainedIds"], [])
        self.assertEqual(before["recent"], [])
        with self.timings.run("request") as run:
            run["outcome"] = "ok"
        after = self.timings.snapshot()
        self.assertEqual(before["instanceId"], after["instanceId"])
        self.assertEqual(after["recent"][0]["completionSequence"], 1)
        restarted = model.RunnerTimings(self.clock).snapshot()
        self.assertNotEqual(after["instanceId"], restarted["instanceId"])
        self.assertEqual((restarted["started"], restarted["completed"]), (0, 0))

    def test_completion_cursor_detects_loss_without_confusing_active_start_ids(self):
        timings = model.RunnerTimings(limit=2)
        entered, release = threading.Event(), threading.Event()
        failures = []

        def slow_first():
            try:
                with timings.run("request") as run:
                    entered.set()
                    if not release.wait(3):
                        raise AssertionError("test synchronization timed out")
                    run["outcome"] = "ok"
            except BaseException as error:
                failures.append(error)

        thread = threading.Thread(target=slow_first)
        thread.start()
        try:
            self.assertTrue(entered.wait(3))
            empty = timings.snapshot()
            for _ in range(2):
                with timings.run("request") as run:
                    run["outcome"] = "ok"
            partial = timings.snapshot()
            self.assertEqual(partial["retainedIds"], [2, 3])
            self.assertEqual(partial["active"], 1)
            self.assertEqual(partial["evicted"], 0, "missing start ID 1 is active, not lost")
            self.assertEqual([r["completionSequence"] for r in partial["recent"]], [1, 2])
        finally:
            release.set()
            thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertFalse(failures)
        final = timings.snapshot()
        self.assertEqual(final["instanceId"], empty["instanceId"])
        self.assertEqual(final["retainedIds"], [3, 1])
        self.assertEqual([r["completionSequence"] for r in final["recent"]], [2, 3])
        self.assertEqual((final["started"], final["completed"], final["active"], final["evicted"]), (3, 3, 0, 1))
        oldest = final["recent"][0]["completionSequence"]
        self.assertGreater(oldest, empty["completed"] + 1, "collector at the empty snapshot missed a completion")
        self.assertLessEqual(oldest, partial["completed"] + 1, "collector at the partial snapshot lost nothing")

    def test_retained_identity_metadata_is_bounded_detached_and_content_free(self):
        timings = model.RunnerTimings(limit=2)
        for _ in range(5):
            with self.assertRaises(RuntimeError):
                with timings.run("request"):
                    raise RuntimeError("private/path credential-secret prompt-content")
        result = timings.snapshot()
        self.assertEqual(result["retainedIds"], [4, 5])
        self.assertEqual([r["completionSequence"] for r in result["recent"]], [4, 5])
        for secret in ("private/path", "credential-secret", "prompt-content"):
            self.assertNotIn(secret, json.dumps(result))
        result["retainedIds"].append(999)
        result["recent"][0]["completionSequence"] = 999
        self.assertEqual(timings.snapshot()["retainedIds"], [4, 5])
        self.assertEqual(timings.snapshot()["recent"][0]["completionSequence"], 4)

    def test_concurrent_threads_keep_runs_and_first_output_separate(self):
        timings = model.RunnerTimings()
        ready, release = threading.Barrier(3), threading.Event()
        failures = []

        def work(output):
            try:
                with timings.run("request") as run:
                    with timings.stage("model_wait"):
                        ready.wait(timeout=3)
                        if not release.wait(timeout=3):
                            raise AssertionError("test synchronization timed out")
                    if output:
                        timings.first_output()
                    run["outcome"] = "ok" if output else "busy"
            except BaseException as error:
                failures.append(error)

        threads = [threading.Thread(target=work, args=(output,)) for output in (True, False)]
        for thread in threads:
            thread.start()
        try:
            ready.wait(timeout=3)
            self.assertEqual(timings.snapshot()["active"], 2)
        finally:
            release.set()
            for thread in threads:
                thread.join(timeout=3)
        self.assertFalse(failures)
        self.assertTrue(all(not t.is_alive() for t in threads))
        rows = {r["outcome"]: r for r in timings.snapshot()["recent"]}
        self.assertIsNotNone(rows["ok"]["firstOutputMs"])
        self.assertIsNone(rows["busy"]["firstOutputMs"])
        self.assertEqual(rows["ok"]["stages"]["model_wait"]["calls"], 1)

    def test_real_load_path_records_hashing_then_stamp_reuse_and_a_failed_reload(self):
        with tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
            path = Path(folder) / "weights.bin"
            path.write_bytes(b"fixture weights")
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            stack.enter_context(patch.object(model, "CACHE", folder))
            stack.enter_context(patch.dict(model.STATE, status="installing", error=None, gpu="fixture"))
            stack.enter_context(patch.object(model.threading, "Thread"))
            stack.enter_context(patch.object(model, "gpu_after_load"))
            stack.enter_context(patch("builtins.print"))

            def backend():
                self.assertTrue(model.verified_weight(str(path), digest))
                self.clock.advance(2)
                model.STATE["status"] = "ready"

            with patch.object(model, "load_gguf", side_effect=backend):
                model.load_model()
                model.load_model()
            path.write_bytes(b"corrupted weights")
            with patch.object(model, "load_gguf", side_effect=lambda: self._failed_weight(path, digest)):
                model.load_model()
        cold, warm, failed = self.timings.snapshot()["recent"]
        self.assertEqual(cold["outcome"], "ok")
        self.assertEqual(cold["stages"]["weight_hash"]["calls"], 1)
        self.assertEqual(warm["stages"]["weight_verification"]["calls"], 1)
        self.assertNotIn("weight_hash", warm["stages"])
        self.assertEqual(failed["outcome"], "error")
        self.assertEqual(failed["stages"]["weight_hash"]["failedCalls"], 1)
        self.assertEqual(failed["stages"]["weight_verification"]["failedCalls"], 1)
        self.assertNotIn(str(path), json.dumps(self.timings.snapshot()))

    def _failed_weight(self, path, digest):
        if not model.verified_weight(str(path), digest):
            raise RuntimeError("private checkpoint failed validation")

    def test_external_engine_span_includes_spawn_and_readiness_polling(self):
        process = Mock(stderr=iter(()), poll=Mock(return_value=None))

        def spawn(*args, **kwargs):
            self.clock.advance(20)
            return process

        responses = iter((503, 200))

        def health(*args, **kwargs):
            self.clock.advance(10)
            return Mock(), Mock(status=next(responses))

        with patch.dict(os.environ, {"YOUGORI_MODEL_CPU": "1"}), ExitStack() as stack:
            stack.enter_context(patch.dict(model.STATE, status="installing", error=None))
            stack.enter_context(patch.dict(model.LLAMA))
            stack.enter_context(patch.object(model, "ENGINE_PROCESS", None))
            stack.enter_context(patch.object(model.os.path, "exists", return_value=True))
            stack.enter_context(patch.object(model, "install"))
            stack.enter_context(patch.object(model, "llama_server", return_value="fixture-runner"))
            stack.enter_context(patch.object(model, "verified_gguf", return_value="fixture-weights"))
            stack.enter_context(patch.object(model, "llama_cpu_options", return_value=[]))
            stack.enter_context(patch.object(model, "model_memory_events", return_value={}))
            stack.enter_context(patch.object(model, "llama", side_effect=health))
            stack.enter_context(patch.object(model, "llama_json", return_value={}))
            stack.enter_context(patch.object(model.subprocess, "Popen", side_effect=spawn))
            stack.enter_context(patch.object(model.threading, "Thread"))
            stack.enter_context(patch.object(model, "gpu_after_load"))
            stack.enter_context(patch.object(model.time, "sleep", side_effect=lambda seconds: self.clock.advance(seconds * 1000)))
            stack.enter_context(patch("builtins.print"))
            # The ordinary load_gguf path is selected even when a developer has a native backend configured.
            os.environ.pop("YOUGORI_NATIVE_BACKEND", None)
            model.load_model()
        row = self.timings.snapshot()["recent"][0]
        self.assertEqual(row["outcome"], "ok")
        # Spawn 20 ms, two health checks of 10 ms and one readiness poll between them.
        self.assertEqual(row["stages"]["engine_start_to_ready"]["elapsedMs"], 40 + model.READY_POLL_SECONDS * 1000)
        self.assertNotIn("weight_load", row["stages"])
        self.assertEqual(row["stages"]["admission_wait"]["calls"], 1)

    def test_native_backend_measures_wait_without_claiming_process_start(self):
        with patch.dict(os.environ, {"YOUGORI_NATIVE_BACKEND": "cpu", "YOUGORI_NATIVE_TOKEN": "c" * 64,
                                   "YOUGORI_NATIVE_PORT": "12345"}), \
                patch.dict(model.STATE, status="installing", error=None), patch.dict(model.LLAMA), \
                patch.object(model, "verified_gguf"), \
                patch.object(model, "llama_json", side_effect=[OSError("not ready"), {}, {}]), \
                patch.object(model.subprocess, "Popen") as spawn, \
                patch.object(model.threading, "Thread"), patch.object(model, "gpu_after_load"), \
                patch.object(model.time, "sleep", side_effect=lambda seconds: self.clock.advance(seconds * 1000)), \
                patch("builtins.print"):
            model.load_model()
        spawn.assert_not_called()
        row = self.timings.snapshot()["recent"][0]
        self.assertEqual(row["outcome"], "ok")
        self.assertEqual(row["stages"]["native_ready_wait"]["elapsedMs"], model.READY_POLL_SECONDS * 1000)
        self.assertNotIn("engine_start_to_ready", row["stages"])

    def handler(self, body=None):
        handler = object.__new__(model.Handler)
        handler.connection, peer = socket.socketpair()
        self.addCleanup(handler.connection.close)
        self.addCleanup(peer.close)
        raw = body if isinstance(body, bytes) else json.dumps(body or {"messages": [{"role": "user", "content": "private prompt"}]}).encode()
        handler.path = "/v1/chat/completions"
        from http.client import HTTPMessage
        handler.headers = HTTPMessage()
        handler.headers["Authorization"] = "Bearer " + model.TOKEN
        handler.headers["Content-Length"] = str(len(raw))
        handler.rfile = io.BytesIO(raw)
        handler.wfile = io.BytesIO()
        for name in ("reply", "send_response", "send_header", "end_headers"):
            setattr(handler, name, Mock())
        return handler

    def request(self, handler, generate, entered=True):
        def enter(_):
            self.clock.advance(4)
            return entered

        with patch.object(model, "gpu_route", return_value=False), \
                patch.object(model, "gpu_enter", side_effect=enter) as admission, \
                patch.object(model, "gpu_leave") as leave, \
                patch.object(model, "generate", side_effect=generate), \
                patch.object(model, "record_listen"), patch.object(model, "record_usage"):
            handler.do_POST()
        return admission, leave

    def test_stream_first_output_excludes_role_only_and_includes_model_wait(self):
        def generate(body, handler, meter):
            model.RUNNER_TIMINGS.boundary("admittedMs")
            events = iter([
                (3, {"choices": [{"delta": {"role": "assistant", "content": ""}}]}),
                (5, {"choices": [{"delta": {"content": "private output"}}]}),
                (4, {"choices": [{"delta": {}, "finish_reason": "stop"}]}),
            ])

            def readline(_):
                item = next(events, None)
                if item is None:
                    return b"data: [DONE]\n"
                delay, value = item
                self.clock.advance(delay)
                return b"data: " + json.dumps(value).encode() + b"\n"

            response = Mock(readline=readline)
            model.stream_gguf(handler, response, 3, 16, {}, meter)

        self.request(self.handler({"messages": [{"role": "user", "content": "private prompt"}], "stream": True}), generate)
        row = self.timings.snapshot()["recent"][0]
        self.assertEqual(row["outcome"], "ok")
        self.assertEqual(row["firstOutputMs"], 12)
        self.assertEqual(row["elapsedMs"], 16)
        self.assertEqual(row["stages"]["model_wait"]["elapsedMs"], 4)
        self.assertEqual(row["stages"]["generation"]["elapsedMs"], 12)
        self.assertNotIn("private", json.dumps(row))

    def test_first_tool_fragment_counts_as_output_and_is_not_stored(self):
        def generate(body, handler, meter):
            model.RUNNER_TIMINGS.boundary("admittedMs")
            tool = {"choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"arguments": "{private"}}]}}]}
            end = {"choices": [{"delta": {}, "finish_reason": "tool_calls"}]}
            response = Mock(readline=Mock(side_effect=[b"data: " + json.dumps(tool).encode(), b"data: " + json.dumps(end).encode(), b"data: [DONE]"]))
            model.stream_gguf(handler, response, 3, 16, {}, meter)
        self.request(self.handler(), generate)
        row = self.timings.snapshot()["recent"][0]
        self.assertEqual(row["firstOutputMs"], 4)
        self.assertNotIn("private", json.dumps(row))

    def test_buffered_response_does_not_invent_a_first_token_time(self):
        def generate(body, handler, meter):
            model.RUNNER_TIMINGS.boundary("admittedMs")
            self.clock.advance(15)
            meter["outcome"] = "ok"
            return 200, {"choices": [{"message": {"content": "private output"}}]}
        self.request(self.handler(), generate)
        row = self.timings.snapshot()["recent"][0]
        self.assertEqual(row["outcome"], "ok")
        self.assertEqual(row["elapsedMs"], 19)
        self.assertIsNone(row["firstOutputMs"])

    def test_failed_output_write_never_becomes_first_output(self):
        class Disconnect(io.BytesIO):
            def write(self, data):
                if b"private output" in data:
                    raise BrokenPipeError()
                return super().write(data)

        def generate(body, handler, meter):
            model.RUNNER_TIMINGS.boundary("admittedMs")
            event = {"choices": [{"delta": {"content": "private output"}}]}
            response = Mock(readline=Mock(return_value=b"data: " + json.dumps(event).encode()))
            model.stream_gguf(handler, response, 3, 16, {}, meter)

        handler = self.handler()
        handler.wfile = Disconnect()
        self.request(handler, generate)
        row = self.timings.snapshot()["recent"][0]
        self.assertEqual(row["outcome"], "cancelled")
        self.assertIsNone(row["firstOutputMs"])

    def test_invalid_busy_and_failed_preparation_are_separate_attempts(self):
        admission, _ = self.request(self.handler(b"not JSON"), Mock())
        admission.assert_not_called()

        def busy(body, handler, meter):
            meter["outcome"] = "busy"
            return 429, {"error": {"message": "busy"}}

        self.request(self.handler(), busy)
        generate = Mock()
        _, leave = self.request(self.handler(), generate, entered=False)
        generate.assert_not_called()
        leave.assert_not_called()
        rows = self.timings.snapshot()["recent"]
        self.assertEqual([r["outcome"] for r in rows], ["invalid", "busy", "error"])
        self.assertEqual(rows[0]["stages"]["request_validation"]["failedCalls"], 1)
        self.assertEqual(rows[1]["stages"]["generation"]["failedCalls"], 1)
        self.assertEqual(rows[2]["stages"]["model_wait"]["failedCalls"], 1)
        self.assertTrue(all(r["firstOutputMs"] is None for r in rows))

    def test_diagnostics_require_both_credentials_and_are_absent_from_health(self):
        handler = self.handler()
        handler.path = "/v1/diagnostics/timings"
        handler.headers.replace_header("Authorization", "Bearer invalid")
        handler.do_GET()
        self.assertEqual(handler.reply.call_args.args[0], 401)
        handler.headers.replace_header("Authorization", "Bearer " + model.TOKEN)
        handler.do_GET()
        self.assertEqual(handler.reply.call_args.args[0], 403)
        handler.headers["X-Yougori-Admin"] = model.ADMIN_TOKEN
        handler.do_GET()
        self.assertEqual(handler.reply.call_args.args, (200, self.timings.snapshot()))
        handler.path = "/health"
        with patch.object(model, "gpu_snapshot", return_value={}):
            handler.do_GET()
        self.assertNotIn("recent", handler.reply.call_args.args[1])
        with patch.object(model, "ADMIN_TOKEN", ""):
            handler.path = "/v1/diagnostics/timings"
            handler.do_GET()
            self.assertEqual(handler.reply.call_args.args[0], 403)

    def test_the_load_view_shows_the_load_running_then_the_last_one_to_the_engine_only(self):
        self.assertEqual(self.timings.load_view(), {"inProgress": False})
        with self.timings.run("load") as run:
            with self.timings.stage("download"):
                self.clock.advance(5)
            with self.timings.stage("import"):
                self.clock.advance(2)
                self.assertEqual(self.timings.load_view(), {"inProgress": True, "elapsedMs": 7, "open": ["import"],
                                                            "stages": {"download": 5}})
            run["outcome"] = "ok"
        # The ring of recent records forgets the load after enough requests; the view keeps it.
        for _ in range(70):
            with self.timings.run("request") as request:
                request["outcome"] = "ok"
        self.assertEqual(self.timings.load_view(), {"inProgress": False, "outcome": "ok", "elapsedMs": 7,
                                                    "stages": {"download": 5, "import": 2}})
        handler = self.handler()
        handler.path = "/v1/diagnostics/load"
        handler.do_GET()
        self.assertEqual(handler.reply.call_args.args[0], 403)
        handler.headers["X-Yougori-Admin"] = model.ADMIN_TOKEN
        handler.do_GET()
        self.assertEqual(handler.reply.call_args.args, (200, self.timings.load_view()))
        handler.path = "/health"
        with patch.object(model, "gpu_snapshot", return_value={}):
            handler.do_GET()
        self.assertNotIn("stages", json.dumps(handler.reply.call_args.args[1]))

    def test_real_generation_admission_and_response_flush_exclude_cleanup(self):
        handler = self.handler()
        response = Mock(status=200, read=Mock(return_value=json.dumps({
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "private"}, "finish_reason": "stop"}]}).encode()))
        def prepare(*args):
            self.clock.advance(7)
            return [], 3, 0
        def reply(*args):
            self.clock.advance(11)
        handler.reply = reply
        class Writer(io.BytesIO):
            def flush(inner):
                self.clock.advance(5)
        handler.wfile = Writer()
        with patch.object(model, "gpu_enter", side_effect=lambda _: (self.clock.advance(4) or True)), \
                patch.object(model, "gpu_leave", side_effect=lambda: self.clock.advance(100)), \
                patch.object(model, "prepare_gguf", side_effect=prepare), \
                patch.object(model, "llama", return_value=(Mock(), response)), \
                patch.object(model, "record_listen"), patch.object(model, "record_usage"), \
                patch.object(model, "gpu_route", return_value=False):
            handler.do_POST()
        row = self.timings.snapshot()["recent"][0]
        self.assertEqual(row["outcome"], "ok")
        self.assertEqual(row["boundaries"], {"version": 1, "acceptedMs": 0, "admittedMs": 4, "completedMs": 27})
        self.assertEqual(row["elapsedMs"], 127)
        self.assertIsNone(row["firstOutputMs"])
        model.RunnerTimings.validate_boundaries(row)
        self.assertTrue(model.GENERATION.acquire(blocking=False))
        model.GENERATION.release()

    def test_real_generation_busy_never_claims_admission_or_completion(self):
        # The one-slot Transformers runner's lock (a stalled generation still owns it); relays to
        # llama.cpp and vLLM are bounded by the queue's slots instead.
        handler = self.handler()
        self.assertTrue(model.GENERATION.acquire(blocking=False))
        try:
            with patch.object(model, "FORMAT", "safetensors"):
                self.request(handler, model.generate)
        finally:
            model.GENERATION.release()
        row = self.timings.snapshot()["recent"][0]
        self.assertEqual(row["outcome"], "busy")
        self.assertEqual(row["boundaries"], {"version": 1, "acceptedMs": 0, "admittedMs": None, "completedMs": None})

    def test_final_stream_writes_cannot_turn_disconnect_into_success(self):
        for failure_marker in (b'"finish_reason": "stop"', b"[DONE]"):
            with self.subTest(marker=failure_marker):
                class Disconnect(io.BytesIO):
                    def write(inner, data):
                        if failure_marker in data:
                            raise BrokenPipeError()
                        return super().write(data)
                def generate(body, handler, meter):
                    model.RUNNER_TIMINGS.boundary("admittedMs")
                    response = Mock(readline=Mock(side_effect=[
                        b'data: {"choices":[{"delta":{"content":"text"}}]}',
                        b'data: {"choices":[{"delta":{},"finish_reason":"stop"}]}',
                        b'data: [DONE]']))
                    model.stream_gguf(handler, response, 1, 8, {}, meter)
                handler = self.handler()
                handler.wfile = Disconnect()
                self.request(handler, generate)
                row = self.timings.snapshot()["recent"][-1]
                self.assertEqual(row["outcome"], "cancelled")
                self.assertIsNone(row["boundaries"]["completedMs"])
                model.RunnerTimings.validate_boundaries(row)

    def test_buffered_disconnect_is_cancelled_without_second_response(self):
        def generate(body, handler, meter):
            model.RUNNER_TIMINGS.boundary("admittedMs")
            meter["outcome"] = "ok"
            return 200, {}
        handler = self.handler()
        handler.reply.side_effect = BrokenPipeError()
        self.request(handler, generate)
        self.assertEqual(handler.reply.call_count, 1)
        row = self.timings.snapshot()["recent"][0]
        self.assertEqual(row["outcome"], "cancelled")
        self.assertIsNone(row["boundaries"]["completedMs"])

    def test_transformer_stream_final_disconnect_is_cancelled(self):
        class Streamer:
            def __init__(inner, *args, **kwargs):
                inner.chunks = iter(("text",))
            def __next__(inner):
                return next(inner.chunks)
            def end(inner):
                pass
        transformers = SimpleNamespace(StoppingCriteriaList=list, TextIteratorStreamer=Streamer)
        for failure_marker in (b'"finish_reason": "stop"', b"[DONE]"):
            with self.subTest(marker=failure_marker):
                class Disconnect(io.BytesIO):
                    def write(inner, data):
                        if failure_marker in data:
                            raise BrokenPipeError()
                        return super().write(data)
                def generate(body, handler, meter):
                    model.RUNNER_TIMINGS.boundary("admittedMs")
                    model.stream_reply(handler, {}, 1, 8, {}, {}, meter)
                handler = self.handler()
                handler.wfile = Disconnect()
                with patch.dict("sys.modules", transformers=transformers), \
                        patch.object(model, "base_chat", return_value=False), \
                        patch.object(model, "TORCH", SimpleNamespace(inference_mode=nullcontext)), \
                        patch.object(model, "NETWORK", Mock(generate=Mock(return_value=SimpleNamespace(shape=(1, 2))))):
                    self.request(handler, generate)
                row = self.timings.snapshot()["recent"][-1]
                self.assertEqual(row["outcome"], "cancelled")
                self.assertIsNone(row["boundaries"]["completedMs"])
                model.RunnerTimings.validate_boundaries(row)

    def test_request_boundaries_are_write_once_and_validate_order(self):
        with self.timings.run("request") as run:
            self.timings.boundary("acceptedMs")
            self.clock.advance(3)
            self.timings.boundary("admittedMs")
            self.clock.advance(5)
            self.timings.boundary("admittedMs")
            self.timings.boundary("completedMs")
            run["outcome"] = "ok"
        row = self.timings.snapshot()["recent"][0]
        self.assertEqual(row["boundaries"]["admittedMs"], 3)
        model.RunnerTimings.validate_boundaries(row)
        for changes in ({"version": True}, {"acceptedMs": None}, {"admittedMs": 9},
                        {"admittedMs": None}, {"completedMs": -1}, {"secret": "private"}):
            bad = {**row, "boundaries": {**row["boundaries"], **changes}}
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                model.RunnerTimings.validate_boundaries(bad)


    def measured_stream(self, events, writer=None):
        self.timings.journal = Mock(status="recording")
        handler = self.handler({"messages": [{"role": "user", "content": "private"}], "stream": True})
        if writer is not None:
            handler.wfile = writer
        lines = iter([b"data: " + json.dumps(event).encode() + b"\n" for event in events] + [b"data: [DONE]\n"])
        def read(_):
            self.clock.advance(2)
            return next(lines, b"")
        upstream = Mock(return_value=(Mock(), Mock(status=200, readline=read)))
        with patch.object(model, "prepare_gguf", return_value=([], 1, 0)), patch.object(model, "llama", upstream):
            self.request(handler, model.generate_gguf)
        return self.timings.snapshot()["recent"][-1], handler, upstream

    @staticmethod
    def token_event(text, pieces=None, **delta):
        return {"choices": [{"index": 0, "delta": {"content": text, **delta},
                            "logprobs": {"content": [{"bytes": list(piece), "token": "private"}
                                for piece in (pieces if pieces is not None else [text.encode()])]}}]}

    @staticmethod
    def token_end(count):
        return [{"choices": [{"delta": {}, "finish_reason": "stop"}]},
                {"choices": [], "usage": {"completion_tokens": count}}]

    def test_exact_tokens_use_successful_flush_and_preserve_batched_unicode(self):
        class Writer(io.BytesIO):
            def flush(inner):
                self.clock.advance(3)
        events = [self.token_event("\u00e9", [b"\xc3", b"\xa9"]), self.token_event("!")] + self.token_end(3)
        row, handler, upstream = self.measured_stream(events, Writer())
        self.assertTrue(row["tokens"]["complete"])
        times = row["tokens"]["emittedMs"]
        self.assertEqual(times, [12, 12, 17])
        self.assertEqual(row["tokens"]["outputTokens"], 3)
        model.RunnerTimings.validate_tokens(row)
        self.assertTrue(upstream.call_args.args[1]["logprobs"])
        # These tests run as a GGUF runner: llama.cpp streams token entries only for an alternative.
        self.assertEqual(upstream.call_args.args[1]["top_logprobs"], 1)
        self.assertNotIn(b"logprobs", handler.wfile.getvalue())
        self.assertNotIn("private", json.dumps(row))

    def test_a_vllm_end_of_sequence_the_text_skips_closes_an_exact_trace_only_at_a_stop(self):
        class Writer(io.BytesIO):
            def flush(inner):
                self.clock.advance(3)
        # vLLM lists its end of sequence among the last text chunk's tokens; the text skips it.
        events = [self.token_event("Hi"), self.token_event(" there", [b" there", b"<|im_end|>"])] + self.token_end(3)
        row, _, _ = self.measured_stream(events, Writer())
        self.assertTrue(row["tokens"]["complete"])
        self.assertEqual(row["tokens"]["outputTokens"], 3)
        times = row["tokens"]["emittedMs"]
        self.assertEqual((len(times), times[1] == times[2]), (3, True))
        model.RunnerTimings.validate_tokens(row)
        length = [{"choices": [{"delta": {}, "finish_reason": "length"}]}, {"choices": [], "usage": {"completion_tokens": 3}}]
        # With longer replies the end of sequence comes in a chunk of its own, never forwarded:
        # it crossed the finishing chunk's flush.
        alone = {"choices": [{"index": 0, "delta": {"content": ""}, "logprobs": {"content": [{"bytes": list(b"<|im_end|>"), "token": "private"}]}}]}
        row, handler, _ = self.measured_stream([self.token_event("Hi"), self.token_event(" there"), alone] + self.token_end(3), Writer())
        self.assertTrue(row["tokens"]["complete"])
        times = row["tokens"]["emittedMs"]
        self.assertEqual(len(times), 3)
        self.assertGreater(times[2], times[1])
        model.RunnerTimings.validate_tokens(row)
        self.assertNotIn(b"im_end", handler.wfile.getvalue())
        for events in ([self.token_event("a", [b"a", b"<|im_end|>"]), self.token_event("b")] + self.token_end(3),
                       [self.token_event("a"), alone, self.token_event("b")] + self.token_end(3),
                       [self.token_event("a"), alone, alone, alone] + self.token_end(4),
                       [self.token_event("a"), alone] + [{"choices": [{"delta": {}, "finish_reason": "length"}]}, {"choices": [], "usage": {"completion_tokens": 2}}],
                       [self.token_event("a", [b"a", b"<|e|>", b"<|e|>", b"<|e|>"])] + self.token_end(4),
                       [self.token_event("ab", [b"a", b"x", b"<|im_end|>"])] + self.token_end(3),
                       [self.token_event("Hi"), self.token_event(" there", [b" there", b"<|im_end|>"])] + length):
            with self.subTest(events=events):
                row, _, _ = self.measured_stream(events)
                self.assertFalse(row["tokens"]["complete"])

    def test_llama_cpp_streams_token_entries_and_its_unstreamed_end_of_generation_closes_the_trace(self):
        class Writer(io.BytesIO):
            def flush(inner):
                self.clock.advance(3)
        stop = lambda reason, count: [{"choices": [{"delta": {}, "finish_reason": reason}]}, {"choices": [], "usage": {"completion_tokens": count}}]
        with patch.object(model, "FORMAT", "gguf"):
            # llama.cpp counts its end of generation in the usage but never streams it.
            row, _, upstream = self.measured_stream([self.token_event("Hi"), self.token_event(" there")] + stop("stop", 3), Writer())
            self.assertEqual(upstream.call_args.args[1]["top_logprobs"], 1)
            self.assertTrue(row["tokens"]["complete"])
            times = row["tokens"]["emittedMs"]
            self.assertEqual(len(times), 3)
            self.assertGreater(times[2], times[1])
            model.RunnerTimings.validate_tokens(row)
            for events in ([self.token_event("Hi")] + stop("length", 2), [self.token_event("Hi")] + stop("stop", 3)):
                with self.subTest(events=events):
                    row, _, _ = self.measured_stream(events)
                    self.assertFalse(row["tokens"]["complete"])
        # vLLM streams its end of sequence as an entry: no unstreamed token is allowed there.
        with patch.object(model, "FORMAT", "vllm"), patch.object(model, "vllm_model", create=True, return_value=model.MODEL), \
             patch.object(model, "backend_observation_start", create=True, return_value=None):
            row, _, upstream = self.measured_stream([self.token_event("Hi")] + stop("stop", 2))
            chat = [call for call in upstream.call_args_list if call.args and call.args[0] == "/v1/chat/completions"]
            self.assertEqual(chat[-1].args[1]["top_logprobs"], 0)
            self.assertFalse(row["tokens"]["complete"])

    def test_missing_mismatched_filtered_and_overflow_tokens_remain_gaps(self):
        cases = [
            ([{"choices": [{"delta": {"content": "x"}}]}], 1),
            ([self.token_event("x", [b"y"])], 1),
            ([self.token_event("x", [b""])], 1),
            ([self.token_event("x", reasoning_content="hidden")], 1),
            ([self.token_event("x", tool_calls=[{"id": "tool"}])], 1),
            ([self.token_event("x")], 3),
            ([self.token_event("x")], None),
            ([self.token_event("x" * 257, [b"x"] * 257)], 257),
        ]
        for events, count in cases:
            with self.subTest(count=count, events=events):
                row, _, _ = self.measured_stream(events + self.token_end(count))
                self.assertEqual(row["outcome"], "ok")
                self.assertFalse(row["tokens"]["complete"])
                self.assertLessEqual(len(row["tokens"]["emittedMs"]), 256)
                model.RunnerTimings.validate_tokens(row)

    def test_token_trace_never_promotes_disconnect_or_backend_error(self):
        class Disconnect(io.BytesIO):
            def write(inner, data):
                if b"[DONE]" in data:
                    raise BrokenPipeError()
                return super().write(data)
        for writer, ending in [(Disconnect(), self.token_end(1)),
                               (None, [{"error": {"message": "failure"}}])]:
            row, _, _ = self.measured_stream([self.token_event("x")] + ending, writer)
            self.assertNotEqual(row["outcome"], "ok")
            self.assertFalse(row["tokens"]["complete"])
            model.RunnerTimings.validate_tokens(row)

    def test_trace_is_opt_in_and_not_created_without_admission(self):
        with self.timings.run("request"):
            self.assertIsNone(self.timings.token_trace())
            self.timings.boundary("acceptedMs")
            self.timings.boundary("admittedMs")
            self.assertIsNone(self.timings.token_trace())
            self.timings.journal = Mock(status="sealed")
            self.assertIsNone(self.timings.token_trace())

    def test_token_record_validation_rejects_bad_schema_and_order(self):
        row, _, _ = self.measured_stream([self.token_event("x")] + self.token_end(1))
        for changes in ({"version": True}, {"source": "invented"}, {"complete": 1},
                        {"emittedMs": [-1]}, {"emittedMs": [999999]}, {"emittedMs": [7, 6]},
                        {"outputTokens": True}, {"outputTokens": 2}, {"private": "secret"}):
            bad = {**row, "tokens": {**row["tokens"], **changes}}
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                model.RunnerTimings.validate_tokens(bad)


    def test_duplicate_loads_do_not_repeat_backend_or_finish_another_owners_state(self):
        entered, release = threading.Event(), threading.Event()
        calls, cleanup = [], []
        @model.single_model_load
        @model.timed_load
        def load():
            calls.append(1)
            entered.set()
            self.assertTrue(release.wait(3))
            model.STATE["status"] = "ready"
        def after():
            # The admission lock is released before completion becomes visible.
            self.assertFalse(model.MODEL_LOAD_LOCK.locked())
            cleanup.append(1)
        with patch.object(model, "gpu_after_load", side_effect=after):
            thread = threading.Thread(target=load)
            thread.start()
            try:
                self.assertTrue(entered.wait(2))
                load()
                self.assertEqual(calls, [1])
                self.assertEqual(cleanup, [])
                self.assertEqual(self.timings.snapshot()["started"], 1)
            finally:
                release.set(); thread.join(3)
            self.assertFalse(thread.is_alive())
            self.assertEqual(cleanup, [1])
            load()
            self.assertEqual(calls, [1, 1])

    def test_load_exception_releases_owner_and_allows_retry(self):
        @model.single_model_load
        def load():
            raise RuntimeError("fixture")
        with patch.object(model, "gpu_after_load") as after:
            for _ in range(2):
                with self.assertRaisesRegex(RuntimeError, "fixture"): load()
                self.assertFalse(model.MODEL_LOAD_LOCK.locked())
            self.assertEqual(after.call_count, 2)



    def finish_load(self, succeed=True):
        @model.timed_load
        def load():
            self.clock.advance(4)
            model.STATE["status"] = "ready" if succeed else "error"
        thread = threading.Thread(target=load)
        thread.start(); thread.join(3)
        self.assertFalse(thread.is_alive())

    def test_demand_load_captured_by_real_gpu_admission_once(self):
        self.timings.journal = Mock(status="recording")
        with patch.object(model, "gpu_prepare"), patch.object(model, "gpu_publish"):
            with self.timings.run("request") as run:
                self.timings.boundary("acceptedMs")
                self.clock.advance(3)
                self.finish_load()
                self.assertTrue(model.gpu_enter(Mock()))
                model.gpu_leave()
                self.timings.boundary("admittedMs")
                original = run["demandLoad"].copy()
                self.finish_load()
                self.timings.capture_demand_load()
                self.assertEqual(run["demandLoad"], original)
                run["outcome"] = "ok"
        row = self.timings.snapshot()["recent"][-1]
        self.assertEqual(row["demandLoad"], {"version": 1, "source": "runner-load-call",
            "loadAttemptId": 2, "startedMs": 3, "readyMs": 7})
        model.RunnerTimings.validate_demand_load(row)
        row["demandLoad"]["readyMs"] = 999
        self.assertEqual(self.timings.snapshot()["recent"][-1]["demandLoad"]["readyMs"], 7)

    def test_demand_load_ignores_prior_failed_pending_and_disabled_measurements(self):
        for case in ("prior", "failed", "pending", "disabled", "sealed", "unaccepted"):
            with self.subTest(case=case):
                self.timings.journal = Mock(status="recording")
                self.timings.invalidate_load()
                if case == "prior": self.finish_load()
                self.clock.advance(1)
                with self.timings.run("request") as run:
                    if case != "unaccepted": self.timings.boundary("acceptedMs")
                    if case != "prior": self.finish_load(case != "failed")
                    if case == "pending":
                        self.timings.latest_load = (99, self.clock(), None)
                    if case == "disabled": self.timings.journal = None
                    if case == "sealed": self.timings.journal.status = "sealed"
                    self.timings.capture_demand_load()
                    self.assertNotIn("demandLoad", run)

    def test_in_progress_on_arrival_is_not_retimed(self):
        self.timings.journal = Mock(status="recording")
        with self.timings.run("load") as load:
            self.timings.load_started(load)
            self.clock.advance(1)
            with self.timings.run("request") as run:
                self.timings.boundary("acceptedMs")
                self.clock.advance(4)
                self.timings.load_finished(load, True)
                self.timings.capture_demand_load()
                self.assertNotIn("demandLoad", run)

    def test_old_finish_and_failed_release_cannot_restore_stale_load(self):
        self.timings.journal = Mock(status="recording")
        with self.timings.run("load") as old:
            self.timings.load_started(old)
            with self.timings.run("load") as newer:
                self.timings.load_started(newer)
                self.timings.load_finished(newer, True)
                current = self.timings.latest_load
                self.timings.load_finished(old, True)
                self.assertEqual(self.timings.latest_load, current)
                process = Mock()
                process.poll.return_value = None
                process.terminate.side_effect = RuntimeError("fixture")
                with patch.object(model, "ENGINE_PROCESS", process):
                    with self.assertRaisesRegex(RuntimeError, "fixture"):
                        model.gpu_release_memory()
                self.assertIsNone(self.timings.latest_load)
                self.timings.load_finished(newer, True)
                self.assertIsNone(self.timings.latest_load)

    def test_concurrent_waiters_share_load_without_sharing_request_records(self):
        self.timings.journal = Mock(status="recording")
        accepted, loaded = threading.Barrier(3), threading.Event()
        records = []
        def request():
            with self.timings.run("request") as run:
                self.timings.boundary("acceptedMs")
                accepted.wait(timeout=3)
                if loaded.wait(3):
                    self.timings.capture_demand_load()
                    records.append(run)
        threads = [threading.Thread(target=request) for _ in range(2)]
        for thread in threads: thread.start()
        try:
            accepted.wait(timeout=3)
            self.clock.advance(1)
            self.finish_load()
        finally:
            loaded.set()
            for thread in threads: thread.join(3)
        self.assertEqual(len(records), 2)
        self.assertNotEqual(records[0]["id"], records[1]["id"])
        self.assertEqual(records[0]["demandLoad"], records[1]["demandLoad"])
        self.assertIsNot(records[0]["demandLoad"], records[1]["demandLoad"])

    def test_demand_load_schema_rejects_untrusted_or_impossible_fields(self):
        row = {"id": 1, "kind": "request", "elapsedMs": 20,
            "boundaries": {"acceptedMs": 2, "admittedMs": 10},
            "demandLoad": {"version": 1, "source": "runner-load-call", "loadAttemptId": 2,
                "startedMs": 3, "readyMs": 8}}
        model.RunnerTimings.validate_demand_load(row)
        for changes in ({"version": True}, {"version": 2}, {"source": "device"},
                        {"loadAttemptId": True}, {"loadAttemptId": 1}, {"loadAttemptId": 2**53},
                        {"startedMs": 1}, {"startedMs": 9}, {"readyMs": 11},
                        {"readyMs": float("nan")}, {"private": "secret"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                model.RunnerTimings.validate_demand_load({**row, "demandLoad": {**row["demandLoad"], **changes}})


    def test_backend_clocks_are_kept_only_whole_for_a_successful_request_inside_a_window(self):
        clocks = {"version": 1, "source": "llama-cpp-timings", "promptTokens": 120, "cachedTokens": 20,
                  "queueMs": None, "prefillMs": 50.5, "decodeMs": 40.25, "outputTokens": 3}
        self.timings.journal = Mock(status="recording")
        with self.timings.run("request") as run:
            self.timings.boundary("acceptedMs")
            self.timings.boundary("admittedMs")
            self.assertTrue(self.timings.measuring())
            for broken in ({**clocks, "cachedTokens": 121}, {**clocks, "source": "device"}, {**clocks, "prefillMs": None},
                           {**clocks, "queueMs": -1}, {**clocks, "extra": 1}, {**clocks, "version": True}):
                self.timings.backend(broken)
                self.assertNotIn("backend", run)
            self.timings.backend(clocks)
            run["outcome"] = "ok"
        row = self.timings.snapshot()["recent"][-1]
        self.assertEqual(row["backend"], clocks)
        model.RunnerTimings.validate_backend(row)
        # A failed request keeps none; outside a window none is taken.
        with self.timings.run("request") as run:
            self.timings.boundary("acceptedMs")
            self.timings.boundary("admittedMs")
            self.timings.backend(clocks)
            run["outcome"] = "error"
        self.assertNotIn("backend", self.timings.snapshot()["recent"][-1])
        self.timings.journal = None
        with self.timings.run("request") as run:
            self.timings.boundary("acceptedMs")
            self.timings.boundary("admittedMs")
            self.assertFalse(self.timings.measuring())
            self.timings.backend(clocks)
            run["outcome"] = "ok"
        self.assertNotIn("backend", self.timings.snapshot()["recent"][-1])

    def test_a_load_that_woke_a_sleeping_engine_is_a_waiting_requests_demand_wake(self):
        self.timings.journal = Mock(status="recording")

        @model.timed_load
        def wake():
            with self.timings.stage("engine_wake"):
                self.clock.advance(2)
            with self.timings.stage("weight_reload"):
                self.clock.advance(3)
            model.STATE["status"] = "ready"
        with self.timings.run("request") as run:
            self.timings.boundary("acceptedMs")
            self.clock.advance(1)
            wake()
            self.timings.capture_demand_load()
            self.timings.boundary("admittedMs")
            run["outcome"] = "ok"
        rows = self.timings.snapshot()["recent"]
        self.assertEqual(rows[0]["stages"], {"engine_wake": {"calls": 1, "failedCalls": 0, "elapsedMs": 2},
                                             "weight_reload": {"calls": 1, "failedCalls": 0, "elapsedMs": 3}})
        self.assertEqual(rows[1]["demandLoad"], {"version": 1, "source": "runner-wake-call", "loadAttemptId": 2,
                                                 "startedMs": 1, "readyMs": 6})
        model.RunnerTimings.validate_demand_load(rows[1])
        # A load from scratch afterwards is a load again.
        with self.timings.run("request") as run:
            self.timings.boundary("acceptedMs")
            self.finish_load()
            self.timings.capture_demand_load()
            run["outcome"] = "ok"
        self.assertEqual(self.timings.snapshot()["recent"][-1]["demandLoad"]["source"], "runner-load-call")


if __name__ == "__main__":
    unittest.main()
