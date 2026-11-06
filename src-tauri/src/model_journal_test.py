"""Durable measurement windows through actual timing and HTTP paths, offline."""
import http.client
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch


class JournalTests(unittest.TestCase):
    def setUp(self):
        scratch = "D:/YougoriBuildCache/scratch"
        self.folder = tempfile.TemporaryDirectory(dir=scratch if os.path.isdir(scratch) else None)
        self.session = "a" * 32
        self.environment = patch.dict(os.environ, {
            "YOUGORI_MODEL": "fixture/journal", "YOUGORI_MODEL_TOKEN": "fixture-model",
            "YOUGORI_MODEL_ADMIN_TOKEN": "fixture-admin", "YOUGORI_MEASUREMENT_SESSION": self.session,
            "YOUGORI_MODEL_FORMAT": "gguf", "HF_HOME": self.folder.name,
        })
        self.environment.start()
        self.model = self.module()
        self.timings = self.model.RUNNER_TIMINGS
        self.journal = self.timings.journal
        self.server = self.model.Server(("127.0.0.1", 0), self.model.Handler)
        self.server_thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": .01}, daemon=True)
        self.server_thread.start()

    def module(self):
        spec = importlib.util.spec_from_file_location("journal_fixture", Path(__file__).with_name("model_server.py"))
        model = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(model)
        return model

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.server_thread.join(2)
        self.environment.stop()
        self.folder.cleanup()

    def request(self, query="?journal=1", body=None, authorized=True, admin=True):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        try:
            headers = {"Content-Type": "application/json"}
            if authorized:
                headers["Authorization"] = "Bearer fixture-model"
            if admin:
                headers["X-Yougori-Admin"] = "fixture-admin"
            connection.request("GET" if body is None else "POST", "/v1/diagnostics/timings" + query,
                               None if body is None else json.dumps(body), headers)
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def complete(self, outcome="ok"):
        with self.timings.run("request") as run:
            with self.timings.stage("generation"):
                self.timings.first_output()
            run["outcome"] = outcome

    def test_start_is_durable_before_work_and_terminal_failure_is_redacted(self):
        with self.assertRaisesRegex(RuntimeError, "PRIVATE"):
            with self.timings.run("load"):
                disk = [json.loads(line) for line in Path(self.journal.path).read_text().splitlines()]
                self.assertEqual(disk[-1]["event"], "start")
                self.assertEqual(disk[-1]["attemptId"], 1)
                raise RuntimeError("PRIVATE prompt key /path")
        code, page = self.request()
        self.assertEqual(code, 200)
        records = page["journal"]["records"]
        self.assertEqual([row["event"] for row in records], ["instance", "start", "finish"])
        self.assertEqual(records[-1]["record"]["outcome"], "error")
        self.assertNotIn("PRIVATE", json.dumps(page))
        self.assertNotIn(self.folder.name, json.dumps(page))
        self.assertFalse(page["journal"]["complete"])

    def test_journal_replays_evicted_ring_records_with_stable_global_cursor(self):
        for _ in range(70):
            self.complete()
        self.assertEqual(self.timings.snapshot()["evicted"], 6)
        rows, after = [], 0
        while True:
            code, reply = self.request(f"?journal=1&after={after}&limit=17")
            self.assertEqual(code, 200)
            page = reply["journal"]
            rows.extend(page["records"])
            after = page["nextAfter"]
            if not page["hasMore"]:
                break
        self.assertEqual([row["sequence"] for row in rows], list(range(1, 142)))
        self.assertEqual(len([row for row in rows if row["event"] == "finish"]), 70)
        self.assertFalse(page["loss"])

    def test_request_boundaries_survive_sealing_and_restart_replay(self):
        with self.timings.run("request") as run:
            self.timings.boundary("acceptedMs")
            self.timings.boundary("admittedMs")
            self.timings.first_output()
            self.timings.boundary("completedMs")
            run["outcome"] = "ok"
        self.assertTrue(self.timings.seal_journal(self.session))
        original = self.request()[1]["journal"]["records"]
        row = original[-2]["record"]
        self.model.RunnerTimings.validate_boundaries(row)
        reopened = self.module().RUNNER_TIMINGS.journal_snapshot()["journal"]
        self.assertEqual(reopened["records"], original)
        self.assertTrue(reopened["loss"])

    def test_invalid_boundary_metadata_fails_closed_without_persisting_it(self):
        with self.timings.run("request") as run:
            self.timings.boundary("acceptedMs")
            run["boundaries"]["secret"] = "PRIVATE"
            run["outcome"] = "ok"
        self.assertEqual(self.journal.status, "degraded")
        self.assertNotIn("PRIVATE", Path(self.journal.path).read_text())
        self.assertFalse(self.timings.seal_journal(self.session))

    def test_both_credentials_protect_replay_and_sealing(self):
        seal = {"action": "seal", "sessionId": self.session}
        for authorized, admin, expected in ((False, True, 401), (True, False, 403)):
            self.assertEqual(self.request(authorized=authorized, admin=admin)[0], expected)
            self.assertEqual(self.request("", body=seal, authorized=authorized, admin=admin)[0], expected)
        self.assertEqual(self.journal.status, "recording")

    def test_malformed_queries_and_seal_bodies_do_not_expose_record_data(self):
        for query in ("?journal=1&limit=129", "?journal=1&after=-1", "?journal=1&after=9007199254740992",
                      "?journal=1&after=0&after=1", "?journal=1&private=secret", "?journal=1&limit=0", "?journal=2"):
            code, reply = self.request(query)
            self.assertEqual(code, 400)
            self.assertNotIn("records", json.dumps(reply))
        for body in ([], {"action": "seal"}, {"action": "unknown", "sessionId": self.session}):
            self.assertEqual(self.request("", body=body)[0], 400)

    def test_seal_refuses_active_attempt_and_closes_only_explicit_window(self):
        body = {"action": "seal", "sessionId": self.session}
        with self.timings.run("request") as run:
            self.assertEqual(self.request("", body=body)[0], 409)
            run["outcome"] = "ok"
        code, reply = self.request("", body=body)
        self.assertEqual(code, 200)
        self.assertTrue(reply["journal"]["complete"])
        self.assertEqual(reply["journal"]["scope"], "session_window")
        size = Path(self.journal.path).stat().st_size
        with self.timings.run("request") as run:
            self.assertEqual(self.request("", body=body)[0], 200, "sealing is idempotent outside the closed window")
            run["outcome"] = "ok"
        self.assertEqual(Path(self.journal.path).stat().st_size, size)
        self.assertEqual(self.timings.snapshot()["completed"], 2)
        self.assertEqual(len(self.journal.replay()["records"]), 4)

    def test_crashed_session_replays_open_attempt_but_never_continues_or_seals(self):
        self.journal.append({"event": "start", "attemptId": 1, "kind": "request"})
        before = Path(self.journal.path).read_bytes()
        restarted = self.module().RUNNER_TIMINGS
        page = restarted.journal_snapshot()["journal"]
        self.assertEqual(page["status"], "degraded")
        self.assertTrue(page["loss"])
        self.assertEqual(page["inflight"], 1)
        self.assertEqual(page["interrupted"], 1)
        self.assertNotEqual(page["instanceId"], self.timings.instance_id)
        self.assertEqual([row["sequence"] for row in page["records"]], [1, 2])
        with restarted.run("request") as run:
            run["outcome"] = "ok"
        self.assertFalse(restarted.seal_journal(self.session))
        self.assertEqual(Path(self.journal.path).read_bytes(), before)

    def test_restarted_sealed_session_is_conservatively_degraded(self):
        self.complete()
        self.assertTrue(self.timings.seal_journal(self.session))
        restarted = self.module().RUNNER_TIMINGS
        page = restarted.journal_snapshot()["journal"]
        self.assertTrue(page["loss"])
        self.assertFalse(page["complete"])
        self.assertFalse(restarted.seal_journal(self.session))

    def test_torn_or_malformed_tail_preserves_only_valid_redacted_prefix(self):
        self.complete()
        original = Path(self.journal.path).read_bytes()
        for suffix in (b'{"PRIVATE":', b'{"sequence":4,"event":"PRIVATE","instanceId":"' + b"b" * 32 + b'"}\n'):
            Path(self.journal.path).write_bytes(original + suffix)
            restarted = self.module().RUNNER_TIMINGS
            page = restarted.journal_snapshot()["journal"]
            self.assertTrue(page["loss"])
            self.assertEqual([row["sequence"] for row in page["records"]], [1, 2, 3])
            self.assertNotIn("PRIVATE", json.dumps(page))

    def test_fsync_failure_does_not_abort_work_or_allow_complete_evidence(self):
        with patch.object(self.model.os, "fsync", side_effect=OSError("PRIVATE disk-full")):
            self.complete()
        self.assertEqual(self.timings.snapshot()["completed"], 1)
        page = self.timings.journal_snapshot()["journal"]
        self.assertTrue(page["loss"])
        self.assertEqual(page["status"], "degraded")
        self.assertFalse(self.timings.seal_journal(self.session))
        self.assertNotIn("PRIVATE", json.dumps(page))

    def test_failed_terminal_write_leaves_attempt_incomplete(self):
        original = self.journal.append

        def fail_finish(event):
            if event["event"] == "finish":
                with patch.object(self.model.os, "fsync", side_effect=OSError("disk-full")):
                    return original(event)
            return original(event)

        with patch.object(self.journal, "append", side_effect=fail_finish):
            self.complete()
        page = self.timings.journal_snapshot()["journal"]
        self.assertEqual(page["inflight"], 1)
        self.assertTrue(page["loss"])
        self.assertFalse(page["complete"])

    def test_failed_seal_fsync_remains_incomplete_even_if_marker_bytes_exist(self):
        self.complete()
        with patch.object(self.model.os, "fsync", side_effect=OSError("PRIVATE seal failure")):
            self.assertFalse(self.timings.seal_journal(self.session))
        self.assertTrue(self.timings.journal_snapshot()["journal"]["loss"])
        restarted = self.module().RUNNER_TIMINGS
        page = restarted.journal_snapshot()["journal"]
        self.assertFalse(page["complete"])
        self.assertTrue(page["loss"])
        self.assertNotIn("PRIVATE", json.dumps(page))

    def test_concurrent_attempts_replay_out_of_order_finishes_without_lost_starts(self):
        entered, release = threading.Event(), threading.Event()

        def slow():
            with self.timings.run("request") as run:
                entered.set()
                release.wait(3)
                run["outcome"] = "cancelled"

        thread = threading.Thread(target=slow)
        thread.start()
        try:
            self.assertTrue(entered.wait(2))
            self.complete("busy")
            self.assertFalse(self.timings.seal_journal(self.session))
        finally:
            release.set()
            thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertTrue(self.timings.seal_journal(self.session))
        page = self.timings.journal_snapshot()["journal"]
        finishes = [row for row in page["records"] if row["event"] == "finish"]
        self.assertEqual([row["attemptId"] for row in finishes], [2, 1])
        self.assertEqual([row["record"]["completionSequence"] for row in finishes], [1, 2])
        self.assertEqual([row["record"]["outcome"] for row in finishes], ["busy", "cancelled"])
        self.assertTrue(page["complete"])

    def test_session_file_count_and_invalid_configuration_fail_closed(self):
        for letter in ("b", "c", "d"):
            journal = self.model.RunnerJournal(self.folder.name, letter * 32)
            self.model.RunnerTimings(journal=journal)
            self.assertEqual(journal.status, "recording")
        extra = self.model.RunnerJournal(self.folder.name, "e" * 32)
        invalid = self.model.RunnerJournal(self.folder.name, "PRIVATE/invalid")
        for journal in (extra, invalid):
            timings = self.model.RunnerTimings(journal=journal)
            page = timings.journal_snapshot()["journal"]
            self.assertTrue(page["loss"])
            self.assertFalse(page["complete"])
            self.assertNotIn("PRIVATE", json.dumps(page))
        self.assertEqual(len(list(Path(self.folder.name, "yougori-measurements").glob("*.jsonl"))), 4)

    def test_capacity_is_bounded_without_evicting_or_claiming_complete(self):
        with patch.object(self.journal, "MAX_EVENTS", 3):
            self.complete()
            before = Path(self.journal.path).read_bytes()
            self.complete()
            self.assertEqual(Path(self.journal.path).read_bytes(), before)
            self.assertTrue(self.timings.journal_snapshot()["journal"]["loss"])
            self.assertFalse(self.timings.seal_journal(self.session))

    def test_default_off_has_no_journal_io_and_snapshot_stays_compatible(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("YOUGORI_MEASUREMENT_SESSION", None)
            ordinary = self.module().RUNNER_TIMINGS
        self.assertIsNone(ordinary.journal)
        with patch("builtins.open", side_effect=AssertionError("default timing touched disk")):
            with ordinary.run("request") as run:
                run["outcome"] = "ok"
            self.assertEqual(ordinary.snapshot()["completed"], 1)
            self.assertEqual(ordinary.journal_snapshot()["journal"]["status"], "disabled")


    def test_token_trace_round_trips_durable_journal_without_content(self):
        with self.timings.run("request") as run:
            self.timings.boundary("acceptedMs")
            self.timings.boundary("admittedMs")
            trace = self.timings.token_trace()
            trace.observe({"choices": [{"delta": {"content": "private"},
                "logprobs": {"content": [{"bytes": list(b"private")}]}}]}, True, self.timings.elapsed(trace.start))
            trace.observe({"choices": [], "usage": {"completion_tokens": 1}}, False)
            trace.finish(True)
            self.timings.boundary("completedMs")
            run["outcome"] = "ok"
        status, value = self.request()
        self.assertEqual(status, 200)
        finish = next(row for row in value["journal"]["records"] if row["event"] == "finish")
        self.assertTrue(finish["record"]["tokens"]["complete"])
        self.assertNotIn("private", json.dumps(value))
        self.model.RunnerTimings.validate_tokens(finish["record"])
        self.assertEqual(self.journal.status, "recording")
        reopened = self.module().RUNNER_TIMINGS.journal_snapshot()["journal"]
        recovered = next(row for row in reopened["records"] if row["event"] == "finish")
        self.assertEqual(recovered, finish)



    def test_correlated_demand_load_survives_durable_journal_reopen(self):
        with self.timings.run("request") as request:
            self.timings.boundary("acceptedMs")
            with self.timings.run("load") as load:
                self.timings.load_started(load)
                self.timings.load_finished(load, True)
                load["outcome"] = "ok"
            self.timings.capture_demand_load()
            self.timings.boundary("admittedMs")
            self.timings.boundary("completedMs")
            request["outcome"] = "ok"
        status, value = self.request()
        self.assertEqual(status, 200)
        rows = [row for row in value["journal"]["records"] if row["event"] == "finish"]
        self.assertEqual(len(rows), 2)
        record = rows[-1]["record"]
        self.assertEqual(record["demandLoad"]["loadAttemptId"], rows[0]["attemptId"])
        self.model.RunnerTimings.validate_demand_load(record)
        reopened = self.module().RUNNER_TIMINGS.journal_snapshot()["journal"]
        self.assertEqual([row for row in reopened["records"] if row["event"] == "finish"], rows)



    def test_live_enrollment_is_owner_only_idle_and_idempotent(self):
        self.assertTrue(self.timings.abandon_journal(self.session))
        next_id="b"*32
        for authorized,admin in ((False,True),(True,False)):
            status,_=self.request("",{"action":"start","sessionId":next_id},authorized,admin)
            self.assertIn(status,(401,403));self.assertIsNone(self.timings.journal)
        with self.timings.run("request"):
            self.assertFalse(self.timings.start_journal(next_id))
        status,value=self.request("",{"action":"start","sessionId":next_id})
        self.assertEqual(status,200);self.assertEqual(value["journal"]["status"],"recording")
        self.assertEqual(self.timings.started,0)
        instance=self.timings.instance_id
        self.assertTrue(self.timings.start_journal(next_id));self.assertEqual(self.timings.instance_id,instance)
        self.assertFalse(self.timings.start_journal("c"*32))
        self.complete()
        records=self.timings.journal_snapshot()["journal"]["records"]
        self.assertEqual(records[1]["attemptId"],1)

    def test_seal_release_and_next_window_keep_separate_namespaces(self):
        self.complete()
        status,_=self.request("",{"action":"release","sessionId":self.session})
        self.assertEqual(status,409)
        status,_=self.request("",{"action":"seal","sessionId":self.session})
        self.assertEqual(status,200)
        old_path=Path(self.journal.path);old_instance=self.timings.instance_id
        self.assertFalse(self.timings.release_journal("b"*32))
        status,value=self.request("",{"action":"release","sessionId":self.session})
        self.assertEqual(status,200);self.assertEqual(value["journal"]["status"],"disabled")
        self.assertFalse(old_path.exists());self.assertTrue(self.timings.release_journal(self.session))
        self.assertTrue(self.timings.start_journal("b"*32))
        self.assertNotEqual(self.timings.instance_id,old_instance)
        self.assertEqual(self.timings.completed,0)
        self.assertEqual(self.timings.snapshot()["recent"],[])

    def test_abandon_preserves_unsealed_file_and_does_not_reuse_its_id(self):
        self.complete();path=Path(self.journal.path);before=path.read_bytes()
        with self.timings.run("request"):
            self.assertFalse(self.timings.abandon_journal(self.session))
        self.assertTrue(self.timings.abandon_journal(self.session))
        data=path.read_bytes();self.assertTrue(data.startswith(before))
        self.assertNotIn(b'"event":"seal"',data)
        self.assertFalse(self.timings.start_journal(self.session))
        self.assertIsNone(self.timings.journal)
        self.assertTrue(self.timings.start_journal("b"*32))

    def test_start_storage_failure_never_resets_existing_counters(self):
        self.complete();self.assertTrue(self.timings.abandon_journal(self.session))
        started=self.timings.started;instance=self.timings.instance_id
        with patch.object(self.model.os,"fsync",side_effect=OSError("fixture")):
            self.assertFalse(self.timings.start_journal("b"*32))
        self.assertEqual(self.timings.started,started);self.assertEqual(self.timings.instance_id,instance)
        self.assertIsNone(self.timings.journal)


if __name__ == "__main__":
    unittest.main()
