"""HTTP/database and adapter boundary checks. Never rents a real provider resource."""
import hashlib
import json
from pathlib import Path
import secrets
import sys
import threading
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_service import Flow, UPSTREAM_KEY
from compute import Compute
from compute_adapter import Adapter, ComputeError


class ComputeFlow(Flow):
    def agent(self, token, action, **data):
        return self.call("/api/compute/agent", {"action": action, **data}, headers={"Authorization": "Bearer " + token})

    def pair_node(self):
        token = secrets.token_urlsafe(32)
        status, pair, _ = self.call("/api/compute/pair/start", {"credential_hash": hashlib.sha256(token.encode()).hexdigest(), "name": "Contributor", "role": "contributor"})
        self.assertEqual(status, 200, pair)
        return token, pair

    def controller(self):
        token = self.service.compute.local_host("Website server")
        self.assertEqual(self.agent(token, "inventory", models=[], platform="test")[0], 200)
        return token

    def job(self, kind, **data):
        return self.call("/api/admin/compute/jobs", {"host": "website-host", "kind": kind, "request_id": secrets.token_hex(16), **data}, self.admin)

    def offers(self, token):
        status, created, _ = self.job("offers")
        self.assertEqual(status, 202)
        host = self.service.compute.host(token)
        claimed = self.service.compute.poll(host)["job"]
        self.assertEqual(claimed["id"], created["id"])
        self.service.compute.result(host, {"id": created["id"], "state": "done", "result": {"offers": [{"id": "secure:GPU", "gpu": "GPU", "name": "GPU", "hourly_usd": 1.25, "cloud": "secure", "vram_gb": 80}]}})
        return created["id"]

    def test_compute_member_cannot_manage_or_enroll_controller(self):
        member = self.member()
        for path, data in [("/api/admin/compute/jobs", {}), ("/api/admin/compute/password", {"password": ""}), ("/api/admin/compute/disconnect", {"id": "website-host"})]:
            self.assertEqual(self.call(path, data, member)[0], 403)
        self.assertEqual(self.call("/api/admin/compute", session=member)[0], 403)
        self.assertEqual(self.call("/api/compute/pair/start", {"name": "Attacker", "role": "controller", "credential_hash": "a" * 64})[0], 400)
        token, pair = self.pair_node()
        self.assertEqual(self.call("/api/compute/pair/approve", {"code": pair["code"]}, member)[0], 400)
        self.assertEqual(self.agent(token, "poll")[0], 401)
        self.assertEqual(self.call("/api/compute/pair/approve", {"code": pair["code"]}, self.admin)[0], 200)
        self.assertEqual(self.call("/api/compute/pair/approve", {"code": pair["code"]}, self.admin)[0], 400)
        self.assertEqual(self.agent(token, "result", id="x", state="done")[0], 400)

    def test_password_allows_contribution_not_administration(self):
        member = self.member()
        token, pair = self.pair_node()
        password = "disposable-contributor-password"
        self.assertEqual(self.call("/api/admin/compute/password", {"password": password}, self.admin)[0], 200)
        self.assertEqual(self.call("/api/compute/pair/approve", {"code": pair["code"], "password": "wrong"}, member)[0], 400)
        self.assertEqual(self.call("/api/compute/pair/approve", {"code": pair["code"], "password": password}, member)[0], 200)
        host = self.service.compute.host(token)
        self.assertEqual(self.job("offers", host=host["id"])[0], 400)
        with self.service.store.db() as db:
            self.assertNotIn(password, db.execute("SELECT password FROM compute_policy").fetchone()[0])

    def test_contribution_streams_and_registers_without_urls_or_keys(self):
        token, pair = self.pair_node()
        self.call("/api/compute/pair/approve", {"code": pair["code"]}, self.admin)
        models = [{"id": "env-one", "name": "test/one", "state": "ready", "shared": True}]
        self.assertEqual(self.agent(token, "inventory", models=models)[0], 200)
        status, catalog, _ = self.call("/api/models")
        self.assertEqual(status, 200)
        model = catalog["models"][0]["id"]
        self.assertNotIn(UPSTREAM_KEY, json.dumps(catalog))
        self.assertNotIn("compute://", json.dumps(catalog))
        adapter = Adapter("unused", Path(self.temp.name) / "node")
        adapter.shared = {"env-one"}
        adapter.apis = {"env-one": {"apiUrl": self.model_url, "apiKey": UPSTREAM_KEY, "model": "test/one"}}
        stopped = threading.Event()
        errors = []

        def worker():
            while not stopped.is_set():
                status, data, _ = self.agent(token, "poll")
                if status != 200:
                    errors.append(status)
                    return
                if "inference" in data:
                    def send(part):
                        result = self.agent(token, "chunk", **part)
                        if result[0] != 200:
                            errors.append(result)
                    adapter.inference(data["inference"], send)
                stopped.wait(.01)

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        try:
            key = self.key()["key"]
            for streaming in (False, True):
                status, result, _ = self.call("/v1/chat/completions", self.completion(model, streaming), key=key)
                self.assertEqual(status, 200, result)
                self.assertIn("hello", str(result))
                if streaming:
                    self.assertIn("[DONE]", result)
        finally:
            stopped.set()
            thread.join(5)
        self.assertFalse(errors, errors)
        self.assertFalse(self.service.compute.requests)
        host = self.service.compute.host(token)
        self.assertEqual(self.call("/api/admin/compute/disconnect", {"id": host["id"]}, self.admin)[0], 200)
        self.assertEqual(self.agent(token, "inventory", models=models)[0], 401)
        self.assertEqual(self.call("/api/models")[1]["models"], [])

    def test_rental_is_quoted_confirmed_once_and_survives_ambiguous_result(self):
        token = self.controller()
        quote = self.offers(token)
        data = {"model": "Qwen/Qwen3-8B", "offer": "secure:GPU"}
        self.assertEqual(self.job("rent", **data)[0], 400)
        status, result, _ = self.job("rent", cost_acknowledged=True, **data)
        self.assertEqual(status, 202, result)
        repeated = self.job("rent", request_id=result["id"], cost_acknowledged=True, **data)
        self.assertEqual(repeated[1]["id"], result["id"])
        host = self.service.compute.host(token)
        task = self.service.compute.poll(host)["job"]
        self.assertEqual(task["payload"]["offer"]["hourly_usd"], 1.25)
        self.assertEqual(self.service.compute.poll(host), {})
        self.service.compute.result(host, {"id": result["id"], "state": "running", "result": {"environment": "env-rented"}, "detail": "GPU rented; starting model"})
        status, stop, _ = self.job("stop", rental=result["id"])
        self.assertEqual(status, 202)
        urgent = self.service.compute.poll(host, accept_job=False)["job"]
        self.assertEqual(urgent["id"], stop["id"])
        self.assertEqual(urgent["payload"]["environment"], "env-rented")
        recreated = Compute(self.service.store)
        self.assertEqual(recreated.poll(host), {})  # A restart cannot repeat a paid call.
        recreated.local_host("Website server")
        rental = next(j for j in recreated.snapshot()["jobs"] if j["id"] == result["id"])
        self.assertEqual(rental["state"], "attention")
        self.assertEqual(rental["result"]["environment"], "env-rented")
        with self.service.store.db() as db:
            db.execute("UPDATE compute_jobs SET updated=0 WHERE id=?", (quote,))
        self.assertEqual(self.job("rent", cost_acknowledged=True, **data)[0], 400)

    def test_provider_secret_is_not_persisted_and_api_fields_are_not_commands(self):
        token = self.controller()
        key = "disposable-runpod-secret"
        status, created, _ = self.job("provider", key=key)
        self.assertEqual(status, 202)
        self.assertNotIn(key, json.dumps(self.service.compute.snapshot()))
        with self.service.store.db() as db:
            self.assertNotIn(key, json.dumps([dict(row) for row in db.execute("SELECT * FROM compute_jobs")]))
        host = self.service.compute.host(token)
        self.assertEqual(self.service.compute.poll(host)["job"]["payload"]["key"], key)
        self.assertNotIn(created["id"], self.service.compute.sensitive)
        self.assertEqual(self.job("exec", command="anything")[0], 400)
        self.assertEqual(self.job("load", model="https://evil.invalid/api")[0], 400)

    def test_adapter_discovers_real_environment_shape_and_keeps_model_keys_private(self):
        adapter = Adapter("unused", Path(self.temp.name) / "adapter", controller=True)
        def call(method, **params):
            if method in ("get_platform_state", "refresh_host_metrics"):
                return {"environments": [{"id": "env-model", "kind": "container", "status": "running", "description": "Hugging Face · test/one"}]}
            return {"model": "test/one", "apiUrl": self.model_url, "apiKey": UPSTREAM_KEY}
        adapter.call = call
        inventory = adapter.inventory()
        self.assertEqual(inventory["models"][0]["id"], "env-model")
        self.assertNotIn(UPSTREAM_KEY, json.dumps(inventory))
        self.assertNotIn(self.model_url, json.dumps(inventory))
        self.assertFalse(inventory["models"][0]["shared"])
        def older_engine(method, **params):
            if method == "refresh_host_metrics":
                raise ComputeError("Metrics refresh unavailable")
            return call(method, **params)
        adapter.call = older_engine
        fallback = adapter.inventory()
        self.assertEqual(fallback["models"][0]["id"], "env-model")
        self.assertIsNone(fallback["telemetry"]["cpu_percent"])

    def test_adapter_reports_slots_and_enforced_json_output_from_the_model_servers_health(self):
        """A shared model's inventory carries what its server's health says of its launch, read
        once a minute: the requests it generates together and whether it enforces a JSON reply
        format; the website's catalog shows the model JSON-capable from that report alone."""
        adapter = Adapter("unused", Path(self.temp.name) / "facts", controller=True)
        def call(method, **params):
            if method in ("get_platform_state", "refresh_host_metrics"):
                return {"environments": [{"id": "env-model", "kind": "container", "status": "running", "description": "Hugging Face · test/one"}]}
            return {"model": "test/one", "apiUrl": self.model_url, "apiKey": UPSTREAM_KEY}
        adapter.call = call
        adapter.shared.add("env-model")
        self.model.health = {"requestQueue": {"slots": 4}, "capabilities": {"structuredOutput": {"supported": True, "detail": "fixture"}}}
        item = adapter.inventory()["models"][0]
        self.assertEqual((item["slots"], item["json"]), (4, True))
        # The health route is read once a minute, not per inventory.
        self.model.health = {}
        self.assertEqual(adapter.inventory()["models"][0]["json"], True)
        token, pair = self.pair_node()
        self.call("/api/compute/pair/approve", {"code": pair["code"]}, self.admin)
        self.assertEqual(self.agent(token, "inventory", models=[{"id": "env-one", "name": "test/one", "state": "ready", "shared": True, "slots": 4, "json": True}])[0], 200)
        catalog = {m["id"]: m for m in self.call("/api/models")[1]["models"]}
        self.assertEqual(catalog["test/one"]["features"], {"json": True})
        self.assertEqual(self.agent(token, "inventory", models=[{"id": "env-one", "name": "test/one", "state": "ready", "shared": True}])[0], 200)
        self.assertEqual({m["id"]: m["features"] for m in self.call("/api/models")[1]["models"]}["test/one"], {"json": None})

    def test_cloud_adapter_creates_once_then_connects_model_automatically(self):
        adapter = Adapter("unused", Path(self.temp.name) / "cloud", controller=True)
        calls, stages = [], []
        environment = {"id": "env-rented", "kind": "cloud", "name": "solver-" + "a" * 24, "status": "running"}
        def call(method, **params):
            calls.append((method, params))
            if method == "model_preflight":
                return {"supported": True, "runner": "yougori-vllm", "resources": {"gpuMemoryGbEstimated": 16}}
            if method == "get_platform_state":
                return {"environments": [environment] if any(m == "runpod_create_pod" for m, _ in calls) else []}
            if method in ("runpod_create_pod", "runpod_action"):
                return {"environments": [environment]}
            return {"id": environment["id"], "model": "test/one", "apiUrl": self.model_url, "apiKey": UPSTREAM_KEY}
        adapter.call = call
        job = {"id": "a" * 32, "kind": "rent", "payload": {"model": "Qwen/Qwen3-8B", "offer": {
            "gpu": "GPU", "cloud": "secure", "hourly_usd": 1.25, "vram_gb": 80}}}
        result = adapter.execute(job, lambda detail, value: stages.append((detail, value)))
        self.assertEqual(result["environment"], "env-rented")
        self.assertEqual(sum(method == "runpod_create_pod" for method, _ in calls), 1)
        request = next(params["request"] for method, params in calls if method == "runpod_create_pod")
        self.assertEqual(request["maxHourlyUsd"], 1.25)
        self.assertEqual(request["gpuId"], "GPU")
        self.assertIn("env-rented", adapter.shared)
        self.assertTrue(any(value.get("environment") == "env-rented" for _, value in stages))
        self.assertNotIn(UPSTREAM_KEY, json.dumps(result))

    def test_unsupported_cloud_model_is_refused_before_any_purchase(self):
        adapter = Adapter("unused", Path(self.temp.name) / "refusal", controller=True)
        calls = []
        def call(method, **params):
            calls.append(method)
            return {"supported": True, "runner": "yougori-llama-cpp"}
        adapter.call = call
        with self.assertRaises(ComputeError):
            adapter.execute({"id": "b" * 32, "kind": "rent", "payload": {"model": "org/model"}}, lambda *_: None)
        self.assertEqual(calls, ["model_preflight"])

    def test_revocation_interrupts_active_stream_and_other_node_cannot_reply(self):
        from concurrent.futures import ThreadPoolExecutor
        import base64
        token, pair = self.pair_node()
        self.call("/api/compute/pair/approve", {"code": pair["code"]}, self.admin)
        self.agent(token, "inventory", models=[{"id": "env-one", "name": "test/one", "state": "ready", "shared": True}])
        other, pair2 = self.pair_node()
        self.call("/api/compute/pair/approve", {"code": pair2["code"]}, self.admin)
        model = self.call("/api/models")[1]["models"][0]["id"]
        key = self.key()["key"]
        with ThreadPoolExecutor(1) as pool:
            future = pool.submit(self.call, "/v1/chat/completions", self.completion(model, True), None, key)
            task = None
            for _ in range(100):
                task = self.agent(token, "poll")[1].get("inference")
                if task:
                    break
                time.sleep(.01)
            self.assertIsNotNone(task)
            part = {"id": task["id"], "sequence": 0, "status": 200, "stream": True,
                    "data": base64.b64encode(b'data: {"choices":[{"delta":{"content":"hello"}}]}\n\n').decode()}
            self.assertEqual(self.agent(other, "chunk", **part)[0], 400)
            self.assertEqual(self.agent(token, "chunk", **part)[0], 200)
            host = self.service.compute.host(token)
            self.call("/api/admin/compute/disconnect", {"id": host["id"]}, self.admin)
            _, output, _ = future.result(timeout=2)
            self.assertIn("error", str(output))
        self.assertFalse(self.service.compute.requests)


if __name__ == "__main__":
    unittest.main()
