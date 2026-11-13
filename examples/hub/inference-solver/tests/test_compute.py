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
        # A contributing computer serves only the models the administrator lists for computers.
        self.assertEqual(self.call("/api/admin/compute/models", {"models": ["test/one"]}, self.admin)[0], 200)
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

    def test_computers_run_only_the_models_the_administrator_lists(self):
        token, pair = self.pair_node()
        self.call("/api/compute/pair/approve", {"code": pair["code"]}, self.admin)
        # The list: Hugging Face repositories, each once whatever its case, at most twenty.
        status, saved, _ = self.call("/api/admin/compute/models", {"models": ["Qwen/Qwen3-8B", "hf.co/test/one", "qwen/qwen3-8b"]}, self.admin)
        self.assertEqual((status, saved), (200, {"models": ["Qwen/Qwen3-8B", "test/one"]}))
        for bad in (["not a model"], "Qwen/Qwen3-8B", [f"owner/model-{n}" for n in range(21)]):
            self.assertEqual(self.call("/api/admin/compute/models", {"models": bad}, self.admin)[0], 400, bad)
        # A reference pasted from another tool is told what to change: drop the quantization
        # ending (Yougori picks the GGUF file), or add the owner.
        for pasted, words in ((["unsloth/gemma-4-26B-A4B-it-GGUF:UD-Q4_K_M"], "without the ending after ':'"),
                              (["gemma-4-26B-A4B-it-GGUF:UD-Q4_K_M"], "Type the owner too"), (["Qwen3-8B"], "Type the owner too")):
            status, answer, _ = self.call("/api/admin/compute/models", {"models": pasted}, self.admin)
            self.assertEqual(status, 400, pasted)
            self.assertIn(words, json.dumps(answer), pasted)
        self.assertEqual(self.call("/api/admin/compute/models", {"models": []}, self.member())[0], 403)
        # A connecting computer reads it before it is approved, with how many it may run.
        listed = self.call("/api/compute/models")[1]
        self.assertEqual((listed["models"], listed["most"]), (["Qwen/Qwen3-8B", "test/one"], 3))
        self.assertEqual(listed["needs"]["test/one"], {"gpu_gb": 4, "compute": 8.0, "summary": "Chat model · about 4 GB of GPU memory · Ampere (RTX 30, A100, A40) or newer"})
        # A contributor's model joins the catalog only while it is on the list; Admin says why not.
        models = [{"id": "env-one", "name": "test/one", "state": "ready", "shared": True},
                  {"id": "env-two", "name": "Other/Model", "state": "ready", "shared": True}]
        self.assertEqual(self.agent(token, "inventory", models=models)[0], 200)
        self.assertEqual([m["id"] for m in self.call("/api/models")[1]["models"]], ["test/one"])
        node = next(h for h in self.call("/api/admin/compute", session=self.admin)[1]["hosts"] if h["role"] == "contributor")
        self.assertEqual([m["offered"] for m in node["inventory"]["models"]], [True, False])
        self.assertEqual(self.call("/api/admin/compute", session=self.admin)[1]["offered"], ["Qwen/Qwen3-8B", "test/one"])
        # Taken off the list, it leaves the catalog at the computer's next inventory.
        self.assertEqual(self.call("/api/admin/compute/models", {"models": ["Qwen/Qwen3-8B"]}, self.admin)[0], 200)
        self.assertEqual(self.agent(token, "inventory", models=models)[0], 200)
        self.assertEqual(self.call("/api/models")[1]["models"], [])

    def test_a_model_is_checked_when_added_and_shows_which_computers_can_run_it(self):
        import model_check
        token, pair = self.pair_node()
        self.call("/api/compute/pair/approve", {"code": pair["code"]}, self.admin)
        asked = []

        def check(repo):
            asked.append(repo)
            if repo == "Yougori/Ling-mini-2.0-Megakernel":
                raise model_check.CheckError("Yougori/Ling-mini-2.0-Megakernel ships its own megakernel program, built for particular GPUs.")
            needs = {"qwen/qwen3-8b": 21, "big/model": 160}[repo.lower()]
            return {"model": "Qwen/Qwen3-8B" if repo.lower() == "qwen/qwen3-8b" else repo, "kind": "text", "weights_gb": needs / 1.3,
                    "gpu_gb": needs, "disk_gb": 60, "compute": 8.0, "computers": True, "rent": True, "summary": f"Chat model · about {needs} GB", "notes": []}

        self.service.compute.check_model = check
        # One Yougori cannot run is refused with the reason, and the list stays as it was.
        status, refused, _ = self.call("/api/admin/compute/models", {"models": ["Yougori/Ling-mini-2.0-Megakernel"]}, self.admin)
        self.assertEqual(status, 400)
        self.assertIn("ships its own megakernel program", refused["error"]["message"])
        self.assertEqual(self.call("/api/admin/compute", session=self.admin)[1]["offered"], ["test/one"])
        # Its own spelling is kept, and a model is checked once.
        self.assertEqual(self.call("/api/admin/compute/models", {"models": ["test/one", "qwen/qwen3-8b", "big/model"]}, self.admin)[1]["models"],
                         ["test/one", "Qwen/Qwen3-8B", "big/model"])
        self.call("/api/admin/compute/models", {"models": ["test/one", "Qwen/Qwen3-8B", "big/model"]}, self.admin)
        self.assertEqual(asked, ["Yougori/Ling-mini-2.0-Megakernel", "qwen/qwen3-8b", "big/model"])
        # A connected computer with a 24 GB RTX 4090 runs the 21 GB model, not the 160 GB one.
        telemetry = {"gpus": [{"name": "NVIDIA GeForce RTX 4090", "memory_total_mb": 24564, "memory_used_mb": 0, "utilization_percent": 0}]}
        self.assertEqual(self.agent(token, "inventory", models=[], telemetry=telemetry)[0], 200)
        needs = self.call("/api/admin/compute", session=self.admin)[1]["needs"]
        self.assertEqual((needs["Qwen/Qwen3-8B"]["fits"], needs["Qwen/Qwen3-8B"]["computers"]), (1, 1))
        self.assertEqual((needs["big/model"]["fits"], needs["big/model"]["summary"]), (0, "Chat model · about 160 GB"))

    def test_a_model_listed_before_checks_is_checked_in_the_background(self):
        import model_check
        from test_service import checked
        self.assertEqual(self.call("/api/admin/compute/models", {"models": ["test/one", "mega/model"]}, self.admin)[0], 200)
        with self.service.store.db() as db:
            db.execute("DELETE FROM compute_model_facts")  # As a list made before models were checked.

        def check(repo):
            if repo == "mega/model":
                raise model_check.CheckError("mega/model ships its own megakernel program, built for particular GPUs.")
            raise model_check.CheckError("Hugging Face did not answer. Retry in a moment.", transient=True)

        self.service.compute.check_model = check
        self.service.compute.check_listed()
        # One Yougori cannot run keeps the reason for Admin; one not checked yet is tried again.
        self.assertEqual(self.call("/api/admin/compute", session=self.admin)[1]["needs"],
                         {"mega/model": {"model": "mega/model", "problem": "mega/model ships its own megakernel program, built for particular GPUs.", "computers": 0}})
        self.assertEqual(self.call("/api/compute/models")[1]["needs"], {})
        self.service.compute.check_model = checked
        self.service.compute.check_listed()
        self.assertEqual(self.call("/api/compute/models")[1]["needs"]["test/one"]["gpu_gb"], 4)
        self.assertNotIn("mega/model", self.call("/api/compute/models")[1]["needs"])

    def test_a_reply_limit_the_model_cannot_take_is_trimmed_and_a_refusal_says_why(self):
        from compute_adapter import trim
        import base64
        agent_prompt = {"messages": [{"role": "system", "content": "x" * 40000}, {"role": "user", "content": "Hey"}], "max_tokens": 32000}
        # Coding agents ask for 32,000: Yougori's model server takes 4,096, a context leaves the rest.
        self.assertEqual(trim(agent_prompt, 32768, 4096)["max_tokens"], 4096)
        self.assertEqual(trim(agent_prompt, 32768, None)["max_tokens"], 32768 - len(json.dumps(agent_prompt["messages"])) // 3 - 64)
        self.assertEqual(trim({"messages": [], "max_completion_tokens": 100}, 8704, 4096), {"messages": [], "max_completion_tokens": 100})
        # A request that names no limit (Codex's Responses requests name none): a rented GPU's vLLM
        # (no cap) keeps none and gives a reply all its context leaves; a Yougori model server is
        # told the cap or the room when less, since one released up to 1.2.4 stops at 256 tokens.
        for context, cap in ((None, None), (32768, None)):
            self.assertEqual(trim({"messages": []}, context, cap), {"messages": []}, (context, cap))
        self.assertEqual(trim({"messages": []}, 8704, 4096), {"messages": [], "max_tokens": 4096})
        self.assertEqual(trim({"messages": []}, None, 2048), {"messages": [], "max_tokens": 2048})
        near = {"messages": [{"role": "user", "content": "x" * 20000}]}
        self.assertEqual(trim(near, 8704, 4096)["max_tokens"], 8704 - (len(json.dumps(near["messages"])) + len("[]")) // 3 - 64)
        # Also near the context's edge, where an added limit would take the request past the context.
        edge = {"messages": [{"role": "user", "content": "x" * 25000}]}
        self.assertEqual(trim(edge, 8192, 4096), edge)
        self.assertEqual(trim(edge, 8192, None), edge)
        # A named limit is trimmed to what the context leaves after the conversation.
        long_prompt = {"messages": [{"role": "user", "content": "x" * 20000}], "max_tokens": 32000}
        self.assertEqual(trim(long_prompt, 8704, 4096)["max_tokens"], 8704 - (len(json.dumps(long_prompt["messages"])) + len("[]")) // 3 - 64)
        self.assertLess(trim(long_prompt, 8704, 4096)["max_tokens"], 4096)
        # A contributing computer's model refuses with its reason; the caller reads that reason.
        token, pair = self.pair_node()
        self.call("/api/compute/pair/approve", {"code": pair["code"]}, self.admin)
        self.agent(token, "inventory", models=[{"id": "env-one", "name": "test/one", "state": "ready", "shared": True}])
        reason = {"error": {"code": "yougori_context_window", "message": "Conversation exceeds this model's 8704-token context window; shorten it or reduce max_tokens", "context": 8704}}
        stopped = threading.Event()

        def refuse():
            while not stopped.is_set():
                status, data, _ = self.agent(token, "poll")
                if status == 200 and "inference" in data:
                    self.agent(token, "chunk", id=data["inference"]["id"], sequence=0, status=400, done=True,
                               content_type="application/json", data=base64.b64encode(json.dumps(reason).encode()).decode())
                    return
                stopped.wait(.02)

        worker = threading.Thread(target=refuse, daemon=True)
        worker.start()
        try:
            status, answer, _ = self.call("/v1/chat/completions", self.completion("test/one"), key=self.key()["key"])
        finally:
            stopped.set()
            worker.join(5)
        self.assertEqual(status, 400)
        self.assertEqual(answer["error"]["message"], "Conversation exceeds this model's 8704-token context window; shorten it or reduce max_tokens")

    def test_a_relayed_request_without_a_reply_limit_reaches_the_model_without_one(self):
        """A rented GPU's agent (its context known, no cap) relays a request that names no reply
        limit as it is, so vLLM gives the reply what the context leaves; a contributor's connector
        names 4,096 (a released model server stops at 256 unless told). A named limit is trimmed,
        to the context on a rental and to 4,096 elsewhere."""
        adapter = Adapter("unused", Path(self.temp.name) / "relay")
        adapter.shared = {"model", "env-one"}
        adapter.apis = {"model": {"apiUrl": self.model_url, "apiKey": UPSTREAM_KEY, "model": "test/one", "context": 32768, "reply_limit": None},
                        "env-one": {"apiUrl": self.model_url, "apiKey": UPSTREAM_KEY, "model": "test/one", "context": 8704}}
        messages = [{"role": "user", "content": "hi"}]
        for environment, named, expected in (("model", None, None), ("env-one", None, 4096), ("model", 32000, 32000), ("env-one", 32000, 4096)):
            with self.subTest(environment=environment, named=named):
                sent = []
                payload = {"messages": messages, **({"max_tokens": named} if named else {})}
                adapter.inference({"id": "r1", "environment": environment, "payload": payload}, sent.append)
                self.assertEqual(sent[0]["status"], 200)
                self.assertEqual(self.model.calls[-1].get("max_tokens"), expected)

    def test_computers_join_without_a_code_when_the_administrator_lets_them(self):
        def start(token):
            return self.call("/api/compute/pair/start", {"credential_hash": hashlib.sha256(token.encode()).hexdigest(), "name": "Contributor", "role": "contributor"})

        self.assertEqual(self.call("/api/admin/compute", session=self.admin)[1]["open"], False)
        self.assertEqual(self.call("/api/admin/compute/admission", {"open": True}, self.member())[0], 403)
        self.assertEqual(self.call("/api/admin/compute/admission", {"open": "yes"}, self.admin)[0], 400)
        self.assertEqual(self.call("/api/admin/compute/admission", {"open": True}, self.admin)[1], {"open": True})
        # A computer joins at once: no code to approve.
        token = secrets.token_urlsafe(32)
        status, pair, _ = start(token)
        self.assertEqual((status, pair["connected"]), (200, True))
        self.assertEqual(self.agent(token, "inventory", models=[])[0], 200)
        self.assertEqual(self.call("/api/compute/pair/poll", {"device": pair["device"]})[1]["connected"], True)
        # Codes again: the next computer waits for its approval, and the first stays connected.
        self.assertEqual(self.call("/api/admin/compute/admission", {"open": False}, self.admin)[1], {"open": False})
        other = secrets.token_urlsafe(32)
        status, pair, _ = start(other)
        self.assertEqual(status, 200)
        self.assertNotIn("connected", pair)
        self.assertEqual(self.agent(other, "poll")[0], 401)
        self.assertEqual(self.agent(token, "inventory", models=[])[0], 200)

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

    def test_adapter_reports_the_context_its_model_server_serves(self):
        """A shared model's inventory carries the context its server's health says it serves
        (the website lists the smallest of a model's for harnesses); a context outside 256 to
        1,048,576 tokens, or none, is left out."""
        adapter = Adapter("unused", Path(self.temp.name) / "context", controller=True)
        def call(method, **params):
            if method in ("get_platform_state", "refresh_host_metrics"):
                return {"environments": [{"id": "env-model", "kind": "container", "status": "running", "description": "Hugging Face · test/one"}]}
            return {"model": "test/one", "apiUrl": self.model_url, "apiKey": UPSTREAM_KEY}
        adapter.call = call
        adapter.shared.add("env-model")
        for health, context in (({"status": "ready", "weightsVerified": True, "context": 32768}, 32768),
                                ({"status": "ready", "weightsVerified": True, "context": 100}, None),
                                ({"status": "ready", "weightsVerified": True, "context": "32768"}, None),
                                ({"status": "ready", "weightsVerified": True}, None)):
            with self.subTest(health=health):
                adapter.facts_read.clear()
                self.model.health = health
                self.assertEqual(adapter.inventory()["models"][0].get("context"), context)
        # A model the person did not share reports no facts at all.
        adapter.shared.clear()
        adapter.facts_read.clear()
        self.model.health = {"status": "ready", "weightsVerified": True, "context": 32768}
        self.assertNotIn("context", adapter.inventory()["models"][0])

    def test_adapter_lists_a_model_only_while_it_can_answer(self):
        """A shared model is listed ready only while its model server can answer, read from its
        health at every inventory: a download says how far it has got; a model loaded once stays
        ready while automatic GPU memory unloads it (a request wakes it); a server that says
        nothing of its state is ready (a rented GPU's raw vLLM); a model the person did not share
        is listed by its API alone, as before."""
        import compute_adapter
        import socket
        from unittest.mock import patch
        adapter = Adapter("unused", Path(self.temp.name) / "ready", controller=True)
        api = {"model": "test/one", "apiUrl": self.model_url, "apiKey": UPSTREAM_KEY}
        environments = [{"id": "env-model", "kind": "container", "status": "running", "description": "Hugging Face · test/one"},
                        {"id": "env-own", "kind": "container", "status": "running", "description": "Hugging Face · test/two"}]

        def call(method, **params):
            if method in ("get_platform_state", "refresh_host_metrics"):
                return {"environments": environments}
            return dict(api)
        adapter.call = call
        adapter.shared.add("env-model")

        def listed():
            return {item["id"]: item for item in adapter.inventory()["models"]}
        on, off = {"enabled": True}, {"enabled": False}
        for health, state in (
                ({"status": "downloading", "download": {"receivedBytes": 4e9, "totalBytes": 8e9, "bytesPerSecond": 5e6}}, "downloading"),
                ({"status": "installing"}, "loading"),
                ({"status": "queued", "optimizer": on}, "loading"),
                ({"status": "verifying"}, "loading"),
                ({"status": "loading"}, "loading"),
                ({"status": "ready", "weightsVerified": True}, "ready"),
                ({"status": "idle", "weightsVerified": True, "optimizer": on}, "ready"),
                ({"status": "queued", "weightsVerified": True, "optimizer": on}, "ready"),
                ({"status": "loading", "weightsVerified": True, "optimizer": on}, "ready"),
                ({"status": "unloading", "weightsVerified": True, "optimizer": on}, "ready"),
                ({"status": "idle", "weightsVerified": True, "optimizer": off}, "loading"),
                ({"status": "error", "error": "CUDA out of memory"}, "unavailable"),
                ({}, "ready")):
            with self.subTest(health=health):
                self.model.health = health
                models = listed()
                self.assertEqual(models["env-model"]["state"], state)
                self.assertEqual(models["env-own"]["state"], "ready")  # Not shared: its API alone, as before.
                self.assertEqual("progress" in models["env-model"], state == "downloading")
        self.model.health = {"status": "downloading", "download": {"receivedBytes": 4e9, "totalBytes": 8e9, "bytesPerSecond": 5e6}}
        self.assertEqual(listed()["env-model"]["progress"], {"received": 4000000000, "total": 8000000000, "rate": 5000000})
        # Ready on the very next inventory (its health is read every time, not once a minute), and
        # its launch facts, read while it loaded and kept for a minute, are read again.
        adapter.facts_read.clear()
        self.model.health = {"status": "downloading", "requestQueue": {"slots": 1}}
        self.assertEqual(listed()["env-model"].get("slots"), 1)
        self.model.health = {"status": "downloading", "requestQueue": {"slots": 2}}
        self.assertEqual(listed()["env-model"].get("slots"), 1)
        self.model.health = {"status": "ready", "weightsVerified": True, "requestQueue": {"slots": 4}, "capabilities": {"structuredOutput": {"supported": True}}}
        ready = listed()["env-model"]
        self.assertEqual((ready["state"], ready["slots"], ready["json"]), ("ready", 4, True))
        # A health that answers late (the model server is freeing GPU memory) keeps the last state a
        # while; one that never answers ends as starting.
        silent = socket.socket()
        silent.bind(("127.0.0.1", 0))
        silent.listen(4)
        self.addCleanup(silent.close)
        api["apiUrl"] = f"http://127.0.0.1:{silent.getsockname()[1]}/v1"
        with patch.object(compute_adapter, "HEALTH_SECONDS", .3):
            self.assertEqual(listed()["env-model"]["state"], "ready")
            with patch.object(compute_adapter, "KEEP_SECONDS", 0):
                self.assertEqual(listed()["env-model"]["state"], "starting")
        # Nothing listening there yet: starting.
        closed = socket.socket()
        closed.bind(("127.0.0.1", 0))
        port = closed.getsockname()[1]
        closed.close()
        api["apiUrl"] = f"http://127.0.0.1:{port}/v1"
        self.assertEqual(listed()["env-model"]["state"], "starting")
        # An environment Yougori is still creating, before it has an API: starting too.
        environments[0]["status"] = "provisioning"
        self.assertEqual(listed()["env-model"]["state"], "starting")
        environments[0]["status"] = "stopped"
        self.assertEqual(listed()["env-model"]["state"], "unavailable")

    def test_a_model_still_downloading_is_refused_at_once_with_its_progress(self):
        """A computer still downloading a model: the catalog says Starting with how far it has
        got, in the website's own words; /v1/models leaves it out; every protocol's request is
        refused at once, naming the download; once the computer says it is ready, it is served."""
        token, pair = self.pair_node()
        self.call("/api/compute/pair/approve", {"code": pair["code"]}, self.admin)
        downloading = {"id": "env-one", "name": "test/one", "state": "downloading", "shared": True,
                       "progress": {"received": 3400000000, "total": 8000000000, "rate": 5000000}}
        self.assertEqual(self.agent(token, "inventory", models=[downloading])[0], 200)
        model = self.call("/api/models")[1]["models"][0]
        self.assertEqual((model["state"], model["detail"]), ("loading", "downloading (42% of 8.0 GB, about 15 minutes left)"))
        node = next(h for h in self.call("/api/admin/compute", session=self.admin)[1]["hosts"] if h["role"] == "contributor")
        self.assertEqual(node["inventory"]["models"][0]["detail"], "downloading (42% of 8.0 GB, about 15 minutes left)")
        key = self.key()["key"]
        self.assertEqual(self.call("/v1/models", key=key)[1]["data"], [])
        for path, body in (("/v1/chat/completions", self.completion("test/one")),
                           ("/v1/responses", {"model": "test/one", "input": "hi"}),
                           ("/v1/messages", {"model": "test/one", "max_tokens": 16, "messages": [{"role": "user", "content": "hi"}]})):
            with self.subTest(path=path):
                started = time.monotonic()
                status, answer, headers = self.call(path, body, key=key)
                self.assertLess(time.monotonic() - started, 2)
                self.assertEqual(status, 503, answer)
                self.assertEqual(answer["error"]["message"], "test/one is still downloading (42% of 8.0 GB, about 15 minutes left) on the computer that serves it. "
                                                             "It answers once it has loaded; try again then.")
                self.assertNotIn("Retry-After", headers)
        self.assertFalse(self.service.compute.requests)  # Nothing was sent to the computer.
        # Progress that is not whole numbers within bounds is never shown; the words are the website's.
        for bad in ({"received": 9, "total": 8, "rate": 1}, {"received": -1, "total": 8, "rate": 1}, {"received": 1.5, "total": 8, "rate": 1},
                    {"received": 1, "total": 10 ** 14, "rate": 1}, {"received": True, "total": 8, "rate": 1}, "42% <b>done</b>"):
            self.agent(token, "inventory", models=[{**downloading, "progress": bad}])
            self.assertEqual(self.call("/api/models")[1]["models"][0]["detail"], "downloading", bad)
        for state, detail in (("loading", "loading onto the GPU"), ("starting", "starting its model server")):
            self.agent(token, "inventory", models=[{**downloading, "state": state}])
            self.assertEqual(self.call("/api/models")[1]["models"][0]["detail"], detail)
            status, answer, _ = self.call("/v1/chat/completions", self.completion("test/one"), key=key)
            self.assertEqual((status, answer["error"]["message"].split(" on the computer")[0]), (503, "test/one is still " + detail))
        # A connector that says only ready or unavailable (CLI 1.2.4) is listed as before.
        self.agent(token, "inventory", models=[{**downloading, "state": "unavailable"}])
        self.assertEqual(self.call("/api/models")[1]["models"][0]["state"], "unavailable")
        self.assertNotIn("detail", self.call("/api/models")[1]["models"][0])
        self.assertEqual(self.call("/v1/chat/completions", self.completion("test/one"), key=key)[1]["error"]["message"], "The model server is not currently available.")
        # Ready: served as before.
        self.assertEqual(self.agent(token, "inventory", models=[{"id": "env-one", "name": "test/one", "state": "ready", "shared": True}])[0], 200)
        self.assertNotIn("detail", self.call("/api/models")[1]["models"][0])
        adapter = Adapter("unused", Path(self.temp.name) / "node")
        adapter.shared = {"env-one"}
        adapter.apis = {"env-one": {"apiUrl": self.model_url, "apiKey": UPSTREAM_KEY, "model": "test/one"}}
        stopped = threading.Event()

        def worker():
            while not stopped.is_set():
                status, data, _ = self.agent(token, "poll")
                if status == 200 and "inference" in data:
                    adapter.inference(data["inference"], lambda part: self.agent(token, "chunk", **part))
                stopped.wait(.01)

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        try:
            status, answer, _ = self.call("/v1/chat/completions", self.completion("test/one"), key=key)
        finally:
            stopped.set()
            thread.join(5)
        self.assertEqual(status, 200, answer)
        self.assertIn("hello", json.dumps(answer))

    def test_the_connector_refuses_a_request_for_a_model_still_downloading(self):
        """A request for a model its computer is still downloading is refused by the connector at
        once with the download's progress (503, code model_downloading), not held until the website's
        time limit; the website passes such a refusal on with its words, and any other 503 from a
        computer stays its failure (502)."""
        import base64
        adapter = Adapter("unused", Path(self.temp.name) / "refuse")
        adapter.shared = {"env-one"}
        adapter.apis = {"env-one": {"apiUrl": self.model_url, "apiKey": UPSTREAM_KEY, "model": "test/one"}}
        adapter.readiness["env-one"] = ("downloading", None)  # As the last inventory found it.
        self.model.health = {"status": "downloading", "download": {"receivedBytes": 3400000000, "totalBytes": 8000000000, "bytesPerSecond": 5000000}}
        task = {"id": "r1", "environment": "env-one", "payload": {"messages": [{"role": "user", "content": "hi"}]}}
        sent, relayed = [], len(self.model.calls)
        started = time.monotonic()
        adapter.inference(task, sent.append)
        self.assertLess(time.monotonic() - started, 2)
        self.assertEqual(len(self.model.calls), relayed)  # Never sent to the model server.
        [chunk] = sent
        self.assertEqual((chunk["status"], chunk["done"], chunk["content_type"]), (503, True, "application/json"))
        refusal = json.loads(base64.b64decode(chunk["data"]))["error"]
        self.assertEqual(refusal, {"code": "model_downloading", "message": "test/one is still downloading on this computer: 42% of 8.0 GB, about 15 minutes left. It answers once it has loaded."})
        # Its health is read again first: a model that has loaded since the last inventory answers.
        self.model.health = {"status": "ready", "weightsVerified": True}
        sent.clear()
        adapter.inference(task, sent.append)
        self.assertEqual(sent[0]["status"], 200)
        self.assertEqual(adapter.readiness["env-one"], ("ready", None))
        # A rented GPU's agent never reads inventory: without a state, a model is relayed.
        adapter.readiness.clear()
        self.model.health = {"status": "error"}
        sent.clear()
        adapter.inference(task, sent.append)
        self.assertEqual(sent[0]["status"], 200)
        # Through the website: the refusal reaches the caller at once with its words; a computer's
        # other 503 is still its failure.
        token, pair = self.pair_node()
        self.call("/api/compute/pair/approve", {"code": pair["code"]}, self.admin)
        self.agent(token, "inventory", models=[{"id": "env-one", "name": "test/one", "state": "ready", "shared": True}])
        key = self.key()["key"]
        loading = {"error": {"code": "model_loading", "message": "test/one is loading onto the GPU on this computer. It answers once it has loaded."}}
        for body, expected in ((loading, (503, loading["error"]["message"])),
                               ({"error": {"message": "Model preparation timed out"}}, (502, "The contributing computer could not serve this request.")),
                               ({"error": {"code": "model_loading"}}, (503, "The model is still loading onto the contributing computer's GPU."))):
            stopped = threading.Event()

            def refuse():
                while not stopped.is_set():
                    status, data, _ = self.agent(token, "poll")
                    if status == 200 and "inference" in data:
                        self.agent(token, "chunk", id=data["inference"]["id"], sequence=0, status=503, done=True,
                                   content_type="application/json", data=base64.b64encode(json.dumps(body).encode()).decode())
                        return
                    stopped.wait(.02)

            worker = threading.Thread(target=refuse, daemon=True)
            worker.start()
            try:
                status, answer, _ = self.call("/v1/chat/completions", self.completion("test/one"), key=key)
            finally:
                stopped.set()
                worker.join(5)
            self.assertEqual((status, answer["error"]["message"]), expected)

    def test_models_shared_with_the_website_take_the_limits_coding_agents_need(self):
        """A model the website server shares or loads takes the limits coding agents need: a
        running one is restarted with them, a stopped one takes them as it starts, a new one is
        installed with them (on vLLM where vLLM serves it natively). An older Yougori, a media model
        and a rented GPU are shared as before."""
        adapter = Adapter("unused", Path(self.temp.name) / "limits", controller=True)
        status = {"env-run": "running", "env-stopped": "stopped", "env-cloud": "running", "env-new": "running"}
        calls, older = [], []

        def call(method, **params):
            calls.append((method, params))
            if method == "get_platform_state":
                return {"environments": [{"id": name, "kind": "cloud" if name == "env-cloud" else "container", "status": state,
                                          "description": "Hugging Face · test/one"} for name, state in status.items()]}
            if method == "model_agent_api":
                if older:
                    raise ComputeError("Yougori could not complete model agent api.")
                # As the engine answers: restartRequired only while limits saved after the container
                # was configured have not reached it. env-new was installed with them; env-failed had
                # them saved by an earlier connect whose restart failed.
                new, failed = params["environmentId"] == "env-new", params["environmentId"] == "env-failed"
                return {"agentApi": True, "changed": not (new or failed), "restartRequired": not new and status[params["environmentId"]] == "running"}
            if method == "model_preflight":
                return {"supported": True, "runner": "yougori-transformers", "vllmNative": {"architecture": "Qwen3ForCausalLM"}}
            if method == "run_model":
                return {"id": "env-new", "model": params["model"]}
            if method in ("model_api_status", "model_api"):
                return {"model": "test/one", "apiUrl": self.model_url, "apiKey": UPSTREAM_KEY}
            return {}
        adapter.call = call

        def asked():
            names = [method for method, _ in calls if method != "get_platform_state"]
            calls.clear()
            return names
        adapter.share("env-run")
        self.assertEqual(asked(), ["model_agent_api", "stop_model", "start_model", "model_api_status"])
        adapter.share("env-stopped")
        self.assertEqual(asked(), ["model_agent_api", "start_model", "model_api_status"])
        adapter.share("env-cloud")
        self.assertEqual(asked(), ["model_api_status"])
        # A model the CLI has just installed with the limits and found ready is shared as it runs.
        adapter.share("env-new")
        self.assertEqual(asked(), ["model_agent_api", "model_api_status"])
        # Saved earlier but never applied (that restart failed): restarted now.
        status["env-failed"] = "running"
        adapter.share("env-failed")
        self.assertEqual(asked(), ["model_agent_api", "stop_model", "start_model", "model_api_status"])
        older.append(True)
        adapter.share("env-run")
        self.assertEqual(asked(), ["model_agent_api", "model_api_status"])
        older.clear()
        adapter.execute({"id": "c" * 32, "kind": "load", "payload": {"model": "test/one"}}, lambda *_: None)
        run = next(params for method, params in calls if method == "run_model")
        self.assertEqual((run["model"], run["resources"], run["runner"]), ("test/one", {"agentApi": True}, "vllm"))
        self.assertNotIn("stop_model", asked())  # Installed with them: nothing to restart.
        # A model vLLM does not serve natively keeps the engine's own runner.
        adapter.call = lambda method, **params: (calls.append((method, params)) or
                                                 ({"supported": True, "runner": "yougori-llama-cpp"} if method == "model_preflight" else call(method, **params)))
        adapter.execute({"id": "d" * 32, "kind": "load", "payload": {"model": "test/one"}}, lambda *_: None)
        run = next(params for method, params in calls if method == "run_model")
        self.assertEqual(run["resources"], {"agentApi": True})
        self.assertNotIn("runner", run)

    def test_a_model_restarted_for_the_limits_is_not_left_stopped(self):
        """A start that fails right after the restart stopped a running model is tried once more;
        a stopped model whose start fails is reported as before, with no second try."""
        import compute_adapter
        from unittest.mock import patch
        adapter = Adapter("unused", Path(self.temp.name) / "restart", controller=True)
        status = {"env-run": "running", "env-stopped": "stopped"}
        calls, refusals = [], []

        def call(method, **params):
            calls.append(method)
            if method == "get_platform_state":
                return {"environments": [{"id": name, "kind": "container", "status": state} for name, state in status.items()]}
            if method == "model_agent_api":
                return {"agentApi": True, "changed": True, "restartRequired": status[params["environmentId"]] == "running"}
            if method == "start_model" and refusals:
                refusals.pop()
                raise ComputeError("Yougori could not complete start model.")
            if method == "model_api_status":
                return {"model": "test/one", "apiUrl": self.model_url, "apiKey": UPSTREAM_KEY}
            return {}
        adapter.call = call
        with patch.object(compute_adapter, "RESTART_RETRY_SECONDS", 0):
            refusals.append(True)
            adapter.share("env-run")
            self.assertEqual([m for m in calls if m != "get_platform_state"], ["model_agent_api", "stop_model", "start_model", "start_model", "model_api_status"])
            calls.clear()
            refusals.append(True)
            with self.assertRaises(ComputeError):
                adapter.share("env-stopped")
            self.assertEqual([m for m in calls if m != "get_platform_state"], ["model_agent_api", "start_model"])

    def test_the_website_servers_load_falls_back_from_vllm_when_vllm_refuses_the_model(self):
        """vLLM takes a model only when all of it fits the GPU and refuses one that does not before
        it makes anything: the website server's load then asks once more without vLLM, so the
        engine's own runner can fit it. A refusal that made an environment is not asked again."""
        adapter = Adapter("unused", Path(self.temp.name) / "load", controller=True)
        environments, calls = [], []

        def call(method, **params):
            calls.append((method, params))
            if method == "get_platform_state":
                return {"environments": list(environments)}
            if method == "model_preflight":
                return {"supported": True, "runner": "yougori-transformers-chat", "vllmNative": {"runner": "yougori-vllm"}}
            if method == "run_model" and params.get("runner") == "vllm":
                if made:
                    environments.append({"id": "env-half", "kind": "container", "status": "error"})
                raise ComputeError("Yougori could not complete run model.")
            if method == "run_model":
                environments.append({"id": "env-new", "kind": "container", "status": "running"})
                return {"id": "env-new", "model": params["model"]}
            if method == "model_agent_api":
                return {"agentApi": True, "changed": False, "restartRequired": False}
            if method == "model_api_status":
                return {"model": "Qwen/Qwen3-8B", "apiUrl": self.model_url, "apiKey": UPSTREAM_KEY}
            return {}
        adapter.call = call

        def runs():
            return [params.get("runner") for method, params in calls if method == "run_model"]
        made = False
        self.assertEqual(adapter.execute({"id": "e" * 32, "kind": "load", "payload": {"model": "Qwen/Qwen3-8B"}}, lambda *_: None), {"environment": "env-new"})
        self.assertEqual(runs(), ["vllm", None])
        self.assertTrue(all(params["resources"] == {"agentApi": True} for method, params in calls if method == "run_model"))
        self.assertIn("env-new", adapter.shared)
        environments.clear()
        calls.clear()
        made = True
        with self.assertRaises(ComputeError):
            adapter.execute({"id": "f" * 32, "kind": "load", "payload": {"model": "Qwen/Qwen3-8B"}}, lambda *_: None)
        self.assertEqual(runs(), ["vllm"])

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
