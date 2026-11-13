"""Renting GPUs from neoclouds with the administrator's own keys, against a fake RunPod, Vast.ai
and Hugging Face: keys, offers, the checks before anything is rented, the rental (made once),
the GPU's agent download, its reports and its requests, failure and stopping. Nothing real is
rented.

Run: python -I -B examples/hub/inference-solver/tests/test_rentals.py
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
from pathlib import Path
import sys
import threading
import time
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_service import Flow, UPSTREAM_KEY
from compute import ComputeInput
from compute_adapter import Adapter
from compute_node import Link
import model_check
import neocloud
import rental_agent

RUNPOD_KEY, VAST_KEY = "runpod-key-123456", "vast-key-123456"
ORIGIN = "https://example.yougori.com"


def weights(size, name="test/one", gated=False, architectures=("Qwen3ForCausalLM",), model_type="qwen3", files=None, tags=(),
            task="text-generation", config=None, kind="BF16"):
    """A model as Hugging Face's API describes it (with ?blobs=true: each file's size)."""
    return {"id": name, "gated": gated, "pipeline_tag": task, "tags": list(tags),
            "config": {"architectures": list(architectures), "model_type": model_type, **(config or {})},
            "safetensors": {"parameters": {kind: size // 2}},
            "siblings": [{"rfilename": file, "size": count} for file, count in (files or {"model.safetensors": size}).items()]}


MODELS = {
    "test/one": weights(16_000_000_000),
    "small/model": weights(2_000_000_000, name="small/model"),
    "big/model": weights(140_000_000_000, name="big/model"),
    "gated/model": weights(16_000_000_000, name="gated/model", gated="manual"),
    "odd/model": weights(16_000_000_000, name="odd/model", architectures=["SomethingNew"], model_type="something_new"),
    "fp8/model": weights(8_000_000_000, name="fp8/model", config={"quantization_config": {"quant_method": "fp8"}}, kind="F8_E4M3"),
    "gguf/model": weights(0, name="gguf/model", files={"model-Q8_0.gguf": 9_000_000_000, "model-Q4_K_M.gguf": 5_000_000_000}),
    "media/model": weights(0, name="media/model", task="text-to-image", files={
        "single.safetensors": 13_000_000_000, "unet/diffusion_pytorch_model.safetensors": 10_000_000_000,
        "unet/diffusion_pytorch_model.fp16.safetensors": 5_000_000_000, "vae/diffusion_pytorch_model.safetensors": 300_000_000}),
    "mega/model": weights(0, name="mega/model", tags=["megakernel", "base_model:test/one"],
                          files={"kernel.cu": 1000, "packed/layers.safetensors": 4_000_000_000}),
    "runner/repo": weights(0, name="runner/repo", files={"runner.json": 500, "runner.py": 4000}),
    "code/model": weights(16_000_000_000, name="code/model", config={"auto_map": {"AutoModelForCausalLM": "modeling.Model"}}),
}


class Providers(BaseHTTPRequestHandler):
    """RunPod's GraphQL and REST API, Vast.ai's API and Hugging Face's model API, as far as
    rentals use them."""

    def log_message(self, *_):
        pass

    def reply(self, status, value):
        raw = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def note(self, body=None):
        self.server.state["calls"].append((self.command, self.path, body, self.headers.get("Authorization", "").removeprefix("Bearer ")))

    def body(self):
        length = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(length) or b"{}")

    def do_GET(self):
        state, key = self.server.state, self.headers.get("Authorization", "").removeprefix("Bearer ")
        self.note()
        if self.path.startswith("/api/models/"):
            repo = self.path.removeprefix("/api/models/").split("?")[0]
            if repo == "old/name":  # A renamed model: Hugging Face redirects to its new name.
                self.send_response(307)
                self.send_header("Location", "/api/models/test/one?blobs=true")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            model = state["models"].get(repo)
            return self.reply(200, model) if model else self.reply(404, {"error": "Repository not found"})
        if self.path == "/api/v0/users/current/":
            return self.reply(200, {"id": 7, "credit": 10.5}) if key == VAST_KEY else self.reply(401, {"error": "invalid key"})
        if self.path == "/v1/pods/pod-1":
            return self.reply(200, {"id": "pod-1", "desiredStatus": state["pod"]}) if state["pod"] else self.reply(404, {})
        if self.path == "/api/v0/instances/555/":
            return self.reply(200, {"instances": {"actual_status": "running", "intended_status": "running"}})
        self.reply(404, {})

    def do_POST(self):
        state, body = self.server.state, self.body()
        self.note(body)
        key = self.headers.get("Authorization", "").removeprefix("Bearer ")
        if self.path == "/graphql":
            # The GPU inventory is public; the account needs the key.
            if "myself" in body["query"]:
                if key != RUNPOD_KEY:
                    return self.reply(401, {"errors": [{"message": "Unauthorized"}]})
                return self.reply(200, {"data": {"myself": {"id": "user-1", "clientBalance": 25.5, "currentSpendPerHr": 0}}})
            return self.reply(200, {"data": {"gpuTypes": [
                {"id": "NVIDIA GeForce RTX 4090", "displayName": "RTX 4090", "memoryInGb": 24, "secureCloud": True, "communityCloud": True,
                 "secure": {"stockStatus": "High", "uninterruptablePrice": 0.69, "availableGpuCounts": [1, 2]},
                 "community": {"stockStatus": "Low", "uninterruptablePrice": 0.34, "availableGpuCounts": [1]}},
                {"id": "NVIDIA A100 80GB PCIe", "displayName": "A100 PCIe", "memoryInGb": 80, "secureCloud": True, "communityCloud": False,
                 "secure": {"stockStatus": "None", "uninterruptablePrice": 1.64, "availableGpuCounts": [1]}, "community": None},
                {"id": "Tesla T4", "displayName": "Tesla T4", "memoryInGb": 16, "secureCloud": True, "communityCloud": False,
                 "secure": {"stockStatus": "High", "uninterruptablePrice": 0.40, "availableGpuCounts": [1]}, "community": None},
                {"id": "AMD Instinct MI300X OAM", "displayName": "MI300X", "memoryInGb": 192, "secureCloud": True, "communityCloud": False,
                 "secure": {"stockStatus": "High", "uninterruptablePrice": 2.49, "availableGpuCounts": [1]}, "community": None}]}})
        if self.path == "/v1/pods":
            if state["create"] == "refuse":
                return self.reply(400, {"error": "There are no longer any instances available with the requested specifications."})
            if state["create"] == "unclear":
                return self.reply(502, {})
            state["pod"] = "RUNNING"
            return self.reply(201, {"id": "pod-1", "costPerHr": 0.35, "desiredStatus": "RUNNING"})
        if self.path == "/api/v0/bundles/":
            return self.reply(200, {"offers": [{"id": 123, "gpu_name": "RTX 3090", "num_gpus": 1, "gpu_ram": 24576, "dph_total": 0.25,
                                                "geolocation": "Norway, NO", "compute_cap": 860}]})
        self.reply(404, {})

    def do_PUT(self):
        body = self.body()
        self.note(body)
        if self.path == "/api/v0/asks/123/":
            return self.reply(200, {"success": True, "new_contract": 555})
        self.reply(404, {})

    def do_DELETE(self):
        self.note()
        if self.path == "/v1/pods/pod-1":
            self.server.state["pod"] = None
        self.reply(200, {"success": True})


class Ready:
    """A model runtime that is serving, as rental_agent.Model reports one."""
    state, detail = "ready", "Serving test/one."

    def check(self):
        pass

    def report(self):
        return {"action": "inventory", "platform": "Linux", "capacity": 8, "media": False, "detail": self.detail, "failed": False,
                "models": [{"id": "model", "name": "test/one", "state": "ready", "shared": True, "slots": 16}]}


class RentalFlow(Flow):
    def setUp(self):
        super().setUp()
        self.providers = ThreadingHTTPServer(("127.0.0.1", 0), Providers)
        self.providers.state = {"calls": [], "pod": None, "create": "ok", "models": MODELS}
        thread = threading.Thread(target=self.providers.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(lambda: (self.providers.shutdown(), self.providers.server_close(), thread.join()))
        base = f"http://127.0.0.1:{self.providers.server_port}"
        for module, name, value in ((neocloud, "RUNPOD_GRAPHQL", base + "/graphql"), (neocloud, "RUNPOD_REST", base + "/v1"),
                                    (neocloud, "VAST", base + "/api/v0"), (model_check, "HUGGING_FACE", base)):
            patcher = patch.object(module, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def calls(self, method=None, path=None):
        return [call for call in self.providers.state["calls"] if (method is None or call[0] == method) and (path is None or call[1] == path)]

    def keys(self):
        for provider, key in (("runpod", RUNPOD_KEY), ("vast", VAST_KEY)):
            status, view, _ = self.call("/api/admin/rentals/account", {"provider": provider, "key": key}, self.admin)
            self.assertEqual(status, 200, view)

    def quote(self, disk_gb=80):
        status, quote, _ = self.call("/api/admin/rentals/offers", {"gpu_count": 1, "disk_gb": disk_gb}, self.admin)
        self.assertEqual(status, 200, quote)
        return quote

    def rent(self, quote, offer="runpod:community:NVIDIA GeForce RTX 4090", model="test/one", identity="a1b2c3d4e5f6a7b8", **extra):
        data = {"request_id": identity, "quote_id": quote["id"], "offer": offer, "model": model, "cost_acknowledged": True, **extra}
        with self.service.store.db() as db:
            actor = db.execute("SELECT id FROM users WHERE admin=1").fetchone()[0]
        # Called directly: renting needs the website's public https address, which tests lack.
        return self.service.rentals.rent(actor, data, ORIGIN)

    def download(self, token):
        """The agent's download as the GPU makes it: (status, bytes)."""
        import http.client
        connection = http.client.HTTPConnection("127.0.0.1", self.web.server_port, timeout=10)
        try:
            connection.request("GET", "/api/compute/rental-agent", headers={"Authorization": "Bearer " + token})
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def token(self):
        created = self.calls("POST", "/v1/pods")[-1][2]
        return created["env"]["YOUGORI_AGENT_TOKEN"]

    def agent(self, token, **data):
        return self.call("/api/compute/agent", {"action": "inventory", "platform": "Linux", "capacity": 8, **data}, headers={"Authorization": "Bearer " + token})

    def rentals(self):
        status, view, _ = self.call("/api/admin/rentals", session=self.admin)
        self.assertEqual(status, 200, view)
        return view["rentals"]

    def test_keys_are_checked_saved_and_never_shown(self):
        status, refused, _ = self.call("/api/admin/rentals/account", {"provider": "runpod", "key": "wrong-key-1234"}, self.admin)
        self.assertEqual(status, 400)
        self.assertIn("RunPod did not accept this API key", refused["error"]["message"])
        self.assertEqual(self.call("/api/admin/rentals/account", {"provider": "runpod", "key": RUNPOD_KEY}, self.member())[0], 403)
        self.keys()
        status, view, _ = self.call("/api/admin/rentals", session=self.admin)
        self.assertEqual([(a["provider"], a["connected"], a["account"]["balance"]) for a in view["accounts"]], [("runpod", True, 25.5), ("vast", True, 10.5)])
        self.assertNotIn(RUNPOD_KEY, json.dumps(view))
        self.assertNotIn(VAST_KEY, json.dumps(view))
        self.assertEqual(self.call("/api/admin/rentals/forget", {"provider": "vast"}, self.admin)[1]["accounts"][1]["connected"], False)

    def test_offers_show_before_any_key_cheapest_first_and_rent_with_one(self):
        # Both providers list their GPUs without a key: Admin shows them at once.
        quote = self.quote()
        self.assertEqual([(o["id"], o["hourly_usd"], o["vram_gb"], o["where"], o["compute"], o["connected"]) for o in quote["offers"]], [
            ("vast:123", 0.25, 24.6, "Norway, NO", 8.6, False),
            ("runpod:community:NVIDIA GeForce RTX 4090", 0.34, 24, "Community Cloud", 8.9, False),
            ("runpod:secure:Tesla T4", 0.4, 16, "Secure Cloud", 7.5, False),
            ("runpod:secure:NVIDIA GeForce RTX 4090", 0.69, 24, "Secure Cloud", 8.9, False)])  # The A100 is out of stock; AMD runs nothing.
        self.assertEqual([call[3] for call in self.calls("POST", "/graphql")], [""], "no key was sent, none being saved")
        with self.assertRaises(ComputeInput) as refused:
            self.rent(quote)
        self.assertIn("Save the RunPod API key first", str(refused.exception))
        self.keys()
        self.assertEqual({o["connected"] for o in self.quote()["offers"]}, {True})
        asked = self.calls("POST", "/graphql")[-1]
        self.assertEqual(asked[3], RUNPOD_KEY)
        self.assertEqual((asked[2]["variables"]["secure"]["gpuCount"], asked[2]["variables"]["secure"]["minDisk"], asked[2]["variables"]["secure"]["minCudaVersion"]), (1, 80, "12.9"))
        searched = self.calls("POST", "/api/v0/bundles/")[-1][2]
        self.assertEqual((searched["num_gpus"], searched["cuda_max_good"], searched["disk_space"], searched["compute_cap"]),
                         ({"eq": 1}, {"gte": 12.9}, {"gte": 80}, {"gte": 750}))
        for bad in ({"gpu_count": 0, "disk_gb": 80}, {"gpu_count": 1, "disk_gb": 10}, {"gpu_count": "1", "disk_gb": 80}):
            self.assertEqual(self.call("/api/admin/rentals/offers", bad, self.admin)[0], 400, bad)

    def test_nothing_is_rented_until_the_model_fits_and_the_charges_are_approved(self):
        self.keys()
        quote = self.quote()
        for extra, words in (({"cost_acknowledged": False}, "accept the provider's charges"),
                             ({"model": "gated/model"}, "gated or private"),
                             ({"model": "odd/model"}, "(SomethingNew) is not one Yougori's runtimes serve yet"),
                             ({"model": "gguf/model"}, "Rented GPUs cannot run it: rented GPUs run safetensors chat models"),
                             ({"model": "small/model", "offer": "runpod:secure:Tesla T4"}, "is Turing (RTX 20, T4). Choose a newer GPU."),
                             ({"model": "missing/model"}, "no public model missing/model"),
                             ({"model": "big/model"}, "needs about 159 GB of GPU memory and this offer has 24 GB"),
                             ({"offer": "runpod:secure:NVIDIA A100 80GB PCIe"}, "Choose an available GPU")):
            with self.subTest(extra=extra), self.assertRaises(ComputeInput) as refused:
                self.rent(quote, **extra)
            self.assertIn(words, str(refused.exception))
        small = self.quote(disk_gb=40)
        with self.assertRaises(ComputeInput) as refused:
            self.rent(small)
        self.assertIn("needs a disk of at least 54 GB", str(refused.exception))
        with self.service.store.db() as db:
            db.execute("UPDATE rental_quotes SET created=created-600")
        with self.assertRaises(ComputeInput) as refused:
            self.rent(quote)
        self.assertIn("Find GPUs again", str(refused.exception))
        # From this test's http address, a rented GPU could never connect back.
        fresh = self.quote()
        status, said, _ = self.call("/api/admin/rentals/rent", {"request_id": "a1b2c3d4e5f6a7b8", "quote_id": fresh["id"], "model": "test/one",
                                                                "offer": fresh["offers"][1]["id"], "cost_acknowledged": True}, self.admin)
        self.assertEqual(status, 400)
        self.assertIn("public https address", said["error"]["message"])
        self.assertEqual(self.calls("POST", "/v1/pods") + self.calls("PUT"), [])
        self.assertEqual(self.rentals(), [])

    def test_a_rental_is_made_once_and_its_gpu_serves_the_catalog(self):
        self.keys()
        quote = self.quote()
        self.rent(quote)
        self.rent(quote)  # The same request again rents nothing more.
        created = self.calls("POST", "/v1/pods")
        self.assertEqual(len(created), 1)
        body = created[0][2]
        self.assertEqual((body["imageName"], body["gpuTypeIds"], body["cloudType"], body["containerDiskInGb"], body["allowedCudaVersions"]),
                         (neocloud.IMAGE, ["NVIDIA GeForce RTX 4090"], "COMMUNITY", 80, ["12.9", "13.0"]))
        self.assertEqual((body["env"]["YOUGORI_SERVER"], body["env"]["YOUGORI_MODEL"], body["ports"]), (ORIGIN, "test/one", []))
        self.assertEqual(body["dockerEntrypoint"][:2], ["python3", "-c"])
        self.assertIn("/api/compute/rental-agent", body["dockerEntrypoint"][2])
        token = self.token()
        [rental] = self.rentals()
        self.assertEqual((rental["state"], rental["hourly_usd"], rental["model"], rental["provider"]), ("starting", 0.35, "test/one", "RunPod"))
        # The GPU downloads its agent with its own credential, and nothing else does.
        status, raw = self.download(token)
        self.assertEqual(status, 200)
        names = zipfile.ZipFile(io.BytesIO(raw)).namelist()
        self.assertIn("inference-solver/rental_agent.py", names)
        self.assertIn("inference-solver/compute_node.py", names)
        self.assertEqual(self.download("wrong")[0], 401)
        # Its reports: loading, then serving; its model joins the catalog.
        self.assertEqual(self.agent(token, models=[{"id": "model", "name": "test/one", "state": "unavailable", "shared": True}], detail="Downloading and loading test/one.")[0], 200)
        self.assertEqual((self.rentals()[0]["state"], self.rentals()[0]["detail"]), ("loading", "Downloading and loading test/one."))
        # Listed as a connected computer's model is: unavailable until it serves.
        self.assertEqual([(m["id"], m["state"]) for m in self.call("/api/models")[1]["models"]], [("test/one", "unavailable")])
        stopped = threading.Event()
        adapter = Adapter(None, Path(self.temp.name) / "agent")
        adapter.shared, adapter.apis = {"model"}, {"model": {"apiUrl": self.model_url, "apiKey": UPSTREAM_KEY, "model": "test/one"}}
        serving = threading.Thread(target=rental_agent.serve, args=(Link(self.url), token, Ready(), adapter, stopped, 0.2), daemon=True)
        serving.start()
        try:
            for _ in range(100):
                if self.rentals()[0]["state"] == "ready":
                    break
                time.sleep(.1)
            self.assertEqual(self.rentals()[0]["state"], "ready")
            self.assertEqual([m["id"] for m in self.call("/api/models")[1]["models"]], ["test/one"])
            # A request for the model reaches the GPU's model through the agent.
            status, answer, _ = self.call("/v1/chat/completions", self.completion("test/one"), key=self.key()["key"])
            self.assertEqual(status, 200, answer)
            self.assertIn("hello", json.dumps(answer))
            # Local GPUs lists computers only; the rented GPU is under Rent a cloud GPU.
            self.assertEqual([h["role"] for h in self.call("/api/admin/compute", session=self.admin)[1]["hosts"]], ["rental"])
            # Stopping deletes the GPU at its provider, and the agent's credential ends.
            status, view, _ = self.call("/api/admin/rentals/stop", {"id": rental["id"]}, self.admin)
            self.assertEqual((status, view["rentals"][0]["state"]), (200, "stopped"))
            self.assertEqual(len(self.calls("DELETE", "/v1/pods/pod-1")), 1)
            serving.join(10)
            self.assertFalse(serving.is_alive(), "the agent stops once the website revokes its GPU")
        finally:
            stopped.set()
        self.assertEqual(self.call("/api/models")[1]["models"], [])
        self.assertEqual(self.agent(token, models=[])[0], 401)

    def test_the_model_check_says_what_a_model_needs_and_refuses_what_yougori_cannot_run(self):
        def check(model):
            return self.call("/api/admin/rentals/check", {"model": model}, self.admin)

        # A renamed model is followed to its new name; the estimates are the engine's.
        status, facts, _ = check("old/name")
        self.assertEqual((status, facts["model"], facts["gpu_gb"], facts["disk_gb"], facts["compute"], facts["rent"]), (200, "test/one", 20, 54, 8.0, True))
        self.assertEqual(facts["summary"], "Chat model · about 20 GB of GPU memory · Ampere (RTX 30, A100, A40) or newer")
        fp8 = check("fp8/model")[1]
        self.assertEqual((fp8["compute"], fp8["summary"].endswith("Ada (RTX 40, L4, L40S) or newer · FP8")), (8.9, True))
        # Image models count the weights their runtime loads (half precision), not every copy.
        media = check("media/model")[1]
        self.assertEqual((media["kind"], media["gpu_gb"], media["rent"], media["computers"]), ("media", 10, False, True))
        gguf = check("gguf/model")[1]
        self.assertEqual((gguf["kind"], gguf["weights_gb"], gguf["rent"], gguf["computers"]), ("gguf", 4.7, False, True))
        for model, words in (("mega/model", "ships its own megakernel program, built for particular GPUs"),
                             ("runner/repo", "is a megakernel runner, not a model"),
                             ("code/model", "needs its own repository code, which Yougori never runs")):
            with self.subTest(model=model):
                status, refused, _ = check(model)
                self.assertEqual(status, 400)
                self.assertIn(words, refused["error"]["message"])
        # The megakernel's base model runs: it is named instead.
        self.assertIn("add its base model test/one, which Yougori runs", check("mega/model")[1]["error"]["message"])
        self.assertEqual(self.call("/api/admin/rentals/check", {"model": "test/one"}, self.member())[0], 403)

    def test_gpu_names_give_their_generation(self):
        for name, generation in (("NVIDIA GeForce RTX 4090", 8.9), ("RTX A6000", 8.6), ("RTX 6000 Ada", 8.9), ("PRO 6000 MIG 24GB", 12.0),
                                 ("A100 PCIe", 8.0), ("H100 SXM", 9.0), ("Tesla T4", 7.5), ("NVIDIA GeForce RTX 5090", 12.0),
                                 ("AMD Instinct MI300X OAM", 0.0), ("Some Future GPU", None)):
            self.assertEqual(model_check.gpu_generation(name), generation, name)
        need = {"gpu_gb": 20, "compute": 8.0}
        self.assertTrue(model_check.fits(need, [("NVIDIA GeForce RTX 3060", 12), ("NVIDIA GeForce RTX 4090", 24)]))
        self.assertFalse(model_check.fits(need, [("Tesla T4", 32), ("AMD Instinct MI300X", 192), ("RTX 3090", 16)]))

    def test_a_model_that_cannot_start_deletes_its_gpu(self):
        self.keys()
        self.rent(self.quote())
        self.agent(self.token(), models=[{"id": "model", "name": "test/one", "state": "unavailable", "shared": True}],
                   detail="The model could not start: torch.OutOfMemoryError: CUDA out of memory.", failed=True)
        [rental] = self.rentals()
        self.assertEqual(rental["state"], "failed")
        self.assertIn("CUDA out of memory. Yougori deleted the GPU, so it no longer charges.", rental["detail"])
        self.assertEqual(len(self.calls("DELETE", "/v1/pods/pod-1")), 1)

    def test_a_refused_rental_rents_nothing_and_an_unclear_one_is_never_asked_again(self):
        self.keys()
        quote = self.quote()
        self.providers.state["create"] = "refuse"
        with self.assertRaises(ComputeInput) as refused:
            self.rent(quote, identity="a1b2c3d4e5f6a7b8")
        self.assertIn("RunPod refused the rental: There are no longer any instances available", str(refused.exception))
        self.assertEqual((self.rentals()[0]["state"], self.rentals()[0]["detail"].endswith("Nothing was rented.")), ("failed", True))
        self.providers.state["create"] = "unclear"
        with self.assertRaises(ComputeInput) as unclear:
            self.rent(quote, identity="b1b2c3d4e5f6a7b8")
        self.assertIn("did not confirm the rental", str(unclear.exception))
        self.rent(quote, identity="b1b2c3d4e5f6a7b8")
        self.assertEqual(len(self.calls("POST", "/v1/pods")), 2)
        self.assertEqual(self.rentals()[0]["state"], "attention")

    def test_a_gpu_the_provider_ended_ends_its_rental(self):
        self.keys()
        self.rent(self.quote())
        self.providers.state["pod"] = "EXITED"
        self.service.rentals.refresh(force=True)
        self.assertEqual(self.rentals()[0]["state"], "stopped")
        self.assertEqual(len(self.calls("DELETE", "/v1/pods/pod-1")), 1, "an exited pod still charges for its disk")

    def test_vast_rentals_start_the_agent_at_boot_and_stop_by_deleting(self):
        self.keys()
        self.rent(self.quote(), offer="vast:123")
        [asked] = self.calls("PUT", "/api/v0/asks/123/")
        body = asked[2]
        self.assertEqual((body["image"], body["disk"], body["runtype"]), (neocloud.IMAGE, 80, "ssh"))
        self.assertIn("-e YOUGORI_SERVER=" + ORIGIN, body["env"])
        self.assertIn("/api/compute/rental-agent", body["onstart"])
        self.assertLess(len(body["onstart"]), 4048)
        [rental] = self.rentals()
        self.assertEqual((rental["provider"], rental["hourly_usd"]), ("Vast.ai", 0.25))
        self.assertEqual(self.call("/api/admin/rentals/stop", {"id": rental["id"]}, self.admin)[0], 200)
        self.assertEqual(len(self.calls("DELETE", "/api/v0/instances/555/")), 1)
        # A provider with GPUs still rented keeps its key until they stop.
        self.rent(self.quote(), offer="vast:123", identity="c1b2c3d4e5f6a7b8")
        status, refused, _ = self.call("/api/admin/rentals/forget", {"provider": "vast"}, self.admin)
        self.assertEqual(status, 400)
        self.assertIn("Stop this provider's rented GPUs first", refused["error"]["message"])


class AgentTest(unittest.TestCase):
    def model(self, folder):
        with patch.object(rental_agent, "context_length", return_value=32768), patch.object(rental_agent, "gpu_count", return_value=1):
            return rental_agent.Model("test/one", "key", Path(folder) / "model.log")

    def test_the_runtime_is_started_as_the_engine_starts_it(self):
        import tempfile
        with tempfile.TemporaryDirectory() as folder:
            model = self.model(folder)
            command = model.command()
        # The website lists the context the server serves, for harnesses.
        self.assertEqual(model.report()["models"][0]["context"], 32768)
        for flags in (["--served-model-name", "test/one"], ["--host", "127.0.0.1"], ["--max-model-len", "32768"],
                      ["--tensor-parallel-size", "1"], ["--distributed-executor-backend", "uni"], ["--gpu-memory-utilization", "0.90"],
                      ["--enable-prompt-tokens-details"], ["--generation-config", "vllm"]):
            self.assertTrue(any(command[i:i + len(flags)] == flags for i in range(len(command))), flags)

    def test_a_context_too_long_for_the_gpu_starts_once_more_and_then_fails(self):
        import tempfile

        class Ended:
            def poll(self):
                return 1

        with tempfile.TemporaryDirectory() as folder:
            model = self.model(folder)
            model.process = Ended()
            model.log.write_text("ValueError: To serve at least one request with the models's max seq len (32768), (4.5 GiB KV cache is needed, which is "
                                 "larger than the available KV cache memory (1.2 GiB). Based on the available memory, the estimated maximum model length "
                                 "is 8704. Try increasing `gpu_memory_utilization` or decreasing `max_model_len` when initializing the engine.\n", encoding="utf-8")
            with patch.object(model, "start") as start:
                model.check()
            start.assert_called_once()
            self.assertEqual((model.state, model.context), ("loading", 8704))
            self.assertIn("8704-token context", model.detail)
            # The website is told the context the server now starts with.
            self.assertEqual(model.report()["models"][0]["context"], 8704)
            model.check()  # The second stop is final.
            self.assertEqual(model.state, "failed")
            self.assertIn("The model could not start: ValueError: To serve at least one request", model.detail)
            self.assertEqual(model.report()["failed"], True)
            self.assertEqual(model.report()["models"][0]["state"], "unavailable")


if __name__ == "__main__":
    unittest.main()
