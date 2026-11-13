"""GPUs this website rents from neoclouds itself, with its administrator's own provider keys
(RunPod, Vast.ai): no Yougori computer in between. Each runs one model, which joins the catalog
the way a connected computer's does (rental_agent.py on the GPU). Administrator only. A rental
is paid for once and never retried; one whose model cannot start is deleted, so it stops
charging.
"""
import json
import re
import secrets
import threading
import time

import model_check
import neocloud
from compute import ComputeInput, model_name
from store import digest
from upstream import UpstreamError

# A quote's offers are rented only while this fresh.
QUOTE_SECONDS = 120
# How often a rented GPU's provider is asked how it is.
CHECK_SECONDS = 15
# A rented GPU whose agent has not connected by then needs the administrator's attention.
CONNECT_SECONDS = 45 * 60
# Rentals still to be watched: renting, starting, loading the model, serving, or unclear.
LIVE = ("creating", "starting", "loading", "ready", "attention")


class Rentals:
    def __init__(self, store, compute):
        self.store, self.compute = store, compute
        self.lock = threading.Lock()
        with store.db() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS rental_accounts(provider TEXT PRIMARY KEY, key TEXT NOT NULL,
                    account TEXT NOT NULL, saved INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS rental_quotes(id TEXT PRIMARY KEY, created INTEGER NOT NULL,
                    options TEXT NOT NULL, offers TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS rentals(id TEXT PRIMARY KEY, provider TEXT NOT NULL, resource TEXT NOT NULL,
                    host TEXT NOT NULL, model TEXT NOT NULL, offer TEXT NOT NULL, disk INTEGER NOT NULL, hourly REAL NOT NULL,
                    state TEXT NOT NULL, detail TEXT NOT NULL, created INTEGER NOT NULL, updated INTEGER NOT NULL,
                    checked INTEGER NOT NULL);
            """)

    def key(self, provider):
        with self.store.db() as db:
            row = db.execute("SELECT key FROM rental_accounts WHERE provider=?", (provider,)).fetchone()
        return row["key"] if row else None

    def connect(self, actor, data):
        """Saves a provider's API key once the provider accepts it. It is never shown again."""
        provider = data.get("provider")
        try:
            key = neocloud.key_text(provider, data.get("key"))
            account = neocloud.account(provider, key)
        except neocloud.ProviderError as error:
            raise ComputeInput(str(error)) from None
        with self.store.db() as db:
            db.execute("INSERT INTO rental_accounts VALUES(?,?,?,?) ON CONFLICT(provider) DO UPDATE SET key=excluded.key,"
                       "account=excluded.account,saved=excluded.saved", (provider, key, json.dumps(account), int(time.time())))
            self.store.audit(db, actor, "rental.account.saved", provider)
        return self.view()

    def forget(self, actor, provider):
        if provider not in neocloud.PROVIDERS:
            raise ComputeInput("Choose RunPod or Vast.ai.")
        with self.store.db() as db:
            live = db.execute("SELECT COUNT(*) FROM rentals WHERE provider=? AND state IN (%s)" % ",".join("?" * len(LIVE)), (provider, *LIVE)).fetchone()[0]
            if live:
                raise ComputeInput("Stop this provider's rented GPUs first: stopping them needs its key.")
            db.execute("DELETE FROM rental_accounts WHERE provider=?", (provider,))
            self.store.audit(db, actor, "rental.account.forgotten", provider)
        return self.view()

    def quote(self, actor, data):
        """What both providers rent right now, for this many GPUs and this much disk. They list
        their GPUs without a key, so Admin shows them before any key is saved; each offer says
        whether its provider's key is saved, which renting needs."""
        gpu_count, disk_gb = data.get("gpu_count"), data.get("disk_gb")
        if type(gpu_count) is not int or not 1 <= gpu_count <= 8:
            raise ComputeInput("Choose 1 to 8 GPUs per server.")
        if type(disk_gb) is not int or not 40 <= disk_gb <= 2000:
            raise ComputeInput("Choose a disk of 40 to 2000 GB.")
        with self.store.db() as db:
            keys = {row["provider"]: row["key"] for row in db.execute("SELECT provider,key FROM rental_accounts")}
        offers, issues = [], []
        for provider in neocloud.PROVIDERS:
            try:
                found = neocloud.offers(provider, keys.get(provider), gpu_count, disk_gb)
            except neocloud.ProviderError as error:
                issues.append({"provider": provider, "detail": str(error)})
                continue
            for offer in found:
                # Each GPU's generation (compute capability); AMD GPUs run none of the runtimes.
                compute = offer.get("compute") or model_check.gpu_generation(offer["name"])
                if compute != 0.0:
                    offers.append({**offer, "compute": compute, "connected": provider in keys})
        quote = {"id": secrets.token_hex(12), "created": int(time.time()), "options": {"gpu_count": gpu_count, "disk_gb": disk_gb},
                 "offers": sorted(offers, key=lambda offer: offer["hourly_usd"])[:100], "issues": issues}
        with self.store.db() as db:
            db.execute("DELETE FROM rental_quotes WHERE created<?", (int(time.time()) - 3600,))
            db.execute("INSERT INTO rental_quotes VALUES(?,?,?,?)", (quote["id"], quote["created"], json.dumps(quote["options"]), json.dumps(quote["offers"])))
        return quote

    def rent(self, actor, data, origin):
        """Rents the chosen offer for one model, once: checks the model fits first, then asks the
        provider, never twice for the same request. The GPU connects back to `origin`."""
        identity = data.get("request_id")
        if not isinstance(identity, str) or not re.fullmatch(r"[a-f0-9-]{16,64}", identity):
            raise ComputeInput("A request identity is required.")
        with self.store.db() as db:
            if db.execute("SELECT 1 FROM rentals WHERE id=?", (identity,)).fetchone():
                return self.view()
            quote = db.execute("SELECT * FROM rental_quotes WHERE id=?", (str(data.get("quote_id", "")),)).fetchone()
        if not re.fullmatch(r"https://[a-z0-9.-]+(:[0-9]{1,5})?", origin or ""):
            raise ComputeInput("A rented GPU connects to this website over the internet: open Admin from the website's public https address.")
        if data.get("cost_acknowledged") is not True:
            raise ComputeInput("Review and accept the provider's charges first.")
        if not quote or quote["created"] < time.time() - QUOTE_SECONDS:
            raise ComputeInput("Find GPUs again before renting: prices change.")
        offer = next((o for o in json.loads(quote["offers"]) if o["id"] == data.get("offer")), None)
        if not offer:
            raise ComputeInput("Choose an available GPU.")
        key = self.key(offer["provider"])
        if not key:
            raise ComputeInput("Save the " + neocloud.PROVIDERS[offer["provider"]] + " API key first.")
        model = model_name(str(data.get("model", "")).strip()).removeprefix("hf.co/")
        facts = self.check(model)
        if not facts["rent"]:
            raise ComputeInput(facts["notes"][0])
        memory = (offer.get("vram_gb") or 0) * offer["gpu_count"]
        if memory < facts["gpu_gb"]:
            raise ComputeInput(f"{facts['model']} needs about {facts['gpu_gb']:.0f} GB of GPU memory and this offer has {memory:.0f} GB. Choose a larger GPU or more GPUs.")
        if offer.get("compute") and offer["compute"] < facts["compute"]:
            raise ComputeInput(f"{facts['model']} needs a GPU from {model_check.generation_words(facts['compute'])} or newer, and {offer['name']} is "
                               f"{model_check.generation_words(offer['compute'])}. Choose a newer GPU.")
        disk = json.loads(quote["options"])["disk_gb"]
        if disk < facts["disk_gb"]:
            raise ComputeInput(f"{facts['model']} needs a disk of at least {facts['disk_gb']} GB here. Find GPUs again with a larger disk.")
        token, host = secrets.token_urlsafe(32), secrets.token_hex(16)
        name = "yougori-" + identity.replace("-", "")[:8]
        label = (f"{offer['gpu_count']} × " if offer["gpu_count"] > 1 else "") + offer["name"] + " · " + neocloud.PROVIDERS[offer["provider"]]
        now = int(time.time())
        with self.store.db() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM rentals WHERE id=?", (identity,)).fetchone():
                return self.view()
            # The GPU's own credential: it connects as a computer of this website, approved already.
            db.execute("INSERT INTO compute_hosts VALUES(?,?,?,'rental',1,0,'{}')", (host, digest(token), label[:80]))
            db.execute("INSERT INTO rentals VALUES(?,?,'',?,?,?,?,?,'creating',?,?,?,0)",
                       (identity, offer["provider"], host, facts["model"], json.dumps(offer), disk, offer["hourly_usd"],
                        "Renting the GPU.", now, now))
            self.store.audit(db, actor, "rental.created", identity)
        environment = {"YOUGORI_SERVER": origin, "YOUGORI_AGENT_TOKEN": token, "YOUGORI_MODEL": facts["model"]}
        try:
            resource, hourly = neocloud.create(offer["provider"], key, offer, name, environment, disk)
        except neocloud.ProviderError as error:
            if error.definite:
                self.finish(identity, "failed", str(error) + " Nothing was rented.")
            else:
                self.update(identity, state="attention", detail=str(error))
            raise ComputeInput(str(error)) from None
        self.update(identity, resource=resource, hourly=hourly, state="starting",
                    detail="Starting the GPU and the model's runtime. The model downloads next.")
        return self.view()

    def check(self, model):
        """What a model needs from a rented GPU, before choosing one (model_check.check)."""
        try:
            return model_check.check(model_name(str(model or "").strip()).removeprefix("hf.co/"))
        except model_check.CheckError as error:
            raise ComputeInput(str(error)) from None

    def update(self, identity, **values):
        values["updated"] = int(time.time())
        with self.store.db() as db:
            db.execute("UPDATE rentals SET " + ",".join(name + "=?" for name in values) + " WHERE id=?", (*values.values(), identity))

    def finish(self, identity, state, detail, actor=None):
        """Ends a rental here: its GPU's credential stops working and its model leaves the catalog."""
        with self.store.db() as db:
            row = db.execute("SELECT host FROM rentals WHERE id=?", (identity,)).fetchone()
        self.update(identity, state=state, detail=detail)
        if row:
            self.compute.revoke(actor or "rental", row["host"])
            # Its record goes too, so ended rentals never fill the website's computer list.
            with self.store.db() as db:
                db.execute("DELETE FROM compute_hosts WHERE id=? AND role='rental'", (row["host"],))

    def stop(self, actor, identity):
        """Deletes a rented GPU at its provider, which ends its charges."""
        with self.store.db() as db:
            rental = db.execute("SELECT * FROM rentals WHERE id=?", (str(identity),)).fetchone()
        if not rental:
            raise ComputeInput("This rented GPU is no longer listed.")
        if rental["state"] in ("stopped", "failed"):
            return self.view()
        key = self.key(rental["provider"])
        if rental["resource"]:
            if not key:
                raise ComputeInput("Save the " + neocloud.PROVIDERS[rental["provider"]] + " API key again to stop this GPU.")
            try:
                deleted = neocloud.terminate(rental["provider"], key, rental["resource"])
            except neocloud.ProviderError:
                deleted = False
            if not deleted:
                raise ComputeInput("The provider did not confirm the GPU was deleted; it may still be charging. Press Stop again, or delete it in your provider account.")
        self.finish(identity, "stopped", "Stopped and deleted: it no longer charges.", actor)
        with self.store.db() as db:
            self.store.audit(db, actor, "rental.stopped", identity)
        return self.view()

    def refresh(self, force=False):
        """Brings each live rental up to date from its GPU's reports and its provider: serving once
        its model answers; deleted when the model could not start; ended when the provider no
        longer runs it; needing attention when its GPU never connected."""
        if not self.lock.acquire(blocking=False):
            return
        try:
            now = int(time.time())
            with self.store.db() as db:
                rentals = [dict(row) for row in db.execute("SELECT * FROM rentals WHERE state IN (%s)" % ",".join("?" * len(LIVE)), LIVE)]
                hosts = {row["id"]: dict(row) for row in db.execute("SELECT id,seen,inventory,active FROM compute_hosts WHERE role='rental'")}
            for rental in rentals:
                if rental["state"] == "creating" or not rental["resource"]:
                    continue
                host = hosts.get(rental["host"], {})
                inventory = json.loads(host.get("inventory") or "{}")
                key = self.key(rental["provider"])
                if inventory.get("failed"):
                    try:
                        deleted = bool(key) and neocloud.terminate(rental["provider"], key, rental["resource"])
                    except neocloud.ProviderError:
                        deleted = False
                    if deleted:
                        self.finish(rental["id"], "failed", str(inventory.get("detail") or "The model could not start.")[:200] + " Yougori deleted the GPU, so it no longer charges.")
                    else:
                        self.update(rental["id"], state="attention", detail=str(inventory.get("detail") or "The model could not start.")[:200] + " Stop this GPU: it may still be charging.")
                    continue
                if key and (force or rental["checked"] < now - CHECK_SECONDS):
                    said = neocloud.status(rental["provider"], key, rental["resource"])
                    self.update(rental["id"], checked=now)
                    if said in ("gone", "stopped"):
                        if said == "stopped":
                            try:
                                neocloud.terminate(rental["provider"], key, rental["resource"])
                            except neocloud.ProviderError:
                                pass
                        self.finish(rental["id"], "stopped", "The provider ended this GPU; it no longer charges.")
                        continue
                ready = any(model.get("state") == "ready" for model in inventory.get("models", []))
                connected = host.get("seen", 0) > now - 45
                state, detail = rental["state"], rental["detail"]
                if ready and connected:
                    state, detail = "ready", str(inventory.get("detail") or "Serving " + rental["model"] + ".")
                elif connected:
                    state, detail = "loading", str(inventory.get("detail") or "Loading the model.")
                elif state in ("starting", "loading") and rental["created"] < now - CONNECT_SECONDS:
                    state, detail = "attention", "This GPU has not connected for 45 minutes. Check it in your provider account, or stop it here."
                elif state in ("ready", "loading"):
                    state, detail = "starting", "Waiting for the GPU to connect again."
                if (state, detail) != (rental["state"], rental["detail"]):
                    self.update(rental["id"], state=state, detail=detail[:200])
        finally:
            self.lock.release()

    def view(self):
        """For Admin: each provider with its account (never its key), and the rented GPUs."""
        with self.store.db() as db:
            accounts = {row["provider"]: dict(row) for row in db.execute("SELECT provider,account,saved FROM rental_accounts")}
            rows = [dict(row) for row in db.execute("SELECT * FROM rentals ORDER BY state IN ('stopped','failed'), created DESC LIMIT 30")]
        return {
            "accounts": [{"provider": provider, "name": name, "connected": provider in accounts,
                          "account": json.loads(accounts[provider]["account"]) if provider in accounts else None}
                         for provider, name in neocloud.PROVIDERS.items()],
            "rentals": [{"id": row["id"], "provider": neocloud.PROVIDERS.get(row["provider"], row["provider"]),
                         "gpu": json.loads(row["offer"]).get("name"), "gpu_count": json.loads(row["offer"]).get("gpu_count"),
                         "where": json.loads(row["offer"]).get("where"), "model": row["model"], "hourly_usd": row["hourly"],
                         "state": row["state"], "detail": row["detail"], "created": row["created"]} for row in rows],
        }

    def agent(self, token):
        """The rented GPU's own credential, checked before it downloads its agent."""
        with self.store.db() as db:
            row = db.execute("SELECT r.id FROM rentals r JOIN compute_hosts h ON h.id=r.host WHERE h.token=? AND h.active=1 AND r.state IN (%s)"
                             % ",".join("?" * len(LIVE)), (digest(str(token)), *LIVE)).fetchone()
        if not row:
            raise UpstreamError("This GPU is not rented by this website.", 401)
        return row["id"]
