"""Website-managed VM leases. No host paths, engine methods or cloud purchases."""
import json
import re
import secrets
import time

from store import password_hash, password_matches


class GridInput(ValueError):
    """Safe, actionable validation messages for the grid's public API."""


def limits(value):
    result = {}
    for key, default, maximum in (("cpu", 2, 64), ("memory_gb", 4, 256), ("slots", 1, 16)):
        n = value.get(key, default)
        if type(n) is not int or not 1 <= n <= maximum:
            raise GridInput(f"{key} must be a whole number from 1 to {maximum}.")
        result[key] = n
    return result


class Grid:
    def __init__(self, store):
        self.store = store
        with store.db() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS sandbox_grid_policy(id INTEGER PRIMARY KEY CHECK(id=1), enabled INTEGER NOT NULL,
                    admission TEXT NOT NULL, password TEXT NOT NULL);
                INSERT OR IGNORE INTO sandbox_grid_policy VALUES(1,0,'private','');
                CREATE TABLE IF NOT EXISTS sandbox_grid_nodes(host TEXT PRIMARY KEY, capacity TEXT NOT NULL, seen INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS sandbox_grid_vms(id TEXT PRIMARY KEY, host TEXT NOT NULL, owner TEXT NOT NULL,
                    name TEXT NOT NULL, cpu INTEGER NOT NULL, memory_gb INTEGER NOT NULL, state TEXT NOT NULL, sandbox TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS sandbox_grid_jobs(id TEXT PRIMARY KEY, host TEXT NOT NULL, vm TEXT NOT NULL,
                    kind TEXT NOT NULL, payload TEXT NOT NULL, state TEXT NOT NULL, result TEXT NOT NULL, updated INTEGER NOT NULL);
            """)

    def policy(self):
        with self.store.db() as db:
            row = dict(db.execute("SELECT * FROM sandbox_grid_policy WHERE id=1").fetchone())
        return {"enabled": bool(row["enabled"]), "admission": row["admission"], "password_set": bool(row["password"])}

    def configure(self, actor, data):
        mode = data.get("admission")
        if mode not in ("private", "open", "password") or type(data.get("enabled")) is not bool:
            raise GridInput("Choose private, public without password, or public with password.")
        with self.store.db() as db:
            previous = db.execute("SELECT password FROM sandbox_grid_policy WHERE id=1").fetchone()[0]
            password = password_hash(data["password"]) if data.get("password") else previous
            if mode == "password" and not password:
                raise GridInput("Set a contributor password first (at least 12 characters).")
            db.execute("UPDATE sandbox_grid_policy SET enabled=?,admission=?,password=? WHERE id=1",
                       (int(data["enabled"]), mode, password if mode == "password" else ""))
            if "local" in data:
                capacity = limits(data["local"]) if data["local"] else {}
                db.execute("INSERT INTO sandbox_grid_nodes VALUES('website-host',?,0) ON CONFLICT(host) DO UPDATE SET capacity=excluded.capacity", (json.dumps(capacity),))
            self.store.audit(db, actor, "grid.policy", mode)
        return self.policy()

    def local_capacity(self):
        with self.store.db() as db:
            row = db.execute("SELECT capacity FROM sandbox_grid_nodes WHERE host='website-host'").fetchone()
        capacity = json.loads(row[0]) if row else {}
        return limits(capacity) if capacity else {}

    def contributor_allowed(self, user, password):
        with self.store.db() as db:
            row = db.execute("SELECT * FROM sandbox_grid_policy WHERE id=1").fetchone()
        return bool(user["admin"] or (row["enabled"] and (row["admission"] == "open" or
                    (row["admission"] == "password" and password_matches(password, row["password"])))))

    def inventory(self, host, data):
        capacity = limits(data) if data else {}
        if capacity:
            capacity.update(available=data.get("available",True) is True,
                            detail=str(data.get("detail",""))[:200])
        with self.store.db() as db:
            db.execute("INSERT INTO sandbox_grid_nodes VALUES(?,?,?) ON CONFLICT(host) DO UPDATE SET capacity=excluded.capacity,seen=excluded.seen",
                       (host["id"], json.dumps(capacity), int(time.time())))

    def reconcile(self, host, records):
        if not isinstance(records,dict) or len(records)>256:
            raise GridInput("Invalid sandbox inventory.")
        with self.store.db() as db:
            for vm,record in records.items():
                if not isinstance(record,dict):
                    raise GridInput("Invalid sandbox record.")
                identity = record.get("sandbox", "")
                if identity and not re.fullmatch(r"exe-[a-f0-9]{32}",identity):
                    raise GridInput("Invalid sandbox identity.")
                state = "stopped" if record.get("stopped") else "running" if identity else "attention"
                db.execute("UPDATE sandbox_grid_vms SET state=?,sandbox=? WHERE id=? AND host=?",(state,identity,vm,host["id"]))
                # Reconcile the resource identity after a lost launch response;
                # never repeat the launch or an interrupted guest command.
                db.execute("UPDATE sandbox_grid_jobs SET state='attention',result=?,updated=? WHERE vm=? AND host=? AND state='running' AND updated<?",
                    (json.dumps({"sandbox":identity,"error":"Connector interrupted. VM inventory reconciled; inspect before retrying."}),int(time.time()),vm,host["id"],int(time.time())-240))

    def snapshot(self, user):
        with self.store.db() as db:
            nodes = [dict(r) for r in db.execute("SELECT n.host,h.name,n.capacity,n.seen,h.active FROM sandbox_grid_nodes n JOIN compute_hosts h ON h.id=n.host WHERE h.active=1")]
            vms = [dict(r) for r in db.execute("SELECT * FROM sandbox_grid_vms" + ("" if user["admin"] else " WHERE owner=?"), () if user["admin"] else (user["id"],))]
            jobs = [dict(r) for r in db.execute("SELECT j.id,j.vm,j.kind,j.state,j.result,j.updated FROM sandbox_grid_jobs j JOIN sandbox_grid_vms v ON v.id=j.vm" + ("" if user["admin"] else " WHERE v.owner=?") + " ORDER BY updated DESC LIMIT 40", () if user["admin"] else (user["id"],))]
        for n in nodes:
            n["capacity"] = json.loads(n["capacity"])
            n["online"] = n.pop("seen") > time.time() - 45
            # Capacity must count all owners, not just the caller's visible VMs.
            with self.store.db() as db:
                total=db.execute("SELECT COUNT(*),COALESCE(SUM(cpu),0),COALESCE(SUM(memory_gb),0) FROM sandbox_grid_vms WHERE host=? AND state NOT IN ('stopped','failed')",(n['host'],)).fetchone()
            n['free']={key:max(0,n['capacity'].get(key,0)-total[index]) for key,index in (('slots',0),('cpu',1),('memory_gb',2))}
        for j in jobs:
            j["result"] = json.loads(j["result"])
        return {"policy": self.policy(), "nodes": nodes, "vms": vms, "jobs": jobs}

    def catalog(self):
        data=self.snapshot({'admin':False,'id':''})
        return {'enabled':data['policy']['enabled'],'admission':data['policy']['admission'],
                'nodes':[{k:n[k] for k in ('host','name','capacity','free','online')} for n in data['nodes'] if n['capacity']]}

    def submit(self, user, data):
        kind = data.get("kind")
        identity = data.get("request_id")
        if kind not in ("launch", "exec", "stop") or not isinstance(identity, str) or not re.fullmatch(r"[a-f0-9-]{16,64}", identity):
            raise GridInput("Choose a VM action with a request identity.")
        with self.store.db() as db:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute("SELECT j.vm,v.owner FROM sandbox_grid_jobs j JOIN sandbox_grid_vms v ON v.id=j.vm WHERE j.id=?", (identity,)).fetchone()
            if old:
                if not user["admin"] and old["owner"] != user["id"]:
                    raise GridInput("This operation belongs to another account.")
                return {"id": identity, "vm": old["vm"]}
            policy = db.execute("SELECT * FROM sandbox_grid_policy WHERE id=1").fetchone()
            if kind == "launch":
                if not policy["enabled"] or (not user["admin"] and policy["admission"] == "private"):
                    raise GridInput("The sandbox grid is not open for new VMs.")
                resources = limits(data)
                name = data.get("name", "Sandbox VM")
                if not isinstance(name, str) or not 1 <= len(name.strip()) <= 80:
                    raise GridInput("Name the sandbox (1â€“80 characters).")
                node = db.execute("SELECT n.* FROM sandbox_grid_nodes n JOIN compute_hosts h ON h.id=n.host WHERE n.host=? AND h.active=1", (data.get("host"),)).fetchone()
                if not node or node["seen"] < time.time() - 45:
                    raise GridInput("Choose an online contributor.")
                cap = json.loads(node["capacity"])
                used = db.execute("SELECT COUNT(*),COALESCE(SUM(cpu),0),COALESCE(SUM(memory_gb),0) FROM sandbox_grid_vms WHERE host=? AND state NOT IN ('stopped','failed')", (node["host"],)).fetchone()
                if cap and cap.get("available") is False:
                    raise GridInput(cap.get("detail") or "This computer's VM runtime is not ready.")
                if not cap or used[0] >= cap["slots"] or used[1]+resources["cpu"] > cap["cpu"] or used[2]+resources["memory_gb"] > cap["memory_gb"]:
                    raise GridInput("This computer has insufficient contributed capacity.")
                vm, host = secrets.token_hex(16), node["host"]
                payload = {"cpu": resources["cpu"], "memory_gb": resources["memory_gb"]}
                db.execute("INSERT INTO sandbox_grid_vms VALUES(?,?,?,?,?,?,'queued','')", (vm, host, user["id"], name.strip(), payload["cpu"], payload["memory_gb"]))
            else:
                vm = data.get("vm")
                row = db.execute("SELECT * FROM sandbox_grid_vms WHERE id=?", (vm,)).fetchone()
                if not row or (not user["admin"] and row["owner"] != user["id"]):
                    raise GridInput("This VM does not belong to this account.")
                if row["state"] != "running":
                    raise GridInput("Wait for this VM to start, or inspect its failed operation.")
                host, payload = row["host"], {}
                if kind == "exec":
                    command = data.get("input")
                    if not isinstance(command, str) or not 1 <= len(command) <= 16000:
                        raise GridInput("Enter a command of 1â€“16000 characters.")
                    payload = {"input": command}
                if db.execute("SELECT COUNT(*) FROM sandbox_grid_jobs WHERE vm=? AND state IN ('queued','running')", (vm,)).fetchone()[0]:
                    raise GridInput("Wait for this VM's current action to finish.")
            db.execute("INSERT INTO sandbox_grid_jobs VALUES(?,?,?,?,?,'queued','{}',?)", (identity,host,vm,kind,json.dumps(payload),int(time.time())))
            self.store.audit(db,user["id"],"grid."+kind,vm)
        return {"id":identity,"vm":vm}

    def poll(self, host):
        with self.store.db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM sandbox_grid_jobs WHERE host=? AND state='queued' ORDER BY updated LIMIT 1", (host["id"],)).fetchone()
            if not row:
                return {}
            if row["kind"] == "launch" and not db.execute("SELECT enabled FROM sandbox_grid_policy WHERE id=1").fetchone()[0]:
                db.execute("UPDATE sandbox_grid_jobs SET state='cancelled' WHERE id=?",(row["id"],))
                db.execute("UPDATE sandbox_grid_vms SET state='stopped' WHERE id=?",(row["vm"],))
                return {}
            db.execute("UPDATE sandbox_grid_jobs SET state='running',updated=? WHERE id=?", (int(time.time()),row["id"]))
            return {"id":row["id"],"vm":row["vm"],"kind":row["kind"],"payload":json.loads(row["payload"])}

    def result(self, host, data):
        result = data.get("result", {})
        if not isinstance(result, dict) or len(json.dumps(result)) > 140000:
            raise GridInput("VM result too large.")
        clean = {k:result[k] for k in ("sandbox","output","exit_code","error") if k in result}
        with self.store.db() as db:
            row = db.execute("SELECT * FROM sandbox_grid_jobs WHERE id=? AND host=? AND state='running'", (data.get("id"),host["id"])).fetchone()
            if not row:
                raise GridInput("This VM job is no longer assigned to this computer.")
            success = data.get("ok") is True
            if row["kind"] == "launch" and success and not re.fullmatch(r"exe-[a-f0-9]{32}",str(clean.get("sandbox",""))):
                raise GridInput("Yougori did not return a valid VM identity.")
            db.execute("UPDATE sandbox_grid_jobs SET state=?,result=?,updated=? WHERE id=?", ("done" if success else "attention",json.dumps(clean),int(time.time()),row["id"]))
            if row["kind"] == "launch":
                db.execute("UPDATE sandbox_grid_vms SET state=?,sandbox=? WHERE id=?", ("running" if success else "attention",clean.get("sandbox",""),row["vm"]))
            elif row["kind"] == "stop" and success:
                db.execute("UPDATE sandbox_grid_vms SET state='stopped' WHERE id=?", (row["vm"],))
