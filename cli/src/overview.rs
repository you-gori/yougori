//! Read-only views over everything the engine runs, whichever front end created it.
use crate::public::call;
use serde_json::{json, Value};

pub const TYPES: [&str; 8] = ["container", "gpu", "model", "microvm", "vm", "cloud", "shared", "app"];

/// The user-facing type of an environment. Hugging Face models are GPU containers with their own type.
pub fn env_type(env: &Value) -> &'static str {
    let runtime = env["runtime"].as_str().unwrap_or("");
    match (env["kind"].as_str().unwrap_or(""), env["provider"].as_str().unwrap_or("")) {
        _ if runtime.starts_with("shared://") => "shared",
        ("cloud", _) => "cloud",
        ("microVm", _) => "microvm",
        ("fullVm", _) => "vm",
        ("computerBranch", _) | (_, "nativeSandbox") => "app",
        (_, "yougoriCuda") if env["description"].as_str().is_some_and(|d| d.starts_with("Hugging Face · ")) => "model",
        (_, "yougoriCuda") => "gpu",
        _ => "container",
    }
}

/// An environment for listings: long startup commands (model servers embed a whole script) are shortened.
/// `yougori inspect ENV` still returns the full value.
pub fn listing(env: &Value) -> Value {
    let mut env = env.clone();
    if let Some(command) = env["containerCommand"].as_str().filter(|c| c.chars().count() > 300) {
        let short: String = command.chars().take(120).collect();
        env["containerCommand"] = format!("{short}… ({} characters; `yougori inspect ENV` shows all)", command.chars().count()).into();
    }
    env
}

/// `--type gpu` also lists models, which are GPU containers.
pub fn matches_type(env: &Value, wanted: &str) -> bool {
    let actual = env_type(env);
    actual == wanted || (wanted == "gpu" && actual == "model")
}

fn published(services: &Value) -> Vec<Value> {
    services["publications"].as_array().into_iter().flatten().map(|p| json!({
        "id": p["id"], "port": p["port"], "kind": p["kind"], "urls": p["urls"], "status": p["status"],
        "domain": p["cloudflareAccount"] == true,
    })).collect()
}

/// Environments that can hold publications: running, local, not shared from someone else.
fn publishes(env: &Value) -> bool {
    env["status"] == "running" && !matches!(env_type(env), "cloud" | "shared" | "app")
}

async fn services(env: &Value) -> Value {
    call("list_environment_services", json!({"environmentId": env["id"]})).await.unwrap_or(Value::Null)
}

/// Every published port across all environments.
pub async fn all_ports() -> Result<Value, String> {
    let state = call("get_platform_state", json!({})).await?;
    let mut rows = Vec::new();
    for env in state["environments"].as_array().into_iter().flatten().filter(|e| publishes(e)) {
        for publication in published(&services(env).await) {
            rows.push(json!({"environmentId": env["id"], "environment": env["name"], "publication": publication}));
        }
    }
    Ok(Value::Array(rows))
}

/// One overview of the engine, environments, public links, sharing, domains, connections and jobs.
pub async fn status() -> Result<Value, String> {
    // Report a stopped engine instead of starting it just to look.
    let Ok(engine) = crate::client::call(&crate::client::request("app_status", json!({}))).await else {
        return Ok(json!({"engine":{"running":false},"hint":"Start the engine with `yougori app start`, or open the Yougori app."}));
    };
    let state = call("get_platform_state", json!({})).await?;
    let envs = state["environments"].as_array().cloned().unwrap_or_default();
    // Engines without the security monitor simply leave these fields out.
    let monitor = call("security_monitor", json!({})).await.ok();
    let mut by_type = serde_json::Map::new();
    let mut list = Vec::new();
    for env in &envs {
        let kind = env_type(env);
        *by_type.entry(kind).or_insert(json!(0)) = json!(by_type.get(kind).and_then(Value::as_u64).unwrap_or(0) + 1);
        let links = if publishes(env) { published(&services(env).await) } else { Vec::new() };
        let security = monitor.as_ref().and_then(|monitor| security_entry(monitor, &env["id"])).map(crate::security::label);
        list.push(json!({
            "id": env["id"], "name": env["name"], "type": kind, "status": env["status"],
            "cpuPercent": env["cpuUsage"], "memoryGb": env["memoryUsageGb"], "published": links,
            "error": env["lastError"], "security": security,
        }));
    }
    let running = envs.iter().filter(|e| e["status"] == "running").count();
    let sharing = call("list_remote_shares", json!({})).await.unwrap_or(Value::Null);
    let people = sharing["grants"].as_array().map(|g| g.iter().filter(|g| !matches!(g["status"].as_str(), Some("revoked" | "expired"))).count()).unwrap_or(0);
    let jobs = call("jobs_list", json!({})).await.unwrap_or(Value::Null);
    let active_jobs = jobs.as_array().map(|j| j.iter().filter(|j| matches!(j["status"].as_str(), Some("queued" | "running"))).count()).unwrap_or(0);
    Ok(json!({
        "engine": {"running": true, "version": engine["version"], "headless": engine["headless"]},
        "environments": {"total": envs.len(), "running": running, "byType": by_type, "list": list},
        "sharing": {"link": sharing["url"], "people": people},
        "savedDomains": state["savedDomains"].as_array().map(|d| d.iter().map(|d| d["hostname"].clone()).collect::<Vec<_>>()).unwrap_or_default(),
        "connections": state["connections"].as_array().map(Vec::len).unwrap_or(0),
        "activeJobs": active_jobs,
        "security": monitor.as_ref().map(security_summary),
    }))
}

fn security_entry<'a>(monitor: &'a Value, id: &Value) -> Option<&'a Value> {
    monitor["environments"].as_array()?.iter().find(|entry| entry["id"] == *id)
}

/// Monitoring state, active alerts and contained environments, for `status`.
pub fn security_summary(monitor: &Value) -> Value {
    let environments = monitor["environments"].as_array().cloned().unwrap_or_default();
    let alerts = environments.iter().chain(monitor["pools"].as_array().into_iter().flatten().map(|pool| &pool["summary"]))
        .map(|entry| entry["alerts"].as_array().map(Vec::len).unwrap_or(0)).sum::<usize>();
    let contained: Vec<Value> = environments.iter().filter(|entry| entry["containment"].is_object())
        .map(|entry| json!({"id": entry["id"], "name": entry["name"], "level": entry["containment"]["level"], "since": entry["containment"]["since"]}))
        .collect();
    json!({"monitoring": monitor["monitoring"], "alerts": alerts, "contained": contained})
}

/// Adds blocked attempts (last 10 minutes) and the security label to `top` rows.
pub fn add_security(snapshot: &mut Value, monitor: &Value) {
    for row in snapshot["environments"].as_array_mut().into_iter().flatten() {
        if let Some(entry) = security_entry(monitor, &row["id"]) {
            row["blocked"] = entry["network"]["blockedLast10m"].clone();
            row["security"] = crate::security::label(entry).into();
        }
    }
    snapshot["security"] = security_summary(monitor);
}

/// A usage snapshot: this PC and every running environment, busiest first.
pub fn top(state: &Value) -> Value {
    let host = &state["host"];
    let mut rows = state["environments"].as_array().into_iter().flatten().filter(|e| e["status"] == "running").map(|env| json!({
        "id": env["id"], "name": env["name"], "type": env_type(env),
        "cpuPercent": env["cpuUsage"], "memoryGb": env["memoryUsageGb"],
        "storageAddedGb": env["storageDeltaGb"], "networkMbps": env["networkRxMbps"],
    })).collect::<Vec<_>>();
    rows.sort_by(|a, b| b["cpuPercent"].as_f64().unwrap_or(0.0).total_cmp(&a["cpuPercent"].as_f64().unwrap_or(0.0)));
    json!({
        "host": {"cpuPercent": host["usedCpuPercent"], "gpuPercent": host["gpuUsagePercent"], "memoryGb": host["usedMemoryGb"], "totalMemoryGb": host["totalMemoryGb"], "cpus": host["totalCpu"]},
        "environments": rows,
    })
}

/// A compact, secret-free capability map for autonomous clients. Capabilities
/// describe the current state, not permission to perform an action.
pub fn agent_inventory(state: &Value) -> Value {
    let host = &state["host"];
    let deployments = &state["neocloudDeployments"];
    let environments: Vec<Value> = state["environments"].as_array().into_iter().flatten().map(|env| {
        let id = env["id"].as_str().unwrap_or("");
        let kind = env_type(env);
        let running = env["status"] == "running";
        let managed = &deployments[id];
        let serverless = managed["product"] == "serverless";
        let exec = if serverless { "api-only" }
            else if kind == "app" { "unsupported" }
            else if kind == "shared" { "requires-control-grant" }
            else if kind == "vm" { "requires-guest-ssh" }
            else if running { "ready" } else { "requires-start" };
        let files_in = if serverless || kind == "app" { "unsupported" }
            else if kind == "shared" { "requires-edit-grant" }
            else if running { "ready" } else { "requires-start" };
        let files_out = if matches!(kind, "app" | "vm") || serverless { "unsupported" }
            else if kind == "shared" { "requires-view-grant" }
            else if running { "ready" } else { "requires-start" };
        let lifecycle = if managed.is_object() { "neocloud" }
            else if kind == "cloud" { "external-cloud" }
            else if kind == "shared" { "owner-controlled" }
            else if kind == "app" { "app-window" } else { "local" };
        // Cloud and shared capacity is not represented by the local resource
        // policy. Its placeholder zeros must not be used for scheduling.
        let local_capacity = !matches!(kind, "cloud" | "shared");
        json!({
            "id": id, "name": env["name"], "type": kind, "status": env["status"],
            "needsAttention": env["status"] == "error",
            "compute": {
                "configuredCpuCores": if local_capacity { &env["resourcePolicy"]["cpu"]["preferred"] } else { &Value::Null },
                "currentCpuCores": if local_capacity { &env["resourcePolicy"]["cpu"]["current"] } else { &Value::Null },
                "configuredMemoryGb": if local_capacity { &env["resourcePolicy"]["memoryGb"]["preferred"] } else { &Value::Null },
                "currentMemoryGb": if local_capacity { &env["resourcePolicy"]["memoryGb"]["current"] } else { &Value::Null },
                "gpu": env["gpuAccess"] == true || kind == "gpu" || kind == "model" || managed["product"] == "gpu",
            },
            "access": {"exec":exec,"asyncExec":if crate::execution::supports_async(env){if running {"ready"}else{"requires-start"}}else{"unsupported"},"filesIn":files_in,"filesOut":files_out,
                "logs": if kind == "app" || serverless { "unsupported" } else if running { "ready" } else { "requires-start" }},
            "lifecycle": lifecycle,
            "managedCloud": if managed.is_object() { json!({"provider":managed["provider"],"product":managed["product"],"state":managed["state"],"offer":managed["offer"]}) } else { Value::Null },
        })
    }).collect();
    json!({
        "version": 1,
        "observedAt": host["updatedAt"],
        "host": {"cpuCores":host["totalCpu"],"cpuUsedPercent":host["usedCpuPercent"],
            "memoryTotalGb":host["totalMemoryGb"],"memoryUsedGb":host["usedMemoryGb"],
            "gpuUsedPercent":host["gpuUsagePercent"],"pressure":host["pressure"]},
        "runtimes": state["providers"].as_array().into_iter().flatten().map(|p| json!({"id":p["id"],"status":p["status"]})).collect::<Vec<_>>(),
        "environments": environments,
        "commands": {"inspect":"yougori inspect ENV_ID","exec":"yougori exec ENV_ID --no-wait -- COMMAND [ARG...]",
            "executionOutput":"yougori env execution-output ENV_ID --execution-id exec-JOB_ID --stdout-cursor N --stderr-cursor N",
            "logs":"yougori logs ENV_ID --cursor CURSOR","copyIn":"yougori cp PC_PATH ENV_ID",
            "copyOut":"yougori cp ENV_ID:/path PC_FOLDER","prices":"yougori neocloud prices --format json",
            "schema":"yougori schema METHOD","jobs":"yougori jobs list"},
        "note": "This is an inventory, not an authorization grant. Use exact environment IDs. A ready command can still fail guest authentication, remote permissions or provider checks. Review costs before starting managed cloud compute."
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_environment_kind_gets_a_user_facing_type() {
        let env = |kind: &str, provider: &str, runtime: &str, description: &str| json!({"kind":kind,"provider":provider,"runtime":runtime,"description":description});
        assert_eq!(env_type(&env("container", "yougoriOci", "nginx", "")), "container");
        assert_eq!(env_type(&env("container", "yougoriCuda", "ubuntu", "")), "gpu");
        assert_eq!(env_type(&env("container", "yougoriCuda", "pytorch", "Hugging Face · a/b")), "model");
        assert_eq!(env_type(&env("microVm", "qemu", "builtin:alpine", "")), "microvm");
        assert_eq!(env_type(&env("fullVm", "qemu", "C:/a.iso", "")), "vm");
        assert_eq!(env_type(&env("cloud", "cloudSsh", "user@host", "")), "cloud");
        assert_eq!(env_type(&env("container", "yougoriOci", "shared://x", "")), "shared");
        assert_eq!(env_type(&env("computerBranch", "nativeSandbox", "", "")), "app");
        assert!(matches_type(&env("container", "yougoriCuda", "pytorch", "Hugging Face · a/b"), "gpu"));
        assert!(!matches_type(&env("container", "yougoriCuda", "ubuntu", ""), "model"));
    }
    #[test]
    fn top_lists_running_environments_busiest_first() {
        let state = json!({"host":{"usedCpuPercent":40.0,"totalCpu":16},"environments":[
            {"id":"a","name":"idle","kind":"container","provider":"yougoriOci","runtime":"x","status":"running","cpuUsage":1.0},
            {"id":"b","name":"busy","kind":"microVm","provider":"qemu","runtime":"x","status":"running","cpuUsage":80.0},
            {"id":"c","name":"off","kind":"container","provider":"yougoriOci","runtime":"x","status":"stopped","cpuUsage":0.0},
        ]});
        let mut top = top(&state);
        assert_eq!(top["environments"].as_array().unwrap().iter().map(|e| e["name"].as_str().unwrap()).collect::<Vec<_>>(), ["busy", "idle"]);
        assert_eq!(top["environments"][0]["type"], "microvm");
        assert_eq!(top["host"]["cpus"], 16);
        let monitor = json!({"monitoring": true, "environments": [
            {"id":"b","name":"busy","network":{"blockedLast10m":31},"alerts":[{"rule":"hostPortProbe"}],"containment":{"level":"internetCut","since":"t"}},
            {"id":"a","name":"idle","network":null,"alerts":[]},
        ], "pools": [{"summary": {"alerts": [{"rule":"metadataProbe"}]}}]});
        add_security(&mut top, &monitor);
        assert_eq!(top["environments"][0]["blocked"], 31);
        assert_eq!(top["environments"][0]["security"], "internet cut");
        assert_eq!(top["environments"][1]["security"], "ok");
        assert!(top["environments"][1]["blocked"].is_null());
        assert_eq!(top["security"]["alerts"], 2);
        assert_eq!(top["security"]["contained"][0]["name"], "busy");
    }

    #[test]
    fn agent_inventory_distinguishes_ssh_shared_and_serverless_without_leaking_state() {
        let state = json!({"host":{"totalCpu":16,"usedCpuPercent":20,"totalMemoryGb":64,"usedMemoryGb":8,"updatedAt":"now"},
            "settings":{"secret":"never-return"},
            "environments":[
                {"id":"vm-1","name":"VM","kind":"fullVm","provider":"qemu","status":"running","runtime":"x","resourcePolicy":{"cpu":{"preferred":2},"memoryGb":{"preferred":4}}},
                {"id":"peer-1","name":"Peer","kind":"container","provider":"yougoriOci","runtime":"shared://x","status":"running"},
                {"id":"gpu-1","name":"GPU","kind":"cloud","provider":"cloudSsh","runtime":"x","status":"running"},
                {"id":"api-1","name":"API","kind":"cloud","provider":"cloudSsh","runtime":"x","status":"running"}
            ],
            "neocloudDeployments":{"gpu-1":{"provider":"vast","product":"gpu","state":"Running","offer":"123","address":"private.example"},
                "api-1":{"provider":"runpod","product":"serverless","state":"Running","offer":"H100"}}
        });
        let report = agent_inventory(&state);
        assert_eq!(report["environments"][0]["access"]["exec"], "requires-guest-ssh");
        assert_eq!(report["environments"][0]["access"]["filesOut"], "unsupported");
        assert_eq!(report["environments"][1]["access"]["exec"], "requires-control-grant");
        assert_eq!(report["environments"][2]["access"]["exec"], "ready");
        assert!(report["environments"][2]["compute"]["configuredCpuCores"].is_null());
        assert_eq!(report["environments"][3]["access"]["exec"], "api-only");
        let serialized = report.to_string();
        assert!(!serialized.contains("never-return"));
        assert!(!serialized.contains("private.example"));
    }
}
