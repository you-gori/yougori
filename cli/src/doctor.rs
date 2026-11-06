//! `yougori doctor`: is this computer ready, and what to do when it isn't. Read-only.
use crate::public::call;
use serde_json::{json, Value};

fn check(name: &str, status: &str, detail: impl Into<String>, fix: Option<&str>) -> Value {
    json!({"name": name, "status": status, "detail": detail.into(), "fix": fix})
}

fn on_path() -> Option<std::path::PathBuf> {
    let name = if cfg!(windows) { "yougori.exe" } else { "yougori" };
    std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()).map(|dir| dir.join(name)).find(|p| p.is_file())
}

/// Every check runs; a failure in one never hides the others.
pub async fn run() -> Value {
    let mut checks = vec![check("CLI", "ok", format!("yougori {}", env!("CARGO_PKG_VERSION")), None)];
    checks.push(match on_path() {
        Some(path) => check("PATH", "ok", format!("`yougori` runs from {}", path.display()), None),
        None => check("PATH", "warning", "`yougori` is not on your PATH, so new terminals won't find it", Some("Reinstall Yougori, or add its cli folder to your user PATH")),
    });
    let app = crate::client::desktop_executable(None).ok();
    let standalone = crate::client::engine_executable();
    checks.push(match (&app, &standalone) {
        (Some(app), _) => check("Installed", "ok", format!("Yougori app at {}", app.display()), None),
        (None, Some(engine)) => check("Installed", "ok", format!("Engine only (no desktop app) at {}", engine.display()), None),
        (None, None) => check("Installed", "error", "Neither the Yougori app nor the standalone engine was found", Some("Reinstall Yougori, or set YOUGORI_APP / YOUGORI_ENGINE to its absolute path")),
    });
    let engine = crate::client::call(&crate::client::request("app_status", json!({}))).await;
    let Ok(engine) = engine else {
        checks.push(check("Engine", "error", "The Yougori engine is not running", Some("Run `yougori app start`, or open the Yougori app")));
        return summarize(checks);
    };
    let how = if engine["engineOnly"] == true { " as the standalone engine (no dashboard)" } else if engine["headless"] == true { " in the background" } else { "" };
    checks.push(check("Engine", "ok", format!("Running {} (pid {}){how}", engine["version"].as_str().unwrap_or("?"), engine["pid"]), None));
    if let Ok(state) = call("get_platform_state", json!({})).await {
        for provider in state["providers"].as_array().into_iter().flatten() {
            let name = provider["name"].as_str().unwrap_or("Runtime");
            let detail = provider["detail"].as_str().unwrap_or("").to_owned();
            checks.push(match provider["status"].as_str() {
                Some("ready") => check(name, "ok", detail, None),
                Some("needsSetup") => check(name, "warning", detail, Some("Open Yougori and follow the setup for this runtime")),
                _ => check(name, "warning", detail, None),
            });
        }
        let host = &state["host"];
        if let (Some(total), Some(used)) = (host["totalStorageGb"].as_f64(), host["usedStorageGb"].as_f64()) {
            let free = total - used;
            checks.push(if free < 20.0 {
                check("Disk space", "warning", format!("{free:.0} GB free on the environment drive"), Some("Free space or move storage with `yougori storage location --set PATH`"))
            } else {
                check("Disk space", "ok", format!("{free:.0} GB free on the environment drive"), None)
            });
        }
        let settings = &state["settings"];
        checks.push(if settings["launchAtStartup"] == true {
            check("Start at login", "ok", if settings["startupHeadless"] == true { "The engine starts in the background at login" } else { "The app opens at login" }, None)
        } else {
            check("Start at login", "info", "The engine starts only when you run a command or open the app", Some("`yougori app autostart on` keeps it ready in the background"))
        });
    }
    if let Ok(gpu) = call("get_cuda_runtime_status", json!({})).await {
        for item in gpu["checks"].as_array().into_iter().flatten() {
            let name = format!("GPU · {}", item["name"].as_str().unwrap_or("check"));
            checks.push(check(&name, if item["passed"] == true { "ok" } else { "warning" }, item["detail"].as_str().unwrap_or(""), None));
        }
        if gpu["supported"] == true && gpu["installed"] != true {
            checks.push(check("GPU · CUDA runtime", "warning", gpu["detail"].as_str().unwrap_or("Not installed"), Some("`yougori gpu setup --yes`")));
        }
    }
    if let Ok(vm) = call("sandbox_doctor", json!({})).await {
        checks.extend(vm_sandbox_checks(&vm));
    }
    summarize(checks)
}

/// The VM sandbox rows: one per backend the engine's doctor examined, or why it examined
/// none. They inform and never make this computer "not ready": VM sandboxes are validated
/// per backend by their own boundary checks.
fn vm_sandbox_checks(vm: &Value) -> Vec<Value> {
    if vm["examined"] != true {
        return vec![check("VM sandbox", "info", vm["reason"].as_str().unwrap_or("Not examined"), vm["next"].as_str())];
    }
    let report = &vm["report"];
    if let Some(reason) = report["no_backend"].as_str() {
        return vec![check("VM sandbox", "info", reason, None)];
    }
    report["candidates"].as_array().into_iter().flatten().map(|candidate| {
        let backend = candidate["candidate"]["backend"].as_str().unwrap_or("backend");
        let label = candidate["label"].as_str().unwrap_or("unavailable");
        let count = |key: &str| candidate["required"][key].as_u64().unwrap_or(0);
        let total: u64 = ["passed", "failed", "inconclusive", "not_tested", "refused"].into_iter().map(count).sum();
        let detail = format!("{label}: {} of {total} required boundary checks passed, {} failed, {} not tested", count("passed"), count("failed"), count("not_tested"));
        let validated = label == "validated";
        let fix = (!validated).then_some("`yougori call sandbox_doctor --action plan` lists each check and what it would observe");
        check(&format!("VM sandbox · {backend}"), if validated { "ok" } else { "info" }, detail, fix)
    }).collect()
}

fn summarize(checks: Vec<Value>) -> Value {
    let errors = checks.iter().filter(|c| c["status"] == "error").count();
    let warnings = checks.iter().filter(|c| c["status"] == "warning").count();
    json!({"ready": errors == 0, "errors": errors, "warnings": warnings, "checks": checks})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn readiness_counts_errors_and_warnings() {
        let summary = summarize(vec![check("A", "ok", "", None), check("B", "warning", "", Some("fix")), check("C", "error", "", None)]);
        assert_eq!((summary["ready"].as_bool(), summary["errors"].as_u64(), summary["warnings"].as_u64()), (Some(false), Some(1), Some(1)));
        assert_eq!(summary["checks"][1]["fix"], "fix");
    }
    #[test]
    fn vm_sandbox_rows_inform_and_never_block_readiness() {
        let report = json!({"examined": true, "report": {"no_backend": null, "candidates": [
            {"candidate": {"backend": "hcs"}, "label": "unavailable", "required": {"passed": 0, "failed": 0, "inconclusive": 0, "not_tested": 18, "refused": 0}},
            {"candidate": {"backend": "qemu"}, "label": "validated", "required": {"passed": 18, "failed": 0, "inconclusive": 0, "not_tested": 0, "refused": 0}}]}});
        let rows = vm_sandbox_checks(&report);
        assert_eq!(rows[0]["name"], "VM sandbox · hcs");
        assert_eq!(rows[0]["status"], "info");
        assert_eq!(rows[0]["detail"], "unavailable: 0 of 18 required boundary checks passed, 0 failed, 18 not tested");
        assert!(rows[0]["fix"].as_str().unwrap().contains("--action plan"));
        assert_eq!((rows[1]["status"].as_str(), rows[1]["fix"].is_null()), (Some("ok"), true));
        assert_eq!(summarize(rows)["ready"], true);
        let waiting = vm_sandbox_checks(&json!({"examined": false, "reason": "Host evidence has not collected this computer's inventory yet.", "next": "Run it first"}));
        assert_eq!((waiting[0]["status"].as_str(), waiting[0]["fix"].as_str()), (Some("info"), Some("Run it first")));
        let wsl = vm_sandbox_checks(&json!({"examined": true, "report": {"no_backend": "No VM sandbox backend runs inside WSL2.", "candidates": []}}));
        assert_eq!(wsl[0]["detail"], "No VM sandbox backend runs inside WSL2.");
    }
}
