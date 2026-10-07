use super::*;
use std::time::Duration;
use yougori_cli::workload::Options;

pub(super) fn source() -> String {
    let mut packed = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    std::io::Write::write_all(&mut packed, include_bytes!("gpu_optimizer.py")).expect("GPU helper");
    STANDARD.encode(packed.finish().expect("GPU helper compression"))
}

pub(super) fn environment(environment: &mut Value, protected: &mut Value) -> Result<(), String> {
    environment["YOUGORI_MODEL_SERVER_SOURCE"] = json!(super::server_payload());
    let reference = format!("gpu-control-{}", uuid::Uuid::new_v4().simple());
    crate::projects::secrets::store(&reference, &uuid::Uuid::new_v4().simple().to_string())?;
    environment["YOUGORI_GPU_SOURCE"] = json!(source());
    environment["YOUGORI_GPU_OPTIMIZER"] = json!("1");
    protected["YOUGORI_GPU_CONTROL_TOKEN"] = json!(reference);
    Ok(())
}

pub(super) fn refresh_options(options: &mut Options) -> Result<(), String> {
    options.environment.insert("YOUGORI_MODEL_SERVER_SOURCE".into(),super::server_payload());
    options.environment.insert("YOUGORI_GPU_SOURCE".into(),source());
    if options.environment.get("YOUGORI_MODEL_FORMAT").is_some_and(|v| v == "source") { return Ok(()); }
    options.environment.insert("YOUGORI_GPU_SOURCE".into(), source());
    options.environment.entry("YOUGORI_GPU_OPTIMIZER".into()).or_insert("1".into());
    if !options.secret_environment.contains_key("YOUGORI_GPU_CONTROL_TOKEN") {
        let reference = format!("gpu-control-{}", uuid::Uuid::new_v4().simple());
        crate::projects::secrets::store(&reference, &uuid::Uuid::new_v4().simple().to_string())?;
        options.secret_environment.insert("YOUGORI_GPU_CONTROL_TOKEN".into(), reference);
    }
    Ok(())
}

#[tauri::command]
pub async fn model_optimizer(environment_id: String, enabled: Option<bool>, pinned: Option<bool>, idle_timeout_seconds: Option<u64>, app: AppHandle) -> Result<Value, String> {
    let health = super::model_status(environment_id.clone(), app.clone()).await?;
    if enabled.is_none() && pinned.is_none() && idle_timeout_seconds.is_none() { return Ok(health["optimizer"].clone()); }
    if health["optimizer"]["supported"] != true { return Err("Restart this model with the updated engine to enable Automatic GPU memory. Files are kept.".into()); }
    let timeout = idle_timeout_seconds.unwrap_or(health["optimizer"]["idleTimeoutSeconds"].as_u64().unwrap_or(0));
    if timeout != 0 && !(10..=3600).contains(&timeout) { return Err("Idle timeout must be 0 (keep loaded until switching) or 10–3600 seconds".into()); }
    let on = enabled.unwrap_or(health["optimizer"]["enabled"] == true);
    let pin = pinned.unwrap_or(health["optimizer"]["pinned"] == true);
    let answer = model_request(&app, &environment_id, "/v1/yougori/optimizer", Some(json!({"action":"configure","enabled":on,"pinned":pin,"idleTimeoutSeconds":timeout}))).await?;
    let runtime = app.state::<RuntimeManager>();
    let state = app.state::<PlatformStore>().snapshot()?;
    let env = state.environments.iter().find(|e| e.id == environment_id).ok_or("Model not found")?;
    let id = env.runtime_id.as_deref().unwrap_or(&environment_id);
    let mut options = runtime.workload_options(id)?;
    options.environment.insert("YOUGORI_GPU_OPTIMIZER".into(), if on {"1"} else {"0"}.into());
    options.environment.insert("YOUGORI_GPU_PINNED".into(), if pin {"1"} else {"0"}.into());
    options.environment.insert("YOUGORI_GPU_IDLE_SECONDS".into(), timeout.to_string());
    runtime.save_workload_options(id, &options)?;
    Ok(answer["optimizer"].clone())
}

// A conservative shared-device scheduler: one resident model while switching.
// Active/pinned models always retain residency; runners enforce this atomically.
fn demand<'a>(rows: &'a [(String, Value)]) -> Option<&'a (String, Value)> {
    rows.iter().filter(|(_, h)| h["optimizer"]["pending"].as_u64().unwrap_or(0) > 0 && h["optimizer"]["resident"] != true && h["status"] != "error")
        .min_by(|a,b| a.1["optimizer"]["waitingSince"].as_f64().unwrap_or(f64::MAX).total_cmp(&b.1["optimizer"]["waitingSince"].as_f64().unwrap_or(f64::MAX)))
}

fn idle_expired(health: &Value) -> bool {
    let o = &health["optimizer"];
    let timeout = o["idleTimeoutSeconds"].as_u64().unwrap_or(0);
    o["resident"] == true && timeout > 0 && o["idleSeconds"].as_u64().unwrap_or(0) >= timeout
}

pub(crate) fn start(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let shutdown = crate::automation::shutdown_signal(&app);
        loop {
            tokio::select! { _=shutdown.cancelled()=>break, _=tokio::time::sleep(Duration::from_secs(1))=>{} }
            let Ok(state) = app.state::<PlatformStore>().snapshot() else { continue };
            let runtime = app.state::<RuntimeManager>();
            let ids = state.environments.iter().filter(|e| e.status == EnvironmentStatus::Running && e.kind == EnvironmentKind::Container)
                .filter(|e| runtime.workload_options(e.runtime_id.as_deref().unwrap_or(&e.id)).is_ok_and(|o| o.environment.get("YOUGORI_GPU_OPTIMIZER").is_some_and(|v|v == "1")))
                .map(|e|e.id.clone()).collect::<Vec<_>>();
            let mut rows = Vec::new();
            for id in ids {
                let answer = tokio::select! { _=shutdown.cancelled()=>return, answer=tokio::time::timeout(Duration::from_secs(3),super::model_status(id.clone(),app.clone()))=>answer };
                if let Ok(Ok(health)) = answer { if health["optimizer"]["enabled"] == true { rows.push((id, health)); } }
            }
            // Never admit another model while a loader owns the GPU.
            if rows.iter().any(|(_,h)|h["optimizer"]["loading"] == true) { continue; }
            if let Some((id,_)) = demand(&rows) {
                let others = rows.iter().filter(|(other,h)|other != id && h["optimizer"]["resident"] == true).collect::<Vec<_>>();
                if others.iter().any(|(_,h)| h["optimizer"]["active"].as_u64().unwrap_or(0)>0 || h["optimizer"]["pending"].as_u64().unwrap_or(0)>0 || h["optimizer"]["pinned"] == true) { continue; }
                let _ = model_request(&app,id,"/v1/yougori/optimizer",Some(json!({"action":"phase","phase":"freeing_memory"}))).await;
                let mut freed = true;
                for (other,_) in others {
                    if !model_request(&app,other,"/v1/yougori/optimizer",Some(json!({"action":"unload"}))).await.is_ok_and(|v|v["unloaded"] == true) { freed = false; break; }
                }
                if freed { let _ = model_request(&app,id,"/v1/yougori/optimizer",Some(json!({"action":"grant"}))).await; }
            } else {
                for (id,h) in &rows {
                    if idle_expired(h) {
                        let _ = model_request(&app,id,"/v1/yougori/optimizer",Some(json!({"action":"unload"}))).await;
                    }
                }
            }
        }
    });
}

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn resident_waits_for_other_model_demand_without_an_idle_deadline() {
        let resident = json!({"status":"ready","optimizer":{"resident":true,"idleTimeoutSeconds":0,"idleSeconds":86400,"pending":0}});
        let mut rows = vec![("current".into(),resident.clone())];
        assert!(!idle_expired(&resident));
        assert!(demand(&rows).is_none());
        rows.push(("next".into(),json!({"status":"queued","optimizer":{"pending":1,"resident":false,"waitingSince":1}})));
        assert_eq!(demand(&rows).unwrap().0,"next");
        assert!(!idle_expired(&resident));
    }
    #[test] fn timed_idle_unloading_remains_opt_in() {
        let mut health = json!({"optimizer":{"resident":true,"idleSeconds":119,"idleTimeoutSeconds":120}});
        assert!(!idle_expired(&health));
        health["optimizer"]["idleSeconds"] = json!(120);
        assert!(idle_expired(&health));
        health["optimizer"].as_object_mut().unwrap().remove("idleTimeoutSeconds");
        assert!(!idle_expired(&health));
    }
    #[test] fn oldest_waiter_wins_and_loaded_or_failed_models_are_excluded() {
        let rows = vec![("loaded".into(),json!({"status":"ready","optimizer":{"pending":3,"resident":true,"waitingSince":1}})),
            ("new".into(),json!({"status":"queued","optimizer":{"pending":1,"waitingSince":20}})),
            ("old".into(),json!({"status":"queued","optimizer":{"pending":1,"waitingSince":10}})),
            ("failed".into(),json!({"status":"error","optimizer":{"pending":1,"waitingSince":0}}))];
        assert_eq!(demand(&rows).unwrap().0,"old");
    }
}
