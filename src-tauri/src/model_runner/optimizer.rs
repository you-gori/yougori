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
    if options.environment.get("YOUGORI_MODEL_CPU").is_some_and(|v|v == "1") {
        options.environment.insert("YOUGORI_GPU_OPTIMIZER".into(),"0".into());
        return Ok(());
    }
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
    rows.iter().filter(|(_, h)| waiting(h))
        .min_by(|a,b| a.1["optimizer"]["waitingSince"].as_f64().unwrap_or(f64::MAX).total_cmp(&b.1["optimizer"]["waitingSince"].as_f64().unwrap_or(f64::MAX)))
}

/// A model that asked for the GPU and does not hold it.
fn waiting(health: &Value) -> bool {
    health["optimizer"]["pending"].as_u64().unwrap_or(0) > 0 && health["optimizer"]["resident"] != true && health["status"] != "error"
}

/// Why each model waiting for the GPU waits, by model id, in words its person can act on. The
/// scheduler rewrites it on every pass, so a reason is gone once its model is granted or stops
/// waiting.
static WAITING: std::sync::Mutex<std::collections::BTreeMap<String, String>> = std::sync::Mutex::new(std::collections::BTreeMap::new());

/// Why this model waits for the GPU, while it does.
pub(super) fn waiting_for(id: &str) -> Option<String> {
    WAITING.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).get(id).cloned()
}

/// Why each model waiting for the GPU waits: which models hold it, and what the person can do
/// about them, most actionable first. The first in line is the one the scheduler weighs, and the
/// others wait behind it; one the scheduler can grant now gets no reason.
fn reasons(rows: &[(String, Value)], silent: &[String], name: impl Fn(&str) -> String) -> std::collections::BTreeMap<String, String> {
    let mut reasons = std::collections::BTreeMap::new();
    let Some((first, _)) = demand(rows) else { return reasons };
    let others = |holds: fn(&Value) -> bool| rows.iter().filter(|(other, h)| other != first && holds(&h["optimizer"])).map(|(other, _)| name(other)).collect::<Vec<_>>();
    let silent: Vec<String> = silent.iter().map(|id| name(id)).collect();
    let pinned = others(|o| o["resident"] == true && o["pinned"] == true);
    let loading = others(|o| o["loading"] == true);
    let busy = others(|o| o["resident"] == true && (o["active"].as_u64().unwrap_or(0) > 0 || o["pending"].as_u64().unwrap_or(0) > 0));
    let why = match (silent.as_slice(), pinned.as_slice(), loading.as_slice(), busy.as_slice()) {
        ([one], ..) => Some(format!("{one} still holds the GPU (paused or not answering). Resume or stop {one} to let this model load.")),
        ([_, _, ..], ..) => Some(format!("Paused or unresponsive models still hold the GPU: {}. Resume or stop them to let this model load.", silent.join(", "))),
        ([], [one], ..) => Some(format!("{one} keeps the GPU because Prevent automatic model switching is on for it. Turn that off, or stop {one}, to let this model load.")),
        ([], [_, _, ..], ..) => Some(format!("{} keep the GPU because Prevent automatic model switching is on for them. Turn that off, or stop them, to let this model load.", pinned.join(", "))),
        ([], [], [one], _) => Some(format!("{one} is loading into GPU memory. This model loads after it.")),
        ([], [], [_, _, ..], _) => Some(format!("{} are loading into GPU memory. This model loads after them.", loading.join(", "))),
        ([], [], [], [one]) => Some(format!("{one} is using the GPU. This model loads once it is free.")),
        ([], [], [], [_, _, ..]) => Some(format!("{} are using the GPU. This model loads once it is free.", busy.join(", "))),
        ([], [], [], []) => None,
    };
    let ahead = name(first);
    for (id, _) in rows.iter().filter(|(id, health)| id != first && waiting(health)) {
        reasons.insert(id.clone(), format!("{ahead} is first in line for the GPU. This model loads after it."));
    }
    if let Some(why) = why {
        reasons.insert(first.clone(), why);
    }
    reasons
}

/// Whether `id`, waiting for the GPU, must wait longer: another model is using, waiting for or
/// pinning it, or a model may hold GPU memory without saying so (`silent`: paused, or not
/// answering), which cannot be asked to unload, so granting now would only fail this load.
fn must_wait(rows: &[(String, Value)], id: &str, silent: usize) -> bool {
    silent > 0 || rows.iter().filter(|(other, h)| other != id && h["optimizer"]["resident"] == true)
        .any(|(_, h)| h["optimizer"]["active"].as_u64().unwrap_or(0) > 0 || h["optimizer"]["pending"].as_u64().unwrap_or(0) > 0 || h["optimizer"]["pinned"] == true)
}

/// One look at a GPU-optimized model: what it answered, or `None` when it is paused (and cannot
/// be asked) or did not answer.
struct Seen {
    id: String,
    health: Option<Value>,
}

/// Updates the models last seen holding the GPU and returns the rows that answered with the
/// optimizer on, with the models that may hold GPU memory without saying so: one paused, or no
/// longer answering, while it held the GPU. One that held none when last seen (paused before it
/// loaded, or still starting) holds none now, so it never keeps another model waiting. A model
/// paused before this engine started is unknown here; if it does hold memory, the load it would
/// have blocked fails with an error instead of every model waiting for good.
fn observe(seen: &[Seen], resident: &mut std::collections::HashSet<String>) -> (Vec<(String, Value)>, Vec<String>) {
    let mut rows = Vec::new();
    let mut silent = Vec::new();
    for model in seen {
        match &model.health {
            Some(health) => {
                if health["optimizer"]["resident"] == true { resident.insert(model.id.clone()); } else { resident.remove(&model.id); }
                if health["optimizer"]["enabled"] == true { rows.push((model.id.clone(), health.clone())); }
            }
            None => if resident.contains(&model.id) { silent.push(model.id.clone()) },
        }
    }
    resident.retain(|id| seen.iter().any(|model| &model.id == id));
    (rows, silent)
}

fn idle_expired(health: &Value) -> bool {
    let o = &health["optimizer"];
    let timeout = o["idleTimeoutSeconds"].as_u64().unwrap_or(0);
    o["resident"] == true && timeout > 0 && o["idleSeconds"].as_u64().unwrap_or(0) >= timeout
}

pub(crate) fn start(app: &AppHandle) {
    start_until(app, crate::automation::shutdown_signal(app));
}

pub(crate) fn start_until(app: &AppHandle, shutdown: tokio_util::sync::CancellationToken) -> tauri::async_runtime::JoinHandle<()> {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        // Models last seen holding the GPU.
        let mut resident = std::collections::HashSet::<String>::new();
        loop {
            tokio::select! { _=shutdown.cancelled()=>break, _=tokio::time::sleep(Duration::from_secs(1))=>{} }
            let Ok(state) = app.state::<PlatformStore>().snapshot() else { continue };
            let runtime = app.state::<RuntimeManager>();
            let models = state.environments.iter().filter(|e| matches!(e.status, EnvironmentStatus::Running | EnvironmentStatus::Paused) && e.kind == EnvironmentKind::Container)
                .filter(|e| runtime.workload_options(e.runtime_id.as_deref().unwrap_or(&e.id)).is_ok_and(|o| o.environment.get("YOUGORI_GPU_OPTIMIZER").is_some_and(|v|v == "1")))
                .collect::<Vec<_>>();
            let mut seen = Vec::new();
            for model in &models {
                let paused = model.status == EnvironmentStatus::Paused;
                let health = if paused { None } else {
                    let answer = tokio::select! { _=shutdown.cancelled()=>return, answer=tokio::time::timeout(Duration::from_secs(3),super::model_status(model.id.clone(),app.clone()))=>answer };
                    answer.ok().and_then(Result::ok)
                };
                seen.push(Seen { id: model.id.clone(), health });
            }
            let (rows, silent) = observe(&seen, &mut resident);
            let name = |id: &str| models.iter().find(|model| model.id == id).map_or_else(|| id.to_owned(), |model| model.name.clone());
            *WAITING.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = reasons(&rows, &silent, name);
            // Never admit another model while a loader owns the GPU.
            if rows.iter().any(|(_,h)|h["optimizer"]["loading"] == true) { continue; }
            if let Some((id,_)) = demand(&rows) {
                if must_wait(&rows, id, silent.len()) { continue; }
                let others = rows.iter().filter(|(other,h)|other != id && h["optimizer"]["resident"] == true).collect::<Vec<_>>();
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
    })
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
    #[test] fn only_a_model_that_held_the_gpu_keeps_it_from_being_granted() {
        let model = |id: &str, optimizer: Value| Seen { id: id.into(), health: Some(json!({"status":"ready","optimizer":optimizer})) };
        let waiting = || Seen { id: "waiting".into(), health: Some(json!({"status":"queued","optimizer":{"enabled":true,"pending":1,"resident":false,"waitingSince":1}})) };
        let holding = || model("other", json!({"enabled":true,"resident":true,"active":0,"pending":0}));
        let empty = || model("other", json!({"enabled":true,"resident":false,"active":0,"pending":0}));
        // Paused models are not asked, and an unanswering one says nothing: both are seen alike.
        let paused = || Seen { id: "other".into(), health: None };
        let unanswering = paused;
        // Each round is one pass of the scheduler; the answer is whether the waiting model is granted.
        let granted = |rounds: Vec<Vec<Seen>>| {
            let mut resident = std::collections::HashSet::new();
            rounds.into_iter().map(|round| {
                let (rows, silent) = observe(&round, &mut resident);
                !must_wait(&rows, "waiting", silent.len())
            }).last().unwrap()
        };
        // An idle resident model is asked to unload for the waiting one.
        assert!(granted(vec![vec![waiting(), holding()]]));
        // A model paused while it held no GPU memory holds none: it never blocks a grant.
        assert!(granted(vec![vec![waiting(), empty()], vec![waiting(), paused()]]));
        assert!(granted(vec![vec![waiting(), paused()]]));
        assert!(granted(vec![vec![waiting(), empty()], vec![waiting(), unanswering()]]));
        // One paused, or no longer answering, while it held the GPU may still hold it: wait.
        assert!(!granted(vec![vec![waiting(), holding()], vec![waiting(), paused()]]));
        assert!(!granted(vec![vec![waiting(), holding()], vec![waiting(), unanswering()]]));
        // Resumed and unloaded, it holds nothing again.
        assert!(granted(vec![vec![waiting(), holding()], vec![waiting(), paused()], vec![waiting(), empty()]]));
        // A resident model that is busy keeps it as well.
        assert!(!granted(vec![vec![waiting(), model("busy", json!({"enabled":true,"resident":true,"active":1}))]]));
    }
    #[test] fn a_model_waiting_for_the_gpu_says_which_model_holds_it_and_what_to_do() {
        let name = |id: &str| format!("Model {}", id.to_uppercase());
        let waiter = json!({"status":"queued","optimizer":{"pending":1,"resident":false,"waitingSince":1}});
        let behind = json!({"status":"queued","optimizer":{"pending":1,"resident":false,"waitingSince":2}});
        let idle = json!({"status":"ready","optimizer":{"resident":true,"active":0,"pending":0}});
        let busy = json!({"status":"ready","optimizer":{"resident":true,"active":1,"pending":0}});
        let pinned = json!({"status":"ready","optimizer":{"resident":true,"active":0,"pending":0,"pinned":true}});
        let loading = json!({"status":"loading","optimizer":{"resident":true,"loading":true}});
        let rows = |others: Vec<(&str, Value)>| {
            let mut rows = vec![("w".to_owned(), waiter.clone())];
            rows.extend(others.into_iter().map(|(id, health)| (id.to_owned(), health)));
            rows
        };
        // Held by a model that is paused or not answering: which one, and what to do.
        assert_eq!(reasons(&rows(vec![]), &["a".into()], name)["w"], "Model A still holds the GPU (paused or not answering). Resume or stop Model A to let this model load.");
        assert_eq!(reasons(&rows(vec![]), &["a".into(), "b".into()], name)["w"], "Paused or unresponsive models still hold the GPU: Model A, Model B. Resume or stop them to let this model load.");
        // Kept by a pinned model, loading or answering: named too.
        assert_eq!(reasons(&rows(vec![("p", pinned)]), &[], name)["w"], "Model P keeps the GPU because Prevent automatic model switching is on for it. Turn that off, or stop Model P, to let this model load.");
        assert_eq!(reasons(&rows(vec![("l", loading)]), &[], name)["w"], "Model L is loading into GPU memory. This model loads after it.");
        assert_eq!(reasons(&rows(vec![("b", busy.clone())]), &[], name)["w"], "Model B is using the GPU. This model loads once it is free.");
        // A model behind it in line waits for it.
        assert_eq!(reasons(&rows(vec![("b", busy), ("n", behind)]), &[], name)["n"], "Model W is first in line for the GPU. This model loads after it.");
        // One the scheduler grants now (an idle model is asked to unload) has nothing to explain,
        // and with nothing waiting there are no reasons left to show.
        assert!(!reasons(&rows(vec![("i", idle.clone())]), &[], name).contains_key("w"));
        assert!(reasons(&[("i".to_owned(), idle)], &[], name).is_empty());
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
