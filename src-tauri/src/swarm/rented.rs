//! Swarm workers whose model runs on a rented NeoCloud GPU.
//!
//! The worker's agent sandbox reaches the pod exactly as it reaches a model on this computer. Its
//! `swarm-model` name is the pod's private address, which the cloud bridge gives every connected
//! pod, and one one-way connection on port 8000 opens the pod's model server and nothing else. So
//! the sandbox, OpenCode and the tool check are the local ones. What differs is here:
//!
//! - a bounty's code goes to a rented GPU only when its host allowed it, and never from the public
//!   board, whose owners have not been asked;
//! - the pod is checked before every use and never rented or started from here;
//! - its model runs on vLLM with agent tool calling;
//! - the pod is stopped when its worker stops, leaves or is removed, and when Yougori quits. A stop
//!   is written down before it is tried, so one cut short by a closing app is finished on the next
//!   start, and how each one went stays on the Swarm page.
use super::{guest, load, update_if_current, write, Swarm, Worker};
use crate::{
    rented_gpu::{self, Entry, Ledger, Looked, Next, Record, Stopped},
    security::Event,
    store::PlatformStore,
    AppHandle,
};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tauri::Manager;
use tokio_util::sync::CancellationToken;

const TICK: Duration = Duration::from_secs(30);

/// Held by [`Swarm`].
#[derive(Default)]
pub(crate) struct Rented {
    /// The pods Swarm's workers use and the stops owed on them: the same ledger Neo Grid keeps for
    /// its own pods, in a file of its own.
    record: tokio::sync::Mutex<Option<Ledger>>,
    wake: tokio::sync::Notify,
}

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or_default()
}

fn path(app: &AppHandle) -> PathBuf {
    app.state::<PlatformStore>().data_folder("swarm").join("rented.json")
}

/// Reads the record once, changes it, and writes it back when `f` changed something. A record that
/// cannot be read is set aside and said on the page, never taken for an empty one.
async fn with_record<T>(app: &AppHandle, f: impl FnOnce(&mut Record) -> (T, bool)) -> T {
    rented_gpu::with_ledger(&app.state::<Swarm>().rented.record, &path(app), now(), f).await
}

/// Remembers that this worker runs its model on `pod`, so the pod is stopped when it is done.
async fn remember(app: &AppHandle, pod: &str, worker: &str) {
    with_record(app, |record| ((), record.remember(pod, worker))).await
}

/// The pods live workers run their models on, with each worker's name, or why Swarm's workers
/// could not be read. Paused workers keep theirs.
pub(crate) async fn in_use_checked(app: &AppHandle) -> Result<BTreeMap<String, String>, String> {
    load(app).await?;
    let manager = app.state::<Swarm>();
    let inner = manager.inner.lock().await;
    Ok(inner.rows.values()
        .filter(|worker| !matches!(worker.state.as_str(), "stopped" | "failed"))
        .filter_map(|worker| worker.rented_gpu.clone().map(|pod| (pod, worker.name.clone())))
        .collect())
}

/// `in_use_checked`, with workers that cannot be read taken as none. Right only where that errs
/// towards stopping, as Swarm's own stops do. Anything that decides a pod is free to take must use
/// `in_use_checked`, so not knowing is never read as nobody using it.
pub(crate) async fn in_use(app: &AppHandle) -> BTreeMap<String, String> {
    in_use_checked(app).await.unwrap_or_default()
}

/// The worker stopped, left or is being removed: its pod is stopped. The intent is written down
/// first and the stop then runs on its own, because a RunPod stop can take two minutes and a
/// Remove must answer at once. How it went is on the Swarm page; one cut short is finished later.
pub(crate) async fn release(app: &AppHandle, worker: &Worker) {
    let Some(pod) = worker.rented_gpu.clone() else { return };
    with_record(app, |record| {
        record.release(&pod, &worker.name);
        ((), true)
    }).await;
    app.state::<Swarm>().rented.wake.notify_one();
}

fn name_of(app: &AppHandle, pod_id: &str) -> String {
    rented_gpu::pod(app, pod_id).map(|pod| pod.name).unwrap_or_else(|| pod_id.to_owned())
}

/// Stops one recorded pod now and records how it went. A failed stop asks NeoCloud whether the pod
/// was already stopped outside Yougori before calling it a failure, except while quitting. One
/// stop at a time per pod, shared with Neo Grid's.
async fn stop(app: &AppHandle, pod_id: &str, quitting: bool) -> Result<Stopped, String> {
    let result = rented_gpu::settle_stop(app, &app.state::<Swarm>().rented.record, &path(app), pod_id, quitting, now()).await;
    crate::security::record(Event::new(if result.is_ok() { "swarm.rented.stopped" } else { "swarm.rented.stop_failed" }).text("pod", pod_id));
    result
}

/// Stops a recorded pod no live worker uses. It may never have been owed a stop (a worker that
/// failed while preparing, say), and a stop nobody owes is not sent, so it is owed first.
async fn stop_unused(app: &AppHandle, pod_id: &str, worker: &str) {
    let result = rented_gpu::owe_and_stop(app, &app.state::<Swarm>().rented.record, &path(app), pod_id, worker, now()).await;
    crate::security::record(Event::new(if result.is_ok() { "swarm.rented.stopped" } else { "swarm.rented.stop_failed" }).text("pod", pod_id));
}

/// One check of every pod Swarm recorded: stop those no live worker uses, never a Neo Grid pod,
/// and drop a record only on NeoCloud's word or Swarm's own stop.
async fn check(app: &AppHandle) {
    let live = in_use(app).await;
    let grid = crate::grid_neocloud::member_pods(app).await;
    let recorded: Vec<(String, Entry)> = with_record(app, |record| (record.pods.clone().into_iter().collect(), false)).await;
    // Each pod on its own, so one slow RunPod call does not hold up the others.
    futures_util::future::join_all(recorded.into_iter().map(|(pod_id, entry)| {
        let (live, grid) = (&live, &grid);
        async move {
            let state = rented_gpu::pod(app, &pod_id).map(|pod| pod.state);
            let used = live.contains_key(&pod_id) && !entry.stop;
            match rented_gpu::next(entry.stop, live.contains_key(&pod_id), grid.contains(&pod_id), state.as_deref()) {
                Next::Keep => {}
                Next::Forget => with_record(app, |record| ((), record.pods.remove(&pod_id).is_some())).await,
                Next::Stop => stop_unused(app, &pod_id, &entry.worker).await,
                Next::Check => match rented_gpu::after_look(rented_gpu::look(app, &pod_id).await, used) {
                    Looked::Stop => stop_unused(app, &pod_id, &entry.worker).await,
                    Looked::Settle(outcome) => {
                        let name = name_of(app, &pod_id);
                        with_record(app, |record| {
                            record.settle(&pod_id, &name, outcome, now());
                            ((), true)
                        }).await;
                    }
                },
            }
        }
    })).await;
}

/// Watches the recorded pods for as long as Yougori runs. Starts by finishing any stop that a
/// closing app cut short.
pub(crate) fn start(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let shutdown = crate::automation::shutdown_signal(&app);
        let swarm = app.state::<Swarm>();
        loop {
            check(&app).await;
            let wake = swarm.rented.wake.notified();
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = wake => {}
                _ = tokio::time::sleep(TICK) => {}
            }
        }
    });
}

/// Yougori is quitting with its environments: every Swarm pod that may be billing is stopped,
/// paused workers' included. A failure stays recorded and shows on the Swarm page at the next
/// start, which tries again.
pub(crate) async fn stop_on_quit(app: &AppHandle) {
    let recorded: BTreeMap<String, String> = with_record(app, |record| (record.pods.iter().map(|(pod, entry)| (pod.clone(), entry.worker.clone())).collect(), false)).await;
    let targets = rented_gpu::swarm_quit_targets(recorded, in_use(app).await, |pod| rented_gpu::pod(app, pod).is_some_and(|pod| rented_gpu::billing(&pod.state)));
    // Written first, then all sent at once: a quit that does not finish leaves them to the next start.
    rented_gpu::stop_all_owed(app, &app.state::<Swarm>().rented.record, &path(app), now(), &targets, true).await;
}

// ---- Preparation and readiness ----

/// The model's agent tool check, the same request a worker on this computer passes.
fn tool_check_request(model: &str) -> Value {
    json!({"model":model,"messages":[{"role":"user","content":"Use the worker_ready function once with ready=true. Do not perform any other task."}],"tools":[{"type":"function","function":{"name":"worker_ready","description":"Confirm the harmless agent tool check.","parameters":{"type":"object","properties":{"ready":{"type":"boolean"}},"required":["ready"],"additionalProperties":false}}}],"tool_choice":{"type":"function","function":{"name":"worker_ready"}},"max_tokens":128,"temperature":0})
}

/// The pod as it is now, or why it cannot run this worker's model.
async fn usable(app: &AppHandle, pod_id: &str, worker_id: &str, next: &str) -> Result<rented_gpu::Pod, String> {
    let pod = rented_gpu::pod(app, pod_id);
    let grid = crate::grid_neocloud::member_pods(app).await.contains(pod_id);
    let other = {
        let manager = app.state::<Swarm>();
        let inner = manager.inner.lock().await;
        inner.rows.values()
            .find(|worker| worker.id != worker_id && worker.rented_gpu.as_deref() == Some(pod_id) && !matches!(worker.state.as_str(), "stopped" | "failed"))
            .map(|worker| worker.name.clone())
    };
    match rented_gpu::refusal(pod.as_ref(), grid, other.as_deref(), next) {
        Some(reason) => Err(reason),
        None => pod.ok_or_else(|| "That NeoCloud pod no longer exists".into()),
    }
}

/// Starts the worker's model on its running pod with agent tool calling. A model already running
/// there without it, or with another tool-call parser, is restarted once; the pod itself is never
/// started from here.
async fn launch(app: &AppHandle, worker: &Worker, pod_id: &str) -> Result<(), String> {
    let run = || crate::model_runner::run_neocloud_agent_model(worker.model.clone(), pod_id.to_owned(), app.clone());
    match run().await {
        Err(error) if error.contains("without agent tool calling") || error.contains("different tool-call parser") => {
            crate::model_runner::stop_model(pod_id.to_owned(), app.clone()).await?;
            run().await.map(|_| ())
        }
        result => result.map(|_| ()),
    }
}

/// Waits for the model on the pod, saying what it is doing. The pod stopping meanwhile ends the
/// wait with that, never with a model error. Only the worker's stage is written, and only while
/// no control has changed it, so nothing else on the row is overwritten by this copy.
async fn wait_ready(app: &AppHandle, worker: &Worker, pod_id: &str, cancel: &CancellationToken, limit: Duration, next: &str) -> Result<bool, String> {
    let deadline = tokio::time::Instant::now() + limit;
    let mut unreachable = 0;
    let mut shown = worker.stage.clone();
    loop {
        if cancel.is_cancelled() {
            return Ok(false);
        }
        let pod = rented_gpu::pod(app, pod_id).ok_or("Your rented GPU no longer exists in NeoCloud. Remove this worker and create one with another GPU.")?;
        if !rented_gpu::running(&pod.state) {
            return Err(rented_gpu::not_running(&pod.name, &pod.state, next));
        }
        match crate::model_runner::model_status(pod_id.to_owned(), app.clone()).await {
            Ok(health) if health["status"] == "ready" => {
                if health["toolCalling"] != true {
                    return Err(format!("The model on your rented GPU {} was started without agent tool calling. Choose {next} to start it again with it.", pod.name));
                }
                return Ok(true);
            }
            Ok(health) if health["status"] == "error" => {
                let detail = health["error"].as_str().unwrap_or("it stopped while loading");
                return Err(format!("The model could not start on your rented GPU {}: {detail}. Check that the model fits its GPU memory, then choose {next}.", pod.name));
            }
            Ok(health) => {
                unreachable = 0;
                let doing = health["status"].as_str().unwrap_or("starting");
                let stage = format!("Rented GPU {}: model {doing}", pod.name);
                if shown != stage {
                    update_if_current(app, &worker.id, worker.generation, |w| w.stage = stage.clone()).await?;
                    shown = stage;
                }
            }
            Err(error) => {
                unreachable += 1;
                if unreachable >= 12 {
                    return Err(format!("Cannot reach your rented GPU {} ({error}). Check it in NeoCloud, then choose {next}.", pod.name));
                }
                // The pod's SSH session may have dropped; connecting again never powers it on.
                let _ = crate::commands::set_environment_status(pod_id.to_owned(), crate::models::EnvironmentStatus::Running, app.state(), app.state()).await;
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!("The model on your rented GPU {} did not become ready within {} minutes. Check it in NeoCloud, then choose {next}.", pod.name, limit.as_secs() / 60));
        }
        tokio::select! { _ = cancel.cancelled() => return Ok(false), _ = tokio::time::sleep(Duration::from_secs(5)) => {} }
    }
}

/// Preparation for a worker on a rented GPU. Called by `prepare` after its account checks and
/// after it let go of the shared preparation lock: this creates and adopts nothing on this
/// computer, and its wait for the pod must not hold up workers whose models run here.
pub(super) async fn prepare(app: &AppHandle, mut worker: Worker, config: &Value, cancel: &CancellationToken) -> Result<(), String> {
    let pod_id = worker.rented_gpu.clone().ok_or("This worker has no rented GPU")?;
    // A rented pod is never this worker's to create, adopt or tag.
    worker.owned_model = false;
    rented_gpu::bounty_allows(&worker.policy, worker.closed.is_some())?;
    let pod = usable(app, &pod_id, &worker.id, "Retry").await?;
    worker.stage = format!("Checking {} for agent tool calling on a rented GPU", worker.model.trim_start_matches("hf.co/"));
    write(app, worker.clone()).await?;
    tokio::select! {_=cancel.cancelled()=>return Ok(()),result=crate::model_runner::agent_preflight(&worker.model)=>result?};
    worker.quant = None;
    worker.model_environment_id = Some(pod_id.clone());
    write(app, worker.clone()).await?;
    remember(app, &pod_id, &worker.name).await;
    worker.stage = format!("Starting the model on your rented GPU {}", pod.name);
    write(app, worker.clone()).await?;
    tokio::select! {_=cancel.cancelled()=>return Ok(()),result=launch(app, &worker, &pod_id)=>result?};
    if !wait_ready(app, &worker, &pod_id, cancel, Duration::from_secs(3600), "Retry").await? {
        return Ok(());
    }
    // The sandbox names the pod at the address its bridge answers on, and gets the model's own key
    // for this pod and nothing broader.
    let environment = app.state::<PlatformStore>().environment(&pod_id)?;
    if rented_gpu::model_address(&environment).is_none() {
        return Err("This rented GPU's private address could not be confirmed, so the worker was not connected to it. Nothing was changed; tell Yougori support.".into());
    }
    let options = app.state::<crate::runtime::RuntimeManager>().workload_options(&pod_id)?;
    if !rented_gpu::guest_key_is_model_key(&options) {
        return Err("This rented GPU's model key is not the model's own key, so it was not given to the worker's sandbox. Nothing was changed; tell Yougori support.".into());
    }
    worker.stage = "Checking your model's agent tool calling".into();
    write(app, worker.clone()).await?;
    let check = tokio::select! {_=cancel.cancelled()=>return Ok(()),result=crate::model_runner::model_request(app,&pod_id,"/v1/chat/completions",Some(tool_check_request(&worker.model)))=>result?};
    if !guest::tool_check(&check) {
        return Err("The model loaded on your rented GPU, but did not complete the agent tool check. Choose another model from the list.".into());
    }
    worker.stage = "Preparing OpenCode and its private model connection".into();
    write(app, worker.clone()).await?;
    guest::prepare_agent(app, &mut worker, cancel).await?;
    let Some(connection) = &worker.closed else {
        // prepare_worker refuses this; nothing of the public board's is touched if it ever slips.
        let _ = config;
        return Err(rented_gpu::PUBLIC_REFUSAL.into());
    };
    connection.request("POST", "/api/swarm/agent/activate", Some(&json!({"idempotencyKey":format!("activate-{}",worker.id)}))).await?;
    worker.state = "preparing_bounty".into();
    worker.stage = "Preparing your private target sandbox".into();
    write(app, worker).await
}

/// Before each use of the model: the pod must be running, with the model ready to call tools.
/// Never starts or rents the pod; a stopped one pauses the worker with what to do.
pub(crate) async fn ensure_ready(app: &AppHandle, worker: &Worker, cancel: &CancellationToken) -> Result<(), String> {
    let pod_id = worker.rented_gpu.as_deref().ok_or("This worker has no rented GPU")?;
    // `worker.policy` is this computer's copy of the host's terms, not the host's live one, here
    // and in `prepare`. A host who withdraws the rented-GPU permission is seen at the runner's next
    // `execution_authorized` check, which stops the worker; until then a resume can start the model
    // on the pod. One check wide, and the only place where withdrawing it is not immediate.
    rented_gpu::bounty_allows(&worker.policy, worker.closed.is_some())?;
    let pod = usable(app, pod_id, &worker.id, "Resume").await?;
    // The worker takes its pod back, before anything else: a stop owed from the page's Stop would
    // otherwise survive a Resume, and the check loop would stop the pod under the resumed worker.
    remember(app, pod_id, &worker.name).await;
    if let Ok(health) = crate::model_runner::model_status(pod_id.to_owned(), app.clone()).await {
        if health["status"] == "ready" && health["toolCalling"] == true {
            return Ok(());
        }
    }
    if cancel.is_cancelled() {
        return Err("Worker model preparation cancelled".into());
    }
    update_if_current(app, &worker.id, worker.generation, |w| w.stage = format!("Starting the model on your rented GPU {}", pod.name)).await?;
    launch(app, worker, pod_id).await?;
    if wait_ready(app, worker, pod_id, cancel, Duration::from_secs(1800), "Resume").await? {
        Ok(())
    } else {
        Err("Worker model preparation cancelled".into())
    }
}

// ---- The Swarm page ----

/// Each worker's rented GPU with what it costs and does, the pods a new worker could use, and how
/// the latest stops went.
pub(crate) async fn status(app: &AppHandle) -> Result<Value, String> {
    load(app).await?;
    let rows: Vec<(String, String, String, String)> = {
        let manager = app.state::<Swarm>();
        let inner = manager.inner.lock().await;
        inner.rows.values().filter_map(|worker| worker.rented_gpu.clone().map(|pod| (worker.id.clone(), worker.name.clone(), worker.state.clone(), pod))).collect()
    };
    let grid = crate::grid_neocloud::member_pods(app).await;
    let live = in_use(app).await;
    let (mut hourly, mut unpriced) = (0.0, 0);
    let workers: Vec<Value> = rows.iter().map(|(id, name, state, pod_id)| {
        let pod = rented_gpu::pod(app, pod_id);
        let billing = pod.as_ref().is_some_and(|pod| rented_gpu::billing(&pod.state));
        if let Some(pod) = pod.as_ref().filter(|_| billing) {
            // A price NeoCloud did not record is counted apart, never as nothing.
            hourly += pod.hourly_usd;
            unpriced += usize::from(pod.hourly_usd == 0.0);
        }
        json!({"workerId": id, "workerName": name, "workerState": state, "environmentId": pod_id,
            "name": pod.as_ref().map(|pod| pod.name.clone()), "gpu": pod.as_ref().map(|pod| pod.gpu.clone()),
            "gpuCount": pod.as_ref().map(|pod| pod.gpu_count), "hourlyUsd": pod.as_ref().map(|pod| pod.hourly_usd),
            "podState": pod.as_ref().map(|pod| pod.state.clone()).unwrap_or_else(|| "Deleted".into()), "billing": billing})
    }).collect();
    let candidates: Vec<Value> = rented_gpu::pods(app).into_iter()
        .filter(|(id, pod)| !grid.contains(id) && !live.contains_key(id) && !rented_gpu::leaving(&pod.state))
        .map(|(id, pod)| json!({"environmentId": id, "name": pod.name, "gpu": pod.gpu, "gpuCount": pod.gpu_count, "hourlyUsd": pod.hourly_usd, "podState": pod.state}))
        .collect();
    let notices = rented_gpu::ledger_notices(&app.state::<Swarm>().rented.record, &path(app), now()).await;
    Ok(json!({"workers": workers, "candidates": candidates, "hourlyUsd": hourly, "unpriced": unpriced, "notices": notices}))
}

/// Stops one worker's rented GPU now. A worker still working is paused first, so it never reads
/// as working on a stopped pod. The stop is written down before it is tried, like every other.
pub(crate) async fn stop_worker_gpu(app: &AppHandle, worker: &Worker) -> Result<Value, String> {
    let pod_id = worker.rented_gpu.clone().ok_or("This worker's model runs on this computer")?;
    pause_for_stop(app, worker).await?;
    let name = name_of(app, &pod_id);
    rented_gpu::owe(&app.state::<Swarm>().rented.record, &path(app), now(), &[(pod_id.clone(), worker.name.clone())]).await;
    Ok(stop_said(&name, &worker.name, &stop(app, &pod_id, false).await))
}

async fn pause_for_stop(app: &AppHandle, worker: &Worker) -> Result<(), String> {
    if !matches!(worker.state.as_str(), "paused" | "stopped" | "failed") {
        Box::pin(super::swarm_dispatch(json!({"action":"pause","workerId":worker.id}), app.clone())).await?;
    }
    Ok(())
}

/// What the page says about one worker's stop: stopped only when NeoCloud showed it stopped.
fn stop_said(name: &str, worker: &str, result: &Result<Stopped, String>) -> Value {
    match result {
        Ok(Stopped::Confirmed) => json!({"message": format!("{name} was stopped and {worker} paused. Start the GPU in NeoCloud, then choose Resume.")}),
        Ok(Stopped::Pending) => json!({"message": format!("The stop was sent; NeoCloud shows {name} stopping. Yougori checks it again shortly. {worker} is paused.")}),
        Err(error) => json!({"warning": format!("{name} could not be stopped ({error}). Stop it in NeoCloud to end its billing; Yougori keeps trying.")}),
    }
}

/// The page's one Stop: every worker's rented GPU that may be billing.
pub(crate) async fn stop_all(app: &AppHandle) -> Result<Value, String> {
    load(app).await?;
    let workers: Vec<Worker> = {
        let manager = app.state::<Swarm>();
        let inner = manager.inner.lock().await;
        inner.rows.values().filter(|worker| worker.rented_gpu.is_some()).cloned().collect()
    };
    let mut failed = Vec::new();
    // Each worker is paused first, then every pod is owed and stopped at once, so the last one does
    // not bill for the time the others' stops took. A worker that could not be paused keeps its pod.
    let mut pods = Vec::new();
    for worker in workers {
        let billing = worker.rented_gpu.as_deref().and_then(|pod| rented_gpu::pod(app, pod)).is_some_and(|pod| rented_gpu::billing(&pod.state));
        let Some(pod) = worker.rented_gpu.clone().filter(|_| billing) else { continue };
        match pause_for_stop(app, &worker).await {
            Ok(()) => pods.push((pod, worker.name.clone())),
            Err(error) => failed.push(format!("{}: {error}", worker.name)),
        }
    }
    let results = rented_gpu::stop_all_owed(app, &app.state::<Swarm>().rented.record, &path(app), now(), &pods, false).await;
    let mut stopped = 0;
    let mut pending = 0;
    for ((pod, worker), (_, result)) in pods.iter().zip(&results) {
        match result {
            Ok(Stopped::Confirmed) => stopped += 1,
            Ok(Stopped::Pending) => pending += 1,
            Err(_) => failed.push(stop_said(&name_of(app, pod), worker, result)["warning"].as_str().unwrap_or_default().to_owned()),
        }
    }
    if failed.is_empty() && pending > 0 {
        return Ok(json!({"message": format!("Every worker's rented GPU was sent a stop and its worker paused. NeoCloud still shows {pending} of them stopping; Yougori checks them again shortly.")}));
    }
    if failed.is_empty() {
        Ok(json!({"message": match stopped {
            0 => "No rented GPU was running.".to_owned(),
            1 => "1 rented GPU was stopped and its worker paused. Start it in NeoCloud, then choose Resume.".to_owned(),
            n => format!("{n} rented GPUs were stopped and their workers paused. Start them in NeoCloud, then choose Resume."),
        }}))
    } else {
        Ok(json!({"warning": failed.join(" ")}))
    }
}
