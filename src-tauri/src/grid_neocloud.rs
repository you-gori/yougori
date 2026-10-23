//! Rented NeoCloud GPUs in the Closed Neo Grid this computer hosts.
//!
//! A rented pod never runs Yougori. This computer's engine stands in for it: the hub admits the
//! pod as a member made ahead of time, so no company password travels; the stand-in checks in for
//! it every 30 seconds, starts the model the hub assigns on the pod through the pod's SSH session,
//! and serves the grid's jobs through that same session. Nothing is installed on the pod and no
//! tunnel is needed.
//!
//! Every pod is billed by the hour, so a grid takes at most [`MAX`] of them, one control stops
//! them all, and a pod is stopped whenever it leaves the grid: removed here, removed by the admin,
//! with the grid paused or deleted, or when Yougori quits with its environments. Nothing here rents
//! or starts a pod. Pods come from the NeoCloud flow, with its own price review and consent, and a
//! stopped pod stays stopped until its person starts it there.
use crate::{projects::secrets, rented_gpu::{billing, leaving, pod, pods, running, settled, Ledger, Pod, Record, Stopped}, security::Event, store::PlatformStore, AppHandle};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tauri::Manager;
use yougori_grid::{
    activity::Activity,
    hub::ModelReport,
    member::{self, Assignment, Instructions, MemberError, Membership, Outcome, WorkerEvent},
    net::HubAddress,
    policy::Decision,
};

/// The most rented GPUs one grid takes, each billed by the hour.
pub(crate) const MAX: usize = 8;
const TICK: Duration = Duration::from_secs(30);
/// A model that failed to start on a pod is tried again after this long, not every check-in.
const RETRY: Duration = Duration::from_secs(10 * 60);
const PLATFORM: &str = "neocloud";
/// Whose pod an owed stop is, in what the page says about it.
const OWNER: &str = "your Neo Grid";

/// One rented pod in the grid, as saved on disk. Its member token is in the OS vault.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Saved {
    environment_id: String,
    member_id: String,
    grid_id: String,
    grid_name: String,
    address: String,
    certificate: String,
    added_at: i64,
}

/// What a stand-in is doing now, for this computer's page and the hub's report.
#[derive(Clone, Debug)]
struct Live {
    /// The model the pod was asked to run, once it was asked.
    model: Option<String>,
    quant: Option<String>,
    /// One of the hub's model states, or `stopped` and `idle` for this page alone.
    state: String,
    reason: String,
    failed_at: Option<Instant>,
}

impl Default for Live {
    fn default() -> Self {
        Live { model: None, quant: None, state: "preparing".into(), reason: "Checking in with the grid".into(), failed_at: None }
    }
}

struct Worker {
    model: String,
    gate: tokio::sync::watch::Sender<bool>,
    task: tauri::async_runtime::JoinHandle<()>,
}

struct StandIn {
    saved: Saved,
    membership: Option<Membership>,
    live: Live,
    worker: Option<Worker>,
    starting: Option<tauri::async_runtime::JoinHandle<()>>,
    jobs: Arc<AtomicU64>,
}

impl StandIn {
    fn stop_worker(&mut self) {
        if let Some(worker) = self.worker.take() {
            // Closing the gate lets a reply in progress finish before the worker ends.
            let _ = worker.gate.send(false);
            worker.task.abort();
        }
    }
}

#[derive(Default)]
struct Inner {
    loaded: bool,
    /// Why the list of the grid's pods is left where it is (see `read_kept`): nothing is written
    /// over it, it is read again at the next use, and the page says so meanwhile.
    unread: Option<String>,
    members: BTreeMap<String, StandIn>,
    /// Why pods last left the grid on their own, shown once on this computer's page.
    notice: Option<String>,
}

#[derive(Default)]
pub struct RentedGpus {
    inner: tokio::sync::Mutex<Inner>,
    wake: tokio::sync::Notify,
    /// Stops owed on rented pods, kept on disk until NeoCloud confirms each, with how the latest
    /// went. The same ledger Swarm keeps for its own pods, in a file of its own.
    stops: tokio::sync::Mutex<Option<Ledger>>,
    /// Owed stops are being finished now; one pass at a time.
    settling: std::sync::atomic::AtomicBool,
}

fn folder(app: &AppHandle) -> PathBuf {
    app.state::<PlatformStore>().data_folder("grid")
}

fn path(app: &AppHandle) -> PathBuf {
    folder(app).join("neocloud.json")
}

/// Whether this computer runs the grid now.
#[derive(Debug, PartialEq)]
enum Hosting {
    Yes,
    /// Its hub is set up here but cannot start this minute (a port still held, the vault asleep).
    /// The grid module keeps trying; meanwhile pods check in, fail, and say so.
    NotNow,
    /// No grid runs here: none was created, it was deleted, or a rollout moved its hub aside.
    No,
}

/// Asks the grid module, never its files: a rollout can move the hub's record aside without
/// deleting the grid.
async fn hosting(app: &AppHandle) -> Hosting {
    let Ok(status) = crate::grid::grid_status(app.clone()).await else { return Hosting::NotNow };
    hosting_of(&status)
}

fn hosting_of(status: &Value) -> Hosting {
    if !status["hub"].is_null() {
        Hosting::Yes
    } else if !status["hubError"].is_null() {
        Hosting::NotNow
    } else {
        Hosting::No
    }
}

fn token_key(member_id: &str) -> String {
    format!("yougori-grid-neocloud-{member_id}")
}

/// Written the way the owed stops are: a power cut mid-write leaves the last good list, never a
/// truncated one that the next start would set aside, forgetting pods that may be billing.
fn persist(app: &AppHandle, rows: &[Saved]) -> Result<(), String> {
    crate::rented_gpu::write_kept(&path(app), &rows)
}

fn save(app: &AppHandle, inner: &Inner) -> Result<(), String> {
    if inner.unread.is_some() {
        return Err("Yougori cannot write its list of the grid's rented GPUs until it can read the one it has; see the note on this page".into());
    }
    persist(app, &inner.members.values().map(|member| member.saved.clone()).collect::<Vec<_>>())
}

fn stops_path(app: &AppHandle) -> PathBuf {
    folder(app).join("neocloud-stops.json")
}

/// The grid's owed stops, read once and written back when `f` changed them.
async fn with_stops<T>(app: &AppHandle, f: impl FnOnce(&mut Record) -> (T, bool)) -> T {
    crate::rented_gpu::with_ledger(&app.state::<RentedGpus>().stops, &stops_path(app), yougori_grid::now(), f).await
}

/// Writes down that these pods must be stopped, before any stop is tried.
async fn owe(app: &AppHandle, ids: &[String]) {
    let pods: Vec<(String, String)> = ids.iter().map(|id| (id.clone(), OWNER.to_owned())).collect();
    crate::rented_gpu::owe(&app.state::<RentedGpus>().stops, &stops_path(app), yougori_grid::now(), &pods).await;
}

/// Stops one owed pod and writes down how it went, one stop at a time per pod.
async fn stop_owed(app: &AppHandle, id: &str, quitting: bool) -> Result<Stopped, String> {
    crate::rented_gpu::settle_stop(app, &app.state::<RentedGpus>().stops, &stops_path(app), id, quitting, yougori_grid::now()).await
}

/// Lets the next pass start once this one ends, however it ends.
struct Settling<'a>(&'a std::sync::atomic::AtomicBool);

impl Drop for Settling<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// What an owed stop does now. A pod a Swarm worker runs its model on is that worker's now;
/// any other is stopped unless NeoCloud says it is not billing or is gone.
fn owed_next(swarm_uses: bool, state: Option<&str>) -> crate::rented_gpu::Next {
    if swarm_uses {
        return crate::rented_gpu::Next::Forget;
    }
    crate::rented_gpu::next(true, false, false, state)
}

/// Finishes every owed stop, all at once. A pod nobody could check stays owed and, after a few
/// tries in a row, says so on the page. Swarm's workers unreadable read as none: the pass then
/// stops what it owes, which is the side to err on when money is involved, and no worker runs
/// without its journal anyway.
async fn settle_owed(app: &AppHandle) {
    let owed: Vec<String> = with_stops(app, |record| (record.pods.keys().cloned().collect(), false)).await;
    if owed.is_empty() {
        return;
    }
    let swarm = crate::swarm::rented::in_use(app).await;
    futures_util::future::join_all(owed.iter().map(|id| {
        let swarm_uses = swarm.contains_key(id);
        async move {
            let state = pod(app, id).map(|pod| pod.state);
            match owed_next(swarm_uses, state.as_deref()) {
                crate::rented_gpu::Next::Keep => {}
                crate::rented_gpu::Next::Forget => with_stops(app, |record| ((), record.pods.remove(id).is_some())).await,
                crate::rented_gpu::Next::Stop => {
                    let _ = stop_owed(app, id, false).await;
                }
                crate::rented_gpu::Next::Check => match crate::rented_gpu::after_look(crate::rented_gpu::look(app, id).await, false) {
                    crate::rented_gpu::Looked::Stop => {
                        let _ = stop_owed(app, id, false).await;
                    }
                    crate::rented_gpu::Looked::Settle(outcome) => {
                        let name = pod(app, id).map(|pod| pod.name).unwrap_or_else(|| id.clone());
                        with_stops(app, |record| {
                            record.settle(id, &name, outcome, yougori_grid::now());
                            ((), true)
                        }).await;
                    }
                },
            }
        }
    })).await;
}

/// A pod that is out of the grid leaves this computer's list, and its stop is owed until NeoCloud
/// confirms it: a failed stop never loses track of a pod that may still be billing.
fn leave_member(inner: &mut Inner, stops: &mut Record, id: &str, reason: &str) -> Option<StandIn> {
    let member = inner.members.remove(id);
    stops.release(id, OWNER);
    inner.notice = Some(reason.to_owned());
    member
}

async fn leave(app: &AppHandle, id: &str, reason: &str) {
    let member = {
        let rented = app.state::<RentedGpus>();
        let mut inner = rented.inner.lock().await;
        let member = with_stops(app, |stops| (leave_member(&mut inner, stops, id, reason), true)).await;
        let _ = save(app, &inner);
        member
    };
    if let Some(mut member) = member {
        member.stop_worker();
        if let Some(starting) = member.starting.take() {
            starting.abort();
        }
        let _ = secrets::delete_secret(&token_key(&member.saved.member_id));
        crate::security::record(Event::new("grid.neocloud.removed").text("grid", &member.saved.grid_name).text("pod", id));
    }
    // The stop is owed now and the settle pass sends it. Sending it here would hold up every other
    // pod's check-in for as long as a RunPod stop takes, and the hub would mark them offline.
    app.state::<RentedGpus>().wake.notify_one();
}

/// A membership the vault could not give when this computer started is asked for again at every
/// check-in, so a vault that was briefly unavailable does not leave a pod billing and unserved.
fn retry_membership(member: &mut StandIn, restore: impl FnOnce(&Saved) -> Result<Membership, String>) -> Option<Membership> {
    if member.membership.is_some() {
        return member.membership.clone();
    }
    match restore(&member.saved) {
        Ok(membership) => {
            member.membership = Some(membership.clone());
            status(member, "preparing", "Checking in with the grid");
            Some(membership)
        }
        Err(error) => {
            status(member, "error", unreadable(&error));
            None
        }
    }
}

fn unreadable(error: &str) -> String {
    format!("This pod's grid membership could not be read ({error}). Yougori tries again every 30 seconds; if this lasts, remove the pod here and add it again. Until then it serves nothing, and a running pod is still billed.")
}

fn restore(saved: &Saved) -> Result<Membership, String> {
    let address: SocketAddr = saved.address.parse().map_err(|_| "The saved hub address is damaged")?;
    Membership::new(HubAddress::Direct(address), &saved.certificate, saved.member_id.clone(), secrets::resolve(&token_key(&saved.member_id))?)
}

async fn ensure_loaded(app: &AppHandle) {
    let rented = app.state::<RentedGpus>();
    let mut inner = rented.inner.lock().await;
    if inner.loaded {
        return;
    }
    // Unreadable is never an empty grid: the pods would be forgotten, unstopped at quit, free for
    // Swarm to take, and the next save would write the empty list over them. A file the disk would
    // not give is left as it is and read again at the next use. A damaged one is set aside with its
    // bytes kept and the page says so; the grid's hub still lists each pod as a member under its
    // NeoCloud name, which is the way back: remove those there and add the pods again.
    let rows: Vec<Saved> = match crate::rented_gpu::read_kept(&path(app), yougori_grid::now(), "its list of the rented GPUs in the grid") {
        Ok(rows) => rows,
        Err(unreadable) if unreadable.locked => {
            inner.unread = Some(unreadable.said);
            return;
        }
        Err(unreadable) => {
            inner.loaded = true;
            inner.unread = None;
            let said = format!("{} The grid's hub still lists those pods as members under their NeoCloud names: remove them there and add the pods again here.", unreadable.said);
            drop(inner);
            with_stops(app, |record| {
                record.note(said, true, yougori_grid::now());
                ((), true)
            }).await;
            return;
        }
    };
    inner.loaded = true;
    inner.unread = None;
    for saved in rows {
        let (membership, live) = match restore(&saved) {
            Ok(membership) => (Some(membership), Live::default()),
            Err(error) => (None, Live { state: "error".into(), reason: unreadable(&error), ..Live::default() }),
        };
        inner.members.insert(saved.environment_id.clone(), StandIn { saved, membership, live, worker: None, starting: None, jobs: Arc::default() });
    }
}

/// Why a pod may not join this grid, or nothing when it may. `worker` names a Swarm worker that
/// runs its model on the pod: a rented GPU serves the grid or one worker, never both.
fn refusal(members: usize, already: bool, pod: Option<&Pod>, worker: Option<&str>) -> Option<String> {
    if already {
        return Some("This pod is already in the grid.".into());
    }
    let Some(pod) = pod else {
        return Some("That NeoCloud pod no longer exists. Refresh the list and choose another.".into());
    };
    if !pod.serves {
        return Some("Only RunPod GPU pods can serve the grid's models; CPU pods and serverless endpoints cannot.".into());
    }
    if !settled(pod) {
        return Some(format!("{} is still being created in NeoCloud, or needs checking there. Add it once NeoCloud shows it Running or Stopped.", pod.name));
    }
    if leaving(&pod.state) {
        return Some("This pod is being deleted. Choose another, or rent one in NeoCloud.".into());
    }
    if let Some(worker) = worker {
        return Some(format!("{} runs the model for Swarm worker {worker}. Remove that worker first, or choose another pod.", pod.name));
    }
    if members >= MAX {
        return Some(format!("A grid takes at most {MAX} rented GPUs, each billed by the hour. Remove one before adding another."));
    }
    None
}

/// What a check-in answer means for a rented pod.
enum Next {
    /// The pod is out of the grid: stop it and forget it, saying why.
    Leave(&'static str),
    /// The admin scheduled the grid for deletion: serve nothing and stop the pod meanwhile.
    Pause,
    /// No model is assigned to this pod.
    Idle,
    Follow(Assignment),
    /// The hub could not be reached; try again on the next check-in.
    Retry(String),
    /// The hub answered with something this version cannot read: nothing changes on the pod, and
    /// the row says what to do.
    Unreadable(String),
}

fn next(answer: Result<Instructions, MemberError>) -> Next {
    match answer {
        Err(MemberError::Removed) => Next::Leave("The grid's admin removed a rented GPU from the grid, so it left this list. Yougori stops it if it is running."),
        Err(MemberError::Deleted) => Next::Leave("The grid was deleted, so its rented GPUs left this list. Yougori stops any that are running."),
        Err(MemberError::Failed(error)) => Next::Retry(error),
        Err(MemberError::Unreadable(said)) => Next::Unreadable(said),
        Ok(instructions) if instructions.paused_until.is_some() => Next::Pause,
        Ok(instructions) => match instructions.assignment {
            Some(assignment) => Next::Follow(assignment),
            None => Next::Idle,
        },
    }
}

/// Whether the plan's hours let a pod serve now. Nobody sits at a rented pod, so only its
/// schedule decides; a damaged schedule never serves.
fn may_serve(assignment: &Assignment) -> bool {
    assignment.policy().map(|policy| matches!(policy.decide_at(&chrono::Local::now(), &Activity::Nobody), Decision::Serve)).unwrap_or(false)
}

fn spawn_worker(app: &AppHandle, membership: Membership, model: String, environment_id: String, serve: bool, jobs: Arc<AtomicU64>) -> Worker {
    let (gate, receiver) = tokio::sync::watch::channel(serve);
    let connect = {
        let (app, id) = (app.clone(), environment_id);
        move || {
            let (app, id) = (app.clone(), id.clone());
            async move {
                let (io, api_key) = crate::model_runner::model_socket(&app, &id).await?;
                Ok(member::LocalModel { io: Box::new(io), api_key })
            }
        }
    };
    let events = move |event: WorkerEvent| {
        if let WorkerEvent::Finished(Outcome::Served { status }) = event {
            if status < 400 {
                jobs.fetch_add(1, Ordering::Relaxed);
            }
        }
    };
    let task = tauri::async_runtime::spawn(member::serve(membership, model.clone(), receiver, connect, events));
    Worker { model, gate, task }
}

/// Takes a pod out of this computer's list and the vault. The caller stops the pod.
async fn forget(app: &AppHandle, id: &str, notice: Option<&str>) {
    let rented = app.state::<RentedGpus>();
    let mut inner = rented.inner.lock().await;
    if let Some(mut member) = inner.members.remove(id) {
        member.stop_worker();
        if let Some(starting) = member.starting.take() {
            starting.abort();
        }
        let _ = secrets::delete_secret(&token_key(&member.saved.member_id));
        crate::security::record(Event::new("grid.neocloud.removed").text("grid", &member.saved.grid_name).text("pod", id));
    }
    if let Some(notice) = notice {
        inner.notice = Some(notice.to_owned());
    }
    let _ = save(app, &inner);
}

async fn set_live(app: &AppHandle, id: &str, change: impl FnOnce(&mut StandIn)) {
    let rented = app.state::<RentedGpus>();
    let mut inner = rented.inner.lock().await;
    if let Some(member) = inner.members.get_mut(id) {
        change(member);
    }
}

fn status(member: &mut StandIn, state: &str, reason: impl Into<String>) {
    member.live.state = state.into();
    member.live.reason = reason.into();
}

/// What the hub reads about a pod's model.
fn report(live: &Live, gpu: &str) -> Vec<ModelReport> {
    let Some(model) = live.model.clone() else { return Vec::new() };
    let state = match live.state.as_str() {
        "available" | "busy" | "outside_schedule" | "preparing" | "loading" | "error" => live.state.clone(),
        _ => "stopped".into(),
    };
    vec![ModelReport { model, state, reason: live.reason.clone(), quant: live.quant.clone(), gpu: Some(gpu.to_owned()), progress: None }]
}

async fn step(app: &AppHandle, id: &str, owed: bool) {
    let rented = app.state::<RentedGpus>();
    let (membership, live) = {
        let mut inner = rented.inner.lock().await;
        let Some(member) = inner.members.get_mut(id) else { return };
        (retry_membership(member, restore), member.live.clone())
    };
    let Some(pod) = pod(app, id) else {
        // NeoCloud's record no longer shows the pod's node, which NeoCloud allows once the pod is
        // deleted, or the record could not be read. A pod not seen is never taken as not billing:
        // leaving owes its stop, and the settle pass lets it go once NeoCloud confirms it is gone.
        if let Some(membership) = membership {
            let _ = membership.leave().await;
        }
        leave(app, id, "A rented GPU's NeoCloud node was removed, so it left the grid.").await;
        return;
    };
    if owed {
        // A stop this computer owes the pod (one that failed, or that a quit cut short) comes
        // first, and the pod reads as stopping, never stopped, until NeoCloud confirms it.
        set_live(app, id, |member| {
            member.stop_worker();
            status(member, "stopping", "Yougori is stopping this pod and tries again until NeoCloud confirms it. To serve the grid again, start it in NeoCloud once it has stopped.");
        }).await;
        return;
    }
    let Some(membership) = membership else { return };
    if leaving(&pod.state) {
        let _ = membership.leave().await;
        forget(app, id, Some("A rented GPU is being deleted in NeoCloud, so it left the grid.")).await;
        return;
    }
    if !running(&pod.state) {
        // A pod that is not running checks in with nothing, so the hub sees it offline within a
        // minute and gives its work to computers that are. Nothing here starts it.
        set_live(app, id, |member| {
            member.stop_worker();
            match pod.state.as_str() {
                "Creating" | "Starting" => status(member, "starting", "Starting in NeoCloud. It takes the grid's work once it runs."),
                "" => status(member, "stopped", "Not running in NeoCloud. Start it there to serve the grid again."),
                other => status(member, "stopped", format!("{other} in NeoCloud. Start it there to serve the grid again.")),
            }
        }).await;
        return;
    }
    let answer = membership.heartbeat(env!("CARGO_PKG_VERSION"), true, &report(&live, &pod.gpu)).await;
    match next(answer) {
        Next::Retry(error) => set_live(app, id, |member| status(member, "error", format!("Cannot reach this computer's grid hub ({error}). It tries again every 30 seconds."))).await,
        Next::Unreadable(said) => set_live(app, id, |member| status(member, "error", said)).await,
        Next::Leave(reason) => leave(app, id, reason).await,
        Next::Pause => {
            // Owed, like every other stop, and sent by the settle pass: written down if it fails,
            // never raced by another stop of the same pod, and never holding up this check-in.
            owe(app, &[id.to_owned()]).await;
            set_live(app, id, |member| {
                member.stop_worker();
                status(member, "stopping", "The grid is scheduled for deletion, so this pod is being stopped. After a restore, start it in NeoCloud.");
            }).await;
            app.state::<RentedGpus>().wake.notify_one();
        }
        Next::Idle => {
            let model_running = live.model.is_some();
            set_live(app, id, |member| {
                member.stop_worker();
                member.live.model = None;
                status(member, "idle", "No model is assigned to this pod. Assign one under Models, or stop the pod to end its billing.");
            }).await;
            if model_running {
                // On its own, so a slow pod does not hold up the other pods' check-ins.
                let (app, id) = (app.clone(), id.to_owned());
                tauri::async_runtime::spawn(async move {
                    let _ = crate::model_runner::stop_model(id, app).await;
                });
            }
        }
        Next::Follow(assignment) => follow(app, id, &pod, membership, assignment).await,
    }
}

/// What a check-in does about the pod's model.
#[derive(Debug, PartialEq)]
enum Launch {
    /// The model runs, or is starting, or waits out its retry.
    Keep,
    /// Start the assigned model.
    Start,
    /// Stop the model this stand-in started before, then start the assigned one.
    Replace,
}

/// `asked` is the model this stand-in last started on the pod. A pod runs one model and the
/// launcher refuses a second, so a new assignment first stops the one this stand-in started.
fn launch(asked: Option<&str>, assigned: &str, retry_due: bool) -> Launch {
    match asked {
        Some(old) if old != assigned => Launch::Replace,
        None => Launch::Start,
        Some(_) if retry_due => Launch::Start,
        Some(_) => Launch::Keep,
    }
}

async fn follow(app: &AppHandle, id: &str, pod: &Pod, membership: Membership, assignment: Assignment) {
    let rented = app.state::<RentedGpus>();
    let (asked, starting, failed_at) = {
        let inner = rented.inner.lock().await;
        let Some(member) = inner.members.get(id) else { return };
        (member.live.model.clone(), member.starting.as_ref().is_some_and(|task| !task.inner().is_finished()), member.live.failed_at)
    };
    let plan = launch(asked.as_deref(), &assignment.model, failed_at.is_some_and(|at| at.elapsed() >= RETRY));
    if plan != Launch::Keep {
        let model = assignment.model.clone();
        let previous = asked.filter(|_| plan == Launch::Replace);
        let task = {
            let (app, id, model) = (app.clone(), id.to_owned(), model.clone());
            tauri::async_runtime::spawn(async move {
                if let Some(previous) = previous {
                    if let Err(error) = crate::model_runner::stop_model(id.clone(), app.clone()).await {
                        set_live(&app, &id, |member| {
                            member.live.failed_at = Some(Instant::now());
                            status(member, "error", format!("{previous} still runs on the pod and could not be stopped for {model} ({error}). It is tried again in 10 minutes."));
                        }).await;
                        return;
                    }
                }
                let result = crate::model_runner::run_neocloud_model(model.clone(), id.clone(), None, app.clone()).await;
                set_live(&app, &id, |member| match result {
                    Ok(_) => status(member, "loading", format!("Starting {model} on the pod")),
                    Err(error) => {
                        member.live.failed_at = Some(Instant::now());
                        status(member, "error", format!("{model} did not start on the pod: {error}"));
                    }
                }).await;
            })
        };
        set_live(app, id, |member| {
            member.stop_worker();
            if let Some(previous) = member.starting.replace(task) {
                previous.abort();
            }
            member.live.model = Some(assignment.model.clone());
            member.live.quant = assignment.quant.clone();
            member.live.failed_at = None;
            status(member, "preparing", format!("Starting {} on the pod", assignment.model));
        }).await;
        return;
    }
    if starting || failed_at.is_some() {
        return;
    }
    // Ask the pod how its model is doing before giving it any of the grid's work.
    let health = crate::model_runner::model_status(id.to_owned(), app.clone()).await;
    let serve = may_serve(&assignment);
    set_live(app, id, |member| match health {
        Ok(health) if crate::grid::ready(&health) => {
            if member.worker.as_ref().is_none_or(|worker| worker.model != assignment.model) {
                member.stop_worker();
                member.worker = Some(spawn_worker(app, membership, assignment.model.clone(), id.to_owned(), serve, member.jobs.clone()));
            } else if let Some(worker) = &member.worker {
                worker.gate.send_if_modified(|gate| std::mem::replace(gate, serve) != serve);
            }
            if serve {
                status(member, "available", format!("Serving {} on {}", assignment.model, pod.gpu));
            } else {
                status(member, "outside_schedule", "Ready, outside the plan's hours");
            }
        }
        Ok(health) => {
            member.stop_worker();
            let reason = crate::grid::progress(&health).map(|progress| crate::grid::describe(&progress)).unwrap_or_else(|| "Loading the model".into());
            if health["status"] == "error" {
                member.live.failed_at = Some(Instant::now());
                status(member, "error", health["error"].as_str().unwrap_or("The model stopped on the pod. It is started again in 10 minutes.").to_owned());
            } else {
                status(member, "loading", reason);
            }
        }
        Err(error) => {
            member.stop_worker();
            status(member, "error", format!("The pod's model did not answer ({error}). Check the pod in NeoCloud."));
        }
    }).await;
}

async fn tick(app: &AppHandle) {
    ensure_loaded(app).await;
    // Owed stops finish on their own, so a slow RunPod call never delays a check-in.
    if !app.state::<RentedGpus>().settling.swap(true, Ordering::AcqRel) {
        let app = app.clone();
        tauri::async_runtime::spawn(async move {
            let rented = app.state::<RentedGpus>();
            let _pass = Settling(&rented.settling);
            settle_owed(&app).await;
        });
    }
    let ids: Vec<String> = app.state::<RentedGpus>().inner.lock().await.members.keys().cloned().collect();
    if ids.is_empty() {
        return;
    }
    if hosting(app).await == Hosting::No {
        // No grid runs on this computer now (deleted, or moved aside by a rollout): nothing can
        // give these pods work, so none is left billing. Their stops are owed here and sent by the
        // settle pass, never inside this loop. They stay listed, to remove here or to serve again
        // once the grid runs and their person starts them.
        let workers = crate::swarm::rented::in_use(app).await;
        let (ids, owed_now) = owe_all(app, &workers).await;
        let owed: std::collections::BTreeSet<String> = with_stops(app, |record| (record.pods.keys().cloned().collect(), false)).await;
        for id in &ids {
            let (state, text) = waiting_status(owed.contains(id), workers.get(id).map(String::as_str), "No grid runs on this computer, so this pod is stopped. Remove it here, or start it in NeoCloud once the grid runs again.");
            set_live(app, id, |member| status(member, state, text)).await;
        }
        let rented = app.state::<RentedGpus>();
        rented.inner.lock().await.notice = Some("No grid runs on this computer, so its rented GPUs are stopped.".into());
        // Only for a stop owed just now: the settle pass starts at the top of the next tick.
        if owed_now {
            rented.wake.notify_one();
        }
        return;
    }
    let owed: std::collections::BTreeSet<String> = with_stops(app, |record| (record.pods.keys().cloned().collect(), false)).await;
    // Each pod checks in on its own: one slow pod must not keep the others past the hub's
    // online window.
    futures_util::future::join_all(ids.iter().map(|id| step(app, id, owed.contains(id)))).await;
}

pub(crate) fn start(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let shutdown = crate::automation::shutdown_signal(&app);
        loop {
            let rented = app.state::<RentedGpus>();
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = rented.wake.notified() => {}
                _ = tokio::time::sleep(TICK) => {}
            }
            tick(&app).await;
        }
        let rented = app.state::<RentedGpus>();
        let mut inner = rented.inner.lock().await;
        for member in inner.members.values_mut() {
            member.stop_worker();
        }
    });
}

/// Whether the grid's stop reaches this pod: never one a Swarm worker runs its model on.
fn stops(id: &str, workers: &BTreeMap<String, String>) -> bool {
    !workers.contains_key(id)
}

/// The pods in the grid this computer hosts, which Swarm leaves alone.
pub(crate) async fn member_pods(app: &AppHandle) -> std::collections::BTreeSet<String> {
    ensure_loaded(app).await;
    app.state::<RentedGpus>().inner.lock().await.members.keys().cloned().collect()
}

/// What a pod's row says after a stop: stopped only when it was, otherwise why not and what to do.
/// `result` is the stop's, or nothing when the pod was not billing or not the grid's to stop.
fn stopped_status(result: Option<&Result<Stopped, String>>, swarm: Option<&str>, reason: &str) -> (&'static str, String) {
    match (result, swarm) {
        (Some(Err(error)), _) => ("error", format!("It could not be stopped ({error}). Stop it in NeoCloud to end its billing; Yougori keeps trying.")),
        (Some(Ok(Stopped::Pending)), _) => ("stopping", "The stop was sent; NeoCloud shows it stopping. Yougori checks it again shortly.".to_owned()),
        (None, Some(worker)) => ("error", format!("Swarm worker {worker} runs its model on this pod, so the grid left it running. Stop that worker to stop it.")),
        _ => ("stopped", reason.to_owned()),
    }
}

/// What a pod's row says while its stop is owed and not sent yet, or once nothing is owed.
fn waiting_status(owed: bool, swarm: Option<&str>, reason: &str) -> (&'static str, String) {
    match swarm {
        _ if owed => ("stopping", "Yougori is stopping this pod and tries again until NeoCloud confirms it.".to_owned()),
        Some(worker) => ("error", format!("Swarm worker {worker} runs its model on this pod, so the grid left it running. Stop that worker to stop it.")),
        None => ("stopped", reason.to_owned()),
    }
}

/// Owes a stop for every billing pod in the grid not owed one already, except one a Swarm worker
/// runs its model on, and stops their workers. Returns every pod in the grid, and whether anything
/// new is owed. A stop already owed is left as it is, so its count of unanswered checks goes on.
async fn owe_all(app: &AppHandle, workers: &BTreeMap<String, String>) -> (Vec<String>, bool) {
    ensure_loaded(app).await;
    let ids: Vec<String> = {
        let rented = app.state::<RentedGpus>();
        let mut inner = rented.inner.lock().await;
        for member in inner.members.values_mut() {
            member.stop_worker();
        }
        inner.members.keys().cloned().collect()
    };
    let owed: std::collections::BTreeSet<String> = with_stops(app, |record| (record.pods.iter().filter(|(_, entry)| entry.stop).map(|(id, _)| id.clone()).collect(), false)).await;
    let targets: Vec<String> = ids.iter().filter(|id| !owed.contains(*id) && stops(id, workers) && pod(app, id).is_some_and(|pod| billing(&pod.state))).cloned().collect();
    owe(app, &targets).await;
    (ids, !targets.is_empty())
}

/// Stops every rented pod in the grid, all at once; they stay in it, offline. Each stop is owed
/// first, so one that fails is tried again until NeoCloud confirms it. Returns the ones that could
/// not be stopped, and how many NeoCloud still shows stopping.
async fn stop_all(app: &AppHandle, reason: &str) -> (Vec<String>, usize) {
    let workers = crate::swarm::rented::in_use(app).await;
    let (ids, _) = owe_all(app, &workers).await;
    let owed: Vec<String> = with_stops(app, |record| (record.pods.iter().filter(|(_, entry)| entry.stop).map(|(id, _)| id.clone()).collect(), false)).await;
    let targets: Vec<(String, String)> = ids.iter().filter(|id| owed.contains(id)).map(|id| (id.clone(), OWNER.to_owned())).collect();
    let results: BTreeMap<String, Result<Stopped, String>> = futures_util::future::join_all(targets.iter().map(|(id, _)| async move { (id.clone(), stop_owed(app, id, false).await) })).await.into_iter().collect();
    let mut failed = Vec::new();
    let mut pending = 0;
    for id in &ids {
        let result = results.get(id);
        match result {
            Some(Err(error)) => failed.push(format!("{}: {error}", pod(app, id).map(|pod| pod.name).unwrap_or_else(|| id.clone()))),
            Some(Ok(Stopped::Pending)) => pending += 1,
            _ => {}
        }
        let (state, text) = stopped_status(result, workers.get(id).map(String::as_str), reason);
        set_live(app, id, |member| status(member, state, text)).await;
    }
    (failed, pending)
}

/// Stop all, as the dashboard and the command line both report it. A warning means a pod may
/// still be billing.
pub(crate) async fn stop_all_value(app: &AppHandle) -> Result<Value, String> {
    let (failed, pending) = stop_all(app, "Stopped from this page. Start it in NeoCloud to serve the grid again.").await;
    if failed.is_empty() && pending > 0 {
        Ok(json!({"message": format!("Every rented GPU in the grid was sent a stop. NeoCloud still shows {pending} of them stopping; Yougori checks them again shortly. They stay in the grid, offline, until you start them in NeoCloud.")}))
    } else if failed.is_empty() {
        Ok(json!({"message": "Every rented GPU in the grid was stopped. They stay in the grid, offline, until you start them in NeoCloud."}))
    } else {
        Ok(json!({"warning": format!("Some rented GPUs could not be stopped; stop them in NeoCloud to end their billing: {}", failed.join("; "))}))
    }
}

/// The pods quitting stops: every billing pod in the grid and every stop still owed. One Swarm also
/// claims is stopped too: the shared gate makes a second stop of a pod harmless, while leaving it
/// to the other side let a pod both sides claimed go unstopped by either.
fn quit_targets(members: &[String], owed: &[String], billing_now: impl Fn(&str) -> bool) -> Vec<String> {
    let targets: std::collections::BTreeSet<&String> = members.iter().chain(owed).filter(|id| billing_now(id)).collect();
    targets.into_iter().cloned().collect()
}

/// Yougori is quitting with its environments: every rented pod that may be billing is stopped.
/// The stops are written down first and then all sent at once, because each is a RunPod call of
/// up to two minutes and quitting has thirty seconds. One that does not finish is finished at
/// the next start, and the page says how each went.
pub(crate) async fn stop_on_quit(app: &AppHandle) {
    ensure_loaded(app).await;
    let members: Vec<String> = {
        let rented = app.state::<RentedGpus>();
        let mut inner = rented.inner.lock().await;
        for member in inner.members.values_mut() {
            member.stop_worker();
        }
        inner.members.keys().cloned().collect()
    };
    let owed: Vec<String> = with_stops(app, |record| (record.pods.keys().cloned().collect(), false)).await;
    let targets: Vec<(String, String)> = quit_targets(&members, &owed, |id| pod(app, id).is_some_and(|pod| billing(&pod.state))).into_iter().map(|id| (id, OWNER.to_owned())).collect();
    crate::rented_gpu::stop_all_owed(app, &app.state::<RentedGpus>().stops, &stops_path(app), yougori_grid::now(), &targets, true).await;
}

pub(crate) async fn status_value(app: &AppHandle) -> Result<Value, String> {
    ensure_loaded(app).await;
    let hosting = hosting(app).await == Hosting::Yes;
    let notices = crate::rented_gpu::ledger_notices(&app.state::<RentedGpus>().stops, &stops_path(app), yougori_grid::now()).await;
    // Read before the grid's lock is taken: Swarm's own lock is never held inside it. Unreadable,
    // the list may offer a worker's pod, which adding refuses.
    let workers = crate::swarm::rented::in_use(app).await;
    let rented = app.state::<RentedGpus>();
    let inner = rented.inner.lock().await;
    let (mut hourly, mut unpriced) = (0.0, 0);
    let members: Vec<Value> = inner.members.iter().map(|(id, member)| {
        let pod = pod(app, id);
        if let Some(pod) = pod.as_ref().filter(|pod| billing(&pod.state)) {
            // A price NeoCloud did not record is counted apart, never as nothing.
            hourly += pod.hourly_usd;
            unpriced += usize::from(pod.hourly_usd == 0.0);
        }
        json!({
            "environmentId": id,
            "memberId": member.saved.member_id,
            "name": pod.as_ref().map(|pod| pod.name.clone()).unwrap_or_else(|| id.clone()),
            "gpu": pod.as_ref().map(|pod| pod.gpu.clone()),
            "gpuCount": pod.as_ref().map(|pod| pod.gpu_count),
            "hourlyUsd": pod.as_ref().map(|pod| pod.hourly_usd),
            "podState": pod.as_ref().map(|pod| pod.state.clone()),
            "state": member.live.state,
            "reason": member.live.reason,
            "model": member.live.model,
            "jobs": member.jobs.load(Ordering::Relaxed),
        })
    }).collect();
    let candidates: Vec<Value> = pods(app).into_iter()
        .filter(|(id, pod)| !inner.members.contains_key(id) && !workers.contains_key(id) && !leaving(&pod.state))
        .map(|(id, pod)| json!({"environmentId": id, "name": pod.name, "gpu": pod.gpu, "gpuCount": pod.gpu_count, "hourlyUsd": pod.hourly_usd, "podState": pod.state}))
        .collect();
    let mut notices = notices;
    notices.extend(inner.unread.iter().map(|text| crate::rented_gpu::Notice { at: yougori_grid::now(), text: text.clone(), warning: true }));
    Ok(json!({"hosting": hosting, "max": MAX, "hourlyUsd": hourly, "unpriced": unpriced, "members": members, "candidates": candidates, "notice": inner.notice, "notices": notices}))
}

pub(crate) async fn add(app: &AppHandle, id: &str) -> Result<Value, String> {
    ensure_loaded(app).await;
    if hosting(app).await != Hosting::Yes {
        return Err("Host a grid on this computer first; rented GPUs join the grid it hosts.".into());
    }
    let (count, already) = {
        let rented = app.state::<RentedGpus>();
        let inner = rented.inner.lock().await;
        (inner.members.len(), inner.members.contains_key(id))
    };
    let pod = pod(app, id);
    let workers = crate::swarm::rented::in_use_checked(app).await.map_err(|error| format!("Yougori could not read which rented GPUs Swarm's workers use ({error}), so it cannot tell whether one uses this pod. Nothing was changed; try again in a moment."))?;
    if let Some(reason) = refusal(count, already, pod.as_ref(), workers.get(id).map(String::as_str)) {
        return Err(reason);
    }
    let pod = pod.ok_or("That NeoCloud pod no longer exists")?;
    let (made, address, company) = crate::grid::with_hub(app, |hub| {
        let record = hub.record();
        let address = SocketAddr::new(record.address, hub.address().port());
        Ok((hub.preregister_member(&pod.name, PLATFORM)?, address, record.name))
    }).await?;
    let member_id = made["memberId"].as_str().ok_or("The hub did not admit the pod")?.to_owned();
    let token = made["memberToken"].as_str().ok_or("The hub did not admit the pod")?.to_owned();
    let fingerprint = made["fingerprint"].as_str().unwrap_or_default().to_owned();
    let undo = |app: AppHandle, member_id: String| async move {
        let _ = crate::grid::with_hub(&app, |hub| hub.remove_member(&member_id)).await;
    };
    let joined = match member::adopt(&company, HubAddress::Direct(address), &fingerprint, &member_id, &token).await {
        Ok(joined) => joined,
        Err(error) => {
            undo(app.clone(), member_id).await;
            return Err(format!("The grid could not admit the pod ({error}). Nothing was changed; try again."));
        }
    };
    let saved = Saved {
        environment_id: id.to_owned(),
        member_id: member_id.clone(),
        grid_id: joined.grid_id.clone(),
        grid_name: joined.grid_name.clone(),
        address: address.to_string(),
        certificate: joined.certificate.clone(),
        added_at: yougori_grid::now(),
    };
    let rented = app.state::<RentedGpus>();
    let mut inner = rented.inner.lock().await;
    // A second add of the same pod, or one past the cap, may have finished meanwhile.
    if let Some(reason) = refusal(inner.members.len(), inner.members.contains_key(id), Some(&pod), workers.get(id).map(String::as_str)) {
        drop(inner);
        undo(app.clone(), member_id).await;
        return Err(reason);
    }
    if let Err(error) = secrets::store(&token_key(&member_id), &joined.token) {
        drop(inner);
        undo(app.clone(), member_id).await;
        return Err(format!("The pod's grid membership could not be saved in the OS vault ({error}). Nothing was changed."));
    }
    inner.members.insert(id.to_owned(), StandIn { saved: saved.clone(), membership: Some(joined.membership), live: Live::default(), worker: None, starting: None, jobs: Arc::default() });
    inner.notice = None;
    if let Err(error) = save(app, &inner) {
        inner.members.remove(id);
        drop(inner);
        let _ = secrets::delete_secret(&token_key(&member_id));
        undo(app.clone(), member_id).await;
        return Err(format!("The pod could not be saved on this computer ({error}). Nothing was changed."));
    }
    drop(inner);
    // Added back on purpose: a stop still owed from when it left is not finished now. One already on
    // its way finishes first and says so on this page.
    crate::rented_gpu::withdraw_stop(&rented.stops, &stops_path(app), id, yougori_grid::now()).await;
    crate::security::record(Event::new("grid.neocloud.added").text("grid", &saved.grid_name).text("pod", id));
    rented.wake.notify_one();
    Ok(json!({"added": id, "message": format!("{} joined the grid. Assign it a model under Models; it serves once the model is ready.", pod.name)}))
}

/// Whether a pod leaving the grid may be billing. One NeoCloud's record does not show is never taken
/// as stopped: the record may not have been readable, and its stop finds out.
fn may_bill(pod: Option<&Pod>) -> bool {
    pod.is_none_or(|pod| billing(&pod.state))
}

pub(crate) async fn remove(app: &AppHandle, id: &str) -> Result<Value, String> {
    ensure_loaded(app).await;
    let membership = {
        let rented = app.state::<RentedGpus>();
        let inner = rented.inner.lock().await;
        let member = inner.members.get(id).ok_or("That pod is not in the grid")?;
        member.membership.clone().map(|membership| (membership, member.saved.member_id.clone()))
    };
    if let Some((membership, member_id)) = membership {
        if membership.leave().await.is_err() {
            // The hub is this computer's own; take the member out there directly.
            let _ = crate::grid::with_hub(app, |hub| hub.remove_member(&member_id)).await;
        }
    }
    // Owed before it leaves the list, so a stop that fails is still tracked and tried again.
    let seen = pod(app, id);
    let billing_now = may_bill(seen.as_ref());
    if billing_now {
        owe(app, &[id.to_owned()]).await;
    }
    forget(app, id, None).await;
    if !billing_now {
        return Ok(json!({"removed": id, "message": "The pod left the grid. It was not running, so nothing needed stopping; its disk stays in NeoCloud until you delete it there."}));
    }
    match stop_owed(app, id, false).await {
        Ok(Stopped::Confirmed) if seen.is_none() => Ok(json!({"removed": id, "message": "The pod left the grid. NeoCloud no longer shows its node, so there was nothing to stop."})),
        Ok(Stopped::Confirmed) => Ok(json!({"removed": id, "message": "The pod left the grid and was stopped. Its disk stays in NeoCloud until you delete it there."})),
        Ok(Stopped::Pending) => Ok(json!({"removed": id, "message": "The pod left the grid. The stop was sent; NeoCloud shows it stopping, and Yougori checks it again shortly. Its disk stays in NeoCloud until you delete it there."})),
        Err(error) => Ok(json!({"removed": id, "warning": format!("The pod left the grid, but it could not be stopped ({error}). Yougori keeps trying and shows how it goes on this page; stop it in NeoCloud to end its billing now.")})),
    }
}

/// The rented GPUs as the dashboard drives them, only from the main window.
pub(crate) mod commands {
    use super::*;
    use crate::WebviewWindow;

    fn main_window(window: &WebviewWindow) -> Result<(), String> {
        if window.label() == "main" { Ok(()) } else { Err("Closed Neo Grid is managed from the main Yougori window".into()) }
    }

    #[tauri::command]
    pub async fn grid_neocloud_status(app: AppHandle, window: WebviewWindow) -> Result<Value, String> {
        main_window(&window)?;
        status_value(&app).await
    }

    #[tauri::command]
    pub async fn grid_neocloud_add(app: AppHandle, window: WebviewWindow, environment_id: String) -> Result<Value, String> {
        main_window(&window)?;
        add(&app, &environment_id).await
    }

    #[tauri::command]
    pub async fn grid_neocloud_remove(app: AppHandle, window: WebviewWindow, environment_id: String) -> Result<Value, String> {
        main_window(&window)?;
        remove(&app, &environment_id).await
    }

    /// Stops every rented pod in the grid; they stay in it, offline, until started in NeoCloud.
    #[tauri::command]
    pub async fn grid_neocloud_stop_all(app: AppHandle, window: WebviewWindow) -> Result<Value, String> {
        main_window(&window)?;
        stop_all_value(&app).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{neocloud::Deployment, rented_gpu::pod_of};

    fn gpu_pod(state: &str) -> Pod {
        Pod { name: "Pod".into(), gpu: "NVIDIA RTX 4090".into(), gpu_count: 1, hourly_usd: 0.69, state: state.into(), serves: true, known: true }
    }

    fn instructions(assignment: Option<Assignment>, paused_until: Option<i64>) -> Instructions {
        Instructions { assignment, grid_name: "Acme".into(), desks: Vec::new(), paused_until, parking: None }
    }

    fn assignment(model: &str) -> Assignment {
        Assignment { plan_id: "plan-1".into(), model: model.into(), quant: None, idle_after_minutes: 0, schedule: None }
    }

    #[test]
    fn the_cap_holds_at_eight_rented_gpus() {
        assert_eq!(MAX, 8);
        assert!(refusal(MAX - 1, false, Some(&gpu_pod("Running")), None).is_none());
        let refused = refusal(MAX, false, Some(&gpu_pod("Running")), None).expect("the ninth pod is refused");
        assert!(refused.contains("at most 8"), "{refused}");
    }

    #[test]
    fn only_a_live_gpu_pod_may_join_once() {
        assert!(refusal(0, true, Some(&gpu_pod("Running")), None).is_some_and(|reason| reason.contains("already")));
        assert!(refusal(0, false, None, None).is_some_and(|reason| reason.contains("no longer exists")));
        let cpu = Pod { serves: false, ..gpu_pod("Running") };
        assert!(refusal(0, false, Some(&cpu), None).is_some_and(|reason| reason.contains("GPU pods")));
        assert!(refusal(0, false, Some(&gpu_pod("Delete requested — verification pending")), None).is_some_and(|reason| reason.contains("being deleted")));
        // A stopped pod may join; it serves once its person starts it in NeoCloud.
        assert!(refusal(0, false, Some(&gpu_pod("Stopped")), None).is_none());
    }

    #[test]
    fn a_swarm_workers_pod_never_joins_the_grid_or_is_stopped_by_it() {
        let refused = refusal(0, false, Some(&gpu_pod("Running")), Some("Night shift")).expect("a worker's pod is refused");
        assert!(refused.contains("Swarm worker Night shift"), "{refused}");
        let workers = BTreeMap::from([("pod-b".to_owned(), "Night shift".to_owned())]);
        assert!(stops("pod-a", &workers));
        assert!(!stops("pod-b", &workers), "Stop all never reaches a worker's pod");
    }

    #[test]
    fn a_new_assignment_replaces_the_model_this_pod_runs() {
        // A pod runs one model, and the launcher refuses a second: the old one stops first.
        assert_eq!(launch(Some("acme/old"), "acme/new", false), Launch::Replace);
        assert_eq!(launch(Some("acme/old"), "acme/new", true), Launch::Replace);
        assert_eq!(launch(None, "acme/new", false), Launch::Start);
        // The same model is retried in place once its wait is over, and otherwise left alone.
        assert_eq!(launch(Some("acme/new"), "acme/new", true), Launch::Start);
        assert_eq!(launch(Some("acme/new"), "acme/new", false), Launch::Keep);
    }

    fn stand_in(id: &str) -> StandIn {
        let saved = Saved {
            environment_id: id.into(), member_id: format!("member-{id}"), grid_id: "grid-1".into(), grid_name: "Acme".into(),
            address: "127.0.0.1:7462".into(), certificate: String::new(), added_at: 0,
        };
        StandIn { saved, membership: None, live: Live::default(), worker: None, starting: None, jobs: Arc::default() }
    }

    #[test]
    fn a_pod_neocloud_does_not_show_is_never_taken_as_stopped_when_it_leaves() {
        assert!(may_bill(None), "the record may not have been readable: its stop finds out");
        assert!(may_bill(Some(&gpu_pod("Running"))) && may_bill(Some(&gpu_pod("Starting"))));
        assert!(!may_bill(Some(&gpu_pod("Stopped"))));
    }

    #[test]
    fn a_pod_that_leaves_the_grid_owes_its_stop_until_neocloud_confirms_it() {
        use crate::rented_gpu::Next as Owed;
        assert!(matches!(next(Err(MemberError::Removed)), Next::Leave(reason) if reason.contains("removed")));
        assert!(matches!(next(Err(MemberError::Deleted)), Next::Leave(reason) if reason.contains("deleted")));
        assert!(matches!(next(Ok(instructions(Some(assignment("acme/model")), Some(1)))), Next::Pause));
        let mut inner = Inner::default();
        inner.members.insert("pod-a".into(), stand_in("pod-a"));
        let mut stops = Record::default();
        assert!(leave_member(&mut inner, &mut stops, "pod-a", "The grid's admin removed it").is_some());
        assert!(inner.members.is_empty());
        assert_eq!(inner.notice.as_deref(), Some("The grid's admin removed it"));
        // Out of the list, but its stop is owed: a failed stop keeps it, and says so.
        assert!(stops.pods.get("pod-a").is_some_and(|entry| entry.stop), "the stop is owed");
        stops.settle("pod-a", "Pod A", crate::rented_gpu::Outcome::StopFailed("timeout".into()), 1);
        assert!(stops.pods.contains_key("pod-a"), "a failed stop never lets it go");
        assert!(stops.notices.last().is_some_and(|notice| notice.warning && notice.text.contains("could not be stopped (timeout)")));
        // Each pass stops it while it bills, and asks NeoCloud before letting go of one that looks stopped.
        assert!(matches!(owed_next(false, Some("Running")), Owed::Stop));
        assert!(matches!(owed_next(false, Some("Creating")), Owed::Stop));
        assert!(matches!(owed_next(false, Some("Stopped")), Owed::Check));
        assert!(matches!(owed_next(false, None), Owed::Check), "not seeing it never lets it go");
        assert!(matches!(owed_next(false, Some("Delete requested — verification pending")), Owed::Keep));
        assert!(matches!(owed_next(false, Some("Deleted")), Owed::Forget));
        assert!(matches!(owed_next(true, Some("Running")), Owed::Forget), "a Swarm worker's pod is Swarm's to stop");
        stops.settle("pod-a", "Pod A", crate::rented_gpu::Outcome::Stopped, 2);
        assert!(stops.pods.is_empty(), "a confirmed stop lets it go");
    }

    #[test]
    fn stopping_all_says_stopped_only_for_pods_that_stopped() {
        let reason = "Stopped from this page.";
        assert_eq!(stopped_status(Some(&Ok(Stopped::Confirmed)), None, reason), ("stopped", reason.to_owned()));
        let (state, text) = stopped_status(Some(&Ok(Stopped::Pending)), None, reason);
        assert_eq!(state, "stopping", "a stop NeoCloud has not confirmed is never said to be done");
        assert!(text.contains("NeoCloud shows it stopping"), "{text}");
        assert_eq!(stopped_status(None, None, reason), ("stopped", reason.to_owned()), "a pod that was not billing");
        let (state, text) = stopped_status(Some(&Err("timeout".into())), None, reason);
        assert_eq!(state, "error");
        assert!(text.contains("could not be stopped (timeout)") && text.contains("Stop it in NeoCloud"), "{text}");
        let (state, text) = stopped_status(None, Some("Night shift"), reason);
        assert_eq!(state, "error", "a pod the grid did not stop is never said to be stopped");
        assert!(text.contains("Swarm worker Night shift"), "{text}");
    }

    #[test]
    fn quitting_stops_every_billing_pod_and_every_owed_stop() {
        let members = ["pod-a".to_owned(), "pod-b".to_owned(), "pod-c".to_owned()];
        // pod-d left the grid, and its stop failed before this quit.
        let owed = ["pod-d".to_owned(), "pod-e".to_owned(), "pod-a".to_owned()];
        let billing_now = |id: &str| id != "pod-b" && id != "pod-e";
        // pod-c is a Swarm worker's as well: stopped from here too, since the gate makes it harmless.
        assert_eq!(quit_targets(&members, &owed, billing_now), ["pod-a", "pod-c", "pod-d"]);
    }

    #[test]
    fn a_pod_neocloud_has_not_settled_cannot_join_the_grid() {
        for state in ["Creating", "Needs inspection", "Created — inspect to verify"] {
            let refused = refusal(0, false, Some(&gpu_pod(state)), None).unwrap_or_default();
            assert!(refused.contains("still being created"), "{state}: {refused}");
        }
        // Without a provider ID it cannot be stopped from here, so it cannot join.
        let unknown = Pod { known: false, ..gpu_pod("Running") };
        assert!(refusal(0, false, Some(&unknown), None).is_some_and(|reason| reason.contains("still being created")));
    }

    #[test]
    fn a_membership_the_vault_could_not_give_is_asked_for_again() {
        let key = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).expect("a test certificate");
        let mut member = stand_in("pod-a");
        member.saved.certificate = key.cert.pem();
        assert!(retry_membership(&mut member, |_| Err("the vault is locked".into())).is_none());
        assert_eq!(member.live.state, "error");
        assert!(member.live.reason.contains("the vault is locked") && member.live.reason.contains("tries again"), "{}", member.live.reason);
        // The next check-in asks again, and the pod checks in once the vault answers.
        let restored = retry_membership(&mut member, |saved| Membership::new(HubAddress::Direct("127.0.0.1:7462".parse().unwrap()), &saved.certificate, saved.member_id.clone(), "token".into()));
        assert!(restored.is_some() && member.membership.is_some());
        assert_eq!(member.live.state, "preparing");
        assert!(retry_membership(&mut member, |_| Err("never asked".into())).is_some(), "one it has is kept");
    }

    #[test]
    fn only_a_computer_with_no_grid_hub_stops_its_pods() {
        assert_eq!(hosting_of(&json!({"hub": {"name": "Acme"}, "hubError": null})), Hosting::Yes);
        // Set up here but not starting this minute (the vault asleep): pods wait, nothing is stopped.
        assert_eq!(hosting_of(&json!({"hub": null, "hubError": "The OS vault did not answer"})), Hosting::NotNow);
        // None created, deleted, or moved aside by a rollout.
        assert_eq!(hosting_of(&json!({"hub": null, "hubError": null})), Hosting::No);
    }

    #[test]
    fn an_unreachable_hub_is_retried_rather_than_dropping_the_pod() {
        assert!(matches!(next(Err(MemberError::Failed("timed out".into()))), Next::Retry(error) if error == "timed out"));
        // An answer this version cannot read changes nothing on the pod and never lets it go.
        assert!(matches!(next(Err(MemberError::Unreadable("Update Yougori".into()))), Next::Unreadable(said) if said == "Update Yougori"));
    }

    #[test]
    fn a_pod_follows_its_assignment_or_idles_without_one() {
        assert!(matches!(next(Ok(instructions(None, None))), Next::Idle));
        assert!(matches!(next(Ok(instructions(Some(assignment("acme/model")), None))), Next::Follow(found) if found.model == "acme/model"));
    }

    #[test]
    fn deleted_and_deleting_pods_are_leaving_and_only_running_ones_count() {
        assert!(leaving("Deleted") && leaving("Delete requested — verification pending"));
        assert!(!leaving("Stopped") && !leaving("Running"));
        assert!(running("Running") && !running("Starting") && !running("Stopped"));
    }

    #[test]
    fn a_pod_still_powering_on_is_stopped_too_when_it_leaves() {
        assert!(billing("Running") && billing("Starting") && billing("Creating"));
        assert!(!billing("Stopped") && !billing("Stopping") && !billing("Deleted"));
    }

    #[test]
    fn a_stopped_pod_reports_its_model_as_stopped_never_available() {
        let live = Live { model: Some("acme/model".into()), state: "stopped".into(), reason: "Stopped in NeoCloud".into(), ..Live::default() };
        let reports = report(&live, "NVIDIA RTX 4090");
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].state, "stopped");
        let idle = Live { model: None, ..Live::default() };
        assert!(report(&idle, "NVIDIA RTX 4090").is_empty());
        let unknown = Live { model: Some("acme/model".into()), state: "idle".into(), ..Live::default() };
        assert_eq!(report(&unknown, "gpu")[0].state, "stopped");
    }

    #[test]
    fn a_pod_reads_its_gpu_and_price_from_neocloud() {
        let deployment: Deployment = serde_json::from_value(json!({
            "provider": "runpod", "product": "pod", "name": "Pod", "resourceId": "abc", "state": "Running", "image": "", "offer": "NVIDIA RTX 4090",
            "address": "", "requestId": "", "lastError": null, "extra": {"gpuId": "NVIDIA A100", "gpuCount": 2, "hourlyUsd": 1.5}
        })).expect("a RunPod pod");
        let pod = pod_of("Pod", &deployment);
        assert_eq!((pod.gpu.as_str(), pod.gpu_count, pod.hourly_usd, pod.serves), ("NVIDIA A100", 2, 1.5, true));
        let endpoint: Deployment = serde_json::from_value(json!({
            "provider": "runpod", "product": "serverless", "name": "Api", "resourceId": "abc", "state": "Ready", "image": "", "offer": "",
            "address": "", "requestId": "", "lastError": null
        })).expect("an endpoint");
        assert!(!pod_of("Api", &endpoint).serves);
    }
}
