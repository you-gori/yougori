//! Rented NeoCloud GPUs as Neo Grid and Swarm Mining both see them.
//!
//! What a pod is, whether it is billing, and the decisions about who may use one and when it is
//! stopped. Nothing here rents or starts a pod: pods come from the NeoCloud flow, with its own price
//! review and consent, and a stopped pod stays stopped until its person starts it there. The
//! decisions are plain functions kept outside `swarm`, so their tests run without Swarm Mining.
use crate::{models::EnvironmentKind, neocloud::Deployment, store::PlatformStore, AppHandle};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, future::Future, path::Path, sync::Arc};
use tauri::Manager;

/// One rented pod, as NeoCloud describes it.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Pod {
    pub name: String,
    pub gpu: String,
    pub gpu_count: u64,
    /// What NeoCloud recorded it costs an hour, or 0.0 when it recorded nothing: a price this
    /// computer does not know, which every view says as "price unknown", never "$0.00".
    pub hourly_usd: f64,
    pub state: String,
    /// A RunPod GPU pod: the only kind that can run a model for the grid or a worker.
    pub serves: bool,
    /// NeoCloud holds the provider's ID for it. Without one, nothing can stop it from here.
    pub known: bool,
}

pub(crate) fn pod_of(name: &str, deployment: &Deployment) -> Pod {
    let extra = &deployment.extra;
    Pod {
        name: name.to_owned(),
        gpu: extra["gpuId"].as_str().filter(|gpu| !gpu.is_empty()).unwrap_or(&deployment.offer).to_owned(),
        gpu_count: extra["gpuCount"].as_u64().unwrap_or(1),
        hourly_usd: extra["hourlyUsd"].as_f64().filter(|usd| usd.is_finite() && *usd > 0.0).unwrap_or(0.0),
        state: deployment.state.clone(),
        serves: deployment.provider == "runpod" && matches!(deployment.product.as_str(), "pod" | "gpu") && extra["compute"] != "cpu" && extra["kind"] != "endpoint",
        known: !deployment.resource_id.is_empty(),
    }
}

pub(crate) fn pod(app: &AppHandle, id: &str) -> Option<Pod> {
    let state = app.state::<PlatformStore>().snapshot().ok()?;
    let environment = state.environments.iter().find(|environment| environment.id == id && environment.kind == EnvironmentKind::Cloud)?;
    state.neocloud_deployments.get(id).map(|deployment| pod_of(&environment.name, deployment))
}

/// Every rented GPU pod on this computer, by environment id.
pub(crate) fn pods(app: &AppHandle) -> Vec<(String, Pod)> {
    let Ok(state) = app.state::<PlatformStore>().snapshot() else { return Vec::new() };
    state.environments.iter()
        .filter(|environment| environment.kind == EnvironmentKind::Cloud)
        .filter_map(|environment| state.neocloud_deployments.get(&environment.id).map(|deployment| (environment.id.clone(), pod_of(&environment.name, deployment))))
        .filter(|(_, pod)| pod.serves)
        .collect()
}

pub(crate) fn running(state: &str) -> bool {
    state == "Running"
}

/// A pod that may be billing: running, still powering on, not yet checked by NeoCloud after a
/// create it could not confirm, or left unconfirmed by a start or stop whose check ran out ("Start
/// pending — not verified"). Leaving its use stops these.
pub(crate) fn billing(state: &str) -> bool {
    matches!(state, "Running" | "Starting" | "Creating") || state.contains("inspect") || state.ends_with("not verified")
}

/// NeoCloud holds the pod's ID and has checked its state: only such a pod can join something,
/// because only such a pod can be stopped from here.
pub(crate) fn settled(pod: &Pod) -> bool {
    pod.known && pod.state != "Creating" && !pod.state.contains("inspect")
}

/// A pod NeoCloud reports as stopped or deleted. One still being deleted is not: NeoCloud is
/// finishing that itself and says so if it fails. Nor is "Stopping", which NeoCloud writes when it
/// sends a stop and keeps only when it could not read the pod back afterwards.
pub(crate) fn off(state: &str) -> bool {
    state == "Deleted" || !billing(state) && !leaving(state) && state != "Stopping"
}

/// A pod that is gone or going: it never serves again.
pub(crate) fn leaving(state: &str) -> bool {
    state == "Deleted" || state.starts_with("Delete")
}

// ---- Stopping a pod ----

/// What stopping a pod needs from NeoCloud. The app is the real one; tests use a stand-in, so every
/// decision around a stop is checked without RunPod.
pub(crate) trait Cloud: Sync {
    /// The pod as this computer's NeoCloud record shows it now.
    fn pod(&self, id: &str) -> Option<Pod>;
    /// NeoCloud no longer lists the pod's node, read from a record that could be read.
    fn gone(&self, id: &str) -> bool;
    /// Runs one of NeoCloud's pod actions, `stop` or `inspect`, which update that record.
    fn act(&self, id: &str, action: &'static str) -> impl Future<Output = Result<(), String>> + Send;
}

impl Cloud for AppHandle {
    fn pod(&self, id: &str) -> Option<Pod> {
        self::pod(self, id)
    }

    /// NeoCloud lets a node go only once its pod is deleted, or when RunPod refused to create it,
    /// so a pod gone from a record that could be read is not billing.
    fn gone(&self, id: &str) -> bool {
        self.state::<PlatformStore>().snapshot().is_ok_and(|state| !state.neocloud_deployments.contains_key(id))
    }

    fn act(&self, id: &str, action: &'static str) -> impl Future<Output = Result<(), String>> + Send {
        let (app, id) = (self.clone(), id.to_owned());
        async move { crate::neocloud::runpod::runpod_action(id, action.into(), None, app.clone(), app.state(), app.state()).await.map(|_| ()) }
    }
}

/// What a stop NeoCloud accepted came to.
#[derive(Debug, PartialEq)]
pub(crate) enum Stopped {
    /// NeoCloud shows the pod stopped, or gone.
    Confirmed,
    /// NeoCloud sent the stop but could not read the pod back ("Stopping"). Not a stop until a later
    /// look says so; until then it stays owed.
    Pending,
}

/// Why a stop is not even sent. Without a provider ID, NeoCloud's stop only reconciles its own
/// record, so the page would say stopped while the pod may be billing.
pub(crate) fn stop_refusal(pod: Option<&Pod>) -> Option<String> {
    pod.filter(|pod| !pod.known).map(|pod| format!("Neocloud never confirmed it was created, so Yougori has no ID to stop it with. In Sandboxes, open the {} node's card: Check again attaches it if it is in your Neocloud account, where it may be billing; if your account has no such pod, confirm that there by typing its name", pod.name))
}

/// What NeoCloud shows after a stop it accepted. Only a pod shown stopped, or gone, counts: one
/// still billing is a failure, and "Stopping" is a stop nobody has confirmed yet.
pub(crate) fn after_stop(after: Option<&Pod>) -> Result<Stopped, String> {
    match after {
        Some(pod) if billing(&pod.state) => Err(format!("the stop was sent, but NeoCloud still shows it {}", pod.state)),
        Some(pod) if pod.state == "Stopping" => Ok(Stopped::Pending),
        _ => Ok(Stopped::Confirmed),
    }
}

/// Stops a pod through NeoCloud's own action, which ends its GPU billing; its disk stays.
pub(crate) async fn stop_with(cloud: &impl Cloud, id: &str) -> Result<Stopped, String> {
    if let Some(refusal) = stop_refusal(cloud.pod(id).as_ref()) {
        return Err(refusal);
    }
    cloud.act(id, "stop").await?;
    after_stop(cloud.pod(id).as_ref())
}

/// Asks NeoCloud about the pod now and returns its state. An error means it could not be asked,
/// which is never taken to mean the pod is not billing.
pub(crate) async fn look_with(cloud: &impl Cloud, id: &str) -> Result<String, String> {
    if cloud.gone(id) {
        return Ok("Deleted".into());
    }
    cloud.act(id, "inspect").await?;
    if cloud.gone(id) {
        return Ok("Deleted".into());
    }
    Ok(cloud.pod(id).ok_or("NeoCloud does not list this pod on this computer")?.state)
}

pub(crate) async fn look(app: &AppHandle, id: &str) -> Result<String, String> {
    look_with(app, id).await
}

/// How a stop somebody owes went, from the stop and, when it failed, a fresh look. Quitting has no
/// time for the look. Nothing (None) keeps it owed without a word: NeoCloud has not shown it
/// stopped yet, and a later look settles it.
pub(crate) fn stop_outcome(sent: Result<Stopped, String>, looked: Option<Result<String, String>>) -> Option<Outcome> {
    match sent {
        Ok(Stopped::Confirmed) => Some(Outcome::Stopped),
        Ok(Stopped::Pending) => None,
        Err(error) => match looked {
            Some(Ok(state)) if off(&state) => Some(Outcome::NotBilling),
            _ => Some(Outcome::StopFailed(error)),
        },
    }
}

/// An owed stop from start to finish: the stop, a fresh look when it failed, and what they mean.
pub(crate) async fn owed_stop_with(cloud: &impl Cloud, id: &str, quitting: bool) -> Option<Outcome> {
    let sent = stop_with(cloud, id).await;
    let looked = match &sent {
        Err(_) if !quitting => Some(look_with(cloud, id).await),
        _ => None,
    };
    stop_outcome(sent, looked)
}

/// What a fresh look at a pod a stop is owed for means.
#[derive(Debug, PartialEq)]
pub(crate) enum Looked {
    Settle(Outcome),
    Stop,
}

/// `used`: a live worker runs its model on the pod.
pub(crate) fn after_look(looked: Result<String, String>, used: bool) -> Looked {
    match looked {
        Ok(state) if off(&state) => Looked::Settle(Outcome::NotBilling),
        // NeoCloud answered and there is nothing to stop now: in use, or being stopped or deleted.
        Ok(state) if used || leaving(&state) || state == "Stopping" => Looked::Settle(Outcome::InUse),
        Ok(_) => Looked::Stop,
        Err(error) => Looked::Settle(Outcome::Unchecked(error)),
    }
}

/// One stop at a time per pod, across Neo Grid and Swarm alike, so two never report on one stop.
pub(crate) fn gate(pod: &str) -> Arc<tokio::sync::Mutex<()>> {
    static GATES: std::sync::Mutex<BTreeMap<String, Arc<tokio::sync::Mutex<()>>>> = std::sync::Mutex::new(BTreeMap::new());
    GATES.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).entry(pod.to_owned()).or_default().clone()
}

/// The stops one side owes (Neo Grid's or Swarm's, each in its own file), with what its page must
/// be told about that file.
#[derive(Default)]
pub(crate) struct Ledger {
    pub record: Record,
    /// Why the file is left where it is (see `read_kept`): nothing is written over it, and it is read
    /// again at the next use. Stops owed and settled meanwhile are kept here and written down with
    /// what the file holds once it reads.
    unread: Option<String>,
    /// The last write failed: a stop owed now is lost if Yougori quits before a write works.
    unsaved: Option<String>,
}

const UNREADABLE: &str = "Check your rented GPUs in NeoCloud and stop any that should not be running.";

/// A file of Yougori's own that could not be read.
pub(crate) struct Unreadable {
    /// What went wrong, and where its bytes are now, for the page.
    pub said: String,
    /// It is left where it is: the disk would not give it this time, or it is damaged and could not
    /// be moved aside. Nothing may be written over it, and it is read again later.
    pub locked: bool,
}

/// Reads a JSON file Yougori keeps. No file is the empty value. A file that cannot be read is never
/// taken for an empty one. One the disk will not give (held for a moment by an antivirus scan, say)
/// is tried again, then left exactly as it is to be read later. Only one that reads but is damaged
/// is moved aside, with its bytes kept, so no later write can destroy what it holds. Either way the
/// caller is told what to say. `what` names the list, as the page says it.
pub(crate) fn read_kept<T: serde::de::DeserializeOwned + Default>(path: &Path, at: i64, what: &str) -> Result<T, Unreadable> {
    let mut tries = 1;
    let bytes = loop {
        match std::fs::read(path) {
            Ok(bytes) => break bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(T::default()),
            Err(error) if tries == 3 => return Err(Unreadable { said: format!("Yougori could not read {what} ({error}). It leaves that file as it is and reads it again shortly. {UNREADABLE}"), locked: true }),
            Err(_) => {
                tries += 1;
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
        }
    };
    let why = match serde_json::from_slice::<T>(&bytes) {
        Ok(value) => return Ok(value),
        Err(error) => format!("it is damaged ({error})"),
    };
    let name = path.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default();
    let kept = format!("{name}.damaged-{at}");
    if std::fs::rename(path, path.with_file_name(&kept)).is_ok() {
        Err(Unreadable { said: format!("Yougori could not read {what}: {why}. That file was kept as {kept} in Yougori's data folder. {UNREADABLE}"), locked: false })
    } else {
        Err(Unreadable { said: format!("Yougori could not read {what}: {why}, and it leaves that file untouched. {UNREADABLE}"), locked: true })
    }
}

impl Ledger {
    /// Reads the stops kept at `path` afresh, as a restart would.
    #[cfg(test)]
    fn open(path: &Path, at: i64) -> Ledger {
        Ledger::read(path, at, Ledger::default())
    }

    /// Reads the stops kept at `path`, taking in what changed in `meanwhile` while the file could not
    /// be read. One damaged and set aside is replaced by a fresh file that carries the warning, so a
    /// restart still shows it. One left where it is (see `read_kept`) is never written over: this
    /// ledger keeps working without it and reads it again at the next use.
    fn read(path: &Path, at: i64, meanwhile: Ledger) -> Ledger {
        match read_kept::<Record>(path, at, "its list of rented GPUs it still has to stop") {
            Ok(mut record) => {
                let changed = record.absorb(meanwhile.record);
                let mut ledger = Ledger { record, unread: None, unsaved: meanwhile.unsaved };
                if changed || ledger.unsaved.is_some() {
                    ledger.save(path);
                }
                ledger
            }
            Err(Unreadable { said, locked: false }) => {
                let mut ledger = Ledger { record: meanwhile.record, ..Ledger::default() };
                ledger.record.note(said, true, at);
                ledger.save(path);
                ledger
            }
            Err(Unreadable { said, locked: true }) => Ledger { record: meanwhile.record, unread: Some(said), unsaved: meanwhile.unsaved },
        }
    }

    /// Writes the stops back, unless the file is left where it is: that one is never written over.
    pub(crate) fn save(&mut self, path: &Path) {
        if self.unread.is_some() {
            self.unsaved = Some("Yougori cannot write down the rented GPUs it still has to stop until it can read its list of them again. If you quit now, check them in NeoCloud.".into());
            return;
        }
        self.unsaved = write_kept(path, &self.record).err().map(|error| format!("Yougori could not write down the rented GPUs it still has to stop ({error}). If you quit now, check them in NeoCloud."));
    }

    /// What the page shows: how the latest stops went, then anything wrong with the file itself.
    pub(crate) fn notices(&self, at: i64) -> Vec<Notice> {
        let mut notices = self.record.notices.clone();
        notices.extend(self.unread.iter().chain(&self.unsaved).map(|text| Notice { at, text: text.clone(), warning: true }));
        notices
    }
}

/// Writes a JSON file Yougori keeps, whole or not at all, and on the disk before it counts: a crash
/// or power cut mid-write leaves the last good file, never a truncated one read later as damaged.
pub(crate) fn write_kept(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let folder = path.parent().ok_or("Invalid data folder")?;
    std::fs::create_dir_all(folder).map_err(|error| error.to_string())?;
    let mut file = tempfile::NamedTempFile::new_in(folder).map_err(|error| error.to_string())?;
    std::io::Write::write_all(&mut file, &serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?).map_err(|error| error.to_string())?;
    file.as_file().sync_all().map_err(|error| error.to_string())?;
    file.persist(path).map_err(|error| error.to_string())?;
    Ok(())
}

/// The ledger, read from its file at first use, and read again while that file is left where it is.
fn loaded<'a>(slot: &'a mut Option<Ledger>, path: &Path, at: i64) -> &'a mut Ledger {
    match slot.take() {
        Some(ledger) if ledger.unread.is_none() => slot.insert(ledger),
        held => slot.insert(Ledger::read(path, at, held.unwrap_or_default())),
    }
}

/// Reads the ledger, changes its record, and writes it back when `f` changed something.
pub(crate) async fn with_ledger<T>(slot: &tokio::sync::Mutex<Option<Ledger>>, path: &Path, at: i64, f: impl FnOnce(&mut Record) -> (T, bool)) -> T {
    let mut slot = slot.lock().await;
    let ledger = loaded(&mut slot, path, at);
    let (value, changed) = f(&mut ledger.record);
    if changed {
        ledger.save(path);
    }
    value
}

/// What the page shows about the stops this ledger owes.
pub(crate) async fn ledger_notices(slot: &tokio::sync::Mutex<Option<Ledger>>, path: &Path, at: i64) -> Vec<Notice> {
    let mut slot = slot.lock().await;
    loaded(&mut slot, path, at).notices(at)
}

/// Writes down that these pods must be stopped, before any stop is tried: a stop a closing app or
/// a failed call cuts short is finished later, and stays on the page until it is.
pub(crate) async fn owe(slot: &tokio::sync::Mutex<Option<Ledger>>, path: &Path, at: i64, pods: &[(String, String)]) {
    if pods.is_empty() {
        return;
    }
    with_ledger(slot, path, at, |record| {
        for (pod, owner) in pods {
            record.release(pod, owner);
        }
        ((), true)
    }).await;
}

/// Stops one owed pod and writes down how it went. One stop at a time per pod: a second waits and
/// goes no further once the first has settled it. Returns what the stop came to, for a page.
pub(crate) async fn settle_stop(cloud: &impl Cloud, slot: &tokio::sync::Mutex<Option<Ledger>>, path: &Path, id: &str, quitting: bool, at: i64) -> Result<Stopped, String> {
    let gate = gate(id);
    let _one = gate.lock().await;
    if !with_ledger(slot, path, at, |record| (record.pods.get(id).is_some_and(|entry| entry.stop), false)).await {
        // Settled meanwhile: stopped, not billing, or no longer this side's to stop.
        return Ok(Stopped::Confirmed);
    }
    let name = cloud.pod(id).map(|pod| pod.name).unwrap_or_else(|| id.to_owned());
    let outcome = owed_stop_with(cloud, id, quitting).await;
    let said = match &outcome {
        None => Ok(Stopped::Pending),
        Some(Outcome::StopFailed(error)) => Err(error.clone()),
        Some(_) => Ok(Stopped::Confirmed),
    };
    if let Some(outcome) = outcome {
        with_ledger(slot, path, at, |record| {
            record.settle(id, &name, outcome, at);
            ((), true)
        }).await;
    }
    said
}

/// Stops a pod this side remembered and had not owed a stop for yet: one whose worker is gone, or
/// never got going. `settle_stop` sends nothing for a pod nobody owes a stop, which is right for a
/// second stop of one pod, so the stop is written down as owed first; it is then tried again if it
/// fails, and the page says how it went.
pub(crate) async fn owe_and_stop(cloud: &impl Cloud, slot: &tokio::sync::Mutex<Option<Ledger>>, path: &Path, pod: &str, owner: &str, at: i64) -> Result<Stopped, String> {
    owe(slot, path, at, &[(pod.to_owned(), owner.to_owned())]).await;
    settle_stop(cloud, slot, path, pod, false, at).await
}

/// The pod is wanted again (added back to the grid, say), so a stop owed for it is dropped. Under the
/// pod's stop gate: a stop already on its way finishes first and says how it went, rather than
/// stopping a pod that is wanted with nothing on the page to say so.
pub(crate) async fn withdraw_stop(slot: &tokio::sync::Mutex<Option<Ledger>>, path: &Path, pod: &str, at: i64) {
    let gate = gate(pod);
    let _one = gate.lock().await;
    with_ledger(slot, path, at, |record| ((), record.pods.remove(pod).is_some())).await;
}

/// Every one of `pods` owed first, then all stopped at once: each stop is a RunPod call of up to two
/// minutes, and the ones a closing app cuts short are finished at the next start.
pub(crate) async fn stop_all_owed(cloud: &impl Cloud, slot: &tokio::sync::Mutex<Option<Ledger>>, path: &Path, at: i64, pods: &[(String, String)], quitting: bool) -> Vec<(String, Result<Stopped, String>)> {
    owe(slot, path, at, pods).await;
    futures_util::future::join_all(pods.iter().map(|(pod, _)| async move { (pod.clone(), settle_stop(cloud, slot, path, pod, quitting, at).await) })).await
}

/// The pods Swarm stops when Yougori quits: every recorded pod and every live worker's that may be
/// billing. A live worker's name wins over an older record's. One the grid also claims is stopped
/// too: the shared gate makes a second stop of a pod harmless, while leaving it to the other side
/// let a pod both sides claimed go unstopped by either.
pub(crate) fn swarm_quit_targets(recorded: BTreeMap<String, String>, live: BTreeMap<String, String>, billing_now: impl Fn(&str) -> bool) -> Vec<(String, String)> {
    let mut pods = recorded;
    pods.extend(live);
    pods.into_iter().filter(|(pod, _)| billing_now(pod)).collect()
}

// ---- Swarm Mining on a rented GPU ----

/// Why the public board takes no rented GPU yet. Its owners have not been asked.
pub(crate) const PUBLIC_REFUSAL: &str = "Public bounties can't use a rented GPU yet. A bounty's code may only leave this computer when its owner allows it, and the public board doesn't ask owners that yet. Run this worker's model on this computer, or use a closed bounty whose host allows rented GPUs.";

/// Whether the accepted bounty lets its code go to a GPU rented from an outside provider. Only the
/// bounty's host can allow it, in the policy the worker accepts.
pub(crate) fn bounty_allows(policy: &Value, closed: bool) -> Result<(), String> {
    if !closed {
        return Err(PUBLIC_REFUSAL.into());
    }
    if policy["rentedGpu"] == true {
        return Ok(());
    }
    let title = policy["title"].as_str().filter(|title| !title.trim().is_empty()).unwrap_or("This bounty");
    Err(format!("“{title}” doesn't allow its code on a rented GPU, so its worker runs the model on this computer. Choose “On this computer”, or ask the bounty's host to allow rented GPUs."))
}

/// The sentence for a worker whose pod is not running, with the step that is the person's to take.
/// `next` is the control that carries on afterwards: Resume or Retry.
pub(crate) fn not_running(name: &str, state: &str, next: &str) -> String {
    if matches!(state, "Starting" | "Creating") {
        return format!("Your rented GPU {name} is still starting in NeoCloud. Wait until it is Running, then choose {next}.");
    }
    format!("Your rented GPU {name} is {state} in NeoCloud. Start it there, then choose {next}. Yougori never rents or starts a GPU for you.")
}

/// Why a worker may not use this pod, or nothing when it may. `grid` is whether the pod serves Neo
/// Grid; `worker` names another live worker that already runs its model on it; `next` is the
/// control that carries on once a stopped pod is started.
pub(crate) fn refusal(pod: Option<&Pod>, grid: bool, worker: Option<&str>, next: &str) -> Option<String> {
    let Some(pod) = pod else {
        return Some("That NeoCloud pod no longer exists. Choose another, or rent one under Sandboxes, New environment, Neocloud.".into());
    };
    if !pod.serves {
        return Some("Only RunPod GPU pods can run a worker's model; CPU pods and serverless endpoints cannot.".into());
    }
    if leaving(&pod.state) {
        return Some(format!("{} is being deleted. Choose another pod, or rent one in NeoCloud.", pod.name));
    }
    if !settled(pod) {
        return Some(format!("{} is still being created in NeoCloud, or needs checking there. Use it once NeoCloud shows it Running.", pod.name));
    }
    if grid {
        return Some(format!("{} serves your Neo Grid. Remove it from the grid first, or choose another pod.", pod.name));
    }
    if let Some(worker) = worker {
        return Some(format!("{} already runs the model for worker {worker}. Each rented GPU runs one worker's model.", pod.name));
    }
    if !running(&pod.state) {
        return Some(not_running(&pod.name, &pod.state, next));
    }
    None
}

/// The private address a worker's sandbox reaches its pod at: the one the cloud bridge gives a
/// connected pod, which is the address of its environment id. A pod whose runtime has another id
/// would be named at an address nothing answers, so it is refused rather than guessed at.
pub(crate) fn model_address(environment: &crate::models::Environment) -> Option<String> {
    let runtime = environment.runtime_id.as_deref().unwrap_or(&environment.id);
    (environment.kind == EnvironmentKind::Cloud && runtime == environment.id).then(|| crate::runtime::fabric::ip_text(runtime))
}

/// Whether a worker's model stays on this computer, which is what the platform is told.
pub(crate) fn local_only(rented_gpu: Option<&str>) -> bool {
    rented_gpu.is_none()
}

/// What happens to a pod Swarm recorded, on each supervisor check.
#[derive(Debug, PartialEq)]
pub(crate) enum Next {
    /// A live worker uses it, or NeoCloud is deleting it. A paused worker keeps its pod, and its row
    /// says it is still billing.
    Keep,
    /// No live worker uses it, or its worker was stopped or removed, and it is still billing.
    Stop,
    /// Ask NeoCloud before deciding: the pod looks stopped, or cannot be seen here at all. Not
    /// seeing a pod is never taken to mean it is not billing.
    Check,
    /// Not Swarm's to keep track of any more: NeoCloud deleted it, or it serves Neo Grid now.
    Forget,
}

/// `pending` is a stop asked for when a worker was stopped, left or was removed. A pod serving Neo
/// Grid is never stopped from here, whatever Swarm remembers about it, and a record is dropped
/// only on something known for certain.
pub(crate) fn next(pending: bool, live_worker: bool, grid: bool, state: Option<&str>) -> Next {
    if grid {
        return Next::Forget;
    }
    let Some(state) = state else { return Next::Check };
    if state == "Deleted" {
        return Next::Forget;
    }
    if leaving(state) || (live_worker && !pending) {
        return Next::Keep;
    }
    if billing(state) { Next::Stop } else { Next::Check }
}

const NOTICES: usize = 8;
/// After this many checks in a row that could not reach NeoCloud, the page says so.
const UNCHECKED_ROUNDS: u32 = 3;

/// The pods Swarm's workers used, kept on disk so a stop asked for while Yougori was closing is
/// finished on the next start, and how the latest stops went.
#[derive(Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Record {
    #[serde(default)]
    pub pods: BTreeMap<String, Entry>,
    #[serde(default)]
    pub notices: Vec<Notice>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Entry {
    /// The worker's name, for what the page says about the pod.
    pub worker: String,
    /// A stop asked for when the worker stopped, left or was removed, until it is confirmed.
    #[serde(default)]
    pub stop: bool,
    /// Checks in a row that could not reach NeoCloud about this pod.
    #[serde(default)]
    pub unchecked: u32,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Notice {
    pub at: i64,
    pub text: String,
    pub warning: bool,
}

/// What one look at a recorded pod found.
#[derive(Debug, PartialEq)]
pub(crate) enum Outcome {
    /// Swarm stopped it.
    Stopped,
    /// NeoCloud answered: it is not billing, or it is gone.
    NotBilling,
    /// NeoCloud answered, and there is nothing to stop now: a live worker uses it, or NeoCloud is
    /// stopping or deleting it.
    InUse,
    /// The stop failed, and NeoCloud did not say otherwise.
    StopFailed(String),
    /// NeoCloud could not be asked, or did not list the pod.
    Unchecked(String),
}

impl Record {
    pub(crate) fn note(&mut self, text: String, warning: bool, at: i64) {
        // A stop retried every check says its failure once.
        if self.notices.last().is_some_and(|last| last.text == text) {
            return;
        }
        self.notices.push(Notice { at, text, warning });
        let excess = self.notices.len().saturating_sub(NOTICES);
        self.notices.drain(..excess);
    }

    /// Takes in what changed while this record could not be read: those entries are newer than its
    /// own, and their notices come after its own. Returns whether anything was taken in.
    fn absorb(&mut self, newer: Record) -> bool {
        let changed = !newer.pods.is_empty() || !newer.notices.is_empty();
        self.pods.extend(newer.pods);
        for notice in newer.notices {
            self.note(notice.text, notice.warning, notice.at);
        }
        changed
    }

    /// This worker runs its model on `pod`. Returns whether anything changed.
    pub(crate) fn remember(&mut self, pod: &str, worker: &str) -> bool {
        if self.pods.get(pod).is_some_and(|entry| entry.worker == worker && !entry.stop) {
            return false;
        }
        self.pods.insert(pod.to_owned(), Entry { worker: worker.to_owned(), stop: false, unchecked: 0 });
        true
    }

    /// The worker is done with `pod`: stop it, and keep trying until that is confirmed.
    pub(crate) fn release(&mut self, pod: &str, worker: &str) {
        self.pods.insert(pod.to_owned(), Entry { worker: worker.to_owned(), stop: true, unchecked: 0 });
    }

    /// Applies what a check found. A pod leaves the record only when Swarm stopped it or NeoCloud
    /// confirmed it is not billing. One nobody could check stays, and after a few tries in a row the
    /// page says so, the way a failed stop does.
    pub(crate) fn settle(&mut self, pod: &str, name: &str, outcome: Outcome, at: i64) {
        let worker = self.pods.get(pod).map(|entry| entry.worker.clone()).unwrap_or_else(|| "a worker".into());
        match outcome {
            // Said only while the stop was owed: a stop already settled, or no longer anybody's to
            // try, has nothing more to report, and "Yougori keeps trying" would not be true.
            Outcome::Stopped => {
                if self.pods.remove(pod).is_some() {
                    self.note(format!("{name}, the rented GPU of {worker}, was stopped, so it is no longer billed. Start it in NeoCloud if you need it again."), false, at);
                }
            }
            Outcome::NotBilling => {
                self.pods.remove(pod);
            }
            Outcome::InUse => {
                if let Some(entry) = self.pods.get_mut(pod) {
                    entry.unchecked = 0;
                }
            }
            Outcome::StopFailed(error) => {
                let Some(entry) = self.pods.get_mut(pod) else { return };
                entry.unchecked = 0;
                self.note(format!("{name}, the rented GPU of {worker}, could not be stopped ({error}). Stop it in NeoCloud to end its billing; Yougori keeps trying."), true, at);
            }
            Outcome::Unchecked(error) => {
                let Some(entry) = self.pods.get_mut(pod) else { return };
                entry.unchecked += 1;
                if entry.unchecked >= UNCHECKED_ROUNDS {
                    self.note(format!("Yougori could not check {name}, the rented GPU of {worker}, in NeoCloud ({error}). Check it there to make sure it is not billed; Yougori keeps trying."), true, at);
                }
            }
        }
    }
}

/// The only credential a worker's sandbox gets for its rented GPU is the model server's own API
/// key, which opens that pod's chat API and nothing else. This checks the reference before it is
/// read: never the pod's owner token, never an account key that could rent, start, stop or bill.
pub(crate) fn guest_key_is_model_key(options: &yougori_cli::workload::Options) -> bool {
    let Some(reference) = options.secret_environment.get("YOUGORI_MODEL_TOKEN") else { return false };
    // The protection is structural: the reference is a model API key's, and no other secret of
    // the pod shares it, so the owner token cannot travel under the model key's name. The guest
    // side resolves exactly YOUGORI_MODEL_TOKEN and nothing else. The name list below is only
    // hygiene on the pod's own environment, a guess at spellings; it is not what keeps the guest safe.
    reference.starts_with("model-api-")
        && options.secret_environment.iter().all(|(name, other)| name == "YOUGORI_MODEL_TOKEN" || other != reference)
        && !options.environment.keys().chain(options.secret_environment.keys()).any(|name| name.contains("RUNPOD") || name.ends_with("_API_KEY"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn gpu(state: &str) -> Pod {
        Pod { name: "Pod A".into(), gpu: "NVIDIA RTX 4090".into(), gpu_count: 1, hourly_usd: 0.69, state: state.into(), serves: true, known: true }
    }

    #[test]
    fn a_worker_saved_before_rented_gpus_reads_as_local_and_is_written_back_unchanged() {
        let saved = json!({"id":"worker-1","name":"Bounty worker","model":"hf.co/acme/model-GGUF","state":"ready_waiting","stage":"Waiting","site":"https://yougori.com","gpu":"nvidia","resources":{"cpu":4,"memoryGb":8},"quotaGb":20.0,"keepResident":false});
        let worker: crate::swarm::Worker = serde_json::from_value(saved).unwrap();
        assert_eq!(worker.rented_gpu(), None);
        assert!(local_only(worker.rented_gpu()));
        let written = serde_json::to_value(&worker).unwrap();
        assert!(written.get("rentedGpu").is_none(), "a local worker's saved data gains no key");
    }

    #[test]
    fn only_a_closed_bounty_whose_host_allowed_it_sends_code_to_a_rented_gpu() {
        assert!(bounty_allows(&json!({"title":"Acme","rentedGpu":true}), true).is_ok());
        let refused = bounty_allows(&json!({"title":"Acme"}), true).unwrap_err();
        assert!(refused.contains("“Acme” doesn't allow its code on a rented GPU"));
        assert!(bounty_allows(&json!({"title":"Acme","rentedGpu":"true"}), true).is_err());
        // The public board is refused even if a policy claimed it, until its owners are asked.
        assert_eq!(bounty_allows(&json!({"rentedGpu":true}), false).unwrap_err(), PUBLIC_REFUSAL);
        assert!(!local_only(Some("pod-1")) && local_only(None));
    }

    #[test]
    fn a_worker_takes_only_a_running_gpu_pod_that_nothing_else_uses() {
        assert_eq!(refusal(Some(&gpu("Running")), false, None, "Retry"), None);
        assert!(refusal(None, false, None, "Retry").unwrap().contains("no longer exists"));
        assert!(refusal(Some(&Pod { serves: false, ..gpu("Running") }), false, None, "Retry").unwrap().contains("Only RunPod GPU pods"));
        assert!(refusal(Some(&gpu("Delete requested — verification pending")), false, None, "Retry").unwrap().contains("being deleted"));
        assert!(refusal(Some(&gpu("Running")), true, None, "Retry").unwrap().contains("serves your Neo Grid"));
        assert!(refusal(Some(&gpu("Running")), false, Some("Night shift"), "Retry").unwrap().contains("worker Night shift"));
        let stopped = refusal(Some(&gpu("Stopped")), false, None, "Create worker").unwrap();
        assert!(stopped.contains("Start it there, then choose Create worker") && stopped.contains("never rents or starts"));
        assert!(refusal(Some(&gpu("Starting")), false, None, "Resume").unwrap().contains("still starting"));
    }

    #[test]
    fn a_stopped_pod_reads_as_stopped_with_the_persons_next_step() {
        assert_eq!(not_running("Pod A", "Stopped", "Resume"), "Your rented GPU Pod A is Stopped in NeoCloud. Start it there, then choose Resume. Yougori never rents or starts a GPU for you.");
    }

    #[test]
    fn the_supervisor_never_stops_a_neo_grid_pod_or_a_live_workers_pod() {
        // A live worker's pod is kept, paused workers included.
        assert_eq!(next(false, true, false, Some("Running")), Next::Keep);
        // A pod serving Neo Grid is never stopped from Swarm, whatever Swarm remembers.
        for pending in [false, true] {
            assert_eq!(next(pending, false, true, Some("Running")), Next::Forget);
            assert_eq!(next(pending, true, true, Some("Starting")), Next::Forget);
            assert_eq!(next(pending, false, true, None), Next::Forget);
        }
        // A worker stopped, left or removed, or a pod no live worker uses: stopped while billing.
        assert_eq!(next(true, false, false, Some("Running")), Next::Stop);
        assert_eq!(next(false, false, false, Some("Starting")), Next::Stop);
        assert_eq!(next(true, true, false, Some("Running")), Next::Stop);
        // NeoCloud deleted it, or is deleting it: nothing to stop from here.
        assert_eq!(next(true, false, false, Some("Deleted")), Next::Forget);
        assert_eq!(next(true, false, false, Some("Delete requested — verification pending")), Next::Keep);
    }

    #[test]
    fn a_pod_that_cannot_be_seen_is_checked_never_forgotten() {
        // Not in the snapshot, or looking stopped: NeoCloud is asked before the record goes.
        assert_eq!(next(true, false, false, None), Next::Check);
        assert_eq!(next(false, true, false, None), Next::Check);
        assert_eq!(next(true, false, false, Some("Stopped")), Next::Check);
        // NeoCloud could not be asked and the pod is not in the snapshot: the record survives,
        // and after a few checks in a row the page says so.
        let mut record = Record::default();
        record.release("pod-a", "Night shift");
        record.settle("pod-a", "Pod A", Outcome::Unchecked("network unreachable".into()), 1);
        record.settle("pod-a", "Pod A", Outcome::Unchecked("network unreachable".into()), 2);
        assert!(record.pods.contains_key("pod-a"));
        assert!(record.notices.is_empty());
        record.settle("pod-a", "Pod A", Outcome::Unchecked("network unreachable".into()), 3);
        assert!(record.pods["pod-a"].stop, "the stop is still owed");
        let notice = record.notices.last().unwrap();
        assert!(notice.warning && notice.text.contains("could not check Pod A, the rented GPU of Night shift"));
        // Only NeoCloud's answer, or Swarm's own stop, lets the record go.
        record.settle("pod-a", "Pod A", Outcome::NotBilling, 4);
        assert!(!record.pods.contains_key("pod-a"));
    }

    #[test]
    fn a_stop_is_reported_as_it_went_and_a_failure_is_retried() {
        let mut record = Record::default();
        assert!(record.remember("pod-a", "Night shift"));
        assert!(!record.remember("pod-a", "Night shift"), "remembering twice writes nothing");
        record.release("pod-a", "Night shift");
        record.settle("pod-a", "Pod A", Outcome::StopFailed("timeout".into()), 1);
        record.settle("pod-a", "Pod A", Outcome::StopFailed("timeout".into()), 2);
        assert!(record.pods["pod-a"].stop);
        assert_eq!(record.notices.len(), 1, "a failure retried every check is said once");
        assert!(record.notices[0].warning && record.notices[0].text.contains("could not be stopped (timeout)"));
        record.settle("pod-a", "Pod A", Outcome::Stopped, 3);
        assert!(!record.pods.contains_key("pod-a"));
        assert!(!record.notices[1].warning && record.notices[1].text.contains("was stopped, so it is no longer billed"));
    }

    #[test]
    fn the_sandbox_gets_the_model_key_and_never_an_account_or_owner_credential() {
        let mut options = yougori_cli::workload::Options::default();
        options.secret_environment.insert("YOUGORI_MODEL_TOKEN".into(), "model-api-1f2e".into());
        options.secret_environment.insert(crate::model_runner::ADMIN_TOKEN.into(), "model-admin-9a8b".into());
        options.secret_environment.insert("HF_TOKEN".into(), "huggingface-token".into());
        assert!(guest_key_is_model_key(&options));
        // The owner token under the model key's name is refused.
        let mut owner = options.clone();
        owner.secret_environment.insert("YOUGORI_MODEL_TOKEN".into(), "model-admin-9a8b".into());
        assert!(!guest_key_is_model_key(&owner));
        // So is any reference that is not a model API key, like the NeoCloud account's.
        let mut account = options.clone();
        account.secret_environment.insert("YOUGORI_MODEL_TOKEN".into(), "Yougori.Neocloud.v1/runpod".into());
        assert!(!guest_key_is_model_key(&account));
        // And a workload that carries a provider key at all.
        let mut provider = options.clone();
        provider.environment.insert("RUNPOD_API_KEY".into(), "rpa_x".into());
        assert!(!guest_key_is_model_key(&provider));
        assert!(!guest_key_is_model_key(&yougori_cli::workload::Options::default()));
    }

    #[test]
    fn a_worker_reaches_its_pod_at_the_address_the_cloud_bridge_gives_it() {
        let pod = |runtime: Value, kind: &str| -> crate::models::Environment {
            serde_json::from_value(json!({"id":"env-pod-1","name":"Pod A","kind":kind,"status":"running","runtime":"cloud://runpod","runtimeId":runtime,"provider":"cloudSsh","networkAccess":true,"gpuAccess":true,"description":"","createdAt":"","cpuUsage":0,"memoryUsageGb":0,"storageDeltaGb":0,"storageLimitGb":0,"networkRxMbps":0,"resourcePolicy":{"cpu":{"min":1,"preferred":1,"max":1,"current":0},"memoryGb":{"min":1,"preferred":1,"max":1,"current":0},"priority":"normal","dynamic":false}})).unwrap()
        };
        // The bridge attaches a connected pod under its environment id; the hosts entry names the same.
        assert_eq!(model_address(&pod(Value::Null, "cloud")), Some(crate::runtime::fabric::ip_text("env-pod-1")));
        assert_eq!(model_address(&pod(json!("env-pod-1"), "cloud")), Some(crate::runtime::fabric::ip_text("env-pod-1")));
        assert_eq!(model_address(&pod(json!("other-runtime"), "cloud")), None);
        assert_eq!(model_address(&pod(Value::Null, "container")), None);
    }

    #[test]
    fn a_pod_neocloud_has_not_settled_never_joins_and_never_reads_as_stopped() {
        // Created without a provider ID, or a create NeoCloud could not confirm: it may be billing.
        for state in ["Creating", "Needs inspection", "Created — inspect to verify"] {
            assert!(billing(state), "{state}");
            assert!(refusal(Some(&gpu(state)), false, None, "Retry").unwrap().contains("still being created"), "{state}");
        }
        let unknown = Pod { known: false, ..gpu("Running") };
        assert!(!settled(&unknown) && settled(&gpu("Running")) && settled(&gpu("Stopped")));
        assert!(refusal(Some(&unknown), false, None, "Retry").unwrap().contains("still being created"));
        // After a stop, only NeoCloud showing it no longer billing counts as stopped.
        assert!(after_stop(Some(&gpu("Running"))).unwrap_err().contains("still shows it Running"));
        assert!(after_stop(Some(&gpu("Creating"))).is_err());
        assert_eq!(after_stop(Some(&gpu("Stopping"))), Ok(Stopped::Pending), "sent, not confirmed");
        assert_eq!(after_stop(Some(&gpu("Stopped"))), Ok(Stopped::Confirmed));
        assert_eq!(after_stop(None), Ok(Stopped::Confirmed));
    }

    /// NeoCloud as a test sees it: pods by id, what a stop and an inspect do, which actions ran, and
    /// the ledger file as it stood at each stop.
    struct Fake {
        pods: std::sync::Mutex<BTreeMap<String, Pod>>,
        /// The pod's state after a stop NeoCloud accepted, or why the stop failed.
        stop: Result<&'static str, &'static str>,
        /// What an inspect finds, or why it failed.
        inspect: Result<&'static str, &'static str>,
        gone: bool,
        sent: std::sync::Mutex<Vec<&'static str>>,
        watch: Option<std::path::PathBuf>,
        seen: std::sync::Mutex<Vec<String>>,
    }

    impl Cloud for Fake {
        fn pod(&self, id: &str) -> Option<Pod> {
            self.pods.lock().unwrap().get(id).cloned()
        }

        fn gone(&self, _: &str) -> bool {
            self.gone
        }

        fn act(&self, id: &str, action: &'static str) -> impl Future<Output = Result<(), String>> + Send {
            self.sent.lock().unwrap().push(action);
            if action == "stop" {
                if let Some(path) = &self.watch {
                    self.seen.lock().unwrap().push(std::fs::read_to_string(path).unwrap_or_default());
                }
            }
            let result = match if action == "stop" { self.stop } else { self.inspect } {
                Ok(state) => {
                    if let Some(pod) = self.pods.lock().unwrap().get_mut(id) {
                        pod.state = state.into();
                    }
                    Ok(())
                }
                Err(error) => Err(error.to_owned()),
            };
            // A RunPod call takes a while: yielding lets another stop of the same pod start in the
            // meantime, so the gate is what keeps the second from sending again.
            async move {
                tokio::task::yield_now().await;
                result
            }
        }
    }

    fn fake(state: &str, stop: Result<&'static str, &'static str>, inspect: Result<&'static str, &'static str>) -> Fake {
        Fake { pods: std::sync::Mutex::new(BTreeMap::from([("pod-a".to_owned(), gpu(state))])), stop, inspect, gone: false, sent: Default::default(), watch: None, seen: Default::default() }
    }

    #[tokio::test]
    async fn a_stop_counts_only_once_neocloud_shows_the_pod_stopped() {
        // Without a provider ID nothing is sent: NeoCloud's stop would only tidy its own record.
        let unknown = fake("Running", Ok("Stopped"), Err("no provider ID"));
        unknown.pods.lock().unwrap().get_mut("pod-a").unwrap().known = false;
        // And the person is told where the control is: the node's card in Sandboxes, by name.
        assert!(stop_with(&unknown, "pod-a").await.unwrap_err().contains("In Sandboxes, open the Pod A node's card"));
        assert!(!unknown.sent.lock().unwrap().contains(&"stop"), "no stop was sent");
        assert!(matches!(owed_stop_with(&unknown, "pod-a", false).await, Some(Outcome::StopFailed(_))), "and it is never reported stopped");
        // Still running after the stop: a failure, never a stop.
        assert!(stop_with(&fake("Running", Ok("Running"), Ok("Running")), "pod-a").await.unwrap_err().contains("still shows it Running"));
        // Sent, but NeoCloud could not read the pod back: not a stop yet.
        assert_eq!(stop_with(&fake("Running", Ok("Stopping"), Ok("Stopped")), "pod-a").await, Ok(Stopped::Pending));
        assert_eq!(stop_with(&fake("Running", Ok("Stopped"), Ok("Stopped")), "pod-a").await, Ok(Stopped::Confirmed));
    }

    #[tokio::test]
    async fn an_owed_stop_is_settled_only_on_what_neocloud_said() {
        // A failed stop asks NeoCloud before it counts as a failure, except while quitting.
        assert_eq!(owed_stop_with(&fake("Running", Err("timeout"), Ok("Stopped")), "pod-a", false).await, Some(Outcome::NotBilling));
        let quitting = fake("Running", Err("timeout"), Ok("Stopped"));
        assert_eq!(owed_stop_with(&quitting, "pod-a", true).await, Some(Outcome::StopFailed("timeout".into())));
        assert_eq!(*quitting.sent.lock().unwrap(), ["stop"], "quitting has no time for a look");
        // A look that fails, or still sees it billing, never reads as stopped.
        assert_eq!(owed_stop_with(&fake("Running", Err("timeout"), Err("offline")), "pod-a", false).await, Some(Outcome::StopFailed("timeout".into())));
        assert_eq!(owed_stop_with(&fake("Running", Err("timeout"), Ok("Running")), "pod-a", false).await, Some(Outcome::StopFailed("timeout".into())));
        // Sent but not read back: kept owed, without a word.
        assert_eq!(owed_stop_with(&fake("Running", Ok("Stopping"), Ok("Stopped")), "pod-a", false).await, None);
        // NeoCloud let the pod's node go, which it does only for a deleted pod.
        let mut deleted = fake("Running", Err("resource not found"), Err("resource not found"));
        deleted.gone = true;
        assert_eq!(owed_stop_with(&deleted, "pod-a", false).await, Some(Outcome::NotBilling));
    }

    #[test]
    fn a_fresh_look_settles_only_what_neocloud_said() {
        assert_eq!(after_look(Ok("Stopped".into()), false), Looked::Settle(Outcome::NotBilling));
        assert_eq!(after_look(Ok("Deleted".into()), false), Looked::Settle(Outcome::NotBilling));
        assert_eq!(after_look(Ok("Stopping".into()), false), Looked::Settle(Outcome::InUse), "being stopped is not stopped");
        assert_eq!(after_look(Ok("Delete requested — verification pending".into()), false), Looked::Settle(Outcome::InUse));
        assert_eq!(after_look(Ok("Running".into()), true), Looked::Settle(Outcome::InUse));
        assert_eq!(after_look(Ok("Running".into()), false), Looked::Stop);
        assert_eq!(after_look(Err("offline".into()), false), Looked::Settle(Outcome::Unchecked("offline".into())));
        assert!(!off("Stopping") && off("Stopped") && off("Deleted"));
    }

    #[test]
    fn a_record_that_cannot_be_read_is_set_aside_never_taken_for_empty() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("rented.json");
        assert!(Ledger::open(&path, 1).record.pods.is_empty(), "no file is nothing owed");
        let mut owed = Record::default();
        owed.release("pod-a", "Night shift");
        std::fs::write(&path, serde_json::to_vec(&owed).unwrap()).unwrap();
        assert!(Ledger::open(&path, 2).record.pods["pod-a"].stop, "a good file is read as it is");
        // A damaged one keeps its bytes beside it, is never written over, and the page says so.
        std::fs::write(&path, b"{\"pods\": {\"pod-a\": ").unwrap();
        let ledger = Ledger::open(&path, 3);
        assert_eq!(std::fs::read(folder.path().join("rented.json.damaged-3")).unwrap(), b"{\"pods\": {\"pod-a\": ");
        let warning = ledger.notices(3).into_iter().last().unwrap();
        assert!(warning.warning && warning.text.contains("rented.json.damaged-3") && warning.text.contains("Check your rented GPUs in NeoCloud"), "{}", warning.text);
        // The fresh file carries the warning, so it is still on the page after a restart.
        assert!(Ledger::open(&path, 4).record.notices.iter().any(|notice| notice.warning && notice.text.contains("could not read")));
    }

    #[tokio::test]
    async fn a_list_the_disk_will_not_give_is_left_as_it_is_and_read_again() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("held.json");
        // Something the disk will not give as a file, the way a scan holding it for a moment does not.
        std::fs::create_dir(&path).unwrap();
        let held = read_kept::<Record>(&path, 1, "its list").err().expect("never read as empty");
        assert!(held.locked && held.said.contains("reads it again shortly"), "{}", held.said);
        assert!(path.is_dir() && !folder.path().join("held.json.damaged-1").exists(), "left exactly where it is");
        // Stops owed meanwhile are kept, and nothing is written over the file.
        let slot = tokio::sync::Mutex::new(None);
        owe(&slot, &path, 2, &[("pod-new".to_owned(), "your Neo Grid".to_owned())]).await;
        assert!(path.is_dir());
        let notices = ledger_notices(&slot, &path, 2).await;
        assert!(notices.iter().any(|notice| notice.warning && notice.text.contains("could not read")), "the page says why");
        // Once it reads, what it held and what was owed meanwhile are both kept, and written down.
        std::fs::remove_dir(&path).unwrap();
        let mut before = Record::default();
        before.release("pod-old", "Night shift");
        std::fs::write(&path, serde_json::to_vec(&before).unwrap()).unwrap();
        let owed: Vec<String> = with_ledger(&slot, &path, 3, |record| (record.pods.keys().cloned().collect(), false)).await;
        assert_eq!(owed, ["pod-new", "pod-old"]);
        assert_eq!(Ledger::open(&path, 4).record.pods.len(), 2, "both on disk");
        assert!(!ledger_notices(&slot, &path, 4).await.iter().any(|notice| notice.text.contains("could not read")));
    }

    #[tokio::test]
    async fn a_stop_on_its_way_finishes_and_says_so_before_its_pod_is_taken_back() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("back.json");
        let cloud = fake("Running", Ok("Stopped"), Ok("Stopped"));
        let slot = tokio::sync::Mutex::new(None);
        owe(&slot, &path, 1, &[("pod-a".to_owned(), "your Neo Grid".to_owned())]).await;
        // The pod is added back to the grid while its stop is being sent.
        let (stopped, ()) = tokio::join!(settle_stop(&cloud, &slot, &path, "pod-a", false, 2), withdraw_stop(&slot, &path, "pod-a", 2));
        assert_eq!(stopped, Ok(Stopped::Confirmed));
        let after = Ledger::open(&path, 3);
        assert!(after.record.pods.is_empty(), "nothing is owed on a pod that is wanted");
        assert!(after.record.notices.iter().any(|notice| notice.text.contains("was stopped")), "and the stop that happened is on the page");
    }

    #[tokio::test]
    async fn every_stop_is_written_down_before_any_is_sent() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("stops.json");
        let mut cloud = fake("Running", Ok("Stopped"), Ok("Stopped"));
        cloud.pods.lock().unwrap().insert("pod-b".into(), Pod { name: "Pod B".into(), ..gpu("Running") });
        cloud.watch = Some(path.clone());
        let slot = tokio::sync::Mutex::new(None);
        let pods = [("pod-a".to_owned(), "your Neo Grid".to_owned()), ("pod-b".to_owned(), "your Neo Grid".to_owned())];
        let results = stop_all_owed(&cloud, &slot, &path, 5, &pods, true).await;
        let first = cloud.seen.lock().unwrap().first().cloned().unwrap_or_default();
        assert!(first.contains("pod-a") && first.contains("pod-b"), "both owed on disk before the first stop: {first}");
        assert!(results.iter().all(|(_, result)| *result == Ok(Stopped::Confirmed)));
        let after = Ledger::open(&path, 6);
        assert!(after.record.pods.is_empty(), "a confirmed stop leaves the ledger");
        assert_eq!(after.record.notices.len(), 2, "and says so");
    }

    #[tokio::test]
    async fn two_stops_of_one_pod_never_both_report() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("gate.json");
        let cloud = fake("Running", Ok("Stopped"), Ok("Stopped"));
        let slot = tokio::sync::Mutex::new(None);
        owe(&slot, &path, 1, &[("pod-gate".to_owned(), "Night shift".to_owned())]).await;
        cloud.pods.lock().unwrap().insert("pod-gate".into(), gpu("Running"));
        let (first, second) = tokio::join!(settle_stop(&cloud, &slot, &path, "pod-gate", false, 1), settle_stop(&cloud, &slot, &path, "pod-gate", false, 1));
        assert_eq!((first, second), (Ok(Stopped::Confirmed), Ok(Stopped::Confirmed)));
        assert_eq!(*cloud.sent.lock().unwrap(), ["stop"], "the second waited and found it settled");
    }

    #[tokio::test]
    async fn a_pod_whose_worker_is_gone_is_stopped_not_skipped() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("remembered.json");
        let slot = tokio::sync::Mutex::new(None);
        // Remembered while its worker ran, and the worker then failed without a stop owed.
        with_ledger(&slot, &path, 1, |record| ((), record.remember("pod-gone", "Night shift"))).await;
        let cloud = fake("Running", Ok("Stopped"), Ok("Stopped"));
        cloud.pods.lock().unwrap().insert("pod-gone".into(), gpu("Running"));
        // A plain settle sends nothing for a pod nobody owes a stop: that is the second-stop guard.
        assert_eq!(settle_stop(&cloud, &slot, &path, "pod-gone", false, 1).await, Ok(Stopped::Confirmed));
        assert!(cloud.sent.lock().unwrap().is_empty());
        // The supervisor's own stop owes it first, so it is really sent and settled.
        assert_eq!(owe_and_stop(&cloud, &slot, &path, "pod-gone", "Night shift", 2).await, Ok(Stopped::Confirmed));
        assert_eq!(*cloud.sent.lock().unwrap(), ["stop"]);
        let after = Ledger::open(&path, 3);
        assert!(after.record.pods.is_empty());
        assert!(after.record.notices.iter().any(|notice| notice.text.contains("was stopped")));
    }

    #[test]
    fn nothing_is_said_about_a_stop_nobody_owes() {
        // "Yougori keeps trying" is only true while the stop is owed.
        let mut record = Record::default();
        record.settle("pod-a", "Pod A", Outcome::StopFailed("timeout".into()), 1);
        record.settle("pod-a", "Pod A", Outcome::Stopped, 2);
        for at in 3..6 {
            record.settle("pod-a", "Pod A", Outcome::Unchecked("offline".into()), at);
        }
        assert!(record.notices.is_empty(), "{:?}", record.notices);
    }

    #[test]
    fn quitting_stops_every_billing_pod_swarm_knows() {
        let recorded = BTreeMap::from([("pod-a".to_owned(), "Old name".to_owned()), ("pod-b".to_owned(), "Day shift".to_owned()), ("pod-g".to_owned(), "Night".to_owned())]);
        let live = BTreeMap::from([("pod-a".to_owned(), "Night shift".to_owned()), ("pod-c".to_owned(), "Late".to_owned())]);
        // pod-g serves Neo Grid too: stopped from here as well, since the gate makes it harmless.
        let targets = swarm_quit_targets(recorded, live, |pod| pod != "pod-b");
        assert_eq!(targets, [("pod-a".to_owned(), "Night shift".to_owned()), ("pod-c".to_owned(), "Late".to_owned()), ("pod-g".to_owned(), "Night".to_owned())]);
    }

    #[test]
    fn billing_covers_pods_still_powering_on() {
        assert!(billing("Running") && billing("Starting") && billing("Creating"));
        assert!(!billing("Stopped") && !billing("Stopping") && !billing("Deleted"));
        assert!(running("Running") && !running("Starting"));
        assert!(leaving("Deleted") && leaving("Delete requested — verification pending") && !leaving("Stopped"));
        assert!(off("Stopped") && off("Deleted"));
        // Sent, but never read back as stopped: NeoCloud is asked again before it counts.
        assert!(!off("Stopping"));
        assert!(!off("Running") && !off("Starting") && !off("Delete requested — verification pending"));
        // NeoCloud's own power actions, run from the command line, write these when their short
        // check ran out: a pod that may well be running, so Stop all and quitting still stop it.
        for unconfirmed in ["Start pending — not verified", "Stop pending — not verified", "Inspect pending — not verified"] {
            assert!(billing(unconfirmed) && !off(unconfirmed), "{unconfirmed}");
        }
    }
}
