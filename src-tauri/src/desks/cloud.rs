//! A cloud computer the hub creates on its own when no company computer has room for a desk,
//! and removes again when it has hosted nothing for a while. The provider's own signed-in CLI
//! creates the VM; over SSH it gets Yougori and a membership the hub made ahead of time, so it
//! joins with a token and never sees the company password. Every step is in `yougori audit`.
//!
//! Every cloud computer this hub asks for is written to a ledger on disk BEFORE the provider is
//! asked, and stays there until its VM is deleted, whether or not it ever joined: it counts
//! toward the admin's limit, it is the only thing ever deleted here, a failed attempt waits
//! before the next one, and turning the fallback off or deleting the grid removes what it made.
//! Without that, an expired cloud sign-in would create a new computer every few seconds, and a
//! computer made before a crash or a switch-off would bill unseen.
use super::*;
use crate::cloud_deployment::{self, DeployRequest, Deployment};
use crate::deskgrid::CloudSight;
use crate::models::PlatformState;
use crate::runtime::cloud::Profile;
use std::collections::{BTreeMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use yougori_grid::{enterprise::CloudFallback, net::HubAddress};

/// Computers the hub created join under this platform, so they can be told apart and retired.
pub(crate) const PLATFORM: &str = "cloud-fallback";
/// How long a cloud computer may host nothing (or be unreachable) before it is removed.
const RETIRE_AFTER: Duration = Duration::from_secs(60 * 60);
/// How long to wait for a new VM to answer over SSH.
const BOOT_WAIT: Duration = Duration::from_secs(8 * 60);
/// The wait after a failed attempt; each further failure doubles it, up to `MAX_BACKOFF`.
const FIRST_BACKOFF: i64 = 15 * 60;
const MAX_BACKOFF: i64 = 6 * 60 * 60;
/// How long to wait before trying again to delete a VM, or its membership, after a failure.
const RETIRE_RETRY: i64 = 15 * 60;
/// How long a computer recorded before its provider call may go without a deployment record
/// before it is taken as never created (the request records one before it calls the provider).
const PENDING_GRACE: i64 = 30 * 60;

/// One computer is created at a time.
static PROVISIONING: AtomicBool = AtomicBool::new(false);
/// One writer at a time for the ledger file.
static LEDGER: std::sync::Mutex<()> = std::sync::Mutex::new(());
/// Whether the last write of the ledger failed: nothing is created until one succeeds, since a
/// computer that cannot be recorded could not be counted or removed either.
static LEDGER_WRITE_FAILED: AtomicBool = AtomicBool::new(false);
/// Computers being created or removed right now: one task works on each while the grid keeps
/// checking in, so a computer still being set up is never removed under it.
static BUSY: std::sync::Mutex<Option<HashSet<String>>> = std::sync::Mutex::new(None);

/// A computer claimed in `BUSY` until this is dropped.
struct Busy(String);

impl Busy {
    fn claim(environment_id: &str) -> Option<Busy> {
        let mut busy = BUSY.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        busy.get_or_insert_with(HashSet::new).insert(environment_id.to_owned()).then(|| Busy(environment_id.to_owned()))
    }
}

impl Drop for Busy {
    fn drop(&mut self) {
        if let Some(busy) = BUSY.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).as_mut() {
            busy.remove(&self.0);
        }
    }
}

/// Lets the next computer be created when this attempt ends, however it ends.
struct Provisioning;

impl Drop for Provisioning {
    fn drop(&mut self) {
        PROVISIONING.store(false, Ordering::SeqCst);
    }
}

/// What this hub computer has asked its cloud for.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Ledger {
    /// Each cloud computer asked for here, by environment ID, until its VM is deleted.
    #[serde(default)]
    computers: BTreeMap<String, Computer>,
    /// The cloud settings the failures below happened under; changing them starts afresh.
    #[serde(default)]
    settings: String,
    #[serde(default)]
    failures: u32,
    /// No new computer before this time (Unix seconds).
    #[serde(default)]
    retry_after: i64,
    /// Why the last attempt failed, shown to the admin until one succeeds.
    #[serde(default)]
    last_error: Option<String>,
    /// A deployment that may already be billing and needs a person to look at it: nothing new is
    /// created until it is deleted.
    #[serde(default)]
    held_by: Option<String>,
    /// Waiting desks (as `needs_computer` describes them) that a computer of these settings joined
    /// for and never took: they are not tried again until the settings or the desk change.
    #[serde(default)]
    did_not_fit: Vec<String>,
    /// What the admin should know that is not a failure: computers kept because they hold desks,
    /// or what happens to the rest while the grid is paused, deleted or not running.
    #[serde(default)]
    note: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Computer {
    name: String,
    /// Its membership in the grid, once it has one.
    #[serde(default)]
    member_id: Option<String>,
    /// The waiting desk it was created for.
    #[serde(default)]
    reason: String,
    #[serde(default)]
    created_at: i64,
    /// Recorded before the provider was asked; becomes false once its deployment is recorded.
    #[serde(default)]
    pending: bool,
    /// Whether it has ever hosted or packed a desk.
    #[serde(default)]
    hosted: bool,
    #[serde(default)]
    offline_since: Option<i64>,
    /// Its VM is deleted; only its membership is left to remove.
    #[serde(default)]
    vm_deleted: bool,
    /// When removing it last failed: it is tried again later, not on every tick.
    #[serde(default)]
    retire_failed_at: Option<i64>,
}

/// How an attempt failed: one worth trying again after a wait, or one that left a deployment a
/// person has to inspect before anything else is created.
#[derive(Debug, PartialEq)]
enum Failure {
    Retry(String),
    Inspect { environment_id: String, message: String },
}

/// The world the fallback acts on: its ledger, the app's state, the provider and the grid. The
/// app implements it with the real things; tests with a record of what was asked.
trait Cloud {
    fn record(&self, change: &mut dyn FnMut(&mut Ledger)) -> Result<Ledger, String>;
    fn state(&self) -> Result<PlatformState, String>;
    async fn deploy(&self, id: &str, request: DeployRequest) -> Result<(), String>;
    async fn delete(&self, environment_id: &str, deployment_name: &str) -> Result<(), String>;
    async fn join(&self, name: &str, environment_id: &str, deployment: &Deployment) -> Result<(), String>;
    async fn remove_membership(&self, member_id: &str) -> Result<(), String>;
}

struct AppCloud<'a> {
    app: &'a AppHandle,
    fallback: Option<&'a CloudFallback>,
    reach: Option<&'a HubAddress>,
    /// Whether the hub that made the memberships still runs here.
    hub: bool,
}

impl Cloud for AppCloud<'_> {
    fn record(&self, change: &mut dyn FnMut(&mut Ledger)) -> Result<Ledger, String> {
        update_ledger(self.app, change)
    }
    fn state(&self) -> Result<PlatformState, String> {
        self.app.state::<PlatformStore>().snapshot()
    }
    async fn deploy(&self, id: &str, request: DeployRequest) -> Result<(), String> {
        cloud_deployment::deploy_cloud_environment_as(id.to_owned(), request, true, &self.app.state::<PlatformStore>()).await.map(|_| ())
    }
    async fn delete(&self, environment_id: &str, deployment_name: &str) -> Result<(), String> {
        cloud_deployment::delete_cloud_deployment(environment_id.to_owned(), deployment_name.to_owned(), self.app.state(), self.app.state()).await.map(|_| ())
    }
    async fn join(&self, name: &str, environment_id: &str, deployment: &Deployment) -> Result<(), String> {
        let (Some(fallback), Some(reach)) = (self.fallback, self.reach) else { return Err("The sandbox grid is not running".into()) };
        join(self, self.app, fallback, reach, name, environment_id, deployment).await
    }
    async fn remove_membership(&self, member_id: &str) -> Result<(), String> {
        // A grid that is gone has no membership left to remove.
        if !self.hub {
            return Ok(());
        }
        crate::deskgrid::with_hub(self.app, |hub| {
            // One the admin already removed is gone too.
            if !hub.status()["members"].as_array().is_some_and(|members| members.iter().any(|member| member["id"] == member_id)) {
                return Ok(());
            }
            hub.enterprise(json!({"action": "computerRemove", "id": member_id})).map(|_| ())
        })
        .await
    }
}

fn ledger_path(app: &AppHandle) -> PathBuf {
    folder(app).join("cloud-computers.json")
}

const UNREADABLE: &str = "The record of cloud computers could not be read, so none is created or removed automatically. Check Cloud deployments for computers named yougori-desk- and delete any you no longer need, then remove cloud-computers.json from the grid folder in Yougori's data folder.";

fn load_ledger(app: &AppHandle) -> Result<Ledger, String> {
    match std::fs::read(ledger_path(app)) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|_| UNREADABLE.to_owned()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Ledger::default()),
        Err(_) => Err(UNREADABLE.to_owned()),
    }
}

/// Reads, changes and writes the ledger as one step.
fn update_ledger(app: &AppHandle, change: &mut dyn FnMut(&mut Ledger)) -> Result<Ledger, String> {
    let _writer = LEDGER.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut ledger = load_ledger(app)?;
    let before = ledger.clone();
    change(&mut ledger);
    // After a failed write every update writes, unchanged or not, so creating resumes once the
    // disk takes it again.
    if ledger != before || LEDGER_WRITE_FAILED.load(Ordering::SeqCst) {
        let written = write_json(&ledger_path(app), &ledger);
        LEDGER_WRITE_FAILED.store(written.is_err(), Ordering::SeqCst);
        written.map_err(|error| format!("The record of cloud computers could not be saved ({error}), so none is created until it can be."))?;
    }
    Ok(ledger)
}

/// What the admin sees, while there is anything to see: why the last attempt failed, when the
/// next may run, whether creating is held until they inspect a deployment, and how many cloud
/// computers are still running. `null` when the fallback has never made one.
pub(crate) fn status(app: &AppHandle) -> Value {
    match load_ledger(app) {
        Ok(ledger) if ledger == Ledger::default() => Value::Null,
        Ok(ledger) => json!({
            "computers": ledger.computers.values().filter(|computer| !computer.vm_deleted).count(),
            "error": ledger.last_error,
            "note": ledger.note,
            "retryAfter": (ledger.retry_after > yougori_grid::now()).then_some(ledger.retry_after),
            "held": ledger.held_by.is_some(),
        }),
        Err(error) => json!({"computers": null, "error": error, "note": null, "retryAfter": null, "held": true}),
    }
}

/// The settings a failure or a "did not fit" belongs to.
fn settings_of(fallback: &CloudFallback) -> String {
    [&fallback.provider, &fallback.account, &fallback.region, &fallback.image, &fallback.image_project, &fallback.machine_type, &fallback.subnet, &fallback.security_group, &fallback.resource_group, &fallback.key_pair, &fallback.username].map(|value| value.as_str()).join("|")
}

/// Brings the ledger up to date with what the store and the hub say now.
fn observe(ledger: &mut Ledger, state: &PlatformState, members: &[Value], settings: Option<&str>, now: i64) {
    if let Some(settings) = settings.filter(|settings| ledger.settings != *settings) {
        ledger.settings = settings.to_owned();
        ledger.failures = 0;
        ledger.retry_after = 0;
        ledger.last_error = None;
        ledger.did_not_fit.clear();
    }
    let alive = |id: &str| state.cloud_deployments.get(id).is_some_and(|deployment| deployment.state != "Deleted");
    for (id, computer) in ledger.computers.iter_mut() {
        if state.cloud_deployments.contains_key(id) {
            // Its request recorded it, so the provider was asked: from now on it is like any other.
            computer.pending = false;
        }
        if !computer.pending && !alive(id) && computer.member_id.is_some() {
            // Its VM is gone, whoever deleted it: only its place in the grid is left to remove.
            computer.vm_deleted = true;
        }
        let Some(member) = computer.member_id.as_ref().and_then(|member_id| members.iter().find(|member| member["id"] == member_id.as_str())) else { continue };
        if hosting(member) > 0 {
            computer.hosted = true;
        }
        computer.offline_since = if member["online"] == true { None } else { computer.offline_since.or(Some(now)) };
    }
    // A gone VM stops counting once its place in the grid is removed too. One asked for moments
    // ago may have no deployment record yet; one that still has none long after never reached
    // the provider (the request records it first).
    ledger.computers.retain(|id, computer| alive(id) || (computer.vm_deleted && computer.member_id.is_some()) || (computer.pending && now - computer.created_at < PENDING_GRACE));
    if ledger.held_by.as_deref().is_some_and(|id| !alive(id)) {
        // The deployment the admin had to look at is gone, and so is the reason creation stopped.
        ledger.held_by = None;
        ledger.last_error = None;
    }
}

/// How many desks a member hosts or is packing; an unknown count is counted as hosting.
fn hosting(member: &Value) -> u64 {
    member["desks"].as_u64().unwrap_or(1) + member["packing"].as_u64().unwrap_or(0)
}

/// Whether a new computer may be created for `reason` now, or why not.
fn may_create(ledger: &Ledger, max_computers: u32, reason: &str, now: i64, ledger_writable: bool) -> Result<(), String> {
    if !ledger_writable {
        return Err("the record of cloud computers cannot be saved".into());
    }
    if let Some(held) = &ledger.held_by {
        let name = ledger.computers.get(held).map_or(held.as_str(), |computer| computer.name.as_str());
        return Err(format!("{name} needs inspection in Cloud deployments"));
    }
    if now < ledger.retry_after {
        return Err("waiting after a failed attempt".into());
    }
    if ledger.did_not_fit.iter().any(|desk| desk == reason) {
        return Err("a computer of this type did not take this desk".into());
    }
    if ledger.computers.len() as u32 >= max_computers {
        return Err("the limit of cloud computers is reached".into());
    }
    Ok(())
}

/// The wait after `failures` failed attempts in a row.
fn backoff(failures: u32) -> i64 {
    FIRST_BACKOFF.saturating_mul(1 << failures.saturating_sub(1).min(16)).min(MAX_BACKOFF)
}

/// A cloud computer of ours that is online and has hosted nothing for an hour. A desk it is still
/// packing for a move counts as hosted: retiring it then would lose that desk's data.
fn idle(member: &Value, now: i64) -> bool {
    member["online"] == true && hosting(member) == 0 && member["joinedAt"].as_i64().is_some_and(|at| now - at > RETIRE_AFTER.as_secs() as i64)
}

/// Whether to remove this computer now, with its grid open and the fallback on: idle for an
/// hour, unreachable for an hour while hosting nothing, or never given a membership an hour
/// after it was created. Never while a recent removal of it failed.
fn retire_due(computer: &Computer, member: Option<&Value>, now: i64) -> bool {
    let hour = RETIRE_AFTER.as_secs() as i64;
    if computer.retire_failed_at.is_some_and(|at| now - at < RETIRE_RETRY) {
        return false;
    }
    if computer.vm_deleted {
        return true;
    }
    match member {
        Some(member) => idle(member, now) || (hosting(member) == 0 && member["online"] != true && computer.offline_since.is_some_and(|since| now - since > hour)),
        None => now - computer.created_at > hour,
    }
}

/// Which computers to remove, and whether to create one, as the grid stands.
#[derive(Debug, Default, PartialEq)]
struct Plan {
    retire: Vec<String>,
    create: Option<String>,
    note: Option<String>,
    /// Whether a computer removed for sitting idle tells something about its size: only while
    /// the fallback is on, so a desk was waiting for it.
    judge_fit: bool,
}

/// What the fallback does on this tick. With the grid open and the fallback on, computers
/// follow `retire_due` and one is created when a desk waits and `may_create` allows. With the
/// fallback turned off, every computer hosting nothing is removed at once, and those still
/// holding desks are kept (removing one would destroy somebody's desk) and counted for the
/// admin. With the grid deleted, every computer is removed: their desks went with it. While the
/// grid is paused for deletion, or its state is unknown, nothing is removed or created.
fn plan(ledger: &Ledger, sight: &Sight, now: i64, ledger_writable: bool) -> Plan {
    let waited = |computer: &Computer| computer.retire_failed_at.is_none_or(|at| now - at >= RETIRE_RETRY);
    let running = ledger.computers.values().filter(|computer| !computer.vm_deleted).count();
    let say = |one: &str, many: String| match running {
        0 => None,
        1 => Some(one.to_owned()),
        _ => Some(many),
    };
    match sight {
        Sight::Open { enabled, members, needed, max_computers, can_reach } => {
            let member_of = |computer: &Computer| computer.member_id.as_ref().and_then(|id| members.iter().find(|member| member["id"] == id.as_str()));
            if *enabled {
                let retire = ledger.computers.iter().filter(|(_, computer)| !computer.pending && retire_due(computer, member_of(computer), now)).map(|(id, _)| id.clone()).collect();
                let create = needed.as_deref().filter(|reason| *can_reach && may_create(ledger, *max_computers, reason, now, ledger_writable).is_ok()).map(str::to_owned);
                return Plan { retire, create, note: None, judge_fit: true };
            }
            let holding = |computer: &Computer| !computer.vm_deleted && member_of(computer).is_some_and(|member| hosting(member) > 0);
            let retire = ledger.computers.iter().filter(|(_, computer)| !computer.pending && waited(computer) && !holding(computer)).map(|(id, _)| id.clone()).collect();
            let kept = ledger.computers.values().filter(|computer| holding(computer)).count();
            let note = match kept {
                0 => None,
                1 => Some("Cloud computers are turned off. 1 cloud computer still hosts desks; it is removed once they have moved or been deleted.".to_owned()),
                kept => Some(format!("Cloud computers are turned off. {kept} cloud computers still host desks; each is removed once its desks have moved or been deleted.")),
            };
            Plan { retire, create: None, note, judge_fit: false }
        }
        Sight::Gone => Plan {
            retire: ledger.computers.iter().filter(|(_, computer)| !computer.pending && waited(computer)).map(|(id, _)| id.clone()).collect(),
            note: say("This sandbox grid was deleted, so the cloud computer it created is being removed.", format!("This sandbox grid was deleted, so the {running} cloud computers it created are being removed.")),
            ..Plan::default()
        },
        Sight::Closing => Plan {
            note: say("This sandbox grid is paused for deletion. The cloud computer it created is kept, and costs money, until the grid is restored or deleted.", format!("This sandbox grid is paused for deletion. The {running} cloud computers it created are kept, and cost money, until the grid is restored or deleted.")),
            ..Plan::default()
        },
        Sight::Unknown => Plan {
            note: say("This sandbox grid is not running, so nothing removes the cloud computer it created. Start the grid again, or delete it in Cloud deployments.", format!("This sandbox grid is not running, so nothing removes the {running} cloud computers it created. Start the grid again, or delete them in Cloud deployments.")),
            ..Plan::default()
        },
    }
}

/// The grid as `plan` needs it.
enum Sight {
    Open { enabled: bool, members: Vec<Value>, needed: Option<String>, max_computers: u32, can_reach: bool },
    Closing,
    Gone,
    Unknown,
}

/// Runs on every check-in: removes the cloud computers no longer needed (whatever the fallback's
/// setting, so switching it off or deleting the grid stops their bills) and creates one when a
/// desk waits and that is allowed. Both run apart from the check-in, which never waits on them.
pub(crate) async fn tick(app: &AppHandle) {
    let view = {
        let grid = app.state::<crate::deskgrid::DeskGrid>();
        crate::deskgrid::cloud_view(app, &grid).await
    };
    let (sight, fallback, reach) = match view {
        CloudSight::Open { fallback, needed, reach, members } => {
            let fallback = fallback.filter(|fallback| fallback.enabled);
            let max_computers = fallback.as_ref().map_or(0, |fallback| fallback.max_computers);
            (Sight::Open { enabled: fallback.is_some(), members, needed, max_computers, can_reach: reach.is_some() }, fallback, reach)
        }
        CloudSight::Closing => (Sight::Closing, None, None),
        CloudSight::Gone => (Sight::Gone, None, None),
        CloudSight::Unknown => (Sight::Unknown, None, None),
    };
    let Ok(state) = app.state::<PlatformStore>().snapshot() else { return };
    let now = yougori_grid::now();
    let members = match &sight {
        Sight::Open { members, .. } => members.clone(),
        _ => Vec::new(),
    };
    let settings = fallback.as_ref().map(settings_of);
    let mut seen = |ledger: &mut Ledger| observe(ledger, &state, &members, settings.as_deref(), now);
    let ledger = match update_ledger(app, &mut seen) {
        Ok(ledger) => ledger,
        // Unsaved, but removing what is no longer needed must not stop with the disk. Unreadable:
        // nothing is created or removed, and the status says so.
        Err(_) => match load_ledger(app) {
            Ok(mut ledger) => {
                seen(&mut ledger);
                ledger
            }
            Err(_) => return,
        },
    };
    let decided = plan(&ledger, &sight, now, !LEDGER_WRITE_FAILED.load(Ordering::SeqCst));
    if ledger.note != decided.note {
        let note = decided.note.clone();
        let _ = update_ledger(app, &mut |ledger| ledger.note = note.clone());
    }
    let hub = matches!(sight, Sight::Open { .. } | Sight::Closing);
    for environment_id in decided.retire {
        let Some(computer) = ledger.computers.get(&environment_id).cloned() else { continue };
        // Being set up or removed already: that task finishes it.
        let Some(busy) = Busy::claim(&environment_id) else { continue };
        let unfit = decided.judge_fit && computer.member_id.as_ref().is_some_and(|id| members.iter().any(|member| member["id"] == id.as_str()));
        let app = app.clone();
        tauri::async_runtime::spawn(async move {
            let _busy = busy;
            let cloud = AppCloud { app: &app, fallback: None, reach: None, hub };
            retire(&cloud, &environment_id, &computer, unfit).await;
        });
    }
    let (Some(reason), Some(fallback), Some(reach)) = (decided.create, fallback, reach) else { return };
    if PROVISIONING.swap(true, Ordering::SeqCst) {
        return;
    }
    let provisioning = Provisioning;
    let app = app.clone();
    let number = ledger.computers.len() + 1;
    tauri::async_runtime::spawn(async move {
        let _provisioning = provisioning;
        let cloud = AppCloud { app: &app, fallback: Some(&fallback), reach: Some(&reach), hub: true };
        let result = provision(&cloud, &fallback, &reach, &reason, number).await;
        let now = yougori_grid::now();
        let recorded = cloud.record(&mut |ledger| match &result {
            Ok(_) => {
                ledger.failures = 0;
                ledger.retry_after = 0;
                ledger.last_error = None;
            }
            Err(Failure::Retry(message)) => {
                ledger.failures = ledger.failures.saturating_add(1);
                ledger.retry_after = now + backoff(ledger.failures);
                ledger.last_error = Some(format!("No cloud computer was created: {message}"));
            }
            Err(Failure::Inspect { environment_id, message }) => {
                ledger.held_by = Some(environment_id.clone());
                ledger.last_error = Some(message.clone());
            }
        });
        let outcome: Result<(), String> = match (&result, recorded) {
            (_, Err(error)) => Err(error),
            (Ok(_), _) => Ok(()),
            (Err(Failure::Retry(message) | Failure::Inspect { message, .. }), _) => Err(message.clone()),
        };
        crate::security::record(Event::new("desks.cloud.created").text("reason", &reason).outcome(&outcome));
        drop(_provisioning);
        app.state::<crate::deskgrid::DeskGrid>().wake();
    });
}

/// Creates one cloud computer, installs Yougori on it and has it take up a membership the hub
/// made for it. It is written to the ledger under the environment ID it will have before the
/// provider is asked, so a crash, a quit or a failed write in between never leaves a VM nothing
/// counts or removes; and only the deployment with that ID is ever taken for it.
async fn provision<C: Cloud>(cloud: &C, fallback: &CloudFallback, reach: &HubAddress, reason: &str, number: usize) -> Result<String, Failure> {
    if let HubAddress::Direct(direct) = reach {
        if yougori_grid::net::private(direct.ip()) {
            return Err(Failure::Retry("The sandbox grid is reachable only on this network; a cloud computer needs its public link (host it with --tunnel quick or a Cloudflare domain)".into()));
        }
    }
    let retry = |error: String| Failure::Retry(error);
    // A failed or retired computer can leave its environment behind under its name, and an
    // environment name may be used only once: take the first number nobody holds.
    let state = cloud.state().map_err(retry)?;
    let name = (number..).map(|n| format!("yougori-desk-{n}")).find(|name| !state.environments.iter().any(|env| env.name.eq_ignore_ascii_case(name))).ok_or_else(|| retry("No free cloud computer name".into()))?;
    let request = DeployRequest {
        provider: fallback.provider.clone(),
        account: fallback.account.clone(),
        region: fallback.region.clone(),
        name: name.clone(),
        image: fallback.image.clone(),
        machine_type: fallback.machine_type.clone(),
        subnet: fallback.subnet.clone(),
        resource_group: fallback.resource_group.clone(),
        security_group: fallback.security_group.clone(),
        key_pair: fallback.key_pair.clone(),
        ssh_public_key: fallback.ssh_public_key.clone(),
        image_project: fallback.image_project.clone(),
        container_image: String::new(),
        username: fallback.username.clone(),
    };
    cloud_deployment::validate(&request).map_err(retry)?;
    let environment_id = format!("env-{}", uuid::Uuid::new_v4());
    let _busy = Busy::claim(&environment_id);
    // Asked for from here on: counted toward the limit and removed like any other, even if this
    // computer stops during the provider call. If it cannot be written, nothing is asked for.
    cloud.record(&mut |ledger| {
        ledger.computers.insert(environment_id.clone(), Computer { name: name.clone(), reason: reason.to_owned(), created_at: yougori_grid::now(), pending: true, ..Default::default() });
    }).map_err(retry)?;
    let deployed = cloud.deploy(&environment_id, request).await;
    let after = cloud.state().map_err(retry)?;
    let Some(deployment) = after.cloud_deployments.get(&environment_id).cloned() else {
        // The request stopped before it recorded anything, so before the provider was called.
        let _ = cloud.record(&mut |ledger| {
            ledger.computers.remove(&environment_id);
        });
        return Err(retry(deployed.err().unwrap_or_else(|| "The cloud deployment was not recorded".into())));
    };
    let _ = cloud.record(&mut |ledger| {
        if let Some(computer) = ledger.computers.get_mut(&environment_id) {
            computer.pending = false;
        }
    });
    let inspect = |message: String| Failure::Inspect { environment_id: environment_id.clone(), message };
    if let Err(error) = deployed {
        return Err(inspect(format!("Creating cloud computer {name} failed after it was requested ({error}). It may already cost money: inspect it in Cloud deployments and delete it there. No other cloud computer is created until then.")));
    }
    if let Some(error) = &deployment.last_error {
        return Err(inspect(format!("Cloud computer {name} could not be created cleanly: {error} No other cloud computer is created until it is deleted in Cloud deployments.")));
    }
    if deployment.address.is_empty() {
        return Err(inspect(format!("Cloud computer {name} has no address yet. Inspect it in Cloud deployments and delete it there; no other cloud computer is created until then.")));
    }
    if let Err(error) = cloud.join(&name, &environment_id, &deployment).await {
        // It never became a desk computer: delete the VM this attempt created, and only that one,
        // so a failed setup does not keep running and costing money.
        return match cloud.delete(&environment_id, &deployment.name).await {
            Ok(()) => {
                let _ = cloud.record(&mut |ledger| {
                    ledger.computers.remove(&environment_id);
                });
                Err(retry(error))
            }
            Err(cleanup) => Err(inspect(format!("{error}. Cloud computer {name} could not be deleted ({cleanup}); delete it in Cloud deployments before it costs more."))),
        };
    }
    Ok(environment_id)
}

/// Waits for the new VM, installs Yougori on it and has it take up a membership made for it.
async fn join(cloud: &AppCloud<'_>, app: &AppHandle, fallback: &CloudFallback, reach: &HubAddress, name: &str, environment_id: &str, deployment: &Deployment) -> Result<(), String> {
    // Trust the key the brand-new machine shows: nobody else has had its address yet.
    let deadline = Instant::now() + BOOT_WAIT;
    let keys = loop {
        match crate::runtime::cloud::scan(deployment.address.clone(), 22).await {
            Ok(keys) if !keys.is_empty() => break keys,
            _ if Instant::now() < deadline => tokio::time::sleep(Duration::from_secs(10)).await,
            Ok(_) => return Err("The cloud computer did not answer over SSH in time".into()),
            Err(error) => return Err(format!("The cloud computer did not answer over SSH: {error}")),
        }
    };
    let host_key = keys.iter().find(|key| key.key.starts_with("ssh-ed25519 ")).unwrap_or(&keys[0]).key.clone();
    let profile = Profile { name: name.to_owned(), vendor: fallback.provider.clone(), host: deployment.address.clone(), port: 22, username: fallback.username.clone(), identity_file: fallback.identity_file.clone(), host_key };
    let runtime = app.state::<crate::runtime::RuntimeManager>();
    runtime.cloud.save(environment_id, &profile)?;
    let known = crate::runtime::cloud::known_hosts(&runtime.cloud, environment_id)?;
    // A membership made for it: the token is all it gets, on its stdin, never in a command line.
    let made = crate::deskgrid::with_hub(app, |hub| hub.preregister_member(name, PLATFORM)).await?;
    let member_id = made["memberId"].as_str().unwrap_or_default().to_owned();
    // Retirement finds a computer by this membership, never by a name another computer could
    // claim. If it cannot be written, the membership goes again rather than linger unrecorded.
    if let Err(error) = cloud.record(&mut |ledger| {
        if let Some(computer) = ledger.computers.get_mut(environment_id) {
            computer.member_id = Some(member_id.clone());
        }
    }) {
        let _ = cloud.remove_membership(&member_id).await;
        return Err(error);
    }
    let membership = json!({
        "company": made["grid"]["name"], "gridId": made["grid"]["id"], "address": reach.to_string(), "fingerprint": made["fingerprint"],
        "memberId": made["memberId"], "memberToken": made["memberToken"], "name": name,
    });
    let script = "set -e; if ! command -v yougori >/dev/null 2>&1; then curl -fsSL https://yougori.com/install.sh | sh >/dev/null; fi; yougori desks adopt --file - --yes";
    let output = crate::runtime::cloud::run_script(&profile, &known, script, membership.to_string()).await;
    if let Err(error) = &output {
        // It never joined: forget the membership so no ghost computer lingers in the grid.
        let _ = cloud.remove_membership(&member_id).await;
        return Err(format!("Yougori could not be installed on the cloud computer: {error}"));
    }
    Ok(())
}

/// Removes a cloud computer this hub created: the VM and its disk first, then its membership, so
/// a VM whose delete fails stays listed, is retried later and is shown to the admin, never
/// forgotten while it costs money; and a membership that could not be removed is retried too.
/// Only computers in the ledger, under their own environment ID, are ever deleted here.
async fn retire<C: Cloud>(cloud: &C, environment_id: &str, computer: &Computer, unfit: bool) {
    let now = yougori_grid::now();
    let mut deleted: Result<(), String> = Ok(());
    if !computer.vm_deleted {
        let deployment = cloud.state().ok().and_then(|state| state.cloud_deployments.get(environment_id).cloned());
        deleted = match deployment {
            Some(deployment) if deployment.state == "Deleted" => Ok(()),
            // Its deployment name is its own name with a suffix: anything else is not ours to delete.
            Some(deployment) if deployment.name.starts_with(&format!("{}-", computer.name)) => cloud.delete(environment_id, &deployment.name).await,
            Some(_) => Err("its deployment does not carry its name, so it was left for you to inspect".into()),
            None => Ok(()),
        };
        if deleted.is_ok() {
            let _ = cloud.record(&mut |ledger| {
                if let Some(entry) = ledger.computers.get_mut(environment_id) {
                    entry.vm_deleted = true;
                }
            });
        }
    }
    let removed = match (&deleted, &computer.member_id) {
        (Ok(()), Some(member_id)) => cloud.remove_membership(member_id).await,
        _ => Ok(()),
    };
    // A computer that joined, sat idle while the fallback was on and never took a desk was too
    // small for the desk it was made for: do not make the same one again for that desk.
    let did_not_fit = deleted.is_ok() && !computer.vm_deleted && unfit && !computer.hosted && !computer.reason.is_empty();
    let _ = cloud.record(&mut |ledger| match (&deleted, &removed) {
        (Ok(()), Ok(())) => {
            // Only once, should a check-in that read the ledger earlier remove it a second time.
            if ledger.computers.remove(environment_id).is_some() && did_not_fit {
                ledger.did_not_fit.push(computer.reason.clone());
                ledger.last_error = Some(format!("Cloud computer {} joined but no desk was placed on it, so it was removed. Its machine type may be too small for the waiting desk: choose a larger one in the cloud computer settings, or a smaller desk.", computer.name));
            }
        }
        (Ok(()), Err(error)) => {
            if let Some(entry) = ledger.computers.get_mut(environment_id) {
                entry.retire_failed_at = Some(now);
            }
            ledger.last_error = Some(format!("Cloud computer {} was deleted, but its place in the grid could not be removed ({error}); this is retried.", computer.name));
        }
        (Err(error), _) => {
            if let Some(entry) = ledger.computers.get_mut(environment_id) {
                entry.retire_failed_at = Some(now);
            }
            ledger.last_error = Some(format!("Cloud computer {} could not be deleted: {error}. It may still cost money; delete it in Cloud deployments.", computer.name));
        }
    });
    crate::security::record(Event::new("desks.cloud.retired").env(environment_id).text("name", &computer.name).flag("membershipRemoved", removed.is_ok()).flag("didNotFit", did_not_fit).outcome(&deleted));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn deployment(name: &str, state: &str) -> Deployment {
        serde_json::from_value(json!({"provider":"aws","account":"a","region":"r","resourceGroup":"","name":name,"resourceId":"i-1","state":state,"address":"203.0.113.9","username":"ubuntu","requestId":"q","lastError":null})).unwrap()
    }

    fn environment(id: &str, name: &str) -> crate::models::Environment {
        serde_json::from_value(json!({"id":id,"name":name,"kind":"cloud","provider":"cloudSsh","status":"stopped","runtime":"aws","description":"","createdAt":"test","cpuUsage":0,"memoryUsageGb":0,"storageDeltaGb":0,"networkRxMbps":0,"resourcePolicy":{"cpu":{"min":0,"preferred":0,"max":0,"current":0},"memoryGb":{"min":0,"preferred":0,"max":0,"current":0},"priority":"normal","dynamic":false}})).unwrap()
    }

    fn computer(name: &str, member: Option<&str>, created_at: i64) -> Computer {
        Computer { name: name.into(), member_id: member.map(str::to_owned), reason: "Design has waited".into(), created_at, ..Default::default() }
    }

    fn fallback() -> CloudFallback {
        serde_json::from_value(json!({"enabled":true,"provider":"aws","account":"a","region":"eu-west-1","image":"ami-123456","machineType":"t3.large","subnet":"subnet-1","securityGroup":"sg-1","keyPair":"k","username":"ubuntu","identityFile":"id_ed25519","maxComputers":2})).unwrap()
    }

    /// A cloud that records what it was asked, in order, and can be told to fail.
    #[derive(Default)]
    struct Fake {
        ledger: RefCell<Ledger>,
        state: RefCell<Option<PlatformState>>,
        calls: RefCell<Vec<String>>,
        fail_writes: bool,
        /// What `deploy` does: record the deployment (as the real request does before it calls
        /// the provider), or fail before recording anything.
        records: bool,
        /// A person's own environment that appears, with this attempt's name, during the call.
        rival: bool,
    }

    impl Cloud for Fake {
        fn record(&self, change: &mut dyn FnMut(&mut Ledger)) -> Result<Ledger, String> {
            if self.fail_writes {
                return Err("disk full".into());
            }
            change(&mut self.ledger.borrow_mut());
            Ok(self.ledger.borrow().clone())
        }
        fn state(&self) -> Result<PlatformState, String> {
            Ok(self.state.borrow().clone().unwrap_or_else(|| PlatformState::empty().unwrap()))
        }
        async fn deploy(&self, id: &str, request: DeployRequest) -> Result<(), String> {
            self.calls.borrow_mut().push(format!("deploy {id} with ledger {}", self.ledger.borrow().computers.contains_key(id)));
            let mut state = self.state()?;
            if self.rival {
                state.environments.push(environment("env-someone-elses", &request.name));
                state.cloud_deployments.insert("env-someone-elses".into(), deployment(&format!("{}-1234abcd", request.name), "Created"));
            }
            if self.records {
                state.environments.push(environment(id, &request.name));
                state.cloud_deployments.insert(id.to_owned(), deployment(&format!("{}-abcd1234", request.name), "Created"));
            }
            *self.state.borrow_mut() = Some(state);
            if self.records { Ok(()) } else { Err("An environment with this name already exists".into()) }
        }
        async fn delete(&self, environment_id: &str, _: &str) -> Result<(), String> {
            self.calls.borrow_mut().push(format!("delete {environment_id}"));
            Ok(())
        }
        async fn join(&self, _: &str, environment_id: &str, _: &Deployment) -> Result<(), String> {
            self.calls.borrow_mut().push(format!("join {environment_id}"));
            Err("SSH refused".into())
        }
        async fn remove_membership(&self, member_id: &str) -> Result<(), String> {
            self.calls.borrow_mut().push(format!("remove {member_id}"));
            Ok(())
        }
    }

    fn reach() -> HubAddress {
        HubAddress::Direct("203.0.113.1:7470".parse().unwrap())
    }

    fn run<T>(future: impl std::future::Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(future)
    }

    #[test]
    fn a_cloud_computer_still_packing_a_desk_is_not_retired() {
        let joined = 0;
        let later = joined + RETIRE_AFTER.as_secs() as i64 + 1;
        assert!(idle(&json!({"online":true,"desks":0,"packing":0,"joinedAt":joined}), later));
        assert!(!idle(&json!({"online":true,"desks":0,"packing":1,"joinedAt":joined}), later), "packing a desk is hosting it");
        assert!(!idle(&json!({"online":true,"desks":1,"joinedAt":joined}), later));
        assert!(!idle(&json!({"online":true,"joinedAt":joined}), later), "an unknown count is not idle");
        assert!(!idle(&json!({"online":true,"desks":0,"packing":0,"joinedAt":joined}), joined + 10), "not idle for an hour yet");
    }

    #[test]
    fn the_ledger_is_written_before_the_provider_is_asked_and_nothing_is_asked_when_it_cannot_be() {
        let cloud = Fake { records: true, ..Default::default() };
        let _ = run(provision(&cloud, &fallback(), &reach(), "Design has waited", 1));
        assert!(cloud.calls.borrow()[0].starts_with("deploy env-") && cloud.calls.borrow()[0].ends_with("with ledger true"), "{:?}", cloud.calls.borrow());
        let unwritable = Fake { records: true, fail_writes: true, ..Default::default() };
        assert!(matches!(run(provision(&unwritable, &fallback(), &reach(), "Design has waited", 1)), Err(Failure::Retry(_))));
        assert!(unwritable.calls.borrow().is_empty(), "the provider is never asked for a computer that could not be recorded");
        assert!(may_create(&Ledger::default(), 5, "Design has waited", 0, false).is_err(), "nor while the last write failed");
    }

    #[test]
    fn a_computer_someone_else_created_meanwhile_is_never_taken_or_deleted() {
        // Their environment appears under this attempt's name while our request fails before it
        // records anything (and so before the provider is called).
        let cloud = Fake { records: false, rival: true, ..Default::default() };
        assert!(matches!(run(provision(&cloud, &fallback(), &reach(), "Design has waited", 1)), Err(Failure::Retry(_))));
        assert!(cloud.ledger.borrow().computers.is_empty(), "nothing of theirs is recorded as ours");
        assert!(!cloud.calls.borrow().iter().any(|call| call.contains("env-someone-elses")), "{:?}", cloud.calls.borrow());
        // When ours is recorded too, only ours is joined and, after a failed join, deleted.
        let both = Fake { records: true, rival: true, ..Default::default() };
        let _ = run(provision(&both, &fallback(), &reach(), "Design has waited", 1));
        let calls = both.calls.borrow();
        assert!(calls.iter().any(|call| call.starts_with("delete env-")) && !calls.iter().any(|call| call.contains("env-someone-elses")), "{calls:?}");
    }

    #[test]
    fn switching_the_fallback_off_or_deleting_the_grid_removes_what_it_made() {
        let hour = RETIRE_AFTER.as_secs() as i64;
        let mut ledger = Ledger::default();
        ledger.computers.insert("env-idle".into(), computer("yougori-desk-1", Some("member-1"), 0));
        ledger.computers.insert("env-busy".into(), computer("yougori-desk-2", Some("member-2"), 0));
        let members = vec![json!({"id":"member-1","online":true,"desks":0,"packing":0,"joinedAt":0}), json!({"id":"member-2","online":true,"desks":1,"joinedAt":0})];
        // Turned off: the idle one goes at once, not after an hour; the one holding a desk stays and is named.
        let off = plan(&ledger, &Sight::Open { enabled: false, members: members.clone(), needed: Some("Design has waited".into()), max_computers: 5, can_reach: true }, 10, true);
        assert_eq!(off.retire, vec!["env-idle".to_owned()]);
        assert!(off.create.is_none() && off.note.unwrap().contains("1 cloud computer still hosts desks"));
        // The grid deleted: every one goes, their desks went with it.
        let gone = plan(&ledger, &Sight::Gone, 10, true);
        assert_eq!(gone.retire.len(), 2);
        assert!(gone.note.unwrap().contains("2 cloud computers it created are being removed"));
        // Paused for deletion or not running: nothing is removed, and the admin is told what is kept.
        for sight in [Sight::Closing, Sight::Unknown] {
            let held = plan(&ledger, &sight, 10 * hour, true);
            assert!(held.retire.is_empty() && held.create.is_none() && held.note.is_some());
        }
        // On, the usual rules: neither is idle for an hour yet.
        let on = plan(&ledger, &Sight::Open { enabled: true, members, needed: None, max_computers: 5, can_reach: true }, 10, true);
        assert!(on.retire.is_empty());
    }

    #[test]
    fn every_computer_asked_for_counts_until_its_vm_is_gone_and_failures_wait() {
        let mut ledger = Ledger::default();
        let mut state = PlatformState::empty().unwrap();
        ledger.computers.insert("env-failed".into(), computer("yougori-desk-1", None, 0));
        state.cloud_deployments.insert("env-failed".into(), deployment("yougori-desk-1-abcd1234", "Needs inspection"));
        observe(&mut ledger, &state, &[], Some("aws|settings"), 100);
        assert!(may_create(&ledger, 1, "Design has waited", 100, true).is_err(), "it fills the only slot although it never joined");
        assert!(may_create(&ledger, 2, "Design has waited", 100, true).is_ok());
        ledger.retry_after = 100 + backoff(1);
        assert!(may_create(&ledger, 2, "Design has waited", 101, true).is_err());
        assert!(may_create(&ledger, 2, "Design has waited", 100 + backoff(1), true).is_ok());
        assert_eq!((backoff(1), backoff(2), backoff(3), backoff(40)), (FIRST_BACKOFF, 2 * FIRST_BACKOFF, 4 * FIRST_BACKOFF, MAX_BACKOFF));
        ledger.held_by = Some("env-failed".into());
        ledger.last_error = Some("needs inspection".into());
        assert!(may_create(&ledger, 5, "Design has waited", i64::MAX, true).unwrap_err().contains("yougori-desk-1"));
        state.cloud_deployments.insert("env-failed".into(), deployment("yougori-desk-1-abcd1234", "Deleted"));
        observe(&mut ledger, &state, &[], Some("aws|settings"), 200);
        assert!(ledger.computers.is_empty() && ledger.held_by.is_none() && ledger.last_error.is_none(), "a deleted VM frees its slot, the hold and its message");
        // A computer recorded just before its provider call stays counted until its record appears.
        ledger.computers.insert("env-new".into(), Computer { pending: true, created_at: 1000, ..computer("yougori-desk-3", None, 1000) });
        observe(&mut ledger, &state, &[], None, 1000 + 60);
        assert!(ledger.computers.contains_key("env-new"));
        observe(&mut ledger, &state, &[], None, 1000 + PENDING_GRACE + 1);
        assert!(!ledger.computers.contains_key("env-new"), "never recorded: the provider was never called");
    }

    #[test]
    fn a_desk_no_computer_of_these_settings_took_is_not_tried_again_until_they_change() {
        let mut ledger = Ledger { did_not_fit: vec!["Design has waited".into()], failures: 3, retry_after: 50, settings: "small".into(), ..Default::default() };
        let state = PlatformState::empty().unwrap();
        observe(&mut ledger, &state, &[], Some("small"), 100);
        assert!(may_create(&ledger, 3, "Design has waited", 100, true).is_err());
        assert!(may_create(&ledger, 3, "Another desk has waited", 100, true).is_ok());
        observe(&mut ledger, &state, &[], Some("large"), 100);
        assert!(ledger.did_not_fit.is_empty() && ledger.failures == 0 && ledger.retry_after == 0, "new settings start afresh");
    }

    #[test]
    fn computers_are_retired_by_their_own_record_never_by_a_name_another_could_claim() {
        let hour = RETIRE_AFTER.as_secs() as i64;
        let mut ledger = Ledger::default();
        let mut state = PlatformState::empty().unwrap();
        ledger.computers.insert("env-1".into(), computer("yougori-desk-1", Some("member-1"), 0));
        state.cloud_deployments.insert("env-1".into(), deployment("yougori-desk-1-abcd1234", "Created"));
        let offline = json!({"id":"member-1","online":false,"desks":0,"packing":0,"joinedAt":0});
        observe(&mut ledger, &state, &[offline.clone()], Some("s"), 10);
        let record = &ledger.computers["env-1"];
        assert_eq!(record.offline_since, Some(10));
        assert!(!retire_due(record, Some(&offline), 10 + hour - 1));
        assert!(retire_due(record, Some(&offline), 10 + hour + 1));
        let holding = json!({"id":"member-1","online":false,"desks":1,"packing":0,"joinedAt":0});
        assert!(!retire_due(record, Some(&holding), 10 + 10 * hour));
        let unjoined = computer("yougori-desk-2", None, 1000);
        assert!(!retire_due(&unjoined, None, 1000 + hour - 1));
        assert!(retire_due(&unjoined, None, 1000 + hour + 1));
        let failed = Computer { retire_failed_at: Some(5000), ..unjoined };
        assert!(!retire_due(&failed, None, 5000 + RETIRE_RETRY - 1));
        assert!(retire_due(&failed, None, 5000 + RETIRE_RETRY));
        let impostor = json!({"id":"member-x","platform":PLATFORM,"name":"yougori-desk-1","online":true,"desks":0,"joinedAt":0});
        observe(&mut ledger, &state, &[impostor], Some("s"), 20);
        assert!(ledger.computers.values().all(|computer| computer.member_id.as_deref() != Some("member-x")));
    }

    #[test]
    fn a_retired_vm_goes_first_and_a_membership_that_stays_is_retried() {
        struct Stubborn(Fake);
        impl Cloud for Stubborn {
            fn record(&self, change: &mut dyn FnMut(&mut Ledger)) -> Result<Ledger, String> { self.0.record(change) }
            fn state(&self) -> Result<PlatformState, String> { self.0.state() }
            async fn deploy(&self, id: &str, request: DeployRequest) -> Result<(), String> { self.0.deploy(id, request).await }
            async fn delete(&self, environment_id: &str, name: &str) -> Result<(), String> { self.0.delete(environment_id, name).await }
            async fn join(&self, name: &str, environment_id: &str, deployment: &Deployment) -> Result<(), String> { self.0.join(name, environment_id, deployment).await }
            async fn remove_membership(&self, member_id: &str) -> Result<(), String> { self.0.calls.borrow_mut().push(format!("remove {member_id}")); Err("hub busy".into()) }
        }
        let mut state = PlatformState::empty().unwrap();
        state.cloud_deployments.insert("env-1".into(), deployment("yougori-desk-1-abcd1234", "Created"));
        let cloud = Stubborn(Fake { state: RefCell::new(Some(state)), ..Default::default() });
        let entry = computer("yougori-desk-1", Some("member-1"), 0);
        cloud.0.ledger.borrow_mut().computers.insert("env-1".into(), entry.clone());
        run(retire(&cloud, "env-1", &entry, true));
        assert_eq!(*cloud.0.calls.borrow(), vec!["delete env-1".to_owned(), "remove member-1".to_owned()], "the VM goes before the membership");
        let kept = cloud.0.ledger.borrow().computers["env-1"].clone();
        assert!(kept.vm_deleted && kept.retire_failed_at.is_some(), "the membership is retried");
        run(retire(&cloud, "env-1", &kept, true));
        assert_eq!(cloud.0.calls.borrow().len(), 3, "the VM is not deleted twice: {:?}", cloud.0.calls.borrow());
        // A deployment that does not carry its name is never deleted.
        let mut other = PlatformState::empty().unwrap();
        other.cloud_deployments.insert("env-2".into(), deployment("someone-elses-vm-1234abcd", "Created"));
        let careful = Fake { state: RefCell::new(Some(other)), ..Default::default() };
        let foreign = computer("yougori-desk-2", None, 0);
        careful.ledger.borrow_mut().computers.insert("env-2".into(), foreign.clone());
        run(retire(&careful, "env-2", &foreign, false));
        assert!(careful.calls.borrow().is_empty());
    }

    #[test]
    fn a_vm_deleted_elsewhere_still_has_its_place_in_the_grid_removed() {
        let mut ledger = Ledger::default();
        let state = PlatformState::empty().unwrap();
        ledger.computers.insert("env-1".into(), computer("yougori-desk-1", Some("member-1"), 0));
        ledger.computers.insert("env-2".into(), computer("yougori-desk-2", None, 0));
        // A person deleted both VMs in Cloud deployments, and their records with them.
        observe(&mut ledger, &state, &[json!({"id":"member-1","online":false,"desks":0,"joinedAt":0})], None, 10);
        assert!(ledger.computers["env-1"].vm_deleted, "kept until its membership is removed");
        assert!(!ledger.computers.contains_key("env-2"), "nothing left of it to remove");
        assert_eq!(ledger.computers.values().filter(|computer| !computer.vm_deleted).count(), 0, "neither is shown as running");
        // Its desks are gone with it, so a stale count of them never keeps it.
        let off = plan(&ledger, &Sight::Open { enabled: false, members: vec![json!({"id":"member-1","online":false,"desks":2,"joinedAt":0})], needed: None, max_computers: 5, can_reach: true }, 10, true);
        assert_eq!((off.retire, off.note), (vec!["env-1".to_owned()], None));
    }
}
