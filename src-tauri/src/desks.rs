//! Desks on this computer: the sandboxes it hosts for the grid's people, and the desk its own
//! person signed in to. The hub decides which desks this computer hosts (see `grid`); this module
//! builds them, runs them, shares each with its person over pinned TLS and reports back with every
//! check-in. A share dies with the engine and expires after a day, so a fresh invitation is minted
//! whenever none is live. Share tokens stay in memory; only which desk is which sandbox is saved.
pub(crate) mod cloud;
pub(crate) mod media;
pub(crate) mod moving;
pub(crate) mod parking;
pub(crate) mod uploads;
use crate::{models::{CreateEnvironmentRequest, CreateResourcePolicy, CreateResourceRange, EnvironmentKind, EnvironmentStatus, Priority, RuntimeProviderKind}, projects::secrets, security::Event, store::PlatformStore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::HashMap, path::{Path, PathBuf}, time::Duration};
use tauri::Manager;
use crate::AppHandle;
use yougori_grid::{
    activity::Activity,
    desks::{Capacity, DeskKind, DeskOrder, DeskReport, DeskSpec, RENEW_BEFORE},
    invite,
    member::{self, PersonSession},
    password,
};

/// Keyboard or mouse input within this long means someone is using the computer, which only
/// matters to a share the admin limited to idle time.
const IN_USE_WITHIN: Duration = Duration::from_secs(10 * 60);
const PERSON_SESSION: &str = "yougori-desks-person-session";
const PERSON_INVITE: &str = "yougori-grid-desk-invite";

#[derive(Default)]
pub struct DeskHost {
    /// Yougori is closing: the hub is told, so the desks here move before the computer goes.
    pub(crate) closing: std::sync::atomic::AtomicBool,
    inner: tokio::sync::Mutex<Inner>,
    sign_in: tokio::sync::Mutex<()>,
    /// Held across every read-modify-write of the parked-parcel record, and never across the
    /// network. Two writers raced here: a pass deleting one desk's superseded parcel computed
    /// its list, went away to delete objects, and wrote that list back after the park branch had
    /// marked a different parcel as reported — putting the mark back to false, so the next pass
    /// deleted a parcel the hub had already accepted. A generation bumped mid-move was enough
    /// to line it up, which an admin does by resetting somebody's password.
    parcels: tokio::sync::Mutex<()>,
}

#[derive(Default)]
struct Inner {
    loaded: bool,
    hosted: Vec<HostedDesk>,
    /// `hosted` could not be written the last time it changed; written again at the next check-in.
    hosted_dirty: bool,
    /// Connections held open at the hub so a person away from this network can open a desk.
    relays: HashMap<u64, tauri::async_runtime::JoinHandle<()>>,
    relay_next: u64,
    /// Builds in progress, by desk.
    building: HashMap<String, tauri::async_runtime::JoinHandle<()>>,
    /// Desks being packed up or taken over right now, with what to tell the hub when each ends.
    moving: HashMap<String, tauri::async_runtime::JoinHandle<()>>,
    /// Finished moves waiting to be reported: the parcel a desk was packed into, or why not.
    packed: HashMap<String, Result<yougori_grid::desks::Parcel, String>>,
    /// Adopted desks whose settings would not apply yet, with the order to apply. Retried every
    /// pass: the data is here, and a desk that cannot be made what the order describes is one to
    /// keep working on rather than one to give up and delete.
    unsettled: HashMap<String, DeskOrder>,
    /// Desks this computer has taken over: the sandbox the data was unpacked into, or why not.
    /// Keyed by desk AND order, like `packed`, with the checksum of the parcel it answers.
    taken: HashMap<String, (String, Result<String, String>)>,
    /// Why a build failed, by desk, until the hub takes the desk away or orders it again.
    failed: HashMap<String, (u64, String)>,
    deleting: std::collections::HashSet<String>,
    /// Live share invitations, by desk: the invitation, its expiry, the share ID, and whether the
    /// hub still has to hear about it.
    invitations: HashMap<String, Share>,
    login: Option<Login>,
}

struct Share {
    invitation: Value,
    expires_at: i64,
    share_id: String,
    reported: bool,
    generation: u64,
    person_id: Option<String>,
}

/// A desk this computer hosts: which sandbox it is. Saved beside the membership.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HostedDesk {
    id: String,
    name: String,
    environment_id: String,
}

/// The desk this computer's person signed in to, saved without the password.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Login {
    grid_id: String,
    grid_name: String,
    username: String,
    person_id: String,
    #[serde(default)]
    admin_role: yougori_grid::enterprise::AdminRole,
    name: String,
    /// Each desk and the local entry that opens it, when it is reachable.
    desks: Vec<LoginDesk>,
    signed_in_at: i64,
    #[serde(default)]
    connections: Vec<Value>,
    /// Two-step sign-in is on for this person (the hub said so at sign-in or refresh).
    #[serde(default)]
    mfa: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LoginDesk {
    id: String,
    name: String,
    state: String,
    note: String,
    host: Option<String>,
    environment_id: Option<String>,
    address: Option<String>,
    #[serde(default)]
    invitation_hash: String,
}

fn folder(app: &AppHandle) -> PathBuf {
    app.state::<PlatformStore>().data_folder("grid")
}

fn hosted_path(app: &AppHandle) -> PathBuf {
    folder(app).join("desks.json")
}

fn login_path(app: &AppHandle) -> PathBuf {
    folder(app).join("desk-login.json")
}

fn parked_path(app: &AppHandle) -> PathBuf {
    folder(app).join("desk-parcels.json")
}

/// A parcel this computer uploaded, written down so a restart does not forget it.
///
/// The record of a finished park lived only in memory, so a park that landed and was not
/// reported before the engine stopped left its object in the company's bucket with nothing
/// referring to it — and because bucket names carry a timestamp, the next park wrote a new
/// object beside it rather than over it. That is somebody's desk sitting in a company bucket
/// being charged for, invisibly.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Parked {
    desk: String,
    generation: u64,
    parcel: yougori_grid::desks::Parcel,
    /// Whether the hub has been told about this parcel. Once it has, the data belongs to the
    /// move and not to this computer: an adopting computer is going to fetch it, and deleting it
    /// from here destroys the desk. Defaulted so a record written before this reads as not yet
    /// reported, which is the safe way round — it is the state in which nothing is deleted.
    #[serde(default)]
    reported: bool,
}

/// What this computer has uploaded. A damaged file is kept aside rather than read as "nothing
/// was ever uploaded": this is the only note of objects sitting in the company's bucket, and
/// writing over it loses track of them for good.
fn read_parked(path: &Path, at: i64) -> Result<Vec<Parked>, String> {
    crate::rented_gpu::read_kept(path, at, "its record of parked desk data").map_err(|unreadable| unreadable.said)
}

/// Reads the record, changes it and writes it back, with nobody else in between.
///
/// Every change goes through here. A caller that reads, works something out and writes later is
/// the shape that lost the reported mark, so there is no way to do that from outside.
async fn change_parked(app: &AppHandle, change: impl FnOnce(&mut Vec<Parked>)) -> Result<(), String> {
    let host = app.state::<DeskHost>();
    let _held = host.parcels.lock().await;
    rewrite_parked(&parked_path(app), yougori_grid::now(), change)
}

/// `change_parked` on the file itself. It fails as honestly on the way out as on the way in: it
/// used to propagate a read that failed and then return Ok after a write that failed, so a caller
/// could not learn that a reported mark never reached the disk — and a parcel the hub had accepted
/// was then deleted as one nobody had been told about.
fn rewrite_parked(path: &Path, at: i64, change: impl FnOnce(&mut Vec<Parked>)) -> Result<(), String> {
    let mut parked = read_parked(path, at)?;
    change(&mut parked);
    write_parked(path, &parked)
}

fn write_parked(path: &Path, parked: &[Parked]) -> Result<(), String> {
    let result = if parked.is_empty() {
        std::fs::remove_file(path).or_else(|error| if error.kind() == std::io::ErrorKind::NotFound { Ok(()) } else { Err(error) }).map_err(|error| error.to_string())
    } else {
        write_json(path, &parked)
    };
    if let Err(error) = &result {
        crate::security::record(Event::new("grid.desk.parcel_record_failed").text("error", error));
    }
    result.map_err(|error| format!("Yougori could not write down its record of parked desk data ({error})"))
}

/// What a finished park is reported as, given whether its parcel was written down as reported.
///
/// Marked first, and reported only once the mark is on disk: a report that went out and was not
/// written down is the case that destroys a desk. The hub, told, stops asking for the parcel, and
/// a record still saying "not reported" then reads as a parcel nobody wants, so the next pass
/// deletes it from under the computer adopting it. Not written down, the parcel waits in
/// `waiting` for the next pass, and the hub hears that the desk is still moving.
fn park_report(waiting: &mut HashMap<String, Result<yougori_grid::desks::Parcel, String>>, order: &DeskOrder, packed: Result<yougori_grid::desks::Parcel, String>, marked: Result<(), String>) -> DeskReport {
    match (packed, marked) {
        (Ok(parcel), Ok(())) => DeskReport { id: order.id.clone(), state: "parked".into(), note: "Its data is with the hub".into(), parcel: Some(parcel), generation: order.generation, ..DeskReport::default() },
        (Ok(parcel), Err(error)) => {
            waiting.insert(packed_key(&order.id, order.generation), Ok(parcel));
            DeskReport { id: order.id.clone(), state: "moving".into(), note: format!("The desk's data is packed; it is handed on once this computer can write that down. {error}"), generation: order.generation, ..DeskReport::default() }
        }
        (Err(error), _) => DeskReport { id: order.id.clone(), state: "failed".into(), note: error, generation: order.generation, ..DeskReport::default() },
    }
}

/// What becomes of a parcel this computer uploaded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fate {
    /// Still the parcel the hub is asking for: the one about to be reported, or the one a
    /// restart interrupted before it could be.
    Keep,
    /// Reported and no longer asked for. The hub took it and somebody is going to adopt it, so
    /// this computer simply stops tracking it. The adopting computer deletes the bucket copy
    /// once it has unpacked, and removing the desk covers the hub's.
    Forget,
    /// Never reported and no longer asked for: nothing will ever use it, so the data behind it
    /// is this computer's to delete.
    Delete,
}

/// Three outcomes rather than two, and the third is the whole point.
///
/// With two, "no longer being parked" meant "delete the data", and a park that SUCCEEDED is no
/// longer being parked — the hub accepts the report and clears the move, so the next orders do
/// not mention it. That deleted the bucket object on the ordinary successful path, while the
/// local sandbox was being deleted in the same pass for the same reason, and the adopting
/// computer then found nothing. The desk existed nowhere.
///
/// It is the same mistake I had already named and only half applied: a parcel that was reported
/// and is no longer asked for looks exactly like one that was superseded. The question that
/// tells them apart is not "is the hub still asking for it" but "was the hub ever told".
fn fate(entry: &Parked, parking_now: &[(String, u64)]) -> Fate {
    let newest = parking_now.iter().filter(|(id, _)| id == &entry.desk).map(|(_, generation)| *generation).max();
    match (newest == Some(entry.generation), entry.reported) {
        (true, _) => Fate::Keep,
        (false, true) => Fate::Forget,
        (false, false) => Fate::Delete,
    }
}

/// Whether an adopt order can be answered with the sandbox this computer already holds.
///
/// The shortcut exists because the hub can hand a parked desk straight back to the computer it
/// came from, and importing then makes a second full-size copy of a desk already here. But it
/// must never answer for a sandbox on its way out: a desk that was dropped, whose delete is
/// still running, would be reported adopted on something about to vanish — the hub clears the
/// parcel, removing the desk deletes the hub's copy, the delete finishes, and the next order
/// builds an empty desk. Saying nothing for one check-in costs a check-in; the parcel is still
/// there and is adopted normally once the delete is done.
fn already_here(hosted: bool, sandbox_present: bool, deleting: bool) -> bool {
    hosted && sandbox_present && !deleting
}

/// What an adopt is reported as, and whether its desk may start yet.
///
/// Arriving and being configured are two different facts and only the first decides the report.
/// Reporting a failure because the settings would not apply was catastrophic next to the hub
/// rule a few lines away: the hub marks the desk Failed and keeps the parcel, `orders_for` never
/// orders a Failed desk that holds one, so the following pass found the sandbox hosted and
/// unordered and `dropped` deleted it — and for a bucket parcel the copy there had already gone
/// on import, so that sandbox was the only one left.
///
/// What a settings failure withholds is STARTING the desk, never keeping it. A desk running
/// with its network off is a working desk that is quietly broken, and one that cannot yet be
/// made what the order describes is one to keep trying.
fn arrival(settled: &Result<(), String>) -> (&'static str, bool) {
    match settled {
        Ok(()) => ("adopted", true),
        Err(_) => ("adopted", false),
    }
}

/// Drops only the entries whose data was actually deleted, leaving the rest of the record as it
/// now stands — including anything changed while the deleting was going on.
///
/// The deleting happens off the lock, because it is network work with retries, so the record can
/// and does change underneath it: the pass that deletes one desk's superseded parcel runs beside
/// the park branch marking another desk's parcel as reported. Writing back a list worked out
/// before all that put the mark back to false, and the next pass then deleted a parcel the hub
/// had already accepted — the desk gone, on the successful path, from a lost update.
fn without_deleted(parked: &mut Vec<Parked>, gone: &[(String, u64)]) {
    parked.retain(|entry| !gone.iter().any(|(desk, generation)| desk == &entry.desk && *generation == entry.generation));
}

/// The written-down parcels sorted by what becomes of them: what to keep, and what to delete.
/// Anything to forget is in neither — it leaves the record and nothing else happens to it.
fn sort_parked(parked: Vec<Parked>, parking_now: &[(String, u64)]) -> (Vec<Parked>, Vec<Parked>) {
    let mut keep = Vec::new();
    let mut delete = Vec::new();
    for entry in parked {
        match fate(&entry, parking_now) {
            Fate::Keep => keep.push(entry),
            Fate::Forget => {}
            Fate::Delete => delete.push(entry),
        }
    }
    (keep, delete)
}

/// Whole or not at all, and on the disk before it counts: a mark that only reached the disk's cache
/// is lost by a power cut, and a parcel record that comes back saying "not reported" deletes a desk.
fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    crate::rented_gpu::write_kept(path, value)
}

async fn ensure_loaded(app: &AppHandle) {
    let host = app.state::<DeskHost>();
    let mut inner = host.inner.lock().await;
    if inner.loaded {
        return;
    }
    inner.loaded = true;
    // Anything in the move folder is the remains of a move that will never finish: the handles
    // that track one live in memory and went with the last process, so the hub re-issues the
    // order and the desk is packed again from its sandbox. It is written down rather than
    // deleted, because on a computer where a move sent only its manifest that folder holds the
    // one surviving copy of the desk.
    moving::sweep(app);
    match std::fs::read(hosted_path(app)) {
        Ok(bytes) => match serde_json::from_slice(&bytes) {
            Ok(hosted) => inner.hosted = hosted,
            Err(error) => {
                crate::security::record(Event::new("grid.desk.record_damaged").text("error", &error.to_string()));
                // Only when the sandboxes could actually be read. Writing an empty list over a
                // damaged record because the store was also unreadable would forget which
                // sandboxes are desks, and every one of them would be rebuilt empty.
                if let Some(found) = hosted_from_sandboxes(app) {
                    inner.hosted = found;
                    inner.hosted_dirty = true;
                }
            }
        },
        // No record: any sandbox tagged as a desk is still one, so it is not built twice.
        Err(_) => inner.hosted = hosted_from_sandboxes(app).unwrap_or_default(),
    }
    if let Ok(bytes) = std::fs::read(login_path(app)) {
        inner.login = serde_json::from_slice(&bytes).ok();
    }
}

/// How a sandbox kept after leaving a grid is described: it was a desk and is now its owner's.
const RELEASED_DESK: &str = "Kept from grid desk ";

/// The desks this computer holds, read back from the sandboxes themselves: every one carries its
/// desk's ID in its description, so a lost or damaged record does not lose track of their data.
/// The desks this computer holds, read back from the sandboxes themselves. `None` when the
/// record of sandboxes could not be read at all, which is not the same as holding none: writing
/// an empty list over a damaged record would forget which sandboxes are desks, and every one of
/// them would then be rebuilt empty.
fn hosted_from_sandboxes(app: &AppHandle) -> Option<Vec<HostedDesk>> {
    let Ok(state) = app.state::<PlatformStore>().snapshot() else { return None };
    state
        .environments
        .iter()
        .filter_map(|environment| {
            let id = desk_of(&environment.description)?;
            Some(HostedDesk { id: id.to_owned(), name: environment.name.clone(), environment_id: environment.id.clone() })
        })
        .collect::<Vec<_>>()
        .into()
}

/// The desk a sandbox's description names, if it is still a desk.
fn desk_of(description: &str) -> Option<&str> {
    let id = description.strip_prefix("Grid desk ")?.split(" · ").next()?.trim();
    (!id.is_empty()).then_some(id)
}

/// Writes which desk is which sandbox. A write that fails is said so and tried again at the
/// next check-in (`hosted_dirty`), never silently dropped.
fn persist_hosted(app: &AppHandle, hosted: &[HostedDesk]) -> bool {
    let result = if hosted.is_empty() { std::fs::remove_file(hosted_path(app)).or_else(|error| if error.kind() == std::io::ErrorKind::NotFound { Ok(()) } else { Err(error) }).map_err(|error| error.to_string()) } else { write_json(&hosted_path(app), &hosted) };
    if let Err(error) = &result {
        crate::security::record(Event::new("grid.desk.record_failed").text("error", error));
    }
    result.is_ok()
}

/// Why this computer is about to stop hosting, if it is: the desks it holds move to another
/// computer, with their data, before it goes.
pub(crate) fn going_away(power: yougori_grid::power::Power, free_disk_gb: f64, closing: bool) -> Option<String> {
    use yougori_grid::power::{LOW_DISK_GB, MOVE_BELOW_PERCENT};
    if closing {
        return Some("Yougori is closing on this computer".into());
    }
    if power.draining(MOVE_BELOW_PERCENT) {
        return Some(format!("Its battery is down to {}%", power.percent.unwrap_or_default()));
    }
    (free_disk_gb < LOW_DISK_GB).then(|| format!("Only {free_disk_gb:.0} GB of disk is left on it"))
}

/// What this computer has and is using right now, for the hub to fit desks into the share the
/// admin set for it.
pub(crate) fn capacity(app: &AppHandle, activity: &Activity, gpu: bool) -> Capacity {
    let host = app.state::<PlatformStore>().snapshot().map(|state| state.host).ok();
    let Some(host) = host else { return Capacity::default() };
    let free_disk = host
        .storage_drives
        .iter()
        .find(|drive| Some(&drive.path) == host.storage_drive.as_ref())
        .map(|drive| drive.free_gb)
        .unwrap_or((host.total_storage_gb - host.used_storage_gb).max(0.0));
    // When it cannot be told, assume someone is there: that only holds back a share limited to idle time.
    let in_use = match activity {
        Activity::Nobody => false,
        Activity::Idle(idle) => *idle < IN_USE_WITHIN,
        Activity::Unknown(_) => true,
    };
    let power = yougori_grid::power::current();
    let closing = app.state::<DeskHost>().closing.load(std::sync::atomic::Ordering::Relaxed);
    Capacity {
        going_away: going_away(power, free_disk, closing),
        battery_percent: power.percent,
        cpu: u32::try_from(host.total_cpu).unwrap_or(u32::MAX),
        cpu_used_percent: host.used_cpu_percent,
        memory_gb: host.total_memory_gb,
        used_memory_gb: host.used_memory_gb,
        free_disk_gb: free_disk,
        gpu,
        gpu_used_percent: host.gpu_usage_percent.filter(|_| gpu),
        on_battery: power.on_battery,
        desk_protocol: 2,
        in_use,
    }
}

/// The sandbox a desk order asks for, as this computer creates it.
fn request_for(order: &DeskOrder) -> CreateEnvironmentRequest {
    let spec = &order.spec;
    let (kind, provider) = match spec.kind {
        DeskKind::Container if spec.gpu => (EnvironmentKind::Container, RuntimeProviderKind::YougoriCuda),
        DeskKind::Container => (EnvironmentKind::Container, RuntimeProviderKind::YougoriOci),
        DeskKind::MicroVm => (EnvironmentKind::MicroVm, RuntimeProviderKind::Qemu),
        DeskKind::Vm => (EnvironmentKind::FullVm, RuntimeProviderKind::Qemu),
    };
    let range = |wanted: f64| CreateResourceRange { min: (wanted / 4.0).max(0.25), preferred: wanted, max: wanted };
    CreateEnvironmentRequest {
        auto_setup_cuda: spec.gpu,
        workload: None,
        storage_drive: None,
        storage_gb: Some(spec.disk_gb),
        name: format!("Desk {}", order.id),
        kind,
        runtime: spec.image.clone(),
        provider,
        container_command: None,
        network_access: order.access != yougori_grid::enterprise::DeskAccess::Restricted,
        gpu_access: spec.gpu,
        sandbox_policy: None,
        description: desk_tag(&order.id, &order.person_name),
        branch_type: None,
        resource_policy: CreateResourcePolicy { cpu: range(spec.cpu), memory_gb: range(spec.memory_gb), priority: Priority::Normal, dynamic: true },
    }
}

/// Makes an adopted sandbox the desk the order describes.
///
/// A move imports the data as a plain backup, and an import deliberately comes back with its
/// network off, its GPU off and a restored-copy name — right for a file somebody opened, wrong
/// for a desk that is being handed on, where the order already says what it is. Nothing applied
/// the order afterwards, so every moved desk arrived locked down and renamed, and the person it
/// belongs to found something that was not theirs.
///
/// What this does NOT reapply: the resource policy, the provider, the storage drive and
/// auto_setup_cuda. Those match today only because a desk's spec cannot change after it is
/// ordered, so the imported sandbox was built from the same numbers. The day a spec can be
/// edited, they belong here too.
fn as_the_order_says(app: &AppHandle, environment_id: &str, order: &DeskOrder) -> Result<(), String> {
    let (name, tag) = (format!("Desk {}", order.id), desk_tag(&order.id, &order.person_name));
    let network = order.access != yougori_grid::enterprise::DeskAccess::Restricted;
    let gpu = order.spec.gpu;
    app.state::<PlatformStore>().mutate(|state| {
        let environment = state.environments.iter_mut().find(|environment| environment.id == environment_id).ok_or("The adopted sandbox is not in this computer's record")?;
        environment.name = name;
        environment.description = tag;
        environment.network_access = network;
        environment.gpu_access = gpu;
        Ok(())
    })?;
    Ok(())
}

fn desk_tag(desk: &str, person: &str) -> String {
    if person.is_empty() { format!("Grid desk {desk}") } else { format!("Grid desk {desk} · {person}") }
}

/// Builds a desk's sandbox and starts it; the outcome is reported at the next check-in.
/// Runs when a build task is cancelled part-way (the computer leaves the grid): a sandbox it had
/// begun and not finished is marked failed, so it can be deleted, rather than left "creating".
struct BuildGuard {
    app: AppHandle,
    tag: String,
    done: bool,
}

impl Drop for BuildGuard {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        let tag = self.tag.clone();
        let _ = self.app.state::<PlatformStore>().mutate(|state| {
            for environment in state.environments.iter_mut().filter(|environment| environment.description == tag && environment.status == EnvironmentStatus::Provisioning) {
                environment.status = EnvironmentStatus::Error;
                environment.last_error = Some("This computer left the sandbox grid while the desk was being created. Delete this incomplete node.".into());
            }
            Ok(())
        });
    }
}

fn spawn_build(app: &AppHandle, order: DeskOrder, membership: member::Membership) -> tauri::async_runtime::JoinHandle<()> {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let mut guard = BuildGuard { app: app.clone(), tag: desk_tag(&order.id, &order.person_name), done: false };
        let result: Result<String, String> = async {
            let mut request = request_for(&order);
            request.runtime = media::resolve(&app, &order, &membership).await?;
            if order.spec.kind==DeskKind::Vm && order.image_sha256.is_some() {
                app.state::<crate::runtime::RuntimeManager>().validate_prepared_desk_image(std::path::Path::new(&request.runtime),order.spec.disk_gb).await?;
            }
            let tag = request.description.clone();
            let state = crate::commands::create_environment(request, app.clone(), app.state(), app.state()).await?;
            let id = state.environments.iter().rev().find(|environment| environment.description == tag).map(|environment| environment.id.clone()).ok_or("The desk's sandbox was not created")?;
            // Persist ownership before starting: a failed start must not orphan the created disk.
            {
                let host=app.state::<DeskHost>();let mut inner=host.inner.lock().await;
                if !inner.hosted.iter().any(|d|d.id==order.id){inner.hosted.push(HostedDesk{id:order.id.clone(),name:order.name.clone(),environment_id:id.clone()});}
                if !persist_hosted(&app,&inner.hosted){inner.hosted_dirty=true;}
            }
            crate::commands::set_environment_status(id.clone(), EnvironmentStatus::Running, app.state(), app.state()).await?;
            Ok(id)
        }
        .await;
        guard.done = true;
        let host = app.state::<DeskHost>();
        let mut inner = host.inner.lock().await;
        inner.building.remove(&order.id);
        match result {
            Ok(environment_id) => {
                crate::security::record(Event::new("grid.desk.built").env(&environment_id).text("desk", &order.id));
                if !inner.hosted.iter().any(|d|d.id==order.id){inner.hosted.push(HostedDesk { id: order.id.clone(), name: order.name.clone(), environment_id });}
                if !persist_hosted(&app, &inner.hosted) { inner.hosted_dirty = true; }
            }
            Err(error) => {
                crate::security::record(Event::new("grid.desk.build_failed").text("desk", &order.id).text("error", &error));
                inner.failed.insert(order.id.clone(), (order.generation, error));
            }
        }
        app.state::<crate::deskgrid::DeskGrid>().wake();
    })
}

/// Shares a desk's sandbox with its person: a new invitation over this computer's LAN address.
async fn mint_share(app: &AppHandle, environment_id: &str, order: &DeskOrder, membership: &member::Membership) -> Result<Share, String> {
    // A locked-down desk gets no new invitation; checked quietly here so the reconcile loop does
    // not write a refusal to the audit log on every pass. Unlocked, the next pass shares it again.
    if crate::security::is_contained(environment_id) {
        return Err("This desk's sandbox is locked down; it is shared again once it is unlocked".into());
    }
    let address = crate::bounty::suggested_address().ok_or("This computer has no private LAN or VPN address to share the desk from")?;
    let made = crate::peer_sharing::create_desk_share(environment_id.to_owned(), address, order.clone(), membership.clone(), app.clone()).await?;
    let expires_at = made["invitation"]["expiresAt"].as_i64().ok_or("The share has no expiry")?;
    let share_id = made["share"]["id"].as_str().ok_or("The share has no ID")?.to_owned();
    Ok(Share { invitation: made["invitation"].clone(), expires_at, share_id, reported: false, generation: order.generation, person_id: order.person_id.clone() })
}

/// How many connections this computer keeps waiting at the hub for desk sessions.
const DESK_RELAYS: usize = 2;

/// Keeps a couple of connections waiting at the hub while this computer shares any desk, so a
/// person on another network can open theirs. Each carries one session to the desk's own
/// listener and ends with it; the hub only copies bytes.
pub(crate) async fn keep_desk_relays(app: &AppHandle, membership: &member::Membership) {
    let host = app.state::<DeskHost>();
    let mut inner = host.inner.lock().await;
    if inner.invitations.is_empty() {
        for (_, held) in inner.relays.drain() {
            held.abort();
        }
        return;
    }
    while inner.relays.len() < DESK_RELAYS {
        inner.relay_next += 1;
        let (app, membership, mine) = (app.clone(), membership.clone(), inner.relay_next);
        inner.relays.insert(
            mine,
            tauri::async_runtime::spawn(async move {
                let held = membership.hold_desk_relay().await;
                // Whatever happened, this connection is no longer waiting: the next check-in
                // opens another in its place.
                let carry = async {
                    let (desk, relayed) = held.ok()?;
                    let host = app.state::<DeskHost>();
                    let address = host.inner.lock().await.invitations.get(&desk).and_then(|share| share.invitation["address"].as_str().map(str::to_owned))?;
                    let socket = tokio::net::TcpStream::connect(address.parse::<std::net::SocketAddr>().ok()?).await.ok()?;
                    crate::security::record(Event::new("grid.desk.session_relayed").text("desk", &desk));
                    yougori_grid::relay::join_socket(relayed, socket).await;
                    Some(())
                };
                carry.await;
                app.state::<DeskHost>().inner.lock().await.relays.remove(&mine);
            }),
        );
    }
}

async fn revoke_share(app: &AppHandle, share_id: String) {
    let _ = crate::peer_sharing::revoke_environment_share(share_id, app.clone(), app.state()).await;
}

/// The key a packed parcel is filed under: the desk AND the order that asked for it, so a parcel
/// can only ever answer the order it was packed for.
fn packed_key(id: &str, generation: u64) -> String {
    format!("{id}#{generation}")
}

/// Takes the parcel packed for exactly this order, and drops anything left from a superseded one.
/// The hub can call a park off while its upload is still running, and that finished parcel must
/// never be handed to a later order: it holds the desk's data as it was before, so moving it on
/// would quietly lose everything done since.
///
/// The dropped ones come back rather than disappearing. Each is a copy of this desk's data that
/// finished uploading, and forgetting the record does not unsend it: in the company's bucket it
/// stays and is charged for, with nothing left referring to it. The caller deletes what they
/// point at; this stays free of the engine so it can be tested on its own.
fn take_packed(
    packed: &mut HashMap<String, Result<yougori_grid::desks::Parcel, String>>,
    id: &str,
    generation: u64,
) -> (Option<Result<yougori_grid::desks::Parcel, String>>, Vec<yougori_grid::desks::Parcel>) {
    let taken = packed.remove(&packed_key(id, generation));
    let superseded = format!("{id}#");
    let mut orphans = Vec::new();
    packed.retain(|key, value| {
        // This desk's, under any other order. The `#` is what keeps `desk-1` from matching
        // `desk-12`, so it is load-bearing rather than decoration.
        let mine = key == id || key.starts_with(&superseded);
        if mine {
            if let Ok(parcel) = value {
                orphans.push(parcel.clone());
            }
        }
        !mine
    });
    (taken, orphans)
}

/// The adopt result for exactly this order and this parcel, dropping anything left from another.
///
/// Same rule as `take_packed` and for a worse reason: a parcel handed on from a stale success is
/// not merely the wrong data, it makes the hub clear the desk's parcel — and the parcel it
/// clears is the newer one, which `forget_parcel` then deletes.
fn take_taken(
    taken: &mut HashMap<String, (String, Result<String, String>)>,
    id: &str,
    generation: u64,
    parcel: &str,
) -> Option<(String, Result<String, String>)> {
    let key = packed_key(id, generation);
    let answers = taken.get(&key).is_some_and(|(sha, _)| sha == parcel);
    let mine = answers.then(|| taken.remove(&key)).flatten();
    let superseded = format!("{id}#");
    taken.retain(|key, _| key != id && !key.starts_with(&superseded));
    mine
}

/// Copies left in the company's bucket that this computer could not delete, for the hosting
/// page to show. A record nobody reads is not telling anybody.
static LEFTOVERS: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

pub(crate) fn note_bucket_leftover(desk: &str, object: &str, error: &str) {
    let said = format!("A copy of {desk} could not be removed from the company's bucket ({object}): {error}. It is still being charged for; remove it there.");
    let mut leftovers = LEFTOVERS.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if !leftovers.contains(&said) {
        leftovers.push(said);
        leftovers.truncate(32);
    }
}

/// What this computer could not tidy up in the company's bucket.
pub(crate) fn bucket_leftovers() -> Vec<String> {
    LEFTOVERS.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone()
}

/// Deletes the data behind parcels no order will ever use, without holding anything up.
fn forget_parcels(desk: &str, orphans: Vec<yougori_grid::desks::Parcel>, parking: Option<&Value>) {
    if orphans.is_empty() {
        return;
    }
    let (desk, parking) = (desk.to_owned(), parking.cloned());
    tauri::async_runtime::spawn(async move {
        for parcel in &orphans {
            moving::forget(&desk, parcel, parking.as_ref()).await;
        }
    });
}

/// Brings this computer's desks in line with the hub's orders, and says how each is doing.
pub(crate) async fn reconcile(app: &AppHandle, orders: &[DeskOrder], membership: &member::Membership, grid: &str, parking: Option<&Value>) -> Vec<DeskReport> {
    ensure_loaded(app).await;
    let host = app.state::<DeskHost>();
    {
        let mut inner = host.inner.lock().await;
        if inner.hosted_dirty && persist_hosted(app, &inner.hosted) {
            inner.hosted_dirty = false;
        }
    }
    // Not readable is not empty. A desk whose sandbox is missing from this list is reported
    // gone and taken off the record, and the hub then rebuilds it empty — so taking a store
    // this computer could not read to mean "every sandbox has been deleted" turned one bad read
    // into every desk on the computer being thrown away and built again without its data.
    let Ok(environments) = app.state::<PlatformStore>().snapshot().map(|state| state.environments) else {
        crate::security::record(Event::new("grid.desk.reconcile_skipped").text("reason", "This computer's record of its sandboxes could not be read, so its desks were left exactly as they are"));
        return Vec::new();
    };
    let now = yougori_grid::now();
    // Parcels this computer uploaded that nothing is waiting for any more. Judged on what the
    // hub is asking for now rather than on having restarted: a parcel that was reported and
    // then lost from memory looks exactly like one that was never reported, and deleting the
    // wrong one destroys a desk somebody is waiting to receive.
    let parking_now: Vec<(String, u64)> = orders.iter().filter(|order| order.park).map(|order| (order.id.clone(), order.generation)).collect();
    // Decided under the lock, and what is written back here drops only the entries nothing has
    // to be done about: the ones the hub has been told of and stopped asking for. Everything due
    // for deletion stays in the record until its object is actually gone, so a quit in between
    // costs a retry rather than losing the only note of something still being charged for.
    let mut to_delete = Vec::new();
    let decided = change_parked(app, |parked| {
        let (keeping, spent) = sort_parked(std::mem::take(parked), &parking_now);
        to_delete = spent.clone();
        *parked = keeping.into_iter().chain(spent).collect();
    })
    .await;
    if let Err(said) = decided {
        // A damaged record is not an empty one: it is the only note of objects sitting in the
        // company's bucket, so nothing is written over it and nothing is deleted on its word.
        crate::security::record(Event::new("grid.desk.parcel_record_unreadable").text("error", &said));
        to_delete.clear();
    }
    if !to_delete.is_empty() {
        let (away, parking_with) = (app.clone(), parking.cloned());
        tauri::async_runtime::spawn(async move {
            let mut gone = Vec::new();
            for entry in to_delete {
                if moving::forget(&entry.desk, &entry.parcel, parking_with.as_ref()).await {
                    gone.push((entry.desk, entry.generation));
                }
            }
            // Read again, and remove only what was actually deleted. Writing back a list worked
            // out before the network calls is what put a reported mark back to false and had the
            // next pass delete a parcel the hub had already accepted.
            let _ = change_parked(&away, |parked| without_deleted(parked, &gone)).await;
        });
    }
    let mut reports = Vec::new();
    // Keep the ownership record until disk deletion succeeds. Failed deletes retry at the
    // next check-in, including after a restart; no untracked guest data is left behind.
    let dropped: Vec<HostedDesk> = {
        let mut inner = host.inner.lock().await;
        // A desk that is being packed up right now is not "dropped": its data is still needed.
        let dropped:Vec<_>=inner.hosted.iter().filter(|desk| !orders.iter().any(|order| order.id==desk.id) && !inner.deleting.contains(&desk.id) && !inner.moving.contains_key(&desk.id)).cloned().collect();
        for desk in &dropped {
            inner.deleting.insert(desk.id.clone());
            if let Some(share)=inner.invitations.remove(&desk.id){revoke_share(app,share.share_id).await;}
            inner.failed.remove(&desk.id);
        }
        dropped
    };
    for desk in dropped {
        let app = app.clone();
        tauri::async_runtime::spawn(async move {
            let result: Result<(), String> = async {
                if app.state::<PlatformStore>().environment(&desk.environment_id).is_ok() {
                    crate::commands::set_environment_status(desk.environment_id.clone(), EnvironmentStatus::Stopped, app.state(), app.state()).await?;
                    crate::commands::delete_environment(desk.environment_id.clone(), None, app.state(), app.state(), app.state()).await?;
                }
                Ok(())
            }.await;
            crate::security::record(Event::new("grid.desk.dropped").env(&desk.environment_id).text("desk", &desk.id).outcome(&result));
            let host=app.state::<DeskHost>();let mut inner=host.inner.lock().await;
            if result.is_ok(){inner.hosted.retain(|entry|entry.id!=desk.id);if !persist_hosted(&app,&inner.hosted){inner.hosted_dirty=true;}}
            inner.deleting.remove(&desk.id);
        });
    }
    for order in orders {
        let mut inner = host.inner.lock().await;
        // This computer is giving the desk up: pack its data and send it, then say so once.
        if order.park {
            let hosted = inner.hosted.iter().find(|desk| desk.id == order.id).cloned();
            // A locked-down desk stays where it is, and that is settled BEFORE any finished
            // parcel is reported. A park already running when the lockdown started would
            // otherwise land its parcel here and be handed on, opening the desk unlocked on
            // another computer while this one deletes its copy.
            if hosted.as_ref().is_some_and(|desk| crate::security::is_contained(&desk.environment_id)) {
                if let Some(handle) = inner.moving.remove(&order.id) {
                    handle.abort();
                }
                // This order's own finished parcel goes with the superseded ones. A park that
                // landed just as the lockdown began holds the locked-down desk's data, and
                // dropping the record without deleting what it points at leaves exactly that
                // sitting in the company's bucket — the copy the lockdown existed to prevent.
                let (mine, mut orphans) = take_packed(&mut inner.packed, &order.id, order.generation);
                if let Some(Ok(parcel)) = mine {
                    orphans.push(parcel);
                }
                forget_parcels(&order.id, orphans, parking);
                reports.push(DeskReport { id: order.id.clone(), state: "failed".into(), note: "This desk is locked down on its computer, so it cannot be moved until it is unlocked there".into(), generation: order.generation, ..DeskReport::default() });
                continue;
            }
            let (packed, orphans) = take_packed(&mut inner.packed, &order.id, order.generation);
            forget_parcels(&order.id, orphans, parking);
            if let Some(packed) = packed {
                if packed.is_err() {
                    if let Some(handle) = inner.moving.remove(&order.id) {
                        handle.abort();
                    }
                }
                // Told to the hub, so the data is the move's now and not this computer's to
                // delete. Written down before the report goes out, because a report that went out
                // and was not written down is the case that destroys a desk; one that cannot be
                // written down waits (see `park_report`). Written down at all, too, if the park's
                // own note of the parcel did not reach the disk.
                let marked = match &packed {
                    Ok(parcel) => change_parked(app, |parked| {
                        let mut found = false;
                        for entry in parked.iter_mut().filter(|entry| entry.desk == order.id && entry.generation == order.generation) {
                            entry.reported = true;
                            found = true;
                        }
                        if !found {
                            parked.push(Parked { desk: order.id.clone(), generation: order.generation, parcel: parcel.clone(), reported: true });
                        }
                    })
                    .await,
                    Err(_) => Ok(()),
                };
                reports.push(park_report(&mut inner.packed, order, packed, marked));
                continue;
            }
            let Some(hosted) = hosted else {
                if let Some(handle) = inner.moving.remove(&order.id) {
                    handle.abort();
                }
                reports.push(DeskReport { id: order.id.clone(), state: "failed".into(), note: "This computer no longer has that desk".into(), generation: order.generation, ..DeskReport::default() });
                continue;
            };
            if let Some(share) = inner.invitations.remove(&order.id) {
                revoke_share(app, share.share_id).await;
            }
            if !inner.moving.contains_key(&order.id) {
                let (app, moved, membership, grid, parking) = (app.clone(), order.clone(), membership.clone(), grid.to_owned(), parking.cloned());
                let handle = tauri::async_runtime::spawn(async move {
                    let environment_id = hosted.environment_id.clone();
                    // Packing runs only while the desk is open, so a lockdown that starts midway
                    // stops it within half a second instead of carrying the desk to a computer
                    // that knows nothing of the lockdown.
                    let result = match crate::security::while_open(&environment_id, moving::park(&app, &moved, &environment_id, &membership, &grid, parking.as_ref())).await {
                        Some(result) => result,
                        None => Err("This desk was locked down while its data was being packed, so it stayed on its computer".to_string()),
                    };
                    crate::security::record(Event::new("grid.desk.parked").text("desk", &moved.id).outcome(&result.as_ref().map(|_| ()).map_err(Clone::clone)));
                    // Written to disk before it is remembered in memory, because memory is the
                    // thing that does not survive. A park that landed and was not reported
                    // before the engine stopped used to leave its object in the company's
                    // bucket with nothing referring to it, and the bucket name carries a
                    // timestamp so the next park wrote a new object beside it rather than over
                    // it: somebody's desk, charged for, invisible.
                    if let Ok(parcel) = &result {
                        let _ = change_parked(&app, |parked| {
                            parked.retain(|entry| entry.desk != moved.id || entry.generation != moved.generation);
                            parked.push(Parked { desk: moved.id.clone(), generation: moved.generation, parcel: parcel.clone(), reported: false });
                        })
                        .await;
                    }
                    let host = app.state::<DeskHost>();
                    let mut inner = host.inner.lock().await;
                    inner.moving.remove(&moved.id);
                    inner.packed.insert(packed_key(&moved.id, moved.generation), result);
                    drop(inner);
                    app.state::<crate::deskgrid::DeskGrid>().wake();
                });
                inner.moving.insert(order.id.clone(), handle);
            }
            reports.push(DeskReport { id: order.id.clone(), state: "moving".into(), note: "Packing the desk's data to move it".into(), generation: order.generation, ..DeskReport::default() });
            continue;
        }
        // This computer is taking the desk over: fetch the data and unpack it as its own sandbox.
        if let Some(parcel) = order.adopt.clone() {
            // Already here. The hub can hand a parked desk straight back to the computer it
            // came from, in the same answer that accepts "parked": placement excludes only the
            // computer it is moving from, which has just been cleared, and the one hosting it,
            // which is now nobody — and the desk's own trail puts this computer first. Importing
            // then makes a second full-size copy of a desk this computer is already holding.
            // Nothing is lost by it, but a desk's worth of disk is, on a computer that is very
            // often handing desks off because it is short of disk in the first place.
            // Never while its sandbox is on the way out. A desk that was dropped and whose
            // delete is still running would be reported adopted on a sandbox about to vanish:
            // the hub clears the parcel, removing the desk deletes the hub's copy, the delete
            // finishes, and the next order builds an empty desk. Saying nothing this pass costs
            // one check-in; the parcel is still there and is adopted normally once it is gone.
            let here = inner.hosted.iter().find(|desk| desk.id == order.id).cloned();
            let present = here.as_ref().is_some_and(|hosted| environments.iter().any(|environment| environment.id == hosted.environment_id));
            let can_use = already_here(here.is_some(), present, inner.deleting.contains(&order.id));
            if let Some(hosted) = here.filter(|_| can_use) {
                let _ = crate::commands::set_environment_status(hosted.environment_id.clone(), EnvironmentStatus::Running, app.state(), app.state()).await;
                reports.push(DeskReport { id: order.id.clone(), state: "adopted".into(), environment_id: Some(hosted.environment_id), note: "The desk is already on this computer".into(), generation: order.generation, ..DeskReport::default() });
                continue;
            }
            if inner.deleting.contains(&order.id) {
                reports.push(DeskReport { id: order.id.clone(), state: "moving".into(), note: "Making room for the desk's data".into(), generation: order.generation, ..DeskReport::default() });
                continue;
            }
            // The answer to THIS order, carrying the parcel it was the answer to. Keyed on the
            // bare desk before, so an adopt that finished for a withdrawn order answered the
            // next one instead — and the hub, told the desk had arrived, cleared its parcel and
            // `forget_parcel` deleted the newer one. The desk's data, gone, from a stale success.
            // Two locks rather than one: the key pins the order, the checksum pins the parcel,
            // because the hub can send the same generation again with a different parcel after a
            // repack.
            if let Some((answered, taken)) = take_taken(&mut inner.taken, &order.id, order.generation, &parcel.sha256) {
                let _ = answered;
                match taken {
                    Ok(environment_id) => {
                        if !inner.hosted.iter().any(|desk| desk.id == order.id) {
                            inner.hosted.push(HostedDesk { id: order.id.clone(), name: order.name.clone(), environment_id: environment_id.clone() });
                            if !persist_hosted(app, &inner.hosted) { inner.hosted_dirty = true; }
                        }
                        // Before it runs, so it never starts as the locked-down copy an import
                        // makes rather than as the desk the order describes.
                        // The data arrived, and that is what "adopted" means. Reporting a
                        // failure here because the settings would not apply was catastrophic in
                        // combination with the hub rule a few lines away: the hub marked the
                        // desk Failed and kept the parcel, `orders_for` never orders a Failed
                        // desk that holds one, so the next pass found this sandbox hosted and
                        // unordered and `dropped` deleted it — and for a bucket parcel the copy
                        // there had already been deleted on import, so that sandbox was the only
                        // one left. Settings that will not apply are a thing to keep trying,
                        // never a reason to throw the desk away.
                        let settled = as_the_order_says(app, &environment_id, &order);
                        if let Err(error) = &settled {
                            crate::security::record(Event::new("grid.desk.adopted_settings_failed").text("desk", &order.id).text("error", error));
                            inner.unsettled.insert(order.id.clone(), order.clone());
                        }
                        let (state, may_start) = arrival(&settled);
                        if may_start {
                            let _ = crate::commands::set_environment_status(environment_id.clone(), EnvironmentStatus::Running, app.state(), app.state()).await;
                        }
                        let note = match &settled {
                            Ok(()) => "The desk's data is here".to_owned(),
                            Err(error) => format!("The desk's data is here; its settings could not be applied yet and are being retried: {error}"),
                        };
                        reports.push(DeskReport { id: order.id.clone(), state: state.into(), environment_id: Some(environment_id), note, generation: order.generation, ..DeskReport::default() });
                    }
                    Err(error) => {
                        // Written down, not only reported. The hub marks the desk Failed and
                        // leaves this computer as its host, and only a Moving desk carries an
                        // adopt — so the next check-in brought a plain order, found no sandbox,
                        // and BUILT A FRESH ONE. The person got an empty desk while the hub's
                        // parcel still pointed at their data, and the next park of that desk
                        // wrote over the parcel, at which point it was gone. Remembering the
                        // failure stops the build; `place()` sends a desk that still holds a
                        // parcel back to Moving, so a retry adopts rather than starting over.
                        inner.failed.insert(order.id.clone(), (order.generation, error.clone()));
                        reports.push(DeskReport { id: order.id.clone(), state: "failed".into(), note: error, generation: order.generation, ..DeskReport::default() });
                    }
                }
                continue;
            }
            if !inner.moving.contains_key(&order.id) {
                let (app, moved, membership, parking) = (app.clone(), order.clone(), membership.clone(), parking.cloned());
                let handle = tauri::async_runtime::spawn(async move {
                    let result = moving::adopt(&app, &moved, &parcel, &membership, parking.as_ref()).await;
                    crate::security::record(Event::new("grid.desk.adopted").text("desk", &moved.id).outcome(&result.as_ref().map(|_| ()).map_err(Clone::clone)));
                    let host = app.state::<DeskHost>();
                    let mut inner = host.inner.lock().await;
                    inner.moving.remove(&moved.id);
                    inner.taken.insert(packed_key(&moved.id, moved.generation), (parcel.sha256.clone(), result));
                    drop(inner);
                    app.state::<crate::deskgrid::DeskGrid>().wake();
                });
                inner.moving.insert(order.id.clone(), handle);
            }
            reports.push(DeskReport { id: order.id.clone(), state: "moving".into(), note: "Taking the desk's data".into(), generation: order.generation, ..DeskReport::default() });
            continue;
        }
        if inner.failed.get(&order.id).is_some_and(|(generation, _)| *generation != order.generation) { inner.failed.remove(&order.id); }
        if let Some((_, error)) = inner.failed.get(&order.id).cloned() {
            reports.push(DeskReport { id: order.id.clone(), state: "failed".into(), note: error, ..DeskReport::default() });
            continue;
        }
        let Some(hosted) = inner.hosted.iter().find(|desk| desk.id == order.id).cloned() else {
            if !inner.building.contains_key(&order.id) {
                let handle = spawn_build(app, order.clone(), membership.clone());
                inner.building.insert(order.id.clone(), handle);
            }
            reports.push(DeskReport { id: order.id.clone(), state: "building".into(), note: "Creating the sandbox".into(), ..DeskReport::default() });
            continue;
        };
        let Some(environment) = environments.iter().find(|environment| environment.id == hosted.environment_id) else {
            // Its person deleted the sandbox: the hub places the desk again.
            inner.hosted.retain(|desk| desk.id != order.id);
            if !persist_hosted(app, &inner.hosted) { inner.hosted_dirty = true; }
            if let Some(share) = inner.invitations.remove(&order.id) {
                revoke_share(app, share.share_id).await;
            }
            reports.push(DeskReport { id: order.id.clone(), state: "gone".into(), note: "The sandbox is no longer on this computer".into(), ..DeskReport::default() });
            continue;
        };
        // Settings that would not apply when the desk arrived, tried again. The data is here and
        // the desk is kept either way; what is withheld is starting it, because a desk running
        // with its network off is a working desk that is quietly broken.
        if inner.unsettled.contains_key(&order.id) {
            match as_the_order_says(app, &hosted.environment_id, &order) {
                Ok(()) => {
                    inner.unsettled.remove(&order.id);
                    crate::security::record(Event::new("grid.desk.settings_applied").text("desk", &order.id));
                }
                Err(error) => {
                    reports.push(DeskReport { id: order.id.clone(), state: "building".into(), environment_id: Some(hosted.environment_id.clone()), note: format!("Waiting to apply this desk's settings: {error}"), generation: order.generation, ..DeskReport::default() });
                    continue;
                }
            }
        }
        if environment.status != EnvironmentStatus::Running {
            if environment.status == EnvironmentStatus::Stopped {
                let app = app.clone();
                let id = environment.id.clone();
                tauri::async_runtime::spawn(async move {
                    let _ = crate::commands::set_environment_status(id, EnvironmentStatus::Running, app.state(), app.state()).await;
                });
            }
            let note = match environment.status {
                EnvironmentStatus::Error => environment.last_error.clone().unwrap_or_else(|| "The sandbox needs attention".into()),
                _ => "Starting the sandbox".into(),
            };
            reports.push(DeskReport { id: order.id.clone(), state: if environment.status == EnvironmentStatus::Error { "failed".into() } else { "building".into() }, environment_id: Some(environment.id.clone()), note, ..DeskReport::default() });
            continue;
        }
        if order.person_id.is_none() {
            if let Some(old) = inner.invitations.remove(&order.id) { revoke_share(app, old.share_id).await; }
            reports.push(DeskReport { id: order.id.clone(), state: "ready".into(), environment_id: Some(environment.id.clone()), note: "Unassigned; access revoked".into(), ..Default::default() });
            continue;
        }
        // Running: keep a live share and tell the hub about a new one once.
        let stale = inner.invitations.get(&order.id).is_none_or(|share| share.expires_at - now < RENEW_BEFORE || share.generation != order.generation || share.person_id != order.person_id);
        if stale {
            if let Some(old) = inner.invitations.remove(&order.id) {
                revoke_share(app, old.share_id).await;
            }
            match mint_share(app, &environment.id, order, membership).await {
                Ok(share) => {
                    crate::security::record(Event::new("grid.desk.shared").env(&environment.id).text("desk", &order.id));
                    inner.invitations.insert(order.id.clone(), share);
                }
                Err(error) => {
                    reports.push(DeskReport { id: order.id.clone(), state: "failed".into(), environment_id: Some(environment.id.clone()), note: format!("Cannot share the desk: {error}"), ..DeskReport::default() });
                    continue;
                }
            }
        }
        let share = inner.invitations.get_mut(&order.id).expect("inserted above");
        let tell = order.needs_invitation || !share.reported;
        share.reported = true;
        reports.push(DeskReport {
            id: order.id.clone(),
            state: "ready".into(),
            environment_id: Some(environment.id.clone()),
            note: "Ready".into(),
            invitation: tell.then(|| share.invitation.clone()),
            invitation_expires_at: tell.then_some(share.expires_at),
            generation: order.generation,
            parcel: None,
        });
    }
    for report in &mut reports {
        if let Some(order) = orders.iter().find(|order| order.id == report.id) { report.generation = order.generation; }
    }
    reports
}

/// This computer stops hosting: shares end. With `delete` (its grid was deleted) the desks'
/// sandboxes go too, with their data; otherwise they stay for their owner to keep or delete.
pub(crate) async fn stop_hosting(app: &AppHandle, delete: bool) {
    ensure_loaded(app).await;
    let host = app.state::<DeskHost>();
    let mut inner = host.inner.lock().await;
    for (_, share) in inner.invitations.drain() {
        revoke_share(app, share.share_id).await;
    }
    for (_, build) in inner.building.drain() {
        build.abort();
    }
    inner.failed.clear();
    let hosted = std::mem::take(&mut inner.hosted);
    if !delete {
        // The kept sandboxes are no longer desks. Without the record, the next start reads desks
        // back from their descriptions, and a later grid would stop and delete them as strays.
        let released = app.state::<PlatformStore>().mutate(|state| {
            for environment in &mut state.environments {
                if let Some(rest) = environment.description.strip_prefix("Grid desk ") {
                    environment.description = format!("{RELEASED_DESK}{rest}");
                }
            }
            Ok(())
        });
        crate::security::record(Event::new("grid.desk.released").number("desks", hosted.len() as u64).outcome(&released));
    }
    let _ = std::fs::remove_file(hosted_path(app));
    drop(inner);
    if delete {
        for desk in hosted {
            let result: Result<(), String> = async {
                if app.state::<PlatformStore>().environment(&desk.environment_id).is_ok() {
                    let _ = crate::commands::set_environment_status(desk.environment_id.clone(), EnvironmentStatus::Stopped, app.state(), app.state()).await;
                    crate::commands::delete_environment(desk.environment_id.clone(), None, app.state(), app.state(), app.state()).await?;
                }
                Ok(())
            }
            .await;
            crate::security::record(Event::new("grid.desk.deleted_with_grid").env(&desk.environment_id).text("desk", &desk.id).outcome(&result));
        }
    }
}

/// The grid is paused for deletion: every desk here stops and is no longer shared, but stays,
/// with its data, so a restore starts and shares it again.
pub(crate) async fn pause(app: &AppHandle) {
    ensure_loaded(app).await;
    let host = app.state::<DeskHost>();
    let running: Vec<String> = {
        let mut inner = host.inner.lock().await;
        for (_, share) in inner.invitations.drain() {
            revoke_share(app, share.share_id).await;
        }
        let environments = app.state::<PlatformStore>().snapshot().map(|state| state.environments).unwrap_or_default();
        inner.hosted.iter().filter(|desk| environments.iter().any(|environment| environment.id == desk.environment_id && environment.status == EnvironmentStatus::Running)).map(|desk| desk.environment_id.clone()).collect()
    };
    for id in running {
        let result = crate::commands::set_environment_status(id.clone(), EnvironmentStatus::Stopped, app.state(), app.state()).await;
        crate::security::record(Event::new("grid.desk.paused").env(&id).outcome(&result.map(|_| ())));
    }
}

/// This computer holds at least one desk for the grid.
pub(crate) async fn hosts_anything(app: &AppHandle) -> bool {
    ensure_loaded(app).await;
    !app.state::<DeskHost>().inner.lock().await.hosted.is_empty()
}

/// A desk's data is being packed up or taken over right now.
pub(crate) async fn moving_anything(app: &AppHandle) -> bool {
    ensure_loaded(app).await;
    !app.state::<DeskHost>().inner.lock().await.moving.is_empty()
}

/// Every desk here has been packed up and the hub has its data.
pub(crate) async fn parked_everything(app: &AppHandle) -> bool {
    ensure_loaded(app).await;
    let host = app.state::<DeskHost>();
    let inner = host.inner.lock().await;
    // Keyed on the desk, whichever order packed it. `packed` gained the order's generation in
    // its key, and this was left looking up the bare id, so it was never true and the wait for
    // "everything is packed" could only ever end by timing out.
    let packed_for = |desk: &str| {
        let under = format!("{desk}#");
        inner.packed.iter().any(|(key, outcome)| (key == desk || key.starts_with(&under)) && outcome.is_ok())
    };
    !inner.hosted.is_empty() && inner.hosted.iter().all(|desk| packed_for(&desk.id))
}

/// The desks this computer hosts, for its own person to see.
pub(crate) async fn hosting_status(app: &AppHandle) -> Value {
    ensure_loaded(app).await;
    let host = app.state::<DeskHost>();
    let inner = host.inner.lock().await;
    json!(inner.hosted.iter().map(|desk| json!({"id": desk.id, "name": desk.name, "environmentId": desk.environment_id, "shared": inner.invitations.contains_key(&desk.id)})).collect::<Vec<_>>())
}

// ---- The person's side: signing in and opening their desk. ----

fn login_json(login: &Login) -> Value {
    json!({
        "gridId": login.grid_id, "grid": login.grid_name, "username": login.username, "personId": login.person_id, "name": login.name,
        "adminRole": login.admin_role, "signedInAt": login.signed_in_at, "desks": login.desks, "connections":login.connections, "mfa": login.mfa,
    })
}

pub(crate) async fn desk_status(app: &AppHandle) -> Value {
    ensure_loaded(app).await;
    let host = app.state::<DeskHost>();
    let inner = host.inner.lock().await;
    inner.login.as_ref().map(login_json).unwrap_or(Value::Null)
}

/// The signed-in person's session with their grid's hub, used to open a desk through the hub
/// when its host cannot be reached directly.
pub(crate) fn person_session() -> Result<member::DeskSession, String> {
    management_session()
}

pub(crate) fn management_session() -> Result<member::DeskSession, String> {
    let saved = secrets::resolve(PERSON_SESSION).map_err(|_| "Sign in to your Sandbox Grid with an administrator account")?;
    serde_json::from_str(&saved).map_err(|_| "Saved desk session is invalid; sign in again".into())
}

/// Signs in to the grid an invite names and opens every desk that is ready: each becomes a
/// shared environment in this computer's sandbox list, replacing an older entry for the same desk.
pub(crate) async fn desk_login(invite_text: String, username: Option<String>, secret: Option<String>, code: Option<String>, sso: bool, app: AppHandle) -> Result<Value, String> {
    ensure_loaded(&app).await;
    let host=app.state::<DeskHost>();let _sign_in=host.sign_in.lock().await;
    let invite = invite::decode_desk(invite_text.trim())?;
    let session: PersonSession = if sso {
        // The company's identity provider signs them in: the browser opens on it and comes back here.
        member::person_login_sso(&invite, |url| crate::workspace::open_workspace_url(url.to_owned())).await?
    } else {
        let username = username.filter(|name| !name.trim().is_empty()).ok_or("Give your username, or sign in with your company account (sso)")?;
        let secret = secret.ok_or("Give your password")?;
        member::person_login(&invite, &username, &secret, code.as_deref()).await?
    };
    let portal=session.session.manage(json!({"action":"portal"})).await?;
    secrets::store(PERSON_SESSION,&serde_json::to_string(&session.session).map_err(|e|e.to_string())?)?;
    secrets::store(PERSON_INVITE,invite_text.trim())?;
    install_login(&app,portal).await
}

async fn install_login(app:&AppHandle,portal:Value)->Result<Value,String>{
    use sha2::{Digest,Sha256};
    let store=app.state::<PlatformStore>();let host=app.state::<DeskHost>();
    let previous=host.inner.lock().await.login.clone();
    let grid_id=portal["grid"]["id"].as_str().ok_or("Invalid grid response")?.to_owned();
    let person_id=portal["personId"].as_str().ok_or("Invalid person response")?.to_owned();
    let mut desks=Vec::new();
    for desk in portal["desks"].as_array().ok_or("Invalid desk response")?.iter().take(256){
        let id=desk["id"].as_str().ok_or("Invalid desk ID")?.to_owned();
        let previous_entry=previous.as_ref().filter(|p|p.grid_id==grid_id&&p.person_id==person_id).and_then(|p|p.desks.iter().find(|d|d.id==id));
        let invitation=desk.get("invitation");let address=invitation.and_then(|i|i["address"].as_str()).map(str::to_owned);
        let invitation_hash=invitation.map(|i|hex::encode(Sha256::digest(i.to_string().as_bytes()))).unwrap_or_default();
        let mut environment_id=None;let mut note=desk["note"].as_str().unwrap_or_default().to_owned();
        if let Some(invitation)=invitation{
            let existing=previous_entry.filter(|entry|entry.invitation_hash==invitation_hash).and_then(|entry|entry.environment_id.clone()).filter(|id|store.environment(id).is_ok());
            if let Some(id)=existing{environment_id=Some(id)}else{
                let imported:Result<String,String>=async{
                    let invitation:crate::peer_sharing::Invitation=serde_json::from_value(invitation.clone()).map_err(|_|"Invalid desk invitation")?;
                    let before=store.snapshot()?.environments.into_iter().map(|e|e.id).collect::<Vec<_>>();
                    let state=crate::peer_sharing::import_environment_share(invitation,app.state()).await?;
                    state.environments.into_iter().find(|e|!before.contains(&e.id)&&e.runtime.starts_with("shared://desk/")).map(|e|e.id).ok_or("The desk could not be imported".into())
                }.await;
                match imported{Ok(id)=>environment_id=Some(id),Err(error)=>note=format!("Desk unavailable: {error}")}
            }
        }
        desks.push(LoginDesk{id,name:desk["name"].as_str().unwrap_or_default().into(),state:desk["state"].as_str().unwrap_or_default().into(),note,host:desk["host"].as_str().map(str::to_owned),environment_id,address,invitation_hash});
    }
    // Account switches, revoked assignments and rotated grants retire only entries from the old sign-in.
    for old in previous.iter().flat_map(|p|p.desks.iter()).filter_map(|d|d.environment_id.as_ref()){
        if !desks.iter().any(|d|d.environment_id.as_ref()==Some(old)){
            crate::peer_sharing::forget(old)?;
            store.mutate(|state|{state.environments.retain(|e|&e.id!=old);Ok(())})?;
        }
    }
    let login=Login{grid_id,grid_name:portal["grid"]["name"].as_str().unwrap_or_default().into(),username:portal["username"].as_str().unwrap_or_default().into(),person_id,name:portal["name"].as_str().unwrap_or_default().into(),admin_role:serde_json::from_value(portal["adminRole"].clone()).unwrap_or_default(),desks,signed_in_at:yougori_grid::now(),connections:portal["connections"].as_array().cloned().unwrap_or_default(),mfa:portal["mfa"]==true};
    write_json(&login_path(app),&login)?;
    let shown=login_json(&login);host.inner.lock().await.login=Some(login);Ok(shown)
}

pub(crate) async fn desk_refresh(app:AppHandle)->Result<Value,String>{
    ensure_loaded(&app).await;
    let session=management_session()?;
    let portal={let host=app.state::<DeskHost>();let _sign_in=host.sign_in.lock().await;session.manage(json!({"action":"portal"})).await};
    match portal{
        Ok(portal)=>{let host=app.state::<DeskHost>();let _sign_in=host.sign_in.lock().await;install_login(&app,portal).await}
        // The grid was deleted: its desks are gone, so their entries here go too.
        Err(error) if error==yougori_grid::GRID_DELETED=>{
            let grid=app.state::<DeskHost>().inner.lock().await.login.as_ref().map(|login|login.grid_name.clone()).unwrap_or_default();
            desk_logout(app).await?;
            Err(format!("{grid} deleted this sandbox grid; your desks were removed from this computer"))
        }
        Err(error)=>Err(error),
    }
}

/// Forgets the sign-in and removes the desk entries from this computer; the desks and their data
/// stay on their hosts.
pub(crate) async fn desk_logout(app: AppHandle) -> Result<Value, String> {
    ensure_loaded(&app).await;
    let guard_host=app.state::<DeskHost>();let _sign_in=guard_host.sign_in.lock().await;
    if let Ok(session)=management_session(){let _=session.manage(json!({"action":"logout"})).await;}
    let host = app.state::<DeskHost>();
    let login = host.inner.lock().await.login.take();
    let store = app.state::<PlatformStore>();
    for desk in login.iter().flat_map(|login| login.desks.iter()) {
        if let Some(id) = &desk.environment_id {
            if store.environment(id).is_ok() {
                let _ = crate::peer_sharing::forget(id);
                let _ = store.mutate(|state| { state.environments.retain(|environment| &environment.id != id); Ok(()) });
            }
        }
    }
    let _ = std::fs::remove_file(login_path(&app));
    let _ = secrets::delete_secret(PERSON_INVITE);
    let _ = secrets::delete_secret(PERSON_SESSION);
    crate::security::record(Event::new("grid.desk.signed_out"));
    Ok(json!({"signedOut": true}))
}

// ---- The admin's side: people and desks on the hub this computer runs. ----

async fn derive_new(secret: &str) -> Result<(String, String), String> {
    password::validate(secret)?;
    let salt = password::new_salt();
    let secret = secret.to_owned();
    let key = {
        let salt = salt.clone();
        tokio::task::spawn_blocking(move || password::derive(&secret, &salt)).await.map_err(|error| error.to_string())??
    };
    Ok((salt, key))
}

/// Adds a person and, when sized, orders their desk in the same step; the desk is named after them.
pub(crate) async fn person_add(username: String, name: String, secret: String, desk: Option<DeskSpec>, app: AppHandle) -> Result<Value, String> {
    let (salt, key) = derive_new(&secret).await?;
    crate::deskgrid::with_hub(&app, |hub| hub.add_person(&username, &name, &salt, &key, desk)).await
}

/// The desk a person is given with their account, when any of its numbers are set: a container
/// of 2 cores, 4 GB and 20 GB unless said otherwise.
pub(crate) fn person_desk(kind: Option<String>, cpu: Option<f64>, memory_gb: Option<f64>, disk_gb: Option<f64>, gpu: Option<bool>) -> Result<Option<DeskSpec>, String> {
    if kind.is_none() && cpu.is_none() && memory_gb.is_none() && disk_gb.is_none() && gpu.is_none() {
        return Ok(None);
    }
    DeskSpec::checked(DeskKind::parse(kind.as_deref().unwrap_or("container"))?, cpu.unwrap_or(2.0), memory_gb.unwrap_or(4.0), disk_gb.unwrap_or(20.0), gpu.unwrap_or(false), "").map(Some)
}

pub(crate) async fn person_password(person: String, secret: String, app: AppHandle) -> Result<Value, String> {
    let (salt, key) = derive_new(&secret).await?;
    crate::deskgrid::with_hub(&app, |hub| hub.set_person_password(&person, &salt, &key)).await
}

pub(crate) async fn person_remove(person: String, app: AppHandle) -> Result<Value, String> {
    crate::deskgrid::with_hub(&app, |hub| hub.remove_person(&person)).await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn desk_add(name: String, kind: Option<String>, cpu: Option<f64>, memory_gb: Option<f64>, disk_gb: Option<f64>, gpu: Option<bool>, image: Option<String>, person: Option<String>, app: AppHandle) -> Result<Value, String> {
    let spec = DeskSpec::checked(DeskKind::parse(kind.as_deref().unwrap_or("container"))?, cpu.unwrap_or(2.0), memory_gb.unwrap_or(4.0), disk_gb.unwrap_or(20.0), gpu.unwrap_or(false), image.as_deref().unwrap_or(""))?;
    let person = person.map(|person| person.trim().to_owned()).filter(|person| !person.is_empty());
    crate::deskgrid::with_hub(&app, |hub| hub.add_desk(&name, spec, person.as_deref())).await
}

pub(crate) async fn desk_assign(desk: String, person: Option<String>, app: AppHandle) -> Result<Value, String> {
    let person = person.map(|person| person.trim().to_owned()).filter(|person| !person.is_empty());
    crate::deskgrid::with_hub(&app, |hub| hub.assign_desk(&desk, person.as_deref())).await
}

pub(crate) async fn desk_retry(desk: String, app: AppHandle) -> Result<Value, String> {
    crate::deskgrid::with_hub(&app, |hub| hub.retry_desk(&desk)).await
}

pub(crate) async fn desk_remove(desk: String, app: AppHandle) -> Result<Value, String> {
    crate::deskgrid::with_hub(&app, |hub| hub.remove_desk(&desk)).await
}

/// App commands, from the main window only: an environment's window must not manage the sandbox grid.
pub(crate) mod commands {
    use super::*;
    use crate::WebviewWindow;

    fn main_window(window: &WebviewWindow) -> Result<(), String> {
        if window.label() == "main" { Ok(()) } else { Err("Desks are managed from the main Yougori window".into()) }
    }

    #[tauri::command]
    #[allow(clippy::too_many_arguments)]
    pub async fn desks_person_add(app: AppHandle, window: WebviewWindow, username: String, name: String, password: String, kind: Option<String>, cpu: Option<f64>, memory_gb: Option<f64>, disk_gb: Option<f64>, gpu: Option<bool>) -> Result<Value, String> {
        main_window(&window)?;
        let desk = super::person_desk(kind, cpu, memory_gb, disk_gb, gpu)?;
        super::person_add(username, name, password, desk, app).await
    }

    #[tauri::command]
    pub async fn desks_person_password(app: AppHandle, window: WebviewWindow, person: String, password: String) -> Result<Value, String> {
        main_window(&window)?;
        super::person_password(person, password, app).await
    }

    #[tauri::command]
    pub async fn desks_person_remove(app: AppHandle, window: WebviewWindow, person: String) -> Result<Value, String> {
        main_window(&window)?;
        super::person_remove(person, app).await
    }

    #[tauri::command]
    #[allow(clippy::too_many_arguments)]
    pub async fn desks_add(app: AppHandle, window: WebviewWindow, name: String, kind: Option<String>, cpu: Option<f64>, memory_gb: Option<f64>, disk_gb: Option<f64>, gpu: Option<bool>, image: Option<String>, person: Option<String>) -> Result<Value, String> {
        main_window(&window)?;
        super::desk_add(name, kind, cpu, memory_gb, disk_gb, gpu, image, person, app).await
    }

    #[tauri::command]
    pub async fn desks_assign(app: AppHandle, window: WebviewWindow, desk: String, person: Option<String>) -> Result<Value, String> {
        main_window(&window)?;
        super::desk_assign(desk, person, app).await
    }

    #[tauri::command]
    pub async fn desks_retry(app: AppHandle, window: WebviewWindow, desk: String) -> Result<Value, String> {
        main_window(&window)?;
        super::desk_retry(desk, app).await
    }

    #[tauri::command]
    pub async fn desks_remove(app: AppHandle, window: WebviewWindow, desk: String) -> Result<Value, String> {
        main_window(&window)?;
        super::desk_remove(desk, app).await
    }

    #[tauri::command]
    pub async fn desk_refresh(app: AppHandle, window: WebviewWindow) -> Result<Value, String> {
        main_window(&window)?;
        super::desk_refresh(app).await
    }

    #[tauri::command]
    pub async fn desk_login(app: AppHandle, window: WebviewWindow, invite: String, username: Option<String>, password: Option<String>, code: Option<String>, sso: Option<bool>) -> Result<Value, String> {
        main_window(&window)?;
        super::desk_login(invite, username, password, code, sso.unwrap_or(false), app).await
    }

    #[tauri::command]
    pub async fn desk_logout(app: AppHandle, window: WebviewWindow) -> Result<Value, String> {
        main_window(&window)?;
        super::desk_logout(app).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parcel(key: &str) -> yougori_grid::desks::Parcel {
        yougori_grid::desks::Parcel { store: Default::default(), key: key.into(), bytes: 1, sha256: "a".repeat(64), at: 0 }
    }

    fn parking(desk: &str, generation: u64) -> DeskOrder {
        DeskOrder { access: Default::default(), role_id: None, image_sha256: None, generation, person_id: None, id: desk.into(), name: "Design".into(), spec: DeskSpec::checked(DeskKind::Container, 2.0, 8.0, 40.0, false, "").unwrap(), person_name: String::new(), needs_invitation: false, park: true, park_in: yougori_grid::desks::ParcelStore::S3, adopt: None }
    }

    #[test]
    fn a_park_is_reported_only_once_its_mark_is_on_disk() {
        let order = parking("desk-1", 4);
        let mut waiting = HashMap::new();
        // The mark could not be written: the hub hears "moving", and the parcel waits for the next
        // pass. Reporting it here is what had the next pass delete a parcel the hub had accepted.
        let held = park_report(&mut waiting, &order, Ok(parcel("desk-1-4")), Err("the disk said no".into()));
        assert_eq!((held.state.as_str(), held.parcel.is_none()), ("moving", true), "{}", held.note);
        assert_eq!(waiting.get(&packed_key("desk-1", 4)), Some(&Ok(parcel("desk-1-4"))));
        // Written down: reported, with the parcel.
        let (taken, _) = take_packed(&mut waiting, "desk-1", 4);
        let sent = park_report(&mut waiting, &order, taken.unwrap(), Ok(()));
        assert_eq!((sent.state.as_str(), sent.parcel), ("parked", Some(parcel("desk-1-4"))));
        assert!(waiting.is_empty());
        // A park that failed is reported as failed either way.
        assert_eq!(park_report(&mut waiting, &order, Err("upload refused".into()), Ok(())).state, "failed");
    }

    /// A read-only record is one the disk will read and not replace, the way a write fails on a
    /// full or failing disk.
    #[cfg(windows)]
    #[test]
    fn a_parcel_record_that_did_not_reach_the_disk_is_an_error_not_ok() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("desk-parcels.json");
        let entry = Parked { desk: "desk-1".into(), generation: 4, parcel: parcel("desk-1-4"), reported: false };
        rewrite_parked(&path, 1, |parked| parked.push(entry.clone())).unwrap();
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(&path, permissions.clone()).unwrap();
        let marked = rewrite_parked(&path, 2, |parked| parked.iter_mut().for_each(|entry| entry.reported = true));
        permissions.set_readonly(false);
        std::fs::set_permissions(&path, permissions).unwrap();
        assert!(marked.is_err(), "the mark never reached the disk, and the caller was told it had");
        assert!(!read_parked(&path, 3).unwrap()[0].reported, "and the record on disk still says so");
    }

    #[test]
    fn a_parcel_packed_for_a_superseded_order_is_never_handed_on() {
        let mut packed = HashMap::new();
        // Another desk's parcel, and a desk whose id this one is a prefix of, both put in FIRST:
        // dropping a superseded parcel is a blanket drop for the desk, and the only thing keeping
        // it off these two is the `#` in the key. Inserting them afterwards would have left that
        // untested, and a test that passes while `take_packed` quietly deletes another desk's
        // parcel is worse than no test, because it is the reason nobody looks again.
        packed.insert(packed_key("desk-2", 7), Ok(parcel("desk-2")));
        packed.insert(packed_key("desk-12", 1), Ok(parcel("desk-12")));
        // A park finished uploading after the hub had already called it off and asked again.
        packed.insert(packed_key("desk-1", 1), Ok(parcel("desk-1")));

        let (taken, orphans) = take_packed(&mut packed, "desk-1", 2);
        assert!(taken.is_none(), "generation 2 was handed the parcel packed for generation 1, so the desk would move on with the data as it was before");
        // And the copy that was uploaded for generation 1 comes back to be deleted: forgetting
        // the record does not unsend it, and in the company's bucket it is charged for.
        assert_eq!(orphans, vec![parcel("desk-1")], "the superseded parcel was dropped without being handed back, so its copy is orphaned in the bucket");
        assert!(take_packed(&mut packed, "desk-1", 1).0.is_none(), "the superseded parcel stayed in the map, so a later order could still pick it up");

        // Neither neighbour was touched.
        assert_eq!(take_packed(&mut packed, "desk-12", 1), (Some(Ok(parcel("desk-12"))), Vec::new()), "a desk whose id starts with another desk's id lost its parcel");
        // The order that asked for a parcel still gets it, and nothing comes back to delete.
        assert_eq!(take_packed(&mut packed, "desk-2", 7), (Some(Ok(parcel("desk-2"))), Vec::new()));
        assert!(packed.is_empty(), "nothing is left behind for a later order");

        // A superseded park that failed holds no data, so there is nothing to delete for it.
        packed.insert(packed_key("desk-3", 1), Err("the pack failed".to_owned()));
        assert_eq!(take_packed(&mut packed, "desk-3", 2), (None, Vec::new()));
    }

    /// PROVES that deleting one desk's parcel cannot undo another desk's reported mark.
    ///
    /// Deleting happens away from the lock, because it is network work with three tries each, so
    /// the record changes underneath it: the same pass that deletes a superseded parcel also
    /// reports a parked one and marks it. Writing back the list worked out before the deleting
    /// started put that mark back to false, and the next pass — the hub having accepted, no park
    /// order naming the desk — deleted a parcel the hub was already handing on. The desk gone,
    /// on the successful path, from a lost update.
    ///
    /// A generation bumped mid-move lines it up, which an admin does by resetting somebody's
    /// password; two desks moving at once on a closing computer does it as well.
    #[test]
    fn deleting_one_parcel_never_undoes_another_desks_reported_mark() {
        let entry = |desk: &str, generation: u64, reported: bool| Parked {
            desk: desk.into(),
            generation,
            reported,
            parcel: yougori_grid::desks::Parcel { store: yougori_grid::desks::ParcelStore::S3, key: format!("{desk}-{generation}"), bytes: 1, sha256: "a".repeat(64), at: 0 },
        };

        // What the pass saw when it worked out what to delete: one superseded parcel of desk-1,
        // and desk-2's parcel not yet reported.
        let (keeping, to_delete) = sort_parked(vec![entry("desk-1", 1, false), entry("desk-2", 5, false)], &[("desk-2".into(), 5)]);
        assert_eq!(to_delete.len(), 1);
        assert_eq!(keeping.len(), 1);

        // While the deleting was happening, desk-2 was reported and marked.
        let mut now = vec![entry("desk-1", 1, false), entry("desk-2", 5, true)];

        // Removing only what was deleted leaves that mark alone.
        without_deleted(&mut now, &[("desk-1".to_owned(), 1)]);
        assert_eq!(now.len(), 1);
        assert!(now[0].reported, "the reported mark was lost, so the next pass deletes a parcel the hub has already accepted and the desk is gone");

        // And a delete that failed leaves its entry in place, to be tried again.
        let mut after = vec![entry("desk-1", 1, false), entry("desk-2", 5, true)];
        without_deleted(&mut after, &[]);
        assert_eq!(after.len(), 2, "an entry whose object is still there was dropped from the record, so nothing will ever tidy it up");

        // A different generation of the same desk is a different parcel and is not swept up.
        let mut other = vec![entry("desk-1", 2, false)];
        without_deleted(&mut other, &[("desk-1".to_owned(), 1)]);
        assert_eq!(other.len(), 1);
    }

    /// PROVES that the "already here" shortcut never answers for a sandbox being deleted.
    ///
    /// The shortcut saves importing a second full-size copy when the hub hands a parked desk
    /// back to the computer it came from. Answering for a sandbox whose delete is still running
    /// is the opposite: the hub clears the parcel, removing the desk deletes the hub's copy, the
    /// delete finishes, and the next order builds an empty desk over nothing.
    #[test]
    fn the_already_here_shortcut_never_answers_for_a_sandbox_being_deleted() {
        // Held, present and not being deleted: the one case the shortcut is for.
        assert!(already_here(true, true, false));

        // Being deleted: say nothing this pass and adopt from the parcel once it is gone.
        assert!(!already_here(true, true, true), "a desk was reported adopted on a sandbox that was being deleted, so the hub cleared the parcel and the next order built an empty desk");

        // Not held, or held with its sandbox already gone: there is nothing to answer with.
        assert!(!already_here(false, false, false));
        assert!(!already_here(true, false, false));
    }

    /// PROVES that an adopt which arrived is reported as arrived, whatever its settings did.
    ///
    /// SEE ALSO the doc on `arrival` for why reporting a settings failure here deleted desks.
    #[test]
    fn an_adopt_that_arrived_is_reported_arrived_even_if_its_settings_will_not_apply() {
        // Settled: adopted, and the desk may start.
        assert_eq!(arrival(&Ok(())), ("adopted", true));

        // Not settled: STILL adopted, because the data is here and that is what the word means.
        // Reporting "failed" made the hub keep the parcel and this computer delete the only
        // sandbox, between two fixes that were each right on their own.
        let (state, may_start) = arrival(&Err("the store would not take the change".to_owned()));
        assert_eq!(state, "adopted", "a desk whose data had arrived was reported failed, and the hub then kept its parcel while this computer deleted the sandbox holding the only copy");
        assert!(!may_start, "a desk was started before it was the desk the order describes, so it comes up with its network off and looks merely broken");
    }

    /// PROVES that a parcel the hub was told about is never deleted from here, and that one it
    /// was never told about is.
    ///
    /// This is the successful path, and it was destroying desks. A park lands, the report goes
    /// out, the hub accepts it and clears the move — so the next orders do not mention that
    /// desk, which read as "nothing is waiting for this parcel" and deleted the bucket object.
    /// The same pass deleted the local sandbox, for the same reason. The adopting computer then
    /// fetched a parcel that was no longer there, and the desk existed nowhere.
    ///
    /// I had already written down why this happens and applied it only to restarts: a parcel
    /// that was reported and is no longer asked for looks exactly like one that was superseded.
    /// The question that separates them is not whether the hub is still asking, but whether the
    /// hub was ever told.
    #[test]
    fn a_parcel_the_hub_was_told_about_is_never_deleted_from_here() {
        let entry = |desk: &str, generation: u64, reported: bool| Parked {
            desk: desk.into(),
            generation,
            reported,
            parcel: yougori_grid::desks::Parcel { store: yougori_grid::desks::ParcelStore::S3, key: format!("{desk}-{generation}"), bytes: 1, sha256: "a".repeat(64), at: 0 },
        };

        // The successful move, one check-in after the report was accepted. Nothing is asking for
        // this desk any more, and the parcel must survive: somebody is about to adopt it.
        let (keeping, deleting) = sort_parked(vec![entry("desk-1", 2, true)], &[]);
        assert!(deleting.is_empty(), "the parcel of a successfully parked desk was deleted, so the adopting computer finds nothing and the desk is gone");
        assert!(keeping.is_empty(), "it is not this computer's to track any more either; the adopter deletes the copy once it has unpacked");

        // Never reported and no longer asked for: nothing will ever use it, so it goes.
        let (keeping, deleting) = sort_parked(vec![entry("desk-1", 2, false)], &[]);
        assert_eq!(deleting.len(), 1, "a parcel nobody was ever told about was kept and charged for");
        assert!(keeping.is_empty());

        // Still the order being parked: kept either way, reported or not. This is the parcel
        // about to be reported, or the one a restart interrupted before it could be.
        for reported in [false, true] {
            let (keeping, deleting) = sort_parked(vec![entry("desk-1", 2, reported)], &[("desk-1".into(), 2)]);
            assert!(deleting.is_empty() && keeping.len() == 1, "the parcel the hub is still asking for was not kept");
        }

        // A newer order for the same desk supersedes an older parcel that never went out.
        let (keeping, deleting) = sort_parked(vec![entry("desk-1", 1, false), entry("desk-1", 2, false)], &[("desk-1".into(), 2)]);
        assert_eq!(deleting.iter().map(|entry| entry.generation).collect::<Vec<_>>(), vec![1]);
        assert_eq!(keeping.len(), 1);

        // But one that DID go out is not deleted just because a newer park is running: the hub
        // may still hand that one on.
        let (keeping, deleting) = sort_parked(vec![entry("desk-1", 1, true), entry("desk-1", 2, false)], &[("desk-1".into(), 2)]);
        assert!(deleting.is_empty(), "a reported parcel was deleted because a later park started");
        assert_eq!(keeping.len(), 1);

        // Another desk being parked says nothing about this one.
        let (_, deleting) = sort_parked(vec![entry("desk-1", 2, false)], &[("desk-2".into(), 2)]);
        assert_eq!(deleting.len(), 1);
    }

    /// PROVES that an adopt result only ever answers the order and the parcel it was the answer
    /// to, which is the difference between a stale success and losing somebody's desk.
    ///
    /// It was keyed on the bare desk id. So an adopt that finished after its order had been
    /// withdrawn answered the NEXT order instead, this computer reported the desk adopted, and
    /// the hub — believing the data had arrived — cleared the desk's parcel. The parcel it
    /// cleared was the newer one, and `forget_parcel` deleted it. A stale success, and the
    /// desk's data gone.
    ///
    /// Two locks, because one is not enough: the key pins the order, and the checksum pins the
    /// parcel, since the hub can send the same generation again with a different parcel after a
    /// repack.
    #[test]
    fn an_adopt_result_answers_only_the_order_and_parcel_it_was_for() {
        let mut taken: HashMap<String, (String, Result<String, String>)> = HashMap::new();
        let (old_sha, new_sha) = ("a".repeat(64), "b".repeat(64));
        taken.insert(packed_key("desk-1", 1), (old_sha.clone(), Ok("env-old".into())));

        // A later order must not be handed the earlier order's success.
        assert!(take_taken(&mut taken, "desk-1", 2, &new_sha).is_none(), "a later order was handed an earlier adopt's result, so the hub would clear the newer parcel and its data would be deleted");
        assert!(taken.is_empty(), "the stale result stayed, so a later order could still pick it up");

        // The same order, but the parcel was packed again: still not an answer to this one.
        taken.insert(packed_key("desk-1", 3), (old_sha.clone(), Ok("env-old".into())));
        assert!(take_taken(&mut taken, "desk-1", 3, &new_sha).is_none(), "a result for a different parcel answered this order");

        // Its own order and its own parcel is the one case that is handed over.
        taken.insert(packed_key("desk-2", 7), (new_sha.clone(), Ok("env-new".into())));
        assert_eq!(take_taken(&mut taken, "desk-2", 7, &new_sha), Some((new_sha.clone(), Ok("env-new".to_owned()))));

        // And another desk's result is never swept up by this one's take.
        taken.insert(packed_key("desk-2", 1), (new_sha.clone(), Ok("env-two".into())));
        taken.insert(packed_key("desk-21", 1), (new_sha.clone(), Ok("env-twentyone".into())));
        assert!(take_taken(&mut taken, "desk-2", 9, &new_sha).is_none());
        assert_eq!(taken.len(), 1, "a desk whose id starts with another desk's id lost its adopt result");
        assert!(taken.contains_key(&packed_key("desk-21", 1)));
    }

    /// The failed-adopt rule is NOT tested here, deliberately, and this note is where somebody
    /// will come looking for it.
    ///
    /// It was tested here, and the test was worthless: it rewrote the logic inside the test and
    /// then checked the copy, so deleting the real line left it green. Worse, the real line is
    /// only a courtesy — `inner.failed` lives in memory and is cleared by any new generation,
    /// which an admin bumps by resetting a password or changing somebody's details, so the
    /// computer alone could never hold this.
    ///
    /// The rule lives on the hub, in `yougori_grid::desks::orders_for`: a desk that failed while
    /// it still holds a parcel is never sent as something to build. Its test is
    /// `a_desk_that_failed_while_holding_a_parcel_is_never_sent_to_be_built`, and it covers the
    /// generation bump that defeats the computer-side note.

    #[test]
    fn a_sandbox_kept_after_leaving_a_grid_is_not_read_back_as_a_desk() {
        assert_eq!(desk_of("Grid desk desk-1 · Ada"), Some("desk-1"));
        assert_eq!(desk_of("Grid desk desk-2"), Some("desk-2"));
        assert_eq!(desk_of(&format!("{RELEASED_DESK}desk-1 · Ada")), None);
        assert_eq!(desk_of("Grid desk  · Ada"), None);
    }

    #[test]
    fn a_desk_order_becomes_a_sandbox_request_of_its_kind_and_size() {
        let order = DeskOrder { access: Default::default(), role_id: None, image_sha256: None, generation: 0, person_id: Some("person-1".into()), id: "desk-1".into(), name: "Design".into(), spec: DeskSpec::checked(DeskKind::Container, 2.0, 8.0, 40.0, true, "").unwrap(), person_name: "Ada".into(), needs_invitation: false, park: false, park_in: yougori_grid::desks::ParcelStore::Hub, adopt: None };
        let request = request_for(&order);
        assert_eq!((request.kind, request.provider, request.gpu_access, request.auto_setup_cuda), (EnvironmentKind::Container, RuntimeProviderKind::YougoriCuda, true, true));
        assert_eq!((request.resource_policy.cpu.preferred, request.resource_policy.memory_gb.max, request.storage_gb), (2.0, 8.0, Some(40.0)));
        assert_eq!((request.name.as_str(), request.description.as_str()), ("Desk desk-1", "Grid desk desk-1 · Ada"));
        let vm = request_for(&DeskOrder { spec: DeskSpec::checked(DeskKind::Vm, 1.0, 2.0, 10.0, false, "prepared.qcow2").unwrap(), ..order });
        assert_eq!((vm.kind, vm.provider, vm.runtime.as_str()), (EnvironmentKind::FullVm, RuntimeProviderKind::Qemu, "prepared.qcow2"));
    }
}
