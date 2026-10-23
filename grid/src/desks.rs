//! Desks: sandboxes the admin orders for named people, hosted on the company's computers within
//! the share of each that the admin allows (`Share`), whether or not someone is using it. The hub
//! keeps the orders and places each desk on a host with room in its share; the host builds, runs
//! and shares the sandbox and reports back with what it has and is using; the person signs in
//! from any computer and receives the invitation to their own desk. A desk stays its person's,
//! with its data, until the admin releases it. This module is the hub's model and placement;
//! `hub` wires it to the network and `member` carries it to hosts and people.
use crate::{digest, now, token};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const MAX_DESKS: usize = 256;
pub const MAX_PEOPLE: usize = 512;
/// A share invitation this close to expiring is minted again by the host.
pub const RENEW_BEFORE: i64 = 2 * 60 * 60;
/// A desk that failed to build is tried again, on any fitting host, this many times.
pub const MAX_ATTEMPTS: u8 = 3;

/// What kind of sandbox a desk is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DeskKind {
    Container,
    MicroVm,
    Vm,
}

impl DeskKind {
    pub fn parse(text: &str) -> Result<DeskKind, String> {
        match text.trim().to_ascii_lowercase().as_str() {
            "container" | "" => Ok(DeskKind::Container),
            "microvm" | "micro-vm" | "micro" => Ok(DeskKind::MicroVm),
            "vm" | "fullvm" | "full-vm" => Ok(DeskKind::Vm),
            _ => Err("--kind must be container, microvm or vm".into()),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            DeskKind::Container => "Container",
            DeskKind::MicroVm => "MicroVM",
            DeskKind::Vm => "VM",
        }
    }

    fn default_image(self) -> &'static str {
        match self {
            DeskKind::Container => "docker.io/library/ubuntu:24.04",
            DeskKind::MicroVm | DeskKind::Vm => "builtin:alpine",
        }
    }
}

/// What the admin asked for: the sandbox's kind, its share of the host, and its image.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeskSpec {
    pub kind: DeskKind,
    pub cpu: f64,
    pub memory_gb: f64,
    pub disk_gb: f64,
    pub gpu: bool,
    pub image: String,
}

impl DeskSpec {
    /// Checks the admin's numbers; an empty image takes the kind's default.
    pub fn checked(kind: DeskKind, cpu: f64, memory_gb: f64, disk_gb: f64, gpu: bool, image: &str) -> Result<DeskSpec, String> {
        if !cpu.is_finite() || !(0.5..=64.0).contains(&cpu) {
            return Err("--cpu must be between 0.5 and 64 cores".into());
        }
        if !memory_gb.is_finite() || !(0.5..=512.0).contains(&memory_gb) {
            return Err("--memory must be between 0.5 and 512 GB".into());
        }
        if !disk_gb.is_finite() || disk_gb.fract() != 0.0 || !(1.0..=2048.0).contains(&disk_gb) {
            return Err("--disk must be a whole number between 1 and 2048 GB".into());
        }
        let image = image.trim();
        if image.len() > 4096 || image.chars().any(char::is_control) || (kind == DeskKind::Container && image.chars().any(char::is_whitespace)) {
            return Err("--image must be an OCI image reference or a bootable media path".into());
        }
        if kind == DeskKind::Vm && image.is_empty() { return Err("Choose a prepared VM disk image".into()); }
        Ok(DeskSpec { kind, cpu, memory_gb, disk_gb, gpu, image: if image.is_empty() { kind.default_image().into() } else { image.into() } })
    }

    pub fn describe(&self) -> String {
        format!("{} · {} CPU · {} GB memory · {} GB disk{}", self.kind.label(), trim_number(self.cpu), trim_number(self.memory_gb), trim_number(self.disk_gb), if self.gpu { " · GPU" } else { "" })
    }
}

fn trim_number(value: f64) -> String {
    if value.fract() == 0.0 { format!("{}", value as i64) } else { format!("{value:.1}") }
}

/// Where a desk is in its life. The hub derives "offline" from its host's presence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DeskState {
    /// Waiting for a host with room.
    Planned,
    /// A host is building it.
    Building,
    /// Running on its host and shared with its person.
    Ready,
    /// Its computer is going away: the data is being copied to another computer.
    Moving,
    /// The host could not build it; the admin can retry.
    Failed,
}

/// One ordered sandbox, pinned to a person.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Desk {
    pub id: String,
    pub name: String,
    pub spec: DeskSpec,
    #[serde(default)]
    pub access: crate::enterprise::DeskAccess,
    #[serde(default)]
    pub role_id: Option<String>,
    #[serde(default)]
    pub image_sha256: Option<String>,
    #[serde(default)]
    pub generation: u64,
    /// While moving: the computer that still holds the data and is packing it up.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub moving_from: Option<String>,
    /// The packed-up data, waiting for the computer that takes the desk next.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parcel: Option<Parcel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub person: Option<String>,
    pub state: DeskState,
    /// The member hosting it now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// The sandbox's environment ID on its host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment_id: Option<String>,
    /// The latest progress or failure, in plain words.
    #[serde(default)]
    pub note: String,
    /// Hosts that have held this desk's data, newest first: a desk goes back where its data is.
    #[serde(default)]
    pub trail: Vec<String>,
    #[serde(default)]
    pub attempts: u8,
    pub created_at: i64,
    pub updated_at: i64,
}

/// A person the admin created, who signs in with a username and password.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Person {
    pub id: String,
    pub username: String,
    #[serde(default)]
    pub admin_role: crate::enterprise::AdminRole,
    #[serde(default)]
    pub role_id: Option<String>,
    pub name: String,
    /// The password's salt; the key derived with it is kept only as a hash.
    pub salt: String,
    pub key_hash: String,
    pub created_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_login_at: Option<i64>,
    /// Their authenticator secret, once two-step sign-in is on. The hub needs it to check codes;
    /// it never leaves the hub after enrolment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<String>,
    /// A secret shown to them but not yet confirmed with a first code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp_pending: Option<String>,
    /// The email they sign in with through the company's identity provider, when SSO is on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// The identity provider's own id for the account this person signs in with (`sub`), learned
    /// on their first sign-in through it.
    ///
    /// An email is not an identity. Companies hand a leaver's address to whoever replaces them,
    /// and a provider can be asked for a token carrying any address an account claims; matching
    /// on the address alone means whoever holds that address next is this person. The `sub` is
    /// the provider's own id, is never handed to somebody else, and once it is written here only
    /// that account signs this person in. Defaulted so that people written before this loads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sso_subject: Option<String>,
}

/// What a host computer has, and how much of it is busy right now, reported with every
/// check-in. How much of it the grid may take is the admin's decision (`Share`), not the
/// computer's: a computer someone is using still hosts desks within its share.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Capacity {
    pub cpu: u32,
    #[serde(default)]
    pub desk_protocol: u8,
    /// Of the whole computer, 0–100.
    #[serde(default)]
    pub cpu_used_percent: f64,
    pub memory_gb: f64,
    /// By everything on the computer, desks included.
    #[serde(default)]
    pub used_memory_gb: f64,
    pub free_disk_gb: f64,
    #[serde(default)]
    pub gpu: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpu_used_percent: Option<f64>,
    #[serde(default)]
    pub on_battery: bool,
    /// What the battery has left, 0-100, when the computer reports one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub battery_percent: Option<u8>,
    /// This computer is about to stop hosting (shutting down, battery or disk running out): its
    /// desks move to another computer, with their data, before it goes. Plain words for why.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub going_away: Option<String>,
    /// Someone used its keyboard or mouse in the last few minutes.
    #[serde(default)]
    pub in_use: bool,
}

impl Capacity {
    /// Bounds a reported capacity to sane numbers.
    pub fn checked(self) -> Capacity {
        let clamp = |value: f64, max: f64| if value.is_finite() { value.clamp(0.0, max) } else { 0.0 };
        Capacity {
            cpu: self.cpu.min(1024),
            cpu_used_percent: clamp(self.cpu_used_percent, 100.0),
            memory_gb: clamp(self.memory_gb, 65536.0),
            used_memory_gb: clamp(self.used_memory_gb, 65536.0),
            free_disk_gb: clamp(self.free_disk_gb, 1_048_576.0),
            gpu_used_percent: self.gpu_used_percent.map(|value| clamp(value, 100.0)),
            battery_percent: self.battery_percent.filter(|percent| *percent <= 100),
            going_away: self.going_away.map(|reason| reason.chars().filter(|c| !c.is_control()).take(200).collect()),
            ..self
        }
    }
}

/// Memory a suggested share leaves to the computer's own person.
const KEPT_MEMORY_GB: f64 = 2.0;

/// What the admin lets the grid take from a computer, whether or not its person is using it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Share {
    pub cpu: f64,
    pub memory_gb: f64,
    pub disk_gb: f64,
    pub gpu: bool,
    /// Take desks only while nobody is using the computer.
    #[serde(default)]
    pub idle_only: bool,
}

impl Share {
    /// Checks the admin's numbers. Zero means the grid takes none of that resource.
    pub fn checked(cpu: f64, memory_gb: f64, disk_gb: f64, gpu: bool, idle_only: bool) -> Result<Share, String> {
        if !cpu.is_finite() || !(0.0..=1024.0).contains(&cpu) {
            return Err("--cpu is the number of cores the grid may use, 0 to 1024".into());
        }
        if !memory_gb.is_finite() || !(0.0..=65536.0).contains(&memory_gb) {
            return Err("--memory-gb is how much memory the grid may use, in GB".into());
        }
        if !disk_gb.is_finite() || !(0.0..=1_048_576.0).contains(&disk_gb) {
            return Err("--disk-gb is how much disk the grid may use, in GB".into());
        }
        Ok(Share { cpu, memory_gb, disk_gb, gpu, idle_only })
    }

    /// Until the admin decides: half the cores, half the memory with 2 GB kept back, half the
    /// free disk, and the GPU when there is one.
    pub fn suggested(capacity: &Capacity) -> Share {
        Share::suggested_holding(capacity, 0.0)
    }

    /// The suggestion for a computer whose desks already take `held_disk_gb`: the half of the disk
    /// is judged on what was free before those desks filled it, so the suggestion does not shrink
    /// as their data grows.
    pub fn suggested_holding(capacity: &Capacity, held_disk_gb: f64) -> Share {
        let half = |value: f64| (value / 2.0).floor();
        Share {
            cpu: half(f64::from(capacity.cpu)).max(if capacity.cpu > 0 { 1.0 } else { 0.0 }),
            memory_gb: half((capacity.memory_gb - KEPT_MEMORY_GB).max(0.0)),
            disk_gb: half(capacity.free_disk_gb + held_disk_gb),
            gpu: capacity.gpu,
            idle_only: false,
        }
    }

    /// The share as far as the computer can actually give it right now.
    pub fn bounded(&self, capacity: &Capacity) -> Share {
        Share {
            cpu: self.cpu.min(f64::from(capacity.cpu)),
            memory_gb: self.memory_gb.min(capacity.memory_gb),
            disk_gb: self.disk_gb.min(capacity.free_disk_gb),
            gpu: self.gpu && capacity.gpu,
            idle_only: self.idle_only,
        }
    }

    pub fn describe(&self) -> String {
        format!("{} CPU · {} GB memory · {} GB disk{}{}", trim_number(self.cpu), trim_number(self.memory_gb), trim_number(self.disk_gb), if self.gpu { " · GPU" } else { "" }, if self.idle_only { " · only while nobody is using it" } else { "" })
    }
}

/// Where a desk's packed-up data waits while it moves between computers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ParcelStore {
    /// Held by the hub itself: every computer in the grid can reach it, with no setup.
    #[default]
    Hub,
    /// In the company's own S3 bucket, for data too large to pass through the hub.
    S3,
}

/// A desk's data, packed up and waiting for the computer that takes it next.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Parcel {
    #[serde(default)]
    pub store: ParcelStore,
    /// Where it is: the desk's ID for the hub, or the object key in the bucket.
    pub key: String,
    pub bytes: u64,
    pub sha256: String,
    pub at: i64,
}

/// What a host says about one desk it was ordered to run.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeskReport {
    #[serde(default)]
    pub generation: u64,
    pub id: String,
    /// `building`, `ready`, `failed` or `gone` (the host no longer has it).
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment_id: Option<String>,
    #[serde(default)]
    pub note: String,
    /// The packed-up data, when the host finished packing it this check-in (`state: "parked"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parcel: Option<Parcel>,
    /// The share invitation for the desk's person, when the host minted one this check-in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invitation: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invitation_expires_at: Option<i64>,
}

/// What the hub tells a host to run. A desk absent from a host's orders is dropped by it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeskOrder {
    pub id: String,
    pub name: String,
    pub spec: DeskSpec,
    #[serde(default)]
    pub access: crate::enterprise::DeskAccess,
    #[serde(default)]
    pub role_id: Option<String>,
    #[serde(default)]
    pub image_sha256: Option<String>,
    #[serde(default)]
    pub generation: u64,
    #[serde(default)]
    pub person_name: String,
    #[serde(default)]
    pub person_id: Option<String>,
    /// The hub has no current invitation for this desk: mint one and report it.
    #[serde(default)]
    pub needs_invitation: bool,
    /// This computer holds the desk and is going away: stop it, pack its data up, send it, and
    /// report it parked. Until that is done the desk keeps running for its person.
    #[serde(default)]
    pub park: bool,
    /// Where to park it: with the hub, or in the company's bucket (credentials come with the
    /// instructions, only while this computer packs or unpacks).
    #[serde(default)]
    pub park_in: ParcelStore,
    /// The desk's data is packed and waiting: take it, unpack it here and run it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adopt: Option<Parcel>,
}

/// A username: 3–32 characters of letters, digits, `.`, `_` and `-`, kept lowercase.
pub fn username(text: &str) -> Result<String, String> {
    let name = text.trim().to_ascii_lowercase();
    let fits = (3..=32).contains(&name.len()) && name.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-')) && name.starts_with(|c: char| c.is_ascii_alphanumeric());
    fits.then_some(name).ok_or_else(|| "A username is 3–32 letters, digits, dots, dashes or underscores, starting with a letter or digit".into())
}

/// A desk or display name: 1–64 printable characters.
pub fn name(text: &str, what: &str) -> Result<String, String> {
    let name: String = text.trim().chars().filter(|c| !c.is_control()).collect();
    if name.is_empty() || name.chars().count() > 64 {
        return Err(format!("{what} must be 1–64 characters"));
    }
    Ok(name)
}

/// A salt for a username nobody has, stable per grid, so sign-in answers do not reveal who exists.
pub fn decoy_salt(grid_salt: &str, username: &str) -> String {
    crate::password::shaped_like_a_salt(&digest("person-salt", &format!("{grid_salt}:{username}")))
}

/// The hash a person's derived key is kept as.
pub fn key_hash(key: &str) -> String {
    digest("person", key)
}

/// Compares two hashes without an early exit on the first differing byte.
pub fn same_hash(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let mut difference = (a.len() ^ b.len()) as u8;
    for index in 0..a.len().max(b.len()) {
        difference |= a.get(index).copied().unwrap_or(0) ^ b.get(index).copied().unwrap_or(0);
    }
    difference == 0
}

pub fn new_person(username: String, name: String, salt: String, key: &str) -> Person {
    Person { admin_role: Default::default(), role_id: None, id: format!("person-{}", &token()[..12]), username, name, salt, key_hash: key_hash(key), created_at: now(), last_login_at: None, totp: None, totp_pending: None, email: None, sso_subject: None }
}

pub fn new_desk(name: String, spec: DeskSpec, person: Option<String>) -> Desk {
    let at = now();
    Desk { access: Default::default(), role_id: None, image_sha256: None, generation: 0, moving_from: None, parcel: None, id: format!("desk-{}", &token()[..12]), name, spec, person, state: DeskState::Planned, host: None, environment_id: None, note: "Waiting for a computer with room".into(), trail: Vec::new(), attempts: 0, created_at: at, updated_at: at }
}

/// A host as placement sees it: online, allowed, what it has and what the admin lets the grid take.
#[derive(Clone, Debug)]
pub struct HostView {
    pub id: String,
    pub online: bool,
    pub excluded: bool,
    /// It told the hub it is about to stop hosting: it takes no new desk and gives up its own.
    pub going_away: bool,
    pub capacity: Option<Capacity>,
    /// Unset until the admin decides: the suggested share applies.
    pub share: Option<Share>,
}

/// What the grid may take from `host` right now: its share, bounded by what it has. None while
/// it is offline, left out, has not reported yet, runs on battery, or is in use with a share
/// that waits for idle.
pub fn room(host: &HostView) -> Option<Share> {
    let capacity = host.capacity.as_ref().filter(|_| host.online && !host.excluded && !host.going_away)?;
    let share = host.share.clone().unwrap_or_else(|| Share::suggested(capacity)).bounded(capacity);
    if capacity.on_battery || capacity.free_disk_gb < crate::power::KEEP_FREE_DISK_GB || (share.idle_only && capacity.in_use) {
        return None;
    }
    Some(share)
}

/// Whether `host` can take `spec` beside the desks it already holds.
fn fits(host: &HostView, held: &[&DeskSpec], spec: &DeskSpec) -> bool {
    let Some(room) = room(host) else { return false };
    if spec.gpu && !room.gpu {
        return false;
    }
    let used_cpu: f64 = held.iter().map(|desk| desk.cpu).sum();
    let used_memory: f64 = held.iter().map(|desk| desk.memory_gb).sum();
    let used_disk: f64 = held.iter().map(|desk| desk.disk_gb).sum();
    // Disk is judged twice, not double-counted: the new desk must fit in what is free now (the
    // held desks' data is already out of that), and all desks together must stay within the share.
    let capacity = host.capacity.as_ref().expect("room() checked the capacity");
    let promised = host.share.clone().unwrap_or_else(|| Share::suggested_holding(capacity, used_disk)).disk_gb;
    used_cpu + spec.cpu <= room.cpu && used_memory + spec.memory_gb <= room.memory_gb && spec.disk_gb <= room.disk_gb && used_disk + spec.disk_gb <= promised
}

/// Picks a host for `desk`: one that already holds its data if it still fits, otherwise the
/// fitting host with the most memory left in its share; ties go to the lower ID so placement
/// is stable.
pub fn choose_host(desk: &Desk, hosts: &[HostView], desks: &[Desk]) -> Option<String> {
    // Not the computer it is leaving, and not the one it already sits on.
    let hosts: Vec<_> = hosts
        .iter()
        .filter(|host| desk.role_id.is_none() || host.capacity.as_ref().is_some_and(|c| c.desk_protocol >= 2))
        .filter(|host| Some(&host.id) != desk.moving_from.as_ref() && Some(&host.id) != desk.host.as_ref())
        .cloned()
        .collect();
    let held = |host: &str| desks.iter().filter(|other| other.id != desk.id && other.host.as_deref() == Some(host)).map(|other| &other.spec).collect::<Vec<_>>();
    for previous in &desk.trail {
        if let Some(host) = hosts.iter().find(|host| &host.id == previous) {
            if fits(host, &held(&host.id), &desk.spec) {
                return Some(host.id.clone());
            }
        }
    }
    let mut candidates: Vec<(&HostView, f64)> = hosts
        .iter()
        .filter(|host| fits(host, &held(&host.id), &desk.spec))
        .map(|host| {
            let left = room(host).map_or(0.0, |room| room.memory_gb) - held(&host.id).iter().map(|spec| spec.memory_gb).sum::<f64>();
            (host, left)
        })
        .collect();
    candidates.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal).then_with(|| a.0.id.cmp(&b.0.id)));
    candidates.first().map(|(host, _)| host.id.clone())
}

/// The largest desk the hub will carry between computers, in GB; it holds the data in between.
pub const MAX_PARCEL_GB: f64 = 64.0;

/// How long a desk waits for a computer before a cloud one is created for it, when allowed.
pub const CLOUD_AFTER: i64 = 5 * 60;

/// Why a cloud computer is needed right now: a desk has waited for room longer than
/// `CLOUD_AFTER` and no computer in the grid can take it. None when nothing is waiting.
pub fn needs_computer(desks: &[Desk], hosts: &[HostView], at: i64) -> Option<String> {
    let waiting = desks.iter().find(|desk| {
        let stuck = (desk.state == DeskState::Planned) || (desk.state == DeskState::Moving && desk.parcel.is_some() && desk.host.is_none());
        stuck && at - desk.updated_at >= CLOUD_AFTER && choose_host(desk, hosts, desks).is_none()
    })?;
    Some(format!("{} has waited for a computer with room since {}", waiting.name, waiting.updated_at))
}

/// How long a packed-up desk waits for a computer before the admin is told it is stuck.
pub const PARCEL_PATIENCE: i64 = 24 * 60 * 60;

/// Desks on computers that are going away: each is handed to another computer, which first takes
/// its data. Until the copy is done the desk keeps running where it is. Returns whether anything
/// changed.
pub fn hand_off(desks: &mut [Desk], hosts: &[HostView]) -> bool {
    // A computer is giving its desks up when it says so, or when its person came back and the
    // admin only lent the grid its idle time.
    let gives_up = |host: &HostView| {
        if host.going_away {
            return true;
        }
        let Some(capacity) = host.capacity.as_ref() else { return false };
        capacity.in_use && host.share.clone().unwrap_or_else(|| Share::suggested(capacity)).idle_only
    };
    let leaving: Vec<&str> = hosts.iter().filter(|host| gives_up(host)).map(|host| host.id.as_str()).collect();
    if leaving.is_empty() {
        return false;
    }
    let mut changed = false;
    for desk in desks.iter_mut() {
        let Some(host) = desk.host.clone() else { continue };
        if !leaving.contains(&host.as_str()) || !matches!(desk.state, DeskState::Building | DeskState::Ready) {
            continue;
        }
        // The hub holds the data while it moves, so a desk larger than it can hold stays put
        // and says so rather than starting a copy that cannot finish.
        if desk.spec.disk_gb > MAX_PARCEL_GB {
            let note = format!("Too large to move: its disk is {} GB and a move passes through the hub, which holds {MAX_PARCEL_GB} GB", trim_number(desk.spec.disk_gb));
            if desk.note != note {
                desk.note = note;
                desk.updated_at = now();
                changed = true;
            }
            continue;
        }
        desk.state = DeskState::Moving;
        desk.moving_from = Some(host);
        desk.host = None;
        desk.note = "Its computer is giving it up; moving the desk with its data".into();
        desk.updated_at = now();
        changed = true;
    }
    changed
}

/// A desk whose data is packed and waiting goes to any computer with room; with none, it waits,
/// safe, until the admin adds one (a cloud computer counts). Returns whether anything changed.
pub fn place_parcels(desks: &mut [Desk], hosts: &[HostView]) -> bool {
    let mut changed = false;
    for index in 0..desks.len() {
        let desk = &desks[index];
        if desk.state != DeskState::Moving || desk.parcel.is_none() || desk.host.is_some() {
            continue;
        }
        let chosen = choose_host(&desks[index], hosts, desks);
        let desk = &mut desks[index];
        match chosen {
            Some(host) => {
                desk.host = Some(host);
                desk.note = "Its new computer is taking its data".into();
                desk.attempts = 0;
                desk.updated_at = now();
                changed = true;
            }
            None => {
                let stuck = desk.parcel.as_ref().is_some_and(|parcel| now() - parcel.at > PARCEL_PATIENCE);
                let note = if stuck { "Its data is safe, but no computer has had room for a day; add one (a cloud computer counts)" } else { "Its data is packed and waiting for a computer with room" };
                if desk.note != note {
                    desk.note = note.into();
                    desk.updated_at = now();
                    changed = true;
                }
            }
        }
    }
    changed
}

/// Places every desk that is waiting on a host with room. Returns whether anything changed.
pub fn place(desks: &mut [Desk], hosts: &[HostView]) -> bool {
    let mut changed = false;
    for index in 0..desks.len() {
        if desks[index].state != DeskState::Planned {
            continue;
        }
        let Some(host) = choose_host(&desks[index], hosts, desks) else { continue };
        let desk = &mut desks[index];
        let carried = desk.parcel.is_some();
        desk.state = if carried { DeskState::Moving } else { DeskState::Building };
        desk.note = if carried { "Its new computer is taking its data".to_owned() } else { "Building on its computer".to_owned() };
        desk.trail.retain(|previous| previous != &host);
        desk.trail.insert(0, host.clone());
        desk.trail.truncate(8);
        desk.host = Some(host);
        desk.attempts += 1;
        desk.updated_at = now();
        changed = true;
    }
    changed
}

/// Applies what a host reported about a desk it hosts. Returns whether the record changed.
pub fn apply_report(desk: &mut Desk, host: &str, report: &DeskReport) -> bool {
    let note: String = report.note.chars().filter(|c| !c.is_control()).take(300).collect();
    // The computer giving a desk up reports only on the move; everything else comes from the
    // computer that holds it now.
    if desk.moving_from.as_deref() == Some(host) && desk.host.as_deref() != Some(host) {
        return match report.state.as_str() {
            "parked" => {
                let Some(parcel) = report.parcel.clone().filter(|parcel| !parcel.key.is_empty() && parcel.bytes > 0) else { return false };
                desk.parcel = Some(parcel);
                desk.moving_from = None;
                desk.note = "Its data is packed and waiting for a computer with room".into();
                desk.updated_at = now();
                true
            }
            "failed" => {
                // The data could not be packed: the desk stays where it is and the admin is told.
                desk.state = DeskState::Failed;
                desk.host = desk.moving_from.take();
                desk.note = if note.is_empty() { "The desk could not be moved off its computer".to_owned() } else { note };
                desk.updated_at = now();
                true
            }
            _ => false,
        };
    }
    if desk.host.as_deref() != Some(host) {
        return false;
    }
    let (state, note) = match report.state.as_str() {
        "building" => (DeskState::Building, if note.is_empty() { "Building on its computer".to_owned() } else { note }),
        "ready" => (DeskState::Ready, if note.is_empty() { "Ready".to_owned() } else { note }),
        // Its new computer unpacked the data: the parcel is no longer needed anywhere.
        "adopted" => {
            desk.parcel = None;
            (DeskState::Building, if note.is_empty() { "Starting on its new computer".to_owned() } else { note })
        }
        "moving" => (DeskState::Moving, if note.is_empty() { "Taking the desk's data".to_owned() } else { note }),
        "failed" => (DeskState::Failed, if note.is_empty() { "The computer could not build it".to_owned() } else { note }),
        "gone" => {
            // The host lost it (deleted by its person, or a fresh install): build it again elsewhere,
            // or here, up to the limit.
            let retry = desk.attempts < MAX_ATTEMPTS;
            (if retry { DeskState::Planned } else { DeskState::Failed }, if retry { "Its computer no longer has it; finding a computer again".to_owned() } else { "Its computer lost it repeatedly".to_owned() })
        }
        _ => return false,
    };
    let environment = report.environment_id.as_deref().filter(|id| id.starts_with("env-") && id.len() <= 64).map(str::to_owned);
    let changed = desk.state != state || desk.note != note || (environment.is_some() && desk.environment_id != environment);
    if changed {
        desk.state = state;
        desk.note = note;
        if environment.is_some() {
            desk.environment_id = environment;
        }
        if state == DeskState::Planned {
            desk.host = None;
            desk.environment_id = None;
        }
        desk.updated_at = now();
    }
    changed
}

/// The desks a host should be running, and which need an invitation minted.
pub fn orders_for(desks: &[Desk], people: &[Person], host: &str, has_invitation: impl Fn(&str) -> bool) -> Vec<DeskOrder> {
    desks
        .iter()
        .filter(|desk| {
            // The computer that holds it runs it; the one giving it up packs its data; the one
            // taking it over unpacks it.
            // A desk that failed while it still holds a parcel is never sent as something to
            // build. Its data is in that parcel, and a build order makes a fresh empty sandbox
            // over it — the person gets a desk that is not theirs, and the next park of it
            // writes over the parcel, at which point the original is gone. The computer keeps
            // its own note of a failed adopt, but that note is in memory and is cleared by any
            // new generation, and an admin resetting somebody's password bumps the generation.
            // So the rule lives here, where it holds whatever the computer forgets.
            (desk.host.as_deref() == Some(host) && matches!(desk.state, DeskState::Building | DeskState::Ready) )
                || (desk.host.as_deref() == Some(host) && desk.state == DeskState::Failed && desk.parcel.is_none())
                || desk.moving_from.as_deref() == Some(host)
                || (desk.host.as_deref() == Some(host) && desk.state == DeskState::Moving && desk.parcel.is_some())
        })
        .map(|desk| DeskOrder {
            park: desk.moving_from.as_deref() == Some(host),
            park_in: ParcelStore::Hub,
            adopt: (desk.host.as_deref() == Some(host) && desk.state == DeskState::Moving).then(|| desk.parcel.clone()).flatten(),
            id: desk.id.clone(),
            name: desk.name.clone(),
            spec: desk.spec.clone(),
            access: desk.access,
            role_id: desk.role_id.clone(),
            image_sha256: desk.image_sha256.clone(),
            generation: desk.generation,
            person_id: desk.person.clone(),
            person_name: desk.person.as_ref().and_then(|id| people.iter().find(|person| &person.id == id)).map(|person| person.name.clone()).unwrap_or_default(),
            needs_invitation: desk.state == DeskState::Ready && !has_invitation(&desk.id),
        })
        .collect()
}

/// A desk as the admin and its person see it: no invitation, plus whether its host is online.
pub fn desk_json(desk: &Desk, people: &[Person], host_name: Option<&str>, host_online: bool, has_invitation: bool) -> Value {
    let person = desk.person.as_ref().and_then(|id| people.iter().find(|person| &person.id == id));
    json!({
        "id": desk.id, "name": desk.name, "spec": desk.spec, "access": desk.access, "roleId": desk.role_id, "generation": desk.generation, "summary": desk.spec.describe(),
        "personId": desk.person, "person": person.map(|person| person.name.clone()), "username": person.map(|person| person.username.clone()),
        "state": desk.state, "note": desk.note, "hostId": desk.host, "host": host_name, "hostOnline": host_online,
        "movingFrom": desk.moving_from, "parcelBytes": desk.parcel.as_ref().map(|parcel| parcel.bytes),
        "reachable": desk.state == DeskState::Ready && host_online && has_invitation,
        "environmentId": desk.environment_id, "attempts": desk.attempts, "createdAt": desk.created_at, "updatedAt": desk.updated_at,
    })
}

pub fn person_json(person: &Person, desks: &[Desk]) -> Value {
    json!({
        "id": person.id, "username": person.username, "adminRole": person.admin_role, "roleId": person.role_id, "name": person.name, "createdAt": person.created_at, "lastLoginAt": person.last_login_at,
        "mfa": person.totp.is_some(), "email": person.email,
        "desks": desks.iter().filter(|desk| desk.person.as_ref() == Some(&person.id)).map(|desk| desk.id.clone()).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(cpu: f64, memory: f64, gpu: bool) -> DeskSpec {
        DeskSpec::checked(DeskKind::Container, cpu, memory, 10.0, gpu, "").unwrap()
    }
    fn capacity() -> Capacity {
        Capacity { desk_protocol: 2, battery_percent: None, going_away: None, cpu: 8, cpu_used_percent: 35.0, memory_gb: 32.0, used_memory_gb: 10.0, free_disk_gb: 200.0, gpu: false, gpu_used_percent: None, on_battery: false, in_use: true }
    }
    /// A computer in use, whose admin lets the grid take 4 cores, `memory` GB and 100 GB of disk.
    fn host(id: &str, memory: f64) -> HostView {
        HostView { id: id.into(), online: true, excluded: false, going_away: false, capacity: Some(capacity()), share: Some(Share { cpu: 4.0, memory_gb: memory, disk_gb: 100.0, gpu: false, idle_only: false }) }
    }

    #[test]
    fn a_share_is_suggested_until_the_admin_decides_and_never_exceeds_the_computer() {
        let suggested = Share::suggested(&capacity());
        assert_eq!((suggested.cpu, suggested.memory_gb, suggested.disk_gb, suggested.gpu, suggested.idle_only), (4.0, 15.0, 100.0, false, false));
        let tiny = Share::suggested(&Capacity { desk_protocol: 2, cpu: 1, memory_gb: 1.5, free_disk_gb: 3.0, gpu: true, ..Capacity::default() });
        assert_eq!((tiny.cpu, tiny.memory_gb, tiny.disk_gb, tiny.gpu), (1.0, 0.0, 1.0, true), "a core at least; memory below what is kept back gives none");
        let generous = Share::checked(64.0, 512.0, 1000.0, true, true).unwrap();
        let bounded = generous.bounded(&capacity());
        assert_eq!((bounded.cpu, bounded.memory_gb, bounded.disk_gb, bounded.gpu, bounded.idle_only), (8.0, 32.0, 200.0, false, true));
        assert_eq!(generous.describe(), "64 CPU · 512 GB memory · 1000 GB disk · GPU · only while nobody is using it");
        assert!(Share::checked(-1.0, 4.0, 10.0, false, false).is_err() && Share::checked(2.0, f64::NAN, 10.0, false, false).is_err());
        assert_eq!(room(&HostView { share: None, ..host("m-1", 8.0) }).unwrap().memory_gb, 15.0, "no share set: the suggestion applies");
    }

    #[test]
    fn specs_and_names_are_checked() {
        assert_eq!(spec(2.0, 4.0, false).image, "docker.io/library/ubuntu:24.04");
        assert!(DeskSpec::checked(DeskKind::Vm, 2.0, 4.0, 20.0, false, "").is_err());
        assert!(DeskSpec::checked(DeskKind::Vm, 2.0, 4.0, 20.0, false, "C:/Prepared Images/research.qcow2").is_ok());
        assert!(DeskSpec::checked(DeskKind::Container, 2.0, 4.0, 1.5, false, "").is_err());
        assert!(DeskSpec::checked(DeskKind::Container, 0.0, 4.0, 10.0, false, "").is_err());
        assert!(DeskSpec::checked(DeskKind::Container, 2.0, 4.0, 10.0, false, "bad image").is_err());
        assert_eq!(spec(2.0, 4.0, true).describe(), "Container · 2 CPU · 4 GB memory · 10 GB disk · GPU");
        assert_eq!(DeskKind::parse("Micro-VM").unwrap(), DeskKind::MicroVm);
        assert!(DeskKind::parse("laptop").is_err());
        assert_eq!(username("  Ada.Lovelace ").unwrap(), "ada.lovelace");
        assert!(username("ab").is_err() && username("-ada").is_err() && username("ada lovelace").is_err());
        assert!(name("", "The desk name").is_err());
    }

    #[test]
    fn placement_prefers_the_host_with_the_data_then_the_roomiest_share_and_respects_limits() {
        let mut desks = vec![new_desk("Design".into(), spec(2.0, 8.0, false), None), new_desk("Render".into(), spec(2.0, 8.0, true), None)];
        let mut idle_only = host("m-idle-only", 24.0);
        idle_only.share.as_mut().unwrap().idle_only = true;
        let hosts = vec![host("m-small", 12.0), host("m-big", 24.0), idle_only];
        assert!(place(&mut desks, &hosts));
        assert_eq!((desks[0].state, desks[0].host.as_deref()), (DeskState::Building, Some("m-big")), "the host with the most memory left in its share wins; being in use does not matter");
        assert_eq!(desks[1].state, DeskState::Planned, "nothing has a GPU yet");
        // The same host is not overfilled: a second 8 GB desk still fits m-big (24 - 8), a third goes to m-small.
        desks.push(new_desk("Ops".into(), spec(2.0, 8.0, false), None));
        desks.push(new_desk("QA".into(), spec(2.0, 8.0, false), None));
        place(&mut desks, &hosts);
        assert_eq!(desks[2].host.as_deref(), Some("m-big"));
        assert_eq!(desks[3].host.as_deref(), Some("m-small"));
        // A desk that lost its host goes back to a host that held its data when that one has room.
        let mut moved = desks[0].clone();
        moved.state = DeskState::Planned;
        moved.host = None;
        let mut one = vec![moved];
        place(&mut one, &[host("m-small", 24.0), host("m-big", 9.0)]);
        assert_eq!(one[0].host.as_deref(), Some("m-big"), "its data is there and it still fits");
        place(&mut one, &[host("m-big", 1.0)]);
        assert_eq!(one[0].host.as_deref(), Some("m-big"), "already placed; placement is not repeated");
    }

    #[test]
    fn hosts_on_battery_offline_left_out_unreported_or_waiting_for_idle_take_nothing() {
        let mut desks = vec![new_desk("Design".into(), spec(1.0, 2.0, false), None)];
        let mut battery = host("m-1", 16.0);
        battery.capacity.as_mut().unwrap().on_battery = true;
        let mut offline = host("m-2", 16.0);
        offline.online = false;
        let mut excluded = host("m-3", 16.0);
        excluded.excluded = true;
        let mut idle_only = host("m-5", 16.0);
        idle_only.share.as_mut().unwrap().idle_only = true;
        let mut none_of_it = host("m-6", 0.0);
        none_of_it.share.as_mut().unwrap().cpu = 0.0;
        let hosts = vec![battery, offline, excluded, HostView { id: "m-4".into(), online: true, excluded: false, going_away: false, capacity: None, share: None }, idle_only, none_of_it];
        assert!(!place(&mut desks, &hosts));
        assert_eq!(desks[0].state, DeskState::Planned);
        // The computer that waits for idle takes the desk once nobody is using it.
        let mut idle = host("m-5", 16.0);
        idle.share.as_mut().unwrap().idle_only = true;
        idle.capacity.as_mut().unwrap().in_use = false;
        assert!(place(&mut desks, &[idle]));
        assert_eq!(desks[0].host.as_deref(), Some("m-5"));
    }

    #[test]
    fn reports_move_a_desk_along_and_a_lost_desk_is_placed_again() {
        let mut desk = new_desk("Design".into(), spec(1.0, 2.0, false), None);
        let id = desk.id.clone();
        let report = |state: &str, environment: Option<&str>| DeskReport { id: id.clone(), state: state.into(), environment_id: environment.map(str::to_owned), ..DeskReport::default() };
        place(std::slice::from_mut(&mut desk), &[host("m-1", 16.0)]);
        assert!(!apply_report(&mut desk, "m-other", &report("ready", None)), "only its host may report");
        assert!(apply_report(&mut desk, "m-1", &report("ready", Some("env-1"))));
        assert_eq!((desk.state, desk.environment_id.as_deref(), desk.note.as_str()), (DeskState::Ready, Some("env-1"), "Ready"));
        assert!(apply_report(&mut desk, "m-1", &report("gone", None)));
        assert_eq!((desk.state, desk.host.as_deref(), desk.environment_id.as_deref()), (DeskState::Planned, None, None));
        assert_eq!(desk.trail, vec!["m-1".to_owned()], "where its data was is remembered");
        desk.attempts = MAX_ATTEMPTS;
        desk.state = DeskState::Ready;
        desk.host = Some("m-1".into());
        apply_report(&mut desk, "m-1", &report("gone", None));
        assert_eq!(desk.state, DeskState::Failed, "a desk lost again and again stops being retried");
    }

    #[test]
    fn orders_list_a_hosts_desks_and_ask_for_missing_invitations() {
        let person = new_person("ada".into(), "Ada Lovelace".into(), "salt".into(), "key");
        let mut desks = vec![new_desk("Design".into(), spec(1.0, 2.0, false), Some(person.id.clone())), new_desk("Ops".into(), spec(1.0, 2.0, false), None)];
        place(&mut desks, &[host("m-1", 16.0)]);
        let ready = DeskReport { id: desks[0].id.clone(), state: "ready".into(), ..DeskReport::default() };
        apply_report(&mut desks[0], "m-1", &ready);
        let orders = orders_for(&desks, std::slice::from_ref(&person), "m-1", |id| id == desks[1].id);
        assert_eq!(orders.len(), 2);
        assert_eq!((orders[0].person_name.as_str(), orders[0].needs_invitation), ("Ada Lovelace", true), "ready without an invitation asks for one");
        assert_eq!((orders[1].person_name.as_str(), orders[1].needs_invitation), ("", false), "still building: no invitation yet");
        assert!(orders_for(&desks, &[], "m-2", |_| false).is_empty());
        let shown = desk_json(&desks[0], std::slice::from_ref(&person), Some("Laptop"), true, true);
        assert_eq!((shown["person"].as_str(), shown["username"].as_str(), shown["reachable"].as_bool()), (Some("Ada Lovelace"), Some("ada"), Some(true)));
        assert!(shown.get("invitation").is_none());
        assert_eq!(person_json(&person, &desks)["desks"], json!([desks[0].id]));
    }

    /// PROVES that a desk whose move failed is never handed back as something to build while its
    /// data is still in a parcel.
    ///
    /// When an adopt fails the hub marks the desk Failed and keeps the adopting computer as its
    /// host, and only a Moving desk carries an adopt — so the plain order that followed made the
    /// computer build a fresh empty sandbox over data that was still sitting in the parcel. The
    /// person got a desk that was not theirs, and the next park of it wrote over the parcel, at
    /// which point the original was gone.
    ///
    /// The computer keeps its own note of a failed adopt, and that note cannot be relied on: it
    /// lives in memory, and it is cleared by any new generation — which an admin bumps by
    /// resetting somebody's password, changing their details, or removing them. So the rule has
    /// to hold here, where it survives everything the computer forgets.
    #[test]
    fn a_desk_that_failed_while_holding_a_parcel_is_never_sent_to_be_built() {
        let person = new_person("ada".into(), "Ada Lovelace".into(), "salt".into(), "key");
        let mut desks = vec![new_desk("Design".into(), spec(1.0, 2.0, false), Some(person.id.clone()))];
        place(&mut desks, &[host("m-1", 16.0)]);
        desks[0].state = DeskState::Failed;
        desks[0].parcel = Some(Parcel { store: ParcelStore::Hub, key: desks[0].id.clone(), bytes: 1, sha256: "a".repeat(64), at: 0 });

        assert!(orders_for(&desks, std::slice::from_ref(&person), "m-1", |_| false).is_empty(), "the hub asked this computer to build a desk whose data is still in a parcel");

        // A generation bumped by anything at all — a password reset, not only a retry — must not
        // change that answer, because the computer's own note is cleared by exactly that.
        desks[0].generation += 1;
        assert!(orders_for(&desks, std::slice::from_ref(&person), "m-1", |_| false).is_empty());

        // Once the parcel is gone there is nothing left to lose, so it is built again.
        desks[0].parcel = None;
        assert_eq!(orders_for(&desks, std::slice::from_ref(&person), "m-1", |_| false).len(), 1);

        // And a desk still being moved is an adopt, which is how its data gets there at all.
        desks[0].state = DeskState::Moving;
        desks[0].parcel = Some(Parcel { store: ParcelStore::Hub, key: desks[0].id.clone(), bytes: 1, sha256: "a".repeat(64), at: 0 });
        let orders = orders_for(&desks, std::slice::from_ref(&person), "m-1", |_| false);
        assert!(orders.len() == 1 && orders[0].adopt.is_some(), "a moving desk must still be offered to its adopter");
    }

    #[test]
    fn sign_in_secrets_are_hashed_and_compared_in_constant_time_and_unknown_names_get_a_decoy_salt() {
        let person = new_person("ada".into(), "Ada".into(), crate::password::new_salt(), "derived-key");
        assert!(same_hash(&person.key_hash, &key_hash("derived-key")));
        assert!(!same_hash(&person.key_hash, &key_hash("derived-kex")));
        assert!(!same_hash("abc", "abcd"));
        assert_eq!(decoy_salt("grid-salt", "nobody"), decoy_salt("grid-salt", "nobody"));
        assert_ne!(decoy_salt("grid-salt", "nobody"), decoy_salt("grid-salt", "somebody"));
        assert_eq!(decoy_salt("grid-salt", "nobody").len(), crate::password::new_salt().len(), "indistinguishable from a real salt");
        // A real salt is a UUID v4 in hex, and a decoy has the same shape: version 4 at index 12,
        // and 8, 9, a or b at index 16. Otherwise the shape alone says who exists.
        for name in 0..256 {
            let decoy = decoy_salt("grid-salt", &format!("nobody{name}"));
            assert!(decoy.as_bytes()[12] == b'4' && b"89ab".contains(&decoy.as_bytes()[16]), "{decoy}");
        }
        let capacity = Capacity { desk_protocol: 2, cpu: 9999, cpu_used_percent: 250.0, memory_gb: f64::NAN, used_memory_gb: -1.0, free_disk_gb: 1e12, gpu_used_percent: Some(-5.0), ..Capacity::default() }.checked();
        assert_eq!((capacity.cpu, capacity.cpu_used_percent, capacity.memory_gb, capacity.used_memory_gb, capacity.free_disk_gb, capacity.gpu_used_percent), (1024, 100.0, 0.0, 0.0, 1_048_576.0, Some(0.0)));
    }
}
