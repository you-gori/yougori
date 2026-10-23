//! What computers offer, what is reserved on them, and the life of a piece of work.
//!
//! Every profile uses these: a model being served, a workspace being hosted, a credential request
//! being brokered and an authorised research run are all workloads with one lifecycle, running
//! under a lease on a host that offered the resources.
use serde::{Deserialize, Serialize};

/// What a computer has, or what a piece of work needs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Resources {
    pub cpu: f64,
    pub memory_gb: f64,
    pub disk_gb: f64,
    pub gpu: bool,
    #[serde(default)]
    pub vram_gb: f64,
}

impl Resources {
    /// Whether `self` covers `wanted` in full.
    pub fn covers(&self, wanted: &Resources) -> bool {
        self.cpu + f64::EPSILON >= wanted.cpu
            && self.memory_gb + f64::EPSILON >= wanted.memory_gb
            && self.disk_gb + f64::EPSILON >= wanted.disk_gb
            && (!wanted.gpu || self.gpu)
            && self.vram_gb + f64::EPSILON >= wanted.vram_gb
    }

    /// What is left after `taken`, never below zero.
    pub fn less(&self, taken: &Resources) -> Resources {
        Resources {
            cpu: (self.cpu - taken.cpu).max(0.0),
            memory_gb: (self.memory_gb - taken.memory_gb).max(0.0),
            disk_gb: (self.disk_gb - taken.disk_gb).max(0.0),
            gpu: self.gpu,
            vram_gb: (self.vram_gb - taken.vram_gb).max(0.0),
        }
    }
}

/// How a GPU is shared, which the scheduler must know before it places work on one. A card that
/// is merely visible is not therefore safely shareable.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum GpuIsolation {
    /// One workload at a time, the whole card.
    Exclusive,
    /// Hardware-partitioned into separate instances.
    Partitioned,
    /// A hypervisor hands out virtual GPUs.
    Virtual,
    /// Shared by time slicing, with no hardware boundary between tenants.
    TimeSliced,
    /// Passed straight through to one virtual machine.
    Passthrough,
    /// Present, with no established isolation; treated as unshareable.
    #[default]
    Unknown,
}

impl GpuIsolation {
    /// Whether two pieces of work from different people may share this card.
    pub fn shareable(self) -> bool {
        matches!(self, GpuIsolation::Partitioned | GpuIsolation::Virtual)
    }
}

/// A computer offering part of itself to its realm.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Host {
    pub id: String,
    pub realm_id: String,
    pub device_id: String,
    pub name: String,
    /// What the computer has in total.
    pub capacity: Resources,
    /// What its owner lets the realm use, never more than it has.
    pub offered: Resources,
    #[serde(default)]
    pub gpu_isolation: GpuIsolation,
    /// How the computer was committed: a bounded share, the whole computer, or nothing.
    pub commitment: Commitment,
    /// Set while the host is being emptied; it takes no new work.
    #[serde(default)]
    pub draining: bool,
    pub joined_at: i64,
}

/// How much of a computer its owner gave to the realm. Dedicating a computer never means handing
/// over the person's files: what the realm may read is still its own decision, made elsewhere.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Commitment {
    /// The default: a capped share, with the person's own use protected.
    #[default]
    Share,
    /// The computer is managed by the realm, and local interactive use is limited by policy.
    Dedicated,
    /// Nothing runs here; the computer is only a client.
    None,
}

impl Host {
    pub fn new(realm_id: &str, device_id: &str, name: &str, capacity: Resources, offered: Resources, commitment: Commitment, now: i64) -> Result<Host, String> {
        if !capacity.covers(&offered) {
            return Err("A computer cannot offer more than it has".into());
        }
        Ok(Host {
            id: format!("host-{}", &crate::token()[..16]),
            realm_id: realm_id.to_owned(),
            device_id: device_id.to_owned(),
            name: crate::label(name, "computer name")?,
            capacity,
            offered,
            gpu_isolation: GpuIsolation::default(),
            commitment,
            draining: false,
            joined_at: now,
        })
    }

    /// Whether this computer takes new work at all.
    pub fn takes_work(&self) -> bool {
        !self.draining && self.commitment != Commitment::None
    }
}

/// A reservation on a host, held by one piece of work until it expires or is given back.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Lease {
    pub id: String,
    pub realm_id: String,
    pub host_id: String,
    pub workload_id: String,
    pub resources: Resources,
    /// Raised every time the lease is renewed, so a stale holder cannot act on an old one.
    pub generation: u64,
    pub granted_at: i64,
    pub expires_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub released_at: Option<i64>,
}

impl Lease {
    /// Whether this lease still authorises work at `now`.
    pub fn holds(&self, now: i64) -> bool {
        self.released_at.is_none() && now < self.expires_at
    }
}

/// Where a piece of work has got to. The same states for every profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Stage {
    Draft,
    Validating,
    Queued,
    Leased,
    Preparing,
    Running,
    Draining,
    Completed,
    Rejected,
    Cancelled,
    Expired,
    Failed,
    Quarantined,
}

impl Stage {
    /// Whether nothing more will happen to work in this state.
    pub fn finished(self) -> bool {
        matches!(self, Stage::Completed | Stage::Rejected | Stage::Cancelled | Stage::Expired | Stage::Failed | Stage::Quarantined)
    }

    /// Whether work in this state may move to `next`. Everything else is refused, so a workload
    /// cannot be revived after it has finished, or run without a lease.
    pub fn may_become(self, next: Stage) -> bool {
        use Stage::*;
        match (self, next) {
            (Draft, Validating | Rejected | Cancelled) => true,
            (Validating, Queued | Rejected | Cancelled | Failed) => true,
            (Queued, Leased | Cancelled | Expired | Failed) => true,
            // A computer that was given the work but had not begun the answer can give it back,
            // and the work waits for another computer. `Running` is deliberately not here: part
            // of the answer may already be with the caller, and nobody is ever sent two answers.
            (Leased, Preparing | Queued | Cancelled | Expired | Failed) => true,
            (Preparing, Running | Queued | Cancelled | Expired | Failed | Quarantined) => true,
            (Running, Draining | Completed | Cancelled | Failed | Quarantined) => true,
            (Draining, Completed | Failed | Quarantined) => true,
            _ => false,
        }
    }
}

/// How many computers one piece of work may be offered to before it is given up on. The legacy
/// hub allows the same three attempts, so moving a grid onto the core does not quietly change
/// what a request is allowed to cost.
pub const TRIES: u64 = 3;

/// How long a request waits for its answer when the caller names no deadline of its own. This is
/// the legacy hub's generation window, so a request admitted here costs what it costs there.
pub const ANSWER_WITHIN: i64 = 30 * 60;

/// The longest deadline a caller may name. Nothing in a realm waits for ever.
pub const LONGEST_WAIT: i64 = 24 * 60 * 60;

/// Why one computer's attempt at a piece of work ended without an answer.
///
/// This is an enum and not a sentence from the caller because a member computer reporting a
/// failure over the network must not be able to choose the words that go into a history sealed
/// with the realm's key, whether those words are its own or a piece of someone's request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Setback {
    /// The computer stopped answering: a dead connection, or nothing for long enough.
    WentQuiet,
    /// The computer had the work but could not take it on just then.
    Busy,
    /// The model was not ready on that computer.
    ModelNotReady,
    /// Something came back, and it was not an answer.
    Unusable,
    /// The computer was taken out of the grid while it held the work.
    LeftTheGrid,
}

impl Setback {
    /// What the record says happened, in words fixed here.
    pub fn say(self) -> &'static str {
        match self {
            Setback::WentQuiet => "the computer stopped answering",
            Setback::Busy => "the computer was busy",
            Setback::ModelNotReady => "the model was not ready on that computer",
            Setback::Unusable => "the computer sent nothing that could be used",
            Setback::LeftTheGrid => "the computer was taken out of the grid",
        }
    }
}

/// What kind of work this is. The profile that owns it keeps its own detail elsewhere.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Kind {
    Inference,
    Workspace,
    CredentialRequest,
    Research,
    ConnectorTask,
    ArtifactTransfer,
}

/// One piece of work in one realm.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Workload {
    pub id: String,
    pub realm_id: String,
    pub capability: super::realm::Capability,
    pub kind: Kind,
    pub principal_id: String,
    pub device_id: String,
    pub stage: Stage,
    pub needs: Resources,
    /// The policy in force when it was admitted; a later change does not silently re-scope it.
    pub policy_version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
}

impl Workload {
    pub fn new(realm_id: &str, capability: super::realm::Capability, kind: Kind, principal_id: &str, device_id: &str, needs: Resources, policy_version: u64, now: i64) -> Workload {
        Workload {
            id: format!("work-{}", &crate::token()[..16]),
            realm_id: realm_id.to_owned(),
            capability,
            kind,
            principal_id: principal_id.to_owned(),
            device_id: device_id.to_owned(),
            stage: Stage::Draft,
            needs,
            policy_version,
            lease_id: None,
            note: None,
            created_at: now,
            updated_at: now,
            expires_at: None,
        }
    }

    /// Moves the work on, if that step is allowed from where it is.
    pub fn advance(&mut self, next: Stage, now: i64) -> Result<(), String> {
        if !self.stage.may_become(next) {
            return Err(format!("Work that is {:?} cannot become {:?}", self.stage, next));
        }
        self.stage = next;
        self.updated_at = now;
        Ok(())
    }
}
