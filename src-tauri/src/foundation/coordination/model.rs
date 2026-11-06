//! Model activation (S2 CORE-04; S3.1; INT-03; GPU part §3.6), owned by MODELS.
//!
//! One state machine per model under one parent execution. It owns the model activation
//! generation and the GPU allocation generation and hands each value out once; the
//! sandbox lifecycle cannot advance them, and nothing here can advance a sandbox
//! generation.
//!
//! Memory is held in holdings, each reserved as a child of the sandbox reservation: one
//! GPU allocation per device, with its own allocation generation, and the host memory an
//! activation reserved. An activation allocates holdings or acquires existing ones under
//! their own generations (§3.6 step 2), so memory several activations share counts once.
//! A holding is released when no unretired activation uses it, unless it is retained for
//! a reactivation. A new activation takes over new requests while the one it replaces
//! finishes the requests it admitted (INT-03); when capacity allows only one resident
//! generation, the old one drains first and hands its memory over (§3.6 line 597). A
//! retired activation, and any GPU pointer it handed out, is never served again (INT-04).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use super::capacity::{CapacityRefusal, ReservationKey, ReservationPurpose, ResourceKind};
use super::identity::{ModelGenerations, ModelId, SandboxGenerations};
use super::lease::{ActivationView, LeaseRefusal};
use super::revocation::RevocationNotice;
use crate::foundation::evidence::{
    ArtifactBypass, AuthorityGrant, FallbackRefusal, NetworkGrant, Optimization, RuntimeSettings,
    RuntimeSubject,
};
use crate::foundation::ids::{
    ExecutionCategory, ExecutionId, GpuAllocationGeneration, GpuDeviceKey, LeaseId,
    ModelActivationGeneration, OperationId,
};

/// Where one activation is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum ActivationState {
    /// Being prepared: memory is loading; it admits no serving request, only the one
    /// request assigned to it for execute-while-load (§3.6 line 601).
    Loading,
    /// Serving: new requests are admitted to this activation.
    Active,
    /// A newer activation takes new requests, or the activation drains first for one;
    /// it finishes the requests it admitted (INT-03).
    Draining,
    /// The parent's authority was revoked: it admits nothing, and its memory is released
    /// once every lease on it is closed (INT-02).
    Reclaiming,
    /// Finished; it is never served again.
    Retired { reason: RetireReason },
}

crate::foundation::strict_serde::strict_tag!(ActivationState, "state");

impl ActivationState {
    /// Whether requests admitted to it are served.
    pub const fn is_serving(self) -> bool {
        matches!(self, Self::Active | Self::Draining)
    }

    /// Whether it is finished for good.
    pub const fn is_retired(self) -> bool {
        matches!(self, Self::Retired { .. })
    }
}

impl fmt::Display for ActivationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Loading => f.write_str("loading"),
            Self::Active => f.write_str("active"),
            Self::Draining => f.write_str("draining"),
            Self::Reclaiming => f.write_str("being reclaimed"),
            Self::Retired { reason } => write!(f, "retired ({reason})"),
        }
    }
}

/// Why an activation was retired.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetireReason {
    /// A newer activation replaced it and it drained (INT-03).
    Replaced,
    /// Evicted, or parked when its memory is retained; eviction never renews sandbox
    /// authority (S2 CORE-04).
    Evicted,
    /// Parked while idle: it serves no more, and every holding it used is kept for a
    /// reactivation until released (GPU part §3.6: draining → parked).
    Parked,
    /// The parent's authority was revoked (INT-02).
    Revoked,
    /// Loading failed or was abandoned.
    LoadFailed,
    /// A crash ended it; recovery never revives it (INT-04).
    Recovered,
    /// The owner took the GPU back (S10 line 185).
    ReturnedToOwner,
    /// The parent sandbox stopped.
    SandboxStopped,
}

impl fmt::Display for RetireReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Replaced => "replaced",
            Self::Evicted => "evicted",
            Self::Parked => "parked",
            Self::Revoked => "revoked",
            Self::LoadFailed => "load failed",
            Self::Recovered => "ended by a crash",
            Self::ReturnedToOwner => "returned to the owner",
            Self::SandboxStopped => "sandbox stopped",
        })
    }
}

/// Where a holding's reservations stand in the ledger (S2 CORE-03). For an activation it
/// sums up its holdings: held if any is, else releasing if any is, else released.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GpuReservationState {
    /// Reserved; its memory is in use or about to be.
    Held,
    /// Cancelled, and still counted until the runtime or the host observes its release:
    /// stopping work does not free its allocations (S10 line 185).
    Releasing,
    /// Returned to the parent reservation, or handed over to a successor.
    Released,
}

/// One holding of a model's memory under its parent (S2 CORE-03; GPU part §3.6 step 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "holding", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum HoldingId {
    /// A GPU allocation on one device, by its generation.
    Gpu { allocation: GpuAllocationGeneration },
    /// Host memory, by the activation that reserved it.
    Host {
        reserved_by: ModelActivationGeneration,
    },
}

crate::foundation::strict_serde::strict_tag!(HoldingId, "holding");

/// The memory one holding stands for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "memory", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum HoldingMemory {
    /// GPU memory on one device (VRAM is counted per device, S10 line 179).
    Gpu {
        device: GpuDeviceKey,
        memory_bytes: u64,
    },
    /// Host memory: `memory_bytes` pageable and `pinned_memory_bytes` pinned. Pinned
    /// pages are host RAM too, so host RAM is charged with both and pinned RAM with the
    /// pinned part (GPU part §2.7; decisions T08 and P02).
    Host {
        memory_bytes: u64,
        pinned_memory_bytes: u64,
    },
}

crate::foundation::strict_serde::strict_tag!(HoldingMemory, "memory");

impl HoldingMemory {
    /// The ledger demand, zero amounts left out. Host RAM is charged with pageable and
    /// pinned memory together, pinned RAM with the pinned memory alone.
    pub fn demand(&self) -> BTreeMap<ResourceKind, u64> {
        let entries = match self {
            Self::Gpu {
                device,
                memory_bytes,
            } => vec![(
                ResourceKind::GpuMemoryBytes { device: *device },
                *memory_bytes,
            )],
            Self::Host {
                memory_bytes,
                pinned_memory_bytes,
            } => vec![
                (
                    ResourceKind::HostMemoryBytes,
                    memory_bytes.saturating_add(*pinned_memory_bytes),
                ),
                (ResourceKind::PinnedHostMemoryBytes, *pinned_memory_bytes),
            ],
        };
        entries
            .into_iter()
            .filter(|(_, bytes)| *bytes > 0)
            .collect()
    }

    /// What `self` needs beyond `covered`, which must be memory of the same kind and
    /// device.
    fn beyond(self, covered: &[HoldingMemory]) -> HoldingMemory {
        match self {
            Self::Gpu {
                device,
                memory_bytes,
            } => {
                let held: u64 = covered
                    .iter()
                    .map(|memory| match memory {
                        Self::Gpu { memory_bytes, .. } => *memory_bytes,
                        Self::Host { .. } => 0,
                    })
                    .fold(0, u64::saturating_add);
                Self::Gpu {
                    device,
                    memory_bytes: memory_bytes.saturating_sub(held),
                }
            }
            Self::Host {
                memory_bytes,
                pinned_memory_bytes,
            } => {
                let (held, pinned) = covered
                    .iter()
                    .map(|memory| match memory {
                        Self::Host {
                            memory_bytes,
                            pinned_memory_bytes,
                        } => (*memory_bytes, *pinned_memory_bytes),
                        Self::Gpu { .. } => (0, 0),
                    })
                    .fold((0u64, 0u64), |(a, b), (c, d)| {
                        (a.saturating_add(c), b.saturating_add(d))
                    });
                Self::Host {
                    memory_bytes: memory_bytes.saturating_sub(held),
                    pinned_memory_bytes: pinned_memory_bytes.saturating_sub(pinned),
                }
            }
        }
    }

    /// Whether `other` is memory of the same kind and, for GPU memory, the same device.
    fn same_place(&self, other: &HoldingMemory) -> bool {
        match (self, other) {
            (Self::Gpu { device: a, .. }, Self::Gpu { device: b, .. }) => a == b,
            (Self::Host { .. }, Self::Host { .. }) => true,
            _ => false,
        }
    }
}

/// Whether a holding outlives its last user.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Retention {
    /// Released as soon as no unretired activation uses it.
    #[default]
    ReleaseWhenUnused,
    /// Kept after its last user retires, for a reactivation, until released and
    /// confirmed explicitly (GPU part §3.6 line 585: a valid GPU allocation may outlive
    /// one serving process).
    KeepUntilReleased,
}

/// One holding: memory reserved as a child of the sandbox reservation and used by one or
/// more activations of the model.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Holding {
    id: HoldingId,
    memory: HoldingMemory,
    bound_to: SandboxGenerations,
    reservations: Vec<ReservationKey>,
    state: GpuReservationState,
    users: BTreeSet<ModelActivationGeneration>,
    retention: Retention,
    promised_to: Option<(ModelActivationGeneration, HoldingId)>,
    awaiting: BTreeSet<HoldingId>,
    #[serde(default)]
    weights: bool,
}

impl Holding {
    /// Which holding it is: a GPU allocation by its generation, or host memory by the
    /// activation that reserved it.
    pub fn id(&self) -> HoldingId {
        self.id
    }

    /// The memory it stands for.
    pub fn memory(&self) -> HoldingMemory {
        self.memory
    }

    /// The parent's generations when it was reserved; only an activation under the same
    /// boot and authorization epoch may acquire it (INT-04).
    pub fn bound_to(&self) -> SandboxGenerations {
        self.bound_to
    }

    /// Its ledger reservations: its own, then any taken over in a drain-first handover.
    pub fn reservations(&self) -> &[ReservationKey] {
        &self.reservations
    }

    /// Where its reservations stand.
    pub fn state(&self) -> GpuReservationState {
        self.state
    }

    /// The activations that use it, retired ones included.
    pub fn users(&self) -> &BTreeSet<ModelActivationGeneration> {
        &self.users
    }

    /// Whether it outlives its last user.
    pub fn retention(&self) -> Retention {
        self.retention
    }

    /// The successor activation and holding it passes to in a drain-first handover.
    pub fn promised_to(&self) -> Option<(ModelActivationGeneration, HoldingId)> {
        self.promised_to
    }

    /// The predecessor holdings it waits for in a drain-first handover; until they pass
    /// to it, its memory is not all reserved and must not be used.
    pub fn awaiting(&self) -> &BTreeSet<HoldingId> {
        &self.awaiting
    }

    /// Whether every byte of it is reserved: it waits for no handover.
    pub fn is_backed(&self) -> bool {
        self.awaiting.is_empty()
    }

    /// Whether it holds immutable weights reserved apart from any activation's own memory
    /// (GPU part §2.7; T15 decision 1). Activations acquire it beside the working memory
    /// they reserve themselves; it outlives them until released
    /// ([`super::Coordinator::release_unused_holding`]) or reclaimed with the parent.
    pub fn holds_weights(&self) -> bool {
        self.weights
    }
}

/// What a new activation needs (GPU part §3.6 steps 1–2).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ActivationDemand {
    /// GPU memory to allocate anew, steady state plus transition peak (§3.6 step 1): one
    /// allocation, with a new generation, per device.
    pub gpu_memory_bytes: BTreeMap<GpuDeviceKey, u64>,
    /// Pageable host memory to reserve anew, counted like VRAM (GPU part §2.7).
    pub host_memory_bytes: u64,
    /// Pinned host memory to reserve anew, such as staging buffers. Pinned pages are host
    /// RAM, so it is charged to host RAM as well as to pinned RAM (GPU part §2.7;
    /// decisions T08 and P02).
    pub pinned_host_memory_bytes: u64,
    /// Holdings of this model to acquire as they are (§3.6 step 2: acquire immutable
    /// extents). They keep their generation and reservation, so memory several
    /// activations share counts once (GPU part §2.7). The coordinator accounts the
    /// memory, not its contents: whether an extent is usable stays with the placement.
    pub acquire: BTreeSet<HoldingId>,
    /// Whether the new holdings outlive the activation, for a reactivation.
    pub retention: Retention,
}

impl ActivationDemand {
    /// One new GPU allocation on one device, released when no longer used.
    pub fn gpu(demand: GpuDemand) -> Self {
        Self {
            gpu_memory_bytes: BTreeMap::from([(demand.device, demand.memory_bytes)]),
            ..Self::default()
        }
    }
}

/// The GPU memory one model allocation needs, on one device (S2 CORE-03: MODELS supplies
/// placement demand, and VRAM is counted per device).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GpuDemand {
    pub device: GpuDeviceKey,
    pub memory_bytes: u64,
}

/// One activation of a model.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Activation {
    generations: ModelGenerations,
    state: ActivationState,
    bound_to: SandboxGenerations,
    holdings: BTreeSet<HoldingId>,
    gpu_reservation: ReservationKey,
    gpu_reservation_state: GpuReservationState,
    awaiting_handover: Option<ModelActivationGeneration>,
    settings: RuntimeSettings,
}

impl Activation {
    /// Its activation generation and the newest GPU allocation generation it uses.
    pub fn generations(&self) -> ModelGenerations {
        self.generations
    }

    /// Where it is.
    pub fn state(&self) -> ActivationState {
        self.state
    }

    /// The parent's generations when the activation began (S3.1: bound to the parent
    /// execution and authorization epoch).
    pub fn bound_to(&self) -> SandboxGenerations {
        self.bound_to
    }

    /// The holdings it uses: those it reserved and those it acquired.
    pub fn holdings(&self) -> &BTreeSet<HoldingId> {
        &self.holdings
    }

    /// The reservation of its newest GPU allocation: the first one that allocation
    /// holds, or the key its own reservation has or would have. The memory it uses is in
    /// [`Self::holdings`].
    pub fn gpu_reservation(&self) -> ReservationKey {
        self.gpu_reservation
    }

    /// Where its holdings stand together: held if any is held, else releasing if any is,
    /// else released.
    pub fn gpu_reservation_state(&self) -> GpuReservationState {
        self.gpu_reservation_state
    }

    /// Whether the ledger still counts any of its holdings.
    pub fn gpu_reservation_counted(&self) -> bool {
        self.gpu_reservation_state != GpuReservationState::Released
    }

    /// The predecessor whose memory it waits for in a drain-first handover.
    pub fn awaiting_handover(&self) -> Option<ModelActivationGeneration> {
        self.awaiting_handover
    }

    /// The runtime settings it was authorized with.
    pub fn settings(&self) -> &RuntimeSettings {
        &self.settings
    }
}

/// A handle into one GPU allocation as one activation uses it. Runtime code presents it
/// before touching the allocation; a handle of a retired activation, or into an
/// allocation the activation does not use, is refused (INT-04: old GPU pointers are never
/// reused).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GpuAllocationHandle {
    pub execution: ExecutionId,
    pub model: ModelId,
    pub generations: ModelGenerations,
}

/// What a begun activation got (GPU part §3.6 steps 1–2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivationHandle {
    /// The parent execution.
    pub execution: ExecutionId,
    /// The model.
    pub model: ModelId,
    /// Its activation generation and the newest GPU allocation generation it uses.
    pub generations: ModelGenerations,
    /// The GPU allocations it reserved anew, one per device.
    pub allocated: BTreeMap<GpuDeviceKey, GpuAllocationGeneration>,
    /// The holdings it acquired as they were.
    pub acquired: BTreeSet<HoldingId>,
    /// The predecessor whose memory it waits for in a drain-first handover.
    pub awaiting_handover: Option<ModelActivationGeneration>,
}

impl ActivationHandle {
    /// A handle into each GPU allocation the activation uses, new and acquired.
    pub fn gpu_handles(&self) -> Vec<GpuAllocationHandle> {
        let allocations: BTreeSet<GpuAllocationGeneration> = self
            .allocated
            .values()
            .copied()
            .chain(self.acquired.iter().filter_map(|holding| match holding {
                HoldingId::Gpu { allocation } => Some(*allocation),
                HoldingId::Host { .. } => None,
            }))
            .collect();
        allocations
            .into_iter()
            .map(|allocation| GpuAllocationHandle {
                execution: self.execution.clone(),
                model: self.model,
                generations: ModelGenerations {
                    activation: self.generations.activation,
                    gpu_allocation: allocation,
                },
            })
            .collect()
    }
}

/// What completing an activation changed (INT-03).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Completion {
    /// The activation was already active; nothing changed.
    pub already_active: bool,
    /// The activation it replaced, now draining.
    pub draining: Option<ModelGenerations>,
}

/// An activation step, for refusals.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationStep {
    Complete,
    FailLoad,
    Evict,
    /// Assign the request an activation being prepared computes for (§3.6 line 601).
    Prepare,
    /// Hand the activation's memory to a drain-first successor (§3.6 line 597).
    HandOver,
    /// Park an idle activation, keeping its memory (§3.6).
    Park,
}

impl fmt::Display for ActivationStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Complete => "complete",
            Self::FailLoad => "fail the load of",
            Self::Evict => "evict",
            Self::Prepare => "assign a request to",
            Self::HandOver => "hand over the memory of",
            Self::Park => "park",
        })
    }
}

/// What is wrong with an activation's demand.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum DemandProblem {
    /// An activation needs at least one GPU allocation, new or acquired.
    NoGpuMemory,
    /// A new GPU allocation of zero bytes.
    ZeroGpuMemory { device: GpuDeviceKey },
}

crate::foundation::strict_serde::strict_tag!(DemandProblem, "problem");

/// Why a model activation step was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "model_refusal", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum ModelRefusal {
    UnknownModel {
        model: ModelId,
    },
    UnknownActivation {
        activation: ModelActivationGeneration,
    },
    NoServingActivation {
        model: ModelId,
    },
    InvalidActivationTransition {
        activation: ModelActivationGeneration,
        state: ActivationState,
        step: ActivationStep,
    },
    /// Leases still use the activation.
    RequestsInFlight {
        activation: ModelActivationGeneration,
        leases: Vec<LeaseId>,
    },
    /// A model runs in its parent's execution category (S3.5).
    CategoryMismatch {
        parent: ExecutionCategory,
        settings: ExecutionCategory,
    },
    /// The settings claim more authority than the parent holds (S3.1).
    AuthorityExceedsParent {
        parent: AuthorityGrant,
        settings: AuthorityGrant,
    },
    /// The settings use network grants the parent's authority does not grant (S3.5).
    NetworkNotGranted {
        grants: BTreeSet<NetworkGrant>,
    },
    /// The settings' loader skips verification, or reads artifacts the parent's authority
    /// has not verified (S3.5; INT-09).
    ArtifactsNotGranted {
        bypass: ArtifactBypass,
    },
    /// The settings' loader uses optimizations the gate's plan did not enable for the
    /// parent's runtime (S3.5; INT-06).
    LoaderNotGranted {
        optimizations: BTreeSet<Optimization>,
    },
    /// An unretired activation still uses the holding, or a drain-first successor waits
    /// for it.
    HoldingInUse {
        holding: HoldingId,
    },
    /// The parent cannot take new work now.
    Parent {
        refusal: LeaseRefusal,
    },
    /// The parent holds no reservation to charge the GPU memory within.
    NoSandboxReservation,
    Capacity {
        refusal: CapacityRefusal,
    },
    /// The GPU reservation waits in the ledger's bounded queue.
    Queued {
        position: u32,
    },
    /// The recovery fallback was refused (S3.5).
    Fallback {
        refusal: FallbackRefusal,
    },
    /// The loader plan was made for another runtime than the parent's current boot.
    PlanForOtherRuntime {
        plan: RuntimeSubject,
        runtime: RuntimeSubject,
    },
    /// Reloading needs an earlier activation to fall back from.
    NoPriorActivation {
        model: ModelId,
    },
    /// Nothing the activation used is left to release or confirm, or the activation
    /// still runs.
    NothingToRelease {
        activation: ModelActivationGeneration,
    },
    GenerationsExhausted,
    /// The demand cannot be met as stated.
    InvalidDemand {
        problem: DemandProblem,
    },
    /// The holding cannot be acquired: it is unknown, released or releasing, promised to
    /// a successor, still waiting for a handover, or from an earlier boot or authorization
    /// epoch (INT-04: old GPU pointers are never reused).
    HoldingUnavailable {
        holding: HoldingId,
    },
    /// The activation waits for its predecessor's memory in a drain-first handover.
    HandoverPending {
        predecessor: ModelActivationGeneration,
    },
    /// A request is already assigned to the activation being prepared; it computes for
    /// that request only (§3.6 line 601).
    PreparationAssigned {
        assigned: OperationId,
    },
}

crate::foundation::strict_serde::strict_tag!(ModelRefusal, "model_refusal");

impl fmt::Display for ModelRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownModel { model } => write!(f, "model {model} has no activations here"),
            Self::UnknownActivation { activation } => {
                write!(f, "activation generation {activation} is unknown")
            }
            Self::NoServingActivation { model } => {
                write!(f, "model {model} has no active activation")
            }
            Self::InvalidActivationTransition {
                activation,
                state,
                step,
            } => write!(
                f,
                "cannot {step} activation generation {activation} while it is {state}"
            ),
            Self::RequestsInFlight { activation, leases } => write!(
                f,
                "activation generation {activation} still has {} lease(s) in use",
                leases.len()
            ),
            Self::CategoryMismatch { parent, settings } => write!(
                f,
                "the model would run as \"{}\" under a \"{}\" parent; a model stays in its \
                 parent's category",
                settings.label(),
                parent.label()
            ),
            Self::AuthorityExceedsParent { parent, settings } => write!(
                f,
                "the settings claim authority epoch {} until {} ns, beyond the parent's epoch \
                 {} until {} ns",
                settings.epoch,
                settings.expires_at.as_nanos(),
                parent.epoch,
                parent.expires_at.as_nanos()
            ),
            Self::NetworkNotGranted { grants } => write!(
                f,
                "the settings use {} network grant(s) the parent's authority does not grant",
                grants.len()
            ),
            Self::ArtifactsNotGranted { bypass } => match bypass {
                ArtifactBypass::VerificationSkipped => {
                    f.write_str("the settings' loader would read without verification")
                }
                ArtifactBypass::UnverifiedArtifacts { artifacts } => write!(
                    f,
                    "the settings' loader would read {} artifact(s) the parent's authority has \
                     not verified",
                    artifacts.len()
                ),
            },
            Self::LoaderNotGranted { optimizations } => write!(
                f,
                "the settings' loader uses {} optimization(s) the gate did not enable for this \
                 runtime",
                optimizations.len()
            ),
            Self::HoldingInUse { holding } => write!(f, "{holding:?} is still in use"),
            Self::Parent { refusal } => write!(f, "{refusal}"),
            Self::NoSandboxReservation => {
                f.write_str("the parent holds no reservation to charge GPU memory within")
            }
            Self::Capacity { refusal } => write!(f, "{refusal}"),
            Self::Queued { position } => write!(
                f,
                "the GPU reservation waits at position {position} in the ledger's queue"
            ),
            Self::Fallback { refusal } => write!(f, "{refusal}"),
            Self::PlanForOtherRuntime { .. } => f.write_str(
                "the loader plan was made for another runtime than the parent's current boot",
            ),
            Self::NoPriorActivation { model } => {
                write!(f, "model {model} has no earlier activation to reload")
            }
            Self::NothingToRelease { activation } => write!(
                f,
                "activation generation {activation} has no memory left to release or confirm"
            ),
            Self::GenerationsExhausted => {
                f.write_str("the model's generations are exhausted; replace the parent")
            }
            Self::InvalidDemand { problem } => match problem {
                DemandProblem::NoGpuMemory => {
                    f.write_str("an activation needs at least one GPU allocation")
                }
                DemandProblem::ZeroGpuMemory { .. } => {
                    f.write_str("a new GPU allocation must be larger than zero bytes")
                }
            },
            Self::HoldingUnavailable { holding } => {
                write!(f, "{holding:?} cannot be acquired now")
            }
            Self::HandoverPending { predecessor } => write!(
                f,
                "the activation waits for the memory of activation generation {predecessor}"
            ),
            Self::PreparationAssigned { assigned } => write!(
                f,
                "request {assigned} is assigned to this activation; it computes for no other"
            ),
        }
    }
}

impl std::error::Error for ModelRefusal {}

/// A new holding an activation reserves (GPU part §3.6 step 1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct FreshHolding {
    pub(super) id: HoldingId,
    pub(super) memory: HoldingMemory,
    /// What it reserves itself: all of its memory, or in a drain-first handover what the
    /// predecessor's promised holdings do not cover.
    pub(super) own: HoldingMemory,
    pub(super) awaiting: BTreeSet<HoldingId>,
}

/// An activation planned, before anything is reserved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Plan {
    pub(super) generations: ModelGenerations,
    pub(super) allocated: BTreeMap<GpuDeviceKey, GpuAllocationGeneration>,
    pub(super) acquired: BTreeSet<HoldingId>,
    pub(super) fresh: Vec<FreshHolding>,
    /// Predecessor holdings and the successor holdings they pass to.
    pub(super) promises: Vec<(HoldingId, HoldingId)>,
    pub(super) predecessor: Option<ModelActivationGeneration>,
    retention: Retention,
    next: ModelGenerations,
}

/// How one holding a retired activation left is closed once its release is observed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Closing {
    /// Still held, and kept by nothing but retention: release it, then confirm.
    Release,
    /// Released and still counted: confirm the release.
    Confirm,
    /// Promised to an unretired drain-first successor: pass it on (§3.6 line 597).
    HandOver,
}

/// Holdings of weights planned apart from any activation, before anything is reserved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct WeightsPlan {
    pub(super) fresh: Vec<FreshHolding>,
    next_allocation: GpuAllocationGeneration,
}

/// Why a GPU allocation handle is not honoured.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum HandleProblem {
    Stale,
    AwaitingHandover,
}

/// Every activation and holding of one model under one parent execution (S3.1), owned by
/// MODELS.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelActivations {
    execution: ExecutionId,
    model: ModelId,
    next: ModelGenerations,
    activations: Vec<Activation>,
    holdings: Vec<Holding>,
}

impl ModelActivations {
    pub(super) fn new(execution: ExecutionId, model: ModelId) -> Self {
        Self {
            execution,
            model,
            next: ModelGenerations::FIRST,
            activations: Vec::new(),
            holdings: Vec::new(),
        }
    }

    /// The parent execution.
    pub fn execution(&self) -> &ExecutionId {
        &self.execution
    }

    /// The model.
    pub fn model(&self) -> ModelId {
        self.model
    }

    /// The generations handed out next; each value is handed out once.
    pub fn next_generations(&self) -> ModelGenerations {
        self.next
    }

    /// Raises the generations handed out next to at least `floor`'s (CORE-04 durable
    /// epochs): activations restored from a state older than the durable floor are never
    /// given a generation that was already handed out. Returns the generations before.
    pub(super) fn raise_next(&mut self, floor: ModelGenerations) -> ModelGenerations {
        let before = self.next;
        self.next = ModelGenerations {
            activation: before.activation.max(floor.activation),
            gpu_allocation: before.gpu_allocation.max(floor.gpu_allocation),
        };
        before
    }

    /// Every activation, oldest first.
    pub fn activations(&self) -> &[Activation] {
        &self.activations
    }

    /// The activation of one generation.
    pub fn activation(&self, activation: ModelActivationGeneration) -> Option<&Activation> {
        self.activations
            .iter()
            .find(|entry| entry.generations.activation == activation)
    }

    /// The activation new requests are admitted to.
    pub fn serving(&self) -> Option<&Activation> {
        self.activations
            .iter()
            .find(|entry| entry.state == ActivationState::Active)
    }

    /// The most recent activation, whatever its state.
    pub fn latest(&self) -> Option<&Activation> {
        self.activations.last()
    }

    /// Every holding, oldest first, released ones included.
    pub fn holdings(&self) -> &[Holding] {
        &self.holdings
    }

    /// One holding.
    pub fn holding(&self, holding: HoldingId) -> Option<&Holding> {
        self.holdings.iter().find(|entry| entry.id == holding)
    }

    fn holding_mut(&mut self, holding: HoldingId) -> Option<&mut Holding> {
        self.holdings.iter_mut().find(|entry| entry.id == holding)
    }

    fn entry_mut(
        &mut self,
        activation: ModelActivationGeneration,
    ) -> Result<&mut Activation, ModelRefusal> {
        self.activations
            .iter_mut()
            .find(|entry| entry.generations.activation == activation)
            .ok_or(ModelRefusal::UnknownActivation { activation })
    }

    fn is_unretired(&self, activation: ModelActivationGeneration) -> bool {
        self.activation(activation)
            .is_some_and(|entry| !entry.state.is_retired())
    }

    /// Whether `holding` may be acquired by an activation under `current`.
    fn acquirable(&self, holding: &Holding, current: SandboxGenerations) -> bool {
        holding.state == GpuReservationState::Held
            && holding.is_backed()
            && holding.promised_to.is_none()
            && holding.bound_to.boot == current.boot
            && holding.bound_to.authorization == current.authorization
    }

    /// Plans an activation with `demand` under `current`, as the drain-first successor
    /// of `predecessor` when one is named. Nothing changes until [`Self::apply`].
    pub(super) fn plan(
        &self,
        demand: &ActivationDemand,
        current: SandboxGenerations,
        predecessor: Option<ModelActivationGeneration>,
    ) -> Result<Plan, ModelRefusal> {
        for holding in &demand.acquire {
            let available = self
                .holding(*holding)
                .is_some_and(|entry| self.acquirable(entry, current));
            if !available {
                return Err(ModelRefusal::HoldingUnavailable { holding: *holding });
            }
        }
        if let Some((device, _)) = demand
            .gpu_memory_bytes
            .iter()
            .find(|(_, bytes)| **bytes == 0)
        {
            return Err(ModelRefusal::InvalidDemand {
                problem: DemandProblem::ZeroGpuMemory { device: *device },
            });
        }
        let acquired_gpu: BTreeSet<GpuAllocationGeneration> = demand
            .acquire
            .iter()
            .filter_map(|holding| match holding {
                HoldingId::Gpu { allocation } => Some(*allocation),
                HoldingId::Host { .. } => None,
            })
            .collect();
        if demand.gpu_memory_bytes.is_empty() && acquired_gpu.is_empty() {
            return Err(ModelRefusal::InvalidDemand {
                problem: DemandProblem::NoGpuMemory,
            });
        }

        let activation = self.next.activation;
        let next_activation = activation
            .next()
            .ok_or(ModelRefusal::GenerationsExhausted)?;
        let mut cursor = self.next.gpu_allocation;
        let mut allocated = BTreeMap::new();
        let mut fresh = Vec::new();
        for (device, memory_bytes) in &demand.gpu_memory_bytes {
            let allocation = cursor;
            cursor = cursor.next().ok_or(ModelRefusal::GenerationsExhausted)?;
            allocated.insert(*device, allocation);
            let memory = HoldingMemory::Gpu {
                device: *device,
                memory_bytes: *memory_bytes,
            };
            fresh.push(FreshHolding {
                id: HoldingId::Gpu { allocation },
                memory,
                own: memory,
                awaiting: BTreeSet::new(),
            });
        }
        if demand.host_memory_bytes > 0 || demand.pinned_host_memory_bytes > 0 {
            let memory = HoldingMemory::Host {
                memory_bytes: demand.host_memory_bytes,
                pinned_memory_bytes: demand.pinned_host_memory_bytes,
            };
            fresh.push(FreshHolding {
                id: HoldingId::Host {
                    reserved_by: activation,
                },
                memory,
                own: memory,
                awaiting: BTreeSet::new(),
            });
        }

        let mut promises = Vec::new();
        if let Some(predecessor) = predecessor {
            let entry = self
                .activation(predecessor)
                .ok_or(ModelRefusal::UnknownActivation {
                    activation: predecessor,
                })?;
            if !matches!(
                entry.state,
                ActivationState::Active | ActivationState::Draining
            ) {
                return Err(ModelRefusal::InvalidActivationTransition {
                    activation: predecessor,
                    state: entry.state,
                    step: ActivationStep::HandOver,
                });
            }
            let transferable: Vec<&Holding> = entry
                .holdings
                .iter()
                .filter(|holding| !demand.acquire.contains(holding))
                .filter_map(|holding| self.holding(*holding))
                .filter(|holding| {
                    // Weights reserved apart are the model's, not the predecessor's to hand
                    // over: a successor acquires them or reserves its own.
                    !holding.weights
                        && self.acquirable(holding, current)
                        && holding
                            .users
                            .iter()
                            .all(|user| *user == predecessor || !self.is_unretired(*user))
                })
                .collect();
            for holding in &mut fresh {
                let inherited: Vec<&Holding> = transferable
                    .iter()
                    .copied()
                    .filter(|candidate| candidate.memory.same_place(&holding.memory))
                    .collect();
                let covered: Vec<HoldingMemory> =
                    inherited.iter().map(|candidate| candidate.memory).collect();
                holding.own = holding.memory.beyond(&covered);
                for candidate in inherited {
                    holding.awaiting.insert(candidate.id);
                    promises.push((candidate.id, holding.id));
                }
            }
        }

        let newest = allocated
            .values()
            .copied()
            .chain(acquired_gpu.iter().copied())
            .max()
            .ok_or(ModelRefusal::InvalidDemand {
                problem: DemandProblem::NoGpuMemory,
            })?;
        Ok(Plan {
            generations: ModelGenerations {
                activation,
                gpu_allocation: newest,
            },
            allocated,
            acquired: demand.acquire.clone(),
            fresh,
            promises,
            predecessor,
            retention: demand.retention,
            next: ModelGenerations {
                activation: next_activation,
                gpu_allocation: cursor,
            },
        })
    }

    /// Plans one holding of immutable weights per device of `weights`, apart from any
    /// activation, each with a new allocation generation (GPU part §2.7; T15 decision 1).
    pub(super) fn plan_weights(
        &self,
        weights: &BTreeMap<GpuDeviceKey, u64>,
    ) -> Result<WeightsPlan, ModelRefusal> {
        if weights.is_empty() {
            return Err(ModelRefusal::InvalidDemand {
                problem: DemandProblem::NoGpuMemory,
            });
        }
        let mut cursor = self.next.gpu_allocation;
        let mut fresh = Vec::new();
        for (device, memory_bytes) in weights {
            if *memory_bytes == 0 {
                return Err(ModelRefusal::InvalidDemand {
                    problem: DemandProblem::ZeroGpuMemory { device: *device },
                });
            }
            let allocation = cursor;
            cursor = cursor.next().ok_or(ModelRefusal::GenerationsExhausted)?;
            let memory = HoldingMemory::Gpu {
                device: *device,
                memory_bytes: *memory_bytes,
            };
            fresh.push(FreshHolding {
                id: HoldingId::Gpu { allocation },
                memory,
                own: memory,
                awaiting: BTreeSet::new(),
            });
        }
        Ok(WeightsPlan {
            fresh,
            next_allocation: cursor,
        })
    }

    /// Records planned weights once their reservations, `reserved`, are made: held, used
    /// by no activation yet, kept until released.
    pub(super) fn apply_weights(
        &mut self,
        plan: WeightsPlan,
        bound_to: SandboxGenerations,
        reserved: &BTreeMap<HoldingId, ReservationKey>,
    ) -> BTreeMap<GpuDeviceKey, HoldingId> {
        let mut holdings = BTreeMap::new();
        for fresh in plan.fresh {
            if let HoldingMemory::Gpu { device, .. } = fresh.memory {
                holdings.insert(device, fresh.id);
            }
            self.holdings.push(Holding {
                id: fresh.id,
                memory: fresh.memory,
                bound_to,
                reservations: reserved.get(&fresh.id).copied().into_iter().collect(),
                state: GpuReservationState::Held,
                users: BTreeSet::new(),
                retention: Retention::KeepUntilReleased,
                promised_to: None,
                awaiting: BTreeSet::new(),
                weights: true,
            });
        }
        self.next.gpu_allocation = plan.next_allocation;
        self.refresh();
        holdings
    }

    /// Keeps every holding `activation` uses until released, as parking does.
    pub(super) fn retain(&mut self, activation: ModelActivationGeneration) {
        for holding in &mut self.holdings {
            if holding.users.contains(&activation) {
                holding.retention = Retention::KeepUntilReleased;
            }
        }
    }

    /// Whether `holding` is in use: by an unretired activation, or promised to an
    /// unretired drain-first successor.
    pub(super) fn in_use(&self, holding: &Holding) -> bool {
        holding.users.iter().any(|user| self.is_unretired(*user))
            || holding
                .promised_to
                .is_some_and(|(successor, _)| self.is_unretired(successor))
    }

    /// Records a planned activation once its own reservations, `reserved`, are made.
    pub(super) fn apply(
        &mut self,
        plan: Plan,
        settings: RuntimeSettings,
        bound_to: SandboxGenerations,
        reserved: &BTreeMap<HoldingId, ReservationKey>,
    ) -> ActivationHandle {
        let activation = plan.generations.activation;
        for fresh in &plan.fresh {
            self.holdings.push(Holding {
                id: fresh.id,
                memory: fresh.memory,
                bound_to,
                reservations: reserved.get(&fresh.id).copied().into_iter().collect(),
                state: GpuReservationState::Held,
                users: BTreeSet::from([activation]),
                retention: plan.retention,
                promised_to: None,
                awaiting: fresh.awaiting.clone(),
                weights: false,
            });
        }
        for holding in &plan.acquired {
            if let Some(entry) = self.holding_mut(*holding) {
                entry.users.insert(activation);
            }
        }
        for (from, to) in &plan.promises {
            if let Some(entry) = self.holding_mut(*from) {
                entry.promised_to = Some((activation, *to));
            }
        }
        let awaiting_handover = (!plan.promises.is_empty())
            .then_some(plan.predecessor)
            .flatten();
        if let Some(predecessor) = plan.predecessor {
            for entry in &mut self.activations {
                if entry.generations.activation == predecessor
                    && entry.state == ActivationState::Active
                {
                    entry.state = ActivationState::Draining;
                }
            }
        }
        let holdings: BTreeSet<HoldingId> = plan
            .fresh
            .iter()
            .map(|fresh| fresh.id)
            .chain(plan.acquired.iter().copied())
            .collect();
        self.activations.push(Activation {
            generations: plan.generations,
            state: ActivationState::Loading,
            bound_to,
            holdings,
            gpu_reservation: self.gpu_key(plan.generations.gpu_allocation),
            gpu_reservation_state: GpuReservationState::Held,
            awaiting_handover,
            settings,
        });
        self.next = plan.next;
        self.refresh();
        ActivationHandle {
            execution: self.execution.clone(),
            model: self.model,
            generations: plan.generations,
            allocated: plan.allocated,
            acquired: plan.acquired,
            awaiting_handover,
        }
    }

    /// The first reservation of a GPU allocation, or the key its own reservation has.
    fn gpu_key(&self, allocation: GpuAllocationGeneration) -> ReservationKey {
        self.holding(HoldingId::Gpu { allocation })
            .and_then(|holding| holding.reservations.first().copied())
            .unwrap_or_else(|| {
                ReservationKey::derive(
                    &self.execution,
                    &ReservationPurpose::ModelGpu {
                        model: self.model,
                        gpu_allocation: allocation,
                    },
                )
            })
    }

    /// Recomputes what each activation shows of its holdings.
    fn refresh(&mut self) {
        let summaries: Vec<(GpuReservationState, ReservationKey)> = self
            .activations
            .iter()
            .map(|entry| {
                let states: Vec<GpuReservationState> = entry
                    .holdings
                    .iter()
                    .filter_map(|holding| self.holding(*holding))
                    .map(|holding| holding.state)
                    .collect();
                let state = if states.contains(&GpuReservationState::Held) {
                    GpuReservationState::Held
                } else if states.contains(&GpuReservationState::Releasing) {
                    GpuReservationState::Releasing
                } else {
                    GpuReservationState::Released
                };
                (state, self.gpu_key(entry.generations.gpu_allocation))
            })
            .collect();
        for (entry, (state, key)) in self.activations.iter_mut().zip(summaries) {
            entry.gpu_reservation_state = state;
            entry.gpu_reservation = key;
        }
    }

    /// Makes a loaded activation the serving one; the one it replaces drains (INT-03).
    pub(super) fn complete(
        &mut self,
        activation: ModelActivationGeneration,
    ) -> Result<Completion, ModelRefusal> {
        let entry = self.entry_mut(activation)?;
        let state = entry.state;
        match state {
            ActivationState::Active => {
                return Ok(Completion {
                    already_active: true,
                    draining: None,
                })
            }
            ActivationState::Loading => {}
            state => {
                return Err(ModelRefusal::InvalidActivationTransition {
                    activation,
                    state,
                    step: ActivationStep::Complete,
                })
            }
        }
        if let Some(predecessor) = entry.awaiting_handover {
            return Err(ModelRefusal::HandoverPending { predecessor });
        }
        let mut draining = None;
        for entry in &mut self.activations {
            if entry.generations.activation == activation {
                entry.state = ActivationState::Active;
            } else if entry.state == ActivationState::Active {
                entry.state = ActivationState::Draining;
                draining = Some(entry.generations);
            }
        }
        Ok(Completion {
            already_active: false,
            draining,
        })
    }

    /// Checks that `activation` may take `step` now.
    pub(super) fn check_step(
        &self,
        activation: ModelActivationGeneration,
        step: ActivationStep,
    ) -> Result<(), ModelRefusal> {
        let state = self
            .activation(activation)
            .ok_or(ModelRefusal::UnknownActivation { activation })?
            .state;
        let allowed = match step {
            ActivationStep::Evict | ActivationStep::Park => state.is_serving(),
            ActivationStep::FailLoad | ActivationStep::Complete | ActivationStep::Prepare => {
                state == ActivationState::Loading
            }
            ActivationStep::HandOver => {
                matches!(state, ActivationState::Active | ActivationState::Draining)
            }
        };
        if allowed {
            Ok(())
        } else {
            Err(ModelRefusal::InvalidActivationTransition {
                activation,
                state,
                step,
            })
        }
    }

    /// Ends the promises a successor waited for, so the predecessor keeps its memory (a
    /// successor retired first gives the share back). The successor's own holdings that
    /// still wait stay unbacked, so nothing can acquire memory they never fully reserved.
    fn withdraw_handover(&mut self, successor: ModelActivationGeneration) {
        for holding in &mut self.holdings {
            if holding.promised_to.is_some_and(|(to, _)| to == successor) {
                holding.promised_to = None;
            }
        }
        if let Ok(entry) = self.entry_mut(successor) {
            entry.awaiting_handover = None;
        }
    }

    /// Retires `activation`; retiring again keeps the first reason.
    pub(super) fn retire(
        &mut self,
        activation: ModelActivationGeneration,
        reason: RetireReason,
    ) -> Result<ModelGenerations, ModelRefusal> {
        let entry = self.entry_mut(activation)?;
        let generations = entry.generations;
        if !entry.state.is_retired() {
            entry.state = ActivationState::Retired { reason };
            self.withdraw_handover(activation);
        }
        self.refresh();
        Ok(generations)
    }

    /// Retires every activation not yet retired; returns their generations.
    pub(super) fn retire_all(&mut self, reason: RetireReason) -> Vec<ModelGenerations> {
        let retiring: Vec<ModelActivationGeneration> = self
            .activations
            .iter()
            .filter(|entry| !entry.state.is_retired())
            .map(|entry| entry.generations.activation)
            .collect();
        let mut retired = Vec::new();
        for activation in retiring {
            if let Ok(generations) = self.retire(activation, reason) {
                retired.push(generations);
            }
        }
        retired
    }

    /// The explicit adapter call by which the model side learns of a revocation (S2
    /// CORE-04): every unretired activation stops admitting and waits to be reclaimed. No
    /// generation changes.
    pub(super) fn on_parent_revoked(&mut self, notice: &RevocationNotice) -> Vec<ModelGenerations> {
        let mut reclaiming = Vec::new();
        if notice.execution != self.execution {
            return reclaiming;
        }
        for entry in &mut self.activations {
            if !entry.state.is_retired() {
                entry.state = ActivationState::Reclaiming;
                reclaiming.push(entry.generations);
            }
        }
        reclaiming
    }

    /// Holdings to release now: held, used by no unretired activation, and, unless
    /// `force`, not promised to an unretired successor and either not retained or never
    /// fully reserved, as a withdrawn successor's holding is.
    pub(super) fn releasable(&self, force: bool) -> Vec<HoldingId> {
        self.holdings
            .iter()
            .filter(|holding| holding.state == GpuReservationState::Held)
            .filter(|holding| !holding.users.iter().any(|user| self.is_unretired(*user)))
            .filter(|holding| {
                let promised = holding
                    .promised_to
                    .is_some_and(|(successor, _)| self.is_unretired(successor));
                let kept = holding.retention == Retention::KeepUntilReleased && holding.is_backed();
                force || !(promised || kept)
            })
            .map(|holding| holding.id)
            .collect()
    }

    /// The holdings of a retired `activation` that no unretired activation uses.
    fn left_by(&self, activation: ModelActivationGeneration) -> Vec<HoldingId> {
        self.activation(activation)
            .map(|entry| {
                entry
                    .holdings
                    .iter()
                    .filter_map(|holding| self.holding(*holding))
                    .filter(|holding| !holding.users.iter().any(|user| self.is_unretired(*user)))
                    .map(|holding| holding.id)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// What closing the memory a retired `activation` left takes, holding by holding.
    /// Weights reserved apart from activations are not its to close.
    pub(super) fn closing(
        &self,
        activation: ModelActivationGeneration,
    ) -> Vec<(HoldingId, Closing)> {
        self.left_by(activation)
            .into_iter()
            .filter_map(|id| {
                let holding = self.holding(id).filter(|holding| !holding.weights)?;
                let promised = holding
                    .promised_to
                    .is_some_and(|(successor, _)| self.is_unretired(successor));
                match (holding.state, promised) {
                    (GpuReservationState::Released, _) => None,
                    (GpuReservationState::Releasing, _) => Some((id, Closing::Confirm)),
                    (GpuReservationState::Held, true) => Some((id, Closing::HandOver)),
                    (GpuReservationState::Held, false) => Some((id, Closing::Release)),
                }
            })
            .collect()
    }

    /// The reservations the ledger should still count for this model: every reservation
    /// of a holding not yet released (S2 CORE-03).
    pub(super) fn counted_reservations(&self) -> impl Iterator<Item = ReservationKey> + '_ {
        self.holdings
            .iter()
            .filter(|holding| holding.state != GpuReservationState::Released)
            .flat_map(|holding| holding.reservations.iter().copied())
    }

    /// Records where a holding's reservations stand. A holding no longer held passes to
    /// no successor.
    pub(super) fn set_holding_state(&mut self, holding: HoldingId, state: GpuReservationState) {
        if let Some(entry) = self.holding_mut(holding) {
            entry.state = state;
            if state != GpuReservationState::Held {
                entry.promised_to = None;
            }
        }
        self.refresh();
    }

    /// Passes a promised holding's reservations to the successor holding it was promised
    /// to (§3.6 line 597): the ledger keeps counting them, so no other request can take
    /// the share in between. Returns the successor when its handover is complete.
    pub(super) fn hand_over(&mut self, holding: HoldingId) -> Option<ModelActivationGeneration> {
        let (successor, target) = self.holding(holding)?.promised_to?;
        let reservations = match self.holding_mut(holding) {
            Some(entry) => {
                entry.promised_to = None;
                entry.state = GpuReservationState::Released;
                std::mem::take(&mut entry.reservations)
            }
            None => return None,
        };
        if let Some(entry) = self.holding_mut(target) {
            entry.reservations.extend(reservations);
            entry.awaiting.remove(&holding);
        }
        let complete = !self
            .holdings
            .iter()
            .any(|entry| entry.users.contains(&successor) && !entry.awaiting.is_empty());
        if complete {
            if let Ok(entry) = self.entry_mut(successor) {
                entry.awaiting_handover = None;
            }
        }
        self.refresh();
        complete.then_some(successor)
    }

    /// Every holding is returned, as when the parent's release was observed and closed
    /// its children.
    pub(super) fn mark_all_gpu_released(&mut self) {
        for holding in &mut self.holdings {
            holding.state = GpuReservationState::Released;
            holding.promised_to = None;
        }
        self.refresh();
    }

    /// How a lease bound to `activation` sees it.
    pub(super) fn view(&self, activation: ModelActivationGeneration) -> ActivationView {
        match self.activation(activation) {
            None => ActivationView::Unknown,
            Some(entry) => {
                let gpu_allocation = entry.generations.gpu_allocation;
                match entry.state {
                    ActivationState::Loading => ActivationView::Loading { gpu_allocation },
                    ActivationState::Active | ActivationState::Draining => {
                        ActivationView::Serving { gpu_allocation }
                    }
                    state => ActivationView::NotServing { state },
                }
            }
        }
    }

    /// Why a handle into allocation `generations.gpu_allocation`, as activation
    /// `generations.activation` uses it, is not honoured, if it is not.
    pub(super) fn handle_problem(&self, generations: ModelGenerations) -> Option<HandleProblem> {
        let Some(entry) = self.activation(generations.activation) else {
            return Some(HandleProblem::Stale);
        };
        let live = matches!(
            entry.state,
            ActivationState::Loading | ActivationState::Active | ActivationState::Draining
        );
        let holding = HoldingId::Gpu {
            allocation: generations.gpu_allocation,
        };
        if !live || !entry.holdings.contains(&holding) {
            return Some(HandleProblem::Stale);
        }
        match self.holding(holding) {
            Some(entry) if entry.state != GpuReservationState::Held => Some(HandleProblem::Stale),
            Some(entry) if !entry.is_backed() => Some(HandleProblem::AwaitingHandover),
            Some(_) => None,
            None => Some(HandleProblem::Stale),
        }
    }
}
