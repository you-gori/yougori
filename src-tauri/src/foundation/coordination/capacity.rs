//! The capacity port (S2 CORE-03 and CORE-04; S3.2; S10): what the coordination protocol
//! needs from the host reservation ledger, with typed refusals. The ledger adapter
//! implements it over the CORE-03 ledger; tests also use a fake with the same semantics.
//!
//! A reservation is made before its workload is created, and creation is announced
//! before it starts. Cancelling a reservation whose workload was created does not return
//! its amounts: they stay counted until a release is observed, by the host for a parent
//! and by the runtime for a child, so stopping work never yields false free capacity.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use super::identity::ModelId;
use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::{
    Digest, DigestBuilder, ExecutionId, GpuAllocationGeneration, GpuDeviceKey,
    ModelActivationGeneration, SandboxBootGeneration, TenantId,
};

/// The idempotency key of one reservation (S10: reserve before creating; reconcile after
/// a partial start).
///
/// It is derived from what the reservation is for, so the coordinator knows it before it
/// reserves, a retried request names the same reservation, and recovery can match the
/// ledger's reservations to its own records.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ReservationKey(Digest);

impl ReservationKey {
    /// The digest domain of reservation keys.
    pub const DOMAIN: &'static str = "yougori/coordination/reservation/v1";

    /// The key of the reservation `purpose` names under `execution`.
    pub fn derive(execution: &ExecutionId, purpose: &ReservationPurpose) -> Self {
        let builder = DigestBuilder::new(Self::DOMAIN).str(execution.as_str());
        let builder = match purpose {
            ReservationPurpose::Sandbox { boot } => builder.str("sandbox").u64(boot.get()),
            ReservationPurpose::ModelGpu {
                model,
                gpu_allocation,
            } => builder
                .str("model_gpu")
                .digest(&model.digest())
                .u64(gpu_allocation.get()),
            ReservationPurpose::ModelHost { model, activation } => builder
                .str("model_host")
                .digest(&model.digest())
                .u64(activation.get()),
        };
        Self(builder.finish())
    }

    /// A key read back from a record.
    pub(super) const fn from_digest(digest: Digest) -> Self {
        Self(digest)
    }

    /// The digest the key is made of.
    pub const fn digest(self) -> Digest {
        self.0
    }
}

impl fmt::Debug for ReservationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ReservationKey({})", self.0)
    }
}

impl fmt::Display for ReservationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// What a reservation is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "purpose", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum ReservationPurpose {
    /// Everything the host allocates to one boot of a VM sandbox. It is the parent of that
    /// boot's other reservations (CORE-03 parent/child budgets).
    Sandbox { boot: SandboxBootGeneration },
    /// GPU memory for one model allocation, charged within the sandbox reservation (S3.2:
    /// a model adapter requests reservations within the host's allocations).
    ModelGpu {
        model: ModelId,
        gpu_allocation: GpuAllocationGeneration,
    },
    /// Pageable and pinned host memory one model activation reserved, charged within the
    /// sandbox reservation.
    ModelHost {
        model: ModelId,
        activation: ModelActivationGeneration,
    },
}

crate::foundation::strict_serde::strict_tag!(ReservationPurpose, "purpose");

/// A resource the ledger accounts, with its unit in the name (CORE-03; S10 line 179).
/// GPU memory is counted per device.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    HostMemoryBytes,
    PinnedHostMemoryBytes,
    StorageBytes,
    StorageIoBytesPerSecond,
    NetworkSlots,
    CpuInitializationSlots,
    BurstVmRoots,
    SnapshotPages,
    GpuMemoryBytes { device: GpuDeviceKey },
    GpuLoadSlots { device: GpuDeviceKey },
}

impl fmt::Display for ResourceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HostMemoryBytes => f.write_str("host memory bytes"),
            Self::PinnedHostMemoryBytes => f.write_str("pinned host memory bytes"),
            Self::StorageBytes => f.write_str("storage bytes"),
            Self::StorageIoBytesPerSecond => f.write_str("storage I/O bytes per second"),
            Self::NetworkSlots => f.write_str("network slots"),
            Self::CpuInitializationSlots => f.write_str("CPU initialization slots"),
            Self::BurstVmRoots => f.write_str("burst VM roots"),
            Self::SnapshotPages => f.write_str("snapshot pages"),
            Self::GpuMemoryBytes { device } => {
                let hex = device.device.to_hex();
                write!(
                    f,
                    "GPU memory bytes of GPU {}",
                    hex.get(..12).unwrap_or(&hex)
                )
            }
            Self::GpuLoadSlots { device } => {
                let hex = device.device.to_hex();
                write!(
                    f,
                    "model load slots of GPU {}",
                    hex.get(..12).unwrap_or(&hex)
                )
            }
        }
    }
}

/// Whether an owner resource-return hold denies the reservation (S10 line 185). A child
/// has its parent's priority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationPriority {
    Background,
    Foreground,
}

/// One reservation request (CORE-03).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReservationRequest {
    pub key: ReservationKey,
    pub tenant: TenantId,
    pub execution: ExecutionId,
    pub purpose: ReservationPurpose,
    pub priority: ReservationPriority,
    /// The reservation a child is carved from; `None` for a parent.
    pub parent: Option<ReservationKey>,
    /// Amounts, each in its resource's unit.
    pub demand: BTreeMap<ResourceKind, u64>,
}

/// How a reservation request ended when it was not refused (S10: bounded queueing).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum ReserveOutcome {
    /// The capacity is reserved.
    Granted,
    /// The request waits in the ledger's bounded queue; reserving the same key again
    /// reports its progress.
    Queued { position: u32 },
}

crate::foundation::strict_serde::strict_tag!(ReserveOutcome, "outcome");

/// Whether retrying a refused request later can make progress (S10).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryProspect {
    /// A release, a host observation or the end of a hold can let it fit.
    CanProgress,
    /// The request exceeds what the host, the tenant's budget or the parent can ever
    /// provide.
    CannotProgress,
}

impl fmt::Display for RetryProspect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::CanProgress => "retrying later can make progress",
            Self::CannotProgress => "retrying cannot make progress",
        })
    }
}

/// Which limit a request ran into.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapacityLimit {
    /// The host's physical capacity, less its supervisor reserve and observed unmanaged
    /// use.
    Host,
    /// The tenant's budget, charged separately from physical capacity.
    TenantBudget,
}

/// Why the ledger refused (S10: the error names the limiting resource and whether a retry
/// can make progress).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum CapacityRefusal {
    /// The host or the tenant's budget does not have `requested` of `resource` free.
    Insufficient {
        resource: ResourceKind,
        limit: CapacityLimit,
        requested: u64,
        available: u64,
        retry: RetryProspect,
    },
    /// A child asks for more than its parent reservation has left (CORE-03 parent/child
    /// budgets).
    ExceedsParentBudget {
        parent: ReservationKey,
        resource: ResourceKind,
        requested: u64,
        remaining: u64,
        retry: RetryProspect,
    },
    /// The host has not observed this resource, or its observation is stale, so none of
    /// it is free; unknown usage is never counted as free (S2 CORE-03).
    NotObserved { resource: ResourceKind },
    /// An owner resource-return hold denies new background reservations of it (S10 line
    /// 185).
    OwnerReturnHold { resource: ResourceKind },
    /// The ledger's bounded queue is full.
    QueueFull { resource: ResourceKind },
    /// The named parent reservation is not open.
    UnknownParent { parent: ReservationKey },
    /// No open reservation has this key.
    UnknownReservation { key: ReservationKey },
    /// The key was reserved for a different request; a key never names other content.
    KeyConflict { key: ReservationKey },
    /// The observation that would close a reservation came from too weak a source: a
    /// parent's release needs the host, a child's at least its runtime (S3.2).
    SourceTooWeak {
        source: SourceClass,
        required: SourceClass,
    },
    /// Any other refusal of the ledger, as it described it.
    Refused { reason: String },
}

crate::foundation::strict_serde::strict_tag!(CapacityRefusal, "refusal");

impl CapacityRefusal {
    /// The resource that limited the request, when one did.
    pub fn limiting_resource(&self) -> Option<ResourceKind> {
        match self {
            Self::Insufficient { resource, .. }
            | Self::ExceedsParentBudget { resource, .. }
            | Self::NotObserved { resource }
            | Self::OwnerReturnHold { resource }
            | Self::QueueFull { resource } => Some(*resource),
            Self::UnknownParent { .. }
            | Self::UnknownReservation { .. }
            | Self::KeyConflict { .. }
            | Self::SourceTooWeak { .. }
            | Self::Refused { .. } => None,
        }
    }

    /// Whether retrying later can make progress.
    pub fn retry(&self) -> RetryProspect {
        match self {
            Self::Insufficient { retry, .. } | Self::ExceedsParentBudget { retry, .. } => *retry,
            Self::NotObserved { .. } | Self::OwnerReturnHold { .. } | Self::QueueFull { .. } => {
                RetryProspect::CanProgress
            }
            Self::UnknownParent { .. }
            | Self::UnknownReservation { .. }
            | Self::KeyConflict { .. }
            | Self::SourceTooWeak { .. }
            | Self::Refused { .. } => RetryProspect::CannotProgress,
        }
    }
}

impl fmt::Display for CapacityRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Insufficient {
                resource,
                limit,
                requested,
                available,
                retry,
            } => write!(
                f,
                "not enough {resource} under the {}: {requested} requested, {available} \
                 available; {retry}",
                match limit {
                    CapacityLimit::Host => "host's capacity",
                    CapacityLimit::TenantBudget => "tenant's budget",
                }
            ),
            Self::ExceedsParentBudget {
                parent,
                resource,
                requested,
                remaining,
                retry,
            } => write!(
                f,
                "{requested} {resource} exceeds the {remaining} left in parent reservation \
                 {parent}; {retry}"
            ),
            Self::NotObserved { resource } => write!(
                f,
                "the host has no current observation of {resource}, so none is free; {}",
                RetryProspect::CanProgress
            ),
            Self::OwnerReturnHold { resource } => write!(
                f,
                "the owner is taking {resource} back, so new background work is denied; {}",
                RetryProspect::CanProgress
            ),
            Self::QueueFull { resource } => write!(
                f,
                "the queue for {resource} is full; {}",
                RetryProspect::CanProgress
            ),
            Self::UnknownParent { parent } => write!(f, "parent reservation {parent} is not open"),
            Self::UnknownReservation { key } => write!(f, "reservation {key} is not open"),
            Self::KeyConflict { key } => write!(
                f,
                "reservation {key} was made for a different request; a key never names other \
                 content"
            ),
            Self::SourceTooWeak { source, required } => write!(
                f,
                "a release reported by a {source} cannot close it; it needs a {required}"
            ),
            Self::Refused { reason } => write!(f, "the ledger refused: {reason}"),
        }
    }
}

impl std::error::Error for CapacityRefusal {}

/// What cancelling or confirming a release did. Both are idempotent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseOutcome {
    /// The amounts returned now.
    Released,
    /// The workload was created, so its amounts stay counted until its release is
    /// observed (S10 line 185: stopping work does not free its allocations).
    Pending,
    /// Nothing is open under the key, such as after an earlier release.
    NotHeld,
}

/// The ledger compared with what the coordinator expects for one execution (S10:
/// reconcile after a partial start; VM part §6.1: recovery reconciles actual resources).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconcileReport {
    /// Expected and open.
    pub confirmed: BTreeSet<ReservationKey>,
    /// Expected but not open.
    pub missing: BTreeSet<ReservationKey>,
    /// Open but no longer expected, never created, and now returned.
    pub released_orphans: BTreeSet<ReservationKey>,
    /// Open but no longer expected, with a created workload: cancelled and counted until
    /// their release is observed.
    pub pending_orphans: BTreeSet<ReservationKey>,
}

/// What cancelling every reservation of an execution did (INT-02).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionCancellation {
    /// Reservations never created, returned now.
    pub released: usize,
    /// Reservations with a created workload, counted until their release is observed.
    pub pending: usize,
    /// Queued requests withdrawn.
    pub dequeued: usize,
}

/// An owner resource-return hold in force (S10 line 185).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ReturnHold(u64);

impl ReturnHold {
    /// A hold numbered by the port that began it.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// The hold number.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// What the coordination protocol needs from the host reservation ledger (S2 CORE-03,
/// CORE-04).
///
/// The ledger counts physical capacity once and charges children within their parent.
/// Every refusal is typed and names what limited it.
pub trait CapacityPort {
    /// Reserves `request.demand` under `request.key` before the workload is created.
    /// Reserving the same key with the same request again returns the same outcome; with
    /// a different request it is refused.
    fn reserve(&mut self, request: &ReservationRequest) -> Result<ReserveOutcome, CapacityRefusal>;

    /// Creation of the reserved workload starts now. From here its amounts return only
    /// through an observed release. A child's parent must already be created. Idempotent.
    fn begin_create(&mut self, key: &ReservationKey) -> Result<(), CapacityRefusal>;

    /// Cancels the reservation and its children: amounts never created return now, those
    /// of a created workload stay counted until their release is observed. Idempotent.
    fn release(&mut self, key: &ReservationKey) -> Result<ReleaseOutcome, CapacityRefusal>;

    /// The release of the reservation's workload, and of its children's, was observed by
    /// `source`: the host for a parent, at least the runtime for a child. Idempotent.
    fn confirm_release(
        &mut self,
        key: &ReservationKey,
        source: SourceClass,
    ) -> Result<ReleaseOutcome, CapacityRefusal>;

    /// Cancels every reservation and queued request of `execution`, whoever made them, as
    /// on revocation (INT-02). Created workloads stay counted until their release is
    /// observed.
    fn cancel_execution(
        &mut self,
        execution: &ExecutionId,
    ) -> Result<ExecutionCancellation, CapacityRefusal>;

    /// Compares the reservations open for `execution` with `expected`, and cancels every
    /// open one that is not expected, with its children.
    fn reconcile(
        &mut self,
        execution: &ExecutionId,
        expected: &BTreeSet<ReservationKey>,
    ) -> Result<ReconcileReport, CapacityRefusal>;

    /// Begins an owner resource-return hold: new background reservations of `resources`
    /// are denied until it ends, while existing ones drain (S10 line 185).
    fn begin_hold(
        &mut self,
        resources: &BTreeSet<ResourceKind>,
    ) -> Result<ReturnHold, CapacityRefusal>;

    /// Ends a hold. Idempotent.
    fn end_hold(&mut self, hold: ReturnHold) -> Result<(), CapacityRefusal>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::digest;

    fn execution(name: &str) -> ExecutionId {
        ExecutionId::new(name).unwrap()
    }

    #[test]
    fn keys_differ_by_execution_purpose_and_generation() {
        let model = ModelId::new(digest("yougori/test/model/v1", &[b"m"]));
        let first = ReservationPurpose::Sandbox {
            boot: SandboxBootGeneration::FIRST,
        };
        let second = ReservationPurpose::Sandbox {
            boot: SandboxBootGeneration::new(2),
        };
        let gpu = ReservationPurpose::ModelGpu {
            model,
            gpu_allocation: GpuAllocationGeneration::FIRST,
        };
        let keys = [
            ReservationKey::derive(&execution("exe-a"), &first),
            ReservationKey::derive(&execution("exe-a"), &second),
            ReservationKey::derive(&execution("exe-b"), &first),
            ReservationKey::derive(&execution("exe-a"), &gpu),
        ];
        let distinct: BTreeSet<ReservationKey> = keys.iter().copied().collect();
        assert_eq!(distinct.len(), keys.len());
        assert_eq!(
            ReservationKey::derive(&execution("exe-a"), &first),
            keys[0],
            "a key is a pure function of what it is for"
        );
        assert_eq!(ReservationKey::from_digest(keys[3].digest()), keys[3]);
    }

    #[test]
    fn refusals_name_the_limiting_resource_and_retry_prospect() {
        let key = ReservationKey::derive(
            &execution("exe-a"),
            &ReservationPurpose::Sandbox {
                boot: SandboxBootGeneration::FIRST,
            },
        );
        let short = CapacityRefusal::Insufficient {
            resource: ResourceKind::HostMemoryBytes,
            limit: CapacityLimit::Host,
            requested: 8,
            available: 4,
            retry: RetryProspect::CanProgress,
        };
        assert_eq!(
            short.limiting_resource(),
            Some(ResourceKind::HostMemoryBytes)
        );
        assert_eq!(short.retry(), RetryProspect::CanProgress);
        let message = short.to_string();
        assert!(message.contains("host memory bytes"), "{message}");
        assert!(
            message.contains("retrying later can make progress"),
            "{message}"
        );

        let device = GpuDeviceKey {
            machine: digest("yougori/test/machine/v1", &[b"host"]),
            device: digest("yougori/test/device/v1", &[b"gpu0"]),
        };
        let never = CapacityRefusal::ExceedsParentBudget {
            parent: key,
            resource: ResourceKind::GpuMemoryBytes { device },
            requested: 10,
            remaining: 2,
            retry: RetryProspect::CannotProgress,
        };
        assert_eq!(
            never.limiting_resource(),
            Some(ResourceKind::GpuMemoryBytes { device })
        );
        assert!(never.to_string().contains("retrying cannot make progress"));
        assert_eq!(
            CapacityRefusal::KeyConflict { key }.retry(),
            RetryProspect::CannotProgress
        );
        assert_eq!(
            CapacityRefusal::OwnerReturnHold {
                resource: ResourceKind::HostMemoryBytes
            }
            .retry(),
            RetryProspect::CanProgress
        );

        let json = serde_json::to_value(&never).unwrap();
        assert_eq!(json["refusal"], "exceeds_parent_budget");
        assert_eq!(
            serde_json::from_value::<CapacityRefusal>(json).unwrap(),
            never
        );
    }
}
