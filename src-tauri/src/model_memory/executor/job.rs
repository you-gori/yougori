//! What a caller submits and what it can observe about a job (GPU §3.5).

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::error::JobFailure;
use super::model::{Destination, LoaderPermissions, Priority, Stage};
use super::network::SourceGrant;
use crate::foundation::ids::{AuthorizationEpoch, ContentKey, ExecutionId, OperationId, TenantId};
use crate::foundation::ledger;
use crate::model_memory::math::prefetch::PrefetchValue;

/// A dependency inside a job, such as a tensor or a layer: a node of the request state
/// graph (GPU §2.3) that becomes usable as a whole.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DependencyId(pub u64);

impl fmt::Display for DependencyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "dependency {}", self.0)
    }
}

/// A dependency: the extents it needs and the dependencies that must be usable first.
/// It is published only after every extent's chain and every prerequisite completed
/// (§3.5 step 7).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DependencySpec {
    pub id: DependencyId,
    /// Extent indices in the manifest.
    pub extents: Vec<u64>,
    pub requires: Vec<DependencyId>,
}

/// Whether a job serves a request now or a prediction (GPU §2.9).
#[derive(Clone, Debug, PartialEq)]
pub enum JobPriority {
    Foreground,
    /// Admitted only with a positive expected value, within the speculative budget and
    /// outside the foreground reserve. `value.bytes` must equal the job's decoded bytes.
    Speculative {
        value: PrefetchValue,
    },
}

impl JobPriority {
    /// The scheduling priority: foreground or speculative.
    pub fn priority(&self) -> Priority {
        match self {
            Self::Foreground => Priority::Foreground,
            Self::Speculative { .. } => Priority::Speculative,
        }
    }
}

/// One transfer job: load these dependencies of one representation into one
/// destination.
#[derive(Clone, Debug, PartialEq)]
pub struct TransferRequest {
    /// Names the job; unique among the jobs the executor knows.
    pub operation: OperationId,
    pub execution: ExecutionId,
    pub tenant: TenantId,
    /// The artifact's content key.
    pub artifact: ContentKey,
    /// The content key of the representation to read.
    pub representation: ContentKey,
    pub destination: Destination,
    pub dependencies: Vec<DependencySpec>,
    pub priority: JobPriority,
    /// Gated read methods, from the evidence gate's plan for this runtime
    /// ([`LoaderPermissions::from_runtime`]).
    pub loader: LoaderPermissions,
}

/// How a job is submitted beyond its request ([`super::TransferExecutor::submit_with`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SubmitOptions {
    /// The reservation each new destination reservation is carved from, such as the
    /// placement's (P04; CORE-03 parent and child).
    pub within: Option<ledger::ReservationId>,
    /// CORE-05 grants for the job's reads from network sources (GPU-W09).
    pub transfers: Vec<SourceGrant>,
}

/// Why a job was cancelled.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CancelReason {
    /// The caller cancelled.
    Requested,
    /// Scheduling fell back to demand-only (GPU §2.9).
    DemandOnly,
    /// The job's execution was revoked; `revoked` is the epoch no longer honoured
    /// (INT-02, VM part §6.3).
    Revoked { revoked: AuthorizationEpoch },
}

/// Where a job is.
#[derive(Clone, Debug, PartialEq)]
pub enum JobStatus {
    Running,
    /// Every dependency is usable.
    Completed,
    Failed {
        failure: JobFailure,
    },
    Cancelled {
        reason: CancelReason,
    },
}

impl JobStatus {
    /// Whether the job can still make progress.
    pub fn is_running(&self) -> bool {
        matches!(self, Self::Running)
    }
}

/// Totals of one measured stage (§3.5 step 9).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageTotal {
    /// How many measurements.
    pub count: u64,
    pub bytes: u64,
    pub duration: Duration,
}

/// A job's progress without its stage totals.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgressSnapshot {
    /// Decoded bytes the job needs.
    pub total_bytes: u64,
    /// Decoded bytes whose identity was validated.
    pub verified_bytes: u64,
    /// Decoded bytes whose completion event was observed.
    pub committed_bytes: u64,
    pub usable_dependencies: usize,
    pub total_dependencies: usize,
}

/// A job's progress with measured stage durations (§3.5 step 9).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct JobProgress {
    pub snapshot: ProgressSnapshot,
    pub stages: BTreeMap<Stage, StageTotal>,
}

impl JobProgress {
    pub(super) fn add_stage(&mut self, stage: Stage, bytes: u64, duration: Duration) {
        let total = self.stages.entry(stage).or_default();
        total.count = total.count.saturating_add(1);
        total.bytes = total.bytes.saturating_add(bytes);
        total.duration = total.duration.saturating_add(duration);
    }
}
