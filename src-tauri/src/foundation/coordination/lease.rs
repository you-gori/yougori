//! Child work and leases (S2 CORE-04; S3.1; VM part §6.2–§6.3).
//!
//! Child operations run under their parent execution. Every lease carries the sandbox
//! generations it was issued under, model leases also the model generations, and an
//! expiry on the shared monotonic clock. A lease is honoured only while each of those
//! generations is current and the parent still holds unexpired authority. Renewal follows
//! the rules on [`LeaseTerms`]: it never revives an expired, cancelled or stale lease,
//! never passes the lease's maximum lifetime and never passes the parent's authority.
//! A lease may also be issued under grants of the parent's authority; revoking one of
//! them cancels it, and it is never honoured again (CORE-04 per-grant revocation).

use std::cmp::min;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::identity::{ModelGenerations, ModelId, SandboxGenerations};
use super::model::ActivationState;
use super::sandbox::SandboxState;
use crate::foundation::evidence::{AuthorityGrant, ClockSession};
use crate::foundation::ids::{
    AuthorizationEpoch, ExecutionId, GpuAllocationGeneration, GrantId, LeaseId,
    ModelActivationGeneration, MonotonicTime, OperationId, PolicyEpoch, SandboxBootGeneration,
};

/// What a lease authorizes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseKind {
    /// Child work of the parent execution.
    ChildWork,
    /// A transfer such as a weight load, prefetch or download (INT-02).
    Transfer,
    /// A service or session lease (INT-03).
    Service,
    /// One model request, bound to the activation that admitted it (INT-03).
    ModelRequest,
    /// The one pending request explicitly assigned to an activation being prepared,
    /// for execute-while-load (GPU part §3.6 line 601). It is honoured from preparation
    /// through serving, and for no other request.
    Preparation,
}

/// How long a lease lasts and how it renews (VM part §6.2: bounded authority and resource
/// leases; §6.3: leases with explicit maximum staleness).
///
/// Renewal rules: a renewal moves the expiry to `term` from now, but never past
/// `max_lifetime` after issue and never past the parent's authority expiry. Only an
/// unexpired, uncancelled lease whose every generation is still current renews.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseTerms {
    /// How far an issue or a renewal extends the lease from now.
    pub term: Duration,
    /// The longest the lease lasts after issue, however often it renews.
    pub max_lifetime: Duration,
    /// The declared bound within which the holder stops after a cancellation or a
    /// revocation (INT-02: leases cancel by declared bounds).
    pub cancel_within: Duration,
}

impl LeaseTerms {
    /// Refuses a zero term and a maximum lifetime shorter than one term.
    pub fn check(&self) -> Result<(), TermsProblem> {
        if self.term.is_zero() {
            return Err(TermsProblem::ZeroTerm);
        }
        if self.max_lifetime < self.term {
            return Err(TermsProblem::LifetimeShorterThanTerm);
        }
        Ok(())
    }
}

/// Why lease terms were refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TermsProblem {
    ZeroTerm,
    LifetimeShorterThanTerm,
}

/// The model activation a model lease is bound to (INT-03).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelBinding {
    pub model: ModelId,
    pub generations: ModelGenerations,
}

/// One lease (S2 CORE-04; S3.1). Only the coordinator issues leases; a copy shows what was
/// issued, and enforcement points check the lease number with the coordinator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lease {
    id: LeaseId,
    parent: ExecutionId,
    operation: OperationId,
    kind: LeaseKind,
    sandbox: SandboxGenerations,
    model: Option<ModelBinding>,
    /// The grants of the parent's authority the lease was issued under.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    grants: BTreeSet<GrantId>,
    terms: LeaseTerms,
    clock: ClockSession,
    issued_at: MonotonicTime,
    expires_at: MonotonicTime,
    renewals: u32,
}

impl Lease {
    /// The shared execution lease id.
    pub fn id(&self) -> LeaseId {
        self.id
    }

    /// The parent execution the child work runs under.
    pub fn parent(&self) -> &ExecutionId {
        &self.parent
    }

    /// The child operation.
    pub fn operation(&self) -> &OperationId {
        &self.operation
    }

    /// What the lease authorizes.
    pub fn kind(&self) -> LeaseKind {
        self.kind
    }

    /// The parent's generations when the lease was issued.
    pub fn sandbox(&self) -> SandboxGenerations {
        self.sandbox
    }

    /// The model activation a model lease is bound to.
    pub fn model(&self) -> Option<ModelBinding> {
        self.model
    }

    /// The grants of the parent's authority the lease was issued under, such as a route
    /// or a scoped delegation; revoking any of them cancels the lease (CORE-04 per-grant
    /// revocation). Empty for a lease that needs no grant beyond the authority itself.
    pub fn grants(&self) -> &BTreeSet<GrantId> {
        &self.grants
    }

    /// How it lasts and renews.
    pub fn terms(&self) -> LeaseTerms {
        self.terms
    }

    /// The clock session its times are points on; times on another session, such as
    /// before a restart, are never compared.
    pub fn clock(&self) -> ClockSession {
        self.clock
    }

    /// When it was issued.
    pub fn issued_at(&self) -> MonotonicTime {
        self.issued_at
    }

    /// When it ends unless renewed.
    pub fn expires_at(&self) -> MonotonicTime {
        self.expires_at
    }

    /// The latest the lease can ever reach: `max_lifetime` after issue.
    pub fn deadline(&self) -> MonotonicTime {
        self.issued_at.saturating_add(self.terms.max_lifetime)
    }

    /// How often it was renewed.
    pub fn renewals(&self) -> u32 {
        self.renewals
    }
}

/// Why a lease was cancelled.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CancelCause {
    /// The parent's authorization was revoked (INT-02).
    Revocation,
    /// The parent's policy epoch advanced (S3.1).
    PolicyChange,
    /// The parent booted again (S7 line 125: fresh lease epochs).
    NewBoot,
    /// The owner is taking the resource back (S10 line 185).
    ResourceReturn,
    /// A grant the lease depends on was revoked: one it was issued under, or a network
    /// grant its activation's settings use. The parent's authorization epoch and its
    /// other grants stay in force (CORE-04 per-grant revocation).
    GrantRevoked,
}

impl fmt::Display for CancelCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Revocation => "the parent's authorization was revoked",
            Self::PolicyChange => "the parent's policy changed",
            Self::NewBoot => "the parent booted again",
            Self::ResourceReturn => "the owner is taking the resource back",
            Self::GrantRevoked => "a grant the lease depends on was revoked",
        })
    }
}

/// Where a lease is in its life.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum LeaseState {
    Active,
    /// The holder released it.
    Released {
        at: MonotonicTime,
    },
    /// Cancellation was requested; the holder stops by `bound_at` (INT-02).
    Cancelling {
        cause: CancelCause,
        requested_at: MonotonicTime,
        bound_at: MonotonicTime,
    },
    /// The holder acknowledged the cancellation.
    Cancelled {
        cause: CancelCause,
        requested_at: MonotonicTime,
        acknowledged_at: MonotonicTime,
    },
    /// Recorded before a crash; recovery never revives it (INT-04).
    NotRevived,
}

crate::foundation::strict_serde::strict_tag!(LeaseState, "state");

/// A lease and where it is in its life.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseRecord {
    lease: Lease,
    state: LeaseState,
}

impl LeaseRecord {
    /// The lease as issued or last renewed.
    pub fn lease(&self) -> &Lease {
        &self.lease
    }

    /// Where the lease is in its life.
    pub fn state(&self) -> LeaseState {
        self.state
    }

    /// Whether the holder may still be acting at `now`: active or cancelling without an
    /// acknowledgment, and not yet expired. Resources such a lease uses are not reclaimed.
    pub fn may_be_in_use(&self, now: MonotonicTime) -> bool {
        matches!(
            self.state,
            LeaseState::Active | LeaseState::Cancelling { .. }
        ) && now < self.lease.expires_at
    }
}

/// One lease's cancellation, with its declared bound (INT-02; VM part §6.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseCancellation {
    pub lease: LeaseId,
    pub kind: LeaseKind,
    pub requested_at: MonotonicTime,
    /// When the holder must have stopped: `cancel_within` after the request, or the
    /// lease's expiry if that is sooner.
    pub bound_at: MonotonicTime,
    pub expires_at: MonotonicTime,
}

/// Which renewal limit was reached.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RenewalLimit {
    /// The lease's maximum lifetime after issue.
    MaxLifetime,
    /// The parent's authority expiry; a renewal never extends authority.
    AuthorityExpiry,
}

/// Why a lease was not issued, honoured or renewed (S2 CORE-04; S3.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum LeaseRefusal {
    UnknownLease {
        lease: LeaseId,
    },
    UnknownExecution {
        execution: ExecutionId,
    },
    InvalidTerms {
        problem: TermsProblem,
    },
    /// A model request lease comes only from admission to an activation.
    NeedsModelAdmission,
    /// The parent holds no authority in this state; nothing external is exposed before
    /// authority_active (VM part §6.1).
    NoAuthority {
        state: SandboxState,
    },
    AuthorityExpired {
        expired_at: MonotonicTime,
    },
    /// The parent denies new work while its owner takes a resource back (S10 line 185).
    NewWorkDenied {
        execution: ExecutionId,
    },
    Released,
    Cancelled {
        cause: CancelCause,
    },
    /// Only a cancelling lease can be acknowledged.
    NotCancelling,
    /// Recorded before a crash; recovery never revives it (INT-04).
    NotRevived,
    Expired {
        expired_at: MonotonicTime,
    },
    /// The lease or the parent's authority was stamped on another clock session, such as
    /// before a restart; its times cannot be compared, so it is not honoured.
    OtherClock,
    /// The parent booted again, such as from a snapshot; a restored identity never
    /// revives a lease (S2 CORE-04).
    StaleBootGeneration {
        bound: SandboxBootGeneration,
        current: SandboxBootGeneration,
    },
    /// The parent's authorization epoch advanced (INT-02).
    RevokedAuthorization {
        bound: AuthorizationEpoch,
        current: AuthorizationEpoch,
    },
    StalePolicyEpoch {
        bound: PolicyEpoch,
        current: PolicyEpoch,
    },
    /// The activation the lease is bound to does not serve (INT-03).
    ActivationNotServing {
        activation: ModelActivationGeneration,
        state: Option<ActivationState>,
    },
    /// The GPU allocation the lease is bound to was replaced (INT-04).
    StaleGpuAllocation {
        bound: GpuAllocationGeneration,
        current: Option<GpuAllocationGeneration>,
    },
    RenewalLimitReached {
        limit: RenewalLimit,
        expires_at: MonotonicTime,
    },
    LeaseIdsExhausted,
    /// The clock reads earlier than a reading the coordinator already took on this clock
    /// session. Until it passes that high-water mark again no lease is issued, honoured or
    /// renewed, so a clock going backward never extends a lease nor revives an expired one
    /// (VM part §6.2).
    ClockWentBack {
        now: MonotonicTime,
        high_water: MonotonicTime,
    },
    /// No lease id at or above `limit` is issued until a persisted state recording a
    /// higher mark is confirmed, so recovery never hands out an id that may still be held
    /// (VM part §6.3: persist replay protection across restarts).
    LeaseIdsNotPersisted {
        limit: LeaseId,
    },
    /// The GPU allocation waits for a drain-first handover; until the predecessor's
    /// memory passes to it, it must not be used (GPU part §3.6 line 597).
    AllocationAwaitingHandover {
        allocation: GpuAllocationGeneration,
    },
    /// A grant the work depends on was revoked under the parent's authority, and is never
    /// honoured there again: one the lease is issued under, or a network grant its
    /// activation's settings use (CORE-04 per-grant revocation; VM part §6.3 step 1).
    GrantRevoked {
        grant: GrantId,
    },
}

crate::foundation::strict_serde::strict_tag!(LeaseRefusal, "refusal");

impl fmt::Display for LeaseRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownLease { lease } => write!(f, "lease {lease} is unknown"),
            Self::UnknownExecution { execution } => write!(f, "execution {execution} is unknown"),
            Self::InvalidTerms { problem } => match problem {
                TermsProblem::ZeroTerm => f.write_str("a lease term must be longer than zero"),
                TermsProblem::LifetimeShorterThanTerm => {
                    f.write_str("a lease's maximum lifetime must be at least one term")
                }
            },
            Self::NeedsModelAdmission => {
                f.write_str("a model request lease comes only from admission to an activation")
            }
            Self::NoAuthority { state } => write!(
                f,
                "the parent holds no authority while {state}; nothing is exposed before \
                 authority_active"
            ),
            Self::AuthorityExpired { expired_at } => write!(
                f,
                "the parent's authority expired at {} ns",
                expired_at.as_nanos()
            ),
            Self::NewWorkDenied { execution } => write!(
                f,
                "{execution} denies new work while its owner takes the resource back"
            ),
            Self::Released => f.write_str("the lease was released"),
            Self::Cancelled { cause } => write!(f, "the lease was cancelled: {cause}"),
            Self::NotCancelling => f.write_str("the lease is not being cancelled"),
            Self::NotRevived => {
                f.write_str("the lease was issued before a crash, and recovery never revives it")
            }
            Self::Expired { expired_at } => {
                write!(f, "the lease expired at {} ns", expired_at.as_nanos())
            }
            Self::OtherClock => f.write_str(
                "the lease or the parent's authority is from another clock session, such as \
                 before a restart",
            ),
            Self::StaleBootGeneration { bound, current } => write!(
                f,
                "the lease is bound to boot generation {bound}, but the parent is at {current}; \
                 a restored identity never revives a lease"
            ),
            Self::RevokedAuthorization { bound, current } => write!(
                f,
                "the lease is bound to authorization epoch {bound}, which was revoked; the \
                 parent is at {current}"
            ),
            Self::StalePolicyEpoch { bound, current } => write!(
                f,
                "the lease is bound to policy epoch {bound}, but the parent is at {current}"
            ),
            Self::ActivationNotServing { activation, state } => match state {
                Some(state) => write!(f, "activation generation {activation} is {state}"),
                None => write!(f, "activation generation {activation} is unknown"),
            },
            Self::StaleGpuAllocation { bound, current } => match current {
                Some(current) => write!(
                    f,
                    "GPU allocation generation {bound} is stale; the current one is {current}"
                ),
                None => write!(f, "GPU allocation generation {bound} is stale"),
            },
            Self::RenewalLimitReached { limit, .. } => match limit {
                RenewalLimit::MaxLifetime => {
                    f.write_str("the lease has reached its maximum lifetime")
                }
                RenewalLimit::AuthorityExpiry => f.write_str(
                    "the lease has reached the parent's authority expiry; renewal never \
                     extends authority",
                ),
            },
            Self::LeaseIdsExhausted => f.write_str("no lease numbers are left"),
            Self::ClockWentBack { now, high_water } => write!(
                f,
                "the clock reads {} ns, earlier than the {} ns it already read; no lease is \
                 honoured until it passes that again",
                now.as_nanos(),
                high_water.as_nanos()
            ),
            Self::LeaseIdsNotPersisted { limit } => write!(
                f,
                "lease number {limit} and above are issued only after the coordinator's state \
                 is persisted again"
            ),
            Self::AllocationAwaitingHandover { allocation } => write!(
                f,
                "GPU allocation generation {allocation} waits for its predecessor's memory"
            ),
            Self::GrantRevoked { grant } => write!(
                f,
                "grant {grant} was revoked under the parent's authority and is never \
                 honoured there again"
            ),
        }
    }
}

impl std::error::Error for LeaseRefusal {}

/// What a lease is checked against, read through the adapters: the parent's state,
/// generations and authority, and for a model lease the bound activation.
#[derive(Clone, Copy, Debug)]
pub(super) struct LeaseContext {
    /// The coordinator's clock session now.
    pub(super) clock: ClockSession,
    pub(super) state: SandboxState,
    pub(super) generations: SandboxGenerations,
    pub(super) authority: Option<AuthorityGrant>,
    pub(super) activation: Option<ActivationView>,
}

/// One activation as a lease sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ActivationView {
    /// Loading into its allocation; it holds the allocation but admits nothing.
    Loading {
        gpu_allocation: GpuAllocationGeneration,
    },
    /// Serving requests from its allocation.
    Serving {
        gpu_allocation: GpuAllocationGeneration,
    },
    /// Reclaiming or retired.
    NotServing {
        state: ActivationState,
    },
    Unknown,
}

/// What a new lease is for.
#[derive(Clone, Debug)]
pub(super) struct LeaseRequest {
    pub(super) parent: ExecutionId,
    pub(super) operation: OperationId,
    pub(super) kind: LeaseKind,
    pub(super) model: Option<ModelBinding>,
    /// The grants the lease is issued under.
    pub(super) grants: BTreeSet<GrantId>,
    /// A grant the lease would depend on that was revoked under the parent: the lease is
    /// refused after the parent's and the activation's checks.
    pub(super) revoked_grant: Option<GrantId>,
    pub(super) terms: LeaseTerms,
}

/// The authority the parent holds at `now`, or why it holds none.
pub(super) fn parent_authority(
    context: &LeaseContext,
    now: MonotonicTime,
) -> Result<AuthorityGrant, LeaseRefusal> {
    let no_authority = LeaseRefusal::NoAuthority {
        state: context.state,
    };
    if !context.state.holds_authority() {
        return Err(no_authority);
    }
    let authority = context.authority.ok_or(no_authority)?;
    if authority.clock != context.clock {
        return Err(LeaseRefusal::OtherClock);
    }
    if authority.epoch != context.generations.authorization {
        return Err(LeaseRefusal::RevokedAuthorization {
            bound: authority.epoch,
            current: context.generations.authorization,
        });
    }
    if now >= authority.expires_at {
        return Err(LeaseRefusal::AuthorityExpired {
            expired_at: authority.expires_at,
        });
    }
    Ok(authority)
}

/// Whether the activation a model lease is bound to honours it: a serving activation for
/// every model lease, and one being prepared only for a preparation lease (GPU part §3.6
/// line 601).
fn activation_serves(
    context: &LeaseContext,
    binding: ModelBinding,
    kind: LeaseKind,
) -> Result<(), LeaseRefusal> {
    let activation = binding.generations.activation;
    let bound = binding.generations.gpu_allocation;
    match context.activation {
        Some(ActivationView::Serving { gpu_allocation }) if gpu_allocation == bound => Ok(()),
        Some(ActivationView::Loading { gpu_allocation })
            if kind == LeaseKind::Preparation && gpu_allocation == bound =>
        {
            Ok(())
        }
        Some(ActivationView::Serving { gpu_allocation }) => Err(LeaseRefusal::StaleGpuAllocation {
            bound,
            current: Some(gpu_allocation),
        }),
        Some(ActivationView::Loading { gpu_allocation }) if kind == LeaseKind::Preparation => {
            Err(LeaseRefusal::StaleGpuAllocation {
                bound,
                current: Some(gpu_allocation),
            })
        }
        Some(ActivationView::Loading { .. }) => Err(LeaseRefusal::ActivationNotServing {
            activation,
            state: Some(ActivationState::Loading),
        }),
        Some(ActivationView::NotServing { state }) => Err(LeaseRefusal::ActivationNotServing {
            activation,
            state: Some(state),
        }),
        Some(ActivationView::Unknown) | None => Err(LeaseRefusal::ActivationNotServing {
            activation,
            state: None,
        }),
    }
}

/// Whether `record` is honoured at `now` (S3.1: every bound generation must be current).
pub(super) fn check(
    record: &LeaseRecord,
    now: MonotonicTime,
    context: &LeaseContext,
) -> Result<(), LeaseRefusal> {
    match record.state {
        LeaseState::Active => {}
        LeaseState::Released { .. } => return Err(LeaseRefusal::Released),
        LeaseState::Cancelling { cause, .. } | LeaseState::Cancelled { cause, .. } => {
            return Err(LeaseRefusal::Cancelled { cause })
        }
        LeaseState::NotRevived => return Err(LeaseRefusal::NotRevived),
    }
    let lease = &record.lease;
    if lease.clock != context.clock {
        return Err(LeaseRefusal::OtherClock);
    }
    if now >= lease.expires_at {
        return Err(LeaseRefusal::Expired {
            expired_at: lease.expires_at,
        });
    }
    let (bound, current) = (lease.sandbox, context.generations);
    if bound.boot != current.boot {
        return Err(LeaseRefusal::StaleBootGeneration {
            bound: bound.boot,
            current: current.boot,
        });
    }
    if bound.authorization != current.authorization {
        return Err(LeaseRefusal::RevokedAuthorization {
            bound: bound.authorization,
            current: current.authorization,
        });
    }
    if bound.policy != current.policy {
        return Err(LeaseRefusal::StalePolicyEpoch {
            bound: bound.policy,
            current: current.policy,
        });
    }
    parent_authority(context, now)?;
    if let Some(binding) = lease.model {
        activation_serves(context, binding, lease.kind)?;
    }
    Ok(())
}

/// How far above the next lease id a persisted state's high-water mark lies: the ids a
/// coordinator may issue before its state must be persisted again (VM part §6.3).
pub(super) const LEASE_IDS_PER_PERSIST: u64 = 1 << 20;

/// Every lease the coordinator issued, by its shared execution lease id (ids.rs), issued
/// in order and never reused, across recovery too (VM part §6.3: never reuse an identity
/// while old capabilities can exist; persist replay protection across restarts).
///
/// Ids stay below a limit: the high-water mark of the latest persisted state confirmed
/// durable, or a fresh table's first allowance. Recovery starts at the mark the state
/// recorded, above every id issued since it was taken, and issues nothing until a new
/// state is confirmed.
#[derive(Clone, Debug)]
pub(super) struct LeaseTable {
    next: LeaseId,
    limit: LeaseId,
    records: BTreeMap<LeaseId, LeaseRecord>,
}

impl LeaseTable {
    /// A table for a coordinator with no earlier run: it may issue its first allowance
    /// before its state is first persisted.
    pub(super) fn new() -> Self {
        Self {
            next: LeaseId::FIRST,
            limit: LeaseId::new(LeaseId::FIRST.get().saturating_add(LEASE_IDS_PER_PERSIST)),
            records: BTreeMap::new(),
        }
    }

    /// A table restored after a crash: ids continue at the persisted high-water `mark`
    /// and after every recorded id, and every lease still active or cancelling is marked
    /// not revived (INT-04). Returns those. Nothing is issued until a new persisted state
    /// is confirmed, so a second crash cannot hand out the same ids again.
    pub(super) fn restored(mark: LeaseId, records: Vec<LeaseRecord>) -> (Self, Vec<LeaseId>) {
        let mut not_revived = Vec::new();
        let mut table = Self {
            next: mark.max(LeaseId::FIRST),
            limit: LeaseId::FIRST,
            records: BTreeMap::new(),
        };
        for mut record in records {
            let id = record.lease.id;
            if matches!(
                record.state,
                LeaseState::Active | LeaseState::Cancelling { .. }
            ) {
                record.state = LeaseState::NotRevived;
                not_revived.push(id);
            }
            if id >= table.next {
                table.next = id.next().unwrap_or(id);
            }
            table.records.insert(id, record);
        }
        table.limit = table.next;
        (table, not_revived)
    }

    /// The high-water mark to persist now: every id issued so far is below it, and none
    /// at or above it is issued until a state recording it, or a later one, is confirmed.
    pub(super) fn high_water_mark(&self) -> LeaseId {
        LeaseId::new(self.next.get().saturating_add(LEASE_IDS_PER_PERSIST)).max(self.limit)
    }

    /// The persisted state recording `mark` is durable: ids below it may be issued.
    pub(super) fn confirm_persisted(&mut self, mark: LeaseId) {
        self.limit = self.limit.max(mark);
    }

    /// No id at or above this is issued now.
    pub(super) fn limit(&self) -> LeaseId {
        self.limit
    }

    pub(super) fn get(&self, lease: LeaseId) -> Option<&LeaseRecord> {
        self.records.get(&lease)
    }

    pub(super) fn records(&self) -> impl Iterator<Item = &LeaseRecord> {
        self.records.values()
    }

    /// Issues a lease under a parent that holds current authority. Its expiry is one term
    /// away, but never past the parent's authority.
    pub(super) fn issue(
        &mut self,
        request: LeaseRequest,
        now: MonotonicTime,
        context: &LeaseContext,
    ) -> Result<Lease, LeaseRefusal> {
        request
            .terms
            .check()
            .map_err(|problem| LeaseRefusal::InvalidTerms { problem })?;
        let authority = parent_authority(context, now)?;
        if let Some(binding) = request.model {
            activation_serves(context, binding, request.kind)?;
        }
        if let Some(grant) = request.revoked_grant {
            return Err(LeaseRefusal::GrantRevoked { grant });
        }
        let id = self.next;
        if id >= self.limit {
            return Err(LeaseRefusal::LeaseIdsNotPersisted { limit: self.limit });
        }
        let next = match id.next() {
            Some(next) if !self.records.contains_key(&id) => next,
            _ => return Err(LeaseRefusal::LeaseIdsExhausted),
        };
        let expires_at = min(
            now.saturating_add(request.terms.term),
            min(
                now.saturating_add(request.terms.max_lifetime),
                authority.expires_at,
            ),
        );
        let lease = Lease {
            id,
            parent: request.parent,
            operation: request.operation,
            kind: request.kind,
            sandbox: context.generations,
            model: request.model,
            grants: request.grants,
            terms: request.terms,
            clock: context.clock,
            issued_at: now,
            expires_at,
            renewals: 0,
        };
        self.next = next;
        self.records.insert(
            id,
            LeaseRecord {
                lease: lease.clone(),
                state: LeaseState::Active,
            },
        );
        Ok(lease)
    }

    /// Renews a lease by the rules on [`LeaseTerms`].
    pub(super) fn renew(
        &mut self,
        lease: LeaseId,
        now: MonotonicTime,
        context: &LeaseContext,
    ) -> Result<Lease, LeaseRefusal> {
        let record = self
            .records
            .get_mut(&lease)
            .ok_or(LeaseRefusal::UnknownLease { lease })?;
        check(record, now, context)?;
        let authority = parent_authority(context, now)?;
        let current = &mut record.lease;
        let wanted = now.saturating_add(current.terms.term);
        let deadline = current.deadline();
        let next = min(wanted, min(deadline, authority.expires_at));
        if next <= current.expires_at {
            if wanted > current.expires_at {
                let limit = if deadline <= authority.expires_at {
                    RenewalLimit::MaxLifetime
                } else {
                    RenewalLimit::AuthorityExpiry
                };
                return Err(LeaseRefusal::RenewalLimitReached {
                    limit,
                    expires_at: current.expires_at,
                });
            }
            return Ok(current.clone());
        }
        current.expires_at = next;
        current.renewals = current.renewals.saturating_add(1);
        Ok(current.clone())
    }

    /// The holder is done. Releasing a cancelling lease acknowledges its cancellation;
    /// releasing again changes nothing.
    pub(super) fn release(
        &mut self,
        lease: LeaseId,
        now: MonotonicTime,
    ) -> Result<(), LeaseRefusal> {
        let record = self
            .records
            .get_mut(&lease)
            .ok_or(LeaseRefusal::UnknownLease { lease })?;
        record.state = match record.state {
            LeaseState::Active => LeaseState::Released { at: now },
            LeaseState::Cancelling {
                cause,
                requested_at,
                ..
            } => LeaseState::Cancelled {
                cause,
                requested_at,
                acknowledged_at: now,
            },
            state => state,
        };
        Ok(())
    }

    /// The holder acknowledges a cancellation; acknowledging again changes nothing.
    pub(super) fn acknowledge(
        &mut self,
        lease: LeaseId,
        now: MonotonicTime,
    ) -> Result<(), LeaseRefusal> {
        let record = self
            .records
            .get_mut(&lease)
            .ok_or(LeaseRefusal::UnknownLease { lease })?;
        record.state = match record.state {
            LeaseState::Cancelling {
                cause,
                requested_at,
                ..
            } => LeaseState::Cancelled {
                cause,
                requested_at,
                acknowledged_at: now,
            },
            state @ LeaseState::Cancelled { .. } => state,
            _ => return Err(LeaseRefusal::NotCancelling),
        };
        Ok(())
    }

    /// Adds `grants` to the grants `lease` depends on; returns the lease as now recorded.
    pub(super) fn bind_grants(
        &mut self,
        lease: LeaseId,
        grants: &BTreeSet<GrantId>,
    ) -> Result<Lease, LeaseRefusal> {
        let record = self
            .records
            .get_mut(&lease)
            .ok_or(LeaseRefusal::UnknownLease { lease })?;
        record.lease.grants.extend(grants.iter().copied());
        Ok(record.lease.clone())
    }

    /// Cancels every active lease `selected` picks. Each must stop by `cancel_within`
    /// from now, or by its expiry if that is sooner.
    pub(super) fn cancel_where(
        &mut self,
        mut selected: impl FnMut(&Lease) -> bool,
        cause: CancelCause,
        now: MonotonicTime,
    ) -> Vec<LeaseCancellation> {
        let mut cancelled = Vec::new();
        for record in self.records.values_mut() {
            if record.state != LeaseState::Active || !selected(&record.lease) {
                continue;
            }
            let lease = &record.lease;
            let bound_at = min(
                now.saturating_add(lease.terms.cancel_within),
                lease.expires_at,
            );
            record.state = LeaseState::Cancelling {
                cause,
                requested_at: now,
                bound_at,
            };
            cancelled.push(LeaseCancellation {
                lease: lease.id,
                kind: lease.kind,
                requested_at: now,
                bound_at,
                expires_at: lease.expires_at,
            });
        }
        cancelled
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::digest;

    const SECOND: Duration = Duration::from_secs(1);

    fn at(seconds: u64) -> MonotonicTime {
        MonotonicTime::from_nanos(seconds * 1_000_000_000)
    }

    fn terms() -> LeaseTerms {
        LeaseTerms {
            term: 10 * SECOND,
            max_lifetime: 25 * SECOND,
            cancel_within: 2 * SECOND,
        }
    }

    fn session() -> ClockSession {
        ClockSession::from_uuid(uuid::Uuid::from_u128(1))
    }

    fn context(authority_expires: u64) -> LeaseContext {
        LeaseContext {
            clock: session(),
            state: SandboxState::Running,
            generations: SandboxGenerations::FIRST,
            authority: Some(AuthorityGrant {
                epoch: AuthorizationEpoch::FIRST,
                clock: session(),
                expires_at: at(authority_expires),
            }),
            activation: None,
        }
    }

    fn request(kind: LeaseKind, model: Option<ModelBinding>) -> LeaseRequest {
        LeaseRequest {
            parent: ExecutionId::new("exe-parent").unwrap(),
            operation: OperationId::new("op-child").unwrap(),
            kind,
            model,
            grants: BTreeSet::new(),
            revoked_grant: None,
            terms: terms(),
        }
    }

    #[test]
    fn terms_are_checked() {
        let mut zero = terms();
        zero.term = Duration::ZERO;
        assert_eq!(zero.check(), Err(TermsProblem::ZeroTerm));
        let mut short = terms();
        short.max_lifetime = SECOND;
        assert_eq!(short.check(), Err(TermsProblem::LifetimeShorterThanTerm));
        let mut table = LeaseTable::new();
        assert_eq!(
            table.issue(
                LeaseRequest {
                    terms: zero,
                    ..request(LeaseKind::ChildWork, None)
                },
                at(0),
                &context(100)
            ),
            Err(LeaseRefusal::InvalidTerms {
                problem: TermsProblem::ZeroTerm
            })
        );
    }

    #[test]
    fn renewal_follows_the_term_the_lifetime_and_the_authority() {
        let mut table = LeaseTable::new();
        let lease = table
            .issue(request(LeaseKind::ChildWork, None), at(0), &context(100))
            .unwrap();
        assert_eq!(lease.expires_at(), at(10));
        assert_eq!(lease.deadline(), at(25));

        let renewed = table.renew(lease.id(), at(5), &context(100)).unwrap();
        assert_eq!(renewed.expires_at(), at(15));
        assert_eq!(renewed.renewals(), 1);
        let early = table.renew(lease.id(), at(5), &context(100)).unwrap();
        assert_eq!(
            early.expires_at(),
            at(15),
            "renewing again at once adds nothing"
        );

        let capped = table.renew(lease.id(), at(14), &context(100)).unwrap();
        assert_eq!(capped.expires_at(), at(24));
        let last = table.renew(lease.id(), at(20), &context(100)).unwrap();
        assert_eq!(last.expires_at(), at(25), "never past the maximum lifetime");
        assert_eq!(
            table.renew(lease.id(), at(24), &context(100)),
            Err(LeaseRefusal::RenewalLimitReached {
                limit: RenewalLimit::MaxLifetime,
                expires_at: at(25)
            })
        );
        assert_eq!(
            table.renew(lease.id(), at(25), &context(100)),
            Err(LeaseRefusal::Expired { expired_at: at(25) }),
            "an expired lease never renews"
        );
    }

    #[test]
    fn renewal_never_passes_the_parents_authority() {
        let mut table = LeaseTable::new();
        let lease = table
            .issue(request(LeaseKind::Service, None), at(0), &context(12))
            .unwrap();
        assert_eq!(lease.expires_at(), at(10));
        let renewed = table.renew(lease.id(), at(9), &context(12)).unwrap();
        assert_eq!(renewed.expires_at(), at(12));
        assert_eq!(
            table.renew(lease.id(), at(11), &context(12)),
            Err(LeaseRefusal::RenewalLimitReached {
                limit: RenewalLimit::AuthorityExpiry,
                expires_at: at(12)
            })
        );
        let short = table
            .issue(request(LeaseKind::Transfer, None), at(5), &context(8))
            .unwrap();
        assert_eq!(
            short.expires_at(),
            at(8),
            "issue never passes the authority"
        );
    }

    #[test]
    fn every_bound_generation_must_be_current() {
        let mut table = LeaseTable::new();
        let lease = table
            .issue(request(LeaseKind::ChildWork, None), at(0), &context(100))
            .unwrap();
        let record = table.get(lease.id()).unwrap().clone();
        let mut rebooted = context(100);
        rebooted.generations.boot = SandboxBootGeneration::new(2);
        assert_eq!(
            check(&record, at(1), &rebooted),
            Err(LeaseRefusal::StaleBootGeneration {
                bound: SandboxBootGeneration::FIRST,
                current: SandboxBootGeneration::new(2)
            })
        );
        let mut revoked = context(100);
        revoked.generations.authorization = AuthorizationEpoch::new(2);
        revoked.authority = Some(AuthorityGrant {
            epoch: AuthorizationEpoch::new(2),
            clock: session(),
            expires_at: at(100),
        });
        assert_eq!(
            check(&record, at(1), &revoked),
            Err(LeaseRefusal::RevokedAuthorization {
                bound: AuthorizationEpoch::FIRST,
                current: AuthorizationEpoch::new(2)
            })
        );
        let mut new_policy = context(100);
        new_policy.generations.policy = PolicyEpoch::new(2);
        assert!(matches!(
            check(&record, at(1), &new_policy),
            Err(LeaseRefusal::StalePolicyEpoch { .. })
        ));
        let mut restarted = context(100);
        restarted.clock = ClockSession::from_uuid(uuid::Uuid::from_u128(2));
        assert_eq!(
            check(&record, at(1), &restarted),
            Err(LeaseRefusal::OtherClock),
            "times on another clock session are never compared"
        );
        let mut stopped = context(100);
        stopped.state = SandboxState::Revoking;
        assert_eq!(
            check(&record, at(1), &stopped),
            Err(LeaseRefusal::NoAuthority {
                state: SandboxState::Revoking
            })
        );
        assert!(check(&record, at(1), &context(100)).is_ok());
    }

    #[test]
    fn model_leases_need_their_activation_serving() {
        let model = ModelId::new(digest("yougori/test/model/v1", &[b"m"]));
        let binding = ModelBinding {
            model,
            generations: ModelGenerations::FIRST,
        };
        let mut serving = context(100);
        serving.activation = Some(ActivationView::Serving {
            gpu_allocation: GpuAllocationGeneration::FIRST,
        });
        let mut table = LeaseTable::new();
        let lease = table
            .issue(
                request(LeaseKind::ModelRequest, Some(binding)),
                at(0),
                &serving,
            )
            .unwrap();
        let record = table.get(lease.id()).unwrap().clone();
        let mut retired = serving;
        retired.activation = Some(ActivationView::NotServing {
            state: ActivationState::Reclaiming,
        });
        assert_eq!(
            check(&record, at(1), &retired),
            Err(LeaseRefusal::ActivationNotServing {
                activation: ModelGenerations::FIRST.activation,
                state: Some(ActivationState::Reclaiming)
            })
        );
        let mut loading = serving;
        loading.activation = Some(ActivationView::Loading {
            gpu_allocation: GpuAllocationGeneration::FIRST,
        });
        assert!(table
            .issue(
                request(LeaseKind::ModelRequest, Some(binding)),
                at(0),
                &loading
            )
            .is_err());
    }

    #[test]
    fn cancellation_has_a_declared_bound_and_acknowledgment() {
        let mut table = LeaseTable::new();
        let lease = table
            .issue(request(LeaseKind::Transfer, None), at(0), &context(100))
            .unwrap();
        assert_eq!(
            table.acknowledge(lease.id(), at(1)),
            Err(LeaseRefusal::NotCancelling)
        );
        let cancelled = table.cancel_where(|_| true, CancelCause::Revocation, at(3));
        assert_eq!(cancelled.len(), 1);
        assert_eq!(cancelled[0].bound_at, at(5));
        assert!(table.get(lease.id()).unwrap().may_be_in_use(at(4)));
        table.acknowledge(lease.id(), at(4)).unwrap();
        table.acknowledge(lease.id(), at(4)).unwrap();
        assert!(!table.get(lease.id()).unwrap().may_be_in_use(at(4)));
        assert_eq!(
            check(table.get(lease.id()).unwrap(), at(4), &context(100)),
            Err(LeaseRefusal::Cancelled {
                cause: CancelCause::Revocation
            })
        );
        assert!(
            table
                .cancel_where(|_| true, CancelCause::Revocation, at(5))
                .is_empty(),
            "only active leases are cancelled"
        );
    }

    #[test]
    fn restored_tables_never_revive_and_never_reuse_numbers() {
        let mut table = LeaseTable::new();
        let first = table
            .issue(request(LeaseKind::Service, None), at(0), &context(100))
            .unwrap();
        let second = table
            .issue(request(LeaseKind::ChildWork, None), at(0), &context(100))
            .unwrap();
        table.release(second.id(), at(1)).unwrap();
        let records: Vec<LeaseRecord> = table.records().cloned().collect();
        let (mut restored, not_revived) = LeaseTable::restored(LeaseId::FIRST, records);
        assert_eq!(not_revived, vec![first.id()]);
        assert_eq!(
            check(restored.get(first.id()).unwrap(), at(1), &context(100)),
            Err(LeaseRefusal::NotRevived)
        );
        assert_eq!(
            restored.renew(first.id(), at(1), &context(100)),
            Err(LeaseRefusal::NotRevived)
        );
        assert_eq!(
            restored.issue(request(LeaseKind::Service, None), at(1), &context(100)),
            Err(LeaseRefusal::LeaseIdsNotPersisted {
                limit: LeaseId::new(3)
            }),
            "nothing is issued before the recovered state is persisted"
        );
        let mark = restored.high_water_mark();
        restored.confirm_persisted(mark);
        let fresh = restored
            .issue(request(LeaseKind::Service, None), at(1), &context(100))
            .unwrap();
        assert!(fresh.id() > second.id(), "lease numbers are never reused");
    }
}
