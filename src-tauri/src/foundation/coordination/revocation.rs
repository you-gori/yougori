//! Revocation (S6 INT-02; VM part §6.3).
//!
//! Revoking a sandbox advances its authorization epoch, which blocks new child work at
//! once, and cancels every lease bound to the old epoch with that lease's declared bound.
//! The model side learns of it through an explicit adapter call and stops admitting. GPU
//! memory is released only once no lease may still use it, and nothing in the protocol
//! renews or extends authority. Each acknowledgment is its own milestone: "new
//! authorizations denied" is not "all sockets closed", "leases closed", "VM stopped",
//! "remote provider stopped billing" or "cleanup finished". The external effects' bounds,
//! sockets, all channels and billing, are acknowledged by the host and the provider.
//!
//! Two milestones make the bound of §6.5 measurable. "New authorizations denied" is the
//! decision taking effect; the first authorization actually refused after it is its own
//! milestone, recorded once with what refused it: the coordinator's own check, or an
//! enforcement point outside it as the host observed. "All channels closed" is every
//! eligible release channel of §2.5, a superset of the sockets: it implies sockets closed,
//! never the reverse. Every milestone keeps what established it ([`MilestoneSource`]).

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::capacity::{CapacityPort, CapacityRefusal, ExecutionCancellation};
use super::coordinator::{Compensation, CoordinationError, Coordinator};
use super::identity::ModelId;
use super::lease::{self, CancelCause, LeaseCancellation, LeaseKind, LeaseRefusal, LeaseState};
use super::model::{ActivationState, ModelRefusal, RetireReason};
use super::port::SandboxPort;
use super::sandbox::{SandboxState, SandboxStep};
use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::{
    AuthorizationEpoch, Clock, ExecutionId, LeaseId, ModelActivationGeneration, MonotonicTime,
};

/// One acknowledgment of a revocation (VM part §6.3: define the acknowledgment
/// precisely).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationMilestone {
    /// The epoch advanced and new authorizations are denied (§6.3 steps 1–2): the decision
    /// in force at the coordinator.
    NewAuthorizationsDenied,
    /// The first authorization actually refused for want of the authority the revocation
    /// took away (§6.3 step 2; VM-P14: new-request denial is measured apart from the
    /// decision): refused by the coordinator's own check, which records it when it refuses,
    /// or by an enforcement point outside it, as the host observed. Recorded once; the
    /// first refusal stands.
    FirstDeniedAuthorization,
    /// Every network socket of the sandbox is closed, as the host's network enforcement
    /// observed it (§6.3 step 2: existing channels closed); not new authorizations denied.
    SocketsClosed,
    /// Every eligible release channel of the sandbox is closed, as the host observed it
    /// (§6.3 step 2: "closes/invalidates eligible existing channels"; VM-P14: active-channel
    /// closure; §2.5: provider requests, transport streams, DNS queries, published-service
    /// responses, files, terminal output, logs, browser previews and user-approved
    /// transfers). A superset of [`RevocationMilestone::SocketsClosed`]: recording it
    /// records sockets closed too, when they were not yet, as implied by it; sockets closed
    /// never implies it. Neither is leases closed, which the holders' acknowledgments
    /// reach.
    AllChannelsClosed,
    /// Every cancelled lease acknowledged or reached its declared bound (§6.3 step 3).
    LeasesClosed,
    /// The revoked activations' GPU memory was reclaimed: nothing uses it, and its
    /// reservations are cancelled, still counted until the VM's end is observed (INT-02).
    GpuReclaimed,
    /// The VM stopped (§6.3 step 4).
    VmStopped,
    /// The remote provider stopped billing for the sandbox, as its control-plane API
    /// reported (§6.3); not the VM stopping.
    ProviderStoppedBilling,
    /// Cleanup finished (§6.3 step 5).
    CleanupFinished,
}

impl RevocationMilestone {
    /// The source an external effect's acknowledgment needs, for the milestones external
    /// enforcement acknowledges (VM part §6.3 and §2.5: post-revocation bounds for
    /// external effects): sockets, all channels and an enforcement point's first refusal
    /// by the host, billing by the provider's API. `None` for the milestones the
    /// revocation reaches itself. The coordinator also records the first denied
    /// authorization itself, when its own check refuses one.
    pub const fn acknowledged_by(self) -> Option<SourceClass> {
        match self {
            Self::FirstDeniedAuthorization | Self::SocketsClosed | Self::AllChannelsClosed => {
                Some(SourceClass::HostProbe)
            }
            Self::ProviderStoppedBilling => Some(SourceClass::ProviderApi),
            Self::NewAuthorizationsDenied
            | Self::LeasesClosed
            | Self::GpuReclaimed
            | Self::VmStopped
            | Self::CleanupFinished => None,
        }
    }
}

/// What established a revocation milestone (VM part §6.3: define the acknowledgment
/// precisely).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "established_by", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum MilestoneSource {
    /// The coordinator itself: its decision, its own refusal, its leases'
    /// acknowledgments and bounds, its ledger, or the sandbox port's termination.
    Coordinator,
    /// An enforcement point outside the coordinator acknowledged it, from `source`
    /// ([`Coordinator::acknowledge_revocation`]).
    Acknowledged { source: SourceClass },
    /// Implied by the broader milestone `by`, acknowledged at the same time from `source`:
    /// all channels closed includes every socket.
    ImpliedBy {
        by: RevocationMilestone,
        source: SourceClass,
    },
}

crate::foundation::strict_serde::strict_tag!(MilestoneSource, "established_by");

/// What the coordinator refused when it denied an authorization.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "request", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum DeniedRequest {
    /// A lease checked for an enforcement point or its holder
    /// ([`Coordinator::check_lease`], [`Coordinator::check_presented_lease`]).
    LeaseCheck { lease: LeaseId },
    /// A lease renewal.
    LeaseRenewal { lease: LeaseId },
    /// New work under the parent: child work, a model request or a preparation.
    NewLease { kind: LeaseKind },
    /// A model activation under the parent's authority.
    Activation { model: ModelId },
}

crate::foundation::strict_serde::strict_tag!(DeniedRequest, "request");

/// Who refused the first authorization after a revocation, and what.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "denied_by", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum Denial {
    /// The coordinator's own check refused `request` for `refusal`.
    Coordinator {
        request: DeniedRequest,
        refusal: LeaseRefusal,
    },
    /// An enforcement point outside the coordinator refused one, as `source` observed
    /// ([`Coordinator::acknowledge_revocation`]).
    EnforcementPoint { source: SourceClass },
}

crate::foundation::strict_serde::strict_tag!(Denial, "denied_by");

/// The first authorization refused after a revocation (VM part §6.3 step 2; VM-P14).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeniedAuthorization {
    pub at: MonotonicTime,
    pub denial: Denial,
}

impl DeniedAuthorization {
    /// What established the milestone.
    pub fn source(&self) -> MilestoneSource {
        match self.denial {
            Denial::Coordinator { .. } => MilestoneSource::Coordinator,
            Denial::EnforcementPoint { source } => MilestoneSource::Acknowledged { source },
        }
    }
}

/// The first refused authorization of one revocation. It is set through a shared
/// reference, so a check made with `&Coordinator`, as enforcement points make it, records
/// it too; the first one stands.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct FirstDenial(OnceLock<DeniedAuthorization>);

impl FirstDenial {
    fn get(&self) -> Option<&DeniedAuthorization> {
        self.0.get()
    }

    /// Records `denial` unless one is recorded; returns the one that stands.
    fn record(&self, denial: impl FnOnce() -> DeniedAuthorization) -> &DeniedAuthorization {
        self.0.get_or_init(denial)
    }

    fn is_empty(&self) -> bool {
        self.0.get().is_none()
    }
}

impl Serialize for FirstDenial {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.get().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for FirstDenial {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Option::<DeniedAuthorization>::deserialize(deserializer)?
            .map_or_else(Self::default, |denial| Self(OnceLock::from(denial))))
    }
}

/// Whether `refusal` denies authority a revocation took away (§6.3 step 2), rather than
/// a request refused for its own sake, such as for invalid terms.
fn denies_revoked_authority(refusal: &LeaseRefusal) -> bool {
    matches!(
        refusal,
        LeaseRefusal::NoAuthority { .. }
            | LeaseRefusal::RevokedAuthorization { .. }
            | LeaseRefusal::Cancelled {
                cause: CancelCause::Revocation
            }
    )
}

/// What the model side is told when its parent is revoked: the explicit adapter call
/// between the two state machines (S2 CORE-04).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationNotice {
    pub execution: ExecutionId,
    /// The epoch no longer honoured.
    pub revoked: AuthorizationEpoch,
    /// The epoch now in force, under which no authority has been granted.
    pub current: AuthorizationEpoch,
    pub at: MonotonicTime,
}

/// An outcome the revocation could not confirm (VM part §6.3 step 5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum UncertainOutcome {
    /// The holder did not acknowledge by its declared bound. Its lease is refused
    /// everywhere, and memory it may use is not reclaimed before the lease expires.
    UnacknowledgedLease {
        lease: LeaseId,
        kind: LeaseKind,
        bound_at: MonotonicTime,
        expires_at: MonotonicTime,
    },
    /// The ledger refused to cancel the execution's reservations; the revocation went on,
    /// and termination releases them.
    LedgerNotCancelled { refusal: CapacityRefusal },
}

crate::foundation::strict_serde::strict_tag!(UncertainOutcome, "outcome");

impl UncertainOutcome {
    /// The lease the outcome is about, if any.
    pub fn lease(&self) -> Option<LeaseId> {
        match self {
            Self::UnacknowledgedLease { lease, .. } => Some(*lease),
            Self::LedgerNotCancelled { .. } => None,
        }
    }
}

/// One revocation and how far it has come (VM part §6.3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationOperation {
    notice: RevocationNotice,
    cancellations: Vec<LeaseCancellation>,
    ledger: Option<ExecutionCancellation>,
    /// Every milestone reached but the first denied authorization, which `first_denial`
    /// holds.
    milestones: BTreeMap<RevocationMilestone, MonotonicTime>,
    /// What established each milestone in `milestones`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    sources: BTreeMap<RevocationMilestone, MilestoneSource>,
    #[serde(default, skip_serializing_if = "FirstDenial::is_empty")]
    first_denial: FirstDenial,
    uncertain: Vec<UncertainOutcome>,
}

impl RevocationOperation {
    /// What the model side was told.
    pub fn notice(&self) -> &RevocationNotice {
        &self.notice
    }

    /// The leases the revocation cancelled, each with its declared bound.
    pub fn cancellations(&self) -> &[LeaseCancellation] {
        &self.cancellations
    }

    /// What the ledger cancelled of the execution's reservations and queued requests.
    pub fn ledger(&self) -> Option<ExecutionCancellation> {
        self.ledger
    }

    /// When each milestone was reached, the first denied authorization included.
    pub fn milestones(&self) -> BTreeMap<RevocationMilestone, MonotonicTime> {
        let mut milestones = self.milestones.clone();
        if let Some(denied) = self.first_denial.get() {
            milestones.insert(RevocationMilestone::FirstDeniedAuthorization, denied.at);
        }
        milestones
    }

    /// When `milestone` was reached, if it was.
    pub fn milestone(&self, milestone: RevocationMilestone) -> Option<MonotonicTime> {
        match milestone {
            RevocationMilestone::FirstDeniedAuthorization => {
                self.first_denial.get().map(|denied| denied.at)
            }
            _ => self.milestones.get(&milestone).copied(),
        }
    }

    /// What established `milestone`, if it was reached.
    pub fn milestone_source(&self, milestone: RevocationMilestone) -> Option<MilestoneSource> {
        match milestone {
            RevocationMilestone::FirstDeniedAuthorization => {
                self.first_denial.get().map(DeniedAuthorization::source)
            }
            _ => self.sources.get(&milestone).copied(),
        }
    }

    /// The first authorization refused after the revocation: when, and who refused what.
    pub fn first_denied_authorization(&self) -> Option<&DeniedAuthorization> {
        self.first_denial.get()
    }

    /// Records `milestone` at `at` from `source` unless it is recorded; returns when it
    /// was first reached.
    fn reach(
        &mut self,
        milestone: RevocationMilestone,
        at: MonotonicTime,
        source: MilestoneSource,
    ) -> MonotonicTime {
        self.sources.entry(milestone).or_insert(source);
        *self.milestones.entry(milestone).or_insert(at)
    }

    /// Outcomes the revocation could not confirm.
    pub fn uncertain(&self) -> &[UncertainOutcome] {
        &self.uncertain
    }
}

/// Where a revocation stands.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RevocationStatus {
    /// Waiting for these leases to acknowledge or to reach their declared bounds.
    WaitingForLeases {
        pending: Vec<LeaseId>,
        next_bound_at: MonotonicTime,
    },
    /// GPU memory waits until no lease may still use it, at the latest by `safe_at`.
    WaitingForGpuReclaim {
        blocking: Vec<LeaseId>,
        safe_at: MonotonicTime,
    },
    /// The VM is terminated and everything is released.
    Completed { compensations: Vec<Compensation> },
}

impl<C: Clock, P: CapacityPort> Coordinator<C, P> {
    /// Revokes the sandbox's authorization (INT-02; VM part §6.3 steps 1–2).
    ///
    /// The authorization epoch advances, so new child work is refused at once; every
    /// active lease of the sandbox is cancelled with its declared bound; the model side is
    /// told through an explicit adapter call; and the ledger cancels the execution's
    /// reservations and queued requests, created ones staying counted until their release
    /// is observed. Revoking again returns the same notice.
    pub fn revoke(
        &mut self,
        execution: &ExecutionId,
    ) -> Result<RevocationNotice, CoordinationError> {
        if let Some(operation) = self.revocations.get(execution) {
            return Ok(operation.notice.clone());
        }
        let now = self.monotonic_now();
        let applied = self.apply_step(execution, SandboxStep::Revoke)?;
        let record = applied.record();
        let notice = RevocationNotice {
            execution: execution.clone(),
            revoked: record.presented.authorization,
            current: record.generations.authorization,
            at: now,
        };
        let cancellations = self.leases.cancel_where(
            |lease| lease.parent() == execution,
            CancelCause::Revocation,
            now,
        );
        for ((owner, _), models) in self.models.iter_mut() {
            if owner == execution {
                models.on_parent_revoked(&notice);
            }
        }
        let (ledger, uncertain) = match self.capacity.cancel_execution(execution) {
            Ok(cancelled) => (Some(cancelled), Vec::new()),
            Err(refusal) => (None, vec![UncertainOutcome::LedgerNotCancelled { refusal }]),
        };
        self.revocations.insert(
            execution.clone(),
            RevocationOperation {
                notice: notice.clone(),
                cancellations,
                ledger,
                milestones: BTreeMap::from([(RevocationMilestone::NewAuthorizationsDenied, now)]),
                sources: BTreeMap::from([(
                    RevocationMilestone::NewAuthorizationsDenied,
                    MilestoneSource::Coordinator,
                )]),
                first_denial: FirstDenial::default(),
                uncertain,
            },
        );
        Ok(notice)
    }

    /// The revocation of `execution`, if one is recorded.
    pub fn revocation(&self, execution: &ExecutionId) -> Option<&RevocationOperation> {
        self.revocations.get(execution)
    }

    /// Records an external effect's bound after the revocation of `execution` (VM part
    /// §6.3: the acknowledgment defined precisely): every socket closed or every release
    /// channel closed, as the host observed, an enforcement point's first refusal of an
    /// authorization, as the host observed, or the remote provider stopped billing, as its
    /// API reported. Each is recorded once, at its first acknowledgment from a strong
    /// enough source, with that source; all channels closed also records sockets closed,
    /// when they were not yet, as implied by it. The first denied authorization stands
    /// whether the coordinator's own check or an enforcement point refused first. The
    /// milestones the revocation reaches itself are refused here. Returns when the
    /// milestone was first reached.
    pub fn acknowledge_revocation(
        &mut self,
        execution: &ExecutionId,
        milestone: RevocationMilestone,
        source: SourceClass,
    ) -> Result<MonotonicTime, CoordinationError> {
        let required = milestone
            .acknowledged_by()
            .ok_or(CoordinationError::NotAcknowledgedExternally { milestone })?;
        if !source.satisfies(required) {
            return Err(CoordinationError::AcknowledgmentTooWeak {
                milestone,
                source,
                required,
            });
        }
        let state = self.sandbox_ref(execution)?.state();
        let now = self.monotonic_now();
        let operation = self
            .revocations
            .get_mut(execution)
            .ok_or(CoordinationError::NotRevoking { state })?;
        let acknowledged = MilestoneSource::Acknowledged { source };
        Ok(match milestone {
            RevocationMilestone::FirstDeniedAuthorization => {
                operation
                    .first_denial
                    .record(|| DeniedAuthorization {
                        at: now,
                        denial: Denial::EnforcementPoint { source },
                    })
                    .at
            }
            RevocationMilestone::AllChannelsClosed => {
                let at = operation.reach(milestone, now, acknowledged);
                operation.reach(
                    RevocationMilestone::SocketsClosed,
                    at,
                    MilestoneSource::ImpliedBy {
                        by: RevocationMilestone::AllChannelsClosed,
                        source,
                    },
                );
                at
            }
            _ => operation.reach(milestone, now, acknowledged),
        })
    }

    /// Records the coordinator's refusal of `request` for `refusal` as the first denied
    /// authorization of `execution`'s revocation, when a revocation of it is recorded, the
    /// refusal denies the authority the revocation took away, and no refusal was recorded
    /// first (§6.3 step 2). Checks made through a shared reference record it too.
    pub(super) fn note_denial(
        &self,
        execution: &ExecutionId,
        request: DeniedRequest,
        refusal: &LeaseRefusal,
    ) {
        if !denies_revoked_authority(refusal) {
            return;
        }
        if let Some(operation) = self.revocations.get(execution) {
            operation.first_denial.record(|| DeniedAuthorization {
                at: self.monotonic_now(),
                denial: Denial::Coordinator {
                    request,
                    refusal: refusal.clone(),
                },
            });
        }
    }

    /// [`Coordinator::note_denial`] for a model refusal: the parent's refusal, or an
    /// activation that no longer serves because the revocation reclaimed it, when the
    /// parent holds no authority.
    pub(super) fn note_model_denial(
        &self,
        execution: &ExecutionId,
        request: DeniedRequest,
        refusal: &ModelRefusal,
    ) {
        match refusal {
            ModelRefusal::Parent { refusal } => self.note_denial(execution, request, refusal),
            ModelRefusal::NoServingActivation { .. }
            | ModelRefusal::InvalidActivationTransition { .. } => {
                if !self.revocations.contains_key(execution) {
                    return;
                }
                let parent = self.lease_context(execution, None).and_then(|context| {
                    lease::parent_authority(&context, self.monotonic_now()).map(|_| ())
                });
                if let Err(refusal) = parent {
                    self.note_denial(execution, request, &refusal);
                }
            }
            _ => {}
        }
    }

    /// Advances a revocation as far as acknowledgments and time allow (VM part §6.3 steps
    /// 3–5): every cancelled lease acknowledges or reaches its declared bound; the revoked
    /// activations' GPU reservations are cancelled once no lease may still use them, and
    /// stay counted until the VM's end is observed; then the VM is terminated and cleaned
    /// up. A lease that reached its bound without acknowledging is recorded as uncertain.
    pub fn advance_revocation(
        &mut self,
        execution: &ExecutionId,
        port: &mut dyn SandboxPort,
    ) -> Result<RevocationStatus, CoordinationError> {
        let state = self.sandbox_ref(execution)?.state();
        let Some(mut operation) = self.revocations.remove(execution) else {
            return Err(CoordinationError::NotRevoking { state });
        };
        let status = self.advance(&mut operation, execution, port);
        self.revocations.insert(execution.clone(), operation);
        status
    }

    fn advance(
        &mut self,
        operation: &mut RevocationOperation,
        execution: &ExecutionId,
        port: &mut dyn SandboxPort,
    ) -> Result<RevocationStatus, CoordinationError> {
        let now = self.monotonic_now();
        let mut pending = Vec::new();
        let mut next_bound_at: Option<MonotonicTime> = None;
        for cancellation in &operation.cancellations {
            let acknowledged = matches!(
                self.leases
                    .get(cancellation.lease)
                    .map(|record| record.state()),
                Some(LeaseState::Cancelled { .. })
            );
            if acknowledged {
                continue;
            }
            if now < cancellation.bound_at {
                pending.push(cancellation.lease);
                next_bound_at = Some(
                    next_bound_at.map_or(cancellation.bound_at, |at| at.min(cancellation.bound_at)),
                );
            } else if !operation
                .uncertain
                .iter()
                .any(|outcome| outcome.lease() == Some(cancellation.lease))
            {
                operation
                    .uncertain
                    .push(UncertainOutcome::UnacknowledgedLease {
                        lease: cancellation.lease,
                        kind: cancellation.kind,
                        bound_at: cancellation.bound_at,
                        expires_at: cancellation.expires_at,
                    });
            }
        }
        if let Some(next_bound_at) = next_bound_at {
            return Ok(RevocationStatus::WaitingForLeases {
                pending,
                next_bound_at,
            });
        }
        operation.reach(
            RevocationMilestone::LeasesClosed,
            now,
            MilestoneSource::Coordinator,
        );

        let reclaiming: Vec<(ModelId, ModelActivationGeneration)> = self
            .models
            .iter()
            .filter(|((owner, _), _)| owner == execution)
            .flat_map(|((_, model), models)| {
                models
                    .activations()
                    .iter()
                    .filter(|activation| activation.state() == ActivationState::Reclaiming)
                    .map(move |activation| (*model, activation.generations().activation))
            })
            .collect();
        let mut blocking = Vec::new();
        let mut safe_at: Option<MonotonicTime> = None;
        let refused = |refusal| CoordinationError::Model { refusal };
        for (model, activation) in reclaiming {
            let users = self.live_leases(execution, model, activation, now);
            if users.is_empty() {
                if let Some(models) = self.models.get_mut(&(execution.clone(), model)) {
                    models
                        .retire(activation, RetireReason::Revoked)
                        .map_err(refused)?;
                }
                continue;
            }
            for lease in users {
                if let Some(record) = self.leases.get(lease) {
                    let expires_at = record.lease().expires_at();
                    safe_at = Some(safe_at.map_or(expires_at, |at| at.max(expires_at)));
                }
                blocking.push(lease);
            }
        }
        // Memory no unretired activation uses is reclaimed now, retained memory included:
        // nothing may be reactivated under the revoked epoch.
        let models: Vec<ModelId> = self
            .models
            .keys()
            .filter(|(owner, _)| owner == execution)
            .map(|(_, model)| *model)
            .collect();
        for model in models {
            self.settle_holdings(execution, model, true)
                .map_err(refused)?;
        }
        if let Some(safe_at) = safe_at {
            return Ok(RevocationStatus::WaitingForGpuReclaim { blocking, safe_at });
        }
        operation.reach(
            RevocationMilestone::GpuReclaimed,
            now,
            MilestoneSource::Coordinator,
        );

        match self.finish_termination(execution, port)? {
            Ok(compensations) => {
                operation.reach(
                    RevocationMilestone::VmStopped,
                    now,
                    MilestoneSource::Coordinator,
                );
                operation.reach(
                    RevocationMilestone::CleanupFinished,
                    now,
                    MilestoneSource::Coordinator,
                );
                Ok(RevocationStatus::Completed { compensations })
            }
            Err(stall) => {
                let terminated = stall
                    .completed
                    .iter()
                    .any(|step| matches!(step, Compensation::TerminateVm { .. }))
                    || self.sandbox_ref(execution)?.state() == SandboxState::CleanupPending;
                if terminated {
                    operation.reach(
                        RevocationMilestone::VmStopped,
                        now,
                        MilestoneSource::Coordinator,
                    );
                }
                Err(CoordinationError::Stalled { stall })
            }
        }
    }
}
