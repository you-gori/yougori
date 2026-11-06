//! The revocation protocol (VM part §6.3 lines 2308–2323; §6.5 lines 2333–2337; VM-P14
//! line 2787; §12.3 models 3 and 5 lines 2835 and 2837).
//!
//! A revocation advances the durable epoch through CORE-04 (the linearization point:
//! from then on no new authorization succeeds), stops issuing, invalidates eligible
//! channels, waits for the enforcement acknowledgments or the lease-expiry bound,
//! terminates when the policy says, and records uncertain external outcomes before a
//! bounded cleanup. The five acknowledgments are distinct typed facts: "new authorizations
//! denied" is not "channels closed", "VM stopped", "provider billing stopped" or "cleanup
//! finished". Provider billing stops only on the provider's own acknowledgment, and a
//! security revocation never waits for recursive cleanup.
//!
//! Where CORE-04 records an acknowledgment's milestone, the run takes the fact from
//! CORE-04's revocation operation with what established it there
//! ([`RevocationRun::observe_operation`]) and keeps no account of its own: "new
//! authorizations denied" is CORE-04's first denied authorization, the first request
//! actually refused after the decision, and "channels closed" is CORE-04's all channels
//! closed. CORE-04's sockets closed and leases closed are never channel closure. Every
//! acknowledgment keeps its source ([`AckSource`]).

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::leases::LimitKind;
use super::measurements::CleanupReport;
use crate::foundation::coordination::{
    MilestoneSource, RevocationMilestone, RevocationNotice, RevocationOperation, UncertainOutcome,
};
use crate::foundation::events::RevocationReason;
use crate::foundation::ids::{AuthorizationEpoch, Digest, ExecutionId, MonotonicTime};

/// One enforcement acknowledgment of a revocation (§6.3 "define the acknowledgment
/// precisely"). Each is its own fact; none implies another.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Acknowledgment {
    /// New authorizations are denied in fact: the first authorization refused after the
    /// durable decision, by the coordinator's own check or by an enforcement point the
    /// host observed (CORE-04's first denied authorization; VM-P14 line 2789: new-request
    /// denial measured apart from the decision). The decision itself is the run's
    /// [`RevocationRun::decided_at`].
    NewAuthorizationsDenied,
    /// Every eligible release channel is closed, as the host observed (CORE-04's all
    /// channels closed: §2.5's channels, sockets included); sockets alone never are.
    ChannelsClosed,
    /// The VM stopped.
    VmStopped,
    /// The remote provider acknowledged that billing stopped.
    ProviderBillingStopped,
    /// Every disk cleanup finished.
    CleanupFinished,
}

impl Acknowledgment {
    pub const ALL: [Self; 5] = [
        Self::NewAuthorizationsDenied,
        Self::ChannelsClosed,
        Self::VmStopped,
        Self::ProviderBillingStopped,
        Self::CleanupFinished,
    ];

    /// The CORE-04 milestone this acknowledgment is taken from, where CORE-04 records
    /// it: the first denied authorization and all channels closed. The VM stop is the
    /// supervisor's own observation through its handle, billing the provider's word and
    /// cleanup its own report.
    pub const fn milestone(self) -> Option<RevocationMilestone> {
        match self {
            Self::NewAuthorizationsDenied => Some(RevocationMilestone::FirstDeniedAuthorization),
            Self::ChannelsClosed => Some(RevocationMilestone::AllChannelsClosed),
            Self::VmStopped | Self::ProviderBillingStopped | Self::CleanupFinished => None,
        }
    }
}

/// What established one acknowledgment of a revocation (§6.3 line 2314: define the
/// acknowledgment precisely; VM-CP-14 line 3164: five separately measured times).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "by", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum AckSource {
    /// Taken from CORE-04's revocation operation: `milestone`, as `source` established it
    /// there (the coordinator's own refusal, or an enforcement point's acknowledgment
    /// with its source class).
    Coordination {
        milestone: RevocationMilestone,
        source: MilestoneSource,
    },
    /// The supervisor stopped the VM through its checked handle and observed it stop
    /// (§6.4).
    SupervisorHandle,
    /// The provider's own acknowledgment that billing stopped (§6.5).
    Provider { provider: Digest },
    /// The bounded cleanup's own report (§6.5).
    CleanupReport,
}

crate::foundation::strict_serde::strict_tag!(AckSource, "by");

impl fmt::Display for Acknowledgment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NewAuthorizationsDenied => "new authorizations denied",
            Self::ChannelsClosed => "all channels closed",
            Self::VmStopped => "VM stopped",
            Self::ProviderBillingStopped => "provider billing stopped",
            Self::CleanupFinished => "all disk cleanup finished",
        })
    }
}

/// Why a sandbox is revoked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "cause", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum RevocationCause {
    UserRequested,
    PolicyChanged,
    /// A sandbox limit ran out (§6.2).
    LeaseExpired {
        kind: LimitKind,
    },
    /// A clear violation (VM-D10).
    Violation,
    /// The engine died and the sandbox's class ends with it (VM-D7).
    EngineDied,
    /// A planned service renewal (§5.5).
    ServiceRenewal,
    OwnerReclaimed,
    /// The clock read earlier than the persisted high-water mark (§6.2).
    ClockRolledBack,
}

crate::foundation::strict_serde::strict_tag!(RevocationCause, "cause");

impl RevocationCause {
    /// The CORE-06 reason the revocation is published with.
    pub const fn reason(self) -> RevocationReason {
        match self {
            Self::UserRequested | Self::ServiceRenewal => RevocationReason::UserRequested,
            Self::PolicyChanged => RevocationReason::PolicyChanged,
            Self::LeaseExpired { .. } | Self::ClockRolledBack => {
                RevocationReason::AuthorizationExpired
            }
            Self::Violation | Self::EngineDied => RevocationReason::SecurityEvent,
            Self::OwnerReclaimed => RevocationReason::OwnerReclaimed,
        }
    }
}

/// Why one grant under a sandbox's authority is revoked alone (§6.3 step 1, line 2308:
/// "records a generation tombstone"; CORE-04 per-grant revocation). The causes that end
/// the whole sandbox, such as a limit running out, the engine's death, a planned renewal
/// or a clock rollback, have no per-grant form: they revoke the sandbox
/// ([`RevocationCause`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantRevocationCause {
    UserRequested,
    PolicyChanged,
    /// The grant was violated, possibly by another sandbox that shares it (VM-D10).
    Violation,
    OwnerReclaimed,
}

impl GrantRevocationCause {
    /// The CORE-06 reason the grant revocation is published with.
    pub const fn reason(self) -> RevocationReason {
        match self {
            Self::UserRequested => RevocationReason::UserRequested,
            Self::PolicyChanged => RevocationReason::PolicyChanged,
            Self::Violation => RevocationReason::SecurityEvent,
            Self::OwnerReclaimed => RevocationReason::OwnerReclaimed,
        }
    }
}

/// When the VM is terminated (§6.3 step 4: "when required by the incident/lifecycle
/// policy").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminationTiming {
    /// Stop the VM at once, before any acknowledgment; for incidents.
    Immediate,
    /// Stop once the channels are acknowledged closed or the lease-expiry bound passed.
    AfterChannelAcknowledgmentOrBound,
}

/// The revocation policy of a supervisor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationPolicy {
    pub timing: TerminationTiming,
    /// How long cleanup may take after the VM stopped before it is recorded as
    /// incomplete (§6.5 "starts bounded cleanup").
    pub cleanup_bound: Duration,
}

/// The provider's acknowledgment that billing stopped (§6.5 "provider billing
/// termination requires provider acknowledgment").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderAcknowledgment {
    pub provider: Digest,
    pub at: MonotonicTime,
}

/// Where provider billing stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "billing", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum ProviderBilling {
    /// No provider bills this sandbox.
    NotApplicable,
    /// Waiting for the provider; it may outlive local VM and channel shutdown.
    AwaitingProvider,
    Stopped {
        provider: Digest,
        at: MonotonicTime,
    },
}

crate::foundation::strict_serde::strict_tag!(ProviderBilling, "billing");

/// Where cleanup stands (§6.5: separate from security revocation, and bounded).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "cleanup", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum CleanupState {
    NotStarted,
    Started {
        at: MonotonicTime,
        bound_at: MonotonicTime,
    },
    Finished {
        at: MonotonicTime,
        report: CleanupReport,
        /// Whether it finished after the bound.
        late: bool,
    },
}

crate::foundation::strict_serde::strict_tag!(CleanupState, "cleanup");

/// An outcome the revocation could not confirm (§6.3 step 5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "uncertain", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum Uncertain {
    /// The channels were not acknowledged closed by the lease-expiry bound; they are
    /// treated as closed only because no lease can be honoured any more.
    ChannelsUnacknowledged { bound_at: MonotonicTime },
    /// Cleanup did not finish within its bound.
    CleanupIncomplete { bound_at: MonotonicTime },
    /// The provider has not acknowledged that billing stopped.
    ProviderBillingUnconfirmed { since: MonotonicTime },
    /// The VM's stop was refused or stalled.
    VmStopUncertain { detail: String },
    /// What CORE-04 could not confirm.
    Coordination { outcome: UncertainOutcome },
}

crate::foundation::strict_serde::strict_tag!(Uncertain, "uncertain");

/// Whether the VM may be terminated now.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "gate", rename_all = "snake_case")]
pub enum TerminationGate {
    /// The policy stops the VM at once.
    Immediate,
    /// The channels were acknowledged closed.
    ChannelsClosed,
    /// The lease-expiry bound passed without an acknowledgment.
    BoundReached { bound_at: MonotonicTime },
    /// Still waiting for the acknowledgment, until the bound.
    Wait { until: MonotonicTime },
}

/// Why an acknowledgment was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum AckRefusal {
    /// Billing stops only on the provider's acknowledgment, never on a local report.
    NeedsProviderAcknowledgment,
    /// Cleanup finishes through its own report, never by a bare acknowledgment.
    NeedsCleanupReport,
    /// Nothing bills this sandbox.
    NoProvider,
    /// An acknowledgment before the decision cannot be about this revocation.
    BeforeDecision {
        at: MonotonicTime,
        decided_at: MonotonicTime,
    },
    /// Cleanup starts only after the VM stopped.
    VmNotStopped,
    /// Cleanup was not started.
    CleanupNotStarted,
    /// Cleanup already finished.
    CleanupAlreadyFinished,
    /// The VM's stop is the supervisor's own observation through the backend handle; no
    /// enforcement point can claim it.
    VmStopIsObserved,
    /// The acknowledgment is CORE-04's `milestone`, taken from its revocation operation
    /// ([`RevocationRun::observe_operation`]); it is never recorded by hand.
    TakenFromCoordination { milestone: RevocationMilestone },
    /// The CORE-04 operation is another revocation than this run's.
    OtherRevocation,
}

crate::foundation::strict_serde::strict_tag!(AckRefusal, "refusal");

impl fmt::Display for AckRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NeedsProviderAcknowledgment => {
                f.write_str("provider billing stops only on the provider's own acknowledgment")
            }
            Self::NeedsCleanupReport => {
                f.write_str("cleanup finishes through a cleanup report, not an acknowledgment")
            }
            Self::NoProvider => f.write_str("no provider bills this sandbox"),
            Self::BeforeDecision { at, decided_at } => write!(
                f,
                "an acknowledgment at {} ns precedes the decision at {} ns",
                at.as_nanos(),
                decided_at.as_nanos()
            ),
            Self::VmNotStopped => f.write_str("cleanup starts only after the VM stopped"),
            Self::CleanupNotStarted => f.write_str("cleanup was not started"),
            Self::CleanupAlreadyFinished => f.write_str("cleanup already finished"),
            Self::VmStopIsObserved => f.write_str(
                "the VM's stop is observed by the supervisor, never acknowledged for it",
            ),
            Self::TakenFromCoordination { milestone } => write!(
                f,
                "this acknowledgment is the coordinator's {} milestone and is taken from its \
                 revocation record",
                milestone_name(*milestone)
            ),
            Self::OtherRevocation => {
                f.write_str("the coordinator's operation belongs to another revocation")
            }
        }
    }
}

impl std::error::Error for AckRefusal {}

/// The plain name of a CORE-04 revocation milestone.
const fn milestone_name(milestone: RevocationMilestone) -> &'static str {
    match milestone {
        RevocationMilestone::NewAuthorizationsDenied => "new authorizations denied",
        RevocationMilestone::FirstDeniedAuthorization => "first denied authorization",
        RevocationMilestone::SocketsClosed => "sockets closed",
        RevocationMilestone::AllChannelsClosed => "all channels closed",
        RevocationMilestone::LeasesClosed => "leases closed",
        RevocationMilestone::GpuReclaimed => "GPU memory reclaimed",
        RevocationMilestone::VmStopped => "VM stopped",
        RevocationMilestone::ProviderStoppedBilling => "provider stopped billing",
        RevocationMilestone::CleanupFinished => "cleanup finished",
    }
}

/// What recording an acknowledgment did.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AckEffect {
    Recorded,
    /// The same fact was recorded before; the first time stands.
    AlreadyRecorded,
}

/// A summary of where a revocation stands.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RevocationProgress {
    pub execution: ExecutionId,
    pub decided_at: MonotonicTime,
    pub acknowledged: Vec<Acknowledgment>,
    pub pending: Vec<Acknowledgment>,
    pub gate: TerminationGate,
    pub uncertain: usize,
}

/// One revocation of one sandbox, from the durable decision to the end of cleanup
/// (§6.3). Only the supervisor makes one, from the CORE-04 notice.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationRun {
    execution: ExecutionId,
    cause: RevocationCause,
    /// The epoch no longer honoured.
    revoked: AuthorizationEpoch,
    /// The epoch now in force, under which no authority exists.
    current: AuthorizationEpoch,
    /// The linearization point: the durable decision.
    decided_at: MonotonicTime,
    /// When every lease bound to the revoked epoch has expired everywhere, clock
    /// uncertainty included; after it nothing can be honoured, acknowledged or not.
    lease_expiry_bound_at: MonotonicTime,
    acknowledgments: BTreeMap<Acknowledgment, MonotonicTime>,
    /// What established each acknowledgment.
    sources: BTreeMap<Acknowledgment, AckSource>,
    provider: ProviderBilling,
    cleanup: CleanupState,
    uncertain: Vec<Uncertain>,
}

impl RevocationRun {
    /// A run from the coordinator's notice: the epoch advanced at `notice.at`, the
    /// durable decision. No acknowledgment is recorded yet; "new authorizations denied"
    /// waits for the first refused authorization CORE-04 records.
    pub fn new(
        notice: &RevocationNotice,
        cause: RevocationCause,
        lease_expiry_bound_at: MonotonicTime,
        provider_bills: bool,
    ) -> Self {
        Self {
            execution: notice.execution.clone(),
            cause,
            revoked: notice.revoked,
            current: notice.current,
            decided_at: notice.at,
            lease_expiry_bound_at: lease_expiry_bound_at.max(notice.at),
            acknowledgments: BTreeMap::new(),
            sources: BTreeMap::new(),
            provider: if provider_bills {
                ProviderBilling::AwaitingProvider
            } else {
                ProviderBilling::NotApplicable
            },
            cleanup: CleanupState::NotStarted,
            uncertain: Vec::new(),
        }
    }

    pub fn execution(&self) -> &ExecutionId {
        &self.execution
    }

    pub fn cause(&self) -> RevocationCause {
        self.cause
    }

    pub fn revoked_epoch(&self) -> AuthorizationEpoch {
        self.revoked
    }

    pub fn current_epoch(&self) -> AuthorizationEpoch {
        self.current
    }

    /// The linearization point (§2.6: no new authorization succeeds after it).
    pub fn decided_at(&self) -> MonotonicTime {
        self.decided_at
    }

    pub fn lease_expiry_bound_at(&self) -> MonotonicTime {
        self.lease_expiry_bound_at
    }

    pub fn acknowledgments(&self) -> &BTreeMap<Acknowledgment, MonotonicTime> {
        &self.acknowledgments
    }

    pub fn acknowledged_at(&self, acknowledgment: Acknowledgment) -> Option<MonotonicTime> {
        self.acknowledgments.get(&acknowledgment).copied()
    }

    /// What established `acknowledgment`, if it was recorded.
    pub fn source(&self, acknowledgment: Acknowledgment) -> Option<AckSource> {
        self.sources.get(&acknowledgment).copied()
    }

    /// How long after the decision `acknowledgment` arrived.
    pub fn elapsed(&self, acknowledgment: Acknowledgment) -> Option<Duration> {
        self.acknowledged_at(acknowledgment)
            .map(|at| at.saturating_duration_since(self.decided_at))
    }

    pub fn provider(&self) -> ProviderBilling {
        self.provider
    }

    pub fn cleanup(&self) -> &CleanupState {
        &self.cleanup
    }

    pub fn uncertain(&self) -> &[Uncertain] {
        &self.uncertain
    }

    /// Records an outcome the run could not confirm.
    pub fn record_uncertain(&mut self, outcome: Uncertain) {
        if !self.uncertain.contains(&outcome) {
            self.uncertain.push(outcome);
        }
    }

    fn record(
        &mut self,
        acknowledgment: Acknowledgment,
        at: MonotonicTime,
        source: AckSource,
    ) -> AckEffect {
        if self.acknowledgments.contains_key(&acknowledgment) {
            return AckEffect::AlreadyRecorded;
        }
        self.acknowledgments.insert(acknowledgment, at);
        self.sources.insert(acknowledgment, source);
        AckEffect::Recorded
    }

    /// Records that the VM stopped at `at`, as the supervisor observed through its
    /// checked handle. Every other acknowledgment has its own typed input and is refused
    /// here: new authorizations denied and channels closed come from CORE-04
    /// ([`RevocationRun::observe_operation`]), billing from the provider and cleanup from
    /// its report. The first record of a fact stands.
    pub fn acknowledge(
        &mut self,
        acknowledgment: Acknowledgment,
        at: MonotonicTime,
    ) -> Result<AckEffect, AckRefusal> {
        if at < self.decided_at {
            return Err(AckRefusal::BeforeDecision {
                at,
                decided_at: self.decided_at,
            });
        }
        match acknowledgment {
            Acknowledgment::ProviderBillingStopped => Err(AckRefusal::NeedsProviderAcknowledgment),
            Acknowledgment::CleanupFinished => Err(AckRefusal::NeedsCleanupReport),
            Acknowledgment::NewAuthorizationsDenied => Err(AckRefusal::TakenFromCoordination {
                milestone: RevocationMilestone::FirstDeniedAuthorization,
            }),
            Acknowledgment::ChannelsClosed => Err(AckRefusal::TakenFromCoordination {
                milestone: RevocationMilestone::AllChannelsClosed,
            }),
            Acknowledgment::VmStopped => {
                Ok(self.record(Acknowledgment::VmStopped, at, AckSource::SupervisorHandle))
            }
        }
    }

    /// Takes from CORE-04's revocation operation each acknowledgment it records that this
    /// run has not recorded yet: its first denied authorization as "new authorizations
    /// denied" and its all channels closed as "channels closed", each at the time and with
    /// what established it there. Sockets closed and leases closed are never taken as
    /// either. Refuses the operation of another revocation. Returns what was taken, in
    /// [`Acknowledgment`] order, with its time and source.
    pub fn observe_operation(
        &mut self,
        operation: &RevocationOperation,
    ) -> Result<Vec<(Acknowledgment, MonotonicTime, AckSource)>, AckRefusal> {
        let notice = operation.notice();
        if notice.execution != self.execution
            || notice.revoked != self.revoked
            || notice.current != self.current
            || notice.at != self.decided_at
        {
            return Err(AckRefusal::OtherRevocation);
        }
        let mut taken = Vec::new();
        for acknowledgment in Acknowledgment::ALL {
            let Some(milestone) = acknowledgment.milestone() else {
                continue;
            };
            if self.acknowledgments.contains_key(&acknowledgment) {
                continue;
            }
            let (Some(at), Some(source)) = (
                operation.milestone(milestone),
                operation.milestone_source(milestone),
            ) else {
                continue;
            };
            if at < self.decided_at {
                return Err(AckRefusal::BeforeDecision {
                    at,
                    decided_at: self.decided_at,
                });
            }
            let source = AckSource::Coordination { milestone, source };
            self.record(acknowledgment, at, source);
            taken.push((acknowledgment, at, source));
        }
        Ok(taken)
    }

    /// Records the provider's acknowledgment that billing stopped.
    pub fn provider_acknowledged(
        &mut self,
        acknowledgment: ProviderAcknowledgment,
    ) -> Result<AckEffect, AckRefusal> {
        match self.provider {
            ProviderBilling::NotApplicable => Err(AckRefusal::NoProvider),
            ProviderBilling::Stopped { .. } => Ok(AckEffect::AlreadyRecorded),
            ProviderBilling::AwaitingProvider => {
                if acknowledgment.at < self.decided_at {
                    return Err(AckRefusal::BeforeDecision {
                        at: acknowledgment.at,
                        decided_at: self.decided_at,
                    });
                }
                self.provider = ProviderBilling::Stopped {
                    provider: acknowledgment.provider,
                    at: acknowledgment.at,
                };
                Ok(self.record(
                    Acknowledgment::ProviderBillingStopped,
                    acknowledgment.at,
                    AckSource::Provider {
                        provider: acknowledgment.provider,
                    },
                ))
            }
        }
    }

    /// Whether the VM may be terminated at `now` under `timing` (§6.3 steps 3–4).
    pub fn termination_gate(
        &self,
        now: MonotonicTime,
        timing: TerminationTiming,
    ) -> TerminationGate {
        if timing == TerminationTiming::Immediate {
            return TerminationGate::Immediate;
        }
        if self
            .acknowledgments
            .contains_key(&Acknowledgment::ChannelsClosed)
        {
            return TerminationGate::ChannelsClosed;
        }
        if now >= self.lease_expiry_bound_at {
            TerminationGate::BoundReached {
                bound_at: self.lease_expiry_bound_at,
            }
        } else {
            TerminationGate::Wait {
                until: self.lease_expiry_bound_at,
            }
        }
    }

    /// Notes that the lease-expiry bound passed without the channels being acknowledged
    /// closed: an uncertain outcome, recorded once.
    pub fn note_bound_reached(&mut self, now: MonotonicTime) {
        if now >= self.lease_expiry_bound_at
            && !self
                .acknowledgments
                .contains_key(&Acknowledgment::ChannelsClosed)
        {
            self.record_uncertain(Uncertain::ChannelsUnacknowledged {
                bound_at: self.lease_expiry_bound_at,
            });
        }
    }

    /// Starts the bounded cleanup once the VM stopped (§6.5: cleanup time is separate
    /// and security revocation does not wait for it).
    pub fn start_cleanup(
        &mut self,
        now: MonotonicTime,
        bound: Duration,
    ) -> Result<AckEffect, AckRefusal> {
        if !self
            .acknowledgments
            .contains_key(&Acknowledgment::VmStopped)
        {
            return Err(AckRefusal::VmNotStopped);
        }
        match self.cleanup {
            CleanupState::NotStarted => {
                self.cleanup = CleanupState::Started {
                    at: now,
                    bound_at: now.saturating_add(bound),
                };
                Ok(AckEffect::Recorded)
            }
            CleanupState::Started { .. } => Ok(AckEffect::AlreadyRecorded),
            CleanupState::Finished { .. } => Err(AckRefusal::CleanupAlreadyFinished),
        }
    }

    /// Notes that the cleanup bound passed without a finish: recorded as incomplete, once.
    pub fn note_cleanup_bound(&mut self, now: MonotonicTime) {
        if let CleanupState::Started { bound_at, .. } = self.cleanup {
            if now > bound_at {
                self.record_uncertain(Uncertain::CleanupIncomplete { bound_at });
            }
        }
    }

    /// Finishes cleanup with `report`, which is always a logical cleanup (§6.5). A finish
    /// after the bound is recorded as late.
    pub fn finish_cleanup(
        &mut self,
        now: MonotonicTime,
        report: CleanupReport,
    ) -> Result<bool, AckRefusal> {
        match self.cleanup {
            CleanupState::NotStarted => Err(AckRefusal::CleanupNotStarted),
            CleanupState::Finished { .. } => Err(AckRefusal::CleanupAlreadyFinished),
            CleanupState::Started { bound_at, .. } => {
                let late = now > bound_at;
                self.cleanup = CleanupState::Finished {
                    at: now,
                    report,
                    late,
                };
                self.record(
                    Acknowledgment::CleanupFinished,
                    now,
                    AckSource::CleanupReport,
                );
                Ok(late)
            }
        }
    }

    /// Whether the revocation is complete: every applicable acknowledgment recorded.
    pub fn is_complete(&self) -> bool {
        self.pending().is_empty()
    }

    /// The acknowledgments still outstanding.
    pub fn pending(&self) -> Vec<Acknowledgment> {
        Acknowledgment::ALL
            .into_iter()
            .filter(|acknowledgment| !self.acknowledgments.contains_key(acknowledgment))
            .filter(|acknowledgment| {
                *acknowledgment != Acknowledgment::ProviderBillingStopped
                    || self.provider != ProviderBilling::NotApplicable
            })
            .collect()
    }

    pub fn progress(&self, now: MonotonicTime, timing: TerminationTiming) -> RevocationProgress {
        RevocationProgress {
            execution: self.execution.clone(),
            decided_at: self.decided_at,
            acknowledged: self.acknowledgments.keys().copied().collect(),
            pending: self.pending(),
            gate: self.termination_gate(now, timing),
            uncertain: self.uncertain.len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::evidence::SourceClass;
    use crate::foundation::ids::digest;
    use serde_json::json;

    fn at(seconds: u64) -> MonotonicTime {
        MonotonicTime::from_nanos(seconds * 1_000_000_000)
    }

    fn nanos(seconds: u64) -> u64 {
        at(seconds).as_nanos()
    }

    fn notice() -> RevocationNotice {
        RevocationNotice {
            execution: ExecutionId::new("exe-a").unwrap(),
            revoked: AuthorizationEpoch::FIRST,
            current: AuthorizationEpoch::new(2),
            at: at(100),
        }
    }

    fn run(provider: bool) -> RevocationRun {
        RevocationRun::new(&notice(), RevocationCause::UserRequested, at(160), provider)
    }

    /// A CORE-04 revocation operation in its persisted form, for unit tests of the run
    /// alone; the supervisor's tests drive the real coordinator.
    fn operation(
        notice: &RevocationNotice,
        milestones: serde_json::Value,
        sources: serde_json::Value,
        first_denial: serde_json::Value,
    ) -> RevocationOperation {
        serde_json::from_value(json!({
            "notice": notice,
            "cancellations": [],
            "ledger": null,
            "milestones": milestones,
            "sources": sources,
            "first_denial": first_denial,
            "uncertain": [],
        }))
        .unwrap()
    }

    /// CORE-04's record of the decision at 100, a first refusal by a host-observed
    /// enforcement point at `denied`, and all channels closed at `closed`, when given.
    fn core04(denied: Option<u64>, closed: Option<u64>) -> RevocationOperation {
        let mut milestones = json!({"new_authorizations_denied": nanos(100)});
        let mut sources = json!({"new_authorizations_denied": {"established_by": "coordinator"}});
        if let Some(closed) = closed {
            milestones["all_channels_closed"] = nanos(closed).into();
            milestones["sockets_closed"] = nanos(closed).into();
            sources["all_channels_closed"] =
                json!({"established_by": "acknowledged", "source": "host_probe"});
            sources["sockets_closed"] = json!({
                "established_by": "implied_by",
                "by": "all_channels_closed",
                "source": "host_probe"
            });
        }
        let first_denial = match denied {
            Some(denied) => json!({
                "at": nanos(denied),
                "denial": {"denied_by": "enforcement_point", "source": "host_probe"}
            }),
            None => serde_json::Value::Null,
        };
        operation(&notice(), milestones, sources, first_denial)
    }

    fn host_acknowledged(milestone: RevocationMilestone) -> AckSource {
        AckSource::Coordination {
            milestone,
            source: MilestoneSource::Acknowledged {
                source: SourceClass::HostProbe,
            },
        }
    }

    #[test]
    fn the_five_acknowledgments_are_distinct_facts() {
        let mut run = run(true);
        assert!(
            run.acknowledgments().is_empty(),
            "the decision alone acknowledges nothing"
        );
        assert_eq!(run.decided_at(), at(100));
        assert_eq!(run.pending(), Acknowledgment::ALL.to_vec());

        // New authorizations denied and channels closed are CORE-04's to record.
        assert_eq!(
            run.acknowledge(Acknowledgment::NewAuthorizationsDenied, at(101)),
            Err(AckRefusal::TakenFromCoordination {
                milestone: RevocationMilestone::FirstDeniedAuthorization
            })
        );
        assert_eq!(
            run.acknowledge(Acknowledgment::ChannelsClosed, at(101)),
            Err(AckRefusal::TakenFromCoordination {
                milestone: RevocationMilestone::AllChannelsClosed
            })
        );
        assert!(run.acknowledgments().is_empty());
        let taken = run
            .observe_operation(&core04(Some(100), Some(101)))
            .unwrap();
        assert_eq!(
            taken,
            vec![
                (
                    Acknowledgment::NewAuthorizationsDenied,
                    at(100),
                    host_acknowledged(RevocationMilestone::FirstDeniedAuthorization)
                ),
                (
                    Acknowledgment::ChannelsClosed,
                    at(101),
                    host_acknowledged(RevocationMilestone::AllChannelsClosed)
                ),
            ]
        );
        assert_eq!(
            run.source(Acknowledgment::NewAuthorizationsDenied),
            Some(host_acknowledged(
                RevocationMilestone::FirstDeniedAuthorization
            ))
        );
        // The first record stands: observing again takes nothing.
        assert!(run
            .observe_operation(&core04(Some(100), Some(101)))
            .unwrap()
            .is_empty());
        assert_eq!(
            run.elapsed(Acknowledgment::NewAuthorizationsDenied),
            Some(Duration::ZERO)
        );
        assert_eq!(
            run.elapsed(Acknowledgment::ChannelsClosed),
            Some(Duration::from_secs(1))
        );
        assert_eq!(run.acknowledged_at(Acknowledgment::VmStopped), None);
        assert_eq!(
            run.acknowledge(Acknowledgment::ProviderBillingStopped, at(102)),
            Err(AckRefusal::NeedsProviderAcknowledgment)
        );
        assert_eq!(
            run.acknowledge(Acknowledgment::CleanupFinished, at(102)),
            Err(AckRefusal::NeedsCleanupReport)
        );
        assert_eq!(
            run.acknowledge(Acknowledgment::VmStopped, at(99)),
            Err(AckRefusal::BeforeDecision {
                at: at(99),
                decided_at: at(100)
            })
        );
        assert_eq!(
            run.start_cleanup(at(102), Duration::from_secs(10)),
            Err(AckRefusal::VmNotStopped)
        );
        run.acknowledge(Acknowledgment::VmStopped, at(102)).unwrap();
        assert_eq!(
            run.source(Acknowledgment::VmStopped),
            Some(AckSource::SupervisorHandle)
        );
        assert_eq!(
            run.acknowledged_at(Acknowledgment::ProviderBillingStopped),
            None,
            "a stopped VM does not stop provider billing"
        );
        let provider = digest("yougori/test/provider/v1", &[b"p"]);
        run.provider_acknowledged(ProviderAcknowledgment {
            provider,
            at: at(130),
        })
        .unwrap();
        assert_eq!(
            run.elapsed(Acknowledgment::ProviderBillingStopped),
            Some(Duration::from_secs(30)),
            "provider billing may outlive local shutdown"
        );
        assert_eq!(
            run.source(Acknowledgment::ProviderBillingStopped),
            Some(AckSource::Provider { provider })
        );
        assert!(!run.is_complete());
        run.start_cleanup(at(103), Duration::from_secs(10)).unwrap();
        assert_eq!(
            run.finish_cleanup(at(120), CleanupReport::logical([])),
            Ok(true),
            "a finish after the bound is late"
        );
        assert!(run.is_complete());
        assert_eq!(
            run.elapsed(Acknowledgment::CleanupFinished),
            Some(Duration::from_secs(20))
        );
        assert_eq!(
            run.source(Acknowledgment::CleanupFinished),
            Some(AckSource::CleanupReport)
        );
        let mut without =
            super::RevocationRun::new(&notice(), RevocationCause::Violation, at(160), false);
        assert_eq!(
            without.provider_acknowledged(ProviderAcknowledgment {
                provider,
                at: at(130)
            }),
            Err(AckRefusal::NoProvider)
        );
        assert!(!without
            .pending()
            .contains(&Acknowledgment::ProviderBillingStopped));
    }

    #[test]
    fn sockets_closed_is_never_channels_closed_nor_a_denial() {
        let mut run = run(false);
        let sockets_only = operation(
            &notice(),
            json!({"new_authorizations_denied": nanos(100), "sockets_closed": nanos(101)}),
            json!({
                "new_authorizations_denied": {"established_by": "coordinator"},
                "sockets_closed": {"established_by": "acknowledged", "source": "host_probe"}
            }),
            serde_json::Value::Null,
        );
        assert!(run.observe_operation(&sockets_only).unwrap().is_empty());
        assert_eq!(
            run.pending(),
            vec![
                Acknowledgment::NewAuthorizationsDenied,
                Acknowledgment::ChannelsClosed,
                Acknowledgment::VmStopped,
                Acknowledgment::CleanupFinished
            ],
            "CORE-04's decision is not a denied authorization, and sockets are not every \
             channel"
        );
        assert_eq!(
            run.termination_gate(
                at(120),
                TerminationTiming::AfterChannelAcknowledgmentOrBound
            ),
            TerminationGate::Wait { until: at(160) }
        );
    }

    #[test]
    fn another_revocations_operation_is_refused() {
        let mut run = run(false);
        let mut later = notice();
        later.at = at(200);
        let other = operation(
            &later,
            json!({"new_authorizations_denied": nanos(200)}),
            json!({"new_authorizations_denied": {"established_by": "coordinator"}}),
            serde_json::Value::Null,
        );
        assert_eq!(
            run.observe_operation(&other),
            Err(AckRefusal::OtherRevocation)
        );
        let mut elsewhere = notice();
        elsewhere.execution = ExecutionId::new("exe-b").unwrap();
        let other = operation(
            &elsewhere,
            json!({"new_authorizations_denied": nanos(100)}),
            json!({"new_authorizations_denied": {"established_by": "coordinator"}}),
            json!({
                "at": nanos(100),
                "denial": {"denied_by": "enforcement_point", "source": "host_probe"}
            }),
        );
        assert_eq!(
            run.observe_operation(&other),
            Err(AckRefusal::OtherRevocation)
        );
        assert!(run.acknowledgments().is_empty());
        assert!(AckRefusal::OtherRevocation
            .to_string()
            .contains("another revocation"));
        assert!(AckRefusal::TakenFromCoordination {
            milestone: RevocationMilestone::AllChannelsClosed
        }
        .to_string()
        .contains("all channels closed"));
    }

    #[test]
    fn termination_waits_for_the_channels_or_the_lease_expiry_bound() {
        let mut run = run(false);
        let waiting = TerminationTiming::AfterChannelAcknowledgmentOrBound;
        assert_eq!(
            run.termination_gate(at(120), waiting),
            TerminationGate::Wait { until: at(160) }
        );
        assert_eq!(
            run.termination_gate(at(120), TerminationTiming::Immediate),
            TerminationGate::Immediate
        );
        run.note_bound_reached(at(120));
        assert!(run.uncertain().is_empty());
        assert_eq!(
            run.termination_gate(at(160), waiting),
            TerminationGate::BoundReached { bound_at: at(160) }
        );
        run.note_bound_reached(at(160));
        assert_eq!(
            run.uncertain(),
            [Uncertain::ChannelsUnacknowledged { bound_at: at(160) }]
        );
        run.observe_operation(&core04(None, Some(161))).unwrap();
        assert_eq!(
            run.termination_gate(at(161), waiting),
            TerminationGate::ChannelsClosed
        );
        let progress = run.progress(at(161), waiting);
        assert_eq!(progress.uncertain, 1);
        assert_eq!(
            progress.pending,
            vec![
                Acknowledgment::NewAuthorizationsDenied,
                Acknowledgment::VmStopped,
                Acknowledgment::CleanupFinished
            ],
            "closed channels never imply a denied authorization"
        );
    }

    #[test]
    fn every_cause_maps_to_a_core06_reason_and_the_run_round_trips() {
        for cause in [
            RevocationCause::UserRequested,
            RevocationCause::PolicyChanged,
            RevocationCause::LeaseExpired {
                kind: LimitKind::Idle,
            },
            RevocationCause::Violation,
            RevocationCause::EngineDied,
            RevocationCause::ServiceRenewal,
            RevocationCause::OwnerReclaimed,
            RevocationCause::ClockRolledBack,
        ] {
            let _ = cause.reason();
        }
        assert_eq!(
            RevocationCause::Violation.reason(),
            RevocationReason::SecurityEvent
        );
        assert_eq!(
            RevocationCause::LeaseExpired {
                kind: LimitKind::Absolute
            }
            .reason(),
            RevocationReason::AuthorizationExpired
        );
        let mut run = run(true);
        let json = serde_json::to_string(&run).unwrap();
        assert_eq!(serde_json::from_str::<RevocationRun>(&json).unwrap(), run);
        run.observe_operation(&core04(Some(100), Some(101)))
            .unwrap();
        let json = serde_json::to_value(&run).unwrap();
        assert_eq!(
            json["sources"]["channels_closed"]["by"], "coordination",
            "{json}"
        );
        assert_eq!(
            serde_json::from_value::<RevocationRun>(json.clone()).unwrap(),
            run
        );
        let mut forged = json;
        forged["sources"]["vm_stopped"] = json!({"by": "guest"});
        assert!(serde_json::from_value::<RevocationRun>(forged).is_err());
    }
}
