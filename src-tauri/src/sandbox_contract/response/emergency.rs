//! Emergency revocation that audit overload cannot block (VM-W43 line 2491: "audit overload
//! cannot block emergency revocation"; §8.2 line 2270: "Audit failure has a defined policy:
//! deny new high-impact operations or use a bounded local spool; never block the revocation
//! channel"; §6.3 lines 2131–2137).
//!
//! [`emergency_revoke`] revokes through CORE-04 first (the durable epoch advance), puts the
//! revocation on the CORE-06 priority lane second, keeps it on the coordinator's durable
//! revocation stream third, and only then offers its record to the audit journal, through
//! CORE-04's `revoke_and_publish_durably` (docs/combined-plan-leftover-tasks.md S06). A full
//! or failing journal refuses the record and nothing else: the revocation is already in
//! force. The record then waits in a bounded [`DeferredAudit`] to be written afterward, and
//! [`HighImpactGate`] denies new high-impact operations while any record waits or the
//! journal fails closed.
//!
//! [`revoke_shared_grant`] does the same for one grant of a bystander sandbox: CORE-04's
//! tombstone first (`revoke_grant_and_publish_durably`), the lane second, the durable
//! stream third, the journal last, its refused record deferred in the same queue.
//!
//! The durable revocation stream (a `RevocationLog` the coordinator owns) is what lets a
//! restart that comes before the next persisted state still end a revoked sandbox and keep a
//! revoked grant's tombstone (`PersistedState::adopt_revocations`). Its refusal (storage
//! full or failing, a stream owned under the lane issuer's name) follows the same policy as
//! an audit refusal (§8.2 line 2270 audit failure policy; VM-W43 line 2491): it never undoes
//! or delays the revocation, which CORE-04 already holds and the lane already carried, and
//! it is never silent. The receipt reports it (`recorded`), the revocation waits in the
//! [`DeferredAudit`] as an [`UnrecordedRevocation`] under the operation it was published
//! with, and [`HighImpactGate`] denies new high-impact operations
//! ([`HighImpactDenial::RevocationsNotDurable`]) until [`DeferredAudit::record_unrecorded`]
//! has put every one on the stream. That denial comes first, since a restart would forget
//! such a revocation. These waiting revocations are not bounded by the queue's capacity:
//! there is at most one per revoked sandbox and one per revoked grant, no more than the
//! coordinator itself holds, and dropping one would lose a revocation across a restart.
//!
//! [`execute_target`] carries one target of a response out on the coordinator: the
//! revocation or grant revocation as above and a stop through V05's
//! [`respond_to_violation`](crate::sandbox_contract::files::respond_to_violation), which
//! holds VM-D10. Isolation, high-impact denial, corroboration requests and notification
//! are returned for the runtime, which owns the perimeter and the UI.

use std::collections::VecDeque;
use std::fmt;

use serde::Serialize;

use super::policy::{ResponseAction, RevokePolicy};
use super::responder::{NotificationOutcome, TargetResponse, TargetRole};
use crate::foundation::coordination::{
    CapacityPort, CoordinationError, Coordinator, RevocationEvents, RevocationNotice, RevokedGrant,
    SandboxPort,
};
use crate::foundation::events::{
    AuditAppendAuthority, AuditDraft, AuditHealth, AuditJournal, AuditReceipt, AuditRefusal,
    AuditSpool, AuditStore, Durability, DurablyPublished, EmitError, EventContext, EventSequence,
    Field, Generations, GrantRevocation, HostFact, Phase, RecordError, Revocation,
    RevocationAdmission, RevocationIssuer, RevocationLog, StoreRefusal,
};
use crate::foundation::ids::{
    AuthorizationEpoch, Clock, ExecutionId, GrantId, MonotonicTime, OperationId,
};
use crate::sandbox_contract::files::{respond_to_violation, ViolationOutcome};

/// Revocation records the journal refused, waiting to be written afterward (§8.2 "a
/// bounded local spool"). One whole-revocation record per execution is kept, the highest
/// epoch winning, as on the CORE-06 lane, and one grant-revocation record per execution
/// and grant; past the bound, records are counted and the count is written as its own
/// record, so a lost record is visible rather than silent.
///
/// Apart from those records it keeps the revocations the durable revocation stream refused
/// ([`UnrecordedRevocation`]), one per execution and one per execution and grant, until
/// [`DeferredAudit::record_unrecorded`] puts them on the stream (S06). The capacity does
/// not bound them, and [`DeferredAudit::len`], [`DeferredAudit::is_empty`] and
/// [`DeferredAudit::pending`] leave them out; [`DeferredAudit::unrecorded`] lists them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeferredAudit {
    capacity_records: usize,
    pending: VecDeque<DeferredRecord>,
    overflowed: u64,
    unrecorded: VecDeque<UnrecordedRevocation>,
}

/// A revocation in force that the coordinator's durable revocation stream refused, waiting
/// to be recorded there (S06; §8.2 audit failure policy): a restart before the next
/// persisted state would forget it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnrecordedRevocation {
    /// The revocation as the stream keeps it.
    pub record: DeferredRecord,
    /// The operation it was published under, so its record still correlates with the
    /// lane's notice and the audit record.
    pub operation: OperationId,
    /// When the coordinator revoked, on its clock.
    pub at: MonotonicTime,
    /// Why the stream refused it last.
    pub refusal: RecordError,
}

/// What one [`DeferredAudit::record_unrecorded`] put on the durable revocation stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnrecordedRetry {
    /// Where the stream keeps each revocation recorded, in the order they waited.
    pub recorded: Vec<EventSequence>,
    /// Revocations still waiting.
    pub remaining: usize,
    /// Why the stream stopped the retry.
    pub refusal: Option<RecordError>,
}

/// One revocation record waiting to be written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeferredRecord {
    /// A sandbox's whole authority was revoked.
    Revocation(Revocation),
    /// One grant was revoked under a sandbox's authority.
    Grant(GrantRevocation),
}

impl DeferredRecord {
    /// The authorization epoch the record carries.
    pub const fn epoch(&self) -> AuthorizationEpoch {
        match self {
            Self::Revocation(revocation) => revocation.epoch,
            Self::Grant(revocation) => revocation.epoch,
        }
    }

    fn draft(&self) -> AuditDraft {
        match self {
            Self::Revocation(revocation) => AuditDraft::Revocation(revocation.clone()),
            Self::Grant(revocation) => AuditDraft::GrantRevocation(revocation.clone()),
        }
    }
}

/// Why a deferred audit queue was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeferredProblem {
    ZeroCapacity,
}

impl fmt::Display for DeferredProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the deferred audit queue holds no record")
    }
}

impl std::error::Error for DeferredProblem {}

/// What the queue did with one revocation record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Deferral {
    Queued,
    /// Replaced the waiting record of the same execution with this higher epoch.
    Raised,
    /// A record of the same execution with an equal or higher epoch already waits.
    AlreadyCovered,
    /// The queue was full: counted, and the count is written afterward.
    Overflowed,
}

/// What one flush wrote.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeferredFlush {
    pub written: usize,
    pub remaining: usize,
    /// The overflow count written as its own record, if one was written.
    pub overflow_recorded: Option<u64>,
    /// Why the journal stopped the flush.
    pub refusal: Option<AuditRefusal>,
}

impl DeferredAudit {
    /// A queue of at most `capacity_records` revocation records (§8.2 bounded spool).
    pub fn new(capacity_records: usize) -> Result<Self, DeferredProblem> {
        if capacity_records == 0 {
            return Err(DeferredProblem::ZeroCapacity);
        }
        Ok(Self {
            capacity_records,
            pending: VecDeque::new(),
            overflowed: 0,
            unrecorded: VecDeque::new(),
        })
    }

    /// Records waiting to be written.
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Whether no record waits.
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Records counted past the bound and not yet written as a count.
    pub const fn overflowed(&self) -> u64 {
        self.overflowed
    }

    /// The waiting records, oldest first.
    pub fn pending(&self) -> impl Iterator<Item = &DeferredRecord> {
        self.pending.iter()
    }

    /// Keeps one whole-revocation record for later.
    pub fn defer(&mut self, revocation: Revocation) -> Deferral {
        let waiting = self.pending.iter_mut().find_map(|waiting| match waiting {
            DeferredRecord::Revocation(waiting) if waiting.execution == revocation.execution => {
                Some(waiting)
            }
            _ => None,
        });
        if let Some(waiting) = waiting {
            if revocation.epoch > waiting.epoch {
                *waiting = revocation;
                return Deferral::Raised;
            }
            return Deferral::AlreadyCovered;
        }
        self.queue(DeferredRecord::Revocation(revocation))
    }

    /// Keeps one grant-revocation record for later.
    pub fn defer_grant(&mut self, revocation: GrantRevocation) -> Deferral {
        let covered = self.pending.iter().any(|waiting| match waiting {
            DeferredRecord::Grant(waiting) => {
                waiting.execution == revocation.execution && waiting.grant == revocation.grant
            }
            DeferredRecord::Revocation(_) => false,
        });
        if covered {
            return Deferral::AlreadyCovered;
        }
        self.queue(DeferredRecord::Grant(revocation))
    }

    fn queue(&mut self, record: DeferredRecord) -> Deferral {
        if self.pending.len() < self.capacity_records {
            self.pending.push_back(record);
            return Deferral::Queued;
        }
        self.overflowed = self.overflowed.saturating_add(1);
        Deferral::Overflowed
    }

    /// Writes the waiting records in order, then the overflow count, stopping at the first
    /// refusal. A refused record the journal kept (storage may hold it) is the journal's to
    /// offer again, so it leaves this queue.
    pub fn flush<S: AuditStore, Q: AuditSpool, J: Clock>(
        &mut self,
        journal: &mut AuditJournal<S, Q, J>,
        authority: &mut AuditAppendAuthority,
        operation: &OperationId,
    ) -> DeferredFlush {
        let mut written = 0;
        while let Some(front) = self.pending.front() {
            let context = EventContext::new(operation.clone(), Phase::Revoked)
                .with_generations(Generations::NONE.with_authorization(front.epoch()));
            match journal.append(authority, context, front.draft()) {
                Ok(_) => {
                    self.pending.pop_front();
                    written += 1;
                }
                Err(refusal) => {
                    if matches!(refusal, AuditRefusal::FailClosed { kept: Some(_), .. }) {
                        self.pending.pop_front();
                    }
                    return DeferredFlush {
                        written,
                        remaining: self.pending.len(),
                        overflow_recorded: None,
                        refusal: Some(refusal),
                    };
                }
            }
        }
        let mut flush = DeferredFlush {
            written,
            remaining: 0,
            overflow_recorded: None,
            refusal: None,
        };
        if self.overflowed > 0 {
            let draft = AuditDraft::HostFact {
                fact: HostFact::AuthorizationDecision,
                fields: vec![
                    Field::metadata("event", "deferred_revocation_records_overflowed"),
                    Field::metadata("records", self.overflowed),
                ],
            };
            match journal.append(
                authority,
                EventContext::new(operation.clone(), Phase::Revoked),
                draft,
            ) {
                Ok(_) => {
                    flush.overflow_recorded = Some(self.overflowed);
                    self.overflowed = 0;
                }
                Err(refusal) => flush.refusal = Some(refusal),
            }
        }
        flush
    }

    /// Revocations the durable revocation stream refused, oldest first, waiting to be
    /// recorded there.
    pub fn unrecorded(&self) -> impl Iterator<Item = &UnrecordedRevocation> {
        self.unrecorded.iter()
    }

    /// How many revocations wait to be recorded on the durable revocation stream.
    pub fn unrecorded_len(&self) -> usize {
        self.unrecorded.len()
    }

    /// Keeps a revocation the durable revocation stream refused until it is recorded: one
    /// per execution, the highest epoch winning, and one per execution and grant.
    fn keep_unrecorded(&mut self, unrecorded: UnrecordedRevocation) {
        let waiting = self.unrecorded.iter_mut().find(|waiting| {
            match (&waiting.record, &unrecorded.record) {
                (DeferredRecord::Revocation(waiting), DeferredRecord::Revocation(revocation)) => {
                    waiting.execution == revocation.execution
                }
                (DeferredRecord::Grant(waiting), DeferredRecord::Grant(revocation)) => {
                    waiting.execution == revocation.execution && waiting.grant == revocation.grant
                }
                _ => false,
            }
        });
        match waiting {
            Some(waiting) if unrecorded.record.epoch() > waiting.record.epoch() => {
                *waiting = unrecorded;
            }
            Some(waiting) => waiting.refusal = unrecorded.refusal,
            None => self.unrecorded.push_back(unrecorded),
        }
    }

    /// Records the revocations the durable revocation stream refused on `log`, oldest first,
    /// each under the operation and time it was published with, and stops at the first
    /// refusal (S06). As CORE-04's publisher does, it refuses a stream owned under the name
    /// of the lane's `issuer`. Once none waits, [`HighImpactGate`] no longer denies for them.
    pub fn record_unrecorded(
        &mut self,
        log: &mut RevocationLog,
        issuer: &RevocationIssuer,
    ) -> UnrecordedRetry {
        let mut recorded = Vec::new();
        while let Some(front) = self.unrecorded.front_mut() {
            match front.record_on(log, issuer) {
                Ok(sequence) => {
                    self.unrecorded.pop_front();
                    recorded.push(sequence);
                }
                Err(refusal) => {
                    front.refusal = refusal.clone();
                    return UnrecordedRetry {
                        recorded,
                        remaining: self.unrecorded.len(),
                        refusal: Some(refusal),
                    };
                }
            }
        }
        UnrecordedRetry {
            recorded,
            remaining: 0,
            refusal: None,
        }
    }
}

impl UnrecordedRevocation {
    /// Records this revocation on `log` with the context CORE-04's publisher gives it: its
    /// operation, the phase `Revoked` and the authorization epoch it carries.
    fn record_on(
        &self,
        log: &mut RevocationLog,
        issuer: &RevocationIssuer,
    ) -> Result<EventSequence, RecordError> {
        let producer = issuer.key().producer;
        if log.owner() == &producer {
            return Err(RecordError::SharedProducer { producer });
        }
        let context = EventContext::new(self.operation.clone(), Phase::Revoked)
            .with_generations(Generations::NONE.with_authorization(self.record.epoch()));
        match &self.record {
            DeferredRecord::Revocation(revocation) => {
                log.record(context, self.at, revocation.clone())
            }
            DeferredRecord::Grant(revocation) => {
                log.record_grant(context, self.at, revocation.clone())
            }
        }
    }
}

/// Where a revocation's audit record went.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RevocationAudit {
    /// Stored, or waiting in the journal's own bounded spool.
    Written { durability: Durability },
    /// Storage may hold the record, so the journal keeps exactly it under `sequence` and
    /// offers it again before any other.
    KeptByJournal {
        sequence: EventSequence,
        refusal: AuditRefusal,
    },
    /// The journal refused it; it waits in the [`DeferredAudit`].
    Deferred {
        deferral: Deferral,
        refusal: AuditRefusal,
    },
}

/// Why new high-impact operations are denied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HighImpactDenial {
    /// The journal fails closed (§8.2 audit failure policy).
    AuditFailClosed { store: StoreRefusal },
    /// Revocation records wait to be written.
    RevocationRecordsDeferred { pending: usize, overflowed: u64 },
    /// Revocations in force wait to be recorded on the durable revocation stream (S06): a
    /// restart before the next persisted state would forget them.
    RevocationsNotDurable { unrecorded: usize },
}

/// Whether new high-impact operations may proceed while audit or the durable revocation
/// stream is degraded (§8.2: "deny new high-impact operations or use a bounded local
/// spool"). A high-impact operation still needs its own receipt from
/// `AuditJournal::admit_high_impact`; this gate only adds the denial while revocation
/// records wait, for the journal or for the durable revocation stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HighImpactGate {
    Admitted,
    /// The journal spools and its policy lets high-impact operations go ahead on a spooled
    /// record.
    AdmittedOnSpool,
    Denied {
        reason: HighImpactDenial,
    },
}

impl HighImpactGate {
    /// The gate for the journal's `health` and the waiting records (§8.2 audit failure
    /// policy). Revocations not yet on the durable revocation stream are named first.
    pub fn judge(health: AuditHealth, deferred: &DeferredAudit) -> Self {
        if deferred.unrecorded_len() > 0 {
            return Self::Denied {
                reason: HighImpactDenial::RevocationsNotDurable {
                    unrecorded: deferred.unrecorded_len(),
                },
            };
        }
        if !deferred.is_empty() || deferred.overflowed() > 0 {
            return Self::Denied {
                reason: HighImpactDenial::RevocationRecordsDeferred {
                    pending: deferred.len(),
                    overflowed: deferred.overflowed(),
                },
            };
        }
        match health {
            AuditHealth::Durable => Self::Admitted,
            AuditHealth::Spooling { .. } => Self::AdmittedOnSpool,
            AuditHealth::FailClosed { store, .. } => Self::Denied {
                reason: HighImpactDenial::AuditFailClosed { store },
            },
        }
    }

    /// Whether new high-impact operations may proceed.
    pub const fn admits(self) -> bool {
        !matches!(self, Self::Denied { .. })
    }
}

/// One emergency revocation and where its record went.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmergencyReceipt {
    /// The CORE-04 notice: the epoch advanced and new authorizations are denied.
    pub notice: RevocationNotice,
    /// The CORE-06 priority lane's admission, which nothing in audit can delay.
    pub lane: Result<RevocationAdmission, EmitError>,
    /// Where the coordinator's durable revocation stream keeps the revocation, or why it
    /// does not (S06). A refused one waits in the [`DeferredAudit`] to be recorded.
    pub recorded: Result<EventSequence, RecordError>,
    pub audit: RevocationAudit,
    pub high_impact: HighImpactGate,
    /// Post-revocation exposure (§2.5 lines 1819–1824): the latest declared bound by which
    /// the holders of the cancelled leases must have stopped; `None` when no lease was
    /// cancelled. Already committed external actions are not undone by any revocation.
    pub leases_bounded_until: Option<MonotonicTime>,
}

/// Revokes `execution` for a security event (VM-W43; §6.3 steps 1–2): CORE-04 first, the
/// priority lane second, the coordinator's durable revocation stream `log` third, the audit
/// journal last. Neither a stream refusal nor an audit refusal undoes or delays the
/// revocation; the refused revocation or record waits in `deferred`.
pub fn emergency_revoke<C, P, H, S, Q, J>(
    coordinator: &mut Coordinator<C, P>,
    events: &mut RevocationEvents<'_, H, S, Q, J>,
    log: &mut RevocationLog,
    deferred: &mut DeferredAudit,
    execution: &ExecutionId,
    operation: OperationId,
) -> Result<EmergencyReceipt, CoordinationError>
where
    C: Clock,
    P: CapacityPort,
    H: Clock,
    S: AuditStore,
    Q: AuditSpool,
    J: Clock,
{
    let DurablyPublished {
        published,
        recorded,
    } = coordinator.revoke_and_publish_durably(
        execution,
        operation.clone(),
        RevokePolicy::REASON,
        events,
        log,
    )?;
    let revocation = Revocation {
        execution: published.notice.execution.clone(),
        epoch: published.notice.current,
        reason: RevokePolicy::REASON,
    };
    if let Err(refusal) = &recorded {
        deferred.keep_unrecorded(UnrecordedRevocation {
            record: DeferredRecord::Revocation(revocation.clone()),
            operation,
            at: published.notice.at,
            refusal: refusal.clone(),
        });
    }
    let audit = audit_outcome(published.audit, deferred, |deferred| {
        deferred.defer(revocation)
    });
    let high_impact = HighImpactGate::judge(events.journal.health(), deferred);
    let leases_bounded_until = coordinator.revocation(execution).and_then(|operation| {
        operation
            .cancellations()
            .iter()
            .map(|cancellation| cancellation.bound_at)
            .max()
    });
    Ok(EmergencyReceipt {
        notice: published.notice,
        lane: published.lane,
        recorded,
        audit,
        high_impact,
        leases_bounded_until,
    })
}

/// Where the journal's answer leaves a revocation's record: written, kept by the journal,
/// or deferred through `defer`.
fn audit_outcome(
    audit: Result<AuditReceipt, AuditRefusal>,
    deferred: &mut DeferredAudit,
    defer: impl FnOnce(&mut DeferredAudit) -> Deferral,
) -> RevocationAudit {
    match audit {
        Ok(receipt) => RevocationAudit::Written {
            durability: receipt.durability,
        },
        Err(refusal) => {
            let kept = match &refusal {
                AuditRefusal::FailClosed { kept, .. } => *kept,
                _ => None,
            };
            match kept {
                Some(sequence) => RevocationAudit::KeptByJournal { sequence, refusal },
                None => RevocationAudit::Deferred {
                    deferral: defer(deferred),
                    refusal,
                },
            }
        }
    }
}

/// One grant revocation of a bystander sandbox and where its record went.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantRevocationReceipt {
    /// CORE-04's record: the tombstone, the epoch it left unchanged and the leases bound to
    /// the grant it cancelled.
    pub revoked: RevokedGrant,
    /// The CORE-06 priority lane's admission, which nothing in audit can delay.
    pub lane: Result<RevocationAdmission, EmitError>,
    /// Where the coordinator's durable revocation stream keeps the grant's tombstone, or why
    /// it does not (S06). A refused one waits in the [`DeferredAudit`] to be recorded.
    pub recorded: Result<EventSequence, RecordError>,
    pub audit: RevocationAudit,
    pub high_impact: HighImpactGate,
    /// The latest declared bound by which the holders of the leases bound to the grant
    /// must have stopped; `None` when none was cancelled.
    pub leases_bounded_until: Option<MonotonicTime>,
}

/// Revokes one grant under a bystander's authority (VM-W43; §6.3 step 1: a tombstone):
/// CORE-04 first, the priority lane second, the coordinator's durable revocation stream
/// `log` third, the audit journal last. The sandbox keeps its authorization epoch and every
/// other grant. Neither a stream refusal nor an audit refusal undoes or delays the
/// revocation; the refused revocation or record waits in `deferred`.
pub fn revoke_shared_grant<C, P, H, S, Q, J>(
    coordinator: &mut Coordinator<C, P>,
    events: &mut RevocationEvents<'_, H, S, Q, J>,
    log: &mut RevocationLog,
    deferred: &mut DeferredAudit,
    execution: &ExecutionId,
    grant: GrantId,
    operation: OperationId,
) -> Result<GrantRevocationReceipt, CoordinationError>
where
    C: Clock,
    P: CapacityPort,
    H: Clock,
    S: AuditStore,
    Q: AuditSpool,
    J: Clock,
{
    let DurablyPublished {
        published,
        recorded,
    } = coordinator.revoke_grant_and_publish_durably(
        execution,
        grant,
        operation.clone(),
        RevokePolicy::REASON,
        events,
        log,
    )?;
    let revoked = published.revoked;
    let revocation = GrantRevocation {
        execution: revoked.execution.clone(),
        grant: revoked.grant,
        epoch: revoked.epoch,
        reason: RevokePolicy::REASON,
    };
    if let Err(refusal) = &recorded {
        deferred.keep_unrecorded(UnrecordedRevocation {
            record: DeferredRecord::Grant(revocation.clone()),
            operation,
            at: revoked.at,
            refusal: refusal.clone(),
        });
    }
    let audit = audit_outcome(published.audit, deferred, |deferred| {
        deferred.defer_grant(revocation)
    });
    let high_impact = HighImpactGate::judge(events.journal.health(), deferred);
    let leases_bounded_until = revoked
        .cancellations
        .iter()
        .map(|cancellation| cancellation.bound_at)
        .max();
    Ok(GrantRevocationReceipt {
        revoked,
        lane: published.lane,
        recorded,
        audit,
        high_impact,
        leases_bounded_until,
    })
}

/// What carrying out one target did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetExecution {
    pub sandbox: ExecutionId,
    /// The revocation, when the target newly revokes.
    pub revocation: Option<EmergencyReceipt>,
    /// The grant revocation, when a bystander target newly loses the violated grant.
    pub grant_revocation: Option<GrantRevocationReceipt>,
    /// V05's VM-D10 outcome, when the target newly stops.
    pub class_response: Option<ViolationOutcome>,
    /// Restrictions left for the runtime: corroboration requests, high-impact denial and
    /// isolation, in ladder order.
    pub runtime_actions: Vec<ResponseAction>,
    /// The notification for the runtime to deliver to the user, if one was sent.
    pub notification: Option<NotificationOutcome>,
}

/// Carries out the new actions of one target on the CORE-04 coordinator: a revocation
/// through [`emergency_revoke`] or a bystander's grant revocation through
/// [`revoke_shared_grant`], then a stop through V05's `respond_to_violation`, which stops a
/// task sandbox or locks a service sandbox down with a one-click stop (VM-D10). A grant
/// revocation on a target whose role names no grant cannot be narrowed to one, so the
/// sandbox's whole authority is revoked instead: it fails closed. Either revocation is also
/// kept on the coordinator's durable revocation stream `log`.
pub fn execute_target<C, P, H, S, Q, J>(
    coordinator: &mut Coordinator<C, P>,
    port: &mut dyn SandboxPort,
    events: &mut RevocationEvents<'_, H, S, Q, J>,
    log: &mut RevocationLog,
    deferred: &mut DeferredAudit,
    target: &TargetResponse,
    operation: OperationId,
) -> Result<TargetExecution, CoordinationError>
where
    C: Clock,
    P: CapacityPort,
    H: Clock,
    S: AuditStore,
    Q: AuditSpool,
    J: Clock,
{
    let revokes = target.new_actions.contains(&ResponseAction::Revoke);
    let revokes_grant = target.new_actions.contains(&ResponseAction::RevokeGrant);
    let (revocation, grant_revocation) = match (revokes, revokes_grant, target.role) {
        (true, _, _) | (false, true, TargetRole::Observed) => (
            Some(emergency_revoke(
                coordinator,
                events,
                log,
                deferred,
                &target.sandbox,
                operation,
            )?),
            None,
        ),
        (false, true, TargetRole::SharesViolatedGrant { grant }) => (
            None,
            Some(revoke_shared_grant(
                coordinator,
                events,
                log,
                deferred,
                &target.sandbox,
                grant,
                operation,
            )?),
        ),
        (false, false, _) => (None, None),
    };
    let class_response = if target.new_actions.contains(&ResponseAction::Stop) {
        Some(respond_to_violation(
            coordinator,
            &target.sandbox,
            target.sandbox_class,
            port,
        )?)
    } else {
        None
    };
    let runtime_actions = target
        .new_actions
        .iter()
        .copied()
        .filter(|action| {
            matches!(
                action,
                ResponseAction::RequestHostCorroboration
                    | ResponseAction::DenyNewHighImpact
                    | ResponseAction::Isolate
            )
        })
        .collect();
    Ok(TargetExecution {
        sandbox: target.sandbox.clone(),
        revocation,
        grant_revocation,
        class_response,
        runtime_actions,
        notification: target.notification,
    })
}
