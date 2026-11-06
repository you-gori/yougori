//! The coordinator's revocations on the CORE-06 event plane (S2 CORE-06; S6 INT-10; VM
//! part §8.2).
//!
//! A revocation takes effect in the coordinator first (INT-02). The adapter then carries
//! its notice to the event plane through the plane's own public authorities: onto the
//! hub's priority revocation lane through the coordinator's registered
//! [`RevocationIssuer`], which nothing on the other streams can make wait, and into the
//! audit journal through its one [`AuditAppendAuthority`]. A refusal by either is
//! reported beside the notice and never undoes the revocation. The revocation of one
//! grant takes the same path, as a grant revocation that names the epoch left in force.
//!
//! A revocation that must survive a restart is also kept on the coordinator's durable
//! revocation stream, a [`RevocationLog`] the coordinator owns
//! (docs/combined-plan-leftover-tasks.md S06), after the lane and before the audit
//! journal: the lane never waits for it, and audit overload never reaches it. At a
//! restart, [`PersistedState::adopt_revocations`] takes a replay of that stream into the
//! persisted state before recovery, restoring the grant tombstones it lacked, and
//! [`Coordinator::complete_revocations`] then ends the sandboxes whose revocation the
//! state predates, so none regains authority.

use std::collections::BTreeMap;

use super::capacity::CapacityPort;
use super::coordinator::{Compensation, CoordinationError, Coordinator};
use super::grants::RevokedGrant;
use super::port::SandboxPort;
use super::recovery::PersistedState;
use super::revocation::RevocationNotice;
use super::sandbox::SandboxState;
use crate::foundation::events::{
    AuditAppendAuthority, AuditDraft, AuditJournal, AuditReceipt, AuditRefusal, AuditSpool,
    AuditStore, DurablyPublished, EmitError, EventContext, EventHub, Generations, GrantRevocation,
    Phase, ProducerId, RebuiltRevocations, RecordError, Revocation, RevocationAdmission,
    RevocationIssuer, RevocationLog, RevocationReason, RevocationReplay,
};
use crate::foundation::ids::{Clock, ExecutionId, GrantId, OperationId};

/// Where the coordinator's revocations go on the event plane: the hub with the
/// coordinator's registered revocation issuer, and the audit journal with its append
/// authority (CORE-06).
pub struct RevocationEvents<'a, H, S, Q, J> {
    /// The in-process event plane.
    pub hub: &'a mut EventHub<H>,
    /// The coordinator's registration as the issuer of revocations.
    pub issuer: &'a mut RevocationIssuer,
    /// The durable security audit.
    pub journal: &'a mut AuditJournal<S, Q, J>,
    /// The one authority that may extend the journal.
    pub authority: &'a mut AuditAppendAuthority,
}

/// What the event plane did with one revocation. The revocation is in force either way.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevocationPublished {
    /// The coordinator's notice of the revocation.
    pub notice: RevocationNotice,
    /// The priority lane's admission (VM part §8.2: never blocked).
    pub lane: Result<RevocationAdmission, EmitError>,
    /// The audit journal's receipt.
    pub audit: Result<AuditReceipt, AuditRefusal>,
}

/// What the event plane did with the revocation of one grant. The revocation is in force
/// either way.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantRevocationPublished {
    /// The coordinator's record of the revocation.
    pub revoked: RevokedGrant,
    /// The priority lane's admission (VM part §8.2: never blocked).
    pub lane: Result<RevocationAdmission, EmitError>,
    /// The audit journal's receipt.
    pub audit: Result<AuditReceipt, AuditRefusal>,
}

impl<H: Clock, S: AuditStore, Q: AuditSpool, J: Clock> RevocationEvents<'_, H, S, Q, J> {
    /// Publishes `notice` as the revocation of its execution for `reason`, under
    /// `operation`: first on the priority lane, then into the audit journal. The event
    /// carries the authorization epoch now in force.
    pub fn publish(
        &mut self,
        notice: &RevocationNotice,
        operation: OperationId,
        reason: RevocationReason,
    ) -> RevocationPublished {
        self.publish_with(notice, operation, reason, |_, _| ()).0
    }

    /// Publishes `notice` as [`RevocationEvents::publish`] does, and keeps it on the
    /// coordinator's durable revocation stream `log` between the lane and the audit
    /// journal (S06): the lane never waits for the stream, and the stream never waits for
    /// the journal. The stream's refusal is reported beside the others and never undoes
    /// the revocation.
    pub fn publish_durably(
        &mut self,
        notice: &RevocationNotice,
        operation: OperationId,
        reason: RevocationReason,
        log: &mut RevocationLog,
    ) -> DurablyPublished<RevocationPublished> {
        let issuer = self.issuer.key().producer;
        let (published, recorded) =
            self.publish_with(notice, operation, reason, |context, revocation| {
                shared_producer(log, &issuer)?;
                log.record(context.clone(), notice.at, revocation.clone())
            });
        DurablyPublished {
            published,
            recorded,
        }
    }

    /// The path of [`RevocationEvents::publish`], with `record` run between the lane and
    /// the audit journal.
    fn publish_with<R>(
        &mut self,
        notice: &RevocationNotice,
        operation: OperationId,
        reason: RevocationReason,
        record: impl FnOnce(&EventContext, &Revocation) -> R,
    ) -> (RevocationPublished, R) {
        let revocation = Revocation {
            execution: notice.execution.clone(),
            epoch: notice.current,
            reason,
        };
        let context = EventContext::new(operation, Phase::Revoked)
            .with_generations(Generations::NONE.with_authorization(notice.current));
        let lane = self
            .hub
            .emit_revocation(self.issuer, context.clone(), revocation.clone());
        let recorded = record(&context, &revocation);
        let audit =
            self.journal
                .append(self.authority, context, AuditDraft::Revocation(revocation));
        let published = RevocationPublished {
            notice: notice.clone(),
            lane,
            audit,
        };
        (published, recorded)
    }

    /// Publishes `revoked`, the revocation of one grant, for `reason` under `operation`, as
    /// [`RevocationEvents::publish`] publishes a revocation: first on the priority lane,
    /// then into the audit journal, where it may use the revocation reserve. The event
    /// carries the authorization epoch the revocation left in force.
    pub fn publish_grant(
        &mut self,
        revoked: &RevokedGrant,
        operation: OperationId,
        reason: RevocationReason,
    ) -> GrantRevocationPublished {
        self.publish_grant_with(revoked, operation, reason, |_, _| ())
            .0
    }

    /// Publishes `revoked` as [`RevocationEvents::publish_grant`] does, and keeps it on the
    /// durable revocation stream `log` as [`RevocationEvents::publish_durably`] keeps a
    /// revocation, so the grant's tombstone survives a restart that comes before the next
    /// persisted state.
    pub fn publish_grant_durably(
        &mut self,
        revoked: &RevokedGrant,
        operation: OperationId,
        reason: RevocationReason,
        log: &mut RevocationLog,
    ) -> DurablyPublished<GrantRevocationPublished> {
        let issuer = self.issuer.key().producer;
        let (published, recorded) =
            self.publish_grant_with(revoked, operation, reason, |context, revocation| {
                shared_producer(log, &issuer)?;
                log.record_grant(context.clone(), revoked.at, revocation.clone())
            });
        DurablyPublished {
            published,
            recorded,
        }
    }

    /// The path of [`RevocationEvents::publish_grant`], with `record` run between the lane
    /// and the audit journal.
    fn publish_grant_with<R>(
        &mut self,
        revoked: &RevokedGrant,
        operation: OperationId,
        reason: RevocationReason,
        record: impl FnOnce(&EventContext, &GrantRevocation) -> R,
    ) -> (GrantRevocationPublished, R) {
        let revocation = GrantRevocation {
            execution: revoked.execution.clone(),
            grant: revoked.grant,
            epoch: revoked.epoch,
            reason,
        };
        let context = EventContext::new(operation, Phase::Revoked)
            .with_generations(Generations::NONE.with_authorization(revoked.epoch));
        let lane = self
            .hub
            .emit_grant_revocation(self.issuer, context.clone(), revocation.clone());
        let recorded = record(&context, &revocation);
        let audit = self.journal.append(
            self.authority,
            context,
            AuditDraft::GrantRevocation(revocation),
        );
        let published = GrantRevocationPublished {
            revoked: revoked.clone(),
            lane,
            audit,
        };
        (published, recorded)
    }
}

/// Refuses a durable stream owned by the lane's issuer: its records would share the
/// issuer's sequence space with different envelopes.
fn shared_producer(log: &RevocationLog, issuer: &ProducerId) -> Result<(), RecordError> {
    if log.owner() == issuer {
        return Err(RecordError::SharedProducer {
            producer: issuer.clone(),
        });
    }
    Ok(())
}

impl<C: Clock, P: CapacityPort> Coordinator<C, P> {
    /// Revokes `execution` ([`Coordinator::revoke`], INT-02), then carries the notice onto
    /// the event plane through `events` (INT-10): the priority revocation lane and the
    /// audit journal. Revoking again publishes the same notice again.
    pub fn revoke_and_publish<H: Clock, S: AuditStore, Q: AuditSpool, J: Clock>(
        &mut self,
        execution: &ExecutionId,
        operation: OperationId,
        reason: RevocationReason,
        events: &mut RevocationEvents<'_, H, S, Q, J>,
    ) -> Result<RevocationPublished, CoordinationError> {
        let notice = self.revoke(execution)?;
        Ok(events.publish(&notice, operation, reason))
    }

    /// Revokes one grant under `execution`'s authority ([`Coordinator::revoke_grant`]),
    /// then carries the revocation onto the event plane through `events`, the path
    /// [`Coordinator::revoke_and_publish`] takes. Revoking again publishes the same
    /// revocation again.
    pub fn revoke_grant_and_publish<H: Clock, S: AuditStore, Q: AuditSpool, J: Clock>(
        &mut self,
        execution: &ExecutionId,
        grant: GrantId,
        operation: OperationId,
        reason: RevocationReason,
        events: &mut RevocationEvents<'_, H, S, Q, J>,
    ) -> Result<GrantRevocationPublished, CoordinationError> {
        let revoked = self.revoke_grant(execution, grant)?;
        Ok(events.publish_grant(&revoked, operation, reason))
    }

    /// Revokes `execution` and publishes the notice as [`Coordinator::revoke_and_publish`]
    /// does, keeping it on the coordinator's durable revocation stream `log` too
    /// ([`RevocationEvents::publish_durably`]), so a restart before the next persisted
    /// state still ends the sandbox ([`PersistedState::adopt_revocations`]).
    pub fn revoke_and_publish_durably<H: Clock, S: AuditStore, Q: AuditSpool, J: Clock>(
        &mut self,
        execution: &ExecutionId,
        operation: OperationId,
        reason: RevocationReason,
        events: &mut RevocationEvents<'_, H, S, Q, J>,
        log: &mut RevocationLog,
    ) -> Result<DurablyPublished<RevocationPublished>, CoordinationError> {
        let notice = self.revoke(execution)?;
        Ok(events.publish_durably(&notice, operation, reason, log))
    }

    /// Revokes one grant and publishes it as [`Coordinator::revoke_grant_and_publish`]
    /// does, keeping it on the durable revocation stream `log` too
    /// ([`RevocationEvents::publish_grant_durably`]), so its tombstone survives a restart
    /// before the next persisted state.
    pub fn revoke_grant_and_publish_durably<H: Clock, S: AuditStore, Q: AuditSpool, J: Clock>(
        &mut self,
        execution: &ExecutionId,
        grant: GrantId,
        operation: OperationId,
        reason: RevocationReason,
        events: &mut RevocationEvents<'_, H, S, Q, J>,
        log: &mut RevocationLog,
    ) -> Result<DurablyPublished<GrantRevocationPublished>, CoordinationError> {
        let revoked = self.revoke_grant(execution, grant)?;
        Ok(events.publish_grant_durably(&revoked, operation, reason, log))
    }

    /// Ends, after [`Coordinator::recover`], each sandbox whose revocation `rebuilt` found
    /// the persisted state predates (S06; INT-02, INT-04). Recovery kept such a sandbox's
    /// live VM without authority, for fresh evidence and a fresh grant; the revocation it
    /// already received ends it instead, through its handle ([`Coordinator::terminate`]).
    /// A sandbox already stopped is left as it is, one recovery left stalled continues its
    /// termination, and one granted authority since is refused, as `terminate` refuses it.
    /// Returns what each sandbox ended released, or why it did not end.
    pub fn complete_revocations(
        &mut self,
        rebuilt: &RebuiltRevocations,
        port: &mut dyn SandboxPort,
    ) -> BTreeMap<ExecutionId, Result<Vec<Compensation>, CoordinationError>> {
        let mut completed = BTreeMap::new();
        for execution in rebuilt.unpersisted.keys() {
            let ended = self
                .sandbox(execution)
                .is_none_or(|sandbox| sandbox.state() == SandboxState::Stopped);
            if !ended {
                completed.insert(execution.clone(), self.terminate(execution, port));
            }
        }
        completed
    }
}

impl PersistedState {
    /// Takes `replay`, read from the coordinator's durable revocation stream, into this
    /// state before [`Coordinator::recover`] (S06; VM part §6.3 step 1: a tombstone
    /// persists). Every grant revoked there is tombstoned here, so recovery restores the
    /// tombstone and no relaunch grants the grant again. A revocation of an execution at an
    /// epoch above the one this state holds for its sandbox came after the state was
    /// taken; it is returned for [`Coordinator::complete_revocations`]. One at or below it
    /// is already reflected here, by a revoking, stopped or relaunched sandbox. The
    /// replay's gaps are returned as well: revocations there are unknown.
    ///
    /// Store the stream's end cursor with each persisted state and replay from it. A
    /// replay from earlier is correct too, since adopting a revocation twice changes
    /// nothing, but its gaps may lie before the state and still be reported.
    pub fn adopt_revocations(&mut self, replay: &RevocationReplay) -> RebuiltRevocations {
        let mut rebuilt = RebuiltRevocations {
            gaps: replay.gaps.clone(),
            ..RebuiltRevocations::default()
        };
        for (execution, grants) in replay.tombstones() {
            let held = self.revoked_grants.entry(execution.clone()).or_default();
            for grant in grants {
                if held.insert(grant) {
                    rebuilt
                        .tombstones_restored
                        .entry(execution.clone())
                        .or_default()
                        .insert(grant);
                }
            }
        }
        for (execution, revocation) in &replay.executions {
            let predates = self.sandboxes.iter().any(|sandbox| {
                sandbox.execution() == execution
                    && sandbox.generations().authorization < revocation.payload().epoch
            });
            if predates {
                rebuilt
                    .unpersisted
                    .insert(execution.clone(), revocation.clone());
            }
        }
        rebuilt
    }
}
