//! Restart recovery's outcomes on a durable CORE-06 stream (docs/combined-gpu-memory-and-vm-sandbox-plan.md:
//! S2 CORE-04 and CORE-06; S6 INT-04; S7 restart recovery; VM part §6.1 "recovery reconciles
//! actual VM objects and resources" and §6.3 step 1; docs/combined-plan-leftover-tasks.md
//! S06 "publish real ... recovery events through CORE-06").
//!
//! What a recovery did is a host fact that must outlive the process that did it: which
//! sandboxes kept their VM without authority, lost it or finished terminating, which VMs
//! without a trusted record were terminated, how the ledger reconciled, which leases were not
//! revived and which activations the crash retired, which revocations the persisted state
//! lacked and how the sandboxes they name ended, and which models were activated again. The
//! coordinator publishes each as a [`RecoveryEvent`] on its [`RecoveryLog`], an audit-class
//! [`EventLog`] with one owner, all under the operation of the recovery, and closes a
//! publication with [`RecoveryEvent::Recovered`], so a reader in another process tells a
//! complete publication from one a crash interrupted.
//!
//! Publishing never changes what recovery did and never waits on the hub or the audit
//! journal. A record the stream refuses is reported in [`RecoveryPublished`], never dropped
//! silently; the outcome stands either way.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::capacity::{CapacityPort, ReconcileReport, ReservationKey, ReturnHold};
use super::coordinator::{Compensation, CoordinationError, Coordinator};
use super::floor::{FloorRestore, FloorUpgrade};
use super::identity::VmInstanceId;
use super::model::GpuAllocationHandle;
use super::port::SandboxPort;
use super::recovery::{RecoveryReport, SandboxRecovery};
use crate::foundation::events::{
    DurableStreamId, EventContext, EventLog, EventSequence, GapReason, Generations, LogConfig,
    LogError, LoggedStream, OpenReport, Phase, ProducerId, RebuiltRevocations, RecordError,
    SequenceRange,
};
use crate::foundation::ids::{
    AuthorizationEpoch, Clock, ExecutionId, GrantId, LeaseId, MonotonicTime, OperationId,
};

/// One outcome of a restart recovery, as the coordinator's durable recovery stream keeps it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
#[serde(remote = "Self")]
pub enum RecoveryEvent {
    /// What recovery did with one sandbox.
    Sandbox {
        execution: ExecutionId,
        recovery: SandboxRecovery,
    },
    /// A VM with no trusted record, terminated through its handle.
    UntrustedVmTerminated { vm: VmInstanceId },
    /// How the ledger reconciled one execution's reservations.
    Reservations {
        execution: ExecutionId,
        reconciled: ReconcileReport,
    },
    /// What else the crash ended, and what stays counted: leases not revived, activations
    /// retired for good, GPU reservations still counted because a live VM may use them,
    /// and owner resource-return holds ended.
    Ended {
        leases_not_revived: Vec<LeaseId>,
        retired_activations: Vec<GpuAllocationHandle>,
        gpu_reservations_counted: Vec<ReservationKey>,
        return_holds_ended: Vec<ReturnHold>,
    },
    /// Revocations from the durable revocation stream that the persisted state lacked
    /// (`PersistedState::adopt_revocations`): grant tombstones restored, executions
    /// revoked at an epoch above the state's, and the stream's gaps, where revocations are
    /// unknown.
    RevocationsAdopted {
        tombstones_restored: BTreeMap<ExecutionId, BTreeSet<GrantId>>,
        unpersisted: BTreeMap<ExecutionId, AuthorizationEpoch>,
        gaps: Vec<(SequenceRange, GapReason)>,
    },
    /// The persisted state was below the durable authority floor of sequence `floor`, as
    /// after a restored backup or VM snapshot of the engine's data, and was raised to it
    /// before recovery (`AuthorityFloor::restore`): every part raised, and the executions
    /// whose records were below the floor, whose sandboxes end after recovery
    /// ([`Coordinator::end_stale`]).
    FloorRaised {
        floor: u64,
        upgrades: Vec<FloorUpgrade>,
        stale: BTreeSet<ExecutionId>,
    },
    /// A sandbox whose revocation the persisted state predated, ended after recovery
    /// ([`Coordinator::complete_revocations`]), and what ending it released.
    RevocationCompleted {
        execution: ExecutionId,
        compensations: Vec<Compensation>,
    },
    /// A sandbox whose revocation the persisted state predated that did not end, and why.
    RevocationNotCompleted {
        execution: ExecutionId,
        refusal: String,
    },
    /// A model activated again after recovery, under a fresh authority
    /// ([`Coordinator::reload_model`]).
    ModelReloaded { activation: GpuAllocationHandle },
    /// Recovery stopped; nothing still in use was released, and it can be tried again.
    Failed { error: String },
    /// The publication of one recovery is complete: how many sandbox outcomes, untrusted
    /// VMs and reconciled executions came before it.
    Recovered {
        sandboxes: u64,
        untrusted_vms_terminated: u64,
        executions_reconciled: u64,
    },
}

crate::foundation::strict_serde::strict_tag!(RecoveryEvent, "outcome");

impl RecoveryEvent {
    /// The adoption `rebuilt` describes.
    pub fn adopted(rebuilt: &RebuiltRevocations) -> Self {
        Self::RevocationsAdopted {
            tombstones_restored: rebuilt.tombstones_restored.clone(),
            unpersisted: rebuilt
                .unpersisted
                .iter()
                .map(|(execution, revocation)| (execution.clone(), revocation.payload().epoch))
                .collect(),
            gaps: rebuilt.gaps.clone(),
        }
    }

    /// What `restore`, a restore against the floor of sequence `floor`, raised; nothing
    /// when the state was the newest durable one.
    pub fn raised(floor: u64, restore: &FloorRestore) -> Option<Self> {
        (!restore.is_current()).then(|| Self::FloorRaised {
            floor,
            upgrades: restore.upgrades.clone(),
            stale: restore.stale.clone(),
        })
    }

    /// How ending `execution`, whose revocation the persisted state predated, went.
    pub fn completed(
        execution: &ExecutionId,
        ended: &Result<Vec<Compensation>, CoordinationError>,
    ) -> Self {
        match ended {
            Ok(compensations) => Self::RevocationCompleted {
                execution: execution.clone(),
                compensations: compensations.clone(),
            },
            Err(refusal) => Self::RevocationNotCompleted {
                execution: execution.clone(),
                refusal: refusal.to_string(),
            },
        }
    }

    /// The phase of the recovery operation the event reports: restoring while outcomes
    /// arrive, loading for a reloaded model, then completed or failed.
    pub fn phase(&self) -> Phase {
        match self {
            Self::ModelReloaded { .. } => Phase::Loading,
            Self::Failed { .. } => Phase::Failed,
            Self::Recovered { .. } => Phase::Completed,
            _ => Phase::Restoring,
        }
    }

    /// The typed generations the event was decided under, where it names any.
    pub fn generations(&self) -> Generations {
        match self {
            Self::Sandbox {
                recovery: SandboxRecovery::VmKeptWithoutAuthority { generations, .. },
                ..
            } => Generations::NONE
                .with_sandbox_boot(generations.boot)
                .with_policy(generations.policy)
                .with_authorization(generations.authorization),
            Self::ModelReloaded { activation } => Generations::NONE
                .with_model_activation(activation.generations.activation)
                .with_gpu_allocation(activation.generations.gpu_allocation),
            _ => Generations::NONE,
        }
    }
}

impl RecoveryReport {
    /// What this report holds, as recovery events: each sandbox's outcome, each untrusted
    /// VM terminated and each execution's reconciliation, in the order of their keys, what
    /// else the crash ended when anything did, and the closing summary.
    pub fn events(&self) -> Vec<RecoveryEvent> {
        let mut events: Vec<RecoveryEvent> = self
            .sandboxes
            .iter()
            .map(|(execution, recovery)| RecoveryEvent::Sandbox {
                execution: execution.clone(),
                recovery: recovery.clone(),
            })
            .collect();
        events.extend(
            self.untrusted_vms_terminated
                .iter()
                .map(|vm| RecoveryEvent::UntrustedVmTerminated { vm: *vm }),
        );
        events.extend(self.reservations.iter().map(|(execution, reconciled)| {
            RecoveryEvent::Reservations {
                execution: execution.clone(),
                reconciled: reconciled.clone(),
            }
        }));
        let ended = !(self.leases_not_revived.is_empty()
            && self.retired_activations.is_empty()
            && self.gpu_reservations_counted.is_empty()
            && self.return_holds_ended.is_empty());
        if ended {
            events.push(RecoveryEvent::Ended {
                leases_not_revived: self.leases_not_revived.clone(),
                retired_activations: self.retired_activations.clone(),
                gpu_reservations_counted: self.gpu_reservations_counted.clone(),
                return_holds_ended: self.return_holds_ended.clone(),
            });
        }
        let count = |len: usize| u64::try_from(len).unwrap_or(u64::MAX);
        events.push(RecoveryEvent::Recovered {
            sandboxes: count(self.sandboxes.len()),
            untrusted_vms_terminated: count(self.untrusted_vms_terminated.len()),
            executions_reconciled: count(self.reservations.len()),
        });
        events
    }
}

/// The coordinator's durable stream of restart-recovery outcomes (S06).
pub type RecoveryLog = EventLog<RecoveryEvent>;

/// Takes ownership of the recovery stream `stream` in `directory` for `owner`, an
/// audit-class stream, as [`EventLog::open`] does. `owner` seals the events, so it must be
/// neither a hub producer nor the owner of another stream: the coordinator owns it as, say,
/// `coordinator.recovery`.
pub fn open_recovery_log(
    directory: &Path,
    stream: DurableStreamId,
    owner: ProducerId,
    config: LogConfig,
) -> Result<(RecoveryLog, OpenReport), LogError> {
    EventLog::open(directory, stream, owner, LoggedStream::Audit, config)
}

/// What publishing recovery outcomes did: each event, in order, and its sequence in the
/// stream or why the stream refused it. The outcomes stand either way.
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryPublished {
    pub recorded: Vec<(RecoveryEvent, Result<EventSequence, RecordError>)>,
}

impl RecoveryPublished {
    /// Whether the stream keeps every event.
    pub fn is_complete(&self) -> bool {
        self.recorded.iter().all(|(_, recorded)| recorded.is_ok())
    }

    /// The events the stream refused, and why.
    pub fn refused(&self) -> impl Iterator<Item = (&RecoveryEvent, &RecordError)> {
        self.recorded
            .iter()
            .filter_map(|(event, recorded)| recorded.as_ref().err().map(|error| (event, error)))
    }
}

/// Publishes `events` on `log` under `operation`, each stamped `at` on the caller's clock
/// with its own phase and generations, in order. A refused event is reported and the rest
/// are still offered: each is a fact of its own. For a recovery that stopped, with no
/// coordinator to read the clock from, publish [`RecoveryEvent::Failed`] this way.
pub fn publish_recovery_events(
    log: &mut RecoveryLog,
    operation: &OperationId,
    at: MonotonicTime,
    events: Vec<RecoveryEvent>,
) -> RecoveryPublished {
    let recorded = events
        .into_iter()
        .map(|event| {
            let context = EventContext::new(operation.clone(), event.phase())
                .with_generations(event.generations());
            let recorded = log.record(context, at, event.clone());
            (event, recorded)
        })
        .collect();
    RecoveryPublished { recorded }
}

impl<C: Clock, P: CapacityPort> Coordinator<C, P> {
    /// Publishes what restart recovery did on `log` under `operation`, stamped on the
    /// coordinator's clock: the revocations adopted before it, when `adopted` is given,
    /// then `report`'s events ([`RecoveryReport::events`]), the last of them the closing
    /// summary.
    pub fn publish_recovery(
        &self,
        adopted: Option<&RebuiltRevocations>,
        report: &RecoveryReport,
        operation: &OperationId,
        log: &mut RecoveryLog,
    ) -> RecoveryPublished {
        let events = adopted
            .map(RecoveryEvent::adopted)
            .into_iter()
            .chain(report.events())
            .collect();
        publish_recovery_events(log, operation, self.monotonic_now(), events)
    }

    /// Ends each sandbox whose revocation `rebuilt` found the persisted state predates, as
    /// [`Coordinator::complete_revocations`] does, and publishes how each ended on `log`
    /// under `operation`.
    pub fn complete_revocations_and_publish(
        &mut self,
        rebuilt: &RebuiltRevocations,
        port: &mut dyn SandboxPort,
        operation: &OperationId,
        log: &mut RecoveryLog,
    ) -> (
        BTreeMap<ExecutionId, Result<Vec<Compensation>, CoordinationError>>,
        RecoveryPublished,
    ) {
        let completed = self.complete_revocations(rebuilt, port);
        let events = completed
            .iter()
            .map(|(execution, ended)| RecoveryEvent::completed(execution, ended))
            .collect();
        let published = publish_recovery_events(log, operation, self.monotonic_now(), events);
        (completed, published)
    }

    /// Publishes `activation`, a model activated again after recovery by
    /// [`Coordinator::reload_model`], on `log` under `operation`, stamped on the
    /// coordinator's clock, with the activation's generations.
    pub fn publish_reload(
        &self,
        activation: &GpuAllocationHandle,
        operation: &OperationId,
        log: &mut RecoveryLog,
    ) -> RecoveryPublished {
        publish_recovery_events(
            log,
            operation,
            self.monotonic_now(),
            vec![RecoveryEvent::ModelReloaded {
                activation: activation.clone(),
            }],
        )
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::super::coordinator::{StallCause, TerminationStalled};
    use super::super::fakes::{FakeLedger, FakeSandbox};
    use super::super::identity::{ModelGenerations, ModelId, SandboxGenerations};
    use super::super::port::{ObservedVm, PortFailure, PortOperation};
    use super::*;
    use crate::foundation::events::{DurableReader, EventEnvelope, LogEntry, ReadItem, StreamKind};
    use crate::foundation::evidence::ClockSession;
    use crate::foundation::ids::{
        digest, GpuAllocationGeneration, ManualClock, ModelActivationGeneration, PolicyEpoch,
        SandboxBootGeneration,
    };

    fn execution(name: &str) -> ExecutionId {
        ExecutionId::new(name).unwrap()
    }

    fn operation(name: &str) -> OperationId {
        OperationId::new(name).unwrap()
    }

    fn stream_id() -> DurableStreamId {
        DurableStreamId::new("coordinator.recovery").unwrap()
    }

    fn config(segment_bytes: u64) -> LogConfig {
        LogConfig {
            max_entries: 1_000,
            max_bytes: 1 << 24,
            segment_entries: 8,
            segment_bytes,
        }
    }

    fn open(directory: &Path, segment_bytes: u64) -> RecoveryLog {
        open_recovery_log(
            directory,
            stream_id(),
            ProducerId::new("coordinator.recovery").unwrap(),
            config(segment_bytes),
        )
        .unwrap()
        .0
    }

    fn session(number: u128) -> ClockSession {
        ClockSession::from_uuid(uuid::Uuid::from_u128(number))
    }

    fn vm(name: &str) -> VmInstanceId {
        VmInstanceId::new(digest("yougori/test/vm/v1", &[name.as_bytes()]))
    }

    fn grant(name: &str) -> GrantId {
        GrantId::from_digest(digest("yougori/test/grant/v1", &[name.as_bytes()]))
    }

    fn events_of(log: &RecoveryLog) -> Vec<EventEnvelope<RecoveryEvent>> {
        log.log()
            .read(&log.log().start(), usize::MAX)
            .unwrap()
            .items
            .into_iter()
            .filter_map(|item| match item {
                ReadItem::Entry {
                    entry: LogEntry::Record(event),
                    ..
                } => Some(event),
                _ => None,
            })
            .collect()
    }

    fn rebuilt() -> RebuiltRevocations {
        RebuiltRevocations {
            tombstones_restored: BTreeMap::from([(
                execution("exe-a"),
                BTreeSet::from([grant("network")]),
            )]),
            unpersisted: BTreeMap::new(),
            gaps: vec![(
                SequenceRange::new(EventSequence::FIRST, EventSequence::new(3).unwrap()).unwrap(),
                GapReason::Retention,
            )],
        }
    }

    #[test]
    fn a_recovery_publishes_each_outcome_durably_under_its_operation() {
        let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(5_000_000_000)));
        let ledger = FakeLedger::new([]);
        let first = Coordinator::new(Arc::clone(&clock), session(1), ledger.clone());
        let state = first.persist();
        // A VM the persisted state knows nothing of: recovery terminates it.
        let ghost = execution("exe-ghost");
        let mut port = FakeSandbox::new();
        let stray = FakeSandbox::vm_for(&ghost, SandboxBootGeneration::FIRST, false);
        port.live.insert(
            stray,
            ObservedVm {
                vm: stray,
                execution: ghost.clone(),
                boot: SandboxBootGeneration::FIRST,
            },
        );
        let (coordinator, report) =
            Coordinator::recover(state, Arc::clone(&clock), session(2), ledger, &mut port).unwrap();
        assert_eq!(report.untrusted_vms_terminated, [stray]);

        let directory = tempfile::tempdir().unwrap();
        let mut log = open(directory.path(), 1 << 16);
        let recovery = operation("op-recovery-2");
        let published =
            coordinator.publish_recovery(Some(&rebuilt()), &report, &recovery, &mut log);
        assert!(published.is_complete());
        let events = events_of(&log);
        let outcomes: Vec<&RecoveryEvent> = events.iter().map(|event| event.payload()).collect();
        assert_eq!(
            outcomes,
            [
                &RecoveryEvent::adopted(&rebuilt()),
                &RecoveryEvent::UntrustedVmTerminated { vm: stray },
                &RecoveryEvent::Reservations {
                    execution: ghost.clone(),
                    reconciled: report.reservations[&ghost].clone(),
                },
                &RecoveryEvent::Recovered {
                    sandboxes: 0,
                    untrusted_vms_terminated: 1,
                    executions_reconciled: 1,
                },
            ]
        );
        assert!(events.iter().all(|event| event.operation() == &recovery
            && event.stream() == StreamKind::Audit
            && event.emitted_at() == clock.now()));
        assert_eq!(
            events.iter().map(|event| event.phase()).collect::<Vec<_>>(),
            [
                Phase::Restoring,
                Phase::Restoring,
                Phase::Restoring,
                Phase::Completed
            ]
        );
        // The recovery's events correlate by its operation, in this process and, through
        // a reader that does not own the stream, in any other.
        assert_eq!(log.log().correlate(&recovery).unwrap().records.len(), 4);
        // A model activated again afterwards is published under its own operation, with
        // its activation's generations.
        let activation = GpuAllocationHandle {
            execution: execution("exe-b"),
            model: ModelId::new(digest("yougori/test/model/v1", &[b"chat"])),
            generations: ModelGenerations {
                activation: ModelActivationGeneration::new(2),
                gpu_allocation: GpuAllocationGeneration::new(4),
            },
        };
        let reload = operation("op-reload");
        assert!(coordinator
            .publish_reload(&activation, &reload, &mut log)
            .is_complete());
        let reloaded = log.log().correlate(&reload).unwrap().records;
        assert_eq!(reloaded.len(), 1);
        let (_, reloaded) = &reloaded[0];
        assert_eq!(
            reloaded.payload(),
            &RecoveryEvent::ModelReloaded { activation }
        );
        assert_eq!(reloaded.phase(), Phase::Loading);
        assert_eq!(
            reloaded.generations().model_activation,
            Some(ModelActivationGeneration::new(2))
        );
        log.close().unwrap();
        let mut reader =
            DurableReader::<EventEnvelope<RecoveryEvent>>::open(directory.path(), stream_id())
                .unwrap();
        let correlation = reader.correlate(&recovery).unwrap();
        assert_eq!(
            correlation
                .records
                .into_iter()
                .map(|(_, event)| event)
                .collect::<Vec<_>>(),
            events
        );
    }

    fn every_outcome() -> RecoveryReport {
        let generations = SandboxGenerations {
            boot: SandboxBootGeneration::new(3),
            policy: PolicyEpoch::FIRST,
            authorization: AuthorizationEpoch::new(5),
        };
        RecoveryReport {
            sandboxes: BTreeMap::from([
                (execution("exe-a"), SandboxRecovery::AlreadyStopped),
                (
                    execution("exe-b"),
                    SandboxRecovery::VmKeptWithoutAuthority {
                        vm: vm("b"),
                        generations,
                    },
                ),
                (
                    execution("exe-c"),
                    SandboxRecovery::VmLost {
                        compensations: vec![Compensation::TerminateVm { vm: vm("c") }],
                    },
                ),
                (
                    execution("exe-d"),
                    SandboxRecovery::Stalled {
                        stall: TerminationStalled {
                            completed: vec![],
                            cause: StallCause::Port {
                                failure: PortFailure {
                                    operation: PortOperation::TerminateVm,
                                    detail: "injected failure".to_owned(),
                                },
                            },
                        },
                    },
                ),
            ]),
            untrusted_vms_terminated: vec![vm("stray")],
            leases_not_revived: vec![LeaseId::new(7)],
            retired_activations: vec![GpuAllocationHandle {
                execution: execution("exe-b"),
                model: ModelId::new(digest("yougori/test/model/v1", &[b"chat"])),
                generations: ModelGenerations {
                    activation: ModelActivationGeneration::new(2),
                    gpu_allocation: GpuAllocationGeneration::new(4),
                },
            }],
            gpu_reservations_counted: vec![],
            reservations: BTreeMap::new(),
            return_holds_ended: vec![ReturnHold::new(1)],
        }
    }

    #[test]
    fn every_outcome_reads_back_strictly_with_its_generations() {
        let report = every_outcome();
        let events = report.events();
        assert_eq!(events.len(), 7);
        assert!(matches!(
            events.last(),
            Some(RecoveryEvent::Recovered {
                sandboxes: 4,
                untrusted_vms_terminated: 1,
                executions_reconciled: 0,
            })
        ));
        for event in &events {
            let json = serde_json::to_string(event).unwrap();
            assert_eq!(
                &serde_json::from_str::<RecoveryEvent>(&json).unwrap(),
                event
            );
        }
        // Unknown fields are refused, in the event and in the sandbox outcome it carries.
        let lost = serde_json::to_value(&events[2]).unwrap();
        let mut extra = lost.clone();
        extra["extra"] = serde_json::json!(1);
        assert!(serde_json::from_value::<RecoveryEvent>(extra).is_err());
        let mut nested = lost;
        nested["recovery"]["extra"] = serde_json::json!(1);
        assert!(serde_json::from_value::<RecoveryEvent>(nested).is_err());

        // The sandbox kept without authority carries its new generations in the envelope,
        // and a reloaded model its activation's.
        let directory = tempfile::tempdir().unwrap();
        let mut log = open(directory.path(), 1 << 16);
        let reloaded = RecoveryEvent::ModelReloaded {
            activation: report.retired_activations[0].clone(),
        };
        let published = publish_recovery_events(
            &mut log,
            &operation("op-recovery"),
            MonotonicTime::from_nanos(9),
            vec![events[1].clone(), reloaded],
        );
        assert!(published.is_complete());
        let stored = events_of(&log);
        assert_eq!(
            stored[0].generations(),
            &Generations::NONE
                .with_sandbox_boot(SandboxBootGeneration::new(3))
                .with_policy(PolicyEpoch::FIRST)
                .with_authorization(AuthorizationEpoch::new(5))
        );
        assert_eq!(stored[1].phase(), Phase::Loading);
        assert_eq!(
            stored[1].generations(),
            &Generations::NONE
                .with_model_activation(ModelActivationGeneration::new(2))
                .with_gpu_allocation(GpuAllocationGeneration::new(4))
        );
    }

    #[test]
    fn a_refused_record_is_reported_and_the_others_are_still_kept() {
        let directory = tempfile::tempdir().unwrap();
        // Segments too small for the adoption below, large enough for the rest.
        let mut log = open(directory.path(), 1_024);
        let mut adopted = rebuilt();
        adopted.tombstones_restored.insert(
            execution("exe-many"),
            (0..40)
                .map(|index| grant(&format!("grant-{index}")))
                .collect(),
        );
        let events = vec![
            RecoveryEvent::UntrustedVmTerminated { vm: vm("one") },
            RecoveryEvent::adopted(&adopted),
            RecoveryEvent::completed(&execution("exe-a"), &Ok(vec![])),
            RecoveryEvent::completed(
                &execution("exe-b"),
                &Err(CoordinationError::UnknownExecution {
                    execution: execution("exe-b"),
                }),
            ),
            RecoveryEvent::Failed {
                error: "the VM list could not be read".to_owned(),
            },
        ];
        let published = publish_recovery_events(
            &mut log,
            &operation("op-recovery"),
            MonotonicTime::from_nanos(1),
            events.clone(),
        );
        assert!(!published.is_complete());
        let refused: Vec<_> = published.refused().collect();
        assert_eq!(refused.len(), 1);
        assert_eq!(refused[0].0, &events[1]);
        assert!(matches!(
            refused[0].1,
            RecordError::Log(LogError::TooLarge { .. })
        ));
        let stored = events_of(&log);
        let kept: Vec<RecoveryEvent> = stored.iter().map(|event| event.payload().clone()).collect();
        assert_eq!(
            kept,
            [
                events[0].clone(),
                events[2].clone(),
                events[3].clone(),
                events[4].clone()
            ]
        );
        assert!(matches!(
            &kept[2],
            RecoveryEvent::RevocationNotCompleted { refusal, .. } if refusal.contains("exe-b")
        ));
        assert_eq!(
            stored.iter().map(|event| event.phase()).collect::<Vec<_>>(),
            [
                Phase::Restoring,
                Phase::Restoring,
                Phase::Restoring,
                Phase::Failed
            ]
        );
    }
}
