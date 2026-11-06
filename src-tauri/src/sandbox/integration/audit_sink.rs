//! Lifecycle receipts, revocations, launch records and refused launches into one durable
//! audit stream (S2 CORE-06 row, line 215; VM part §6.3 lines 2304–2323, §8.1 lines
//! 2433–2439 and §8.2 lines 2441–2450; VM-W42 and VM-W44, lines 2665 and 2667; VM-P22 line
//! 2797; VM-P29 line 2804; the VA1 and VL1 integration notes of the rollout plan).
//!
//! The [`AuditSink`] owns one stream and the single append authority the stream
//! directory issued for it. Every record carries the CORE-06 context of the lifecycle
//! receipt it came from, with its typed generations; records without a receipt context
//! reuse the operation of the sandbox's last receipt, so an incident reconstruction finds
//! them under one operation identity (VM-W44). A launch record is written as a host fact
//! under its identity digest, and what the guest asserted is written as a guest report:
//! the two go through different `AuditEvent` variants, so a guest assertion can never be
//! stored as a host fact (§8.2; VM-P29). A refused launch is written with its typed
//! refusal, a perimeter refusal with the rule and principal it names. A revocation is the
//! durable copy of what the priority lane delivered; the lane never waits for it (§8.2
//! "never block the revocation channel"). Each acknowledgment is written with what
//! established it, CORE-04's milestone and source included. The revocation of one grant
//! is written as the stream's typed grant revocation, naming the grant and the epoch left
//! in force, never as a revocation of the sandbox; like a revocation it may use the
//! journal's revocation reserve, so a stream that fails closed for ordinary records still
//! records it while the reserve has room (§6.3 step 1; §8.2).
//!
//! [`AuditSink::open_durable`] puts the sink on a CORE-06 durable stream
//! (`sandbox::audit::DurableSegments`): one owner across the host's processes, a sequence
//! that continues after a restart, and a torn tail or retention reported when it opens.
//! [`AuditSink::open_durable_spooled`] is the durable stream with its bounded spool on file
//! (`sandbox::audit::FileSpool`), the way a sink opens in production: records the log
//! refused survive a restart and reach the log, in order, before any new record, and the
//! spool's room is the same after the restart, so ordinary records still fail closed where
//! they did and revocations still have exactly the reserve that was left (§8.2 line 2445;
//! VM-W42 at line 2665; VM-W43 at line 2666). The in-memory path ([`AuditSink::open`]) stays
//! for tests that model a full disk.
//!
//! [`AuditSink::release`] closes a durable sink's stream and releases its log, and returns
//! the outcome as a [`SinkRelease`]: a seal or an owner record that could not be written is
//! reported there as a [`ReleaseFailure`], never swallowed, since the released stream takes
//! no record of it. Dropping the sink stays the fallback: it releases the log as far as it
//! can and reports nothing, and the next owner then finds a stale owner if the release
//! record was not written.

use std::collections::BTreeMap;
use std::fmt;

use serde::Serialize;

use super::backend_port::{LaunchAttempt, LaunchProblem, RefusedLaunch};
use crate::foundation::coordination::{LaunchFailure, MilestoneSource, RevocationMilestone};
use crate::foundation::events::AuditSpool;
use crate::foundation::events::{
    AuditReceipt, EventContext, EvidenceLink, Field, FlushReport, Generations,
    HostFact as AuditFact, JournalId, LogConfig, Phase, ProducerId, RevocationReason,
};
use crate::foundation::evidence::EvidenceRefusal;
use crate::foundation::ids::{Clock, ExecutionId, IdError, OperationId};
use crate::sandbox::audit::{
    AuditEvent, AuditStream, DurableError, DurableOpening, DurableSegments, FileSpool, HeadAnchor,
    SegmentStorage, SpooledOpening, StreamAuthority, StreamClose, StreamConfig, StreamDirectory,
    StreamError, StreamRefusal, StreamRelease,
};
use crate::sandbox::backend::{
    Accelerator, FactName, FactSource, Feature, LaunchRecord, LaunchRefusal, LeftBehind,
    VmProcessState,
};
use crate::sandbox::lifecycle::{
    AckSource, Acknowledgment, GrantRevocationCause, LifecycleReceipt, PhysicalWipe,
    RevocationCause,
};

/// The operation records of the supervisor itself travel under, when no sandbox is
/// concerned (a GUI closure, the engine's death).
pub const SUPERVISOR_OPERATION: &str = "lifecycle-supervisor";

/// Why the sink did not record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SinkRefusal {
    /// The stream refused; the record was not written and the refusal is visible.
    Stream(StreamRefusal),
    /// A value could not be encoded for the record.
    Encoding {
        detail: String,
    },
    Identifier(IdError),
}

impl fmt::Display for SinkRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stream(refusal) => write!(f, "{refusal}"),
            Self::Encoding { detail } => write!(f, "the record could not be encoded: {detail}"),
            Self::Identifier(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for SinkRefusal {}

impl From<StreamRefusal> for SinkRefusal {
    fn from(refusal: StreamRefusal) -> Self {
        Self::Stream(refusal)
    }
}

/// The receipts of one launch record: its host fact, and the guest report when the
/// guest asserted anything.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LaunchAudit {
    pub host_fact: AuditReceipt,
    pub guest_report: Option<AuditReceipt>,
}

/// Counts of what the sink did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct SinkTotals {
    pub records: u64,
    pub refused: u64,
    /// Records written under the supervisor's operation because no receipt of their
    /// sandbox had been recorded yet.
    pub uncorrelated: u64,
}

/// What part of releasing a durable sink failed ([`AuditSink::release`]). Neither stops the
/// release: the log's lock is given up either way.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReleaseFailure {
    /// The current segment could not be sealed; the next owner resumes an unsealed
    /// segment.
    Seal(StreamError),
    /// The owner record could not say that its owner left cleanly and how far the stream
    /// was durable; the next owner finds a stale owner and recovers as after a crash.
    OwnerRecord(DurableError),
}

impl fmt::Display for ReleaseFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Seal(error) => write!(f, "the audit stream could not be sealed: {error}"),
            Self::OwnerRecord(error) => write!(
                f,
                "the audit stream's owner record could not record its release: {error}"
            ),
        }
    }
}

impl std::error::Error for ReleaseFailure {}

/// What releasing a durable sink did ([`AuditSink::release`]): the close and the release of
/// its log as the stream reports them, and what the sink recorded. The released stream
/// takes no record, so a failure is reported here and nowhere else
/// ([`SinkRelease::failures`]).
#[must_use = "a failed release of the audit stream is reported only here"]
#[derive(Debug)]
pub struct SinkRelease {
    pub stream: StreamRelease,
    pub totals: SinkTotals,
}

impl SinkRelease {
    /// Whether the seal and the owner record were both written.
    pub fn is_clean(&self) -> bool {
        self.stream.close.is_ok() && self.stream.release.is_ok()
    }

    /// What failed, in the order the release went: the seal, then the owner record. Empty
    /// for a clean release.
    pub fn failures(&self) -> Vec<ReleaseFailure> {
        let mut failures = Vec::new();
        if let Err(error) = &self.stream.close {
            failures.push(ReleaseFailure::Seal(error.clone()));
        }
        if let Err(error) = &self.stream.release {
            failures.push(ReleaseFailure::OwnerRecord(error.clone()));
        }
        failures
    }

    /// Records still waiting in the spool when the stream was released, as its last flush
    /// left them; on a spool on file they reach the log first when the stream opens again.
    /// `None` when the seal failed, which leaves no flush report.
    pub fn spooled_records(&self) -> Option<usize> {
        self.stream
            .close
            .as_ref()
            .ok()
            .map(|close| close.flush.remaining)
    }
}

/// One actor's audit sink for the lifecycle, over one stream and its one authority.
pub struct AuditSink<S, P, A, C> {
    stream: AuditStream<S, P, A, C>,
    authority: StreamAuthority,
    contexts: BTreeMap<ExecutionId, EventContext>,
    supervisor: OperationId,
    totals: SinkTotals,
}

impl<S: SegmentStorage, P: AuditSpool, A: HeadAnchor, C: Clock + Clone> AuditSink<S, P, A, C> {
    /// Opens the stream `id` through `directory`, which refuses while another authority
    /// for it lives (VM-W42 "one append authority per stream").
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        directory: &mut StreamDirectory,
        id: JournalId,
        owner: ProducerId,
        storage: S,
        spool: P,
        anchor: A,
        clock: C,
        config: StreamConfig,
    ) -> Result<Self, StreamError> {
        let supervisor = OperationId::new(SUPERVISOR_OPERATION).map_err(StreamError::Identifier)?;
        let (stream, authority) =
            AuditStream::open(directory, id, owner, storage, spool, anchor, clock, config)?;
        Ok(Self::over(stream, authority, supervisor))
    }

    fn over(
        stream: AuditStream<S, P, A, C>,
        authority: StreamAuthority,
        supervisor: OperationId,
    ) -> Self {
        Self {
            stream,
            authority,
            contexts: BTreeMap::new(),
            supervisor,
            totals: SinkTotals::default(),
        }
    }

    pub fn stream(&self) -> &AuditStream<S, P, A, C> {
        &self.stream
    }

    pub fn totals(&self) -> SinkTotals {
        self.totals
    }

    /// The last receipt context recorded for `execution`.
    pub fn context_of(&self, execution: &ExecutionId) -> Option<&EventContext> {
        self.contexts.get(execution)
    }

    fn remember(&mut self, execution: &ExecutionId, context: &EventContext) {
        self.contexts.insert(execution.clone(), context.clone());
    }

    /// The context of `execution` at `phase`: its last receipt's operation and
    /// generations, or the supervisor's operation when none was recorded yet.
    fn context(&mut self, execution: &ExecutionId, phase: Phase) -> EventContext {
        match self.contexts.get(execution) {
            Some(known) => EventContext {
                phase,
                evidence: None,
                ..known.clone()
            },
            None => {
                self.totals.uncorrelated = self.totals.uncorrelated.saturating_add(1);
                EventContext::new(self.supervisor.clone(), phase)
            }
        }
    }

    fn supervisor_context(&self, phase: Phase) -> EventContext {
        EventContext::new(self.supervisor.clone(), phase)
    }

    fn append(
        &mut self,
        context: EventContext,
        event: AuditEvent,
    ) -> Result<AuditReceipt, SinkRefusal> {
        let outcome = self.stream.record(&mut self.authority, context, event);
        self.counted(outcome)
    }

    fn host_fact(
        &mut self,
        context: EventContext,
        fact: AuditFact,
        fields: Vec<Field>,
    ) -> Result<AuditReceipt, SinkRefusal> {
        self.append(context, AuditEvent::HostFact { fact, fields })
    }

    /// Counts what the stream did with a record.
    fn counted(
        &mut self,
        outcome: Result<AuditReceipt, StreamRefusal>,
    ) -> Result<AuditReceipt, SinkRefusal> {
        match outcome {
            Ok(receipt) => {
                self.totals.records = self.totals.records.saturating_add(1);
                Ok(receipt)
            }
            Err(refusal) => {
                self.totals.refused = self.totals.refused.saturating_add(1);
                Err(SinkRefusal::Stream(refusal))
            }
        }
    }

    /// Records one lifecycle receipt. A receipt that carries a context is recorded under
    /// it and the context is remembered for the sandbox; a revocation, and the revocation
    /// of one grant, go through the stream's revocation paths, which may use the journal's
    /// reserve.
    pub fn record_receipt(
        &mut self,
        receipt: &LifecycleReceipt,
    ) -> Result<AuditReceipt, SinkRefusal> {
        match receipt {
            LifecycleReceipt::Launched {
                execution,
                boot,
                context,
            } => {
                self.remember(execution, context);
                self.host_fact(
                    context.clone(),
                    AuditFact::LaunchFact,
                    vec![
                        Field::metadata("execution", execution.as_str()),
                        Field::metadata("boot", boot.get()),
                        Field::metadata("event", "launched"),
                    ],
                )
            }
            LifecycleReceipt::LaunchFailed {
                execution,
                failure,
                context,
            } => {
                self.remember(execution, context);
                self.host_fact(
                    context.clone(),
                    AuditFact::LaunchFact,
                    vec![
                        Field::metadata("execution", execution.as_str()),
                        Field::metadata("event", "launch_failed"),
                        Field::metadata("failure", launch_failure_tag(failure)),
                    ],
                )
            }
            LifecycleReceipt::FirstCommand {
                execution,
                boot,
                elapsed,
            } => {
                let context = self.context(execution, Phase::Running);
                self.host_fact(
                    context,
                    AuditFact::Lease,
                    vec![
                        Field::metadata("execution", execution.as_str()),
                        Field::metadata("boot", boot.get()),
                        Field::metadata("event", "first_command"),
                        Field::metadata("elapsed_nanos", nanos(elapsed.as_nanos())),
                    ],
                )
            }
            LifecycleReceipt::Revoked {
                revocation,
                context,
                ..
            } => {
                self.remember(&revocation.execution, context);
                let outcome = self.stream.record_revocation(
                    &mut self.authority,
                    context.clone(),
                    revocation.clone(),
                );
                self.counted(outcome)
            }
            LifecycleReceipt::Acknowledged {
                execution,
                acknowledgment,
                at,
                source,
            } => {
                let context = self.context(execution, Phase::Releasing);
                let mut fields = vec![
                    Field::metadata("execution", execution.as_str()),
                    Field::metadata("event", "acknowledged"),
                    Field::metadata("acknowledgment", acknowledgment_tag(*acknowledgment)),
                    Field::metadata("at_nanos", at.as_nanos()),
                    Field::metadata("source", ack_source_tag(source)),
                ];
                if let AckSource::Coordination {
                    milestone,
                    source: established,
                } = source
                {
                    fields.push(Field::metadata("milestone", milestone_tag(*milestone)));
                    fields.push(Field::metadata(
                        "established_by",
                        milestone_source_tag(established),
                    ));
                    if let MilestoneSource::Acknowledged { source: class }
                    | MilestoneSource::ImpliedBy { source: class, .. } = established
                    {
                        fields.push(Field::metadata("source_class", source_class_tag(*class)));
                    }
                }
                self.host_fact(context, AuditFact::TerminationReceipt, fields)
            }
            // The typed grant revocation carries the execution, the grant, the epoch left
            // in force and the reason, which names the cause one to one. Like the
            // revocation of the sandbox, whose cause is not recorded either, it carries
            // nothing else: the cancelled leases are CORE-04's record.
            LifecycleReceipt::GrantRevoked {
                revocation,
                context,
                ..
            } => {
                self.remember(&revocation.execution, context);
                let outcome = self.stream.record_grant_revocation(
                    &mut self.authority,
                    context.clone(),
                    revocation.clone(),
                );
                self.counted(outcome)
            }
            LifecycleReceipt::Stopped { execution, context } => {
                self.remember(execution, context);
                self.host_fact(
                    context.clone(),
                    AuditFact::TerminationReceipt,
                    vec![
                        Field::metadata("execution", execution.as_str()),
                        Field::metadata("event", "vm_stopped"),
                    ],
                )
            }
            LifecycleReceipt::CleanupFinished {
                execution,
                report,
                late,
                context,
            } => {
                self.remember(execution, context);
                let physical = match report.physical {
                    PhysicalWipe::NotProven => "not_proven",
                    PhysicalWipe::CoveredByKeyDestruction { .. } => "covered_by_key_destruction",
                };
                self.host_fact(
                    context.clone(),
                    AuditFact::TerminationReceipt,
                    vec![
                        Field::metadata("execution", execution.as_str()),
                        Field::metadata("event", "cleanup_finished"),
                        Field::metadata("late", *late),
                        Field::metadata("actions", count(report.actions.len())),
                        Field::metadata("physical", physical),
                    ],
                )
            }
            LifecycleReceipt::GuiClosed { report } => {
                let context = self.supervisor_context(Phase::Running);
                self.host_fact(
                    context,
                    AuditFact::Lease,
                    vec![
                        Field::metadata("event", "gui_closed"),
                        Field::metadata("tasks_kept", count(report.tasks_kept)),
                        Field::metadata("services_kept", count(report.services_kept)),
                    ],
                )
            }
            LifecycleReceipt::EngineDied { report } => {
                let context = self.supervisor_context(Phase::Failed);
                self.host_fact(
                    context,
                    AuditFact::Lease,
                    vec![
                        Field::metadata("event", "engine_died"),
                        Field::metadata("since_nanos", report.since.as_nanos()),
                        Field::metadata("tasks_ended", count(report.ended.len())),
                        Field::metadata("services_continued", count(report.continued.len())),
                    ],
                )
            }
            LifecycleReceipt::LockedDown { execution, since } => {
                let context = self.context(execution, Phase::Draining);
                self.host_fact(
                    context,
                    AuditFact::AuthorizationDecision,
                    vec![
                        Field::metadata("execution", execution.as_str()),
                        Field::metadata("event", "locked_down"),
                        Field::metadata("since_nanos", since.as_nanos()),
                    ],
                )
            }
        }
    }

    /// Records every receipt in order; each outcome is returned, refused ones included.
    pub fn record_receipts(
        &mut self,
        receipts: &[LifecycleReceipt],
    ) -> Vec<Result<AuditReceipt, SinkRefusal>> {
        receipts
            .iter()
            .map(|receipt| self.record_receipt(receipt))
            .collect()
    }

    /// Records a sealed launch record (§8.1): one host fact under the record's identity
    /// digest, with the CORE-01 hypervisor evidence as the record's evidence link, and a
    /// guest report of what the guest asserted, when it asserted anything. The guest
    /// report never becomes a host fact.
    pub fn record_launch(&mut self, record: &LaunchRecord) -> Result<LaunchAudit, SinkRefusal> {
        let execution = &record.sandbox().execution;
        let generations = record.sandbox().generations;
        let evidence = record.hypervisor_evidence();
        let link = EvidenceLink {
            capability: evidence.capability(),
            subject: evidence.subject(),
            configuration: evidence.configuration(),
            source: evidence.source(),
            clock: record.clock(),
            observed_at: evidence.observed_at(),
        };
        let mut context = self.context(execution, Phase::Booting);
        context.generations = Generations::NONE
            .with_sandbox_boot(generations.boot)
            .with_policy(generations.policy)
            .with_authorization(generations.authorization);
        context.evidence = Some(link);
        let guest_context = context.clone();

        let sources = record.fact_sources();
        let counted = |wanted: FactSource| {
            count(
                sources
                    .iter()
                    .filter(|(_, source)| *source == wanted)
                    .count(),
            )
        };
        let mut fields = vec![
            Field::metadata("execution", execution.as_str()),
            Field::metadata("tenant", record.sandbox().tenant.as_str()),
            Field::metadata("boot", generations.boot.get()),
            Field::metadata("policy", generations.policy.get()),
            Field::metadata("authorization", generations.authorization.get()),
            Field::metadata("record", record.identity()),
            Field::metadata("contract", record.contract()),
            Field::metadata("vm", record.vm().digest()),
            Field::metadata("reservation", record.reservation().get()),
            Field::metadata("backend", record.backend().kind.tag()),
            Field::metadata("backend_version", record.backend().version.as_str()),
            Field::metadata("backend_artifact", record.backend().artifact),
            Field::metadata("hypervisor", record.backend().hypervisor.tag()),
            Field::metadata(
                "accelerator",
                accelerator_tag(*record.accelerator().value()),
            ),
            Field::metadata("guest_image", record.pinned().guest_image),
            Field::metadata("device_profile", record.device_profile().identity),
            Field::metadata("evidence_source", source_class_tag(evidence.source())),
            Field::metadata("recorded_at_nanos", record.recorded_at().as_nanos()),
            Field::metadata("host_observed_facts", counted(FactSource::HostObserved)),
            Field::metadata("verified_facts", counted(FactSource::Verified)),
            Field::metadata("unavailable_facts", counted(FactSource::Unavailable)),
            Field::metadata("checks", count(record.checks().len())),
        ];
        if let Some(snapshot) = record.restored_from() {
            fields.push(Field::metadata("restored_from", snapshot.digest()));
        }
        let perimeter = record.perimeter_evidence();
        if !perimeter.is_empty() {
            fields.push(Field::metadata("perimeter_rules", count(perimeter.len())));
            let weakest = perimeter.iter().map(|evidence| evidence.source()).min();
            if let Some(source) = weakest {
                fields.push(Field::metadata(
                    "perimeter_evidence_source",
                    source_class_tag(source),
                ));
            }
        }
        let host_fact = self.host_fact(context, AuditFact::LaunchFact, fields)?;

        let guest = record.guest_asserted();
        let mut guest_fields = vec![
            Field::untrusted("execution", execution.as_str()),
            Field::untrusted("boot", generations.boot.get()),
        ];
        let mut asserted = 0usize;
        let mut push = |name: &'static str, value: Option<String>| {
            if let Some(value) = value {
                asserted += 1;
                guest_fields.push(Field::untrusted(name, value));
            }
        };
        push(
            "guest_accelerator",
            encode(guest.accelerator.as_ref().map(|a| a.value()))?,
        );
        push(
            "guest_isolation",
            encode(guest.isolation.as_ref().map(|a| a.value()))?,
        );
        push(
            "guest_confinement",
            encode(guest.confinement.as_ref().map(|a| a.value()))?,
        );
        push(
            "guest_network",
            encode(guest.network.as_ref().map(|a| a.value()))?,
        );
        push(
            "guest_credentials",
            encode(guest.credentials.as_ref().map(|a| a.value()))?,
        );
        push(
            "guest_persistence",
            encode(guest.persistence.as_ref().map(|a| a.value()))?,
        );
        push(
            "guest_devices",
            encode(guest.devices.as_ref().map(|a| a.value()))?,
        );
        push(
            "guest_confidentiality",
            encode(guest.confidentiality.as_ref().map(|a| a.value()))?,
        );
        let guest_report = if asserted == 0 {
            None
        } else {
            Some(self.append(
                guest_context,
                AuditEvent::GuestReport {
                    fields: guest_fields,
                },
            )?)
        };
        Ok(LaunchAudit {
            host_fact,
            guest_report,
        })
    }

    /// Records a refused launch as the host's own decision, with the typed refusal.
    pub fn record_refusal(&mut self, refused: &RefusedLaunch) -> Result<AuditReceipt, SinkRefusal> {
        let context = self.context(&refused.execution, Phase::Failed);
        let attempt = match refused.attempt {
            LaunchAttempt::Launch => "launch",
            LaunchAttempt::Restore => "restore",
        };
        let mut fields = vec![
            Field::metadata("execution", refused.execution.as_str()),
            Field::metadata("boot", refused.boot.get()),
            Field::metadata("attempt", attempt),
            Field::metadata("decision", "launch_refused"),
            Field::metadata("problem", problem_tag(&refused.problem)),
            Field::metadata("at_nanos", refused.at.as_nanos()),
        ];
        if let LaunchProblem::Backend { refusal } = &refused.problem {
            fields.push(Field::metadata("refusal", refusal_tag(refusal)));
            match refusal {
                LaunchRefusal::Unsupported { feature } => {
                    fields.push(Field::metadata("feature", feature_tag(*feature)));
                }
                LaunchRefusal::ObservationNotCurrent { fact, .. } => {
                    fields.push(Field::metadata("fact", fact_tag(*fact)));
                }
                LaunchRefusal::PropertiesNotSatisfied { .. } => {
                    fields.push(Field::metadata(
                        "failed_checks",
                        count(refusal.failed_checks().len()),
                    ));
                }
                LaunchRefusal::PerimeterNotEvidenced { rule, refusal } => {
                    fields.push(Field::metadata("perimeter", rule.perimeter));
                    fields.push(Field::metadata("perimeter_rule", rule.rule));
                    fields.push(Field::metadata("principal", rule.principal));
                    fields.push(Field::metadata("evidence", evidence_refusal_tag(refusal)));
                }
                LaunchRefusal::NoPerimeterRules {
                    perimeter,
                    principal,
                } => {
                    fields.push(Field::metadata("perimeter", *perimeter));
                    fields.push(Field::metadata("principal", *principal));
                }
                _ => {}
            }
            refusal_fields(refusal, &mut fields);
        }
        self.host_fact(context, AuditFact::AuthorizationDecision, fields)
    }

    /// Records a host fact about `execution` while it runs, drafted outside the supervisor:
    /// the engine's response path gives its monitoring signals (`DetectionSignal`) and its
    /// decisions (`AuthorizationDecision`) here, in the execution's context at the running
    /// phase (the supervisor's own context for an execution it never knew, counted as
    /// uncorrelated).
    pub fn record_running_fact(
        &mut self,
        execution: &ExecutionId,
        fact: AuditFact,
        fields: Vec<Field>,
    ) -> Result<AuditReceipt, SinkRefusal> {
        self.record_fact(execution, Phase::Running, fact, fields)
    }

    /// [`AuditSink::record_running_fact`] at `phase`, for a fact about an execution that no
    /// longer runs, such as a promotion of its files after it stopped.
    pub fn record_fact(
        &mut self,
        execution: &ExecutionId,
        phase: Phase,
        fact: AuditFact,
        fields: Vec<Field>,
    ) -> Result<AuditReceipt, SinkRefusal> {
        let context = self.context(execution, phase);
        self.host_fact(context, fact, fields)
    }

    /// Moves spooled records to storage as far as it takes them.
    pub fn flush(&mut self) -> FlushReport {
        self.stream.flush()
    }

    /// Closes the stream: one flush, the seal, one anchor attempt; nothing waits. A sink on
    /// a durable stream is released with [`AuditSink::release`] instead, which also reports
    /// how its log was released; closing leaves that to drop.
    pub fn close(self) -> Result<StreamClose, StreamError> {
        self.stream.close()
    }
}

impl<P: AuditSpool, A: HeadAnchor, C: Clock + Clone> AuditSink<DurableSegments, P, A, C> {
    /// Opens the sink on the durable stream `id` under the root of `directory`
    /// (`AuditStream::open_durable`): `owner` becomes the stream's only appender in this
    /// process and across the host's processes, a stream that holds segments resumes
    /// after its last record, and the result reports what the log found (a stale owner, a
    /// torn tail, retention). Contexts of sandboxes recorded before a restart are not
    /// kept: their records are uncorrelated until a receipt with a context arrives.
    #[allow(clippy::too_many_arguments)]
    pub fn open_durable(
        directory: &mut StreamDirectory,
        id: JournalId,
        owner: ProducerId,
        spool: P,
        anchor: A,
        clock: C,
        config: StreamConfig,
        log: LogConfig,
    ) -> Result<(Self, DurableOpening), StreamError> {
        let supervisor = OperationId::new(SUPERVISOR_OPERATION).map_err(StreamError::Identifier)?;
        let (stream, authority, opening) =
            AuditStream::open_durable(directory, id, owner, spool, anchor, clock, config, log)?;
        Ok((Self::over(stream, authority, supervisor), opening))
    }

    /// Closes the stream and releases its durable log (`AuditStream::release`), and
    /// returns the outcome with the sink's totals: a seal or an owner record that could not
    /// be written is reported, never swallowed. The log is released either way. Dropping
    /// the sink stays the fallback; it releases the log as far as it can and cannot report
    /// a release record it failed to write.
    pub fn release(self) -> SinkRelease {
        let totals = self.totals;
        let Self {
            stream, authority, ..
        } = self;
        let stream = stream.release();
        drop(authority);
        SinkRelease { stream, totals }
    }
}

impl<A: HeadAnchor, C: Clock + Clone> AuditSink<DurableSegments, FileSpool, A, C> {
    /// Opens the sink on the durable stream `id` with its spool on file in the stream's
    /// directory (`AuditStream::open_durable_spooled`), as [`AuditSink::open_durable`]
    /// opens it otherwise. The spool holds at most `config.audit.spool_records` records,
    /// keeps the revocation reserve, and survives a restart: the records it held are
    /// offered to the log, in order, before any new record, and the room it leaves
    /// ordinary records and revocations is what it was before the restart
    /// (`AuditStream::spool_room`). The opening reports what the log and the spool held.
    /// Refused as the stream refuses, also when the spool is damaged or holds more records
    /// than its bound. Contexts of sandboxes recorded before a restart are not kept.
    pub fn open_durable_spooled(
        directory: &mut StreamDirectory,
        id: JournalId,
        owner: ProducerId,
        anchor: A,
        clock: C,
        config: StreamConfig,
        log: LogConfig,
    ) -> Result<(Self, SpooledOpening), StreamError> {
        let supervisor = OperationId::new(SUPERVISOR_OPERATION).map_err(StreamError::Identifier)?;
        let (stream, authority, opening) =
            AuditStream::open_durable_spooled(directory, id, owner, anchor, clock, config, log)?;
        Ok((Self::over(stream, authority, supervisor), opening))
    }
}

fn encode<T: Serialize>(value: Option<&T>) -> Result<Option<String>, SinkRefusal> {
    match value {
        None => Ok(None),
        Some(value) => {
            serde_json::to_string(value)
                .map(Some)
                .map_err(|error| SinkRefusal::Encoding {
                    detail: error.to_string(),
                })
        }
    }
}

fn nanos(value: u128) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn count(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// The stable tag of a coordination launch failure.
pub fn launch_failure_tag(failure: &LaunchFailure) -> &'static str {
    match failure {
        LaunchFailure::Capacity { .. } => "capacity",
        LaunchFailure::Port { .. } => "port",
        LaunchFailure::NotReady { .. } => "not_ready",
        LaunchFailure::Transition { .. } => "transition",
        LaunchFailure::RestoreRefused { .. } => "restore_refused",
        LaunchFailure::RuntimeEvidence { .. } => "runtime_evidence",
        LaunchFailure::RuntimeCategory { .. } => "runtime_category",
    }
}

/// The stable tag of a revocation acknowledgment.
pub const fn acknowledgment_tag(acknowledgment: Acknowledgment) -> &'static str {
    match acknowledgment {
        Acknowledgment::NewAuthorizationsDenied => "new_authorizations_denied",
        Acknowledgment::ChannelsClosed => "channels_closed",
        Acknowledgment::VmStopped => "vm_stopped",
        Acknowledgment::ProviderBillingStopped => "provider_billing_stopped",
        Acknowledgment::CleanupFinished => "cleanup_finished",
    }
}

/// The stable tag of what established an acknowledgment.
pub const fn ack_source_tag(source: &AckSource) -> &'static str {
    match source {
        AckSource::Coordination { .. } => "coordination",
        AckSource::SupervisorHandle => "supervisor_handle",
        AckSource::Provider { .. } => "provider",
        AckSource::CleanupReport => "cleanup_report",
    }
}

/// The stable tag of a CORE-04 revocation milestone, the same as its serialized form.
pub const fn milestone_tag(milestone: RevocationMilestone) -> &'static str {
    match milestone {
        RevocationMilestone::NewAuthorizationsDenied => "new_authorizations_denied",
        RevocationMilestone::FirstDeniedAuthorization => "first_denied_authorization",
        RevocationMilestone::SocketsClosed => "sockets_closed",
        RevocationMilestone::AllChannelsClosed => "all_channels_closed",
        RevocationMilestone::LeasesClosed => "leases_closed",
        RevocationMilestone::GpuReclaimed => "gpu_reclaimed",
        RevocationMilestone::VmStopped => "vm_stopped",
        RevocationMilestone::ProviderStoppedBilling => "provider_stopped_billing",
        RevocationMilestone::CleanupFinished => "cleanup_finished",
    }
}

/// The stable tag of what established a CORE-04 milestone.
pub const fn milestone_source_tag(source: &MilestoneSource) -> &'static str {
    match source {
        MilestoneSource::Coordinator => "coordinator",
        MilestoneSource::Acknowledged { .. } => "acknowledged",
        MilestoneSource::ImpliedBy { .. } => "implied_by",
    }
}

/// The stable tag of a CORE-06 revocation reason.
pub const fn reason_tag(reason: RevocationReason) -> &'static str {
    match reason {
        RevocationReason::UserRequested => "user_requested",
        RevocationReason::PolicyChanged => "policy_changed",
        RevocationReason::AuthorizationExpired => "authorization_expired",
        RevocationReason::SecurityEvent => "security_event",
        RevocationReason::OwnerReclaimed => "owner_reclaimed",
    }
}

/// The stable tag of a grant revocation's cause.
pub const fn grant_cause_tag(cause: GrantRevocationCause) -> &'static str {
    match cause {
        GrantRevocationCause::UserRequested => "user_requested",
        GrantRevocationCause::PolicyChanged => "policy_changed",
        GrantRevocationCause::Violation => "violation",
        GrantRevocationCause::OwnerReclaimed => "owner_reclaimed",
    }
}

/// The stable tag of a CORE-01 evidence refusal, the same as its serialized `refusal`.
pub const fn evidence_refusal_tag(refusal: &EvidenceRefusal) -> &'static str {
    match refusal {
        EvidenceRefusal::Missing { .. } => "missing",
        EvidenceRefusal::SourceTooWeak { .. } => "source_too_weak",
        EvidenceRefusal::FingerprintChanged { .. } => "fingerprint_changed",
        EvidenceRefusal::Stale { .. } => "stale",
        EvidenceRefusal::Unsupported { .. } => "unsupported",
        EvidenceRefusal::Unknown { .. } => "unknown",
    }
}

/// The stable tag of a revocation cause.
pub const fn cause_tag(cause: RevocationCause) -> &'static str {
    match cause {
        RevocationCause::UserRequested => "user_requested",
        RevocationCause::PolicyChanged => "policy_changed",
        RevocationCause::LeaseExpired { .. } => "lease_expired",
        RevocationCause::Violation => "violation",
        RevocationCause::EngineDied => "engine_died",
        RevocationCause::ServiceRenewal => "service_renewal",
        RevocationCause::OwnerReclaimed => "owner_reclaimed",
        RevocationCause::ClockRolledBack => "clock_rolled_back",
    }
}

/// The stable tag of a port launch problem.
pub const fn problem_tag(problem: &LaunchProblem) -> &'static str {
    match problem {
        LaunchProblem::NoProfile { .. } => "no_profile",
        LaunchProblem::Reservation { .. } => "reservation",
        LaunchProblem::PerimeterNotPrepared { .. } => "perimeter_not_prepared",
        LaunchProblem::Backend { .. } => "backend",
    }
}

/// The metadata of a real backend's refusal: the backend, which configuration checks
/// failed, whether confinement was observed and how many findings there were, the
/// process state, and for an incomplete cleanup the VM, the refusal behind it and how
/// much may remain. The backend's own words and the host's findings are text a VM can
/// influence, so only their count is recorded.
fn refusal_fields(refusal: &LaunchRefusal, fields: &mut Vec<Field>) {
    match refusal {
        LaunchRefusal::ProfileRefused { backend, .. }
        | LaunchRefusal::LayoutRefused { backend, .. }
        | LaunchRefusal::BackendSpecific { backend, .. } => {
            fields.push(Field::metadata("backend", backend.tag()));
        }
        LaunchRefusal::ConfigurationNotApproved {
            backend,
            checks,
            findings,
        } => {
            fields.push(Field::metadata("backend", backend.tag()));
            let tags: Vec<&str> = checks.iter().map(|check| check.tag()).collect();
            fields.push(Field::metadata("configuration_checks", tags.join("+")));
            fields.push(Field::metadata("findings", count(findings.len())));
        }
        LaunchRefusal::ConfinementNotInEffect {
            backend,
            observed,
            findings,
        } => {
            fields.push(Field::metadata("backend", backend.tag()));
            fields.push(Field::metadata("confinement_observed", *observed));
            fields.push(Field::metadata("findings", count(findings.len())));
        }
        LaunchRefusal::ProcessNotRunning { backend, state } => {
            fields.push(Field::metadata("backend", backend.tag()));
            fields.push(Field::metadata("process_state", state.tag()));
            if let VmProcessState::Exited { exit_code } = state {
                fields.push(Field::metadata("exit_code", u64::from(*exit_code)));
            }
        }
        LaunchRefusal::CleanupIncomplete { vm, left, .. } => {
            fields.push(Field::metadata("vm", vm.digest()));
            fields.push(Field::metadata(
                "cleanup_refusal",
                refusal_tag(refusal.cause()),
            ));
            fields.push(Field::metadata("left", count(left.len())));
            fields.push(Field::metadata(
                "left_process",
                left.iter()
                    .any(|item| matches!(item, LeftBehind::Process { .. })),
            ));
        }
        _ => {}
    }
}

/// The stable tag of a backend launch refusal, the same as its serialized `kind`.
pub const fn refusal_tag(refusal: &LaunchRefusal) -> &'static str {
    match refusal {
        LaunchRefusal::Evidence { .. } => "evidence",
        LaunchRefusal::EvidenceNotBound { .. } => "evidence_not_bound",
        LaunchRefusal::PerimeterNotEvidenced { .. } => "perimeter_not_evidenced",
        LaunchRefusal::NoPerimeterRules { .. } => "no_perimeter_rules",
        LaunchRefusal::HardwareVirtualizationFailed { .. } => "hardware_virtualization_failed",
        LaunchRefusal::AcceleratorNotObserved { .. } => "accelerator_not_observed",
        LaunchRefusal::NotHardwareVirtualized { .. } => "not_hardware_virtualized",
        LaunchRefusal::UnexpectedAccelerator { .. } => "unexpected_accelerator",
        LaunchRefusal::Unsupported { .. } => "unsupported",
        LaunchRefusal::BackendArtifactMismatch { .. } => "backend_artifact_mismatch",
        LaunchRefusal::BootGenerationUsed { .. } => "boot_generation_used",
        LaunchRefusal::ObservationNotCurrent { .. } => "observation_not_current",
        LaunchRefusal::PropertiesNotSatisfied { .. } => "properties_not_satisfied",
        LaunchRefusal::SnapshotNotRestorable { .. } => "snapshot_not_restorable",
        LaunchRefusal::RestoreRefused { .. } => "restore_refused",
        LaunchRefusal::CreateFailed { .. } => "create_failed",
        LaunchRefusal::RecordNotSealed { .. } => "record_not_sealed",
        LaunchRefusal::ProfileRefused { .. } => "profile_refused",
        LaunchRefusal::LayoutRefused { .. } => "layout_refused",
        LaunchRefusal::ConfigurationNotApproved { .. } => "configuration_not_approved",
        LaunchRefusal::ConfinementNotInEffect { .. } => "confinement_not_in_effect",
        LaunchRefusal::ProcessNotRunning { .. } => "process_not_running",
        LaunchRefusal::BackendSpecific { .. } => "backend_specific",
        LaunchRefusal::CleanupIncomplete { .. } => "cleanup_incomplete",
    }
}

const fn feature_tag(feature: Feature) -> &'static str {
    match feature {
        Feature::Snapshot => "snapshot",
        Feature::Restore => "restore",
        Feature::DeveloperEmulation => "developer_emulation",
        Feature::GpuAssignment => "gpu_assignment",
        Feature::GpuParavirtualization => "gpu_paravirtualization",
        Feature::Display => "display",
        Feature::ConfidentialVm => "confidential_vm",
        Feature::DedicatedHost => "dedicated_host",
    }
}

const fn fact_tag(fact: FactName) -> &'static str {
    match fact {
        FactName::HypervisorEvidence => "hypervisor_evidence",
        FactName::Accelerator => "accelerator",
        FactName::Host => "host",
        FactName::GuestImage => "guest_image",
        FactName::Isolation => "isolation",
        FactName::Confinement => "confinement",
        FactName::Network => "network",
        FactName::Credentials => "credentials",
        FactName::Persistence => "persistence",
        FactName::Devices => "devices",
        FactName::Confidentiality => "confidentiality",
    }
}

fn accelerator_tag(accelerator: Accelerator) -> String {
    match accelerator {
        Accelerator::Hardware { hypervisor } => format!("hardware:{}", hypervisor.tag()),
        Accelerator::Emulation { emulator } => format!("emulation:{}", emulator.tag()),
    }
}

const fn source_class_tag(source: crate::foundation::evidence::SourceClass) -> &'static str {
    use crate::foundation::evidence::SourceClass;
    match source {
        SourceClass::Fixture => "fixture",
        SourceClass::RecordedDeclaration => "recorded_declaration",
        SourceClass::GuestReport => "guest_report",
        SourceClass::ProviderApi => "provider_api",
        SourceClass::HostProbe => "host_probe",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::SandboxBootGeneration;

    #[test]
    fn tags_are_stable_snake_case_identifiers() {
        for tag in [
            acknowledgment_tag(Acknowledgment::VmStopped),
            cause_tag(RevocationCause::ClockRolledBack),
            ack_source_tag(&AckSource::SupervisorHandle),
            milestone_source_tag(&MilestoneSource::Coordinator),
            reason_tag(RevocationReason::SecurityEvent),
            grant_cause_tag(GrantRevocationCause::OwnerReclaimed),
            evidence_refusal_tag(&EvidenceRefusal::Missing {
                capability: crate::foundation::evidence::Capability::PerimeterRuleEnforced,
            }),
            refusal_tag(&LaunchRefusal::BootGenerationUsed {
                execution: ExecutionId::new("exe-1").unwrap(),
                boot: SandboxBootGeneration::FIRST,
            }),
            feature_tag(Feature::ConfidentialVm),
            fact_tag(FactName::GuestImage),
            launch_failure_tag(&LaunchFailure::NotReady {
                detail: String::new(),
            }),
            SUPERVISOR_OPERATION,
        ] {
            assert!(
                crate::foundation::ids::validate_identifier(tag).is_ok(),
                "{tag}"
            );
            assert_eq!(tag, tag.to_ascii_lowercase());
        }
        let refusal = LaunchRefusal::Unsupported {
            feature: Feature::DedicatedHost,
        };
        assert_eq!(
            serde_json::to_value(&refusal).unwrap()["kind"],
            refusal_tag(&refusal)
        );
        assert_eq!(
            accelerator_tag(Accelerator::Hardware {
                hypervisor: crate::foundation::evidence::HypervisorKind::Whpx
            }),
            "hardware:whpx"
        );
        assert_eq!(nanos(u128::MAX), u64::MAX);
        assert_eq!(count(3), 3);
    }

    #[test]
    fn tags_match_the_serialized_forms() {
        use crate::foundation::coordination::RevocationMilestone as M;
        for milestone in [
            M::NewAuthorizationsDenied,
            M::FirstDeniedAuthorization,
            M::SocketsClosed,
            M::AllChannelsClosed,
            M::LeasesClosed,
            M::GpuReclaimed,
            M::VmStopped,
            M::ProviderStoppedBilling,
            M::CleanupFinished,
        ] {
            assert_eq!(
                serde_json::to_value(milestone).unwrap(),
                milestone_tag(milestone)
            );
        }
        for reason in [
            RevocationReason::UserRequested,
            RevocationReason::PolicyChanged,
            RevocationReason::AuthorizationExpired,
            RevocationReason::SecurityEvent,
            RevocationReason::OwnerReclaimed,
        ] {
            assert_eq!(serde_json::to_value(reason).unwrap(), reason_tag(reason));
        }
        for cause in [
            GrantRevocationCause::UserRequested,
            GrantRevocationCause::PolicyChanged,
            GrantRevocationCause::Violation,
            GrantRevocationCause::OwnerReclaimed,
        ] {
            assert_eq!(serde_json::to_value(cause).unwrap(), grant_cause_tag(cause));
        }
        let source = AckSource::Coordination {
            milestone: M::AllChannelsClosed,
            source: MilestoneSource::Acknowledged {
                source: crate::foundation::evidence::SourceClass::HostProbe,
            },
        };
        let json = serde_json::to_value(source).unwrap();
        assert_eq!(json["by"], ack_source_tag(&source));
        assert_eq!(
            json["source"]["established_by"],
            milestone_source_tag(&MilestoneSource::Acknowledged {
                source: crate::foundation::evidence::SourceClass::HostProbe
            })
        );
        let refusal = EvidenceRefusal::Stale {
            capability: crate::foundation::evidence::Capability::PerimeterRuleEnforced,
            staleness: crate::foundation::evidence::Staleness::OtherClock,
        };
        assert_eq!(
            serde_json::to_value(&refusal).unwrap()["refusal"],
            evidence_refusal_tag(&refusal)
        );
    }

    #[test]
    fn real_backend_refusal_tags_match_their_kinds_and_carry_no_backend_text() {
        use crate::sandbox::backend::{BackendKind, ConfigurationCheck};
        let backend = BackendKind::Firecracker;
        let detail = "C:\\Users\\someone\\qemu.exe".to_owned();
        let vm = crate::foundation::coordination::VmInstanceId::new(
            crate::foundation::ids::digest("yougori/test/vm/v1", &[b"left"]),
        );
        let refusals = [
            LaunchRefusal::ProfileRefused {
                backend,
                detail: detail.clone(),
            },
            LaunchRefusal::LayoutRefused {
                backend,
                detail: detail.clone(),
            },
            LaunchRefusal::ConfigurationNotApproved {
                backend,
                checks: [ConfigurationCheck::GoldenConfiguration]
                    .into_iter()
                    .collect(),
                findings: vec![detail.clone()],
            },
            LaunchRefusal::ConfinementNotInEffect {
                backend,
                observed: true,
                findings: vec![detail.clone()],
            },
            LaunchRefusal::ProcessNotRunning {
                backend,
                state: VmProcessState::Exited { exit_code: 2 },
            },
            LaunchRefusal::BackendSpecific {
                backend,
                detail: detail.clone(),
            },
            LaunchRefusal::CleanupIncomplete {
                vm,
                refusal: Box::new(LaunchRefusal::BackendSpecific {
                    backend,
                    detail: detail.clone(),
                }),
                left: vec![LeftBehind::Process {
                    detail: detail.clone(),
                }],
            },
        ];
        for refusal in &refusals {
            assert_eq!(
                serde_json::to_value(refusal).unwrap()["kind"],
                refusal_tag(refusal)
            );
            let mut fields = Vec::new();
            refusal_fields(refusal, &mut fields);
            assert!(!fields.is_empty(), "{refusal:?}");
            let shown = format!("{fields:?}");
            assert!(!shown.contains("someone"), "{shown}");
        }
        let mut fields = Vec::new();
        refusal_fields(&refusals[6], &mut fields);
        let shown = format!("{fields:?}");
        assert!(shown.contains("\"cleanup_refusal\""), "{shown}");
        assert!(shown.contains("backend_specific"), "{shown}");
    }
}
