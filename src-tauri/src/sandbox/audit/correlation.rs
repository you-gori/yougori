//! Incident correlation (VM-W44 at line 2667: "Correlate user-visible tool requests,
//! approvals, operations and artifacts using CORE-06 identities. Do not require hidden
//! chain-of-thought, raw prompts or unrestricted request-body logging"; §8.2 at line
//! 2443: "label telemetry sources correctly"; VM-P33 at line 2808).
//!
//! The records here hold identifiers, digests, counts, times and typed labels, and
//! nothing else: no field can carry a request body, a prompt, an output, a header or a
//! path, so secrets and unrelated user data are excluded by construction. A
//! [`CorrelationIndex`] links the records by CORE-06 identities and
//! [`CorrelationIndex::reconstruct`] builds an incident timeline from them and the audit
//! records that carry the same operation ids. Every observation carries its
//! [`TelemetrySource`]; a guest report is labelled from the record's provenance, never
//! from what the payload claims, and the hypervisor's host syscalls are labelled as what
//! they are: a host observation of the hypervisor process, not the guest's syscalls.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::foundation::events::{
    AuditEntry, AuditRecord, ConfigError, EventSequence, Generations, HostFact, JournalId, Phase,
    RedactedValue, RevocationReason,
};
use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::{
    AuthorizationEpoch, ContentKey, Digest, ExecutionId, MonotonicTime, OperationId,
};

identifier_type!(
    /// A user-visible tool request.
    RequestId
);
identifier_type!(
    /// One approval decision.
    ApprovalId
);
identifier_type!(
    /// The tool a request names, as the engine's tool registry names it; never text from
    /// the request itself.
    ToolName
);

/// A user-visible tool request: who asked, through which execution, for which tool, with
/// arguments kept only as a digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolRequest {
    pub request: RequestId,
    pub execution: ExecutionId,
    pub tool: ToolName,
    /// The digest of the canonical arguments; the arguments themselves are never kept.
    pub arguments: Digest,
    pub requested_at: MonotonicTime,
    pub generations: Generations,
}

/// How a request was decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    Approved,
    Denied,
    Expired,
}

/// Who decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Approver {
    User,
    Policy,
}

/// A pointer to one audit record: the stream, the sequence and the record's digest, so
/// the record can be found and checked against the chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditPointer {
    pub stream: JournalId,
    pub sequence: EventSequence,
    pub digest: Digest,
}

impl AuditPointer {
    pub fn of(record: &AuditRecord) -> Self {
        Self {
            stream: record.journal().clone(),
            sequence: record.sequence(),
            digest: record.digest(),
        }
    }
}

/// A record that is not a host-observed fact, and so cannot be pointed to as one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotHostObserved {
    pub source: SourceClass,
    pub entry: &'static str,
}

impl fmt::Display for NotHostObserved {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the record is a {} entry from a {}, not a host-observed fact",
            self.entry, self.source
        )
    }
}

impl std::error::Error for NotHostObserved {}

/// A pointer to a host-observed fact in the audit stream. Built only from a record whose
/// provenance is a host probe and whose entry is a host fact, so a guest report can never
/// be pointed to as a host fact (§8.2; VM-W44 "guest-reported events marked as such").
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HostFactPointer {
    pointer: AuditPointer,
    fact: HostFact,
}

impl HostFactPointer {
    pub fn of(record: &AuditRecord) -> Result<Self, NotHostObserved> {
        let source = record.event().provenance().source();
        let entry = entry_name(record.event().payload());
        match record.event().payload() {
            AuditEntry::HostFact { fact, .. } if source == SourceClass::HostProbe => Ok(Self {
                pointer: AuditPointer::of(record),
                fact: *fact,
            }),
            _ => Err(NotHostObserved { source, entry }),
        }
    }

    pub fn pointer(&self) -> &AuditPointer {
        &self.pointer
    }

    pub fn fact(&self) -> HostFact {
        self.fact
    }
}

fn entry_name(entry: &AuditEntry) -> &'static str {
    match entry {
        AuditEntry::HostFact { .. } => "host fact",
        AuditEntry::GuestObservation { .. } => "guest observation",
        AuditEntry::Revocation { .. } => "revocation",
        AuditEntry::GrantRevocation { .. } => "grant revocation",
        AuditEntry::Linkage { .. } => "linkage",
        AuditEntry::EventsLost { .. } => "events lost",
    }
}

/// One approval decision on a request, with the audit record that holds the decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    pub approval: ApprovalId,
    pub request: RequestId,
    pub decision: ApprovalDecision,
    pub decided_by: Approver,
    /// The authorization epoch the decision was made under.
    pub epoch: AuthorizationEpoch,
    pub decided_at: MonotonicTime,
    pub audit: Option<AuditPointer>,
}

/// An operation started for a request, under an approval when one was needed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationLink {
    pub operation: OperationId,
    pub request: RequestId,
    pub approval: Option<ApprovalId>,
    pub execution: ExecutionId,
    pub started_at: MonotonicTime,
}

/// What an operation did with an artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactRole {
    Consumed,
    Produced,
    /// Left the sandbox through a release contract.
    Released,
}

/// An artifact an operation consumed, produced or released, by content identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactLink {
    pub artifact: ContentKey,
    pub operation: OperationId,
    pub role: ArtifactRole,
    pub bytes: u64,
    pub at: MonotonicTime,
}

/// What kind of report a guest made.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuestReportKind {
    Stdout,
    Stderr,
    SyscallReport,
    InitReport,
    AgentReport,
    /// A guest observation recorded in the audit stream.
    AuditObservation,
}

strict_tagged_enum! {
    /// Where an observation came from (§8.2 line 2443). The label travels with every
    /// observation and every timeline entry.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum TelemetrySource (tag = "source", wire = TelemetrySourceWire, wire_name = "TelemetrySourceWire") {
        /// The host observed it itself: configuration, process state or a controlled
        /// external observation.
        HostObservation,
        /// The guest reported it: untrusted, whatever it claims (§8.1 line 2437).
        GuestReport { kind: GuestReportKind },
        /// Syscalls of the hypervisor process as the host observed them: a host
        /// observation about the hypervisor, which does not reveal every syscall inside
        /// the guest.
        HypervisorHostSyscalls,
        /// A record from another source class, labelled as such.
        OtherSource { class: SourceClass },
    }
}

impl TelemetrySource {
    /// The label of a record, from its provenance and never from its payload.
    pub fn of_record(record: &AuditRecord) -> Self {
        match record.event().provenance().source() {
            SourceClass::HostProbe => Self::HostObservation,
            SourceClass::GuestReport => Self::GuestReport {
                kind: GuestReportKind::AuditObservation,
            },
            class => Self::OtherSource { class },
        }
    }

    /// Whether the observation is the host's own.
    pub const fn is_host_observation(&self) -> bool {
        matches!(self, Self::HostObservation | Self::HypervisorHostSyscalls)
    }

    /// Whether the observation describes syscalls made inside the guest. Only a guest's
    /// own syscall report claims to, and it is untrusted; the hypervisor's host syscalls
    /// never do.
    pub const fn describes_guest_syscalls(&self) -> bool {
        matches!(
            self,
            Self::GuestReport {
                kind: GuestReportKind::SyscallReport
            }
        )
    }

    pub const fn label(&self) -> &'static str {
        match self {
            Self::HostObservation => "host observation",
            Self::GuestReport { .. } => "guest report (untrusted)",
            Self::HypervisorHostSyscalls => {
                "hypervisor host syscalls (host-observed; not the guest's syscalls)"
            }
            Self::OtherSource { .. } => "other source",
        }
    }
}

strict_tagged_enum! {
    /// What an observation found, as a typed number; never text.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum ObservationSummary (tag = "measure", wire = ObservationSummaryWire, wire_name = "ObservationSummaryWire") {
        ExitCode { code: i64 },
        Bytes { bytes: u64 },
        Syscalls { calls: u64 },
        Events { events: u64 },
        DeniedAttempts { attempts: u64 },
    }
}

/// One observation about an operation, with its source label.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub source: TelemetrySource,
    pub operation: OperationId,
    pub observed_at: MonotonicTime,
    pub summary: ObservationSummary,
}

impl Observation {
    pub fn host(
        operation: OperationId,
        observed_at: MonotonicTime,
        summary: ObservationSummary,
    ) -> Self {
        Self {
            source: TelemetrySource::HostObservation,
            operation,
            observed_at,
            summary,
        }
    }

    pub fn guest_report(
        kind: GuestReportKind,
        operation: OperationId,
        observed_at: MonotonicTime,
        summary: ObservationSummary,
    ) -> Self {
        Self {
            source: TelemetrySource::GuestReport { kind },
            operation,
            observed_at,
            summary,
        }
    }

    pub fn hypervisor_host_syscalls(
        operation: OperationId,
        observed_at: MonotonicTime,
        calls: u64,
    ) -> Self {
        Self {
            source: TelemetrySource::HypervisorHostSyscalls,
            operation,
            observed_at,
            summary: ObservationSummary::Syscalls { calls },
        }
    }
}

/// Bounds of one index; each at least one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CorrelationBounds {
    pub max_requests: usize,
    pub max_approvals: usize,
    pub max_operations: usize,
    pub max_artifacts: usize,
    pub max_observations: usize,
}

impl CorrelationBounds {
    pub fn validate(&self) -> Result<(), ConfigError> {
        for (setting, value) in [
            ("max_requests", self.max_requests),
            ("max_approvals", self.max_approvals),
            ("max_operations", self.max_operations),
            ("max_artifacts", self.max_artifacts),
            ("max_observations", self.max_observations),
        ] {
            if value == 0 {
                return Err(ConfigError::Zero { setting });
            }
        }
        Ok(())
    }
}

/// Why the index refused a record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CorrelationError {
    Config(ConfigError),
    UnknownRequest {
        request: RequestId,
    },
    UnknownApproval {
        approval: ApprovalId,
    },
    UnknownOperation {
        operation: OperationId,
    },
    /// The approval decided another request than the operation names.
    ApprovalForAnotherRequest {
        approval: ApprovalId,
        request: RequestId,
    },
    DuplicateRequest {
        request: RequestId,
    },
    DuplicateApproval {
        approval: ApprovalId,
    },
    DuplicateOperation {
        operation: OperationId,
    },
    /// The bound on `what` is reached; nothing was dropped to make room.
    Bound {
        what: &'static str,
        limit: usize,
    },
}

impl fmt::Display for CorrelationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(error) => write!(f, "{error}"),
            Self::UnknownRequest { request } => write!(f, "request {request} is not indexed"),
            Self::UnknownApproval { approval } => {
                write!(f, "approval {approval} is not indexed")
            }
            Self::UnknownOperation { operation } => {
                write!(f, "operation {operation} is not indexed")
            }
            Self::ApprovalForAnotherRequest { approval, request } => {
                write!(f, "approval {approval} did not decide request {request}")
            }
            Self::DuplicateRequest { request } => {
                write!(f, "request {request} is already indexed")
            }
            Self::DuplicateApproval { approval } => {
                write!(f, "approval {approval} is already indexed")
            }
            Self::DuplicateOperation { operation } => {
                write!(f, "operation {operation} is already indexed")
            }
            Self::Bound { what, limit } => {
                write!(f, "the index holds its bound of {limit} {what}")
            }
        }
    }
}

impl std::error::Error for CorrelationError {}

/// Requests, approvals, operations, artifacts and observations linked by CORE-06
/// identities (VM-W44). Bounded; every record it refuses is refused visibly.
#[derive(Clone, Debug)]
pub struct CorrelationIndex {
    bounds: CorrelationBounds,
    requests: BTreeMap<RequestId, ToolRequest>,
    approvals: BTreeMap<ApprovalId, Approval>,
    operations: BTreeMap<OperationId, OperationLink>,
    artifacts: Vec<ArtifactLink>,
    observations: Vec<Observation>,
}

impl CorrelationIndex {
    pub fn new(bounds: CorrelationBounds) -> Result<Self, CorrelationError> {
        bounds.validate().map_err(CorrelationError::Config)?;
        Ok(Self {
            bounds,
            requests: BTreeMap::new(),
            approvals: BTreeMap::new(),
            operations: BTreeMap::new(),
            artifacts: Vec::new(),
            observations: Vec::new(),
        })
    }

    pub fn add_request(&mut self, request: ToolRequest) -> Result<(), CorrelationError> {
        if self.requests.contains_key(&request.request) {
            return Err(CorrelationError::DuplicateRequest {
                request: request.request,
            });
        }
        bound("requests", self.requests.len(), self.bounds.max_requests)?;
        self.requests.insert(request.request.clone(), request);
        Ok(())
    }

    /// Adds a decision on an indexed request.
    pub fn add_approval(&mut self, approval: Approval) -> Result<(), CorrelationError> {
        if !self.requests.contains_key(&approval.request) {
            return Err(CorrelationError::UnknownRequest {
                request: approval.request,
            });
        }
        if self.approvals.contains_key(&approval.approval) {
            return Err(CorrelationError::DuplicateApproval {
                approval: approval.approval,
            });
        }
        bound("approvals", self.approvals.len(), self.bounds.max_approvals)?;
        self.approvals.insert(approval.approval.clone(), approval);
        Ok(())
    }

    /// Adds an operation of an indexed request; its approval, if named, must have decided
    /// that request. An operation under a denied approval is indexed too: it is what an
    /// incident reconstruction is for.
    pub fn add_operation(&mut self, operation: OperationLink) -> Result<(), CorrelationError> {
        if !self.requests.contains_key(&operation.request) {
            return Err(CorrelationError::UnknownRequest {
                request: operation.request,
            });
        }
        if let Some(approval) = &operation.approval {
            let decided =
                self.approvals
                    .get(approval)
                    .ok_or_else(|| CorrelationError::UnknownApproval {
                        approval: approval.clone(),
                    })?;
            if decided.request != operation.request {
                return Err(CorrelationError::ApprovalForAnotherRequest {
                    approval: approval.clone(),
                    request: operation.request,
                });
            }
        }
        if self.operations.contains_key(&operation.operation) {
            return Err(CorrelationError::DuplicateOperation {
                operation: operation.operation,
            });
        }
        bound(
            "operations",
            self.operations.len(),
            self.bounds.max_operations,
        )?;
        self.operations
            .insert(operation.operation.clone(), operation);
        Ok(())
    }

    pub fn add_artifact(&mut self, artifact: ArtifactLink) -> Result<(), CorrelationError> {
        if !self.operations.contains_key(&artifact.operation) {
            return Err(CorrelationError::UnknownOperation {
                operation: artifact.operation,
            });
        }
        bound("artifacts", self.artifacts.len(), self.bounds.max_artifacts)?;
        self.artifacts.push(artifact);
        Ok(())
    }

    pub fn add_observation(&mut self, observation: Observation) -> Result<(), CorrelationError> {
        if !self.operations.contains_key(&observation.operation) {
            return Err(CorrelationError::UnknownOperation {
                operation: observation.operation,
            });
        }
        bound(
            "observations",
            self.observations.len(),
            self.bounds.max_observations,
        )?;
        self.observations.push(observation);
        Ok(())
    }

    pub fn request(&self, request: &RequestId) -> Option<&ToolRequest> {
        self.requests.get(request)
    }

    pub fn approval(&self, approval: &ApprovalId) -> Option<&Approval> {
        self.approvals.get(approval)
    }

    pub fn operation(&self, operation: &OperationId) -> Option<&OperationLink> {
        self.operations.get(operation)
    }

    pub fn artifacts(&self) -> &[ArtifactLink] {
        &self.artifacts
    }

    pub fn observations(&self) -> &[Observation] {
        &self.observations
    }

    /// Reconstructs an incident: the requests, approvals, operations and artifacts in
    /// `scope`, the audit records whose operation is in scope (and, for an execution, the
    /// revocations of that execution and of its grants), and the observations about those
    /// operations, as one timeline on the host's clock. Audit fields come as the journal
    /// redacted them; nothing else is retained (VM-W44 "minimal content retention").
    pub fn reconstruct(&self, scope: &IncidentScope, audit: &[AuditRecord]) -> Reconstruction {
        let requests: Vec<ToolRequest> = match scope {
            IncidentScope::Execution { execution } => self
                .requests
                .values()
                .filter(|request| &request.execution == execution)
                .cloned()
                .collect(),
            IncidentScope::Request { request } => {
                self.requests.get(request).cloned().into_iter().collect()
            }
            IncidentScope::Operation { operation } => self
                .operations
                .get(operation)
                .and_then(|link| self.requests.get(&link.request))
                .cloned()
                .into_iter()
                .collect(),
        };
        let request_ids: BTreeSet<&RequestId> =
            requests.iter().map(|request| &request.request).collect();
        let operations: Vec<OperationLink> = self
            .operations
            .values()
            .filter(|link| match scope {
                IncidentScope::Execution { execution } => &link.execution == execution,
                IncidentScope::Request { request } => &link.request == request,
                IncidentScope::Operation { operation } => &link.operation == operation,
            })
            .cloned()
            .collect();
        let mut operation_ids: BTreeSet<OperationId> = operations
            .iter()
            .map(|link| link.operation.clone())
            .collect();
        if let IncidentScope::Operation { operation } = scope {
            operation_ids.insert(operation.clone());
        }
        let approvals: Vec<Approval> = self
            .approvals
            .values()
            .filter(|approval| request_ids.contains(&approval.request))
            .cloned()
            .collect();
        let artifacts: Vec<ArtifactLink> = self
            .artifacts
            .iter()
            .filter(|artifact| operation_ids.contains(&artifact.operation))
            .cloned()
            .collect();
        let observations: Vec<&Observation> = self
            .observations
            .iter()
            .filter(|observation| operation_ids.contains(&observation.operation))
            .collect();

        let mut timeline = Vec::new();
        for request in &requests {
            timeline.push(TimelineEntry {
                at: request.requested_at,
                source: TelemetrySource::HostObservation,
                operation: None,
                event: TimelineEvent::Requested {
                    request: request.request.clone(),
                    tool: request.tool.clone(),
                },
                audit: None,
            });
        }
        for approval in &approvals {
            timeline.push(TimelineEntry {
                at: approval.decided_at,
                source: TelemetrySource::HostObservation,
                operation: None,
                event: TimelineEvent::Decided {
                    approval: approval.approval.clone(),
                    decision: approval.decision,
                    decided_by: approval.decided_by,
                },
                audit: approval.audit.clone(),
            });
        }
        for link in &operations {
            timeline.push(TimelineEntry {
                at: link.started_at,
                source: TelemetrySource::HostObservation,
                operation: Some(link.operation.clone()),
                event: TimelineEvent::Started {
                    request: link.request.clone(),
                    approval: link.approval.clone(),
                },
                audit: None,
            });
        }
        let mut audit_records = 0u64;
        let mut guest_reports = 0u64;
        let mut retained_text_bytes = 0u64;
        for record in audit {
            let event = record.event();
            let in_scope = operation_ids.contains(event.operation())
                || match (scope, event.payload()) {
                    (
                        IncidentScope::Execution { execution },
                        AuditEntry::Revocation { revocation },
                    ) => &revocation.execution == execution,
                    (
                        IncidentScope::Execution { execution },
                        AuditEntry::GrantRevocation { revocation },
                    ) => &revocation.execution == execution,
                    _ => false,
                };
            if !in_scope {
                continue;
            }
            audit_records = audit_records.saturating_add(1);
            let source = TelemetrySource::of_record(record);
            if matches!(source, TelemetrySource::GuestReport { .. }) {
                guest_reports = guest_reports.saturating_add(1);
            }
            retained_text_bytes = retained_text_bytes.saturating_add(text_bytes(event.payload()));
            let timeline_event = match event.payload() {
                AuditEntry::Revocation { revocation } => TimelineEvent::Revoked {
                    execution: revocation.execution.clone(),
                    epoch: revocation.epoch,
                    reason: revocation.reason,
                },
                entry => TimelineEvent::Audited {
                    phase: event.phase(),
                    entry: entry.clone(),
                },
            };
            timeline.push(TimelineEntry {
                at: event.emitted_at(),
                source,
                operation: Some(event.operation().clone()),
                event: timeline_event,
                audit: Some(AuditPointer::of(record)),
            });
        }
        for artifact in &artifacts {
            timeline.push(TimelineEntry {
                at: artifact.at,
                source: TelemetrySource::HostObservation,
                operation: Some(artifact.operation.clone()),
                event: TimelineEvent::Artifact {
                    artifact: artifact.artifact,
                    role: artifact.role,
                    bytes: artifact.bytes,
                },
                audit: None,
            });
        }
        for observation in observations {
            if matches!(observation.source, TelemetrySource::GuestReport { .. }) {
                guest_reports = guest_reports.saturating_add(1);
            }
            timeline.push(TimelineEntry {
                at: observation.observed_at,
                source: observation.source,
                operation: Some(observation.operation.clone()),
                event: TimelineEvent::Observed {
                    summary: observation.summary,
                },
                audit: None,
            });
        }
        timeline.sort_by_key(|entry| entry.at);
        Reconstruction {
            scope: scope.clone(),
            requests,
            approvals,
            operations,
            artifacts,
            timeline,
            audit_records,
            guest_reports,
            retained_text_bytes,
        }
    }
}

fn bound(what: &'static str, len: usize, limit: usize) -> Result<(), CorrelationError> {
    if len >= limit {
        return Err(CorrelationError::Bound { what, limit });
    }
    Ok(())
}

/// The bytes of kept text in an entry's redacted fields.
fn text_bytes(entry: &AuditEntry) -> u64 {
    let fields = match entry {
        AuditEntry::HostFact { fields, .. } | AuditEntry::GuestObservation { fields } => fields,
        _ => return 0,
    };
    fields
        .fields()
        .iter()
        .map(|field| match field.value() {
            RedactedValue::Text { text, .. } => u64::try_from(text.len()).unwrap_or(u64::MAX),
            _ => 0,
        })
        .fold(0u64, u64::saturating_add)
}

strict_tagged_enum! {
    /// What an incident is about.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum IncidentScope (tag = "scope", wire = IncidentScopeWire, wire_name = "IncidentScopeWire") {
        Execution { execution: ExecutionId },
        Operation { operation: OperationId },
        Request { request: RequestId },
    }
}

/// One step of an incident timeline. Written for reports; never read back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum TimelineEvent {
    Requested {
        request: RequestId,
        tool: ToolName,
    },
    Decided {
        approval: ApprovalId,
        decision: ApprovalDecision,
        decided_by: Approver,
    },
    Started {
        request: RequestId,
        approval: Option<ApprovalId>,
    },
    /// An audit record, with its fields as the journal redacted them.
    Audited {
        phase: Phase,
        entry: AuditEntry,
    },
    Artifact {
        artifact: ContentKey,
        role: ArtifactRole,
        bytes: u64,
    },
    Observed {
        summary: ObservationSummary,
    },
    Revoked {
        execution: ExecutionId,
        epoch: AuthorizationEpoch,
        reason: RevocationReason,
    },
}

/// One timeline entry, labelled with its source.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TimelineEntry {
    pub at: MonotonicTime,
    pub source: TelemetrySource,
    pub operation: Option<OperationId>,
    pub event: TimelineEvent,
    pub audit: Option<AuditPointer>,
}

/// An incident reconstructed from identities and audit records (VM-W44). Written for
/// reports; never read back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Reconstruction {
    pub scope: IncidentScope,
    pub requests: Vec<ToolRequest>,
    pub approvals: Vec<Approval>,
    pub operations: Vec<OperationLink>,
    pub artifacts: Vec<ArtifactLink>,
    pub timeline: Vec<TimelineEntry>,
    pub audit_records: u64,
    /// Entries labelled as guest reports, in the audit records and the observations.
    pub guest_reports: u64,
    /// Bytes of kept text across every audit entry in the timeline: what the
    /// reconstruction retains beyond identifiers, digests and numbers.
    pub retained_text_bytes: u64,
}

impl Reconstruction {
    /// The entries labelled as guest reports.
    pub fn guest_reported(&self) -> impl Iterator<Item = &TimelineEntry> {
        self.timeline
            .iter()
            .filter(|entry| matches!(entry.source, TelemetrySource::GuestReport { .. }))
    }
}
