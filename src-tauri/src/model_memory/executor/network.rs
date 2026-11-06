//! CORE-05 authenticated, resumable transfers for network sources: the model-extent
//! payload adapter (GPU-W09, docs/combined-plan-unfinished-work.md line 167).
//!
//! With [`TransferExecutor::with_transfers`] the executor reads a remote store or an
//! authorized peer only through a CORE-05 [`TransferSession`] of the job, opened from a
//! sealed grant at submission ([`SourceGrant`], [`super::SubmitOptions`]). The grant is
//! bound to this executor, this job and this source: its operation is
//! [`session_operation`], and its tenant, parent, direction, endpoints, object and scope
//! are the job's. Together with CORE-05's own checks (the seal, the key's replay
//! registry, the clock session and the parent's authority), a replayed envelope, one from
//! another process and one issued for another executor or job are refused before
//! anything is reserved (T14's open item: bind the envelope to the executor).
//!
//! Each batch read from such a source is one CORE-05 chunk covering exactly the batch's
//! extents: admitted, and so charged to the grant's budget and to the host ledger through
//! CORE-05's byte budget, before the read starts, and delivered when it finishes.
//! Everything after is P03's: each extent is verified against the manifest before use,
//! decoded and validated, copied with its own completion event and published per
//! dependency (§3.5). A transport failure interrupts the session, and the batch is read
//! again in a new attempt under the same envelope. The extents a job verified at its
//! destination are its gate's verified extents, so a retry never moves them again and
//! the session completes once every granted range is among them. A revocation of the
//! parent's authority stops the session and cancels the job; an expired grant or an
//! exhausted budget ends the source for the job, whose extents go to its other sources
//! or fail; a source that served an extent not the manifest's is blacklisted for the job
//! and its session cancelled. A session ends with its job, and its reservation and
//! network slot go back.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use super::error::SubmitError;
use super::job::{CancelReason, TransferRequest};
use super::machine::TransferExecutor;
use super::model::{ManifestExtent, SourceCandidate, SourceKind};
use super::ports::TransferEventKind;
use crate::foundation::ids::{
    AuthorizationEpoch, Clock, ContentKey, DigestBuilder, ExecutionId, IdError, OperationId,
    TenantId,
};
use crate::foundation::transfer::{
    ByteRange, ChunkPermit, Connection, Direction, Endpoint, RangeSet, SealedEnvelope, StopReason,
    TransferEnvelope, TransferGate, TransferKey, TransferPorts, TransferRefusal, TransferSession,
    TransferStatus, VerifiedExtentsPort,
};
use crate::model_memory::math::SourceId;

/// Domain of [`session_operation`].
pub const SESSION_DOMAIN: &str = "yougori/model-memory/executor/transfer-session/v1";

/// The operation a CORE-05 grant carries to move `job`'s reads from `source` on the
/// executor whose own operation is `executor`: `op-` and the hex digest of the three
/// under [`SESSION_DOMAIN`]. It binds the envelope to this executor, this job and this
/// source, so no other executor, job or source opens it, and an issuer can compute it.
pub fn session_operation(
    executor: &OperationId,
    job: &OperationId,
    source: &SourceId,
) -> Result<OperationId, IdError> {
    let digest = DigestBuilder::new(SESSION_DOMAIN)
        .str(executor.as_str())
        .str(job.as_str())
        .str(source.as_str())
        .finish();
    OperationId::new(format!("op-{}", digest.to_hex()))
}

/// A sealed CORE-05 grant for one job's reads from one network source, and the
/// connection its attempts make: the authenticated source and recipient and the
/// credential presented (INT-08).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceGrant {
    pub source: SourceId,
    pub sealed: SealedEnvelope,
    pub connection: Connection,
}

/// The envelope field that does not bind a grant to the job.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BindingField {
    /// Not [`session_operation`] of this executor, job and source.
    Operation,
    Tenant,
    Parent,
    /// Not a peer transfer for an authorized peer, or not a download for a remote store.
    Direction,
    /// Not the connection's source, or not an enrolled peer host or registered route as
    /// the source's kind needs.
    Source,
    /// Not the job's own execution.
    Recipient,
    /// The scope does not name the stored object the job reads.
    Object,
    /// The scope does not cover every extent the job reads.
    Scope,
}

impl fmt::Display for BindingField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Operation => "its operation is not this executor's for this job and source",
            Self::Tenant => "it is another tenant's",
            Self::Parent => "it belongs to another execution",
            Self::Direction => "its direction does not fit the source",
            Self::Source => "its source is not the source connected",
            Self::Recipient => "its recipient is not the job's execution",
            Self::Object => "its scope does not name the object the job reads",
            Self::Scope => "its scope does not cover every extent the job reads",
        })
    }
}

/// Why a grant cannot carry a job's reads (GPU-W09).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransferBindingError {
    /// The executor reads no source through CORE-05 sessions
    /// ([`TransferExecutor::with_transfers`]).
    NoTransfers,
    /// The job does not read the source over the network: it is not among the job's
    /// sources, not a remote store or an authorized peer, or not readable here.
    NotNetworkSource,
    /// Another grant of the submission names the source.
    DuplicateGrant,
    /// The envelope is not bound to this executor, this job and this source.
    NotBound { field: BindingField },
    /// CORE-05 refused the envelope: tampered, replayed, from another clock session,
    /// expired, without the parent's authority, or without budget or a network slot.
    Refused { refusal: TransferRefusal },
}

impl fmt::Display for TransferBindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoTransfers => {
                f.write_str("the executor reads nothing through transfer sessions")
            }
            Self::NotNetworkSource => {
                f.write_str("the job does not read this source over the network")
            }
            Self::DuplicateGrant => f.write_str("two grants name the source"),
            Self::NotBound { field } => write!(f, "the grant is not bound to the job: {field}"),
            Self::Refused { refusal } => write!(f, "the transfer was refused: {refusal}"),
        }
    }
}

impl std::error::Error for TransferBindingError {}

/// The CORE-05 transfers the executor reads network sources through: the host's transfer
/// key, whose clones share its replay registry, and the host's transfer ports.
pub(super) struct NetworkTransfers {
    pub(super) key: TransferKey,
    pub(super) ports: TransferPorts,
}

/// The extents one job verified at its destination, as the verified-extents port of the
/// job's own gate (the CORE-02 role in CORE-05): ranges of the stored object its execution
/// holds verified against the manifest, never another job's (S3.3).
pub(super) struct JobExtents {
    tenant: TenantId,
    parent: ExecutionId,
    verified: Mutex<BTreeMap<ContentKey, RangeSet>>,
}

impl JobExtents {
    fn new(tenant: TenantId, parent: ExecutionId) -> Self {
        Self {
            tenant,
            parent,
            verified: Mutex::new(BTreeMap::new()),
        }
    }

    fn record(&self, object: ContentKey, range: ByteRange) {
        lock(&self.verified)
            .entry(object)
            .or_default()
            .insert(range);
    }
}

impl VerifiedExtentsPort for JobExtents {
    fn verified(
        &self,
        tenant: &TenantId,
        parent: &ExecutionId,
        recipient: &Endpoint,
        object: &ContentKey,
    ) -> RangeSet {
        let ours = Endpoint::Execution {
            execution: self.parent.clone(),
        };
        if *tenant != self.tenant || *parent != self.parent || *recipient != ours {
            return RangeSet::new();
        }
        lock(&self.verified)
            .get(object)
            .cloned()
            .unwrap_or_default()
    }
}

/// One job's CORE-05 transfer from one network source.
pub(super) struct JobTransfer {
    pub(super) session: TransferSession,
    pub(super) connection: Connection,
    /// The stored object the session moves.
    pub(super) object: ContentKey,
    extents: Arc<JobExtents>,
    /// Why the source ended for the job while its session did not stop, such as an
    /// exhausted budget.
    pub(super) refused: Option<TransferRefusal>,
}

impl JobTransfer {
    /// Whether the session can still move the job's bytes.
    pub(super) fn usable(&self) -> bool {
        self.refused.is_none() && self.session.status().is_live()
    }
}

/// What a grant must name to carry one job's reads from one source.
struct Binding<'a> {
    operation: OperationId,
    tenant: &'a TenantId,
    parent: &'a ExecutionId,
    kind: SourceKind,
    object: ContentKey,
    extents: &'a [ManifestExtent],
}

/// The first field of `envelope` that does not bind it to the job.
fn check_binding(
    envelope: &TransferEnvelope,
    connection: &Connection,
    binding: &Binding<'_>,
) -> Result<(), BindingField> {
    let fields = envelope.fields();
    if fields.operation != binding.operation {
        return Err(BindingField::Operation);
    }
    if fields.tenant != *binding.tenant {
        return Err(BindingField::Tenant);
    }
    if fields.parent != *binding.parent {
        return Err(BindingField::Parent);
    }
    let (direction, source_fits) = match binding.kind {
        SourceKind::AuthorizedPeer => (
            Direction::Peer,
            matches!(fields.source, Endpoint::PeerHost { .. }),
        ),
        SourceKind::Remote => (
            Direction::Download,
            matches!(fields.source, Endpoint::NamedRoute { .. }),
        ),
        SourceKind::LocalFile | SourceKind::GpuPeer { .. } | SourceKind::ImportOnlyBind => {
            return Err(BindingField::Source)
        }
    };
    if fields.direction != direction {
        return Err(BindingField::Direction);
    }
    if !source_fits || fields.source != connection.source {
        return Err(BindingField::Source);
    }
    let recipient = Endpoint::Execution {
        execution: binding.parent.clone(),
    };
    if fields.recipient != recipient {
        return Err(BindingField::Recipient);
    }
    let grant = fields
        .scope
        .grant(&binding.object)
        .ok_or(BindingField::Object)?;
    for extent in binding.extents {
        let covered =
            ByteRange::starting_at(extent.stored_offset_bytes, extent.stored_length_bytes)
                .is_ok_and(|range| grant.granted().covers(range));
        if !covered {
            return Err(BindingField::Scope);
        }
    }
    Ok(())
}

/// What admitting one batch's chunk into its subscribers' sessions came to.
pub(super) enum ChunkAdmission {
    /// Every subscriber's session admitted the chunk; the read may start.
    Admitted(Vec<(OperationId, ChunkPermit)>),
    /// A session's in-flight bound, or a chunk of its current attempt still in flight,
    /// holds the batch back; it stays ready.
    Wait,
    /// A session refused, and its job was cancelled or lost the source; the batch is
    /// planned again for its subscribers.
    Refused,
}

/// Whether a session can take a chunk now.
enum Ready {
    Now,
    Wait,
}

/// The session's own checks of [`TransferSession::admit`], made before any session of a
/// shared batch admits, so no session admits a chunk another then refuses.
enum Precheck {
    Ready,
    Wait,
    /// The chunk overlaps bytes verified, delivered or in flight in this attempt.
    Covered,
    Refuse(TransferRefusal),
}

fn precheck(session: &TransferSession, object: &ContentKey, span: ByteRange) -> Precheck {
    let fields = session.envelope().fields();
    let Some(grant) = fields.scope.grant(object) else {
        return Precheck::Refuse(TransferRefusal::ObjectOutOfScope { object: *object });
    };
    if !grant.granted().covers(span) {
        return Precheck::Refuse(TransferRefusal::RangeOutOfScope {
            object: *object,
            range: span,
        });
    }
    if !session
        .missing()
        .get(object)
        .is_some_and(|missing| missing.covers(span))
    {
        return Precheck::Covered;
    }
    let requested_bytes = span.length_bytes();
    if session.remaining_budget_bytes() < requested_bytes {
        return Precheck::Refuse(TransferRefusal::BudgetExhausted {
            budget_bytes: fields.budget_bytes,
            used_bytes: session.used_bytes(),
            requested_bytes,
        });
    }
    let max_in_flight_bytes = fields.stop_bounds.max_in_flight_bytes;
    let in_flight_bytes = session
        .in_flight_bytes()
        .saturating_add(session.settling_bytes());
    if in_flight_bytes.saturating_add(requested_bytes) > max_in_flight_bytes {
        // A chunk larger than the bound never fits; any other waits for chunks to land.
        if requested_bytes > max_in_flight_bytes {
            return Precheck::Refuse(TransferRefusal::InFlightLimit {
                max_in_flight_bytes,
                in_flight_bytes,
                requested_bytes,
            });
        }
        return Precheck::Wait;
    }
    Precheck::Ready
}

/// Whether `transfer` can take `span` of `object` now, resuming an interrupted attempt
/// first (INT-08). A revocation or expiry is seen before any byte moves (INT-02).
fn ready_for(
    transfer: &mut JobTransfer,
    object: &ContentKey,
    span: ByteRange,
) -> Result<Ready, TransferRefusal> {
    if let Some(refusal) = &transfer.refused {
        return Err(refusal.clone());
    }
    let session = &mut transfer.session;
    if let TransferStatus::Stopped(record) = session.poll() {
        return Err(TransferRefusal::Stopped {
            reason: record.reason.clone(),
        });
    }
    if *session.status() == TransferStatus::Interrupted {
        session.retry(&transfer.connection)?;
    }
    match precheck(session, object, span) {
        Precheck::Ready => Ok(Ready::Now),
        Precheck::Wait => Ok(Ready::Wait),
        Precheck::Refuse(refusal) => Err(refusal),
        Precheck::Covered => {
            // The job reads again bytes delivered in this attempt that were not usable,
            // such as an extent that failed validation: once nothing of the attempt is in
            // flight, a new attempt moves them again.
            if session.in_flight_bytes() > 0 {
                return Ok(Ready::Wait);
            }
            session.interrupt()?;
            session.retry(&transfer.connection)?;
            match precheck(session, object, span) {
                Precheck::Ready => Ok(Ready::Now),
                Precheck::Wait => Ok(Ready::Wait),
                Precheck::Covered => Err(TransferRefusal::AlreadyCovered {
                    object: *object,
                    range: span,
                }),
                Precheck::Refuse(refusal) => Err(refusal),
            }
        }
    }
}

/// The epoch a revocation took from the transfer's parent, if `refusal` is one (INT-02).
fn revoked_epoch(refusal: &TransferRefusal) -> Option<AuthorizationEpoch> {
    match refusal {
        TransferRefusal::Stopped { reason } if reason.is_revocation() => match reason {
            StopReason::AuthorityNotCurrent { granted, .. } => Some(*granted),
            _ => None,
        },
        _ => None,
    }
}

impl<C: Clock> TransferExecutor<C> {
    /// Reads remote stores and authorized peers only through CORE-05 sessions (GPU-W09):
    /// each job's grants are opened at submission through a gate of its own, made from
    /// `key`, the host's transfer key, whose clones share its replay registry, over
    /// `ports`, the host's transfer ports (the parent's authority, the byte budget with
    /// the network slot every transfer holds, and progress), with the job's verified
    /// extents as the gate's verified-extents port. Without it the backend reads network
    /// sources on its own, as before.
    pub fn with_transfers(mut self, key: TransferKey, ports: TransferPorts) -> Self {
        self.transfers = Some(NetworkTransfers { key, ports });
        self
    }

    /// The CORE-05 session `operation`'s reads from `source` move through, if any.
    pub fn transfer(&self, operation: &OperationId, source: &SourceId) -> Option<&TransferSession> {
        self.jobs
            .get(operation)?
            .transfers
            .get(source)
            .map(|transfer| &transfer.session)
    }

    /// Checks a submission's grants before anything is reserved: each names a network
    /// source the job reads, once, carries this key's seal, and is bound to this
    /// executor, this job and this source, covering every extent the job reads of
    /// `object`.
    pub(super) fn check_grants(
        &self,
        request: &TransferRequest,
        object: ContentKey,
        needed: &[ManifestExtent],
        usable: &[SourceCandidate],
        grants: &[SourceGrant],
    ) -> Result<(), SubmitError> {
        let Some(network) = &self.transfers else {
            return match grants.first() {
                Some(grant) => Err(SubmitError::Transfer {
                    source: grant.source.clone(),
                    error: TransferBindingError::NoTransfers,
                }),
                None => Ok(()),
            };
        };
        let mut seen = BTreeSet::new();
        for grant in grants {
            let refuse = |error| SubmitError::Transfer {
                source: grant.source.clone(),
                error,
            };
            let Some(candidate) = usable
                .iter()
                .find(|candidate| candidate.spec.id == grant.source && candidate.kind.is_network())
            else {
                return Err(refuse(TransferBindingError::NotNetworkSource));
            };
            if !seen.insert(&grant.source) {
                return Err(refuse(TransferBindingError::DuplicateGrant));
            }
            let envelope = network.key.verify(&grant.sealed).map_err(|_| {
                refuse(TransferBindingError::Refused {
                    refusal: TransferRefusal::Tampered,
                })
            })?;
            let operation =
                session_operation(&self.config.operation, &request.operation, &grant.source)
                    .map_err(|_| {
                        refuse(TransferBindingError::NotBound {
                            field: BindingField::Operation,
                        })
                    })?;
            let binding = Binding {
                operation,
                tenant: &request.tenant,
                parent: &request.execution,
                kind: candidate.kind,
                object,
                extents: needed,
            };
            check_binding(envelope, &grant.connection, &binding)
                .map_err(|field| refuse(TransferBindingError::NotBound { field }))?;
        }
        Ok(())
    }

    /// Opens one session per grant through a gate of the job's own (CORE-05
    /// `TransferGate::open`: the seal, the key's replay registry, the clock session and
    /// expiry, the parent's authority, the connection, then the whole byte budget with
    /// its network slot reserved). A refusal cancels the sessions this call opened.
    pub(super) fn open_grants(
        &self,
        tenant: &TenantId,
        parent: &ExecutionId,
        object: ContentKey,
        grants: Vec<SourceGrant>,
    ) -> Result<BTreeMap<SourceId, JobTransfer>, SubmitError> {
        let mut opened: BTreeMap<SourceId, JobTransfer> = BTreeMap::new();
        let Some(network) = &self.transfers else {
            return Ok(opened);
        };
        if grants.is_empty() {
            return Ok(opened);
        }
        let extents = Arc::new(JobExtents::new(tenant.clone(), parent.clone()));
        let mut ports = network.ports.clone();
        ports.extents = Arc::clone(&extents) as Arc<dyn VerifiedExtentsPort>;
        let gate = TransferGate::new(network.key.clone(), ports);
        for grant in grants {
            match gate.open(&grant.sealed, &grant.connection) {
                Ok(session) => {
                    opened.insert(
                        grant.source,
                        JobTransfer {
                            session,
                            connection: grant.connection,
                            object,
                            extents: Arc::clone(&extents),
                            refused: None,
                        },
                    );
                }
                Err(refusal) => {
                    for transfer in opened.values_mut() {
                        transfer.session.cancel();
                    }
                    return Err(SubmitError::Transfer {
                        source: grant.source,
                        error: TransferBindingError::Refused { refusal },
                    });
                }
            }
        }
        Ok(opened)
    }

    /// Admits one batch's chunk, `span` of `object`, into the session each subscriber
    /// holds for `source` (CORE-05 `TransferSession::admit`), charging its bytes before
    /// they move. Every session is checked before any admits; a session that refuses ends
    /// the source for its job, or cancels the job on a revocation.
    pub(super) fn admit_chunk(
        &mut self,
        subscribers: &BTreeSet<OperationId>,
        source: &SourceId,
        object: ContentKey,
        span: ByteRange,
    ) -> ChunkAdmission {
        let mut refused = Vec::new();
        let mut waiting = false;
        for operation in subscribers {
            let Some(transfer) = self.job_transfer(operation, source) else {
                continue;
            };
            match ready_for(transfer, &object, span) {
                Ok(Ready::Now) => {}
                Ok(Ready::Wait) => waiting = true,
                Err(refusal) => refused.push((operation.clone(), refusal)),
            }
        }
        if !refused.is_empty() {
            for (operation, refusal) in refused {
                self.transfer_refused(&operation, source, refusal);
            }
            return ChunkAdmission::Refused;
        }
        if waiting {
            return ChunkAdmission::Wait;
        }
        let mut permits = Vec::new();
        for operation in subscribers {
            let Some(transfer) = self.job_transfer(operation, source) else {
                continue;
            };
            match transfer.session.admit(&object, span) {
                Ok(permit) => permits.push((operation.clone(), permit)),
                Err(refusal) => refused.push((operation.clone(), refusal)),
            }
        }
        if refused.is_empty() {
            return ChunkAdmission::Admitted(permits);
        }
        // A session refused after the checks, as when its reservation was withdrawn: the
        // chunks the others admitted are dropped with their attempts.
        let admitted: Vec<OperationId> = permits
            .into_iter()
            .map(|(operation, _)| operation)
            .collect();
        self.interrupt_transfers(source, admitted);
        for (operation, refusal) in refused {
            self.transfer_refused(&operation, source, refusal);
        }
        ChunkAdmission::Refused
    }

    /// Delivers a finished read's chunks into their sessions (CORE-05
    /// `TransferSession::deliver`). Returns how many sessions took the chunk and the
    /// first refusal; a chunk dropped by an interruption or delivered late does not
    /// count, and a stopped session ends the source for its job or cancels the job.
    pub(super) fn deliver_chunk(
        &mut self,
        source: &SourceId,
        permits: Vec<(OperationId, ChunkPermit)>,
    ) -> (usize, Option<TransferRefusal>) {
        let mut accepted = 0;
        let mut first = None;
        let mut stopped = Vec::new();
        for (operation, permit) in permits {
            let Some(transfer) = self.job_transfer(&operation, source) else {
                continue;
            };
            match transfer.session.deliver(permit) {
                Ok(()) => accepted += 1,
                Err(refusal) => {
                    if matches!(refusal, TransferRefusal::Stopped { .. }) {
                        stopped.push((operation, refusal.clone()));
                    }
                    first.get_or_insert(refusal);
                }
            }
        }
        for (operation, refusal) in stopped {
            self.transfer_refused(&operation, source, refusal);
        }
        (accepted, first)
    }

    /// Ends the current attempt of each job's session for `source` after a transport
    /// failure (CORE-05 `TransferSession::interrupt`): its chunks in flight are dropped,
    /// and the next chunk resumes it.
    pub(super) fn interrupt_transfers(
        &mut self,
        source: &SourceId,
        operations: impl IntoIterator<Item = OperationId>,
    ) {
        let mut stopped = Vec::new();
        for operation in operations {
            let Some(transfer) = self.job_transfer(&operation, source) else {
                continue;
            };
            if *transfer.session.status() != TransferStatus::Active {
                continue;
            }
            if let Err(refusal) = transfer.session.interrupt() {
                if matches!(refusal, TransferRefusal::Stopped { .. }) {
                    stopped.push((operation, refusal));
                }
            }
        }
        for (operation, refusal) in stopped {
            self.transfer_refused(&operation, source, refusal);
        }
    }

    /// Checks every running job's sessions for a revocation or an expiry even while no
    /// chunk moves (CORE-05 `TransferSession::poll`, INT-02).
    pub(super) fn poll_transfers(&mut self) {
        if self.transfers.is_none() {
            return;
        }
        let mut stopped = Vec::new();
        for (operation, job) in &mut self.jobs {
            if !job.status.is_running() {
                continue;
            }
            for (source, transfer) in &mut job.transfers {
                if transfer.refused.is_some() {
                    continue;
                }
                if let TransferStatus::Stopped(record) = transfer.session.poll() {
                    stopped.push((
                        operation.clone(),
                        source.clone(),
                        TransferRefusal::Stopped {
                            reason: record.reason.clone(),
                        },
                    ));
                }
            }
        }
        for (operation, source, refusal) in stopped {
            self.transfer_refused(&operation, &source, refusal);
        }
    }

    /// A session refused one of the job's chunks or stopped. A revocation cancels the
    /// job (INT-02); anything else ends the source for the job, once, with an event, and
    /// its extents go to its other sources or fail.
    pub(super) fn transfer_refused(
        &mut self,
        operation: &OperationId,
        source: &SourceId,
        refusal: TransferRefusal,
    ) {
        let running = self
            .jobs
            .get(operation)
            .is_some_and(|job| job.status.is_running());
        if let Some(revoked) = revoked_epoch(&refusal) {
            if running {
                self.cancel_job(operation, CancelReason::Revoked { revoked });
            }
            return;
        }
        let newly = self
            .job_transfer(operation, source)
            .is_some_and(|transfer| {
                let newly = transfer.refused.is_none();
                transfer.refused.get_or_insert_with(|| refusal.clone());
                newly
            });
        if newly && running {
            self.emit(
                operation,
                TransferEventKind::TransferRefused {
                    source: source.clone(),
                    refusal,
                },
            );
        }
    }

    /// Ends the job's session for `source`, such as one that served bytes not the
    /// manifest's: its reservation and network slot go back.
    pub(super) fn end_transfer(&mut self, operation: &OperationId, source: &SourceId) {
        if let Some(transfer) = self.job_transfer(operation, source) {
            if transfer.session.status().is_live() {
                transfer.session.cancel();
            }
        }
    }

    /// Ends every session of a job that ended: a completed job's session completes when
    /// every granted range is among the extents the job verified, and is cancelled
    /// otherwise, so its reservation and network slot always go back.
    pub(super) fn close_transfers(&mut self, operation: &OperationId, completed: bool) {
        let Some(job) = self.jobs.get_mut(operation) else {
            return;
        };
        for transfer in job.transfers.values_mut() {
            if !transfer.session.status().is_live() {
                continue;
            }
            if !(completed && transfer.session.finish().is_ok()) {
                transfer.session.cancel();
            }
        }
    }

    /// Records an extent the job verified and delivered as verified at its execution, in
    /// the job's own verified-extents port, so a retry never moves it again.
    pub(super) fn record_verified(
        &self,
        operation: &OperationId,
        object: ContentKey,
        extent: &ManifestExtent,
    ) {
        let Some(job) = self.jobs.get(operation) else {
            return;
        };
        let Ok(range) =
            ByteRange::starting_at(extent.stored_offset_bytes, extent.stored_length_bytes)
        else {
            return;
        };
        for transfer in job.transfers.values() {
            if transfer.object == object {
                transfer.extents.record(object, range);
            }
        }
    }

    fn job_transfer(
        &mut self,
        operation: &OperationId,
        source: &SourceId,
    ) -> Option<&mut JobTransfer> {
        self.jobs.get_mut(operation)?.transfers.get_mut(source)
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
