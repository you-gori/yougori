//! One actor's durable audit stream (VM-W42 at line 2665; §8.2 at lines 2441–2450; the
//! CORE-06 row at line 215: durable security audit stays a separate stream with its own
//! ordering, retention and backpressure).
//!
//! An [`AuditStream`] is a CORE-06 [`AuditJournal`] whose storage is a
//! [`SegmentedStore`] and whose head may be published to a [`HeadAnchor`]. The journal
//! supplies the chain, the one append authority, the bounded spool with its declared
//! failure policy, redaction before append and the bound on guest observations; this
//! module adds the stream directory (one live authority per stream), rotation, resume
//! with restart and truncation detection, and anchoring that never delays an append.
//! Revocations travel on the event plane's priority lane, which never waits on this
//! stream; recording one here is a second, durable copy whose refusal is visible and
//! never stops the lane (§8.2 "never block the revocation channel"). The revocation of
//! one grant is recorded the same way, on the same reserve (§6.3 step 1 at line 2308).
//!
//! A stream opened with [`AuditStream::open_durable`] keeps its segments in a CORE-06
//! durable log ([`DurableSegments`]) in its own directory under the root of a
//! [`StreamDirectory::durable`]: the log's stream owner makes it the only appender in
//! this process and across the processes of the host, and the log continues its sequence
//! after a restart and reports a torn tail and what retention dropped. One opened with
//! [`AuditStream::open_durable_spooled`] keeps its bounded spool on file in that directory
//! too ([`FileSpool`]), so records accepted while the log refused survive a restart and
//! reach the log, in order, when the stream opens again; [`AuditStream::spool_room`] shows
//! the slots ordinary records and revocations may still take, the same after a restart
//! under the same configuration. [`AuditStream::release`] closes a durable stream and
//! releases its log with the outcome; dropping it releases the log as far as it can, but
//! cannot report a release record it failed to write (§8.2 at lines 2441–2450; VM-W42 at
//! line 2665; VM-W43 at line 2666).

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Weak};

use serde::Serialize;

use super::anchor::{AnchorRefusal, AnchorState, AnchoredHead, HeadAnchor};
use super::durable::{
    check_retention, stream_directory_name, DurableError, DurableOpening, DurableSegments,
};
use super::segment::{
    ResumeReport, SegmentConfig, SegmentControl, SegmentError, SegmentHeader, SegmentSeal,
    SegmentStorage, SegmentTotals, SegmentedStore,
};
use super::spool::{FileSpool, SpoolError, SpooledOpening, SPOOL_DIRECTORY};
use crate::foundation::events::{
    AuditAppendAuthority, AuditConfig, AuditDraft, AuditHealth, AuditJournal, AuditReceipt,
    AuditRefusal, AuditSpool, AuditTotals, ConfigError, EventContext, Field, FlushReport,
    GrantRevocation, HostFact, JournalError, JournalHead, JournalId, LogConfig, LossReason,
    LostRange, Phase, ProducerId, ProducerIncarnation, Revocation, StoreRefusal, StreamKey,
    StreamKind,
};
use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::{Clock, IdError, OperationId};

/// What the redaction tests of this module scan, and what they do not (VM-P12 at line
/// 2787: "state the scan's limited coverage").
pub const SECRET_SCAN_COVERAGE: &str = "The redaction tests scan the serialized form of \
every stored segment, every spooled record and every reconstruction for the fixture \
secrets they planted. They do not scan process memory, the guest, storage's or the \
spool's own logs, terminal output, crash dumps or any channel outside this module, and \
they find only the fixture values they look for.";

/// The operation id of records the stream writes about itself, such as lost sequences
/// recorded at resume.
pub const MAINTENANCE_OPERATION: &str = "audit-stream-maintenance";

/// When the stream publishes its head to the anchor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Anchoring {
    /// No anchor: the chain is verified against itself only.
    Off,
    /// After every rotation and at close; [`AuditStream::anchor_now`] works too.
    OnRotation,
}

/// Bounds and policies of one stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamConfig {
    /// The journal's spool bound, revocation reserve, failure policy, guest observation
    /// limit and redaction policy.
    pub audit: AuditConfig,
    pub segment: SegmentConfig,
    pub anchoring: Anchoring,
}

impl StreamConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.audit.validate()?;
        self.segment.validate()
    }
}

/// The streams of one process and which of them hold a live append authority. Opening
/// or resuming a stream through the directory refuses while its earlier stream or
/// authority still exists, so exactly one append authority per stream is ever live
/// (VM-W42 "one append authority per stream").
///
/// A directory made with [`StreamDirectory::durable`] also keeps each stream as a
/// CORE-06 durable log in a directory of its own under its root
/// ([`AuditStream::open_durable`]). There the log's stream owner adds what this registry
/// cannot: one appender across the processes of the host, with the holder named when
/// another process owns the stream.
#[derive(Debug, Default)]
pub struct StreamDirectory {
    live: BTreeMap<JournalId, Weak<()>>,
    root: Option<PathBuf>,
}

impl StreamDirectory {
    /// A directory of streams whose storage the caller supplies.
    pub fn new() -> Self {
        Self::default()
    }

    /// A directory of durable streams under `root`, one directory per stream.
    pub fn durable(root: impl Into<PathBuf>) -> Self {
        Self {
            live: BTreeMap::new(),
            root: Some(root.into()),
        }
    }

    /// The root of the durable streams, if this directory keeps them.
    pub fn root(&self) -> Option<&Path> {
        self.root.as_deref()
    }

    /// The directory of `stream`'s durable log, if this directory keeps durable streams.
    pub fn stream_path(&self, stream: &JournalId) -> Option<PathBuf> {
        self.root
            .as_ref()
            .map(|root| root.join(stream_directory_name(stream)))
    }

    /// The directory of `stream`'s spool on file, inside the directory of its durable log
    /// ([`AuditStream::open_durable_spooled`]), if this directory keeps durable streams.
    pub fn spool_path(&self, stream: &JournalId) -> Option<PathBuf> {
        self.stream_path(stream)
            .map(|path| path.join(SPOOL_DIRECTORY))
    }

    /// Whether a stream or authority for `stream` exists.
    pub fn is_live(&self, stream: &JournalId) -> bool {
        self.live
            .get(stream)
            .is_some_and(|live| live.strong_count() > 0)
    }

    fn claim(&mut self, stream: &JournalId) -> Result<Arc<()>, StreamError> {
        if self.is_live(stream) {
            return Err(StreamError::AuthorityLive {
                stream: stream.clone(),
            });
        }
        let live = Arc::new(());
        self.live.insert(stream.clone(), Arc::downgrade(&live));
        Ok(live)
    }
}

/// The one append authority of a stream: the journal's authority, plus the token that
/// keeps the stream live in its directory. Not `Clone`, `Default` or deserializable.
#[derive(Debug)]
pub struct StreamAuthority {
    inner: AuditAppendAuthority,
    _live: Arc<()>,
}

impl StreamAuthority {
    pub fn stream(&self) -> &JournalId {
        self.inner.journal()
    }

    pub fn owner(&self) -> &ProducerId {
        self.inner.owner()
    }
}

/// What an actor records: the vocabulary of §8.2 as the CORE-06 journal can carry it.
/// Each variant fixes its source label; nothing in the fields can change it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditEvent {
    /// A fact the host decided or observed itself: an authorization decision, a budget,
    /// a lease event, a launch fact or a termination receipt (§8.2 line 2443). Written as
    /// a host observation.
    HostFact { fact: HostFact, fields: Vec<Field> },
    /// What a guest reported (stdout, a syscall report, an init or agent report): an
    /// untrusted observation, always written as a guest report, its text withheld under
    /// the metadata-only policy and its rate bounded (§8.2 line 2443).
    GuestReport { fields: Vec<Field> },
    /// The head of another actor's stream (§8.2 line 2447 "explicit linkage").
    Linkage(JournalHead),
}

impl AuditEvent {
    /// The source class the record will carry, fixed by the variant.
    pub const fn source(&self) -> SourceClass {
        match self {
            Self::HostFact { .. } | Self::Linkage(_) => SourceClass::HostProbe,
            Self::GuestReport { .. } => SourceClass::GuestReport,
        }
    }

    fn into_draft(self) -> AuditDraft {
        match self {
            Self::HostFact { fact, fields } => AuditDraft::HostFact { fact, fields },
            Self::GuestReport { fields } => AuditDraft::GuestObservation { fields },
            Self::Linkage(head) => AuditDraft::Linkage(head),
        }
    }
}

/// Why a stream could not be opened, resumed or closed. Each refusal fails closed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StreamError {
    /// A stream or authority for this stream already exists in the directory.
    AuthorityLive {
        stream: JournalId,
    },
    Config(ConfigError),
    Journal(JournalError),
    Segment(SegmentError),
    Identifier(IdError),
    /// Resume found lost sequences and could not record them, so it did not resume.
    LossNotRecorded(AuditRefusal),
    /// The durable log refused: another owner holds it, it lost lines it had
    /// acknowledged, its lines do not form segments, or its bounds do not fit.
    Durable(DurableError),
    /// The spool on file could not be opened: it is damaged, or storage refused.
    Spool(SpoolError),
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthorityLive { stream } => write!(
                f,
                "stream {stream} already has a live append authority; only dropping it ends that \
                 registration"
            ),
            Self::Config(error) => write!(f, "{error}"),
            Self::Journal(error) => write!(f, "{error}"),
            Self::Segment(error) => write!(f, "{error}"),
            Self::Identifier(error) => write!(f, "{error}"),
            Self::LossNotRecorded(refusal) => write!(
                f,
                "lost sequences could not be recorded, so the stream did not resume: {refusal}"
            ),
            Self::Durable(error) => write!(f, "{error}"),
            Self::Spool(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for StreamError {}

impl From<ConfigError> for StreamError {
    fn from(error: ConfigError) -> Self {
        Self::Config(error)
    }
}

impl From<JournalError> for StreamError {
    fn from(error: JournalError) -> Self {
        Self::Journal(error)
    }
}

impl From<SegmentError> for StreamError {
    fn from(error: SegmentError) -> Self {
        Self::Segment(error)
    }
}

impl From<DurableError> for StreamError {
    fn from(error: DurableError) -> Self {
        Self::Durable(error)
    }
}

impl From<SpoolError> for StreamError {
    fn from(error: SpoolError) -> Self {
        Self::Spool(error)
    }
}

/// Why a record was refused; its operation must not proceed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StreamRefusal {
    /// The authority belongs to another stream.
    WrongStream {
        authority: JournalId,
        stream: JournalId,
    },
    Audit(AuditRefusal),
}

impl fmt::Display for StreamRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongStream { authority, stream } => write!(
                f,
                "an authority for stream {authority} cannot append to stream {stream}"
            ),
            Self::Audit(refusal) => write!(f, "{refusal}"),
        }
    }
}

impl std::error::Error for StreamRefusal {}

/// What resuming did: what it found, the record of lost sequences, if any, and whether
/// the anchor could be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamResume {
    pub report: ResumeReport,
    /// The receipt of the `EventsLost` record written for lost sequences.
    pub loss_record: Option<AuditReceipt>,
    /// Why the anchored head could not be read; the chain was then verified against
    /// itself only.
    pub anchor_refusal: Option<AnchorRefusal>,
}

/// What closing did. The seal is durable; the flush and the anchor were tried once each
/// and never waited for (VM-P22 "without blocking shutdown").
#[derive(Debug)]
pub struct StreamClose {
    pub flush: FlushReport,
    pub seal: SegmentSeal,
    pub anchor: Option<Result<AnchoredHead, AnchorRefusal>>,
}

/// What releasing a durable stream did ([`AuditStream::release`]): the close, then the
/// release of its log. Neither waited for storage to recover.
#[derive(Debug)]
pub struct StreamRelease {
    /// The flush, the seal and the anchor, as [`AuditStream::close`] reports them, or why
    /// the seal could not be written; the log is released either way, and the next owner
    /// then resumes an unsealed segment.
    pub close: Result<StreamClose, StreamError>,
    /// `Ok` once the log's owner record says its owner left cleanly and how far the stream
    /// was durable. On `Err` the lock was given up anyway, and the next owner will find a
    /// stale owner and recover as after a crash.
    pub release: Result<(), DurableError>,
}

/// The stream as operations that need audit see it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamState {
    pub health: AuditHealth,
    /// The chain head, stored or spooled.
    pub head: JournalHead,
    /// The head of what storage holds.
    pub durable_head: JournalHead,
    pub segment: u64,
    pub spooled_records: usize,
    /// Durable records past the last anchored head.
    pub anchor_lag_records: u64,
    pub closed: bool,
}

/// The stream's spool as the journal gives out its slots (§8.2 line 2445 "use a bounded
/// local spool; never block the revocation channel"; VM-W43 at line 2666 "audit overload
/// cannot block emergency revocation"): an ordinary record may take a slot while fewer than
/// `bound - reserve` records wait in the spool, a revocation or the revocation of one grant
/// while fewer than `bound` do, so ordinary records never take the reserve. A spool on file
/// holds the same records after a restart ([`AuditStream::open_durable_spooled`]), so a
/// stream opened again with the same configuration has the same room.
///
/// Only the spool is counted. A record storage refused that the spool did not take
/// (`AuditRefusal::FailClosed` with `kept`) waits outside it and takes one of the next
/// record's slots; a high-impact admission under `AuditFailurePolicy::DenyHighImpact` takes
/// none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpoolRoom {
    /// Records in the spool, waiting for storage.
    pub spooled_records: usize,
    /// The spool's bound, the journal's `spool_records`.
    pub bound: usize,
    /// Slots only revocations may use, the journal's `revocation_reserve_records`.
    pub reserve: usize,
    /// Slots an ordinary record may still take.
    pub ordinary: usize,
    /// Slots a revocation or the revocation of one grant may still take: the ordinary room
    /// and what is left of the reserve.
    pub revocation: usize,
}

impl SpoolRoom {
    fn new(spooled_records: usize, bound: usize, reserve: usize) -> Self {
        Self {
            spooled_records,
            bound,
            reserve,
            ordinary: bound
                .saturating_sub(reserve)
                .saturating_sub(spooled_records),
            revocation: bound.saturating_sub(spooled_records),
        }
    }

    /// The slots of the reserve still free: what revocations may take beyond the ordinary
    /// room.
    pub fn reserve_left(&self) -> usize {
        self.revocation.saturating_sub(self.ordinary)
    }
}

/// Counts of what the stream did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct StreamTotals {
    pub audit: AuditTotals,
    pub segments: SegmentTotals,
    pub anchor_publications: u64,
    pub anchor_refusals: u64,
}

/// One actor's durable audit stream (VM-W42).
#[derive(Debug)]
pub struct AuditStream<S, P, A, C> {
    journal: AuditJournal<SegmentedStore<S>, P, C>,
    control: SegmentControl<S>,
    anchor: A,
    anchoring: Anchoring,
    anchor_state: AnchorState,
    rotations_anchored: u64,
    clock: C,
    /// The journal's spool bound and revocation reserve, for [`AuditStream::spool_room`].
    spool_bound: usize,
    revocation_reserve: usize,
    _live: Arc<()>,
}

impl<S: SegmentStorage, P: AuditSpool, A: HeadAnchor, C: Clock + Clone> AuditStream<S, P, A, C> {
    /// Opens a new stream on empty storage and issues its one authority to `owner`.
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
    ) -> Result<(Self, StreamAuthority), StreamError> {
        config.validate()?;
        let live = directory.claim(&id)?;
        let genesis = JournalHead::genesis(id, owner);
        let (store, control) = SegmentedStore::open(storage, genesis.clone(), config.segment)?;
        let (journal, authority) =
            AuditJournal::resume(genesis, store, spool, clock.clone(), config.audit)?;
        Ok(Self::assemble(
            journal, control, anchor, config, clock, authority, live,
        ))
    }

    /// Resumes a stream from what storage, the spool and the anchor hold: the segments
    /// are verified and compared with the anchored head, the journal continues after the
    /// last durable or spooled record, and sequences that were durable once and are gone
    /// are recorded in the chain as lost. A rewritten chain is refused. An anchor that
    /// cannot be reached is counted as a refusal and the chain is verified against
    /// itself only, visibly in the result.
    #[allow(clippy::too_many_arguments)]
    pub fn resume(
        directory: &mut StreamDirectory,
        id: JournalId,
        owner: ProducerId,
        storage: S,
        spool: P,
        anchor: A,
        clock: C,
        config: StreamConfig,
    ) -> Result<(Self, StreamAuthority, StreamResume), StreamError> {
        config.validate()?;
        let live = directory.claim(&id)?;
        let genesis = JournalHead::genesis(id.clone(), owner.clone());
        let (anchored, anchor_refusal) = match config.anchoring {
            Anchoring::Off => (None, None),
            Anchoring::OnRotation => match anchor.latest(&id) {
                Ok(anchored) => (anchored, None),
                Err(refusal) => (None, Some(refusal)),
            },
        };
        let (store, control, report) =
            SegmentedStore::resume(storage, genesis, config.segment, anchored.as_ref())?;
        let (mut journal, mut authority) = AuditJournal::resume(
            report.head.clone(),
            store,
            spool,
            clock.clone(),
            config.audit,
        )?;
        let loss_record = match report.lost {
            Some(range) => {
                let lost = LostRange {
                    key: StreamKey {
                        producer: owner,
                        incarnation: ProducerIncarnation::FIRST,
                        stream: StreamKind::Audit,
                    },
                    range,
                    reason: LossReason::ProducerRestarted,
                };
                let context = maintenance_context().map_err(StreamError::Identifier)?;
                Some(
                    journal
                        .append(&mut authority, context, AuditDraft::EventsLost(lost))
                        .map_err(StreamError::LossNotRecorded)?,
                )
            }
            None => None,
        };
        let (mut stream, authority) =
            Self::assemble(journal, control, anchor, config, clock, authority, live);
        if anchor_refusal.is_some() {
            let head = stream.control.head();
            stream.anchor_state.record_refusal(head);
        }
        Ok((
            stream,
            authority,
            StreamResume {
                report,
                loss_record,
                anchor_refusal,
            },
        ))
    }

    fn assemble(
        journal: AuditJournal<SegmentedStore<S>, P, C>,
        control: SegmentControl<S>,
        anchor: A,
        config: StreamConfig,
        clock: C,
        authority: AuditAppendAuthority,
        live: Arc<()>,
    ) -> (Self, StreamAuthority) {
        (
            Self {
                journal,
                control,
                anchor,
                anchoring: config.anchoring,
                anchor_state: AnchorState::default(),
                rotations_anchored: 0,
                clock,
                spool_bound: config.audit.spool_records,
                revocation_reserve: config.audit.revocation_reserve_records,
                _live: Arc::clone(&live),
            },
            StreamAuthority {
                inner: authority,
                _live: live,
            },
        )
    }

    pub fn id(&self) -> &JournalId {
        self.journal.id()
    }

    pub fn anchoring(&self) -> Anchoring {
        self.anchoring
    }

    /// Records one event after redacting it, through the stream's authority.
    pub fn record(
        &mut self,
        authority: &mut StreamAuthority,
        context: EventContext,
        event: AuditEvent,
    ) -> Result<AuditReceipt, StreamRefusal> {
        self.check(authority)?;
        let receipt = self
            .journal
            .append(&mut authority.inner, context, event.into_draft())
            .map_err(StreamRefusal::Audit)?;
        self.anchor_after_rotation();
        Ok(receipt)
    }

    /// Admits a high-impact operation by recording it first: the receipt is the
    /// permission to proceed, under the journal's declared failure policy (§8.2 line
    /// 2445: deny new high-impact operations, or use a bounded local spool).
    pub fn admit_high_impact(
        &mut self,
        authority: &mut StreamAuthority,
        context: EventContext,
        fields: Vec<Field>,
    ) -> Result<AuditReceipt, StreamRefusal> {
        self.check(authority)?;
        let receipt = self
            .journal
            .admit_high_impact(&mut authority.inner, context, fields)
            .map_err(StreamRefusal::Audit)?;
        self.anchor_after_rotation();
        Ok(receipt)
    }

    /// Records a revocation that the event plane's priority lane already delivered. The
    /// lane never waits for this; a refusal here is visible and leaves the revocation in
    /// force. The record may use the journal's revocation reserve.
    pub fn record_revocation(
        &mut self,
        authority: &mut StreamAuthority,
        context: EventContext,
        revocation: Revocation,
    ) -> Result<AuditReceipt, StreamRefusal> {
        self.check(authority)?;
        let receipt = self
            .journal
            .append(
                &mut authority.inner,
                context,
                AuditDraft::Revocation(revocation),
            )
            .map_err(StreamRefusal::Audit)?;
        self.anchor_after_rotation();
        Ok(receipt)
    }

    /// Records the revocation of one grant that the event plane's priority lane already
    /// delivered, exactly as [`AuditStream::record_revocation`] records a revocation: the
    /// record may use the journal's revocation reserve, so a stream that fails closed for
    /// ordinary records still takes it while the reserve has room. The lane never waits
    /// for this; a refusal here is visible and leaves the grant revoked. The record is a
    /// typed grant revocation naming the grant and the epoch left in force, never a
    /// revocation of the execution.
    pub fn record_grant_revocation(
        &mut self,
        authority: &mut StreamAuthority,
        context: EventContext,
        revocation: GrantRevocation,
    ) -> Result<AuditReceipt, StreamRefusal> {
        self.check(authority)?;
        let receipt = self
            .journal
            .append(
                &mut authority.inner,
                context,
                AuditDraft::GrantRevocation(revocation),
            )
            .map_err(StreamRefusal::Audit)?;
        self.anchor_after_rotation();
        Ok(receipt)
    }

    /// Moves spooled records to storage, in order, as far as storage takes them.
    pub fn flush(&mut self) -> FlushReport {
        let report = self.journal.flush();
        self.anchor_after_rotation();
        report
    }

    /// Seals the current segment and starts the next; `None` when it was empty. Spooled
    /// records are not durable and are not part of the seal.
    pub fn rotate(&mut self) -> Result<Option<SegmentSeal>, StoreRefusal> {
        let seal = self.control.rotate()?;
        self.anchor_after_rotation();
        Ok(seal)
    }

    /// Publishes the durable head to the anchor now. A refusal is counted, the head stays
    /// pending, and nothing else waits.
    pub fn anchor_now(&mut self) -> Result<AnchoredHead, AnchorRefusal> {
        let head = self.control.head();
        let segment = self.control.current_segment().index();
        let anchored = AnchoredHead::new(head.clone(), segment, self.clock.now())?;
        match self.anchor.publish(&anchored) {
            Ok(()) => {
                self.anchor_state.record_publication(anchored.clone());
                Ok(anchored)
            }
            Err(refusal) => {
                self.anchor_state.record_refusal(head);
                Err(refusal)
            }
        }
    }

    /// Flushes once, seals the current segment and, with anchoring on, publishes the head
    /// once. Nothing here waits for storage or the anchor to recover.
    pub fn close(mut self) -> Result<StreamClose, StreamError> {
        self.close_in_place()
    }

    fn close_in_place(&mut self) -> Result<StreamClose, StreamError> {
        let flush = self.journal.flush();
        let seal = self
            .control
            .close()
            .map_err(|refusal| StreamError::Segment(SegmentError::Storage(refusal)))?;
        let anchor = match self.anchoring {
            Anchoring::Off => None,
            Anchoring::OnRotation => Some(self.anchor_now()),
        };
        Ok(StreamClose {
            flush,
            seal,
            anchor,
        })
    }

    pub fn state(&self) -> StreamState {
        let durable_head = self.control.head();
        StreamState {
            health: self.journal.health(),
            head: self.journal.head(),
            anchor_lag_records: self.anchor_state.lag_records(&durable_head),
            durable_head,
            segment: self.control.current_segment().index(),
            spooled_records: self.journal.spooled(),
            closed: self.control.is_closed(),
        }
    }

    pub fn health(&self) -> AuditHealth {
        self.journal.health()
    }

    /// The spool's room: the slots ordinary records and revocations may still take.
    pub fn spool_room(&self) -> SpoolRoom {
        SpoolRoom::new(
            self.journal.spooled(),
            self.spool_bound,
            self.revocation_reserve,
        )
    }

    /// The chain head, stored or spooled.
    pub fn head(&self) -> JournalHead {
        self.journal.head()
    }

    /// The head of what storage holds.
    pub fn durable_head(&self) -> JournalHead {
        self.control.head()
    }

    pub fn current_segment(&self) -> SegmentHeader {
        self.control.current_segment()
    }

    pub fn anchor_state(&self) -> &AnchorState {
        &self.anchor_state
    }

    pub fn anchor(&self) -> &A {
        &self.anchor
    }

    pub fn totals(&self) -> StreamTotals {
        StreamTotals {
            audit: self.journal.totals(),
            segments: self.control.totals(),
            anchor_publications: self.anchor_state.publications(),
            anchor_refusals: self.anchor_state.refusals(),
        }
    }

    /// Reads storage; it is never lent mutably, so records reach it only through an
    /// append with the stream's authority.
    pub fn with_storage<R>(&self, read: impl FnOnce(&S) -> R) -> R {
        self.control.with_storage(read)
    }

    fn check(&self, authority: &StreamAuthority) -> Result<(), StreamRefusal> {
        if authority.stream() != self.id() {
            return Err(StreamRefusal::WrongStream {
                authority: authority.stream().clone(),
                stream: self.id().clone(),
            });
        }
        Ok(())
    }

    /// Publishes the head once after each rotation the store made. A refusal is recorded
    /// and retried at the next rotation; appends never wait on it.
    fn anchor_after_rotation(&mut self) {
        if self.anchoring != Anchoring::OnRotation {
            return;
        }
        let rotations = self.control.totals().rotations;
        if rotations > self.rotations_anchored {
            self.rotations_anchored = rotations;
            // The outcome is in the anchor state either way.
            let _outcome = self.anchor_now();
        }
    }
}

impl<P: AuditSpool, A: HeadAnchor, C: Clock + Clone> AuditStream<DurableSegments, P, A, C> {
    /// Opens the durable stream `id` in its directory under the root of `directory`, and
    /// issues its one authority to `owner`. Opening the log makes `owner` its only
    /// appender: a second owner in this process or in another one on the host is
    /// refused at once, naming the holder when its record is readable. A log that holds
    /// no segment starts the stream at genesis; otherwise the stream resumes from the
    /// segments read back, as [`AuditStream::resume`] does, from the first segment
    /// retention left. The result reports what the log found (a stale owner, a torn tail
    /// moved to quarantine), its gaps and what resuming found.
    ///
    /// Refused, before the log is touched, while this directory holds a live authority
    /// for `id`, when `directory` keeps no durable streams, or when `log` could let
    /// retention drop the header of the segment being written ([`check_retention`]).
    /// Refused after opening the log when lines it acknowledged are gone from its end:
    /// no record could then be shown to continue the chain.
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
    ) -> Result<(Self, StreamAuthority, DurableOpening), StreamError> {
        let (stream, authority, opening, ()) = Self::open_durable_with(
            directory,
            id,
            owner,
            |_| Ok((spool, ())),
            anchor,
            clock,
            config,
            log,
        )?;
        Ok((stream, authority, opening))
    }

    /// Opens the durable stream as [`AuditStream::open_durable`] describes, with the spool
    /// that `spool` opens once the log is held; `spool` also returns what it found.
    #[allow(clippy::too_many_arguments)]
    fn open_durable_with<R>(
        directory: &mut StreamDirectory,
        id: JournalId,
        owner: ProducerId,
        spool: impl FnOnce(&DurableSegments) -> Result<(P, R), StreamError>,
        anchor: A,
        clock: C,
        config: StreamConfig,
        log: LogConfig,
    ) -> Result<(Self, StreamAuthority, DurableOpening, R), StreamError> {
        config.validate()?;
        check_retention(&config.segment, &log)?;
        let path = directory.stream_path(&id).ok_or(DurableError::NoRoot)?;
        if directory.is_live(&id) {
            return Err(StreamError::AuthorityLive { stream: id });
        }
        let (storage, found) = DurableSegments::open(&path, &id, owner.clone(), log)?;
        let (spool, spool_found) = spool(&storage)?;
        if found.fresh {
            let (stream, authority) =
                Self::open(directory, id, owner, storage, spool, anchor, clock, config)?;
            return Ok((stream, authority, found.into_opening(None), spool_found));
        }
        let (stream, authority, resumed) =
            Self::resume(directory, id, owner, storage, spool, anchor, clock, config)?;
        Ok((
            stream,
            authority,
            found.into_opening(Some(resumed)),
            spool_found,
        ))
    }

    /// Closes the stream as [`AuditStream::close`] does, then releases its durable log and
    /// returns how that went: the owner record then says its owner left cleanly and how
    /// far the stream was durable, or the result says why it could not be written. The log
    /// is released even when the seal could not be written. The journal and its spool are
    /// dropped before the log's lock is given up, so no next owner finds the spool open.
    ///
    /// Dropping a durable stream releases its log too, as far as it can, and stays the
    /// fallback; it cannot report a release record it failed to write, and the next owner
    /// then finds a stale owner ([`Takeover::Stale`]).
    ///
    /// [`Takeover::Stale`]: crate::foundation::events::Takeover::Stale
    pub fn release(mut self) -> StreamRelease {
        let close = self.close_in_place();
        let Self {
            journal, control, ..
        } = self;
        drop(journal);
        let release = match control.into_storage() {
            Ok(storage) => storage.release(),
            Err(control) => {
                drop(control);
                Err(DurableError::StillShared)
            }
        };
        StreamRelease { close, release }
    }
}

impl<A: HeadAnchor, C: Clock + Clone> AuditStream<DurableSegments, FileSpool, A, C> {
    /// Opens the durable stream `id` as [`AuditStream::open_durable`] does, with its spool
    /// on file in the stream's own directory ([`StreamDirectory::spool_path`]): records the
    /// journal accepted while the log refused them survive a restart, and the stream
    /// offers them to the log, in order, before any other record when it opens again. The
    /// spool holds at most `config.audit.spool_records` records and keeps the revocation
    /// reserve as an in-memory spool does ([`FileSpool`]). It is opened after the log,
    /// under the log's owner, so that owner is its only writer.
    ///
    /// Refused as [`AuditStream::open_durable`] refuses, when the spool's file is damaged
    /// anywhere but its last line ([`SpoolError::Damaged`]), and when it holds more records
    /// than `config.audit.spool_records` ([`SpoolError::OverBound`]: it was written under a
    /// larger bound, and opening it under this one would give revocations less than the
    /// reserve). A torn last line is quarantined and reported in the opening. A refused open
    /// releases the log again.
    pub fn open_durable_spooled(
        directory: &mut StreamDirectory,
        id: JournalId,
        owner: ProducerId,
        anchor: A,
        clock: C,
        config: StreamConfig,
        log: LogConfig,
    ) -> Result<(Self, StreamAuthority, SpooledOpening), StreamError> {
        let journal = id.clone();
        let (stream, authority, durable, spool) = Self::open_durable_with(
            directory,
            id,
            owner,
            |storage| {
                let path = storage.log().owner().directory().join(SPOOL_DIRECTORY);
                FileSpool::open(&path, &journal, &config.audit).map_err(StreamError::Spool)
            },
            anchor,
            clock,
            config,
            log,
        )?;
        Ok((stream, authority, SpooledOpening { durable, spool }))
    }
}

fn maintenance_context() -> Result<EventContext, IdError> {
    Ok(EventContext::new(
        OperationId::new(MAINTENANCE_OPERATION)?,
        Phase::Running,
    ))
}
