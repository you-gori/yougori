//! Segments of one audit stream: rotation that keeps linkage, a storage port, and the
//! detection of restarts and truncation when a stream resumes (VM-W42 "rotation" and
//! "restart/truncation ... tested" at line 2665; VM-P22 at line 2797; §8.2 line 2447).
//!
//! The CORE-06 journal chains records by digest. A [`SegmentedStore`] takes those records
//! as the journal's [`AuditStore`] and files them into segments: each segment starts with
//! a [`SegmentHeader`] that names the chain head it continues and the digest of the
//! previous header, and ends with a [`SegmentSeal`] that names the head and record count
//! it closed with. Rotation therefore never breaks the chain; [`verify_segments`] walks
//! headers, records and seals as one structure.
//!
//! When a stream resumes, the stored segments are verified first. A segment without a
//! seal was cut by a stop; a sealed segment whose records end before its seal was
//! truncated afterwards. Either is recorded in the header of the segment opened at
//! resume ([`SegmentOpening::Resume`]), and the stream records lost sequences in the
//! chain itself. A chain whose digests do not verify was rewritten; it is refused, never
//! continued.
//!
//! Storage with a retention bound of its own, such as the CORE-06 durable log behind
//! [`DurableSegments`](super::DurableSegments), may drop the oldest segments. It declares
//! that ([`SegmentStorage::retention`]), and only then may the stored segments start after
//! segment 0: the chain is verified from the first segment whose header is still held,
//! and the verified chain says where it starts ([`RetainedStart`]). Storage that declares
//! no retention must hold every segment from the first, so a missing first segment stays
//! damage.

use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use serde::{Deserialize, Serialize};

use super::anchor::{compare_retained_with_anchor, AnchorVerdict, AnchoredHead};
use crate::foundation::events::{
    verify_chain, AuditRecord, AuditStore, ChainError, ConfigError, EventSequence, JournalHead,
    JournalId, SequenceRange, StoreRefusal,
};
use crate::foundation::ids::{Digest, DigestBuilder};

const HEADER_DOMAIN: &str = "yougori/sandbox/audit/segment-header/v1";
const SEAL_DOMAIN: &str = "yougori/sandbox/audit/segment-seal/v1";

/// Bounds of the segments of one stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SegmentConfig {
    /// Records per segment before the store rotates; at least one.
    pub max_records_per_segment: u64,
}

impl SegmentConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.max_records_per_segment == 0 {
            return Err(ConfigError::Zero {
                setting: "max_records_per_segment",
            });
        }
        Ok(())
    }
}

/// Who showed that records were removed from the end of a sealed segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TruncationWitness {
    /// The segment's own seal names records that are not there.
    Seal,
    /// The anchored head is past the last stored record.
    Anchor,
}

strict_tagged_enum! {
    /// What the stream found in its stored segments when it resumed.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum ResumeFinding (tag = "kind", wire = ResumeFindingWire, wire_name = "ResumeFindingWire") {
        /// The last segment was sealed and complete: a clean stop.
        Sealed,
        /// The last segment had no seal: the stream stopped before sealing it, and its
        /// records were verified up to the last one found.
        Unsealed { records_found: u64 },
        /// Records after `intact_through` are gone although the seal or the anchor named
        /// them; the chain continues from `continued_from`, and the sequences between are
        /// recorded as lost.
        Truncated {
            intact_through: Option<EventSequence>,
            continued_from: EventSequence,
            witness: TruncationWitness,
        },
    }
}

strict_tagged_enum! {
    /// Why a segment was opened.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SegmentOpening (tag = "reason", wire = SegmentOpeningWire, wire_name = "SegmentOpeningWire") {
        /// The first segment of the stream.
        Genesis,
        /// The previous segment reached its bound or was rotated on request.
        Rotation,
        /// The stream resumed after a stop, with what it found.
        Resume { finding: ResumeFinding },
    }
}

/// The start of one segment: the chain head it continues and the header it follows.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SegmentHeader {
    stream: JournalId,
    index: u64,
    opened_from: JournalHead,
    opening: SegmentOpening,
    previous_header: Option<Digest>,
    digest: Digest,
}

impl SegmentHeader {
    fn new(
        stream: JournalId,
        index: u64,
        opened_from: JournalHead,
        opening: SegmentOpening,
        previous_header: Option<Digest>,
    ) -> Result<Self, serde_json::Error> {
        let digest = header_digest(&stream, index, &opened_from, &opening, previous_header)?;
        Ok(Self {
            stream,
            index,
            opened_from,
            opening,
            previous_header,
            digest,
        })
    }

    pub fn stream(&self) -> &JournalId {
        &self.stream
    }

    pub fn index(&self) -> u64 {
        self.index
    }

    /// The chain head this segment's first record follows.
    pub fn opened_from(&self) -> &JournalHead {
        &self.opened_from
    }

    pub fn opening(&self) -> SegmentOpening {
        self.opening
    }

    pub fn previous_header(&self) -> Option<Digest> {
        self.previous_header
    }

    pub fn digest(&self) -> Digest {
        self.digest
    }

    fn recompute(&self) -> Result<Digest, serde_json::Error> {
        header_digest(
            &self.stream,
            self.index,
            &self.opened_from,
            &self.opening,
            self.previous_header,
        )
    }
}

fn header_digest(
    stream: &JournalId,
    index: u64,
    opened_from: &JournalHead,
    opening: &SegmentOpening,
    previous_header: Option<Digest>,
) -> Result<Digest, serde_json::Error> {
    let previous = previous_header.map_or_else(Vec::new, |digest| digest.as_bytes().to_vec());
    Ok(DigestBuilder::new(HEADER_DOMAIN)
        .str(stream.as_str())
        .u64(index)
        .bytes(&serde_json::to_vec(opened_from)?)
        .bytes(&serde_json::to_vec(opening)?)
        .bytes(&previous)
        .finish())
}

/// The close of one segment: the head and record count it ended with.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SegmentSeal {
    index: u64,
    header: Digest,
    head: JournalHead,
    records: u64,
    digest: Digest,
}

impl SegmentSeal {
    fn new(
        header: &SegmentHeader,
        head: &JournalHead,
        records: u64,
    ) -> Result<Self, serde_json::Error> {
        let digest = seal_digest(header.digest, head, records)?;
        Ok(Self {
            index: header.index,
            header: header.digest,
            head: head.clone(),
            records,
            digest,
        })
    }

    pub fn index(&self) -> u64 {
        self.index
    }

    pub fn header(&self) -> Digest {
        self.header
    }

    /// The chain head the segment ended with.
    pub fn head(&self) -> &JournalHead {
        &self.head
    }

    pub fn records(&self) -> u64 {
        self.records
    }

    pub fn digest(&self) -> Digest {
        self.digest
    }

    fn recompute(&self) -> Result<Digest, serde_json::Error> {
        seal_digest(self.header, &self.head, self.records)
    }
}

fn seal_digest(
    header: Digest,
    head: &JournalHead,
    records: u64,
) -> Result<Digest, serde_json::Error> {
    Ok(DigestBuilder::new(SEAL_DOMAIN)
        .digest(&header)
        .bytes(&serde_json::to_vec(head)?)
        .u64(records)
        .finish())
}

/// One segment as storage holds it: its header, the records found and the seal, if any.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredSegment {
    pub header: SegmentHeader,
    pub records: Vec<AuditRecord>,
    pub seal: Option<SegmentSeal>,
}

/// Durable storage of one stream's segments: the port a storage adapter implements.
/// Writes are durable on `Ok`. A refusal may be unclear (a write that landed after its
/// deadline), so writing the same header, record or seal again is `Ok` and stores
/// nothing; the store retries exactly what it offered and never different content under
/// the same index or sequence.
pub trait SegmentStorage {
    /// Starts segment `header.index()` after every segment stored before it.
    fn begin_segment(&mut self, header: &SegmentHeader) -> Result<(), StoreRefusal>;

    /// Appends `record` to the open segment, after every record stored before it.
    fn append(&mut self, record: &AuditRecord) -> Result<(), StoreRefusal>;

    /// Closes the open segment with `seal`.
    fn seal_segment(&mut self, seal: &SegmentSeal) -> Result<(), StoreRefusal>;

    /// Every stored segment in index order, as found, damaged or not.
    fn segments(&self) -> Result<Vec<StoredSegment>, StoreRefusal>;

    /// The stored record with `sequence`, if any.
    fn record(&self, sequence: EventSequence) -> Result<Option<AuditRecord>, StoreRefusal>;

    /// What a retention bound of storage's own dropped from the start of the stream, if
    /// anything. Only then may [`SegmentStorage::segments`] start after segment 0. Storage
    /// that keeps every segment answers `None`, which is the default.
    fn retention(&self) -> Result<Option<SegmentRetention>, StoreRefusal> {
        Ok(None)
    }
}

/// What storage dropped from the start of a stream under its retention bound, as storage
/// counts it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct SegmentRetention {
    /// Entries dropped over the stream's life: headers, records and seals, and whatever
    /// else storage keeps among them.
    pub dropped_entries: u64,
    pub dropped_bytes: u64,
    /// Lines still held of a segment whose header was dropped: they cannot be verified
    /// from a header, so they count as dropped too.
    pub headless_entries: u64,
}

/// Where a chain verified after retention starts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RetainedStart {
    /// The first segment storage still holds from its header on.
    pub segment: u64,
    /// The chain head that segment continues; the records up to it were dropped.
    pub after: JournalHead,
    /// What storage says it dropped.
    pub retention: SegmentRetention,
}

strict_tagged_enum! {
    /// Damage [`verify_segments`] found and the stream acknowledged; a chain with any of
    /// these still verifies, with the damage in view.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Damage (tag = "kind", wire = DamageWire, wire_name = "DamageWire") {
        /// Records after `intact_through` of `segment` are gone although its seal or the
        /// anchored head named them; the chain continued from `continued_from`.
        TailTruncated {
            segment: u64,
            intact_through: Option<EventSequence>,
            continued_from: EventSequence,
            witness: TruncationWitness,
        },
        /// `segment` was never sealed: the stream stopped, and the next segment
        /// continued from its last verified record.
        Unsealed { segment: u64, records_found: u64 },
    }
}

/// What verifying a stream's segments established.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct VerifiedChain {
    /// The verified end of the last segment's records.
    pub head: JournalHead,
    /// Where the chain continues: the last seal's head when the tail was truncated after
    /// sealing, otherwise [`VerifiedChain::head`].
    pub continues_from: JournalHead,
    pub segments: u64,
    pub records: u64,
    pub last_sealed: bool,
    pub last_records: u64,
    pub damage: Vec<Damage>,
    /// Where the chain starts when storage's retention dropped the segments before it;
    /// `None` when it was verified from genesis.
    pub retained_from: Option<RetainedStart>,
}

/// Why segments do not form one stream, or why the store could not open or resume.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SegmentError {
    Config(ConfigError),
    Storage(StoreRefusal),
    Encoding {
        message: String,
    },
    /// Storage already holds segments; resume instead of opening.
    NotEmpty,
    /// Storage holds no segment; open instead of resuming.
    Empty,
    WrongStream {
        segment: u64,
    },
    /// Segments are numbered without gaps from zero.
    MissingSegment {
        expected: u64,
        found: u64,
    },
    /// A header's content does not match its digest.
    HeaderDigest {
        segment: u64,
    },
    /// A header does not name the previous header's digest.
    HeaderChainBroken {
        segment: u64,
    },
    /// A header does not continue where the previous segment ended, and does not
    /// declare a truncation or an unsealed stop that explains the difference.
    DoesNotContinue {
        segment: u64,
    },
    /// The records of a segment do not continue the chain from its header.
    Chain {
        segment: u64,
        error: ChainError,
    },
    /// A seal's content does not match its digest or its header.
    SealDigest {
        segment: u64,
    },
    /// A seal names a head the records contradict: fewer records than found, or another
    /// digest for the same last record.
    SealMismatch {
        segment: u64,
    },
    /// A segment before the last one has no seal.
    MissingSeal {
        segment: u64,
    },
    /// The anchored head shows the stored chain was rewritten; it cannot be continued.
    Rewritten {
        anchored: EventSequence,
    },
    /// The store was closed; nothing is appended after the final seal.
    Closed,
}

impl fmt::Display for SegmentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(error) => write!(f, "{error}"),
            Self::Storage(refusal) => write!(f, "segment storage refused: {refusal}"),
            Self::Encoding { message } => write!(f, "a segment could not be encoded: {message}"),
            Self::NotEmpty => f.write_str("storage already holds segments; resume the stream"),
            Self::Empty => f.write_str("storage holds no segment; open the stream"),
            Self::WrongStream { segment } => {
                write!(f, "segment {segment} belongs to another stream")
            }
            Self::MissingSegment { expected, found } => {
                write!(f, "expected segment {expected}, found segment {found}")
            }
            Self::HeaderDigest { segment } => {
                write!(
                    f,
                    "the header of segment {segment} does not match its digest"
                )
            }
            Self::HeaderChainBroken { segment } => write!(
                f,
                "the header of segment {segment} does not name the previous header"
            ),
            Self::DoesNotContinue { segment } => write!(
                f,
                "segment {segment} does not continue where the previous segment ended"
            ),
            Self::Chain { segment, error } => {
                write!(f, "the records of segment {segment} do not verify: {error}")
            }
            Self::SealDigest { segment } => {
                write!(f, "the seal of segment {segment} does not match its digest")
            }
            Self::SealMismatch { segment } => write!(
                f,
                "the seal of segment {segment} contradicts the records found"
            ),
            Self::MissingSeal { segment } => {
                write!(f, "segment {segment} is not the last one and has no seal")
            }
            Self::Rewritten { anchored } => write!(
                f,
                "the stored chain differs from the anchored head at record {anchored}: it was \
                 rewritten and cannot be continued"
            ),
            Self::Closed => f.write_str("the segment store is closed"),
        }
    }
}

impl std::error::Error for SegmentError {}

impl From<serde_json::Error> for SegmentError {
    fn from(error: serde_json::Error) -> Self {
        Self::Encoding {
            message: error.to_string(),
        }
    }
}

/// What resuming established, for the stream to record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ResumeReport {
    pub finding: ResumeFinding,
    /// Where the chain continues.
    pub head: JournalHead,
    /// Sequences that were durable once and are gone now.
    pub lost: Option<SequenceRange>,
    pub chain: VerifiedChain,
    pub anchor: AnchorVerdict,
}

/// Counts of what the store did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct SegmentTotals {
    pub records: u64,
    pub duplicates: u64,
    /// Offers that did not continue the stored chain, refused and never stored.
    pub out_of_order: u64,
    pub rotations: u64,
    pub storage_refusals: u64,
}

struct SegmentState<S> {
    storage: S,
    stream: JournalId,
    config: SegmentConfig,
    current: SegmentHeader,
    /// False between a seal that succeeded and the next header that storage took.
    segment_open: bool,
    current_records: u64,
    head: JournalHead,
    closed: bool,
    totals: SegmentTotals,
}

/// The journal's storage: records go in only through [`AuditStore::append`], which the
/// journal calls with its one authority. Rotation happens here at the record bound; the
/// paired [`SegmentControl`] rotates, seals and reads, and can append nothing.
#[derive(Debug)]
pub struct SegmentedStore<S> {
    state: Arc<Mutex<SegmentState<S>>>,
}

/// The handle that rotates, closes and inspects a [`SegmentedStore`] without being able
/// to append to it.
#[derive(Debug)]
pub struct SegmentControl<S> {
    state: Arc<Mutex<SegmentState<S>>>,
}

impl<S> fmt::Debug for SegmentState<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SegmentState")
            .field("stream", &self.stream)
            .field("segment", &self.current.index)
            .field("head", &self.head)
            .field("closed", &self.closed)
            .finish()
    }
}

fn lock<S>(state: &Mutex<SegmentState<S>>) -> MutexGuard<'_, SegmentState<S>> {
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

impl<S: SegmentStorage> SegmentedStore<S> {
    /// Opens a new stream on empty storage, starting segment 0 from `genesis`. Storage
    /// that holds segments, or dropped some under its retention bound, is not empty.
    pub fn open(
        mut storage: S,
        genesis: JournalHead,
        config: SegmentConfig,
    ) -> Result<(Self, SegmentControl<S>), SegmentError> {
        config.validate().map_err(SegmentError::Config)?;
        if !storage
            .segments()
            .map_err(SegmentError::Storage)?
            .is_empty()
            || storage
                .retention()
                .map_err(SegmentError::Storage)?
                .is_some()
        {
            return Err(SegmentError::NotEmpty);
        }
        let header = SegmentHeader::new(
            genesis.journal.clone(),
            0,
            genesis.clone(),
            SegmentOpening::Genesis,
            None,
        )?;
        storage
            .begin_segment(&header)
            .map_err(SegmentError::Storage)?;
        Ok(Self::pair(SegmentState {
            storage,
            stream: genesis.journal.clone(),
            config,
            current: header,
            segment_open: true,
            current_records: 0,
            head: genesis,
            closed: false,
            totals: SegmentTotals::default(),
        }))
    }

    /// Resumes a stream from the segments storage holds: verifies them, from the first
    /// one retention left when storage declares retention, compares them with `anchored`,
    /// and opens the next segment with what it found. A chain that was rewritten is
    /// refused.
    pub fn resume(
        mut storage: S,
        genesis: JournalHead,
        config: SegmentConfig,
        anchored: Option<&AnchoredHead>,
    ) -> Result<(Self, SegmentControl<S>, ResumeReport), SegmentError> {
        config.validate().map_err(SegmentError::Config)?;
        let segments = storage.segments().map_err(SegmentError::Storage)?;
        if segments.is_empty() {
            return Err(SegmentError::Empty);
        }
        let retention = storage.retention().map_err(SegmentError::Storage)?;
        let chain = verify_retained_segments(&genesis, retention, &segments)?;
        let retained_after = chain.retained_from.as_ref().map(|start| &start.after);
        let verdict =
            compare_retained_with_anchor(&genesis.journal, &segments, retained_after, anchored);
        let anchored_beyond = match (verdict, anchored) {
            (AnchorVerdict::Rewritten { anchored }, _) => {
                return Err(SegmentError::Rewritten { anchored })
            }
            (AnchorVerdict::Truncated { .. }, Some(anchored))
                if anchored.head().last > chain.continues_from.last =>
            {
                Some(anchored.head().clone())
            }
            _ => None,
        };
        let (finding, head) = match anchored_beyond {
            Some(head) => (
                ResumeFinding::Truncated {
                    intact_through: chain.head.last,
                    continued_from: head.last.unwrap_or(EventSequence::FIRST),
                    witness: TruncationWitness::Anchor,
                },
                head,
            ),
            None if chain.continues_from.last > chain.head.last => (
                ResumeFinding::Truncated {
                    intact_through: chain.head.last,
                    continued_from: chain.continues_from.last.unwrap_or(EventSequence::FIRST),
                    witness: TruncationWitness::Seal,
                },
                chain.continues_from.clone(),
            ),
            None if !chain.last_sealed => (
                ResumeFinding::Unsealed {
                    records_found: chain.last_records,
                },
                chain.head.clone(),
            ),
            None => (ResumeFinding::Sealed, chain.head.clone()),
        };
        let lost = lost_range(chain.head.last, head.last);
        // After the last stored segment, which is not the count of segments once
        // retention dropped some.
        let index = segments
            .last()
            .map_or(0, |segment| segment.header.index.saturating_add(1));
        let previous_header = segments.last().map(|segment| segment.header.digest);
        let header = SegmentHeader::new(
            genesis.journal.clone(),
            index,
            head.clone(),
            SegmentOpening::Resume { finding },
            previous_header,
        )?;
        storage
            .begin_segment(&header)
            .map_err(SegmentError::Storage)?;
        let report = ResumeReport {
            finding,
            head: head.clone(),
            lost,
            chain,
            anchor: verdict,
        };
        let (store, control) = Self::pair(SegmentState {
            storage,
            stream: genesis.journal,
            config,
            current: header,
            segment_open: true,
            current_records: 0,
            head,
            closed: false,
            totals: SegmentTotals::default(),
        });
        Ok((store, control, report))
    }

    fn pair(state: SegmentState<S>) -> (Self, SegmentControl<S>) {
        let state = Arc::new(Mutex::new(state));
        (
            Self {
                state: Arc::clone(&state),
            },
            SegmentControl { state },
        )
    }
}

/// The sequences after `intact_through` up to `continued_from`, when any.
fn lost_range(
    intact_through: Option<EventSequence>,
    continued_from: Option<EventSequence>,
) -> Option<SequenceRange> {
    let last = continued_from?;
    let first = match intact_through {
        None => EventSequence::FIRST,
        Some(through) if through < last => through.next()?,
        Some(_) => return None,
    };
    SequenceRange::new(first, last)
}

impl<S: SegmentStorage> SegmentState<S> {
    fn append(&mut self, record: &AuditRecord) -> Result<(), StoreRefusal> {
        if self.closed {
            self.totals.storage_refusals = self.totals.storage_refusals.saturating_add(1);
            return Err(StoreRefusal::Failed);
        }
        if record.journal() != &self.stream {
            return self.refuse_out_of_order();
        }
        if let Some(last) = self.head.last {
            if record.sequence() <= last {
                let stored = self.storage.record(record.sequence()).map_err(|refusal| {
                    self.totals.storage_refusals = self.totals.storage_refusals.saturating_add(1);
                    refusal
                })?;
                return if stored.as_ref() == Some(record) {
                    self.totals.duplicates = self.totals.duplicates.saturating_add(1);
                    Ok(())
                } else {
                    self.refuse_out_of_order()
                };
            }
        }
        let expected = self
            .head
            .last
            .map_or(Some(EventSequence::FIRST), EventSequence::next);
        if expected != Some(record.sequence()) || record.previous() != self.head.digest {
            return self.refuse_out_of_order();
        }
        if self.segment_open && self.current_records >= self.config.max_records_per_segment {
            self.seal_current()?;
        }
        if !self.segment_open {
            self.begin_next(SegmentOpening::Rotation)?;
        }
        if let Err(refusal) = self.storage.append(record) {
            self.totals.storage_refusals = self.totals.storage_refusals.saturating_add(1);
            return Err(refusal);
        }
        self.current_records = self.current_records.saturating_add(1);
        self.head = JournalHead {
            journal: self.stream.clone(),
            owner: self.head.owner.clone(),
            last: Some(record.sequence()),
            digest: record.digest(),
        };
        self.totals.records = self.totals.records.saturating_add(1);
        Ok(())
    }

    fn refuse_out_of_order(&mut self) -> Result<(), StoreRefusal> {
        self.totals.out_of_order = self.totals.out_of_order.saturating_add(1);
        Err(StoreRefusal::Failed)
    }

    /// Seals the open segment; afterwards no segment is open until the next header.
    fn seal_current(&mut self) -> Result<SegmentSeal, StoreRefusal> {
        let seal = SegmentSeal::new(&self.current, &self.head, self.current_records)
            .map_err(|_| StoreRefusal::Failed)?;
        if let Err(refusal) = self.storage.seal_segment(&seal) {
            self.totals.storage_refusals = self.totals.storage_refusals.saturating_add(1);
            return Err(refusal);
        }
        self.segment_open = false;
        Ok(seal)
    }

    fn begin_next(&mut self, opening: SegmentOpening) -> Result<(), StoreRefusal> {
        let header = SegmentHeader::new(
            self.stream.clone(),
            self.current.index.saturating_add(1),
            self.head.clone(),
            opening,
            Some(self.current.digest),
        )
        .map_err(|_| StoreRefusal::Failed)?;
        if let Err(refusal) = self.storage.begin_segment(&header) {
            self.totals.storage_refusals = self.totals.storage_refusals.saturating_add(1);
            return Err(refusal);
        }
        self.current = header;
        self.current_records = 0;
        self.segment_open = true;
        self.totals.rotations = self.totals.rotations.saturating_add(1);
        Ok(())
    }

    /// Seals the open segment and begins the next; nothing happens to an empty one.
    fn rotate(&mut self) -> Result<Option<SegmentSeal>, StoreRefusal> {
        if self.closed {
            return Err(StoreRefusal::Failed);
        }
        if !self.segment_open {
            self.begin_next(SegmentOpening::Rotation)?;
            return Ok(None);
        }
        if self.current_records == 0 {
            return Ok(None);
        }
        let seal = self.seal_current()?;
        self.begin_next(SegmentOpening::Rotation)?;
        Ok(Some(seal))
    }

    /// Seals the open segment, empty or not, and closes the store.
    fn close(&mut self) -> Result<SegmentSeal, StoreRefusal> {
        if self.closed {
            return Err(StoreRefusal::Failed);
        }
        if !self.segment_open {
            self.begin_next(SegmentOpening::Rotation)?;
        }
        let seal = self.seal_current()?;
        self.closed = true;
        Ok(seal)
    }
}

impl<S: SegmentStorage> AuditStore for SegmentedStore<S> {
    fn append(&mut self, record: &AuditRecord) -> Result<(), StoreRefusal> {
        lock(&self.state).append(record)
    }
}

impl<S: SegmentStorage> SegmentControl<S> {
    /// Seals the open segment and starts the next one; `None` when the segment was
    /// empty. Spooled records are not stored yet and are not part of the seal.
    pub fn rotate(&self) -> Result<Option<SegmentSeal>, StoreRefusal> {
        lock(&self.state).rotate()
    }

    /// Seals the open segment and closes the store; nothing is appended afterwards.
    pub fn close(&self) -> Result<SegmentSeal, StoreRefusal> {
        lock(&self.state).close()
    }

    /// The last durable record's head.
    pub fn head(&self) -> JournalHead {
        lock(&self.state).head.clone()
    }

    pub fn current_segment(&self) -> SegmentHeader {
        lock(&self.state).current.clone()
    }

    pub fn is_closed(&self) -> bool {
        lock(&self.state).closed
    }

    pub fn totals(&self) -> SegmentTotals {
        lock(&self.state).totals
    }

    /// Reads storage; it is never lent mutably.
    pub fn with_storage<R>(&self, read: impl FnOnce(&S) -> R) -> R {
        read(&lock(&self.state).storage)
    }

    /// Takes storage back once its store is gone, to release it; `Err(self)` while the
    /// store still holds it.
    pub(super) fn into_storage(self) -> Result<S, Self> {
        match Arc::try_unwrap(self.state) {
            Ok(state) => Ok(state
                .into_inner()
                .unwrap_or_else(PoisonError::into_inner)
                .storage),
            Err(state) => Err(Self { state }),
        }
    }
}

/// The verified end of one segment, for the continuity check of the next.
struct SegmentEnd {
    verified: JournalHead,
    seal: Option<SegmentSeal>,
    records: u64,
}

/// Checks that `segments` are one stream from `genesis`: headers numbered from zero and
/// digest-chained, each continuing where the previous one ended (or declaring the
/// truncation or unsealed stop that explains why not), records continuing the chain
/// from each header, and seals matching the records. Returns the chain's verified end and
/// the damage declared along the way.
pub fn verify_segments(
    genesis: &JournalHead,
    segments: &[StoredSegment],
) -> Result<VerifiedChain, SegmentError> {
    verify_retained_segments(genesis, None, segments)
}

/// [`verify_segments`] for storage that declares `retention`: the first segment may then
/// be any later one, whose header names a previous header that is gone and continues a
/// head of the stream's own journal and owner. Everything after it is checked as
/// [`verify_segments`] checks it, and the result says where the chain starts. Without
/// `retention`, or when the first segment held is segment 0, it is [`verify_segments`].
pub fn verify_retained_segments(
    genesis: &JournalHead,
    retention: Option<SegmentRetention>,
    segments: &[StoredSegment],
) -> Result<VerifiedChain, SegmentError> {
    let first_index = match (retention, segments.first()) {
        (Some(_), Some(first)) => first.header.index,
        _ => 0,
    };
    let mut retained_from = None;
    let mut previous_header = None;
    let mut previous_end: Option<SegmentEnd> = None;
    let mut damage = Vec::new();
    let mut records_total = 0u64;
    let mut head = genesis.clone();
    let mut continues_from = genesis.clone();
    let mut last_sealed = true;
    let mut last_records = 0u64;
    let count = segments.len();
    for (position, segment) in segments.iter().enumerate() {
        let index = first_index.saturating_add(u64::try_from(position).unwrap_or(u64::MAX));
        let header = &segment.header;
        if header.stream != genesis.journal {
            return Err(SegmentError::WrongStream { segment: index });
        }
        if header.index != index {
            return Err(SegmentError::MissingSegment {
                expected: index,
                found: header.index,
            });
        }
        if header.recompute()? != header.digest {
            return Err(SegmentError::HeaderDigest { segment: index });
        }
        // The first segment retention left names a previous header that is gone: one
        // must be named, but it cannot be checked.
        let retained_start = previous_end.is_none() && index > 0;
        let linked = if retained_start {
            header.previous_header.is_some() && header.opening != SegmentOpening::Genesis
        } else {
            header.previous_header == previous_header
        };
        if !linked {
            return Err(SegmentError::HeaderChainBroken { segment: index });
        }
        if header.opened_from.journal != genesis.journal
            || header.opened_from.owner != genesis.owner
        {
            return Err(SegmentError::DoesNotContinue { segment: index });
        }
        match &previous_end {
            None if retained_start => {
                if let Some(retention) = retention {
                    retained_from = Some(RetainedStart {
                        segment: index,
                        after: header.opened_from.clone(),
                        retention,
                    });
                }
            }
            None => {
                if header.opened_from != *genesis || header.opening != SegmentOpening::Genesis {
                    return Err(SegmentError::DoesNotContinue { segment: index });
                }
            }
            Some(previous) => {
                let declared = continuity(header, previous, index)
                    .ok_or(SegmentError::DoesNotContinue { segment: index })?;
                damage.extend(declared);
            }
        }
        let verified = verify_chain(&header.opened_from, &segment.records).map_err(|error| {
            SegmentError::Chain {
                segment: index,
                error,
            }
        })?;
        let records = u64::try_from(segment.records.len()).unwrap_or(u64::MAX);
        let mut segment_continues_from = verified.clone();
        match &segment.seal {
            Some(seal) => {
                if seal.recompute()? != seal.digest
                    || seal.index != index
                    || seal.header != header.digest
                {
                    return Err(SegmentError::SealDigest { segment: index });
                }
                if seal.head == verified && seal.records == records {
                    // A complete segment.
                } else if seal.head.last > verified.last && seal.records > records {
                    damage.push(Damage::TailTruncated {
                        segment: index,
                        intact_through: verified.last,
                        continued_from: seal.head.last.unwrap_or(EventSequence::FIRST),
                        witness: TruncationWitness::Seal,
                    });
                    segment_continues_from = seal.head.clone();
                } else {
                    return Err(SegmentError::SealMismatch { segment: index });
                }
            }
            None => {
                // A segment a stop left unsealed is acceptable only when the next header
                // says so; the continuity check of that header verifies the details.
                let declared_by_next = segments.get(position + 1).is_some_and(|next| {
                    matches!(
                        next.header.opening,
                        SegmentOpening::Resume {
                            finding: ResumeFinding::Unsealed { .. }
                        }
                    )
                });
                if position + 1 < count && !declared_by_next {
                    return Err(SegmentError::MissingSeal { segment: index });
                }
            }
        }
        records_total = records_total.saturating_add(records);
        last_sealed = segment.seal.is_some();
        last_records = records;
        head = verified.clone();
        continues_from = segment_continues_from;
        previous_header = Some(header.digest);
        previous_end = Some(SegmentEnd {
            verified,
            seal: segment.seal.clone(),
            records,
        });
    }
    Ok(VerifiedChain {
        head,
        continues_from,
        segments: u64::try_from(count).unwrap_or(u64::MAX),
        records: records_total,
        last_sealed,
        last_records,
        damage,
        retained_from,
    })
}

/// Whether `header` continues `previous` as its opening declares; the damage the
/// declaration acknowledges, or `None` when the declaration does not fit.
fn continuity(header: &SegmentHeader, previous: &SegmentEnd, index: u64) -> Option<Vec<Damage>> {
    // A sealed segment may lose records later; the seal check records that damage, and
    // the next segment still continues from the sealed head.
    let sealed_at = previous.seal.as_ref().map(|seal| &seal.head);
    match header.opening {
        SegmentOpening::Genesis => None,
        SegmentOpening::Rotation
        | SegmentOpening::Resume {
            finding: ResumeFinding::Sealed,
        } => (sealed_at == Some(&header.opened_from)).then(Vec::new),
        SegmentOpening::Resume {
            finding: ResumeFinding::Unsealed { records_found },
        } => (previous.seal.is_none()
            && records_found == previous.records
            && header.opened_from == previous.verified)
            .then(|| {
                vec![Damage::Unsealed {
                    segment: index.saturating_sub(1),
                    records_found,
                }]
            }),
        SegmentOpening::Resume {
            finding:
                ResumeFinding::Truncated {
                    intact_through,
                    continued_from,
                    witness,
                },
        } => {
            let declared = intact_through == previous.verified.last
                && header.opened_from.last == Some(continued_from)
                && header.opened_from.last > previous.verified.last;
            if !declared {
                return None;
            }
            match witness {
                // The seal check already recorded this damage.
                TruncationWitness::Seal => previous
                    .seal
                    .as_ref()
                    .is_some_and(|seal| seal.head == header.opened_from)
                    .then(Vec::new),
                TruncationWitness::Anchor => {
                    // The anchor cannot be checked here; a seal that knows more than the
                    // anchor would have been the witness instead.
                    let seal_agrees = match &previous.seal {
                        None => true,
                        Some(seal) if seal.head == previous.verified => true,
                        Some(seal) => seal.head == header.opened_from,
                    };
                    seal_agrees.then(|| {
                        vec![Damage::TailTruncated {
                            segment: index.saturating_sub(1),
                            intact_through,
                            continued_from,
                            witness,
                        }]
                    })
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::events::ProducerId;
    use crate::foundation::ids::digest;

    fn genesis() -> JournalHead {
        JournalHead::genesis(
            JournalId::new("engine").unwrap(),
            ProducerId::new("engine.audit").unwrap(),
        )
    }

    fn head(last: u64) -> JournalHead {
        JournalHead {
            last: EventSequence::new(last),
            digest: digest("yougori/test/head/v1", &[&last.to_be_bytes()]),
            ..genesis()
        }
    }

    #[test]
    fn headers_and_seals_are_digested_and_refuse_unknown_fields() {
        let header = SegmentHeader::new(
            genesis().journal,
            0,
            genesis(),
            SegmentOpening::Genesis,
            None,
        )
        .unwrap();
        assert_eq!(header.recompute().unwrap(), header.digest());
        assert_eq!(header.index(), 0);
        assert_eq!(header.opening(), SegmentOpening::Genesis);
        assert_eq!(header.previous_header(), None);
        let json = serde_json::to_value(&header).unwrap();
        assert_eq!(json["opening"]["reason"], "genesis");
        assert_eq!(
            serde_json::from_value::<SegmentHeader>(json.clone()).unwrap(),
            header
        );
        let mut extra = json;
        extra["note"] = serde_json::json!("x");
        assert!(serde_json::from_value::<SegmentHeader>(extra).is_err());

        let seal = SegmentSeal::new(&header, &head(3), 3).unwrap();
        assert_eq!(seal.recompute().unwrap(), seal.digest());
        assert_eq!((seal.index(), seal.records()), (0, 3));
        assert_eq!(seal.header(), header.digest());
        assert_eq!(seal.head(), &head(3));
        let other = SegmentSeal::new(&header, &head(3), 4).unwrap();
        assert_ne!(seal.digest(), other.digest());
        let rotation = SegmentHeader::new(
            genesis().journal,
            1,
            head(3),
            SegmentOpening::Rotation,
            Some(header.digest()),
        )
        .unwrap();
        assert_ne!(rotation.digest(), header.digest());
        assert!(
            serde_json::from_str::<SegmentOpening>(r#"{"reason":"rotation","extra":1}"#).is_err()
        );
        assert!(serde_json::from_str::<ResumeFinding>(r#"{"kind":"sealed"}"#).is_ok());
    }

    #[test]
    fn lost_ranges_cover_exactly_the_missing_sequences() {
        let at = |value: u64| EventSequence::new(value).unwrap();
        assert_eq!(
            lost_range(Some(at(3)), Some(at(5))),
            SequenceRange::new(at(4), at(5))
        );
        assert_eq!(
            lost_range(None, Some(at(2))),
            SequenceRange::new(at(1), at(2))
        );
        assert_eq!(lost_range(Some(at(3)), Some(at(3))), None);
        assert_eq!(lost_range(Some(at(4)), Some(at(3))), None);
        assert_eq!(lost_range(None, None), None);
    }

    #[test]
    fn configuration_is_checked() {
        assert_eq!(
            SegmentConfig {
                max_records_per_segment: 0
            }
            .validate(),
            Err(ConfigError::Zero {
                setting: "max_records_per_segment"
            })
        );
        assert!(SegmentError::Config(ConfigError::Zero { setting: "x" })
            .to_string()
            .contains("at least one"));
        for error in [
            SegmentError::NotEmpty,
            SegmentError::Empty,
            SegmentError::WrongStream { segment: 1 },
            SegmentError::MissingSegment {
                expected: 1,
                found: 2,
            },
            SegmentError::HeaderDigest { segment: 1 },
            SegmentError::HeaderChainBroken { segment: 1 },
            SegmentError::DoesNotContinue { segment: 1 },
            SegmentError::SealDigest { segment: 1 },
            SegmentError::SealMismatch { segment: 1 },
            SegmentError::MissingSeal { segment: 1 },
            SegmentError::Rewritten {
                anchored: EventSequence::FIRST,
            },
            SegmentError::Closed,
            SegmentError::Storage(StoreRefusal::Full),
        ] {
            assert!(!error.to_string().is_empty());
        }
    }
}
