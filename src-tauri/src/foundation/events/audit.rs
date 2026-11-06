//! The durable security audit stream (CORE-06; INT-10; VM part §8.2 "detection and
//! audit"; §16.3 "metrics producers use the common envelope without sharing its append
//! authority").
//!
//! An [`AuditJournal`] is one actor's append-only hash chain with a single sequence: the
//! engine and the warden each keep their own journal and link them explicitly, so no two
//! writers ever append to one chain, and [`verify_chain`] refuses a chain that has a
//! second writer. Appending needs the [`AuditAppendAuthority`] the journal issued when it
//! was opened; it is not `Clone`, `Default` or deserializable, and no producer handle
//! converts into it. The journal lends its storage to nobody, so a record reaches storage
//! only through an append with that authority. Records reach storage strictly in sequence
//! order. When storage is slow or full they wait in a bounded [`AuditSpool`], a port the
//! storage adapter implements on durable local storage; a record counts as accepted only
//! once the spool holds it, and [`AuditJournal::resume`] continues after the last spooled
//! record, so a crash neither loses an accepted record nor reuses its sequence. Once the
//! spool is full or refuses, appends fail closed: the record is refused, visibly, and its
//! operation must not proceed. The [`AuditFailurePolicy`] says whether a high-impact
//! operation may go ahead on a spooled record. A reserve in the spool keeps room for
//! revocation records, and the revocation lane itself never waits on this journal.
//!
//! Storage may hold a record it refused (an unclear refusal, such as a write that lands
//! after its deadline), so a record storage saw keeps its sequence even when it is refused:
//! the journal offers exactly that record again before any other, to storage or, when the
//! next record has to follow it, to the spool, and never offers different content under
//! its sequence. Such a kept record can join the chain although its operation was denied:
//! a record in the chain is not a permission, only an [`AuditReceipt`] is.
//!
//! The chain makes an edited, removed or reordered record detectable against a trusted
//! head. It is not WORM storage: whoever can rewrite the whole chain can forge it, and
//! signing or anchoring heads elsewhere is left to the storage adapter (§8.2).

use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::envelope::{
    ConfigError, EmitError, EventContext, EventEnvelope, EventSequence, ProducerCore, ProducerId,
    ProducerIncarnation, StreamKind,
};
use super::reconcile::LostRange;
use super::redaction::{EmissionLimit, Field, RateLimiter, RedactedFields, RedactionPolicy};
use super::revocation::{GrantRevocation, Revocation};
use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::{digest, Clock, Digest, DigestBuilder, MonotonicTime};

const RECORD_DOMAIN: &str = "yougori/events/audit-record/v1";
const GENESIS_DOMAIN: &str = "yougori/events/audit-genesis/v1";

name_type!(
    /// One actor's audit journal, such as `engine` or `warden` (VM part §8.2: separate
    /// actor journals with explicit linkage).
    JournalId
);

/// A fact the host decided or observed itself, kept outside the guest (VM part §8.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostFact {
    AuthorizationDecision,
    Budget,
    Lease,
    LaunchFact,
    TerminationReceipt,
    HighImpactOperation,
    /// An external effect the host dispatched or settled for a sandbox (VM part §9.2).
    ExternalEffect,
    /// A detection signal the host observed, such as an internal canary hit (VM-W10): a
    /// signal, never proof of a compromise.
    DetectionSignal,
}

/// The last record of a journal and the one producer that appends to it: what a resumed
/// journal continues, what [`verify_chain`] starts from and what another journal links to.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalHead {
    pub journal: JournalId,
    pub owner: ProducerId,
    /// `None` for an empty journal.
    pub last: Option<EventSequence>,
    pub digest: Digest,
}

impl JournalHead {
    /// The head of an empty journal; its digest binds the chain to the journal and its
    /// owner.
    pub fn genesis(journal: JournalId, owner: ProducerId) -> Self {
        let digest = digest(
            GENESIS_DOMAIN,
            &[journal.as_str().as_bytes(), owner.as_str().as_bytes()],
        );
        Self {
            journal,
            owner,
            last: None,
            digest,
        }
    }
}

strict_tagged_enum! {
    /// What one audit record says.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum AuditEntry (tag = "kind", wire = AuditEntryWire, wire_name = "AuditEntryWire") {
        /// Labelled a host observation.
        HostFact { fact: HostFact, fields: RedactedFields },
        /// What a guest reported: an untrusted observation, labelled a guest report.
        GuestObservation { fields: RedactedFields },
        /// A revocation, as it was issued on the priority lane.
        Revocation { revocation: Revocation },
        /// The revocation of one grant, as it was issued on the priority lane.
        GrantRevocation { revocation: GrantRevocation },
        /// The head of another actor's journal (§8.2 explicit linkage).
        Linkage { head: JournalHead },
        /// Events that reconciliation marked lost, recorded rather than skipped.
        EventsLost { lost: LostRange },
    }
}

/// An audit record before redaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditDraft {
    HostFact {
        fact: HostFact,
        fields: Vec<Field>,
    },
    /// Every field is treated as untrusted, whatever class it was declared with.
    GuestObservation {
        fields: Vec<Field>,
    },
    Revocation(Revocation),
    /// The revocation of one grant; like a revocation, it may use the revocation reserve.
    GrantRevocation(GrantRevocation),
    Linkage(JournalHead),
    EventsLost(LostRange),
}

/// One link of the chain: the event and the digests that bind it to its predecessor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRecord {
    journal: JournalId,
    previous: Digest,
    digest: Digest,
    event: EventEnvelope<AuditEntry>,
}

impl AuditRecord {
    pub fn journal(&self) -> &JournalId {
        &self.journal
    }

    /// The digest of the record before this one, or the journal's genesis digest.
    pub fn previous(&self) -> Digest {
        self.previous
    }

    /// The digest of the journal name, `previous` and this event's canonical JSON.
    pub fn digest(&self) -> Digest {
        self.digest
    }

    pub fn event(&self) -> &EventEnvelope<AuditEntry> {
        &self.event
    }

    pub fn sequence(&self) -> EventSequence {
        self.event.sequence()
    }
}

/// Why storage or the spool did not take a record. After a storage refusal, storage may
/// hold the record anyway (see [`AuditStore::append`]); after a spool refusal the spool
/// keeps nothing new.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoreRefusal {
    /// The write did not complete in time.
    Slow,
    Full,
    Failed,
}

impl fmt::Display for StoreRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Slow => "audit storage is slow",
            Self::Full => "audit storage is full",
            Self::Failed => "audit storage failed",
        })
    }
}

/// Durable storage of one journal, the port an adapter to `security/audit.rs` implements.
pub trait AuditStore {
    /// Stores `record` after every record already stored; `Ok` once it is durable. Storing
    /// a record identical to one already stored is `Ok` and stores nothing. A refusal may
    /// be unclear: storage may hold the whole record anyway (a write that completed after
    /// its deadline, for example), though never part of it. The journal therefore offers
    /// exactly the refused record again and never a different one under its sequence, a
    /// retry the duplicate rule makes safe.
    fn append(&mut self, record: &AuditRecord) -> Result<(), StoreRefusal>;
}

/// The bounded local spool of one journal (VM part §8.2 "a bounded local spool"): records
/// accepted while storage refused, kept in order until storage takes them. The storage
/// adapter implements it on durable local storage, so a spooled record survives a crash
/// and [`AuditJournal::resume`] continues after it.
pub trait AuditSpool {
    /// Keeps `record` after every record already spooled. Either it is durable in the
    /// spool and the result is `Ok`, or nothing new is kept.
    fn push(&mut self, record: &AuditRecord) -> Result<(), StoreRefusal>;

    /// The oldest spooled record.
    fn front(&self) -> Result<Option<AuditRecord>, StoreRefusal>;

    /// Removes the oldest spooled record, durably before it returns `Ok`, once storage
    /// holds it. After a refusal the record stays, and storage takes it again later as a
    /// duplicate.
    fn pop_front(&mut self) -> Result<(), StoreRefusal>;

    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Every spooled record, oldest first, for [`AuditJournal::resume`].
    fn records(&self) -> Result<Vec<AuditRecord>, StoreRefusal>;
}

/// The journal's defined audit failure policy for high-impact operations (VM part §8.2:
/// "deny new high-impact operations or use a bounded local spool").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditFailurePolicy {
    /// A high-impact operation goes ahead only once its record is durable.
    DenyHighImpact,
    /// A high-impact operation may go ahead once its record waits in the bounded spool.
    SpoolHighImpact,
}

/// Bounds and policy of one journal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditConfig {
    /// Records that may wait in the spool while storage is slow or full.
    pub spool_records: usize,
    /// Spool slots only revocation records, and a kept record that has to go ahead of
    /// one, may use; at least one.
    pub revocation_reserve_records: usize,
    pub failure_policy: AuditFailurePolicy,
    /// Bound on guest observations (§8.2 "bound ... emission rate").
    pub guest_observations: EmissionLimit,
    pub redaction: RedactionPolicy,
}

impl AuditConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.revocation_reserve_records == 0 {
            return Err(ConfigError::Zero {
                setting: "revocation_reserve_records",
            });
        }
        if self.revocation_reserve_records > self.spool_records {
            return Err(ConfigError::Exceeds {
                setting: "revocation_reserve_records",
                limit: "spool_records",
            });
        }
        Ok(())
    }
}

/// The capability to append to one journal (§16.3: metrics producers use the common
/// envelope without sharing its append authority). Its journal issues exactly one, when
/// it is opened or resumed. It is deliberately not `Clone`, `Default`, `Serialize` or
/// `Deserialize`, and nothing converts into it.
#[derive(Debug)]
pub struct AuditAppendAuthority {
    journal: JournalId,
    owner: ProducerId,
}

impl AuditAppendAuthority {
    pub fn journal(&self) -> &JournalId {
        &self.journal
    }

    pub fn owner(&self) -> &ProducerId {
        &self.owner
    }
}

/// Where an accepted record is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Durability {
    Durable,
    /// Waiting in the bounded spool, in order, for storage to take it.
    Spooled {
        spooled_records: usize,
    },
}

/// Proof that a record was accepted; for a high-impact operation, the permission to go
/// ahead.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditReceipt {
    pub sequence: EventSequence,
    pub digest: Digest,
    pub durability: Durability,
}

/// Why a record was refused; its operation must not proceed. Nothing was appended and no
/// sequence was used, unless a [`AuditRefusal::FailClosed`] names a `kept` sequence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuditRefusal {
    /// The authority belongs to another journal.
    WrongJournal {
        authority: JournalId,
        journal: JournalId,
    },
    /// Storage refused (`store`) and the spool did not take the record: it was full, the
    /// policy needs a durable record, the spool refused too (`spool`), or a kept record
    /// that has to go first could not. The journal fails closed, and the operation the
    /// record describes must not proceed.
    ///
    /// `kept` is the record's sequence when storage saw the record: storage may hold it
    /// anyway, so the journal keeps exactly this record under that sequence and offers it
    /// again before any other. It can still join the chain; its operation stays denied.
    FailClosed {
        store: StoreRefusal,
        spool: Option<StoreRefusal>,
        spooled_records: usize,
        kept: Option<EventSequence>,
    },
    /// Guest observations exceeded their emission limit.
    RateLimited {
        retry_after: Duration,
    },
    Invalid(EmitError),
    /// The journal used its last sequence.
    SequenceExhausted,
    Encoding {
        message: String,
    },
}

impl fmt::Display for AuditRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongJournal { authority, journal } => write!(
                f,
                "an authority for journal {authority} cannot append to journal {journal}"
            ),
            Self::FailClosed {
                store,
                spool,
                spooled_records,
                kept,
            } => {
                match spool {
                    None => write!(
                        f,
                        "{store} and {spooled_records} records already wait in the spool"
                    )?,
                    Some(spool) => write!(
                        f,
                        "{store}, and the spool holding {spooled_records} records refused too ({spool})"
                    )?,
                }
                if let Some(kept) = kept {
                    write!(
                        f,
                        "; storage may hold record {kept} anyway, so it keeps that sequence"
                    )?;
                }
                f.write_str("; the operation is denied until storage recovers")
            }
            Self::RateLimited { retry_after } => write!(
                f,
                "too many guest observations; retry in {} ms",
                retry_after.as_millis()
            ),
            Self::Invalid(error) => write!(f, "invalid audit record: {error}"),
            Self::SequenceExhausted => f.write_str("the audit journal used its last sequence"),
            Self::Encoding { message } => {
                write!(f, "the audit record could not be encoded: {message}")
            }
        }
    }
}

impl std::error::Error for AuditRefusal {}

/// Why a journal could not be opened or resumed. Each refusal fails closed: no journal,
/// no appends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JournalError {
    Config(ConfigError),
    /// The head, or the last spooled record, already carries the last sequence.
    SequenceExhausted,
    /// The spool could not be read.
    SpoolUnreadable(StoreRefusal),
    /// The spooled records do not continue the chain from the stored head.
    SpoolDoesNotContinue(ChainError),
}

impl fmt::Display for JournalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(error) => write!(f, "{error}"),
            Self::SequenceExhausted => f.write_str("the journal already used its last sequence"),
            Self::SpoolUnreadable(refusal) => {
                write!(f, "the audit spool cannot be read: {refusal}")
            }
            Self::SpoolDoesNotContinue(error) => {
                write!(
                    f,
                    "the audit spool does not continue the stored chain: {error}"
                )
            }
        }
    }
}

impl std::error::Error for JournalError {}

/// The journal's state as seen by operations that need audit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditHealth {
    /// Everything accepted is stored.
    Durable,
    /// Storage refused; records wait in the spool, and a high-impact operation may still
    /// go ahead on a spooled record.
    Spooling {
        store: StoreRefusal,
        spooled_records: usize,
    },
    /// Storage refused and high-impact operations are denied: the policy needs durable
    /// records, or no ordinary record fits in the spool.
    FailClosed {
        store: StoreRefusal,
        spooled_records: usize,
    },
}

/// What one flush moved to storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlushReport {
    /// Records storage took: spooled ones, removed from the spool, then a kept one.
    pub written: usize,
    /// Records still waiting for storage: spooled ones and a kept one.
    pub remaining: usize,
    /// Why storage stopped the flush.
    pub refusal: Option<StoreRefusal>,
    /// Why the spool stopped the flush; a record storage took stays spooled until it can
    /// be removed.
    pub spool_refusal: Option<StoreRefusal>,
}

/// Counts of what the journal did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditTotals {
    /// Stored when appended.
    pub durable: u64,
    /// Spooled when appended.
    pub spooled: u64,
    /// Moved from the spool to storage.
    pub flushed: u64,
    /// Refused because storage refused and the spool did not take the record.
    pub refused: u64,
    /// Refused records storage saw that joined the chain later, stored or spooled,
    /// because storage may have held them.
    pub kept_after_refusal: u64,
    /// Times the spool refused to keep, read or remove a record.
    pub spool_refusals: u64,
    pub suppressed_guest_observations: u64,
}

/// One actor's durable security audit journal (CORE-06; VM part §8.2).
#[derive(Debug)]
pub struct AuditJournal<S, P, C> {
    journal: JournalId,
    core: ProducerCore,
    head: Digest,
    last: Option<EventSequence>,
    store: S,
    spool: P,
    clock: C,
    config: AuditConfig,
    last_refusal: Option<StoreRefusal>,
    /// A refused record storage saw, which keeps its sequence: it goes first, to storage
    /// or the spool, before anything else can follow. The spool is empty meanwhile.
    kept: Option<AuditRecord>,
    guest_rate: RateLimiter,
    totals: AuditTotals,
}

impl<S: AuditStore, P: AuditSpool, C: Clock> AuditJournal<S, P, C> {
    /// Opens a new journal and issues its one append authority to `owner`. Anything
    /// already in `spool` must continue the new chain, as for [`AuditJournal::resume`].
    pub fn open(
        journal: JournalId,
        owner: ProducerId,
        store: S,
        spool: P,
        clock: C,
        config: AuditConfig,
    ) -> Result<(Self, AuditAppendAuthority), JournalError> {
        Self::resume(
            JournalHead::genesis(journal, owner),
            store,
            spool,
            clock,
            config,
        )
    }

    /// Continues the chain after the stored `head`, which the caller verified with
    /// [`verify_chain`], and issues the journal's one append authority to the head's
    /// owner. The spooled records must continue the chain from `head`; the journal goes
    /// on after the last of them, so no accepted record is lost and no sequence is used
    /// twice. The spool may still repeat records storage already took (a crash between
    /// storing one and removing it from the spool), which must end exactly at `head`. A
    /// spool that does not continue the chain refuses to open: fail closed. A journal is
    /// one sequence space across restarts, so its records keep incarnation 1.
    pub fn resume(
        head: JournalHead,
        store: S,
        spool: P,
        clock: C,
        config: AuditConfig,
    ) -> Result<(Self, AuditAppendAuthority), JournalError> {
        config.validate().map_err(JournalError::Config)?;
        let spooled = spool.records().map_err(JournalError::SpoolUnreadable)?;
        let tail = spool_tail(&head, &spooled).map_err(JournalError::SpoolDoesNotContinue)?;
        let next = match tail.last {
            None => EventSequence::FIRST,
            Some(last) => last.next().ok_or(JournalError::SequenceExhausted)?,
        };
        let core = ProducerCore::continuing(
            tail.owner.clone(),
            ProducerIncarnation::FIRST,
            StreamKind::Audit,
            SourceClass::HostProbe,
            Some(next),
        );
        let authority = AuditAppendAuthority {
            journal: tail.journal.clone(),
            owner: tail.owner,
        };
        let mut journal = Self {
            journal: tail.journal,
            core,
            head: tail.digest,
            last: tail.last,
            store,
            spool,
            clock,
            guest_rate: RateLimiter::new(config.guest_observations),
            config,
            last_refusal: None,
            kept: None,
            totals: AuditTotals::default(),
        };
        // Records left from before the restart go to storage first, if it takes them.
        journal.flush();
        Ok((journal, authority))
    }

    /// Appends one record after redacting it. Spooled records and a kept record are
    /// flushed first, and a new record never overtakes them. If storage refuses, the
    /// record waits in the spool when it fits; otherwise it is refused, and nothing is
    /// appended unless storage saw it (see [`AuditRefusal::FailClosed`]).
    pub fn append(
        &mut self,
        authority: &mut AuditAppendAuthority,
        context: EventContext,
        draft: AuditDraft,
    ) -> Result<AuditReceipt, AuditRefusal> {
        self.accept(authority, context, draft, false)
    }

    /// Admits a high-impact operation by recording it first: the receipt is the
    /// permission to proceed, and a refusal denies the operation. Under
    /// [`AuditFailurePolicy::DenyHighImpact`] the record must be durable, so no operation
    /// goes ahead on a spooled record (VM part §8.2 audit failure policy). A refused record
    /// storage saw is kept and can still join the chain; its operation stays denied.
    pub fn admit_high_impact(
        &mut self,
        authority: &mut AuditAppendAuthority,
        context: EventContext,
        fields: Vec<Field>,
    ) -> Result<AuditReceipt, AuditRefusal> {
        let durable_only = self.config.failure_policy == AuditFailurePolicy::DenyHighImpact;
        self.accept(
            authority,
            context,
            AuditDraft::HostFact {
                fact: HostFact::HighImpactOperation,
                fields,
            },
            durable_only,
        )
    }

    fn accept(
        &mut self,
        authority: &mut AuditAppendAuthority,
        context: EventContext,
        draft: AuditDraft,
        durable_only: bool,
    ) -> Result<AuditReceipt, AuditRefusal> {
        if authority.journal != self.journal || authority.owner != *self.core.producer() {
            return Err(AuditRefusal::WrongJournal {
                authority: authority.journal.clone(),
                journal: self.journal.clone(),
            });
        }
        let now = self.clock.now();
        let (entry, source, revocation) = self.seal_entry(draft, now)?;
        // Spool slots this record may use.
        let room = if durable_only {
            0
        } else if revocation {
            self.config.spool_records
        } else {
            self.ordinary_room()
        };
        self.flush();
        if let Err(spool) = self.spool_kept(room) {
            return Err(self.fail_closed(spool, None));
        }
        let event = self
            .core
            .draft(source, context, now, entry)
            .map_err(|_| AuditRefusal::SequenceExhausted)?;
        let sequence = event.sequence();
        let digest = record_digest(&self.journal, &self.head, &event).map_err(|error| {
            AuditRefusal::Encoding {
                message: error.to_string(),
            }
        })?;
        let record = AuditRecord {
            journal: self.journal.clone(),
            previous: self.head,
            digest,
            event,
        };
        // Storage sees the record only when nothing waits ahead of it.
        let offered = self.spool.is_empty();
        if offered {
            match self.store.append(&record) {
                Ok(()) => {
                    self.commit(sequence, digest);
                    self.last_refusal = None;
                    self.totals.durable = self.totals.durable.saturating_add(1);
                    return Ok(AuditReceipt {
                        sequence,
                        digest,
                        durability: Durability::Durable,
                    });
                }
                Err(refusal) => self.last_refusal = Some(refusal),
            }
        }
        // The record counts as accepted only once the spool holds it.
        let mut spool_refusal = None;
        if self.spool.len() < room {
            match self.spool.push(&record) {
                Ok(()) => {
                    self.commit(sequence, digest);
                    self.totals.spooled = self.totals.spooled.saturating_add(1);
                    return Ok(AuditReceipt {
                        sequence,
                        digest,
                        durability: Durability::Spooled {
                            spooled_records: self.spool.len(),
                        },
                    });
                }
                Err(refusal) => {
                    self.totals.spool_refusals = self.totals.spool_refusals.saturating_add(1);
                    spool_refusal = Some(refusal);
                }
            }
        }
        if !offered {
            return Err(self.fail_closed(spool_refusal, None));
        }
        // Storage may hold the record despite its refusal, so the record keeps its
        // sequence: no other content is ever offered under it.
        self.kept = Some(record);
        Err(self.fail_closed(spool_refusal, Some(sequence)))
    }

    /// Counts and describes a refusal.
    fn fail_closed(
        &mut self,
        spool: Option<StoreRefusal>,
        kept: Option<EventSequence>,
    ) -> AuditRefusal {
        self.totals.refused = self.totals.refused.saturating_add(1);
        AuditRefusal::FailClosed {
            store: self.last_refusal.unwrap_or(StoreRefusal::Failed),
            spool,
            spooled_records: self.spool.len(),
            kept,
        }
    }

    /// Puts a kept record that storage still refuses into the spool, ahead of the record
    /// being appended and on that record's `room`, because nothing can follow it until
    /// storage or the spool holds it. `Err` carries the spool's refusal, or `None` when
    /// there is no room, and the record stays kept.
    fn spool_kept(&mut self, room: usize) -> Result<(), Option<StoreRefusal>> {
        let Some(kept) = self.kept.take() else {
            return Ok(());
        };
        let pushed = if self.spool.len() < room {
            self.spool.push(&kept).map_err(Some)
        } else {
            Err(None)
        };
        match pushed {
            Ok(()) => {
                self.settle(&kept);
                Ok(())
            }
            Err(refusal) => {
                if refusal.is_some() {
                    self.totals.spool_refusals = self.totals.spool_refusals.saturating_add(1);
                }
                self.kept = Some(kept);
                Err(refusal)
            }
        }
    }

    /// A kept record joined the chain, stored or spooled.
    fn settle(&mut self, kept: &AuditRecord) {
        self.commit(kept.sequence(), kept.digest);
        self.totals.kept_after_refusal = self.totals.kept_after_refusal.saturating_add(1);
    }

    /// Records waiting for storage: the spooled ones and a kept one.
    fn waiting(&self) -> usize {
        self.spool
            .len()
            .saturating_add(usize::from(self.kept.is_some()))
    }

    /// Moves spooled records to storage in sequence order, then offers a kept record
    /// again, stopping at the first refusal of either. A record leaves the spool only
    /// after storage holds it.
    pub fn flush(&mut self) -> FlushReport {
        let mut written = 0;
        let mut refusal = None;
        let mut spool_refusal = None;
        loop {
            let front = match self.spool.front() {
                Ok(Some(front)) => front,
                Ok(None) => break,
                Err(error) => {
                    spool_refusal = Some(error);
                    break;
                }
            };
            if let Err(store) = self.store.append(&front) {
                refusal = Some(store);
                break;
            }
            if let Err(error) = self.spool.pop_front() {
                spool_refusal = Some(error);
                break;
            }
            written += 1;
        }
        let flushed = written;
        // A kept record comes after every spooled one; the spool is empty while it waits.
        if refusal.is_none() && spool_refusal.is_none() {
            if let Some(kept) = self.kept.take() {
                match self.store.append(&kept) {
                    Ok(()) => {
                        self.settle(&kept);
                        written += 1;
                    }
                    Err(store) => {
                        refusal = Some(store);
                        self.kept = Some(kept);
                    }
                }
            }
        }
        if spool_refusal.is_some() {
            self.totals.spool_refusals = self.totals.spool_refusals.saturating_add(1);
        }
        if let Some(stopped) = refusal.or(spool_refusal) {
            self.last_refusal = Some(stopped);
        } else if written > 0 {
            self.last_refusal = None;
        }
        self.totals.flushed = self
            .totals
            .flushed
            .saturating_add(u64::try_from(flushed).unwrap_or(u64::MAX));
        FlushReport {
            written,
            remaining: self.waiting(),
            refusal,
            spool_refusal,
        }
    }

    /// `store` in the result is the refusal that keeps records waiting: storage's, or the
    /// spool's when it could not hand a record over. A kept record counts against the
    /// spool, since the next record can only follow it there.
    pub fn health(&self) -> AuditHealth {
        let spooled_records = self.spool.len();
        let waiting = self.waiting();
        let spooling_allowed = self.config.failure_policy == AuditFailurePolicy::SpoolHighImpact
            && waiting < self.ordinary_room();
        match self.last_refusal {
            None if waiting == 0 => AuditHealth::Durable,
            None => AuditHealth::FailClosed {
                store: StoreRefusal::Failed,
                spooled_records,
            },
            Some(store) if spooling_allowed => AuditHealth::Spooling {
                store,
                spooled_records,
            },
            Some(store) => AuditHealth::FailClosed {
                store,
                spooled_records,
            },
        }
    }

    /// The last record of the chain, stored or spooled. A kept record joins it only once
    /// storage or the spool holds it.
    pub fn head(&self) -> JournalHead {
        JournalHead {
            journal: self.journal.clone(),
            owner: self.core.producer().clone(),
            last: self.last,
            digest: self.head,
        }
    }

    pub fn id(&self) -> &JournalId {
        &self.journal
    }

    pub fn spooled(&self) -> usize {
        self.spool.len()
    }

    pub fn totals(&self) -> AuditTotals {
        self.totals
    }

    /// Storage, to read. It is never lent mutably: records reach it only through an append
    /// with the journal's authority (§16.3).
    pub fn store(&self) -> &S {
        &self.store
    }

    fn ordinary_room(&self) -> usize {
        self.config
            .spool_records
            .saturating_sub(self.config.revocation_reserve_records)
    }

    fn commit(&mut self, sequence: EventSequence, digest: Digest) {
        self.core.commit(sequence);
        self.last = Some(sequence);
        self.head = digest;
    }

    /// Redacts a draft; returns its entry, its source class and whether it may use the
    /// revocation reserve. Host facts are labelled host observations and guest
    /// observations guest reports, whatever their fields claim.
    fn seal_entry(
        &mut self,
        draft: AuditDraft,
        now: MonotonicTime,
    ) -> Result<(AuditEntry, SourceClass, bool), AuditRefusal> {
        let policy = self.config.redaction;
        Ok(match draft {
            AuditDraft::HostFact { fact, fields } => (
                AuditEntry::HostFact {
                    fact,
                    fields: policy.redact(fields).map_err(AuditRefusal::Invalid)?,
                },
                SourceClass::HostProbe,
                false,
            ),
            AuditDraft::GuestObservation { fields } => {
                let fields = policy
                    .redact_untrusted(fields)
                    .map_err(AuditRefusal::Invalid)?;
                if let Err(retry_after) = self.guest_rate.admit(now) {
                    self.totals.suppressed_guest_observations =
                        self.totals.suppressed_guest_observations.saturating_add(1);
                    return Err(AuditRefusal::RateLimited { retry_after });
                }
                (
                    AuditEntry::GuestObservation { fields },
                    SourceClass::GuestReport,
                    false,
                )
            }
            AuditDraft::Revocation(revocation) => (
                AuditEntry::Revocation { revocation },
                SourceClass::HostProbe,
                true,
            ),
            AuditDraft::GrantRevocation(revocation) => (
                AuditEntry::GrantRevocation { revocation },
                SourceClass::HostProbe,
                true,
            ),
            AuditDraft::Linkage(head) => {
                (AuditEntry::Linkage { head }, SourceClass::HostProbe, false)
            }
            AuditDraft::EventsLost(lost) => (
                AuditEntry::EventsLost { lost },
                SourceClass::HostProbe,
                false,
            ),
        })
    }
}

/// Why a sequence of records is not an unbroken continuation of a journal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChainError {
    /// A record belongs to another journal.
    WrongJournal { sequence: EventSequence },
    /// A record is not on the audit stream.
    NotAudit { sequence: EventSequence },
    /// A record was appended by a producer other than the journal's owner: two writers
    /// shared one chain (VM part §8.2).
    ForeignAppender {
        sequence: EventSequence,
        producer: ProducerId,
    },
    /// A record is missing, repeated or reordered.
    OutOfOrder {
        expected: Option<EventSequence>,
        found: EventSequence,
    },
    /// A record does not name its predecessor's digest.
    BrokenLink { sequence: EventSequence },
    /// A record's content does not match its digest.
    DigestMismatch { sequence: EventSequence },
    /// Spooled records repeating stored ones do not end exactly at the stored head.
    DivergesFromHead { sequence: EventSequence },
    Encoding {
        sequence: EventSequence,
        message: String,
    },
}

impl fmt::Display for ChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongJournal { sequence } => {
                write!(f, "record {sequence} belongs to another journal")
            }
            Self::NotAudit { sequence } => write!(f, "record {sequence} is not an audit event"),
            Self::ForeignAppender { sequence, producer } => write!(
                f,
                "record {sequence} was appended by {producer}, not the journal's owner"
            ),
            Self::OutOfOrder {
                expected: Some(expected),
                found,
            } => write!(f, "expected record {expected}, found {found}"),
            Self::OutOfOrder {
                expected: None,
                found,
            } => write!(f, "found record {found} after the last sequence"),
            Self::BrokenLink { sequence } => {
                write!(f, "record {sequence} does not link to its predecessor")
            }
            Self::DigestMismatch { sequence } => {
                write!(f, "record {sequence} does not match its digest")
            }
            Self::DivergesFromHead { sequence } => write!(
                f,
                "spooled record {sequence} repeats storage but does not end at its head"
            ),
            Self::Encoding { sequence, message } => {
                write!(f, "record {sequence} could not be encoded: {message}")
            }
        }
    }
}

impl std::error::Error for ChainError {}

/// Checks that `records` continue the chain after `start` (a genesis head for a whole
/// journal): consecutive sequences, each appended by the journal's owner, each naming its
/// predecessor's digest and matching its own. Returns the new head, which a resumed
/// journal or a linking journal uses.
pub fn verify_chain(
    start: &JournalHead,
    records: &[AuditRecord],
) -> Result<JournalHead, ChainError> {
    let mut head = start.clone();
    for record in records {
        let sequence = record.sequence();
        if record.journal != start.journal {
            return Err(ChainError::WrongJournal { sequence });
        }
        if record.event.stream() != StreamKind::Audit {
            return Err(ChainError::NotAudit { sequence });
        }
        let producer = record.event.provenance().producer();
        if *producer != start.owner {
            return Err(ChainError::ForeignAppender {
                sequence,
                producer: producer.clone(),
            });
        }
        let expected = match head.last {
            None => Some(EventSequence::FIRST),
            Some(last) => last.next(),
        };
        if expected != Some(sequence) {
            return Err(ChainError::OutOfOrder {
                expected,
                found: sequence,
            });
        }
        if record.previous != head.digest {
            return Err(ChainError::BrokenLink { sequence });
        }
        let recomputed =
            record_digest(&start.journal, &record.previous, &record.event).map_err(|error| {
                ChainError::Encoding {
                    sequence,
                    message: error.to_string(),
                }
            })?;
        if recomputed != record.digest {
            return Err(ChainError::DigestMismatch { sequence });
        }
        head.last = Some(sequence);
        head.digest = record.digest;
    }
    Ok(head)
}

/// The head after `spooled`, which must continue the stored `head`. Spooled records that
/// storage already holds (a crash between storing one and removing it from the spool)
/// must form a chain that ends exactly at `head`.
fn spool_tail(head: &JournalHead, spooled: &[AuditRecord]) -> Result<JournalHead, ChainError> {
    let stored_through = head.last.map_or(0, EventSequence::get);
    let split = spooled
        .iter()
        .position(|record| record.sequence().get() > stored_through)
        .unwrap_or(spooled.len());
    let (repeated, pending) = spooled.split_at_checked(split).unwrap_or((spooled, &[]));
    if let (Some(first), Some(last)) = (repeated.first(), repeated.last()) {
        let start = JournalHead {
            journal: head.journal.clone(),
            owner: head.owner.clone(),
            last: first.sequence().previous(),
            digest: first.previous(),
        };
        let reached = verify_chain(&start, repeated)?;
        if reached.last != head.last || reached.digest != head.digest {
            return Err(ChainError::DivergesFromHead {
                sequence: last.sequence(),
            });
        }
    }
    verify_chain(head, pending)
}

fn record_digest(
    journal: &JournalId,
    previous: &Digest,
    event: &EventEnvelope<AuditEntry>,
) -> Result<Digest, serde_json::Error> {
    let encoded = serde_json::to_vec(event)?;
    Ok(DigestBuilder::new(RECORD_DOMAIN)
        .str(journal.as_str())
        .digest(previous)
        .bytes(&encoded)
        .finish())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::foundation::events::envelope::Phase;
    use crate::foundation::events::fakes::{
        context, execution, journal_id, manual_clock, producer, FakeAuditSpool, FakeAuditStore,
    };
    use crate::foundation::events::reconcile::{LossReason, SequenceRange};
    use crate::foundation::events::redaction::RedactedValue;
    use crate::foundation::events::revocation::RevocationReason;
    use crate::foundation::events::StreamKey;
    use crate::foundation::ids::{AuthorizationEpoch, ManualClock};

    type Journal = AuditJournal<FakeAuditStore, FakeAuditSpool, Arc<ManualClock>>;

    fn config(spool_records: usize, revocation_reserve_records: usize) -> AuditConfig {
        AuditConfig {
            spool_records,
            revocation_reserve_records,
            failure_policy: AuditFailurePolicy::SpoolHighImpact,
            guest_observations: EmissionLimit::new(2, Duration::from_secs(1)).unwrap(),
            redaction: RedactionPolicy::metadata_only(),
        }
    }

    fn genesis(name: &str) -> JournalHead {
        JournalHead::genesis(journal_id(name), producer(&format!("{name}.audit")))
    }

    fn open(
        name: &str,
        store: FakeAuditStore,
        config: AuditConfig,
    ) -> (Journal, AuditAppendAuthority) {
        open_spooled(name, store, &FakeAuditSpool::new(), config)
    }

    /// Opens a journal on `spool`, whose content outlives the journal.
    fn open_spooled(
        name: &str,
        store: FakeAuditStore,
        spool: &FakeAuditSpool,
        config: AuditConfig,
    ) -> (Journal, AuditAppendAuthority) {
        AuditJournal::open(
            journal_id(name),
            producer(&format!("{name}.audit")),
            store,
            spool.clone(),
            manual_clock(),
            config,
        )
        .unwrap()
    }

    /// Resumes `name` after the records `store` holds, on `spool`.
    fn resume(
        name: &str,
        store: FakeAuditStore,
        spool: &FakeAuditSpool,
        config: AuditConfig,
    ) -> Result<(Journal, AuditAppendAuthority), JournalError> {
        let head = verify_chain(&genesis(name), store.records()).unwrap();
        AuditJournal::resume(head, store, spool.clone(), manual_clock(), config)
    }

    fn deny_high_impact(config: AuditConfig) -> AuditConfig {
        AuditConfig {
            failure_policy: AuditFailurePolicy::DenyHighImpact,
            ..config
        }
    }

    fn admit(
        journal: &mut Journal,
        authority: &mut AuditAppendAuthority,
    ) -> Result<AuditReceipt, AuditRefusal> {
        journal.admit_high_impact(authority, context("op-1", Phase::Requested), vec![])
    }

    fn step_of(record: &AuditRecord) -> Option<&RedactedValue> {
        match record.event().payload() {
            AuditEntry::HostFact { fields, .. } => fields.get("step"),
            _ => None,
        }
    }

    fn fact(step: u64) -> AuditDraft {
        AuditDraft::HostFact {
            fact: HostFact::Lease,
            fields: vec![Field::metadata("step", step)],
        }
    }

    fn revocation() -> AuditDraft {
        AuditDraft::Revocation(Revocation {
            execution: execution("exe-1"),
            epoch: AuthorizationEpoch::new(2),
            reason: RevocationReason::SecurityEvent,
        })
    }

    fn append(
        journal: &mut Journal,
        authority: &mut AuditAppendAuthority,
        draft: AuditDraft,
    ) -> Result<AuditReceipt, AuditRefusal> {
        journal.append(authority, context("op-1", Phase::Running), draft)
    }

    fn stored(journal: &Journal) -> Vec<u64> {
        journal
            .store()
            .records()
            .iter()
            .map(|record| record.sequence().get())
            .collect()
    }

    #[test]
    fn appends_form_a_chain_that_exposes_tampering() {
        let (mut journal, mut authority) = open("engine", FakeAuditStore::new(100), config(4, 1));
        for step in 0..3 {
            let receipt = append(&mut journal, &mut authority, fact(step)).unwrap();
            assert_eq!(receipt.durability, Durability::Durable);
            assert_eq!(receipt.sequence.get(), step + 1);
        }
        let records = journal.store().records().to_vec();
        let head = verify_chain(&genesis("engine"), &records).unwrap();
        assert_eq!(head, journal.head());
        assert_eq!(head.last.map(EventSequence::get), Some(3));

        // Reordered.
        let mut reordered = records.clone();
        reordered.swap(0, 1);
        assert_eq!(
            verify_chain(&genesis("engine"), &reordered),
            Err(ChainError::OutOfOrder {
                expected: Some(EventSequence::FIRST),
                found: EventSequence::new(2).unwrap()
            })
        );
        // A record removed from the middle.
        let gapped = [records[0].clone(), records[2].clone()];
        assert!(matches!(
            verify_chain(&genesis("engine"), &gapped),
            Err(ChainError::OutOfOrder { .. })
        ));
        // A payload edited after the fact.
        let mut json = serde_json::to_value(&records[1]).unwrap();
        json["event"]["payload"]["fields"]["fields"][0]["value"]["value"] = serde_json::json!(99);
        let edited: AuditRecord = serde_json::from_value(json).unwrap();
        let tampered = [records[0].clone(), edited, records[2].clone()];
        assert_eq!(
            verify_chain(&genesis("engine"), &tampered),
            Err(ChainError::DigestMismatch {
                sequence: EventSequence::new(2).unwrap()
            })
        );
        // Records of another journal.
        assert_eq!(
            verify_chain(&genesis("warden"), &records),
            Err(ChainError::WrongJournal {
                sequence: EventSequence::FIRST
            })
        );
        // Records that do not continue the given head.
        let unlinked = verify_chain(&head, &records[..1]);
        assert!(matches!(unlinked, Err(ChainError::OutOfOrder { .. })));
        // A record spliced in from another chain under the same name.
        let (mut fork, mut fork_authority) = open("engine", FakeAuditStore::new(100), config(4, 1));
        let _ = append(&mut fork, &mut fork_authority, fact(7)).unwrap();
        let _ = append(&mut fork, &mut fork_authority, fact(8)).unwrap();
        let spliced = [records[0].clone(), fork.store().records()[1].clone()];
        assert_eq!(
            verify_chain(&genesis("engine"), &spliced),
            Err(ChainError::BrokenLink {
                sequence: EventSequence::new(2).unwrap()
            })
        );
    }

    #[test]
    fn slow_storage_spools_in_order_and_flushes_in_order() {
        let store = FakeAuditStore::new(100);
        store.control().slow_for(3);
        let (mut journal, mut authority) = open("engine", store, config(8, 2));
        // First append: storage is slow, so the record waits in the spool.
        let first = append(&mut journal, &mut authority, fact(1)).unwrap();
        assert_eq!(first.durability, Durability::Spooled { spooled_records: 1 });
        assert_eq!(
            journal.health(),
            AuditHealth::Spooling {
                store: StoreRefusal::Slow,
                spooled_records: 1
            }
        );
        // Each later append retries the spool first and never overtakes it.
        let _ = append(&mut journal, &mut authority, fact(2)).unwrap();
        let _ = append(&mut journal, &mut authority, fact(3)).unwrap();
        assert!(stored(&journal).is_empty());
        // Storage recovers: the spool is written in order, then the new record.
        let fourth = append(&mut journal, &mut authority, fact(4)).unwrap();
        assert_eq!(fourth.durability, Durability::Durable);
        assert_eq!(stored(&journal), [1, 2, 3, 4]);
        assert_eq!(journal.health(), AuditHealth::Durable);
        // One direct attempt, two failed flushes, three flushed records, one direct write.
        assert_eq!(journal.store().attempts(), 7);
        assert_eq!(journal.store().out_of_order_attempts(), 0);
        let totals = journal.totals();
        assert_eq!((totals.spooled, totals.flushed, totals.durable), (3, 3, 1));
        verify_chain(&genesis("engine"), journal.store().records()).unwrap();
    }

    #[test]
    fn full_storage_fails_closed_and_drops_nothing_silently() {
        let store = FakeAuditStore::new(1);
        let device = store.control();
        let (mut journal, mut authority) = open("engine", store, config(3, 1));
        let _ = append(&mut journal, &mut authority, fact(1)).unwrap();
        // Storage is now full: two ordinary records fit in the spool, then it fails closed.
        for step in 2..=3 {
            let receipt = append(&mut journal, &mut authority, fact(step)).unwrap();
            assert!(matches!(receipt.durability, Durability::Spooled { .. }));
        }
        let refused = journal.admit_high_impact(
            &mut authority,
            context("op-2", Phase::Requested),
            vec![Field::metadata("action", "reset_device")],
        );
        // Storage never saw the record, so nothing keeps its sequence.
        assert_eq!(
            refused,
            Err(AuditRefusal::FailClosed {
                store: StoreRefusal::Full,
                spool: None,
                spooled_records: 2,
                kept: None
            })
        );
        assert_eq!(
            journal.health(),
            AuditHealth::FailClosed {
                store: StoreRefusal::Full,
                spooled_records: 2
            }
        );
        // The refusal used no sequence: the next accepted record is 4.
        assert_eq!(journal.head().last.map(EventSequence::get), Some(3));
        device.set_capacity(10);
        let permit = journal
            .admit_high_impact(
                &mut authority,
                context("op-2", Phase::Requested),
                vec![Field::metadata("action", "reset_device")],
            )
            .unwrap();
        assert_eq!(permit.sequence.get(), 4);
        assert_eq!(stored(&journal), [1, 2, 3, 4]);
        assert_eq!(journal.totals().refused, 1);
        verify_chain(&genesis("engine"), journal.store().records()).unwrap();
    }

    #[test]
    fn revocation_records_use_the_reserve_when_ordinary_records_fail_closed() {
        let store = FakeAuditStore::new(0);
        let device = store.control();
        let (mut journal, mut authority) = open("engine", store, config(3, 1));
        let _ = append(&mut journal, &mut authority, fact(1)).unwrap();
        let _ = append(&mut journal, &mut authority, fact(2)).unwrap();
        assert!(matches!(
            append(&mut journal, &mut authority, fact(3)),
            Err(AuditRefusal::FailClosed { .. })
        ));
        let receipt = append(&mut journal, &mut authority, revocation()).unwrap();
        assert_eq!(
            receipt.durability,
            Durability::Spooled { spooled_records: 3 }
        );
        // The reserve is now used up too: the refusal is visible, never a silent drop.
        assert!(matches!(
            append(&mut journal, &mut authority, revocation()),
            Err(AuditRefusal::FailClosed { .. })
        ));
        device.set_capacity(10);
        assert_eq!(
            journal.flush(),
            FlushReport {
                written: 3,
                remaining: 0,
                refusal: None,
                spool_refusal: None
            }
        );
        let kinds: Vec<bool> = journal
            .store()
            .records()
            .iter()
            .map(|record| matches!(record.event().payload(), AuditEntry::Revocation { .. }))
            .collect();
        assert_eq!(kinds, [false, false, true]);
    }

    #[test]
    fn a_grant_revocation_uses_the_revocation_reserve_too() {
        let store = FakeAuditStore::new(0);
        let device = store.control();
        let (mut journal, mut authority) = open("engine", store, config(3, 1));
        let _ = append(&mut journal, &mut authority, fact(1)).unwrap();
        let _ = append(&mut journal, &mut authority, fact(2)).unwrap();
        assert!(matches!(
            append(&mut journal, &mut authority, fact(3)),
            Err(AuditRefusal::FailClosed { .. })
        ));
        let grant = GrantRevocation {
            execution: execution("exe-1"),
            grant: crate::foundation::ids::GrantId::from_digest(digest(
                "yougori/test/grant/v1",
                &[b"route"],
            )),
            epoch: AuthorizationEpoch::new(1),
            reason: RevocationReason::SecurityEvent,
        };
        let receipt = append(
            &mut journal,
            &mut authority,
            AuditDraft::GrantRevocation(grant.clone()),
        )
        .unwrap();
        assert_eq!(
            receipt.durability,
            Durability::Spooled { spooled_records: 3 }
        );
        device.set_capacity(10);
        assert_eq!(journal.flush().written, 3);
        let kinds: Vec<bool> = journal
            .store()
            .records()
            .iter()
            .map(|record| {
                matches!(
                    record.event().payload(),
                    AuditEntry::GrantRevocation { revocation } if *revocation == grant
                )
            })
            .collect();
        assert_eq!(kinds, [false, false, true]);
    }

    #[test]
    fn the_deny_policy_admits_no_high_impact_operation_on_a_spooled_record() {
        let store = FakeAuditStore::new(10);
        store.control().slow_for(3);
        let spool = FakeAuditSpool::new();
        let (mut journal, mut authority) =
            open_spooled("engine", store, &spool, deny_high_impact(config(4, 1)));
        // Storage saw the record before it refused, so the record keeps sequence 1.
        assert_eq!(
            admit(&mut journal, &mut authority),
            Err(AuditRefusal::FailClosed {
                store: StoreRefusal::Slow,
                spool: None,
                spooled_records: 0,
                kept: Some(EventSequence::FIRST)
            })
        );
        // Ordinary records still wait in the spool, behind the kept record, which storage
        // may already hold; its operation stays denied.
        let lease = append(&mut journal, &mut authority, fact(1)).unwrap();
        assert_eq!(lease.sequence.get(), 2);
        assert_eq!(lease.durability, Durability::Spooled { spooled_records: 2 });
        // A high-impact record that cannot be durable reaches neither storage nor the
        // spool, and uses no sequence.
        assert_eq!(
            admit(&mut journal, &mut authority),
            Err(AuditRefusal::FailClosed {
                store: StoreRefusal::Slow,
                spool: None,
                spooled_records: 2,
                kept: None
            })
        );
        assert_eq!(
            journal.health(),
            AuditHealth::FailClosed {
                store: StoreRefusal::Slow,
                spooled_records: 2
            }
        );
        let spooled: Vec<u64> = spool
            .snapshot()
            .iter()
            .map(|record| record.sequence().get())
            .collect();
        assert_eq!(spooled, [1, 2]);
        // Storage recovers: the spooled records go first, then the permit is durable.
        let permit = admit(&mut journal, &mut authority).unwrap();
        assert_eq!(permit.durability, Durability::Durable);
        assert_eq!(permit.sequence.get(), 3);
        assert_eq!(stored(&journal), [1, 2, 3]);
        assert_eq!(journal.store().out_of_order_attempts(), 0);
        let totals = journal.totals();
        assert_eq!(
            (totals.refused, totals.kept_after_refusal, totals.durable),
            (2, 1, 1)
        );
        verify_chain(&genesis("engine"), journal.store().records()).unwrap();
    }

    #[test]
    fn a_kept_record_is_offered_again_exactly_before_any_other() {
        let store = FakeAuditStore::new(10);
        store.control().store_but_report_slow_once();
        let (mut journal, mut authority) = open("engine", store, deny_high_impact(config(2, 1)));
        // Storage stored the record yet reported slow: the operation is denied, and the
        // record keeps sequence 1.
        let refused = admit(&mut journal, &mut authority);
        assert_eq!(
            refused,
            Err(AuditRefusal::FailClosed {
                store: StoreRefusal::Slow,
                spool: None,
                spooled_records: 0,
                kept: Some(EventSequence::FIRST)
            })
        );
        assert_eq!(
            refused.unwrap_err().to_string(),
            "audit storage is slow and 0 records already wait in the spool; storage may hold record 1 anyway, so it keeps that sequence; the operation is denied until storage recovers"
        );
        assert_eq!(stored(&journal), [1]);
        assert_eq!(journal.head().last, None);
        assert_eq!(
            journal.health(),
            AuditHealth::FailClosed {
                store: StoreRefusal::Slow,
                spooled_records: 0
            }
        );
        // A flush offers exactly that record again, and storage takes it as a duplicate.
        assert_eq!(
            journal.flush(),
            FlushReport {
                written: 1,
                remaining: 0,
                refusal: None,
                spool_refusal: None
            }
        );
        assert_eq!(journal.head().last, Some(EventSequence::FIRST));
        assert_eq!(journal.head().digest, journal.store().records()[0].digest());
        assert_eq!(journal.health(), AuditHealth::Durable);
        let permit = admit(&mut journal, &mut authority).unwrap();
        assert_eq!(permit.sequence.get(), 2);
        assert_eq!(stored(&journal), [1, 2]);
        assert_eq!(journal.store().attempts(), 3);
        assert_eq!(journal.store().out_of_order_attempts(), 0);
        let totals = journal.totals();
        assert_eq!(
            (totals.refused, totals.kept_after_refusal, totals.flushed),
            (1, 1, 0)
        );
        verify_chain(&genesis("engine"), journal.store().records()).unwrap();
    }

    #[test]
    fn a_kept_record_waits_in_the_spool_ahead_of_the_next_record_on_its_room() {
        let store = FakeAuditStore::new(0);
        let device = store.control();
        let spool = FakeAuditSpool::new();
        let (mut journal, mut authority) =
            open_spooled("engine", store, &spool, deny_high_impact(config(2, 1)));
        assert!(matches!(
            admit(&mut journal, &mut authority),
            Err(AuditRefusal::FailClosed { kept: Some(kept), .. }) if kept == EventSequence::FIRST
        ));
        // A flush offers it again; storage still refuses, and it keeps waiting.
        assert_eq!(
            journal.flush(),
            FlushReport {
                written: 0,
                remaining: 1,
                refusal: Some(StoreRefusal::Full),
                spool_refusal: None
            }
        );
        // A second high-impact record may not use the spool, so it cannot follow the kept
        // record, and it is refused without a sequence.
        assert_eq!(
            admit(&mut journal, &mut authority),
            Err(AuditRefusal::FailClosed {
                store: StoreRefusal::Full,
                spool: None,
                spooled_records: 0,
                kept: None
            })
        );
        // An ordinary record lets the kept record into the spool, but its one ordinary slot
        // is then taken.
        assert_eq!(
            append(&mut journal, &mut authority, fact(1)),
            Err(AuditRefusal::FailClosed {
                store: StoreRefusal::Full,
                spool: None,
                spooled_records: 1,
                kept: None
            })
        );
        // A revocation record may use the reserve; it takes sequence 2.
        let receipt = append(&mut journal, &mut authority, revocation()).unwrap();
        assert_eq!(receipt.sequence.get(), 2);
        assert_eq!(
            receipt.durability,
            Durability::Spooled { spooled_records: 2 }
        );
        let spooled: Vec<bool> = spool
            .snapshot()
            .iter()
            .map(|record| matches!(record.event().payload(), AuditEntry::Revocation { .. }))
            .collect();
        assert_eq!(spooled, [false, true]);
        device.set_capacity(10);
        assert_eq!(journal.flush().written, 2);
        assert_eq!(stored(&journal), [1, 2]);
        assert_eq!(journal.store().out_of_order_attempts(), 0);
        assert_eq!(journal.totals().kept_after_refusal, 1);
        verify_chain(&genesis("engine"), journal.store().records()).unwrap();
    }

    #[test]
    fn a_kept_record_does_not_shut_revocation_records_out_of_the_reserve() {
        // A spool that is all reserve: ordinary records never wait in it.
        let spool = FakeAuditSpool::new();
        let (mut journal, mut authority) =
            open_spooled("engine", FakeAuditStore::new(0), &spool, config(2, 2));
        assert!(matches!(
            append(&mut journal, &mut authority, fact(1)),
            Err(AuditRefusal::FailClosed { kept: Some(kept), .. }) if kept == EventSequence::FIRST
        ));
        // The revocation record can only follow the kept record, which goes ahead of it.
        let receipt = append(&mut journal, &mut authority, revocation()).unwrap();
        assert_eq!(receipt.sequence.get(), 2);
        assert_eq!(
            receipt.durability,
            Durability::Spooled { spooled_records: 2 }
        );
        assert_eq!(
            spool.snapshot().first().and_then(step_of),
            Some(&RedactedValue::Unsigned { value: 1 })
        );
        // The bound holds: the next revocation record is refused, visibly.
        assert_eq!(
            append(&mut journal, &mut authority, revocation()),
            Err(AuditRefusal::FailClosed {
                store: StoreRefusal::Full,
                spool: None,
                spooled_records: 2,
                kept: None
            })
        );
    }

    #[test]
    fn a_second_writer_on_one_chain_is_detected() {
        let (mut journal, mut authority) = open("engine", FakeAuditStore::new(10), config(4, 1));
        let _ = append(&mut journal, &mut authority, fact(1)).unwrap();
        let _ = append(&mut journal, &mut authority, fact(2)).unwrap();
        let head = journal.head();
        // A second writer resumes the same chain under its own name; its record links
        // correctly, yet the chain now has two writers.
        let (mut intruder, mut intruder_authority) = AuditJournal::resume(
            JournalHead {
                owner: producer("warden"),
                ..head
            },
            FakeAuditStore::new(10),
            FakeAuditSpool::new(),
            manual_clock(),
            config(4, 1),
        )
        .unwrap();
        let _ = append(&mut intruder, &mut intruder_authority, fact(3)).unwrap();
        let mut records = journal.store().records().to_vec();
        records.extend_from_slice(intruder.store().records());
        assert_eq!(
            verify_chain(&genesis("engine"), &records),
            Err(ChainError::ForeignAppender {
                sequence: EventSequence::new(3).unwrap(),
                producer: producer("warden")
            })
        );
    }

    #[test]
    fn an_authority_appends_only_to_its_own_journal() {
        let (mut engine, mut engine_authority) =
            open("engine", FakeAuditStore::new(10), config(2, 1));
        let (_warden, mut warden_authority) = open("warden", FakeAuditStore::new(10), config(2, 1));
        assert_eq!(
            append(&mut engine, &mut warden_authority, fact(1)),
            Err(AuditRefusal::WrongJournal {
                authority: journal_id("warden"),
                journal: journal_id("engine")
            })
        );
        assert!(stored(&engine).is_empty());
        let _ = append(&mut engine, &mut engine_authority, fact(1)).unwrap();
        assert_eq!(engine_authority.journal(), engine.id());
        assert_eq!(engine_authority.owner(), &producer("engine.audit"));
    }

    #[test]
    fn guest_observations_are_labelled_withheld_and_rate_limited() {
        let (mut journal, mut authority) = open("engine", FakeAuditStore::new(10), config(2, 1));
        let observation = || AuditDraft::GuestObservation {
            fields: vec![
                Field::metadata("uname", "Linux trusted-host 6.1"),
                Field::untrusted("exit_code", 0u64),
            ],
        };
        let _ = append(&mut journal, &mut authority, observation()).unwrap();
        let _ = append(&mut journal, &mut authority, fact(1)).unwrap();
        let _ = append(&mut journal, &mut authority, observation()).unwrap();
        assert!(matches!(
            append(&mut journal, &mut authority, observation()),
            Err(AuditRefusal::RateLimited { .. })
        ));
        assert_eq!(journal.totals().suppressed_guest_observations, 1);
        let records = journal.store().records();
        assert_eq!(
            records[0].event().provenance().source(),
            SourceClass::GuestReport
        );
        assert_eq!(
            records[1].event().provenance().source(),
            SourceClass::HostProbe
        );
        let AuditEntry::GuestObservation { fields } = records[0].event().payload() else {
            panic!("expected a guest observation");
        };
        // A guest cannot declare its text to be the host's metadata.
        assert_eq!(
            fields.get("uname"),
            Some(&RedactedValue::Withheld { bytes: 22 })
        );
        assert_eq!(
            fields.get("exit_code"),
            Some(&RedactedValue::Unsigned { value: 0 })
        );
    }

    #[test]
    fn actor_journals_link_explicitly_instead_of_sharing_a_chain() {
        let (mut warden, mut warden_authority) =
            open("warden", FakeAuditStore::new(10), config(2, 1));
        let (mut engine, mut engine_authority) =
            open("engine", FakeAuditStore::new(10), config(2, 1));
        let _ = append(&mut warden, &mut warden_authority, fact(1)).unwrap();
        let _ = append(&mut warden, &mut warden_authority, fact(2)).unwrap();
        let warden_head = warden.head();
        let _ = append(
            &mut engine,
            &mut engine_authority,
            AuditDraft::Linkage(warden_head.clone()),
        )
        .unwrap();
        // The link names exactly the warden chain up to its second record.
        let AuditEntry::Linkage { head } = engine.store().records()[0].event().payload() else {
            panic!("expected a linkage record");
        };
        assert_eq!(
            verify_chain(&genesis("warden"), warden.store().records()).unwrap(),
            *head
        );
        let _ = append(&mut warden, &mut warden_authority, fact(3)).unwrap();
        let later = verify_chain(&genesis("warden"), warden.store().records()).unwrap();
        assert_ne!(later, *head);
        // Each journal is its own chain with its own sequence.
        assert_eq!(stored(&engine), [1]);
        assert_eq!(stored(&warden), [1, 2, 3]);
    }

    #[test]
    fn an_unclear_refusal_is_retried_without_duplicating_the_record() {
        let store = FakeAuditStore::new(10);
        store.control().store_but_report_slow_once();
        let (mut journal, mut authority) = open("engine", store, config(4, 1));
        let first = append(&mut journal, &mut authority, fact(1)).unwrap();
        assert!(matches!(first.durability, Durability::Spooled { .. }));
        assert_eq!(stored(&journal), [1]);
        let _ = append(&mut journal, &mut authority, fact(2)).unwrap();
        assert_eq!(stored(&journal), [1, 2]);
        assert_eq!(journal.spooled(), 0);
        verify_chain(&genesis("engine"), journal.store().records()).unwrap();
    }

    #[test]
    fn a_resumed_journal_continues_the_chain() {
        let (mut journal, mut authority) = open("engine", FakeAuditStore::new(10), config(2, 1));
        let _ = append(&mut journal, &mut authority, fact(1)).unwrap();
        let _ = append(&mut journal, &mut authority, fact(2)).unwrap();
        let earlier = journal.store().records().to_vec();
        let head = verify_chain(&genesis("engine"), &earlier).unwrap();

        let (mut resumed, mut resumed_authority) = AuditJournal::resume(
            head.clone(),
            FakeAuditStore::new(10),
            FakeAuditSpool::new(),
            manual_clock(),
            config(2, 1),
        )
        .unwrap();
        let receipt = append(&mut resumed, &mut resumed_authority, fact(3)).unwrap();
        assert_eq!(receipt.sequence.get(), 3);
        let continued = verify_chain(&head, resumed.store().records()).unwrap();
        assert_eq!(continued, resumed.head());
        let mut whole = earlier;
        whole.extend_from_slice(resumed.store().records());
        assert_eq!(verify_chain(&genesis("engine"), &whole).unwrap(), continued);

        let exhausted = JournalHead {
            last: EventSequence::new(u64::MAX),
            ..head
        };
        assert_eq!(
            AuditJournal::resume(
                exhausted,
                FakeAuditStore::new(1),
                FakeAuditSpool::new(),
                manual_clock(),
                config(2, 1)
            )
            .err(),
            Some(JournalError::SequenceExhausted)
        );
    }

    #[test]
    fn spooled_records_survive_a_crash_and_resume_continues_after_them() {
        let spool = FakeAuditSpool::new();
        let (mut journal, mut authority) =
            open_spooled("engine", FakeAuditStore::new(1), &spool, config(8, 1));
        let _ = append(&mut journal, &mut authority, fact(1)).unwrap();
        // Storage is full from here: the next records wait in the spool, with receipts.
        let receipts: Vec<AuditReceipt> = (2..=4)
            .map(|step| append(&mut journal, &mut authority, fact(step)).unwrap())
            .collect();
        assert!(receipts
            .iter()
            .all(|receipt| matches!(receipt.durability, Durability::Spooled { .. })));
        let stored_before = journal.store().records().to_vec();
        assert_eq!(stored_before.len(), 1);
        // The process stops: storage and the spool survive, the journal does not.
        drop(journal);
        let store = FakeAuditStore::holding(stored_before, 1);
        let device = store.control();
        let (mut resumed, mut resumed_authority) =
            resume("engine", store, &spool, config(8, 1)).unwrap();
        // Storage is still full, so the spooled records still wait; none is lost.
        assert_eq!(resumed.spooled(), 3);
        let last = receipts[2];
        assert_eq!(resumed.head().last, Some(last.sequence));
        assert_eq!(resumed.head().digest, last.digest);
        assert!(matches!(
            resumed.health(),
            AuditHealth::Spooling {
                store: StoreRefusal::Full,
                ..
            }
        ));
        // The next record follows the last spooled one; no sequence is used twice.
        let next = append(&mut resumed, &mut resumed_authority, fact(5)).unwrap();
        assert_eq!(next.sequence.get(), 5);
        // Storage recovers: a flush stores everything, in order.
        device.set_capacity(100);
        assert_eq!(resumed.flush().written, 4);
        assert_eq!(stored(&resumed), [1, 2, 3, 4, 5]);
        verify_chain(&genesis("engine"), resumed.store().records()).unwrap();
        assert!(spool.snapshot().is_empty());
        assert_eq!(resumed.health(), AuditHealth::Durable);
    }

    #[test]
    fn a_crash_between_storing_and_unspooling_loses_and_repeats_nothing() {
        let spool = FakeAuditSpool::new();
        let store = FakeAuditStore::new(10);
        store.control().slow_for(1);
        let (mut journal, mut authority) = open_spooled("engine", store, &spool, config(4, 1));
        let first = append(&mut journal, &mut authority, fact(1)).unwrap();
        assert!(matches!(first.durability, Durability::Spooled { .. }));
        // Storage takes the record, but removing it from the spool fails; then the crash.
        spool.refuse_next_pops(1);
        let report = journal.flush();
        assert_eq!(report.written, 0);
        assert_eq!(report.spool_refusal, Some(StoreRefusal::Failed));
        assert_eq!(journal.totals().spool_refusals, 1);
        let stored_before = journal.store().records().to_vec();
        assert_eq!(stored_before.len(), 1);
        assert_eq!(spool.snapshot().len(), 1);
        drop(journal);
        let (mut resumed, mut resumed_authority) = resume(
            "engine",
            FakeAuditStore::holding(stored_before, 10),
            &spool,
            config(4, 1),
        )
        .unwrap();
        // Resuming handed the repeat to storage again, which took it as a duplicate.
        assert!(spool.snapshot().is_empty());
        let second = append(&mut resumed, &mut resumed_authority, fact(2)).unwrap();
        assert_eq!(second.sequence.get(), 2);
        assert_eq!(stored(&resumed), [1, 2]);
        verify_chain(&genesis("engine"), resumed.store().records()).unwrap();
    }

    #[test]
    fn a_spool_that_does_not_continue_the_chain_refuses_to_open() {
        let spool = FakeAuditSpool::new();
        let (mut journal, mut authority) =
            open_spooled("engine", FakeAuditStore::new(0), &spool, config(8, 1));
        for step in 1..=3 {
            let _ = append(&mut journal, &mut authority, fact(step)).unwrap();
        }
        drop(journal);
        let records = spool.snapshot();
        let resume_with = |content: Vec<AuditRecord>| {
            let tampered = FakeAuditSpool::new();
            tampered.replace(content);
            resume("engine", FakeAuditStore::new(0), &tampered, config(8, 1)).err()
        };
        // A record edited on disk.
        let mut json = serde_json::to_value(&records[1]).unwrap();
        json["event"]["payload"]["fields"]["fields"][0]["value"]["value"] = serde_json::json!(99);
        let edited = vec![
            records[0].clone(),
            serde_json::from_value(json).unwrap(),
            records[2].clone(),
        ];
        assert_eq!(
            resume_with(edited),
            Some(JournalError::SpoolDoesNotContinue(
                ChainError::DigestMismatch {
                    sequence: EventSequence::new(2).unwrap()
                }
            ))
        );
        // A record missing.
        assert!(matches!(
            resume_with(vec![records[0].clone(), records[2].clone()]),
            Some(JournalError::SpoolDoesNotContinue(
                ChainError::OutOfOrder { .. }
            ))
        ));
        // Another journal's spool.
        let warden_spool = FakeAuditSpool::new();
        let (mut warden, mut warden_authority) = open_spooled(
            "warden",
            FakeAuditStore::new(0),
            &warden_spool,
            config(8, 1),
        );
        let _ = append(&mut warden, &mut warden_authority, fact(1)).unwrap();
        drop(warden);
        assert!(matches!(
            resume_with(warden_spool.snapshot()),
            Some(JournalError::SpoolDoesNotContinue(
                ChainError::WrongJournal { .. }
            ))
        ));
        // Storage holds a different record 1 than the one the spool repeats.
        let (mut other, mut other_authority) =
            open("engine", FakeAuditStore::new(10), config(8, 1));
        let _ = append(&mut other, &mut other_authority, fact(9)).unwrap();
        let diverging = other.store().records().to_vec();
        let copy = FakeAuditSpool::new();
        copy.replace(records.clone());
        assert!(matches!(
            resume(
                "engine",
                FakeAuditStore::holding(diverging, 10),
                &copy,
                config(8, 1)
            )
            .err(),
            Some(JournalError::SpoolDoesNotContinue(
                ChainError::DivergesFromHead { .. }
            ))
        ));
        // The untouched spool opens.
        assert_eq!(resume_with(records), None);
    }

    #[test]
    fn an_unreadable_spool_refuses_to_open_and_stops_a_flush() {
        let spool = FakeAuditSpool::new();
        spool.refuse_reads(Some(StoreRefusal::Failed));
        assert_eq!(
            resume("engine", FakeAuditStore::new(10), &spool, config(4, 1)).err(),
            Some(JournalError::SpoolUnreadable(StoreRefusal::Failed))
        );
        spool.refuse_reads(None);
        let store = FakeAuditStore::new(10);
        store.control().slow_for(1);
        let (mut journal, mut authority) = open_spooled("engine", store, &spool, config(4, 1));
        let _ = append(&mut journal, &mut authority, fact(1)).unwrap();
        spool.refuse_reads(Some(StoreRefusal::Failed));
        let report = journal.flush();
        assert_eq!(report.spool_refusal, Some(StoreRefusal::Failed));
        assert_eq!(report.remaining, 1);
        assert!(matches!(
            journal.health(),
            AuditHealth::Spooling {
                store: StoreRefusal::Failed,
                ..
            }
        ));
        spool.refuse_reads(None);
        assert_eq!(journal.flush().written, 1);
        assert_eq!(journal.health(), AuditHealth::Durable);
    }

    #[test]
    fn a_record_refused_by_storage_and_the_spool_keeps_its_sequence() {
        let spool = FakeAuditSpool::new();
        spool.refuse_pushes(Some(StoreRefusal::Full));
        let store = FakeAuditStore::new(0);
        let device = store.control();
        let (mut journal, mut authority) = open_spooled("engine", store, &spool, config(8, 1));
        // Storage saw the record, so it keeps sequence 1 although it was refused.
        assert_eq!(
            append(&mut journal, &mut authority, fact(1)),
            Err(AuditRefusal::FailClosed {
                store: StoreRefusal::Full,
                spool: Some(StoreRefusal::Full),
                spooled_records: 0,
                kept: Some(EventSequence::FIRST)
            })
        );
        // A revocation record cannot go ahead of it: refused the same visible way, without
        // a sequence of its own.
        assert_eq!(
            append(&mut journal, &mut authority, revocation()),
            Err(AuditRefusal::FailClosed {
                store: StoreRefusal::Full,
                spool: Some(StoreRefusal::Full),
                spooled_records: 0,
                kept: None
            })
        );
        assert_eq!(journal.head().last, None);
        assert_eq!(journal.totals().spool_refusals, 2);
        // The spool recovers: the kept record enters it first, and the next record follows.
        spool.refuse_pushes(None);
        let receipt = append(&mut journal, &mut authority, fact(2)).unwrap();
        assert_eq!(receipt.sequence.get(), 2);
        assert_eq!(
            receipt.durability,
            Durability::Spooled { spooled_records: 2 }
        );
        device.set_capacity(10);
        assert_eq!(journal.flush().written, 2);
        let steps: Vec<Option<&RedactedValue>> =
            journal.store().records().iter().map(step_of).collect();
        assert_eq!(
            steps,
            [
                Some(&RedactedValue::Unsigned { value: 1 }),
                Some(&RedactedValue::Unsigned { value: 2 })
            ]
        );
        assert_eq!(journal.store().out_of_order_attempts(), 0);
        verify_chain(&genesis("engine"), journal.store().records()).unwrap();
    }

    #[test]
    fn lost_events_are_recorded_explicitly() {
        let (mut journal, mut authority) = open("engine", FakeAuditStore::new(10), config(2, 1));
        let lost = LostRange {
            key: StreamKey {
                producer: producer("warden"),
                incarnation: ProducerIncarnation::FIRST,
                stream: StreamKind::Audit,
            },
            range: SequenceRange::single(EventSequence::new(4).unwrap()),
            reason: LossReason::RecoveryExhausted,
        };
        let _ = append(
            &mut journal,
            &mut authority,
            AuditDraft::EventsLost(lost.clone()),
        )
        .unwrap();
        assert_eq!(
            journal.store().records()[0].event().payload(),
            &AuditEntry::EventsLost { lost }
        );
    }

    #[test]
    fn configuration_is_checked() {
        let open_with = |config: AuditConfig| {
            AuditJournal::open(
                journal_id("engine"),
                producer("engine.audit"),
                FakeAuditStore::new(1),
                FakeAuditSpool::new(),
                manual_clock(),
                config,
            )
            .err()
        };
        assert_eq!(
            open_with(config(4, 0)),
            Some(JournalError::Config(ConfigError::Zero {
                setting: "revocation_reserve_records"
            }))
        );
        assert_eq!(
            open_with(config(1, 2)),
            Some(JournalError::Config(ConfigError::Exceeds {
                setting: "revocation_reserve_records",
                limit: "spool_records"
            }))
        );
    }

    #[test]
    fn audit_entries_refuse_unknown_fields() {
        let (mut journal, mut authority) = open("engine", FakeAuditStore::new(10), config(2, 1));
        let _ = append(&mut journal, &mut authority, revocation()).unwrap();
        let record = journal.store().records()[0].clone();
        let mut json = serde_json::to_value(&record).unwrap();
        assert_eq!(json["event"]["payload"]["kind"], "revocation");
        assert_eq!(
            serde_json::from_value::<AuditRecord>(json.clone()).unwrap(),
            record
        );
        json["event"]["payload"]["note"] = serde_json::json!("x");
        assert!(serde_json::from_value::<AuditRecord>(json).is_err());
    }
}
