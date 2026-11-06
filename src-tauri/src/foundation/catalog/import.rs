//! The importer (S2 CORE-02 "atomic publication", "resumable verified data"; GPU part
//! §3.3, line 533; GPU part §3.4, line 546: only the importer writes committed content).
//!
//! An import is admitted by [`Catalog::begin_import`] (bounded manifest checks, trust,
//! references and a quota reservation, all before anything is written) and then driven
//! by [`Catalog::drive_import`] through the protocol of line 533:
//!
//! 1. bounded source verification;
//! 2. temporary representation, from verified extents only;
//! 3. complete index;
//! 4. read-back validation, including the class verifier;
//! 5. durable commit;
//! 6. catalog publication.
//!
//! A control may interrupt before any stage or extent. An interrupted, cancelled or
//! failed import never publishes: an object is published only by the final atomic write
//! of its record.
//!
//! Imports are single-flight per tenant scope, source and model execution identity (line
//! 533; GPU part §3.2 layer 3). A second import of the same key, by the same or another
//! execution of the same tenant, subscribes to the running import instead of starting
//! again: one import, one reservation charged to the tenant, every byte fetched once.
//! Each subscriber holds its own ticket bound to its own execution, and cancelling one
//! leaves the import to the others. Imports in different tenant scopes never share.

use std::collections::BTreeSet;
use std::fmt;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::content::{ExtentDigest, ImportManifest, ManifestError};
use super::identity::{
    ArtifactClass, ModelExecutionKey, ObjectId, ObjectRole, Scope, SourceIdentity,
};
use super::migrate::{read_staging, StagingRead};
use super::provenance::{
    bounded_detail, FailureReason, FailureRecord, StorageFailure, StorageOperation,
};
use super::state::{Catalog, Entry, MetadataError, ObjectMetadata, QuotaRefusal, Remnant};
use super::store::{
    ObjectIndex, ObjectRecord, StagingRecord, DATA_FILE, FORMAT_VERSION, INDEX_FILE, STAGING_FORMAT,
};
use super::trust::{
    evaluate_trust, recheck_trust, ContentDescriptor, TrustBasis, TrustClaim, TrustRefusal,
};
use crate::foundation::ids::{
    ContentKey, Digest, DigestBuilder, ExecutionId, MonotonicTime, OperationId,
};

/// Domain of the single-flight key: tenant scope, source and model execution identity.
pub const FLIGHT_DOMAIN: &str = "yougori/catalog/flight/v2";

/// One import as its caller declares it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportRequest {
    /// Correlates the import's records (CORE-06).
    pub operation: OperationId,
    /// The parent execution importing. It binds this caller's ticket and its records; it
    /// is not part of the single-flight key, so another execution of the same tenant
    /// subscribes to the same import.
    pub execution: ExecutionId,
    /// The scope that will own the object.
    pub scope: Scope,
    pub class: ArtifactClass,
    pub role: ObjectRole,
    /// What the source declares: true length, content key and extent digests.
    pub manifest: ImportManifest,
    pub trust: TrustClaim,
    /// Objects of the same scope this object needs (line 527 "dependency roots").
    pub depends_on: BTreeSet<ObjectId>,
    /// Private to the owning scope (INT-05).
    pub metadata: ObjectMetadata,
}

/// Why a source could not deliver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceError {
    pub detail: String,
}

impl fmt::Display for SourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.detail)
    }
}

impl std::error::Error for SourceError {}

/// Where an import's bytes come from. Specialized importers implement it over their
/// transports; it is read only through bounded ranges.
pub trait ImportSource {
    /// The source's identity; it must match the one the import was admitted with.
    fn identity(&self) -> SourceIdentity;

    /// The source's total length, checked against the declared true length before any
    /// byte is fetched.
    fn length_bytes(&mut self) -> Result<u64, SourceError>;

    /// Reads from `offset_bytes` into `buffer` and returns how many bytes were read; zero
    /// means the source ended. It can never deliver more than `buffer` holds.
    fn read_at(&mut self, offset_bytes: u64, buffer: &mut [u8]) -> Result<usize, SourceError>;
}

/// The stages of the importer protocol (line 533).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportStage {
    SourceVerification,
    TemporaryRepresentation,
    CompleteIndex,
    ReadBackValidation,
    DurableCommit,
    CatalogPublication,
}

impl ImportStage {
    /// The six stages in protocol order (line 533).
    pub const ALL: [Self; 6] = [
        Self::SourceVerification,
        Self::TemporaryRepresentation,
        Self::CompleteIndex,
        Self::ReadBackValidation,
        Self::DurableCommit,
        Self::CatalogPublication,
    ];
}

/// A point where an import may be interrupted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "checkpoint", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum Checkpoint {
    /// Before a protocol stage starts.
    Stage { stage: ImportStage },
    /// Before an extent is fetched from the source.
    Extent { extent: u32 },
}

crate::foundation::strict_serde::strict_tag!(Checkpoint, "checkpoint");

/// A control's answer at a checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proceed {
    Continue,
    Interrupt,
}

/// Decides at every checkpoint whether an import goes on (cancellation, deadlines).
pub trait ImportControl {
    fn proceed(&mut self, at: Checkpoint) -> Proceed;
}

/// A control that never interrupts.
#[derive(Clone, Copy, Debug, Default)]
pub struct Uninterrupted;

impl ImportControl for Uninterrupted {
    fn proceed(&mut self, _at: Checkpoint) -> Proceed {
        Proceed::Continue
    }
}

/// A control another thread can cancel; the import stops at the next checkpoint.
#[derive(Clone, Debug, Default)]
pub struct CancelFlag {
    cancelled: Arc<AtomicBool>,
}

impl CancelFlag {
    /// A flag that is not yet cancelled.
    pub fn new() -> Self {
        Self::default()
    }

    /// Cancels the import at its next checkpoint.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    /// Whether the import was cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

impl ImportControl for CancelFlag {
    fn proceed(&mut self, _at: Checkpoint) -> Proceed {
        if self.is_cancelled() {
            Proceed::Interrupt
        } else {
            Proceed::Continue
        }
    }
}

/// One subscriber's attachment to an import, bound to the execution and operation of the
/// request that took it. It is not cloneable: each subscriber holds its own and detaches
/// it with [`Catalog::cancel_import`]. Dropping a ticket does not cancel: an unfinished
/// import keeps its reservation until its last ticket is cancelled.
#[derive(Debug, PartialEq, Eq)]
pub struct ImportTicket {
    number: u64,
}

/// How an admitted import starts.
#[derive(Debug, PartialEq, Eq)]
pub enum ImportStart {
    /// A new import; drive it.
    Started(ImportTicket),
    /// An import with the same tenant scope, source and model execution identity is in
    /// flight, perhaps started by another execution of the tenant; this ticket subscribes
    /// to it and nothing is fetched twice (line 533 single flight).
    Attached(ImportTicket),
    /// The object is already published in this scope; this claim's trust was checked.
    AlreadyPublished(ObjectId),
}

/// Why an import was refused before anything was written.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum ImportRefusal {
    /// The declaration is corrupt or out of bounds (line 531).
    Manifest {
        error: ManifestError,
    },
    Metadata {
        error: MetadataError,
    },
    Trust {
        refusal: TrustRefusal,
    },
    Quota {
        refusal: QuotaRefusal,
    },
    /// A prepared representation must name what it was derived from.
    NoDerivation,
    TooManyReferences {
        references: u64,
        max_references: u32,
    },
    /// A derivation source or dependency is not a healthy published object of the
    /// importing scope. Another scope's object is refused the same way as a missing one.
    UnknownReference {
        object: ObjectId,
    },
    /// The same scope, source and execution is already importing a different
    /// declaration.
    ConflictingFlight {
        object: ObjectId,
    },
    /// The object is published in this scope with another role or dependencies.
    ConflictsWithPublished {
        object: ObjectId,
    },
    Storage {
        failure: StorageFailure,
    },
}

crate::foundation::strict_serde::strict_tag!(ImportRefusal, "kind");

impl fmt::Display for ImportRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Manifest { error } => write!(f, "the manifest is rejected: {error}"),
            Self::Metadata { error } => write!(f, "the metadata is rejected: {error}"),
            Self::Trust { refusal } => refusal.fmt(f),
            Self::Quota { refusal } => refusal.fmt(f),
            Self::NoDerivation => {
                f.write_str("a prepared representation must name the objects it was derived from")
            }
            Self::TooManyReferences {
                references,
                max_references,
            } => write!(f, "{references} references; the limit is {max_references}"),
            Self::UnknownReference { object } => {
                write!(f, "{object} is not a published object of this scope")
            }
            Self::ConflictingFlight { object } => write!(
                f,
                "this source and execution are already importing a different declaration of \
                 {object}"
            ),
            Self::ConflictsWithPublished { object } => write!(
                f,
                "{object} is already published with another role or dependencies"
            ),
            Self::Storage { failure } => failure.fmt(f),
        }
    }
}

impl std::error::Error for ImportRefusal {}

/// Extent accounting for one import, across every drive.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportProgress {
    /// Extents verified in the latest drive.
    pub verified_extents: u32,
    /// Extents fetched from the source and verified.
    pub fetched_extents: u32,
    /// Staged extents re-verified and reused instead of fetched.
    pub reused_extents: u32,
    /// Staged extents that failed re-verification and were fetched again.
    pub refetched_extents: u32,
    /// Bytes delivered by the source, including rejected deliveries.
    pub fetched_bytes: u64,
}

/// Where an import stands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImportStatus {
    /// Not finished: drive it to continue. Verified extents are kept.
    Pending {
        progress: ImportProgress,
        last_failure: Option<FailureRecord>,
    },
    Published {
        object: ObjectId,
        progress: ImportProgress,
    },
    /// Ended without publishing; its staging was discarded.
    Failed { failure: FailureRecord },
}

/// Misuse of the import API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImportError {
    UnknownTicket,
    /// The source differs from the one the import was admitted with.
    WrongSource {
        expected: SourceIdentity,
        found: SourceIdentity,
    },
}

impl fmt::Display for ImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownTicket => f.write_str("the import ticket is unknown or detached"),
            Self::WrongSource { expected, found } => write!(
                f,
                "the import was admitted for source {expected}, not {found}"
            ),
        }
    }
}

impl std::error::Error for ImportError {}

/// What detaching a ticket did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CancelOutcome {
    /// The last party detached from an unfinished import: nothing was published, and its
    /// verified extents remain for a later resume until collected.
    Cancelled,
    /// Other parties still follow the import, which goes on.
    Continuing {
        remaining_tickets: usize,
    },
    /// The import had already finished.
    Finished(ImportStatus),
    UnknownTicket,
}

#[derive(Clone, Debug)]
pub(super) enum Outcome {
    Pending { last_failure: Option<FailureRecord> },
    Published,
    Failed { failure: FailureRecord },
}

/// A half-open byte range `[offset_bytes, offset_bytes + length_bytes)` of one object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ByteSpan {
    pub offset_bytes: u64,
    pub length_bytes: u64,
}

/// What a pending import has verified of one object so far, as its owning scope sees it
/// (S2 CORE-05: a retry reuses verified extents; INT-08). It names byte ranges only and
/// carries no data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagedExtents {
    pub object: ObjectId,
    pub content_key: ContentKey,
    pub true_length_bytes: u64,
    /// Ranges whose extents the import verified against their declared digests in this
    /// process, fetched and checked or re-checked from staging; sorted, disjoint and
    /// coalesced. Journal claims not yet re-checked, and any other staged bytes, are
    /// never listed. The whole object is checked against the content key before it is
    /// published.
    pub verified: Vec<ByteSpan>,
}

impl StagedExtents {
    /// Bytes covered by [`StagedExtents::verified`].
    pub fn verified_bytes(&self) -> u64 {
        self.verified
            .iter()
            .fold(0u64, |sum, span| sum.saturating_add(span.length_bytes))
    }
}

/// One ticket's subscriber: the import it follows, and the execution and operation of the
/// request that took it, which its own records name.
#[derive(Clone, Debug)]
pub(super) struct Subscriber {
    pub(super) flight: u64,
    pub(super) execution: ExecutionId,
    pub(super) operation: OperationId,
}

/// One import in flight, with every subscriber attached to it.
#[derive(Debug)]
pub(super) struct Flight {
    pub(super) key: Digest,
    /// The request that started the import; its execution is the publication's provenance.
    pub(super) request: ImportRequest,
    pub(super) source: SourceIdentity,
    pub(super) object: ObjectId,
    pub(super) trust: TrustBasis,
    pub(super) manifest_digest: Digest,
    pub(super) tickets: BTreeSet<u64>,
    pub(super) outcome: Outcome,
    pub(super) progress: ImportProgress,
    pub(super) reserved_bytes: u64,
    pub(super) stage: ImportStage,
    /// Extents verified in this process since the current staging pass began: fetched and
    /// checked, or re-checked from staging. Cleared when a read-back finds the staged
    /// data changed.
    pub(super) verified: BTreeSet<u32>,
}

impl Flight {
    pub(super) fn is_pending(&self) -> bool {
        matches!(self.outcome, Outcome::Pending { .. })
    }

    fn status(&self) -> ImportStatus {
        match &self.outcome {
            Outcome::Pending { last_failure } => ImportStatus::Pending {
                progress: self.progress,
                last_failure: last_failure.clone(),
            },
            Outcome::Published => ImportStatus::Published {
                object: self.object,
                progress: self.progress,
            },
            Outcome::Failed { failure } => ImportStatus::Failed {
                failure: failure.clone(),
            },
        }
    }

    fn declares_same(&self, request: &ImportRequest, manifest_digest: &Digest) -> bool {
        self.manifest_digest == *manifest_digest
            && self.request.class == request.class
            && self.request.role == request.role
            && self.request.depends_on == request.depends_on
            && self.request.metadata == request.metadata
    }

    fn index(&self) -> ObjectIndex {
        ObjectIndex {
            format: FORMAT_VERSION,
            object: self.object,
            scope: self.request.scope.clone(),
            class: self.request.class,
            role: self.request.role.clone(),
            depends_on: self.request.depends_on.clone(),
            manifest: self.request.manifest.clone(),
        }
    }

    /// A failure as `by`, the subscriber that drove or cancelled the import, records it.
    fn failure(
        &self,
        by: &Subscriber,
        stage: ImportStage,
        reason: FailureReason,
        observed_at: MonotonicTime,
    ) -> FailureRecord {
        FailureRecord {
            operation: by.operation.clone(),
            execution: by.execution.clone(),
            scope: self.request.scope.clone(),
            class: self.request.class,
            source: self.source,
            object: self.object,
            stage,
            reason,
            observed_at,
        }
    }

    /// The verified extents as coalesced half-open `(start, end)` byte ranges.
    fn verified_ranges(&self) -> Vec<(u64, u64)> {
        let mut ranges: Vec<(u64, u64)> = Vec::new();
        for index in &self.verified {
            let Some(extent) = self.request.manifest.extents.get(*index as usize) else {
                continue;
            };
            let start = extent.offset_bytes;
            let end = start.saturating_add(extent.length_bytes);
            match ranges.last_mut() {
                Some(last) if last.1 == start => last.1 = end,
                _ => ranges.push((start, end)),
            }
        }
        ranges
    }
}

/// The ranges covered by both sorted, disjoint lists, coalesced.
fn intersect_ranges(left: &[(u64, u64)], right: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut both: Vec<(u64, u64)> = Vec::new();
    let (mut i, mut j) = (0, 0);
    while let (Some(a), Some(b)) = (left.get(i), right.get(j)) {
        let (start, end) = (a.0.max(b.0), a.1.min(b.1));
        if start < end {
            match both.last_mut() {
                Some(last) if last.1 == start => last.1 = end,
                _ => both.push((start, end)),
            }
        }
        if a.1 < b.1 {
            i += 1;
        } else {
            j += 1;
        }
    }
    both
}

/// Why a drive stopped: paused (resumable, staging kept) or failed (staging discarded).
enum Stop {
    Pause {
        stage: ImportStage,
        reason: FailureReason,
    },
    Fail {
        stage: ImportStage,
        reason: FailureReason,
    },
}

fn storage_pause(stage: ImportStage) -> impl Fn(StorageFailure) -> Stop {
    move |failure| Stop::Pause {
        stage,
        reason: FailureReason::Storage { failure },
    }
}

/// The single-flight key: tenant scope, source and model execution identity (line 533;
/// GPU part §3.2 layer 3). The scope keeps one tenant from subscribing to another's
/// import; the parent execution is not part of it.
pub(super) fn flight_key(
    scope: &Scope,
    source: &SourceIdentity,
    model_execution: Option<&ModelExecutionKey>,
) -> Digest {
    let builder = scope
        .bind(DigestBuilder::new(FLIGHT_DOMAIN))
        .digest(&source.digest());
    match model_execution {
        None => builder.str("any-execution").finish(),
        Some(key) => builder.str("execution").digest(&key.digest()).finish(),
    }
}

fn enter(
    flight: &mut Flight,
    control: &mut dyn ImportControl,
    stage: ImportStage,
) -> Result<(), Stop> {
    flight.stage = stage;
    let at = Checkpoint::Stage { stage };
    match control.proceed(at) {
        Proceed::Continue => Ok(()),
        Proceed::Interrupt => Err(Stop::Pause {
            stage,
            reason: FailureReason::Interrupted { at },
        }),
    }
}

/// Fills `buffer` from the source at `offset_bytes`, refusing short or oversized
/// deliveries.
fn fetch_exact(
    source: &mut dyn ImportSource,
    offset_bytes: u64,
    buffer: &mut [u8],
) -> Result<(), String> {
    let total = buffer.len();
    let mut filled = 0usize;
    while filled < total {
        let rest = buffer
            .get_mut(filled..)
            .ok_or_else(|| "the read position left the buffer".to_owned())?;
        let room = rest.len();
        let at = offset_bytes
            .checked_add(filled as u64)
            .ok_or_else(|| "the read position overflows".to_owned())?;
        let read = source
            .read_at(at, rest)
            .map_err(|error| bounded_detail(error))?;
        if read == 0 {
            return Err(format!("the source ended {} bytes early", total - filled));
        }
        if read > room {
            return Err("the source reported more bytes than it was asked for".to_owned());
        }
        filled += read;
    }
    Ok(())
}

fn read_at(file: &mut File, offset_bytes: u64, buffer: &mut [u8]) -> std::io::Result<()> {
    file.seek(SeekFrom::Start(offset_bytes))?;
    file.read_exact(buffer)
}

fn write_at(file: &mut File, offset_bytes: u64, buffer: &[u8]) -> std::io::Result<()> {
    file.seek(SeekFrom::Start(offset_bytes))?;
    file.write_all(buffer)
}

impl Catalog {
    /// Admits an import whose bytes do not depend on a model execution identity, such as
    /// original model files, or refuses it before anything is written: the manifest is
    /// validated for bounds (line 531), the trust claim is checked under the class's own
    /// policy (INT-09; a checksum alone is refused), references must be published objects
    /// of the same scope, and the true length is reserved against the scope's quota.
    /// Every refusal leaves a [`FailureRecord`].
    ///
    /// The import is single-flight per tenant scope and source: a request from any
    /// execution of the tenant subscribes to one already running (line 533).
    pub fn begin_import(
        &mut self,
        request: ImportRequest,
        source: SourceIdentity,
    ) -> Result<ImportStart, ImportRefusal> {
        self.begin(request, source, None)
    }

    /// [`Catalog::begin_import`] for a representation prepared for one model execution
    /// identity (GPU part §3.2 layer 3), such as processed weights for one runner and
    /// layout: single flight per tenant scope, source and that identity (line 533).
    pub fn begin_import_for(
        &mut self,
        request: ImportRequest,
        source: SourceIdentity,
        model_execution: ModelExecutionKey,
    ) -> Result<ImportStart, ImportRefusal> {
        self.begin(request, source, Some(model_execution))
    }

    fn begin(
        &mut self,
        request: ImportRequest,
        source: SourceIdentity,
        model_execution: Option<ModelExecutionKey>,
    ) -> Result<ImportStart, ImportRefusal> {
        let object = ObjectId::new(&request.scope, request.class, request.manifest.content_key);
        let (operation, execution, scope, class) = (
            request.operation.clone(),
            request.execution.clone(),
            request.scope.clone(),
            request.class,
        );
        let result = self.admit(request, source, model_execution, object);
        if let Err(refusal) = &result {
            self.failures.push(FailureRecord {
                operation,
                execution,
                scope,
                class,
                source,
                object,
                stage: ImportStage::SourceVerification,
                reason: FailureReason::Refused {
                    refusal: refusal.clone(),
                },
                observed_at: self.now(),
            });
        }
        result
    }

    fn admit(
        &mut self,
        request: ImportRequest,
        source: SourceIdentity,
        model_execution: Option<ModelExecutionKey>,
        object: ObjectId,
    ) -> Result<ImportStart, ImportRefusal> {
        request
            .manifest
            .validate(&self.config.limits.manifest())
            .map_err(|error| ImportRefusal::Manifest { error })?;
        request
            .metadata
            .check(&self.config.limits)
            .map_err(|error| ImportRefusal::Metadata { error })?;
        self.check_references(&request)?;
        let manifest_digest = request.manifest.digest();
        let trust = evaluate_trust(
            &self.verifiers,
            &self.config.trust,
            &ContentDescriptor {
                scope: request.scope.clone(),
                class: request.class,
                content_key: request.manifest.content_key,
                length_bytes: request.manifest.true_length_bytes,
                manifest_digest,
            },
            &request.trust,
        )
        .map_err(|refusal| ImportRefusal::Trust { refusal })?;

        let key = flight_key(&request.scope, &source, model_execution.as_ref());
        if let Some(number) = self.active.get(&key).copied() {
            let same = self
                .flights
                .get(&number)
                .is_some_and(|flight| flight.declares_same(&request, &manifest_digest));
            if !same {
                return Err(ImportRefusal::ConflictingFlight { object });
            }
            return Ok(ImportStart::Attached(self.attach(number, &request)));
        }
        if let Some(entry) = self
            .entries
            .get(&object)
            .filter(|entry| self.is_usable(entry))
        {
            let index = entry.index();
            if index.role == request.role && index.depends_on == request.depends_on {
                return Ok(ImportStart::AlreadyPublished(object));
            }
            return Err(ImportRefusal::ConflictsWithPublished { object });
        }

        let staged_bytes = self
            .remnants
            .get(&key)
            .filter(|remnant| remnant.scope.as_ref() == Some(&request.scope))
            .map_or(0, |remnant| remnant.length_bytes);
        self.reserve(
            &request.scope,
            request.manifest.true_length_bytes,
            staged_bytes,
        )
        .map_err(|refusal| ImportRefusal::Quota { refusal })?;
        self.prepare_staging(&StagingRecord {
            format: STAGING_FORMAT,
            flight: key,
            scope: request.scope.clone(),
            class: request.class,
            source,
            model_execution,
            manifest_digest,
            true_length_bytes: request.manifest.true_length_bytes,
        })
        .map_err(|failure| ImportRefusal::Storage { failure })?;
        self.remnants.remove(&key);

        let number = self.next_number();
        let ticket = self.next_number();
        let reserved_bytes = request.manifest.true_length_bytes;
        let subscriber = Subscriber {
            flight: number,
            execution: request.execution.clone(),
            operation: request.operation.clone(),
        };
        self.flights.insert(
            number,
            Flight {
                key,
                request,
                source,
                object,
                trust,
                manifest_digest,
                tickets: BTreeSet::from([ticket]),
                outcome: Outcome::Pending { last_failure: None },
                progress: ImportProgress::default(),
                reserved_bytes,
                stage: ImportStage::SourceVerification,
                verified: BTreeSet::new(),
            },
        );
        self.active.insert(key, number);
        self.tickets.insert(ticket, subscriber);
        Ok(ImportStart::Started(ImportTicket { number: ticket }))
    }

    fn check_references(&self, request: &ImportRequest) -> Result<(), ImportRefusal> {
        let derived_from = match &request.role {
            ObjectRole::Original => None,
            ObjectRole::Prepared { derived_from } => Some(derived_from),
        };
        if derived_from.is_some_and(BTreeSet::is_empty) {
            return Err(ImportRefusal::NoDerivation);
        }
        let references =
            derived_from.map_or(0, BTreeSet::len) as u64 + request.depends_on.len() as u64;
        if references > u64::from(self.config.limits.max_references) {
            return Err(ImportRefusal::TooManyReferences {
                references,
                max_references: self.config.limits.max_references,
            });
        }
        for object in derived_from
            .into_iter()
            .flatten()
            .chain(&request.depends_on)
        {
            let in_scope = self
                .entries
                .get(object)
                .is_some_and(|entry| entry.scope() == &request.scope && self.is_usable(entry));
            if !in_scope {
                return Err(ImportRefusal::UnknownReference { object: *object });
            }
        }
        Ok(())
    }

    /// Creates the staging directory, or keeps an existing one made for exactly this
    /// declaration so its verified extents can be reused. Data staged for any other
    /// declaration is removed, never trusted.
    fn prepare_staging(&self, declaration: &StagingRecord) -> Result<(), StorageFailure> {
        let dir = self.layout.flight_dir(&declaration.flight);
        let path = self.layout.flight_record(&declaration.flight);
        if self.layout.exists(&dir) {
            match read_staging(&self.layout, &path) {
                Ok(StagingRead::Current(existing)) if existing == *declaration => return Ok(()),
                // A newer build's staging is never removed or rewritten.
                Ok(StagingRead::Refused(refused)) => return Err(refused.to_failure()),
                _ => self.layout.remove_tree(&dir)?,
            }
        }
        self.layout.create_dir(&dir)?;
        self.layout.write_json_atomic(&path, declaration)
    }

    /// Subscribes `request`'s execution to the running import `number`.
    fn attach(&mut self, number: u64, request: &ImportRequest) -> ImportTicket {
        let ticket = self.next_number();
        if let Some(flight) = self.flights.get_mut(&number) {
            flight.tickets.insert(ticket);
        }
        self.tickets.insert(
            ticket,
            Subscriber {
                flight: number,
                execution: request.execution.clone(),
                operation: request.operation.clone(),
            },
        );
        ImportTicket { number: ticket }
    }

    /// Drives an import until it publishes, pauses or fails. Any subscriber may drive it,
    /// and the records of that drive name it; a finished import just reports its status.
    pub fn drive_import(
        &mut self,
        ticket: &ImportTicket,
        source: &mut dyn ImportSource,
        control: &mut dyn ImportControl,
    ) -> Result<ImportStatus, ImportError> {
        let subscriber = self
            .tickets
            .get(&ticket.number)
            .cloned()
            .ok_or(ImportError::UnknownTicket)?;
        let number = subscriber.flight;
        let mut flight = self
            .flights
            .remove(&number)
            .ok_or(ImportError::UnknownTicket)?;
        let found = source.identity();
        let result = if !flight.is_pending() {
            Ok(())
        } else if found != flight.source {
            Err(ImportError::WrongSource {
                expected: flight.source,
                found,
            })
        } else {
            let run = self.run(&mut flight, source, control);
            self.settle(&mut flight, &subscriber, run);
            Ok(())
        };
        let status = flight.status();
        self.flights.insert(number, flight);
        self.forget_oldest_finished();
        result.map(|()| status)
    }

    /// Keeps the status of at most `max_finished_imports` finished imports for tickets
    /// that were never cancelled; older ones are forgotten with their tickets.
    fn forget_oldest_finished(&mut self) {
        let limit = usize::try_from(self.config.limits.max_finished_imports).unwrap_or(usize::MAX);
        let finished: Vec<u64> = self
            .flights
            .iter()
            .filter(|(_, flight)| !flight.is_pending())
            .map(|(number, _)| *number)
            .collect();
        let excess = finished.len().saturating_sub(limit);
        for number in finished.into_iter().take(excess) {
            if let Some(flight) = self.flights.remove(&number) {
                for ticket in flight.tickets {
                    self.tickets.remove(&ticket);
                }
            }
        }
    }

    /// The import's status, as any subscriber sees it.
    pub fn import_status(&self, ticket: &ImportTicket) -> Option<ImportStatus> {
        let number = self.tickets.get(&ticket.number)?.flight;
        self.flights.get(&number).map(Flight::status)
    }

    /// The executions subscribed to the import `ticket` follows, one per ticket in the
    /// order they subscribed (GPU-T02: one import, several subscribers).
    pub fn import_subscribers(&self, ticket: &ImportTicket) -> Option<Vec<ExecutionId>> {
        let number = self.tickets.get(&ticket.number)?.flight;
        let flight = self.flights.get(&number)?;
        Some(
            flight
                .tickets
                .iter()
                .filter_map(|ticket| self.tickets.get(ticket))
                .map(|subscriber| subscriber.execution.clone())
                .collect(),
        )
    }

    /// What a pending import of `content` of `class` into `reader`'s own scope, to which
    /// `execution` is subscribed, has verified so far, so a retried transfer moves only the
    /// rest (S2 CORE-05; INT-08). Every subscriber of a shared import sees the same
    /// extents, whichever execution started it.
    ///
    /// Scope-checked like a read: another scope's import, or equal content imported
    /// elsewhere, is never reported (S3.3), and neither is an import `execution` has not
    /// subscribed to. An import whose trust basis the current policy no longer accepts
    /// reports nothing. With several pending imports of the object for the execution, only
    /// the ranges every one of them verified are reported. `None` when no such import is
    /// pending; read a published object through [`Catalog::object_view`].
    pub fn staged_extents(
        &self,
        reader: &Scope,
        execution: &ExecutionId,
        class: ArtifactClass,
        content: ContentKey,
    ) -> Option<StagedExtents> {
        let object = ObjectId::new(reader, class, content);
        let mut pending = self.flights.values().filter(|flight| {
            flight.is_pending()
                && flight.object == object
                && flight.request.scope == *reader
                && flight.tickets.iter().any(|ticket| {
                    self.tickets
                        .get(ticket)
                        .is_some_and(|subscriber| subscriber.execution == *execution)
                })
                && recheck_trust(
                    &self.verifiers,
                    &self.config.trust,
                    reader,
                    class,
                    &flight.trust,
                )
                .is_ok()
        });
        let first = pending.next()?;
        let ranges = pending.fold(first.verified_ranges(), |ranges, flight| {
            intersect_ranges(&ranges, &flight.verified_ranges())
        });
        Some(StagedExtents {
            object,
            content_key: content,
            true_length_bytes: first.request.manifest.true_length_bytes,
            verified: ranges
                .into_iter()
                .map(|(start, end)| ByteSpan {
                    offset_bytes: start,
                    length_bytes: end.saturating_sub(start),
                })
                .collect(),
        })
    }

    /// Detaches `ticket`. The other subscribers keep the import; when the last one
    /// detaches from an unfinished import, it is cancelled: nothing is published, its
    /// reservation is released and its verified extents stay staged, charged to the scope,
    /// until resumed or collected.
    pub fn cancel_import(&mut self, ticket: ImportTicket) -> CancelOutcome {
        let Some(subscriber) = self.tickets.remove(&ticket.number) else {
            return CancelOutcome::UnknownTicket;
        };
        let number = subscriber.flight;
        let Some(mut flight) = self.flights.remove(&number) else {
            return CancelOutcome::UnknownTicket;
        };
        flight.tickets.remove(&ticket.number);
        if !flight.is_pending() {
            let status = flight.status();
            if !flight.tickets.is_empty() {
                self.flights.insert(number, flight);
            }
            return CancelOutcome::Finished(status);
        }
        if !flight.tickets.is_empty() {
            let remaining_tickets = flight.tickets.len();
            self.flights.insert(number, flight);
            return CancelOutcome::Continuing { remaining_tickets };
        }
        self.active.remove(&flight.key);
        let now = self.now();
        let dir = self.layout.flight_dir(&flight.key);
        if self.layout.exists(&dir) {
            let length_bytes = self
                .layout
                .file_len(&self.layout.staged_object(&flight.key).join(DATA_FILE))
                .unwrap_or(0);
            self.remnants.insert(
                flight.key,
                Remnant {
                    path: dir,
                    scope: Some(flight.request.scope.clone()),
                    length_bytes,
                    since: now,
                    retained: false,
                },
            );
        }
        let record = flight.failure(&subscriber, flight.stage, FailureReason::Cancelled, now);
        self.failures.push(record);
        CancelOutcome::Cancelled
    }

    fn settle(&mut self, flight: &mut Flight, by: &Subscriber, run: Result<(), Stop>) {
        match run {
            Ok(()) => {
                self.active.remove(&flight.key);
                flight.reserved_bytes = 0;
                flight.outcome = Outcome::Published;
            }
            Err(Stop::Pause { stage, reason }) => {
                let record = flight.failure(by, stage, reason, self.now());
                self.failures.push(record.clone());
                flight.outcome = Outcome::Pending {
                    last_failure: Some(record),
                };
            }
            Err(Stop::Fail { stage, reason }) => {
                let record = flight.failure(by, stage, reason, self.now());
                self.failures.push(record.clone());
                self.active.remove(&flight.key);
                flight.reserved_bytes = 0;
                self.discard_staging(flight);
                flight.outcome = Outcome::Failed { failure: record };
            }
        }
    }

    /// Removes a flight's staging; if that fails, the directory stays as a remnant for the
    /// collector.
    fn discard_staging(&mut self, flight: &Flight) {
        let dir = self.layout.flight_dir(&flight.key);
        if self.layout.remove_tree(&dir).is_err() {
            let length_bytes = self
                .layout
                .file_len(&self.layout.staged_object(&flight.key).join(DATA_FILE))
                .unwrap_or(0);
            let since = self.now();
            self.remnants.insert(
                flight.key,
                Remnant {
                    path: dir,
                    scope: Some(flight.request.scope.clone()),
                    length_bytes,
                    since,
                    retained: false,
                },
            );
        }
    }

    fn run(
        &mut self,
        flight: &mut Flight,
        source: &mut dyn ImportSource,
        control: &mut dyn ImportControl,
    ) -> Result<(), Stop> {
        if let Err(refusal) = recheck_trust(
            &self.verifiers,
            &self.config.trust,
            &flight.request.scope,
            flight.request.class,
            &flight.trust,
        ) {
            // The policy withdrew the trust this import was admitted under (INT-09).
            flight.verified.clear();
            return Err(Stop::Fail {
                stage: flight.stage,
                reason: FailureReason::Refused {
                    refusal: ImportRefusal::Trust { refusal },
                },
            });
        }
        if self
            .entries
            .get(&flight.object)
            .is_some_and(|entry| self.is_usable(entry))
        {
            // Another import of this scope published the same object meanwhile.
            self.discard_staging(flight);
            return Ok(());
        }
        let index = flight.index();
        if self.unpublished.contains_key(&flight.object) {
            // Committed before an interruption, never published: validate it in full.
            enter(flight, control, ImportStage::ReadBackValidation)?;
            if self.adopt_unpublished(&index)? {
                enter(flight, control, ImportStage::CatalogPublication)?;
                return self.publish(flight, index);
            }
        }
        enter(flight, control, ImportStage::SourceVerification)?;
        Self::verify_source(flight, source)?;
        enter(flight, control, ImportStage::TemporaryRepresentation)?;
        self.fill_staging(flight, source, control)?;
        enter(flight, control, ImportStage::CompleteIndex)?;
        self.write_index(flight, &index)?;
        enter(flight, control, ImportStage::ReadBackValidation)?;
        if let Err(stop) = self.read_back(flight, &index) {
            // The staged data no longer reads back as verified; nothing of it counts.
            flight.verified.clear();
            return Err(stop);
        }
        enter(flight, control, ImportStage::DurableCommit)?;
        self.commit(flight)?;
        enter(flight, control, ImportStage::CatalogPublication)?;
        self.publish(flight, index)
    }

    /// Bounded source verification: the source's length must be the declared true
    /// length before any byte is fetched.
    fn verify_source(flight: &Flight, source: &mut dyn ImportSource) -> Result<(), Stop> {
        const STAGE: ImportStage = ImportStage::SourceVerification;
        let declared_bytes = flight.request.manifest.true_length_bytes;
        let source_bytes = source.length_bytes().map_err(|error| Stop::Pause {
            stage: STAGE,
            reason: FailureReason::SourceFailed {
                extent: None,
                detail: bounded_detail(error),
            },
        })?;
        if source_bytes != declared_bytes {
            return Err(Stop::Fail {
                stage: STAGE,
                reason: FailureReason::SourceLengthMismatch {
                    declared_bytes,
                    source_bytes,
                },
            });
        }
        Ok(())
    }

    /// The temporary representation, built from verified extents only. Extents the
    /// journal lists are re-verified against the manifest and reused; a corrupt one is
    /// fetched again, and data the journal does not list is never trusted.
    fn fill_staging(
        &mut self,
        flight: &mut Flight,
        source: &mut dyn ImportSource,
        control: &mut dyn ImportControl,
    ) -> Result<(), Stop> {
        const STAGE: ImportStage = ImportStage::TemporaryRepresentation;
        let pause = storage_pause(STAGE);
        let dir = self.layout.staged_object(&flight.key);
        self.layout.create_dir(&dir).map_err(&pause)?;
        let data_path = dir.join(DATA_FILE);
        self.layout.make_writable(&data_path).map_err(&pause)?;
        let mut data = self
            .layout
            .open_staging_data(&data_path, flight.request.manifest.true_length_bytes)
            .map_err(&pause)?;
        let journal = self.layout.journal(&flight.key);
        let listed = self
            .layout
            .journal_load(
                &journal,
                &flight.manifest_digest,
                flight.request.manifest.extent_count(),
            )
            .map_err(&pause)?;
        let attempts_allowed = self.config.limits.max_fetch_attempts.max(1);
        let io = |operation: StorageOperation, error: std::io::Error| {
            pause(self.layout.failure(operation, &data_path, error))
        };
        flight.progress.verified_extents = 0;
        flight.verified.clear();
        let mut buffer = Vec::new();
        for (position, extent) in flight.request.manifest.extents.iter().enumerate() {
            let index = u32::try_from(position).unwrap_or(u32::MAX);
            let length = usize::try_from(extent.length_bytes).map_err(|_| {
                pause(self.layout.failure(
                    StorageOperation::TooLarge,
                    &data_path,
                    "an extent does not fit in memory",
                ))
            })?;
            buffer.resize(length, 0);
            if listed.contains(&index) {
                read_at(&mut data, extent.offset_bytes, &mut buffer)
                    .map_err(|error| io(StorageOperation::Read, error))?;
                if ExtentDigest::of(&buffer) == extent.digest {
                    flight.progress.reused_extents =
                        flight.progress.reused_extents.saturating_add(1);
                    flight.progress.verified_extents =
                        flight.progress.verified_extents.saturating_add(1);
                    flight.verified.insert(index);
                    continue;
                }
                flight.progress.refetched_extents =
                    flight.progress.refetched_extents.saturating_add(1);
            }
            let at = Checkpoint::Extent { extent: index };
            if control.proceed(at) == Proceed::Interrupt {
                return Err(Stop::Pause {
                    stage: STAGE,
                    reason: FailureReason::Interrupted { at },
                });
            }
            let mut attempts = 0u32;
            loop {
                attempts += 1;
                fetch_exact(source, extent.offset_bytes, &mut buffer).map_err(|detail| {
                    Stop::Pause {
                        stage: STAGE,
                        reason: FailureReason::SourceFailed {
                            extent: Some(index),
                            detail,
                        },
                    }
                })?;
                flight.progress.fetched_bytes = flight
                    .progress
                    .fetched_bytes
                    .saturating_add(extent.length_bytes);
                if ExtentDigest::of(&buffer) == extent.digest {
                    break;
                }
                if attempts >= attempts_allowed {
                    return Err(Stop::Pause {
                        stage: STAGE,
                        reason: FailureReason::ExtentDigestMismatch {
                            extent: index,
                            attempts,
                        },
                    });
                }
            }
            write_at(&mut data, extent.offset_bytes, &buffer)
                .map_err(|error| io(StorageOperation::Write, error))?;
            data.sync_data()
                .map_err(|error| io(StorageOperation::Sync, error))?;
            self.layout
                .journal_append(&journal, index)
                .map_err(&pause)?;
            flight.progress.fetched_extents = flight.progress.fetched_extents.saturating_add(1);
            flight.progress.verified_extents = flight.progress.verified_extents.saturating_add(1);
            flight.verified.insert(index);
        }
        data.sync_all()
            .map_err(|error| io(StorageOperation::Sync, error))
    }

    /// The complete index, next to the temporary representation.
    fn write_index(&self, flight: &Flight, index: &ObjectIndex) -> Result<(), Stop> {
        let pause = storage_pause(ImportStage::CompleteIndex);
        let path = self.layout.staged_object(&flight.key).join(INDEX_FILE);
        self.layout.make_writable(&path).map_err(&pause)?;
        self.layout.write_json_atomic(&path, index).map_err(&pause)
    }

    /// Read-back validation of the temporary representation: index, length, every extent,
    /// the content key, and the class's responsible verifier.
    fn read_back(&self, flight: &Flight, index: &ObjectIndex) -> Result<(), Stop> {
        const STAGE: ImportStage = ImportStage::ReadBackValidation;
        let dir = self.layout.staged_object(&flight.key);
        self.validate_dir(&dir, index).map_err(|failure| {
            use super::state::IntegrityFailure as Problem;
            match failure {
                Problem::Unreadable { failure } => Stop::Pause {
                    stage: STAGE,
                    reason: FailureReason::Storage { failure },
                },
                Problem::IndexMismatch | Problem::MissingData | Problem::LengthMismatch { .. } => {
                    Stop::Pause {
                        stage: STAGE,
                        reason: FailureReason::ReadBackMismatch { extent: None },
                    }
                }
                Problem::ExtentCorrupt { extent } => Stop::Pause {
                    stage: STAGE,
                    reason: FailureReason::ReadBackMismatch {
                        extent: Some(extent),
                    },
                },
                Problem::ContentKeyMismatch { expected, found } => Stop::Fail {
                    stage: STAGE,
                    reason: FailureReason::ContentKeyMismatch { expected, found },
                },
                Problem::VerifierRejected { rejection } => Stop::Fail {
                    stage: STAGE,
                    reason: FailureReason::VerifierRejected { rejection },
                },
                Problem::NoVerifier { class } => Stop::Fail {
                    stage: STAGE,
                    reason: FailureReason::Refused {
                        refusal: ImportRefusal::Trust {
                            refusal: TrustRefusal::NoVerifier { class },
                        },
                    },
                },
                Problem::ManifestInvalid { error } => Stop::Fail {
                    stage: STAGE,
                    reason: FailureReason::Refused {
                        refusal: ImportRefusal::Manifest { error },
                    },
                },
                Problem::TrustWithdrawn { refusal } => Stop::Fail {
                    stage: STAGE,
                    reason: FailureReason::Refused {
                        refusal: ImportRefusal::Trust { refusal },
                    },
                },
            }
        })
    }

    /// Durable commit: the files are synced and made read-only, then the directory is
    /// renamed into the object store. The object is still unpublished.
    fn commit(&mut self, flight: &mut Flight) -> Result<(), Stop> {
        let pause = storage_pause(ImportStage::DurableCommit);
        let staged = self.layout.staged_object(&flight.key);
        for name in [DATA_FILE, INDEX_FILE] {
            let path = staged.join(name);
            self.layout.make_writable(&path).map_err(&pause)?;
            self.layout.sync_file(&path).map_err(&pause)?;
            self.layout.set_read_only(&path).map_err(&pause)?;
        }
        let target = self.layout.object_dir(&flight.object);
        if self.entries.contains_key(&flight.object) {
            // Only a quarantined copy reaches here (failed validation or withdrawn trust):
            // verified bytes of the same content, admitted under the current policy,
            // replace it.
            self.remove_object(flight.object).map_err(&pause)?;
        } else if self.layout.exists(&target) {
            // Committed earlier and never published, and it did not validate.
            self.layout.remove_tree(&target).map_err(&pause)?;
            self.unpublished.remove(&flight.object);
        }
        self.layout.rename(&staged, &target).map_err(&pause)?;
        self.layout
            .sync_dir(&self.layout.objects())
            .map_err(&pause)?;
        let since = self.now();
        self.unpublished.insert(
            flight.object,
            super::state::Unpublished {
                scope: Some(flight.request.scope.clone()),
                length_bytes: flight.request.manifest.true_length_bytes,
                since,
            },
        );
        flight.reserved_bytes = 0;
        Ok(())
    }

    /// Catalog publication: the record is written atomically; from then on the object is
    /// published, and before then it is not.
    fn publish(&mut self, flight: &mut Flight, index: ObjectIndex) -> Result<(), Stop> {
        let pause = storage_pause(ImportStage::CatalogPublication);
        let record = ObjectRecord {
            format: FORMAT_VERSION,
            index,
            source: flight.source,
            trust: flight.trust.clone(),
            metadata: flight.request.metadata.clone(),
            operation: flight.request.operation.clone(),
            execution: flight.request.execution.clone(),
        };
        self.layout
            .write_json_atomic(&self.layout.record(&flight.object), &record)
            .map_err(&pause)?;
        let now = self.now();
        self.unpublished.remove(&flight.object);
        self.entries
            .insert(flight.object, Entry::published(record, now));
        self.refresh_reachability(now);
        self.discard_staging(flight);
        flight.reserved_bytes = 0;
        Ok(())
    }

    /// Validates a committed but unpublished object for this declaration; one that does
    /// not validate is removed, since it was never readable.
    fn adopt_unpublished(&mut self, index: &ObjectIndex) -> Result<bool, Stop> {
        let dir = self.layout.object_dir(&index.object);
        if self.validate_dir(&dir, index).is_ok() {
            return Ok(true);
        }
        self.layout
            .remove_tree(&dir)
            .map_err(storage_pause(ImportStage::ReadBackValidation))?;
        self.unpublished.remove(&index.object);
        Ok(false)
    }
}
