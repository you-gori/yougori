//! The catalog: configuration, the in-memory view of what is published, quota
//! accounting and reopening from the caller's root (S2 CORE-02).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::access::{GrantId, GrantState, LeaseId, LeaseState};
use super::content::{ExtentDigest, ManifestError, ManifestLimits};
use super::identity::{ArtifactClass, ObjectId, RootId, Scope};
use super::import::{Flight, Subscriber};
use super::migrate::{
    migrate, read_layout, read_staging, read_versioned, FormatRefusal, MigrationReport, RecordKind,
    StagingRead, FLIGHT_FILE,
};
use super::provenance::{FailureLog, FailureRecord, StorageFailure, StorageOperation};
use super::store::{
    Layout, ObjectIndex, ObjectRecord, RootRecord, DATA_FILE, FORMAT_VERSION, INDEX_FILE,
    MAX_SMALL_RECORD_BYTES,
};
use super::trust::{
    recheck_trust, ContentDescriptor, ObjectBytes, TrustPolicy, TrustRefusal, VerifierRegistry,
    VerifierRejection,
};
use crate::foundation::ids::{digest, Clock, ContentHasher, ContentKey, Digest, MonotonicTime};

/// Domain naming staging directories whose names are not flight keys.
const STRAY_DOMAIN: &str = "yougori/catalog/stray/v1";

/// Bounds on everything the catalog accepts (line 531: validate bounds before
/// allocating).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CatalogLimits {
    pub max_object_bytes: u64,
    pub max_extent_bytes: u64,
    pub max_extents: u32,
    /// Most objects one import may name as derivation sources and dependencies together.
    pub max_references: u32,
    /// Most deliveries of one extent per drive before the import pauses as resumable.
    pub max_fetch_attempts: u32,
    /// Longest lease a consumer may take or renew at once.
    pub max_lease: Duration,
    pub max_labels: u32,
    pub max_label_bytes: u32,
    pub max_root_objects: u32,
    pub failure_log_capacity: u32,
    /// Finished imports whose status stays available to tickets never cancelled.
    pub max_finished_imports: u32,
}

impl Default for CatalogLimits {
    fn default() -> Self {
        Self {
            max_object_bytes: 1 << 40,
            max_extent_bytes: 64 << 20,
            max_extents: 1 << 20,
            max_references: 4096,
            max_fetch_attempts: 3,
            max_lease: Duration::from_secs(24 * 60 * 60),
            max_labels: 64,
            max_label_bytes: 1024,
            max_root_objects: 1 << 16,
            failure_log_capacity: 1024,
            max_finished_imports: 1024,
        }
    }
}

impl CatalogLimits {
    /// The bounds every import manifest is validated against (line 531).
    pub fn manifest(&self) -> ManifestLimits {
        ManifestLimits {
            max_object_bytes: self.max_object_bytes,
            max_extent_bytes: self.max_extent_bytes,
            max_extents: self.max_extents,
        }
    }

    /// Bound for an index file: the extent table, the references and fixed fields.
    pub(super) fn max_index_bytes(&self) -> u64 {
        (64u64 << 10)
            .saturating_add(u64::from(self.max_extents).saturating_mul(256))
            .saturating_add(u64::from(self.max_references).saturating_mul(80))
    }

    /// Bound for a publication record: an index plus provenance and labels.
    pub(super) fn max_record_bytes(&self) -> u64 {
        self.max_index_bytes().saturating_add(
            u64::from(self.max_labels)
                .saturating_mul(u64::from(self.max_label_bytes).saturating_mul(4)),
        )
    }
}

/// Catalog configuration. Nothing is admitted until it is configured: a scope without a
/// quota stores nothing and a class without a trust policy trusts nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogConfig {
    pub limits: CatalogLimits,
    /// How long an object remains after it becomes both unreachable and unleased
    /// (S2 CORE-02 garbage collection; line 533).
    pub gc_grace: Duration,
    /// Each scope's explicit space budget (line 548; CORE-02 quotas).
    pub quota_bytes: BTreeMap<Scope, u64>,
    /// Each artifact class's own publisher/trust policy (S2 CORE-08).
    pub trust: BTreeMap<ArtifactClass, TrustPolicy>,
}

impl CatalogConfig {
    /// Default limits, no quotas and no trust policies: nothing is admitted until configured.
    pub fn new(gc_grace: Duration) -> Self {
        Self {
            limits: CatalogLimits::default(),
            gc_grace,
            quota_bytes: BTreeMap::new(),
            trust: BTreeMap::new(),
        }
    }

    /// Replaces the limits.
    pub fn with_limits(mut self, limits: CatalogLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Gives `scope` an explicit space budget (line 548).
    pub fn with_quota(mut self, scope: Scope, quota_bytes: u64) -> Self {
        self.quota_bytes.insert(scope, quota_bytes);
        self
    }

    /// Sets `class`'s own publisher/trust policy (S2 CORE-08).
    pub fn with_trust(mut self, class: ArtifactClass, policy: TrustPolicy) -> Self {
        self.trust.insert(class, policy);
        self
    }
}

/// The owner's private description of an object. It is never readable outside the
/// owning scope, with or without a grant (INT-05).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectMetadata {
    pub labels: BTreeMap<String, String>,
}

impl ObjectMetadata {
    /// Metadata without labels.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds or replaces one private label.
    pub fn with_label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.insert(key.into(), value.into());
        self
    }

    pub(super) fn check(&self, limits: &CatalogLimits) -> Result<(), MetadataError> {
        if self.labels.len() as u64 > u64::from(limits.max_labels) {
            return Err(MetadataError::TooManyLabels {
                labels: self.labels.len() as u64,
                max_labels: limits.max_labels,
            });
        }
        for (key, value) in &self.labels {
            if key.is_empty() {
                return Err(MetadataError::EmptyKey);
            }
            let max = limits.max_label_bytes as usize;
            if key.len() > max || value.len() > max {
                return Err(MetadataError::LabelTooLong {
                    max_label_bytes: limits.max_label_bytes,
                });
            }
        }
        Ok(())
    }
}

/// Why private metadata was refused at import.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "error", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum MetadataError {
    TooManyLabels { labels: u64, max_labels: u32 },
    EmptyKey,
    LabelTooLong { max_label_bytes: u32 },
}

crate::foundation::strict_serde::strict_tag!(MetadataError, "error");

impl fmt::Display for MetadataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyLabels { labels, max_labels } => {
                write!(f, "{labels} labels; the limit is {max_labels}")
            }
            Self::EmptyKey => f.write_str("a label has an empty key"),
            Self::LabelTooLong { max_label_bytes } => {
                write!(f, "a label is longer than {max_label_bytes} bytes")
            }
        }
    }
}

/// A scope's storage charge (CORE-02 quotas).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuotaUsage {
    /// `None` when the scope has no explicit budget.
    pub limit_bytes: Option<u64>,
    pub published_bytes: u64,
    /// Reserved by imports in flight before they write anything.
    pub reserved_bytes: u64,
    /// Interrupted staging and committed-but-unpublished objects, until they are resumed
    /// or collected.
    pub unpublished_bytes: u64,
}

impl QuotaUsage {
    /// Everything charged against the budget: published, reserved and unpublished bytes.
    pub fn charged_bytes(&self) -> u64 {
        self.published_bytes
            .saturating_add(self.reserved_bytes)
            .saturating_add(self.unpublished_bytes)
    }
}

/// Why an import's reservation was refused (CORE-02 quotas).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum QuotaRefusal {
    /// The scope has no explicit space budget (line 548), so it stores nothing.
    NoBudget { scope: Scope },
    /// The import would exceed the scope's budget. Nothing is evicted to make room:
    /// `evictable_bytes` is what a separate cache eviction could free, never counting a
    /// user's original (line 552).
    Exceeded {
        scope: Scope,
        limit_bytes: u64,
        charged_bytes: u64,
        requested_bytes: u64,
        evictable_bytes: u64,
    },
}

crate::foundation::strict_serde::strict_tag!(QuotaRefusal, "refusal");

impl QuotaRefusal {
    /// The bytes an import is over its scope's budget by, when a cache eviction could free
    /// any: what [`Catalog::evict_for_import`] must free before the import is admitted again.
    pub fn evictable_shortfall(&self) -> Option<u64> {
        match self {
            Self::Exceeded {
                limit_bytes,
                charged_bytes,
                requested_bytes,
                evictable_bytes,
                ..
            } if *evictable_bytes > 0 => Some(
                charged_bytes
                    .saturating_add(*requested_bytes)
                    .saturating_sub(*limit_bytes),
            ),
            _ => None,
        }
    }
}

impl fmt::Display for QuotaRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoBudget { scope } => write!(
                f,
                "{scope} has no explicit space budget; configure a quota before importing"
            ),
            Self::Exceeded {
                scope,
                limit_bytes,
                charged_bytes,
                requested_bytes,
                evictable_bytes,
            } => write!(
                f,
                "{scope} would hold {charged_bytes} + {requested_bytes} bytes against a budget \
                 of {limit_bytes}; cache eviction could free {evictable_bytes} bytes, or raise \
                 the budget"
            ),
        }
    }
}

impl std::error::Error for QuotaRefusal {}

/// Why a committed object is quarantined: it failed validation, or the current policy no
/// longer accepts the trust basis it was published under (INT-09). A quarantined object
/// is unreadable and reported, and nothing deletes it automatically; a verified, trusted
/// import of the same content replaces it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "integrity", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum IntegrityFailure {
    /// The class's current verifiers or trust policy no longer accept the recorded trust
    /// basis, as when a publisher key is withdrawn (S2 CORE-08).
    TrustWithdrawn {
        refusal: TrustRefusal,
    },
    /// The index on disk differs from the published record.
    IndexMismatch,
    /// The recorded manifest is out of bounds or malformed.
    ManifestInvalid {
        error: ManifestError,
    },
    MissingData,
    LengthMismatch {
        expected_bytes: u64,
        found_bytes: u64,
    },
    ExtentCorrupt {
        extent: u32,
    },
    ContentKeyMismatch {
        expected: ContentKey,
        found: ContentKey,
    },
    VerifierRejected {
        rejection: VerifierRejection,
    },
    NoVerifier {
        class: ArtifactClass,
    },
    Unreadable {
        failure: StorageFailure,
    },
}

crate::foundation::strict_serde::strict_tag!(IntegrityFailure, "integrity");

/// What an owner sees of one of its objects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObjectStatus {
    Published,
    Quarantined {
        reason: IntegrityFailure,
    },
    /// Not published in this scope (whatever another scope holds).
    Absent,
}

/// What reopening found (line 533: nothing unpublished becomes visible).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OpenReport {
    pub published: usize,
    pub quarantined: Vec<(ObjectId, IntegrityFailure)>,
    /// Committed objects without a publication record: never readable; collected after
    /// the grace period unless a resumed import validates and publishes them.
    pub unpublished: Vec<ObjectId>,
    /// Staging directories of interrupted imports: never trusted; a resumed import
    /// re-verifies every extent it reuses.
    pub staging: usize,
    /// Records and roots that could not be read; retained untouched.
    pub unreadable: Vec<StorageFailure>,
    /// Temporary files of interrupted atomic writes, which were never published.
    pub temporaries_removed: usize,
    /// Records in a newer or unknown format: kept untouched and never collected.
    pub refused: Vec<FormatRefusal>,
    /// What the layout migration did on this open.
    pub migration: MigrationReport,
}

#[derive(Debug)]
pub(super) struct Entry {
    pub(super) record: ObjectRecord,
    pub(super) unreachable_since: Option<MonotonicTime>,
    pub(super) last_lease_end: Option<MonotonicTime>,
    pub(super) last_used_at: Option<MonotonicTime>,
    pub(super) quarantine: Option<IntegrityFailure>,
}

impl Entry {
    pub(super) fn published(record: ObjectRecord, now: MonotonicTime) -> Self {
        Self {
            record,
            unreachable_since: Some(now),
            last_lease_end: None,
            last_used_at: None,
            quarantine: None,
        }
    }

    pub(super) fn index(&self) -> &ObjectIndex {
        &self.record.index
    }

    pub(super) fn scope(&self) -> &Scope {
        &self.record.index.scope
    }
}

/// What changing a class's trust policy did (INT-09).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TrustRevision {
    /// Objects whose recorded trust basis the new policy no longer accepts: quarantined
    /// and their leases revoked, never deleted.
    pub quarantined: Vec<ObjectId>,
    /// Objects quarantined only for withdrawn trust that the new policy accepts again.
    pub restored: Vec<ObjectId>,
}

/// A committed object directory without a publication record.
#[derive(Debug)]
pub(super) struct Unpublished {
    pub(super) scope: Option<Scope>,
    pub(super) length_bytes: u64,
    pub(super) since: MonotonicTime,
}

/// A staging directory no import is using.
#[derive(Debug)]
pub(super) struct Remnant {
    pub(super) path: PathBuf,
    pub(super) scope: Option<Scope>,
    pub(super) length_bytes: u64,
    pub(super) since: MonotonicTime,
    /// Its declaration is in a newer or unknown format: never collected.
    pub(super) retained: bool,
}

/// The immutable object catalog (S2 CORE-02) over one root directory the caller owns.
///
/// Only the importer writes committed content; consumers read through leases and
/// read-only handles. All file I/O stays under the root. Grants and leases live only as
/// long as this value: they are not persisted, so a reopened catalog never revives one.
pub struct Catalog {
    pub(super) layout: Layout,
    pub(super) config: CatalogConfig,
    pub(super) verifiers: VerifierRegistry,
    pub(super) clock: Arc<dyn Clock>,
    pub(super) entries: BTreeMap<ObjectId, Entry>,
    pub(super) unpublished: BTreeMap<ObjectId, Unpublished>,
    /// Objects whose records could not be read: never collected.
    pub(super) unclassified: BTreeSet<ObjectId>,
    /// Roots that could not be read: garbage collection is refused while any exist.
    pub(super) unreadable_roots: Vec<StorageFailure>,
    pub(super) roots: BTreeMap<RootId, RootRecord>,
    pub(super) flights: BTreeMap<u64, Flight>,
    pub(super) active: BTreeMap<Digest, u64>,
    pub(super) tickets: BTreeMap<u64, Subscriber>,
    pub(super) remnants: BTreeMap<Digest, Remnant>,
    pub(super) grants: BTreeMap<GrantId, GrantState>,
    pub(super) leases: BTreeMap<LeaseId, LeaseState>,
    pub(super) failures: FailureLog,
    next_number: u64,
}

impl fmt::Debug for Catalog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Catalog")
            .field("layout", &self.layout)
            .field("objects", &self.entries.len())
            .field("roots", &self.roots.len())
            .field("flights", &self.flights.len())
            .finish_non_exhaustive()
    }
}

impl Catalog {
    /// Opens the catalog in `root`, creating its directories. Only records whose identity,
    /// index and data length check out, and whose trust basis the current policy still
    /// accepts, are published; any other is quarantined and reported, an unreadable one is
    /// retained untouched, and unpublished data is never made visible.
    pub fn open(
        root: impl AsRef<Path>,
        config: CatalogConfig,
        verifiers: VerifierRegistry,
        clock: Arc<dyn Clock>,
    ) -> Result<(Self, OpenReport), StorageFailure> {
        let layout = Layout::new(root.as_ref());
        layout.ensure()?;
        let from_format = read_layout(&layout)?;
        let migration = migrate(&layout, from_format, &mut |_| true)?.ok_or_else(|| {
            layout.failure(
                StorageOperation::Format,
                layout.root_path(),
                "the layout migration stopped before it finished",
            )
        })?;
        let failures = FailureLog::new(
            usize::try_from(config.limits.failure_log_capacity).unwrap_or(usize::MAX),
        );
        let mut catalog = Self {
            layout,
            config,
            verifiers,
            clock,
            entries: BTreeMap::new(),
            unpublished: BTreeMap::new(),
            unclassified: BTreeSet::new(),
            unreadable_roots: Vec::new(),
            roots: BTreeMap::new(),
            flights: BTreeMap::new(),
            active: BTreeMap::new(),
            tickets: BTreeMap::new(),
            remnants: BTreeMap::new(),
            grants: BTreeMap::new(),
            leases: BTreeMap::new(),
            failures,
            next_number: 0,
        };
        let now = catalog.clock.now();
        let mut report = OpenReport {
            temporaries_removed: catalog.layout.remove_temporaries()?,
            migration,
            ..OpenReport::default()
        };
        catalog.load_records(&mut report)?;
        catalog.load_unpublished(now, &mut report)?;
        catalog.load_roots(&mut report)?;
        catalog.load_staging(now, &mut report)?;
        catalog.refresh_reachability(now);
        report.published = catalog
            .entries
            .values()
            .filter(|entry| catalog.is_usable(entry))
            .count();
        Ok((catalog, report))
    }

    /// Why `entry` is unusable now: its recorded quarantine, or a trust basis the current
    /// verifiers and policy no longer accept. Every read and decision checks this, so a
    /// withdrawn publisher's objects stop being served at once.
    pub(super) fn quarantine_of(&self, entry: &Entry) -> Option<IntegrityFailure> {
        entry.quarantine.clone().or_else(|| {
            self.trust_lapse(entry)
                .map(|refusal| IntegrityFailure::TrustWithdrawn { refusal })
        })
    }

    pub(super) fn is_usable(&self, entry: &Entry) -> bool {
        entry.quarantine.is_none() && self.trust_lapse(entry).is_none()
    }

    fn trust_lapse(&self, entry: &Entry) -> Option<TrustRefusal> {
        recheck_trust(
            &self.verifiers,
            &self.config.trust,
            entry.scope(),
            entry.index().class,
            &entry.record.trust,
        )
        .err()
    }

    /// Replaces `class`'s trust policy while the catalog runs, as when a publisher key is
    /// withdrawn (INT-09; S2 CORE-08). Every object of the class is re-checked at once:
    /// one whose trust basis the new policy no longer accepts is quarantined and its
    /// leases revoked, so open handles stop reading; one quarantined only for withdrawn
    /// trust that the new policy accepts again is restored. Nothing is deleted.
    pub fn set_trust_policy(&mut self, class: ArtifactClass, policy: TrustPolicy) -> TrustRevision {
        self.config.trust.insert(class, policy);
        let now = self.now();
        let mut revision = TrustRevision::default();
        let objects: Vec<ObjectId> = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.index().class == class)
            .map(|(object, _)| *object)
            .collect();
        for object in objects {
            let Some(entry) = self.entries.get(&object) else {
                continue;
            };
            let (current, lapse) = (entry.quarantine.clone(), self.trust_lapse(entry));
            let next = match (current, lapse) {
                (None, Some(refusal)) => {
                    revision.quarantined.push(object);
                    Some(IntegrityFailure::TrustWithdrawn { refusal })
                }
                (Some(IntegrityFailure::TrustWithdrawn { .. }), None) => {
                    revision.restored.push(object);
                    None
                }
                (Some(IntegrityFailure::TrustWithdrawn { .. }), Some(refusal)) => {
                    Some(IntegrityFailure::TrustWithdrawn { refusal })
                }
                (current, _) => current,
            };
            if let Some(entry) = self.entries.get_mut(&object) {
                entry.quarantine = next;
            }
            if revision.quarantined.last() == Some(&object) {
                self.revoke_leases(|lease| lease.object == object, now);
            }
        }
        revision
    }

    fn load_records(&mut self, report: &mut OpenReport) -> Result<(), StorageFailure> {
        let now = self.clock.now();
        for listed in self.layout.list(&self.layout.records())? {
            let Some(object) = listed.name.strip_suffix(".json").and_then(parse_object) else {
                continue;
            };
            if listed.is_dir {
                continue;
            }
            let record = match read_versioned::<ObjectRecord>(
                &self.layout,
                &listed.path,
                self.config.limits.max_record_bytes(),
                RecordKind::ObjectRecord,
                FORMAT_VERSION,
            ) {
                Ok(Ok(record)) => record,
                Ok(Err(refused)) => {
                    report.refused.push(refused);
                    self.unclassified.insert(object);
                    continue;
                }
                Err(failure) => {
                    report.unreadable.push(failure);
                    self.unclassified.insert(object);
                    continue;
                }
            };
            if record.format != FORMAT_VERSION
                || record.index.object != object
                || !record.index.identity_holds()
            {
                report.unreadable.push(self.layout.failure(
                    StorageOperation::Parse,
                    &listed.path,
                    "the record's identity does not match its scope, class and content key",
                ));
                self.unclassified.insert(object);
                continue;
            }
            let mut entry = Entry::published(record, now);
            entry.quarantine = self
                .check_committed(entry.index())
                .or_else(|| self.quarantine_of(&entry));
            if let Some(reason) = &entry.quarantine {
                report.quarantined.push((object, reason.clone()));
            }
            self.entries.insert(object, entry);
        }
        Ok(())
    }

    /// The cheap checks at open: manifest bounds, the index file and the data length.
    /// [`Catalog::verify_object`] re-hashes everything.
    fn check_committed(&self, index: &ObjectIndex) -> Option<IntegrityFailure> {
        if let Err(error) = index.manifest.validate(&self.config.limits.manifest()) {
            return Some(IntegrityFailure::ManifestInvalid { error });
        }
        let dir = self.layout.object_dir(&index.object);
        let Some(found_bytes) = self.layout.file_len(&dir.join(DATA_FILE)) else {
            return Some(IntegrityFailure::MissingData);
        };
        match read_versioned::<ObjectIndex>(
            &self.layout,
            &dir.join(INDEX_FILE),
            self.config.limits.max_index_bytes(),
            RecordKind::ObjectIndex,
            FORMAT_VERSION,
        ) {
            Ok(Ok(on_disk)) if on_disk == *index && on_disk.digest() == index.digest() => {}
            Ok(Ok(_)) => return Some(IntegrityFailure::IndexMismatch),
            Ok(Err(refused)) => {
                return Some(IntegrityFailure::Unreadable {
                    failure: refused.to_failure(),
                })
            }
            Err(failure) => return Some(IntegrityFailure::Unreadable { failure }),
        }
        if found_bytes != index.length_bytes() {
            return Some(IntegrityFailure::LengthMismatch {
                expected_bytes: index.length_bytes(),
                found_bytes,
            });
        }
        None
    }

    fn load_unpublished(
        &mut self,
        now: MonotonicTime,
        report: &mut OpenReport,
    ) -> Result<(), StorageFailure> {
        for listed in self.layout.list(&self.layout.objects())? {
            let Some(object) = parse_object(&listed.name) else {
                continue;
            };
            if !listed.is_dir
                || self.entries.contains_key(&object)
                || self.unclassified.contains(&object)
            {
                continue;
            }
            let scope = match read_versioned::<ObjectIndex>(
                &self.layout,
                &listed.path.join(INDEX_FILE),
                self.config.limits.max_index_bytes(),
                RecordKind::ObjectIndex,
                FORMAT_VERSION,
            ) {
                Ok(Ok(index)) => Some(index)
                    .filter(|index| index.object == object && index.identity_holds())
                    .map(|index| index.scope),
                Ok(Err(refused)) => {
                    // Committed by a newer build: kept, never collected.
                    report.refused.push(refused);
                    self.unclassified.insert(object);
                    continue;
                }
                Err(_) => None,
            };
            let length_bytes = self
                .layout
                .file_len(&listed.path.join(DATA_FILE))
                .unwrap_or(0);
            self.unpublished.insert(
                object,
                Unpublished {
                    scope,
                    length_bytes,
                    since: now,
                },
            );
            report.unpublished.push(object);
        }
        Ok(())
    }

    fn load_roots(&mut self, report: &mut OpenReport) -> Result<(), StorageFailure> {
        for listed in self.layout.list(&self.layout.roots())? {
            let Some(name) = listed.name.strip_suffix(".json") else {
                continue;
            };
            if listed.is_dir {
                continue;
            }
            let loaded = match read_versioned::<RootRecord>(
                &self.layout,
                &listed.path,
                MAX_SMALL_RECORD_BYTES,
                RecordKind::Root,
                FORMAT_VERSION,
            ) {
                Ok(Ok(root)) if root.id().to_string() == name => Ok(root),
                Ok(Ok(_)) => Err(self.layout.failure(
                    StorageOperation::Parse,
                    &listed.path,
                    "the root's identity does not match its scope, kind and name",
                )),
                Ok(Err(refused)) => {
                    // Reachability is unknown while a root cannot be read, so collection
                    // stays refused.
                    let failure = refused.to_failure();
                    report.refused.push(refused);
                    self.unreadable_roots.push(failure);
                    continue;
                }
                Err(failure) => Err(failure),
            };
            match loaded {
                Ok(root) => {
                    self.roots.insert(root.id(), root);
                }
                Err(failure) => {
                    report.unreadable.push(failure.clone());
                    self.unreadable_roots.push(failure);
                }
            }
        }
        Ok(())
    }

    fn load_staging(
        &mut self,
        now: MonotonicTime,
        report: &mut OpenReport,
    ) -> Result<(), StorageFailure> {
        for listed in self.layout.list(&self.layout.staging())? {
            let key = Digest::from_hex(&listed.name)
                .unwrap_or_else(|_| digest(STRAY_DOMAIN, &[listed.name.as_bytes()]));
            let (scope, retained) = match read_staging(&self.layout, &listed.path.join(FLIGHT_FILE))
            {
                Ok(StagingRead::Refused(refused)) => {
                    // A newer build's import: kept, never collected.
                    report.refused.push(refused);
                    (None, true)
                }
                Ok(read) => {
                    let named = match &read {
                        StagingRead::Current(record)
                        | StagingRead::Unversioned(record)
                        | StagingRead::ParentKeyed { record, .. } => record.flight == key,
                        StagingRead::Refused(_) => false,
                    };
                    (read.scope().cloned().filter(|_| named), false)
                }
                Err(_) => (None, false),
            };
            let length_bytes = self
                .layout
                .file_len(&listed.path.join("object").join(DATA_FILE))
                .unwrap_or(0);
            self.remnants.insert(
                key,
                Remnant {
                    path: listed.path,
                    scope,
                    length_bytes,
                    since: now,
                    retained,
                },
            );
            report.staging += 1;
        }
        Ok(())
    }

    pub(super) fn next_number(&mut self) -> u64 {
        self.next_number = self.next_number.wrapping_add(1);
        self.next_number
    }

    pub(super) fn now(&self) -> MonotonicTime {
        self.clock.now()
    }

    /// Objects reachable from `roots` through dependency edges (line 527 "dependency
    /// roots").
    pub(super) fn reachable_from<'a>(
        &self,
        roots: impl Iterator<Item = &'a RootRecord>,
    ) -> BTreeSet<ObjectId> {
        let mut reachable = BTreeSet::new();
        let mut pending: Vec<ObjectId> = roots
            .flat_map(|root| root.objects.iter().copied())
            .collect();
        while let Some(object) = pending.pop() {
            if !reachable.insert(object) {
                continue;
            }
            if let Some(entry) = self.entries.get(&object) {
                pending.extend(entry.index().depends_on.iter().copied());
            }
        }
        reachable
    }

    pub(super) fn reachable(&self) -> BTreeSet<ObjectId> {
        self.reachable_from(self.roots.values())
    }

    /// Stamps when each object became unreachable; reachable objects lose the stamp.
    pub(super) fn refresh_reachability(&mut self, now: MonotonicTime) {
        let reachable = self.reachable();
        for (object, entry) in &mut self.entries {
            if reachable.contains(object) {
                entry.unreachable_since = None;
            } else if entry.unreachable_since.is_none() {
                entry.unreachable_since = Some(now);
            }
        }
    }

    /// Re-reads a committed or staged object directory against `expected`: the index, the
    /// length, every extent digest, the content key, and the class verifier.
    pub(super) fn validate_dir(
        &self,
        dir: &Path,
        expected: &ObjectIndex,
    ) -> Result<(), IntegrityFailure> {
        let unreadable = |failure| IntegrityFailure::Unreadable { failure };
        let on_disk: ObjectIndex = read_versioned(
            &self.layout,
            &dir.join(INDEX_FILE),
            self.config.limits.max_index_bytes(),
            RecordKind::ObjectIndex,
            FORMAT_VERSION,
        )
        .map_err(unreadable)?
        .map_err(|refused| unreadable(refused.to_failure()))?;
        if on_disk != *expected {
            return Err(IntegrityFailure::IndexMismatch);
        }
        let manifest = &expected.manifest;
        let data_path = dir.join(DATA_FILE);
        let open = || {
            ObjectBytes::open(&data_path).map_err(|error| {
                unreadable(
                    self.layout
                        .failure(StorageOperation::Open, &data_path, error),
                )
            })
        };
        let mut bytes = open()?;
        if bytes.length_bytes() != manifest.true_length_bytes {
            return Err(IntegrityFailure::LengthMismatch {
                expected_bytes: manifest.true_length_bytes,
                found_bytes: bytes.length_bytes(),
            });
        }
        let mut content = ContentHasher::new(manifest.true_length_bytes);
        let mut buffer = Vec::new();
        for (position, extent) in manifest.extents.iter().enumerate() {
            let index = u32::try_from(position).unwrap_or(u32::MAX);
            let length = usize::try_from(extent.length_bytes)
                .map_err(|_| IntegrityFailure::ExtentCorrupt { extent: index })?;
            buffer.resize(length, 0);
            bytes
                .read_exact_at(extent.offset_bytes, &mut buffer)
                .map_err(|error| {
                    unreadable(
                        self.layout
                            .failure(StorageOperation::Read, &data_path, error),
                    )
                })?;
            if ExtentDigest::of(&buffer) != extent.digest {
                return Err(IntegrityFailure::ExtentCorrupt { extent: index });
            }
            content
                .update(&buffer)
                .map_err(|_| IntegrityFailure::ExtentCorrupt { extent: index })?;
        }
        let found = content
            .finish()
            .map_err(|_| IntegrityFailure::LengthMismatch {
                expected_bytes: manifest.true_length_bytes,
                found_bytes: bytes.length_bytes(),
            })?;
        if found != manifest.content_key {
            return Err(IntegrityFailure::ContentKeyMismatch {
                expected: manifest.content_key,
                found,
            });
        }
        let verifier = self
            .verifiers
            .get(expected.class)
            .ok_or(IntegrityFailure::NoVerifier {
                class: expected.class,
            })?;
        let descriptor = ContentDescriptor {
            scope: expected.scope.clone(),
            class: expected.class,
            content_key: manifest.content_key,
            length_bytes: manifest.true_length_bytes,
            manifest_digest: manifest.digest(),
        };
        let mut bytes = open()?;
        verifier
            .validate(&descriptor, &mut bytes)
            .map_err(|rejection| IntegrityFailure::VerifierRejected { rejection })
    }

    /// The scope's storage charge.
    pub fn quota_usage(&self, scope: &Scope) -> QuotaUsage {
        let in_scope = |owner: Option<&Scope>| owner == Some(scope);
        let published_bytes = self
            .entries
            .values()
            .filter(|entry| entry.scope() == scope)
            .fold(0u64, |sum, entry| {
                sum.saturating_add(entry.index().length_bytes())
            });
        let reserved_bytes = self
            .flights
            .values()
            .filter(|flight| flight.request.scope == *scope)
            .fold(0u64, |sum, flight| {
                sum.saturating_add(flight.reserved_bytes)
            });
        let unpublished_bytes = self
            .unpublished
            .values()
            .filter(|unpublished| in_scope(unpublished.scope.as_ref()))
            .map(|unpublished| unpublished.length_bytes)
            .chain(
                self.remnants
                    .values()
                    .filter(|remnant| in_scope(remnant.scope.as_ref()))
                    .map(|remnant| remnant.length_bytes),
            )
            .fold(0u64, u64::saturating_add);
        QuotaUsage {
            limit_bytes: self.config.quota_bytes.get(scope).copied(),
            published_bytes,
            reserved_bytes,
            unpublished_bytes,
        }
    }

    /// Reserves `requested_bytes` in `scope`, of which `already_charged_bytes` are already
    /// counted (staging a resumed import takes over). Refuses rather than evicting.
    pub(super) fn reserve(
        &self,
        scope: &Scope,
        requested_bytes: u64,
        already_charged_bytes: u64,
    ) -> Result<(), QuotaRefusal> {
        let limit_bytes =
            *self
                .config
                .quota_bytes
                .get(scope)
                .ok_or_else(|| QuotaRefusal::NoBudget {
                    scope: scope.clone(),
                })?;
        let charged_bytes = self
            .quota_usage(scope)
            .charged_bytes()
            .saturating_sub(already_charged_bytes);
        let fits = charged_bytes
            .checked_add(requested_bytes)
            .is_some_and(|total| total <= limit_bytes);
        if !fits {
            return Err(QuotaRefusal::Exceeded {
                scope: scope.clone(),
                limit_bytes,
                charged_bytes,
                requested_bytes,
                evictable_bytes: self.evictable_bytes(scope),
            });
        }
        Ok(())
    }

    /// The scope's objects that are published and healthy, or quarantined.
    pub fn objects(&self, scope: &Scope) -> Vec<ObjectId> {
        self.entries
            .iter()
            .filter(|(_, entry)| entry.scope() == scope)
            .map(|(object, _)| *object)
            .collect()
    }

    /// The published object of `class` with `content` in the reader's own scope. Equal
    /// content in another scope is invisible here (S3.3).
    pub fn find(
        &self,
        scope: &Scope,
        class: ArtifactClass,
        content: ContentKey,
    ) -> Option<ObjectId> {
        let object = ObjectId::new(scope, class, content);
        self.entries
            .get(&object)
            .filter(|entry| entry.scope() == scope && self.is_usable(entry))
            .map(|_| object)
    }

    /// The object's status as its owner sees it; [`ObjectStatus::Absent`] for any object
    /// outside `owner`'s scope.
    pub fn status(&self, owner: &Scope, object: ObjectId) -> ObjectStatus {
        match self
            .entries
            .get(&object)
            .filter(|entry| entry.scope() == owner)
        {
            None => ObjectStatus::Absent,
            Some(entry) => match self.quarantine_of(entry) {
                None => ObjectStatus::Published,
                Some(reason) => ObjectStatus::Quarantined { reason },
            },
        }
    }

    /// The configuration in force: the one the catalog was opened with, as revised by
    /// [`Catalog::set_trust_policy`].
    pub fn config(&self) -> &CatalogConfig {
        &self.config
    }

    /// Every failure provenance record, oldest first (S2 CORE-08). This is the host's
    /// complete log across scopes; show a tenant only [`Catalog::failures_in`].
    pub fn failures(&self) -> impl Iterator<Item = &FailureRecord> {
        self.failures.records()
    }

    /// The failure records of one scope's imports. Another scope's records, which name
    /// its sources and objects, never appear (INT-05).
    pub fn failures_in<'a>(&'a self, scope: &'a Scope) -> impl Iterator<Item = &'a FailureRecord> {
        self.failures
            .records()
            .filter(move |record| record.scope == *scope)
    }

    /// Records dropped because the log was full.
    pub fn dropped_failures(&self) -> u64 {
        self.failures.dropped()
    }
}

fn parse_object(hex: &str) -> Option<ObjectId> {
    Digest::from_hex(hex).ok().map(ObjectId::from_digest)
}
