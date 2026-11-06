//! Roots, garbage collection, cache eviction and the three delete actions (S2 CORE-02
//! leases and garbage collection; GPU part §3.3, line 533; GPU part §3.4, lines 548–552).
//!
//! - Roots keep objects reachable, and dependencies keep what they need reachable.
//! - Garbage collection removes only prepared representations that are unreachable,
//!   unleased and not quarantined, and only once the grace period has passed since they
//!   became garbage. It never removes a user's original, so deleting a local model never
//!   ends in deleting one, and it never removes a quarantined object.
//! - Cache eviction removes only prepared representations that are unleased, trusted,
//!   still reconstructible and needed by no other object. It never removes an original.
//! - Local model deletion removes a model's root and nothing else. Source-file deletion,
//!   on explicit request, is the only action that deletes an original (line 552).

use std::collections::BTreeSet;
use std::fmt;

use super::identity::{ObjectId, ObjectRole, RootId, RootKind, RootName, Scope};
use super::provenance::StorageFailure;
use super::state::{Catalog, IntegrityFailure, Unpublished};
use super::store::{RootRecord, FORMAT_VERSION};
use super::trust::recheck_trust;
use crate::foundation::ids::{Digest, MonotonicTime};

/// A root as its owner sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootView {
    pub id: RootId,
    pub kind: RootKind,
    pub name: RootName,
    pub objects: BTreeSet<ObjectId>,
}

/// Why a root was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RootRefusal {
    /// A root holds only its own scope's published objects; another scope's object is
    /// refused the same way as a missing one.
    NotInScope {
        object: ObjectId,
    },
    /// A source-file root holds only originals.
    NotAnOriginal {
        object: ObjectId,
    },
    /// Dropping an original from a source-file root is source-file deletion, a separate
    /// action (line 552).
    WouldDropOriginals {
        objects: BTreeSet<ObjectId>,
    },
    TooManyObjects {
        objects: u64,
        max_root_objects: u32,
    },
    Storage {
        failure: StorageFailure,
    },
}

impl fmt::Display for RootRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInScope { object } => write!(f, "{object} is not published in this scope"),
            Self::NotAnOriginal { object } => {
                write!(
                    f,
                    "{object} is not an original; a source-file root holds originals"
                )
            }
            Self::WouldDropOriginals { objects } => write!(
                f,
                "the root would drop {} original(s); use source-file deletion",
                objects.len()
            ),
            Self::TooManyObjects {
                objects,
                max_root_objects,
            } => write!(
                f,
                "{objects} objects; a root holds at most {max_root_objects}"
            ),
            Self::Storage { failure } => failure.fmt(f),
        }
    }
}

impl std::error::Error for RootRefusal {}

/// What one collection did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GcReport {
    pub removed: Vec<ObjectId>,
    pub removed_bytes: u64,
    /// Unreachable originals: never collected; only source-file deletion removes one
    /// (line 552).
    pub kept_originals: Vec<ObjectId>,
    /// Unreachable but quarantined: reported, never collected.
    pub kept_quarantined: Vec<ObjectId>,
    /// Unreachable but leased.
    pub kept_leased: Vec<ObjectId>,
    /// Unreachable and unleased, but within the grace period.
    pub kept_in_grace: Vec<ObjectId>,
    /// Committed objects never published, removed after the grace period.
    pub removed_unpublished: Vec<ObjectId>,
    /// Staging directories of abandoned imports, removed after the grace period.
    pub removed_staging: usize,
}

/// Why a collection was refused or stopped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GcRefusal {
    /// Some roots could not be read, so reachability is unknown; nothing is collected.
    UnreadableRoots {
        failures: Vec<StorageFailure>,
    },
    Storage {
        failure: StorageFailure,
    },
}

impl fmt::Display for GcRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnreadableRoots { failures } => write!(
                f,
                "{} root record(s) could not be read; nothing is collected until they are \
                 repaired",
                failures.len()
            ),
            Self::Storage { failure } => failure.fmt(f),
        }
    }
}

impl std::error::Error for GcRefusal {}

/// A prepared representation cache eviction may remove.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvictionCandidate {
    pub object: ObjectId,
    pub length_bytes: u64,
    pub last_used_at: Option<MonotonicTime>,
}

/// What a cache eviction removed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CacheEviction {
    pub evicted: Vec<ObjectId>,
    pub freed_bytes: u64,
}

/// Why [`Catalog::evict_for_import`] made no room; nothing was evicted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImportEvictionRefusal {
    /// The prepared representations cache eviction may remove free less than is needed.
    Insufficient {
        freeable_bytes: u64,
        needed_bytes: u64,
    },
    /// The catalog refused the eviction it chose.
    Refused(EvictionRefusal),
}

impl fmt::Display for ImportEvictionRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Insufficient {
                freeable_bytes,
                needed_bytes,
            } => write!(
                f,
                "the evictable prepared representations free {freeable_bytes} bytes; \
                 {needed_bytes} are needed"
            ),
            Self::Refused(refusal) => refusal.fmt(f),
        }
    }
}

impl std::error::Error for ImportEvictionRefusal {}

/// Why a cache eviction was refused; a refused eviction removes nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvictionRefusal {
    NotInScope {
        object: ObjectId,
    },
    /// A user's original is never evicted to meet a budget (line 552).
    UserOriginal {
        object: ObjectId,
    },
    Leased {
        object: ObjectId,
    },
    /// Quarantined objects are kept for inspection, never evicted.
    Quarantined {
        object: ObjectId,
    },
    /// Not every object it was derived from is still published and usable, so it is no
    /// longer a reconstructible copy.
    NotReconstructible {
        object: ObjectId,
        missing: BTreeSet<ObjectId>,
    },
    /// Another published object depends on it.
    Required {
        object: ObjectId,
        by: ObjectId,
    },
    Storage {
        failure: StorageFailure,
    },
}

impl fmt::Display for EvictionRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInScope { object } => write!(f, "{object} is not published in this scope"),
            Self::UserOriginal { object } => write!(
                f,
                "{object} is a user's original; cache eviction never deletes one"
            ),
            Self::Leased { object } => write!(f, "{object} is leased"),
            Self::Quarantined { object } => {
                write!(f, "{object} is quarantined; quarantined objects are kept")
            }
            Self::NotReconstructible { object, missing } => write!(
                f,
                "{object} can no longer be reconstructed: {} source object(s) are gone",
                missing.len()
            ),
            Self::Required { object, by } => write!(f, "{by} depends on {object}"),
            Self::Storage { failure } => failure.fmt(f),
        }
    }
}

impl std::error::Error for EvictionRefusal {}

/// What local model deletion did: removed the model's root. No bytes are deleted by it.
/// Of the objects it no longer keeps reachable, prepared representations are collected
/// after the grace period; originals stay until source-file deletion (line 552).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalModelDeletion {
    pub root: RootId,
    pub now_unreachable: Vec<ObjectId>,
}

/// What a source-file deletion names (line 552).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceFileTarget {
    /// A source-file root, and every original it holds.
    Root(RootName),
    /// One original that no root holds, such as one a deleted local model left behind.
    Original(ObjectId),
}

/// What source-file deletion did: deleted the originals, and removed the source-file root
/// when it named one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceFileDeletion {
    pub root: Option<RootId>,
    pub deleted: Vec<ObjectId>,
    pub freed_bytes: u64,
}

/// What keeps an object that a deletion would remove.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Holder {
    Lease,
    Root { root: RootId },
    Dependent { object: ObjectId },
}

/// Why a deletion was refused; a refused deletion removes nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeleteRefusal {
    NoSuchRoot {
        kind: RootKind,
        name: RootName,
    },
    /// No such object in this scope; another scope's object is refused the same way.
    NoSuchOriginal {
        object: ObjectId,
    },
    /// A prepared representation is not a source file; eviction and collection remove it.
    NotAnOriginal {
        object: ObjectId,
    },
    InUse {
        object: ObjectId,
        holder: Holder,
    },
    Storage {
        failure: StorageFailure,
    },
}

impl fmt::Display for DeleteRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSuchRoot { kind, name } => write!(f, "no {} root named {name}", kind.tag()),
            Self::NoSuchOriginal { object } => {
                write!(f, "{object} is not published in this scope")
            }
            Self::NotAnOriginal { object } => write!(
                f,
                "{object} is a prepared representation, not a source file"
            ),
            Self::InUse { object, holder } => write!(f, "{object} is still in use: {holder:?}"),
            Self::Storage { failure } => failure.fmt(f),
        }
    }
}

impl std::error::Error for DeleteRefusal {}

/// Why verification could not run or failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// Only the owning scope verifies; another scope's object is refused like a missing
    /// one.
    NotOwner { object: ObjectId },
    /// Verification failed and the object is now quarantined.
    Quarantined { reason: IntegrityFailure },
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotOwner { object } => write!(f, "{object} is not published in this scope"),
            Self::Quarantined { reason } => write!(f, "verification failed: {reason:?}"),
        }
    }
}

impl std::error::Error for VerifyError {}

impl Catalog {
    /// Creates or replaces a root of `scope`. A root holds only the scope's own published
    /// objects; a source-file root holds only originals and can never drop one, because
    /// that is source-file deletion.
    pub fn set_root(
        &mut self,
        scope: &Scope,
        kind: RootKind,
        name: RootName,
        objects: BTreeSet<ObjectId>,
    ) -> Result<RootId, RootRefusal> {
        let max_root_objects = self.config.limits.max_root_objects;
        if objects.len() as u64 > u64::from(max_root_objects) {
            return Err(RootRefusal::TooManyObjects {
                objects: objects.len() as u64,
                max_root_objects,
            });
        }
        for object in &objects {
            let entry = self
                .entries
                .get(object)
                .filter(|entry| entry.scope() == scope)
                .ok_or(RootRefusal::NotInScope { object: *object })?;
            if kind == RootKind::SourceFile && !entry.index().role.is_original() {
                return Err(RootRefusal::NotAnOriginal { object: *object });
            }
        }
        let record = RootRecord {
            format: FORMAT_VERSION,
            scope: scope.clone(),
            kind,
            name,
            objects,
        };
        let id = record.id();
        if kind == RootKind::SourceFile {
            if let Some(existing) = self.roots.get(&id) {
                let dropped: BTreeSet<ObjectId> = existing
                    .objects
                    .difference(&record.objects)
                    .copied()
                    .collect();
                if !dropped.is_empty() {
                    return Err(RootRefusal::WouldDropOriginals { objects: dropped });
                }
            }
        }
        self.layout
            .write_json_atomic(&self.layout.root_record(&id), &record)
            .map_err(|failure| RootRefusal::Storage { failure })?;
        self.roots.insert(id, record);
        let now = self.now();
        self.refresh_reachability(now);
        Ok(id)
    }

    /// The scope's roots.
    pub fn roots(&self, scope: &Scope) -> Vec<RootView> {
        self.roots
            .iter()
            .filter(|(_, root)| root.scope == *scope)
            .map(|(id, root)| RootView {
                id: *id,
                kind: root.kind,
                name: root.name.clone(),
                objects: root.objects.clone(),
            })
            .collect()
    }

    /// Removes prepared representations that are unreachable, unleased and not
    /// quarantined once the grace period has passed since they became garbage (CORE-02;
    /// line 533), then unpublished commits and abandoned staging past the grace period.
    /// Originals and quarantined objects are reported and kept: only source-file deletion
    /// removes an original (line 552). Refused while any root is unreadable.
    pub fn collect_garbage(&mut self) -> Result<GcReport, GcRefusal> {
        if !self.unreadable_roots.is_empty() {
            return Err(GcRefusal::UnreadableRoots {
                failures: self.unreadable_roots.clone(),
            });
        }
        let storage = |failure| GcRefusal::Storage { failure };
        let now = self.now();
        let grace = self.config.gc_grace;
        self.expire_leases(now);
        self.refresh_reachability(now);
        let leased = self.leased_objects(now);
        let mut report = GcReport::default();

        let unreachable: Vec<(ObjectId, MonotonicTime, bool, bool)> = self
            .entries
            .iter()
            .filter_map(|(object, entry)| {
                entry.unreachable_since.map(|since| {
                    let garbage_since =
                        entry.last_lease_end.map_or(since, |ended| since.max(ended));
                    (
                        *object,
                        garbage_since,
                        entry.index().role.is_original(),
                        !self.is_usable(entry),
                    )
                })
            })
            .collect();
        for (object, garbage_since, original, quarantined) in unreachable {
            if original {
                report.kept_originals.push(object);
            } else if quarantined {
                report.kept_quarantined.push(object);
            } else if leased.contains(&object) {
                report.kept_leased.push(object);
            } else if now < garbage_since.saturating_add(grace) {
                report.kept_in_grace.push(object);
            } else {
                let freed = self.remove_object(object).map_err(storage)?;
                report.removed.push(object);
                report.removed_bytes = report.removed_bytes.saturating_add(freed);
            }
        }

        let due: Vec<ObjectId> = self
            .unpublished
            .iter()
            .filter(|(object, unpublished)| {
                now >= unpublished.since.saturating_add(grace)
                    && !self
                        .flights
                        .values()
                        .any(|flight| flight.object == **object && flight.is_pending())
            })
            .map(|(object, _)| *object)
            .collect();
        for object in due {
            self.layout
                .remove_tree(&self.layout.object_dir(&object))
                .map_err(storage)?;
            self.unpublished.remove(&object);
            report.removed_unpublished.push(object);
        }

        let due: Vec<Digest> = self
            .remnants
            .iter()
            .filter(|(key, remnant)| {
                !remnant.retained
                    && !self.active.contains_key(*key)
                    && now >= remnant.since.saturating_add(grace)
            })
            .map(|(key, _)| *key)
            .collect();
        for key in due {
            if let Some(remnant) = self.remnants.remove(&key) {
                self.layout.remove_tree(&remnant.path).map_err(storage)?;
                report.removed_staging += 1;
            }
        }
        self.refresh_reachability(now);
        Ok(report)
    }

    fn eviction_check(
        &self,
        scope: &Scope,
        object: ObjectId,
        leased: &BTreeSet<ObjectId>,
    ) -> Result<u64, EvictionRefusal> {
        let entry = self
            .entries
            .get(&object)
            .filter(|entry| entry.scope() == scope)
            .ok_or(EvictionRefusal::NotInScope { object })?;
        let ObjectRole::Prepared { derived_from } = &entry.index().role else {
            return Err(EvictionRefusal::UserOriginal { object });
        };
        if !self.is_usable(entry) {
            return Err(EvictionRefusal::Quarantined { object });
        }
        if leased.contains(&object) {
            return Err(EvictionRefusal::Leased { object });
        }
        let missing: BTreeSet<ObjectId> = derived_from
            .iter()
            .filter(|source| {
                !self
                    .entries
                    .get(source)
                    .is_some_and(|source| source.scope() == scope && self.is_usable(source))
            })
            .copied()
            .collect();
        if !missing.is_empty() {
            return Err(EvictionRefusal::NotReconstructible { object, missing });
        }
        if let Some((by, _)) = self
            .entries
            .iter()
            .find(|(other, entry)| **other != object && entry.index().depends_on.contains(&object))
        {
            return Err(EvictionRefusal::Required { object, by: *by });
        }
        Ok(entry.index().length_bytes())
    }

    /// The scope's prepared representations that cache eviction may remove now, least
    /// recently used first. Originals never appear.
    pub fn eviction_candidates(&self, scope: &Scope) -> Vec<EvictionCandidate> {
        let leased = self.leased_objects(self.now());
        let mut candidates: Vec<EvictionCandidate> = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.scope() == scope)
            .filter_map(|(object, entry)| {
                self.eviction_check(scope, *object, &leased)
                    .ok()
                    .map(|length_bytes| EvictionCandidate {
                        object: *object,
                        length_bytes,
                        last_used_at: entry.last_used_at,
                    })
            })
            .collect();
        candidates.sort_by_key(|candidate| (candidate.last_used_at, candidate.object));
        candidates
    }

    pub(super) fn evictable_bytes(&self, scope: &Scope) -> u64 {
        self.eviction_candidates(scope)
            .iter()
            .fold(0u64, |sum, candidate| {
                sum.saturating_add(candidate.length_bytes)
            })
    }

    /// Cache eviction: removes the chosen prepared representations, or refuses and
    /// removes nothing. A retention policy chooses; the catalog enforces that an original,
    /// a quarantined or leased object, a no longer reconstructible copy and a dependency
    /// are never evicted.
    pub fn evict_cache(
        &mut self,
        scope: &Scope,
        objects: &[ObjectId],
    ) -> Result<CacheEviction, EvictionRefusal> {
        let now = self.now();
        self.expire_leases(now);
        let leased = self.leased_objects(now);
        let chosen: BTreeSet<ObjectId> = objects.iter().copied().collect();
        for object in &chosen {
            self.eviction_check(scope, *object, &leased)?;
        }
        let mut eviction = CacheEviction::default();
        for object in chosen {
            let freed = self
                .remove_object(object)
                .map_err(|failure| EvictionRefusal::Storage { failure })?;
            eviction.evicted.push(object);
            eviction.freed_bytes = eviction.freed_bytes.saturating_add(freed);
        }
        self.refresh_reachability(now);
        Ok(eviction)
    }

    /// Cache eviction for an import `needed_bytes` over `scope`'s budget: the least recently
    /// used prepared representations [`Self::eviction_candidates`] lists, as many as free the
    /// bytes needed and no more, removed through [`Self::evict_cache`]. Originals, leased
    /// objects and dependencies are never candidates, so a user's model is never deleted for
    /// a budget. Refused, removing nothing, when the candidates do not free enough.
    pub fn evict_for_import(
        &mut self,
        scope: &Scope,
        needed_bytes: u64,
    ) -> Result<CacheEviction, ImportEvictionRefusal> {
        let mut chosen = Vec::new();
        let mut freed = 0u64;
        for candidate in self.eviction_candidates(scope) {
            if freed >= needed_bytes {
                break;
            }
            freed = freed.saturating_add(candidate.length_bytes);
            chosen.push(candidate.object);
        }
        if freed < needed_bytes {
            return Err(ImportEvictionRefusal::Insufficient {
                freeable_bytes: freed,
                needed_bytes,
            });
        }
        self.evict_cache(scope, &chosen)
            .map_err(ImportEvictionRefusal::Refused)
    }

    /// Local model deletion: removes the model's root and nothing else. No bytes are
    /// deleted here, and the originals it held stay until source-file deletion (line 552).
    pub fn delete_local_model(
        &mut self,
        scope: &Scope,
        name: &RootName,
    ) -> Result<LocalModelDeletion, DeleteRefusal> {
        let id = RootId::new(scope, RootKind::LocalModel, name);
        if !self.roots.contains_key(&id) {
            return Err(DeleteRefusal::NoSuchRoot {
                kind: RootKind::LocalModel,
                name: name.clone(),
            });
        }
        self.layout
            .remove_file_if_exists(&self.layout.root_record(&id))
            .map_err(|failure| DeleteRefusal::Storage { failure })?;
        let before = self.reachable();
        self.roots.remove(&id);
        let after = self.reachable();
        let now = self.now();
        self.refresh_reachability(now);
        let now_unreachable = before
            .difference(&after)
            .filter(|object| self.entries.contains_key(object))
            .copied()
            .collect();
        Ok(LocalModelDeletion {
            root: id,
            now_unreachable,
        })
    }

    /// Source-file deletion, on the user's explicit request: the only action that deletes
    /// an original (line 552). [`SourceFileTarget::Root`] removes a source-file root and
    /// deletes the originals it held; [`SourceFileTarget::Original`] deletes one original no
    /// root holds. Refused, removing nothing, while any of them is leased or still needed
    /// through a root or a dependent.
    pub fn delete_source_file(
        &mut self,
        scope: &Scope,
        target: &SourceFileTarget,
    ) -> Result<SourceFileDeletion, DeleteRefusal> {
        let (root, originals) = match target {
            SourceFileTarget::Root(name) => {
                let id = RootId::new(scope, RootKind::SourceFile, name);
                let held = self
                    .roots
                    .get(&id)
                    .map(|root| root.objects.clone())
                    .ok_or_else(|| DeleteRefusal::NoSuchRoot {
                        kind: RootKind::SourceFile,
                        name: name.clone(),
                    })?;
                (Some(id), held)
            }
            SourceFileTarget::Original(object) => {
                let entry = self
                    .entries
                    .get(object)
                    .filter(|entry| entry.scope() == scope)
                    .ok_or(DeleteRefusal::NoSuchOriginal { object: *object })?;
                if !entry.index().role.is_original() {
                    return Err(DeleteRefusal::NotAnOriginal { object: *object });
                }
                (None, BTreeSet::from([*object]))
            }
        };
        let now = self.now();
        self.expire_leases(now);
        let leased = self.leased_objects(now);
        let others = self.reachable_from(
            self.roots
                .iter()
                .filter(|(other, _)| Some(**other) != root)
                .map(|(_, held)| held),
        );
        for object in &originals {
            if leased.contains(object) {
                return Err(DeleteRefusal::InUse {
                    object: *object,
                    holder: Holder::Lease,
                });
            }
            if let Some(holder) = self.holder(object, &others, root) {
                return Err(DeleteRefusal::InUse {
                    object: *object,
                    holder,
                });
            }
        }
        let storage = |failure| DeleteRefusal::Storage { failure };
        if let Some(id) = root {
            self.layout
                .remove_file_if_exists(&self.layout.root_record(&id))
                .map_err(storage)?;
            self.roots.remove(&id);
        }
        let mut deletion = SourceFileDeletion {
            root,
            deleted: Vec::new(),
            freed_bytes: 0,
        };
        for object in originals {
            if self.entries.contains_key(&object) {
                let freed = self.remove_object(object).map_err(storage)?;
                deletion.deleted.push(object);
                deletion.freed_bytes = deletion.freed_bytes.saturating_add(freed);
            }
        }
        self.refresh_reachability(now);
        Ok(deletion)
    }

    /// What keeps `object` reachable from the roots other than `excluded`, whose
    /// reachable objects are `others`: a root naming it, or a reachable dependent.
    fn holder(
        &self,
        object: &ObjectId,
        others: &BTreeSet<ObjectId>,
        excluded: Option<RootId>,
    ) -> Option<Holder> {
        self.roots
            .iter()
            .find(|(id, held)| Some(**id) != excluded && held.objects.contains(object))
            .map(|(id, _)| Holder::Root { root: *id })
            .or_else(|| {
                self.entries
                    .iter()
                    .find(|(dependent, entry)| {
                        others.contains(*dependent) && entry.index().depends_on.contains(object)
                    })
                    .map(|(dependent, _)| Holder::Dependent { object: *dependent })
            })
    }

    /// Re-reads one of the owner's objects in full (index, length, every extent digest,
    /// the content key and the class verifier) and re-checks its recorded trust basis
    /// against the current policy (INT-09). A failure quarantines it, revokes its leases
    /// and is reported; nothing is deleted. A pass clears an earlier quarantine.
    pub fn verify_object(&mut self, owner: &Scope, object: ObjectId) -> Result<(), VerifyError> {
        let (index, basis) = self
            .entries
            .get(&object)
            .filter(|entry| entry.scope() == owner)
            .map(|entry| (entry.index().clone(), entry.record.trust.clone()))
            .ok_or(VerifyError::NotOwner { object })?;
        let result = self
            .validate_dir(&self.layout.object_dir(&object), &index)
            .and_then(|()| {
                recheck_trust(
                    &self.verifiers,
                    &self.config.trust,
                    &index.scope,
                    index.class,
                    &basis,
                )
                .map_err(|refusal| IntegrityFailure::TrustWithdrawn { refusal })
            });
        let now = self.now();
        if let Some(entry) = self.entries.get_mut(&object) {
            entry.quarantine = result.clone().err();
        }
        match result {
            Ok(()) => Ok(()),
            Err(reason) => {
                self.revoke_leases(|lease| lease.object == object, now);
                Err(VerifyError::Quarantined { reason })
            }
        }
    }

    /// Unpublishes and removes one object: its record first, so an interruption leaves an
    /// unpublished directory for the collector, never a record without bytes.
    pub(super) fn remove_object(&mut self, object: ObjectId) -> Result<u64, StorageFailure> {
        let Some(entry) = self.entries.get(&object) else {
            return Ok(0);
        };
        let length_bytes = entry.index().length_bytes();
        let scope = entry.scope().clone();
        self.layout
            .remove_file_if_exists(&self.layout.record(&object))?;
        self.entries.remove(&object);
        self.grants.retain(|_, grant| grant.object != object);
        let now = self.now();
        self.revoke_leases(|lease| lease.object == object, now);
        if let Err(failure) = self.layout.remove_tree(&self.layout.object_dir(&object)) {
            self.unpublished.insert(
                object,
                Unpublished {
                    scope: Some(scope),
                    length_bytes,
                    since: now,
                },
            );
            return Err(failure);
        }
        Ok(length_bytes)
    }
}
