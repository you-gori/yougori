//! Grants, leases and read-only handles (S3.3: read-only artifact reuse needs a scoped
//! grant; INT-05; GPU part §3.4, line 546: consumers get read-only artifacts).
//!
//! A reader is its scope plus the execution reading. It reads its own scope's objects
//! freely, and another scope's object only under a grant for that exact object: equal
//! content anywhere else is never permission. A grant covers content only; the owner's
//! private metadata is never readable outside the owning scope. Reads go through leases,
//! which keep objects from collection, and handles, which check their lease on every
//! read so revocation and expiry take effect immediately.

use std::collections::BTreeSet;
use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::content::{ExtentDigest, ExtentEntry};
use super::identity::{ArtifactClass, ObjectId, ObjectRole, Scope, SourceIdentity};
use super::provenance::{StorageFailure, StorageOperation};
use super::state::{Catalog, Entry, ObjectMetadata};
use super::store::DATA_FILE;
use super::trust::{ObjectBytes, TrustBasis};
use crate::foundation::evidence::ArtifactVerification;
use crate::foundation::ids::{Clock, ContentKey, ExecutionId, MonotonicTime, OperationId};

/// A grant's identity, local to one catalog instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GrantId(u64);

/// A lease's identity, local to one catalog instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LeaseId(u64);

/// A request to let another scope read one object (S3.3 "scoped grant").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantRequest {
    /// Exactly one object: a grant never extends to equal content elsewhere.
    pub object: ObjectId,
    pub grantee: Scope,
    /// Narrows the grant to one execution of the grantee.
    pub execution: Option<ExecutionId>,
    pub expires_at: MonotonicTime,
}

#[derive(Clone, Debug)]
pub(super) struct GrantState {
    pub(super) object: ObjectId,
    pub(super) grantee: Scope,
    pub(super) execution: Option<ExecutionId>,
    pub(super) expires_at: MonotonicTime,
}

/// Why a grant was refused or could not be revoked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GrantRefusal {
    /// Only the owning scope grants; an object outside it is refused the same way as a
    /// missing one.
    NotOwner {
        object: ObjectId,
    },
    Quarantined {
        object: ObjectId,
    },
    /// The grantee already owns the object.
    SameScope,
    AlreadyExpired,
    UnknownGrant,
}

impl fmt::Display for GrantRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotOwner { object } => write!(f, "{object} is not published in this scope"),
            Self::Quarantined { object } => write!(f, "{object} is quarantined"),
            Self::SameScope => f.write_str("the grantee already owns the object"),
            Self::AlreadyExpired => f.write_str("the grant would already be expired"),
            Self::UnknownGrant => f.write_str("no such grant in this scope"),
        }
    }
}

impl std::error::Error for GrantRefusal {}

const ACTIVE: u8 = 0;
const RELEASED: u8 = 1;
const REVOKED: u8 = 2;

/// A lease's state, shared with the handles opened under it.
#[derive(Debug)]
pub(super) struct LeaseCell {
    state: AtomicU8,
    expires_at_nanos: AtomicU64,
}

/// How a lease ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LeaseEnded {
    Expired,
    Released,
    Revoked,
}

impl LeaseCell {
    fn new(expires_at: MonotonicTime) -> Self {
        Self {
            state: AtomicU8::new(ACTIVE),
            expires_at_nanos: AtomicU64::new(expires_at.as_nanos()),
        }
    }

    pub(super) fn expires_at(&self) -> MonotonicTime {
        MonotonicTime::from_nanos(self.expires_at_nanos.load(Ordering::SeqCst))
    }

    fn check(&self, now: MonotonicTime) -> Result<(), LeaseEnded> {
        match self.state.load(Ordering::SeqCst) {
            ACTIVE if now < self.expires_at() => Ok(()),
            ACTIVE => Err(LeaseEnded::Expired),
            RELEASED => Err(LeaseEnded::Released),
            _ => Err(LeaseEnded::Revoked),
        }
    }

    pub(super) fn is_live(&self, now: MonotonicTime) -> bool {
        self.check(now).is_ok()
    }

    fn end(&self, state: u8) {
        self.state.store(state, Ordering::SeqCst);
    }
}

#[derive(Debug)]
pub(super) struct LeaseState {
    pub(super) object: ObjectId,
    pub(super) holder: Scope,
    pub(super) execution: ExecutionId,
    pub(super) grant: Option<GrantId>,
    pub(super) cell: Arc<LeaseCell>,
}

/// Why a read, lease or view was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadRefusal {
    /// The object is not published in the reader's scope and no live grant for this
    /// exact object covers the reader and execution (S3.3, INT-05). Missing objects of
    /// other scopes are refused the same way.
    NotGranted {
        object: ObjectId,
    },
    /// Covered by a grant, but no longer published.
    NotPublished {
        object: ObjectId,
    },
    /// Failed verification, or its trust basis is no longer accepted by the current
    /// policy; unreadable until a verified, trusted import replaces it or the policy
    /// accepts it again (INT-09).
    Quarantined {
        object: ObjectId,
    },
    ZeroDuration,
    DurationTooLong {
        max: Duration,
    },
    UnknownLease,
    LeaseNotHeld,
    /// An expired lease is never revived; take a new one.
    LeaseExpired,
    LeaseReleased,
    /// Revoked with its grant, or by quarantine.
    LeaseRevoked,
    Storage {
        failure: StorageFailure,
    },
}

impl From<LeaseEnded> for ReadRefusal {
    fn from(ended: LeaseEnded) -> Self {
        match ended {
            LeaseEnded::Expired => Self::LeaseExpired,
            LeaseEnded::Released => Self::LeaseReleased,
            LeaseEnded::Revoked => Self::LeaseRevoked,
        }
    }
}

impl fmt::Display for ReadRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotGranted { object } => write!(
                f,
                "{object} is not published in your scope and no grant covers it; equal content \
                 elsewhere is not permission"
            ),
            Self::NotPublished { object } => write!(f, "{object} is no longer published"),
            Self::Quarantined { object } => write!(
                f,
                "{object} is quarantined: it failed verification or its publisher is no longer \
                 trusted"
            ),
            Self::ZeroDuration => f.write_str("a lease needs a duration"),
            Self::DurationTooLong { max } => write!(f, "a lease lasts at most {max:?}"),
            Self::UnknownLease => f.write_str("no such lease"),
            Self::LeaseNotHeld => f.write_str("the lease belongs to another reader"),
            Self::LeaseExpired => f.write_str("the lease expired; take a new one"),
            Self::LeaseReleased => f.write_str("the lease was released"),
            Self::LeaseRevoked => f.write_str("the lease was revoked"),
            Self::Storage { failure } => failure.fmt(f),
        }
    }
}

impl std::error::Error for ReadRefusal {}

/// The owner's private metadata was asked for from outside the owning scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MetadataRefusal {
    pub object: ObjectId,
}

impl fmt::Display for MetadataRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the metadata of {} is private to its owning scope",
            self.object
        )
    }
}

impl std::error::Error for MetadataRefusal {}

/// What any authorized reader, including a grantee, sees of an object: content facts
/// only, never the owner's metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectView {
    pub object: ObjectId,
    pub class: ArtifactClass,
    pub content_key: ContentKey,
    pub length_bytes: u64,
    pub extents: Vec<ExtentEntry>,
}

/// What only the owning scope sees (INT-05: private model metadata never becomes
/// cross-tenant readable).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateMetadata {
    pub object: ObjectId,
    pub scope: Scope,
    pub class: ArtifactClass,
    pub role: ObjectRole,
    pub depends_on: BTreeSet<ObjectId>,
    pub content_key: ContentKey,
    pub length_bytes: u64,
    pub metadata: ObjectMetadata,
    pub source: SourceIdentity,
    pub trust: TrustBasis,
    pub operation: OperationId,
    pub execution: ExecutionId,
}

/// A failed read through a handle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadError {
    LeaseExpired,
    LeaseReleased,
    LeaseRevoked,
    OutOfRange {
        extent: u32,
    },
    /// The extent no longer matches its digest.
    ExtentCorrupt {
        extent: u32,
    },
    TooLarge,
    Io {
        detail: String,
    },
}

impl From<LeaseEnded> for ReadError {
    fn from(ended: LeaseEnded) -> Self {
        match ended {
            LeaseEnded::Expired => Self::LeaseExpired,
            LeaseEnded::Released => Self::LeaseReleased,
            LeaseEnded::Revoked => Self::LeaseRevoked,
        }
    }
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LeaseExpired => f.write_str("the lease expired"),
            Self::LeaseReleased => f.write_str("the lease was released"),
            Self::LeaseRevoked => f.write_str("the lease was revoked"),
            Self::OutOfRange { extent } => write!(f, "the object has no extent {extent}"),
            Self::ExtentCorrupt { extent } => {
                write!(f, "extent {extent} does not match its digest")
            }
            Self::TooLarge => f.write_str("the object does not fit in memory"),
            Self::Io { detail } => f.write_str(detail),
        }
    }
}

impl std::error::Error for ReadError {}

/// A consumer's read-only handle on one committed object (line 546). It offers no way to
/// write, and every read first checks the lease it was opened under.
pub struct ReadHandle {
    bytes: ObjectBytes,
    object: ObjectId,
    class: ArtifactClass,
    content_key: ContentKey,
    extents: Vec<ExtentEntry>,
    lease: Arc<LeaseCell>,
    clock: Arc<dyn Clock>,
}

impl fmt::Debug for ReadHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadHandle")
            .field("object", &self.object)
            .field("length_bytes", &self.bytes.length_bytes())
            .finish_non_exhaustive()
    }
}

impl ReadHandle {
    /// The object this handle reads.
    pub fn object(&self) -> ObjectId {
        self.object
    }

    /// The object's artifact class.
    pub fn class(&self) -> ArtifactClass {
        self.class
    }

    /// The object's content key (line 529).
    pub fn content_key(&self) -> ContentKey {
        self.content_key
    }

    /// The object's true length.
    pub fn length_bytes(&self) -> u64 {
        self.bytes.length_bytes()
    }

    /// The object's extent table, each with its digest.
    pub fn extents(&self) -> &[ExtentEntry] {
        &self.extents
    }

    fn check(&self) -> Result<(), ReadError> {
        self.lease.check(self.clock.now()).map_err(ReadError::from)
    }

    /// Fills `buffer` from `offset_bytes`.
    pub fn read_exact_at(&mut self, offset_bytes: u64, buffer: &mut [u8]) -> Result<(), ReadError> {
        self.check()?;
        self.bytes
            .read_exact_at(offset_bytes, buffer)
            .map_err(|error| ReadError::Io {
                detail: error.to_string(),
            })
    }

    /// One extent, verified against its digest before it is returned.
    pub fn read_extent(&mut self, extent: u32) -> Result<Vec<u8>, ReadError> {
        let entry = *self
            .extents
            .get(extent as usize)
            .ok_or(ReadError::OutOfRange { extent })?;
        let length = usize::try_from(entry.length_bytes).map_err(|_| ReadError::TooLarge)?;
        let mut buffer = vec![0u8; length];
        self.read_exact_at(entry.offset_bytes, &mut buffer)?;
        if ExtentDigest::of(&buffer) != entry.digest {
            return Err(ReadError::ExtentCorrupt { extent });
        }
        Ok(buffer)
    }

    /// The whole object, extent by extent, each verified.
    pub fn read_all(&mut self) -> Result<Vec<u8>, ReadError> {
        let length = usize::try_from(self.length_bytes()).map_err(|_| ReadError::TooLarge)?;
        let mut bytes = Vec::with_capacity(length);
        for extent in 0..self.extents.len() {
            let extent = u32::try_from(extent).map_err(|_| ReadError::TooLarge)?;
            bytes.extend(self.read_extent(extent)?);
        }
        Ok(bytes)
    }
}

/// How a reader is authorized for one object.
#[derive(Clone, Copy, Debug)]
enum Authority {
    Owner,
    Granted {
        grant: GrantId,
        expires_at: MonotonicTime,
    },
}

impl Catalog {
    fn authorize(
        &self,
        reader: &Scope,
        execution: &ExecutionId,
        object: ObjectId,
        now: MonotonicTime,
    ) -> Result<Authority, ReadRefusal> {
        if self
            .entries
            .get(&object)
            .is_some_and(|entry| entry.scope() == reader)
        {
            return Ok(Authority::Owner);
        }
        self.grants
            .iter()
            .filter(|(_, grant)| {
                grant.object == object
                    && grant.grantee == *reader
                    && grant
                        .execution
                        .as_ref()
                        .is_none_or(|bound| bound == execution)
                    && now < grant.expires_at
            })
            .max_by_key(|(_, grant)| grant.expires_at)
            .map(|(grant, state)| Authority::Granted {
                grant: *grant,
                expires_at: state.expires_at,
            })
            .ok_or(ReadRefusal::NotGranted { object })
    }

    /// The entry if it may be read now: published, not quarantined, and trusted under the
    /// current policy (INT-09), checked on every read.
    fn readable(&self, object: ObjectId) -> Result<&Entry, ReadRefusal> {
        let entry = self
            .entries
            .get(&object)
            .ok_or(ReadRefusal::NotPublished { object })?;
        if !self.is_usable(entry) {
            return Err(ReadRefusal::Quarantined { object });
        }
        Ok(entry)
    }

    fn check_duration(&self, duration: Duration) -> Result<(), ReadRefusal> {
        if duration.is_zero() {
            return Err(ReadRefusal::ZeroDuration);
        }
        if duration > self.config.limits.max_lease {
            return Err(ReadRefusal::DurationTooLong {
                max: self.config.limits.max_lease,
            });
        }
        Ok(())
    }

    /// Lets `request.grantee` read one object of `owner`'s scope until the grant expires
    /// or is revoked (S3.3). A grant covers content, never the private metadata.
    pub fn grant(&mut self, owner: &Scope, request: GrantRequest) -> Result<GrantId, GrantRefusal> {
        let object = request.object;
        let entry = self
            .entries
            .get(&object)
            .filter(|entry| entry.scope() == owner)
            .ok_or(GrantRefusal::NotOwner { object })?;
        if !self.is_usable(entry) {
            return Err(GrantRefusal::Quarantined { object });
        }
        if request.grantee == *owner {
            return Err(GrantRefusal::SameScope);
        }
        if request.expires_at <= self.now() {
            return Err(GrantRefusal::AlreadyExpired);
        }
        let id = GrantId(self.next_number());
        self.grants.insert(
            id,
            GrantState {
                object,
                grantee: request.grantee,
                execution: request.execution,
                expires_at: request.expires_at,
            },
        );
        Ok(id)
    }

    /// Revokes a grant and every lease taken under it; open handles stop reading at once.
    /// Returns how many leases were revoked.
    pub fn revoke_grant(&mut self, owner: &Scope, grant: GrantId) -> Result<usize, GrantRefusal> {
        let owned = self
            .grants
            .get(&grant)
            .and_then(|state| self.entries.get(&state.object))
            .is_some_and(|entry| entry.scope() == owner);
        if !owned {
            return Err(GrantRefusal::UnknownGrant);
        }
        self.grants.remove(&grant);
        let now = self.now();
        Ok(self.revoke_leases(|lease| lease.grant == Some(grant), now))
    }

    /// Takes a lease on an object the reader may read: its own scope's, or another's
    /// under a live grant for that exact object and execution. A lease under a grant ends
    /// no later than the grant.
    pub fn acquire_lease(
        &mut self,
        reader: &Scope,
        execution: &ExecutionId,
        object: ObjectId,
        duration: Duration,
    ) -> Result<LeaseId, ReadRefusal> {
        self.check_duration(duration)?;
        let now = self.now();
        let authority = self.authorize(reader, execution, object, now)?;
        self.readable(object)?;
        let (grant, expires_at) = match authority {
            Authority::Owner => (None, now.saturating_add(duration)),
            Authority::Granted { grant, expires_at } => {
                (Some(grant), now.saturating_add(duration).min(expires_at))
            }
        };
        let id = LeaseId(self.next_number());
        self.leases.insert(
            id,
            LeaseState {
                object,
                holder: reader.clone(),
                execution: execution.clone(),
                grant,
                cell: Arc::new(LeaseCell::new(expires_at)),
            },
        );
        if let Some(entry) = self.entries.get_mut(&object) {
            entry.last_used_at = Some(now);
        }
        Ok(id)
    }

    fn held(
        &self,
        reader: &Scope,
        execution: &ExecutionId,
        lease: LeaseId,
        now: MonotonicTime,
    ) -> Result<&LeaseState, ReadRefusal> {
        let state = self.leases.get(&lease).ok_or(ReadRefusal::UnknownLease)?;
        if state.holder != *reader || state.execution != *execution {
            return Err(ReadRefusal::LeaseNotHeld);
        }
        state.cell.check(now)?;
        if let Some(grant) = state.grant {
            let live = self
                .grants
                .get(&grant)
                .is_some_and(|grant| now < grant.expires_at);
            if !live {
                return Err(ReadRefusal::LeaseRevoked);
            }
        }
        Ok(state)
    }

    /// Extends a live lease, never past its grant. An expired lease is never revived.
    pub fn renew_lease(
        &mut self,
        reader: &Scope,
        execution: &ExecutionId,
        lease: LeaseId,
        duration: Duration,
    ) -> Result<MonotonicTime, ReadRefusal> {
        self.check_duration(duration)?;
        let now = self.now();
        let state = self.held(reader, execution, lease, now)?;
        let mut expires_at = now.saturating_add(duration);
        if let Some(grant) = state.grant.and_then(|grant| self.grants.get(&grant)) {
            expires_at = expires_at.min(grant.expires_at);
        }
        self.readable(state.object)?;
        state
            .cell
            .expires_at_nanos
            .store(expires_at.as_nanos(), Ordering::SeqCst);
        Ok(expires_at)
    }

    /// When a held, live lease ends, so its holder can renew it in time or plan around it,
    /// as a recovery recipe holding the catalog object does. Refused exactly like a read
    /// through the lease: another reader's lease, an unknown, expired, released or revoked
    /// one, or an object no longer readable.
    pub fn lease_expires_at(
        &self,
        reader: &Scope,
        execution: &ExecutionId,
        lease: LeaseId,
    ) -> Result<MonotonicTime, ReadRefusal> {
        let state = self.held(reader, execution, lease, self.now())?;
        self.readable(state.object)?;
        Ok(state.cell.expires_at())
    }

    /// The object a held, live lease reads and when the lease ends, so a holder can bind
    /// the lease to the object it expects without opening a handle, as a recovery recipe
    /// holding the catalog object does. Refused exactly like [`Catalog::lease_expires_at`].
    pub fn lease_object(
        &self,
        reader: &Scope,
        execution: &ExecutionId,
        lease: LeaseId,
    ) -> Result<(ObjectId, MonotonicTime), ReadRefusal> {
        let state = self.held(reader, execution, lease, self.now())?;
        self.readable(state.object)?;
        Ok((state.object, state.cell.expires_at()))
    }

    /// Ends a lease; handles opened under it stop reading.
    pub fn release_lease(
        &mut self,
        reader: &Scope,
        execution: &ExecutionId,
        lease: LeaseId,
    ) -> Result<(), ReadRefusal> {
        let state = self.leases.get(&lease).ok_or(ReadRefusal::UnknownLease)?;
        if state.holder != *reader || state.execution != *execution {
            return Err(ReadRefusal::LeaseNotHeld);
        }
        if let Some(state) = self.leases.remove(&lease) {
            state.cell.end(RELEASED);
            let ended_at = self.now().min(state.cell.expires_at());
            self.note_lease_end(state.object, ended_at);
        }
        Ok(())
    }

    /// Opens a read-only handle under a held, live lease.
    pub fn open_read(
        &self,
        reader: &Scope,
        execution: &ExecutionId,
        lease: LeaseId,
    ) -> Result<ReadHandle, ReadRefusal> {
        let now = self.now();
        let state = self.held(reader, execution, lease, now)?;
        let entry = self.readable(state.object)?;
        let path = self.layout.object_dir(&state.object).join(DATA_FILE);
        let storage = |detail: String| ReadRefusal::Storage {
            failure: self.layout.failure(StorageOperation::Open, &path, detail),
        };
        let bytes = ObjectBytes::open(&path).map_err(|error| storage(error.to_string()))?;
        let index = entry.index();
        if bytes.length_bytes() != index.length_bytes() {
            return Err(storage(format!(
                "{} bytes on disk; the index records {}",
                bytes.length_bytes(),
                index.length_bytes()
            )));
        }
        Ok(ReadHandle {
            bytes,
            object: state.object,
            class: index.class,
            content_key: index.manifest.content_key,
            extents: index.manifest.extents.clone(),
            lease: Arc::clone(&state.cell),
            clock: Arc::clone(&self.clock),
        })
    }

    /// The committed data file of the object a held, live lease reads, for a consumer that
    /// mounts the object read-only (such as a hard-linked model view) instead of reading
    /// through a handle (GPU-W03 "Keep consumer mounts read-only"). The lease is checked
    /// exactly as [`Catalog::open_read`] checks it, and a data file whose length is not
    /// the index's is refused the same way. The path names a read-only file the importer
    /// committed; nothing here opens it.
    pub fn leased_path(
        &self,
        reader: &Scope,
        execution: &ExecutionId,
        lease: LeaseId,
    ) -> Result<PathBuf, ReadRefusal> {
        let now = self.now();
        let state = self.held(reader, execution, lease, now)?;
        let entry = self.readable(state.object)?;
        let path = self.layout.object_dir(&state.object).join(DATA_FILE);
        let storage = |detail: String| ReadRefusal::Storage {
            failure: self.layout.failure(StorageOperation::Open, &path, detail),
        };
        let length_bytes = self
            .layout
            .file_len(&path)
            .ok_or_else(|| storage("the committed data file is missing".to_owned()))?;
        let index = entry.index();
        if length_bytes != index.length_bytes() {
            return Err(storage(format!(
                "{length_bytes} bytes on disk; the index records {}",
                index.length_bytes()
            )));
        }
        Ok(path)
    }

    /// Content facts for an authorized reader, owner or grantee.
    pub fn object_view(
        &self,
        reader: &Scope,
        execution: &ExecutionId,
        object: ObjectId,
    ) -> Result<ObjectView, ReadRefusal> {
        self.authorize(reader, execution, object, self.now())?;
        let index = self.readable(object)?.index();
        Ok(ObjectView {
            object,
            class: index.class,
            content_key: index.manifest.content_key,
            length_bytes: index.length_bytes(),
            extents: index.manifest.extents.clone(),
        })
    }

    /// The owner's private metadata; refused for every other scope, grant or not
    /// (INT-05).
    pub fn private_metadata(
        &self,
        reader: &Scope,
        object: ObjectId,
    ) -> Result<PrivateMetadata, MetadataRefusal> {
        let entry = self
            .entries
            .get(&object)
            .filter(|entry| entry.scope() == reader)
            .ok_or(MetadataRefusal { object })?;
        let record = &entry.record;
        let index = &record.index;
        Ok(PrivateMetadata {
            object,
            scope: index.scope.clone(),
            class: index.class,
            role: index.role.clone(),
            depends_on: index.depends_on.clone(),
            content_key: index.manifest.content_key,
            length_bytes: index.length_bytes(),
            metadata: record.metadata.clone(),
            source: record.source,
            trust: record.trust.clone(),
            operation: record.operation.clone(),
            execution: record.execution.clone(),
        })
    }

    /// The verified-artifact set a loader may declare to the S3.5 fallback guard
    /// ([`crate::foundation::evidence::guard_fallback`]): every object must be published,
    /// healthy and readable by this reader and execution.
    pub fn artifact_verification(
        &self,
        reader: &Scope,
        execution: &ExecutionId,
        objects: impl IntoIterator<Item = ObjectId>,
    ) -> Result<ArtifactVerification, ReadRefusal> {
        let now = self.now();
        let mut artifacts = BTreeSet::new();
        for object in objects {
            self.authorize(reader, execution, object, now)?;
            self.readable(object)?;
            artifacts.insert(object.digest());
        }
        Ok(ArtifactVerification::Verified { artifacts })
    }

    pub(super) fn note_lease_end(&mut self, object: ObjectId, at: MonotonicTime) {
        if let Some(entry) = self.entries.get_mut(&object) {
            entry.last_lease_end = Some(entry.last_lease_end.map_or(at, |ended| ended.max(at)));
        }
    }

    /// Revokes every lease `which` selects; returns how many.
    pub(super) fn revoke_leases(
        &mut self,
        which: impl Fn(&LeaseState) -> bool,
        now: MonotonicTime,
    ) -> usize {
        let chosen: Vec<LeaseId> = self
            .leases
            .iter()
            .filter(|(_, lease)| which(lease))
            .map(|(id, _)| *id)
            .collect();
        for id in &chosen {
            if let Some(lease) = self.leases.remove(id) {
                lease.cell.end(REVOKED);
                let ended_at = now.min(lease.cell.expires_at());
                self.note_lease_end(lease.object, ended_at);
            }
        }
        chosen.len()
    }

    /// Drops leases that expired or whose grant ended, recording when each ended.
    pub(super) fn expire_leases(&mut self, now: MonotonicTime) {
        let ended: Vec<LeaseId> = self
            .leases
            .iter()
            .filter(|(_, lease)| {
                !lease.cell.is_live(now)
                    || lease.grant.is_some_and(|grant| {
                        !self
                            .grants
                            .get(&grant)
                            .is_some_and(|grant| now < grant.expires_at)
                    })
            })
            .map(|(id, _)| *id)
            .collect();
        for id in ended {
            if let Some(lease) = self.leases.remove(&id) {
                if lease.cell.is_live(now) {
                    // Live by its own expiry, so its grant is what ended.
                    lease.cell.end(REVOKED);
                }
                let ended_at = now.min(lease.cell.expires_at());
                self.note_lease_end(lease.object, ended_at);
            }
        }
    }

    /// Objects under at least one live lease.
    pub(super) fn leased_objects(&self, now: MonotonicTime) -> BTreeSet<ObjectId> {
        self.leases
            .values()
            .filter(|lease| lease.cell.is_live(now))
            .map(|lease| lease.object)
            .collect()
    }
}
