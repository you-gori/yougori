//! VM-N4 fetch by approved content identity (VM part §9.4, lines 2385–2389; §5.3–§5.4;
//! VM-P45; VM-W57).
//!
//! The [`FetchService`] owns its own catalog scope. It resolves approved object IDs to
//! pinned registry artifacts and imports them through the CORE-02 catalog, which checks
//! every extent, the content key and the class's publisher trust; it holds no grant on
//! the compute VM's scope, so it cannot read private project content. It follows no
//! redirect.
//!
//! The [`ContentService`] answers the compute VM. It accepts only an approved object ID
//! from the VM's manifest; URLs, package names, queries and redirects are refused before
//! anything leaves, and after private inputs entered such a request is refused as a
//! potential exfiltration message (VM-P45). Hits and misses read through the same
//! per-object grant to the VM's own scope and execution, so the cache enforces the same
//! scope as a download. In strict private mode the whole manifest is prefetched before
//! private computation and later lookups are served locally with no registry contact;
//! lazy mode is a permitted metadata channel, never noninterference.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;

use super::contract::Approval;
use super::manifest::{
    DependencyManifest, PinnedSource, PrivateExposure, RegistryPort, RegistryReply,
};
use super::plan::to_u64;
use crate::foundation::catalog::{
    Catalog, FailureRecord, GrantRefusal, GrantRequest, ImportError, ImportRefusal, ImportRequest,
    ImportSource, ImportStart, ImportStatus, ObjectId, ObjectMetadata, ObjectRole, ObjectStatus,
    ReadError, ReadRefusal, Scope, SourceError, SourceIdentity, TrustClaim, Uninterrupted,
};
use crate::foundation::ids::{Clock, ExecutionId, MonotonicTime, OperationId};

/// Largest request the content service reads from a compute VM.
pub const MAX_REQUEST_BYTES: usize = 4096;

strict_tagged_enum! {
/// Everything a compute VM might send the content service. Only [`ContentRequest::Object`]
/// is ever answered; the other shapes exist so they can be recognized and refused
/// (line 2387).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContentRequest (tag = "request", wire = ContentRequestWire, wire_name = "ContentRequestWire") {
    /// An approved object ID.
    Object { object: ObjectId },
    Url { url: String },
    PackageName { name: String, version: Option<String> },
    Query { query: String },
    Redirect { object: ObjectId, location: String },
}
}

/// The shape of a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestKind {
    Object,
    Url,
    PackageName,
    Query,
    Redirect,
}

impl ContentRequest {
    pub fn kind(&self) -> RequestKind {
        match self {
            Self::Object { .. } => RequestKind::Object,
            Self::Url { .. } => RequestKind::Url,
            Self::PackageName { .. } => RequestKind::PackageName,
            Self::Query { .. } => RequestKind::Query,
            Self::Redirect { .. } => RequestKind::Redirect,
        }
    }

    /// Reads a request from the VM's JSON, strictly: a bounded size, a known shape and
    /// no unknown field.
    pub fn from_wire(bytes: &[u8]) -> Result<Self, ContentRefusal> {
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(ContentRefusal::TooLarge {
                bytes: bytes.len(),
                max: MAX_REQUEST_BYTES,
            });
        }
        serde_json::from_slice(bytes).map_err(|_| ContentRefusal::Malformed)
    }
}

/// How the content service obtains objects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FetchMode {
    /// Strict private-data mode: the whole manifest is prefetched before private inputs
    /// enter, and later lookups never reach a registry (line 2389, VM-W57).
    StrictPrivate,
    /// Lazy remote fetches. They reveal selection, timing and misses, so the metadata
    /// channel needs its own explicit approval (line 2389).
    Lazy { metadata_channel: Approval },
}

/// Whether a request was served from the scoped cache or fetched.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheResult {
    Hit,
    Miss,
}

/// What [`FetchService::ensure`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct FetchOutcome {
    pub object: ObjectId,
    pub cache: CacheResult,
}

/// What a prefetch did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct PrefetchReport {
    pub objects: u32,
    pub fetched: u32,
    pub already_cached: u32,
}

/// One lazy remote fetch, as the fetch path can observe it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct MetadataObservation {
    pub object: ObjectId,
    pub at: MonotonicTime,
}

/// What lazy fetches reveal (line 2389).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MetadataLeak {
    ObjectSelection,
    Timing,
    CacheMisses,
}

/// How a content service's remote activity is classified. There is deliberately no
/// noninterference variant (line 2389).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChannelClassification {
    /// Prefetched before private computation; later lookups are local, with no network
    /// activity.
    NoNetworkAfterPrefetch,
    /// Lazy fetches: a permitted metadata channel revealing what is listed.
    PermittedMetadataChannel {
        reveals: BTreeSet<MetadataLeak>,
        remote_fetches: u64,
        approval: Approval,
    },
}

/// One object served to the compute VM.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServedObject {
    pub object: ObjectId,
    pub cache: CacheResult,
    pub bytes: Vec<u8>,
}

/// Why the fetch service did not provide an object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FetchRefusal {
    /// The manifest belongs to another fetch scope.
    WrongScope,
    /// Only approved objects are fetched (line 2387).
    NotInManifest {
        object: ObjectId,
    },
    /// A redirect is never followed (line 2387).
    Redirect {
        object: ObjectId,
        location: String,
    },
    /// The registry declared other content or another publisher than approved.
    PinMismatch {
        object: ObjectId,
    },
    Registry {
        object: ObjectId,
        detail: String,
    },
    Import {
        object: ObjectId,
        refusal: ImportRefusal,
    },
    ImportApi {
        object: ObjectId,
        error: ImportError,
    },
    /// The import ended without publishing; nothing is served.
    ImportFailed {
        object: ObjectId,
        failure: FailureRecord,
    },
    /// The import paused with unverified extents; nothing is served.
    ImportIncomplete {
        object: ObjectId,
    },
    /// The object is held but not servable, such as when quarantined.
    NotServable {
        object: ObjectId,
    },
    /// Strict private mode prefetches only before private inputs enter (VM-W57).
    PrefetchAfterPrivateInputs,
}

impl fmt::Display for FetchRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongScope => f.write_str("the manifest belongs to another fetch scope"),
            Self::NotInManifest { object } => {
                write!(f, "{object} is not in the approved manifest")
            }
            Self::Redirect { object, location } => write!(
                f,
                "the registry redirected {object} to {location}; redirects are never followed"
            ),
            Self::PinMismatch { object } => write!(
                f,
                "the registry declared other content or another publisher for {object}"
            ),
            Self::Registry { object, detail } => write!(f, "fetching {object}: {detail}"),
            Self::Import { object, refusal } => write!(f, "importing {object}: {refusal}"),
            Self::ImportApi { object, error } => write!(f, "importing {object}: {error}"),
            Self::ImportFailed { object, failure } => write!(
                f,
                "importing {object} failed at {:?}: {:?}",
                failure.stage, failure.reason
            ),
            Self::ImportIncomplete { object } => {
                write!(f, "importing {object} paused with unverified extents")
            }
            Self::NotServable { object } => write!(f, "{object} is held but not servable"),
            Self::PrefetchAfterPrivateInputs => {
                f.write_str("strict private mode prefetches before private inputs enter, not after")
            }
        }
    }
}

impl std::error::Error for FetchRefusal {}

/// Why the content service refused a request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContentRefusal {
    Malformed,
    TooLarge {
        bytes: usize,
        max: usize,
    },
    /// Only approved object IDs are answered; nothing was resolved (line 2387).
    NotAnObjectRequest {
        kind: RequestKind,
    },
    /// After private inputs entered, a name, URL, query or redirect can carry private
    /// data: refused as a potential exfiltration message (§5.4, VM-P45).
    PotentialExfiltration {
        kind: RequestKind,
    },
    /// The object ID is not approved; it is refused locally and nothing leaves.
    NotInManifest {
        object: ObjectId,
    },
    /// Strict private mode serves only what was prefetched; it never fetches.
    NotPrefetched {
        object: ObjectId,
    },
    /// Lazy fetching was asked of a strict private service.
    WrongMode,
    Fetch(FetchRefusal),
    Grant(GrantRefusal),
    Read(ReadRefusal),
    ReadFailed(ReadError),
}

impl fmt::Display for ContentRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed => f.write_str("the request is not a known request shape"),
            Self::TooLarge { bytes, max } => {
                write!(f, "the request has {bytes} bytes; the limit is {max}")
            }
            Self::NotAnObjectRequest { kind } => write!(
                f,
                "a {kind:?} request is not an approved object ID; nothing was resolved"
            ),
            Self::PotentialExfiltration { kind } => write!(
                f,
                "a {kind:?} request after private inputs entered could carry private data; it \
                 is refused and nothing was sent"
            ),
            Self::NotInManifest { object } => write!(
                f,
                "{object} is not in the approved manifest; it was refused locally"
            ),
            Self::NotPrefetched { object } => write!(
                f,
                "{object} was not prefetched; strict private mode does not fetch after private \
                 inputs enter"
            ),
            Self::WrongMode => {
                f.write_str("this service is strict private and never fetches lazily")
            }
            Self::Fetch(refusal) => refusal.fmt(f),
            Self::Grant(refusal) => refusal.fmt(f),
            Self::Read(refusal) => refusal.fmt(f),
            Self::ReadFailed(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for ContentRefusal {}

/// A pinned registry artifact as a catalog import source.
pub struct RegistrySource<'a> {
    registry: &'a mut dyn RegistryPort,
    pin: PinnedSource,
}

impl<'a> RegistrySource<'a> {
    pub fn new(registry: &'a mut dyn RegistryPort, pin: PinnedSource) -> Self {
        Self { registry, pin }
    }

    /// The source identity of a pin: its route and coordinates.
    pub fn identity_of(pin: &PinnedSource) -> SourceIdentity {
        let route = match &pin.route {
            crate::foundation::transfer::Endpoint::NamedRoute { route } => route.to_hex(),
            other => format!("{other:?}"),
        };
        SourceIdentity::describe(
            "registry-pin",
            &format!("{route}:{}", pin.coordinates.to_hex()),
        )
    }
}

impl ImportSource for RegistrySource<'_> {
    fn identity(&self) -> SourceIdentity {
        Self::identity_of(&self.pin)
    }

    fn length_bytes(&mut self) -> Result<u64, SourceError> {
        self.registry
            .length_bytes(&self.pin)
            .map_err(|error| SourceError {
                detail: error.to_string(),
            })
    }

    fn read_at(&mut self, offset_bytes: u64, buffer: &mut [u8]) -> Result<usize, SourceError> {
        self.registry
            .read_at(&self.pin, offset_bytes, buffer)
            .map_err(|error| SourceError {
                detail: error.to_string(),
            })
    }
}

/// The separate fetch service (line 2385). It writes only into its own scope and reads
/// nothing of the compute VM's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchService {
    scope: Scope,
    execution: ExecutionId,
    operation: OperationId,
}

impl FetchService {
    pub fn new(scope: Scope, execution: ExecutionId, operation: OperationId) -> Self {
        Self {
            scope,
            execution,
            operation,
        }
    }

    pub fn scope(&self) -> &Scope {
        &self.scope
    }

    pub fn execution(&self) -> &ExecutionId {
        &self.execution
    }

    /// Makes one approved object available in the fetch scope: a cache hit if it is
    /// already published there, otherwise an import of the pinned artifact through the
    /// catalog, which verifies extents, the content key and publisher trust (§5.3).
    pub fn ensure(
        &self,
        catalog: &mut Catalog,
        manifest: &DependencyManifest,
        object: ObjectId,
        registry: &mut dyn RegistryPort,
    ) -> Result<FetchOutcome, FetchRefusal> {
        if manifest.fetch_scope() != &self.scope {
            return Err(FetchRefusal::WrongScope);
        }
        let entry = manifest
            .entry(&object)
            .ok_or(FetchRefusal::NotInManifest { object })?;
        if catalog.find(&self.scope, entry.class, entry.content_key) == Some(object) {
            return Ok(FetchOutcome {
                object,
                cache: CacheResult::Hit,
            });
        }
        let artifact = match registry.declaration(&entry.pin) {
            Ok(RegistryReply::Artifact(artifact)) => artifact,
            Ok(RegistryReply::Redirect { location }) => {
                return Err(FetchRefusal::Redirect { object, location })
            }
            Err(error) => {
                return Err(FetchRefusal::Registry {
                    object,
                    detail: error.to_string(),
                })
            }
        };
        if artifact.manifest.content_key != entry.content_key
            || artifact.manifest.true_length_bytes != entry.length_bytes
            || artifact.publisher != entry.publisher
        {
            return Err(FetchRefusal::PinMismatch { object });
        }
        let request = ImportRequest {
            operation: self.operation.clone(),
            execution: self.execution.clone(),
            scope: self.scope.clone(),
            class: entry.class,
            role: ObjectRole::Original,
            manifest: artifact.manifest,
            trust: TrustClaim::Publisher {
                publisher: artifact.publisher,
                attestation: artifact.attestation,
            },
            depends_on: BTreeSet::new(),
            metadata: ObjectMetadata::new(),
        };
        let identity = RegistrySource::identity_of(&entry.pin);
        let start = catalog
            .begin_import(request, identity)
            .map_err(|refusal| FetchRefusal::Import { object, refusal })?;
        let ticket = match start {
            ImportStart::AlreadyPublished(_) => {
                return match catalog.status(&self.scope, object) {
                    ObjectStatus::Published => Ok(FetchOutcome {
                        object,
                        cache: CacheResult::Hit,
                    }),
                    _ => Err(FetchRefusal::NotServable { object }),
                }
            }
            ImportStart::Started(ticket) | ImportStart::Attached(ticket) => ticket,
        };
        let mut source = RegistrySource::new(registry, entry.pin.clone());
        let status = catalog.drive_import(&ticket, &mut source, &mut Uninterrupted);
        let _ = catalog.cancel_import(ticket);
        match status.map_err(|error| FetchRefusal::ImportApi { object, error })? {
            ImportStatus::Published {
                object: published, ..
            } if published == object => Ok(FetchOutcome {
                object,
                cache: CacheResult::Miss,
            }),
            ImportStatus::Published { .. } => Err(FetchRefusal::PinMismatch { object }),
            ImportStatus::Pending { .. } => Err(FetchRefusal::ImportIncomplete { object }),
            ImportStatus::Failed { failure } => Err(FetchRefusal::ImportFailed { object, failure }),
        }
    }
}

/// The compute VM's only content path (line 2385).
pub struct ContentService {
    manifest: DependencyManifest,
    mode: FetchMode,
    exposure: PrivateExposure,
    read_duration: Duration,
    clock: Arc<dyn Clock>,
    observations: Vec<MetadataObservation>,
}

impl fmt::Debug for ContentService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContentService")
            .field("manifest", &self.manifest.digest())
            .field("mode", &self.mode)
            .field("exposure", &self.exposure)
            .finish_non_exhaustive()
    }
}

impl ContentService {
    /// A service for the manifest's compute VM, before private inputs enter. Each read
    /// is under a grant and lease of `read_duration`, revoked as soon as it is done.
    pub fn new(
        manifest: DependencyManifest,
        mode: FetchMode,
        read_duration: Duration,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            manifest,
            mode,
            exposure: PrivateExposure::BeforePrivateInputs,
            read_duration,
            clock,
            observations: Vec::new(),
        }
    }

    pub fn manifest(&self) -> &DependencyManifest {
        &self.manifest
    }

    pub fn exposure(&self) -> PrivateExposure {
        self.exposure
    }

    /// Fetches every manifest object into the fetch scope (line 2389). Strict private
    /// mode allows this only before private inputs enter.
    pub fn prefetch(
        &mut self,
        catalog: &mut Catalog,
        fetch: &FetchService,
        registry: &mut dyn RegistryPort,
    ) -> Result<PrefetchReport, FetchRefusal> {
        if self.mode == FetchMode::StrictPrivate
            && self.exposure == PrivateExposure::PrivateInputsEntered
        {
            return Err(FetchRefusal::PrefetchAfterPrivateInputs);
        }
        let mut report = PrefetchReport::default();
        let objects: Vec<ObjectId> = self.manifest.entries().keys().copied().collect();
        for object in objects {
            report.objects = report.objects.saturating_add(1);
            match fetch
                .ensure(catalog, &self.manifest, object, registry)?
                .cache
            {
                CacheResult::Hit => report.already_cached = report.already_cached.saturating_add(1),
                CacheResult::Miss => report.fetched = report.fetched.saturating_add(1),
            }
        }
        Ok(report)
    }

    /// Records that private inputs entered the compute VM. Strict private mode refuses
    /// unless every manifest object is already published in the fetch scope (VM-W57).
    pub fn private_inputs_entered(&mut self, catalog: &Catalog) -> Result<(), ContentRefusal> {
        if self.mode == FetchMode::StrictPrivate {
            for entry in self.manifest.entries().values() {
                if catalog.status(self.manifest.fetch_scope(), entry.object)
                    != ObjectStatus::Published
                {
                    return Err(ContentRefusal::NotPrefetched {
                        object: entry.object,
                    });
                }
            }
        }
        self.exposure = PrivateExposure::PrivateInputsEntered;
        Ok(())
    }

    /// The approved object a request names, or the refusal: only object IDs in the
    /// manifest pass, and every other shape is refused before anything leaves.
    fn approved(&self, request: &ContentRequest) -> Result<ObjectId, ContentRefusal> {
        let ContentRequest::Object { object } = request else {
            let kind = request.kind();
            return Err(match self.exposure {
                PrivateExposure::PrivateInputsEntered => {
                    ContentRefusal::PotentialExfiltration { kind }
                }
                PrivateExposure::BeforePrivateInputs => ContentRefusal::NotAnObjectRequest { kind },
            });
        };
        if self.manifest.entry(object).is_none() {
            return Err(ContentRefusal::NotInManifest { object: *object });
        }
        Ok(*object)
    }

    /// Serves a request from the fetch scope only, with no registry access at all: the
    /// strongest variant's local lookups (line 2389).
    pub fn serve_offline(
        &mut self,
        catalog: &mut Catalog,
        request: &ContentRequest,
    ) -> Result<ServedObject, ContentRefusal> {
        let object = self.approved(request)?;
        if catalog.status(self.manifest.fetch_scope(), object) != ObjectStatus::Published {
            return Err(ContentRefusal::NotPrefetched { object });
        }
        let bytes = self.read(catalog, object)?;
        Ok(ServedObject {
            object,
            cache: CacheResult::Hit,
            bytes,
        })
    }

    /// Serves a request in lazy mode: a miss is fetched through the fetch service and
    /// observed as metadata (line 2389). Strict private services refuse.
    pub fn serve_lazy(
        &mut self,
        catalog: &mut Catalog,
        fetch: &FetchService,
        registry: &mut dyn RegistryPort,
        request: &ContentRequest,
    ) -> Result<ServedObject, ContentRefusal> {
        if self.mode == FetchMode::StrictPrivate {
            return Err(ContentRefusal::WrongMode);
        }
        let object = self.approved(request)?;
        let outcome = fetch
            .ensure(catalog, &self.manifest, object, registry)
            .map_err(ContentRefusal::Fetch)?;
        if outcome.cache == CacheResult::Miss {
            self.observations.push(MetadataObservation {
                object,
                at: self.clock.now(),
            });
        }
        let bytes = self.read(catalog, object)?;
        Ok(ServedObject {
            object,
            cache: outcome.cache,
            bytes,
        })
    }

    /// Reads one object as the compute VM: a grant for exactly this object to the VM's
    /// scope and execution, a lease, a read-only handle, then release and revocation.
    /// Hits and misses take this same path (line 2387).
    fn read(&mut self, catalog: &mut Catalog, object: ObjectId) -> Result<Vec<u8>, ContentRefusal> {
        let owner = self.manifest.fetch_scope().clone();
        let reader = self.manifest.consumer().clone();
        let execution = self.manifest.execution().clone();
        let grant = catalog
            .grant(
                &owner,
                GrantRequest {
                    object,
                    grantee: reader.clone(),
                    execution: Some(execution.clone()),
                    expires_at: self.clock.now().saturating_add(self.read_duration),
                },
            )
            .map_err(ContentRefusal::Grant)?;
        let result = (|| {
            let lease = catalog
                .acquire_lease(&reader, &execution, object, self.read_duration)
                .map_err(ContentRefusal::Read)?;
            let bytes = catalog
                .open_read(&reader, &execution, lease)
                .map_err(ContentRefusal::Read)
                .and_then(|mut handle| handle.read_all().map_err(ContentRefusal::ReadFailed));
            let released = catalog.release_lease(&reader, &execution, lease);
            let bytes = bytes?;
            released.map_err(ContentRefusal::Read)?;
            Ok(bytes)
        })();
        let revoked = catalog.revoke_grant(&owner, grant);
        let bytes = result?;
        revoked.map_err(ContentRefusal::Grant)?;
        Ok(bytes)
    }

    /// Lazy fetches observed so far.
    pub fn observations(&self) -> &[MetadataObservation] {
        &self.observations
    }

    /// How this service's remote activity is classified (line 2389).
    pub fn channel(&self) -> ChannelClassification {
        match &self.mode {
            FetchMode::StrictPrivate => ChannelClassification::NoNetworkAfterPrefetch,
            FetchMode::Lazy { metadata_channel } => {
                ChannelClassification::PermittedMetadataChannel {
                    reveals: [
                        MetadataLeak::ObjectSelection,
                        MetadataLeak::Timing,
                        MetadataLeak::CacheMisses,
                    ]
                    .into_iter()
                    .collect(),
                    remote_fetches: to_u64(self.observations.len()),
                    approval: metadata_channel.clone(),
                }
            }
        }
    }
}
