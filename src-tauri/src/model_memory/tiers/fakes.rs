//! Test fixtures: a real CORE-02 catalog in a temporary directory and its importer, a
//! CORE-03 ledger (T04), T08 host scopes, an explicitly seeded generator and naming
//! helpers.

use std::collections::BTreeSet;
use std::num::NonZeroU64;
use std::sync::Arc;
use std::time::Duration;

use tempfile::TempDir;

use super::charge::LedgerCharge;
use super::object::{Consumer, ObjectRef};
use super::representations::ModelKey;
use super::source::SourcePath;
use crate::foundation::catalog::{
    ArtifactClass, ArtifactVerifier, Catalog, CatalogConfig, CatalogLimits, ContentDescriptor,
    ImportManifest, ImportRequest, ImportSource, ImportStart, ImportStatus, LeaseId, ObjectBytes,
    ObjectMetadata, ObjectRole, PublisherId, ReadHandle, ReadRefusal, RootName, Scope, SourceError,
    SourceIdentity, TrustClaim, TrustPolicy, Uninterrupted, VerifierRegistry, VerifierRejection,
};
use crate::foundation::evidence::{HostSubject, SourceClass};
use crate::foundation::ids::{
    digest, Clock, ContentKey, ExecutionCategory, ExecutionId, GpuDeviceKey, ManualClock,
    MonotonicTime, OperationId, TenantId, TrustScope,
};
use crate::foundation::ledger::{
    CapacityDeclaration, HostResource, Ledger, LedgerConfig, Priority, QueueLimits, ResourceKey,
};
use crate::model_memory::math::bounds::BandwidthRating;
use crate::model_memory::math::sources::{CutSpec, StealPolicy};
use crate::model_memory::math::{CutId, SourceId};
use crate::model_memory::residency::host::{HostScope, HostScopeKind, ScopeOccupancy};
use crate::model_memory::residency::Capacity;

pub(crate) const GIB: u64 = 1 << 30;
pub(crate) const MIB: u64 = 1 << 20;
pub(crate) const KIB: u64 = 1 << 10;
/// Decimal gigabyte, as the plan writes "14 GB" and "24 GB".
pub(crate) const GB: f64 = 1e9;

pub(crate) const RAM: ResourceKey = ResourceKey::Host(HostResource::Ram);
pub(crate) const PINNED: ResourceKey = ResourceKey::Host(HostResource::PinnedRam);
pub(crate) const STORAGE: ResourceKey = ResourceKey::Host(HostResource::StorageQuota);

/// SplitMix64: a small deterministic generator, seeded explicitly by each test.
pub(crate) struct SeededRng(u64);

impl SeededRng {
    pub(crate) fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub(crate) fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A value in `0..bound`.
    pub(crate) fn below(&mut self, bound: u64) -> u64 {
        self.next_u64() % bound
    }
}

pub(crate) fn tenant(name: &str) -> TenantId {
    TenantId::new(name).unwrap()
}

pub(crate) fn execution(name: &str) -> ExecutionId {
    ExecutionId::new(name).unwrap()
}

pub(crate) fn operation(name: &str) -> OperationId {
    OperationId::new(name).unwrap()
}

pub(crate) fn scope(tenant_name: &str) -> Scope {
    Scope::tenant(tenant(tenant_name))
}

/// A tenant's trust scope in these tests: its WSL GPU runtime.
pub(crate) fn trust(tenant_name: &str) -> TrustScope {
    TrustScope::named(ExecutionCategory::SharedKernelGpuRuntime, tenant_name)
}

/// A consumer of `tenant_name` in its own trust scope.
pub(crate) fn consumer(tenant_name: &str, execution_name: &str) -> Consumer {
    Consumer {
        tenant: tenant(tenant_name),
        execution: execution(execution_name),
        trust: trust(tenant_name),
    }
}

/// The same tenant's execution in a VM sandbox: another trust scope.
pub(crate) fn in_vm(tenant_name: &str, execution_name: &str) -> Consumer {
    Consumer {
        trust: TrustScope::named(ExecutionCategory::VmSandbox, tenant_name),
        ..consumer(tenant_name, execution_name)
    }
}

/// The content key of test bytes named `name`.
pub(crate) fn content(name: &str) -> ContentKey {
    ContentKey::of(name.as_bytes())
}

/// Model weights named `name` owned by `tenant_name`, not necessarily published.
pub(crate) fn weights(tenant_name: &str, name: &str) -> ObjectRef {
    ObjectRef {
        scope: scope(tenant_name),
        class: ArtifactClass::ModelWeights,
        content: content(name),
    }
}

pub(crate) fn model(tenant_name: &str, name: &str) -> ModelKey {
    ModelKey {
        scope: scope(tenant_name),
        model: digest("yougori/test/tiers/model/v1", &[name.as_bytes()]),
    }
}

pub(crate) fn root(name: &str) -> RootName {
    RootName::new(name).unwrap()
}

pub(crate) fn at_seconds(seconds: u64) -> MonotonicTime {
    MonotonicTime::from_nanos(seconds * 1_000_000_000)
}

pub(crate) fn clock_at(seconds: u64) -> ManualClock {
    ManualClock::new(at_seconds(seconds))
}

pub(crate) fn device(index: u8) -> GpuDeviceKey {
    GpuDeviceKey {
        machine: digest("yougori/test/machine/v1", &[b"workstation"]),
        device: digest("yougori/test/gpu/v1", &[&[index]]),
    }
}

/// A T08 host scope with nothing observed in it yet.
pub(crate) fn host_scope(
    name: &str,
    kind: HostScopeKind,
    parent: Option<&str>,
    capacity_bytes: u64,
    safety_reserve_bytes: u64,
) -> HostScope {
    HostScope {
        name: name.to_string(),
        kind,
        parent: parent.map(str::to_string),
        capacity: Capacity::Physical {
            bytes: capacity_bytes,
        },
        safety_reserve_bytes,
        occupancy: ScopeOccupancy::default(),
    }
}

/// A ledger on `clock` with nothing declared yet.
pub(crate) fn empty_ledger<C: Clock>(clock: C) -> Ledger<C> {
    Ledger::new(
        clock,
        HostSubject {
            machine: digest("yougori/test/machine/v1", &[b"workstation"]),
        },
        LedgerConfig {
            queue: QueueLimits {
                max_entries: 4,
                max_entries_per_tenant: 2,
                max_wait: Duration::from_secs(60),
            },
            grant_ttl: Duration::from_secs(300),
            unmanaged_usage_max_age: Duration::from_secs(1 << 40),
        },
    )
}

/// Declares `total` units of `resource` from a host probe and gives each named tenant an
/// unlimited budget for it.
pub(crate) fn declare<C: Clock>(
    ledger: &mut Ledger<C>,
    resource: ResourceKey,
    total: u64,
    tenants: &[&str],
) {
    ledger
        .declare_capacity(
            resource,
            CapacityDeclaration {
                total,
                supervisor_reserve: 0,
                unmanaged_in_use: 0,
                source: SourceClass::HostProbe,
            },
        )
        .unwrap();
    for name in tenants {
        ledger
            .set_tenant_budget(tenant(name), resource, u64::MAX)
            .unwrap();
    }
}

/// A foreground first attempt of `operation_name`.
pub(crate) fn charge(operation_name: &str) -> LedgerCharge {
    LedgerCharge {
        operation: operation(operation_name),
        priority: Priority::Foreground,
        retry_number: 0,
    }
}

pub(crate) fn source_id(name: &str) -> SourceId {
    SourceId::new(name).unwrap()
}

pub(crate) fn cut_id(name: &str) -> CutId {
    CutId::new(name).unwrap()
}

pub(crate) fn cut(name: &str, bytes_per_second: f64) -> CutSpec {
    CutSpec {
        id: cut_id(name),
        bandwidth: BandwidthRating::measured_directional(bytes_per_second).unwrap(),
    }
}

/// A measured path with no interference.
pub(crate) fn path(bytes_per_second: f64, startup_seconds: f64, cuts: &[&str]) -> SourcePath {
    SourcePath {
        startup_seconds,
        bandwidth: BandwidthRating::measured_directional(bytes_per_second).unwrap(),
        cuts: cuts.iter().map(|name| cut_id(name)).collect(),
        max_in_flight: 4,
        interference_seconds_per_byte: 0.0,
    }
}

/// Hysteresis as T03's tests use it.
pub(crate) const HYSTERESIS: StealPolicy = StealPolicy {
    min_gain_seconds: 0.0,
    min_gain_fraction: 0.05,
    max_moves_per_batch: 1,
    max_moves_per_rebalance: 16,
};

/// True when `actual` is within `tolerance` of `expected`.
pub(crate) fn close(actual: f64, expected: f64, tolerance: f64) -> bool {
    (actual - expected).abs() <= tolerance
}

/// Accepts every structure; the catalog still checks every byte against the content key.
struct AcceptingVerifier(ArtifactClass);

impl ArtifactVerifier for AcceptingVerifier {
    fn class(&self) -> ArtifactClass {
        self.0
    }

    fn authenticate(
        &self,
        _content: &ContentDescriptor,
        _publisher: &PublisherId,
        _attestation: &[u8],
    ) -> Result<(), VerifierRejection> {
        Err(VerifierRejection::AttestationInvalid)
    }

    fn validate(
        &self,
        _content: &ContentDescriptor,
        _bytes: &mut ObjectBytes,
    ) -> Result<(), VerifierRejection> {
        Ok(())
    }
}

/// The publisher of Yougori's own artifacts in these tests.
pub(crate) fn release_publisher() -> PublisherId {
    PublisherId::from_key_fingerprint(digest("yougori/test/tiers/publisher/v1", &[b"release"]))
}

/// The release publisher's attestation of `content`: its content key, which
/// [`ReleaseVerifier`] checks.
pub(crate) fn release_attestation(content: &ContentKey) -> Vec<u8> {
    content.to_string().into_bytes()
}

/// Accepts the release publisher's attestation of the content key and every structure;
/// the catalog still checks every byte against the content key.
struct ReleaseVerifier(ArtifactClass);

impl ArtifactVerifier for ReleaseVerifier {
    fn class(&self) -> ArtifactClass {
        self.0
    }

    fn authenticate(
        &self,
        content: &ContentDescriptor,
        publisher: &PublisherId,
        attestation: &[u8],
    ) -> Result<(), VerifierRejection> {
        if *publisher == release_publisher()
            && attestation == release_attestation(&content.content_key)
        {
            Ok(())
        } else {
            Err(VerifierRejection::AttestationInvalid)
        }
    }

    fn validate(
        &self,
        _content: &ContentDescriptor,
        _bytes: &mut ObjectBytes,
    ) -> Result<(), VerifierRejection> {
        Ok(())
    }
}

/// Bytes in memory, read in bounded ranges.
struct BytesSource {
    identity: SourceIdentity,
    bytes: Vec<u8>,
}

impl ImportSource for BytesSource {
    fn identity(&self) -> SourceIdentity {
        self.identity
    }

    fn length_bytes(&mut self) -> Result<u64, SourceError> {
        Ok(self.bytes.len() as u64)
    }

    fn read_at(&mut self, offset_bytes: u64, buffer: &mut [u8]) -> Result<usize, SourceError> {
        let start = usize::try_from(offset_bytes).unwrap();
        let available = self.bytes.get(start..).unwrap_or(&[]);
        let count = available.len().min(buffer.len());
        buffer[..count].copy_from_slice(&available[..count]);
        Ok(count)
    }
}

/// A real catalog in a temporary directory. Each named tenant and Yougori's own host
/// scope have a 1 MiB quota; user-selected model weights and the release publisher's
/// guest images are trusted; collection waits a 60 s grace period.
pub(crate) struct TestCatalog {
    pub(crate) catalog: Catalog,
    _root: TempDir,
}

pub(crate) fn open_catalog(clock: Arc<ManualClock>, tenants: &[&str]) -> TestCatalog {
    let root = TempDir::new().unwrap();
    let mut config = CatalogConfig::new(Duration::from_secs(60))
        .with_limits(CatalogLimits {
            max_object_bytes: 1 << 20,
            max_extent_bytes: 64,
            ..CatalogLimits::default()
        })
        .with_trust(
            ArtifactClass::ModelWeights,
            TrustPolicy::new().accept_user_selected(),
        )
        .with_trust(
            ArtifactClass::GuestImage,
            TrustPolicy::new().trust_publisher(release_publisher()),
        )
        .with_quota(Scope::Host, 1 << 20);
    for name in tenants {
        config = config.with_quota(scope(name), 1 << 20);
    }
    let mut verifiers = VerifierRegistry::new();
    verifiers
        .register(Box::new(AcceptingVerifier(ArtifactClass::ModelWeights)))
        .unwrap();
    verifiers
        .register(Box::new(ReleaseVerifier(ArtifactClass::GuestImage)))
        .unwrap();
    let clock: Arc<dyn Clock> = clock;
    let (catalog, _) = Catalog::open(root.path(), config, verifiers, clock).unwrap();
    TestCatalog {
        catalog,
        _root: root,
    }
}

/// One clock shared by a real catalog for `tenants` and an empty ledger.
pub(crate) struct World {
    pub(crate) clock: Arc<ManualClock>,
    pub(crate) catalog: Catalog,
    pub(crate) ledger: Ledger<Arc<ManualClock>>,
    _root: TempDir,
}

pub(crate) fn world(tenants: &[&str]) -> World {
    let clock = Arc::new(clock_at(0));
    let TestCatalog { catalog, _root } = open_catalog(clock.clone(), tenants);
    World {
        ledger: empty_ledger(clock.clone()),
        clock,
        catalog,
        _root,
    }
}

/// The importer publishes `bytes` as model weights of `owner`'s scope with `role`.
pub(crate) fn publish(
    catalog: &mut Catalog,
    owner: &Consumer,
    bytes: &[u8],
    role: ObjectRole,
) -> ObjectRef {
    publish_in(
        catalog,
        owner.scope(),
        &owner.execution,
        ArtifactClass::ModelWeights,
        bytes,
        role,
    )
}

/// The importer, run by `importer`, publishes `bytes` as an object of `class` in `scope`
/// with `role`. A tenant's object is user-selected; one of Yougori's own host scope
/// carries the release publisher's attestation, since user selection is tenant-only.
pub(crate) fn publish_in(
    catalog: &mut Catalog,
    scope: Scope,
    importer: &ExecutionId,
    class: ArtifactClass,
    bytes: &[u8],
    role: ObjectRole,
) -> ObjectRef {
    let manifest = ImportManifest::describe(bytes, NonZeroU64::new(64).unwrap());
    let object = ObjectRef {
        scope,
        class,
        content: manifest.content_key,
    };
    let mut source = BytesSource {
        identity: SourceIdentity::describe("test", &object.content.to_string()),
        bytes: bytes.to_vec(),
    };
    let request = ImportRequest {
        operation: operation("op-import"),
        execution: importer.clone(),
        scope: object.scope.clone(),
        class: object.class,
        role,
        manifest,
        trust: match &object.scope {
            Scope::Host => TrustClaim::Publisher {
                publisher: release_publisher(),
                attestation: release_attestation(&object.content),
            },
            Scope::Tenant { .. } => TrustClaim::UserSelected,
        },
        depends_on: BTreeSet::new(),
        metadata: ObjectMetadata::new(),
    };
    let ticket = match catalog.begin_import(request, source.identity()).unwrap() {
        ImportStart::Started(ticket) => ticket,
        other => panic!("expected a new import, got {other:?}"),
    };
    match catalog
        .drive_import(&ticket, &mut source, &mut Uninterrupted)
        .unwrap()
    {
        ImportStatus::Published { object: id, .. } => assert_eq!(id, object.id()),
        other => panic!("expected publication, got {other:?}"),
    }
    object
}

/// The importer publishes `bytes` as a representation prepared from `sources`.
pub(crate) fn publish_prepared(
    catalog: &mut Catalog,
    owner: &Consumer,
    bytes: &[u8],
    sources: &[&ObjectRef],
) -> ObjectRef {
    let derived_from = sources.iter().map(|source| source.id()).collect();
    publish(catalog, owner, bytes, ObjectRole::Prepared { derived_from })
}

/// A fresh ten-minute lease for `reader` on `object`.
pub(crate) fn lease(
    catalog: &mut Catalog,
    reader: &Consumer,
    object: &ObjectRef,
) -> Result<LeaseId, ReadRefusal> {
    catalog.acquire_lease(
        &reader.scope(),
        &reader.execution,
        object.id(),
        Duration::from_secs(600),
    )
}

/// Opens a read-only handle for `reader` on `object` under a fresh lease.
pub(crate) fn read_handle(
    catalog: &mut Catalog,
    reader: &Consumer,
    object: &ObjectRef,
) -> Result<ReadHandle, ReadRefusal> {
    let lease = lease(catalog, reader, object)?;
    catalog.open_read(&reader.scope(), &reader.execution, lease)
}

/// Flips the first byte of `object`'s committed data file under the catalog's root, as a
/// disk fault or an unauthorized write would.
pub(crate) fn corrupt_stored(world: &World, object: &ObjectRef) {
    let path = world
        ._root
        .path()
        .join("objects")
        .join(object.id().to_string())
        .join("data");
    let mut permissions = std::fs::metadata(&path).unwrap().permissions();
    permissions.set_readonly(false);
    std::fs::set_permissions(&path, permissions).unwrap();
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[0] ^= 0xFF;
    std::fs::write(&path, bytes).unwrap();
}
