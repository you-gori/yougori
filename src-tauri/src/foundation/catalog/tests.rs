//! Rule tests for the catalog (S2 CORE-02, S3.3, INT-05, INT-09, GPU part §1.1 line 306
//! and §3.3–§3.4). Each "never", "cannot" and "must" in those lines is tried and shown
//! refused.

use std::collections::BTreeSet;
use std::fs;
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use tempfile::TempDir;

use super::fakes::{
    attestation, header_object, manifest_attestation, FakeSource, FakeVerifier, StopAt,
};
use super::*;
use crate::foundation::evidence::ArtifactVerification;
use crate::foundation::ids::{
    digest, Clock, ContentKey, ExecutionId, ManualClock, MonotonicTime, OperationId, TenantId,
};
use crate::foundation::report::{FailureKind, Label, Outcome};

const GRACE: Duration = Duration::from_secs(60);
const EXTENT_BYTES: u64 = 8;
const QUOTA_BYTES: u64 = 4096;
const LEASE: Duration = Duration::from_secs(30);

fn tenant(name: &str) -> Scope {
    Scope::tenant(TenantId::new(name).unwrap())
}

fn execution(name: &str) -> ExecutionId {
    ExecutionId::new(name).unwrap()
}

fn publisher(name: &str) -> PublisherId {
    PublisherId::from_key_fingerprint(digest("yougori/test/publisher/v1", &[name.as_bytes()]))
}

fn acme() -> PublisherId {
    publisher("acme")
}

fn data(seed: u8, length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| seed.wrapping_add((index as u8).wrapping_mul(7)))
        .collect()
}

fn base_config() -> CatalogConfig {
    let mut config = CatalogConfig::new(GRACE).with_limits(CatalogLimits {
        max_object_bytes: 1 << 20,
        max_extent_bytes: 64,
        ..CatalogLimits::default()
    });
    for scope in [tenant("a"), tenant("b"), tenant("c"), Scope::Host] {
        config = config.with_quota(scope, QUOTA_BYTES);
    }
    for class in ArtifactClass::ALL {
        let mut policy = TrustPolicy::new().trust_publisher(acme());
        if class == ArtifactClass::ModelWeights {
            policy = policy.accept_user_selected();
        }
        config = config.with_trust(class, policy);
    }
    config
}

fn verifiers() -> VerifierRegistry {
    let mut registry = VerifierRegistry::new();
    for class in ArtifactClass::ALL {
        let verifier = if class == ArtifactClass::DocumentManifest {
            FakeVerifier::header(class)
        } else {
            FakeVerifier::new(class)
        };
        registry.register(Box::new(verifier)).unwrap();
    }
    registry
}

struct Fixture {
    dir: TempDir,
    clock: Arc<ManualClock>,
}

impl Fixture {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
            clock: Arc::new(ManualClock::new(MonotonicTime::from_nanos(1_000_000_000))),
        }
    }

    fn root(&self) -> &Path {
        self.dir.path()
    }

    fn open(&self) -> Catalog {
        self.open_with(base_config(), verifiers()).0
    }

    fn open_with(
        &self,
        config: CatalogConfig,
        verifiers: VerifierRegistry,
    ) -> (Catalog, OpenReport) {
        Catalog::open(self.root(), config, verifiers, self.clock.clone()).unwrap()
    }

    /// Drops the catalog, as a crash or restart would, and opens the root again.
    fn reopen(&self, catalog: Catalog) -> (Catalog, OpenReport) {
        drop(catalog);
        self.open_with(base_config(), verifiers())
    }

    fn advance(&self, by: Duration) {
        self.clock.advance(by);
    }

    fn now(&self) -> MonotonicTime {
        self.clock.now()
    }

    fn object_dir(&self, object: ObjectId) -> PathBuf {
        self.root().join("objects").join(object.to_string())
    }

    fn record(&self, object: ObjectId) -> PathBuf {
        self.root().join("records").join(format!("{object}.json"))
    }

    fn staging_dirs(&self) -> Vec<PathBuf> {
        list(&self.root().join("staging"))
    }

    fn staged_data(&self) -> PathBuf {
        let dirs = self.staging_dirs();
        assert_eq!(dirs.len(), 1);
        dirs[0].join("object").join("data")
    }

    fn journal(&self) -> PathBuf {
        let dirs = self.staging_dirs();
        assert_eq!(dirs.len(), 1);
        dirs[0].join("journal")
    }
}

impl Drop for Fixture {
    /// Committed files are read-only; make them writable so the temporary root goes.
    fn drop(&mut self) {
        make_tree_writable(self.dir.path());
    }
}

fn make_tree_writable(path: &Path) {
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            make_tree_writable(&entry.path());
        }
    }
    if let Ok(metadata) = fs::metadata(path) {
        let mut permissions = metadata.permissions();
        if permissions.readonly() {
            permissions.set_readonly(false);
            let _ = fs::set_permissions(path, permissions);
        }
    }
}

fn list(dir: &Path) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = fs::read_dir(dir)
        .map(|entries| entries.flatten().map(|entry| entry.path()).collect())
        .unwrap_or_default();
    paths.sort();
    paths
}

fn overwrite(path: &Path, offset: u64, bytes: &[u8]) {
    make_tree_writable(path);
    let mut file = fs::OpenOptions::new().write(true).open(path).unwrap();
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.write_all(bytes).unwrap();
}

fn request(scope: &Scope, class: ArtifactClass, bytes: &[u8]) -> ImportRequest {
    let manifest = ImportManifest::describe(bytes, NonZeroU64::new(EXTENT_BYTES).unwrap());
    ImportRequest {
        operation: OperationId::new("op-import").unwrap(),
        execution: execution("exe-1"),
        scope: scope.clone(),
        class,
        role: ObjectRole::Original,
        trust: TrustClaim::Publisher {
            publisher: acme(),
            attestation: attestation(&acme(), class, manifest.content_key),
        },
        manifest,
        depends_on: BTreeSet::new(),
        metadata: ObjectMetadata::new().with_label("name", "private-model"),
    }
}

fn weights(scope: &Scope, bytes: &[u8]) -> ImportRequest {
    request(scope, ArtifactClass::ModelWeights, bytes)
}

fn prepared_request(scope: &Scope, bytes: &[u8], from: &[ObjectId]) -> ImportRequest {
    let mut request = request(scope, ArtifactClass::ModelSidecar, bytes);
    request.role = ObjectRole::Prepared {
        derived_from: from.iter().copied().collect(),
    };
    request
}

fn started(start: ImportStart) -> ImportTicket {
    match start {
        ImportStart::Started(ticket) => ticket,
        other => panic!("expected a new import, got {other:?}"),
    }
}

fn published(status: ImportStatus) -> (ObjectId, ImportProgress) {
    match status {
        ImportStatus::Published { object, progress } => (object, progress),
        other => panic!("expected publication, got {other:?}"),
    }
}

fn pending(status: ImportStatus) -> (ImportProgress, FailureRecord) {
    match status {
        ImportStatus::Pending {
            progress,
            last_failure: Some(failure),
        } => (progress, failure),
        other => panic!("expected a paused import, got {other:?}"),
    }
}

fn failed(status: ImportStatus) -> FailureRecord {
    match status {
        ImportStatus::Failed { failure } => failure,
        other => panic!("expected a failed import, got {other:?}"),
    }
}

fn import(catalog: &mut Catalog, request: ImportRequest, source: &mut FakeSource) -> ObjectId {
    match catalog.begin_import(request, source.identity()).unwrap() {
        ImportStart::Started(ticket) | ImportStart::Attached(ticket) => {
            published(
                catalog
                    .drive_import(&ticket, source, &mut Uninterrupted)
                    .unwrap(),
            )
            .0
        }
        ImportStart::AlreadyPublished(object) => object,
    }
}

fn import_bytes(catalog: &mut Catalog, request: ImportRequest, bytes: &[u8]) -> ObjectId {
    let locator = format!("source-{}", ContentKey::of(bytes));
    import(catalog, request, &mut FakeSource::new(&locator, bytes))
}

fn read(
    catalog: &mut Catalog,
    reader: &Scope,
    execution: &ExecutionId,
    object: ObjectId,
) -> Result<Vec<u8>, ReadRefusal> {
    let lease = catalog.acquire_lease(reader, execution, object, LEASE)?;
    let bytes = catalog
        .open_read(reader, execution, lease)?
        .read_all()
        .unwrap();
    catalog.release_lease(reader, execution, lease)?;
    Ok(bytes)
}

fn grant_to(grantee: &Scope, object: ObjectId, expires_at: MonotonicTime) -> GrantRequest {
    GrantRequest {
        object,
        grantee: grantee.clone(),
        execution: None,
        expires_at,
    }
}

// Publication (line 533) and read-only consumers (line 546).

#[test]
fn an_import_runs_the_protocol_in_order_and_publishes_read_only_content() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let a = tenant("a");
    let bytes = data(1, 20);
    let mut source = FakeSource::new("weights", &bytes);
    let ticket = started(
        catalog
            .begin_import(weights(&a, &bytes), source.identity())
            .unwrap(),
    );
    let mut control = StopAt::extent(u32::MAX);
    let (object, progress) = published(
        catalog
            .drive_import(&ticket, &mut source, &mut control)
            .unwrap(),
    );

    let stages: Vec<ImportStage> = control
        .seen
        .iter()
        .filter_map(|checkpoint| match checkpoint {
            Checkpoint::Stage { stage } => Some(*stage),
            Checkpoint::Extent { .. } => None,
        })
        .collect();
    assert_eq!(stages, ImportStage::ALL);
    assert_eq!(
        progress,
        ImportProgress {
            verified_extents: 3,
            fetched_extents: 3,
            reused_extents: 0,
            refetched_extents: 0,
            fetched_bytes: 20,
        }
    );
    assert_eq!(source.reads(), 3);
    assert_eq!(
        object,
        ObjectId::new(&a, ArtifactClass::ModelWeights, ContentKey::of(&bytes))
    );
    assert_eq!(
        catalog.find(&a, ArtifactClass::ModelWeights, ContentKey::of(&bytes)),
        Some(object)
    );
    assert_eq!(catalog.status(&a, object), ObjectStatus::Published);
    assert_eq!(
        read(&mut catalog, &a, &execution("exe-1"), object).unwrap(),
        bytes
    );

    // Committed content is read-only: no consumer, or anyone else, opens it to write.
    for name in ["data", "index.json"] {
        let path = fixture.object_dir(object).join(name);
        assert!(
            fs::metadata(&path).unwrap().permissions().readonly(),
            "{name}"
        );
        assert!(
            fs::OpenOptions::new().write(true).open(&path).is_err(),
            "{name}"
        );
    }
    assert!(fixture.record(object).exists());
    assert!(fixture.staging_dirs().is_empty());
    let usage = catalog.quota_usage(&a);
    assert_eq!(
        (
            usage.published_bytes,
            usage.reserved_bytes,
            usage.unpublished_bytes
        ),
        (20, 0, 0)
    );

    let reader = execution("exe-1");
    let lease = catalog.acquire_lease(&a, &reader, object, LEASE).unwrap();
    let mut handle = catalog.open_read(&a, &reader, lease).unwrap();
    assert_eq!(handle.read_extent(2).unwrap(), bytes[16..]);
    assert_eq!(
        handle.read_extent(3),
        Err(ReadError::OutOfRange { extent: 3 })
    );
    assert_eq!(
        (
            handle.object(),
            handle.class(),
            handle.content_key(),
            handle.length_bytes()
        ),
        (
            object,
            ArtifactClass::ModelWeights,
            ContentKey::of(&bytes),
            20
        )
    );
    assert_eq!(handle.extents().len(), 3);
}

#[test]
fn an_interrupted_publication_publishes_nothing() {
    let a = tenant("a");
    let bytes = data(2, 20);
    for stage in ImportStage::ALL {
        let fixture = Fixture::new();
        let mut catalog = fixture.open();
        let mut source = FakeSource::new("weights", &bytes);
        let ticket = started(
            catalog
                .begin_import(weights(&a, &bytes), source.identity())
                .unwrap(),
        );
        let (_, failure) = pending(
            catalog
                .drive_import(&ticket, &mut source, &mut StopAt::stage(stage))
                .unwrap(),
        );
        assert_eq!(failure.stage, stage);
        assert_eq!(
            failure.reason,
            FailureReason::Interrupted {
                at: Checkpoint::Stage { stage }
            }
        );
        let object = failure.object;
        assert_eq!(
            catalog.find(&a, ArtifactClass::ModelWeights, ContentKey::of(&bytes)),
            None,
            "{stage:?}"
        );
        assert_eq!(catalog.status(&a, object), ObjectStatus::Absent);
        assert_eq!(
            catalog.acquire_lease(&a, &execution("exe-1"), object, LEASE),
            Err(ReadRefusal::NotGranted { object })
        );
        assert!(!fixture.record(object).exists());

        // A crash at this point: the reopened catalog publishes nothing either.
        let (mut catalog, report) = fixture.reopen(catalog);
        assert_eq!(report.published, 0, "{stage:?}");
        assert_eq!(
            report.unpublished.contains(&object),
            stage == ImportStage::CatalogPublication,
            "{stage:?}"
        );
        assert_eq!(catalog.status(&a, object), ObjectStatus::Absent);

        // Resuming publishes, reusing what was verified before the interruption.
        source.reset_reads();
        let ticket = started(
            catalog
                .begin_import(weights(&a, &bytes), source.identity())
                .unwrap(),
        );
        let (resumed, _) = published(
            catalog
                .drive_import(&ticket, &mut source, &mut Uninterrupted)
                .unwrap(),
        );
        assert_eq!(resumed, object);
        let expected_reads = if stage <= ImportStage::TemporaryRepresentation {
            3
        } else {
            0
        };
        assert_eq!(source.reads(), expected_reads, "{stage:?}");
        assert_eq!(
            read(&mut catalog, &a, &execution("exe-1"), object).unwrap(),
            bytes
        );
    }
}

#[test]
fn a_cancelled_import_never_publishes_and_resumes_from_verified_extents() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let a = tenant("a");
    let bytes = data(3, 32);
    let mut source = FakeSource::new("weights", &bytes);
    let ticket = started(
        catalog
            .begin_import(weights(&a, &bytes), source.identity())
            .unwrap(),
    );
    let (progress, failure) = pending(
        catalog
            .drive_import(&ticket, &mut source, &mut StopAt::extent(2))
            .unwrap(),
    );
    assert_eq!(progress.verified_extents, 2);
    assert_eq!(
        failure.reason,
        FailureReason::Interrupted {
            at: Checkpoint::Extent { extent: 2 }
        }
    );
    assert_eq!(failure.reason.kind(), FailureKind::EarlyTermination);
    assert_eq!(catalog.quota_usage(&a).reserved_bytes, 32);

    assert_eq!(catalog.cancel_import(ticket), CancelOutcome::Cancelled);
    assert_eq!(
        catalog.find(&a, ArtifactClass::ModelWeights, ContentKey::of(&bytes)),
        None
    );
    // The cancelled staging stays charged until it is resumed or collected.
    let usage = catalog.quota_usage(&a);
    assert_eq!((usage.reserved_bytes, usage.unpublished_bytes), (0, 32));
    assert!(catalog
        .failures()
        .any(|record| record.reason == FailureReason::Cancelled));

    let (mut catalog, report) = fixture.reopen(catalog);
    assert_eq!((report.published, report.staging), (0, 1));
    let ticket = started(
        catalog
            .begin_import(weights(&a, &bytes), source.identity())
            .unwrap(),
    );
    // A cancel flag stops the import at its next checkpoint.
    let flag = CancelFlag::new();
    flag.cancel();
    assert!(flag.is_cancelled());
    let (_, failure) = pending(
        catalog
            .drive_import(&ticket, &mut source, &mut flag.clone())
            .unwrap(),
    );
    assert_eq!(
        failure.reason,
        FailureReason::Interrupted {
            at: Checkpoint::Stage {
                stage: ImportStage::SourceVerification
            }
        }
    );

    source.reset_reads();
    let (object, progress) = published(
        catalog
            .drive_import(&ticket, &mut source, &mut Uninterrupted)
            .unwrap(),
    );
    assert_eq!((progress.reused_extents, progress.fetched_extents), (2, 2));
    assert_eq!(
        [0, 8, 16, 24].map(|offset| source.reads_at(offset)),
        [0, 0, 1, 1]
    );
    assert_eq!(
        read(&mut catalog, &a, &execution("exe-1"), object).unwrap(),
        bytes
    );
}

// Resumable verified data (CORE-02).

#[test]
fn a_resumed_import_refetches_corrupt_extents_and_never_trusts_unlisted_data() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let a = tenant("a");
    let bytes = data(4, 32);
    let mut source = FakeSource::new("weights", &bytes);
    let ticket = started(
        catalog
            .begin_import(weights(&a, &bytes), source.identity())
            .unwrap(),
    );
    pending(
        catalog
            .drive_import(&ticket, &mut source, &mut StopAt::extent(3))
            .unwrap(),
    );

    let staged = fixture.staged_data();
    // Extent 1 was verified, then corrupted on disk.
    overwrite(&staged, 8, b"garbage!");
    // Extent 3 now holds the right bytes, but they were never verified.
    overwrite(&staged, 24, &bytes[24..32]);

    source.reset_reads();
    let (object, progress) = published(
        catalog
            .drive_import(&ticket, &mut source, &mut Uninterrupted)
            .unwrap(),
    );
    assert_eq!(
        [0, 8, 16, 24].map(|offset| source.reads_at(offset)),
        [0, 1, 0, 1]
    );
    assert_eq!(
        (
            progress.reused_extents,
            progress.refetched_extents,
            progress.fetched_extents
        ),
        (2, 1, 5)
    );
    assert_eq!(
        read(&mut catalog, &a, &execution("exe-1"), object).unwrap(),
        bytes
    );
}

#[test]
fn a_torn_journal_costs_refetches_never_trust() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let a = tenant("a");
    let bytes = data(5, 32);
    let mut source = FakeSource::new("weights", &bytes);
    let ticket = started(
        catalog
            .begin_import(weights(&a, &bytes), source.identity())
            .unwrap(),
    );
    pending(
        catalog
            .drive_import(&ticket, &mut source, &mut StopAt::extent(2))
            .unwrap(),
    );
    // A crash in the middle of an append, then an entry naming no extent.
    let journal = fixture.journal();
    let mut text = fs::read_to_string(&journal).unwrap();
    text.push_str("extent 9\nextent 3\nexte");
    fs::write(&journal, text).unwrap();

    source.reset_reads();
    published(
        catalog
            .drive_import(&ticket, &mut source, &mut Uninterrupted)
            .unwrap(),
    );
    assert_eq!(
        [0, 8, 16, 24].map(|offset| source.reads_at(offset)),
        [0, 0, 1, 1]
    );
}

#[test]
fn staged_data_of_another_declaration_is_discarded() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let a = tenant("a");
    let first = data(6, 24);
    let mut source = FakeSource::new("weights", &first);
    let ticket = started(
        catalog
            .begin_import(weights(&a, &first), source.identity())
            .unwrap(),
    );
    pending(
        catalog
            .drive_import(&ticket, &mut source, &mut StopAt::extent(2))
            .unwrap(),
    );
    assert_eq!(catalog.cancel_import(ticket), CancelOutcome::Cancelled);

    // The same source and execution now declare other content of the same length.
    let second = data(7, 24);
    let mut source = FakeSource::new("weights", &second);
    let object = import(&mut catalog, weights(&a, &second), &mut source);
    assert_eq!(source.reads(), 3);
    assert_eq!(
        read(&mut catalog, &a, &execution("exe-1"), object).unwrap(),
        second
    );
}

#[test]
fn a_source_that_keeps_corrupting_an_extent_is_retried_within_bounds() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let a = tenant("a");
    let bytes = data(8, 24);
    let mut source = FakeSource::new("weights", &bytes);
    source.corrupt_at(8, 2);
    let object = import(&mut catalog, weights(&a, &bytes), &mut source);
    assert_eq!(source.reads_at(8), 3);
    assert_eq!(
        read(&mut catalog, &a, &execution("exe-1"), object).unwrap(),
        bytes
    );

    let other = data(9, 24);
    let mut source = FakeSource::new("other", &other);
    source.corrupt_at(8, 10);
    let ticket = started(
        catalog
            .begin_import(weights(&a, &other), source.identity())
            .unwrap(),
    );
    let (_, failure) = pending(
        catalog
            .drive_import(&ticket, &mut source, &mut Uninterrupted)
            .unwrap(),
    );
    assert_eq!(
        failure.reason,
        FailureReason::ExtentDigestMismatch {
            extent: 1,
            attempts: 3
        }
    );
    assert_eq!(failure.reason.kind(), FailureKind::InvalidResult);
    assert_eq!(source.reads_at(8), 3);
    assert_eq!(
        catalog.find(&a, ArtifactClass::ModelWeights, ContentKey::of(&other)),
        None
    );

    source.heal();
    source.reset_reads();
    let (object, _) = published(
        catalog
            .drive_import(&ticket, &mut source, &mut Uninterrupted)
            .unwrap(),
    );
    assert_eq!(source.reads_at(0), 0);
    assert_eq!(
        read(&mut catalog, &a, &execution("exe-1"), object).unwrap(),
        other
    );
}

#[test]
fn bounded_source_verification_refuses_a_wrong_length_before_fetching() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let a = tenant("a");
    let bytes = data(10, 20);
    let mut source = FakeSource::new("weights", &bytes);
    source.report_length(21);
    let ticket = started(
        catalog
            .begin_import(weights(&a, &bytes), source.identity())
            .unwrap(),
    );
    let failure = failed(
        catalog
            .drive_import(&ticket, &mut source, &mut Uninterrupted)
            .unwrap(),
    );
    assert_eq!(failure.stage, ImportStage::SourceVerification);
    assert_eq!(
        failure.reason,
        FailureReason::SourceLengthMismatch {
            declared_bytes: 20,
            source_bytes: 21
        }
    );
    assert_eq!(source.reads(), 0);
    assert!(fixture.staging_dirs().is_empty());
    assert_eq!(catalog.quota_usage(&a).charged_bytes(), 0);
    // A finished import only reports its status.
    assert_eq!(
        catalog.drive_import(&ticket, &mut source, &mut Uninterrupted),
        Ok(ImportStatus::Failed { failure })
    );

    // A source failing midway pauses, keeping what was verified.
    let mut source = FakeSource::new("flaky", &bytes);
    source.fail_from(8);
    let ticket = started(
        catalog
            .begin_import(weights(&a, &bytes), source.identity())
            .unwrap(),
    );
    let (progress, failure) = pending(
        catalog
            .drive_import(&ticket, &mut source, &mut Uninterrupted)
            .unwrap(),
    );
    assert_eq!(progress.verified_extents, 1);
    assert!(matches!(
        failure.reason,
        FailureReason::SourceFailed {
            extent: Some(1),
            ..
        }
    ));
    assert_eq!(failure.reason.kind(), FailureKind::CommandFailure);
    source.heal();
    source.reset_reads();
    published(
        catalog
            .drive_import(&ticket, &mut source, &mut Uninterrupted)
            .unwrap(),
    );
    assert_eq!(source.reads_at(0), 0);
}

#[test]
fn only_the_admitted_source_drives_an_import() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let a = tenant("a");
    let bytes = data(11, 20);
    let source = FakeSource::new("weights", &bytes);
    let ticket = started(
        catalog
            .begin_import(weights(&a, &bytes), source.identity())
            .unwrap(),
    );
    let mut impostor = FakeSource::new("impostor", &bytes);
    assert_eq!(
        catalog.drive_import(&ticket, &mut impostor, &mut Uninterrupted),
        Err(ImportError::WrongSource {
            expected: source.identity(),
            found: impostor.identity()
        })
    );
    assert_eq!(impostor.reads(), 0);
}

#[test]
fn empty_objects_and_piecemeal_sources_publish_exactly() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let a = tenant("a");
    let empty = import_bytes(&mut catalog, weights(&a, b""), b"");
    assert_eq!(
        read(&mut catalog, &a, &execution("exe-1"), empty).unwrap(),
        b""
    );

    let bytes = data(12, 20);
    let mut source = FakeSource::new("trickle", &bytes).chunked(3);
    let object = import(&mut catalog, weights(&a, &bytes), &mut source);
    assert!(source.reads() > 3);
    assert_eq!(
        read(&mut catalog, &a, &execution("exe-1"), object).unwrap(),
        bytes
    );
}

// Corrupt manifests (CORE-02 tests; line 531).

#[test]
fn a_corrupt_manifest_is_rejected_before_anything_is_written() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let a = tenant("a");
    let bytes = data(13, 24);
    let source = FakeSource::new("weights", &bytes);
    let corruptions: Vec<(Box<dyn Fn(&mut ImportManifest)>, ManifestError)> = vec![
        (
            Box::new(|manifest| manifest.extents[1].offset_bytes = 4),
            ManifestError::Overlap {
                extent: 1,
                expected_offset_bytes: 8,
                found_offset_bytes: 4,
            },
        ),
        (
            Box::new(|manifest| manifest.extents[2].offset_bytes = 17),
            ManifestError::Gap {
                extent: 2,
                expected_offset_bytes: 16,
                found_offset_bytes: 17,
            },
        ),
        (
            Box::new(|manifest| {
                manifest.extents.pop();
            }),
            ManifestError::LengthMismatch {
                covered_bytes: 16,
                true_length_bytes: 24,
            },
        ),
        (
            Box::new(|manifest| manifest.true_length_bytes = 1 << 21),
            ManifestError::ObjectTooLarge {
                true_length_bytes: 1 << 21,
                max_object_bytes: 1 << 20,
            },
        ),
        (
            Box::new(|manifest| manifest.extents[0].length_bytes = 65),
            ManifestError::ExtentTooLarge {
                extent: 0,
                length_bytes: 65,
                max_extent_bytes: 64,
            },
        ),
    ];
    let count = corruptions.len();
    for (corrupt, error) in corruptions {
        let mut request = weights(&a, &bytes);
        corrupt(&mut request.manifest);
        assert_eq!(
            catalog.begin_import(request, source.identity()),
            Err(ImportRefusal::Manifest { error })
        );
    }
    assert!(fixture.staging_dirs().is_empty());
    assert!(list(&fixture.root().join("objects")).is_empty());
    let records: Vec<&FailureRecord> = catalog.failures().collect();
    assert_eq!(records.len(), count);
    for record in records {
        assert_eq!(record.stage, ImportStage::SourceVerification);
        assert!(matches!(
            record.reason,
            FailureReason::Refused {
                refusal: ImportRefusal::Manifest { .. }
            }
        ));
        assert_eq!(record.reason.kind(), FailureKind::Rejected);
        assert_eq!(record.reason.code(), "manifest_rejected");
    }
}

#[test]
fn a_manifest_contradicting_its_content_key_is_rejected_at_read_back() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let a = tenant("a");
    let bytes = data(14, 20);
    let claimed = ContentKey::of(b"something else");
    let mut request = weights(&a, &bytes);
    request.manifest.content_key = claimed;
    request.trust = TrustClaim::Publisher {
        publisher: acme(),
        attestation: attestation(&acme(), ArtifactClass::ModelWeights, claimed),
    };
    let mut source = FakeSource::new("weights", &bytes);
    let ticket = started(catalog.begin_import(request, source.identity()).unwrap());
    let failure = failed(
        catalog
            .drive_import(&ticket, &mut source, &mut Uninterrupted)
            .unwrap(),
    );
    assert_eq!(failure.stage, ImportStage::ReadBackValidation);
    assert_eq!(
        failure.reason,
        FailureReason::ContentKeyMismatch {
            expected: claimed,
            found: ContentKey::of(&bytes)
        }
    );
    assert!(fixture.staging_dirs().is_empty());
    assert!(catalog.objects(&a).is_empty());
}

#[test]
fn a_tampered_committed_index_is_quarantined_until_a_verified_import_replaces_it() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let a = tenant("a");
    let bytes = data(15, 20);
    let object = import_bytes(&mut catalog, weights(&a, &bytes), &bytes);
    let index_path = fixture.object_dir(object).join("index.json");
    make_tree_writable(&index_path);
    let mut index: serde_json::Value =
        serde_json::from_slice(&fs::read(&index_path).unwrap()).unwrap();
    index["manifest"]["extents"][1]["length_bytes"] = 9.into();
    fs::write(&index_path, serde_json::to_vec(&index).unwrap()).unwrap();

    let (mut catalog, report) = fixture.reopen(catalog);
    assert_eq!(
        report.quarantined,
        vec![(object, IntegrityFailure::IndexMismatch)]
    );
    assert_eq!(report.published, 0);
    assert_eq!(
        catalog.status(&a, object),
        ObjectStatus::Quarantined {
            reason: IntegrityFailure::IndexMismatch
        }
    );
    assert_eq!(
        catalog.acquire_lease(&a, &execution("exe-1"), object, LEASE),
        Err(ReadRefusal::Quarantined { object })
    );
    assert_eq!(
        catalog.find(&a, ArtifactClass::ModelWeights, ContentKey::of(&bytes)),
        None
    );

    assert_eq!(
        import_bytes(&mut catalog, weights(&a, &bytes), &bytes),
        object
    );
    assert_eq!(catalog.status(&a, object), ObjectStatus::Published);
    assert_eq!(
        read(&mut catalog, &a, &execution("exe-1"), object).unwrap(),
        bytes
    );
}

#[test]
fn an_unreadable_record_is_retained_and_never_collected() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let a = tenant("a");
    let bytes = data(16, 20);
    let object = import_bytes(&mut catalog, weights(&a, &bytes), &bytes);
    drop(catalog);
    fs::write(fixture.record(object), b"{ not json").unwrap();

    let (mut catalog, report) = fixture.open_with(base_config(), verifiers());
    assert_eq!(report.unreadable.len(), 1);
    assert_eq!(report.unreadable[0].operation, StorageOperation::Parse);
    assert_eq!(report.published, 0);
    assert!(report.unpublished.is_empty());
    fixture.advance(GRACE * 3);
    let collected = catalog.collect_garbage().unwrap();
    assert!(collected.removed.is_empty() && collected.removed_unpublished.is_empty());
    assert!(fixture.object_dir(object).join("data").exists());
}

#[test]
fn a_temporary_record_left_by_a_crash_is_never_published() {
    let fixture = Fixture::new();
    drop(fixture.open());
    let object = ObjectId::new(
        &tenant("a"),
        ArtifactClass::ModelWeights,
        ContentKey::of(b"x"),
    );
    fs::write(
        fixture.root().join("records").join(format!("{object}.tmp")),
        b"{}",
    )
    .unwrap();
    let (catalog, report) = fixture.open_with(base_config(), verifiers());
    assert_eq!((report.temporaries_removed, report.published), (1, 0));
    assert!(catalog.objects(&tenant("a")).is_empty());
}

// Typed verifiers and trust per artifact class (INT-09; S2 CORE-08).

#[test]
fn the_responsible_verifier_rejects_a_corrupt_object_and_originals_stay_intact() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let a = tenant("a");
    let original_bytes = data(17, 20);
    let original = import_bytes(&mut catalog, weights(&a, &original_bytes), &original_bytes);

    let host = Scope::Host;
    let good = header_object(b"document body");
    let document = import_bytes(
        &mut catalog,
        request(&host, ArtifactClass::DocumentManifest, &good),
        &good,
    );
    assert_eq!(catalog.status(&host, document), ObjectStatus::Published);

    let mut corrupt = header_object(b"document body");
    corrupt[11] ^= 1;
    let mut source = FakeSource::new("corrupt-document", &corrupt);
    let ticket = started(
        catalog
            .begin_import(
                request(&host, ArtifactClass::DocumentManifest, &corrupt),
                source.identity(),
            )
            .unwrap(),
    );
    let failure = failed(
        catalog
            .drive_import(&ticket, &mut source, &mut Uninterrupted)
            .unwrap(),
    );
    assert_eq!(failure.stage, ImportStage::ReadBackValidation);
    assert!(matches!(
        failure.reason,
        FailureReason::VerifierRejected {
            rejection: VerifierRejection::CorruptStructure { .. }
        }
    ));
    assert_eq!(failure.reason.kind(), FailureKind::InvalidResult);
    assert_eq!(
        catalog.find(
            &host,
            ArtifactClass::DocumentManifest,
            ContentKey::of(&corrupt)
        ),
        None
    );
    assert!(fixture.staging_dirs().is_empty());

    let mut wrong_format = good.clone();
    wrong_format[0] = b'X';
    let mut source = FakeSource::new("not-a-document", &wrong_format);
    let ticket = started(
        catalog
            .begin_import(
                request(&host, ArtifactClass::DocumentManifest, &wrong_format),
                source.identity(),
            )
            .unwrap(),
    );
    assert!(matches!(
        failed(
            catalog
                .drive_import(&ticket, &mut source, &mut Uninterrupted)
                .unwrap()
        )
        .reason,
        FailureReason::VerifierRejected {
            rejection: VerifierRejection::WrongFormat { .. }
        }
    ));
    // The retained user original is intact.
    assert_eq!(
        read(&mut catalog, &a, &execution("exe-1"), original).unwrap(),
        original_bytes
    );
}

#[test]
fn a_checksum_alone_is_not_trust() {
    let fixture = Fixture::new();
    // Even verifiers that accept every attestation cannot turn a checksum into trust.
    let mut permissive = VerifierRegistry::new();
    for class in ArtifactClass::ALL {
        permissive
            .register(Box::new(FakeVerifier::permissive(class)))
            .unwrap();
    }
    let (mut catalog, _) = fixture.open_with(base_config(), permissive);
    let a = tenant("a");
    let bytes = data(18, 20);
    let source = FakeSource::new("weights", &bytes);
    for class in ArtifactClass::ALL {
        let mut checksum_only = request(&a, class, &bytes);
        checksum_only.trust = TrustClaim::ChecksumOnly;
        assert_eq!(
            catalog.begin_import(checksum_only, source.identity()),
            Err(ImportRefusal::Trust {
                refusal: TrustRefusal::ChecksumIsNotTrust { class }
            })
        );
    }
    // Identical content already published under real trust lends no pass either.
    let object = import_bytes(&mut catalog, weights(&a, &bytes), &bytes);
    let mut checksum_only = weights(&a, &bytes);
    checksum_only.trust = TrustClaim::ChecksumOnly;
    assert!(catalog
        .begin_import(checksum_only, source.identity())
        .is_err());
    assert_eq!(
        catalog.begin_import(weights(&a, &bytes), source.identity()),
        Ok(ImportStart::AlreadyPublished(object))
    );
    assert!(catalog
        .failures()
        .any(|record| record.reason.code() == "trust_refused"));
}

#[test]
fn each_class_keeps_its_own_publisher_policy() {
    let fixture = Fixture::new();
    let vendor = publisher("vendor");
    let config = base_config().with_trust(
        ArtifactClass::RuntimeUpdate,
        TrustPolicy::new().trust_publisher(vendor),
    );
    let (mut catalog, _) = fixture.open_with(config, verifiers());
    let host = Scope::Host;
    let update = data(19, 20);
    let key = ContentKey::of(&update);
    let source = FakeSource::new("update", &update);
    let signed = |by: PublisherId, class: ArtifactClass, content: ContentKey| {
        let mut request = request(&host, ArtifactClass::RuntimeUpdate, &update);
        request.trust = TrustClaim::Publisher {
            publisher: by,
            attestation: attestation(&by, class, content),
        };
        request
    };
    // Trusted for model weights, not for runtime updates.
    assert_eq!(
        catalog.begin_import(
            signed(acme(), ArtifactClass::RuntimeUpdate, key),
            source.identity()
        ),
        Err(ImportRefusal::Trust {
            refusal: TrustRefusal::PublisherNotTrusted {
                class: ArtifactClass::RuntimeUpdate,
                publisher: acme()
            }
        })
    );
    // The trusted publisher's attestation must name this class and this content.
    for (class, content) in [
        (ArtifactClass::RuntimeUpdate, ContentKey::of(b"other")),
        (ArtifactClass::ModelWeights, key),
    ] {
        assert_eq!(
            catalog.begin_import(signed(vendor, class, content), source.identity()),
            Err(ImportRefusal::Trust {
                refusal: TrustRefusal::AttestationRejected {
                    class: ArtifactClass::RuntimeUpdate,
                    publisher: vendor,
                    rejection: VerifierRejection::AttestationInvalid
                }
            })
        );
    }
    let object = import_bytes(
        &mut catalog,
        signed(vendor, ArtifactClass::RuntimeUpdate, key),
        &update,
    );
    assert_eq!(
        catalog.private_metadata(&host, object).unwrap().trust,
        TrustBasis::Publisher { publisher: vendor }
    );
}

#[test]
fn user_selected_originals_are_accepted_only_where_the_policy_allows() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let a = tenant("a");
    let bytes = data(20, 20);
    let mut selected = weights(&a, &bytes);
    selected.trust = TrustClaim::UserSelected;
    let object = import_bytes(&mut catalog, selected, &bytes);
    assert_eq!(
        catalog.private_metadata(&a, object).unwrap().trust,
        TrustBasis::UserSelected {
            tenant: TenantId::new("a").unwrap()
        }
    );
    let source = FakeSource::new("selected", &bytes);
    let mut into_host = weights(&Scope::Host, &bytes);
    into_host.trust = TrustClaim::UserSelected;
    assert_eq!(
        catalog.begin_import(into_host, source.identity()),
        Err(ImportRefusal::Trust {
            refusal: TrustRefusal::UserSelectionOutsideTenantScope {
                class: ArtifactClass::ModelWeights
            }
        })
    );
    let mut update = request(&a, ArtifactClass::RuntimeUpdate, &bytes);
    update.trust = TrustClaim::UserSelected;
    assert_eq!(
        catalog.begin_import(update, source.identity()),
        Err(ImportRefusal::Trust {
            refusal: TrustRefusal::UserSelectionNotAccepted {
                class: ArtifactClass::RuntimeUpdate
            }
        })
    );
}

#[test]
fn a_class_without_a_verifier_or_a_policy_trusts_nothing() {
    let fixture = Fixture::new();
    let mut registry = VerifierRegistry::new();
    registry
        .register(Box::new(FakeVerifier::new(ArtifactClass::ModelWeights)))
        .unwrap();
    assert_eq!(
        registry.register(Box::new(FakeVerifier::new(ArtifactClass::ModelWeights))),
        Err(DuplicateVerifier {
            class: ArtifactClass::ModelWeights
        })
    );
    assert!(!registry.is_registered(ArtifactClass::GuestImage));
    let mut config = base_config();
    config.trust.remove(&ArtifactClass::ModelWeights);
    let (mut catalog, _) = fixture.open_with(config, registry);
    let a = tenant("a");
    let bytes = data(21, 20);
    let source = FakeSource::new("weights", &bytes);
    assert_eq!(
        catalog.begin_import(
            request(&a, ArtifactClass::GuestImage, &bytes),
            source.identity()
        ),
        Err(ImportRefusal::Trust {
            refusal: TrustRefusal::NoVerifier {
                class: ArtifactClass::GuestImage
            }
        })
    );
    assert_eq!(
        catalog.begin_import(weights(&a, &bytes), source.identity()),
        Err(ImportRefusal::Trust {
            refusal: TrustRefusal::NoPolicy {
                class: ArtifactClass::ModelWeights
            }
        })
    );
}

// Grants: equal content is not permission (S3.3, INT-05).

#[test]
fn a_cross_tenant_read_is_denied_without_a_grant_and_allowed_with_one() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let (a, b, c) = (tenant("a"), tenant("b"), tenant("c"));
    let reader = execution("exe-b");
    let bytes = data(22, 20);
    let key = ContentKey::of(&bytes);
    let object = import_bytes(&mut catalog, weights(&a, &bytes), &bytes);

    // Without a grant the read is denied, exactly as for an object that does not exist.
    let missing = ObjectId::new(&a, ArtifactClass::ModelWeights, ContentKey::of(b"never"));
    for probe in [object, missing] {
        assert_eq!(
            catalog.acquire_lease(&b, &reader, probe, LEASE),
            Err(ReadRefusal::NotGranted { object: probe })
        );
        assert_eq!(
            catalog.object_view(&b, &reader, probe),
            Err(ReadRefusal::NotGranted { object: probe })
        );
        assert_eq!(
            catalog.private_metadata(&b, probe),
            Err(MetadataRefusal { object: probe })
        );
        assert_eq!(catalog.status(&b, probe), ObjectStatus::Absent);
    }
    assert_eq!(catalog.find(&b, ArtifactClass::ModelWeights, key), None);
    assert!(catalog.objects(&b).is_empty());

    // With a grant the content is readable; the owner's metadata never is.
    let grant = catalog
        .grant(
            &a,
            grant_to(
                &b,
                object,
                fixture.now().saturating_add(Duration::from_secs(300)),
            ),
        )
        .unwrap();
    assert_eq!(read(&mut catalog, &b, &reader, object).unwrap(), bytes);
    let view = catalog.object_view(&b, &reader, object).unwrap();
    assert_eq!(
        (view.object, view.class, view.content_key, view.length_bytes),
        (object, ArtifactClass::ModelWeights, key, 20)
    );
    assert_eq!(
        catalog.private_metadata(&b, object),
        Err(MetadataRefusal { object })
    );
    assert_eq!(
        catalog
            .private_metadata(&a, object)
            .unwrap()
            .metadata
            .labels
            .get("name")
            .map(String::as_str),
        Some("private-model")
    );
    // The grant names b alone, and does not make the object b's.
    assert_eq!(
        catalog.acquire_lease(&c, &reader, object, LEASE),
        Err(ReadRefusal::NotGranted { object })
    );
    assert_eq!(catalog.find(&b, ArtifactClass::ModelWeights, key), None);
    assert_eq!(catalog.revoke_grant(&a, grant), Ok(0));
    assert_eq!(
        catalog.acquire_lease(&b, &reader, object, LEASE),
        Err(ReadRefusal::NotGranted { object })
    );
}

#[test]
fn equal_bytes_in_another_scope_are_not_permission() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let (a, b, c) = (tenant("a"), tenant("b"), tenant("c"));
    let reader = execution("exe-b");
    let bytes = data(23, 20);
    let in_a = import_bytes(&mut catalog, weights(&a, &bytes), &bytes);
    let mut own_source = FakeSource::new("b-own-source", &bytes);
    let in_b = import(&mut catalog, weights(&b, &bytes), &mut own_source);
    assert_eq!(own_source.reads(), 3);
    let in_c = import_bytes(&mut catalog, weights(&c, &bytes), &bytes);
    assert_eq!(BTreeSet::from([in_a, in_b, in_c]).len(), 3);
    assert_eq!(read(&mut catalog, &b, &reader, in_b).unwrap(), bytes);
    assert_eq!(
        catalog.acquire_lease(&b, &reader, in_a, LEASE),
        Err(ReadRefusal::NotGranted { object: in_a })
    );
    // A grant for a's object never reaches c's identical object.
    catalog
        .grant(
            &a,
            grant_to(
                &b,
                in_a,
                fixture.now().saturating_add(Duration::from_secs(300)),
            ),
        )
        .unwrap();
    assert!(catalog.acquire_lease(&b, &reader, in_a, LEASE).is_ok());
    assert_eq!(
        catalog.acquire_lease(&b, &reader, in_c, LEASE),
        Err(ReadRefusal::NotGranted { object: in_c })
    );
}

#[test]
fn grants_are_narrow_bounded_and_revocable() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let (a, b) = (tenant("a"), tenant("b"));
    let (x, y) = (execution("exe-x"), execution("exe-y"));
    let bytes = data(24, 20);
    let object = import_bytes(&mut catalog, weights(&a, &bytes), &bytes);
    let expires_at = fixture.now().saturating_add(Duration::from_secs(30));

    assert_eq!(
        catalog.grant(&b, grant_to(&b, object, expires_at)),
        Err(GrantRefusal::NotOwner { object })
    );
    assert_eq!(
        catalog.grant(&a, grant_to(&a, object, expires_at)),
        Err(GrantRefusal::SameScope)
    );
    assert_eq!(
        catalog.grant(&a, grant_to(&b, object, fixture.now())),
        Err(GrantRefusal::AlreadyExpired)
    );

    // Narrowed to one execution of the grantee.
    let grant = catalog
        .grant(
            &a,
            GrantRequest {
                execution: Some(x.clone()),
                ..grant_to(&b, object, expires_at)
            },
        )
        .unwrap();
    assert_eq!(
        catalog.acquire_lease(&b, &y, object, LEASE),
        Err(ReadRefusal::NotGranted { object })
    );
    // A lease under a grant ends no later than the grant.
    let lease = catalog
        .acquire_lease(&b, &x, object, Duration::from_secs(600))
        .unwrap();
    let mut handle = catalog.open_read(&b, &x, lease).unwrap();
    assert!(handle.read_extent(0).is_ok());
    assert_eq!(
        catalog.open_read(&b, &y, lease).map(|_| ()),
        Err(ReadRefusal::LeaseNotHeld)
    );
    assert_eq!(
        catalog.revoke_grant(&b, grant),
        Err(GrantRefusal::UnknownGrant)
    );
    fixture.advance(Duration::from_secs(30));
    assert_eq!(handle.read_extent(0), Err(ReadError::LeaseExpired));
    assert_eq!(
        catalog.renew_lease(&b, &x, lease, LEASE),
        Err(ReadRefusal::LeaseExpired)
    );
    assert_eq!(
        catalog.acquire_lease(&b, &x, object, LEASE),
        Err(ReadRefusal::NotGranted { object })
    );
    drop(handle);

    // Revocation stops open handles at once.
    let grant = catalog
        .grant(
            &a,
            grant_to(
                &b,
                object,
                fixture.now().saturating_add(Duration::from_secs(300)),
            ),
        )
        .unwrap();
    let lease = catalog.acquire_lease(&b, &y, object, LEASE).unwrap();
    let renewed = catalog.renew_lease(&b, &y, lease, LEASE).unwrap();
    assert_eq!(renewed, fixture.now().saturating_add(LEASE));
    let mut handle = catalog.open_read(&b, &y, lease).unwrap();
    assert!(handle.read_extent(0).is_ok());
    assert_eq!(catalog.revoke_grant(&a, grant), Ok(1));
    assert_eq!(handle.read_extent(0), Err(ReadError::LeaseRevoked));
    assert_eq!(
        catalog.open_read(&b, &y, lease).map(|_| ()),
        Err(ReadRefusal::UnknownLease)
    );
    assert_eq!(
        catalog.acquire_lease(&b, &y, object, LEASE),
        Err(ReadRefusal::NotGranted { object })
    );
}

#[test]
fn grants_and_leases_never_survive_a_reopen() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let (a, b) = (tenant("a"), tenant("b"));
    let reader = execution("exe-b");
    let bytes = data(25, 20);
    let object = import_bytes(&mut catalog, weights(&a, &bytes), &bytes);
    catalog
        .grant(
            &a,
            grant_to(
                &b,
                object,
                fixture.now().saturating_add(Duration::from_secs(300)),
            ),
        )
        .unwrap();
    let lease = catalog.acquire_lease(&b, &reader, object, LEASE).unwrap();
    let (catalog, _) = fixture.reopen(catalog);
    assert_eq!(
        catalog.open_read(&b, &reader, lease).map(|_| ()),
        Err(ReadRefusal::UnknownLease)
    );
    let mut catalog = catalog;
    assert_eq!(
        catalog.acquire_lease(&b, &reader, object, LEASE),
        Err(ReadRefusal::NotGranted { object })
    );
}

#[test]
fn lease_durations_are_bounded() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let a = tenant("a");
    let reader = execution("exe-1");
    let bytes = data(26, 20);
    let object = import_bytes(&mut catalog, weights(&a, &bytes), &bytes);
    assert_eq!(
        catalog.acquire_lease(&a, &reader, object, Duration::ZERO),
        Err(ReadRefusal::ZeroDuration)
    );
    let max = catalog.config().limits.max_lease;
    assert_eq!(
        catalog.acquire_lease(&a, &reader, object, max + Duration::from_secs(1)),
        Err(ReadRefusal::DurationTooLong { max })
    );
    assert!(catalog.acquire_lease(&a, &reader, object, max).is_ok());
}

// Quotas (CORE-02; line 548).

#[test]
fn the_quota_refuses_with_a_typed_refusal_and_never_evicts() {
    let fixture = Fixture::new();
    let a = tenant("a");
    let (mut catalog, _) = fixture.open_with(base_config().with_quota(a.clone(), 80), verifiers());

    let unbudgeted = tenant("d");
    let original_bytes = data(27, 40);
    let source = FakeSource::new("weights", &original_bytes);
    assert_eq!(
        catalog.begin_import(weights(&unbudgeted, &original_bytes), source.identity()),
        Err(ImportRefusal::Quota {
            refusal: QuotaRefusal::NoBudget {
                scope: unbudgeted.clone()
            }
        })
    );
    assert_eq!(catalog.quota_usage(&unbudgeted).limit_bytes, None);

    let original = import_bytes(&mut catalog, weights(&a, &original_bytes), &original_bytes);
    let prepared_bytes = data(28, 16);
    let prepared = import_bytes(
        &mut catalog,
        prepared_request(&a, &prepared_bytes, &[original]),
        &prepared_bytes,
    );
    let large = data(29, 40);
    let source = FakeSource::new("large", &large);
    assert_eq!(
        catalog.begin_import(weights(&a, &large), source.identity()),
        Err(ImportRefusal::Quota {
            refusal: QuotaRefusal::Exceeded {
                scope: a.clone(),
                limit_bytes: 80,
                charged_bytes: 56,
                requested_bytes: 40,
                evictable_bytes: 16,
            }
        })
    );
    // Nothing was staged, and nothing was evicted to make room.
    assert!(fixture.staging_dirs().is_empty());
    assert_eq!(catalog.status(&a, original), ObjectStatus::Published);
    assert_eq!(catalog.status(&a, prepared), ObjectStatus::Published);

    // A reservation counts before anything is written.
    let medium = data(30, 24);
    let reserved = started(
        catalog
            .begin_import(
                weights(&a, &medium),
                FakeSource::new("medium", &medium).identity(),
            )
            .unwrap(),
    );
    assert_eq!(catalog.quota_usage(&a).reserved_bytes, 24);
    let small = data(31, 8);
    let small_source = FakeSource::new("small", &small);
    assert!(matches!(
        catalog.begin_import(weights(&a, &small), small_source.identity()),
        Err(ImportRefusal::Quota {
            refusal: QuotaRefusal::Exceeded {
                charged_bytes: 80,
                requested_bytes: 8,
                ..
            }
        })
    ));
    assert_eq!(catalog.cancel_import(reserved), CancelOutcome::Cancelled);
    assert!(matches!(
        catalog.begin_import(weights(&a, &small), small_source.identity()),
        Ok(ImportStart::Started(_))
    ));
    let refusal = catalog
        .failures()
        .find(|record| record.reason.code() == "quota_refused")
        .unwrap();
    assert_eq!(refusal.reason.kind(), FailureKind::Rejected);
}

// Leases and garbage collection (CORE-02; line 533).

#[test]
fn garbage_collection_respects_leases_and_the_grace_period() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let a = tenant("a");
    let reader = execution("exe-1");
    let original_bytes = data(32, 20);
    let original = import_bytes(&mut catalog, weights(&a, &original_bytes), &original_bytes);
    let prepared_bytes = data(66, 12);
    let prepared = import_bytes(
        &mut catalog,
        prepared_request(&a, &prepared_bytes, &[original]),
        &prepared_bytes,
    );
    let model = RootName::new("model").unwrap();
    catalog
        .set_root(
            &a,
            RootKind::LocalModel,
            model.clone(),
            BTreeSet::from([original, prepared]),
        )
        .unwrap();
    fixture.advance(GRACE * 10);
    assert!(catalog.collect_garbage().unwrap().removed.is_empty());

    // Unreachable from now; the deletion itself removes no bytes.
    let deletion = catalog.delete_local_model(&a, &model).unwrap();
    assert_eq!(
        deletion
            .now_unreachable
            .into_iter()
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([original, prepared])
    );
    assert_eq!(catalog.status(&a, prepared), ObjectStatus::Published);
    fixture.advance(GRACE - Duration::from_nanos(1));
    let collected = catalog.collect_garbage().unwrap();
    assert_eq!(
        (collected.kept_in_grace, collected.kept_originals),
        (vec![prepared], vec![original])
    );

    let lease = catalog.acquire_lease(&a, &reader, prepared, LEASE).unwrap();
    fixture.advance(Duration::from_nanos(1));
    assert_eq!(
        catalog.collect_garbage().unwrap().kept_leased,
        vec![prepared]
    );

    // Garbage only once both unreachable and unleased; the grace period starts again.
    fixture.advance(Duration::from_secs(5));
    catalog.release_lease(&a, &reader, lease).unwrap();
    assert_eq!(
        catalog.collect_garbage().unwrap().kept_in_grace,
        vec![prepared]
    );
    fixture.advance(GRACE - Duration::from_nanos(1));
    assert_eq!(
        catalog.collect_garbage().unwrap().kept_in_grace,
        vec![prepared]
    );
    fixture.advance(Duration::from_nanos(1));
    let collected = catalog.collect_garbage().unwrap();
    assert_eq!(
        (collected.removed, collected.removed_bytes),
        (vec![prepared], 12)
    );
    assert!(!fixture.object_dir(prepared).exists());
    assert!(!fixture.record(prepared).exists());
    assert_eq!(catalog.status(&a, prepared), ObjectStatus::Absent);
    // The original outlives its local model: only source-file deletion removes it.
    assert_eq!(collected.kept_originals, vec![original]);
    assert_eq!(
        read(&mut catalog, &a, &reader, original).unwrap(),
        original_bytes
    );
    let (_, report) = fixture.reopen(catalog);
    assert_eq!(report.published, 1);
}

#[test]
fn an_expired_lease_neither_protects_nor_revives() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let a = tenant("a");
    let reader = execution("exe-1");
    let original_bytes = data(33, 20);
    let original = import_bytes(&mut catalog, weights(&a, &original_bytes), &original_bytes);
    let bytes = data(67, 12);
    let object = import_bytes(
        &mut catalog,
        prepared_request(&a, &bytes, &[original]),
        &bytes,
    );
    let lease = catalog
        .acquire_lease(&a, &reader, object, Duration::from_secs(10))
        .unwrap();
    let mut handle = catalog.open_read(&a, &reader, lease).unwrap();
    fixture.advance(Duration::from_secs(11));
    assert_eq!(handle.read_extent(0), Err(ReadError::LeaseExpired));
    assert_eq!(
        catalog.renew_lease(&a, &reader, lease, LEASE),
        Err(ReadRefusal::LeaseExpired)
    );
    drop(handle);
    // Garbage since the lease ended at 10 s, so collectable at 70 s.
    fixture.advance(GRACE - Duration::from_secs(1) - Duration::from_nanos(1));
    assert_eq!(
        catalog.collect_garbage().unwrap().kept_in_grace,
        vec![object]
    );
    fixture.advance(Duration::from_nanos(1));
    let collected = catalog.collect_garbage().unwrap();
    assert_eq!(
        (collected.removed, collected.kept_originals),
        (vec![object], vec![original])
    );
}

#[test]
fn dependencies_keep_what_they_need_reachable() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let a = tenant("a");
    let weights_bytes = data(34, 24);
    let base = import_bytes(&mut catalog, weights(&a, &weights_bytes), &weights_bytes);
    let sidecar_bytes = data(35, 8);
    let mut sidecar_request = prepared_request(&a, &sidecar_bytes, &[base]);
    sidecar_request.depends_on = BTreeSet::from([base]);
    let sidecar = import_bytes(&mut catalog, sidecar_request, &sidecar_bytes);
    let model = RootName::new("model").unwrap();
    catalog
        .set_root(
            &a,
            RootKind::LocalModel,
            model.clone(),
            BTreeSet::from([sidecar]),
        )
        .unwrap();
    fixture.advance(GRACE * 2);
    assert!(catalog.collect_garbage().unwrap().removed.is_empty());
    assert_eq!(catalog.status(&a, base), ObjectStatus::Published);

    catalog.delete_local_model(&a, &model).unwrap();
    fixture.advance(GRACE);
    // The sidecar is collected; the original it depended on is kept (line 552).
    let collected = catalog.collect_garbage().unwrap();
    assert_eq!(
        (collected.removed, collected.kept_originals),
        (vec![sidecar], vec![base])
    );
    assert_eq!(catalog.status(&a, base), ObjectStatus::Published);
}

#[test]
fn unpublished_commits_and_abandoned_staging_are_collected_after_the_grace_period() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let a = tenant("a");
    let bytes = data(36, 20);
    let mut source = FakeSource::new("weights", &bytes);
    let ticket = started(
        catalog
            .begin_import(weights(&a, &bytes), source.identity())
            .unwrap(),
    );
    let (_, failure) = pending(
        catalog
            .drive_import(
                &ticket,
                &mut source,
                &mut StopAt::stage(ImportStage::CatalogPublication),
            )
            .unwrap(),
    );
    let object = failure.object;
    assert_eq!(catalog.cancel_import(ticket), CancelOutcome::Cancelled);

    let (mut catalog, report) = fixture.reopen(catalog);
    assert_eq!(
        (report.unpublished.clone(), report.staging),
        (vec![object], 1)
    );
    assert_eq!(catalog.quota_usage(&a).unpublished_bytes, 20);
    let collected = catalog.collect_garbage().unwrap();
    assert!(collected.removed_unpublished.is_empty());
    assert_eq!(collected.removed_staging, 0);

    fixture.advance(GRACE);
    let collected = catalog.collect_garbage().unwrap();
    assert_eq!(
        (collected.removed_unpublished, collected.removed_staging),
        (vec![object], 1)
    );
    assert!(list(&fixture.root().join("objects")).is_empty());
    assert!(fixture.staging_dirs().is_empty());
    assert_eq!(catalog.quota_usage(&a).charged_bytes(), 0);
}

#[test]
fn collection_is_refused_while_a_root_is_unreadable() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let a = tenant("a");
    let bytes = data(37, 20);
    let object = import_bytes(&mut catalog, weights(&a, &bytes), &bytes);
    let id = catalog
        .set_root(
            &a,
            RootKind::LocalModel,
            RootName::new("model").unwrap(),
            BTreeSet::from([object]),
        )
        .unwrap();
    drop(catalog);
    fs::write(
        fixture.root().join("roots").join(format!("{id}.json")),
        b"truncated",
    )
    .unwrap();
    let (mut catalog, report) = fixture.open_with(base_config(), verifiers());
    assert_eq!(report.unreadable.len(), 1);
    fixture.advance(GRACE * 2);
    assert!(matches!(
        catalog.collect_garbage(),
        Err(GcRefusal::UnreadableRoots { .. })
    ));
    assert_eq!(catalog.status(&a, object), ObjectStatus::Published);
}

// Eviction and the three delete actions (line 552).

#[test]
fn cache_eviction_never_deletes_a_users_original() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let a = tenant("a");
    let original_bytes = data(38, 20);
    let original = import_bytes(&mut catalog, weights(&a, &original_bytes), &original_bytes);
    let prepared_bytes = data(39, 12);
    let prepared = import_bytes(
        &mut catalog,
        prepared_request(&a, &prepared_bytes, &[original]),
        &prepared_bytes,
    );
    assert_eq!(
        catalog
            .eviction_candidates(&a)
            .iter()
            .map(|candidate| candidate.object)
            .collect::<Vec<_>>(),
        vec![prepared]
    );
    for chosen in [vec![original], vec![prepared, original]] {
        assert_eq!(
            catalog.evict_cache(&a, &chosen),
            Err(EvictionRefusal::UserOriginal { object: original })
        );
        assert_eq!(catalog.status(&a, original), ObjectStatus::Published);
        assert_eq!(catalog.status(&a, prepared), ObjectStatus::Published);
    }
    assert_eq!(
        catalog.evict_cache(&tenant("b"), &[prepared]),
        Err(EvictionRefusal::NotInScope { object: prepared })
    );
    assert_eq!(
        catalog.evict_cache(&a, &[prepared]),
        Ok(CacheEviction {
            evicted: vec![prepared],
            freed_bytes: 12
        })
    );
    assert_eq!(catalog.status(&a, prepared), ObjectStatus::Absent);
    assert_eq!(
        read(&mut catalog, &a, &execution("exe-1"), original).unwrap(),
        original_bytes
    );
    assert!(catalog.eviction_candidates(&a).is_empty());
}

#[test]
fn eviction_needs_an_unleased_reconstructible_copy_nothing_depends_on() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let a = tenant("a");
    let reader = execution("exe-1");
    let original_bytes = data(40, 20);
    let original = import_bytes(&mut catalog, weights(&a, &original_bytes), &original_bytes);
    let source_root = RootName::new("download").unwrap();
    catalog
        .set_root(
            &a,
            RootKind::SourceFile,
            source_root.clone(),
            BTreeSet::from([original]),
        )
        .unwrap();
    let p_bytes = data(41, 12);
    let p = import_bytes(
        &mut catalog,
        prepared_request(&a, &p_bytes, &[original]),
        &p_bytes,
    );
    let q_bytes = data(42, 12);
    let mut q_request = prepared_request(&a, &q_bytes, &[original]);
    q_request.depends_on = BTreeSet::from([p]);
    let q = import_bytes(&mut catalog, q_request, &q_bytes);

    assert_eq!(
        catalog.evict_cache(&a, &[p]),
        Err(EvictionRefusal::Required { object: p, by: q })
    );
    let lease = catalog.acquire_lease(&a, &reader, q, LEASE).unwrap();
    assert_eq!(
        catalog.evict_cache(&a, &[q]),
        Err(EvictionRefusal::Leased { object: q })
    );
    catalog.release_lease(&a, &reader, lease).unwrap();
    assert!(catalog.evict_cache(&a, &[q]).is_ok());

    // Once the original is gone, p is the only copy and no longer evictable.
    catalog
        .delete_source_file(&a, &SourceFileTarget::Root(source_root.clone()))
        .unwrap();
    assert_eq!(
        catalog.evict_cache(&a, &[p]),
        Err(EvictionRefusal::NotReconstructible {
            object: p,
            missing: BTreeSet::from([original])
        })
    );
    assert_eq!(catalog.status(&a, p), ObjectStatus::Published);
}

#[test]
fn local_model_deletion_cache_eviction_and_source_file_deletion_stay_separate() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let a = tenant("a");
    let original_bytes = data(43, 24);
    let original = import_bytes(&mut catalog, weights(&a, &original_bytes), &original_bytes);
    let prepared_bytes = data(44, 16);
    let prepared = import_bytes(
        &mut catalog,
        prepared_request(&a, &prepared_bytes, &[original]),
        &prepared_bytes,
    );
    let model = RootName::new("llama").unwrap();
    let file = RootName::new("llama-download").unwrap();
    catalog
        .set_root(
            &a,
            RootKind::SourceFile,
            file.clone(),
            BTreeSet::from([original]),
        )
        .unwrap();
    let model_root = catalog
        .set_root(
            &a,
            RootKind::LocalModel,
            model.clone(),
            BTreeSet::from([original, prepared]),
        )
        .unwrap();

    // Cache eviction removes the prepared representation only; both roots stay.
    assert_eq!(
        catalog.evict_cache(&a, &[original]),
        Err(EvictionRefusal::UserOriginal { object: original })
    );
    assert_eq!(
        catalog.evict_cache(&a, &[prepared]).unwrap().evicted,
        vec![prepared]
    );
    assert_eq!(catalog.roots(&a).len(), 2);
    assert_eq!(catalog.status(&a, original), ObjectStatus::Published);

    // Source-file deletion is refused while the local model needs the original.
    assert_eq!(
        catalog.delete_source_file(&a, &SourceFileTarget::Root(file.clone())),
        Err(DeleteRefusal::InUse {
            object: original,
            holder: Holder::Root { root: model_root }
        })
    );
    assert_eq!(catalog.status(&a, original), ObjectStatus::Published);

    // Each action acts only on its own kind of root.
    assert_eq!(
        catalog.delete_local_model(&a, &file),
        Err(DeleteRefusal::NoSuchRoot {
            kind: RootKind::LocalModel,
            name: file.clone()
        })
    );
    assert_eq!(
        catalog.delete_source_file(&a, &SourceFileTarget::Root(model.clone())),
        Err(DeleteRefusal::NoSuchRoot {
            kind: RootKind::SourceFile,
            name: model.clone()
        })
    );

    // Local model deletion removes the model's root and deletes no bytes.
    let deletion = catalog.delete_local_model(&a, &model).unwrap();
    assert_eq!(deletion.root, model_root);
    assert!(deletion.now_unreachable.is_empty());
    fixture.advance(GRACE * 2);
    assert!(catalog.collect_garbage().unwrap().removed.is_empty());
    assert_eq!(
        read(&mut catalog, &a, &execution("exe-1"), original).unwrap(),
        original_bytes
    );

    // Source-file deletion, on explicit request, deletes the original now.
    let deletion = catalog
        .delete_source_file(&a, &SourceFileTarget::Root(file.clone()))
        .unwrap();
    assert_eq!(
        (deletion.deleted, deletion.freed_bytes),
        (vec![original], 24)
    );
    assert_eq!(catalog.status(&a, original), ObjectStatus::Absent);
    assert!(catalog.roots(&a).is_empty());
}

#[test]
fn source_file_deletion_is_refused_while_the_original_is_in_use() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let a = tenant("a");
    let reader = execution("exe-1");
    let original_bytes = data(45, 20);
    let original = import_bytes(&mut catalog, weights(&a, &original_bytes), &original_bytes);
    let file = RootName::new("download").unwrap();
    catalog
        .set_root(
            &a,
            RootKind::SourceFile,
            file.clone(),
            BTreeSet::from([original]),
        )
        .unwrap();
    let lease = catalog.acquire_lease(&a, &reader, original, LEASE).unwrap();
    assert_eq!(
        catalog.delete_source_file(&a, &SourceFileTarget::Root(file.clone())),
        Err(DeleteRefusal::InUse {
            object: original,
            holder: Holder::Lease
        })
    );
    catalog.release_lease(&a, &reader, lease).unwrap();

    let sidecar_bytes = data(46, 8);
    let mut sidecar_request = prepared_request(&a, &sidecar_bytes, &[original]);
    sidecar_request.depends_on = BTreeSet::from([original]);
    let sidecar = import_bytes(&mut catalog, sidecar_request, &sidecar_bytes);
    let model = RootName::new("model").unwrap();
    catalog
        .set_root(
            &a,
            RootKind::LocalModel,
            model.clone(),
            BTreeSet::from([sidecar]),
        )
        .unwrap();
    assert_eq!(
        catalog.delete_source_file(&a, &SourceFileTarget::Root(file.clone())),
        Err(DeleteRefusal::InUse {
            object: original,
            holder: Holder::Dependent { object: sidecar }
        })
    );
    assert_eq!(catalog.status(&a, original), ObjectStatus::Published);
    catalog.delete_local_model(&a, &model).unwrap();
    assert_eq!(
        catalog
            .delete_source_file(&a, &SourceFileTarget::Root(file.clone()))
            .unwrap()
            .deleted,
        vec![original]
    );
}

#[test]
fn roots_hold_their_own_scopes_objects_and_source_roots_never_drop_originals() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let (a, b) = (tenant("a"), tenant("b"));
    let first_bytes = data(47, 20);
    let first = import_bytes(&mut catalog, weights(&a, &first_bytes), &first_bytes);
    let second_bytes = data(48, 20);
    let second = import_bytes(&mut catalog, weights(&a, &second_bytes), &second_bytes);
    let foreign = import_bytes(&mut catalog, weights(&b, &first_bytes), &first_bytes);
    let prepared_bytes = data(49, 8);
    let prepared = import_bytes(
        &mut catalog,
        prepared_request(&a, &prepared_bytes, &[first]),
        &prepared_bytes,
    );
    let name = RootName::new("root").unwrap();

    assert_eq!(
        catalog.set_root(
            &a,
            RootKind::LocalModel,
            name.clone(),
            BTreeSet::from([foreign])
        ),
        Err(RootRefusal::NotInScope { object: foreign })
    );
    assert_eq!(
        catalog.set_root(
            &a,
            RootKind::SourceFile,
            name.clone(),
            BTreeSet::from([prepared])
        ),
        Err(RootRefusal::NotAnOriginal { object: prepared })
    );
    catalog
        .set_root(
            &a,
            RootKind::SourceFile,
            name.clone(),
            BTreeSet::from([first, second]),
        )
        .unwrap();
    assert_eq!(
        catalog.set_root(
            &a,
            RootKind::SourceFile,
            name.clone(),
            BTreeSet::from([first])
        ),
        Err(RootRefusal::WouldDropOriginals {
            objects: BTreeSet::from([second])
        })
    );
    // A model update may change which representations its root holds.
    catalog
        .set_root(
            &a,
            RootKind::LocalModel,
            name.clone(),
            BTreeSet::from([first, prepared]),
        )
        .unwrap();
    catalog
        .set_root(
            &a,
            RootKind::LocalModel,
            name.clone(),
            BTreeSet::from([first]),
        )
        .unwrap();

    let (catalog, _) = fixture.reopen(catalog);
    let mut roots = catalog.roots(&a);
    roots.sort_by_key(|root| root.kind);
    assert_eq!(
        roots
            .iter()
            .map(|root| (root.kind, root.objects.clone()))
            .collect::<Vec<_>>(),
        vec![
            (RootKind::LocalModel, BTreeSet::from([first])),
            (RootKind::SourceFile, BTreeSet::from([first, second])),
        ]
    );
    assert!(catalog.roots(&b).is_empty());
}

// Single flight (line 533).

#[test]
fn a_second_import_of_the_same_key_attaches_to_the_first() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let a = tenant("a");
    let bytes = data(50, 24);
    let mut source = FakeSource::new("weights", &bytes);
    let first = started(
        catalog
            .begin_import(weights(&a, &bytes), source.identity())
            .unwrap(),
    );
    let mut again = weights(&a, &bytes);
    again.operation = OperationId::new("op-second").unwrap();
    let second = match catalog.begin_import(again, source.identity()).unwrap() {
        ImportStart::Attached(ticket) => ticket,
        other => panic!("expected to attach, got {other:?}"),
    };
    assert_eq!(catalog.quota_usage(&a).reserved_bytes, 24);
    assert_eq!(fixture.staging_dirs().len(), 1);

    // Any attached party may drive; the bytes are fetched once.
    let (object, _) = published(
        catalog
            .drive_import(&second, &mut source, &mut Uninterrupted)
            .unwrap(),
    );
    assert_eq!(source.reads(), 3);
    assert!(matches!(
        catalog.import_status(&first),
        Some(ImportStatus::Published { object: seen, .. }) if seen == object
    ));
    assert!(matches!(
        catalog.cancel_import(first),
        CancelOutcome::Finished(ImportStatus::Published { .. })
    ));
    assert!(matches!(
        catalog.cancel_import(second),
        CancelOutcome::Finished(ImportStatus::Published { .. })
    ));
    assert_eq!(
        catalog.begin_import(weights(&a, &bytes), source.identity()),
        Ok(ImportStart::AlreadyPublished(object))
    );
    // The same content under another role is not the published object.
    let other_source = FakeSource::new("other", &bytes);
    let mut as_prepared = prepared_request(&a, &bytes, &[object]);
    as_prepared.class = ArtifactClass::ModelWeights;
    as_prepared.trust = weights(&a, &bytes).trust;
    assert_eq!(
        catalog.begin_import(as_prepared, other_source.identity()),
        Err(ImportRefusal::ConflictsWithPublished { object })
    );
    assert_eq!(source.reads(), 3);
}

#[test]
fn conflicting_or_foreign_imports_never_share_a_flight() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let (a, b) = (tenant("a"), tenant("b"));
    let bytes = data(51, 24);
    let other = data(52, 24);
    let source = FakeSource::new("weights", &bytes);
    started(
        catalog
            .begin_import(weights(&a, &bytes), source.identity())
            .unwrap(),
    );
    assert_eq!(
        catalog.begin_import(weights(&a, &other), source.identity()),
        Err(ImportRefusal::ConflictingFlight {
            object: ObjectId::new(&a, ArtifactClass::ModelWeights, ContentKey::of(&other))
        })
    );
    // Another tenant with the same source and execution never subscribes to a's import.
    started(
        catalog
            .begin_import(weights(&b, &bytes), source.identity())
            .unwrap(),
    );
    // Another model execution identity is another import.
    let runner = ModelExecutionKey::from_digest(digest("yougori/test/execution/v1", &[b"x"]));
    started(
        catalog
            .begin_import_for(weights(&a, &bytes), source.identity(), runner)
            .unwrap(),
    );
    assert_eq!(fixture.staging_dirs().len(), 3);
    let conflict = catalog
        .failures()
        .find(|record| record.reason.code() == "conflicting_flight")
        .unwrap();
    assert_eq!(conflict.reason.kind(), FailureKind::DuplicateIdentity);
}

#[test]
fn cancelling_one_party_leaves_the_import_running_for_the_others() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let a = tenant("a");
    let bytes = data(53, 24);
    let mut source = FakeSource::new("weights", &bytes);
    let first = started(
        catalog
            .begin_import(weights(&a, &bytes), source.identity())
            .unwrap(),
    );
    let second = match catalog
        .begin_import(weights(&a, &bytes), source.identity())
        .unwrap()
    {
        ImportStart::Attached(ticket) => ticket,
        other => panic!("expected to attach, got {other:?}"),
    };
    assert_eq!(
        catalog.cancel_import(first),
        CancelOutcome::Continuing {
            remaining_tickets: 1
        }
    );
    let (object, _) = published(
        catalog
            .drive_import(&second, &mut source, &mut Uninterrupted)
            .unwrap(),
    );
    assert_eq!(catalog.status(&a, object), ObjectStatus::Published);
}

// References of prepared representations.

#[test]
fn a_prepared_representation_names_published_sources_of_its_own_scope() {
    let fixture = Fixture::new();
    let mut limits = base_config().limits;
    limits.max_references = 2;
    let (mut catalog, _) = fixture.open_with(base_config().with_limits(limits), verifiers());
    let (a, b) = (tenant("a"), tenant("b"));
    let base_bytes = data(54, 20);
    let in_a = import_bytes(&mut catalog, weights(&a, &base_bytes), &base_bytes);
    let in_b = import_bytes(&mut catalog, weights(&b, &base_bytes), &base_bytes);
    let missing = ObjectId::new(&a, ArtifactClass::ModelWeights, ContentKey::of(b"never"));
    let bytes = data(55, 8);
    let source = FakeSource::new("prepared", &bytes);

    assert_eq!(
        catalog.begin_import(prepared_request(&a, &bytes, &[]), source.identity()),
        Err(ImportRefusal::NoDerivation)
    );
    for foreign in [in_b, missing] {
        assert_eq!(
            catalog.begin_import(prepared_request(&a, &bytes, &[foreign]), source.identity()),
            Err(ImportRefusal::UnknownReference { object: foreign })
        );
        let mut depends = weights(&a, &bytes);
        depends.depends_on = BTreeSet::from([foreign]);
        assert_eq!(
            catalog.begin_import(depends, source.identity()),
            Err(ImportRefusal::UnknownReference { object: foreign })
        );
    }
    let mut crowded = prepared_request(&a, &bytes, &[in_a]);
    crowded.depends_on = BTreeSet::from([in_a, missing]);
    assert_eq!(
        catalog.begin_import(crowded, source.identity()),
        Err(ImportRefusal::TooManyReferences {
            references: 3,
            max_references: 2
        })
    );
}

#[test]
fn private_metadata_is_bounded() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let a = tenant("a");
    let bytes = data(56, 8);
    let source = FakeSource::new("weights", &bytes);
    let mut crowded = weights(&a, &bytes);
    crowded.metadata = (0..65).fold(ObjectMetadata::new(), |metadata, index| {
        metadata.with_label(format!("key-{index}"), "value")
    });
    assert_eq!(
        catalog.begin_import(crowded, source.identity()),
        Err(ImportRefusal::Metadata {
            error: MetadataError::TooManyLabels {
                labels: 65,
                max_labels: 64
            }
        })
    );
    let mut empty_key = weights(&a, &bytes);
    empty_key.metadata = ObjectMetadata::new().with_label("", "value");
    assert_eq!(
        catalog.begin_import(empty_key, source.identity()),
        Err(ImportRefusal::Metadata {
            error: MetadataError::EmptyKey
        })
    );
    let mut long = weights(&a, &bytes);
    long.metadata = ObjectMetadata::new().with_label("name", "x".repeat(1025));
    assert_eq!(
        catalog.begin_import(long, source.identity()),
        Err(ImportRefusal::Metadata {
            error: MetadataError::LabelTooLong {
                max_label_bytes: 1024
            }
        })
    );
}

// Verification at rest (INT-09).

#[test]
fn verification_quarantines_bit_rot_and_revokes_leases() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let a = tenant("a");
    let reader = execution("exe-1");
    let bytes = data(57, 20);
    let object = import_bytes(&mut catalog, weights(&a, &bytes), &bytes);
    let lease = catalog.acquire_lease(&a, &reader, object, LEASE).unwrap();
    let mut handle = catalog.open_read(&a, &reader, lease).unwrap();

    let data_path = fixture.object_dir(object).join("data");
    overwrite(&data_path, 9, &[bytes[9] ^ 0xff]);
    // Handles verify each extent they return.
    assert_eq!(
        handle.read_extent(1),
        Err(ReadError::ExtentCorrupt { extent: 1 })
    );
    assert_eq!(
        catalog.verify_object(&tenant("b"), object),
        Err(VerifyError::NotOwner { object })
    );
    assert_eq!(
        catalog.verify_object(&a, object),
        Err(VerifyError::Quarantined {
            reason: IntegrityFailure::ExtentCorrupt { extent: 1 }
        })
    );
    assert_eq!(handle.read_extent(0), Err(ReadError::LeaseRevoked));
    assert_eq!(
        catalog.acquire_lease(&a, &reader, object, LEASE),
        Err(ReadRefusal::Quarantined { object })
    );
    drop(handle);

    overwrite(&data_path, 9, &bytes[9..10]);
    assert_eq!(catalog.verify_object(&a, object), Ok(()));
    assert_eq!(catalog.status(&a, object), ObjectStatus::Published);
}

// Integration with CORE-01's fallback guard (S3.5) and CORE-08 reporting.

#[test]
fn catalog_verification_supplies_the_fallback_guards_verified_set() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let (a, b) = (tenant("a"), tenant("b"));
    let (owner, reader) = (execution("exe-a"), execution("exe-b"));
    let x_bytes = data(58, 20);
    let x = import_bytes(&mut catalog, weights(&a, &x_bytes), &x_bytes);
    let y_bytes = data(59, 20);
    let y = import_bytes(&mut catalog, weights(&a, &y_bytes), &y_bytes);

    assert_eq!(
        catalog.artifact_verification(&a, &owner, [x, y]),
        Ok(ArtifactVerification::Verified {
            artifacts: BTreeSet::from([x.digest(), y.digest()])
        })
    );
    assert_eq!(
        catalog.artifact_verification(&b, &reader, [x]),
        Err(ReadRefusal::NotGranted { object: x })
    );
    catalog
        .grant(
            &a,
            grant_to(
                &b,
                x,
                fixture.now().saturating_add(Duration::from_secs(300)),
            ),
        )
        .unwrap();
    assert_eq!(
        catalog.artifact_verification(&b, &reader, [x]),
        Ok(ArtifactVerification::Verified {
            artifacts: BTreeSet::from([x.digest()])
        })
    );
    assert_eq!(
        catalog.artifact_verification(&b, &reader, [x, y]),
        Err(ReadRefusal::NotGranted { object: y })
    );
    overwrite(&fixture.object_dir(y).join("data"), 0, &[y_bytes[0] ^ 1]);
    assert!(catalog.verify_object(&a, y).is_err());
    assert_eq!(
        catalog.artifact_verification(&a, &owner, [y]),
        Err(ReadRefusal::Quarantined { object: y })
    );
}

#[test]
fn failure_records_are_typed_bounded_and_map_to_report_outcomes() {
    let fixture = Fixture::new();
    let mut limits = base_config().limits;
    limits.failure_log_capacity = 2;
    let (mut catalog, _) = fixture.open_with(base_config().with_limits(limits), verifiers());
    let a = tenant("a");
    let bytes = data(60, 16);
    let source = FakeSource::new("weights", &bytes);
    let mut checksum_only = weights(&a, &bytes);
    checksum_only.trust = TrustClaim::ChecksumOnly;
    assert!(catalog
        .begin_import(checksum_only, source.identity())
        .is_err());
    assert!(catalog
        .begin_import(weights(&tenant("d"), &bytes), source.identity())
        .is_err());
    let mut corrupt = weights(&a, &bytes);
    corrupt.manifest.extents[1].offset_bytes = 9;
    assert!(catalog.begin_import(corrupt, source.identity()).is_err());
    assert_eq!(catalog.failures().count(), 2);
    assert_eq!(catalog.dropped_failures(), 1);

    let record = catalog.failures().last().unwrap().clone();
    assert_eq!(
        record.object,
        ObjectId::new(&a, ArtifactClass::ModelWeights, ContentKey::of(&bytes))
    );
    assert_eq!(record.source, source.identity());
    assert_eq!(record.operation, OperationId::new("op-import").unwrap());
    let json = serde_json::to_value(&record).unwrap();
    assert_eq!(json["stage"], "source_verification");
    assert_eq!(json["reason"]["reason"], "refused");
    assert_eq!(json["reason"]["refusal"]["kind"], "manifest");
    assert_eq!(
        serde_json::from_value::<FailureRecord>(json).unwrap(),
        record
    );
    assert_eq!(
        record.outcome().unwrap(),
        Outcome::Failed {
            failure: FailureKind::Rejected,
            component: Label::new(FAILURE_COMPONENT).unwrap(),
            code: Label::new("manifest_rejected").unwrap(),
        }
    );

    // Every reason maps to the S8 taxonomy with a code that is a valid report label.
    let key = ContentKey::of(&bytes);
    let reasons = [
        (
            FailureReason::Refused {
                refusal: ImportRefusal::Storage {
                    failure: StorageFailure {
                        operation: StorageOperation::Write,
                        path: "staging".to_owned(),
                        detail: "disk full".to_owned(),
                    },
                },
            },
            FailureKind::CommandFailure,
        ),
        (
            FailureReason::Refused {
                refusal: ImportRefusal::ConflictsWithPublished {
                    object: record.object,
                },
            },
            FailureKind::DuplicateIdentity,
        ),
        (
            FailureReason::Refused {
                refusal: ImportRefusal::NoDerivation,
            },
            FailureKind::Rejected,
        ),
        (FailureReason::Cancelled, FailureKind::EarlyTermination),
        (
            FailureReason::Interrupted {
                at: Checkpoint::Extent { extent: 4 },
            },
            FailureKind::EarlyTermination,
        ),
        (
            FailureReason::SourceFailed {
                extent: None,
                detail: "reset".to_owned(),
            },
            FailureKind::CommandFailure,
        ),
        (
            FailureReason::SourceLengthMismatch {
                declared_bytes: 1,
                source_bytes: 2,
            },
            FailureKind::InvalidResult,
        ),
        (
            FailureReason::ExtentDigestMismatch {
                extent: 0,
                attempts: 3,
            },
            FailureKind::InvalidResult,
        ),
        (
            FailureReason::ReadBackMismatch { extent: Some(1) },
            FailureKind::InvalidResult,
        ),
        (
            FailureReason::ContentKeyMismatch {
                expected: key,
                found: key,
            },
            FailureKind::InvalidResult,
        ),
        (
            FailureReason::VerifierRejected {
                rejection: VerifierRejection::AttestationInvalid,
            },
            FailureKind::InvalidResult,
        ),
        (
            FailureReason::Storage {
                failure: StorageFailure {
                    operation: StorageOperation::Sync,
                    path: "objects".to_owned(),
                    detail: "io".to_owned(),
                },
            },
            FailureKind::CommandFailure,
        ),
    ];
    for (reason, kind) in reasons {
        let code = reason.code();
        let failure = FailureRecord {
            reason,
            ..record.clone()
        };
        assert_eq!(
            failure.outcome().unwrap(),
            Outcome::Failed {
                failure: kind,
                component: Label::new(FAILURE_COMPONENT).unwrap(),
                code: Label::new(code).unwrap(),
            }
        );
        let json = serde_json::to_string(&failure).unwrap();
        assert_eq!(
            serde_json::from_str::<FailureRecord>(&json).unwrap(),
            failure
        );
    }
}

#[test]
fn finished_imports_are_forgotten_beyond_their_bound() {
    let fixture = Fixture::new();
    let mut limits = base_config().limits;
    limits.max_finished_imports = 1;
    let (mut catalog, _) = fixture.open_with(base_config().with_limits(limits), verifiers());
    let a = tenant("a");
    let first_bytes = data(61, 8);
    let mut first_source = FakeSource::new("first", &first_bytes);
    let first = started(
        catalog
            .begin_import(weights(&a, &first_bytes), first_source.identity())
            .unwrap(),
    );
    published(
        catalog
            .drive_import(&first, &mut first_source, &mut Uninterrupted)
            .unwrap(),
    );
    assert!(catalog.import_status(&first).is_some());

    let second_bytes = data(62, 8);
    let mut second_source = FakeSource::new("second", &second_bytes);
    let second = started(
        catalog
            .begin_import(weights(&a, &second_bytes), second_source.identity())
            .unwrap(),
    );
    published(
        catalog
            .drive_import(&second, &mut second_source, &mut Uninterrupted)
            .unwrap(),
    );
    assert_eq!(catalog.import_status(&first), None);
    assert_eq!(catalog.cancel_import(first), CancelOutcome::UnknownTicket);
    assert!(matches!(
        catalog.import_status(&second),
        Some(ImportStatus::Published { .. })
    ));
}

#[test]
fn a_class_may_authenticate_the_whole_manifest() {
    let fixture = Fixture::new();
    let mut registry = VerifierRegistry::new();
    for class in ArtifactClass::ALL {
        let verifier = if class == ArtifactClass::GuestImage {
            FakeVerifier::manifest_bound(class)
        } else {
            FakeVerifier::new(class)
        };
        registry.register(Box::new(verifier)).unwrap();
    }
    let (mut catalog, _) = fixture.open_with(base_config(), registry);
    let host = Scope::Host;
    let bytes = data(64, 24);
    let mut signed = request(&host, ArtifactClass::GuestImage, &bytes);
    signed.trust = TrustClaim::Publisher {
        publisher: acme(),
        attestation: manifest_attestation(
            &acme(),
            ArtifactClass::GuestImage,
            signed.manifest.digest(),
        ),
    };
    // An extent table altered after signing is refused before anything is fetched.
    let mut altered = signed.clone();
    altered.manifest.extents[1].digest = ExtentDigest::of(b"other");
    let source = FakeSource::new("image", &bytes);
    assert!(matches!(
        catalog.begin_import(altered, source.identity()),
        Err(ImportRefusal::Trust {
            refusal: TrustRefusal::AttestationRejected { .. }
        })
    ));
    assert!(fixture.staging_dirs().is_empty());
    let object = import_bytes(&mut catalog, signed, &bytes);
    assert_eq!(catalog.status(&host, object), ObjectStatus::Published);
}

#[test]
fn a_scope_sees_only_its_own_failure_records() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let (a, b) = (tenant("a"), tenant("b"));
    let bytes = data(65, 8);
    let source = FakeSource::new("weights", &bytes);
    let mut checksum_only = weights(&a, &bytes);
    checksum_only.trust = TrustClaim::ChecksumOnly;
    assert!(catalog
        .begin_import(checksum_only, source.identity())
        .is_err());
    assert_eq!(catalog.failures().count(), 1);
    assert_eq!(catalog.failures_in(&a).count(), 1);
    assert_eq!(catalog.failures_in(&b).count(), 0);
}

#[test]
fn the_catalog_and_its_handles_can_be_shared_across_threads() {
    fn shareable<T: Send + Sync>() {}
    shareable::<Catalog>();
    shareable::<ReadHandle>();
    shareable::<FailureRecord>();
}

// Review findings: withdrawn trust quarantines (INT-09), and only source-file deletion
// removes an original (line 552).

/// The R1-b probe `a_withdrawn_publisher_keeps_its_objects_trusted_after_reopen`, turned
/// into a refusal test.
#[test]
fn a_withdrawn_publishers_objects_are_quarantined_on_reopen() {
    let fixture = Fixture::new();
    let a = tenant("a");
    let reader = execution("exe-2");
    let bytes: Vec<u8> = (0u8..100).collect();
    let update = || request(&a, ArtifactClass::RuntimeUpdate, &bytes);
    let mut catalog = fixture.open();
    let object = import_bytes(&mut catalog, update(), &bytes);
    let lease = catalog.acquire_lease(&a, &reader, object, LEASE).unwrap();
    drop(catalog);

    // The operator withdraws acme from the class policy and reopens.
    let withdrawn = base_config().with_trust(ArtifactClass::RuntimeUpdate, TrustPolicy::new());
    let (mut catalog, report) = fixture.open_with(withdrawn, verifiers());
    let reason = IntegrityFailure::TrustWithdrawn {
        refusal: TrustRefusal::PublisherNotTrusted {
            class: ArtifactClass::RuntimeUpdate,
            publisher: acme(),
        },
    };
    assert_eq!(report.published, 0);
    assert_eq!(report.quarantined, vec![(object, reason.clone())]);
    assert_eq!(
        catalog.status(&a, object),
        ObjectStatus::Quarantined {
            reason: reason.clone()
        }
    );
    assert_eq!(
        catalog.artifact_verification(&a, &reader, [object]),
        Err(ReadRefusal::Quarantined { object })
    );
    assert_eq!(
        catalog.verify_object(&a, object),
        Err(VerifyError::Quarantined { reason })
    );
    assert_eq!(
        catalog.acquire_lease(&a, &reader, object, LEASE),
        Err(ReadRefusal::Quarantined { object })
    );
    assert_eq!(
        catalog.open_read(&a, &reader, lease).map(|_| ()),
        Err(ReadRefusal::UnknownLease)
    );
    assert_eq!(
        catalog.object_view(&a, &reader, object),
        Err(ReadRefusal::Quarantined { object })
    );
    assert_eq!(
        catalog.find(&a, ArtifactClass::RuntimeUpdate, ContentKey::of(&bytes)),
        None
    );
    assert_eq!(
        catalog.grant(
            &a,
            grant_to(&tenant("b"), object, fixture.now().saturating_add(LEASE))
        ),
        Err(GrantRefusal::Quarantined { object })
    );
    // The same claim is refused for a fresh import, which never reports it published.
    let source = FakeSource::new("again", &bytes);
    assert!(matches!(
        catalog.begin_import(update(), source.identity()),
        Err(ImportRefusal::Trust {
            refusal: TrustRefusal::PublisherNotTrusted { .. }
        })
    ));
    // Quarantined, it is reported and kept, never collected.
    fixture.advance(GRACE * 3);
    assert!(catalog.collect_garbage().unwrap().removed.is_empty());
    assert!(fixture.object_dir(object).join("data").exists());
    drop(catalog);

    // Trusted again, it is served again.
    let (mut catalog, report) = fixture.open_with(base_config(), verifiers());
    assert_eq!((report.published, report.quarantined.len()), (1, 0));
    assert_eq!(read(&mut catalog, &a, &reader, object).unwrap(), bytes);
    assert_eq!(catalog.verify_object(&a, object), Ok(()));
}

#[test]
fn withdrawing_a_publisher_at_runtime_quarantines_its_objects_at_once() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let (a, b) = (tenant("a"), tenant("b"));
    let (owner, reader) = (execution("exe-a"), execution("exe-b"));
    let update_bytes = data(68, 20);
    let update = import_bytes(
        &mut catalog,
        request(&a, ArtifactClass::RuntimeUpdate, &update_bytes),
        &update_bytes,
    );
    let weights_bytes = data(69, 20);
    let model = import_bytes(&mut catalog, weights(&a, &weights_bytes), &weights_bytes);
    catalog
        .grant(
            &a,
            grant_to(
                &b,
                update,
                fixture.now().saturating_add(Duration::from_secs(300)),
            ),
        )
        .unwrap();
    let lease = catalog.acquire_lease(&b, &reader, update, LEASE).unwrap();
    let mut handle = catalog.open_read(&b, &reader, lease).unwrap();
    assert!(handle.read_extent(0).is_ok());

    let revision = catalog.set_trust_policy(ArtifactClass::RuntimeUpdate, TrustPolicy::new());
    assert_eq!(
        revision,
        TrustRevision {
            quarantined: vec![update],
            restored: vec![],
        }
    );
    // Open handles stop at once, nothing new is served, and other classes are untouched.
    assert_eq!(handle.read_extent(0), Err(ReadError::LeaseRevoked));
    drop(handle);
    assert_eq!(
        catalog.acquire_lease(&b, &reader, update, LEASE),
        Err(ReadRefusal::Quarantined { object: update })
    );
    assert_eq!(
        catalog.artifact_verification(&a, &owner, [update]),
        Err(ReadRefusal::Quarantined { object: update })
    );
    assert!(matches!(
        catalog.status(&a, update),
        ObjectStatus::Quarantined {
            reason: IntegrityFailure::TrustWithdrawn { .. }
        }
    ));
    assert_eq!(catalog.status(&a, model), ObjectStatus::Published);

    // Trusting the publisher again restores it; nothing was deleted.
    let trusted = TrustPolicy::new().trust_publisher(acme());
    let revision = catalog.set_trust_policy(ArtifactClass::RuntimeUpdate, trusted.clone());
    assert_eq!(
        revision,
        TrustRevision {
            quarantined: vec![],
            restored: vec![update],
        }
    );
    assert_eq!(
        catalog.config().trust.get(&ArtifactClass::RuntimeUpdate),
        Some(&trusted)
    );
    assert_eq!(
        read(&mut catalog, &a, &owner, update).unwrap(),
        update_bytes
    );
    assert_eq!(
        read(&mut catalog, &b, &reader, update).unwrap(),
        update_bytes
    );
}

#[test]
fn withdrawing_user_selection_quarantines_user_selected_originals() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let a = tenant("a");
    let signed_bytes = data(70, 20);
    let signed = import_bytes(&mut catalog, weights(&a, &signed_bytes), &signed_bytes);
    let selected_bytes = data(71, 20);
    let mut selected_request = weights(&a, &selected_bytes);
    selected_request.trust = TrustClaim::UserSelected;
    let selected = import_bytes(&mut catalog, selected_request, &selected_bytes);

    let revision = catalog.set_trust_policy(
        ArtifactClass::ModelWeights,
        TrustPolicy::new().trust_publisher(acme()),
    );
    assert_eq!(revision.quarantined, vec![selected]);
    assert_eq!(catalog.status(&a, signed), ObjectStatus::Published);
    assert_eq!(
        catalog.status(&a, selected),
        ObjectStatus::Quarantined {
            reason: IntegrityFailure::TrustWithdrawn {
                refusal: TrustRefusal::UserSelectionNotAccepted {
                    class: ArtifactClass::ModelWeights
                }
            }
        }
    );
    // Still an original: kept by collection, removed only on explicit request.
    fixture.advance(GRACE * 2);
    assert_eq!(
        catalog
            .collect_garbage()
            .unwrap()
            .kept_originals
            .into_iter()
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([signed, selected])
    );
    assert_eq!(
        catalog
            .delete_source_file(&a, &SourceFileTarget::Original(selected))
            .unwrap()
            .deleted,
        vec![selected]
    );
}

#[test]
fn only_source_file_deletion_removes_an_original() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let (a, b) = (tenant("a"), tenant("b"));
    let reader = execution("exe-1");
    let original_bytes = data(72, 24);
    let original = import_bytes(&mut catalog, weights(&a, &original_bytes), &original_bytes);
    let prepared_bytes = data(73, 8);
    let prepared = import_bytes(
        &mut catalog,
        prepared_request(&a, &prepared_bytes, &[original]),
        &prepared_bytes,
    );
    let model = RootName::new("model").unwrap();
    let model_root = catalog
        .set_root(
            &a,
            RootKind::LocalModel,
            model.clone(),
            BTreeSet::from([original, prepared]),
        )
        .unwrap();
    let target = SourceFileTarget::Original(original);
    assert_eq!(
        catalog.delete_source_file(&a, &target),
        Err(DeleteRefusal::InUse {
            object: original,
            holder: Holder::Root { root: model_root }
        })
    );

    // Deleting the local model and outwaiting any grace period never deletes the original.
    catalog.delete_local_model(&a, &model).unwrap();
    for _ in 0..3 {
        fixture.advance(GRACE * 10);
        assert_eq!(
            catalog.collect_garbage().unwrap().kept_originals,
            vec![original]
        );
    }
    assert_eq!(catalog.status(&a, prepared), ObjectStatus::Absent);
    assert_eq!(
        read(&mut catalog, &a, &reader, original).unwrap(),
        original_bytes
    );

    // Source-file deletion by identity takes only an unheld original of the scope.
    let sidecar_bytes = data(74, 8);
    let sidecar = import_bytes(
        &mut catalog,
        prepared_request(&a, &sidecar_bytes, &[original]),
        &sidecar_bytes,
    );
    assert_eq!(
        catalog.delete_source_file(&a, &SourceFileTarget::Original(sidecar)),
        Err(DeleteRefusal::NotAnOriginal { object: sidecar })
    );
    assert_eq!(
        catalog.delete_source_file(&b, &target),
        Err(DeleteRefusal::NoSuchOriginal { object: original })
    );
    let lease = catalog.acquire_lease(&a, &reader, original, LEASE).unwrap();
    assert_eq!(
        catalog.delete_source_file(&a, &target),
        Err(DeleteRefusal::InUse {
            object: original,
            holder: Holder::Lease
        })
    );
    catalog.release_lease(&a, &reader, lease).unwrap();

    assert_eq!(
        catalog.delete_source_file(&a, &target),
        Ok(SourceFileDeletion {
            root: None,
            deleted: vec![original],
            freed_bytes: 24,
        })
    );
    assert_eq!(catalog.status(&a, original), ObjectStatus::Absent);
    assert!(!fixture.object_dir(original).exists());
}

#[test]
fn quarantined_objects_are_never_collected_or_evicted() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let a = tenant("a");
    let original_bytes = data(75, 20);
    let original = import_bytes(&mut catalog, weights(&a, &original_bytes), &original_bytes);
    let prepared_bytes = data(76, 16);
    let prepared = import_bytes(
        &mut catalog,
        prepared_request(&a, &prepared_bytes, &[original]),
        &prepared_bytes,
    );
    overwrite(
        &fixture.object_dir(prepared).join("data"),
        0,
        &[prepared_bytes[0] ^ 1],
    );
    assert!(catalog.verify_object(&a, prepared).is_err());
    assert_eq!(
        catalog.evict_cache(&a, &[prepared]),
        Err(EvictionRefusal::Quarantined { object: prepared })
    );
    assert!(catalog.eviction_candidates(&a).is_empty());
    fixture.advance(GRACE * 3);
    let collected = catalog.collect_garbage().unwrap();
    assert_eq!(
        (collected.kept_quarantined, collected.removed),
        (vec![prepared], vec![])
    );
    assert!(fixture.object_dir(prepared).join("data").exists());
}

// Staged extents for retried transfers (S2 CORE-05; INT-08; T16 gap G9).

/// A request for `bytes` in 64-byte extents, the shape of the T16 scenario.
fn wide_weights(scope: &Scope, bytes: &[u8]) -> ImportRequest {
    let mut request = weights(scope, bytes);
    request.manifest = ImportManifest::describe(bytes, NonZeroU64::new(64).unwrap());
    request
}

#[test]
fn a_pending_import_reports_what_it_verified_to_its_own_scope() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let (a, b) = (tenant("a"), tenant("b"));
    let owner = execution("exe-1");
    let class = ArtifactClass::ModelWeights;
    let bytes = data(77, 4096);
    let key = ContentKey::of(&bytes);
    let mut source = FakeSource::new("large", &bytes);
    let ticket = started(
        catalog
            .begin_import(wide_weights(&a, &bytes), source.identity())
            .unwrap(),
    );
    assert_eq!(
        catalog
            .staged_extents(&a, &owner, class, key)
            .map(|staged| staged.verified),
        Some(vec![])
    );

    // 48 of 64 extents verified and staged, then interrupted.
    pending(
        catalog
            .drive_import(&ticket, &mut source, &mut StopAt::extent(48))
            .unwrap(),
    );
    let staged = catalog.staged_extents(&a, &owner, class, key).unwrap();
    assert_eq!(
        staged,
        StagedExtents {
            object: ObjectId::new(&a, class, key),
            content_key: key,
            true_length_bytes: 4096,
            verified: vec![ByteSpan {
                offset_bytes: 0,
                length_bytes: 48 * 64,
            }],
        }
    );
    assert_eq!(staged.verified_bytes(), 3072);

    // Scope-checked like a read: another tenant, execution, class or content sees nothing.
    assert_eq!(catalog.staged_extents(&b, &owner, class, key), None);
    assert_eq!(
        catalog.staged_extents(&a, &execution("exe-2"), class, key),
        None
    );
    assert_eq!(
        catalog.staged_extents(&a, &owner, ArtifactClass::ModelSidecar, key),
        None
    );
    assert_eq!(
        catalog.staged_extents(&a, &owner, class, ContentKey::of(b"other")),
        None
    );

    // Once published, the whole object is read through its view instead.
    let (object, _) = published(
        catalog
            .drive_import(&ticket, &mut source, &mut Uninterrupted)
            .unwrap(),
    );
    assert_eq!(catalog.staged_extents(&a, &owner, class, key), None);
    assert_eq!(
        catalog
            .object_view(&a, &owner, object)
            .unwrap()
            .length_bytes,
        4096
    );
}

#[test]
fn staged_extents_list_only_extents_checked_in_this_process() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let a = tenant("a");
    let owner = execution("exe-1");
    let class = ArtifactClass::ModelWeights;
    let bytes = data(78, 1024);
    let key = ContentKey::of(&bytes);
    let mut source = FakeSource::new("weights", &bytes);
    let ticket = started(
        catalog
            .begin_import(wide_weights(&a, &bytes), source.identity())
            .unwrap(),
    );
    pending(
        catalog
            .drive_import(&ticket, &mut source, &mut StopAt::extent(12))
            .unwrap(),
    );
    assert_eq!(
        catalog
            .staged_extents(&a, &owner, class, key)
            .unwrap()
            .verified_bytes(),
        12 * 64
    );
    // A cancelled import's staging is a remnant: unverified until an import resumes it.
    assert_eq!(catalog.cancel_import(ticket), CancelOutcome::Cancelled);
    assert_eq!(catalog.staged_extents(&a, &owner, class, key), None);

    // Resumed after a restart, its journal claims count only once re-checked.
    let (mut catalog, _) = fixture.reopen(catalog);
    let ticket = started(
        catalog
            .begin_import(wide_weights(&a, &bytes), source.identity())
            .unwrap(),
    );
    assert_eq!(
        catalog
            .staged_extents(&a, &owner, class, key)
            .map(|staged| staged.verified),
        Some(vec![])
    );
    overwrite(&fixture.staged_data(), 5 * 64, b"corrupt!");
    pending(
        catalog
            .drive_import(&ticket, &mut source, &mut StopAt::extent(5))
            .unwrap(),
    );
    // Extents 0-4 were re-checked; 5 failed its check, and 6-11 were not reached.
    assert_eq!(
        catalog
            .staged_extents(&a, &owner, class, key)
            .unwrap()
            .verified,
        vec![ByteSpan {
            offset_bytes: 0,
            length_bytes: 5 * 64,
        }]
    );
    let (object, _) = published(
        catalog
            .drive_import(&ticket, &mut source, &mut Uninterrupted)
            .unwrap(),
    );
    assert_eq!(read(&mut catalog, &a, &owner, object).unwrap(), bytes);
}

#[test]
fn withdrawn_trust_hides_staged_extents_and_fails_the_import() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let a = tenant("a");
    let owner = execution("exe-1");
    let class = ArtifactClass::ModelWeights;
    let bytes = data(79, 1024);
    let key = ContentKey::of(&bytes);
    let mut source = FakeSource::new("weights", &bytes);
    let ticket = started(
        catalog
            .begin_import(wide_weights(&a, &bytes), source.identity())
            .unwrap(),
    );
    pending(
        catalog
            .drive_import(&ticket, &mut source, &mut StopAt::extent(8))
            .unwrap(),
    );
    assert_eq!(
        catalog
            .staged_extents(&a, &owner, class, key)
            .unwrap()
            .verified_bytes(),
        512
    );

    catalog.set_trust_policy(class, TrustPolicy::new());
    assert_eq!(catalog.staged_extents(&a, &owner, class, key), None);
    let failure = failed(
        catalog
            .drive_import(&ticket, &mut source, &mut Uninterrupted)
            .unwrap(),
    );
    assert_eq!(
        failure.reason,
        FailureReason::Refused {
            refusal: ImportRefusal::Trust {
                refusal: TrustRefusal::PublisherNotTrusted {
                    class,
                    publisher: acme()
                }
            }
        }
    );
    assert!(fixture.staging_dirs().is_empty());
    assert_eq!(catalog.find(&a, class, key), None);
}

#[test]
fn several_pending_imports_report_only_what_every_one_verified() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let a = tenant("a");
    let owner = execution("exe-1");
    let class = ArtifactClass::ModelWeights;
    let bytes = data(80, 1024);
    let key = ContentKey::of(&bytes);
    let mut first = FakeSource::new("first", &bytes);
    let mut second = FakeSource::new("second", &bytes);
    let first_ticket = started(
        catalog
            .begin_import(wide_weights(&a, &bytes), first.identity())
            .unwrap(),
    );
    let second_ticket = started(
        catalog
            .begin_import(wide_weights(&a, &bytes), second.identity())
            .unwrap(),
    );
    pending(
        catalog
            .drive_import(&first_ticket, &mut first, &mut StopAt::extent(10))
            .unwrap(),
    );
    pending(
        catalog
            .drive_import(&second_ticket, &mut second, &mut StopAt::extent(4))
            .unwrap(),
    );
    assert_eq!(
        catalog
            .staged_extents(&a, &owner, class, key)
            .unwrap()
            .verified,
        vec![ByteSpan {
            offset_bytes: 0,
            length_bytes: 4 * 64,
        }]
    );
}

// GPU-T02: single flight per tenant scope, source and model execution identity (line 533;
// GPU part §3.2 layer 3), with one subscriber per execution.

fn by(scope: &Scope, bytes: &[u8], execution_name: &str, operation_name: &str) -> ImportRequest {
    let mut request = weights(scope, bytes);
    request.execution = execution(execution_name);
    request.operation = OperationId::new(operation_name).unwrap();
    request
}

#[test]
fn another_execution_of_the_tenant_subscribes_to_the_running_import() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let a = tenant("a");
    let (exe_a, exe_b) = (execution("exe-a"), execution("exe-b"));
    let class = ArtifactClass::ModelWeights;
    let bytes = data(81, 32);
    let key = ContentKey::of(&bytes);
    let mut source = FakeSource::new("model", &bytes);
    let first = started(
        catalog
            .begin_import(by(&a, &bytes, "exe-a", "op-a"), source.identity())
            .unwrap(),
    );
    pending(
        catalog
            .drive_import(&first, &mut source, &mut StopAt::extent(2))
            .unwrap(),
    );
    let second = match catalog
        .begin_import(by(&a, &bytes, "exe-b", "op-b"), source.identity())
        .unwrap()
    {
        ImportStart::Attached(ticket) => ticket,
        other => panic!("another execution of the tenant subscribes: {other:?}"),
    };

    // One import with two subscribers and one reservation charged to the tenant.
    let both = vec![exe_a.clone(), exe_b.clone()];
    assert_eq!(catalog.import_subscribers(&first), Some(both.clone()));
    assert_eq!(catalog.import_subscribers(&second), Some(both));
    assert_eq!(catalog.quota_usage(&a).reserved_bytes, 32);
    assert_eq!(fixture.staging_dirs().len(), 1);

    // Every subscriber sees the shared import's verified extents; an execution that has
    // not subscribed does not.
    for subscriber in [&exe_a, &exe_b] {
        assert_eq!(
            catalog
                .staged_extents(&a, subscriber, class, key)
                .map(|staged| staged.verified_bytes()),
            Some(16)
        );
    }
    assert_eq!(
        catalog.staged_extents(&a, &execution("exe-c"), class, key),
        None
    );

    // The second subscriber drives; the records of its drive name it.
    let (_, failure) = pending(
        catalog
            .drive_import(&second, &mut source, &mut StopAt::extent(3))
            .unwrap(),
    );
    assert_eq!(
        (failure.execution, failure.operation),
        (exe_b.clone(), OperationId::new("op-b").unwrap())
    );
    let (object, _) = published(
        catalog
            .drive_import(&second, &mut source, &mut Uninterrupted)
            .unwrap(),
    );
    assert_eq!(source.reads(), 4, "every extent fetched once");
    assert!(matches!(
        catalog.import_status(&first),
        Some(ImportStatus::Published { object: seen, .. }) if seen == object
    ));

    // Each subscriber reads the result under its own execution; the record keeps the one
    // that started the import.
    for subscriber in [&exe_a, &exe_b] {
        assert_eq!(read(&mut catalog, &a, subscriber, object).unwrap(), bytes);
    }
    assert_eq!(
        catalog.private_metadata(&a, object).unwrap().execution,
        exe_a
    );
}

#[test]
fn one_subscriber_cancelling_leaves_the_import_to_the_other_executions() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let a = tenant("a");
    let (exe_a, exe_b) = (execution("exe-a"), execution("exe-b"));
    let class = ArtifactClass::ModelWeights;
    let bytes = data(82, 32);
    let key = ContentKey::of(&bytes);
    let mut source = FakeSource::new("model", &bytes);
    let first = started(
        catalog
            .begin_import(by(&a, &bytes, "exe-a", "op-a"), source.identity())
            .unwrap(),
    );
    let second = ticket_of_attached(
        catalog
            .begin_import(by(&a, &bytes, "exe-b", "op-b"), source.identity())
            .unwrap(),
    );
    pending(
        catalog
            .drive_import(&first, &mut source, &mut StopAt::extent(1))
            .unwrap(),
    );
    assert_eq!(
        catalog.cancel_import(first),
        CancelOutcome::Continuing {
            remaining_tickets: 1
        }
    );
    assert_eq!(
        catalog.import_subscribers(&second),
        Some(vec![exe_b.clone()])
    );
    assert_eq!(catalog.staged_extents(&a, &exe_a, class, key), None);
    assert_eq!(
        catalog
            .staged_extents(&a, &exe_b, class, key)
            .map(|staged| staged.verified_bytes()),
        Some(8)
    );
    let (object, _) = published(
        catalog
            .drive_import(&second, &mut source, &mut Uninterrupted)
            .unwrap(),
    );
    assert_eq!(catalog.status(&a, object), ObjectStatus::Published);

    // When the last subscriber leaves an unfinished import, the cancellation names it.
    let other = data(83, 32);
    let mut other_source = FakeSource::new("other", &other);
    let first = started(
        catalog
            .begin_import(by(&a, &other, "exe-a", "op-a"), other_source.identity())
            .unwrap(),
    );
    let second = ticket_of_attached(
        catalog
            .begin_import(by(&a, &other, "exe-b", "op-b"), other_source.identity())
            .unwrap(),
    );
    pending(
        catalog
            .drive_import(&second, &mut other_source, &mut StopAt::extent(2))
            .unwrap(),
    );
    assert_eq!(
        catalog.cancel_import(second),
        CancelOutcome::Continuing {
            remaining_tickets: 1
        }
    );
    assert_eq!(catalog.cancel_import(first), CancelOutcome::Cancelled);
    let cancelled = catalog
        .failures()
        .filter(|record| record.reason == FailureReason::Cancelled)
        .last()
        .unwrap();
    assert_eq!(cancelled.execution, exe_a);
    assert_eq!(catalog.quota_usage(&a).reserved_bytes, 0);
}

fn ticket_of_attached(start: ImportStart) -> ImportTicket {
    match start {
        ImportStart::Attached(ticket) => ticket,
        other => panic!("expected to subscribe, got {other:?}"),
    }
}

#[test]
fn the_model_execution_identity_keys_single_flight() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let a = tenant("a");
    let bytes = data(84, 24);
    let source = FakeSource::new("prepared", &bytes);
    let runner = |name: &str| {
        ModelExecutionKey::from_digest(digest("yougori/test/execution/v1", &[name.as_bytes()]))
    };
    let (x, y) = (runner("x"), runner("y"));
    let first = started(
        catalog
            .begin_import_for(by(&a, &bytes, "exe-a", "op-a"), source.identity(), x)
            .unwrap(),
    );
    // The same identity from another execution subscribes.
    let second = ticket_of_attached(
        catalog
            .begin_import_for(by(&a, &bytes, "exe-b", "op-b"), source.identity(), x)
            .unwrap(),
    );
    assert_eq!(
        catalog.import_subscribers(&second),
        Some(vec![execution("exe-a"), execution("exe-b")])
    );
    // Another execution identity, or none, is another import.
    let third = started(
        catalog
            .begin_import_for(by(&a, &bytes, "exe-a", "op-a"), source.identity(), y)
            .unwrap(),
    );
    let fourth = started(
        catalog
            .begin_import(by(&a, &bytes, "exe-a", "op-a"), source.identity())
            .unwrap(),
    );
    assert_eq!(
        catalog.import_subscribers(&third),
        Some(vec![execution("exe-a")])
    );
    assert_eq!(
        catalog.import_subscribers(&fourth),
        Some(vec![execution("exe-a")])
    );
    assert_eq!(
        catalog.import_subscribers(&first).map(|all| all.len()),
        Some(2)
    );
    assert_eq!(fixture.staging_dirs().len(), 3);
}

#[test]
fn another_execution_resumes_the_tenants_staging_after_a_restart() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let a = tenant("a");
    let bytes = data(85, 32);
    let mut source = FakeSource::new("model", &bytes);
    let ticket = started(
        catalog
            .begin_import(by(&a, &bytes, "exe-a", "op-a"), source.identity())
            .unwrap(),
    );
    pending(
        catalog
            .drive_import(&ticket, &mut source, &mut StopAt::extent(2))
            .unwrap(),
    );
    let (mut catalog, report) = fixture.reopen(catalog);
    assert_eq!(report.staging, 1);
    source.reset_reads();
    let ticket = started(
        catalog
            .begin_import(by(&a, &bytes, "exe-b", "op-b"), source.identity())
            .unwrap(),
    );
    let (_, progress) = published(
        catalog
            .drive_import(&ticket, &mut source, &mut Uninterrupted)
            .unwrap(),
    );
    assert_eq!((progress.reused_extents, progress.fetched_extents), (2, 2));
    assert_eq!(source.reads(), 2);
}

// V04: dependency packages are their own artifact class.

#[test]
fn dependency_packages_are_their_own_class() {
    let fixture = Fixture::new();
    let registry = publisher("package-registry");
    let config = base_config().with_trust(
        ArtifactClass::DependencyPackage,
        TrustPolicy::new().trust_publisher(registry),
    );
    let (mut catalog, _) = fixture.open_with(config, verifiers());
    let a = tenant("a");
    let bytes = data(86, 24);
    let key = ContentKey::of(&bytes);
    let source = FakeSource::new("package", &bytes);
    let signed = |by: PublisherId| {
        let mut request = request(&a, ArtifactClass::DependencyPackage, &bytes);
        request.trust = TrustClaim::Publisher {
            publisher: by,
            attestation: attestation(&by, ArtifactClass::DependencyPackage, key),
        };
        request
    };
    // A publisher trusted for OCI layers is not thereby trusted for dependency packages.
    assert_eq!(
        catalog.begin_import(signed(acme()), source.identity()),
        Err(ImportRefusal::Trust {
            refusal: TrustRefusal::PublisherNotTrusted {
                class: ArtifactClass::DependencyPackage,
                publisher: acme()
            }
        })
    );
    let package = import_bytes(&mut catalog, signed(registry), &bytes);
    assert_eq!(
        package,
        ObjectId::new(&a, ArtifactClass::DependencyPackage, key)
    );
    assert_ne!(package, ObjectId::new(&a, ArtifactClass::OciLayer, key));
    assert_eq!(
        catalog.find(&a, ArtifactClass::OciLayer, key),
        None,
        "equal bytes as another class are another object"
    );
    assert_eq!(
        serde_json::to_value(ArtifactClass::DependencyPackage).unwrap(),
        serde_json::json!("dependency_package")
    );
    assert!(ArtifactClass::ALL.contains(&ArtifactClass::DependencyPackage));
}

// P10: a lease's expiry, for its holder only.

#[test]
fn a_lease_reports_its_expiry_to_its_holder_only() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let (a, b) = (tenant("a"), tenant("b"));
    let (owner, other) = (execution("exe-a"), execution("exe-b"));
    let bytes = data(87, 20);
    let object = import_bytes(&mut catalog, weights(&a, &bytes), &bytes);
    let lease = catalog.acquire_lease(&a, &owner, object, LEASE).unwrap();
    assert_eq!(
        catalog.lease_expires_at(&a, &owner, lease),
        Ok(fixture.now().saturating_add(LEASE))
    );
    assert_eq!(
        catalog.lease_object(&a, &owner, lease),
        Ok((object, fixture.now().saturating_add(LEASE)))
    );
    assert_eq!(
        catalog.lease_object(&b, &owner, lease),
        Err(ReadRefusal::LeaseNotHeld)
    );
    fixture.advance(Duration::from_secs(10));
    let renewed = catalog.renew_lease(&a, &owner, lease, LEASE).unwrap();
    assert_eq!(catalog.lease_expires_at(&a, &owner, lease), Ok(renewed));
    assert_eq!(
        catalog.lease_expires_at(&a, &other, lease),
        Err(ReadRefusal::LeaseNotHeld)
    );
    assert_eq!(
        catalog.lease_expires_at(&b, &owner, lease),
        Err(ReadRefusal::LeaseNotHeld)
    );

    // Under a grant, the expiry is the grant's when that is sooner.
    let grant_ends = fixture.now().saturating_add(Duration::from_secs(5));
    catalog.grant(&a, grant_to(&b, object, grant_ends)).unwrap();
    let granted = catalog
        .acquire_lease(&b, &other, object, Duration::from_secs(60))
        .unwrap();
    assert_eq!(
        catalog.lease_expires_at(&b, &other, granted),
        Ok(grant_ends)
    );
    fixture.advance(Duration::from_secs(5));
    assert_eq!(
        catalog.lease_expires_at(&b, &other, granted),
        Err(ReadRefusal::LeaseExpired)
    );

    catalog.release_lease(&a, &owner, lease).unwrap();
    assert_eq!(
        catalog.lease_expires_at(&a, &owner, lease),
        Err(ReadRefusal::UnknownLease)
    );
}

// Versioned records and layout migration (GPU-W03: "support catalog schema migration
// without rewriting or deleting original model files").

/// Every file under `root`'s `dir` ("" for the whole root), by relative path, with the
/// digest of its bytes.
fn file_digests(
    root: &Path,
    dir: &str,
) -> std::collections::BTreeMap<String, crate::foundation::ids::Digest> {
    let mut found = std::collections::BTreeMap::new();
    let mut pending = vec![root.join(dir)];
    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(&path).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else {
                let relative = path
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                found.insert(
                    relative,
                    digest("yougori/test/file/v1", &[&fs::read(&path).unwrap()]),
                );
            }
        }
    }
    found
}

/// Imports `bytes` for tenant a from `locator` until extent `stop`, leaving it pending.
fn interrupt(catalog: &mut Catalog, locator: &str, bytes: &[u8], stop: u32) -> FakeSource {
    let mut source = FakeSource::new(locator, bytes);
    let ticket = started(
        catalog
            .begin_import(weights(&tenant("a"), bytes), source.identity())
            .unwrap(),
    );
    pending(
        catalog
            .drive_import(&ticket, &mut source, &mut StopAt::extent(stop))
            .unwrap(),
    );
    source
}

/// Resumes the import of `bytes` from `source` under `execution` and publishes it.
fn resume(
    catalog: &mut Catalog,
    execution_name: &str,
    bytes: &[u8],
    source: &mut FakeSource,
) -> ImportProgress {
    source.reset_reads();
    let ticket = started(
        catalog
            .begin_import(
                by(&tenant("a"), bytes, execution_name, "op-resume"),
                source.identity(),
            )
            .unwrap(),
    );
    published(
        catalog
            .drive_import(&ticket, source, &mut Uninterrupted)
            .unwrap(),
    )
    .1
}

/// The staging directory of tenant a's import from `source` under the current key.
fn staging_dir(fixture: &Fixture, source: &FakeSource) -> PathBuf {
    fixture
        .root()
        .join("staging")
        .join(super::import::flight_key(&tenant("a"), &source.identity(), None).to_hex())
}

/// Rewrites a staging directory as layout 1 wrote it: a format 1 declaration keyed by
/// tenant scope, source and parent execution, in a directory named by that key.
fn rewrite_parent_keyed(dir: &Path, execution: &ExecutionId) -> PathBuf {
    let record: super::store::StagingRecord =
        serde_json::from_slice(&fs::read(dir.join("flight.json")).unwrap()).unwrap();
    let key = super::migrate::flight_key_v1(&record.scope, &record.source, execution);
    let legacy = serde_json::json!({
        "format": 1,
        "flight": key,
        "scope": record.scope,
        "class": record.class,
        "source": record.source,
        "execution": execution,
        "manifest_digest": record.manifest_digest,
        "true_length_bytes": record.true_length_bytes,
    });
    fs::write(
        dir.join("flight.json"),
        serde_json::to_vec_pretty(&legacy).unwrap(),
    )
    .unwrap();
    let target = dir.parent().unwrap().join(key.to_hex());
    fs::rename(dir, &target).unwrap();
    target
}

/// Sets the format a record declares, keeping every other field.
fn set_format(path: &Path, format: u32) {
    make_tree_writable(path);
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    value["format"] = format.into();
    fs::write(path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
}

/// A catalog in the layout 1 shape: an original, a prepared representation and their
/// roots, one interrupted import keyed by parent execution and one written by a build
/// that already keyed by model execution identity but still declared format 1.
struct LayoutOne {
    fixture: Fixture,
    original: ObjectId,
    original_bytes: Vec<u8>,
    parent_keyed: (FakeSource, Vec<u8>),
    unversioned: (FakeSource, Vec<u8>),
}

fn layout_one() -> LayoutOne {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let a = tenant("a");
    let original_bytes = data(90, 40);
    let original = import_bytes(&mut catalog, weights(&a, &original_bytes), &original_bytes);
    let prepared_bytes = data(91, 16);
    let prepared = import_bytes(
        &mut catalog,
        prepared_request(&a, &prepared_bytes, &[original]),
        &prepared_bytes,
    );
    catalog
        .set_root(
            &a,
            RootKind::SourceFile,
            RootName::new("download").unwrap(),
            BTreeSet::from([original]),
        )
        .unwrap();
    catalog
        .set_root(
            &a,
            RootKind::LocalModel,
            RootName::new("model").unwrap(),
            BTreeSet::from([original, prepared]),
        )
        .unwrap();
    let parent_bytes = data(92, 32);
    let parent_source = interrupt(&mut catalog, "interrupted", &parent_bytes, 2);
    let unversioned_bytes = data(93, 24);
    let unversioned_source = interrupt(&mut catalog, "unversioned", &unversioned_bytes, 1);
    drop(catalog);
    rewrite_parent_keyed(&staging_dir(&fixture, &parent_source), &execution("exe-1"));
    set_format(
        &staging_dir(&fixture, &unversioned_source).join("flight.json"),
        1,
    );
    fs::remove_file(fixture.root().join("format.json")).unwrap();
    LayoutOne {
        fixture,
        original,
        original_bytes,
        parent_keyed: (parent_source, parent_bytes),
        unversioned: (unversioned_source, unversioned_bytes),
    }
}

/// The layout 2 staging directories `layout_one` migrates to.
fn migrated_staging(one: &LayoutOne) -> BTreeSet<PathBuf> {
    BTreeSet::from([
        staging_dir(&one.fixture, &one.parent_keyed.0),
        staging_dir(&one.fixture, &one.unversioned.0),
    ])
}

#[test]
fn the_layout_one_key_binds_the_parent_execution() {
    let source = SourceIdentity::describe("test", "weights");
    let a = tenant("a");
    let one = super::migrate::flight_key_v1(&a, &source, &execution("exe-1"));
    assert_ne!(
        one,
        super::migrate::flight_key_v1(&a, &source, &execution("exe-2"))
    );
    assert_ne!(one, super::import::flight_key(&a, &source, None));
}

#[test]
fn migration_keeps_every_original_byte_for_byte() {
    let one = layout_one();
    let root = one.fixture.root();
    let objects = file_digests(root, "objects");
    let records = file_digests(root, "records");
    let roots = file_digests(root, "roots");
    let parent_staged = file_digests(root, "staging")
        .into_iter()
        .filter(|(path, _)| path.ends_with("object/data"))
        .map(|(_, digest)| digest)
        .collect::<BTreeSet<_>>();

    let (mut catalog, report) = one.fixture.open_with(base_config(), verifiers());
    assert_eq!(
        (report.migration.from_format, report.migration.to_format),
        (1, CATALOG_FORMAT)
    );
    assert_eq!(report.migration.rekeyed.len(), 1);
    assert_eq!(report.migration.upgraded, 1);
    assert!(report.migration.unresumable.is_empty() && report.refused.is_empty());
    assert_eq!(file_digests(root, "objects"), objects);
    assert_eq!(file_digests(root, "records"), records);
    assert_eq!(file_digests(root, "roots"), roots);
    // Staged bytes move with their directory, unchanged.
    assert_eq!(
        file_digests(root, "staging")
            .into_iter()
            .filter(|(path, _)| path.ends_with("object/data"))
            .map(|(_, digest)| digest)
            .collect::<BTreeSet<_>>(),
        parent_staged
    );
    assert_eq!(report.published, 2);
    assert_eq!(
        read(
            &mut catalog,
            &tenant("a"),
            &execution("exe-1"),
            one.original
        )
        .unwrap(),
        one.original_bytes
    );

    // Collection after migration never removes an original, even once its local model
    // is deleted and the grace period has passed.
    let original_files = |root: &Path| file_digests(root, &format!("objects/{}", one.original));
    let kept = original_files(root);
    catalog
        .delete_local_model(&tenant("a"), &RootName::new("model").unwrap())
        .unwrap();
    one.fixture.advance(GRACE * 3);
    let collected = catalog.collect_garbage().unwrap();
    assert!(!collected.removed.contains(&one.original));
    assert_eq!(original_files(root), kept);
}

#[test]
fn a_layout_one_interrupted_import_resumes_its_verified_extents() {
    let mut one = layout_one();
    let (mut catalog, report) = one.fixture.open_with(base_config(), verifiers());
    let rekeyed = &report.migration.rekeyed[0];
    assert_eq!(
        rekeyed.to,
        super::import::flight_key(&tenant("a"), &one.parent_keyed.0.identity(), None)
    );
    assert_eq!(
        (&rekeyed.scope, rekeyed.source),
        (&tenant("a"), one.parent_keyed.0.identity())
    );
    assert!(!one
        .fixture
        .root()
        .join("staging")
        .join(&rekeyed.from)
        .exists());
    let staged: BTreeSet<PathBuf> = one.fixture.staging_dirs().into_iter().collect();
    assert_eq!(staged, migrated_staging(&one));

    // Any execution of the tenant resumes it; the two verified extents are not fetched.
    let (source, bytes) = &mut one.parent_keyed;
    let progress = resume(&mut catalog, "exe-2", bytes, source);
    assert_eq!((progress.reused_extents, progress.fetched_extents), (2, 2));
    assert_eq!(source.reads(), 2);
    let (source, bytes) = &mut one.unversioned;
    let progress = resume(&mut catalog, "exe-1", bytes, source);
    assert_eq!((progress.reused_extents, progress.fetched_extents), (1, 2));
}

#[test]
fn two_layout_one_imports_of_one_source_keep_the_second_unresumable() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let bytes = data(94, 32);
    let mut source = interrupt(&mut catalog, "shared", &bytes, 2);
    drop(catalog);
    let first = rewrite_parent_keyed(&staging_dir(&fixture, &source), &execution("exe-1"));
    // The same import by a second parent execution: layout 1 kept a flight for each.
    let copy = fixture.root().join("staging").join("copy");
    fs::create_dir_all(copy.join("object")).unwrap();
    for name in ["flight.json", "journal", "object/data"] {
        fs::copy(first.join(name), copy.join(name)).unwrap();
    }
    let second = {
        let record: serde_json::Value =
            serde_json::from_slice(&fs::read(copy.join("flight.json")).unwrap()).unwrap();
        let scope: Scope = serde_json::from_value(record["scope"].clone()).unwrap();
        let key = super::migrate::flight_key_v1(&scope, &source.identity(), &execution("exe-2"));
        let mut record = record;
        record["flight"] = serde_json::to_value(key).unwrap();
        record["execution"] = "exe-2".into();
        fs::write(
            copy.join("flight.json"),
            serde_json::to_vec_pretty(&record).unwrap(),
        )
        .unwrap();
        let target = fixture.root().join("staging").join(key.to_hex());
        fs::rename(&copy, &target).unwrap();
        target
    };
    fs::remove_file(fixture.root().join("format.json")).unwrap();

    let (mut catalog, report) = fixture.open_with(base_config(), verifiers());
    let key = super::import::flight_key(&tenant("a"), &source.identity(), None);
    assert_eq!(report.migration.rekeyed.len(), 1);
    assert_eq!(report.migration.unresumable.len(), 1);
    let unresumable = &report.migration.unresumable[0];
    assert_eq!(unresumable.reason, UnresumableReason::KeyTaken { key });
    let kept = fixture.root().join("staging").join(&unresumable.staging);
    assert!(kept == first || kept == second);
    assert!(kept.join("object").join("data").exists());
    // Its bytes stay, charged to the tenant, until the usual grace period.
    assert_eq!(catalog.quota_usage(&tenant("a")).unpublished_bytes, 64);
    let progress = resume(&mut catalog, "exe-1", &bytes, &mut source);
    assert_eq!(progress.reused_extents, 2);
    assert_eq!(catalog.collect_garbage().unwrap().removed_staging, 0);
    assert!(kept.exists());
    fixture.advance(GRACE);
    assert_eq!(catalog.collect_garbage().unwrap().removed_staging, 1);
    assert!(!kept.exists());
}

#[test]
fn a_crash_between_migration_steps_resumes() {
    // Rewrite and move the parent-keyed declaration, rewrite the other, write the marker.
    let steps = 4;
    for stop in 0..steps {
        let mut one = layout_one();
        let root = one.fixture.root().to_path_buf();
        let objects = file_digests(&root, "objects");
        let mut taken = 0;
        let stopped = super::migrate::migrate(&super::store::Layout::new(&root), 1, &mut |_| {
            taken += 1;
            taken <= stop
        })
        .unwrap();
        assert!(stopped.is_none(), "stopped before step {stop}");
        assert!(!root.join("format.json").exists());

        // A crash here; the next open finishes the migration.
        let (mut catalog, report) = one.fixture.open_with(base_config(), verifiers());
        assert!(report.migration.unresumable.is_empty(), "stop {stop}");
        assert!(root.join("format.json").exists());
        let staged: BTreeSet<PathBuf> = one.fixture.staging_dirs().into_iter().collect();
        assert_eq!(staged, migrated_staging(&one), "stop {stop}");
        for dir in &staged {
            let record: serde_json::Value =
                serde_json::from_slice(&fs::read(dir.join("flight.json")).unwrap()).unwrap();
            assert_eq!(record["format"], 2, "stop {stop}");
        }
        assert_eq!(file_digests(&root, "objects"), objects);

        let (source, bytes) = &mut one.parent_keyed;
        assert_eq!(
            resume(&mut catalog, "exe-1", bytes, source).reused_extents,
            2
        );
        let (source, bytes) = &mut one.unversioned;
        assert_eq!(
            resume(&mut catalog, "exe-1", bytes, source).reused_extents,
            1
        );
        // Collection after the interrupted migration never removes an original.
        one.fixture.advance(GRACE * 3);
        catalog.collect_garbage().unwrap();
        assert!(root
            .join("objects")
            .join(one.original.to_string())
            .join("data")
            .exists());
    }
}

#[test]
fn repeated_opens_are_idempotent() {
    let one = layout_one();
    let root = one.fixture.root();
    let (catalog, first) = one.fixture.open_with(base_config(), verifiers());
    assert_eq!(first.migration.rekeyed.len(), 1);
    drop(catalog);
    let migrated = file_digests(root, "");
    for _ in 0..2 {
        let (catalog, again) = one.fixture.open_with(base_config(), verifiers());
        assert_eq!(
            again.migration,
            MigrationReport {
                from_format: CATALOG_FORMAT,
                to_format: CATALOG_FORMAT,
                ..MigrationReport::default()
            }
        );
        assert_eq!(again.published, first.published);
        drop(catalog);
        assert_eq!(file_digests(root, ""), migrated);
    }
}

#[test]
fn a_newer_layout_is_refused_whole_and_left_alone() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let bytes = data(95, 20);
    import_bytes(&mut catalog, weights(&tenant("a"), &bytes), &bytes);
    drop(catalog);
    let marker = fixture.root().join("format.json");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&fs::read(&marker).unwrap()).unwrap(),
        serde_json::json!({ "format": CATALOG_FORMAT })
    );
    for content in [
        serde_json::to_vec(&serde_json::json!({ "format": CATALOG_FORMAT + 1 })).unwrap(),
        b"not a marker".to_vec(),
    ] {
        fs::write(&marker, &content).unwrap();
        let before = file_digests(fixture.root(), "");
        let refused = Catalog::open(
            fixture.root(),
            base_config(),
            verifiers(),
            fixture.clock.clone(),
        )
        .unwrap_err();
        assert!(
            matches!(
                &refused,
                OpenFailure::Storage(StorageFailure {
                    operation: StorageOperation::Format | StorageOperation::Parse,
                    ..
                })
            ),
            "{refused:?}"
        );
        assert_eq!(file_digests(fixture.root(), ""), before);
    }
}

#[test]
fn newer_records_are_refused_and_kept() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let a = tenant("a");
    let bytes = data(96, 20);
    let object = import_bytes(&mut catalog, weights(&a, &bytes), &bytes);
    let staged_bytes = data(97, 24);
    let source = interrupt(&mut catalog, "newer", &staged_bytes, 1);
    drop(catalog);
    let record = fixture.record(object);
    set_format(&record, 2);
    let staging = staging_dir(&fixture, &source);
    set_format(&staging.join("flight.json"), 3);
    let kept = file_digests(fixture.root(), "");

    let (mut catalog, report) = fixture.open_with(base_config(), verifiers());
    let refused: BTreeSet<(RecordKind, u32, u32)> = report
        .refused
        .iter()
        .map(|refusal| (refusal.kind, refusal.found, refusal.supported))
        .collect();
    assert_eq!(
        refused,
        BTreeSet::from([
            (RecordKind::ObjectRecord, 2, 1),
            (RecordKind::Staging, 3, 2)
        ])
    );
    assert!(report.refused.iter().all(FormatRefusal::is_newer));
    assert_eq!(catalog.status(&a, object), ObjectStatus::Absent);
    // Never collected, and an import of the same key never removes or rewrites it.
    fixture.advance(GRACE * 3);
    let collected = catalog.collect_garbage().unwrap();
    assert!(collected.removed_unpublished.is_empty() && collected.removed_staging == 0);
    match catalog.begin_import(weights(&a, &staged_bytes), source.identity()) {
        Err(ImportRefusal::Storage { failure }) => {
            assert_eq!(failure.operation, StorageOperation::Format)
        }
        other => panic!("a newer staging declaration is refused: {other:?}"),
    }
    assert_eq!(file_digests(fixture.root(), ""), kept);
}

#[test]
fn a_newer_root_is_refused_and_blocks_collection() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let a = tenant("a");
    let bytes = data(98, 20);
    let object = import_bytes(&mut catalog, weights(&a, &bytes), &bytes);
    let id = catalog
        .set_root(
            &a,
            RootKind::LocalModel,
            RootName::new("model").unwrap(),
            BTreeSet::from([object]),
        )
        .unwrap();
    drop(catalog);
    set_format(&fixture.root().join("roots").join(format!("{id}.json")), 2);
    let (mut catalog, report) = fixture.open_with(base_config(), verifiers());
    assert_eq!(report.refused[0].kind, RecordKind::Root);
    fixture.advance(GRACE * 3);
    assert!(matches!(
        catalog.collect_garbage(),
        Err(GcRefusal::UnreadableRoots { .. })
    ));
    assert_eq!(catalog.status(&a, object), ObjectStatus::Published);
}

#[test]
fn a_newer_journal_is_refused_and_never_overwritten() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let a = tenant("a");
    let bytes = data(99, 24);
    let mut source = interrupt(&mut catalog, "journal", &bytes, 1);
    drop(catalog);
    let journal = staging_dir(&fixture, &source).join("journal");
    fs::write(&journal, b"journal 2 manifest 00\nextent 0\n").unwrap();
    let (mut catalog, _) = fixture.open_with(base_config(), verifiers());
    let ticket = started(
        catalog
            .begin_import(weights(&a, &bytes), source.identity())
            .unwrap(),
    );
    let (_, failure) = pending(
        catalog
            .drive_import(&ticket, &mut source, &mut Uninterrupted)
            .unwrap(),
    );
    match failure.reason {
        FailureReason::Storage { failure } => {
            assert_eq!(failure.operation, StorageOperation::Format)
        }
        other => panic!("a newer journal is refused: {other:?}"),
    }
    assert_eq!(
        fs::read(&journal).unwrap(),
        b"journal 2 manifest 00\nextent 0\n"
    );
}

#[test]
fn corrupt_records_are_reported_never_deleted() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let a = tenant("a");
    let bytes = data(100, 20);
    let object = import_bytes(&mut catalog, weights(&a, &bytes), &bytes);
    let inconsistent_bytes = data(101, 24);
    let inconsistent = interrupt(&mut catalog, "inconsistent", &inconsistent_bytes, 1);
    let garbled_bytes = data(102, 24);
    let garbled = interrupt(&mut catalog, "garbled", &garbled_bytes, 1);
    drop(catalog);
    // A layout 1 declaration whose key matches neither its fields nor its directory.
    let moved = rewrite_parent_keyed(&staging_dir(&fixture, &inconsistent), &execution("exe-1"));
    let mut record: serde_json::Value =
        serde_json::from_slice(&fs::read(moved.join("flight.json")).unwrap()).unwrap();
    record["flight"] = serde_json::to_value(digest("yougori/test/other/v1", &[b"x"])).unwrap();
    fs::write(
        moved.join("flight.json"),
        serde_json::to_vec_pretty(&record).unwrap(),
    )
    .unwrap();
    // A declaration that does not parse at all, and a corrupt publication record.
    fs::write(
        staging_dir(&fixture, &garbled).join("flight.json"),
        b"{ torn",
    )
    .unwrap();
    fs::write(fixture.record(object), b"{ torn").unwrap();
    fs::remove_file(fixture.root().join("format.json")).unwrap();
    let object_files = file_digests(fixture.root(), &format!("objects/{object}"));

    let (mut catalog, report) = fixture.open_with(base_config(), verifiers());
    assert_eq!(
        report.migration.unresumable,
        vec![Unresumable {
            staging: moved.file_name().unwrap().to_string_lossy().into_owned(),
            reason: UnresumableReason::Inconsistent,
        }]
    );
    assert!(moved.join("object").join("data").exists());
    assert!(staging_dir(&fixture, &garbled)
        .join("object")
        .join("data")
        .exists());
    assert_eq!(report.unreadable.len(), 1);
    fixture.advance(GRACE * 3);
    catalog.collect_garbage().unwrap();
    // The unreadable publication record and its object stay; the corrupt staging is
    // collected after the grace period, as before.
    assert!(fixture.record(object).exists());
    assert_eq!(
        file_digests(fixture.root(), &format!("objects/{object}")),
        object_files
    );
}

#[test]
fn a_leased_path_names_the_committed_data_and_is_refused_like_a_read() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let a = tenant("a");
    let bytes = data(9, 20);
    let object = import_bytes(&mut catalog, weights(&a, &bytes), &bytes);
    let reader = execution("exe-view");
    let lease = catalog.acquire_lease(&a, &reader, object, LEASE).unwrap();

    // The path is the committed, read-only data file, the one `open_read` reads.
    let path = catalog.leased_path(&a, &reader, lease).unwrap();
    assert_eq!(path, fixture.object_dir(object).join("data"));
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert!(fs::metadata(&path).unwrap().permissions().readonly());

    // Another reader's lease, an unknown lease and an ended lease are refused as a read is.
    assert_eq!(
        catalog.leased_path(&a, &execution("exe-other"), lease),
        Err(ReadRefusal::LeaseNotHeld)
    );
    assert_eq!(
        catalog.leased_path(&tenant("b"), &reader, lease),
        Err(ReadRefusal::LeaseNotHeld)
    );
    fixture.advance(LEASE * 2);
    assert_eq!(
        catalog.leased_path(&a, &reader, lease),
        Err(ReadRefusal::LeaseExpired)
    );
    let lease = catalog.acquire_lease(&a, &reader, object, LEASE).unwrap();
    assert!(catalog.leased_path(&a, &reader, lease).is_ok());
    catalog.release_lease(&a, &reader, lease).unwrap();
    // A released lease is forgotten, so it is unknown to a path as to a read.
    assert_eq!(
        catalog.leased_path(&a, &reader, lease),
        Err(ReadRefusal::UnknownLease)
    );
    assert!(matches!(
        catalog.open_read(&a, &reader, lease),
        Err(ReadRefusal::UnknownLease)
    ));

    // A data file that is not the index's length is refused before anyone mounts it.
    let lease = catalog.acquire_lease(&a, &reader, object, LEASE).unwrap();
    make_tree_writable(&path);
    fs::write(&path, &bytes[..10]).unwrap();
    assert!(matches!(
        catalog.leased_path(&a, &reader, lease),
        Err(ReadRefusal::Storage { .. })
    ));
}

// ---- One owner per root -------------------------------------------------------------------

/// What a holder's atomic writes in progress leave under the root: a temporary beside the
/// records and one in the root itself, the two places an open removes them from.
fn writes_in_progress(fixture: &Fixture) -> [PathBuf; 2] {
    let paths = [
        fixture.root().join("records").join("in-progress.tmp"),
        fixture.root().join("format.tmp"),
    ];
    for path in &paths {
        fs::write(path, b"being written").unwrap();
    }
    paths
}

#[test]
fn a_second_open_of_a_held_root_is_refused_and_removes_nothing() {
    let fixture = Fixture::new();
    let mut catalog = fixture.open();
    let a = tenant("a");
    let bytes = data(98, 20);
    let object = import_bytes(&mut catalog, weights(&a, &bytes), &bytes);
    let _interrupted = interrupt(&mut catalog, "held", &data(99, 24), 1);
    let in_progress = writes_in_progress(&fixture);
    let before = file_digests(fixture.root(), "");
    // The lock file is there, and others can read it while it is held.
    assert_eq!(
        before.get(LOCK_FILE),
        Some(&digest("yougori/test/file/v1", &[b""]))
    );

    let started = Instant::now();
    let refused = Catalog::open(
        fixture.root(),
        base_config(),
        verifiers(),
        fixture.clock.clone(),
    )
    .unwrap_err();
    assert_eq!(
        refused,
        OpenFailure::InUse {
            root: fixture.root().to_path_buf()
        }
    );
    // It waited for a holder that might be ending, then gave up.
    assert!(started.elapsed() >= super::lock::RELEASE_GRACE);
    let message = refused.to_string();
    assert!(
        message.contains(&fixture.root().display().to_string()) && message.contains(LOCK_FILE),
        "{message}"
    );
    // Nothing under the root was created, changed or removed, and the holder carries on.
    assert_eq!(file_digests(fixture.root(), ""), before);
    assert_eq!(catalog.status(&a, object), ObjectStatus::Published);

    // The lock goes with the catalog that held it. The root opens again, and only now are
    // the temporaries of the writes that never finished removed; the interrupted import's
    // staging is still there to resume from.
    drop(catalog);
    let (catalog, report) = fixture.open_with(base_config(), verifiers());
    assert_eq!(report.temporaries_removed, in_progress.len());
    assert!(in_progress.iter().all(|path| !path.exists()));
    assert_eq!(report.staging, 1);
    assert_eq!(catalog.status(&a, object), ObjectStatus::Published);
    assert!(matches!(
        Catalog::open(
            fixture.root(),
            base_config(),
            verifiers(),
            fixture.clock.clone()
        ),
        Err(OpenFailure::InUse { .. })
    ));
}

/// The root a child process of this test executable holds, and the start of each line it
/// prints ([`catalog_holder_child_process`]).
const HOLDER_ROOT: &str = "YOUGORI_TEST_CATALOG_HOLDER_ROOT";
const HOLDER_PREFIX: &str = "catalog-holder-child:";

/// This test executable again, running only [`catalog_holder_child_process`] on a root:
/// another process holding it. Killed when dropped, so a failing test leaves no process.
struct HoldingProcess(Child);

impl HoldingProcess {
    /// Starts the child on `root` and waits until it holds the root.
    fn start(root: &Path) -> Self {
        let child_test = module_path!()
            .split_once("::")
            .map(|(_, path)| format!("{path}::catalog_holder_child_process"))
            .unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                child_test.as_str(),
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(HOLDER_ROOT, root)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let holder = Self(child);
        let (send, lines) = mpsc::channel();
        // The child's lines, wherever the test harness's own output put them on a line.
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if let Some(at) = line.find(HOLDER_PREFIX) {
                    let _ = send.send(line[at..].to_owned());
                }
            }
        });
        let line = lines
            .recv_timeout(Duration::from_secs(120))
            .expect("the child process reports that it holds the root");
        assert_eq!(line, format!("{HOLDER_PREFIX} holding"));
        holder
    }

    /// Ends the child at once, without letting it close anything, as a crash would, and
    /// waits until it is gone.
    fn kill(&mut self) {
        self.0.kill().unwrap();
        self.0.wait().unwrap();
    }
}

impl Drop for HoldingProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The child half of [`a_root_another_process_holds_is_refused_and_opens_once_it_dies`]: a
/// no-op unless that test started this executable to run it.
#[test]
fn catalog_holder_child_process() {
    let Some(root) = std::env::var_os(HOLDER_ROOT) else {
        return;
    };
    let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(1)));
    let (_catalog, _) = Catalog::open(Path::new(&root), base_config(), verifiers(), clock).unwrap();
    println!("{HOLDER_PREFIX} holding");
    // The parent kills this process; the bound only keeps an orphan from waiting for ever.
    std::thread::sleep(Duration::from_secs(120));
}

#[test]
fn a_root_another_process_holds_is_refused_and_opens_once_it_dies() {
    let fixture = Fixture::new();
    drop(fixture.open());
    let mut holder = HoldingProcess::start(fixture.root());
    let in_progress = writes_in_progress(&fixture);
    let before = file_digests(fixture.root(), "");
    assert!(matches!(
        Catalog::open(
            fixture.root(),
            base_config(),
            verifiers(),
            fixture.clock.clone()
        ),
        Err(OpenFailure::InUse { .. })
    ));
    assert_eq!(file_digests(fixture.root(), ""), before);

    // The holder dies without closing anything. The system releases its lock: the root
    // opens again, with no stale lock to clear, and recovers what the holder left.
    holder.kill();
    let deadline = Instant::now() + Duration::from_secs(30);
    let report = loop {
        match Catalog::open(
            fixture.root(),
            base_config(),
            verifiers(),
            fixture.clock.clone(),
        ) {
            Ok((_, report)) => break report,
            // The system may take a moment to release a lock after its process has gone.
            Err(OpenFailure::InUse { .. }) if Instant::now() < deadline => {}
            Err(other) => panic!("the root did not open after its holder died: {other}"),
        }
    };
    assert_eq!(report.temporaries_removed, in_progress.len());
    assert!(in_progress.iter().all(|path| !path.exists()));
}
