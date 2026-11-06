//! Rule tests across the module (VM-W45–VM-W48, lines 2668–2671; VM-P23, line 2798;
//! VM-P37, line 2812). Each "never", "cannot" and "must" in those lines is tried and
//! shown refused. The update fixture here is shared with `tests_update`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::num::NonZeroU64;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tempfile::TempDir;

use super::*;
use crate::foundation::catalog::{
    ArtifactClass, ArtifactVerifier, Catalog, CatalogConfig, ContentDescriptor, ImportManifest,
    ImportRequest, ImportSource, ImportStart, ImportStatus, IntegrityFailure, ObjectBytes,
    ObjectId, ObjectMetadata, ObjectRole, PublisherId, ReadRefusal, Scope, SourceError,
    SourceIdentity, TrustRefusal, Uninterrupted, VerifierRegistry, VerifierRejection,
};
use crate::foundation::evidence::ArtifactVerification;
use crate::foundation::ids::{
    digest, ContentKey, ExecutionId, ManualClock, MonotonicTime, OperationId, TenantId,
};

pub(super) const NOW: UnixSeconds = UnixSeconds::new(1_700_000_000);
pub(super) const DAY: u64 = 86_400;

// Keys and signing.

/// A test double of the Ed25519 adapter: it declares [`SchemeKind::Ed25519`] and checks
/// HMAC-SHA256 inside, so the production profile can be exercised before the `ring`
/// adapter lands. Whoever can verify can forge, which is fine in a test.
pub(super) struct FakeEd25519;

impl SignatureScheme for FakeEd25519 {
    fn kind(&self) -> SchemeKind {
        SchemeKind::Ed25519
    }

    fn verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), SignatureRejection> {
        HmacSha256TestScheme.verify(public_key, message, signature)
    }
}

pub(super) fn schemes() -> SchemeRegistry {
    let mut registry = SchemeRegistry::new();
    registry.register(Box::new(FakeEd25519)).unwrap();
    registry.register(Box::new(HmacSha256TestScheme)).unwrap();
    registry
}

#[derive(Clone)]
pub(super) struct Signer {
    secret: Vec<u8>,
    pub(super) key: PublicKey,
}

impl Signer {
    pub(super) fn new(name: &str, scheme: SchemeKind) -> Self {
        let secret = format!("secret-of-{name}").into_bytes();
        Self {
            key: PublicKey::new(scheme, secret.clone()),
            secret,
        }
    }

    pub(super) fn key_id(&self) -> KeyId {
        self.key.key_id()
    }

    pub(super) fn sign(&self, file: &mut MetadataFile, role: Role) {
        let message = file.message(role).unwrap();
        file.add_signature(Signature {
            key_id: self.key_id(),
            signature: HexBytes::new(HmacSha256TestScheme::sign(&self.secret, &message)),
        });
    }
}

pub(super) struct Fixture {
    pub(super) roots: Vec<Signer>,
    pub(super) timestamp: Signer,
    pub(super) snapshot: Signer,
    pub(super) targets: Signer,
    pub(super) revocation: Signer,
    pub(super) expires: UnixSeconds,
}

pub(super) const KERNEL_BYTES: &[u8] = b"vmlinuz-6.6.52-yougori";

pub(super) fn kernel_name() -> TargetName {
    TargetName::new("guest-kernel").unwrap()
}

pub(super) fn kernel_entry(bytes: &[u8], release: &str) -> TargetEntry {
    TargetEntry {
        class: ArtifactClass::GuestImage,
        length_bytes: bytes.len() as u64,
        content_key: ContentKey::of(bytes),
        release: ReleaseVersion::new(release).unwrap(),
    }
}

pub(super) fn kernel_targets(bytes: &[u8], release: &str) -> BTreeMap<TargetName, TargetEntry> {
    BTreeMap::from([(kernel_name(), kernel_entry(bytes, release))])
}

impl Fixture {
    pub(super) fn new() -> Self {
        Self::with_scheme(SchemeKind::Ed25519)
    }

    pub(super) fn with_scheme(scheme: SchemeKind) -> Self {
        Self {
            roots: ["root-1", "root-2", "root-3"]
                .iter()
                .map(|name| Signer::new(name, scheme))
                .collect(),
            timestamp: Signer::new("timestamp", scheme),
            snapshot: Signer::new("snapshot", scheme),
            targets: Signer::new("targets", scheme),
            revocation: Signer::new("revocation", scheme),
            expires: NOW.plus_seconds(7 * DAY),
        }
    }

    pub(super) fn root_metadata(&self, version: u64) -> RootMetadata {
        let mut keys = BTreeMap::new();
        for signer in self.roots.iter().chain([
            &self.timestamp,
            &self.snapshot,
            &self.targets,
            &self.revocation,
        ]) {
            keys.insert(signer.key_id(), signer.key.clone());
        }
        let roles = BTreeMap::from([
            (
                Role::Root,
                RoleKeys::new(self.roots.iter().map(Signer::key_id), 2),
            ),
            (Role::Timestamp, RoleKeys::new([self.timestamp.key_id()], 1)),
            (Role::Snapshot, RoleKeys::new([self.snapshot.key_id()], 1)),
            (Role::Targets, RoleKeys::new([self.targets.key_id()], 1)),
            (
                Role::Revocation,
                RoleKeys::new([self.revocation.key_id()], 1),
            ),
        ]);
        RootMetadata {
            role: Role::Root,
            version: MetadataVersion::new(version),
            expires: self.expires,
            keys,
            roles,
        }
    }

    pub(super) fn root_file(&self, version: u64) -> MetadataFile {
        let mut file = MetadataFile::unsigned(&self.root_metadata(version)).unwrap();
        for signer in &self.roots {
            signer.sign(&mut file, Role::Root);
        }
        file
    }

    pub(super) fn targets_file(
        &self,
        version: u64,
        targets: BTreeMap<TargetName, TargetEntry>,
        expires: UnixSeconds,
    ) -> MetadataFile {
        let metadata = TargetsMetadata {
            role: Role::Targets,
            version: MetadataVersion::new(version),
            expires,
            targets,
        };
        let mut file = MetadataFile::unsigned(&metadata).unwrap();
        self.targets.sign(&mut file, Role::Targets);
        file
    }

    pub(super) fn snapshot_file(
        &self,
        version: u64,
        targets: &MetadataFile,
        targets_version: u64,
        expires: UnixSeconds,
    ) -> MetadataFile {
        let metadata = SnapshotMetadata {
            role: Role::Snapshot,
            version: MetadataVersion::new(version),
            expires,
            targets: targets
                .file_reference(MetadataVersion::new(targets_version))
                .unwrap(),
        };
        let mut file = MetadataFile::unsigned(&metadata).unwrap();
        self.snapshot.sign(&mut file, Role::Snapshot);
        file
    }

    pub(super) fn timestamp_file(
        &self,
        version: u64,
        snapshot: &MetadataFile,
        snapshot_version: u64,
        expires: UnixSeconds,
    ) -> MetadataFile {
        let metadata = TimestampMetadata {
            role: Role::Timestamp,
            version: MetadataVersion::new(version),
            expires,
            snapshot: snapshot
                .file_reference(MetadataVersion::new(snapshot_version))
                .unwrap(),
        };
        let mut file = MetadataFile::unsigned(&metadata).unwrap();
        self.timestamp.sign(&mut file, Role::Timestamp);
        file
    }

    /// A consistent timestamp, snapshot and targets set at `version`.
    pub(super) fn chain(&self, version: u64, bytes: &[u8], release: &str) -> Chain {
        self.chain_expiring(version, bytes, release, self.expires)
    }

    pub(super) fn chain_expiring(
        &self,
        version: u64,
        bytes: &[u8],
        release: &str,
        expires: UnixSeconds,
    ) -> Chain {
        let targets = self.targets_file(version, kernel_targets(bytes, release), expires);
        let snapshot = self.snapshot_file(version, &targets, version, expires);
        let timestamp = self.timestamp_file(version, &snapshot, version, expires);
        Chain {
            timestamp,
            snapshot,
            targets,
        }
    }

    pub(super) fn revocation_file(&self, version: u64, revoked: &[(&[u8], &str)]) -> MetadataFile {
        let metadata = RevocationMetadata {
            role: Role::Revocation,
            version: MetadataVersion::new(version),
            issued: NOW,
            revoked: revoked
                .iter()
                .map(|(bytes, reason)| (ContentKey::of(bytes), (*reason).to_owned()))
                .collect(),
        };
        let mut file = MetadataFile::unsigned(&metadata).unwrap();
        self.revocation.sign(&mut file, Role::Revocation);
        file
    }

    pub(super) fn client(&self) -> UpdateClient {
        UpdateClient::new(
            schemes(),
            ResolvedProfile::PRODUCTION,
            &self.root_file(1),
            NOW,
        )
        .unwrap()
    }

    /// A production client with the version-1 chain for the kernel loaded.
    pub(super) fn loaded(&self) -> UpdateClient {
        let mut client = self.client();
        self.chain(1, KERNEL_BYTES, "2026.10.1")
            .load(&mut client, NOW)
            .unwrap();
        client
    }
}

pub(super) struct Chain {
    pub(super) timestamp: MetadataFile,
    pub(super) snapshot: MetadataFile,
    pub(super) targets: MetadataFile,
}

impl Chain {
    pub(super) fn load(
        &self,
        client: &mut UpdateClient,
        now: UnixSeconds,
    ) -> Result<(), UpdateRefusal> {
        client.update_timestamp(&self.timestamp, now)?;
        client.update_snapshot(&self.snapshot, now)?;
        client.update_targets(&self.targets, now)
    }
}

fn tampered(file: &MetadataFile, field: &str, value: serde_json::Value) -> MetadataFile {
    let mut signed = file.signed().clone();
    signed[field] = value;
    MetadataFile::new(signed, file.signatures().to_vec())
}

pub(super) fn developer_profile() -> ResolvedProfile {
    ResolvedProfile::resolve(&ProfileRequest {
        profile: AssuranceProfile::Developer,
        origin: RequestOrigin::HostConfiguration {
            setting: "sandbox.assurance_profile".to_owned(),
        },
    })
    .unwrap()
}

// VM-W45: update trust.

#[test]
fn the_chain_verifies_and_only_the_verified_bytes_launch() {
    let fixture = Fixture::new();
    let client = fixture.loaded();
    assert_eq!(
        client.trusted_versions(),
        TrustedVersions {
            root: MetadataVersion::new(1),
            timestamp: Some(MetadataVersion::new(1)),
            snapshot: Some(MetadataVersion::new(1)),
            targets: Some(MetadataVersion::new(1)),
            revocation: None,
        }
    );
    let verified = client
        .verify_target(&kernel_name(), ArtifactClass::GuestImage, NOW)
        .unwrap();
    assert_eq!(verified.content_key(), ContentKey::of(KERNEL_BYTES));
    assert_eq!(verified.assurance(), AssuranceProfile::Production);
    assert_eq!(
        verified.basis(),
        &VerificationBasis::Signed {
            root_version: MetadataVersion::new(1),
            timestamp_version: MetadataVersion::new(1),
            snapshot_version: MetadataVersion::new(1),
            targets_version: MetadataVersion::new(1),
        }
    );
    assert!(verified.production_release().is_ok());

    // The bytes on disk were replaced between verification and launch.
    let replaced = b"vmlinuz-6.6.52-yougori".map(|byte| byte ^ 0x01).to_vec();
    assert_eq!(
        verified.open(replaced.clone()),
        Err(OpenRefusal::BytesDiffer {
            expected: ContentKey::of(KERNEL_BYTES),
            found: ContentKey::of(&replaced),
        })
    );
    let opened = verified.open(KERNEL_BYTES.to_vec()).unwrap();
    let admission = client.admit_launch(&opened, NOW.plus_seconds(60)).unwrap();
    assert_eq!(admission.content_key, ContentKey::of(KERNEL_BYTES));
    assert_eq!(admission.assurance, AssuranceProfile::Production);
    assert_eq!(admission.admitted_at, NOW.plus_seconds(60));

    // A class other than the declared one is refused, and an unknown name too.
    assert_eq!(
        client
            .verify_target(&kernel_name(), ArtifactClass::OciLayer, NOW)
            .map(|_| ()),
        Err(UpdateRefusal::ClassMismatch {
            name: kernel_name(),
            declared: ArtifactClass::GuestImage,
            expected: ArtifactClass::OciLayer,
        })
    );
    let other = TargetName::new("firmware").unwrap();
    assert_eq!(
        client
            .verify_target(&other, ArtifactClass::GuestImage, NOW)
            .map(|_| ()),
        Err(UpdateRefusal::UnknownTarget { name: other })
    );
}

#[test]
fn tampered_metadata_is_refused() {
    let fixture = Fixture::new();
    let chain = fixture.chain(1, KERNEL_BYTES, "2026.10.1");

    // A targets file altered after signing is not the file the snapshot references.
    let mut client = fixture.client();
    client.update_timestamp(&chain.timestamp, NOW).unwrap();
    client.update_snapshot(&chain.snapshot, NOW).unwrap();
    let mut targets = chain.targets.signed().clone();
    targets["targets"]["guest-kernel"]["content_key"] =
        serde_json::json!(ContentKey::of(b"evil").to_string());
    let altered = MetadataFile::new(targets, chain.targets.signatures().to_vec());
    assert!(matches!(
        client.update_targets(&altered, NOW),
        Err(UpdateRefusal::DoesNotMatchReference {
            role: Role::Targets,
            referenced_by: Role::Snapshot,
            ..
        })
    ));

    // The timestamp has no referencing role; its signatures fail instead.
    let altered_timestamp = tampered(
        &chain.timestamp,
        "expires",
        serde_json::json!(9_999_999_999u64),
    );
    let mut client = fixture.client();
    assert_eq!(
        client.update_timestamp(&altered_timestamp, NOW),
        Err(UpdateRefusal::Signatures {
            failure: SignatureFailure::ThresholdNotMet {
                role: Role::Timestamp,
                required: 1,
                valid: BTreeSet::new(),
                invalid: BTreeSet::from([fixture.timestamp.key_id()]),
                unknown: BTreeSet::new(),
            }
        })
    );

    // Signed by the wrong role's key: ignored, so the threshold is not met.
    let mut wrong_key = MetadataFile::new(chain.timestamp.signed().clone(), Vec::new());
    fixture.targets.sign(&mut wrong_key, Role::Timestamp);
    assert!(matches!(
        client.update_timestamp(&wrong_key, NOW),
        Err(UpdateRefusal::Signatures {
            failure: SignatureFailure::ThresholdNotMet { ref unknown, .. }
        }) if unknown == &BTreeSet::from([fixture.targets.key_id()])
    ));

    // A root whose keys were altered after signing is refused at bootstrap.
    let root = fixture.root_file(1);
    let altered_root = tampered(&root, "expires", serde_json::json!(9_999_999_999u64));
    assert!(matches!(
        UpdateClient::new(schemes(), ResolvedProfile::PRODUCTION, &altered_root, NOW).map(|_| ()),
        Err(UpdateRefusal::Signatures { .. })
    ));
    // The client itself never signed anything and holds no key.
    assert!(client.trusted_versions().timestamp.is_none());
}

#[test]
fn replayed_metadata_is_refused() {
    let fixture = Fixture::new();
    let mut client = fixture.loaded();
    let chain = fixture.chain(1, KERNEL_BYTES, "2026.10.1");
    assert_eq!(
        client.update_timestamp(&chain.timestamp, NOW),
        Err(UpdateRefusal::Replayed {
            role: Role::Timestamp,
            version: MetadataVersion::new(1)
        })
    );
    assert_eq!(
        client.update_root(&fixture.root_file(1), NOW).map(|_| ()),
        Err(UpdateRefusal::Replayed {
            role: Role::Root,
            version: MetadataVersion::new(1)
        })
    );
    let revocation = fixture.revocation_file(1, &[(b"old", "superseded")]);
    client.update_revocation(&revocation).unwrap();
    assert_eq!(
        client.update_revocation(&revocation).map(|_| ()),
        Err(UpdateRefusal::Replayed {
            role: Role::Revocation,
            version: MetadataVersion::new(1)
        })
    );
}

#[test]
fn expired_metadata_is_refused_when_fetched_and_when_used_offline() {
    let fixture = Fixture::new();
    let soon = NOW.plus_seconds(600);
    let chain = fixture.chain_expiring(1, KERNEL_BYTES, "2026.10.1", soon);

    // Already expired when offered: a frozen mirror.
    let mut client = fixture.client();
    assert_eq!(
        client.update_timestamp(&chain.timestamp, soon),
        Err(UpdateRefusal::Expired {
            role: Role::Timestamp,
            expires: soon,
            now: soon,
        })
    );

    // Fresh when fetched, then the device goes offline past the expiry.
    let mut client = fixture.client();
    chain.load(&mut client, NOW).unwrap();
    let verified = client
        .verify_target(&kernel_name(), ArtifactClass::GuestImage, NOW)
        .unwrap();
    let opened = verified.open(KERNEL_BYTES.to_vec()).unwrap();
    assert!(client
        .admit_launch(&opened, soon.plus_seconds(0).plus_seconds(0))
        .is_err());
    assert_eq!(
        client
            .verify_target(&kernel_name(), ArtifactClass::GuestImage, soon)
            .map(|_| ()),
        Err(UpdateRefusal::Expired {
            role: Role::Timestamp,
            expires: soon,
            now: soon,
        })
    );
    assert_eq!(
        client.admit_launch(&opened, soon).map(|_| ()),
        Err(UpdateRefusal::Expired {
            role: Role::Timestamp,
            expires: soon,
            now: soon,
        })
    );
    // One second before expiry it still verifies.
    assert!(client
        .verify_target(
            &kernel_name(),
            ArtifactClass::GuestImage,
            NOW.plus_seconds(599)
        )
        .is_ok());

    // An expired root refuses bootstrap and later verification alike.
    let expired_root = UpdateClient::new(
        schemes(),
        ResolvedProfile::PRODUCTION,
        &fixture.root_file(1),
        fixture.expires,
    );
    assert_eq!(
        expired_root.map(|_| ()),
        Err(UpdateRefusal::Expired {
            role: Role::Root,
            expires: fixture.expires,
            now: fixture.expires,
        })
    );
    let far = fixture.chain_expiring(1, KERNEL_BYTES, "2026.10.1", NOW.plus_seconds(365 * DAY));
    let mut client = fixture.client();
    far.load(&mut client, NOW).unwrap();
    assert_eq!(
        client
            .verify_target(&kernel_name(), ArtifactClass::GuestImage, fixture.expires)
            .map(|_| ()),
        Err(UpdateRefusal::Expired {
            role: Role::Root,
            expires: fixture.expires,
            now: fixture.expires,
        })
    );
}

#[test]
fn rolled_back_metadata_is_refused() {
    let fixture = Fixture::new();
    let mut client = fixture.loaded();
    let v2 = fixture.chain(2, b"vmlinuz-6.6.53", "2026.10.2");
    v2.load(&mut client, NOW).unwrap();
    let v1 = fixture.chain(1, KERNEL_BYTES, "2026.10.1");

    assert_eq!(
        client.update_timestamp(&v1.timestamp, NOW),
        Err(UpdateRefusal::RolledBack {
            role: Role::Timestamp,
            trusted: MetadataVersion::new(2),
            offered: MetadataVersion::new(1),
        })
    );
    // A newer timestamp that points back at the older snapshot.
    let back = fixture.timestamp_file(3, &v1.snapshot, 1, fixture.expires);
    assert_eq!(
        client.update_timestamp(&back, NOW),
        Err(UpdateRefusal::RolledBack {
            role: Role::Snapshot,
            trusted: MetadataVersion::new(2),
            offered: MetadataVersion::new(1),
        })
    );
    // A newer snapshot that binds older targets.
    let old_targets_snapshot = fixture.snapshot_file(3, &v1.targets, 1, fixture.expires);
    let timestamp = fixture.timestamp_file(3, &old_targets_snapshot, 3, fixture.expires);
    client.update_timestamp(&timestamp, NOW).unwrap();
    assert_eq!(
        client.update_snapshot(&old_targets_snapshot, NOW),
        Err(UpdateRefusal::RolledBack {
            role: Role::Targets,
            trusted: MetadataVersion::new(2),
            offered: MetadataVersion::new(1),
        })
    );
    // The trusted set is unchanged by refusals; the targets kept are version 2.
    assert_eq!(
        client.trusted_versions().targets,
        Some(MetadataVersion::new(2))
    );
    assert_eq!(
        client.update_root(&fixture.root_file(0), NOW).map(|_| ()),
        Err(UpdateRefusal::Metadata {
            error: MetadataError::ZeroVersion { role: Role::Root }
        })
    );
    let mut rotated = fixture.loaded();
    rotated.update_root(&fixture.root_file(2), NOW).unwrap();
    assert_eq!(
        rotated.update_root(&fixture.root_file(1), NOW).map(|_| ()),
        Err(UpdateRefusal::RolledBack {
            role: Role::Root,
            trusted: MetadataVersion::new(2),
            offered: MetadataVersion::new(1),
        })
    );
}

#[test]
fn mixed_version_metadata_is_refused() {
    let fixture = Fixture::new();
    let v1 = fixture.chain(1, KERNEL_BYTES, "2026.10.1");
    let v2 = fixture.chain(2, b"vmlinuz-6.6.53", "2026.10.2");

    // Timestamp 2 with snapshot 1: the snapshot is not the one referenced.
    let mut client = fixture.client();
    client.update_timestamp(&v2.timestamp, NOW).unwrap();
    assert_eq!(
        client.update_snapshot(&v1.snapshot, NOW),
        Err(UpdateRefusal::DoesNotMatchReference {
            role: Role::Snapshot,
            referenced_by: Role::Timestamp,
            expected: v2.snapshot.file_reference(MetadataVersion::new(2)).unwrap(),
            found: v1.snapshot.file_reference(MetadataVersion::new(1)).unwrap(),
        })
    );
    // Snapshot 2 with targets 1.
    client.update_snapshot(&v2.snapshot, NOW).unwrap();
    assert_eq!(
        client.update_targets(&v1.targets, NOW),
        Err(UpdateRefusal::DoesNotMatchReference {
            role: Role::Targets,
            referenced_by: Role::Snapshot,
            expected: v2.targets.file_reference(MetadataVersion::new(2)).unwrap(),
            found: v1.targets.file_reference(MetadataVersion::new(1)).unwrap(),
        })
    );
    // Nothing verifies until the matching targets arrive.
    assert_eq!(
        client
            .verify_target(&kernel_name(), ArtifactClass::GuestImage, NOW)
            .map(|_| ()),
        Err(UpdateRefusal::MissingPrerequisite {
            needed: Role::Targets
        })
    );
    client.update_targets(&v2.targets, NOW).unwrap();
    assert_eq!(
        client
            .verify_target(&kernel_name(), ArtifactClass::GuestImage, NOW)
            .unwrap()
            .content_key(),
        ContentKey::of(b"vmlinuz-6.6.53")
    );
    // Snapshot before timestamp, targets before snapshot: refused in order.
    let mut client = fixture.client();
    assert_eq!(
        client.update_snapshot(&v1.snapshot, NOW),
        Err(UpdateRefusal::MissingPrerequisite {
            needed: Role::Timestamp
        })
    );
    assert_eq!(
        client.update_targets(&v1.targets, NOW),
        Err(UpdateRefusal::MissingPrerequisite {
            needed: Role::Snapshot
        })
    );
}

#[test]
fn key_rotation_needs_both_thresholds_one_version_at_a_time() {
    let old = Fixture::new();
    let mut client = old.loaded();

    // New root keys; the online keys stay.
    let mut new = Fixture::new();
    new.roots = ["root-4", "root-5", "root-6"]
        .iter()
        .map(|name| Signer::new(name, SchemeKind::Ed25519))
        .collect();
    let unsigned = MetadataFile::unsigned(&new.root_metadata(2)).unwrap();

    // One old key and three new keys: the old threshold is not met.
    let mut few_old = unsigned.clone();
    old.roots[0].sign(&mut few_old, Role::Root);
    for signer in &new.roots {
        signer.sign(&mut few_old, Role::Root);
    }
    assert!(matches!(
        client.update_root(&few_old, NOW),
        Err(UpdateRefusal::Signatures {
            failure: SignatureFailure::ThresholdNotMet { role: Role::Root, required: 2, ref valid, .. }
        }) if valid.len() == 1
    ));
    // Two old keys and one new key: the new threshold is not met.
    let mut few_new = unsigned.clone();
    old.roots[0].sign(&mut few_new, Role::Root);
    old.roots[1].sign(&mut few_new, Role::Root);
    new.roots[0].sign(&mut few_new, Role::Root);
    assert!(matches!(
        client.update_root(&few_new, NOW),
        Err(UpdateRefusal::Signatures {
            failure: SignatureFailure::ThresholdNotMet { role: Role::Root, required: 2, ref valid, .. }
        }) if valid.len() == 1
    ));
    // Two of each: rotated, and the online metadata stays because its keys did not change.
    let mut both = unsigned;
    old.roots[1].sign(&mut both, Role::Root);
    old.roots[2].sign(&mut both, Role::Root);
    new.roots[1].sign(&mut both, Role::Root);
    new.roots[2].sign(&mut both, Role::Root);
    assert_eq!(
        client.update_root(&both, NOW).unwrap(),
        RootRotation {
            from: MetadataVersion::new(1),
            to: MetadataVersion::new(2),
            cleared: BTreeSet::new(),
        }
    );
    assert_eq!(client.root().version, MetadataVersion::new(2));
    assert!(client
        .verify_target(&kernel_name(), ArtifactClass::GuestImage, NOW)
        .is_ok());
    // The old keys alone no longer rotate anything.
    let mut old_only = MetadataFile::unsigned(&new.root_metadata(3)).unwrap();
    for signer in &old.roots {
        signer.sign(&mut old_only, Role::Root);
    }
    assert!(matches!(
        client.update_root(&old_only, NOW),
        Err(UpdateRefusal::Signatures { .. })
    ));
    // Skipping a version is refused.
    let mut gap = MetadataFile::unsigned(&new.root_metadata(4)).unwrap();
    for signer in &new.roots {
        signer.sign(&mut gap, Role::Root);
    }
    assert_eq!(
        client.update_root(&gap, NOW).map(|_| ()),
        Err(UpdateRefusal::VersionGap {
            role: Role::Root,
            trusted: MetadataVersion::new(2),
            offered: MetadataVersion::new(4),
        })
    );

    // Rotating an online key drops the metadata it signed; it must be fetched again.
    let mut rotated_online = new.clone_with_timestamp("timestamp-2");
    let mut file = MetadataFile::unsigned(&rotated_online.root_metadata(3)).unwrap();
    for signer in &new.roots {
        signer.sign(&mut file, Role::Root);
    }
    assert_eq!(
        client.update_root(&file, NOW).unwrap(),
        RootRotation {
            from: MetadataVersion::new(2),
            to: MetadataVersion::new(3),
            cleared: BTreeSet::from([Role::Timestamp, Role::Snapshot, Role::Targets]),
        }
    );
    assert_eq!(
        client
            .verify_target(&kernel_name(), ArtifactClass::GuestImage, NOW)
            .map(|_| ()),
        Err(UpdateRefusal::MissingPrerequisite {
            needed: Role::Timestamp
        })
    );
    // The old timestamp key signs nothing the new root accepts.
    let stale = old.chain(2, KERNEL_BYTES, "2026.10.1");
    assert!(matches!(
        client.update_timestamp(&stale.timestamp, NOW),
        Err(UpdateRefusal::Signatures { .. })
    ));
    rotated_online.expires = new.expires;
    let fresh = rotated_online.chain(2, KERNEL_BYTES, "2026.10.1");
    fresh.load(&mut client, NOW).unwrap();
    assert!(client
        .verify_target(&kernel_name(), ArtifactClass::GuestImage, NOW)
        .is_ok());
}

impl Fixture {
    pub(super) fn clone_with_timestamp(&self, name: &str) -> Fixture {
        Fixture {
            roots: self.roots.clone(),
            timestamp: Signer::new(name, SchemeKind::Ed25519),
            snapshot: self.snapshot.clone(),
            targets: self.targets.clone(),
            revocation: self.revocation.clone(),
            expires: self.expires,
        }
    }
}

#[test]
fn a_revoked_release_is_refused_at_verification_and_at_launch_and_stays_revoked() {
    let fixture = Fixture::new();
    let mut client = fixture.loaded();
    let verified = client
        .verify_target(&kernel_name(), ArtifactClass::GuestImage, NOW)
        .unwrap();
    let opened = verified.open(KERNEL_BYTES.to_vec()).unwrap();
    assert!(client.admit_launch(&opened, NOW).is_ok());

    // Emergency revocation arrives; the timestamp has meanwhile expired, which does
    // not matter to a revocation.
    let later = fixture.expires.plus_seconds(DAY);
    let applied = client
        .update_revocation(
            &fixture.revocation_file(1, &[(KERNEL_BYTES, "signing key compromised")]),
        )
        .unwrap();
    assert_eq!(
        applied,
        RevocationApplied {
            version: MetadataVersion::new(1),
            newly_revoked: BTreeSet::from([ContentKey::of(KERNEL_BYTES)]),
            total_revoked: 1,
        }
    );
    let revoked = UpdateRefusal::RevokedRelease {
        content_key: ContentKey::of(KERNEL_BYTES),
        reason: "signing key compromised".to_owned(),
    };
    assert_eq!(
        client
            .verify_target(&kernel_name(), ArtifactClass::GuestImage, NOW)
            .map(|_| ()),
        Err(revoked.clone())
    );
    // The already opened artifact is caught at the execution boundary too, before any
    // expiry check.
    assert_eq!(
        client.admit_launch(&opened, NOW).map(|_| ()),
        Err(revoked.clone())
    );
    assert_eq!(
        client.admit_launch(&opened, later).map(|_| ()),
        Err(revoked.clone())
    );

    // A later list that omits the release does not restore it.
    let applied = client
        .update_revocation(&fixture.revocation_file(2, &[(b"other", "unrelated")]))
        .unwrap();
    assert_eq!(applied.total_revoked, 2);
    assert_eq!(
        client.admit_launch(&opened, NOW).map(|_| ()),
        Err(revoked.clone())
    );
    assert_eq!(client.revoked().len(), 2);
    // An older list is refused.
    assert_eq!(
        client
            .update_revocation(&fixture.revocation_file(1, &[]))
            .map(|_| ()),
        Err(UpdateRefusal::RolledBack {
            role: Role::Revocation,
            trusted: MetadataVersion::new(2),
            offered: MetadataVersion::new(1),
        })
    );
    // A list signed by an online key is not a revocation.
    let mut forged = MetadataFile::new(
        fixture
            .revocation_file(3, &[(b"x", "forged")])
            .signed()
            .clone(),
        Vec::new(),
    );
    fixture.targets.sign(&mut forged, Role::Revocation);
    assert!(matches!(
        client.update_revocation(&forged),
        Err(UpdateRefusal::Signatures { .. })
    ));
    // A new release with other bytes verifies, since revocation is by content key.
    let v2 = fixture.chain(2, b"vmlinuz-6.6.53", "2026.10.2");
    v2.load(&mut client, NOW).unwrap();
    assert!(client
        .verify_target(&kernel_name(), ArtifactClass::GuestImage, NOW)
        .is_ok());
    // The handle verified before the release changed cannot launch the old bytes.
    assert_eq!(client.admit_launch(&opened, NOW).map(|_| ()), Err(revoked));
}

#[test]
fn a_superseded_target_cannot_launch_from_an_old_handle() {
    let fixture = Fixture::new();
    let mut client = fixture.loaded();
    let opened = client
        .verify_target(&kernel_name(), ArtifactClass::GuestImage, NOW)
        .unwrap()
        .open(KERNEL_BYTES.to_vec())
        .unwrap();
    fixture
        .chain(2, b"vmlinuz-6.6.53", "2026.10.2")
        .load(&mut client, NOW)
        .unwrap();
    assert_eq!(
        client.admit_launch(&opened, NOW).map(|_| ()),
        Err(UpdateRefusal::Superseded {
            name: kernel_name(),
            verified: ContentKey::of(KERNEL_BYTES),
            current: ContentKey::of(b"vmlinuz-6.6.53"),
        })
    );
}

#[test]
fn developer_mode_stays_outside_the_production_profile() {
    // Test-scheme keys cannot bootstrap a production client.
    let test_keys = Fixture::with_scheme(SchemeKind::HmacSha256Test);
    let refused = UpdateClient::new(
        schemes(),
        ResolvedProfile::PRODUCTION,
        &test_keys.root_file(1),
        NOW,
    );
    assert!(matches!(
        refused.map(|_| ()),
        Err(UpdateRefusal::NonProductionScheme {
            scheme: SchemeKind::HmacSha256Test,
            ..
        })
    ));
    // Nor rotate into one.
    let mut production = Fixture::new().loaded();
    let mut downgrade = MetadataFile::unsigned(&test_keys.root_metadata(2)).unwrap();
    for signer in Fixture::new().roots.iter().chain(test_keys.roots.iter()) {
        signer.sign(&mut downgrade, Role::Root);
    }
    assert!(matches!(
        production.update_root(&downgrade, NOW),
        Err(UpdateRefusal::NonProductionScheme { .. })
    ));

    // The developer profile accepts them, and what it verifies is marked as such.
    let mut developer =
        UpdateClient::new(schemes(), developer_profile(), &test_keys.root_file(1), NOW).unwrap();
    assert_eq!(developer.profile(), AssuranceProfile::Developer);
    test_keys
        .chain(1, KERNEL_BYTES, "2026.10.1")
        .load(&mut developer, NOW)
        .unwrap();
    let verified = developer
        .verify_target(&kernel_name(), ArtifactClass::GuestImage, NOW)
        .unwrap();
    assert_eq!(verified.assurance(), AssuranceProfile::Developer);
    assert_eq!(
        verified.production_release().map(|_| ()),
        Err(AssuranceRefusal::NotProduction {
            assurance: AssuranceProfile::Developer
        })
    );
    let opened = verified.open(KERNEL_BYTES.to_vec()).unwrap();
    assert!(developer.admit_launch(&opened, NOW).is_ok());
    // A production client refuses to launch it.
    assert_eq!(
        production.admit_launch(&opened, NOW).map(|_| ()),
        Err(UpdateRefusal::NotProduction {
            name: kernel_name(),
            assurance: AssuranceProfile::Developer,
        })
    );

    // An unsigned developer build: only with a host-granted developer profile, and
    // never through an environment-like or guest input.
    for origin in [
        RequestOrigin::InheritedEnvironment {
            variable: "YOUGORI_UNSIGNED_DEV".to_owned(),
        },
        RequestOrigin::GuestInput {
            channel: "sandbox-template".to_owned(),
        },
    ] {
        let request = ProfileRequest {
            profile: AssuranceProfile::Developer,
            origin,
        };
        assert!(ResolvedProfile::resolve(&request).is_err());
    }
    let unsigned = VerifiedTarget::developer_unsigned(
        developer_profile(),
        TargetName::new("local-kernel").unwrap(),
        ArtifactClass::GuestImage,
        ContentKey::of(b"local"),
        5,
        ReleaseVersion::new("dev").unwrap(),
        NOW,
    )
    .unwrap();
    let opened = unsigned.open(b"local".to_vec()).unwrap();
    assert_eq!(
        production.admit_launch(&opened, NOW).map(|_| ()),
        Err(UpdateRefusal::NotProduction {
            name: TargetName::new("local-kernel").unwrap(),
            assurance: AssuranceProfile::Developer,
        })
    );
    let admitted = developer.admit_launch(&opened, NOW).unwrap();
    assert_eq!(admitted.assurance, AssuranceProfile::Developer);
    // A revocation still reaches an unsigned developer build.
    developer
        .update_revocation(&test_keys.revocation_file(1, &[(b"local", "known bad")]))
        .unwrap();
    assert!(matches!(
        developer.admit_launch(&opened, NOW),
        Err(UpdateRefusal::RevokedRelease { .. })
    ));
}

#[test]
fn the_calendar_clock_drives_expiry() {
    let fixture = Fixture::new();
    let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(1_000)));
    let trust_clock = TrustClock::new(
        clock.clone(),
        CalendarAnchor {
            monotonic: MonotonicTime::from_nanos(1_000),
            unix_seconds: NOW,
        },
    )
    .unwrap();
    let mut client = fixture.client();
    fixture
        .chain_expiring(1, KERNEL_BYTES, "2026.10.1", NOW.plus_seconds(100))
        .load(&mut client, trust_clock.now())
        .unwrap();
    clock.advance(Duration::from_secs(99));
    assert!(client
        .verify_target(&kernel_name(), ArtifactClass::GuestImage, trust_clock.now())
        .is_ok());
    clock.advance(Duration::from_secs(1));
    assert!(matches!(
        client.verify_target(&kernel_name(), ArtifactClass::GuestImage, trust_clock.now()),
        Err(UpdateRefusal::Expired {
            role: Role::Timestamp,
            ..
        })
    ));
}

// VM-W48 with the real catalog: the catalog's trust policy decides.

const TEST_ATTESTATION_DOMAIN: &str = "yougori/sandbox/trust/test-attestation/v1";

fn attestation_bytes(
    publisher: &PublisherId,
    class: ArtifactClass,
    content: ContentKey,
) -> Vec<u8> {
    digest(
        TEST_ATTESTATION_DOMAIN,
        &[
            publisher.digest().as_bytes(),
            class.tag().as_bytes(),
            content.digest().as_bytes(),
        ],
    )
    .as_bytes()
    .to_vec()
}

struct TestVerifier {
    class: ArtifactClass,
}

impl ArtifactVerifier for TestVerifier {
    fn class(&self) -> ArtifactClass {
        self.class
    }

    fn authenticate(
        &self,
        content: &ContentDescriptor,
        publisher: &PublisherId,
        attestation: &[u8],
    ) -> Result<(), VerifierRejection> {
        if attestation == attestation_bytes(publisher, content.class, content.content_key) {
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

struct MemorySource {
    identity: SourceIdentity,
    bytes: Vec<u8>,
}

impl ImportSource for MemorySource {
    fn identity(&self) -> SourceIdentity {
        self.identity
    }

    fn length_bytes(&mut self) -> Result<u64, SourceError> {
        Ok(self.bytes.len() as u64)
    }

    fn read_at(&mut self, offset_bytes: u64, buffer: &mut [u8]) -> Result<usize, SourceError> {
        let available = self.bytes.get(offset_bytes as usize..).unwrap_or(&[]);
        let count = available.len().min(buffer.len());
        buffer[..count].copy_from_slice(&available[..count]);
        Ok(count)
    }
}

struct CatalogFixture {
    dir: TempDir,
    clock: Arc<ManualClock>,
    publisher: Signer,
}

impl CatalogFixture {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
            clock: Arc::new(ManualClock::new(MonotonicTime::from_nanos(1_000_000_000))),
            publisher: Signer::new("kernel-publisher", SchemeKind::Ed25519),
        }
    }

    fn publisher_id(&self) -> PublisherId {
        self.publisher.key.publisher_id()
    }

    fn config(&self, kernel_policy: TrustPolicy) -> CatalogConfig {
        CatalogConfig::new(Duration::from_secs(60))
            .with_quota(tenant("a"), 1 << 20)
            .with_quota(tenant("b"), 1 << 20)
            .with_quota(Scope::Host, 1 << 20)
            .with_trust(ArtifactClass::GuestImage, kernel_policy)
            .with_trust(
                ArtifactClass::OciLayer,
                TrustPolicy::new().trust_publisher(self.publisher_id()),
            )
    }

    fn verifiers(classes: &[ArtifactClass]) -> VerifierRegistry {
        let mut registry = VerifierRegistry::new();
        for class in classes {
            registry
                .register(Box::new(TestVerifier { class: *class }))
                .unwrap();
        }
        registry
    }

    fn open(&self, config: CatalogConfig, verifiers: VerifierRegistry) -> Catalog {
        Catalog::open(self.dir.path(), config, verifiers, self.clock.clone())
            .unwrap()
            .0
    }

    fn import(
        &self,
        catalog: &mut Catalog,
        scope: &Scope,
        record: &ProvenanceRecord,
        bytes: &[u8],
    ) -> ObjectId {
        let manifest = ImportManifest::describe(bytes, NonZeroU64::new(64).unwrap());
        let request = ImportRequest {
            operation: OperationId::new("op-import").unwrap(),
            execution: execution("exe-import"),
            scope: scope.clone(),
            class: record.class().artifact_class(),
            role: ObjectRole::Original,
            manifest,
            trust: record.trust_claim(),
            depends_on: BTreeSet::new(),
            metadata: ObjectMetadata::new(),
        };
        let mut source = MemorySource {
            identity: SourceIdentity::describe("test", "kernel"),
            bytes: bytes.to_vec(),
        };
        let ticket = match catalog.begin_import(request, source.identity()).unwrap() {
            ImportStart::Started(ticket) | ImportStart::Attached(ticket) => ticket,
            ImportStart::AlreadyPublished(object) => return object,
        };
        match catalog
            .drive_import(&ticket, &mut source, &mut Uninterrupted)
            .unwrap()
        {
            ImportStatus::Published { object, .. } => object,
            other => panic!("expected publication, got {other:?}"),
        }
    }
}

impl Drop for CatalogFixture {
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

fn tenant(name: &str) -> Scope {
    Scope::tenant(TenantId::new(name).unwrap())
}

fn execution(name: &str) -> ExecutionId {
    ExecutionId::new(name).unwrap()
}

fn kernel_record(publisher: PublisherId, bytes: &[u8]) -> ProvenanceRecord {
    let content = ContentKey::of(bytes);
    ProvenanceRecord {
        provenance: Provenance::Kernel(KernelProvenance {
            version: ComponentVersion::new("6.6.52").unwrap(),
            build: BuildInputs {
                source: crate::foundation::report::CommitHash::new("b".repeat(40)).unwrap(),
                toolchain: digest("yougori/test/toolchain/v1", &[b"rust"]),
                configuration: digest("yougori/test/config/v1", &[b"defconfig"]),
                builder: digest("yougori/test/builder/v1", &[b"image"]),
            },
            content,
        }),
        attestation: Attestation {
            publisher,
            attestation: HexBytes::new(attestation_bytes(
                &publisher,
                ArtifactClass::GuestImage,
                content,
            )),
        },
    }
}

#[test]
fn the_catalogs_trust_policy_decides_and_a_withdrawn_verifier_withdraws_trust() {
    let fixture = CatalogFixture::new();
    let publisher = fixture.publisher_id();
    let a = tenant("a");
    let record = kernel_record(publisher, KERNEL_BYTES);
    let trusted = TrustPolicy::new().trust_publisher(publisher);
    let all = [ArtifactClass::GuestImage, ArtifactClass::OciLayer];

    // Trusted for OCI layers only: the kernel class policy refuses before the catalog
    // is consulted.
    let mut catalog = fixture.open(
        fixture.config(TrustPolicy::new()),
        CatalogFixture::verifiers(&all),
    );
    assert_eq!(
        identify(&catalog, &a, &record).map(|_| ()),
        Err(ProvenanceRefusal::PublisherNotTrusted {
            class: ArtifactClass::GuestImage,
            publisher,
        })
    );
    // Trusted for kernels, but not in the catalog yet.
    catalog.set_trust_policy(ArtifactClass::GuestImage, trusted.clone());
    let object = ObjectId::new(&a, ArtifactClass::GuestImage, ContentKey::of(KERNEL_BYTES));
    assert_eq!(
        identify(&catalog, &a, &record).map(|_| ()),
        Err(ProvenanceRefusal::NotInCatalog { object })
    );
    // Imported under the catalog's own verifier and policy: identified.
    assert_eq!(
        fixture.import(&mut catalog, &a, &record, KERNEL_BYTES),
        object
    );
    let identity = identify(&catalog, &a, &record).unwrap();
    assert_eq!(identity.object(), object);
    assert_eq!(identity.class(), ProvenanceClass::Kernel);
    assert_eq!(identity.publisher(), publisher);
    assert_eq!(identity.scope(), &a);

    // Identity is not permission: execution needs a permission for this exact object,
    // for a scope the catalog lets read it.
    let permission = ExecutionPermission {
        scope: a.clone(),
        execution: execution("exe-run"),
        object,
    };
    let admission = admit_execution(&catalog, &identity, &permission).unwrap();
    assert_eq!(
        admission.verification,
        ArtifactVerification::Verified {
            artifacts: BTreeSet::from([object.digest()])
        }
    );
    let other_object = ObjectId::new(&a, ArtifactClass::GuestImage, ContentKey::of(b"other"));
    assert_eq!(
        admit_execution(
            &catalog,
            &identity,
            &ExecutionPermission {
                object: other_object,
                ..permission.clone()
            }
        )
        .map(|_| ()),
        Err(ProvenanceRefusal::PermissionForAnotherObject {
            permitted: other_object,
            identified: object,
        })
    );
    assert_eq!(
        admit_execution(
            &catalog,
            &identity,
            &ExecutionPermission {
                scope: tenant("b"),
                ..permission.clone()
            }
        )
        .map(|_| ()),
        Err(ProvenanceRefusal::CatalogRefused {
            refusal: ReadRefusal::NotGranted { object }
        })
    );

    // The publisher is withdrawn from the kernel policy: the catalog quarantines the
    // object, and this module refuses with the catalog's reason.
    let revision = catalog.set_trust_policy(ArtifactClass::GuestImage, TrustPolicy::new());
    assert_eq!(revision.quarantined, vec![object]);
    let withdrawn = IntegrityFailure::TrustWithdrawn {
        refusal: TrustRefusal::PublisherNotTrusted {
            class: ArtifactClass::GuestImage,
            publisher,
        },
    };
    assert_eq!(
        identify(&catalog, &a, &record).map(|_| ()),
        Err(ProvenanceRefusal::PublisherNotTrusted {
            class: ArtifactClass::GuestImage,
            publisher,
        })
    );
    assert_eq!(
        admit_execution(&catalog, &identity, &permission).map(|_| ()),
        Err(ProvenanceRefusal::CatalogRefused {
            refusal: ReadRefusal::Quarantined { object }
        })
    );
    // Trusted again, served again.
    catalog.set_trust_policy(ArtifactClass::GuestImage, trusted.clone());
    assert!(identify(&catalog, &a, &record).is_ok());
    assert_eq!(
        catalog.status(&a, object),
        crate::foundation::catalog::ObjectStatus::Published
    );
    drop(catalog);

    // Reopened without the kernel class verifier: the policy still trusts the
    // publisher, but a class without a verifier loses trust in the catalog, so here too.
    let catalog = fixture.open(
        fixture.config(trusted),
        CatalogFixture::verifiers(&[ArtifactClass::OciLayer]),
    );
    assert_eq!(
        identify(&catalog, &a, &record).map(|_| ()),
        Err(ProvenanceRefusal::Quarantined {
            object,
            reason: IntegrityFailure::TrustWithdrawn {
                refusal: TrustRefusal::NoVerifier {
                    class: ArtifactClass::GuestImage
                }
            }
        })
    );
    assert_ne!(
        withdrawn,
        IntegrityFailure::TrustWithdrawn {
            refusal: TrustRefusal::NoVerifier {
                class: ArtifactClass::GuestImage
            }
        }
    );
    assert_eq!(
        admit_execution(&catalog, &identity, &permission).map(|_| ()),
        Err(ProvenanceRefusal::CatalogRefused {
            refusal: ReadRefusal::Quarantined { object }
        })
    );
}

#[test]
fn a_wrong_attestation_never_enters_the_catalog() {
    let fixture = CatalogFixture::new();
    let publisher = fixture.publisher_id();
    let a = tenant("a");
    let mut catalog = fixture.open(
        fixture.config(TrustPolicy::new().trust_publisher(publisher)),
        CatalogFixture::verifiers(&[ArtifactClass::GuestImage]),
    );
    let mut record = kernel_record(publisher, KERNEL_BYTES);
    record.attestation.attestation = HexBytes::new(vec![0; 32]);
    // The publisher is trusted, so the pre-import gate passes; the catalog's verifier
    // then rejects the attestation and nothing is published.
    assert_eq!(admit_publisher(&catalog.config().trust, &record), Ok(()));
    let manifest = ImportManifest::describe(KERNEL_BYTES, NonZeroU64::new(64).unwrap());
    let request = ImportRequest {
        operation: OperationId::new("op-import").unwrap(),
        execution: execution("exe-import"),
        scope: a.clone(),
        class: ArtifactClass::GuestImage,
        role: ObjectRole::Original,
        manifest,
        trust: record.trust_claim(),
        depends_on: BTreeSet::new(),
        metadata: ObjectMetadata::new(),
    };
    let source = SourceIdentity::describe("test", "kernel");
    assert!(matches!(
        catalog.begin_import(request, source),
        Err(crate::foundation::catalog::ImportRefusal::Trust {
            refusal: TrustRefusal::AttestationRejected { .. }
        })
    ));
    assert_eq!(
        identify(&catalog, &a, &record).map(|_| ()),
        Err(ProvenanceRefusal::NotInCatalog {
            object: ObjectId::new(&a, ArtifactClass::GuestImage, ContentKey::of(KERNEL_BYTES))
        })
    );
}

#[test]
fn a_mutable_tag_or_redirect_is_refused_before_the_catalog_is_asked() {
    let fixture = CatalogFixture::new();
    let publisher = fixture.publisher_id();
    let catalog = fixture.open(
        fixture.config(TrustPolicy::new()),
        CatalogFixture::verifiers(&[ArtifactClass::OciLayer]),
    );
    let layer = ContentKey::of(b"layer");
    let mut record = ProvenanceRecord {
        provenance: Provenance::Oci(OciProvenance {
            registry: RegistryHost::new("registry.example").unwrap(),
            repository: RepositoryPath::new("library/debian").unwrap(),
            reference: OciReference::Tag {
                tag: "bookworm".to_owned(),
            },
            served_by: RegistryHost::new("registry.example").unwrap(),
            layer,
        }),
        attestation: Attestation {
            publisher,
            attestation: HexBytes::new(attestation_bytes(
                &publisher,
                ArtifactClass::OciLayer,
                layer,
            )),
        },
    };
    assert_eq!(
        identify(&catalog, &tenant("a"), &record).map(|_| ()),
        Err(ProvenanceRefusal::MutableTag {
            tag: "bookworm".to_owned()
        })
    );
    if let Provenance::Oci(oci) = &mut record.provenance {
        oci.reference = OciReference::Digest {
            manifest: digest("yougori/test/manifest/v1", &[b"m"]),
        };
        oci.served_by = RegistryHost::new("mirror.example").unwrap();
    }
    assert_eq!(
        identify(&catalog, &tenant("a"), &record).map(|_| ()),
        Err(ProvenanceRefusal::RegistryRedirect {
            pinned: RegistryHost::new("registry.example").unwrap(),
            served_by: RegistryHost::new("mirror.example").unwrap(),
        })
    );
}

// VM-W46 and VM-W47 together: the matrix row the gate judges is the pinned one.

#[test]
fn findings_are_judged_against_the_pinned_row_and_the_update_handle_names_it() {
    let configuration = super::pinned::tests::row(super::pinned::tests::linux_firecracker());
    let mut matrix = ConfigurationMatrix::new();
    matrix.pin(configuration.clone()).unwrap();
    let governance = Governance::new(super::vulnerability::tests::policy()).unwrap();
    let finding = super::vulnerability::tests::finding(
        "CVE-2026-0100",
        Severity::Critical,
        Remediation::NoFix,
    );
    let row = matrix.lookup(&configuration.key).unwrap();
    assert!(governance.assess(&finding, row, NOW).blocks());

    // The pinned kernel's content key is what the update metadata must name; a release
    // naming other bytes is a different configuration.
    let pinned_kernel = row.component(ComponentKind::GuestKernel).unwrap();
    let fixture = Fixture::new();
    let mut client = fixture.client();
    fixture
        .chain(1, b"kernel", "2026.10.1")
        .load(&mut client, NOW)
        .unwrap();
    let verified = client
        .verify_target(&kernel_name(), ArtifactClass::GuestImage, NOW)
        .unwrap();
    assert_eq!(verified.content_key(), pinned_kernel.content_key);
    assert_eq!(verified.length_bytes(), pinned_kernel.length_bytes);
    let fingerprint = row.fingerprint().unwrap();
    let mut other = configuration.clone();
    other.components.insert(
        ComponentKind::GuestKernel,
        super::pinned::tests::pin(ComponentKind::GuestKernel, "6.6.53", b"kernel-2"),
    );
    assert_ne!(other.fingerprint().unwrap(), fingerprint);
}
