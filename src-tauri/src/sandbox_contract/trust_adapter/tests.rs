//! The production registry, configured roots and the end-to-end path: metadata signed in
//! the test with `ring`'s Ed25519 key pairs (fixed seeds) and verified through the trust
//! client's own metadata verification, as its tests do with the fake scheme (VM-W45,
//! line 2668; VM-P23, line 2798). The fixture is shared with `tests_roots`.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU32;

use chrono::{DateTime, SecondsFormat, Utc};
use ring::signature::{Ed25519KeyPair, KeyPair};

use super::*;
use crate::foundation::catalog::ArtifactClass;
use crate::foundation::ids::ContentKey;
use crate::foundation::report::PublicUrl;
use crate::foundation::signing::{SharedTrustRoots, TrustRoots};
use crate::sandbox::trust::{
    AssuranceProfile, HexBytes, HmacSha256TestScheme, KeyId, MetadataFile, MetadataVersion,
    ProfileRequest, PublicKey, ReleaseVersion, RequestOrigin, ResolvedProfile, RevocationMetadata,
    Role, RoleKeys, RootMetadata, SchemeKind, SchemeRegistry, Signature, SignatureFailure,
    SignatureRejection, SnapshotMetadata, TargetEntry, TargetName, TargetsMetadata,
    TimestampMetadata, UnixSeconds, UpdateClient, UpdateRefusal, VerificationBasis,
};

pub(super) const NOW: UnixSeconds = UnixSeconds::new(1_700_000_000);
pub(super) const DAY: u64 = 86_400;
const KERNEL_BYTES: &[u8] = b"vmlinuz-6.6.52-yougori";

pub(super) fn location() -> PublicUrl {
    PublicUrl::new("https://yougori.com/releases/sandbox/trust").unwrap()
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

// Signing with real Ed25519 keys, made from fixed seeds.

pub(super) struct Signer {
    pub(super) pair: Ed25519KeyPair,
    pub(super) key: PublicKey,
}

impl Signer {
    pub(super) fn from_seed(seed: u8) -> Self {
        let pair = Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap();
        let key = PublicKey::new(SchemeKind::Ed25519, pair.public_key().as_ref().to_vec());
        Self { pair, key }
    }

    pub(super) fn key_id(&self) -> KeyId {
        self.key.key_id()
    }

    pub(super) fn signature(&self, file: &MetadataFile, role: Role) -> Signature {
        let message = file.message(role).unwrap();
        Signature {
            key_id: self.key_id(),
            signature: HexBytes::new(self.pair.sign(&message).as_ref().to_vec()),
        }
    }

    pub(super) fn sign(&self, file: &mut MetadataFile, role: Role) {
        let signature = self.signature(file, role);
        file.add_signature(signature);
    }
}

pub(super) struct Fixture {
    pub(super) roots: Vec<Signer>,
    timestamp: Signer,
    snapshot: Signer,
    targets: Signer,
    revocation: Signer,
    pub(super) expires: UnixSeconds,
}

impl Fixture {
    pub(super) fn new() -> Self {
        Self::with_root_seeds([1, 2, 3])
    }

    pub(super) fn with_root_seeds(seeds: [u8; 3]) -> Self {
        Self {
            roots: seeds.into_iter().map(Signer::from_seed).collect(),
            timestamp: Signer::from_seed(40),
            snapshot: Signer::from_seed(50),
            targets: Signer::from_seed(60),
            revocation: Signer::from_seed(70),
            expires: NOW.plus_seconds(7 * DAY),
        }
    }

    /// The three root signers' entries (`root-0` to `root-2`), usable now.
    pub(super) fn root_entries(&self) -> Vec<RootEntry> {
        self.roots
            .iter()
            .enumerate()
            .map(|(index, signer)| RootEntry::usable(&format!("root-{index}"), signer))
            .collect()
    }

    /// The three root signers as update roots with threshold 2, under production.
    pub(super) fn pinned(&self) -> PinnedRoots {
        pinned_roots(
            trust_roots(&self.root_entries()),
            2,
            ResolvedProfile::PRODUCTION,
        )
    }

    pub(super) fn root_metadata(&self, version: u64, expires: UnixSeconds) -> RootMetadata {
        let roots: Vec<&Signer> = self.roots.iter().collect();
        self.root_metadata_with(&roots, 2, version, expires)
    }

    /// A root whose root role is `roots` with `threshold`, beside the fixture's online
    /// keys.
    pub(super) fn root_metadata_with(
        &self,
        roots: &[&Signer],
        threshold: u32,
        version: u64,
        expires: UnixSeconds,
    ) -> RootMetadata {
        let mut keys = BTreeMap::new();
        for signer in roots.iter().copied().chain([
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
                RoleKeys::new(roots.iter().map(|signer| signer.key_id()), threshold),
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
            expires,
            keys,
            roles,
        }
    }

    /// The root at `version`, signed by the root signers at `signers` (indices).
    pub(super) fn root_signed_by(&self, version: u64, signers: &[usize]) -> MetadataFile {
        let mut file = MetadataFile::unsigned(&self.root_metadata(version, self.expires)).unwrap();
        for index in signers {
            self.roots[*index].sign(&mut file, Role::Root);
        }
        file
    }

    pub(super) fn root_file(&self, version: u64) -> MetadataFile {
        self.root_signed_by(version, &[0, 1, 2])
    }

    fn chain(&self, version: u64, bytes: &[u8], release: &str) -> Chain {
        let targets = TargetsMetadata {
            role: Role::Targets,
            version: MetadataVersion::new(version),
            expires: self.expires,
            targets: BTreeMap::from([(
                kernel_name(),
                TargetEntry {
                    class: ArtifactClass::GuestImage,
                    length_bytes: u64::try_from(bytes.len()).unwrap(),
                    content_key: ContentKey::of(bytes),
                    release: ReleaseVersion::new(release).unwrap(),
                },
            )]),
        };
        let mut targets = MetadataFile::unsigned(&targets).unwrap();
        self.targets.sign(&mut targets, Role::Targets);
        let snapshot = SnapshotMetadata {
            role: Role::Snapshot,
            version: MetadataVersion::new(version),
            expires: self.expires,
            targets: targets
                .file_reference(MetadataVersion::new(version))
                .unwrap(),
        };
        let mut snapshot = MetadataFile::unsigned(&snapshot).unwrap();
        self.snapshot.sign(&mut snapshot, Role::Snapshot);
        let timestamp = TimestampMetadata {
            role: Role::Timestamp,
            version: MetadataVersion::new(version),
            expires: self.expires,
            snapshot: snapshot
                .file_reference(MetadataVersion::new(version))
                .unwrap(),
        };
        let mut timestamp = MetadataFile::unsigned(&timestamp).unwrap();
        self.timestamp.sign(&mut timestamp, Role::Timestamp);
        Chain {
            timestamp,
            snapshot,
            targets,
        }
    }

    fn revocation_file(&self, version: u64, revoked: &[u8], reason: &str) -> MetadataFile {
        let metadata = RevocationMetadata {
            role: Role::Revocation,
            version: MetadataVersion::new(version),
            issued: NOW,
            revoked: BTreeMap::from([(ContentKey::of(revoked), reason.to_owned())]),
        };
        let mut file = MetadataFile::unsigned(&metadata).unwrap();
        self.revocation.sign(&mut file, Role::Revocation);
        file
    }

    fn client(&self) -> UpdateClient {
        self.pinned()
            .bootstrap(production_registry(), &self.root_file(1), NOW)
            .unwrap()
    }
}

struct Chain {
    timestamp: MetadataFile,
    snapshot: MetadataFile,
    targets: MetadataFile,
}

impl Chain {
    fn load(&self, client: &mut UpdateClient, now: UnixSeconds) -> Result<(), UpdateRefusal> {
        client.update_timestamp(&self.timestamp, now)?;
        client.update_snapshot(&self.snapshot, now)?;
        client.update_targets(&self.targets, now)
    }
}

fn kernel_name() -> TargetName {
    TargetName::new("guest-kernel").unwrap()
}

/// A root whose every key is of the HMAC test scheme, signed by its one root key.
fn test_scheme_root() -> (PublicKey, MetadataFile) {
    let key = |secret: &str| PublicKey::new(SchemeKind::HmacSha256Test, secret.as_bytes().to_vec());
    let keys: BTreeMap<KeyId, PublicKey> = ["root", "ts", "snap", "targets", "revoke"]
        .iter()
        .map(|secret| (key(secret).key_id(), key(secret)))
        .collect();
    let roles = BTreeMap::from([
        (Role::Root, RoleKeys::new([key("root").key_id()], 1)),
        (Role::Timestamp, RoleKeys::new([key("ts").key_id()], 1)),
        (Role::Snapshot, RoleKeys::new([key("snap").key_id()], 1)),
        (Role::Targets, RoleKeys::new([key("targets").key_id()], 1)),
        (Role::Revocation, RoleKeys::new([key("revoke").key_id()], 1)),
    ]);
    let metadata = RootMetadata {
        role: Role::Root,
        version: MetadataVersion::FIRST,
        expires: NOW.plus_seconds(DAY),
        keys,
        roles,
    };
    let mut file = MetadataFile::unsigned(&metadata).unwrap();
    let message = file.message(Role::Root).unwrap();
    file.add_signature(Signature {
        key_id: key("root").key_id(),
        signature: HexBytes::new(HmacSha256TestScheme::sign(b"root", &message)),
    });
    (key("root"), file)
}

// The end-to-end path with real signatures.

#[test]
fn ring_signed_metadata_verifies_end_to_end_through_the_trust_client() {
    let fixture = Fixture::new();
    let mut client = fixture.client();
    assert_eq!(client.profile(), AssuranceProfile::Production);
    fixture
        .chain(1, KERNEL_BYTES, "2026.10.1")
        .load(&mut client, NOW)
        .unwrap();
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
    let opened = verified.open(KERNEL_BYTES.to_vec()).unwrap();
    let admission = client.admit_launch(&opened, NOW.plus_seconds(60)).unwrap();
    assert_eq!(admission.content_key, ContentKey::of(KERNEL_BYTES));

    // A newer release, then a key rotation signed by the old and the new root keys.
    fixture
        .chain(2, b"vmlinuz-6.6.53-yougori", "2026.10.2")
        .load(&mut client, NOW)
        .unwrap();
    let rotated = Fixture::with_root_seeds([4, 5, 6]);
    let mut root_2 = MetadataFile::unsigned(&rotated.root_metadata(2, fixture.expires)).unwrap();
    for signer in fixture
        .roots
        .iter()
        .take(2)
        .chain(rotated.roots.iter().take(2))
    {
        signer.sign(&mut root_2, Role::Root);
    }
    let rotation = client.update_root(&root_2, NOW).unwrap();
    assert_eq!(rotation.to, MetadataVersion::new(2));

    // Emergency revocation signed with the revocation key applies offline.
    let revocation = fixture.revocation_file(1, KERNEL_BYTES, "CVE-2026-0001");
    let applied = client.update_revocation(&revocation).unwrap();
    assert_eq!(
        applied.newly_revoked,
        BTreeSet::from([ContentKey::of(KERNEL_BYTES)])
    );
    assert!(matches!(
        client.admit_launch(&opened, NOW),
        Err(UpdateRefusal::RevokedRelease { .. })
    ));
}

#[test]
fn tampered_or_wrongly_signed_metadata_is_refused_end_to_end() {
    let fixture = Fixture::new();
    let chain = fixture.chain(1, KERNEL_BYTES, "2026.10.1");
    let mut client = fixture.client();
    let invalid_timestamp = |failure: Result<(), UpdateRefusal>| {
        assert_eq!(
            failure,
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
    };

    // The payload altered after signing.
    let mut altered = chain.timestamp.signed().clone();
    altered["expires"] = serde_json::json!(9_999_999_999u64);
    let altered = MetadataFile::new(altered, chain.timestamp.signatures().to_vec());
    invalid_timestamp(client.update_timestamp(&altered, NOW));

    // One bit of the signature flipped, and the signature cut short.
    let original = chain.timestamp.signatures()[0].clone();
    let mut bytes = original.signature.as_bytes().to_vec();
    bytes[10] ^= 0x04;
    let flipped = Signature {
        key_id: original.key_id,
        signature: HexBytes::new(bytes.clone()),
    };
    invalid_timestamp(client.update_timestamp(
        &MetadataFile::new(chain.timestamp.signed().clone(), vec![flipped]),
        NOW,
    ));
    let short = Signature {
        key_id: original.key_id,
        signature: HexBytes::new(bytes[..63].to_vec()),
    };
    invalid_timestamp(client.update_timestamp(
        &MetadataFile::new(chain.timestamp.signed().clone(), vec![short]),
        NOW,
    ));

    // The timestamp key's signature made for another role does not count for this one.
    let other_role = fixture
        .timestamp
        .signature(&chain.timestamp, Role::Snapshot);
    invalid_timestamp(client.update_timestamp(
        &MetadataFile::new(chain.timestamp.signed().clone(), vec![other_role]),
        NOW,
    ));

    // Signed by another role's key: outside the role, so ignored.
    let mut wrong_key = MetadataFile::new(chain.timestamp.signed().clone(), Vec::new());
    fixture.targets.sign(&mut wrong_key, Role::Timestamp);
    assert!(matches!(
        client.update_timestamp(&wrong_key, NOW),
        Err(UpdateRefusal::Signatures {
            failure: SignatureFailure::ThresholdNotMet { ref unknown, .. }
        }) if unknown == &BTreeSet::from([fixture.targets.key_id()])
    ));

    // The genuine chain still loads afterwards.
    chain.load(&mut client, NOW).unwrap();
}

// Bootstrapping from the configured roots.

#[test]
fn bootstrap_needs_the_configured_threshold_of_configured_keys() {
    let fixture = Fixture::new();
    let pinned = fixture.pinned();

    // One configured key is below the threshold of two.
    let one = fixture.root_signed_by(1, &[0]);
    assert!(matches!(
        pinned.bootstrap(production_registry(), &one, NOW).map(|_| ()),
        Err(BootstrapRefusal::NotSignedByPinnedRoots {
            failure: SignatureFailure::ThresholdNotMet { required: 2, ref valid, .. }
        }) if valid == &BTreeSet::from([fixture.roots[0].key_id()])
    ));
    // Two of three are enough.
    assert!(pinned
        .bootstrap(
            production_registry(),
            &fixture.root_signed_by(1, &[0, 2]),
            NOW
        )
        .is_ok());

    // A self-consistent root signed only by keys that were not configured.
    let stranger = Fixture::with_root_seeds([11, 12, 13]);
    let foreign = stranger.root_file(1);
    let refused = pinned.bootstrap(production_registry(), &foreign, NOW);
    assert!(matches!(
        refused.map(|_| ()),
        Err(BootstrapRefusal::NotSignedByPinnedRoots {
            failure: SignatureFailure::ThresholdNotMet { ref valid, ref unknown, .. }
        }) if valid.is_empty() && unknown.len() == 3
    ));
    // The client itself would accept that root: the configured keys are what refuse it.
    assert!(UpdateClient::new(
        production_registry(),
        ResolvedProfile::PRODUCTION,
        &foreign,
        NOW
    )
    .is_ok());

    // Signed by the configured keys but expired: the client's own check refuses it.
    let mut expired =
        MetadataFile::unsigned(&fixture.root_metadata(1, NOW.plus_seconds(10))).unwrap();
    for signer in &fixture.roots {
        signer.sign(&mut expired, Role::Root);
    }
    assert!(matches!(
        pinned
            .bootstrap(production_registry(), &expired, NOW.plus_seconds(10))
            .map(|_| ()),
        Err(BootstrapRefusal::Client {
            reason: UpdateRefusal::Expired {
                role: Role::Root,
                ..
            }
        })
    ));
}

#[test]
fn a_production_bootstrap_refuses_a_registry_with_the_test_scheme() {
    let fixture = Fixture::new();
    let mut mixed = SchemeRegistry::new();
    mixed.register(Box::new(Ed25519Scheme)).unwrap();
    mixed.register(Box::new(HmacSha256TestScheme)).unwrap();
    let refused = fixture
        .pinned()
        .bootstrap(mixed, &fixture.root_file(1), NOW);
    assert_eq!(
        refused.map(|_| ()),
        Err(BootstrapRefusal::TestSchemeRegistered {
            scheme: SchemeKind::HmacSha256Test
        })
    );

    // The developer profile, granted by the host, may hold the test scheme beside it.
    let developer = pinned_roots(trust_roots(&fixture.root_entries()), 2, developer_profile());
    let mut mixed = SchemeRegistry::new();
    mixed.register(Box::new(Ed25519Scheme)).unwrap();
    mixed.register(Box::new(HmacSha256TestScheme)).unwrap();
    let client = developer
        .bootstrap(mixed, &fixture.root_file(1), NOW)
        .unwrap();
    assert_eq!(client.profile(), AssuranceProfile::Developer);
}

// The production registry.

#[test]
fn the_production_registry_holds_ed25519_only_and_refuses_the_test_scheme() {
    let registry = production_registry();
    assert!(registry.is_registered(SchemeKind::Ed25519));
    assert!(!registry.is_registered(SchemeKind::HmacSha256Test));
    assert_eq!(format!("{registry:?}"), "{Ed25519}");
    assert_eq!(check_production_registry(&registry), Ok(()));

    let (test_key, test_root) = test_scheme_root();
    let message = test_root.message(Role::Root).unwrap();
    assert_eq!(
        registry.verify(
            &test_key,
            &message,
            test_root.signatures()[0].signature.as_bytes()
        ),
        Err(SignatureRejection::SchemeUnavailable {
            scheme: SchemeKind::HmacSha256Test
        })
    );
    // A test-signed root cannot start a client on the production registry.
    assert!(matches!(
        UpdateClient::new(registry, ResolvedProfile::PRODUCTION, &test_root, NOW).map(|_| ()),
        Err(UpdateRefusal::Signatures {
            failure: SignatureFailure::SchemeUnavailable { .. }
        })
    ));

    let mut with_test = SchemeRegistry::new();
    with_test.register(Box::new(HmacSha256TestScheme)).unwrap();
    let refused = check_production_registry(&with_test);
    assert_eq!(
        refused,
        Err(TestSchemeRegistered {
            scheme: SchemeKind::HmacSha256Test
        })
    );
    assert!(refused
        .unwrap_err()
        .to_string()
        .contains("hmac-sha256-test"));
}

// Trust-root files and update roots, shared with `tests_roots`.

/// One key of the trust-root file.
pub(super) struct RootEntry {
    pub(super) id: String,
    pub(super) key: PublicKey,
    pub(super) classes: Vec<ArtifactClass>,
    pub(super) valid_from: UnixSeconds,
    pub(super) valid_until: UnixSeconds,
    pub(super) replaces: Option<String>,
    pub(super) revoked: bool,
}

impl RootEntry {
    /// A runtime-update key from a day before [`NOW`] to a year after.
    pub(super) fn usable(id: &str, signer: &Signer) -> Self {
        Self {
            id: id.to_owned(),
            key: signer.key.clone(),
            classes: vec![ArtifactClass::RuntimeUpdate],
            valid_from: UnixSeconds::new(NOW.get() - DAY),
            valid_until: NOW.plus_seconds(365 * DAY),
            replaces: None,
            revoked: false,
        }
    }
}

fn rfc3339(at: UnixSeconds) -> String {
    DateTime::<Utc>::from_timestamp(i64::try_from(at.get()).unwrap(), 0)
        .unwrap()
        .to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// The trust-root file for `entries`, in the foundation's format 1.
pub(super) fn trust_roots_json(entries: &[RootEntry]) -> String {
    let keys: Vec<serde_json::Value> = entries
        .iter()
        .map(|entry| {
            let mut key = serde_json::json!({
                "id": entry.id,
                "algorithm": "ed25519",
                "public_key": hex::encode(entry.key.material.as_bytes()),
                "classes": entry.classes,
                "valid_from": rfc3339(entry.valid_from),
                "valid_until": rfc3339(entry.valid_until),
            });
            if let Some(replaces) = &entry.replaces {
                key["replaces"] = serde_json::json!(replaces);
            }
            if entry.revoked {
                key["revoked"] = serde_json::json!({"reason": "key-compromise"});
            }
            key
        })
        .collect();
    serde_json::json!({"format": 1, "keys": keys}).to_string()
}

/// The trust-root file for `entries`, parsed and checked by the foundation.
pub(super) fn trust_roots(entries: &[RootEntry]) -> TrustRoots {
    TrustRoots::from_json(&trust_roots_json(entries)).unwrap()
}

pub(super) fn config(threshold: u32) -> UpdateTrustConfig {
    UpdateTrustConfig::new(NonZeroU32::new(threshold).unwrap(), location())
}

pub(super) fn pinned_roots(
    roots: TrustRoots,
    threshold: u32,
    profile: ResolvedProfile,
) -> PinnedRoots {
    PinnedRoots::new(SharedTrustRoots::new(roots), config(threshold), profile)
}
