//! Runtime updates through the trust client against a real catalog service: a target the
//! client verified through Ed25519-signed metadata is admitted as the update root key's;
//! other bytes, a developer's unsigned build, a guest image target, forged and reused
//! tickets, wrongly signed metadata, a revoked release, a revoked or unlisted root key
//! and an object corrupted after publication are refused (VM-W48, line 2671; VM-W45,
//! line 2668).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use ring::signature::KeyPair;

use super::tests::{
    assert_absent, calendar, execution, keys, keys_revoking, now, operation, pair, publisher,
    raw_import, trust_refusal, Fixture, Opened, OCI, ROGUE, UPDATE_ROOT,
};
use super::*;
use crate::foundation::catalog::{
    ArtifactClass, ContentDescriptor, ImportManifest, IntegrityFailure, ObjectStatus, ReadError,
    ReadRefusal, Scope, TrustBasis, TrustClaim, TrustRefusal, Uninterrupted, VerifyError,
};
use crate::foundation::ids::{digest, ContentKey};
use crate::foundation::report::CommitHash;
use crate::sandbox::trust::{
    admit_execution, identify, AssuranceProfile, Attestation, BuildInputs, ComponentVersion,
    ExecutionPermission, HexBytes, MetadataFile, MetadataVersion, OpenRefusal, OpenedArtifact,
    ProfileRequest, Provenance, ProvenanceRecord, ProvenanceRefusal, PublicKey, ReleaseVersion,
    RequestOrigin, ResolvedProfile, RevocationMetadata, Role, RoleKeys, RootMetadata, SchemeKind,
    Signature, SnapshotMetadata, TargetEntry, TargetName, TargetsMetadata, TimestampMetadata,
    ToolName, ToolProvenance, UnixSeconds, UpdateClient, UpdateRefusal, VerifiedTarget,
};
use crate::sandbox_contract::trust_adapter::production_registry;

pub(super) const RUNTIME: &[u8] = b"m18f sandbox runtime 2026.10.1";
const GUEST_KERNEL: &[u8] = b"m18f guest kernel from the update metadata";
pub(super) const RUNTIME_TARGET: &str = "sandbox-runtime";
pub(super) const KERNEL_TARGET: &str = "guest-kernel";

const TIMESTAMP: u8 = 41;
const SNAPSHOT: u8 = 42;
const TARGETS: u8 = 43;
const REVOCATION: u8 = 44;

/// The trust client's key for `seed`'s Ed25519 key pair.
fn client_key(seed: u8) -> PublicKey {
    PublicKey::new(
        SchemeKind::Ed25519,
        pair(seed).public_key().as_ref().to_vec(),
    )
}

fn sign(file: &mut MetadataFile, role: Role, seed: u8) {
    let message = file.message(role).unwrap();
    file.add_signature(Signature {
        key_id: client_key(seed).key_id(),
        signature: HexBytes::new(pair(seed).sign(&message).as_ref().to_vec()),
    });
}

fn entry(class: ArtifactClass, bytes: &[u8]) -> TargetEntry {
    TargetEntry {
        class,
        length_bytes: bytes.len() as u64,
        content_key: ContentKey::of(bytes),
        release: ReleaseVersion::new("2026.10.1").unwrap(),
    }
}

/// Release metadata as the update repository publishes it, signed by its role keys, with
/// `root` as the one update root key.
pub(super) struct UpdateRepository {
    root: u8,
    expires: UnixSeconds,
}

impl UpdateRepository {
    pub(super) fn new() -> Self {
        Self::rooted_in(UPDATE_ROOT)
    }

    pub(super) fn rooted_in(root: u8) -> Self {
        Self {
            root,
            expires: now().plus_seconds(7 * 86_400),
        }
    }

    fn root_file(&self) -> MetadataFile {
        let keys = [self.root, TIMESTAMP, SNAPSHOT, TARGETS, REVOCATION]
            .into_iter()
            .map(|seed| (client_key(seed).key_id(), client_key(seed)))
            .collect();
        let role = |seed: u8| RoleKeys::new([client_key(seed).key_id()], 1);
        let root = RootMetadata {
            role: Role::Root,
            version: MetadataVersion::new(1),
            expires: self.expires,
            keys,
            roles: BTreeMap::from([
                (Role::Root, role(self.root)),
                (Role::Timestamp, role(TIMESTAMP)),
                (Role::Snapshot, role(SNAPSHOT)),
                (Role::Targets, role(TARGETS)),
                (Role::Revocation, role(REVOCATION)),
            ]),
        };
        let mut file = MetadataFile::unsigned(&root).unwrap();
        sign(&mut file, Role::Root, self.root);
        file
    }

    /// Timestamp, snapshot and targets at version 1, the targets signed by `signer`.
    fn chain(&self, signer: u8) -> [MetadataFile; 3] {
        let targets = TargetsMetadata {
            role: Role::Targets,
            version: MetadataVersion::new(1),
            expires: self.expires,
            targets: BTreeMap::from([
                (
                    TargetName::new(RUNTIME_TARGET).unwrap(),
                    entry(ArtifactClass::RuntimeUpdate, RUNTIME),
                ),
                (
                    TargetName::new(KERNEL_TARGET).unwrap(),
                    entry(ArtifactClass::GuestImage, GUEST_KERNEL),
                ),
            ]),
        };
        let mut targets = MetadataFile::unsigned(&targets).unwrap();
        sign(&mut targets, Role::Targets, signer);
        let snapshot = SnapshotMetadata {
            role: Role::Snapshot,
            version: MetadataVersion::new(1),
            expires: self.expires,
            targets: targets.file_reference(MetadataVersion::new(1)).unwrap(),
        };
        let mut snapshot = MetadataFile::unsigned(&snapshot).unwrap();
        sign(&mut snapshot, Role::Snapshot, SNAPSHOT);
        let timestamp = TimestampMetadata {
            role: Role::Timestamp,
            version: MetadataVersion::new(1),
            expires: self.expires,
            snapshot: snapshot.file_reference(MetadataVersion::new(1)).unwrap(),
        };
        let mut timestamp = MetadataFile::unsigned(&timestamp).unwrap();
        sign(&mut timestamp, Role::Timestamp, TIMESTAMP);
        [timestamp, snapshot, targets]
    }

    /// A production client over the Ed25519 registry with the targets signed by
    /// `signer` offered to it.
    fn client_loading(&self, signer: u8) -> (UpdateClient, Result<(), UpdateRefusal>) {
        let mut client = UpdateClient::new(
            production_registry(),
            ResolvedProfile::PRODUCTION,
            &self.root_file(),
            now(),
        )
        .unwrap();
        let [timestamp, snapshot, targets] = self.chain(signer);
        client.update_timestamp(&timestamp, now()).unwrap();
        client.update_snapshot(&snapshot, now()).unwrap();
        let loaded = client.update_targets(&targets, now());
        (client, loaded)
    }

    /// A production client with the release metadata loaded.
    pub(super) fn client(&self) -> UpdateClient {
        let (client, loaded) = self.client_loading(TARGETS);
        loaded.unwrap();
        client
    }

    /// The target `name` as the client verifies and opens it.
    pub(super) fn opened(&self, client: &UpdateClient, name: &str) -> OpenedArtifact {
        let (class, bytes) = match name {
            KERNEL_TARGET => (ArtifactClass::GuestImage, GUEST_KERNEL),
            _ => (ArtifactClass::RuntimeUpdate, RUNTIME),
        };
        client
            .verify_target(&TargetName::new(name).unwrap(), class, now())
            .unwrap()
            .open(bytes.to_vec())
            .unwrap()
    }
}

/// An import of `opened` now.
pub(super) fn import_of(opened: &OpenedArtifact) -> UpdateImport<'_> {
    UpdateImport {
        operation: operation(),
        execution: execution("update-importer"),
        opened,
        now: now(),
    }
}

fn import(
    opened: &Opened,
    client: &UpdateClient,
    artifact: &OpenedArtifact,
) -> Result<ImportedUpdate, UpdateImportError> {
    opened.classes.updates().import(
        &mut opened.service.catalog(),
        client,
        import_of(artifact),
        &mut Uninterrupted,
    )
}

/// The runtime's typed tool provenance (tools map onto runtime updates).
fn runtime_record() -> ProvenanceRecord {
    ProvenanceRecord {
        provenance: Provenance::Tool(ToolProvenance {
            name: ToolName::new(RUNTIME_TARGET).unwrap(),
            version: ComponentVersion::new("2026.10.1").unwrap(),
            build: BuildInputs {
                source: CommitHash::new("0123456789abcdef0123456789abcdef01234567").unwrap(),
                toolchain: digest("yougori/test/m18f/toolchain/v1", &[b"go"]),
                configuration: digest("yougori/test/m18f/configuration/v1", &[b"release"]),
                builder: digest("yougori/test/m18f/builder/v1", &[b"ci"]),
            },
            content: ContentKey::of(RUNTIME),
        }),
        attestation: Attestation {
            publisher: publisher(UPDATE_ROOT),
            attestation: HexBytes::new(Vec::new()),
        },
    }
}

/// Ticket bytes naming `number`, as anyone can write them; only a ticket the admission
/// issued names a waiting target.
fn forged_ticket(number: u64) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "format": UPDATE_TICKET_FORMAT,
        "ticket": number,
    }))
    .unwrap()
}

fn ticket_claim(seed: u8, attestation: Vec<u8>) -> TrustClaim {
    TrustClaim::Publisher {
        publisher: publisher(seed),
        attestation,
    }
}

fn descriptor(class: ArtifactClass, bytes: &[u8]) -> ContentDescriptor {
    let manifest = ImportManifest::describe(bytes, UPDATE_EXTENT_BYTES);
    ContentDescriptor {
        scope: Scope::Host,
        class,
        content_key: manifest.content_key,
        length_bytes: manifest.true_length_bytes,
        manifest_digest: manifest.digest(),
    }
}

#[test]
fn a_target_verified_through_the_update_metadata_is_admitted() {
    let fixture = Fixture::new();
    let mut trust = fixture.trust(Some(keys()));
    let opened = fixture.open(&mut trust);
    let repository = UpdateRepository::new();
    let client = repository.client();
    let runtime = repository.opened(&client, RUNTIME_TARGET);

    let imported = import(&opened, &client, &runtime).unwrap();
    assert_eq!(imported.publisher, publisher(UPDATE_ROOT));
    assert_eq!(imported.name.as_str(), RUNTIME_TARGET);
    assert_eq!(imported.release.as_str(), "2026.10.1");
    assert!(!imported.cache_hit);
    assert_eq!(opened.classes.updates().pending(), 0);

    let reader = execution("sandbox-1");
    {
        let mut catalog = opened.service.catalog();
        assert_eq!(
            catalog.status(&Scope::Host, imported.object),
            ObjectStatus::Published
        );
        let metadata = catalog
            .private_metadata(&Scope::Host, imported.object)
            .unwrap();
        assert_eq!(metadata.class, ArtifactClass::RuntimeUpdate);
        assert_eq!(
            metadata.trust,
            TrustBasis::Publisher {
                publisher: publisher(UPDATE_ROOT)
            }
        );
        assert_eq!(
            metadata
                .metadata
                .labels
                .get(UPDATE_TARGET_LABEL)
                .map(String::as_str),
            Some(RUNTIME_TARGET)
        );
        let lease = catalog
            .acquire_lease(
                &Scope::Host,
                &reader,
                imported.object,
                Duration::from_secs(60),
            )
            .unwrap();
        assert_eq!(
            catalog
                .open_read(&Scope::Host, &reader, lease)
                .unwrap()
                .read_all()
                .unwrap(),
            RUNTIME
        );
        let identity = identify(&catalog, &Scope::Host, &runtime_record()).unwrap();
        assert_eq!(identity.object(), imported.object);
        let permission = ExecutionPermission {
            scope: Scope::Host,
            execution: reader,
            object: imported.object,
        };
        assert!(admit_execution(&catalog, &identity, &permission).is_ok());
    }
    // Imported again, the host scope holds it already; the claim was checked again.
    let again = import(&opened, &client, &runtime).unwrap();
    assert!(again.cache_hit);
    assert_eq!(again.object, imported.object);
    assert_eq!(opened.classes.updates().pending(), 0);
}

#[test]
fn only_a_metadata_verified_target_with_its_own_bytes_is_admitted() {
    let fixture = Fixture::new();
    let mut trust = fixture.trust(Some(keys()));
    let opened = fixture.open(&mut trust);
    let repository = UpdateRepository::new();
    let client = repository.client();
    let target = client
        .verify_target(
            &TargetName::new(RUNTIME_TARGET).unwrap(),
            ArtifactClass::RuntimeUpdate,
            now(),
        )
        .unwrap();

    // Other bytes never become the verified artifact.
    let other = b"m18f sandbox runtime 2026.10.X".to_vec();
    assert!(matches!(
        target.open(other.clone()),
        Err(OpenRefusal::BytesDiffer { .. })
    ));

    // A developer's unsigned build of the same bytes is no release artifact.
    let developer = ResolvedProfile::resolve(&ProfileRequest {
        profile: AssuranceProfile::Developer,
        origin: RequestOrigin::OperatorCommand,
    })
    .unwrap();
    let unsigned = VerifiedTarget::developer_unsigned(
        developer,
        TargetName::new(RUNTIME_TARGET).unwrap(),
        ArtifactClass::RuntimeUpdate,
        ContentKey::of(RUNTIME),
        RUNTIME.len() as u64,
        ReleaseVersion::new("dev").unwrap(),
        now(),
    )
    .unwrap()
    .open(RUNTIME.to_vec())
    .unwrap();
    assert_eq!(
        import(&opened, &client, &unsigned),
        Err(UpdateImportError::NotThroughMetadata {
            name: TargetName::new(RUNTIME_TARGET).unwrap()
        })
    );

    let mut catalog = opened.service.catalog();
    // A ticket nobody issued.
    assert!(matches!(
        trust_refusal(raw_import(
            &mut catalog,
            &Scope::Host,
            ArtifactClass::RuntimeUpdate,
            RUNTIME,
            ticket_claim(UPDATE_ROOT, forged_ticket(999))
        )),
        TrustRefusal::AttestationRejected { .. }
    ));
    // A genuine ticket presented with other bytes is refused and used up, so it cannot be
    // presented again with the right ones.
    let desk = opened.classes.updates();
    let ticket = desk
        .offer(target.clone(), publisher(UPDATE_ROOT))
        .unwrap()
        .attestation();
    assert_eq!(desk.pending(), 1);
    assert!(matches!(
        trust_refusal(raw_import(
            &mut catalog,
            &Scope::Host,
            ArtifactClass::RuntimeUpdate,
            &other,
            ticket_claim(UPDATE_ROOT, ticket.clone())
        )),
        TrustRefusal::AttestationRejected { .. }
    ));
    assert_eq!(desk.pending(), 0);
    assert!(matches!(
        trust_refusal(raw_import(
            &mut catalog,
            &Scope::Host,
            ArtifactClass::RuntimeUpdate,
            RUNTIME,
            ticket_claim(UPDATE_ROOT, ticket)
        )),
        TrustRefusal::AttestationRejected { .. }
    ));
    assert_absent(
        &mut catalog,
        &Scope::Host,
        ArtifactClass::RuntimeUpdate,
        RUNTIME,
    );
    assert_absent(
        &mut catalog,
        &Scope::Host,
        ArtifactClass::RuntimeUpdate,
        &other,
    );
    drop(catalog);

    // The verifier's typed reasons, on a desk of its own.
    let admissions = Arc::new(UpdateAdmissions::new());
    let verifier =
        RuntimeUpdateVerifier::new(Arc::clone(&admissions), trust.shared().unwrap(), calendar());
    let runtime = descriptor(ArtifactClass::RuntimeUpdate, RUNTIME);
    let issue = |publisher_seed: u8| {
        admissions
            .offer(target.clone(), publisher(publisher_seed))
            .unwrap()
            .attestation()
    };
    assert_eq!(
        verifier.check(
            &descriptor(ArtifactClass::GuestImage, RUNTIME),
            &publisher(UPDATE_ROOT),
            &forged_ticket(12_345)
        ),
        Err(UpdateAttestationRefusal::WrongClass {
            class: ArtifactClass::GuestImage
        })
    );
    assert_eq!(
        verifier.check(&runtime, &publisher(OCI), &issue(UPDATE_ROOT)),
        Err(UpdateAttestationRefusal::OtherPublisher)
    );
    assert!(matches!(
        verifier.check(&runtime, &publisher(OCI), &issue(OCI)),
        Err(UpdateAttestationRefusal::Key { .. })
    ));
    assert!(matches!(
        verifier.check(
            &runtime,
            &publisher(UPDATE_ROOT),
            b"{\"format\":\"x\",\"ticket\":1}"
        ),
        Err(UpdateAttestationRefusal::Malformed { .. })
    ));
    assert!(matches!(
        verifier.check(
            &runtime,
            &publisher(UPDATE_ROOT),
            &[b' '; MAX_UPDATE_TICKET_BYTES + 1]
        ),
        Err(UpdateAttestationRefusal::Malformed { .. })
    ));
    assert_eq!(
        verifier.check(&runtime, &publisher(UPDATE_ROOT), &issue(UPDATE_ROOT)),
        Ok(())
    );
    assert_eq!(admissions.pending(), 0);
}

#[test]
fn wrong_signatures_revoked_releases_and_revoked_root_keys_admit_no_update() {
    let fixture = Fixture::new();
    let mut trust = fixture.trust(Some(keys()));
    let opened = fixture.open(&mut trust);
    let repository = UpdateRepository::new();

    // Targets signed by a key the root does not delegate: the client verifies nothing.
    let (wrongly_signed, loaded) = repository.client_loading(OCI);
    assert!(loaded.is_err());
    assert!(wrongly_signed
        .verify_target(
            &TargetName::new(RUNTIME_TARGET).unwrap(),
            ArtifactClass::RuntimeUpdate,
            now()
        )
        .is_err());

    // A release the client's revocation list revokes after it was opened.
    let mut client = repository.client();
    let runtime = repository.opened(&client, RUNTIME_TARGET);
    let revocation = RevocationMetadata {
        role: Role::Revocation,
        version: MetadataVersion::new(1),
        issued: now(),
        revoked: BTreeMap::from([(ContentKey::of(RUNTIME), "withdrawn".to_owned())]),
    };
    let mut file = MetadataFile::unsigned(&revocation).unwrap();
    sign(&mut file, Role::Revocation, REVOCATION);
    client.update_revocation(&file).unwrap();
    assert!(matches!(
        import(&opened, &client, &runtime),
        Err(UpdateImportError::Client { .. })
    ));
    assert_absent(
        &mut opened.service.catalog(),
        &Scope::Host,
        ArtifactClass::RuntimeUpdate,
        RUNTIME,
    );

    // A client whose update root the trust roots do not list admits nothing.
    let unlisted = UpdateRepository::rooted_in(ROGUE);
    let unlisted_client = unlisted.client();
    let unlisted_runtime = unlisted.opened(&unlisted_client, RUNTIME_TARGET);
    assert_eq!(
        import(&opened, &unlisted_client, &unlisted_runtime),
        Err(UpdateImportError::NoTrustedRootKey)
    );

    // Revoking the update root key quarantines what it admitted and admits nothing new.
    let client = repository.client();
    let runtime = repository.opened(&client, RUNTIME_TARGET);
    let imported = import(&opened, &client, &runtime).unwrap();
    let applied = fixture.reload(&opened, &mut trust, keys_revoking("update-root"));
    let updates = applied
        .iter()
        .find(|applied| applied.class == ArtifactClass::RuntimeUpdate)
        .unwrap();
    assert_eq!(updates.quarantined, vec![imported.object]);
    assert_eq!(
        import(&opened, &client, &runtime),
        Err(UpdateImportError::NoTrustedRootKey)
    );
    assert_eq!(
        opened.service.catalog().acquire_lease(
            &Scope::Host,
            &execution("sandbox-1"),
            imported.object,
            Duration::from_secs(60)
        ),
        Err(ReadRefusal::Quarantined {
            object: imported.object
        })
    );
    assert_eq!(opened.classes.updates().pending(), 0);
}

#[test]
fn a_corrupted_update_is_refused_when_read_back_and_never_executed() {
    let fixture = Fixture::new();
    let mut trust = fixture.trust(Some(keys()));
    let opened = fixture.open(&mut trust);
    let repository = UpdateRepository::new();
    let client = repository.client();
    let runtime = repository.opened(&client, RUNTIME_TARGET);
    let object = import(&opened, &client, &runtime).unwrap().object;
    let reader = execution("sandbox-1");

    let mut catalog = opened.service.catalog();
    let identity = identify(&catalog, &Scope::Host, &runtime_record()).unwrap();
    let lease = catalog
        .acquire_lease(&Scope::Host, &reader, object, Duration::from_secs(60))
        .unwrap();
    let mut handle = catalog.open_read(&Scope::Host, &reader, lease).unwrap();
    fixture.corrupt(object, 7);
    assert_eq!(
        handle.read_all(),
        Err(ReadError::ExtentCorrupt { extent: 0 })
    );
    assert_eq!(
        catalog.verify_object(&Scope::Host, object),
        Err(VerifyError::Quarantined {
            reason: IntegrityFailure::ExtentCorrupt { extent: 0 }
        })
    );
    assert!(matches!(
        identify(&catalog, &Scope::Host, &runtime_record()),
        Err(ProvenanceRefusal::Quarantined { .. })
    ));
    let permission = ExecutionPermission {
        scope: Scope::Host,
        execution: reader,
        object,
    };
    assert_eq!(
        admit_execution(&catalog, &identity, &permission),
        Err(ProvenanceRefusal::CatalogRefused {
            refusal: ReadRefusal::Quarantined { object }
        })
    );
}
