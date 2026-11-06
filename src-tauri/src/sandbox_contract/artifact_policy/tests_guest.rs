//! Guest images through the install path against a real catalog service: a release
//! signed by the trust roots' guest image key installs every artifact its manifest
//! names; an artifact the manifest does not name, wrong signatures, wrong-class and
//! revoked keys, corrupted local files and an object corrupted after publication are
//! refused, and nothing refused is published, readable or executable (VM-W48, line 2671;
//! VM-W05, line 2590).

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use super::tests::{
    calendar, execution, keys, keys_revoking, operation, pair, publisher, raw_import, tenant,
    trust_refusal, Bytes, Fixture, Opened, GUEST, OCI, REVOKED, ROGUE,
};
use super::*;
use crate::foundation::catalog::{
    ArtifactClass, ContentDescriptor, ImportManifest, IntegrityFailure, ObjectStatus, ReadError,
    ReadRefusal, Scope, TrustBasis, TrustClaim, TrustRefusal, Uninterrupted, VerifyError,
};
use crate::foundation::ids::{digest, ContentKey};
use crate::foundation::report::CommitHash;
use crate::foundation::signing::{ComponentVerification, SharedTrustRoots};
use crate::sandbox::guest_image::{
    parse_kernel_config, signing_statement, AgentFeatures, ArtifactRole, BuildArgument,
    BuildInputSet, BuildRecord, BuildStep, FeatureManifest, FileInput, ImageName, InputName,
    InputVersion, ManifestDocument, ManifestSignature, ProducedArtifact, RecordDocument,
    ReleaseNumber, ToolInput, VerifyRefusal, WorkloadFeature, GUEST_IMAGE_FORMAT,
};
use crate::sandbox::link::PROTOCOL_VERSION;
use crate::sandbox::trust::{
    admit_execution, identify, Architecture, Attestation, BootMethod, ComponentVersion,
    DeviceModel, ExecutionPermission, HexBytes, KernelProvenance, Provenance, ProvenanceRecord,
    ProvenanceRefusal, UnixSeconds,
};
use crate::sandbox_contract::confinement::WorkloadProfile;

pub(super) const ROOT_IMAGE: &[u8] = b"m18f guest root image, read-only";
pub(super) const KERNEL: &[u8] = b"m18f vmlinuz 6.12.47-0-virt";
pub(super) const INITRD: &[u8] = b"m18f initramfs with the boot payload";
pub(super) const FIRMWARE: &[u8] = b"m18f edk2 firmware volume";
pub(super) const PROFILE: &[u8] = b"m18f sealed guest policies";
const KERNEL_CONFIG: &[u8] = b"CONFIG_MODULES=y\n# CONFIG_IO_URING is not set\n";

fn produced(version: &str, bytes: &[u8]) -> ProducedArtifact {
    ProducedArtifact {
        version: ComponentVersion::new(version).unwrap(),
        content_key: ContentKey::of(bytes),
        length_bytes: bytes.len() as u64,
    }
}

fn role_bytes() -> [(ArtifactRole, &'static [u8]); 5] {
    [
        (ArtifactRole::RootImage, ROOT_IMAGE),
        (ArtifactRole::Kernel, KERNEL),
        (ArtifactRole::Initrd, INITRD),
        (ArtifactRole::Firmware, FIRMWARE),
        (ArtifactRole::Profile, PROFILE),
    ]
}

/// The build record of a firmware-booted release with all five artifacts.
pub(super) fn build_record() -> BuildRecord {
    BuildRecord::new(RecordDocument {
        format: GUEST_IMAGE_FORMAT,
        image: ImageName::new("yougori-guest-m18f").unwrap(),
        architecture: Architecture::X86_64,
        inputs: BuildInputSet {
            repository: CommitHash::new("0123456789abcdef0123456789abcdef01234567").unwrap(),
            source_date_epoch: UnixSeconds::new(1_780_000_000),
            sources: Vec::new(),
            toolchain: vec![ToolInput {
                name: InputName::new("mkfs.erofs").unwrap(),
                version: InputVersion::new("1.8.1").unwrap(),
                content_key: ContentKey::of(b"mkfs.erofs executable"),
                length_bytes: 21,
            }],
            kernel_configuration: FileInput {
                content_key: ContentKey::of(KERNEL_CONFIG),
                length_bytes: KERNEL_CONFIG.len() as u64,
            },
            packages: Vec::new(),
        },
        steps: vec![BuildStep {
            name: InputName::new("make-root-image").unwrap(),
            program: InputName::new("mkfs.erofs").unwrap(),
            arguments: vec![BuildArgument::new("root.img").unwrap()],
            environment: BTreeMap::new(),
        }],
        artifacts: role_bytes()
            .into_iter()
            .map(|(role, bytes)| (role, produced("2026.10.1", bytes)))
            .collect(),
    })
    .unwrap()
}

fn feature_manifest(record: &BuildRecord) -> FeatureManifest {
    FeatureManifest::new(ManifestDocument {
        format: GUEST_IMAGE_FORMAT,
        image: record.image().clone(),
        release: ReleaseNumber::new(1).unwrap(),
        issued_at: UnixSeconds::new(1_790_000_000),
        expires_at: UnixSeconds::new(1_800_000_000),
        build_record: record.content_key(),
        architecture: record.architecture(),
        boot: BootMethod::Firmware,
        artifacts: record.artifacts().clone(),
        agent: AgentFeatures {
            version: ComponentVersion::new("agent-1.0.0").unwrap(),
            build: *ContentKey::of(b"agent").digest(),
            link_protocol: PROTOCOL_VERSION,
        },
        kernel: parse_kernel_config(*ContentKey::of(KERNEL).digest(), KERNEL_CONFIG).unwrap(),
        workloads: vec![WorkloadFeature {
            workload: WorkloadProfile::StrictTool,
            confinement_profile: digest("yougori/test/m18f/profile/v1", &[b"strict"]),
            guest_policy: digest("yougori/test/m18f/policy/v1", &[b"strict"]),
        }],
        devices: BTreeSet::from([DeviceModel::VirtioBlk, DeviceModel::VirtioVsock]),
    })
    .unwrap()
}

fn sign_manifest(seed: u8, manifest: &[u8]) -> ManifestSignature {
    ManifestSignature {
        publisher: publisher(seed),
        signature: HexBytes::new(
            pair(seed)
                .sign(signing_statement(&publisher(seed), manifest).as_bytes())
                .as_ref()
                .to_vec(),
        ),
    }
}

/// Every artifact's bytes, as the bundled runtime directory holds them.
pub(super) fn files() -> BTreeMap<ArtifactRole, Bytes> {
    role_bytes()
        .into_iter()
        .map(|(role, bytes)| (role, Bytes::new(role.tag(), bytes)))
        .collect()
}

/// The release signed by `seed`, and its files.
pub(super) fn release_signed_by(seed: u8) -> (GuestRelease, BTreeMap<ArtifactRole, Bytes>) {
    let record = build_record();
    let manifest = feature_manifest(&record);
    let release = GuestRelease {
        manifest: manifest.canonical_bytes().to_vec(),
        record: record.canonical_bytes().to_vec(),
        signature: sign_manifest(seed, manifest.canonical_bytes()),
    };
    (release, files())
}

fn install(
    opened: &Opened,
    release: &GuestRelease,
    files: &mut BTreeMap<ArtifactRole, Bytes>,
) -> Result<InstalledRelease, GuestInstallError> {
    opened.classes.guest().install(
        &mut opened.service.catalog(),
        GuestInstall {
            operation: operation(),
            execution: execution("guest-installer"),
            release,
        },
        files,
        &mut Uninterrupted,
    )
}

/// The kernel's typed provenance, as the launch path would identify it.
fn kernel_record() -> ProvenanceRecord {
    ProvenanceRecord {
        provenance: Provenance::Kernel(KernelProvenance {
            version: ComponentVersion::new("2026.10.1").unwrap(),
            build: build_record().build_inputs(),
            content: ContentKey::of(KERNEL),
        }),
        attestation: Attestation {
            publisher: publisher(GUEST),
            attestation: HexBytes::new(Vec::new()),
        },
    }
}

fn descriptor(class: ArtifactClass, bytes: &[u8]) -> ContentDescriptor {
    let manifest = ImportManifest::describe(bytes, GUEST_EXTENT_BYTES);
    ContentDescriptor {
        scope: Scope::Host,
        class,
        content_key: manifest.content_key,
        length_bytes: manifest.true_length_bytes,
        manifest_digest: manifest.digest(),
    }
}

/// The verification outcome inside a signature refusal.
fn verification(error: GuestInstallError) -> ComponentVerification {
    match error {
        GuestInstallError::Release { refusal } => match *refusal {
            VerifyRefusal::Signature { component } => component.verification().clone(),
            other => panic!("not a signature refusal: {other:?}"),
        },
        other => panic!("not a release refusal: {other:?}"),
    }
}

#[test]
fn a_release_signed_by_the_guest_key_installs_every_artifact() {
    let fixture = Fixture::new();
    let mut trust = fixture.trust(Some(keys()));
    let opened = fixture.open(&mut trust);
    let (release, mut files) = release_signed_by(GUEST);
    let installed = install(&opened, &release, &mut files).unwrap();
    assert_eq!(installed.image.key().as_str(), "guest-release");
    assert_eq!(
        installed.artifacts.keys().copied().collect::<Vec<_>>(),
        ArtifactRole::ALL.to_vec()
    );

    let reader = execution("sandbox-1");
    let mut catalog = opened.service.catalog();
    let mut parts = installed
        .artifacts
        .iter()
        .map(|(role, object)| {
            let bytes = role_bytes()
                .into_iter()
                .find(|(listed, _)| listed == role)
                .unwrap()
                .1
                .to_vec();
            (ReleasePart::Artifact { role: *role }, *object, bytes)
        })
        .collect::<Vec<_>>();
    parts.push((
        ReleasePart::Manifest,
        installed.manifest,
        release.manifest.clone(),
    ));
    parts.push((
        ReleasePart::BuildRecord,
        installed.record,
        release.record.clone(),
    ));
    for (part, object, bytes) in parts {
        assert_eq!(
            catalog.status(&Scope::Host, object),
            ObjectStatus::Published
        );
        let metadata = catalog.private_metadata(&Scope::Host, object).unwrap();
        assert_eq!(metadata.class, ArtifactClass::GuestImage);
        assert_eq!(
            metadata.trust,
            TrustBasis::Publisher {
                publisher: publisher(GUEST)
            }
        );
        assert_eq!(
            metadata
                .metadata
                .labels
                .get(GUEST_PART_LABEL)
                .map(String::as_str),
            Some(part.tag())
        );
        let lease = catalog
            .acquire_lease(&Scope::Host, &reader, object, Duration::from_secs(60))
            .unwrap();
        let read = catalog
            .open_read(&Scope::Host, &reader, lease)
            .unwrap()
            .read_all()
            .unwrap();
        assert_eq!(read, bytes);
    }

    // The kernel is identified through its typed provenance, and may execute only under
    // a permission for that exact object.
    let kernel = installed.artifacts[&ArtifactRole::Kernel];
    let identity = identify(&catalog, &Scope::Host, &kernel_record()).unwrap();
    assert_eq!(identity.object(), kernel);
    let permission = ExecutionPermission {
        scope: Scope::Host,
        execution: reader.clone(),
        object: kernel,
    };
    assert!(admit_execution(&catalog, &identity, &permission).is_ok());
    // A tenant does not read the host's kernel without a grant.
    assert_eq!(
        catalog.acquire_lease(&tenant("a"), &reader, kernel, Duration::from_secs(60)),
        Err(ReadRefusal::NotGranted { object: kernel })
    );
    drop(catalog);

    // A repeated install finds the same objects, each claim checked again.
    let again = install(&opened, &release, &mut files).unwrap();
    assert_eq!(again.artifacts, installed.artifacts);
    assert_eq!(again.manifest, installed.manifest);
}

#[test]
fn only_what_the_signed_manifest_names_is_admitted() {
    let fixture = Fixture::new();
    let mut trust = fixture.trust(Some(keys()));
    let opened = fixture.open(&mut trust);
    let (release, _) = release_signed_by(GUEST);
    let claim = release.trust_claim();
    let TrustClaim::Publisher { attestation, .. } = &claim else {
        unreachable!()
    };

    // The verifier places each part of the release and nothing else.
    let verifier = GuestImageVerifier::new(trust.shared().unwrap(), calendar());
    let place = |class: ArtifactClass, bytes: &[u8]| {
        verifier
            .check(&descriptor(class, bytes), &publisher(GUEST), attestation)
            .map(|(_, part)| part)
    };
    for (role, bytes) in role_bytes() {
        assert_eq!(
            place(ArtifactClass::GuestImage, bytes),
            Ok(ReleasePart::Artifact { role })
        );
    }
    assert_eq!(
        place(ArtifactClass::GuestImage, &release.manifest),
        Ok(ReleasePart::Manifest)
    );
    assert_eq!(
        place(ArtifactClass::GuestImage, &release.record),
        Ok(ReleasePart::BuildRecord)
    );
    assert_eq!(
        place(
            ArtifactClass::GuestImage,
            b"a kernel the release does not name"
        ),
        Err(GuestAttestationRefusal::NotInRelease)
    );
    assert_eq!(
        place(ArtifactClass::RuntimeUpdate, KERNEL),
        Err(GuestAttestationRefusal::WrongClass {
            class: ArtifactClass::RuntimeUpdate
        })
    );
    // The attestation is read strictly and within its bound.
    let mut extra: serde_json::Value = serde_json::from_slice(attestation).unwrap();
    extra["kernel_cmdline"] = serde_json::json!("init=/bin/sh");
    let mut other_format: serde_json::Value = serde_json::from_slice(attestation).unwrap();
    other_format["format"] = serde_json::json!("yougori.guest-image.release-attestation.v2");
    for forged in [
        serde_json::to_vec(&extra).unwrap(),
        serde_json::to_vec(&other_format).unwrap(),
        vec![b' '; MAX_GUEST_ATTESTATION_BYTES + 1],
        b"not json".to_vec(),
    ] {
        assert!(matches!(
            verifier.check(
                &descriptor(ArtifactClass::GuestImage, KERNEL),
                &publisher(GUEST),
                &forged
            ),
            Err(GuestAttestationRefusal::Malformed { .. })
        ));
    }
    assert_eq!(
        GuestReleaseAttestation::decode(attestation)
            .unwrap()
            .encode(),
        *attestation
    );

    // Through the catalog, bytes the manifest does not name are refused with the
    // genuine claim, and nothing of them is published or readable.
    let mut catalog = opened.service.catalog();
    let unnamed = b"a kernel the release does not name";
    assert!(matches!(
        trust_refusal(raw_import(
            &mut catalog,
            &Scope::Host,
            ArtifactClass::GuestImage,
            unnamed,
            claim.clone()
        )),
        TrustRefusal::AttestationRejected { .. }
    ));
    super::tests::assert_absent(
        &mut catalog,
        &Scope::Host,
        ArtifactClass::GuestImage,
        unnamed,
    );
    // A named artifact is admitted with it.
    assert!(raw_import(
        &mut catalog,
        &Scope::Host,
        ArtifactClass::GuestImage,
        INITRD,
        claim
    )
    .is_ok());
}

#[test]
fn wrong_signatures_and_wrong_class_or_revoked_keys_install_nothing() {
    let fixture = Fixture::new();
    let mut trust = fixture.trust(Some(keys()));
    let opened = fixture.open(&mut trust);

    let (mut flipped, mut files) = release_signed_by(GUEST);
    let mut signature = flipped.signature.signature.as_bytes().to_vec();
    signature[3] ^= 0x01;
    flipped.signature.signature = HexBytes::new(signature);
    assert!(matches!(
        verification(install(&opened, &flipped, &mut files).unwrap_err()),
        ComponentVerification::BadSignature { .. }
    ));

    // The manifest edited after signing: the signature no longer covers it.
    let (mut edited, _) = release_signed_by(GUEST);
    let position = edited.manifest.len() / 2;
    edited.manifest[position] ^= 0x01;
    assert!(matches!(
        verification(install(&opened, &edited, &mut files).unwrap_err()),
        ComponentVerification::BadSignature { .. }
    ));

    // A key allowed OCI layers only, a revoked key and a key in no trust-root file.
    for (seed, expected) in [
        (OCI, "ClassNotAllowed"),
        (REVOKED, "Revoked"),
        (ROGUE, "UnknownPublisher"),
    ] {
        let (release, _) = release_signed_by(seed);
        let refused = verification(install(&opened, &release, &mut files).unwrap_err());
        assert!(format!("{refused:?}").starts_with(expected), "{refused:?}");
    }

    // The guest key's signature claimed for the OCI key.
    let (mut claimed, _) = release_signed_by(GUEST);
    claimed.signature.publisher = publisher(OCI);
    assert!(matches!(
        verification(install(&opened, &claimed, &mut files).unwrap_err()),
        ComponentVerification::ClassNotAllowed { .. }
    ));

    // No signature at all.
    let (mut unsigned, _) = release_signed_by(GUEST);
    unsigned.signature.signature = HexBytes::new(Vec::new());
    assert_eq!(
        install(&opened, &unsigned, &mut files),
        Err(GuestInstallError::Release {
            refusal: Box::new(VerifyRefusal::Unsigned)
        })
    );
    assert!(opened.service.catalog().objects(&Scope::Host).is_empty());
}

#[test]
fn a_corrupted_local_file_installs_nothing() {
    let fixture = Fixture::new();
    let mut trust = fixture.trust(Some(keys()));
    let opened = fixture.open(&mut trust);
    let (release, _) = release_signed_by(GUEST);

    // The kernel file changed on disk, same length.
    let mut changed = files();
    let mut kernel = KERNEL.to_vec();
    kernel[4] ^= 0x20;
    changed.insert(ArtifactRole::Kernel, Bytes::new("kernel", &kernel));
    assert_eq!(
        install(&opened, &release, &mut changed),
        Err(GuestInstallError::CorruptedLocalFile {
            role: ArtifactRole::Kernel,
            refusal: ProvenanceRefusal::CorruptedLocalFile {
                expected: ContentKey::of(KERNEL),
                found: ContentKey::of(&kernel),
            },
        })
    );
    // The firmware file cut short.
    let mut short = files();
    short.insert(
        ArtifactRole::Firmware,
        Bytes::new("firmware", &FIRMWARE[..FIRMWARE.len() - 1]),
    );
    assert_eq!(
        install(&opened, &release, &mut short),
        Err(GuestInstallError::LengthDiffers {
            role: ArtifactRole::Firmware,
            expected_bytes: FIRMWARE.len() as u64,
            found_bytes: FIRMWARE.len() as u64 - 1,
        })
    );
    // The profile missing.
    let mut missing = files();
    missing.remove(&ArtifactRole::Profile);
    assert_eq!(
        install(&opened, &release, &mut missing),
        Err(GuestInstallError::MissingArtifact {
            role: ArtifactRole::Profile
        })
    );
    // Every file is checked before anything is published.
    let mut catalog = opened.service.catalog();
    assert!(catalog.objects(&Scope::Host).is_empty());
    for (_, bytes) in role_bytes() {
        super::tests::assert_absent(&mut catalog, &Scope::Host, ArtifactClass::GuestImage, bytes);
    }
}

#[test]
fn a_corrupted_kernel_is_refused_when_read_back_and_never_executed() {
    let fixture = Fixture::new();
    let mut trust = fixture.trust(Some(keys()));
    let opened = fixture.open(&mut trust);
    let (release, mut files) = release_signed_by(GUEST);
    let installed = install(&opened, &release, &mut files).unwrap();
    let kernel = installed.artifacts[&ArtifactRole::Kernel];
    let reader = execution("sandbox-1");

    let mut catalog = opened.service.catalog();
    let identity = identify(&catalog, &Scope::Host, &kernel_record()).unwrap();
    let lease = catalog
        .acquire_lease(&Scope::Host, &reader, kernel, Duration::from_secs(60))
        .unwrap();
    let mut handle = catalog.open_read(&Scope::Host, &reader, lease).unwrap();
    fixture.corrupt(kernel, 3);

    assert!(matches!(
        handle.read_all(),
        Err(ReadError::ExtentCorrupt { extent: 0 })
    ));
    assert!(matches!(
        catalog.verify_object(&Scope::Host, kernel),
        Err(VerifyError::Quarantined {
            reason: IntegrityFailure::ExtentCorrupt { extent: 0 }
        })
    ));
    assert_eq!(handle.read_all(), Err(ReadError::LeaseRevoked));
    assert_eq!(
        catalog.acquire_lease(&Scope::Host, &reader, kernel, Duration::from_secs(60)),
        Err(ReadRefusal::Quarantined { object: kernel })
    );
    assert!(matches!(
        identify(&catalog, &Scope::Host, &kernel_record()),
        Err(ProvenanceRefusal::Quarantined { object, .. }) if object == kernel
    ));
    let permission = ExecutionPermission {
        scope: Scope::Host,
        execution: reader,
        object: kernel,
    };
    assert_eq!(
        admit_execution(&catalog, &identity, &permission),
        Err(ProvenanceRefusal::CatalogRefused {
            refusal: ReadRefusal::Quarantined { object: kernel }
        })
    );
    // The rest of the release is untouched.
    assert_eq!(
        catalog.status(&Scope::Host, installed.artifacts[&ArtifactRole::Initrd]),
        ObjectStatus::Published
    );
}

#[test]
fn revoking_the_release_key_quarantines_the_installed_release() {
    let fixture = Fixture::new();
    let mut trust = fixture.trust(Some(keys()));
    let opened = fixture.open(&mut trust);
    let (release, mut files) = release_signed_by(GUEST);
    let installed = install(&opened, &release, &mut files).unwrap();
    let mut objects: Vec<_> = installed.artifacts.values().copied().collect();
    objects.extend([installed.manifest, installed.record]);
    objects.sort();
    // A verifier holding the shared roots from before the reload.
    let shared: SharedTrustRoots = trust.shared().unwrap();
    let verifier = GuestImageVerifier::new(shared, calendar());

    let applied = fixture.reload(&opened, &mut trust, keys_revoking("guest-release"));
    let guest = applied
        .iter()
        .find(|applied| applied.class == ArtifactClass::GuestImage)
        .unwrap();
    let mut quarantined = guest.quarantined.clone();
    quarantined.sort();
    assert_eq!(quarantined, objects);
    {
        let catalog = opened.service.catalog();
        assert!(identify(&catalog, &Scope::Host, &kernel_record()).is_err());
    }
    // The verifiers read the reloaded roots: the same release installs nothing now.
    let refused = verification(install(&opened, &release, &mut files).unwrap_err());
    assert!(matches!(refused, ComponentVerification::Revoked { .. }));
    // The verifier built before the reload sees the revocation too.
    let TrustClaim::Publisher { attestation, .. } = release.trust_claim() else {
        unreachable!()
    };
    assert!(matches!(
        verifier.check(
            &descriptor(ArtifactClass::GuestImage, KERNEL),
            &publisher(GUEST),
            &attestation
        ),
        Err(GuestAttestationRefusal::Release { refusal })
            if matches!(*refusal, VerifyRefusal::Signature { .. })
    ));
}
