//! Test fixtures: a build record shaped like today's appliance build
//! (`scripts/build-appliance.sh`: an Alpine base, the Go agent built with `-trimpath`
//! and an empty build id, the musl-built mount helper, `mkinitfs`, an ext4 root image),
//! its feature manifest, test keys from fixed seeds that are never release keys, a pinned
//! Firecracker row and a clock. Digests of upstream files are of placeholder bytes.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use ring::signature::{Ed25519KeyPair, KeyPair};

use super::*;
use crate::foundation::catalog::PublisherId;
use crate::foundation::evidence::OsKind;
use crate::foundation::ids::{digest, ContentKey, ManualClock, MonotonicTime};
use crate::foundation::report::CommitHash;
use crate::foundation::signing::{Ed25519PublicKey, TrustRoots};
use crate::sandbox::link::PROTOCOL_VERSION;
use crate::sandbox::trust::{
    Architecture, BootMethod, CalendarAnchor, ComponentKind, ComponentPin, ComponentVersion,
    ConfigurationKey, DeviceModel, HexBytes, PinnedConfiguration, SandboxBackend, TrustClock,
    UnixSeconds,
};
use crate::sandbox_contract::confinement::{
    ConfinementProfile, KernelOption, KernelSetting, OptionState, WorkloadProfile,
};

pub(super) const ROOT_IMAGE: &[u8] = b"appliance-base root image, release 3";
pub(super) const KERNEL: &[u8] = b"vmlinuz-virt 6.12.47-0-virt";
pub(super) const INITRD: &[u8] = b"initramfs-virt with the yougori boot payload";
pub(super) const AGENT: &[u8] = b"yougori-agent static executable";

/// The kernel configuration of [`KERNEL`]: io_uring, bpf(2) and userfaultfd removed.
pub(super) const KERNEL_CONFIG: &str = "#\n\
# Automatically generated file; DO NOT EDIT.\n\
# Linux/x86 6.12.47 Kernel Configuration\n\
#\n\
CONFIG_CC_VERSION_TEXT=\"gcc (Alpine 14.2.0) 14.2.0\"\n\
CONFIG_MODULES=y\n\
# CONFIG_IO_URING is not set\n\
# CONFIG_BPF_SYSCALL is not set\n\
# CONFIG_USERFAULTFD is not set\n\
CONFIG_PERF_EVENTS=y\n\
# CONFIG_KEXEC is not set\n\
# CONFIG_KEXEC_FILE is not set\n\
CONFIG_VSOCKETS=y\n\
CONFIG_VIRTIO_VSOCKETS=m\n\
\n\
# CONFIG_LOCK_DOWN_KERNEL_FORCE_INTEGRITY is not set\n";

/// No kernel option, no required absent option and no kernel setting.
pub(super) const NO_OPTIONS: [(KernelOption, OptionState); 0] = [];
pub(super) const NO_ABSENT: [KernelOption; 0] = [];
pub(super) const NO_SETTINGS: [KernelSetting; 0] = [];

/// The time of the fixtures' launches: 2026-09-21, inside the test key's window.
pub(super) const NOW: u64 = 1_790_000_000;
pub(super) const ISSUED_AT: u64 = 1_785_000_000;
pub(super) const EXPIRES_AT: u64 = 1_795_000_000;

pub(super) fn pair(seed: u8) -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap()
}

pub(super) fn public_key(seed: u8) -> Ed25519PublicKey {
    Ed25519PublicKey::from_bytes(pair(seed).public_key().as_ref()).unwrap()
}

pub(super) fn publisher(seed: u8) -> PublisherId {
    public_key(seed).publisher_id()
}

/// The release key's seed.
pub(super) const RELEASE: u8 = 7;

/// One trust-root key as JSON.
pub(super) fn key_json(id: &str, seed: u8, classes: &[&str], until: &str, revoked: bool) -> String {
    let classes: Vec<String> = classes.iter().map(|class| format!("\"{class}\"")).collect();
    let revoked = if revoked {
        ",\"revoked\":{\"reason\":\"key-compromise\"}"
    } else {
        ""
    };
    format!(
        "{{\"id\":\"{id}\",\"algorithm\":\"ed25519\",\"public_key\":\"{}\",\"classes\":[{}],\
         \"valid_from\":\"2026-01-01T00:00:00Z\",\"valid_until\":\"{until}\"{revoked}}}",
        public_key(seed).to_hex(),
        classes.join(",")
    )
}

/// Trust roots with these keys.
pub(super) fn roots_of(keys: &[String]) -> TrustRoots {
    TrustRoots::from_json(&format!("{{\"format\":1,\"keys\":[{}]}}", keys.join(","))).unwrap()
}

/// The owner's trust roots: the release key may sign guest images through 2026.
pub(super) fn roots() -> TrustRoots {
    roots_of(&[key_json(
        "guest-release-2026",
        RELEASE,
        &["guest_image"],
        "2027-01-01T00:00:00Z",
        false,
    )])
}

pub(super) fn name(value: &str) -> InputName {
    InputName::new(value).unwrap()
}

pub(super) fn version(value: &str) -> InputVersion {
    InputVersion::new(value).unwrap()
}

pub(super) fn file(bytes: &[u8]) -> FileInput {
    FileInput {
        content_key: ContentKey::of(bytes),
        length_bytes: bytes.len() as u64,
    }
}

pub(super) fn tool(tool: &str, tool_version: &str) -> ToolInput {
    let bytes = format!("{tool} {tool_version} executable");
    ToolInput {
        name: name(tool),
        version: version(tool_version),
        content_key: ContentKey::of(bytes.as_bytes()),
        length_bytes: bytes.len() as u64,
    }
}

pub(super) fn package(package: &str, package_version: &str) -> PackageInput {
    let bytes = format!("{package}-{package_version}.apk");
    PackageInput {
        name: name(package),
        version: version(package_version),
        content_key: ContentKey::of(bytes.as_bytes()),
        length_bytes: bytes.len() as u64,
    }
}

pub(super) fn step(
    step: &str,
    program: &str,
    arguments: &[&str],
    environment: &[(&str, &str)],
) -> BuildStep {
    BuildStep {
        name: name(step),
        program: name(program),
        arguments: arguments
            .iter()
            .map(|argument| BuildArgument::new(*argument).unwrap())
            .collect(),
        environment: environment
            .iter()
            .map(|(key, value)| {
                (
                    EnvironmentName::new(*key).unwrap(),
                    EnvironmentValue::new(*value).unwrap(),
                )
            })
            .collect(),
    }
}

pub(super) fn produced(artifact_version: &str, bytes: &[u8]) -> ProducedArtifact {
    ProducedArtifact {
        version: ComponentVersion::new(artifact_version).unwrap(),
        content_key: ContentKey::of(bytes),
        length_bytes: bytes.len() as u64,
    }
}

pub(super) fn image_name() -> ImageName {
    ImageName::new("yougori-guest-developer").unwrap()
}

/// The record of one appliance build. Lists are deliberately unsorted; the record sorts
/// them.
pub(super) fn record_document() -> RecordDocument {
    let alpine = b"alpine-minirootfs-3.24.1-x86_64.tar.gz bytes";
    let oci = b"yougori-oci-runtime-linux-amd64.tar.gz bytes";
    RecordDocument {
        format: GUEST_IMAGE_FORMAT,
        image: image_name(),
        architecture: Architecture::X86_64,
        inputs: BuildInputSet {
            repository: CommitHash::new("3f1c9a7e5b2d4086a1e7c3b9f0d2e4a6c8b0d1e2").unwrap(),
            source_date_epoch: UnixSeconds::new(1_780_000_000),
            sources: vec![
                SourceInput {
                    name: name("yougori-oci-runtime-linux-amd64.tar.gz"),
                    content_key: ContentKey::of(oci),
                    length_bytes: oci.len() as u64,
                },
                SourceInput {
                    name: name("alpine-minirootfs-3.24.1-x86_64.tar.gz"),
                    content_key: ContentKey::of(alpine),
                    length_bytes: alpine.len() as u64,
                },
            ],
            toolchain: vec![
                tool("go", "go1.27.2"),
                tool("musl-cc", "14.2.0"),
                tool("apk", "2.14.10-r0"),
                tool("mkinitfs", "3.12.0-r0"),
                tool("mkfs.ext4", "1.47.2-r1"),
                tool("qemu-img", "10.1.0"),
            ],
            kernel_configuration: file(KERNEL_CONFIG.as_bytes()),
            packages: vec![
                package("openrc", "0.62.6-r0"),
                package("linux-virt", "6.12.47-r0"),
                package("busybox-mdev-openrc", "1.37.0-r30"),
                package("ca-certificates", "20250911-r0"),
                package("e2fsprogs", "1.47.2-r1"),
                package("iproute2-minimal", "6.15.0-r0"),
                package("iptables", "1.8.11-r1"),
                package("libstdc++", "14.2.0-r6"),
            ],
        },
        steps: vec![
            step(
                "build-agent",
                "go",
                &[
                    "build",
                    "-buildvcs=false",
                    "-trimpath",
                    "-ldflags=-s -w -buildid=",
                    "-o",
                    "yougori-agent",
                    ".",
                ],
                &[("CGO_ENABLED", "0"), ("GOOS", "linux"), ("GOARCH", "amd64")],
            ),
            step(
                "build-mount-helper",
                "musl-cc",
                &[
                    "-static-pie",
                    "-Os",
                    "-s",
                    "-fstack-protector-strong",
                    "-Wl,-z,relro,-z,now,-z,noexecstack",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-o",
                    "yougori-mount-helper",
                    "mount-helper.c",
                ],
                &[],
            ),
            step(
                "install-packages",
                "apk",
                &[
                    "add",
                    "--no-cache",
                    "--root",
                    "rootfs",
                    "busybox-mdev-openrc",
                    "ca-certificates",
                    "e2fsprogs",
                    "iproute2-minimal",
                    "iptables",
                    "linux-virt",
                    "openrc",
                ],
                &[],
            ),
            step(
                "make-initramfs",
                "mkinitfs",
                &[
                    "-F",
                    "base virtio ext4 yougori-security",
                    "-i",
                    "usr/share/mkinitfs/yougori-init",
                    "6.12.47-0-virt",
                ],
                &[],
            ),
            step(
                "make-root-image",
                "mkfs.ext4",
                &[
                    "-F",
                    "-m",
                    "0",
                    "-L",
                    "yougori-root",
                    "-U",
                    "clear",
                    "-E",
                    "hash_seed=00000000-0000-0000-0000-000000000000",
                    "-d",
                    "rootfs",
                    "yougori-appliance.raw",
                    "6G",
                ],
                &[("E2FSPROGS_FAKE_TIME", "1780000000")],
            ),
            step(
                "convert-root-image",
                "qemu-img",
                &[
                    "convert",
                    "-f",
                    "raw",
                    "-O",
                    "qcow2",
                    "yougori-appliance.raw",
                    "appliance-base.qcow2",
                ],
                &[],
            ),
        ],
        artifacts: BTreeMap::from([
            (
                ArtifactRole::RootImage,
                produced("appliance-2026.10.3", ROOT_IMAGE),
            ),
            (ArtifactRole::Kernel, produced("6.12.47-0-virt", KERNEL)),
            (ArtifactRole::Initrd, produced("6.12.47-0-virt", INITRD)),
        ]),
    }
}

pub(super) fn strict() -> ConfinementProfile {
    ConfinementProfile::builtin(WorkloadProfile::StrictTool).unwrap()
}

pub(super) fn developer() -> ConfinementProfile {
    ConfinementProfile::builtin(WorkloadProfile::Developer).unwrap()
}

pub(super) fn workload(profile: &ConfinementProfile) -> WorkloadFeature {
    WorkloadFeature {
        workload: profile.workload(),
        confinement_profile: profile.digest(),
        guest_policy: digest(
            "yougori/test/guest-policy/v1",
            &[profile.workload().label().as_bytes()],
        ),
    }
}

/// The manifest of `record`, release 3.
pub(super) fn manifest_document(record: &BuildRecord) -> ManifestDocument {
    let kernel = record.artifact(ArtifactRole::Kernel).unwrap();
    ManifestDocument {
        format: GUEST_IMAGE_FORMAT,
        image: record.image().clone(),
        release: ReleaseNumber::new(3).unwrap(),
        issued_at: UnixSeconds::new(ISSUED_AT),
        expires_at: UnixSeconds::new(EXPIRES_AT),
        build_record: record.content_key(),
        architecture: record.architecture(),
        boot: BootMethod::DirectKernel,
        artifacts: record.artifacts().clone(),
        agent: AgentFeatures {
            version: ComponentVersion::new("agent-1.4.0").unwrap(),
            build: *ContentKey::of(AGENT).digest(),
            link_protocol: PROTOCOL_VERSION,
        },
        kernel: parse_kernel_config(*kernel.content_key.digest(), KERNEL_CONFIG.as_bytes())
            .unwrap(),
        workloads: vec![workload(&developer()), workload(&strict())],
        devices: BTreeSet::from([
            DeviceModel::VirtioBlk,
            DeviceModel::VirtioVsock,
            DeviceModel::VirtioRng,
        ]),
    }
}

/// A signed release.
#[derive(Clone, Debug)]
pub(super) struct Release {
    pub record: BuildRecord,
    pub manifest: FeatureManifest,
    pub signature: ManifestSignature,
}

impl Release {
    pub fn verify(&self, roots: &TrustRoots, now: u64) -> Result<VerifiedImage, VerifyRefusal> {
        verify_release(
            self.manifest.canonical_bytes(),
            self.record.canonical_bytes(),
            &self.signature,
            roots,
            UnixSeconds::new(now),
        )
    }

    pub fn verified(&self) -> VerifiedImage {
        self.verify(&roots(), NOW).unwrap()
    }
}

/// `seed`'s signature over the manifest whose canonical bytes are `bytes`.
pub(super) fn sign(seed: u8, bytes: &[u8]) -> ManifestSignature {
    let publisher = publisher(seed);
    let statement = signing_statement(&publisher, bytes);
    ManifestSignature {
        publisher,
        signature: HexBytes::new(pair(seed).sign(statement.as_bytes()).as_ref().to_vec()),
    }
}

/// The release of `record` with `manifest`, signed by the release key.
pub(super) fn release_of(record: BuildRecord, manifest: ManifestDocument) -> Release {
    let manifest = FeatureManifest::new(manifest).unwrap();
    let signature = sign(RELEASE, manifest.canonical_bytes());
    Release {
        record,
        manifest,
        signature,
    }
}

/// The fixture release, with `edit` applied to the manifest before it is signed.
pub(super) fn release_with(edit: impl FnOnce(&mut ManifestDocument)) -> Release {
    let record = BuildRecord::new(record_document()).unwrap();
    let mut manifest = manifest_document(&record);
    edit(&mut manifest);
    release_of(record, manifest)
}

pub(super) fn release() -> Release {
    release_with(|_| {})
}

pub(super) fn pin(
    kind: ComponentKind,
    artifact: &ProducedArtifact,
    record: &BuildRecord,
) -> ComponentPin {
    ComponentPin {
        kind,
        version: artifact.version.clone(),
        content_key: artifact.content_key,
        length_bytes: artifact.length_bytes,
        build: record.build_inputs(),
    }
}

pub(super) fn firecracker_key() -> ConfigurationKey {
    ConfigurationKey {
        os: OsKind::Linux,
        architecture: Architecture::X86_64,
        backend: SandboxBackend::Firecracker,
    }
}

/// The Firecracker row pinning `record`'s kernel and root image, and its initrd and
/// profile when it has them.
pub(super) fn row(record: &BuildRecord) -> PinnedConfiguration {
    let mut row = row_without_initrd_or_profile(record);
    for role in [ArtifactRole::Initrd, ArtifactRole::Profile] {
        if let Some(artifact) = record.artifact(role) {
            row.components.insert(
                role.pinned_kind(),
                pin(role.pinned_kind(), artifact, record),
            );
        }
    }
    row
}

/// The Firecracker row pinning `record`'s kernel and root image only, as a row written
/// before `sandbox::trust` had initrd and profile kinds.
pub(super) fn row_without_initrd_or_profile(record: &BuildRecord) -> PinnedConfiguration {
    let runtime = produced("firecracker-1.13.1", b"firecracker");
    let runtime_record = BuildRecord::new(record_document()).unwrap();
    let mut jailer = pin(ComponentKind::Jailer, &runtime, &runtime_record);
    jailer.content_key = ContentKey::of(b"jailer");
    PinnedConfiguration {
        key: firecracker_key(),
        boot: BootMethod::DirectKernel,
        components: BTreeMap::from([
            (
                ComponentKind::Runtime,
                pin(ComponentKind::Runtime, &runtime, &runtime_record),
            ),
            (ComponentKind::Jailer, jailer),
            (
                ComponentKind::GuestKernel,
                pin(
                    ComponentKind::GuestKernel,
                    record.artifact(ArtifactRole::Kernel).unwrap(),
                    record,
                ),
            ),
            (
                ComponentKind::GuestImage,
                pin(
                    ComponentKind::GuestImage,
                    record.artifact(ArtifactRole::RootImage).unwrap(),
                    record,
                ),
            ),
        ]),
        devices: BTreeSet::from([
            DeviceModel::VirtioNet,
            DeviceModel::VirtioBlk,
            DeviceModel::VirtioVsock,
            DeviceModel::VirtioRng,
        ]),
    }
}

/// The boot set of the fixture's bytes.
pub(super) fn boot_set() -> BootSet {
    BootSet::new()
        .with(ArtifactRole::RootImage, HostArtifact::of_bytes(ROOT_IMAGE))
        .with(ArtifactRole::Kernel, HostArtifact::of_bytes(KERNEL))
        .with(ArtifactRole::Initrd, HostArtifact::of_bytes(INITRD))
}

/// The selection of the fixture release for the strict profile at [`NOW`].
pub(super) fn selected(release: &Release) -> SelectedImage {
    let row = row(&release.record);
    let profile = strict();
    select(
        release.verified(),
        Selection {
            row: &row,
            profile: &profile,
            floor: None,
            now: UnixSeconds::new(NOW),
        },
    )
    .unwrap()
}

/// A clock reading [`NOW`], and the manual clock that drives it.
pub(super) fn clock() -> (Arc<ManualClock>, TrustClock) {
    let start = MonotonicTime::from_nanos(5_000_000_000);
    let manual = Arc::new(ManualClock::new(start));
    let trust = TrustClock::new(
        manual.clone(),
        CalendarAnchor {
            monotonic: start,
            unix_seconds: UnixSeconds::new(NOW),
        },
    )
    .unwrap();
    (manual, trust)
}
