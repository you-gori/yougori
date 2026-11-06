//! The feature manifest of one guest image release, bound to its build record and its
//! artifacts (VM-W05, line 2590: "Minimal supported init, required drivers and
//! hardening; signed artifacts from the first release"; VM-CP-05, line 3155: the
//! booted root image and kernel build record "match the signed manifest"; §8.3, line
//! 2455: expiry and rollback protection).
//!
//! A manifest states what the release is and what it needs: the image line and its
//! release number, when it was issued and until when it may be selected, the build
//! record it came from (by content key), the boot method and the artifacts by version,
//! content key and length; the guest agent's version and build and the link protocol it
//! speaks; the kernel's build record (V15's [`KernelBuildRecord`], bound to the kernel
//! artifact); the workload profiles whose confinement the image's agent installs, each
//! by its V15 profile digest and its sealed guest policy digest; and the devices the
//! image expects.
//!
//! [`FeatureManifest::bind`] checks that a manifest and a record describe the same
//! build: the record's content key, the image line, the architecture and every artifact.
//! The manifest is what a publisher signs ([`super::signed`]); the record is bound
//! through its content key, so one signature covers both.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::canonical::{self, DocumentError, GUEST_IMAGE_FORMAT};
use super::record::{ArtifactRole, BuildRecord, ProducedArtifact};
use super::text::ImageName;
use crate::foundation::ids::{ContentKey, Digest};
use crate::sandbox::link::Hello;
use crate::sandbox::trust::{Architecture, BootMethod, ComponentVersion, DeviceModel, UnixSeconds};
use crate::sandbox_contract::confinement::{
    KernelBuildRecord, ManifestExpectation, WorkloadProfile,
};

/// Largest feature manifest read.
pub const MAX_MANIFEST_BYTES: usize = 256 * 1024;

/// The release number of one manifest in its image line, from one. A later release of
/// the line has a larger number; a host never selects a smaller one than it already
/// admitted (rollback protection, §8.3 line 2455).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ReleaseNumber(u64);

impl ReleaseNumber {
    /// The first release.
    pub const FIRST: Self = Self(1);

    /// `number`, if it is at least one.
    pub const fn new(number: u64) -> Option<Self> {
        if number == 0 {
            None
        } else {
            Some(Self(number))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for ReleaseNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<'de> Deserialize<'de> for ReleaseNumber {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(u64::deserialize(deserializer)?)
            .ok_or_else(|| serde::de::Error::custom("a release number starts at 1"))
    }
}

/// The guest agent the image contains.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentFeatures {
    pub version: ComponentVersion,
    /// The content key digest of the agent executable inside the root image, the value
    /// the agent's `Hello` names as its build.
    pub build: Digest,
    /// The `sandbox::link` protocol version the agent speaks.
    pub link_protocol: u8,
}

/// Why a guest's hello does not agree with the manifest. A hello that agrees is still
/// the guest's claim and never evidence; one that disagrees is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "mismatch", rename_all = "snake_case")]
pub enum HelloMismatch {
    ProtocolVersion { manifest: u8, guest: u8 },
    AgentBuild { manifest: Digest, guest: Digest },
}

impl fmt::Display for HelloMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProtocolVersion { manifest, guest } => write!(
                f,
                "the guest speaks link protocol {guest}; the image's agent speaks {manifest}"
            ),
            Self::AgentBuild { manifest, guest } => write!(
                f,
                "the guest names agent build {guest}; the image contains {manifest}"
            ),
        }
    }
}

impl std::error::Error for HelloMismatch {}

impl AgentFeatures {
    /// Whether `hello` names this agent's protocol version and build.
    pub fn check_hello(&self, hello: &Hello) -> Result<(), HelloMismatch> {
        if hello.guest_version != self.link_protocol {
            return Err(HelloMismatch::ProtocolVersion {
                manifest: self.link_protocol,
                guest: hello.guest_version,
            });
        }
        if hello.agent_build != self.build {
            return Err(HelloMismatch::AgentBuild {
                manifest: self.build,
                guest: hello.agent_build,
            });
        }
        Ok(())
    }
}

/// One workload profile whose confinement the image's agent installs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadFeature {
    pub workload: WorkloadProfile,
    /// The digest of the V15 confinement profile (`ConfinementProfile::digest`).
    pub confinement_profile: Digest,
    /// The digest of the sealed guest policy compiled from it (`GuestPolicy::digest`).
    pub guest_policy: Digest,
}

/// The data of a feature manifest, as written. [`FeatureManifest::new`] checks it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestDocument {
    pub format: u64,
    pub image: ImageName,
    pub release: ReleaseNumber,
    pub issued_at: UnixSeconds,
    /// The first instant the manifest may no longer be selected (exclusive, as
    /// `UnixSeconds::is_expired_at` reads it).
    pub expires_at: UnixSeconds,
    /// The content key of the build record the artifacts came from.
    pub build_record: ContentKey,
    pub architecture: Architecture,
    pub boot: BootMethod,
    pub artifacts: BTreeMap<ArtifactRole, ProducedArtifact>,
    pub agent: AgentFeatures,
    /// The kernel's build record, bound to the kernel artifact's content key digest.
    pub kernel: KernelBuildRecord,
    /// Sorted by workload, each once.
    pub workloads: Vec<WorkloadFeature>,
    pub devices: BTreeSet<DeviceModel>,
}

/// Why a feature manifest was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum ManifestError {
    Document {
        error: DocumentError,
    },
    /// `expires_at` is not after `issued_at`.
    ExpiryNotAfterIssue,
    MissingArtifact {
        role: ArtifactRole,
    },
    /// An artifact of zero bytes.
    EmptyArtifact {
        role: ArtifactRole,
    },
    /// Firmware is listed although the guest boots its kernel directly.
    FirmwareWithoutFirmwareBoot,
    /// The guest boots through firmware and no firmware is listed.
    FirmwareBootWithoutFirmware,
    /// The kernel build record describes another kernel image than the kernel artifact.
    KernelRecordNotBound {
        kernel: Digest,
        record: Digest,
    },
    /// The image installs no workload profile.
    NoWorkloads,
    DuplicateWorkload {
        workload: WorkloadProfile,
    },
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Document { error } => write!(f, "{error}"),
            Self::ExpiryNotAfterIssue => {
                f.write_str("the manifest expires no later than it was issued")
            }
            Self::MissingArtifact { role } => write!(f, "the manifest lists no {role}"),
            Self::EmptyArtifact { role } => write!(f, "the manifest's {role} is empty"),
            Self::FirmwareWithoutFirmwareBoot => {
                f.write_str("the manifest lists firmware but boots its kernel directly")
            }
            Self::FirmwareBootWithoutFirmware => {
                f.write_str("the manifest boots through firmware and lists none")
            }
            Self::KernelRecordNotBound { kernel, record } => write!(
                f,
                "the kernel build record describes kernel {record}, not the kernel artifact \
                 {kernel}"
            ),
            Self::NoWorkloads => f.write_str("the manifest installs no workload profile"),
            Self::DuplicateWorkload { workload } => {
                write!(f, "the manifest lists workload {} twice", workload.label())
            }
        }
    }
}

impl std::error::Error for ManifestError {}

impl From<DocumentError> for ManifestError {
    fn from(error: DocumentError) -> Self {
        Self::Document { error }
    }
}

/// Why a manifest and a build record do not describe the same build.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "mismatch", rename_all = "snake_case")]
pub enum BindingError {
    /// The record's bytes are not the record the manifest names.
    RecordNotBound {
        manifest: ContentKey,
        record: ContentKey,
    },
    ImageDiffers {
        manifest: ImageName,
        record: ImageName,
    },
    ArchitectureDiffers {
        manifest: Architecture,
        record: Architecture,
    },
    /// The manifest lists an artifact the record did not produce.
    ArtifactNotBuilt { role: ArtifactRole },
    /// The record produced an artifact the manifest does not list.
    ArtifactNotListed { role: ArtifactRole },
    /// The manifest and the record give the artifact other versions or bytes.
    ArtifactDiffers { role: ArtifactRole },
}

impl fmt::Display for BindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RecordNotBound { manifest, record } => write!(
                f,
                "the manifest names build record {manifest}; the record given is {record}"
            ),
            Self::ImageDiffers { manifest, record } => write!(
                f,
                "the manifest is for image {manifest} and the record for {record}"
            ),
            Self::ArchitectureDiffers { manifest, record } => write!(
                f,
                "the manifest is for {manifest} and the record for {record}"
            ),
            Self::ArtifactNotBuilt { role } => {
                write!(f, "the manifest lists a {role} the build did not produce")
            }
            Self::ArtifactNotListed { role } => {
                write!(f, "the build produced a {role} the manifest does not list")
            }
            Self::ArtifactDiffers { role } => write!(
                f,
                "the manifest and the build record disagree about the {role}"
            ),
        }
    }
}

impl std::error::Error for BindingError {}

/// A checked feature manifest with its canonical bytes and content key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeatureManifest {
    document: ManifestDocument,
    bytes: Vec<u8>,
    key: ContentKey,
    root_image: Digest,
}

impl FeatureManifest {
    /// Checks `document`: the format, an expiry after the issue time, the root image and
    /// kernel listed and nothing of zero bytes, firmware exactly for firmware boot, the
    /// kernel record bound to the kernel artifact, and at least one workload, each once
    /// (sorted here).
    pub fn new(mut document: ManifestDocument) -> Result<Self, ManifestError> {
        if document.format != GUEST_IMAGE_FORMAT {
            return Err(DocumentError::UnsupportedFormat {
                found: document.format,
            }
            .into());
        }
        if document.expires_at <= document.issued_at {
            return Err(ManifestError::ExpiryNotAfterIssue);
        }
        for role in ArtifactRole::REQUIRED {
            if !document.artifacts.contains_key(&role) {
                return Err(ManifestError::MissingArtifact { role });
            }
        }
        let root_image = document
            .artifacts
            .get(&ArtifactRole::RootImage)
            .map(|artifact| *artifact.content_key.digest())
            .ok_or(ManifestError::MissingArtifact {
                role: ArtifactRole::RootImage,
            })?;
        if let Some((role, _)) = document
            .artifacts
            .iter()
            .find(|(_, artifact)| artifact.length_bytes == 0)
        {
            return Err(ManifestError::EmptyArtifact { role: *role });
        }
        let firmware = document.artifacts.contains_key(&ArtifactRole::Firmware);
        match (document.boot, firmware) {
            (BootMethod::DirectKernel, true) => {
                return Err(ManifestError::FirmwareWithoutFirmwareBoot)
            }
            (BootMethod::Firmware, false) => {
                return Err(ManifestError::FirmwareBootWithoutFirmware)
            }
            _ => {}
        }
        if let Some(kernel) = document.artifacts.get(&ArtifactRole::Kernel) {
            let kernel = *kernel.content_key.digest();
            let record = document.kernel.kernel_image();
            if kernel != record {
                return Err(ManifestError::KernelRecordNotBound { kernel, record });
            }
        }
        if document.workloads.is_empty() {
            return Err(ManifestError::NoWorkloads);
        }
        document
            .workloads
            .sort_by(|left, right| left.workload.cmp(&right.workload));
        if let Some(pair) = document
            .workloads
            .windows(2)
            .find(|pair| pair[0].workload == pair[1].workload)
        {
            return Err(ManifestError::DuplicateWorkload {
                workload: pair[0].workload,
            });
        }
        let bytes = canonical::encode(&document)?;
        let key = ContentKey::of(&bytes);
        Ok(Self {
            document,
            bytes,
            key,
            root_image,
        })
    }

    /// Reads a manifest from its canonical bytes, strictly ([`canonical`](super::canonical)).
    pub fn from_canonical(bytes: &[u8]) -> Result<Self, ManifestError> {
        let document: ManifestDocument = canonical::decode(bytes, MAX_MANIFEST_BYTES)?;
        let manifest = Self::new(document)?;
        canonical::require_canonical(bytes, &manifest.bytes)?;
        Ok(manifest)
    }

    pub fn document(&self) -> &ManifestDocument {
        &self.document
    }

    /// The canonical bytes, the bytes a publisher signs.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The manifest's identity: the content key of its canonical bytes.
    pub fn content_key(&self) -> ContentKey {
        self.key
    }

    pub fn image(&self) -> &ImageName {
        &self.document.image
    }

    pub fn release(&self) -> ReleaseNumber {
        self.document.release
    }

    pub fn artifact(&self, role: ArtifactRole) -> Option<&ProducedArtifact> {
        self.document.artifacts.get(&role)
    }

    pub fn artifacts(&self) -> &BTreeMap<ArtifactRole, ProducedArtifact> {
        &self.document.artifacts
    }

    pub fn agent(&self) -> &AgentFeatures {
        &self.document.agent
    }

    pub fn kernel(&self) -> &KernelBuildRecord {
        &self.document.kernel
    }

    pub fn devices(&self) -> &BTreeSet<DeviceModel> {
        &self.document.devices
    }

    /// The image's confinement for `workload`, if its agent installs that profile.
    pub fn workload(&self, workload: WorkloadProfile) -> Option<&WorkloadFeature> {
        self.document
            .workloads
            .iter()
            .find(|feature| feature.workload == workload)
    }

    /// The root image's identity: the content key digest a launch request pins
    /// (`sandbox::backend::PinnedArtifacts::guest_image`) and the host compares.
    pub fn root_image(&self) -> Digest {
        self.root_image
    }

    /// The signed manifest's expected values in the form VM-CP-05's evaluator takes
    /// (`sandbox_contract::confinement::evaluate`).
    pub fn expectation(&self) -> ManifestExpectation {
        ManifestExpectation {
            root_image: self.root_image,
            kernel: self.document.kernel.clone(),
        }
    }

    /// Checks that `record` is the build this manifest names and describes.
    pub fn bind(&self, record: &BuildRecord) -> Result<(), BindingError> {
        let document = &self.document;
        if document.build_record != record.content_key() {
            return Err(BindingError::RecordNotBound {
                manifest: document.build_record,
                record: record.content_key(),
            });
        }
        if &document.image != record.image() {
            return Err(BindingError::ImageDiffers {
                manifest: document.image.clone(),
                record: record.image().clone(),
            });
        }
        if document.architecture != record.architecture() {
            return Err(BindingError::ArchitectureDiffers {
                manifest: document.architecture,
                record: record.architecture(),
            });
        }
        for role in ArtifactRole::ALL {
            match (self.artifact(role), record.artifact(role)) {
                (Some(_), None) => return Err(BindingError::ArtifactNotBuilt { role }),
                (None, Some(_)) => return Err(BindingError::ArtifactNotListed { role }),
                (Some(listed), Some(built)) if listed != built => {
                    return Err(BindingError::ArtifactDiffers { role })
                }
                _ => {}
            }
        }
        Ok(())
    }
}

impl Serialize for FeatureManifest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.document.serialize(serializer)
    }
}
