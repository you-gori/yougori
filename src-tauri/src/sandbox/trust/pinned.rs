//! Pinned configurations and the compatibility and patch matrix (VM-W46, line 2669:
//! "Pinned runtime, guest, firmware and device configurations for each supported
//! OS/architecture/backend. Maintain a compatibility and patch matrix with reproducible
//! inputs ... known vulnerability decisions record affected configuration, mitigation
//! and owner; unsupported devices are absent"; line 2453: "Pin guest/kernel/hypervisor/
//! helper builds"; §19, from line 3215: the pinned binaries).
//!
//! A row of the matrix pins every component of one configuration by exact version,
//! content key and reproducible build inputs. A configuration not in the matrix is
//! refused as unsupported; a device not listed in a row is [`DeviceSupport::Absent`],
//! and there is no "untested" value. A row's [`ConfigurationFingerprint`] is what
//! CORE-01 evidence binds to, so tests run against exact builds.
//!
//! The guest's initial ramdisk ([`ComponentKind::GuestInitrd`]) and the profile document
//! shipped beside its image ([`ComponentKind::GuestProfile`]) are pinned when the guest
//! has them. Neither is required, so a row written before the two kinds existed reads,
//! checks and fingerprints as it did; whether a guest release ships them is the release
//! manifest's to say (`sandbox::guest_image` refuses a row that does not pin what its
//! manifest names).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

use super::time::UnixSeconds;
use super::vulnerability::ExceptionId;
use crate::foundation::evidence::{
    ConfigurationFingerprint, FingerprintError, HypervisorKind, OsKind,
};
use crate::foundation::ids::{validate_identifier, ContentKey, Digest, DigestBuilder, IdError};
use crate::foundation::report::CommitHash;

/// Domain of [`BuildInputs::digest`].
pub const BUILD_INPUTS_DOMAIN: &str = "yougori/sandbox/trust/build-inputs/v1";
/// Longest accepted free text in a decision.
pub const MAX_TEXT_BYTES: usize = 512;

/// A CPU architecture a configuration is pinned for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Architecture {
    X86_64,
    Aarch64,
}

impl Architecture {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
        }
    }
}

impl fmt::Display for Architecture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.tag())
    }
}

/// A sandbox backend: the virtual machine monitor of §19 (lines 3047–3059).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxBackend {
    Firecracker,
    CloudHypervisor,
    QemuSecure,
    Hcs,
    Vz,
}

impl SandboxBackend {
    pub const ALL: [Self; 5] = [
        Self::Firecracker,
        Self::CloudHypervisor,
        Self::QemuSecure,
        Self::Hcs,
        Self::Vz,
    ];

    pub const fn tag(self) -> &'static str {
        match self {
            Self::Firecracker => "firecracker",
            Self::CloudHypervisor => "cloud_hypervisor",
            Self::QemuSecure => "qemu_secure",
            Self::Hcs => "hcs",
            Self::Vz => "vz",
        }
    }

    /// The hypervisor interface this backend uses on `os`; `None` where the backend does
    /// not run, which makes the pairing unsupported rather than untested.
    pub const fn hypervisor_on(self, os: OsKind) -> Option<HypervisorKind> {
        match (self, os) {
            (Self::Firecracker | Self::CloudHypervisor, OsKind::Linux) => Some(HypervisorKind::Kvm),
            (Self::QemuSecure, OsKind::Linux) => Some(HypervisorKind::Kvm),
            (Self::QemuSecure, OsKind::Windows) => Some(HypervisorKind::Whpx),
            (Self::QemuSecure, OsKind::MacOs) => Some(HypervisorKind::Hvf),
            (Self::Hcs, OsKind::Windows) => Some(HypervisorKind::Hcs),
            (Self::Vz, OsKind::MacOs) => Some(HypervisorKind::Vz),
            _ => None,
        }
    }
}

impl fmt::Display for SandboxBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.tag())
    }
}

/// One supported combination of OS, architecture and backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigurationKey {
    pub os: OsKind,
    pub architecture: Architecture,
    pub backend: SandboxBackend,
}

impl ConfigurationKey {
    /// The hypervisor interface the key implies, or a refusal if the backend does not
    /// run on the OS.
    pub fn hypervisor(&self) -> Result<HypervisorKind, PinRefusal> {
        self.backend
            .hypervisor_on(self.os)
            .ok_or(PinRefusal::BackendNotOnOs {
                backend: self.backend,
                os: self.os,
            })
    }
}

impl fmt::Display for ConfigurationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/{}/{}",
            self.os.tag(),
            self.architecture.tag(),
            self.backend.tag()
        )
    }
}

/// The components a configuration pins. Each serializes as its [`Self::tag`]; the guest
/// initrd and profile come last, so every earlier kind keeps its name and order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentKind {
    /// The virtual machine monitor binary.
    Runtime,
    /// The jailer or privileged launcher (VM-D15).
    Jailer,
    GuestKernel,
    /// The guest root image.
    GuestImage,
    Firmware,
    /// A bundled helper such as the Swift helper of §19.
    Helper,
    /// The initial ramdisk loaded with the guest kernel; pinned when the guest has one.
    GuestInitrd,
    /// A profile document shipped beside the guest image, such as the sealed guest
    /// policies its agent installs; pinned when the guest has one.
    GuestProfile,
}

impl ComponentKind {
    pub const ALL: [Self; 8] = [
        Self::Runtime,
        Self::Jailer,
        Self::GuestKernel,
        Self::GuestImage,
        Self::Firmware,
        Self::Helper,
        Self::GuestInitrd,
        Self::GuestProfile,
    ];

    pub const fn tag(self) -> &'static str {
        match self {
            Self::Runtime => "runtime",
            Self::Jailer => "jailer",
            Self::GuestKernel => "guest_kernel",
            Self::GuestImage => "guest_image",
            Self::Firmware => "firmware",
            Self::Helper => "helper",
            Self::GuestInitrd => "guest_initrd",
            Self::GuestProfile => "guest_profile",
        }
    }
}

impl fmt::Display for ComponentKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.tag())
    }
}

/// An exact component version, compared exactly and never ordered.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ComponentVersion(String);

impl ComponentVersion {
    pub fn new(value: impl Into<String>) -> Result<Self, IdError> {
        let value = value.into();
        validate_identifier(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ComponentVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ComponentVersion({})", self.0)
    }
}

impl fmt::Display for ComponentVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ComponentVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// The reproducible inputs of one build (line 2669 "reproducible inputs"; line 2459:
/// reproducibility "improves provenance" and proves no absence of malicious code).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildInputs {
    pub source: CommitHash,
    pub toolchain: Digest,
    pub configuration: Digest,
    pub builder: Digest,
}

impl BuildInputs {
    /// One digest over all four inputs.
    pub fn digest(&self) -> Digest {
        DigestBuilder::new(BUILD_INPUTS_DOMAIN)
            .str(self.source.as_str())
            .digest(&self.toolchain)
            .digest(&self.configuration)
            .digest(&self.builder)
            .finish()
    }
}

/// One pinned component: exact version, exact bytes, reproducible inputs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentPin {
    pub kind: ComponentKind,
    pub version: ComponentVersion,
    pub content_key: ContentKey,
    pub length_bytes: u64,
    pub build: BuildInputs,
}

/// How the guest boots, which decides whether firmware is pinned.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootMethod {
    /// The runtime loads the pinned kernel directly.
    DirectKernel,
    /// Pinned firmware boots the guest.
    Firmware,
}

impl BootMethod {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::DirectKernel => "direct_kernel",
            Self::Firmware => "firmware",
        }
    }
}

/// A virtual device model a configuration may offer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceModel {
    VirtioNet,
    VirtioBlk,
    VirtioVsock,
    VirtioRng,
    VirtioBalloon,
    VirtioFs,
    VfioPci,
    SerialConsole,
}

impl DeviceModel {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::VirtioNet => "virtio_net",
            Self::VirtioBlk => "virtio_blk",
            Self::VirtioVsock => "virtio_vsock",
            Self::VirtioRng => "virtio_rng",
            Self::VirtioBalloon => "virtio_balloon",
            Self::VirtioFs => "virtio_fs",
            Self::VfioPci => "vfio_pci",
            Self::SerialConsole => "serial_console",
        }
    }
}

/// Whether a configuration offers a device. There is no third value: a device the row
/// does not list is absent, never "untested" (line 2669).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceSupport {
    Supported,
    Absent,
}

/// Why a pinned configuration is not accepted into the matrix.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum PinRefusal {
    /// The backend does not run on this OS.
    BackendNotOnOs { backend: SandboxBackend, os: OsKind },
    /// A pin is listed under another component kind than its own.
    PinKindMismatch {
        listed: ComponentKind,
        pinned: ComponentKind,
    },
    /// A required component is not pinned.
    MissingComponent {
        key: ConfigurationKey,
        component: ComponentKind,
    },
    /// Firmware is pinned although the guest boots its kernel directly.
    FirmwareWithoutFirmwareBoot { key: ConfigurationKey },
    /// The configuration is already in the matrix.
    Duplicate { key: ConfigurationKey },
}

impl fmt::Display for PinRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BackendNotOnOs { backend, os } => {
                write!(f, "the {backend} backend does not run on {os}")
            }
            Self::PinKindMismatch { listed, pinned } => {
                write!(f, "a {pinned} pin is listed as {listed}")
            }
            Self::MissingComponent { key, component } => {
                write!(f, "configuration {key} pins no {component}")
            }
            Self::FirmwareWithoutFirmwareBoot { key } => write!(
                f,
                "configuration {key} pins firmware but boots its kernel directly"
            ),
            Self::Duplicate { key } => write!(f, "configuration {key} is already pinned"),
        }
    }
}

impl std::error::Error for PinRefusal {}

/// One row of the matrix: everything one configuration runs, pinned.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedConfiguration {
    pub key: ConfigurationKey,
    pub boot: BootMethod,
    pub components: BTreeMap<ComponentKind, ComponentPin>,
    pub devices: BTreeSet<DeviceModel>,
}

impl PinnedConfiguration {
    /// Checks the row: the backend runs on the OS, every pin is listed under its own
    /// kind, runtime, guest kernel and guest image are pinned, and firmware is pinned
    /// exactly when the guest boots through firmware. The guest initrd and profile are
    /// optional here; a guest release that has them needs a row that pins them.
    pub fn check(&self) -> Result<(), PinRefusal> {
        self.key.hypervisor()?;
        for (listed, pin) in &self.components {
            if *listed != pin.kind {
                return Err(PinRefusal::PinKindMismatch {
                    listed: *listed,
                    pinned: pin.kind,
                });
            }
        }
        let mut required = vec![
            ComponentKind::Runtime,
            ComponentKind::GuestKernel,
            ComponentKind::GuestImage,
        ];
        match self.boot {
            BootMethod::Firmware => required.push(ComponentKind::Firmware),
            BootMethod::DirectKernel => {
                if self.components.contains_key(&ComponentKind::Firmware) {
                    return Err(PinRefusal::FirmwareWithoutFirmwareBoot { key: self.key });
                }
            }
        }
        for component in required {
            if !self.components.contains_key(&component) {
                return Err(PinRefusal::MissingComponent {
                    key: self.key,
                    component,
                });
            }
        }
        Ok(())
    }

    pub fn component(&self, kind: ComponentKind) -> Option<&ComponentPin> {
        self.components.get(&kind)
    }

    /// Supported if listed; absent otherwise.
    pub fn device_support(&self, device: DeviceModel) -> DeviceSupport {
        if self.devices.contains(&device) {
            DeviceSupport::Supported
        } else {
            DeviceSupport::Absent
        }
    }

    /// The CORE-01 configuration fingerprint of this exact row: OS, architecture,
    /// backend, boot method, every component's version and content key, and the device
    /// set. Evidence observed under another fingerprint does not apply to this row.
    pub fn fingerprint(&self) -> Result<ConfigurationFingerprint, FingerprintError> {
        let mut settings: Vec<(String, String)> = vec![
            ("os".to_owned(), self.key.os.tag().to_owned()),
            (
                "architecture".to_owned(),
                self.key.architecture.tag().to_owned(),
            ),
            ("backend".to_owned(), self.key.backend.tag().to_owned()),
            ("boot".to_owned(), self.boot.tag().to_owned()),
        ];
        for (kind, pin) in &self.components {
            settings.push((
                format!("component.{}", kind.tag()),
                format!("{}@{}", pin.version, pin.content_key),
            ));
        }
        let devices: Vec<&str> = self.devices.iter().map(|device| device.tag()).collect();
        settings.push(("devices".to_owned(), devices.join(",")));
        ConfigurationFingerprint::from_settings(
            settings
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str())),
        )
    }
}

/// An advisory identifier such as `CVE-2026-12345` or `GHSA-xxxx`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct AdvisoryId(String);

impl AdvisoryId {
    pub fn new(value: impl Into<String>) -> Result<Self, IdError> {
        let value = value.into();
        validate_identifier(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AdvisoryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AdvisoryId({})", self.0)
    }
}

impl fmt::Display for AdvisoryId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for AdvisoryId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// The owner of a decision or exception: a team or role identifier, never free text.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct Owner(String);

impl Owner {
    pub fn new(value: impl Into<String>) -> Result<Self, IdError> {
        let value = value.into();
        validate_identifier(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Owner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Owner({})", self.0)
    }
}

impl fmt::Display for Owner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Owner {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// How a known vulnerability is handled in one configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Mitigation {
    /// The pinned component moved to a fixed version.
    Patched { fixed_in: ComponentVersion },
    /// The vulnerable code is not reached in this configuration; `reason` says why.
    NotAffected { reason: String },
    /// A configuration control blocks exploitation; `control` names it.
    Mitigated { control: String },
    /// Accepted under a time-limited exception of the governance (VM-W47).
    Excepted { exception: ExceptionId },
}

/// A recorded decision about a known vulnerability: the affected configuration and
/// component, the mitigation and the owner (line 2669).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnownVulnerabilityDecision {
    pub advisory: AdvisoryId,
    pub affected: ConfigurationKey,
    pub component: ComponentKind,
    pub component_version: ComponentVersion,
    pub mitigation: Mitigation,
    pub owner: Owner,
    pub decided_at: UnixSeconds,
}

/// Why the matrix refused a lookup or a decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MatrixRefusal {
    /// Not in the matrix: unsupported, not untested.
    Unsupported {
        key: ConfigurationKey,
    },
    /// A decision names a configuration the matrix does not pin.
    UnknownConfiguration {
        key: ConfigurationKey,
    },
    /// A decision names a component the configuration does not pin.
    ComponentNotPinned {
        key: ConfigurationKey,
        component: ComponentKind,
    },
    /// A decision is about another version than the pinned one.
    VersionNotPinned {
        key: ConfigurationKey,
        component: ComponentKind,
        pinned: ComponentVersion,
        decided: ComponentVersion,
    },
    /// A decision's free text is empty or longer than [`MAX_TEXT_BYTES`].
    BadText {
        field: &'static str,
    },
    Pin {
        refusal: PinRefusal,
    },
}

impl fmt::Display for MatrixRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported { key } => write!(f, "configuration {key} is not supported"),
            Self::UnknownConfiguration { key } => {
                write!(f, "configuration {key} is not in the matrix")
            }
            Self::ComponentNotPinned { key, component } => {
                write!(f, "configuration {key} pins no {component}")
            }
            Self::VersionNotPinned {
                key,
                component,
                pinned,
                decided,
            } => write!(
                f,
                "configuration {key} pins {component} {pinned}, and the decision is about {decided}"
            ),
            Self::BadText { field } => {
                write!(f, "{field} must be 1 to {MAX_TEXT_BYTES} bytes")
            }
            Self::Pin { refusal } => write!(f, "{refusal}"),
        }
    }
}

impl std::error::Error for MatrixRefusal {}

/// The compatibility and patch matrix: pinned rows and the decisions about them.
#[derive(Debug, Default)]
pub struct ConfigurationMatrix {
    rows: BTreeMap<ConfigurationKey, PinnedConfiguration>,
    decisions: Vec<KnownVulnerabilityDecision>,
}

impl ConfigurationMatrix {
    /// An empty matrix: nothing is supported until pinned.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a checked row; a configuration is pinned once.
    pub fn pin(&mut self, row: PinnedConfiguration) -> Result<(), MatrixRefusal> {
        row.check()
            .map_err(|refusal| MatrixRefusal::Pin { refusal })?;
        if self.rows.contains_key(&row.key) {
            return Err(MatrixRefusal::Pin {
                refusal: PinRefusal::Duplicate { key: row.key },
            });
        }
        self.rows.insert(row.key, row);
        Ok(())
    }

    /// The row for `key`, or the typed refusal that it is unsupported.
    pub fn lookup(&self, key: &ConfigurationKey) -> Result<&PinnedConfiguration, MatrixRefusal> {
        self.rows
            .get(key)
            .ok_or(MatrixRefusal::Unsupported { key: *key })
    }

    pub fn rows(&self) -> impl Iterator<Item = &PinnedConfiguration> {
        self.rows.values()
    }

    /// Records a decision; it must name a pinned configuration, a component that row
    /// pins, at the version pinned there.
    pub fn record_decision(
        &mut self,
        decision: KnownVulnerabilityDecision,
    ) -> Result<(), MatrixRefusal> {
        let row = self
            .rows
            .get(&decision.affected)
            .ok_or(MatrixRefusal::UnknownConfiguration {
                key: decision.affected,
            })?;
        let pin = row
            .component(decision.component)
            .ok_or(MatrixRefusal::ComponentNotPinned {
                key: decision.affected,
                component: decision.component,
            })?;
        if pin.version != decision.component_version {
            return Err(MatrixRefusal::VersionNotPinned {
                key: decision.affected,
                component: decision.component,
                pinned: pin.version.clone(),
                decided: decision.component_version.clone(),
            });
        }
        let text = match &decision.mitigation {
            Mitigation::NotAffected { reason } => Some(("reason", reason)),
            Mitigation::Mitigated { control } => Some(("control", control)),
            Mitigation::Patched { .. } | Mitigation::Excepted { .. } => None,
        };
        if let Some((field, text)) = text {
            if text.is_empty() || text.len() > MAX_TEXT_BYTES {
                return Err(MatrixRefusal::BadText { field });
            }
        }
        self.decisions.push(decision);
        Ok(())
    }

    /// The decisions recorded for `key`, oldest first.
    pub fn decisions_for(&self, key: &ConfigurationKey) -> Vec<&KnownVulnerabilityDecision> {
        self.decisions
            .iter()
            .filter(|decision| decision.affected == *key)
            .collect()
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::foundation::ids::digest;

    pub(crate) fn inputs(seed: &str) -> BuildInputs {
        BuildInputs {
            source: CommitHash::new("a".repeat(40)).unwrap(),
            toolchain: digest("yougori/test/toolchain/v1", &[seed.as_bytes()]),
            configuration: digest("yougori/test/config/v1", &[seed.as_bytes()]),
            builder: digest("yougori/test/builder/v1", &[seed.as_bytes()]),
        }
    }

    pub(crate) fn pin(kind: ComponentKind, version: &str, bytes: &[u8]) -> ComponentPin {
        ComponentPin {
            kind,
            version: ComponentVersion::new(version).unwrap(),
            content_key: ContentKey::of(bytes),
            length_bytes: bytes.len() as u64,
            build: inputs(version),
        }
    }

    pub(crate) fn linux_firecracker() -> ConfigurationKey {
        ConfigurationKey {
            os: OsKind::Linux,
            architecture: Architecture::X86_64,
            backend: SandboxBackend::Firecracker,
        }
    }

    pub(crate) fn row(key: ConfigurationKey) -> PinnedConfiguration {
        PinnedConfiguration {
            key,
            boot: BootMethod::DirectKernel,
            components: BTreeMap::from([
                (
                    ComponentKind::Runtime,
                    pin(ComponentKind::Runtime, "firecracker-1.10.1", b"fc"),
                ),
                (
                    ComponentKind::GuestKernel,
                    pin(ComponentKind::GuestKernel, "6.6.52", b"kernel"),
                ),
                (
                    ComponentKind::GuestImage,
                    pin(ComponentKind::GuestImage, "rootfs-2026.10", b"rootfs"),
                ),
            ]),
            devices: BTreeSet::from([
                DeviceModel::VirtioNet,
                DeviceModel::VirtioBlk,
                DeviceModel::VirtioVsock,
            ]),
        }
    }

    #[test]
    fn an_unsupported_configuration_is_absent_not_untested() {
        let mut matrix = ConfigurationMatrix::new();
        matrix.pin(row(linux_firecracker())).unwrap();
        let windows_hcs = ConfigurationKey {
            os: OsKind::Windows,
            architecture: Architecture::X86_64,
            backend: SandboxBackend::Hcs,
        };
        assert_eq!(
            matrix.lookup(&windows_hcs).map(|_| ()),
            Err(MatrixRefusal::Unsupported { key: windows_hcs })
        );
        let pinned = matrix.lookup(&linux_firecracker()).unwrap();
        assert_eq!(
            pinned.device_support(DeviceModel::VirtioNet),
            DeviceSupport::Supported
        );
        assert_eq!(
            pinned.device_support(DeviceModel::VfioPci),
            DeviceSupport::Absent
        );
        assert_eq!(matrix.rows().count(), 1);
        assert_eq!(
            matrix.pin(row(linux_firecracker())),
            Err(MatrixRefusal::Pin {
                refusal: PinRefusal::Duplicate {
                    key: linux_firecracker()
                }
            })
        );
    }

    #[test]
    fn a_backend_runs_only_where_it_runs() {
        let bad = ConfigurationKey {
            os: OsKind::Windows,
            architecture: Architecture::X86_64,
            backend: SandboxBackend::Firecracker,
        };
        assert_eq!(
            bad.hypervisor(),
            Err(PinRefusal::BackendNotOnOs {
                backend: SandboxBackend::Firecracker,
                os: OsKind::Windows
            })
        );
        assert_eq!(linux_firecracker().hypervisor(), Ok(HypervisorKind::Kvm));
        assert_eq!(
            SandboxBackend::QemuSecure.hypervisor_on(OsKind::Windows),
            Some(HypervisorKind::Whpx)
        );
        assert_eq!(
            SandboxBackend::QemuSecure.hypervisor_on(OsKind::MacOs),
            Some(HypervisorKind::Hvf)
        );
        assert_eq!(SandboxBackend::Vz.hypervisor_on(OsKind::Linux), None);
        assert_eq!(
            SandboxBackend::Hcs.hypervisor_on(OsKind::Windows),
            Some(HypervisorKind::Hcs)
        );
        for backend in SandboxBackend::ALL {
            assert_eq!(backend.hypervisor_on(OsKind::Wsl2), None);
        }
        let mut matrix = ConfigurationMatrix::new();
        assert_eq!(
            matrix.pin(row(bad)),
            Err(MatrixRefusal::Pin {
                refusal: PinRefusal::BackendNotOnOs {
                    backend: SandboxBackend::Firecracker,
                    os: OsKind::Windows
                }
            })
        );
        assert_eq!(bad.to_string(), "windows/x86_64/firecracker");
    }

    #[test]
    fn every_required_component_is_pinned_and_firmware_follows_the_boot_method() {
        let mut missing = row(linux_firecracker());
        missing.components.remove(&ComponentKind::GuestKernel);
        assert_eq!(
            missing.check(),
            Err(PinRefusal::MissingComponent {
                key: linux_firecracker(),
                component: ComponentKind::GuestKernel
            })
        );

        let mut firmware_boot = row(linux_firecracker());
        firmware_boot.boot = BootMethod::Firmware;
        assert_eq!(
            firmware_boot.check(),
            Err(PinRefusal::MissingComponent {
                key: linux_firecracker(),
                component: ComponentKind::Firmware
            })
        );
        firmware_boot.components.insert(
            ComponentKind::Firmware,
            pin(ComponentKind::Firmware, "ovmf-2024.08", b"ovmf"),
        );
        assert_eq!(firmware_boot.check(), Ok(()));

        let mut stray_firmware = row(linux_firecracker());
        stray_firmware.components.insert(
            ComponentKind::Firmware,
            pin(ComponentKind::Firmware, "ovmf-2024.08", b"ovmf"),
        );
        assert_eq!(
            stray_firmware.check(),
            Err(PinRefusal::FirmwareWithoutFirmwareBoot {
                key: linux_firecracker()
            })
        );

        let mut mislisted = row(linux_firecracker());
        mislisted.components.insert(
            ComponentKind::Helper,
            pin(ComponentKind::Jailer, "jailer-1.10.1", b"jailer"),
        );
        assert_eq!(
            mislisted.check(),
            Err(PinRefusal::PinKindMismatch {
                listed: ComponentKind::Helper,
                pinned: ComponentKind::Jailer
            })
        );
    }

    #[test]
    fn the_fingerprint_changes_with_any_pinned_byte_or_device() {
        let base = row(linux_firecracker());
        let fingerprint = base.fingerprint().unwrap();
        assert_eq!(base.fingerprint().unwrap(), fingerprint);

        let mut other_kernel = base.clone();
        other_kernel.components.insert(
            ComponentKind::GuestKernel,
            pin(ComponentKind::GuestKernel, "6.6.52", b"kernel-rebuilt"),
        );
        assert_ne!(other_kernel.fingerprint().unwrap(), fingerprint);

        let mut other_device = base.clone();
        other_device.devices.insert(DeviceModel::VirtioRng);
        assert_ne!(other_device.fingerprint().unwrap(), fingerprint);

        let mut other_boot = base;
        other_boot.boot = BootMethod::Firmware;
        assert_ne!(other_boot.fingerprint().unwrap(), fingerprint);

        assert_ne!(inputs("a").digest(), inputs("b").digest());
        assert_eq!(inputs("a").digest(), inputs("a").digest());
    }

    #[test]
    fn a_decision_names_a_pinned_configuration_component_and_version() {
        let mut matrix = ConfigurationMatrix::new();
        matrix.pin(row(linux_firecracker())).unwrap();
        let decision = |component: ComponentKind, version: &str, affected: ConfigurationKey| {
            KnownVulnerabilityDecision {
                advisory: AdvisoryId::new("CVE-2026-0001").unwrap(),
                affected,
                component,
                component_version: ComponentVersion::new(version).unwrap(),
                mitigation: Mitigation::NotAffected {
                    reason: "the vulnerable driver is not built into the guest kernel".to_owned(),
                },
                owner: Owner::new("release-team").unwrap(),
                decided_at: UnixSeconds::new(1_700_000_000),
            }
        };
        let other = ConfigurationKey {
            os: OsKind::MacOs,
            architecture: Architecture::Aarch64,
            backend: SandboxBackend::Vz,
        };
        assert_eq!(
            matrix.record_decision(decision(ComponentKind::GuestKernel, "6.6.52", other)),
            Err(MatrixRefusal::UnknownConfiguration { key: other })
        );
        assert_eq!(
            matrix.record_decision(decision(
                ComponentKind::Firmware,
                "6.6.52",
                linux_firecracker()
            )),
            Err(MatrixRefusal::ComponentNotPinned {
                key: linux_firecracker(),
                component: ComponentKind::Firmware
            })
        );
        assert_eq!(
            matrix.record_decision(decision(
                ComponentKind::GuestKernel,
                "6.6.51",
                linux_firecracker()
            )),
            Err(MatrixRefusal::VersionNotPinned {
                key: linux_firecracker(),
                component: ComponentKind::GuestKernel,
                pinned: ComponentVersion::new("6.6.52").unwrap(),
                decided: ComponentVersion::new("6.6.51").unwrap(),
            })
        );
        let mut empty = decision(ComponentKind::GuestKernel, "6.6.52", linux_firecracker());
        empty.mitigation = Mitigation::Mitigated {
            control: String::new(),
        };
        assert_eq!(
            matrix.record_decision(empty),
            Err(MatrixRefusal::BadText { field: "control" })
        );
        matrix
            .record_decision(decision(
                ComponentKind::GuestKernel,
                "6.6.52",
                linux_firecracker(),
            ))
            .unwrap();
        let recorded = matrix.decisions_for(&linux_firecracker());
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].owner.as_str(), "release-team");
        assert!(matrix.decisions_for(&other).is_empty());
    }

    #[test]
    fn rows_and_decisions_refuse_unknown_fields() {
        let json = serde_json::to_value(row(linux_firecracker())).unwrap();
        assert_eq!(
            serde_json::from_value::<PinnedConfiguration>(json.clone()).unwrap(),
            row(linux_firecracker())
        );
        let mut extra = json;
        extra["tested"] = serde_json::json!(true);
        assert!(serde_json::from_value::<PinnedConfiguration>(extra).is_err());
        assert!(Owner::new("").is_err());
        assert!(AdvisoryId::new("CVE 2026").is_err());
        assert!(ComponentVersion::new("1.0/2").is_err());
        assert_eq!(
            serde_json::to_value(DeviceSupport::Absent).unwrap(),
            serde_json::json!("absent")
        );
    }

    /// A row as written before the guest initrd and profile kinds existed, by hand.
    fn older_row() -> serde_json::Value {
        let pin = |kind: &str, version: &str, key: char, length: u64| {
            serde_json::json!({
                "kind": kind,
                "version": version,
                "content_key": key.to_string().repeat(64),
                "length_bytes": length,
                "build": {
                    "source": "a".repeat(40),
                    "toolchain": "1".repeat(64),
                    "configuration": "2".repeat(64),
                    "builder": "3".repeat(64),
                },
            })
        };
        serde_json::json!({
            "key": {"os": "linux", "architecture": "x86_64", "backend": "firecracker"},
            "boot": "direct_kernel",
            "components": {
                "runtime": pin("runtime", "firecracker-1.10.1", 'b', 2),
                "guest_kernel": pin("guest_kernel", "6.6.52", 'c', 6),
                "guest_image": pin("guest_image", "rootfs-2026.10", 'd', 6),
            },
            "devices": ["virtio_blk", "virtio_vsock"],
        })
    }

    #[test]
    fn an_older_row_without_the_initrd_and_profile_kinds_still_reads() {
        let older = older_row();
        let row: PinnedConfiguration = serde_json::from_value(older.clone()).unwrap();
        assert_eq!(row.check(), Ok(()));
        assert!(row.component(ComponentKind::GuestInitrd).is_none());
        assert!(row.component(ComponentKind::GuestProfile).is_none());
        // It writes back as the same document: nothing new appears in it.
        assert_eq!(serde_json::to_value(&row).unwrap(), older);
        // Its fingerprint is over what it pins, as before the two kinds existed.
        let key = |digit: char| digit.to_string().repeat(64);
        let settings = [
            ("os", "linux".to_owned()),
            ("architecture", "x86_64".to_owned()),
            ("backend", "firecracker".to_owned()),
            ("boot", "direct_kernel".to_owned()),
            (
                "component.runtime",
                format!("firecracker-1.10.1@{}", key('b')),
            ),
            ("component.guest_kernel", format!("6.6.52@{}", key('c'))),
            (
                "component.guest_image",
                format!("rootfs-2026.10@{}", key('d')),
            ),
            ("devices", "virtio_blk,virtio_vsock".to_owned()),
        ];
        assert_eq!(
            row.fingerprint().unwrap(),
            ConfigurationFingerprint::from_settings(
                settings.iter().map(|(name, value)| (*name, value.as_str()))
            )
            .unwrap()
        );
        let mut matrix = ConfigurationMatrix::new();
        assert_eq!(matrix.pin(row), Ok(()));
    }

    #[test]
    fn a_row_pins_the_guest_initrd_and_profile_under_their_own_names() {
        assert_eq!(
            ComponentKind::ALL[..6]
                .iter()
                .map(|kind| kind.tag())
                .collect::<Vec<_>>(),
            [
                "runtime",
                "jailer",
                "guest_kernel",
                "guest_image",
                "firmware",
                "helper"
            ]
        );
        for kind in ComponentKind::ALL {
            let json = serde_json::to_value(kind).unwrap();
            assert_eq!(json, serde_json::json!(kind.tag()));
            assert_eq!(serde_json::from_value::<ComponentKind>(json).unwrap(), kind);
            assert_eq!(kind.to_string(), kind.tag());
        }
        assert!(serde_json::from_value::<ComponentKind>(serde_json::json!("initrd")).is_err());

        let base = row(linux_firecracker());
        let mut guest = base.clone();
        guest.components.insert(
            ComponentKind::GuestInitrd,
            pin(ComponentKind::GuestInitrd, "6.6.52", b"initramfs"),
        );
        guest.components.insert(
            ComponentKind::GuestProfile,
            pin(ComponentKind::GuestProfile, "profile-1", b"profile"),
        );
        assert_eq!(guest.check(), Ok(()));
        assert_eq!(
            serde_json::from_value::<PinnedConfiguration>(serde_json::to_value(&guest).unwrap())
                .unwrap(),
            guest
        );
        assert_ne!(guest.fingerprint().unwrap(), base.fingerprint().unwrap());
        let mut other_initrd = guest.clone();
        other_initrd.components.insert(
            ComponentKind::GuestInitrd,
            pin(ComponentKind::GuestInitrd, "6.6.52", b"initramfs-rebuilt"),
        );
        assert_ne!(
            other_initrd.fingerprint().unwrap(),
            guest.fingerprint().unwrap()
        );

        // Firmware boot takes them too.
        let mut firmware = guest.clone();
        firmware.boot = BootMethod::Firmware;
        firmware.components.insert(
            ComponentKind::Firmware,
            pin(ComponentKind::Firmware, "ovmf-2024.08", b"ovmf"),
        );
        assert_eq!(firmware.check(), Ok(()));

        let mut mislisted = base;
        mislisted.components.insert(
            ComponentKind::GuestInitrd,
            pin(ComponentKind::GuestProfile, "profile-1", b"profile"),
        );
        assert_eq!(
            mislisted.check(),
            Err(PinRefusal::PinKindMismatch {
                listed: ComponentKind::GuestInitrd,
                pinned: ComponentKind::GuestProfile
            })
        );

        // A decision about the initrd names a row that pins one.
        let mut matrix = ConfigurationMatrix::new();
        matrix.pin(guest).unwrap();
        let decision = KnownVulnerabilityDecision {
            advisory: AdvisoryId::new("CVE-2026-0002").unwrap(),
            affected: linux_firecracker(),
            component: ComponentKind::GuestInitrd,
            component_version: ComponentVersion::new("6.6.52").unwrap(),
            mitigation: Mitigation::NotAffected {
                reason: "the initrd does not ship the vulnerable tool".to_owned(),
            },
            owner: Owner::new("release-team").unwrap(),
            decided_at: UnixSeconds::new(1_700_000_000),
        };
        assert_eq!(matrix.record_decision(decision.clone()), Ok(()));
        let mut plain = ConfigurationMatrix::new();
        plain.pin(row(linux_firecracker())).unwrap();
        assert_eq!(
            plain.record_decision(decision),
            Err(MatrixRefusal::ComponentNotPinned {
                key: linux_firecracker(),
                component: ComponentKind::GuestInitrd
            })
        );
    }
}
