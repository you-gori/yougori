//! The deployment facets of VM part §1.3 (lines 1893–1908): explicit required and
//! observed properties in place of a numbered security ladder.
//!
//! Each facet has a required value, stated by the policy layer in
//! [`RequiredProperties`], and an observed value the host supplies. The rules that decide
//! whether an observation satisfies a requirement live in `checks.rs`; this file only
//! names the values.

use std::collections::BTreeSet;
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::foundation::ids::{Digest, GpuDeviceKey};

/// The eight facets of §1.3 (lines 1897–1906).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Facet {
    Isolation,
    HypervisorConfinement,
    NetworkAuthority,
    CredentialExposure,
    Persistence,
    DeviceExposure,
    OperatorConfidentiality,
    Evidence,
}

impl Facet {
    /// Every facet, in the order of the §1.3 table.
    pub const ALL: [Self; 8] = [
        Self::Isolation,
        Self::HypervisorConfinement,
        Self::NetworkAuthority,
        Self::CredentialExposure,
        Self::Persistence,
        Self::DeviceExposure,
        Self::OperatorConfidentiality,
        Self::Evidence,
    ];

    /// The stable tag used in digests.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Isolation => "isolation",
            Self::HypervisorConfinement => "hypervisor_confinement",
            Self::NetworkAuthority => "network_authority",
            Self::CredentialExposure => "credential_exposure",
            Self::Persistence => "persistence",
            Self::DeviceExposure => "device_exposure",
            Self::OperatorConfidentiality => "operator_confidentiality",
            Self::Evidence => "evidence",
        }
    }
}

impl fmt::Display for Facet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Isolation => "isolation",
            Self::HypervisorConfinement => "hypervisor confinement",
            Self::NetworkAuthority => "network authority",
            Self::CredentialExposure => "credential exposure",
            Self::Persistence => "persistence",
            Self::DeviceExposure => "device exposure",
            Self::OperatorConfidentiality => "operator confidentiality",
            Self::Evidence => "evidence",
        })
    }
}

/// Whether the physical host runs one tenant's sandboxes or several (§1.3 isolation
/// facet, line 1899). Declared weakest first: a dedicated host satisfies a requirement
/// for a shared one, never the reverse.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhysicalHost {
    Shared,
    Dedicated,
}

impl PhysicalHost {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Shared => "shared",
            Self::Dedicated => "dedicated",
        }
    }
}

impl fmt::Display for PhysicalHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Shared => "shared physical host",
            Self::Dedicated => "dedicated physical host",
        })
    }
}

/// The required isolation (§1.3 line 1899). An own guest kernel and a hardware
/// accelerator are required by every production profile (line 1908, "All production
/// sandbox profiles require a VM"), so only the physical host is a choice.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IsolationRequirement {
    pub physical_host: PhysicalHost,
}

/// What the host observed about a VM's isolation (§1.3 line 1899). The accelerator is
/// observed separately as [`Accelerator`](super::Accelerator).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IsolationObservation {
    /// The guest runs its own kernel; a shared WSL kernel, provider container, gVisor
    /// process or host process does not (§0, line 1811).
    pub own_guest_kernel: bool,
    pub physical_host: PhysicalHost,
}

/// A control the hypervisor process runs under (§1.3 line 1900: account/process
/// identity; filesystem limits; syscall/OS restrictions; resource controls).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfinementControl {
    /// A distinct account identity for the hypervisor process.
    AccountIdentity,
    /// A restricted process identity: restricted token, Job or equivalent.
    ProcessIdentity,
    FilesystemLimits,
    SyscallRestrictions,
    OsRestrictions,
    ResourceControls,
}

impl ConfinementControl {
    pub const ALL: [Self; 6] = [
        Self::AccountIdentity,
        Self::ProcessIdentity,
        Self::FilesystemLimits,
        Self::SyscallRestrictions,
        Self::OsRestrictions,
        Self::ResourceControls,
    ];

    pub const fn tag(self) -> &'static str {
        match self {
            Self::AccountIdentity => "account_identity",
            Self::ProcessIdentity => "process_identity",
            Self::FilesystemLimits => "filesystem_limits",
            Self::SyscallRestrictions => "syscall_restrictions",
            Self::OsRestrictions => "os_restrictions",
            Self::ResourceControls => "resource_controls",
        }
    }

    /// Every control, as a set.
    pub fn all() -> BTreeSet<Self> {
        Self::ALL.into_iter().collect()
    }
}

/// A channel through which a sandbox may reach the outside (§1.3 line 1901: named
/// transport routes; typed credentialed operations; published service). No channel at
/// all is offline.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkChannel {
    /// Owner-selected outbound networking through the VM's NAT adapter.
    Internet,
    NamedTransportRoutes,
    TypedCredentialedOperations,
    PublishedService,
}

impl NetworkChannel {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Internet => "internet",
            Self::NamedTransportRoutes => "named_transport_routes",
            Self::TypedCredentialedOperations => "typed_credentialed_operations",
            Self::PublishedService => "published_service",
        }
    }
}

/// The network authority a sandbox has (§1.3 line 1901): the set of channels the host
/// enforces or permits. A requirement is the most a sandbox may have; an observation is
/// what the host enforces.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkAuthority {
    pub channels: BTreeSet<NetworkChannel>,
}

impl NetworkAuthority {
    /// No channel: offline.
    pub fn offline() -> Self {
        Self::default()
    }

    pub fn of(channels: impl IntoIterator<Item = NetworkChannel>) -> Self {
        Self {
            channels: channels.into_iter().collect(),
        }
    }

    pub fn is_offline(&self) -> bool {
        self.channels.is_empty()
    }

    /// Whether every channel here is also in `allowed`.
    pub fn within(&self, allowed: &Self) -> bool {
        self.channels.is_subset(&allowed.channels)
    }
}

/// A kind of credential a sandbox may be exposed to (§1.3 line 1902).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    ExternalProviderCredentials,
    /// Narrowly scoped guest credentials, explicitly permitted.
    NarrowlyScopedGuestCredentials,
    SandboxLocalSecrets,
}

impl CredentialKind {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::ExternalProviderCredentials => "external_provider_credentials",
            Self::NarrowlyScopedGuestCredentials => "narrowly_scoped_guest_credentials",
            Self::SandboxLocalSecrets => "sandbox_local_secrets",
        }
    }
}

/// The credentials a sandbox is exposed to (§1.3 line 1902). A requirement is the most
/// that may be exposed; an observation is what the host found exposed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialExposure {
    pub credentials: BTreeSet<CredentialKind>,
}

impl CredentialExposure {
    /// No credential of any kind.
    pub fn none() -> Self {
        Self::default()
    }

    pub fn of(credentials: impl IntoIterator<Item = CredentialKind>) -> Self {
        Self {
            credentials: credentials.into_iter().collect(),
        }
    }

    /// Whether every credential here is also permitted by `allowed`.
    pub fn within(&self, allowed: &Self) -> bool {
        self.credentials.is_subset(&allowed.credentials)
    }
}

/// What a sandbox keeps across runs (§1.3 line 1903; §1.4 line 1917: task VMs have fresh
/// writable state, service VMs may preserve declared data). Volumes are named by their
/// catalog identities.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Persistence {
    EphemeralTask,
    DeclaredDataVolumes { volumes: BTreeSet<Digest> },
    ControlledServiceRenewal { volumes: BTreeSet<Digest> },
}

impl Persistence {
    /// The volumes the sandbox is allowed to attach; none for an ephemeral task.
    pub fn volumes(&self) -> BTreeSet<Digest> {
        match self {
            Self::EphemeralTask => BTreeSet::new(),
            Self::DeclaredDataVolumes { volumes } | Self::ControlledServiceRenewal { volumes } => {
                volumes.clone()
            }
        }
    }

    pub const fn tag(&self) -> &'static str {
        match self {
            Self::EphemeralTask => "ephemeral_task",
            Self::DeclaredDataVolumes { .. } => "declared_data_volumes",
            Self::ControlledServiceRenewal { .. } => "controlled_service_renewal",
        }
    }
}

/// The devices a VM exposes (§1.3 line 1904: CPU only; display; explicitly assigned GPU).
/// A requirement is the most a sandbox may expose; a device profile states exactly what
/// one VM is built with.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceExposure {
    /// Host-mediated shared GPU access (HCS GPU-PV), distinct from PCI assignment.
    #[serde(default)]
    pub paravirtualized_gpu: bool,
    pub display: bool,
    /// Explicitly assigned GPUs, by the key the ledger and placement share.
    pub gpus: BTreeSet<GpuDeviceKey>,
}

impl DeviceExposure {
    /// CPU only: no display and no GPU.
    pub fn cpu_only() -> Self {
        Self::default()
    }

    pub fn is_cpu_only(&self) -> bool {
        !self.display && !self.paravirtualized_gpu && self.gpus.is_empty()
    }

    /// Whether everything exposed here is also allowed by `allowed`.
    pub fn within(&self, allowed: &Self) -> bool {
        (!self.display || allowed.display) && (!self.paravirtualized_gpu || allowed.paravirtualized_gpu) && self.gpus.is_subset(&allowed.gpus)
    }
}

/// One check of §7.5 (lines 2398–2407) that an assigned GPU's isolation must pass; every
/// one is required (VM-P39, line 2809).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GpuIsolationCheck {
    /// Actual IOMMU and interrupt-remapping enforcement.
    IommuAndInterruptRemapping,
    /// The complete isolation group and all device functions.
    CompleteIsolationGroup,
    /// Safe reset and reassignment behaviour.
    SafeResetAndReassignment,
    /// No host display or other user of the device.
    NoHostDisplayOrOtherUsers,
    /// Driver and guest compatibility.
    DriverAndGuestCompatible,
    /// Firmware and peer-DMA implications and resource controls.
    FirmwarePeerDmaAndResourceControls,
    /// Snapshot and migration limitations recorded.
    SnapshotAndMigrationLimitsRecorded,
    /// No unsafe ACS or IOMMU bypass setting.
    NoUnsafeAcsOrIommuBypass,
}

impl GpuIsolationCheck {
    pub const ALL: [Self; 8] = [
        Self::IommuAndInterruptRemapping,
        Self::CompleteIsolationGroup,
        Self::SafeResetAndReassignment,
        Self::NoHostDisplayOrOtherUsers,
        Self::DriverAndGuestCompatible,
        Self::FirmwarePeerDmaAndResourceControls,
        Self::SnapshotAndMigrationLimitsRecorded,
        Self::NoUnsafeAcsOrIommuBypass,
    ];

    /// Every check, as a set.
    pub fn all() -> BTreeSet<Self> {
        Self::ALL.into_iter().collect()
    }
}

/// A device setting that disqualifies an assignment (§7.5 lines 2407–2409: no unsafe
/// ACS/IOMMU bypass; never copy sample "unsafe interrupts" settings; never the old
/// /dev/vfio/group launch example).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnsafeDeviceSetting {
    UnsafeInterrupts,
    AcsOverride,
    IommuBypass,
    VfioGroupPathLaunch,
}

/// What the host observed about one assigned GPU's isolation (§7.5).
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GpuIsolation {
    pub checks: BTreeSet<GpuIsolationCheck>,
    pub unsafe_settings: BTreeSet<UnsafeDeviceSetting>,
}

impl GpuIsolation {
    /// Every §7.5 check passed and no unsafe setting.
    pub fn complete() -> Self {
        Self {
            checks: GpuIsolationCheck::all(),
            unsafe_settings: BTreeSet::new(),
        }
    }

    /// The §7.5 checks not observed to pass.
    pub fn missing(&self) -> BTreeSet<GpuIsolationCheck> {
        GpuIsolationCheck::all()
            .difference(&self.checks)
            .copied()
            .collect()
    }

    pub fn is_isolated(&self) -> bool {
        self.missing().is_empty() && self.unsafe_settings.is_empty()
    }
}

/// One GPU the host observed assigned to a VM, with its isolation evidence.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedGpu {
    pub device: GpuDeviceKey,
    pub isolation: GpuIsolation,
}

/// The device inventory the host measured on a VM (VM-P02, line 2782: the measured
/// inventory matches the approved profile).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceInventory {
    #[serde(default)]
    pub paravirtualized_gpu: bool,
    pub display: bool,
    pub gpus: BTreeSet<ObservedGpu>,
}

impl DeviceInventory {
    pub fn cpu_only() -> Self {
        Self::default()
    }

    /// The inventory as an exposure, without the isolation evidence.
    pub fn exposure(&self) -> DeviceExposure {
        DeviceExposure {
            paravirtualized_gpu: self.paravirtualized_gpu,
            display: self.display,
            gpus: self.gpus.iter().map(|gpu| gpu.device).collect(),
        }
    }
}

/// Confidentiality from the host's operator (§1.3 line 1905: none, or a verified
/// platform-specific confidential VM with a stated scope). A confidential VM has no
/// better outbound containment by itself (line 1908).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum OperatorConfidentiality {
    None,
    /// A verified confidential VM; `scope` is the digest of the statement of what the
    /// confidentiality covers.
    VerifiedConfidentialVm {
        scope: Digest,
    },
}

impl OperatorConfidentiality {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::VerifiedConfidentialVm { .. } => "verified_confidential_vm",
        }
    }
}

/// The independent perimeter the network facet may ask for (§1.3 network authority, line
/// 1726; §4.4 lines 2153–2165; VM-CP-11 line 3161): a host barrier outside the guest and
/// outside the transport broker, so a compromised broker still cannot reach what the
/// perimeter blocks. When asked for, the launch names the perimeter, the principal its
/// block rules restrict (the transport broker's identity) and every block rule it relies
/// on, and admission needs CORE-01 host-probe evidence that each rule is enforced for that
/// principal ([`perimeter_requirements`](super::perimeter_requirements)).
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PerimeterRequirement {
    /// No independent perimeter is asked for, as in the transport profile without one
    /// (VM-D3, line 3197).
    #[default]
    NotRequired,
    /// An independent perimeter whose block `rules` restrict `principal`; each rule is a
    /// rule digest of the perimeter's profile.
    Independent {
        perimeter: Digest,
        principal: Digest,
        rules: BTreeSet<Digest>,
    },
}

impl PerimeterRequirement {
    pub fn is_required(&self) -> bool {
        !self.is_not_required()
    }

    pub fn is_not_required(&self) -> bool {
        matches!(self, Self::NotRequired)
    }

    pub const fn tag(&self) -> &'static str {
        match self {
            Self::NotRequired => "not_required",
            Self::Independent { .. } => "independent",
        }
    }
}

/// The evidence facet (§1.3 line 1906: backend version; artifact identities; host
/// observations; test results and freshness). Backend and artifact identities are
/// pinned by the launch request; host observations are required of every other facet;
/// this states how fresh they must be. Only a host probe ever satisfies a facet (CORE-01;
/// VM-W09, line 2594), so no weaker source class can be chosen here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRequirement {
    /// The oldest a host observation may be when the launch is decided.
    pub max_age: Duration,
}

/// The required properties of one sandbox: one value per §1.3 facet.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredProperties {
    pub isolation: IsolationRequirement,
    /// The controls the hypervisor process must at least run under.
    pub confinement: BTreeSet<ConfinementControl>,
    /// The most network authority the sandbox may have.
    pub network: NetworkAuthority,
    /// The most credential exposure the sandbox may have.
    pub credentials: CredentialExposure,
    pub persistence: Persistence,
    /// The most the sandbox may expose.
    pub devices: DeviceExposure,
    pub confidentiality: OperatorConfidentiality,
    pub evidence: EvidenceRequirement,
    /// Whether the network facet asks for an independent perimeter (§4.4), with the
    /// perimeter, principal and block rules the launch relies on. Left out of the
    /// serialized form when none is asked for, so the records of such launches keep their
    /// identity.
    #[serde(default, skip_serializing_if = "PerimeterRequirement::is_not_required")]
    pub perimeter: PerimeterRequirement,
    /// The endpoints the guest may address by name over the link's egress channel (the
    /// relay's route table names the same endpoints; VM part §3.1). The guest learns them
    /// at boot and maps each to a loopback address of its own. Left out of the serialized
    /// form when none is declared, so the records of such launches keep their identity.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub declared_endpoints: Vec<GuestEgressEndpoint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_image: Option<crate::sandbox_contract::oci::WorkloadImage>,
}

/// The most endpoints one launch declares: each gets a loopback address of its own in the
/// guest (`127.0.0.2` upward).
pub const MAX_GUEST_EGRESS_ENDPOINTS: usize = 32;

/// The longest endpoint name: the link's name rules (1–128 letters, digits, `.`, `_`
/// or `-`, starting with a letter).
pub const MAX_ENDPOINT_NAME_CHARS: usize = 128;

/// The longest destination host name.
pub const MAX_ENDPOINT_HOST_CHARS: usize = 253;

/// One endpoint the guest may address by name: the name (the guest-facing endpoint and the
/// relay's route id), the destination host name the guest's requests must name, and its
/// port (the `Host` header's port, 443 by default). No address, no credential.
///
/// A sandbox connection endpoint (M14, [`EndpointKind::Connection`]) is a name the guest's
/// programs reach on the port they use (any TCP protocol); its bytes go, unparsed, to the
/// service of another sandbox a grant joins it to, through the connection gate, and nowhere
/// without one.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestEgressEndpoint {
    name: String,
    host: String,
    port: u16,
    /// Left out of the serialized form for a route, so earlier launch records keep their
    /// identity.
    #[serde(default, skip_serializing_if = "EndpointKind::is_route")]
    kind: EndpointKind,
}

/// What a guest endpoint leads to.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum EndpointKind {
    /// A relay route: the guest speaks plain HTTP on port 80 and the relay carries the
    /// request on to `host:port`.
    #[default]
    Route,
    /// A sandbox connection: the guest's programs reach `host` (the endpoint's name) on
    /// `port` itself.
    Connection,
}

impl EndpointKind {
    pub const fn is_route(&self) -> bool {
        matches!(self, Self::Route)
    }
}

/// Why an endpoint declaration was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EndpointError {
    Name { detail: &'static str },
    Host { detail: &'static str },
    Port,
    TooMany { count: usize, max: usize },
    Duplicate { name: String },
}

impl fmt::Display for EndpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name { detail } => write!(f, "the endpoint name is refused: {detail}"),
            Self::Host { detail } => write!(f, "the endpoint host is refused: {detail}"),
            Self::Port => f.write_str("the endpoint port must be 1 to 65535"),
            Self::TooMany { count, max } => {
                write!(f, "{count} endpoints are declared; at most {max} may be")
            }
            Self::Duplicate { name } => write!(f, "the endpoint {name} is declared twice"),
        }
    }
}

impl std::error::Error for EndpointError {}

impl GuestEgressEndpoint {
    pub fn new(name: &str, host: &str, port: u16) -> Result<Self, EndpointError> {
        let name_ok = !name.is_empty()
            && name.len() <= MAX_ENDPOINT_NAME_CHARS
            && name.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
        if !name_ok {
            return Err(EndpointError::Name {
                detail: "1 to 128 letters, digits, '.', '_' or '-', starting with a letter",
            });
        }
        let labels: Vec<&str> = host.split('.').collect();
        let host_ok = !host.is_empty()
            && host.len() <= MAX_ENDPOINT_HOST_CHARS
            && labels.iter().all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            });
        if !host_ok {
            return Err(EndpointError::Host {
                detail: "a host name of 1 to 253 characters in labels of letters, digits and '-'",
            });
        }
        if port == 0 {
            return Err(EndpointError::Port);
        }
        Ok(Self {
            name: name.to_owned(),
            host: host.to_ascii_lowercase(),
            port,
            kind: EndpointKind::Route,
        })
    }

    /// A sandbox connection endpoint: `name` is also the host name the guest's programs
    /// use, so it is one DNS label (letters, digits and '-', starting with a letter), and
    /// `port` the port they connect to.
    pub fn connection(name: &str, port: u16) -> Result<Self, EndpointError> {
        let label = !name.is_empty()
            && name.len() <= 63
            && name.starts_with(|c: char| c.is_ascii_alphabetic())
            && !name.ends_with('-')
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
        if !label {
            return Err(EndpointError::Name {
                detail: "a connection endpoint is one host name label: 1 to 63 letters, digits or '-', starting with a letter",
            });
        }
        let mut endpoint = Self::new(name, name, port)?;
        endpoint.name = endpoint.host.clone();
        endpoint.kind = EndpointKind::Connection;
        Ok(endpoint)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn kind(&self) -> EndpointKind {
        self.kind
    }
}

/// Checks a declaration as a whole: the count and distinct names.
pub fn check_endpoints(endpoints: &[GuestEgressEndpoint]) -> Result<(), EndpointError> {
    if endpoints.len() > MAX_GUEST_EGRESS_ENDPOINTS {
        return Err(EndpointError::TooMany {
            count: endpoints.len(),
            max: MAX_GUEST_EGRESS_ENDPOINTS,
        });
    }
    let mut names = BTreeSet::new();
    for endpoint in endpoints {
        if !names.insert(endpoint.name.as_str()) {
            return Err(EndpointError::Duplicate {
                name: endpoint.name.clone(),
            });
        }
    }
    Ok(())
}

/// The file the guest reads through fw_cfg (`opt/yougori/egress-endpoints`): one line per
/// endpoint, `name host port` for a route and `name host port connection` for a sandbox
/// connection endpoint, in declaration order, which fixes each endpoint's loopback address
/// (`127.0.0.2` for the first). Empty when nothing is declared.
pub fn guest_endpoints_file(endpoints: &[GuestEgressEndpoint]) -> Vec<u8> {
    let mut text = String::new();
    for endpoint in endpoints {
        let kind = match endpoint.kind {
            EndpointKind::Route => "",
            EndpointKind::Connection => " connection",
        };
        text.push_str(&format!(
            "{} {} {}{kind}\n",
            endpoint.name, endpoint.host, endpoint.port
        ));
    }
    text.into_bytes()
}

impl RequiredProperties {
    /// The strictest profile: a shared host is enough, every confinement control,
    /// offline, no credentials, an ephemeral task, CPU only, no confidentiality claim,
    /// and observations no older than `max_age`. It asks for no independent perimeter:
    /// that needs the host's perimeter, rule and principal identities, which the policy
    /// layer sets in [`RequiredProperties::perimeter`].
    pub fn strictest(max_age: Duration) -> Self {
        Self {
            isolation: IsolationRequirement {
                physical_host: PhysicalHost::Shared,
            },
            confinement: ConfinementControl::all(),
            network: NetworkAuthority::offline(),
            credentials: CredentialExposure::none(),
            persistence: Persistence::EphemeralTask,
            devices: DeviceExposure::cpu_only(),
            confidentiality: OperatorConfidentiality::None,
            evidence: EvidenceRequirement { max_age },
            perimeter: PerimeterRequirement::NotRequired,
            declared_endpoints: Vec::new(),
            workload_image: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::digest;

    /// A route keeps its earlier form everywhere; a sandbox connection endpoint is one host
    /// name label the guest's programs reach on their own port, marked as such in the file
    /// the guest reads and in the launch record.
    #[test]
    fn a_connection_endpoint_is_one_label_marked_in_the_guests_file_and_the_record() {
        let route = GuestEgressEndpoint::new("secure", "Example.com", 443).unwrap();
        let api = GuestEgressEndpoint::connection("API", 8080).unwrap();
        assert_eq!(
            (api.name(), api.host(), api.port(), api.kind()),
            ("api", "api", 8080, EndpointKind::Connection)
        );
        assert_eq!(
            String::from_utf8(guest_endpoints_file(&[route.clone(), api.clone()])).unwrap(),
            "secure example.com 443
api api 8080 connection
"
        );
        assert_eq!(
            serde_json::to_value(&route).unwrap(),
            serde_json::json!({"name": "secure", "host": "example.com", "port": 443})
        );
        assert_eq!(
            serde_json::to_value(&api).unwrap(),
            serde_json::json!({"name": "api", "host": "api", "port": 8080, "kind": "connection"})
        );
        let back: GuestEgressEndpoint =
            serde_json::from_value(serde_json::to_value(&api).unwrap()).unwrap();
        assert_eq!(back, api);
        let long = "a".repeat(64);
        for refused in ["a.b", "a_b", "9a", "a-", "", long.as_str()] {
            assert!(
                GuestEgressEndpoint::connection(refused, 80).is_err(),
                "{refused}"
            );
        }
        assert_eq!(
            GuestEgressEndpoint::connection("api", 0),
            Err(EndpointError::Port)
        );
    }

    fn gpu(name: &[u8]) -> GpuDeviceKey {
        GpuDeviceKey {
            machine: digest("yougori/test/machine/v1", &[b"m"]),
            device: digest("yougori/test/device/v1", &[name]),
        }
    }

    #[test]
    fn a_dedicated_host_is_stronger_than_a_shared_one() {
        assert!(PhysicalHost::Dedicated > PhysicalHost::Shared);
        assert_eq!(
            serde_json::to_string(&PhysicalHost::Dedicated).unwrap(),
            "\"dedicated\""
        );
    }

    #[test]
    fn at_most_facets_compare_by_subset() {
        let offline = NetworkAuthority::offline();
        let routes = NetworkAuthority::of([NetworkChannel::NamedTransportRoutes]);
        assert!(offline.is_offline());
        assert!(offline.within(&routes));
        assert!(!routes.within(&offline));
        assert!(routes.within(&routes));

        let none = CredentialExposure::none();
        let local = CredentialExposure::of([CredentialKind::SandboxLocalSecrets]);
        assert!(none.within(&local));
        assert!(!local.within(&none));

        let cpu = DeviceExposure::cpu_only();
        let display = DeviceExposure {
            paravirtualized_gpu: false,
            display: true,
            gpus: BTreeSet::new(),
        };
        let one_gpu = DeviceExposure {
            paravirtualized_gpu: false,
            display: false,
            gpus: [gpu(b"gpu0")].into_iter().collect(),
        };
        assert!(cpu.is_cpu_only());
        assert!(cpu.within(&display));
        assert!(!display.within(&cpu));
        assert!(!one_gpu.within(&display));
        assert!(one_gpu.within(&DeviceExposure {
            paravirtualized_gpu: false,
            display: true,
            gpus: [gpu(b"gpu0"), gpu(b"gpu1")].into_iter().collect(),
        }));
    }

    #[test]
    fn every_gpu_isolation_check_is_required() {
        let complete = GpuIsolation::complete();
        assert!(complete.is_isolated());
        assert!(complete.missing().is_empty());
        for check in GpuIsolationCheck::ALL {
            let mut partial = complete.clone();
            partial.checks.remove(&check);
            assert!(!partial.is_isolated());
            assert_eq!(partial.missing(), [check].into_iter().collect());
        }
        let mut bypass = complete;
        bypass
            .unsafe_settings
            .insert(UnsafeDeviceSetting::AcsOverride);
        assert!(!bypass.is_isolated());
    }

    #[test]
    fn an_inventory_reduces_to_its_exposure() {
        let inventory = DeviceInventory {
            paravirtualized_gpu: false,
            display: true,
            gpus: [ObservedGpu {
                device: gpu(b"gpu0"),
                isolation: GpuIsolation::complete(),
            }]
            .into_iter()
            .collect(),
        };
        assert_eq!(
            inventory.exposure(),
            DeviceExposure {
                paravirtualized_gpu: false,
            display: true,
                gpus: [gpu(b"gpu0")].into_iter().collect(),
            }
        );
        assert!(DeviceInventory::cpu_only().exposure().is_cpu_only());
    }

    #[test]
    fn persistence_names_its_volumes() {
        let volume = digest("yougori/test/volume/v1", &[b"v"]);
        assert!(Persistence::EphemeralTask.volumes().is_empty());
        assert_eq!(
            Persistence::DeclaredDataVolumes {
                volumes: [volume].into_iter().collect()
            }
            .volumes(),
            [volume].into_iter().collect()
        );
        assert_eq!(
            Persistence::ControlledServiceRenewal {
                volumes: [volume].into_iter().collect()
            }
            .tag(),
            "controlled_service_renewal"
        );
    }

    #[test]
    fn the_strictest_profile_round_trips_and_refuses_unknown_fields() {
        let required = RequiredProperties::strictest(Duration::from_secs(60));
        assert_eq!(required.confinement.len(), ConfinementControl::ALL.len());
        let json = serde_json::to_value(&required).unwrap();
        assert_eq!(json["persistence"], "ephemeral_task");
        assert_eq!(json["confidentiality"], "none");
        assert_eq!(
            serde_json::from_value::<RequiredProperties>(json.clone()).unwrap(),
            required
        );
        let mut extra = json.clone();
        extra["score"] = 3.into();
        assert!(serde_json::from_value::<RequiredProperties>(extra).is_err());
        let mut inner = json;
        inner["devices"]["usb"] = true.into();
        assert!(serde_json::from_value::<RequiredProperties>(inner).is_err());

        let confidential = serde_json::json!({
            "verified_confidential_vm": {"scope": digest("yougori/test/scope/v1", &[b"s"]), "level": 2}
        });
        assert!(serde_json::from_value::<OperatorConfidentiality>(confidential).is_err());
        let volumes =
            serde_json::json!({"declared_data_volumes": {"volumes": [], "writable": true}});
        assert!(serde_json::from_value::<Persistence>(volumes).is_err());
    }

    #[test]
    fn a_perimeter_requirement_is_serialized_only_when_asked_for() {
        let required = RequiredProperties::strictest(Duration::from_secs(60));
        assert!(required.perimeter.is_not_required());
        let json = serde_json::to_value(&required).unwrap();
        assert!(
            json.get("perimeter").is_none(),
            "no perimeter asked for leaves the serialized form unchanged"
        );
        assert_eq!(
            serde_json::from_value::<RequiredProperties>(json).unwrap(),
            required
        );

        let rule = digest("yougori/test/rule/v1", &[b"block-private"]);
        let mut strict = required.clone();
        strict.perimeter = PerimeterRequirement::Independent {
            perimeter: digest("yougori/test/perimeter/v1", &[b"host"]),
            principal: digest("yougori/test/principal/v1", &[b"broker"]),
            rules: [rule].into_iter().collect(),
        };
        assert!(strict.perimeter.is_required());
        assert_eq!(strict.perimeter.tag(), "independent");
        let json = serde_json::to_value(&strict).unwrap();
        assert_eq!(json["perimeter"]["independent"]["rules"][0], rule.to_hex());
        assert_eq!(
            serde_json::from_value::<RequiredProperties>(json.clone()).unwrap(),
            strict
        );
        let mut widened = json;
        widened["perimeter"]["independent"]["optional"] = true.into();
        assert!(serde_json::from_value::<RequiredProperties>(widened).is_err());
    }

    #[test]
    fn facets_have_stable_tags() {
        let tags: BTreeSet<&str> = Facet::ALL.iter().map(|facet| facet.tag()).collect();
        assert_eq!(tags.len(), Facet::ALL.len());
        for facet in Facet::ALL {
            assert_eq!(
                serde_json::to_value(facet).unwrap(),
                serde_json::Value::from(facet.tag())
            );
            assert!(!facet.to_string().is_empty());
        }
    }
}
