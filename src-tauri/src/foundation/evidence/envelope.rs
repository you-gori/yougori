//! The versioned evidence envelope (CORE-01, S2): subject, configuration fingerprint,
//! source of observation, freshness, result and refusal reason.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::num::{NonZeroU32, NonZeroU64};
use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize};

use super::remedy::Remedy;
use super::subject::{BackendRelease, HypervisorKind, Subject, SubjectKind};
use crate::foundation::ids::{Digest, DigestBuilder, ExecutionCategory, MonotonicTime};

/// The evidence schema version this build writes and reads.
pub const EVIDENCE_SCHEMA_VERSION: u32 = 1;

/// The pinned schema version of an [`EvidenceEnvelope`] (CORE-01 "versioned").
///
/// Only [`EVIDENCE_SCHEMA_VERSION`] is representable, so an envelope written under any
/// other version is refused when read instead of being reinterpreted (VM-CP-35: an
/// unknown schema version is governed by host policy).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct SchemaVersion(u32);

impl SchemaVersion {
    pub const CURRENT: Self = Self(EVIDENCE_SCHEMA_VERSION);

    pub const fn get(self) -> u32 {
        self.0
    }
}

impl TryFrom<u32> for SchemaVersion {
    type Error = UnsupportedSchemaVersion;

    fn try_from(found: u32) -> Result<Self, Self::Error> {
        if found == EVIDENCE_SCHEMA_VERSION {
            Ok(Self(found))
        } else {
            Err(UnsupportedSchemaVersion { found })
        }
    }
}

impl From<SchemaVersion> for u32 {
    fn from(version: SchemaVersion) -> Self {
        version.0
    }
}

/// An envelope was written under a schema version this build does not read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnsupportedSchemaVersion {
    pub found: u32,
}

impl fmt::Display for UnsupportedSchemaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "evidence schema version {} is not supported; this build reads only version \
             {EVIDENCE_SCHEMA_VERSION}",
            self.found
        )
    }
}

impl std::error::Error for UnsupportedSchemaVersion {}

/// The family a capability check belongs to (CORE-01: each GPU, hypervisor, OS or
/// provider check), plus backend modes, which depend on the backend release, the
/// isolation a runtime actually has, and the boundary facts of one VM sandbox.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityDomain {
    Gpu,
    OperatingSystem,
    Backend,
    Hypervisor,
    Provider,
    /// What kind of runtime executes a workload (VM-D4–VM-D6).
    Isolation,
    /// A boundary fact of one VM sandbox that the host observes outside the hypervisor
    /// process: its booted image, its network path, its transport broker, where a
    /// credential went, or its clones (VM part VM-W09, line 2594; §17, lines 3145–3188).
    SandboxBoundary,
}

/// A capability a typed probe adapter observes (CORE-01).
///
/// The two CUDA IPC capabilities are different API families and never stand in for each
/// other (GPU part §1.1: probe exact IPC and CUDA VMM operations, distinguishing API
/// families).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// Legacy CUDA IPC: `cudaIpcGetMemHandle` and `cudaIpcOpenMemHandle`.
    CudaIpcLegacy,
    /// CUDA VMM shareable handles: `cuMemExportToShareableHandle` and
    /// `cuMemImportFromShareableHandle`.
    CudaIpcVmmShareableHandle,
    /// GPUDirect Storage reads into GPU memory (INT-06).
    GpuDirectStorage,
    /// CUDA checkpoint and restore, a distinct capability-gated experiment (S7).
    CudaCheckpoint,
    /// io_uring in the runtime's kernel (INT-06).
    IoUring,
    /// Zero-copy preloaded weights shared by a backend preload daemon (GPU part §1.2).
    ZeroCopyPreload,
    /// Sleep mode that offloads weights (S7).
    SleepWeightOffload,
    /// A usable hypervisor on the host.
    HypervisorAvailable,
    /// The provider runs the resource as a container: the labelled provider-container
    /// runtime of VM-D5, not a VM.
    ProviderContainer,
    /// The runtime really is the execution category it is offered as, as the host or the
    /// provider API observed it. Admission rests on this, never on a caller's label
    /// (INT-07; VM part §1.3).
    RuntimeCategory,
    /// CUDA VMM allocation with the subject's exact properties, and the granularity the
    /// driver reports for them (`cuMemGetAllocationGranularity`; GPU §3.7: probed, never
    /// assumed).
    CudaVmmAllocation,
    /// The compute platform the runtime actually has, so callers stop asserting CUDA,
    /// Metal or CPU.
    ComputePlatform,
    /// Sleep mode that discards the weights, distinct from offloading them (S7).
    SleepWeightDiscard,
    /// A peer copy from one GPU to another, exercised and successful (FAST-02).
    GpuPeerAccess,
    /// What one checkpoint supports on one pinned engine and hardware class, as measured
    /// (FAST-02 "checkpoint compatibility").
    CheckpointCompatibility,
    /// Free and total memory of one GPU, as the host measured it (FAST-02 "measured free
    /// capacity"; S3.2: guest telemetry is not authority).
    GpuFreeMemory,
    /// The measured peer topology of the GPUs assigned to one runtime (FAST-02: probe
    /// actual peer topology before a per-process NCCL choice).
    PeerTopology,
    /// Execute-while-load runs on this runtime with its dependencies met (GPU-W07).
    ExecuteWhileLoad,
    /// A must-probe showed the block rule enforced (VM §4.4): a controlled endpoint, a
    /// reached positive control and evidence naming the rule; a timeout is inconclusive.
    PerimeterRuleEnforced,
    /// The hypervisor configuration of one launch (Firecracker API calls or QEMU argv)
    /// matches the approved profile's golden file, with no network device, console,
    /// balloon or undeclared PCI transport, no shared-filesystem device, no management
    /// TCP listener, the QMP socket in a private directory and no port forward to the old
    /// agent port (VM part §12.2 VM-P02 and VM-P03, lines 2777–2778; §17 VM-CP-02 and
    /// VM-CP-03, lines 3152–3153).
    HypervisorConfigurationMatches,
    /// The hypervisor process of one launch runs under the host restrictions of its
    /// profile, verified independently of the guest: on Linux the launcher's
    /// unprivileged uid, no new privileges, a seccomp filter, a network namespace with
    /// only `lo`, cgroup limits and a bounded descriptor count; on Windows a restricted
    /// low-integrity token and job limits; on macOS the helper's profile (VM part §1.3
    /// hypervisor confinement, line 1900; §17 VM-CP-04, line 3154).
    HypervisorConfined,
    /// One boot of one sandbox booted the signed base: the root image digest and the
    /// kernel build record match the signed manifest, and a changed root image, an
    /// unsigned manifest, expired metadata, a rolled-back version or a mixed-version set
    /// is refused at the launch boundary (VM part §17: the host corroboration of
    /// VM-CP-05, VM-CP-17 and VM-CP-23, lines 3155, 3167 and 3173).
    BootedImageMatchesManifest,
    /// The transport broker of one perimeter refuses forbidden destinations: a private
    /// answer for an allowed name, a CNAME chain into a private range, and every
    /// non-public address form; a TTL change triggers revalidation and the canary name
    /// produces no upstream query (VM part §17 VM-CP-07 and VM-CP-08, lines 3157–3158).
    DestinationPolicyEnforced,
    /// The host observes no packet from one boot of one sandbox, because it has no
    /// network device (VM part §17: the host part of VM-CP-09, line 3159).
    NoGuestNetworkDevice,
    /// A fixture credential appears in none of the scanned locations of one launch
    /// except the executor's outbound request. It covers only the locations the subject
    /// names and never shows that no secret exists anywhere (VM part §8.1, line 2439;
    /// §17 VM-CP-12, line 3162).
    CredentialAbsentFromScannedLocations,
    /// Clones restored from one golden snapshot have distinct generation and boot ids,
    /// which the host assigns, and the host's executor refuses an approval issued before
    /// the snapshot in each of them (VM part §17: the host corroboration of VM-CP-21,
    /// line 3171).
    CloneIdentityReset,
    /// One GPU may be assigned to a VM: its IOMMU group is complete, the host display
    /// does not own it, and its reset capability and ACS state were checked before
    /// assignment (VM part §12.2 VM-P39, line 2814; §17 VM-CP-31, line 3181).
    DeviceAssignmentIsolated,
    /// The backend maps its KV pool in increments of the reported size as requests need
    /// it, instead of allocating the whole pool when it starts (GPU-W10: "backend-supported
    /// dynamic KV growth and admission limits"). Without it the pool is held whole.
    KvGrowth,
    /// What the backend accepts for unmerged adapters: the largest rank its adapter
    /// kernels take, how many adapters it keeps resident at once and the device bytes they
    /// may hold together (GPU-W10; GPU part §3.9). Without it no unmerged adapter is
    /// attached.
    AdapterLimits,
}

impl Capability {
    pub const ALL: [Self; 29] = [
        Self::CudaIpcLegacy,
        Self::CudaIpcVmmShareableHandle,
        Self::GpuDirectStorage,
        Self::CudaCheckpoint,
        Self::IoUring,
        Self::ZeroCopyPreload,
        Self::SleepWeightOffload,
        Self::HypervisorAvailable,
        Self::ProviderContainer,
        Self::RuntimeCategory,
        Self::CudaVmmAllocation,
        Self::ComputePlatform,
        Self::SleepWeightDiscard,
        Self::GpuPeerAccess,
        Self::CheckpointCompatibility,
        Self::GpuFreeMemory,
        Self::PeerTopology,
        Self::ExecuteWhileLoad,
        Self::PerimeterRuleEnforced,
        Self::HypervisorConfigurationMatches,
        Self::HypervisorConfined,
        Self::BootedImageMatchesManifest,
        Self::DestinationPolicyEnforced,
        Self::NoGuestNetworkDevice,
        Self::CredentialAbsentFromScannedLocations,
        Self::CloneIdentityReset,
        Self::DeviceAssignmentIsolated,
        Self::KvGrowth,
        Self::AdapterLimits,
    ];

    pub const fn domain(self) -> CapabilityDomain {
        match self {
            Self::CudaIpcLegacy
            | Self::CudaIpcVmmShareableHandle
            | Self::GpuDirectStorage
            | Self::CudaCheckpoint
            | Self::CudaVmmAllocation
            | Self::ComputePlatform
            | Self::GpuPeerAccess
            | Self::GpuFreeMemory
            | Self::PeerTopology
            | Self::ExecuteWhileLoad
            | Self::DeviceAssignmentIsolated => CapabilityDomain::Gpu,
            Self::IoUring | Self::PerimeterRuleEnforced => CapabilityDomain::OperatingSystem,
            Self::ZeroCopyPreload
            | Self::SleepWeightOffload
            | Self::SleepWeightDiscard
            | Self::CheckpointCompatibility
            | Self::KvGrowth
            | Self::AdapterLimits => CapabilityDomain::Backend,
            Self::HypervisorAvailable
            | Self::HypervisorConfigurationMatches
            | Self::HypervisorConfined => CapabilityDomain::Hypervisor,
            Self::ProviderContainer => CapabilityDomain::Provider,
            Self::RuntimeCategory => CapabilityDomain::Isolation,
            Self::BootedImageMatchesManifest
            | Self::DestinationPolicyEnforced
            | Self::NoGuestNetworkDevice
            | Self::CredentialAbsentFromScannedLocations
            | Self::CloneIdentityReset => CapabilityDomain::SandboxBoundary,
        }
    }

    /// What this capability is observed on. Loader capabilities are observed for one exact
    /// runtime (INT-06: "the exact runtime/profile"); a capability with parameters, such
    /// as a device pair or a checkpoint, is observed on a subject that names them. A VM
    /// boundary fact is observed on exactly what its §17 check looks at: one launch's
    /// hypervisor process, one boot of one sandbox, one broker of one perimeter, one
    /// launch's credential scan, a golden snapshot and its clones, or one GPU.
    pub const fn subject_kind(self) -> SubjectKind {
        match self {
            Self::HypervisorAvailable => SubjectKind::Hypervisor,
            Self::ProviderContainer => SubjectKind::Provider,
            Self::CudaIpcLegacy
            | Self::CudaIpcVmmShareableHandle
            | Self::GpuDirectStorage
            | Self::CudaCheckpoint
            | Self::IoUring
            | Self::ZeroCopyPreload
            | Self::SleepWeightOffload
            | Self::RuntimeCategory
            | Self::ComputePlatform
            | Self::SleepWeightDiscard
            | Self::PeerTopology
            | Self::ExecuteWhileLoad
            | Self::KvGrowth
            | Self::AdapterLimits => SubjectKind::Runtime,
            Self::CudaVmmAllocation => SubjectKind::CudaAllocation,
            Self::GpuPeerAccess => SubjectKind::GpuPair,
            Self::CheckpointCompatibility => SubjectKind::ModelCheckpoint,
            Self::GpuFreeMemory | Self::DeviceAssignmentIsolated => SubjectKind::GpuDevice,
            Self::PerimeterRuleEnforced => SubjectKind::PerimeterRule,
            Self::HypervisorConfigurationMatches | Self::HypervisorConfined => {
                SubjectKind::HypervisorProcess
            }
            Self::BootedImageMatchesManifest | Self::NoGuestNetworkDevice => {
                SubjectKind::SandboxBoot
            }
            Self::DestinationPolicyEnforced => SubjectKind::TransportBroker,
            Self::CredentialAbsentFromScannedLocations => SubjectKind::CredentialScan,
            Self::CloneIdentityReset => SubjectKind::SnapshotClones,
        }
    }

    /// The weakest source whose evidence can ever count for this capability; a
    /// requirement asking for less is raised to it.
    ///
    /// Hypervisor availability is a host fact (VM-W09: a lying guest cannot satisfy
    /// host-only requirements), and so are a GPU's free memory (S3.2: guest telemetry is
    /// an observation, not authority), a perimeter's enforcement (a host perimeter check,
    /// VM-CP-11) and every other VM boundary fact of §17 (VM part §8.1, line 2437: host
    /// configuration, process state and controlled external observations carry boundary
    /// claims, and a guest can lie about them). What a provider runs is the provider's
    /// report, not the pod's (VM-D5), and a runtime's category, VM sandbox above all, is
    /// the host's or the provider's observation, never a guest report or a declaration.
    /// Other runtime capabilities need a live observation: a recorded declaration or a
    /// fixture never shows support (S2: fakes cannot certify a real backend).
    pub const fn weakest_source(self) -> SourceClass {
        match self {
            Self::HypervisorAvailable
            | Self::GpuFreeMemory
            | Self::PerimeterRuleEnforced
            | Self::HypervisorConfigurationMatches
            | Self::HypervisorConfined
            | Self::BootedImageMatchesManifest
            | Self::DestinationPolicyEnforced
            | Self::NoGuestNetworkDevice
            | Self::CredentialAbsentFromScannedLocations
            | Self::CloneIdentityReset
            | Self::DeviceAssignmentIsolated => SourceClass::HostProbe,
            Self::ProviderContainer | Self::RuntimeCategory => SourceClass::ProviderApi,
            Self::CudaIpcLegacy
            | Self::CudaIpcVmmShareableHandle
            | Self::GpuDirectStorage
            | Self::CudaCheckpoint
            | Self::IoUring
            | Self::ZeroCopyPreload
            | Self::SleepWeightOffload
            | Self::CudaVmmAllocation
            | Self::ComputePlatform
            | Self::SleepWeightDiscard
            | Self::GpuPeerAccess
            | Self::CheckpointCompatibility
            | Self::PeerTopology
            | Self::ExecuteWhileLoad
            | Self::KvGrowth
            | Self::AdapterLimits => SourceClass::GuestReport,
        }
    }

    /// The user-facing name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::CudaIpcLegacy => "legacy CUDA IPC",
            Self::CudaIpcVmmShareableHandle => "CUDA VMM shareable handles",
            Self::GpuDirectStorage => "GPUDirect Storage",
            Self::CudaCheckpoint => "CUDA checkpoint",
            Self::IoUring => "io_uring",
            Self::ZeroCopyPreload => "zero-copy preload",
            Self::SleepWeightOffload => "sleep-mode weight offloading",
            Self::HypervisorAvailable => "hypervisor availability",
            Self::ProviderContainer => "provider container",
            Self::RuntimeCategory => "runtime category",
            Self::CudaVmmAllocation => "CUDA VMM allocation",
            Self::ComputePlatform => "compute platform",
            Self::SleepWeightDiscard => "sleep-mode weight discarding",
            Self::GpuPeerAccess => "GPU peer access",
            Self::CheckpointCompatibility => "checkpoint compatibility",
            Self::GpuFreeMemory => "free GPU memory",
            Self::PeerTopology => "GPU peer topology",
            Self::ExecuteWhileLoad => "execute-while-load",
            Self::PerimeterRuleEnforced => "perimeter rule enforcement",
            Self::HypervisorConfigurationMatches => "approved hypervisor configuration",
            Self::HypervisorConfined => "hypervisor confinement",
            Self::BootedImageMatchesManifest => "booted image matching its signed manifest",
            Self::DestinationPolicyEnforced => "destination policy enforcement",
            Self::NoGuestNetworkDevice => "no guest network device",
            Self::CredentialAbsentFromScannedLocations => {
                "credential absent from the scanned locations"
            }
            Self::CloneIdentityReset => "clone identity reset",
            Self::DeviceAssignmentIsolated => "isolated GPU assignment",
            Self::KvGrowth => "KV growth in increments",
            Self::AdapterLimits => "unmerged adapter limits",
        }
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Where an observation came from (CORE-01 "source of observation").
///
/// Declared weakest first, so the derived order is the trust order:
/// fixture < recorded declaration < guest report < provider API < host probe. A guest
/// can fabricate its report (guest root is in the threat model), a declaration is not an
/// observation, and a fixture never certifies a real backend (S2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceClass {
    /// Test or CI fixture data.
    Fixture,
    /// A recorded statement, such as a user or operator declaration.
    RecordedDeclaration,
    /// A report from inside a guest, pod or other runtime.
    GuestReport,
    /// A report from a provider's control-plane API.
    ProviderApi,
    /// An observation the host made itself.
    HostProbe,
}

impl SourceClass {
    /// Whether evidence from this source meets `minimum`.
    pub fn satisfies(self, minimum: SourceClass) -> bool {
        self >= minimum
    }
}

impl fmt::Display for SourceClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Fixture => "test fixture",
            Self::RecordedDeclaration => "recorded declaration",
            Self::GuestReport => "guest report",
            Self::ProviderApi => "provider API report",
            Self::HostProbe => "host probe",
        })
    }
}

/// Digest of the configuration an observation depends on (CORE-01 "configuration
/// fingerprint"). Evidence observed under one fingerprint never satisfies a requirement
/// stated under another.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ConfigurationFingerprint(Digest);

impl ConfigurationFingerprint {
    /// Domain of [`Self::from_settings`].
    pub const DOMAIN: &'static str = "yougori/evidence/configuration/v1";

    pub const fn from_digest(digest: Digest) -> Self {
        Self(digest)
    }

    pub const fn digest(self) -> Digest {
        self.0
    }

    /// Fingerprints named settings, such as driver and kernel versions or launch flags.
    /// Settings are sorted by name, so their order does not matter; an empty or repeated
    /// name is refused.
    pub fn from_settings<'a>(
        settings: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<Self, FingerprintError> {
        let mut sorted = BTreeMap::new();
        for (name, value) in settings {
            if name.is_empty() {
                return Err(FingerprintError::EmptyName);
            }
            if sorted.insert(name, value).is_some() {
                return Err(FingerprintError::RepeatedName {
                    name: name.to_owned(),
                });
            }
        }
        Ok(Self(
            sorted
                .into_iter()
                .fold(
                    DigestBuilder::new(Self::DOMAIN),
                    |builder, (name, value)| builder.str(name).str(value),
                )
                .finish(),
        ))
    }
}

impl fmt::Display for ConfigurationFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// Why settings could not be fingerprinted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FingerprintError {
    EmptyName,
    RepeatedName { name: String },
}

impl fmt::Display for FingerprintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyName => f.write_str("a configuration setting has an empty name"),
            Self::RepeatedName { name } => {
                write!(f, "the configuration setting {name:?} appears twice")
            }
        }
    }
}

impl std::error::Error for FingerprintError {}

/// The clock an envelope's observation time was read from.
///
/// A [`MonotonicTime`] means nothing on another clock or in another process, so evidence
/// stamped under another session is never treated as fresh: an envelope saved before a
/// restart cannot pass for a current observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ClockSession(uuid::Uuid);

impl ClockSession {
    /// A new random session.
    pub fn generate() -> Self {
        Self(uuid::Uuid::new_v4())
    }

    pub const fn from_uuid(uuid: uuid::Uuid) -> Self {
        Self(uuid)
    }

    pub const fn as_uuid(self) -> uuid::Uuid {
        self.0
    }
}

/// A reading of one clock session. Only a [`ProbeRegistry`](super::ProbeRegistry) reads
/// its clock, so freshness is always judged against the injected clock, never against a
/// time a caller chose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClockReading {
    session: ClockSession,
    at: MonotonicTime,
}

impl ClockReading {
    pub(super) fn new(session: ClockSession, at: MonotonicTime) -> Self {
        Self { session, at }
    }

    pub fn session(self) -> ClockSession {
        self.session
    }

    pub fn at(self) -> MonotonicTime {
        self.at
    }
}

/// The kind of CUDA VMM shareable handle that was exported and imported.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShareableHandle {
    /// `CU_MEM_HANDLE_TYPE_POSIX_FILE_DESCRIPTOR`.
    PosixFileDescriptor,
    /// `CU_MEM_HANDLE_TYPE_WIN32`.
    Win32Handle,
    /// `CU_MEM_HANDLE_TYPE_FABRIC`.
    Fabric,
}

impl ShareableHandle {
    /// The stable tag hashed into subject identities.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::PosixFileDescriptor => "posix_file_descriptor",
            Self::Win32Handle => "win32_handle",
            Self::Fabric => "fabric",
        }
    }
}

/// The compute platform a runtime actually has.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComputePlatform {
    /// An NVIDIA GPU through CUDA.
    Cuda,
    /// Apple Metal, as the native macOS runner uses it (VM-D6).
    Metal,
    /// The CPU only.
    Cpu,
}

/// How two GPUs are connected, as the topology probe found it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerLink {
    NvLink,
    /// PCIe through a shared switch.
    PcieSwitch,
    /// PCIe through the host bridge.
    PcieHostBridge,
    /// Between CPU sockets.
    CrossSocket,
}

/// Whether a peer copy along a path was exercised and succeeded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerAccess {
    Verified,
    Unavailable,
}

/// One direction between two of a runtime's GPUs, named by their index in rank order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerPath {
    pub from: u32,
    pub to: u32,
    pub link: PeerLink,
    pub access: PeerAccess,
}

strict_evidence_enum! {
    /// Typed detail of a supported observation.
    ///
    /// Each capability needs its own detail (see [`SupportDetail::fits`]): a CUDA IPC
    /// check names the API family it exercised, a backend mode names the release that ran
    /// it, a hypervisor check names the hypervisor that answered, a category check names
    /// the category it observed, and a measurement carries its value.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum SupportDetail tag "kind" {
        /// Supported, with nothing more to record (GPUDirect Storage, CUDA checkpoint,
        /// io_uring, and the VM boundary facts of §17 other than hypervisor availability
        /// and perimeter rule enforcement: their subject names everything observed).
        Plain,
        /// The legacy CUDA IPC calls succeeded.
        CudaIpcLegacy,
        /// CUDA VMM export and import succeeded with this handle type.
        CudaIpcVmmShareableHandle { handle: ShareableHandle },
        /// This hypervisor answered.
        Hypervisor { hypervisor: HypervisorKind },
        /// The provider runs the resource as a container, with these hardening layers
        /// (VM-D5: gVisor and nvproxy where the pod permits).
        ProviderContainer { gvisor: bool, nvproxy: bool },
        /// The backend release that ran the mode.
        BackendMode { release: BackendRelease },
        /// The runtime's observed execution category.
        RuntimeCategory { category: ExecutionCategory },
        /// The driver reported CUDA VMM allocation for the subject's properties at this
        /// granularity.
        CudaVmmAllocation { granularity_bytes: NonZeroU64 },
        /// The runtime's observed compute platform.
        ComputePlatform { platform: ComputePlatform },
        /// A peer copy from the pair's first GPU to its second succeeded.
        GpuPeerAccess,
        /// The checkpoint ran on the subject's engine and hardware class; `record` is the
        /// digest of the measured compatibility record.
        CheckpointCompatibility { record: Digest },
        /// The GPU's free and total memory, as the host measured them.
        GpuMemory { free_bytes: u64, total_bytes: NonZeroU64 },
        /// Every ordered pair of the runtime's GPUs, each exactly once.
        PeerTopology { device_count: NonZeroU32, paths: Vec<PeerPath> },
        /// Execute-while-load ran with its dependencies met.
        ExecuteWhileLoad,
        /// The rule blocked the probe, with a reached positive control and evidence
        /// naming the rule.
        PerimeterRuleEnforced,
        /// The backend release that maps its KV pool in increments, and the bytes it maps
        /// at a time.
        KvGrowth { release: BackendRelease, increment_bytes: NonZeroU64 },
        /// The backend release's limits for unmerged adapters: the largest rank, the most
        /// adapters resident at once and the device bytes they hold together.
        AdapterLimits {
            release: BackendRelease,
            max_rank: NonZeroU32,
            max_resident: NonZeroU32,
            max_bytes: NonZeroU64,
        },
    }
}

impl SupportDetail {
    /// Whether this detail can describe `capability` on `subject`. A detail naming the
    /// other CUDA IPC family, another release, another hypervisor or another category
    /// than the subject's does not fit, and neither does an impossible measurement: a
    /// GPU as its own peer, more free memory than total, or a topology that omits or
    /// repeats a path.
    pub fn fits(&self, capability: Capability, subject: &Subject) -> bool {
        match (capability, self, subject) {
            (Capability::CudaIpcLegacy, Self::CudaIpcLegacy, Subject::Runtime(_))
            | (
                Capability::CudaIpcVmmShareableHandle,
                Self::CudaIpcVmmShareableHandle { .. },
                Subject::Runtime(_),
            )
            | (
                Capability::GpuDirectStorage | Capability::CudaCheckpoint | Capability::IoUring,
                Self::Plain,
                Subject::Runtime(_),
            )
            | (
                Capability::ProviderContainer,
                Self::ProviderContainer { .. },
                Subject::Provider(_),
            )
            | (
                Capability::CudaVmmAllocation,
                Self::CudaVmmAllocation { .. },
                Subject::CudaAllocation(_),
            )
            | (Capability::ComputePlatform, Self::ComputePlatform { .. }, Subject::Runtime(_))
            | (
                Capability::CheckpointCompatibility,
                Self::CheckpointCompatibility { .. },
                Subject::ModelCheckpoint(_),
            )
            | (Capability::ExecuteWhileLoad, Self::ExecuteWhileLoad, Subject::Runtime(_))
            | (
                Capability::PerimeterRuleEnforced,
                Self::PerimeterRuleEnforced,
                Subject::PerimeterRule(_),
            )
            | (
                Capability::HypervisorConfigurationMatches | Capability::HypervisorConfined,
                Self::Plain,
                Subject::HypervisorProcess(_),
            )
            | (
                Capability::BootedImageMatchesManifest | Capability::NoGuestNetworkDevice,
                Self::Plain,
                Subject::SandboxBoot(_),
            )
            | (Capability::DestinationPolicyEnforced, Self::Plain, Subject::TransportBroker(_))
            | (
                Capability::CredentialAbsentFromScannedLocations,
                Self::Plain,
                Subject::CredentialScan(_),
            )
            | (Capability::CloneIdentityReset, Self::Plain, Subject::SnapshotClones(_))
            | (Capability::DeviceAssignmentIsolated, Self::Plain, Subject::GpuDevice(_)) => true,
            (
                Capability::ZeroCopyPreload
                | Capability::SleepWeightOffload
                | Capability::SleepWeightDiscard,
                Self::BackendMode { release },
                Subject::Runtime(runtime),
            )
            | (Capability::KvGrowth, Self::KvGrowth { release, .. }, Subject::Runtime(runtime))
            | (
                Capability::AdapterLimits,
                Self::AdapterLimits { release, .. },
                Subject::Runtime(runtime),
            ) => *release == runtime.release,
            (
                Capability::HypervisorAvailable,
                Self::Hypervisor { hypervisor },
                Subject::Hypervisor(subject),
            ) => *hypervisor == subject.hypervisor,
            (
                Capability::RuntimeCategory,
                Self::RuntimeCategory { category },
                Subject::Runtime(runtime),
            ) => *category == runtime.category,
            (Capability::GpuPeerAccess, Self::GpuPeerAccess, Subject::GpuPair(pair)) => {
                pair.from != pair.to
            }
            (
                Capability::GpuFreeMemory,
                Self::GpuMemory {
                    free_bytes,
                    total_bytes,
                },
                Subject::GpuDevice(_),
            ) => *free_bytes <= total_bytes.get(),
            (
                Capability::PeerTopology,
                Self::PeerTopology {
                    device_count,
                    paths,
                },
                Subject::Runtime(_),
            ) => complete_topology(*device_count, paths),
            _ => false,
        }
    }
}

/// Whether `paths` name every ordered pair of `device_count` GPUs exactly once, with no
/// GPU as its own peer: a missing path is never assumed. The length is checked first, so
/// a huge count with few paths is refused without enumerating pairs.
fn complete_topology(device_count: NonZeroU32, paths: &[PeerPath]) -> bool {
    let count = device_count.get();
    let ordered_pairs = u64::from(count).checked_mul(u64::from(count) - 1);
    if ordered_pairs != u64::try_from(paths.len()).ok() {
        return false;
    }
    let mut seen = BTreeSet::new();
    paths.iter().all(|path| {
        path.from < count
            && path.to < count
            && path.from != path.to
            && seen.insert((path.from, path.to))
    })
}

/// Why a capability is unsupported; each reason names what the user can do.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnsupportedReason {
    /// The exact operation was exercised and failed (GPU part §1.1).
    OperationFailed,
    /// The platform, driver or kernel lacks the feature.
    FeatureAbsent,
    /// The runtime's own policy turns it off, as the strict guest kernel does for io_uring
    /// (VM-CP-05).
    DisabledByPolicy,
    /// No usable hypervisor on this host.
    HypervisorUnavailable,
    /// The provider runs this resource as something other than a container.
    NotAProviderContainer,
    /// The runtime is not the execution category it was offered as, such as a provider
    /// container offered as a VM sandbox (INT-07).
    DifferentCategory,
    /// A must-probe connected with the rule in place: the perimeter does not enforce it
    /// (VM §4.4).
    NotEnforced,
    /// The hypervisor configuration differs from the approved profile's golden file, or
    /// exposes an undeclared device, share or management listener (VM-CP-02, VM-CP-03;
    /// VM part §17, lines 3152–3153).
    ConfigurationNotApproved,
    /// The hypervisor process lacks a host restriction its profile requires (VM-CP-04;
    /// VM part §17, line 3154).
    NotConfined,
    /// The booted image or kernel build record differs from the signed manifest, or a
    /// changed component set was not refused at launch (VM-CP-05, VM-CP-17, VM-CP-23;
    /// VM part §17, lines 3155, 3167 and 3173).
    ImageNotAsSigned,
    /// The transport broker let a forbidden answer, name or address form through
    /// (VM-CP-07, VM-CP-08; VM part §17, lines 3157–3158).
    DestinationNotRefused,
    /// The host saw a packet from the VM, so it has a network path (VM-CP-09; VM part
    /// §17, line 3159).
    GuestNetworkPath,
    /// Within the scanned locations, the fixture credential appeared where it must not,
    /// was missing from the executor's request, or the scan did not state its coverage
    /// (VM-CP-12; VM part §17, line 3162).
    CredentialExposed,
    /// Clones restored from one snapshot share an identity or accept an approval issued
    /// before it (VM-CP-21; VM part §17, line 3171); the pool cold-boots instead (VM-P43,
    /// line 2818).
    CloneIdentityShared,
    /// The GPU's IOMMU group, display ownership, reset capability or ACS state does not
    /// allow assignment (VM-CP-31; VM part §17, line 3181).
    DeviceNotIsolated,
}

impl UnsupportedReason {
    /// What the user can do; Yougori never changes host settings itself (S7). A failed
    /// VM boundary fact of §17, other than perimeter enforcement, leaves only another
    /// runtime or device: the plan names no user repair for it.
    pub const fn remedy(self) -> Remedy {
        match self {
            Self::HypervisorUnavailable => Remedy::EnableHypervisorYourself,
            Self::DifferentCategory => Remedy::ChooseAllowedCategory,
            Self::NotEnforced => Remedy::RepairPerimeter,
            Self::OperationFailed
            | Self::FeatureAbsent
            | Self::DisabledByPolicy
            | Self::NotAProviderContainer
            | Self::ConfigurationNotApproved
            | Self::NotConfined
            | Self::ImageNotAsSigned
            | Self::DestinationNotRefused
            | Self::GuestNetworkPath
            | Self::CredentialExposed
            | Self::CloneIdentityShared
            | Self::DeviceNotIsolated => Remedy::ChooseSupportedRuntime,
        }
    }
}

impl fmt::Display for UnsupportedReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::OperationFailed => "the operation failed when it was exercised",
            Self::FeatureAbsent => "the platform, driver or kernel lacks it",
            Self::DisabledByPolicy => "the runtime's policy turns it off",
            Self::HypervisorUnavailable => "no usable hypervisor is available on this host",
            Self::NotAProviderContainer => "the provider does not run this resource as a container",
            Self::DifferentCategory => "the runtime is not the category it was offered as",
            Self::NotEnforced => "the probe got through with the rule in place",
            Self::ConfigurationNotApproved => {
                "the hypervisor configuration differs from the approved profile or exposes an \
                 undeclared device, share or listener"
            }
            Self::NotConfined => "the hypervisor process lacks a restriction its profile requires",
            Self::ImageNotAsSigned => {
                "the booted image or kernel record differs from the signed manifest, or a \
                 changed component set was not refused at launch"
            }
            Self::DestinationNotRefused => {
                "the transport broker let a forbidden answer, name or address form through"
            }
            Self::GuestNetworkPath => "the host saw a packet from the VM, so it has a network path",
            Self::CredentialExposed => {
                "within the scanned locations, the fixture credential was found outside the \
                 executor's request, or not in it"
            }
            Self::CloneIdentityShared => {
                "clones of one snapshot share an identity or accept an approval from before it"
            }
            Self::DeviceNotIsolated => {
                "the GPU's IOMMU group, display ownership, reset or ACS state does not allow \
                 assignment"
            }
        })
    }
}

/// Why a check could not decide; an unknown result fails every requirement (VM-W09:
/// inconclusive results fail required checks).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownReason {
    /// The check was not run: "not tested", never a pass (VM-CP-35).
    NotTested,
    /// The check ran without a conclusive answer.
    Inconclusive,
    /// The subject could not be reached.
    Unreachable,
    /// The adapter's report did not fit its capability or subject, such as a report
    /// naming the other CUDA IPC API family.
    InconsistentReport,
}

impl UnknownReason {
    /// What the user can do: run the check, or run it again.
    pub const fn remedy(self) -> Remedy {
        match self {
            Self::NotTested => Remedy::RunCheck,
            Self::Inconclusive | Self::Unreachable | Self::InconsistentReport => {
                Remedy::RunCheckAgain
            }
        }
    }
}

impl fmt::Display for UnknownReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotTested => "it was not tested",
            Self::Inconclusive => "the check was inconclusive",
            Self::Unreachable => "the subject could not be reached",
            Self::InconsistentReport => "the check's report did not fit what was checked",
        })
    }
}

strict_evidence_enum! {
    /// The result of an observation (CORE-01 "result").
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum ObservationResult tag "outcome" {
        Supported { detail: SupportDetail },
        Unsupported { reason: UnsupportedReason },
        Unknown { reason: UnknownReason },
    }
}

/// What an adapter returns. The registry adds the capability, subject, source and
/// observation time, so an adapter cannot choose its own trust class per observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observation {
    /// The configuration the observation depends on.
    pub configuration: ConfigurationFingerprint,
    /// How long the observation stays fresh (CORE-01 "freshness").
    pub fresh_for: Duration,
    pub result: ObservationResult,
}

impl Observation {
    pub fn supported(
        configuration: ConfigurationFingerprint,
        fresh_for: Duration,
        detail: SupportDetail,
    ) -> Self {
        Self {
            configuration,
            fresh_for,
            result: ObservationResult::Supported { detail },
        }
    }

    pub fn unsupported(
        configuration: ConfigurationFingerprint,
        fresh_for: Duration,
        reason: UnsupportedReason,
    ) -> Self {
        Self {
            configuration,
            fresh_for,
            result: ObservationResult::Unsupported { reason },
        }
    }

    pub fn unknown(
        configuration: ConfigurationFingerprint,
        fresh_for: Duration,
        reason: UnknownReason,
    ) -> Self {
        Self {
            configuration,
            fresh_for,
            result: ObservationResult::Unknown { reason },
        }
    }
}

/// One observation of one capability on one subject (CORE-01).
///
/// Only the [`ProbeRegistry`](super::ProbeRegistry) makes envelopes, from registered
/// adapters. An envelope read back from JSON passes the same checks a stamped one does
/// (the subject kind fits the capability, and a supported detail fits both), so it can be
/// shown or reported; it can never enter an [`EvidenceStore`](super::EvidenceStore), so a
/// forged report cannot satisfy a requirement (VM-CP-25).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EvidenceEnvelope {
    schema_version: SchemaVersion,
    capability: Capability,
    subject: Subject,
    configuration: ConfigurationFingerprint,
    source: SourceClass,
    clock: ClockSession,
    observed_at: MonotonicTime,
    fresh_for: Duration,
    result: ObservationResult,
}

/// The fields of an [`EvidenceEnvelope`] as read, before they are checked.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvelopeRecord {
    schema_version: SchemaVersion,
    capability: Capability,
    subject: Subject,
    configuration: ConfigurationFingerprint,
    source: SourceClass,
    clock: ClockSession,
    observed_at: MonotonicTime,
    fresh_for: Duration,
    result: ObservationResult,
}

/// Why a read envelope could not have been stamped.
#[derive(Debug)]
enum InvalidEnvelope {
    WrongSubjectKind {
        capability: Capability,
        expected: SubjectKind,
        found: SubjectKind,
    },
    DetailDoesNotFit {
        capability: Capability,
    },
}

impl fmt::Display for InvalidEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongSubjectKind {
                capability,
                expected,
                found,
            } => write!(
                f,
                "{capability} evidence is about a {expected}, but this envelope names a {found}"
            ),
            Self::DetailDoesNotFit { capability } => write!(
                f,
                "the envelope's supported detail does not fit {capability} on its subject"
            ),
        }
    }
}

impl<'de> Deserialize<'de> for EvidenceEnvelope {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let record = EnvelopeRecord::deserialize(deserializer)?;
        let expected = record.capability.subject_kind();
        if record.subject.kind() != expected {
            return Err(serde::de::Error::custom(
                InvalidEnvelope::WrongSubjectKind {
                    capability: record.capability,
                    expected,
                    found: record.subject.kind(),
                },
            ));
        }
        if let ObservationResult::Supported { detail } = &record.result {
            if !detail.fits(record.capability, &record.subject) {
                return Err(serde::de::Error::custom(
                    InvalidEnvelope::DetailDoesNotFit {
                        capability: record.capability,
                    },
                ));
            }
        }
        Ok(Self {
            schema_version: record.schema_version,
            capability: record.capability,
            subject: record.subject,
            configuration: record.configuration,
            source: record.source,
            clock: record.clock,
            observed_at: record.observed_at,
            fresh_for: record.fresh_for,
            result: record.result,
        })
    }
}

impl EvidenceEnvelope {
    /// Stamps an adapter's observation. A supported result whose detail does not fit the
    /// capability and subject is recorded as unknown.
    pub(super) fn stamp(
        capability: Capability,
        subject: Subject,
        source: SourceClass,
        observation: Observation,
        reading: ClockReading,
    ) -> Self {
        let Observation {
            configuration,
            fresh_for,
            result,
        } = observation;
        let result = match result {
            ObservationResult::Supported { detail } if !detail.fits(capability, &subject) => {
                ObservationResult::Unknown {
                    reason: UnknownReason::InconsistentReport,
                }
            }
            result => result,
        };
        Self {
            schema_version: SchemaVersion::CURRENT,
            capability,
            subject,
            configuration,
            source,
            clock: reading.session,
            observed_at: reading.at,
            fresh_for,
            result,
        }
    }

    pub fn schema_version(&self) -> SchemaVersion {
        self.schema_version
    }

    pub fn capability(&self) -> Capability {
        self.capability
    }

    pub fn subject(&self) -> &Subject {
        &self.subject
    }

    pub fn subject_identity(&self) -> Digest {
        self.subject.identity()
    }

    pub fn configuration(&self) -> ConfigurationFingerprint {
        self.configuration
    }

    pub fn source(&self) -> SourceClass {
        self.source
    }

    pub fn clock(&self) -> ClockSession {
        self.clock
    }

    pub fn observed_at(&self) -> MonotonicTime {
        self.observed_at
    }

    pub fn fresh_for(&self) -> Duration {
        self.fresh_for
    }

    pub fn result(&self) -> &ObservationResult {
        &self.result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::evidence::subject::{
        Backend, HostSubject, HypervisorSubject, ProviderKind, ProviderSubject, RuntimeSubject,
    };
    use crate::foundation::ids::digest;

    fn runtime(version: &str) -> Subject {
        Subject::Runtime(RuntimeSubject {
            category: ExecutionCategory::SharedKernelGpuRuntime,
            release: BackendRelease::new(Backend::Vllm, version).unwrap(),
            instance: digest("yougori/test/instance/v1", &[b"i1"]),
        })
    }

    fn reading() -> ClockReading {
        ClockReading {
            session: ClockSession::from_uuid(uuid::Uuid::from_u128(7)),
            at: MonotonicTime::from_nanos(5_000),
        }
    }

    fn fingerprint() -> ConfigurationFingerprint {
        ConfigurationFingerprint::from_settings([("driver", "580.1")]).unwrap()
    }

    fn envelope() -> EvidenceEnvelope {
        EvidenceEnvelope::stamp(
            Capability::CudaIpcVmmShareableHandle,
            runtime("0.31.0"),
            SourceClass::HostProbe,
            Observation::supported(
                fingerprint(),
                Duration::from_secs(60),
                SupportDetail::CudaIpcVmmShareableHandle {
                    handle: ShareableHandle::PosixFileDescriptor,
                },
            ),
            reading(),
        )
    }

    #[test]
    fn envelopes_round_trip_with_the_pinned_schema_version() {
        let envelope = envelope();
        let json = serde_json::to_value(&envelope).unwrap();
        assert_eq!(json["schema_version"], EVIDENCE_SCHEMA_VERSION);
        assert_eq!(json["capability"], "cuda_ipc_vmm_shareable_handle");
        assert_eq!(json["source"], "host_probe");
        assert_eq!(json["subject"]["kind"], "runtime");
        assert_eq!(json["result"]["outcome"], "supported");
        assert_eq!(
            json["result"]["detail"]["kind"],
            "cuda_ipc_vmm_shareable_handle"
        );
        assert_eq!(json["result"]["detail"]["handle"], "posix_file_descriptor");
        assert_eq!(json["observed_at"], 5_000);
        let back: EvidenceEnvelope = serde_json::from_value(json).unwrap();
        assert_eq!(back, envelope);
        assert_eq!(back.schema_version(), SchemaVersion::CURRENT);
        assert_eq!(back.subject_identity(), runtime("0.31.0").identity());
    }

    #[test]
    fn other_schema_versions_and_unknown_fields_are_refused() {
        let json = serde_json::to_value(envelope()).unwrap();
        for version in [0, 2, u32::MAX] {
            let mut changed = json.clone();
            changed["schema_version"] = version.into();
            let error = serde_json::from_value::<EvidenceEnvelope>(changed).unwrap_err();
            assert!(error.to_string().contains("not supported"), "{error}");
        }
        let mut missing = json.clone();
        missing.as_object_mut().unwrap().remove("schema_version");
        assert!(serde_json::from_value::<EvidenceEnvelope>(missing).is_err());
        let mut extra = json;
        extra["trusted"] = true.into();
        assert!(serde_json::from_value::<EvidenceEnvelope>(extra).is_err());
        assert_eq!(
            SchemaVersion::try_from(2),
            Err(UnsupportedSchemaVersion { found: 2 })
        );
        assert_eq!(SchemaVersion::CURRENT.get(), 1);
    }

    #[test]
    fn source_classes_are_ordered_by_trust() {
        let ordered = [
            SourceClass::Fixture,
            SourceClass::RecordedDeclaration,
            SourceClass::GuestReport,
            SourceClass::ProviderApi,
            SourceClass::HostProbe,
        ];
        for pair in ordered.windows(2) {
            assert!(pair[0] < pair[1]);
            assert!(pair[1].satisfies(pair[0]));
            assert!(!pair[0].satisfies(pair[1]));
        }
        assert!(SourceClass::HostProbe.satisfies(SourceClass::HostProbe));
        assert!(!SourceClass::GuestReport.satisfies(SourceClass::HostProbe));
    }

    #[test]
    fn capability_floors_and_subjects() {
        assert_eq!(
            Capability::HypervisorAvailable.weakest_source(),
            SourceClass::HostProbe
        );
        assert_eq!(
            Capability::ProviderContainer.weakest_source(),
            SourceClass::ProviderApi
        );
        for capability in Capability::ALL {
            assert!(capability.weakest_source() >= SourceClass::GuestReport);
            assert!(!capability.name().is_empty());
        }
        assert_ne!(
            Capability::CudaIpcLegacy,
            Capability::CudaIpcVmmShareableHandle
        );
        assert_eq!(Capability::CudaIpcLegacy.domain(), CapabilityDomain::Gpu);
        assert_eq!(
            Capability::IoUring.domain(),
            CapabilityDomain::OperatingSystem
        );
        assert_eq!(
            Capability::ZeroCopyPreload.domain(),
            CapabilityDomain::Backend
        );
        assert_eq!(
            Capability::HypervisorAvailable.subject_kind(),
            SubjectKind::Hypervisor
        );
        assert_eq!(
            Capability::ProviderContainer.subject_kind(),
            SubjectKind::Provider
        );
        assert_eq!(
            Capability::CudaCheckpoint.subject_kind(),
            SubjectKind::Runtime
        );
    }

    #[test]
    fn fingerprints_ignore_order_and_refuse_ambiguous_settings() {
        let one = ConfigurationFingerprint::from_settings([("driver", "580.1"), ("kernel", "6.6")])
            .unwrap();
        let other =
            ConfigurationFingerprint::from_settings([("kernel", "6.6"), ("driver", "580.1")])
                .unwrap();
        assert_eq!(one, other);
        let changed =
            ConfigurationFingerprint::from_settings([("driver", "580.2"), ("kernel", "6.6")])
                .unwrap();
        assert_ne!(one, changed);
        assert_ne!(
            ConfigurationFingerprint::from_settings([("ab", "c")]).unwrap(),
            ConfigurationFingerprint::from_settings([("a", "bc")]).unwrap()
        );
        assert_eq!(
            ConfigurationFingerprint::from_settings([("driver", "1"), ("driver", "2")]),
            Err(FingerprintError::RepeatedName {
                name: "driver".to_owned()
            })
        );
        assert_eq!(
            ConfigurationFingerprint::from_settings([("", "1")]),
            Err(FingerprintError::EmptyName)
        );
        assert_eq!(ConfigurationFingerprint::from_digest(one.digest()), one);
    }

    #[test]
    fn details_must_fit_capability_and_subject() {
        let vmm = SupportDetail::CudaIpcVmmShareableHandle {
            handle: ShareableHandle::Win32Handle,
        };
        assert!(vmm.fits(Capability::CudaIpcVmmShareableHandle, &runtime("0.31.0")));
        assert!(!vmm.fits(Capability::CudaIpcLegacy, &runtime("0.31.0")));
        assert!(!SupportDetail::CudaIpcLegacy
            .fits(Capability::CudaIpcVmmShareableHandle, &runtime("0.31.0")));
        assert!(SupportDetail::CudaIpcLegacy.fits(Capability::CudaIpcLegacy, &runtime("0.31.0")));
        assert!(!SupportDetail::Plain.fits(Capability::CudaIpcLegacy, &runtime("0.31.0")));

        let mode = SupportDetail::BackendMode {
            release: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
        };
        assert!(mode.fits(Capability::ZeroCopyPreload, &runtime("0.31.0")));
        assert!(!mode.fits(Capability::ZeroCopyPreload, &runtime("0.29.0")));

        let machine = digest("yougori/test/machine/v1", &[b"m"]);
        let whpx = Subject::Hypervisor(HypervisorSubject {
            machine,
            hypervisor: HypervisorKind::Whpx,
        });
        assert!(SupportDetail::Hypervisor {
            hypervisor: HypervisorKind::Whpx
        }
        .fits(Capability::HypervisorAvailable, &whpx));
        assert!(!SupportDetail::Hypervisor {
            hypervisor: HypervisorKind::Hcs
        }
        .fits(Capability::HypervisorAvailable, &whpx));
        assert!(!SupportDetail::Plain
            .fits(Capability::IoUring, &Subject::Host(HostSubject { machine })));
        let pod = Subject::Provider(ProviderSubject {
            provider: ProviderKind::RunPod,
            resource: machine,
        });
        assert!(SupportDetail::ProviderContainer {
            gvisor: true,
            nvproxy: false
        }
        .fits(Capability::ProviderContainer, &pod));
    }

    #[test]
    fn a_detail_from_the_other_api_family_is_recorded_as_unknown() {
        let envelope = EvidenceEnvelope::stamp(
            Capability::CudaIpcLegacy,
            runtime("0.31.0"),
            SourceClass::HostProbe,
            Observation::supported(
                fingerprint(),
                Duration::from_secs(60),
                SupportDetail::CudaIpcVmmShareableHandle {
                    handle: ShareableHandle::Fabric,
                },
            ),
            reading(),
        );
        assert_eq!(
            envelope.result(),
            &ObservationResult::Unknown {
                reason: UnknownReason::InconsistentReport
            }
        );
    }

    #[test]
    fn every_reason_names_a_remedy() {
        for reason in [
            UnsupportedReason::OperationFailed,
            UnsupportedReason::FeatureAbsent,
            UnsupportedReason::DisabledByPolicy,
            UnsupportedReason::HypervisorUnavailable,
            UnsupportedReason::NotAProviderContainer,
            UnsupportedReason::DifferentCategory,
            UnsupportedReason::NotEnforced,
        ] {
            assert!(!reason.to_string().is_empty());
            assert!(!reason.remedy().to_string().is_empty());
        }
        assert_eq!(
            UnsupportedReason::NotEnforced.remedy(),
            Remedy::RepairPerimeter
        );
        assert_eq!(
            UnsupportedReason::HypervisorUnavailable.remedy(),
            Remedy::EnableHypervisorYourself
        );
        assert_eq!(
            UnsupportedReason::DifferentCategory.remedy(),
            Remedy::ChooseAllowedCategory
        );
        assert_eq!(UnknownReason::NotTested.remedy(), Remedy::RunCheck);
        assert_eq!(UnknownReason::Inconclusive.remedy(), Remedy::RunCheckAgain);
        assert!(Remedy::EnableHypervisorYourself
            .to_string()
            .contains("does not change host settings"));
    }

    #[test]
    fn a_category_detail_fits_only_the_category_of_its_runtime() {
        let wsl = runtime("0.31.0");
        let shared = SupportDetail::RuntimeCategory {
            category: ExecutionCategory::SharedKernelGpuRuntime,
        };
        assert!(shared.fits(Capability::RuntimeCategory, &wsl));
        for category in [
            ExecutionCategory::VmSandbox,
            ExecutionCategory::ProviderContainerRuntime,
            ExecutionCategory::HostProcessModelRuntime,
        ] {
            assert!(!SupportDetail::RuntimeCategory { category }
                .fits(Capability::RuntimeCategory, &wsl));
        }
        assert!(!shared.fits(Capability::IoUring, &wsl));
        assert!(!SupportDetail::Plain.fits(Capability::RuntimeCategory, &wsl));
        assert_eq!(
            Capability::RuntimeCategory.weakest_source(),
            SourceClass::ProviderApi
        );
        assert_eq!(
            Capability::RuntimeCategory.domain(),
            CapabilityDomain::Isolation
        );
    }

    /// Review finding 5: a read envelope used to skip the checks `stamp` makes.
    #[test]
    fn a_read_envelope_must_pass_the_stamp_checks() {
        let machine = digest("yougori/test/machine/v1", &[b"m"]).to_hex();
        let forged = serde_json::json!({
            "schema_version": 1,
            "capability": "cuda_ipc_vmm_shareable_handle",
            "subject": {"kind": "host", "machine": machine},
            "configuration": fingerprint().to_string(),
            "source": "host_probe",
            "clock": "00000000-0000-0000-0000-000000000007",
            "observed_at": 0,
            "fresh_for": {"secs": u64::MAX, "nanos": 0},
            "result": {"outcome": "supported", "detail": {"kind": "cuda_ipc_legacy"}}
        });
        let error = serde_json::from_value::<EvidenceEnvelope>(forged.clone()).unwrap_err();
        assert!(error.to_string().contains("is about a runtime"), "{error}");

        let mut other_family = serde_json::to_value(envelope()).unwrap();
        other_family["result"]["detail"] = serde_json::json!({"kind": "cuda_ipc_legacy"});
        let error = serde_json::from_value::<EvidenceEnvelope>(other_family).unwrap_err();
        assert!(error.to_string().contains("does not fit"), "{error}");

        let mut other_category = serde_json::to_value(EvidenceEnvelope::stamp(
            Capability::RuntimeCategory,
            runtime("0.31.0"),
            SourceClass::HostProbe,
            Observation::supported(
                fingerprint(),
                Duration::from_secs(60),
                SupportDetail::RuntimeCategory {
                    category: ExecutionCategory::SharedKernelGpuRuntime,
                },
            ),
            reading(),
        ))
        .unwrap();
        assert!(serde_json::from_value::<EvidenceEnvelope>(other_category.clone()).is_ok());
        other_category["result"]["detail"]["category"] = "vm_sandbox".into();
        assert!(serde_json::from_value::<EvidenceEnvelope>(other_category).is_err());

        let mut unknown = serde_json::to_value(envelope()).unwrap();
        unknown["result"] = serde_json::json!({"outcome": "unknown", "reason": "not_tested"});
        assert!(serde_json::from_value::<EvidenceEnvelope>(unknown).is_ok());
    }

    /// serde accepts unknown fields beside the tag of a unit variant unless the enum reads
    /// each variant as a struct; every tagged enum here does.
    #[test]
    fn tagged_enums_refuse_unknown_fields() {
        for (json, ok) in [
            (r#"{"kind":"plain"}"#, true),
            (r#"{"kind":"plain","trusted":true}"#, false),
            (r#"{"kind":"cuda_ipc_legacy","family":"vmm"}"#, false),
            (r#"{"kind":"hypervisor","hypervisor":"whpx"}"#, true),
            (
                r#"{"kind":"hypervisor","hypervisor":"whpx","host":true}"#,
                false,
            ),
        ] {
            assert_eq!(
                serde_json::from_str::<SupportDetail>(json).is_ok(),
                ok,
                "{json}"
            );
        }
        assert!(serde_json::from_str::<ObservationResult>(
            r#"{"outcome":"unknown","reason":"not_tested","passed":true}"#
        )
        .is_err());
        assert!(serde_json::from_str::<Remedy>(r#"{"action":"run_check"}"#).is_ok());
        assert!(serde_json::from_str::<Remedy>(r#"{"action":"run_check","then":"x"}"#).is_err());
        assert_eq!(
            serde_json::to_string(&SupportDetail::Plain).unwrap(),
            r#"{"kind":"plain"}"#
        );
    }

    #[test]
    fn new_capabilities_have_their_subject_floor_and_name() {
        for (capability, kind, floor) in [
            (
                Capability::CudaVmmAllocation,
                SubjectKind::CudaAllocation,
                SourceClass::GuestReport,
            ),
            (
                Capability::ComputePlatform,
                SubjectKind::Runtime,
                SourceClass::GuestReport,
            ),
            (
                Capability::SleepWeightDiscard,
                SubjectKind::Runtime,
                SourceClass::GuestReport,
            ),
            (
                Capability::GpuPeerAccess,
                SubjectKind::GpuPair,
                SourceClass::GuestReport,
            ),
            (
                Capability::CheckpointCompatibility,
                SubjectKind::ModelCheckpoint,
                SourceClass::GuestReport,
            ),
            (
                Capability::GpuFreeMemory,
                SubjectKind::GpuDevice,
                SourceClass::HostProbe,
            ),
            (
                Capability::PeerTopology,
                SubjectKind::Runtime,
                SourceClass::GuestReport,
            ),
            (
                Capability::ExecuteWhileLoad,
                SubjectKind::Runtime,
                SourceClass::GuestReport,
            ),
            (
                Capability::PerimeterRuleEnforced,
                SubjectKind::PerimeterRule,
                SourceClass::HostProbe,
            ),
        ] {
            assert_eq!(capability.subject_kind(), kind, "{capability}");
            assert_eq!(capability.weakest_source(), floor, "{capability}");
        }
        let names: BTreeSet<&str> = Capability::ALL.iter().map(|c| c.name()).collect();
        assert_eq!(names.len(), Capability::ALL.len());
        let distinct: BTreeSet<Capability> = Capability::ALL.into_iter().collect();
        assert_eq!(distinct.len(), Capability::ALL.len());
        assert_ne!(
            Capability::SleepWeightDiscard,
            Capability::SleepWeightOffload
        );
    }

    fn pair(from: &[u8], to: &[u8]) -> Subject {
        let machine = digest("yougori/test/machine/v1", &[b"m"]);
        Subject::GpuPair(crate::foundation::evidence::subject::GpuPairSubject {
            machine,
            from: digest("yougori/test/device/v1", &[from]),
            to: digest("yougori/test/device/v1", &[to]),
        })
    }

    fn path(from: u32, to: u32) -> PeerPath {
        PeerPath {
            from,
            to,
            link: PeerLink::NvLink,
            access: PeerAccess::Verified,
        }
    }

    fn topology(count: u32, paths: Vec<PeerPath>) -> SupportDetail {
        SupportDetail::PeerTopology {
            device_count: NonZeroU32::new(count).unwrap(),
            paths,
        }
    }

    #[test]
    fn new_details_fit_only_their_capability_and_possible_measurements() {
        use crate::foundation::evidence::subject::{
            CudaAllocationSubject, GpuDeviceSubject, ModelCheckpointSubject, PerimeterRuleSubject,
        };

        let wsl = runtime("0.31.0");
        let allocation = Subject::CudaAllocation(CudaAllocationSubject {
            runtime: RuntimeSubject {
                category: ExecutionCategory::SharedKernelGpuRuntime,
                release: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
                instance: digest("yougori/test/instance/v1", &[b"i1"]),
            },
            device_ordinal: 0,
            requested_handle: Some(ShareableHandle::PosixFileDescriptor),
        });
        let granularity = SupportDetail::CudaVmmAllocation {
            granularity_bytes: NonZeroU64::new(2 << 20).unwrap(),
        };
        assert!(granularity.fits(Capability::CudaVmmAllocation, &allocation));
        assert!(!granularity.fits(Capability::CudaVmmAllocation, &wsl));
        assert!(!granularity.fits(Capability::CudaIpcVmmShareableHandle, &allocation));

        let cuda = SupportDetail::ComputePlatform {
            platform: ComputePlatform::Cuda,
        };
        assert!(cuda.fits(Capability::ComputePlatform, &wsl));
        assert!(!SupportDetail::Plain.fits(Capability::ComputePlatform, &wsl));

        let mode = SupportDetail::BackendMode {
            release: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
        };
        assert!(mode.fits(Capability::SleepWeightDiscard, &wsl));
        assert!(!mode.fits(Capability::SleepWeightDiscard, &runtime("0.29.0")));

        assert!(SupportDetail::GpuPeerAccess.fits(Capability::GpuPeerAccess, &pair(b"a", b"b")));
        assert!(!SupportDetail::GpuPeerAccess.fits(Capability::GpuPeerAccess, &pair(b"a", b"a")));

        let checkpoint = Subject::ModelCheckpoint(ModelCheckpointSubject {
            checkpoint: digest("yougori/test/checkpoint/v1", &[b"qwen"]),
            release: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
            image: digest("yougori/test/image/v1", &[b"image"]),
            hardware: digest("yougori/test/hardware/v1", &[b"2x4090"]),
        });
        let record = SupportDetail::CheckpointCompatibility {
            record: digest("yougori/test/record/v1", &[b"r"]),
        };
        assert!(record.fits(Capability::CheckpointCompatibility, &checkpoint));
        assert!(!record.fits(Capability::CheckpointCompatibility, &wsl));

        let gpu = Subject::GpuDevice(GpuDeviceSubject {
            machine: digest("yougori/test/machine/v1", &[b"m"]),
            device: digest("yougori/test/device/v1", &[b"a"]),
        });
        let memory = |free: u64, total: u64| SupportDetail::GpuMemory {
            free_bytes: free,
            total_bytes: NonZeroU64::new(total).unwrap(),
        };
        assert!(memory(10, 24).fits(Capability::GpuFreeMemory, &gpu));
        assert!(memory(24, 24).fits(Capability::GpuFreeMemory, &gpu));
        assert!(!memory(25, 24).fits(Capability::GpuFreeMemory, &gpu));

        let complete = topology(2, vec![path(0, 1), path(1, 0)]);
        assert!(complete.fits(Capability::PeerTopology, &wsl));
        assert!(topology(1, Vec::new()).fits(Capability::PeerTopology, &wsl));
        for broken in [
            topology(2, vec![path(0, 1)]),
            topology(2, vec![path(0, 1), path(0, 1)]),
            topology(2, vec![path(0, 1), path(1, 1)]),
            topology(2, vec![path(0, 1), path(1, 2)]),
            topology(u32::MAX, Vec::new()),
            topology(3, vec![path(0, 1), path(1, 0)]),
        ] {
            assert!(!broken.fits(Capability::PeerTopology, &wsl), "{broken:?}");
        }

        assert!(SupportDetail::ExecuteWhileLoad.fits(Capability::ExecuteWhileLoad, &wsl));
        assert!(!SupportDetail::Plain.fits(Capability::ExecuteWhileLoad, &wsl));

        let rule = Subject::PerimeterRule(PerimeterRuleSubject {
            machine: digest("yougori/test/machine/v1", &[b"m"]),
            perimeter: digest("yougori/test/perimeter/v1", &[b"p"]),
            rule: digest("yougori/test/rule/v1", &[b"r"]),
            principal: digest("yougori/test/principal/v1", &[b"broker"]),
        });
        let enforced = SupportDetail::PerimeterRuleEnforced;
        assert!(enforced.fits(Capability::PerimeterRuleEnforced, &rule));
        assert!(!enforced.fits(Capability::PerimeterRuleEnforced, &gpu));
    }

    /// The eight VM boundary facts of §17 (M08), with their subject kind, domain and
    /// serialized name.
    const BOUNDARY: [(Capability, SubjectKind, CapabilityDomain, &str); 8] = [
        (
            Capability::HypervisorConfigurationMatches,
            SubjectKind::HypervisorProcess,
            CapabilityDomain::Hypervisor,
            "hypervisor_configuration_matches",
        ),
        (
            Capability::HypervisorConfined,
            SubjectKind::HypervisorProcess,
            CapabilityDomain::Hypervisor,
            "hypervisor_confined",
        ),
        (
            Capability::BootedImageMatchesManifest,
            SubjectKind::SandboxBoot,
            CapabilityDomain::SandboxBoundary,
            "booted_image_matches_manifest",
        ),
        (
            Capability::DestinationPolicyEnforced,
            SubjectKind::TransportBroker,
            CapabilityDomain::SandboxBoundary,
            "destination_policy_enforced",
        ),
        (
            Capability::NoGuestNetworkDevice,
            SubjectKind::SandboxBoot,
            CapabilityDomain::SandboxBoundary,
            "no_guest_network_device",
        ),
        (
            Capability::CredentialAbsentFromScannedLocations,
            SubjectKind::CredentialScan,
            CapabilityDomain::SandboxBoundary,
            "credential_absent_from_scanned_locations",
        ),
        (
            Capability::CloneIdentityReset,
            SubjectKind::SnapshotClones,
            CapabilityDomain::SandboxBoundary,
            "clone_identity_reset",
        ),
        (
            Capability::DeviceAssignmentIsolated,
            SubjectKind::GpuDevice,
            CapabilityDomain::Gpu,
            "device_assignment_isolated",
        ),
    ];

    /// One subject of each kind a boundary fact is observed on, and of the kinds next to
    /// them.
    fn boundary_subjects() -> Vec<Subject> {
        use crate::foundation::evidence::subject::{
            CredentialScanSubject, GpuDeviceSubject, HypervisorProcessSubject,
            PerimeterRuleSubject, SandboxBootSubject, SnapshotClonesSubject,
            TransportBrokerSubject,
        };
        let part = |name: &[u8]| digest("yougori/test/boundary/v1", &[name]);
        let launch = SandboxBootSubject {
            machine: part(b"machine"),
            vm: part(b"vm"),
            boot: crate::foundation::ids::SandboxBootGeneration::new(4),
        };
        vec![
            Subject::SandboxBoot(launch),
            Subject::HypervisorProcess(HypervisorProcessSubject {
                launch,
                process: part(b"process"),
            }),
            Subject::TransportBroker(TransportBrokerSubject {
                machine: part(b"machine"),
                perimeter: part(b"perimeter"),
                broker: part(b"broker"),
                policy: part(b"policy"),
            }),
            Subject::CredentialScan(CredentialScanSubject {
                launch,
                locations: part(b"locations"),
            }),
            Subject::SnapshotClones(SnapshotClonesSubject {
                machine: part(b"machine"),
                snapshot: part(b"golden"),
                clones: part(b"clones"),
            }),
            Subject::GpuDevice(GpuDeviceSubject {
                machine: part(b"machine"),
                device: part(b"gpu"),
            }),
            Subject::Hypervisor(HypervisorSubject {
                machine: part(b"machine"),
                hypervisor: HypervisorKind::Kvm,
            }),
            Subject::PerimeterRule(PerimeterRuleSubject {
                machine: part(b"machine"),
                perimeter: part(b"perimeter"),
                rule: part(b"rule"),
                principal: part(b"broker"),
            }),
            runtime("0.31.0"),
            Subject::Host(HostSubject {
                machine: part(b"machine"),
            }),
        ]
    }

    #[test]
    fn the_boundary_capabilities_are_additive_host_facts() {
        // Every earlier capability keeps its place and its serialized name.
        let earlier = [
            "cuda_ipc_legacy",
            "cuda_ipc_vmm_shareable_handle",
            "gpu_direct_storage",
            "cuda_checkpoint",
            "io_uring",
            "zero_copy_preload",
            "sleep_weight_offload",
            "hypervisor_available",
            "provider_container",
            "runtime_category",
            "cuda_vmm_allocation",
            "compute_platform",
            "sleep_weight_discard",
            "gpu_peer_access",
            "checkpoint_compatibility",
            "gpu_free_memory",
            "peer_topology",
            "execute_while_load",
            "perimeter_rule_enforced",
        ];
        let names: Vec<serde_json::Value> = Capability::ALL
            .iter()
            .map(|capability| serde_json::to_value(capability).unwrap())
            .collect();
        assert_eq!(names[..earlier.len()], earlier.map(serde_json::Value::from));
        let boundary_end = earlier.len() + BOUNDARY.len();
        assert_eq!(
            Capability::ALL[earlier.len()..boundary_end],
            BOUNDARY.map(|(capability, ..)| capability)
        );
        // The backend capabilities of GPU-W10 come after them.
        assert_eq!(
            Capability::ALL[boundary_end..],
            [Capability::KvGrowth, Capability::AdapterLimits]
        );
        for pair in Capability::ALL.windows(2) {
            assert!(pair[0] < pair[1], "ALL follows the declaration order");
        }
        for (capability, kind, domain, name) in BOUNDARY {
            assert_eq!(capability.subject_kind(), kind, "{capability}");
            assert_eq!(capability.domain(), domain, "{capability}");
            assert_eq!(capability.weakest_source(), SourceClass::HostProbe);
            assert_eq!(serde_json::to_value(capability).unwrap(), name);
            assert_eq!(
                serde_json::from_value::<Capability>(name.into()).unwrap(),
                capability
            );
        }
        let user_names: BTreeSet<&str> = Capability::ALL.iter().map(|c| c.name()).collect();
        assert_eq!(user_names.len(), Capability::ALL.len());
        assert_eq!(
            serde_json::to_value(CapabilityDomain::SandboxBoundary).unwrap(),
            "sandbox_boundary"
        );
    }

    #[test]
    fn a_boundary_fact_is_supported_plainly_and_only_on_its_own_subject() {
        let subjects = boundary_subjects();
        let boundary: BTreeSet<Capability> = BOUNDARY.iter().map(|entry| entry.0).collect();
        let others = [
            SupportDetail::PerimeterRuleEnforced,
            SupportDetail::Hypervisor {
                hypervisor: HypervisorKind::Kvm,
            },
            SupportDetail::GpuMemory {
                free_bytes: 1,
                total_bytes: NonZeroU64::new(2).unwrap(),
            },
            SupportDetail::GpuPeerAccess,
            SupportDetail::ExecuteWhileLoad,
            SupportDetail::CudaIpcLegacy,
        ];
        for (capability, kind, ..) in BOUNDARY {
            for subject in &subjects {
                assert_eq!(
                    SupportDetail::Plain.fits(capability, subject),
                    subject.kind() == kind,
                    "{capability} on {}",
                    subject.kind()
                );
                for detail in &others {
                    assert!(!detail.fits(capability, subject), "{capability} {detail:?}");
                }
            }
        }
        // A plain detail on a boundary subject describes no other capability.
        for capability in Capability::ALL {
            if boundary.contains(&capability) {
                continue;
            }
            for subject in &subjects[..6] {
                assert!(
                    !SupportDetail::Plain.fits(capability, subject),
                    "{capability} on {}",
                    subject.kind()
                );
            }
        }
    }

    #[test]
    fn each_boundary_fact_has_its_own_refusal() {
        let reasons = [
            (
                UnsupportedReason::ConfigurationNotApproved,
                "configuration_not_approved",
            ),
            (UnsupportedReason::NotConfined, "not_confined"),
            (UnsupportedReason::ImageNotAsSigned, "image_not_as_signed"),
            (
                UnsupportedReason::DestinationNotRefused,
                "destination_not_refused",
            ),
            (UnsupportedReason::GuestNetworkPath, "guest_network_path"),
            (UnsupportedReason::CredentialExposed, "credential_exposed"),
            (
                UnsupportedReason::CloneIdentityShared,
                "clone_identity_shared",
            ),
            (UnsupportedReason::DeviceNotIsolated, "device_not_isolated"),
        ];
        let mut texts = BTreeSet::new();
        for (reason, name) in reasons {
            assert_eq!(serde_json::to_value(reason).unwrap(), name);
            assert_eq!(
                serde_json::from_value::<UnsupportedReason>(name.into()).unwrap(),
                reason
            );
            assert_eq!(reason.remedy(), Remedy::ChooseSupportedRuntime);
            assert!(texts.insert(reason.to_string()), "{reason:?}");
        }
        assert_eq!(
            UnsupportedReason::NotEnforced.remedy(),
            Remedy::RepairPerimeter
        );
    }

    #[test]
    fn a_boundary_envelope_round_trips_and_a_misplaced_one_is_refused() {
        let boot = boundary_subjects().remove(0);
        let envelope = EvidenceEnvelope::stamp(
            Capability::NoGuestNetworkDevice,
            boot.clone(),
            SourceClass::HostProbe,
            Observation::supported(fingerprint(), Duration::from_secs(60), SupportDetail::Plain),
            reading(),
        );
        let json = serde_json::to_value(&envelope).unwrap();
        assert_eq!(json["capability"], "no_guest_network_device");
        assert_eq!(json["subject"]["kind"], "sandbox_boot");
        assert_eq!(json["subject"]["boot"], 4);
        assert_eq!(
            serde_json::from_value::<EvidenceEnvelope>(json.clone()).unwrap(),
            envelope
        );

        let mut other_kind = json.clone();
        other_kind["capability"] = "hypervisor_confined".into();
        let error = serde_json::from_value::<EvidenceEnvelope>(other_kind).unwrap_err();
        assert!(
            error.to_string().contains("is about a hypervisor process"),
            "{error}"
        );

        let mut other_detail = json;
        other_detail["result"]["detail"] = serde_json::json!({"kind": "perimeter_rule_enforced"});
        let error = serde_json::from_value::<EvidenceEnvelope>(other_detail).unwrap_err();
        assert!(error.to_string().contains("does not fit"), "{error}");

        let stamped = EvidenceEnvelope::stamp(
            Capability::BootedImageMatchesManifest,
            boot,
            SourceClass::HostProbe,
            Observation::supported(
                fingerprint(),
                Duration::from_secs(60),
                SupportDetail::Hypervisor {
                    hypervisor: HypervisorKind::Kvm,
                },
            ),
            reading(),
        );
        assert_eq!(
            stamped.result(),
            &ObservationResult::Unknown {
                reason: UnknownReason::InconsistentReport
            }
        );
    }

    #[test]
    fn new_details_round_trip_and_refuse_impossible_values() {
        for detail in [
            SupportDetail::CudaVmmAllocation {
                granularity_bytes: NonZeroU64::new(2 << 20).unwrap(),
            },
            SupportDetail::ComputePlatform {
                platform: ComputePlatform::Metal,
            },
            SupportDetail::GpuPeerAccess,
            SupportDetail::CheckpointCompatibility {
                record: digest("yougori/test/record/v1", &[b"r"]),
            },
            SupportDetail::GpuMemory {
                free_bytes: 1,
                total_bytes: NonZeroU64::new(2).unwrap(),
            },
            topology(2, vec![path(0, 1), path(1, 0)]),
            SupportDetail::ExecuteWhileLoad,
            SupportDetail::PerimeterRuleEnforced,
        ] {
            let json = serde_json::to_value(&detail).unwrap();
            assert_eq!(
                serde_json::from_value::<SupportDetail>(json.clone()).unwrap(),
                detail
            );
            let mut extra = json;
            extra["assumed"] = true.into();
            assert!(serde_json::from_value::<SupportDetail>(extra).is_err());
        }
        for zero in [
            r#"{"kind":"cuda_vmm_allocation","granularity_bytes":0}"#,
            r#"{"kind":"gpu_memory","free_bytes":0,"total_bytes":0}"#,
            r#"{"kind":"peer_topology","device_count":0,"paths":[]}"#,
            r#"{"kind":"compute_platform","platform":"other"}"#,
        ] {
            assert!(
                serde_json::from_str::<SupportDetail>(zero).is_err(),
                "{zero}"
            );
        }
    }
}
