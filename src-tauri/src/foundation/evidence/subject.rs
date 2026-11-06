//! What an observation is about: the typed subject and its identity digest (CORE-01).

use std::fmt;

use serde::{Deserialize, Serialize};

use super::envelope::ShareableHandle;
use crate::foundation::ids::{Digest, DigestBuilder, ExecutionCategory, SandboxBootGeneration};

/// Domain of [`Subject::identity`]: the kind tag, then the kind's fields in declaration
/// order.
const SUBJECT_DOMAIN: &str = "yougori/evidence/subject/v1";

/// The kind of thing an observation is about (CORE-01: host, GPU device, hypervisor, OS,
/// provider, runtime/backend and version). A probe sees only its subject, so every
/// parameter it needs, such as a device pair, a checkpoint, a perimeter rule or the boot
/// a VM boundary check looked at, is part of the subject, and evidence about one never
/// answers for another.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectKind {
    Host,
    GpuDevice,
    Hypervisor,
    OperatingSystem,
    Provider,
    Runtime,
    GpuPair,
    ModelCheckpoint,
    CudaAllocation,
    PerimeterRule,
    SandboxBoot,
    HypervisorProcess,
    TransportBroker,
    CredentialScan,
    SnapshotClones,
}

impl SubjectKind {
    /// The stable tag hashed into [`Subject::identity`].
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::GpuDevice => "gpu_device",
            Self::Hypervisor => "hypervisor",
            Self::OperatingSystem => "operating_system",
            Self::Provider => "provider",
            Self::Runtime => "runtime",
            Self::GpuPair => "gpu_pair",
            Self::ModelCheckpoint => "model_checkpoint",
            Self::CudaAllocation => "cuda_allocation",
            Self::PerimeterRule => "perimeter_rule",
            Self::SandboxBoot => "sandbox_boot",
            Self::HypervisorProcess => "hypervisor_process",
            Self::TransportBroker => "transport_broker",
            Self::CredentialScan => "credential_scan",
            Self::SnapshotClones => "snapshot_clones",
        }
    }
}

impl fmt::Display for SubjectKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Host => "host",
            Self::GpuDevice => "GPU device",
            Self::Hypervisor => "hypervisor",
            Self::OperatingSystem => "operating system",
            Self::Provider => "provider resource",
            Self::Runtime => "runtime",
            Self::GpuPair => "GPU pair",
            Self::ModelCheckpoint => "model checkpoint",
            Self::CudaAllocation => "CUDA allocation",
            Self::PerimeterRule => "perimeter rule",
            Self::SandboxBoot => "sandbox boot",
            Self::HypervisorProcess => "hypervisor process",
            Self::TransportBroker => "transport broker",
            Self::CredentialScan => "credential scan",
            Self::SnapshotClones => "golden snapshot and its clones",
        })
    }
}

/// A machine, named by an identity digest its host adapter derives from stable machine
/// facts; raw machine identifiers stay out of evidence (S8 redaction).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostSubject {
    pub machine: Digest,
}

/// One GPU on one machine, named by a digest of its device identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GpuDeviceSubject {
    pub machine: Digest,
    pub device: Digest,
}

/// One hypervisor interface on one machine (VM part §1.3, VM-CP-01).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HypervisorSubject {
    pub machine: Digest,
    pub hypervisor: HypervisorKind,
}

/// The operating system of one machine, or the WSL2 environment on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatingSystemSubject {
    pub machine: Digest,
    pub os: OsKind,
}

/// One resource of a cloud provider, such as a RunPod pod (VM-D5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderSubject {
    pub provider: ProviderKind,
    pub resource: Digest,
}

/// One exact runtime: its execution category, backend release and instance (INT-06:
/// "the exact runtime/profile"). The instance digest names where it runs, such as the
/// machine, device and image, or the VM or pod.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSubject {
    pub category: ExecutionCategory,
    pub release: BackendRelease,
    pub instance: Digest,
}

/// One direction between two GPUs on one machine, by their device digests (FAST-02:
/// peer access is probed, never assumed). The opposite direction is another subject.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GpuPairSubject {
    pub machine: Digest,
    pub from: Digest,
    pub to: Digest,
}

/// One model checkpoint on one pinned engine and hardware class (FAST-02 "checkpoint
/// compatibility"; FAST-04: the pinned engine/model/method combination).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelCheckpointSubject {
    /// The exact checkpoint, such as its logical model identity.
    pub checkpoint: Digest,
    pub release: BackendRelease,
    /// Digest of the engine image.
    pub image: Digest,
    /// Identity of the hardware class: GPU, count, memory, compute capability and peer
    /// topology, never a card name alone.
    pub hardware: Digest,
}

/// CUDA VMM allocation properties on one device of one exact runtime (GPU §3.7: probe
/// allocation granularity for the exact handle type and device).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CudaAllocationSubject {
    pub runtime: RuntimeSubject,
    /// The CUDA device ordinal as the runtime's processes see it.
    pub device_ordinal: u32,
    /// The handle type allocations may be exported as; `None` when never exported.
    pub requested_handle: Option<ShareableHandle>,
}

/// One block rule of one network perimeter on one machine, for one principal (VM §4.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PerimeterRuleSubject {
    pub machine: Digest,
    pub perimeter: Digest,
    pub rule: Digest,
    /// The identity the rule restricts and the must-probe runs as, such as the transport
    /// broker's.
    pub principal: Digest,
}

/// One boot of one VM sandbox on one machine (VM part §8.1, line 2435: a launch record
/// binds the sandbox and its generation).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxBootSubject {
    pub machine: Digest,
    /// The VM the host created, by the digest of its stable handle identity, never a PID
    /// (VM part §6.4, line 2322).
    pub vm: Digest,
    /// The boot generation, which every boot or snapshot restore raises.
    pub boot: SandboxBootGeneration,
}

/// The hypervisor process of one launch (VM part §17 VM-CP-02 to VM-CP-04, lines
/// 3152–3154): the configuration it was given and the restrictions it runs under belong
/// to this process, not to the hypervisor interface of [`HypervisorSubject`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HypervisorProcessSubject {
    pub launch: SandboxBootSubject,
    /// The process, by the digest of its stable host identity, such as a pidfd-checked
    /// identity on Linux or a process handle on Windows, never a bare PID, which can be
    /// reused (VM part §6.4, line 2322).
    pub process: Digest,
}

/// The transport broker of one network perimeter on one machine, with the destination
/// policy it applies (VM part §17 VM-CP-07 and VM-CP-08, lines 3157–3158).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportBrokerSubject {
    pub machine: Digest,
    pub perimeter: Digest,
    /// The broker's identity, such as its executable and the account it runs as.
    pub broker: Digest,
    /// The destination policy it applies: the allowed names and the refused address
    /// classes of the profile.
    pub policy: Digest,
}

/// The credential scan of one launch, with the locations it covered (VM part §17
/// VM-CP-12, line 3162: the check states that it covers only the scanned locations).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialScanSubject {
    pub launch: SandboxBootSubject,
    /// Digest of the scanned locations, such as the launch specification, the relay's
    /// inputs and logs, the audit, the fake provider's echoed response and the executor's
    /// outbound request; evidence about one set never answers for another.
    pub locations: Digest,
}

/// One golden snapshot on one machine and the clones restored from it that were compared
/// (VM part §6.6, line 2336; §17 VM-CP-21, line 3171).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotClonesSubject {
    pub machine: Digest,
    pub snapshot: Digest,
    /// Digest of the clones' VM handle identities, in restore order.
    pub clones: Digest,
}

/// The subject an observation is about, typed by kind (CORE-01 "subject identity").
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum Subject {
    Host(HostSubject),
    GpuDevice(GpuDeviceSubject),
    Hypervisor(HypervisorSubject),
    OperatingSystem(OperatingSystemSubject),
    Provider(ProviderSubject),
    Runtime(RuntimeSubject),
    GpuPair(GpuPairSubject),
    ModelCheckpoint(ModelCheckpointSubject),
    CudaAllocation(CudaAllocationSubject),
    PerimeterRule(PerimeterRuleSubject),
    SandboxBoot(SandboxBootSubject),
    HypervisorProcess(HypervisorProcessSubject),
    TransportBroker(TransportBrokerSubject),
    CredentialScan(CredentialScanSubject),
    SnapshotClones(SnapshotClonesSubject),
}

crate::foundation::strict_serde::strict_tag!(Subject, "kind");

impl Subject {
    pub fn kind(&self) -> SubjectKind {
        match self {
            Self::Host(_) => SubjectKind::Host,
            Self::GpuDevice(_) => SubjectKind::GpuDevice,
            Self::Hypervisor(_) => SubjectKind::Hypervisor,
            Self::OperatingSystem(_) => SubjectKind::OperatingSystem,
            Self::Provider(_) => SubjectKind::Provider,
            Self::Runtime(_) => SubjectKind::Runtime,
            Self::GpuPair(_) => SubjectKind::GpuPair,
            Self::ModelCheckpoint(_) => SubjectKind::ModelCheckpoint,
            Self::CudaAllocation(_) => SubjectKind::CudaAllocation,
            Self::PerimeterRule(_) => SubjectKind::PerimeterRule,
            Self::SandboxBoot(_) => SubjectKind::SandboxBoot,
            Self::HypervisorProcess(_) => SubjectKind::HypervisorProcess,
            Self::TransportBroker(_) => SubjectKind::TransportBroker,
            Self::CredentialScan(_) => SubjectKind::CredentialScan,
            Self::SnapshotClones(_) => SubjectKind::SnapshotClones,
        }
    }

    /// The subject's identity digest. Evidence is kept and looked up per capability and
    /// identity, so evidence about one subject never answers for another.
    pub fn identity(&self) -> Digest {
        let builder = DigestBuilder::new(SUBJECT_DOMAIN).str(self.kind().tag());
        match self {
            Self::Host(host) => builder.digest(&host.machine),
            Self::GpuDevice(gpu) => builder.digest(&gpu.machine).digest(&gpu.device),
            Self::Hypervisor(hypervisor) => builder
                .digest(&hypervisor.machine)
                .str(hypervisor.hypervisor.tag()),
            Self::OperatingSystem(system) => builder.digest(&system.machine).str(system.os.tag()),
            Self::Provider(provider) => builder
                .str(provider.provider.tag())
                .digest(&provider.resource),
            Self::Runtime(runtime) => feed_runtime(builder, runtime),
            Self::GpuPair(pair) => builder
                .digest(&pair.machine)
                .digest(&pair.from)
                .digest(&pair.to),
            Self::ModelCheckpoint(model) => builder
                .digest(&model.checkpoint)
                .str(model.release.backend.tag())
                .str(model.release.version.as_str())
                .digest(&model.image)
                .digest(&model.hardware),
            Self::CudaAllocation(allocation) => feed_runtime(builder, &allocation.runtime)
                .u64(u64::from(allocation.device_ordinal))
                .str(
                    allocation
                        .requested_handle
                        .map_or("none", ShareableHandle::tag),
                ),
            Self::PerimeterRule(rule) => builder
                .digest(&rule.machine)
                .digest(&rule.perimeter)
                .digest(&rule.rule)
                .digest(&rule.principal),
            Self::SandboxBoot(boot) => feed_boot(builder, boot),
            Self::HypervisorProcess(process) => {
                feed_boot(builder, &process.launch).digest(&process.process)
            }
            Self::TransportBroker(broker) => builder
                .digest(&broker.machine)
                .digest(&broker.perimeter)
                .digest(&broker.broker)
                .digest(&broker.policy),
            Self::CredentialScan(scan) => feed_boot(builder, &scan.launch).digest(&scan.locations),
            Self::SnapshotClones(clones) => builder
                .digest(&clones.machine)
                .digest(&clones.snapshot)
                .digest(&clones.clones),
        }
        .finish()
    }
}

/// The boot's fields in identity order: machine, VM, boot generation.
fn feed_boot(builder: DigestBuilder, boot: &SandboxBootSubject) -> DigestBuilder {
    builder
        .digest(&boot.machine)
        .digest(&boot.vm)
        .u64(boot.boot.get())
}

/// The runtime's fields in identity order: category, backend, version, instance.
fn feed_runtime(builder: DigestBuilder, runtime: &RuntimeSubject) -> DigestBuilder {
    builder
        .str(category_tag(runtime.category))
        .str(runtime.release.backend.tag())
        .str(runtime.release.version.as_str())
        .digest(&runtime.instance)
}

impl From<HostSubject> for Subject {
    fn from(subject: HostSubject) -> Self {
        Self::Host(subject)
    }
}

impl From<GpuDeviceSubject> for Subject {
    fn from(subject: GpuDeviceSubject) -> Self {
        Self::GpuDevice(subject)
    }
}

impl From<HypervisorSubject> for Subject {
    fn from(subject: HypervisorSubject) -> Self {
        Self::Hypervisor(subject)
    }
}

impl From<OperatingSystemSubject> for Subject {
    fn from(subject: OperatingSystemSubject) -> Self {
        Self::OperatingSystem(subject)
    }
}

impl From<ProviderSubject> for Subject {
    fn from(subject: ProviderSubject) -> Self {
        Self::Provider(subject)
    }
}

impl From<RuntimeSubject> for Subject {
    fn from(subject: RuntimeSubject) -> Self {
        Self::Runtime(subject)
    }
}

impl From<GpuPairSubject> for Subject {
    fn from(subject: GpuPairSubject) -> Self {
        Self::GpuPair(subject)
    }
}

impl From<ModelCheckpointSubject> for Subject {
    fn from(subject: ModelCheckpointSubject) -> Self {
        Self::ModelCheckpoint(subject)
    }
}

impl From<CudaAllocationSubject> for Subject {
    fn from(subject: CudaAllocationSubject) -> Self {
        Self::CudaAllocation(subject)
    }
}

impl From<PerimeterRuleSubject> for Subject {
    fn from(subject: PerimeterRuleSubject) -> Self {
        Self::PerimeterRule(subject)
    }
}

impl From<SandboxBootSubject> for Subject {
    fn from(subject: SandboxBootSubject) -> Self {
        Self::SandboxBoot(subject)
    }
}

impl From<HypervisorProcessSubject> for Subject {
    fn from(subject: HypervisorProcessSubject) -> Self {
        Self::HypervisorProcess(subject)
    }
}

impl From<TransportBrokerSubject> for Subject {
    fn from(subject: TransportBrokerSubject) -> Self {
        Self::TransportBroker(subject)
    }
}

impl From<CredentialScanSubject> for Subject {
    fn from(subject: CredentialScanSubject) -> Self {
        Self::CredentialScan(subject)
    }
}

impl From<SnapshotClonesSubject> for Subject {
    fn from(subject: SnapshotClonesSubject) -> Self {
        Self::SnapshotClones(subject)
    }
}

/// The stable tag of a category inside identity digests.
const fn category_tag(category: ExecutionCategory) -> &'static str {
    match category {
        ExecutionCategory::VmSandbox => "vm_sandbox",
        ExecutionCategory::SharedKernelGpuRuntime => "shared_kernel_gpu_runtime",
        ExecutionCategory::ProviderContainerRuntime => "provider_container_runtime",
        ExecutionCategory::HostProcessModelRuntime => "host_process_model_runtime",
    }
}

/// A hypervisor interface (VM-CP-01 accelerators, and HCS from VM-D2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HypervisorKind {
    Kvm,
    /// Windows Hypervisor Platform, the QEMU accelerator.
    Whpx,
    /// Windows Host Compute Service (VM-W20 under VM-D2).
    Hcs,
    /// macOS Hypervisor.framework.
    Hvf,
    /// macOS Virtualization.framework.
    Vz,
}

impl HypervisorKind {
    pub const ALL: [Self; 5] = [Self::Kvm, Self::Whpx, Self::Hcs, Self::Hvf, Self::Vz];

    /// The stable tag hashed into [`Subject::identity`].
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Kvm => "kvm",
            Self::Whpx => "whpx",
            Self::Hcs => "hcs",
            Self::Hvf => "hvf",
            Self::Vz => "vz",
        }
    }
}

impl fmt::Display for HypervisorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Kvm => "KVM",
            Self::Whpx => "Windows Hypervisor Platform",
            Self::Hcs => "Windows Host Compute Service",
            Self::Hvf => "Hypervisor.framework",
            Self::Vz => "Virtualization.framework",
        })
    }
}

/// An operating system family; WSL2 is separate from its Windows host because CUDA
/// behaviour differs there (GPU part §1.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OsKind {
    Windows,
    Linux,
    #[serde(rename = "macos")]
    MacOs,
    Wsl2,
}

impl OsKind {
    /// The stable tag hashed into [`Subject::identity`].
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Windows => "windows",
            Self::Linux => "linux",
            Self::MacOs => "macos",
            Self::Wsl2 => "wsl2",
        }
    }
}

impl fmt::Display for OsKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Windows => "Windows",
            Self::Linux => "Linux",
            Self::MacOs => "macOS",
            Self::Wsl2 => "WSL2",
        })
    }
}

/// A NeoCloud provider, or an explicitly attached, externally managed SSH host.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderKind {
    RunPod,
    Vast,
    Jarvis,
    Crusoe,
    Prime,
    Latitude,
    Thunder,
    E2e,
    Civo,
    Nebius,
    #[serde(rename = "existing_ssh")]
    ExistingSsh,
}

impl ProviderKind {
    /// The provider id, also hashed into [`Subject::identity`].
    pub const fn tag(self) -> &'static str {
        match self {
            Self::RunPod => "runpod",
            Self::Vast => "vast",
            Self::Jarvis => "jarvis",
            Self::Crusoe => "crusoe",
            Self::Prime => "prime",
            Self::Latitude => "latitude",
            Self::Thunder => "thunder",
            Self::E2e => "e2e",
            Self::Civo => "civo",
            Self::Nebius => "nebius",
            Self::ExistingSsh => "existing_ssh",
        }
    }
}

impl fmt::Display for ProviderKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RunPod => "RunPod",
            Self::Vast => "Vast",
            Self::Jarvis => "Jarvis",
            Self::Crusoe => "Crusoe",
            Self::Prime => "Prime",
            Self::Latitude => "Latitude",
            Self::Thunder => "Thunder",
            Self::E2e => "E2E",
            Self::Civo => "Civo",
            Self::Nebius => "Nebius",
            Self::ExistingSsh => "Existing SSH host",
        })
    }
}

/// A runtime backend: an inference backend that model_server.py runs (vLLM, llama.cpp,
/// Transformers), or the hypervisor build a VM sandbox runtime runs on (QEMU).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Backend {
    Vllm,
    LlamaCpp,
    Transformers,
    /// The pinned QEMU build of the restricted VM path (`sandbox::qemu`).
    Qemu,
    Hcs,
}

impl Backend {
    /// The stable tag hashed into [`Subject::identity`].
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Vllm => "vllm",
            Self::LlamaCpp => "llama_cpp",
            Self::Transformers => "transformers",
            Self::Qemu => "qemu",
            Self::Hcs => "hcs",
        }
    }
}

impl fmt::Display for Backend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Vllm => "vLLM",
            Self::LlamaCpp => "llama.cpp",
            Self::Transformers => "Transformers",
            Self::Qemu => "QEMU",
            Self::Hcs => "Windows HCS",
        })
    }
}

/// Longest accepted [`BackendVersion`].
pub const MAX_VERSION_LEN: usize = 64;

/// An exact backend version such as `0.31.0`. Versions are compared exactly; no range or
/// semantic-version ordering is assumed (GPU part §1.1: "unless a tested version").
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct BackendVersion(String);

impl BackendVersion {
    /// Accepts 1–64 ASCII letters, digits, '.', '-', '+' or '_', starting with a letter
    /// or digit.
    pub fn new(text: impl Into<String>) -> Result<Self, VersionError> {
        let text = text.into();
        let first = text.chars().next().ok_or(VersionError::Empty)?;
        if text.len() > MAX_VERSION_LEN {
            return Err(VersionError::TooLong {
                max: MAX_VERSION_LEN,
            });
        }
        if let Some(character) = text.chars().find(|character| {
            !(character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '+' | '_'))
        }) {
            return Err(VersionError::InvalidCharacter { character });
        }
        if !first.is_ascii_alphanumeric() {
            return Err(VersionError::InvalidStart);
        }
        Ok(Self(text))
    }

    /// A version written into this module's recorded tables; a test checks each one
    /// against [`Self::new`].
    pub(super) fn known(text: &'static str) -> Self {
        Self(text.to_owned())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for BackendVersion {
    type Error = VersionError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::new(text)
    }
}

impl From<BackendVersion> for String {
    fn from(version: BackendVersion) -> Self {
        version.0
    }
}

impl fmt::Display for BackendVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Why a backend version was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VersionError {
    Empty,
    TooLong { max: usize },
    InvalidCharacter { character: char },
    InvalidStart,
}

impl fmt::Display for VersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("the backend version is empty"),
            Self::TooLong { max } => {
                write!(f, "the backend version is longer than {max} characters")
            }
            Self::InvalidCharacter { character } => write!(
                f,
                "the backend version contains {character:?}; use letters, digits, '.', '-', '+' \
                 or '_'"
            ),
            Self::InvalidStart => {
                f.write_str("the backend version must start with a letter or digit")
            }
        }
    }
}

impl std::error::Error for VersionError {}

/// A backend at one exact version, such as vLLM 0.31.0.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendRelease {
    pub backend: Backend,
    pub version: BackendVersion,
}

impl BackendRelease {
    /// `backend` at exactly `version`, checked as [`BackendVersion::new`] checks it.
    pub fn new(backend: Backend, version: &str) -> Result<Self, VersionError> {
        Ok(Self {
            backend,
            version: BackendVersion::new(version)?,
        })
    }
}

impl fmt::Display for BackendRelease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.backend, self.version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::digest;

    fn machine() -> Digest {
        digest("yougori/test/machine/v1", &[b"m1"])
    }

    fn runtime(version: &str) -> Subject {
        Subject::Runtime(RuntimeSubject {
            category: ExecutionCategory::SharedKernelGpuRuntime,
            release: BackendRelease::new(Backend::Vllm, version).unwrap(),
            instance: digest("yougori/test/instance/v1", &[b"i1"]),
        })
    }

    #[test]
    fn identity_is_pinned() {
        assert_eq!(
            Subject::Host(HostSubject { machine: machine() })
                .identity()
                .to_hex(),
            "c621a6ce727283455ae0f84a82e8aa703fffda55ed79ada543c41ccb856dbfb1"
        );
        assert_eq!(
            runtime("0.31.0").identity().to_hex(),
            "615a2663cc6fe3dde0a491de470e819d3582692885f8585ab2be0d4995bd9955"
        );
    }

    fn vm_runtime() -> RuntimeSubject {
        RuntimeSubject {
            category: ExecutionCategory::VmSandbox,
            release: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
            instance: digest("yougori/test/instance/v1", &[b"vm"]),
        }
    }

    #[test]
    fn every_parameter_of_the_new_kinds_is_part_of_the_identity() {
        let gpu = |name: &[u8]| digest("yougori/test/device/v1", &[name]);
        let pair = GpuPairSubject {
            machine: machine(),
            from: gpu(b"gpu0"),
            to: gpu(b"gpu1"),
        };
        let checkpoint = ModelCheckpointSubject {
            checkpoint: digest("yougori/test/checkpoint/v1", &[b"qwen"]),
            release: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
            image: digest("yougori/test/image/v1", &[b"image"]),
            hardware: digest("yougori/test/hardware/v1", &[b"2x4090"]),
        };
        let allocation = CudaAllocationSubject {
            runtime: vm_runtime(),
            device_ordinal: 0,
            requested_handle: Some(ShareableHandle::PosixFileDescriptor),
        };
        let rule = PerimeterRuleSubject {
            machine: machine(),
            perimeter: digest("yougori/test/perimeter/v1", &[b"p"]),
            rule: digest("yougori/test/rule/v1", &[b"block-private"]),
            principal: digest("yougori/test/principal/v1", &[b"broker"]),
        };
        let subjects = [
            Subject::GpuPair(pair),
            Subject::GpuPair(GpuPairSubject {
                from: pair.to,
                to: pair.from,
                ..pair
            }),
            Subject::GpuPair(GpuPairSubject {
                machine: gpu(b"other-machine"),
                ..pair
            }),
            Subject::ModelCheckpoint(checkpoint.clone()),
            Subject::ModelCheckpoint(ModelCheckpointSubject {
                checkpoint: digest("yougori/test/checkpoint/v1", &[b"llama"]),
                ..checkpoint.clone()
            }),
            Subject::ModelCheckpoint(ModelCheckpointSubject {
                release: BackendRelease::new(Backend::Vllm, "0.31.1").unwrap(),
                ..checkpoint.clone()
            }),
            Subject::ModelCheckpoint(ModelCheckpointSubject {
                image: digest("yougori/test/image/v1", &[b"other"]),
                ..checkpoint.clone()
            }),
            Subject::ModelCheckpoint(ModelCheckpointSubject {
                hardware: digest("yougori/test/hardware/v1", &[b"1x4090"]),
                ..checkpoint
            }),
            Subject::CudaAllocation(allocation.clone()),
            Subject::CudaAllocation(CudaAllocationSubject {
                device_ordinal: 1,
                ..allocation.clone()
            }),
            Subject::CudaAllocation(CudaAllocationSubject {
                requested_handle: None,
                ..allocation.clone()
            }),
            Subject::CudaAllocation(CudaAllocationSubject {
                requested_handle: Some(ShareableHandle::Win32Handle),
                ..allocation.clone()
            }),
            Subject::CudaAllocation(CudaAllocationSubject {
                runtime: RuntimeSubject {
                    category: ExecutionCategory::SharedKernelGpuRuntime,
                    ..vm_runtime()
                },
                ..allocation
            }),
            Subject::PerimeterRule(rule),
            Subject::PerimeterRule(PerimeterRuleSubject {
                rule: digest("yougori/test/rule/v1", &[b"other"]),
                ..rule
            }),
            Subject::PerimeterRule(PerimeterRuleSubject {
                principal: digest("yougori/test/principal/v1", &[b"guest"]),
                ..rule
            }),
            Subject::PerimeterRule(PerimeterRuleSubject {
                perimeter: digest("yougori/test/perimeter/v1", &[b"q"]),
                ..rule
            }),
            Subject::Runtime(vm_runtime()),
            Subject::GpuDevice(GpuDeviceSubject {
                machine: machine(),
                device: gpu(b"gpu0"),
            }),
        ];
        let identities: std::collections::BTreeSet<Digest> =
            subjects.iter().map(Subject::identity).collect();
        assert_eq!(identities.len(), subjects.len());
        for subject in &subjects {
            let json = serde_json::to_value(subject).unwrap();
            assert_eq!(json["kind"], subject.kind().tag());
            assert_eq!(
                &serde_json::from_value::<Subject>(json.clone()).unwrap(),
                subject
            );
            let mut extra = json;
            extra["assumed"] = true.into();
            assert!(serde_json::from_value::<Subject>(extra).is_err());
        }
    }

    #[test]
    fn identities_differ_by_kind_and_every_field() {
        let device = digest("yougori/test/device/v1", &[b"gpu0"]);
        let subjects = [
            Subject::Host(HostSubject { machine: machine() }),
            Subject::GpuDevice(GpuDeviceSubject {
                machine: machine(),
                device,
            }),
            Subject::GpuDevice(GpuDeviceSubject {
                machine: machine(),
                device: digest("yougori/test/device/v1", &[b"gpu1"]),
            }),
            Subject::Hypervisor(HypervisorSubject {
                machine: machine(),
                hypervisor: HypervisorKind::Whpx,
            }),
            Subject::Hypervisor(HypervisorSubject {
                machine: machine(),
                hypervisor: HypervisorKind::Hcs,
            }),
            Subject::OperatingSystem(OperatingSystemSubject {
                machine: machine(),
                os: OsKind::Windows,
            }),
            Subject::OperatingSystem(OperatingSystemSubject {
                machine: machine(),
                os: OsKind::Wsl2,
            }),
            Subject::Provider(ProviderSubject {
                provider: ProviderKind::RunPod,
                resource: device,
            }),
            Subject::Provider(ProviderSubject {
                provider: ProviderKind::Vast,
                resource: device,
            }),
            runtime("0.31.0"),
            runtime("0.31.1"),
            Subject::Runtime(RuntimeSubject {
                category: ExecutionCategory::VmSandbox,
                release: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
                instance: digest("yougori/test/instance/v1", &[b"i1"]),
            }),
        ];
        let identities: std::collections::BTreeSet<Digest> =
            subjects.iter().map(Subject::identity).collect();
        assert_eq!(identities.len(), subjects.len());
        assert_eq!(runtime("0.31.0").identity(), runtime("0.31.0").identity());
    }

    #[test]
    fn subjects_serialize_with_their_kind_and_refuse_unknown_fields() {
        let subject = runtime("0.31.0");
        let json = serde_json::to_value(&subject).unwrap();
        assert_eq!(json["kind"], "runtime");
        assert_eq!(json["category"], "shared_kernel_gpu_runtime");
        assert_eq!(json["release"]["backend"], "vllm");
        assert_eq!(json["release"]["version"], "0.31.0");
        assert_eq!(
            serde_json::from_value::<Subject>(json.clone()).unwrap(),
            subject
        );

        let mut extra = json;
        extra["note"] = "x".into();
        assert!(serde_json::from_value::<Subject>(extra).is_err());

        let provider = Subject::Provider(ProviderSubject {
            provider: ProviderKind::RunPod,
            resource: machine(),
        });
        assert_eq!(
            serde_json::to_value(&provider).unwrap()["provider"],
            "runpod"
        );
        let os = Subject::OperatingSystem(OperatingSystemSubject {
            machine: machine(),
            os: OsKind::MacOs,
        });
        assert_eq!(serde_json::to_value(&os).unwrap()["os"], "macos");
    }

    #[test]
    fn provider_tags_match_their_serde_names() {
        for provider in [
            ProviderKind::RunPod,
            ProviderKind::Vast,
            ProviderKind::Jarvis,
            ProviderKind::Crusoe,
            ProviderKind::Prime,
            ProviderKind::Latitude,
            ProviderKind::Thunder,
            ProviderKind::E2e,
            ProviderKind::Civo,
            ProviderKind::Nebius,
        ] {
            assert_eq!(
                serde_json::to_value(provider).unwrap(),
                serde_json::Value::from(provider.tag())
            );
        }
        for hypervisor in HypervisorKind::ALL {
            assert_eq!(
                serde_json::to_value(hypervisor).unwrap(),
                serde_json::Value::from(hypervisor.tag())
            );
        }
    }

    fn launch() -> SandboxBootSubject {
        SandboxBootSubject {
            machine: machine(),
            vm: digest("yougori/test/vm/v1", &[b"vm"]),
            boot: SandboxBootGeneration::new(4),
        }
    }

    /// The identity encoding of the VM boundary subjects is pinned like the others.
    #[test]
    fn boundary_identities_are_pinned() {
        assert_eq!(
            Subject::SandboxBoot(launch()).identity().to_hex(),
            "819b5d9b1c1c0b90b45995ea776a7917bac5e5d67f6924f417f28e0eec699715"
        );
        assert_eq!(
            Subject::HypervisorProcess(HypervisorProcessSubject {
                launch: launch(),
                process: digest("yougori/test/process/v1", &[b"hypervisor"]),
            })
            .identity()
            .to_hex(),
            "b0acd3e65617721f2b5806762648aae8d20c77964396adcd36bcc9a6d0bda293"
        );
    }

    #[test]
    fn every_field_of_the_boundary_subjects_is_part_of_the_identity() {
        let part = |name: &[u8]| digest("yougori/test/boundary/v1", &[name]);
        let launch = launch();
        let later = SandboxBootSubject {
            boot: SandboxBootGeneration::new(5),
            ..launch
        };
        let process = HypervisorProcessSubject {
            launch,
            process: part(b"process"),
        };
        let broker = TransportBrokerSubject {
            machine: machine(),
            perimeter: part(b"perimeter"),
            broker: part(b"broker"),
            policy: part(b"policy"),
        };
        let scan = CredentialScanSubject {
            launch,
            locations: part(b"locations"),
        };
        let clones = SnapshotClonesSubject {
            machine: machine(),
            snapshot: part(b"golden"),
            clones: part(b"clones"),
        };
        let subjects = [
            Subject::SandboxBoot(launch),
            Subject::SandboxBoot(later),
            Subject::SandboxBoot(SandboxBootSubject {
                machine: part(b"other-machine"),
                ..launch
            }),
            Subject::SandboxBoot(SandboxBootSubject {
                vm: part(b"other-vm"),
                ..launch
            }),
            Subject::HypervisorProcess(process),
            Subject::HypervisorProcess(HypervisorProcessSubject {
                launch: later,
                ..process
            }),
            Subject::HypervisorProcess(HypervisorProcessSubject {
                process: part(b"other-process"),
                ..process
            }),
            Subject::TransportBroker(broker),
            Subject::TransportBroker(TransportBrokerSubject {
                machine: part(b"other-machine"),
                ..broker
            }),
            Subject::TransportBroker(TransportBrokerSubject {
                perimeter: part(b"other-perimeter"),
                ..broker
            }),
            Subject::TransportBroker(TransportBrokerSubject {
                broker: part(b"other-broker"),
                ..broker
            }),
            Subject::TransportBroker(TransportBrokerSubject {
                policy: part(b"other-policy"),
                ..broker
            }),
            Subject::CredentialScan(scan),
            Subject::CredentialScan(CredentialScanSubject {
                launch: later,
                ..scan
            }),
            Subject::CredentialScan(CredentialScanSubject {
                locations: part(b"fewer-locations"),
                ..scan
            }),
            Subject::SnapshotClones(clones),
            Subject::SnapshotClones(SnapshotClonesSubject {
                machine: part(b"other-machine"),
                ..clones
            }),
            Subject::SnapshotClones(SnapshotClonesSubject {
                snapshot: part(b"other-snapshot"),
                ..clones
            }),
            Subject::SnapshotClones(SnapshotClonesSubject {
                clones: part(b"other-clones"),
                ..clones
            }),
        ];
        let identities: std::collections::BTreeSet<Digest> =
            subjects.iter().map(Subject::identity).collect();
        assert_eq!(identities.len(), subjects.len());
        for subject in &subjects {
            let json = serde_json::to_value(subject).unwrap();
            assert_eq!(json["kind"], subject.kind().tag());
            assert_eq!(
                serde_json::to_value(subject.kind()).unwrap(),
                serde_json::Value::from(subject.kind().tag())
            );
            assert!(!subject.kind().to_string().is_empty());
            assert_eq!(
                &serde_json::from_value::<Subject>(json.clone()).unwrap(),
                subject
            );
            let mut extra = json.clone();
            extra["assumed"] = true.into();
            assert!(serde_json::from_value::<Subject>(extra).is_err());
            if json.get("launch").is_some() {
                let mut nested = json;
                nested["launch"]["assumed"] = true.into();
                assert!(serde_json::from_value::<Subject>(nested).is_err());
            }
        }
        let json = serde_json::to_value(Subject::SandboxBoot(launch)).unwrap();
        assert_eq!(json["boot"], 4);
    }

    #[test]
    fn versions_are_checked() {
        assert_eq!(BackendVersion::new("0.31.0").unwrap().as_str(), "0.31.0");
        assert!(BackendVersion::new("b4568+cuda12.8_x-1").is_ok());
        assert_eq!(BackendVersion::new(""), Err(VersionError::Empty));
        assert_eq!(BackendVersion::new(".1"), Err(VersionError::InvalidStart));
        assert_eq!(
            BackendVersion::new("0.31 0"),
            Err(VersionError::InvalidCharacter { character: ' ' })
        );
        assert_eq!(
            BackendVersion::new("1".repeat(MAX_VERSION_LEN + 1)),
            Err(VersionError::TooLong {
                max: MAX_VERSION_LEN
            })
        );
        assert!(serde_json::from_str::<BackendVersion>("\"0.31/0\"").is_err());
        assert_eq!(
            BackendRelease::new(Backend::LlamaCpp, "b4568")
                .unwrap()
                .to_string(),
            "llama.cpp b4568"
        );
    }
}
