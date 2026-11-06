//! Typed serving settings and what a profile is bound to: the model, the pinned engine,
//! the hardware class and its measured peer topology (S13 FAST-02, FAST-04, FAST-05).

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::drafting::DraftingSetting;
use super::formats::feed_kv;
use crate::foundation::evidence::{BackendRelease, HostChange};
use crate::foundation::ids::{Digest, DigestBuilder};
use crate::model_memory::backends::Technique;
use crate::model_memory::identity::{KvRepresentation, LogicalModelIdentity};

const TOPOLOGY_DOMAIN: &str = "yougori/model_memory/profiles/peer-topology/v1";
const HARDWARE_DOMAIN: &str = "yougori/model_memory/profiles/hardware-class/v1";
const SETTINGS_DOMAIN: &str = "yougori/model_memory/profiles/settings/v1";

/// One pinned engine: an exact backend release in an exact image (FAST-04 "pinned
/// engine/model/method combination"; FAST-05 "image digest"). An engine upgrade is
/// another `EngineRef`, with its own compatibility matrix and rollback (FAST-04, GPU-W01).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineRef {
    pub release: BackendRelease,
    /// Digest of the engine image.
    pub image: Digest,
}

impl EngineRef {
    pub(super) fn feed(&self, builder: DigestBuilder) -> DigestBuilder {
        builder
            .str(self.release.backend.tag())
            .str(self.release.version.as_str())
            .digest(&self.image)
    }
}

/// How the engine runs the model's forward pass (FAST-02 "graph mode").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphMode {
    /// No graph capture, as today's `--enforce-eager` (Appendix A.1).
    Eager,
    /// CUDA graphs captured piecewise around attention.
    PiecewiseCudaGraphs,
    /// CUDA graphs for the whole step.
    FullCudaGraphs,
}

impl GraphMode {
    /// The order FAST-02 tries modes in: captured graphs before eager execution. A mode
    /// is tried only where the checkpoint's evidence shows it starting.
    pub const PREFERENCE: [Self; 3] =
        [Self::FullCudaGraphs, Self::PiecewiseCudaGraphs, Self::Eager];

    /// The backend technique a mode needs (GPU part §3.8): captured graphs are the vLLM
    /// retained-process row's "graphs" experiment; eager execution needs none.
    pub const fn technique(self) -> Option<Technique> {
        match self {
            Self::Eager => None,
            Self::PiecewiseCudaGraphs | Self::FullCudaGraphs => Some(Technique::CudaGraphs),
        }
    }

    /// The stable tag hashed into identities.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Eager => "eager",
            Self::PiecewiseCudaGraphs => "piecewise_cuda_graphs",
            Self::FullCudaGraphs => "full_cuda_graphs",
        }
    }
}

/// A share of each GPU's memory in thousandths, the unit of vLLM's
/// `--gpu-memory-utilization` (today 0.90, Appendix A.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "u16", into = "u16")]
pub struct MemoryFraction(u16);

impl MemoryFraction {
    /// Accepts 1–1000 thousandths.
    pub fn new(permille: u16) -> Result<Self, SettingsError> {
        if (1..=1000).contains(&permille) {
            Ok(Self(permille))
        } else {
            Err(SettingsError::MemoryFractionOutOfRange { permille })
        }
    }

    pub const fn permille(self) -> u16 {
        self.0
    }

    /// The bytes of `total_bytes` this fraction allows, rounded down.
    pub fn of_bytes(self, total_bytes: u64) -> u64 {
        let share = u128::from(total_bytes) * u128::from(self.0) / 1000;
        u64::try_from(share).unwrap_or(total_bytes)
    }

    /// The largest fraction of `total_bytes` that is free, rounded down; `None` when less
    /// than a thousandth is free. vLLM does not start when its fraction of a GPU's memory
    /// is more than that GPU has free.
    pub fn largest_free(free_bytes: u64, total_bytes: u64) -> Option<Self> {
        if total_bytes == 0 {
            return None;
        }
        let permille = u128::from(free_bytes.min(total_bytes)) * 1000 / u128::from(total_bytes);
        u16::try_from(permille)
            .ok()
            .filter(|permille| *permille > 0)
            .map(Self)
    }

    /// The flag's text: 900 is "0.90" and 905 is "0.905".
    pub fn flag_value(self) -> String {
        render_permille(self.0)
    }
}

impl TryFrom<u16> for MemoryFraction {
    type Error = SettingsError;

    fn try_from(permille: u16) -> Result<Self, Self::Error> {
        Self::new(permille)
    }
}

impl From<MemoryFraction> for u16 {
    fn from(fraction: MemoryFraction) -> Self {
        fraction.0
    }
}

/// Thousandths as decimal text with at least two places, the way model_server.py writes
/// 0.90.
pub(super) fn render_permille(permille: u16) -> String {
    let whole = permille / 1000;
    let thousandths = permille % 1000;
    if thousandths.is_multiple_of(10) {
        format!("{whole}.{:02}", thousandths / 10)
    } else {
        format!("{whole}.{thousandths:03}")
    }
}

/// The link, access and path types of CORE-01's peer-topology evidence, re-exported so a
/// measured topology is used as it was observed (FAST-02: probe the actual peer
/// topology).
pub use crate::foundation::evidence::{PeerAccess, PeerLink, PeerPath};

/// The stable tag of a link inside topology identities.
const fn link_tag(link: PeerLink) -> &'static str {
    match link {
        PeerLink::NvLink => "nvlink",
        PeerLink::PcieSwitch => "pcie_switch",
        PeerLink::PcieHostBridge => "pcie_host_bridge",
        PeerLink::CrossSocket => "cross_socket",
    }
}

/// The stable tag of a peer copy's outcome inside topology identities.
const fn access_tag(access: PeerAccess) -> &'static str {
    match access {
        PeerAccess::Verified => "verified",
        PeerAccess::Unavailable => "unavailable",
    }
}

/// Measured peer topology of the GPUs assigned to one runtime (FAST-02; FAST-05 "GPU and
/// topology"). Every ordered pair of different GPUs has exactly one path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerTopology {
    pub device_count: u32,
    pub paths: Vec<PeerPath>,
}

impl PeerTopology {
    /// One GPU, which has no peers.
    pub fn single() -> Self {
        Self {
            device_count: 1,
            paths: Vec::new(),
        }
    }

    /// Refuses a topology that is empty, names a GPU outside it, repeats or omits a path,
    /// or has a GPU as its own peer. A missing path is never assumed.
    pub fn check(&self) -> Result<(), TopologyError> {
        if self.device_count == 0 {
            return Err(TopologyError::NoDevices);
        }
        let mut seen = BTreeSet::new();
        for path in &self.paths {
            if path.from >= self.device_count || path.to >= self.device_count {
                return Err(TopologyError::DeviceOutOfRange {
                    from: path.from,
                    to: path.to,
                });
            }
            if path.from == path.to {
                return Err(TopologyError::SelfPath { device: path.from });
            }
            if !seen.insert((path.from, path.to)) {
                return Err(TopologyError::RepeatedPath {
                    from: path.from,
                    to: path.to,
                });
            }
        }
        for from in 0..self.device_count {
            for to in (0..self.device_count).filter(|to| *to != from) {
                if !seen.contains(&(from, to)) {
                    return Err(TopologyError::MissingPath { from, to });
                }
            }
        }
        Ok(())
    }

    /// Whether a peer copy succeeded in every direction.
    pub fn all_peers_verified(&self) -> bool {
        self.paths
            .iter()
            .all(|path| path.access == PeerAccess::Verified)
    }

    /// The topology's identity. Paths are hashed in (from, to) order, so the order they
    /// were listed in does not matter.
    pub fn identity(&self) -> Digest {
        let mut paths = self.paths.clone();
        paths.sort_by_key(|path| (path.from, path.to));
        paths
            .iter()
            .fold(
                DigestBuilder::new(TOPOLOGY_DOMAIN).u64(u64::from(self.device_count)),
                |builder, path| {
                    builder
                        .u64(u64::from(path.from))
                        .u64(u64::from(path.to))
                        .str(link_tag(path.link))
                        .str(access_tag(path.access))
                },
            )
            .finish()
    }
}

/// Why a peer topology was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum TopologyError {
    NoDevices,
    DeviceOutOfRange { from: u32, to: u32 },
    SelfPath { device: u32 },
    RepeatedPath { from: u32, to: u32 },
    MissingPath { from: u32, to: u32 },
}

impl fmt::Display for TopologyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoDevices => f.write_str("the peer topology has no GPUs"),
            Self::DeviceOutOfRange { from, to } => {
                write!(
                    f,
                    "the path {from} to {to} names a GPU outside the topology"
                )
            }
            Self::SelfPath { device } => write!(f, "GPU {device} is listed as its own peer"),
            Self::RepeatedPath { from, to } => write!(f, "the path {from} to {to} is listed twice"),
            Self::MissingPath { from, to } => write!(
                f,
                "the path {from} to {to} was not measured, and an unmeasured path is never assumed"
            ),
        }
    }
}

impl std::error::Error for TopologyError {}

/// Where a communication setting would apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommunicationScope {
    /// The engine process alone, through its own environment.
    EngineProcess,
    /// Every process on the machine. Never allowed: a peer-access probe and a per-process
    /// NCCL experiment cannot justify machine-wide communication settings (line 248).
    MachineWide,
}

/// Whether NCCL may use direct peer-to-peer transfers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerToPeer {
    Direct,
    /// Peer-to-peer off for this engine process only.
    Disabled,
}

/// The per-process NCCL choice for a multi-GPU engine, made only from a measured peer
/// topology (FAST-02: probe actual peer topology before a per-process NCCL choice). It
/// keeps the topology it was made from, and every way to one, reading included, goes
/// through [`NcclChoice::from_topology`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "NcclChoiceWire", into = "NcclChoiceWire")]
pub struct NcclChoice {
    peer_to_peer: PeerToPeer,
    topology: PeerTopology,
}

impl NcclChoice {
    /// Direct peer-to-peer when a peer copy succeeded in every direction, otherwise off.
    /// Refused for a machine-wide scope, a single GPU or an incomplete topology.
    pub fn from_topology(
        topology: &PeerTopology,
        scope: CommunicationScope,
    ) -> Result<Self, CommunicationRefusal> {
        if scope == CommunicationScope::MachineWide {
            return Err(CommunicationRefusal::MachineWide {
                change: HostChange::MachineWideCommunicationSetting,
            });
        }
        topology
            .check()
            .map_err(|error| CommunicationRefusal::Topology { error })?;
        if topology.device_count < 2 {
            return Err(CommunicationRefusal::SingleDevice);
        }
        Ok(Self {
            peer_to_peer: if topology.all_peers_verified() {
                PeerToPeer::Direct
            } else {
                PeerToPeer::Disabled
            },
            topology: topology.clone(),
        })
    }

    pub fn peer_to_peer(&self) -> PeerToPeer {
        self.peer_to_peer
    }

    pub fn device_count(&self) -> u32 {
        self.topology.device_count
    }

    /// The measured topology the choice was made from.
    pub fn topology(&self) -> &PeerTopology {
        &self.topology
    }

    /// Variables for the engine process's own environment; nothing is set machine-wide.
    pub fn process_environment(&self) -> Vec<(&'static str, &'static str)> {
        match self.peer_to_peer {
            PeerToPeer::Direct => Vec::new(),
            PeerToPeer::Disabled => vec![("NCCL_P2P_DISABLE", "1")],
        }
    }
}

/// The written form of an [`NcclChoice`]: its scope, the measured topology and the choice.
/// Reading makes the choice again from the topology and refuses one it does not give.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NcclChoiceWire {
    scope: CommunicationScope,
    topology: PeerTopology,
    peer_to_peer: PeerToPeer,
}

impl TryFrom<NcclChoiceWire> for NcclChoice {
    type Error = CommunicationRefusal;

    fn try_from(wire: NcclChoiceWire) -> Result<Self, Self::Error> {
        let choice = Self::from_topology(&wire.topology, wire.scope)?;
        if choice.peer_to_peer != wire.peer_to_peer {
            return Err(CommunicationRefusal::PeerToPeerNotMeasured {
                written: wire.peer_to_peer,
                measured: choice.peer_to_peer,
            });
        }
        Ok(choice)
    }
}

impl From<NcclChoice> for NcclChoiceWire {
    fn from(choice: NcclChoice) -> Self {
        Self {
            scope: CommunicationScope::EngineProcess,
            topology: choice.topology,
            peer_to_peer: choice.peer_to_peer,
        }
    }
}

/// Why no NCCL choice was made.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum CommunicationRefusal {
    /// The setting would be machine-wide host state (line 248; CORE-01 `HostChange`).
    MachineWide {
        change: HostChange,
    },
    /// One GPU has no peers to communicate with.
    SingleDevice,
    Topology {
        error: TopologyError,
    },
    /// A written choice is not the one its measured topology gives, such as direct
    /// peer-to-peer where a peer copy failed.
    PeerToPeerNotMeasured {
        written: PeerToPeer,
        measured: PeerToPeer,
    },
}

impl fmt::Display for CommunicationRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MachineWide { change } => write!(
                f,
                "a peer-access probe cannot justify changing {change}; NCCL choices apply to \
                 the engine process only"
            ),
            Self::SingleDevice => f.write_str("one GPU needs no NCCL choice"),
            Self::Topology { error } => write!(f, "{error}"),
            Self::PeerToPeerNotMeasured { written, measured } => write!(
                f,
                "the NCCL choice says peer-to-peer is {written:?}, and its measured topology \
                 gives {measured:?}"
            ),
        }
    }
}

impl std::error::Error for CommunicationRefusal {}

/// A CUDA compute capability, such as 8.9.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComputeCapability {
    pub major: u8,
    pub minor: u8,
}

/// The hardware a profile was proven on (FAST-05 "GPU and topology", "hardware class").
///
/// The card name is one field among several: no setting tied to a card name is assumed
/// portable to another count, memory size, compute capability or topology (FAST-02).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HardwareClass {
    /// The card name as reported.
    pub gpu_name: String,
    pub gpu_count: u32,
    pub memory_bytes_per_gpu: u64,
    pub compute_capability: ComputeCapability,
    /// [`PeerTopology::identity`] of the GPUs.
    pub topology: Digest,
}

impl HardwareClass {
    pub fn identity(&self) -> Digest {
        DigestBuilder::new(HARDWARE_DOMAIN)
            .str(&self.gpu_name)
            .u64(u64::from(self.gpu_count))
            .u64(self.memory_bytes_per_gpu)
            .u64(u64::from(self.compute_capability.major))
            .u64(u64::from(self.compute_capability.minor))
            .digest(&self.topology)
            .finish()
    }
}

/// What a before/after comparison holds fixed (FAST-02: BENCH-01/09 and correctness
/// checks compare before/after on the same hardware, driver, model and load).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ComparisonConditions {
    /// [`HardwareClass::identity`].
    pub hardware: Digest,
    pub driver: String,
    /// The logical model (T07): source, dtype and quantization, tokenizer and generation
    /// configuration.
    pub model: LogicalModelIdentity,
    /// Identity of the load: the fixtures, concurrency and request mix.
    pub load: Digest,
}

impl ComparisonConditions {
    /// Refuses a comparison across different conditions, naming each difference.
    pub fn compare(&self, other: &Self) -> Result<(), NotComparable> {
        let mut mismatches = Vec::new();
        if self.hardware != other.hardware {
            mismatches.push(ConditionMismatch::Hardware);
        }
        if self.driver != other.driver {
            mismatches.push(ConditionMismatch::Driver);
        }
        if self.model != other.model {
            mismatches.push(ConditionMismatch::Model);
        }
        if self.load != other.load {
            mismatches.push(ConditionMismatch::Load);
        }
        if mismatches.is_empty() {
            Ok(())
        } else {
            Err(NotComparable { mismatches })
        }
    }
}

/// A condition that differs between two measurements.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionMismatch {
    Hardware,
    Driver,
    Model,
    Load,
}

/// Two measurements were taken under different conditions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NotComparable {
    pub mismatches: Vec<ConditionMismatch>,
}

impl fmt::Display for NotComparable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the measurements differ in ")?;
        for (index, mismatch) in self.mismatches.iter().enumerate() {
            if index > 0 {
                f.write_str(", ")?;
            }
            f.write_str(match mismatch {
                ConditionMismatch::Hardware => "hardware",
                ConditionMismatch::Driver => "driver",
                ConditionMismatch::Model => "model",
                ConditionMismatch::Load => "load",
            })?;
        }
        f.write_str("; compare before and after on the same hardware, driver, model and load")
    }
}

impl std::error::Error for NotComparable {}

/// The settings FAST-02 chooses (line 242): graph mode, concurrent-sequence limit,
/// batched-token budget, KV representation and context, with the tensor-parallel size,
/// memory fraction, per-process NCCL choice and FAST-04 drafting they run with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServingSettings {
    pub graph_mode: GraphMode,
    /// `--max-num-seqs`: sequences batched together.
    pub max_num_seqs: u32,
    /// `--max-num-batched-tokens`: tokens scheduled in one step.
    pub max_num_batched_tokens: u32,
    /// The KV cache's element type, quantization, block size and layout (T07); its
    /// fidelity is judged against the model it caches.
    pub kv_cache: KvRepresentation,
    /// `--max-model-len`.
    pub context_tokens: u32,
    pub tensor_parallel_size: u32,
    /// `--gpu-memory-utilization`.
    pub gpu_memory: MemoryFraction,
    /// Present exactly when more than one GPU is used.
    pub nccl: Option<NcclChoice>,
    pub drafting: Option<DraftingSetting>,
}

impl ServingSettings {
    /// Refuses settings the engine could not run as written.
    pub fn check(&self) -> Result<(), SettingsError> {
        if self.max_num_seqs == 0 {
            return Err(SettingsError::ZeroSequences);
        }
        if self.context_tokens == 0 {
            return Err(SettingsError::ZeroContext);
        }
        if self.tensor_parallel_size == 0 {
            return Err(SettingsError::ZeroTensorParallel);
        }
        if self.max_num_batched_tokens < self.max_num_seqs {
            return Err(SettingsError::BudgetBelowSequences {
                max_num_batched_tokens: self.max_num_batched_tokens,
                max_num_seqs: self.max_num_seqs,
            });
        }
        match (&self.nccl, self.tensor_parallel_size) {
            (None, size) if size > 1 => {
                return Err(SettingsError::MissingNcclChoice {
                    tensor_parallel_size: size,
                })
            }
            (Some(_), 1) => return Err(SettingsError::NcclChoiceForOneDevice),
            (Some(choice), size) if choice.device_count() != size => {
                return Err(SettingsError::NcclChoiceForOtherDeviceCount {
                    tensor_parallel_size: size,
                    nccl_devices: choice.device_count(),
                })
            }
            _ => {}
        }
        if self
            .drafting
            .as_ref()
            .is_some_and(|drafting| drafting.speculative_tokens == 0)
        {
            return Err(SettingsError::ZeroSpeculativeTokens);
        }
        Ok(())
    }

    /// The backend techniques beyond today's flags these settings need (GPU part §3.8):
    /// CUDA graphs for a captured graph mode, concurrency for more than one sequence.
    pub fn techniques(&self) -> Vec<Technique> {
        let concurrency = (self.max_num_seqs > 1).then_some(Technique::Concurrency);
        self.graph_mode
            .technique()
            .into_iter()
            .chain(concurrency)
            .collect()
    }

    pub fn identity(&self) -> Digest {
        self.feed(DigestBuilder::new(SETTINGS_DOMAIN)).finish()
    }

    pub(super) fn feed(&self, builder: DigestBuilder) -> DigestBuilder {
        let builder = builder
            .str(self.graph_mode.tag())
            .u64(u64::from(self.max_num_seqs))
            .u64(u64::from(self.max_num_batched_tokens));
        let builder = feed_kv(builder, &self.kv_cache)
            .u64(u64::from(self.context_tokens))
            .u64(u64::from(self.tensor_parallel_size))
            .u64(u64::from(self.gpu_memory.permille()));
        let builder = match &self.nccl {
            None => builder.str("no_nccl"),
            Some(choice) => builder
                .str(match choice.peer_to_peer {
                    PeerToPeer::Direct => "p2p_direct",
                    PeerToPeer::Disabled => "p2p_disabled",
                })
                .u64(u64::from(choice.device_count()))
                .digest(&choice.topology.identity()),
        };
        match &self.drafting {
            None => builder.str("no_drafting"),
            Some(drafting) => drafting.feed(builder.str("drafting")),
        }
    }
}

/// Why settings were refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum SettingsError {
    MemoryFractionOutOfRange {
        permille: u16,
    },
    ZeroSequences,
    ZeroContext,
    ZeroTensorParallel,
    /// Each step must have room for one token of every sequence.
    BudgetBelowSequences {
        max_num_batched_tokens: u32,
        max_num_seqs: u32,
    },
    /// Several GPUs need a per-process NCCL choice made from measured topology.
    MissingNcclChoice {
        tensor_parallel_size: u32,
    },
    NcclChoiceForOneDevice,
    NcclChoiceForOtherDeviceCount {
        tensor_parallel_size: u32,
        nccl_devices: u32,
    },
    ZeroSpeculativeTokens,
}

impl fmt::Display for SettingsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MemoryFractionOutOfRange { permille } => write!(
                f,
                "a GPU memory fraction is 1–1000 thousandths, not {permille}"
            ),
            Self::ZeroSequences => f.write_str("at least one sequence must be allowed"),
            Self::ZeroContext => f.write_str("the context must hold at least one token"),
            Self::ZeroTensorParallel => f.write_str("the tensor-parallel size is at least one"),
            Self::BudgetBelowSequences {
                max_num_batched_tokens,
                max_num_seqs,
            } => write!(
                f,
                "a budget of {max_num_batched_tokens} batched tokens cannot hold one token of \
                 each of {max_num_seqs} sequences"
            ),
            Self::MissingNcclChoice {
                tensor_parallel_size,
            } => write!(
                f,
                "{tensor_parallel_size} GPUs need a per-process NCCL choice made from measured \
                 peer topology"
            ),
            Self::NcclChoiceForOneDevice => f.write_str("one GPU has no NCCL choice"),
            Self::NcclChoiceForOtherDeviceCount {
                tensor_parallel_size,
                nccl_devices,
            } => write!(
                f,
                "the NCCL choice was made for {nccl_devices} GPUs, not {tensor_parallel_size}"
            ),
            Self::ZeroSpeculativeTokens => {
                f.write_str("drafting needs at least one speculative token")
            }
        }
    }
}

impl std::error::Error for SettingsError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model_memory::identity::LogicalModelSpec;
    use crate::model_memory::profiles::testkit::{
        d, fp8_kv, logical, logical_spec, settings, single_gpu, two_gpu_topology, two_gpus,
    };

    #[test]
    fn memory_fraction_renders_like_the_flag() {
        let fraction = |permille| MemoryFraction::new(permille).unwrap();
        assert_eq!(fraction(900).flag_value(), "0.90");
        assert_eq!(fraction(850).flag_value(), "0.85");
        assert_eq!(fraction(905).flag_value(), "0.905");
        assert_eq!(fraction(5).flag_value(), "0.005");
        assert_eq!(fraction(1000).flag_value(), "1.00");
        assert_eq!(
            MemoryFraction::new(0),
            Err(SettingsError::MemoryFractionOutOfRange { permille: 0 })
        );
        assert_eq!(
            MemoryFraction::new(1001),
            Err(SettingsError::MemoryFractionOutOfRange { permille: 1001 })
        );
        assert!(serde_json::from_str::<MemoryFraction>("1001").is_err());
        assert_eq!(serde_json::to_string(&fraction(900)).unwrap(), "900");
    }

    #[test]
    fn memory_fraction_share_and_largest_free() {
        let gib = 1u64 << 30;
        let fraction = MemoryFraction::new(900).unwrap();
        // 0.90 of 24 GiB, rounded down.
        assert_eq!(fraction.of_bytes(24 * gib), 23_192_823_398);
        assert_eq!(fraction.of_bytes(u64::MAX), 16_602_069_666_338_596_453);
        // 20 of 24 GiB free allows at most 0.833.
        assert_eq!(
            MemoryFraction::largest_free(20 * gib, 24 * gib),
            Some(MemoryFraction::new(833).unwrap())
        );
        assert_eq!(
            MemoryFraction::largest_free(30 * gib, 24 * gib),
            Some(MemoryFraction::new(1000).unwrap())
        );
        assert_eq!(MemoryFraction::largest_free(gib / 2048, gib), None);
        assert_eq!(MemoryFraction::largest_free(gib, 0), None);
    }

    #[test]
    fn nccl_choice_follows_the_measured_topology() {
        let verified = two_gpu_topology(PeerAccess::Verified);
        let choice =
            NcclChoice::from_topology(&verified, CommunicationScope::EngineProcess).unwrap();
        assert_eq!(choice.peer_to_peer(), PeerToPeer::Direct);
        assert!(choice.process_environment().is_empty());
        assert_eq!(choice.topology(), &verified);
        assert_eq!(choice.device_count(), 2);

        let unavailable = two_gpu_topology(PeerAccess::Unavailable);
        let choice =
            NcclChoice::from_topology(&unavailable, CommunicationScope::EngineProcess).unwrap();
        assert_eq!(choice.peer_to_peer(), PeerToPeer::Disabled);
        assert_eq!(
            choice.process_environment(),
            vec![("NCCL_P2P_DISABLE", "1")]
        );
    }

    #[test]
    fn nccl_choices_are_read_only_through_the_constructor() {
        let verified = two_gpu_topology(PeerAccess::Verified);
        let choice =
            NcclChoice::from_topology(&verified, CommunicationScope::EngineProcess).unwrap();
        let written = serde_json::to_value(&choice).unwrap();
        assert_eq!(written["scope"], "engine_process");
        assert_eq!(written["peer_to_peer"], "direct");
        assert_eq!(
            serde_json::from_value::<NcclChoice>(written.clone()).unwrap(),
            choice
        );
        // Direct peer-to-peer over a topology whose peer copies failed is refused.
        let mut forged = written.clone();
        forged["topology"] =
            serde_json::to_value(two_gpu_topology(PeerAccess::Unavailable)).unwrap();
        let error = serde_json::from_value::<NcclChoice>(forged).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("its measured topology gives Disabled"),
            "{error}"
        );
        // So is a choice that names its topology only by digest.
        let digest_only = serde_json::json!({
            "peer_to_peer": "direct",
            "device_count": 2,
            "topology": verified.identity().to_hex(),
        });
        assert!(serde_json::from_value::<NcclChoice>(digest_only).is_err());
        // And a machine-wide scope, an incomplete topology, one GPU or an unknown field.
        let mut machine_wide = written.clone();
        machine_wide["scope"] = serde_json::json!("machine_wide");
        assert!(serde_json::from_value::<NcclChoice>(machine_wide).is_err());
        let mut one_way = verified.clone();
        one_way.paths.retain(|path| path.from == 0);
        let mut incomplete = written.clone();
        incomplete["topology"] = serde_json::to_value(&one_way).unwrap();
        assert!(serde_json::from_value::<NcclChoice>(incomplete).is_err());
        let mut single = written.clone();
        single["topology"] = serde_json::to_value(PeerTopology::single()).unwrap();
        assert!(serde_json::from_value::<NcclChoice>(single).is_err());
        let mut extra = written;
        extra["note"] = serde_json::json!("trusted");
        assert!(serde_json::from_value::<NcclChoice>(extra).is_err());
    }

    #[test]
    fn nccl_choice_is_never_machine_wide() {
        assert_eq!(
            NcclChoice::from_topology(
                &two_gpu_topology(PeerAccess::Verified),
                CommunicationScope::MachineWide
            ),
            Err(CommunicationRefusal::MachineWide {
                change: HostChange::MachineWideCommunicationSetting
            })
        );
    }

    #[test]
    fn nccl_choice_needs_a_complete_measured_topology() {
        let mut one_way = two_gpu_topology(PeerAccess::Verified);
        one_way.paths.retain(|path| path.from == 0);
        assert_eq!(
            NcclChoice::from_topology(&one_way, CommunicationScope::EngineProcess),
            Err(CommunicationRefusal::Topology {
                error: TopologyError::MissingPath { from: 1, to: 0 }
            })
        );
        assert_eq!(
            NcclChoice::from_topology(&PeerTopology::single(), CommunicationScope::EngineProcess),
            Err(CommunicationRefusal::SingleDevice)
        );
        let mut repeated = two_gpu_topology(PeerAccess::Verified);
        repeated.paths.push(repeated.paths[0]);
        assert_eq!(
            repeated.check(),
            Err(TopologyError::RepeatedPath { from: 0, to: 1 })
        );
        let mut outside = two_gpu_topology(PeerAccess::Verified);
        outside.paths[0].to = 2;
        assert_eq!(
            outside.check(),
            Err(TopologyError::DeviceOutOfRange { from: 0, to: 2 })
        );
        let mut itself = two_gpu_topology(PeerAccess::Verified);
        itself.paths[0].to = 0;
        assert_eq!(itself.check(), Err(TopologyError::SelfPath { device: 0 }));
        let empty = PeerTopology {
            device_count: 0,
            paths: Vec::new(),
        };
        assert_eq!(empty.check(), Err(TopologyError::NoDevices));
    }

    #[test]
    fn topology_identity_ignores_listing_order_but_not_links() {
        let topology = two_gpu_topology(PeerAccess::Verified);
        let mut reversed = topology.clone();
        reversed.paths.reverse();
        assert_eq!(topology.identity(), reversed.identity());
        let mut nvlink = topology.clone();
        for path in &mut nvlink.paths {
            path.link = PeerLink::NvLink;
        }
        assert_ne!(topology.identity(), nvlink.identity());
        assert_ne!(
            topology.identity(),
            two_gpu_topology(PeerAccess::Unavailable).identity()
        );
    }

    #[test]
    fn a_card_name_alone_does_not_identify_hardware() {
        let one = single_gpu();
        let two = two_gpus(&two_gpu_topology(PeerAccess::Verified));
        assert_eq!(one.gpu_name, two.gpu_name);
        assert_ne!(one.identity(), two.identity());
        let other_topology = two_gpus(&two_gpu_topology(PeerAccess::Unavailable));
        assert_eq!(two.gpu_name, other_topology.gpu_name);
        assert_eq!(two.gpu_count, other_topology.gpu_count);
        assert_ne!(two.identity(), other_topology.identity());
        let mut other_memory = one.clone();
        other_memory.memory_bytes_per_gpu /= 2;
        assert_ne!(one.identity(), other_memory.identity());
    }

    #[test]
    fn comparisons_hold_hardware_driver_model_and_load_fixed() {
        let before = ComparisonConditions {
            hardware: single_gpu().identity(),
            driver: "580.95.05".to_owned(),
            model: logical(),
            load: d("load"),
        };
        assert_eq!(before.compare(&before.clone()), Ok(()));
        let mut after = before.clone();
        after.hardware = d("other hardware");
        after.driver = "575.0".to_owned();
        after.model = LogicalModelSpec {
            tokenizer: d("other tokenizer"),
            ..logical_spec()
        }
        .identity();
        after.load = d("other load");
        assert_eq!(
            before.compare(&after),
            Err(NotComparable {
                mismatches: vec![
                    ConditionMismatch::Hardware,
                    ConditionMismatch::Driver,
                    ConditionMismatch::Model,
                    ConditionMismatch::Load
                ]
            })
        );
        let mut driver_only = before.clone();
        driver_only.driver = "575.0".to_owned();
        assert_eq!(
            before.compare(&driver_only),
            Err(NotComparable {
                mismatches: vec![ConditionMismatch::Driver]
            })
        );
    }

    #[test]
    fn settings_are_checked() {
        assert_eq!(settings().check(), Ok(()));
        let mut zero = settings();
        zero.max_num_seqs = 0;
        assert_eq!(zero.check(), Err(SettingsError::ZeroSequences));
        let mut budget = settings();
        budget.max_num_seqs = 8;
        budget.max_num_batched_tokens = 4;
        assert_eq!(
            budget.check(),
            Err(SettingsError::BudgetBelowSequences {
                max_num_batched_tokens: 4,
                max_num_seqs: 8
            })
        );
        let mut two = settings();
        two.tensor_parallel_size = 2;
        assert_eq!(
            two.check(),
            Err(SettingsError::MissingNcclChoice {
                tensor_parallel_size: 2
            })
        );
        let choice = NcclChoice::from_topology(
            &two_gpu_topology(PeerAccess::Verified),
            CommunicationScope::EngineProcess,
        )
        .unwrap();
        two.nccl = Some(choice.clone());
        assert_eq!(two.check(), Ok(()));
        let mut one_with_nccl = settings();
        one_with_nccl.nccl = Some(choice);
        assert_eq!(
            one_with_nccl.check(),
            Err(SettingsError::NcclChoiceForOneDevice)
        );
        let mut four = two.clone();
        four.tensor_parallel_size = 4;
        assert_eq!(
            four.check(),
            Err(SettingsError::NcclChoiceForOtherDeviceCount {
                tensor_parallel_size: 4,
                nccl_devices: 2
            })
        );
    }

    #[test]
    fn settings_identity_covers_every_field() {
        let base = settings();
        let mut variants = Vec::new();
        let mut changed = base.clone();
        changed.graph_mode = GraphMode::FullCudaGraphs;
        variants.push(changed);
        let mut changed = base.clone();
        changed.max_num_seqs += 1;
        variants.push(changed);
        let mut changed = base.clone();
        changed.max_num_batched_tokens += 1;
        variants.push(changed);
        let mut changed = base.clone();
        changed.kv_cache = fp8_kv();
        variants.push(changed);
        let mut changed = base.clone();
        changed.context_tokens += 1;
        variants.push(changed);
        let mut changed = base.clone();
        changed.gpu_memory = MemoryFraction::new(800).unwrap();
        variants.push(changed);
        for variant in variants {
            assert_ne!(variant.identity(), base.identity(), "{variant:?}");
        }
        assert_eq!(base.identity(), settings().identity());
    }
}
