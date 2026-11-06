//! Value types of the transfer executor (GPU §3.5): extents and how they are stored,
//! destinations, the singleflight key, sources, paths, read methods, the copy API and the
//! measured stages.

use std::fmt;
use std::num::NonZeroU64;

use serde::{Deserialize, Serialize};

use super::error::MethodUnavailable;
use super::ports::EvidencePort;
use crate::foundation::evidence::{
    Capability, ConfigurationFingerprint, EvidencePolicy, EvidenceRefusal, GpuPairSubject,
    LoaderPlan, Necessity, Optimization, Requirement, Subject,
};
use crate::foundation::ids::{
    ContentKey, Digest, GpuAllocationGeneration, GpuDeviceKey, MonotonicTime,
};
use crate::model_memory::backends::{needs_cuda, BackendRuntime, ComputePlatform, PlatformRefusal};
use crate::model_memory::manifest::{CodecFormat, DictionaryId, EncodedDigest};
use crate::model_memory::math::sources::SourceSpec;

/// One integrity extent (GPU §2.4 `g_h`) of one artifact: the unit verified on its own.
/// The artifact is named by its content key. Equal keys mean equal bytes, never
/// permission to read them (S3.3), so each subscriber's own sources are still checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ExtentId {
    pub artifact: ContentKey,
    pub index: u64,
}

/// How one extent is stored, as the verified manifest records it (GPU §3.3 extents,
/// [`crate::model_memory::manifest::ExtentEncoding`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StoredForm {
    /// The decoded bytes themselves, checked against the decoded content key.
    Raw,
    /// An encoded representation with its own digest over codec format (codec, version and
    /// frame parameters), dictionary and encoded bytes, checked before decoding (§3.5 step
    /// 5).
    Encoded {
        codec: CodecFormat,
        dictionary: Option<DictionaryId>,
        digest: EncodedDigest,
    },
}

impl StoredForm {
    /// Whether the extent needs a decode step and room in a decode slot.
    pub const fn needs_decode(&self) -> bool {
        matches!(self, Self::Encoded { .. })
    }
}

/// One extent as the verified manifest records it (§3.5 step 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ManifestExtent {
    pub index: u64,
    /// Where the stored extent lies in the stored object: the source file for a raw
    /// extent, the prepared file for an encoded one.
    pub stored_offset_bytes: u64,
    pub stored_length_bytes: u64,
    pub stored: StoredForm,
    /// Where the decoded extent lies in the artifact.
    pub decoded_offset_bytes: u64,
    /// The true decoded length; extents are never padded (GPU §2.4).
    pub decoded_length_bytes: u64,
    /// The decoded content key over the true length and the decoded bytes (§3.5 step 5).
    pub decoded_key: ContentKey,
}

impl ManifestExtent {
    /// End of the stored extent in the stored object; `None` on overflow.
    pub fn stored_end_bytes(&self) -> Option<u64> {
        self.stored_offset_bytes
            .checked_add(self.stored_length_bytes)
    }

    /// End of the decoded extent in the artifact; `None` on overflow.
    pub fn decoded_end_bytes(&self) -> Option<u64> {
        self.decoded_offset_bytes
            .checked_add(self.decoded_length_bytes)
    }

    /// The digest the stored bytes must have: the decoded content key's for a raw
    /// extent, the encoded digest for an encoded one.
    pub fn stored_digest(&self) -> Digest {
        match self.stored {
            StoredForm::Raw => *self.decoded_key.digest(),
            StoredForm::Encoded { digest, .. } => digest.digest(),
        }
    }

    /// Bytes the extent needs in a decode slot: its decoded length when encoded, none
    /// when raw.
    pub fn decode_bytes(&self) -> u64 {
        if self.stored.needs_decode() {
            self.decoded_length_bytes
        } else {
            0
        }
    }
}

/// One generation of one GPU allocation (S3.1). A reallocation gets a new generation, so
/// a transfer into the old one is a different destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AllocationKey {
    pub device: GpuDeviceKey,
    pub allocation: Digest,
    pub generation: GpuAllocationGeneration,
}

/// Where a job writes its decoded artifact: byte `base_offset_bytes` of the allocation
/// holds the artifact's first decoded byte, and the job writes nothing at or past
/// `base_offset_bytes + capacity_bytes`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Destination {
    pub allocation: AllocationKey,
    pub base_offset_bytes: u64,
    pub capacity_bytes: u64,
}

/// The singleflight key (§3.5): the artifact extent, its representation and the
/// destination region it fills. Requests with equal keys share one operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FlightKey {
    pub extent: ExtentId,
    /// The representation's content key.
    pub representation: ContentKey,
    pub allocation: AllocationKey,
    /// Offset of the decoded extent in the allocation.
    pub offset_bytes: u64,
}

/// What kind of place a source is (GPU §3.4 tiers; Appendix A.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum SourceKind {
    /// A committed file in local storage, read into the host ring by an ungated method,
    /// or by GPUDirect Storage when the gate enables it.
    LocalFile,
    /// A remote store, read by range requests.
    Remote,
    /// An authorized peer machine, read by range requests.
    AuthorizedPeer,
    /// Another GPU on this host holding the same representation, copied peer to peer.
    GpuPeer { device: GpuDeviceKey },
    /// The `/yougori-model` bind: FUSE over HTTP, an import source and never a hot-path
    /// read source (Appendix A.3).
    ImportOnlyBind,
}

crate::foundation::strict_serde::strict_tag!(SourceKind, "kind");

impl SourceKind {
    /// Whether the executor may ever read from this kind of source.
    pub const fn is_read_source(self) -> bool {
        !matches!(self, Self::ImportOnlyBind)
    }

    /// Whether bytes from this kind of source cross the network to this host: a remote
    /// store or an authorized peer, which CORE-05 transfers carry (GPU-W09).
    pub const fn is_network(self) -> bool {
        matches!(self, Self::Remote | Self::AuthorizedPeer)
    }
}

/// A source the catalog offers, with the measured profile source choice uses (GPU §2.5,
/// through [`crate::model_memory::math::sources`]).
#[derive(Clone, Debug, PartialEq)]
pub struct SourceCandidate {
    pub kind: SourceKind,
    pub spec: SourceSpec,
}

/// Whether work serves a request now or a prediction (GPU §2.9). Foreground is higher.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Priority {
    Speculative,
    Foreground,
}

/// How bytes are read (§3.5 step 4, GPU-W04).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadMethod {
    /// Threaded positioned reads of a local file.
    PositionedRead,
    /// A memory-mapped view of a local file.
    MemoryMap,
    /// An upstream bulk loader that meets the contract (GPU-W04).
    UpstreamLoader,
    /// io_uring, only where its capability gate enables it (GPU-W04, INT-06).
    IoUring,
    /// Range requests to a remote store or authorized peer.
    RangeRequest,
    /// GPUDirect Storage into device staging, only where its gate enables it.
    GpuDirectStorage,
    /// A peer-to-peer copy from another GPU into device staging.
    PeerCopy,
    /// Positioned reads of a local file with direct I/O, bypassing the page cache
    /// (`O_DIRECT`; `F_NOCACHE` on macOS): offsets, lengths and buffers aligned to the
    /// filesystem's block (GPU-W04). Used only through [`DirectIo`], which falls back to
    /// buffered reads with a reason (GPU-T20).
    DirectRead,
}

impl ReadMethod {
    pub const ALL: [Self; 8] = [
        Self::PositionedRead,
        Self::MemoryMap,
        Self::UpstreamLoader,
        Self::IoUring,
        Self::RangeRequest,
        Self::GpuDirectStorage,
        Self::PeerCopy,
        Self::DirectRead,
    ];

    /// The optimization whose gate must enable this method; `None` for ungated methods.
    pub const fn gate(self) -> Option<Optimization> {
        match self {
            Self::IoUring => Some(Optimization::IoUring),
            Self::GpuDirectStorage => Some(Optimization::GpuDirectStorage),
            Self::PositionedRead
            | Self::MemoryMap
            | Self::UpstreamLoader
            | Self::RangeRequest
            | Self::PeerCopy
            | Self::DirectRead => None,
        }
    }

    /// Whether this method reads a local file into the host ring without a gate, so it
    /// can be the configured ordinary loader. Direct I/O is not one: it has its own
    /// fallback ([`DirectIo`]).
    pub const fn is_ordinary_local(self) -> bool {
        matches!(
            self,
            Self::PositionedRead | Self::MemoryMap | Self::UpstreamLoader
        )
    }

    /// The backend API the method names, where it names one.
    pub const fn api_name(self) -> Option<&'static str> {
        match self {
            Self::GpuDirectStorage => Some("cuFileRead"),
            Self::PeerCopy => Some("cudaMemcpyPeerAsync"),
            Self::IoUring => Some("io_uring"),
            Self::DirectRead => Some("O_DIRECT"),
            Self::PositionedRead | Self::MemoryMap | Self::UpstreamLoader | Self::RangeRequest => {
                None
            }
        }
    }
}

impl fmt::Display for ReadMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::PositionedRead => "positioned reads",
            Self::MemoryMap => "a memory map",
            Self::UpstreamLoader => "the upstream loader",
            Self::IoUring => "io_uring",
            Self::RangeRequest => "range requests",
            Self::GpuDirectStorage => "GPUDirect Storage",
            Self::PeerCopy => "a GPU peer copy",
            Self::DirectRead => "direct I/O",
        })
    }
}

/// Where staged bytes live: the host ring or one GPU's staging pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "place", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum StagingPlace {
    Host,
    Device { device: GpuDeviceKey },
}

crate::foundation::strict_serde::strict_tag!(StagingPlace, "place");

/// The path a batch takes (§3.5). Direct paths skip the host ring by design but still
/// use bounded device staging, verification and completion events. A direct path the
/// backend served through host memory is labelled as such (GPU-T21).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "path", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum TransferPath {
    /// The portable path through the host staging ring.
    HostRing,
    /// GPUDirect Storage into device staging.
    DirectStorage,
    /// A GPU peer copy into device staging.
    GpuPeer { from: GpuDeviceKey },
    /// GPUDirect Storage was asked for and cuFile served it in its compatibility mode,
    /// through its own host bounce buffer into device staging: not a direct transfer.
    DirectStorageCompatibility,
    /// A GPU peer copy was asked for and the driver staged it through host memory: not a
    /// direct transfer.
    GpuPeerThroughHost { from: GpuDeviceKey },
}

crate::foundation::strict_serde::strict_tag!(TransferPath, "path");

impl TransferPath {
    /// Whether the bytes never pass through host memory: GPUDirect Storage or a GPU peer
    /// copy, served as asked for.
    pub const fn bypasses_host_ring(self) -> bool {
        matches!(self, Self::DirectStorage | Self::GpuPeer { .. })
    }

    /// Whether a read asked to take `requested` may have taken this path: the same path,
    /// or its host fallback. Anything else breaks the backend contract.
    pub fn serves(self, requested: Self) -> bool {
        self == requested
            || match (requested, self) {
                (Self::DirectStorage, Self::DirectStorageCompatibility) => true,
                (Self::GpuPeer { from }, Self::GpuPeerThroughHost { from: through }) => {
                    from == through
                }
                _ => false,
            }
    }
}

/// What GPU-peer reads need from CORE-01 (FAST-02: peer access is probed, never
/// assumed): `GpuPeerAccess` evidence for the exact direction, an exercised copy, within
/// `evidence` (never below CORE-01's guest-report floor) and observed under
/// `configuration`, the GPU configuration in force now. Without it no GPU peer is read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerAccessPolicy {
    pub evidence: EvidencePolicy,
    pub configuration: ConfigurationFingerprint,
}

impl PeerAccessPolicy {
    /// The CORE-01 requirement a peer copy from `from` into `to` needs; `None` across
    /// machines and for a GPU as its own peer, which are never peers.
    pub fn requirement(&self, from: GpuDeviceKey, to: GpuDeviceKey) -> Option<Requirement> {
        if from.machine != to.machine || from.device == to.device {
            return None;
        }
        Some(Requirement::new(
            Capability::GpuPeerAccess,
            Subject::GpuPair(GpuPairSubject {
                machine: from.machine,
                from: from.device,
                to: to.device,
            }),
            self.evidence.minimum_source,
            self.evidence.max_age,
            self.configuration,
        ))
    }
}

/// Direct I/O for local files (GPU-W04's bounded option; plan line 934): a read the
/// ordinary loader would make uses [`ReadMethod::DirectRead`] when the backend implements
/// it, the read is aligned to `block_bytes` and its file has not refused it; otherwise it
/// is read buffered, and the reason is reported (GPU-T20).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectIo {
    /// The filesystem's direct-I/O block: a direct read's offset and length are
    /// multiples of it, and the backend aligns its staging buffers to it.
    pub block_bytes: NonZeroU64,
}

/// The asynchronous copy API a backend uses for step 6 (§3.5).
///
/// The list is closed and names only real APIs: the report's illustrative
/// `torch.cuda.memcpy_async` is not a PyTorch API and has no variant (§3.5, line 568).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CopyApi {
    /// CUDA runtime `cudaMemcpyAsync` on a stream.
    CudaMemcpyAsync,
    /// CUDA driver `cuMemcpyAsync` on a stream.
    CuMemcpyAsync,
    /// PyTorch `Tensor.copy_` with `non_blocking=True` on the current stream.
    TorchTensorCopyNonBlocking,
}

impl CopyApi {
    pub const ALL: [Self; 3] = [
        Self::CudaMemcpyAsync,
        Self::CuMemcpyAsync,
        Self::TorchTensorCopyNonBlocking,
    ];

    /// The API's exact name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::CudaMemcpyAsync => "cudaMemcpyAsync",
            Self::CuMemcpyAsync => "cuMemcpyAsync",
            Self::TorchTensorCopyNonBlocking => "torch.Tensor.copy_(non_blocking=True)",
        }
    }

    /// The API with exactly this name; any other name, including an invented one, is
    /// refused.
    pub fn from_name(name: &str) -> Result<Self, UnsupportedApi> {
        Self::ALL
            .into_iter()
            .find(|api| api.name() == name)
            .ok_or_else(|| UnsupportedApi {
                name: name.to_owned(),
            })
    }
}

impl fmt::Display for CopyApi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A copy API name that is not a supported backend API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnsupportedApi {
    pub name: String,
}

impl fmt::Display for UnsupportedApi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} is not a supported copy API; use one of cudaMemcpyAsync, cuMemcpyAsync or \
             torch.Tensor.copy_(non_blocking=True)",
            self.name
        )
    }
}

impl std::error::Error for UnsupportedApi {}

/// A measured stage of the portable path (§3.5 step 9), in path order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    /// Step 1: the catalog resolves the verified manifest and candidate sources.
    Resolve,
    /// Step 2: destination reservation before anything starts.
    Reserve,
    /// Step 3: coalescing extents into aligned batches.
    Coalesce,
    /// Step 4: a batch read, from start to observed completion.
    Read,
    /// Step 5: verifying encoded extents.
    Verify,
    /// Step 5: decoding.
    Decode,
    /// Step 5: validating decoded identities.
    Validate,
    /// Steps 6–7: a copy, from enqueue to its observed completion event.
    Copy,
}

impl Stage {
    pub const ALL: [Self; 8] = [
        Self::Resolve,
        Self::Reserve,
        Self::Coalesce,
        Self::Read,
        Self::Verify,
        Self::Decode,
        Self::Validate,
        Self::Copy,
    ];

    /// The step of the portable path this stage belongs to (§3.5, steps 1–7).
    pub const fn step(self) -> u8 {
        match self {
            Self::Resolve => 1,
            Self::Reserve => 2,
            Self::Coalesce => 3,
            Self::Read => 4,
            Self::Verify | Self::Decode | Self::Validate => 5,
            Self::Copy => 6,
        }
    }
}

/// One gated read method the evidence gate enabled for a load (INT-06).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct GatedMethod {
    necessity: Necessity,
    fresh_until: MonotonicTime,
}

impl GatedMethod {
    /// Whether the request required the method or merely accepted it.
    pub const fn necessity(self) -> Necessity {
        self.necessity
    }

    /// The last moment the evidence that enabled the method is fresh, on the clock of
    /// the registry that made the plan.
    pub const fn fresh_until(self) -> MonotonicTime {
        self.fresh_until
    }
}

/// The gated read methods a load may use (INT-06, GPU-W04: io_uring and GPUDirect
/// Storage only behind their capability gates).
///
/// Made only from a [`LoaderPlan`], which only the evidence gate makes, or as the
/// ordinary loader with nothing enabled; a caller cannot enable a method by hand. A
/// gated method lasts only while its plan does: each use rechecks the plan's evidence in
/// the live registry through [`LoaderPlan::recheck`], so evidence that expired, comes
/// from another clock session, or was invalidated by a configuration change (CORE-01)
/// ends it. A CUDA mechanism also needs a runtime that computes on CUDA, shown by fresh
/// CORE-01 `ComputePlatform` evidence on every use, never by the runtime's declaration
/// alone (GPU §3.8, [`BackendRuntime::judge_platform`]). A method that cannot be used
/// gives way to the ordinary loader when optional and is refused, never replaced, when
/// required (INT-06).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoaderPermissions {
    /// The gate's plan; `None` for the ordinary loader.
    plan: Option<LoaderPlan>,
    /// The runtime the plan was made for, whose platform evidence is judged on every use
    /// of a CUDA mechanism; `None` when only the plan is known.
    runtime: Option<Box<BackendRuntime>>,
}

impl LoaderPermissions {
    /// The ordinary authorized loader: no gated method.
    pub const fn ordinary() -> Self {
        Self {
            plan: None,
            runtime: None,
        }
    }

    /// The gated methods of `runtime`'s plan (P06). A CUDA mechanism among them is used
    /// only while fresh CORE-01 evidence shows the runtime's declared CUDA platform under
    /// its platform policy ([`BackendRuntime::with_platform_policy`]); the declaration
    /// alone only ever refuses.
    pub fn from_runtime(runtime: &BackendRuntime) -> Self {
        Self {
            plan: Some(runtime.plan().clone()),
            runtime: Some(Box::new(runtime.clone())),
        }
    }

    /// The gated methods `plan` enabled, for a runtime whose platform is not known. A
    /// plan does not say where its runtime computes, and an unknown platform is never
    /// CUDA (GPU §3.8: "CUDA mechanisms are not silently assumed"), so the plan's CUDA
    /// mechanisms are never permitted and a load that requires one is refused. Use
    /// [`Self::from_runtime`] for a runtime on CUDA.
    pub fn from_plan(plan: &LoaderPlan) -> Self {
        Self {
            plan: Some(plan.clone()),
            runtime: None,
        }
    }

    /// The platform the runtime was declared with, which CUDA mechanisms are checked
    /// against; [`ComputePlatform::Other`] when only the plan is known.
    pub fn platform(&self) -> ComputePlatform {
        self.runtime
            .as_ref()
            .map_or(ComputePlatform::Other, |runtime| runtime.platform())
    }

    /// What the plan enabled for a gated method; `None` for ungated methods and for
    /// gated ones it did not enable.
    pub fn gated(&self, method: ReadMethod) -> Option<GatedMethod> {
        let optimization = method.gate()?;
        let plan = self.plan.as_ref()?;
        Some(GatedMethod {
            necessity: plan.necessity(optimization)?,
            fresh_until: plan.evidence_for(optimization)?.fresh_until(),
        })
    }

    /// Whether `method` may be used now: ungated methods always, gated ones only when
    /// [`Self::unavailable`] finds nothing against them in `evidence`.
    pub fn permits<E: EvidencePort + ?Sized>(&self, method: ReadMethod, evidence: &E) -> bool {
        self.unavailable(method, evidence).is_none()
    }

    /// Why `method` may not be used now; `None` when it may. A gated method needs the
    /// plan to have enabled it; when it is a CUDA mechanism, a runtime declared on CUDA
    /// whose platform fresh evidence in `evidence` shows now; and every piece of the
    /// plan's evidence still holding in `evidence`, its own first: a plan lasts only while
    /// all of its evidence does (T01, [`LoaderPlan::valid_until`]).
    pub fn unavailable<E: EvidencePort + ?Sized>(
        &self,
        method: ReadMethod,
        evidence: &E,
    ) -> Option<MethodUnavailable> {
        let optimization = method.gate()?;
        let Some(plan) = self
            .plan
            .as_ref()
            .filter(|plan| plan.is_enabled(optimization))
        else {
            return Some(MethodUnavailable::NotEnabled);
        };
        if needs_cuda(optimization) {
            let platform = self.platform();
            let Some(runtime) = self.runtime.as_ref().filter(|_| platform.is_cuda()) else {
                return Some(MethodUnavailable::NotOnCuda { platform });
            };
            let judged = match runtime.platform_requirement() {
                Some(requirement) => runtime.judge_platform(evidence.evaluate(&requirement)),
                None => Err(PlatformRefusal::NoPolicy),
            };
            if let Err(refusal) = judged {
                return Some(MethodUnavailable::PlatformNotShown { refusal });
            }
        }
        let others = plan.enabled().filter(|other| *other != optimization);
        std::iter::once(optimization)
            .chain(others)
            .find_map(|enabled| evidence.recheck(plan, enabled).err())
            .map(|refusal| {
                if matches!(refusal, EvidenceRefusal::Stale { .. }) {
                    MethodUnavailable::EvidenceExpired
                } else {
                    MethodUnavailable::EvidenceWithdrawn
                }
            })
    }

    /// The gated methods the request required, which the ordinary loader may never
    /// replace.
    pub fn required(&self) -> Vec<ReadMethod> {
        [ReadMethod::GpuDirectStorage, ReadMethod::IoUring]
            .into_iter()
            .filter(|method| {
                self.gated(*method)
                    .is_some_and(|gated| gated.necessity == Necessity::Required)
            })
            .collect()
    }

    /// Whether two loads can share one read: neither requires a method the other's plan
    /// did not enable, and they do not require two different methods, since one read
    /// uses one method.
    pub fn compatible_with(&self, other: &Self) -> bool {
        let covers = |one: &Self, two: &Self| {
            one.required()
                .into_iter()
                .all(|method| two.gated(method).is_some())
        };
        let (mine, theirs) = (self.required(), other.required());
        let one_method = mine.is_empty() || theirs.is_empty() || mine == theirs;
        covers(self, other) && covers(other, self) && one_method
    }
}
