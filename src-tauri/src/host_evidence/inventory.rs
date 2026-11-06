//! What one collection observed about this computer, parsed and checked (S01).
//!
//! Every parser here is pure and bounded, so the real queries in [`super::collect`] and
//! the recorded fixtures in the tests go through the same checks. Raw machine and GPU
//! identifiers are digested at once, in the domains host admission uses
//! (`model_runner/optimizer/capacity/probe.rs`), and never kept.

use std::fmt;
use std::num::NonZeroU64;

use serde::Serialize;

use crate::foundation::evidence::OsKind;
use crate::foundation::ids::{digest, Digest, MonotonicTime};

/// Domain of a machine's digest; host admission names the same machine with it.
pub const MACHINE_DOMAIN: &str = "yougori/local-machine/v1";
/// Domain of an NVIDIA GPU's digest, over its UUID; host admission uses it too.
pub const NVIDIA_DEVICE_DOMAIN: &str = "yougori/nvidia-device/v1";
/// The most GPUs one inventory accepts; more is refused rather than truncated.
pub const MAX_GPUS: usize = 64;

/// A mebibyte, the unit `nvidia-smi` reports memory in.
const MIB: u64 = 1024 * 1024;
/// The largest GPU memory accepted, 1 PiB, as host admission bounds it.
const MAX_GPU_BYTES: u64 = 1 << 50;

/// Why part of an inventory could not be read. Each names what was wrong, never the raw
/// value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum InventoryProblem {
    /// The query's program is not installed.
    ToolMissing,
    /// The query ran and failed.
    QueryFailed,
    /// The query did not finish within its deadline and was killed.
    TimedOut,
    /// The query wrote more than its output bound.
    OutputTooLong,
    /// The query's output is not UTF-8.
    NotUtf8,
    /// The machine identity is missing or malformed.
    MachineIdentity,
    /// The operating system build is missing or malformed.
    OsBuild,
    /// One GPU row is malformed; rows count from 1.
    MalformedGpuRow { row: usize },
    /// More GPUs than [`MAX_GPUS`].
    TooManyGpus,
    /// Two rows name the same GPU.
    RepeatedGpu,
    /// The query is not available on this operating system.
    NotOnThisPlatform,
}

impl fmt::Display for InventoryProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ToolMissing => f.write_str("the query's program is not installed"),
            Self::QueryFailed => f.write_str("the query failed"),
            Self::TimedOut => f.write_str("the query timed out and was stopped"),
            Self::OutputTooLong => f.write_str("the query's output exceeded its bound"),
            Self::NotUtf8 => f.write_str("the query's output is not text"),
            Self::MachineIdentity => f.write_str("the machine identity is unavailable"),
            Self::OsBuild => f.write_str("the operating system build is unavailable"),
            Self::MalformedGpuRow { row } => write!(f, "GPU row {row} is malformed"),
            Self::TooManyGpus => write!(f, "more than {MAX_GPUS} GPUs were reported"),
            Self::RepeatedGpu => f.write_str("a GPU was reported twice"),
            Self::NotOnThisPlatform => f.write_str("the query does not exist on this platform"),
        }
    }
}

impl std::error::Error for InventoryProblem {}

/// The digest naming this machine: [`MACHINE_DOMAIN`] over its lowercase machine identity
/// (Windows `MachineGuid`, Linux `/etc/machine-id`), checked as host admission checks it.
pub fn machine_digest(raw: &str) -> Result<Digest, InventoryProblem> {
    let raw = raw.trim();
    if raw.is_empty()
        || raw.len() > 128
        || !raw
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
    {
        return Err(InventoryProblem::MachineIdentity);
    }
    Ok(digest(
        MACHINE_DOMAIN,
        &[raw.to_ascii_lowercase().as_bytes()],
    ))
}

/// The digest naming one NVIDIA GPU: [`NVIDIA_DEVICE_DOMAIN`] over its lowercase UUID,
/// which must read `GPU-` and 36 hexadecimal digits or dashes.
pub fn device_digest(uuid: &str) -> Option<Digest> {
    let well_formed = uuid.len() == 40
        && uuid.starts_with("GPU-")
        && uuid[4..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b'-');
    well_formed.then(|| {
        digest(
            NVIDIA_DEVICE_DOMAIN,
            &[uuid.to_ascii_lowercase().as_bytes()],
        )
    })
}

/// The operating system, as configuration that evidence depends on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OsFacts {
    pub kind: OsKind,
    /// The architecture this engine was built for, such as `x86_64`.
    pub architecture: String,
    /// The build or kernel release, such as Windows build `26200` or Linux `6.8.0-45`;
    /// `None` when it could not be read.
    pub build: Option<String>,
}

impl OsFacts {
    /// This engine's operating system and architecture, with `build` as read.
    pub fn this_platform(build: Option<String>) -> Option<Self> {
        let kind = if cfg!(target_os = "windows") {
            OsKind::Windows
        } else if cfg!(target_os = "linux") {
            OsKind::Linux
        } else if cfg!(target_os = "macos") {
            OsKind::MacOs
        } else {
            return None;
        };
        Some(Self {
            kind,
            architecture: std::env::consts::ARCH.to_owned(),
            build,
        })
    }
}

/// How the Windows driver runs a GPU; WSL CUDA needs WDDM.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DriverModel {
    Wddm,
    Tcc,
    Mcdm,
    /// Not reported, as on Linux.
    NotReported,
}

impl DriverModel {
    fn parse(field: &str) -> Option<Self> {
        match field {
            "WDDM" => Some(Self::Wddm),
            "TCC" => Some(Self::Tcc),
            "MCDM" => Some(Self::Mcdm),
            _ if not_reported(field) => Some(Self::NotReported),
            _ => None,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Wddm => "wddm",
            Self::Tcc => "tcc",
            Self::Mcdm => "mcdm",
            Self::NotReported => "not_reported",
        }
    }
}

/// Whether the GPU is partitioned with MIG.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MigMode {
    Enabled,
    Disabled,
    NotSupported,
}

impl MigMode {
    fn parse(field: &str) -> Option<Self> {
        match field {
            "Enabled" => Some(Self::Enabled),
            "Disabled" => Some(Self::Disabled),
            _ if not_reported(field) => Some(Self::NotSupported),
            _ => None,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::Disabled => "disabled",
            Self::NotSupported => "not_supported",
        }
    }
}

/// One NVIDIA GPU as the host saw it, named by its device digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GpuDevice {
    pub device: Digest,
    /// Digits and dots only, such as `592.01`.
    pub driver_version: String,
    /// Such as `8.9`; `None` when the driver does not report it.
    pub compute_capability: Option<String>,
    pub driver_model: DriverModel,
    pub mig: MigMode,
    pub total_bytes: NonZeroU64,
    pub used_bytes: u64,
    pub free_bytes: u64,
}

impl GpuDevice {
    /// The compute capability as (major, minor), when reported.
    pub fn compute_version(&self) -> Option<(u32, u32)> {
        let (major, minor) = self.compute_capability.as_deref()?.split_once('.')?;
        Some((major.parse().ok()?, minor.parse().ok()?))
    }

    pub(super) fn driver_model_label(&self) -> &'static str {
        self.driver_model.label()
    }

    pub(super) fn mig_label(&self) -> &'static str {
        self.mig.label()
    }
}

/// The GPUs one collection found, or why it found none.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum GpuInventory {
    /// The query answered; the list may be empty.
    Devices { devices: Vec<GpuDevice> },
    /// The query could not answer.
    Unavailable { problem: InventoryProblem },
}

/// The local CUDA runtime as the engine reports it (`RuntimeManager::cuda_status`): the
/// WSL 2 GPU runtime, a shared-kernel GPU runtime under VM-D4.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CudaRuntimeFacts {
    /// This computer meets the runtime's prerequisites.
    pub supported: bool,
    pub installed: bool,
    pub running: bool,
    /// The installed payload is not the one this engine ships.
    pub update_available: bool,
}

/// The machine's digest, or why it could not be read; without it no subject can be named.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum MachineIdentity {
    Known { machine: Digest },
    Unavailable { problem: InventoryProblem },
}

impl MachineIdentity {
    pub fn from_result(result: Result<Digest, InventoryProblem>) -> Self {
        match result {
            Ok(machine) => Self::Known { machine },
            Err(problem) => Self::Unavailable { problem },
        }
    }

    pub fn digest(self) -> Option<Digest> {
        match self {
            Self::Known { machine } => Some(machine),
            Self::Unavailable { .. } => None,
        }
    }
}

/// One collection: the machine, its operating system, its GPUs and its CUDA runtime.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostInventory {
    pub machine: MachineIdentity,
    pub os: Option<OsFacts>,
    pub gpus: GpuInventory,
    /// `None` where the engine has no CUDA runtime or did not report it.
    pub cuda_runtime: Option<CudaRuntimeFacts>,
    /// When the collection started, on the evidence service's clock; an observation from
    /// this inventory is never fresher than this.
    pub started_at: MonotonicTime,
}

impl HostInventory {
    /// The GPU named `device`, if this inventory found it.
    pub fn gpu(&self, device: &Digest) -> Option<&GpuDevice> {
        match &self.gpus {
            GpuInventory::Devices { devices } => devices.iter().find(|gpu| gpu.device == *device),
            GpuInventory::Unavailable { .. } => None,
        }
    }
}

/// Whether an `nvidia-smi` field says the value is not available.
fn not_reported(field: &str) -> bool {
    matches!(
        field,
        "N/A" | "[N/A]" | "Not Supported" | "[Not Supported]" | "[Unknown Error]"
    )
}

fn mebibytes(field: &str) -> Option<u64> {
    field
        .parse::<u64>()
        .ok()
        .and_then(|value| value.checked_mul(MIB))
}

fn driver_version(field: &str) -> Option<String> {
    let well_formed = !field.is_empty()
        && field.len() <= 32
        && field
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
        && field
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_digit());
    well_formed.then(|| field.to_owned())
}

fn compute_capability(field: &str) -> Option<Option<String>> {
    if not_reported(field) {
        return Some(None);
    }
    let (major, minor) = field.split_once('.')?;
    let digits = |part: &str| {
        !part.is_empty() && part.len() <= 3 && part.bytes().all(|byte| byte.is_ascii_digit())
    };
    (digits(major) && digits(minor)).then(|| Some(field.to_owned()))
}

fn gpu_row(row: &str) -> Option<GpuDevice> {
    let fields: Vec<&str> = row.split(',').map(str::trim).collect();
    let [uuid, driver, compute, model, mig, total, used, free] = fields.as_slice() else {
        return None;
    };
    let total = mebibytes(total).filter(|bytes| *bytes <= MAX_GPU_BYTES)?;
    let total_bytes = NonZeroU64::new(total)?;
    let used_bytes = mebibytes(used).filter(|bytes| *bytes <= total)?;
    let free_bytes = mebibytes(free).filter(|bytes| *bytes <= total)?;
    Some(GpuDevice {
        device: device_digest(uuid)?,
        driver_version: driver_version(driver)?,
        compute_capability: compute_capability(compute)?,
        driver_model: DriverModel::parse(model)?,
        mig: MigMode::parse(mig)?,
        total_bytes,
        used_bytes,
        free_bytes,
    })
}

/// Parses the rows of `nvidia-smi --query-gpu=` [`super::collect::GPU_FIELDS`] in CSV
/// without header or units. Every row must be well formed; one bad row refuses the whole
/// inventory rather than dropping a GPU silently.
pub fn parse_gpus(csv: &str) -> Result<Vec<GpuDevice>, InventoryProblem> {
    let mut devices: Vec<GpuDevice> = Vec::new();
    for (index, row) in csv
        .lines()
        .filter(|line| !line.trim().is_empty())
        .enumerate()
    {
        if index >= MAX_GPUS {
            return Err(InventoryProblem::TooManyGpus);
        }
        let device = gpu_row(row).ok_or(InventoryProblem::MalformedGpuRow { row: index + 1 })?;
        if devices.iter().any(|seen| seen.device == device.device) {
            return Err(InventoryProblem::RepeatedGpu);
        }
        devices.push(device);
    }
    Ok(devices)
}

/// The `REG_SZ` value `name` in the output of `reg.exe query ... /v name`.
pub fn parse_registry_value<'a>(output: &'a str, name: &str) -> Option<&'a str> {
    output.lines().find_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        match fields.as_slice() {
            [found, "REG_SZ", value] if *found == name => Some(*value),
            _ => None,
        }
    })
}

/// A Windows build number or a Linux kernel release: one short printable token.
pub fn parse_os_release(text: &str) -> Result<String, InventoryProblem> {
    let text = text.trim();
    let well_formed = !text.is_empty()
        && text.len() <= 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".-_+".contains(&byte));
    if well_formed {
        Ok(text.to_owned())
    } else {
        Err(InventoryProblem::OsBuild)
    }
}
