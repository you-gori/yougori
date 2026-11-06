//! The narrow, versioned ABI for native operations (GPU §3.1, line 489).
//!
//! Native operations are kept behind this ABI when upstream libraries cannot supply
//! them. The set is closed: a new operation is a new variant and a new version, never a
//! dynamically loaded plugin (line 489: "ordinary modules and explicit contracts, not a
//! dynamic plugin ecosystem"). A runner adapter declares the version it was built
//! against and the operations it calls; any version difference is refused.
//!
//! Driver and allocation work runs inside the device-owning runtime (line 491), so raw
//! handles live only there. [`NativeHandle`] has no serde, no `Display` and a redacting
//! `Debug`, and no boundary signature outside the runner carries one: the API, CLI and UI
//! adapter can never receive a raw GPU handle (§3.1 row 5).

use std::collections::BTreeSet;
use std::fmt;

use serde::Serialize;

use super::runner::RunnerAdapter;
use crate::foundation::ids::GpuAllocationGeneration;

/// Version of the native-operation ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct NativeAbiVersion {
    pub major: u16,
    pub minor: u16,
}

impl fmt::Display for NativeAbiVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// The ABI version this build provides.
pub const NATIVE_ABI_VERSION: NativeAbiVersion = NativeAbiVersion { major: 1, minor: 0 };

/// The closed set of native operations: the driver steps of GPU §3.5 (asynchronous copies
/// and completion events) and §3.7 (virtual memory and allocation lifetime).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeOperation {
    QueryAllocationGranularity,
    ReserveAddressRange,
    CreatePhysicalAllocation,
    MapAllocation,
    SetAccess,
    /// Unmapping is valid only after quiescence (§3.7).
    UnmapAfterQuiescence,
    ReleasePhysicalAllocation,
    CopyToDeviceAsync,
    RecordCompletionEvent,
    QueryCompletionEvent,
}

impl NativeOperation {
    pub const ALL: [Self; 10] = [
        Self::QueryAllocationGranularity,
        Self::ReserveAddressRange,
        Self::CreatePhysicalAllocation,
        Self::MapAllocation,
        Self::SetAccess,
        Self::UnmapAfterQuiescence,
        Self::ReleasePhysicalAllocation,
        Self::CopyToDeviceAsync,
        Self::RecordCompletionEvent,
        Self::QueryCompletionEvent,
    ];
}

/// What one runner adapter declares: the ABI version it was built against and the
/// native operations it calls. An adapter that uses only upstream facilities declares an
/// empty set, but still declares its version.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AbiDeclaration {
    pub version: NativeAbiVersion,
    pub operations: BTreeSet<NativeOperation>,
}

/// The host side of the ABI: its version and the operations it provides on this machine.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NativeAbi {
    version: NativeAbiVersion,
    provided: BTreeSet<NativeOperation>,
}

/// Why a runner adapter's ABI declaration was refused (line 489).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum AbiRefusal {
    /// The declared version is not exactly the provided one.
    VersionMismatch {
        provided: NativeAbiVersion,
        declared: NativeAbiVersion,
    },
    /// The adapter calls an operation this host's ABI does not provide.
    OperationNotProvided {
        version: NativeAbiVersion,
        operation: NativeOperation,
    },
}

impl fmt::Display for AbiRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VersionMismatch { provided, declared } => write!(
                f,
                "the runner adapter was built for native ABI {declared}; this host provides {provided}"
            ),
            Self::OperationNotProvided { version, operation } => write!(
                f,
                "native ABI {version} on this host does not provide {operation:?}"
            ),
        }
    }
}

impl std::error::Error for AbiRefusal {}

impl NativeAbi {
    /// This build's ABI with every operation.
    pub fn current() -> Self {
        Self::new(
            NATIVE_ABI_VERSION,
            NativeOperation::ALL.into_iter().collect(),
        )
    }

    /// An ABI that provides only some operations, as on a platform without CUDA virtual
    /// memory management.
    pub fn new(version: NativeAbiVersion, provided: BTreeSet<NativeOperation>) -> Self {
        Self { version, provided }
    }

    pub fn version(&self) -> NativeAbiVersion {
        self.version
    }

    pub fn provided(&self) -> &BTreeSet<NativeOperation> {
        &self.provided
    }

    /// The version must equal this ABI's exactly, and every declared operation must be
    /// provided.
    pub fn check(&self, declared: &AbiDeclaration) -> Result<(), AbiRefusal> {
        if declared.version != self.version {
            return Err(AbiRefusal::VersionMismatch {
                provided: self.version,
                declared: declared.version,
            });
        }
        match declared
            .operations
            .iter()
            .find(|operation| !self.provided.contains(operation))
        {
            Some(operation) => Err(AbiRefusal::OperationNotProvided {
                version: self.version,
                operation: *operation,
            }),
            None => Ok(()),
        }
    }

    /// Checks a runner adapter's declaration. Only a [`CheckedRunner`] reaches the flow,
    /// so a refused adapter is never routed to.
    pub fn admit<'r>(
        &self,
        runner: &'r mut dyn RunnerAdapter,
    ) -> Result<CheckedRunner<'r>, AbiRefusal> {
        let declared = runner.profile().abi;
        self.check(&declared)?;
        Ok(CheckedRunner {
            runner,
            version: declared.version,
        })
    }
}

/// A runner adapter whose ABI declaration was accepted.
pub struct CheckedRunner<'r> {
    runner: &'r mut dyn RunnerAdapter,
    version: NativeAbiVersion,
}

impl<'r> CheckedRunner<'r> {
    pub fn runner(&self) -> &dyn RunnerAdapter {
        &*self.runner
    }

    pub(super) fn runner_mut(&mut self) -> &mut dyn RunnerAdapter {
        &mut *self.runner
    }

    pub fn version(&self) -> NativeAbiVersion {
        self.version
    }
}

/// What a raw native handle refers to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NativeHandleKind {
    DevicePointer,
    AddressRange,
    PhysicalAllocation,
    /// An exportable or imported inter-process handle.
    IpcHandle,
    Stream,
    Event,
    Graph,
}

/// A raw handle inside the device-owning runtime: a device pointer, an allocation, an IPC
/// handle, a stream, an event or a captured graph. It belongs to one GPU allocation
/// generation, so a handle from an older allocation is recognisably stale. It is neither
/// serializable nor displayable (§3.10: no raw device pointers in public output or
/// persisted state), and its `Debug` form hides the raw value.
#[derive(PartialEq, Eq)]
pub struct NativeHandle {
    kind: NativeHandleKind,
    raw: u64,
    allocation: GpuAllocationGeneration,
}

impl NativeHandle {
    pub fn new(kind: NativeHandleKind, raw: u64, allocation: GpuAllocationGeneration) -> Self {
        Self {
            kind,
            raw,
            allocation,
        }
    }

    pub fn kind(&self) -> NativeHandleKind {
        self.kind
    }

    pub fn allocation(&self) -> GpuAllocationGeneration {
        self.allocation
    }

    /// The raw value, for the native operation layer inside the device-owning runtime.
    pub fn raw(&self) -> u64 {
        self.raw
    }
}

impl fmt::Debug for NativeHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeHandle")
            .field("kind", &self.kind)
            .field("allocation", &self.allocation)
            .field("raw", &"<redacted>")
            .finish()
    }
}
