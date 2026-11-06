//! Executor configuration: bounded staging, alignment, retries, the ordinary loader and
//! the cost-model policies it uses (GPU §2.5, §2.9, §3.5).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::error::ConfigError;
use super::model::{ReadMethod, StagingPlace};
use super::ports::ReservedResource;
use crate::foundation::ids::{GpuDeviceKey, OperationId};
use crate::model_memory::math::prefetch::PrefetchBudget;
use crate::model_memory::math::sources::StealPolicy;

/// Whether the host ring is pinned or pageable. Pageable staging keeps ordinary loading
/// available where pinning is unavailable (GPU-W04).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostStagingMemory {
    Pinned,
    Pageable,
}

impl HostStagingMemory {
    /// The ledger resource the ring is reserved from.
    pub const fn resource(self) -> ReservedResource {
        match self {
            Self::Pinned => ReservedResource::PinnedHostMemory,
            Self::Pageable => ReservedResource::HostMemory,
        }
    }
}

/// The host staging ring: a fixed number of equal slots, reserved before anything
/// starts (§3.5 step 2; GPU-W04 capped staging rings).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HostStagingConfig {
    pub memory: HostStagingMemory,
    pub slots: u32,
    pub slot_bytes: u64,
}

/// One GPU's staging pool for direct paths, where bytes wait unverified (§3.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceStagingConfig {
    pub slots: u32,
    pub slot_bytes: u64,
}

/// How an executor runs.
#[derive(Clone, Debug, PartialEq)]
pub struct ExecutorConfig {
    /// The executor's own operation: its staging reservations and its own events.
    pub operation: OperationId,
    pub host_staging: HostStagingConfig,
    /// Device staging per GPU; a GPU without a pool has no direct paths.
    pub device_staging: BTreeMap<GpuDeviceKey, DeviceStagingConfig>,
    /// Read alignment for direct I/O; a power of two (GPU-W04 tail handling).
    pub alignment_bytes: u64,
    /// Attempts per extent, the first try included (§3.5: bounded retries).
    pub max_attempts: u32,
    /// The ordinary loader for local files: an ungated method (GPU-W04).
    pub local_read_method: ReadMethod,
    /// Work stealing between sources (GPU §2.5).
    pub steal_policy: StealPolicy,
    /// Speculative budget and foreground reserve (GPU §2.9), over the decoded bytes of
    /// jobs not yet released.
    pub prefetch_budget: PrefetchBudget,
}

impl ExecutorConfig {
    /// Checks the configuration against the read methods the backend implements.
    pub(super) fn validate(&self, implemented: &BTreeSet<ReadMethod>) -> Result<(), ConfigError> {
        let alignment_bytes = self.alignment_bytes;
        if !alignment_bytes.is_power_of_two() {
            return Err(ConfigError::AlignmentNotPowerOfTwo { alignment_bytes });
        }
        check_pool(
            StagingPlace::Host,
            self.host_staging.slots,
            self.host_staging.slot_bytes,
            alignment_bytes,
        )?;
        for (device, pool) in &self.device_staging {
            check_pool(
                StagingPlace::Device { device: *device },
                pool.slots,
                pool.slot_bytes,
                alignment_bytes,
            )?;
        }
        if self.max_attempts == 0 {
            return Err(ConfigError::ZeroAttempts);
        }
        let method = self.local_read_method;
        if !method.is_ordinary_local() {
            return Err(ConfigError::NotAnOrdinaryLocalMethod { method });
        }
        if !implemented.contains(&method) {
            return Err(ConfigError::MethodNotImplemented { method });
        }
        Ok(())
    }
}

/// Bytes of a pool; `None` on overflow.
pub(super) fn pool_bytes(slots: u32, slot_bytes: u64) -> Option<u64> {
    u64::from(slots).checked_mul(slot_bytes)
}

fn check_pool(
    place: StagingPlace,
    slots: u32,
    slot_bytes: u64,
    alignment_bytes: u64,
) -> Result<(), ConfigError> {
    if slots == 0 {
        return Err(ConfigError::NoSlots { place });
    }
    if slot_bytes < alignment_bytes {
        return Err(ConfigError::SlotSmallerThanAlignment {
            place,
            slot_bytes,
            alignment_bytes,
        });
    }
    if pool_bytes(slots, slot_bytes).is_none() {
        return Err(ConfigError::PoolTooLarge { place });
    }
    Ok(())
}
