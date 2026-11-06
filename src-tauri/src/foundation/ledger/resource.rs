//! What the ledger counts: resource kinds, keys and amounts (S10 line 179; CORE-03).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::foundation::evidence::GpuDeviceSubject;
use crate::foundation::ids::{Digest, GpuDeviceKey};

/// How an amount of a resource is counted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceUnit {
    Bytes,
    BytesPerSecond,
    Slots,
    Pages,
}

impl ResourceUnit {
    /// The unit in words, for messages.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Bytes => "bytes",
            Self::BytesPerSecond => "bytes per second",
            Self::Slots => "slots",
            Self::Pages => "pages",
        }
    }
}

/// A resource counted once for the whole host (S10 line 179: burst VM roots,
/// memory/snapshot pages, storage I/O, network slots and CPU initialization; INT-01: host
/// RAM and pinned staging).
///
/// Host RAM capacity and usage come from host observations in which page-cache bytes are
/// in use, not free, and a virtual address reservation supplies no capacity (GPU part
/// §2.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostResource {
    /// Host RAM, in bytes.
    Ram,
    /// Pinned (page-locked) host RAM used for staging, in bytes.
    PinnedRam,
    /// Storage quota, in bytes.
    StorageQuota,
    /// Storage I/O bandwidth, in bytes per second.
    StorageIo,
    /// Network slots, such as tap devices or forwarded ports.
    NetworkSlots,
    /// CPU initialization slots: VMs or runtimes initializing at the same time.
    CpuInitializationSlots,
    /// Burst VM roots: root filesystem clones prepared for VM starts.
    BurstVmRoots,
    /// VM memory and snapshot pages.
    SnapshotPages,
}

impl HostResource {
    /// Every host resource, in order.
    pub const ALL: [Self; 8] = [
        Self::Ram,
        Self::PinnedRam,
        Self::StorageQuota,
        Self::StorageIo,
        Self::NetworkSlots,
        Self::CpuInitializationSlots,
        Self::BurstVmRoots,
        Self::SnapshotPages,
    ];

    /// How amounts of this resource are counted.
    pub const fn unit(self) -> ResourceUnit {
        match self {
            Self::Ram | Self::PinnedRam | Self::StorageQuota => ResourceUnit::Bytes,
            Self::StorageIo => ResourceUnit::BytesPerSecond,
            Self::NetworkSlots | Self::CpuInitializationSlots | Self::BurstVmRoots => {
                ResourceUnit::Slots
            }
            Self::SnapshotPages => ResourceUnit::Pages,
        }
    }

    /// The resource in words, for messages.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ram => "host RAM",
            Self::PinnedRam => "pinned host RAM",
            Self::StorageQuota => "storage quota",
            Self::StorageIo => "storage I/O",
            Self::NetworkSlots => "network slots",
            Self::CpuInitializationSlots => "CPU initialization slots",
            Self::BurstVmRoots => "burst VM roots",
            Self::SnapshotPages => "VM memory/snapshot pages",
        }
    }
}

/// One GPU device on one machine: the shared [`GpuDeviceKey`] that capacity ledgers and
/// placement agree on (CORE-03, GPU part §2.7), as this ledger's VRAM key. It converts to
/// and from the shared key and serializes exactly as the key does. Physical capacity is
/// tracked once per device.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DeviceId(GpuDeviceKey);

impl DeviceId {
    /// The device its evidence subject names, for callers that hold the subject itself.
    pub const fn new(subject: GpuDeviceSubject) -> Self {
        Self(GpuDeviceKey {
            machine: subject.machine,
            device: subject.device,
        })
    }

    /// The device the shared key names.
    pub const fn from_key(key: GpuDeviceKey) -> Self {
        Self(key)
    }

    /// The shared key of this device.
    pub const fn key(self) -> GpuDeviceKey {
        self.0
    }

    /// Identity digest of the machine the device is on.
    pub const fn machine(self) -> Digest {
        self.0.machine
    }

    /// Identity digest of the device.
    pub const fn device(self) -> Digest {
        self.0.device
    }

    /// The evidence subject of this device.
    pub const fn subject(self) -> GpuDeviceSubject {
        GpuDeviceSubject {
            machine: self.0.machine,
            device: self.0.device,
        }
    }
}

impl From<GpuDeviceKey> for DeviceId {
    fn from(key: GpuDeviceKey) -> Self {
        Self(key)
    }
}

impl From<DeviceId> for GpuDeviceKey {
    fn from(device: DeviceId) -> Self {
        device.0
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex = self.0.device.to_hex();
        write!(f, "GPU {}", hex.get(..12).unwrap_or(&hex))
    }
}

/// Where physical capacity is tracked: once per host resource, and VRAM and model load
/// slots once per device.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKey {
    Host(HostResource),
    /// VRAM of one device, in bytes.
    Vram(DeviceId),
    /// Model loads one device runs at the same time, in slots (S10 line 351: CORE-03
    /// accounts for concurrent GPU model loads).
    GpuLoadSlots(DeviceId),
}

impl ResourceKey {
    /// The VRAM key of `device`, given as the shared key or as this ledger's device.
    pub fn vram(device: impl Into<DeviceId>) -> Self {
        Self::Vram(device.into())
    }

    /// The model load slots key of `device`, given as the shared key or as this ledger's
    /// device.
    pub fn gpu_load_slots(device: impl Into<DeviceId>) -> Self {
        Self::GpuLoadSlots(device.into())
    }

    /// How amounts of this resource are counted.
    pub const fn unit(self) -> ResourceUnit {
        match self {
            Self::Host(resource) => resource.unit(),
            Self::Vram(_) => ResourceUnit::Bytes,
            Self::GpuLoadSlots(_) => ResourceUnit::Slots,
        }
    }

    /// The device of a VRAM or model load slots key; `None` for a host resource.
    pub const fn device(self) -> Option<DeviceId> {
        match self {
            Self::Host(_) => None,
            Self::Vram(device) | Self::GpuLoadSlots(device) => Some(device),
        }
    }
}

impl fmt::Display for ResourceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Host(resource) => f.write_str(resource.name()),
            Self::Vram(device) => write!(f, "VRAM on {device}"),
            Self::GpuLoadSlots(device) => write!(f, "model load slots on {device}"),
        }
    }
}

/// Amounts per resource, each in its resource's unit. Zero amounts are not stored, so
/// equal demands compare equal; iteration follows the resource order.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(into = "Vec<AmountEntry>", try_from = "Vec<AmountEntry>")]
pub struct Amounts(BTreeMap<ResourceKey, u64>);

impl Amounts {
    /// No amounts.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds `amount` of `resource`, saturating: an overflowing demand is refused as too
    /// large, never wrapped to a small one.
    pub fn with(mut self, resource: ResourceKey, amount: u64) -> Self {
        let total = self.get(resource).saturating_add(amount);
        self.set(resource, total);
        self
    }

    /// Adds host RAM, in bytes.
    pub fn host_ram_bytes(self, bytes: u64) -> Self {
        self.with(ResourceKey::Host(HostResource::Ram), bytes)
    }

    /// Adds pinned host RAM, in bytes.
    pub fn pinned_host_ram_bytes(self, bytes: u64) -> Self {
        self.with(ResourceKey::Host(HostResource::PinnedRam), bytes)
    }

    /// Adds VRAM of `device`, given as the shared key or as this ledger's device, in
    /// bytes.
    pub fn vram_bytes(self, device: impl Into<DeviceId>, bytes: u64) -> Self {
        self.with(ResourceKey::vram(device), bytes)
    }

    /// Adds model load slots of `device`, given as the shared key or as this ledger's
    /// device.
    pub fn gpu_load_slots(self, device: impl Into<DeviceId>, slots: u64) -> Self {
        self.with(ResourceKey::gpu_load_slots(device), slots)
    }

    /// Adds storage quota, in bytes.
    pub fn storage_quota_bytes(self, bytes: u64) -> Self {
        self.with(ResourceKey::Host(HostResource::StorageQuota), bytes)
    }

    /// Adds storage I/O bandwidth, in bytes per second.
    pub fn storage_io_bytes_per_second(self, bytes_per_second: u64) -> Self {
        self.with(ResourceKey::Host(HostResource::StorageIo), bytes_per_second)
    }

    /// Adds network slots.
    pub fn network_slots(self, slots: u64) -> Self {
        self.with(ResourceKey::Host(HostResource::NetworkSlots), slots)
    }

    /// Adds CPU initialization slots.
    pub fn cpu_initialization_slots(self, slots: u64) -> Self {
        self.with(
            ResourceKey::Host(HostResource::CpuInitializationSlots),
            slots,
        )
    }

    /// Adds burst VM roots.
    pub fn burst_vm_roots(self, roots: u64) -> Self {
        self.with(ResourceKey::Host(HostResource::BurstVmRoots), roots)
    }

    /// Adds VM memory/snapshot pages.
    pub fn snapshot_pages(self, pages: u64) -> Self {
        self.with(ResourceKey::Host(HostResource::SnapshotPages), pages)
    }

    /// The amount of `resource`; zero when absent.
    pub fn get(&self, resource: ResourceKey) -> u64 {
        self.0.get(&resource).copied().unwrap_or(0)
    }

    /// Whether every amount is zero.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// How many resources have a non-zero amount.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Each resource with its amount, in resource order.
    pub fn iter(&self) -> impl Iterator<Item = (ResourceKey, u64)> + '_ {
        self.0.iter().map(|(resource, amount)| (*resource, *amount))
    }

    /// Each resource with a non-zero amount, in order.
    pub fn resources(&self) -> impl Iterator<Item = ResourceKey> + '_ {
        self.0.keys().copied()
    }

    /// Whether any amount is of one of `resources`.
    pub fn touches(&self, resources: &BTreeSet<ResourceKey>) -> bool {
        self.0.keys().any(|resource| resources.contains(resource))
    }

    /// What `self` holds beyond `other`, per resource.
    pub fn excess_over(&self, other: &Amounts) -> Amounts {
        let mut excess = Amounts::new();
        for (resource, amount) in self.iter() {
            excess.set(resource, amount.saturating_sub(other.get(resource)));
        }
        excess
    }

    pub(super) fn set(&mut self, resource: ResourceKey, amount: u64) {
        if amount == 0 {
            self.0.remove(&resource);
        } else {
            self.0.insert(resource, amount);
        }
    }
}

/// One amount in the serialized form of [`Amounts`], a list because JSON object keys are
/// strings only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AmountEntry {
    pub resource: ResourceKey,
    pub amount: u64,
}

impl From<Amounts> for Vec<AmountEntry> {
    fn from(amounts: Amounts) -> Self {
        amounts
            .iter()
            .map(|(resource, amount)| AmountEntry { resource, amount })
            .collect()
    }
}

/// Why a serialized amount list was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AmountsError {
    Zero { resource: ResourceKey },
    Repeated { resource: ResourceKey },
}

impl fmt::Display for AmountsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zero { resource } => write!(f, "the amount of {resource} is zero"),
            Self::Repeated { resource } => write!(f, "{resource} appears twice"),
        }
    }
}

impl std::error::Error for AmountsError {}

impl TryFrom<Vec<AmountEntry>> for Amounts {
    type Error = AmountsError;

    fn try_from(entries: Vec<AmountEntry>) -> Result<Self, Self::Error> {
        let mut amounts = Amounts::new();
        for AmountEntry { resource, amount } in entries {
            if amount == 0 {
                return Err(AmountsError::Zero { resource });
            }
            if amounts.0.insert(resource, amount).is_some() {
                return Err(AmountsError::Repeated { resource });
            }
        }
        Ok(amounts)
    }
}
