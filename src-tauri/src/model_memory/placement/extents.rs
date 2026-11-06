//! Immutable extents resident for a slot's placements (§3.6 step 2: allocate or acquire
//! immutable extents). An extent shared by several placements, such as base weights
//! kept across an adapter update, is held by each of them and freed only when the last
//! holder is reclaimed.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::fields::GpuResidency;
use super::keys::{ExtentKey, PlacementKey, WeightPosition};
use crate::foundation::ids::GpuAllocationGeneration;

/// One extent a generation's content needs at one position.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtentSpec {
    /// Where the generation's computation reads it.
    pub position: WeightPosition,
    /// The immutable content and the device it is resident on.
    pub extent: ExtentKey,
    /// Its size on the device.
    pub bytes: u64,
}

/// An extent freed by reclamation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FreedExtent {
    pub extent: ExtentKey,
    pub bytes: u64,
    pub allocation: GpuAllocationGeneration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ResidentExtent {
    pub(super) bytes: u64,
    pub(super) allocation: GpuAllocationGeneration,
    /// Populated and verified, so computation may read it (§2.6 "usable").
    pub(super) usable: bool,
    pub(super) holders: BTreeSet<PlacementKey>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct ExtentTable {
    extents: BTreeMap<ExtentKey, ResidentExtent>,
}

/// What acquiring a resident extent found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Acquired {
    Shared,
    NotUsable,
    NotResident,
}

/// What releasing a holder did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Released {
    pub(super) freed: Vec<FreedExtent>,
    pub(super) retained: Vec<ExtentKey>,
}

impl ExtentTable {
    pub(super) fn get(&self, key: &ExtentKey) -> Option<&ResidentExtent> {
        self.extents.get(key)
    }

    pub(super) fn is_usable(&self, key: &ExtentKey) -> bool {
        self.extents.get(key).is_some_and(|extent| extent.usable)
    }

    pub(super) fn holds(&self, holder: PlacementKey, key: &ExtentKey) -> bool {
        self.extents
            .get(key)
            .is_some_and(|extent| extent.holders.contains(&holder))
    }

    /// Adds `holder` to a resident, usable extent. An extent another placement holds
    /// but never made usable, such as one a failed transfer left behind, is not shared.
    pub(super) fn acquire(&mut self, key: &ExtentKey, holder: PlacementKey) -> Acquired {
        match self.extents.get_mut(key) {
            Some(extent) if extent.usable => {
                extent.holders.insert(holder);
                Acquired::Shared
            }
            Some(_) => Acquired::NotUsable,
            None => Acquired::NotResident,
        }
    }

    /// Records a newly allocated, not yet usable extent held by `holder`.
    pub(super) fn insert_allocated(
        &mut self,
        key: ExtentKey,
        bytes: u64,
        allocation: GpuAllocationGeneration,
        holder: PlacementKey,
    ) {
        self.extents.insert(
            key,
            ResidentExtent {
                bytes,
                allocation,
                usable: false,
                holders: [holder].into_iter().collect(),
            },
        );
    }

    /// Marks an extent usable; `false` when it is not resident.
    pub(super) fn mark_usable(&mut self, key: &ExtentKey) -> bool {
        match self.extents.get_mut(key) {
            Some(extent) => {
                extent.usable = true;
                true
            }
            None => false,
        }
    }

    /// Drops every hold of `holder`. Extents left without holders are freed; the rest
    /// stay resident for their other holders.
    pub(super) fn release_holder(&mut self, holder: PlacementKey) -> Released {
        let mut released = Released::default();
        let held: Vec<ExtentKey> = self
            .extents
            .iter()
            .filter(|(_, extent)| extent.holders.contains(&holder))
            .map(|(key, _)| *key)
            .collect();
        for key in held {
            let Some(extent) = self.extents.get_mut(&key) else {
                continue;
            };
            extent.holders.remove(&holder);
            if extent.holders.is_empty() {
                if let Some(extent) = self.extents.remove(&key) {
                    released.freed.push(FreedExtent {
                        extent: key,
                        bytes: extent.bytes,
                        allocation: extent.allocation,
                    });
                }
            } else {
                released.retained.push(key);
            }
        }
        released
    }

    /// The GPU residency of `holder`.
    pub(super) fn residency_of(&self, holder: PlacementKey) -> GpuResidency {
        let mut residency = GpuResidency::default();
        for extent in self
            .extents
            .values()
            .filter(|extent| extent.holders.contains(&holder))
        {
            residency.extents += 1;
            residency.bytes = residency.bytes.saturating_add(extent.bytes);
            residency.allocations.insert(extent.allocation);
        }
        residency
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::{digest, ContentKey, GpuDeviceKey};

    fn key(name: &str) -> ExtentKey {
        ExtentKey {
            content: ContentKey::of(name.as_bytes()),
            device: GpuDeviceKey {
                machine: digest("yougori/test/machine/v1", &[b"m"]),
                device: digest("yougori/test/device/v1", &[b"gpu0"]),
            },
        }
    }

    #[test]
    fn a_shared_extent_is_freed_only_by_its_last_holder() {
        let (first, second) = (PlacementKey::new(1), PlacementKey::new(2));
        let mut table = ExtentTable::default();
        table.insert_allocated(key("base"), 100, GpuAllocationGeneration::new(1), first);
        table.insert_allocated(key("adapter-a"), 10, GpuAllocationGeneration::new(2), first);
        assert_eq!(table.acquire(&key("base"), second), Acquired::NotUsable);
        table.mark_usable(&key("base"));
        assert_eq!(table.acquire(&key("base"), second), Acquired::Shared);
        assert_eq!(
            table.acquire(&key("adapter-b"), second),
            Acquired::NotResident
        );

        let released = table.release_holder(first);
        assert_eq!(released.retained, vec![key("base")]);
        assert_eq!(
            released.freed,
            vec![FreedExtent {
                extent: key("adapter-a"),
                bytes: 10,
                allocation: GpuAllocationGeneration::new(2)
            }]
        );
        assert!(table.holds(second, &key("base")));
        assert_eq!(table.residency_of(first), GpuResidency::default());
        assert_eq!(table.residency_of(second).bytes, 100);

        let released = table.release_holder(second);
        assert_eq!(released.freed.len(), 1);
        assert!(table.get(&key("base")).is_none());
    }

    #[test]
    fn a_new_extent_is_not_usable_until_marked() {
        let mut table = ExtentTable::default();
        table.insert_allocated(
            key("layer"),
            5,
            GpuAllocationGeneration::new(1),
            PlacementKey::new(1),
        );
        assert!(!table.is_usable(&key("layer")));
        assert!(table.mark_usable(&key("layer")));
        assert!(table.is_usable(&key("layer")));
        assert!(!table.mark_usable(&key("missing")));
    }
}
