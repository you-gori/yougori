//! The GPU tier (table line 539): immutable weights and separate mutable KV, scratch and
//! graph resources on one device.
//!
//! Accounting counts physical allocations and the references that keep them alive, not
//! mapped bytes (§2.7 line 444: physically shared weights count once; GPU-W05 line 1056:
//! reference lifetimes across mappings, graphs and imports). Each physical allocation is
//! reserved once in the CORE-03 ledger, which keeps the device's capacity; mapping it
//! again or referencing it reserves nothing more. It is freed only once nothing maps or
//! references it, and its handle is stale from then on.
//!
//! Weights come only through a catalog read handle, which a consumer gets only for an
//! object it may read and which offers no way to write (line 546, T05); they are never
//! written afterwards. References and device-to-device copies stay within the owner's
//! tenant and trust scope: sharing processed weights or KV needs an explicitly compatible
//! trust domain (S3.3), which this tier does not assume.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use super::charge::{release, reserve_and_create, Charged, LedgerCharge, Released};
use super::object::{Consumer, ObjectCopy, ObjectRef};
use super::source::{OfferRefusal, SourceOffer, SourcePath, TierRefusal};
use super::Tier;
use crate::foundation::catalog::{Catalog, ObjectId, ReadHandle, ReadRefusal};
use crate::foundation::ids::{
    Clock, Digest, DigestBuilder, GpuAllocationGeneration, GpuDeviceKey, OperationId,
};
use crate::foundation::ledger::{Amounts, CostPurpose, Ledger, LedgerError, ReservationId};
use crate::model_memory::math::SourceId;
use crate::model_memory::residency::eviction::{
    eviction_action, Content, ContentState, EvictionAction, GpuCopy, ReconstructibleCopy, WriteBack,
};
use crate::model_memory::residency::reservation::vram_resource;
use crate::model_memory::residency::vram::{ImmutableAllocation, ImmutableKind};
use crate::model_memory::residency::Interval;

/// Domain of the marker naming one mutable allocation's state for eviction decisions.
const STATE_DOMAIN: &str = "yougori/model-memory/tiers/gpu-state/v1";

/// Mutable state, each kind in allocations of its own (table line 539).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MutableState {
    KvCache,
    Scratch,
    GraphResources { graph: Digest },
}

/// What one physical allocation holds. Each allocation holds one kind, so immutable
/// weights never share an allocation with mutable state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GpuContent {
    /// Immutable weights of a published catalog object, loaded through a read handle.
    ImmutableWeights {
        object: ObjectRef,
    },
    Mutable(MutableState),
}

impl GpuContent {
    pub fn is_mutable(&self) -> bool {
        matches!(self, Self::Mutable(_))
    }

    /// Whether these are the immutable weights of exactly `object`: its scope, class and
    /// content, so equal content of another scope is another object.
    pub fn holds_weights_of(&self, object: &ObjectRef) -> bool {
        matches!(self, Self::ImmutableWeights { object: held } if held == object)
    }
}

/// What keeps a physical allocation alive (GPU-W05 line 1056).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReferenceHolder {
    /// A consumer's execution using the allocation.
    Execution(Consumer),
    /// A captured graph that names the allocation.
    Graph { owner: Consumer, graph: Digest },
    /// An import or load reading or writing it.
    Import {
        importer: Consumer,
        operation: OperationId,
    },
}

impl ReferenceHolder {
    /// The consumer the reference belongs to.
    pub fn consumer(&self) -> &Consumer {
        match self {
            Self::Execution(consumer) => consumer,
            Self::Graph { owner, .. } => owner,
            Self::Import { importer, .. } => importer,
        }
    }
}

/// Names one allocation by its generation (S3.1). Generations are never reused, so a
/// handle to a freed allocation stays recognisably stale.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AllocationHandle {
    generation: GpuAllocationGeneration,
}

impl AllocationHandle {
    pub fn generation(&self) -> GpuAllocationGeneration {
        self.generation
    }
}

/// One virtual mapping of an allocation; never reused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MappingId(u64);

/// Why the GPU tier refused (table line 539).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GpuRefusal {
    ZeroBytes,
    /// The ledger refused the physical bytes: the device's capacity, the tenant's budget
    /// or the runtime's reservation (CORE-03).
    Ledger(LedgerError),
    /// The read handle is for another object than the one named.
    HandleMismatch {
        named: ObjectId,
        handle: ObjectId,
    },
    /// The catalog does not let the owner read the object: it is another scope's and no
    /// grant names exactly it and the owner's execution (line 546; S3.3). A read handle
    /// does not record who opened it, so the owner is checked itself.
    Unreadable(ReadRefusal),
    GenerationsExhausted,
    MappingsExhausted,
    /// The allocation was freed or never existed.
    StaleHandle {
        generation: GpuAllocationGeneration,
    },
    /// A mapping cannot be larger than the physical allocation behind it.
    MappingExceedsAllocation {
        mapped_bytes: u64,
        physical_bytes: u64,
    },
    UnknownMapping {
        mapping: MappingId,
    },
    /// The holder runs outside the owner's tenant or trust scope (S3.3).
    OutsideScope {
        holder: Box<Consumer>,
        owner: Box<Consumer>,
    },
    DuplicateReference,
    UnknownReference,
    /// Freeing would release memory that something still references.
    StillReferenced {
        references: usize,
    },
    /// Freeing would leave mappings over released memory.
    StillMapped {
        mappings: usize,
    },
    /// No allocation holds the object's weights.
    NotResident {
        object: ObjectRef,
    },
}

impl fmt::Display for GpuRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroBytes => f.write_str("an allocation or mapping has at least one byte"),
            Self::Ledger(error) => error.fmt(f),
            Self::HandleMismatch { named, handle } => write!(
                f,
                "the read handle is for object {handle}, not the named object {named}"
            ),
            Self::Unreadable(refusal) => write!(f, "the owner may not read the object: {refusal}"),
            Self::GenerationsExhausted => f.write_str("no allocation generation is left"),
            Self::MappingsExhausted => f.write_str("no mapping identifier is left"),
            Self::StaleHandle { generation } => {
                write!(f, "allocation generation {generation} is not live")
            }
            Self::MappingExceedsAllocation {
                mapped_bytes,
                physical_bytes,
            } => write!(
                f,
                "a {mapped_bytes}-byte mapping exceeds its {physical_bytes}-byte allocation"
            ),
            Self::UnknownMapping { mapping } => write!(f, "mapping {} is unknown", mapping.0),
            Self::OutsideScope { holder, owner } => write!(
                f,
                "{} may not reference memory of {}: sharing needs the same tenant and trust \
                 scope",
                holder.execution, owner.execution
            ),
            Self::DuplicateReference => f.write_str("the holder already references it"),
            Self::UnknownReference => f.write_str("the holder does not reference it"),
            Self::StillReferenced { references } => {
                write!(f, "{references} references still hold the allocation")
            }
            Self::StillMapped { mappings } => {
                write!(f, "{mappings} mappings still cover the allocation")
            }
            Self::NotResident { object } => write!(f, "no allocation holds {object}"),
        }
    }
}

impl std::error::Error for GpuRefusal {}

impl From<LedgerError> for GpuRefusal {
    fn from(error: LedgerError) -> Self {
        Self::Ledger(error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Allocation {
    owner: Consumer,
    content: GpuContent,
    physical_bytes: u64,
    reservation: ReservationId,
    mappings: BTreeMap<MappingId, u64>,
    references: BTreeSet<ReferenceHolder>,
}

/// One device's GPU tier (table line 539).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GpuTier {
    device: GpuDeviceKey,
    runtime: Option<ReservationId>,
    last_generation: Option<GpuAllocationGeneration>,
    next_mapping: u64,
    allocations: BTreeMap<GpuAllocationGeneration, Allocation>,
}

impl GpuTier {
    /// `runtime` is the runtime's own VRAM reservation that allocations are carved from
    /// (S3.2); `None` reserves each allocation at host level.
    pub fn new(device: GpuDeviceKey, runtime: Option<ReservationId>) -> Self {
        Self {
            device,
            runtime,
            last_generation: None,
            next_mapping: 0,
            allocations: BTreeMap::new(),
        }
    }

    pub fn device(&self) -> GpuDeviceKey {
        self.device
    }

    /// Physical bytes allocated, each allocation counted once however many mappings and
    /// references it has.
    pub fn physical_bytes(&self) -> u64 {
        self.allocations.values().fold(0u64, |total, allocation| {
            total.saturating_add(allocation.physical_bytes)
        })
    }

    /// Bytes covered by mappings: reported, never reserved or counted as capacity.
    pub fn mapped_bytes(&self) -> u64 {
        self.allocations
            .values()
            .flat_map(|allocation| allocation.mappings.values())
            .fold(0u64, |total, bytes| total.saturating_add(*bytes))
    }

    pub fn content(&self, handle: AllocationHandle) -> Result<&GpuContent, GpuRefusal> {
        Ok(&self.live(handle)?.content)
    }

    pub fn owner(&self, handle: AllocationHandle) -> Result<&Consumer, GpuRefusal> {
        Ok(&self.live(handle)?.owner)
    }

    pub fn references(&self, handle: AllocationHandle) -> Result<usize, GpuRefusal> {
        Ok(self.live(handle)?.references.len())
    }

    /// The ledger reservation holding the allocation's physical bytes.
    pub fn reservation(&self, handle: AllocationHandle) -> Result<ReservationId, GpuRefusal> {
        Ok(self.live(handle)?.reservation)
    }

    /// Loads immutable weights of `object` for `owner`, read through `handle`, into a new
    /// physical allocation reserved in the ledger first. The handle must be for exactly
    /// that object, and the catalog must let the owner itself read it: its own scope's, or
    /// another's under a live grant for that object and execution (line 546).
    #[allow(clippy::too_many_arguments)]
    pub fn load_weights<C: Clock>(
        &mut self,
        owner: &Consumer,
        object: &ObjectRef,
        handle: &ReadHandle,
        catalog: &Catalog,
        physical_bytes: u64,
        charge: &LedgerCharge,
        ledger: &mut Ledger<C>,
    ) -> Result<AllocationHandle, GpuRefusal> {
        if handle.object() != object.id() {
            return Err(GpuRefusal::HandleMismatch {
                named: object.id(),
                handle: handle.object(),
            });
        }
        catalog
            .object_view(&owner.scope(), &owner.execution, object.id())
            .map_err(GpuRefusal::Unreadable)?;
        self.allocate(
            owner,
            GpuContent::ImmutableWeights {
                object: object.clone(),
            },
            physical_bytes,
            charge,
            ledger,
        )
    }

    /// Allocates mutable state for one consumer, reserved in the ledger first.
    pub fn allocate_state<C: Clock>(
        &mut self,
        owner: &Consumer,
        state: MutableState,
        physical_bytes: u64,
        charge: &LedgerCharge,
        ledger: &mut Ledger<C>,
    ) -> Result<AllocationHandle, GpuRefusal> {
        self.allocate(
            owner,
            GpuContent::Mutable(state),
            physical_bytes,
            charge,
            ledger,
        )
    }

    /// Maps the allocation again; reserves nothing.
    pub fn map(
        &mut self,
        handle: AllocationHandle,
        mapped_bytes: u64,
    ) -> Result<MappingId, GpuRefusal> {
        if mapped_bytes == 0 {
            return Err(GpuRefusal::ZeroBytes);
        }
        let mapping = MappingId(self.next_mapping);
        let next_mapping = self
            .next_mapping
            .checked_add(1)
            .ok_or(GpuRefusal::MappingsExhausted)?;
        let allocation = self.live_mut(handle)?;
        if mapped_bytes > allocation.physical_bytes {
            return Err(GpuRefusal::MappingExceedsAllocation {
                mapped_bytes,
                physical_bytes: allocation.physical_bytes,
            });
        }
        allocation.mappings.insert(mapping, mapped_bytes);
        self.next_mapping = next_mapping;
        Ok(mapping)
    }

    pub fn unmap(
        &mut self,
        handle: AllocationHandle,
        mapping: MappingId,
    ) -> Result<(), GpuRefusal> {
        self.live_mut(handle)?
            .mappings
            .remove(&mapping)
            .map(|_| ())
            .ok_or(GpuRefusal::UnknownMapping { mapping })
    }

    /// Records a holder keeping the allocation alive; refused outside the owner's tenant
    /// and trust scope (S3.3).
    pub fn add_reference(
        &mut self,
        handle: AllocationHandle,
        holder: ReferenceHolder,
    ) -> Result<(), GpuRefusal> {
        let allocation = self.live_mut(handle)?;
        let consumer = holder.consumer();
        if !allocation.owner.shares_trust_with(consumer) {
            return Err(GpuRefusal::OutsideScope {
                holder: Box::new(consumer.clone()),
                owner: Box::new(allocation.owner.clone()),
            });
        }
        if !allocation.references.insert(holder) {
            return Err(GpuRefusal::DuplicateReference);
        }
        Ok(())
    }

    pub fn drop_reference(
        &mut self,
        handle: AllocationHandle,
        holder: &ReferenceHolder,
    ) -> Result<(), GpuRefusal> {
        if self.live_mut(handle)?.references.remove(holder) {
            Ok(())
        } else {
            Err(GpuRefusal::UnknownReference)
        }
    }

    /// Frees the physical memory once nothing references or maps it, and gives its
    /// reservation back to the ledger. The handle is stale afterwards.
    pub fn free<C: Clock>(
        &mut self,
        handle: AllocationHandle,
        ledger: &mut Ledger<C>,
    ) -> Result<Released, GpuRefusal> {
        let allocation = self.live(handle)?;
        if !allocation.references.is_empty() {
            return Err(GpuRefusal::StillReferenced {
                references: allocation.references.len(),
            });
        }
        if !allocation.mappings.is_empty() {
            return Err(GpuRefusal::StillMapped {
                mappings: allocation.mappings.len(),
            });
        }
        let released = release(ledger, allocation.reservation, allocation.physical_bytes)?;
        self.allocations.remove(&handle.generation);
        Ok(released)
    }

    /// The name of an allocation in a VRAM admission plan: its device and generation.
    pub fn allocation_key(&self, handle: AllocationHandle) -> String {
        format!("{}/{}", self.device.device, handle.generation)
    }

    /// The tier's immutable weights as the physical allocations of a §2.7 VRAM plan
    /// (T08 `residency::vram`): one per physical allocation however many references it
    /// has, shareable only within its owner's trust scope.
    pub fn immutable_allocations(&self, resident: Interval) -> Vec<ImmutableAllocation> {
        self.allocations
            .iter()
            .filter(|(_, allocation)| !allocation.content.is_mutable())
            .map(|(generation, allocation)| ImmutableAllocation {
                key: self.allocation_key(AllocationHandle {
                    generation: *generation,
                }),
                kind: ImmutableKind::Weights,
                bytes: allocation.physical_bytes,
                sharing_domain: allocation.owner.trust,
                resident,
            })
            .collect()
    }

    /// How the allocation may be evicted (T08 `residency::eviction`, line 307): clean
    /// weights are dropped only when one of `copies`, which the other tiers report,
    /// verifiably reconstructs them. Only copies of the same object count, so equal
    /// content of another scope never does, and a copy in a runtime's memory counts only
    /// in the owner's tenant and trust scope (S3.3). Mutable state is written back or
    /// retained.
    pub fn eviction_action(
        &self,
        handle: AllocationHandle,
        copies: &[ObjectCopy],
        write_back: WriteBack,
    ) -> Result<EvictionAction, GpuRefusal> {
        let allocation = self.live(handle)?;
        let (copy, same_object) = match &allocation.content {
            GpuContent::ImmutableWeights { object } => (
                GpuCopy {
                    content: Content::Immutable(object.content),
                    state: ContentState::Clean,
                    bytes: allocation.physical_bytes,
                },
                copies
                    .iter()
                    .filter(|held| held.may_rebuild(object, &allocation.owner))
                    .map(|held| held.copy)
                    .collect::<Vec<ReconstructibleCopy>>(),
            ),
            GpuContent::Mutable(_) => (
                GpuCopy {
                    content: Content::SessionState(
                        DigestBuilder::new(STATE_DOMAIN)
                            .digest(&self.device.device)
                            .u64(handle.generation.get())
                            .finish(),
                    ),
                    state: ContentState::Dirty,
                    bytes: allocation.physical_bytes,
                },
                Vec::new(),
            ),
        };
        Ok(eviction_action(&copy, &same_object, write_back))
    }

    /// Allocations holding the weights of exactly this object (scope, class and content).
    pub fn resident(&self, object: &ObjectRef) -> Vec<AllocationHandle> {
        self.allocations
            .iter()
            .filter(|(_, allocation)| allocation.content.holds_weights_of(object))
            .map(|(generation, _)| AllocationHandle {
                generation: *generation,
            })
            .collect()
    }

    /// Offers resident weights as a source for a device-to-device copy to `requester`,
    /// from an allocation whose owner shares the requester's tenant and trust scope
    /// (S3.3). The offer is for that requester only.
    pub fn offer(
        &self,
        source: SourceId,
        object: &ObjectRef,
        requester: &Consumer,
        path: SourcePath,
    ) -> Result<SourceOffer, OfferRefusal> {
        let refuse = |refusal| OfferRefusal::new(&source, Tier::Gpu, TierRefusal::Gpu(refusal));
        let resident: Vec<&Allocation> = self
            .resident(object)
            .iter()
            .filter_map(|handle| self.allocations.get(&handle.generation))
            .collect();
        let Some(first) = resident.first() else {
            return Err(refuse(GpuRefusal::NotResident {
                object: object.clone(),
            }));
        };
        let Some(allocation) = resident
            .iter()
            .find(|allocation| allocation.owner.shares_trust_with(requester))
        else {
            return Err(refuse(GpuRefusal::OutsideScope {
                holder: Box::new(requester.clone()),
                owner: Box::new(first.owner.clone()),
            }));
        };
        let covers_bytes = allocation.physical_bytes;
        Ok(SourceOffer::new(
            Tier::Gpu,
            source,
            object.clone(),
            requester,
            path,
            covers_bytes,
        ))
    }

    fn allocate<C: Clock>(
        &mut self,
        owner: &Consumer,
        content: GpuContent,
        physical_bytes: u64,
        charge: &LedgerCharge,
        ledger: &mut Ledger<C>,
    ) -> Result<AllocationHandle, GpuRefusal> {
        if physical_bytes == 0 {
            return Err(GpuRefusal::ZeroBytes);
        }
        let generation = match self.last_generation {
            None => GpuAllocationGeneration::FIRST,
            Some(last) => last.next().ok_or(GpuRefusal::GenerationsExhausted)?,
        };
        let reservation = reserve_and_create(
            ledger,
            charge,
            Charged {
                tenant: &owner.tenant,
                execution: &owner.execution,
                purpose: CostPurpose::Compute,
                parent: self.runtime,
            },
            Amounts::new().with(vram_resource(self.device), physical_bytes),
        )?;
        self.last_generation = Some(generation);
        self.allocations.insert(
            generation,
            Allocation {
                owner: owner.clone(),
                content,
                physical_bytes,
                reservation,
                mappings: BTreeMap::new(),
                references: BTreeSet::new(),
            },
        );
        Ok(AllocationHandle { generation })
    }

    fn live(&self, handle: AllocationHandle) -> Result<&Allocation, GpuRefusal> {
        self.allocations
            .get(&handle.generation)
            .ok_or(GpuRefusal::StaleHandle {
                generation: handle.generation,
            })
    }

    fn live_mut(&mut self, handle: AllocationHandle) -> Result<&mut Allocation, GpuRefusal> {
        self.allocations
            .get_mut(&handle.generation)
            .ok_or(GpuRefusal::StaleHandle {
                generation: handle.generation,
            })
    }
}

#[cfg(test)]
mod tests;
