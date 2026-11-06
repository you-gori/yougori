//! The model's state and the mapping protocol (GPU part §3.7; Appendix E steps 1–6 and
//! 9): reserve, create, map, set access, populate, and publish only after completion and
//! verification; park only when quiescent; wake at the same offsets.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use serde::Serialize;

use super::canonical::{CanonicalSource, VerifiedCanonicalCopy};
use super::driver::{DriverError, VmmDriver};
use super::error::{NotCallableReason, VmmError};
use super::evidence::{
    evidenced_granularity, DriverGranularityReport, Granularity, GranularityRefusal,
    GranularityResult, ProcessContext,
};
use super::graph::{CapturedGraph, Workspace};
use super::ledger::{
    AllocationContents, AllocationKind, DriverHandle, HandleEntry, PhysicalEntry, PhysicalInfo,
    ReferenceCount,
};
use super::sharing::ExportRecord;
use super::types::{
    AddressRange, AllocationProperties, ArtifactLayout, BatchSpec, BatchState, DeviceOrdinal,
    EventId, ExportId, GraphId, Lifecycle, MappingKey, ParkSource, PhysicalHandle, PhysicalId,
    ProcessId, StreamId, ViewId, VirtualAddress, WorkKind, WorkspaceId,
};
use crate::foundation::catalog::Catalog;
use crate::foundation::evidence::{
    ConfigurationFingerprint, EvidenceRefusal, LoaderPlan, Optimization, ProbeRegistry,
};
use crate::foundation::ids::{Clock, ContentKey, Digest, GpuAllocationGeneration, MonotonicTime};

/// How a VMM reservation gets its physical memory (Appendix E steps 3 and 7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VmmOrigin {
    /// This process creates each batch's allocation (`cuMemCreate`).
    Create,
    /// This process imports each batch from another process's export
    /// (`cuMemImportFromShareableHandle`) into its own reservation.
    Import,
}

/// How one artifact is held in one process.
#[derive(Clone, Copy, Debug)]
pub(super) enum Backing {
    /// A reservation kept for the process lifetime, with one allocation per batch
    /// (Appendix E steps 2–7).
    Vmm {
        properties: AllocationProperties,
        granularity: Granularity,
        reservation: AddressRange,
        origin: VmmOrigin,
    },
    /// One backend allocation in a private pool, without pointer stability (step 9).
    Pool { expandable_segments: bool },
    /// One dedicated `cudaMalloc` allocation for legacy IPC (step 8).
    Legacy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SlotState {
    Empty,
    Ready(PhysicalId),
    Populating(PhysicalId, EventId),
    Rejected(PhysicalId),
    Published(PhysicalId),
}

impl SlotState {
    pub(super) fn physical(self) -> Option<PhysicalId> {
        match self {
            Self::Empty => None,
            Self::Ready(physical)
            | Self::Populating(physical, _)
            | Self::Rejected(physical)
            | Self::Published(physical) => Some(physical),
        }
    }

    pub(super) fn public(self) -> BatchState {
        match self {
            Self::Empty => BatchState::Empty,
            Self::Ready(_) => BatchState::Ready,
            Self::Populating(..) => BatchState::Populating,
            Self::Rejected(_) => BatchState::Rejected,
            Self::Published(_) => BatchState::Published,
        }
    }
}

/// One batch: a VMM batch, or the single allocation of a pool or legacy artifact.
#[derive(Clone, Copy, Debug)]
pub(super) struct Slot {
    pub(super) offset_bytes: u64,
    pub(super) length_bytes: u64,
    /// The length rounded up to the granularity: the size of the batch's allocation.
    pub(super) allocation_bytes: u64,
    pub(super) digest: Digest,
    /// The generation of the latest physical memory behind the slot.
    pub(super) generation: Option<GpuAllocationGeneration>,
    /// Where the slot starts; `None` for a pool or legacy slot without memory.
    pub(super) address: Option<VirtualAddress>,
    pub(super) state: SlotState,
}

#[derive(Debug)]
pub(super) struct Artifact {
    pub(super) length_bytes: u64,
    /// The content key of the artifact's bytes; a clean-drop park needs a verified
    /// canonical copy of exactly this content.
    pub(super) content: ContentKey,
    pub(super) backing: Backing,
    pub(super) lifecycle: Lifecycle,
    pub(super) device_to_host_bytes: u64,
    pub(super) slots: Vec<Slot>,
    /// The catalog proof of the last clean drop, holding its lease until the artifact is
    /// refilled.
    pub(super) canonical: Option<VerifiedCanonicalCopy>,
}

impl Artifact {
    pub(super) fn require(&self, key: MappingKey, expected: Lifecycle) -> Result<(), VmmError> {
        if self.lifecycle == expected {
            Ok(())
        } else {
            Err(VmmError::NotInLifecycle {
                key,
                expected,
                found: self.lifecycle,
            })
        }
    }

    pub(super) fn slot(&self, key: MappingKey, batch: u32) -> Result<Slot, VmmError> {
        usize::try_from(batch)
            .ok()
            .and_then(|index| self.slots.get(index))
            .copied()
            .ok_or(VmmError::UnknownBatch { key, batch })
    }

    /// The end of `[offset, offset + length)` after checking it lies in the artifact.
    pub(super) fn check_range(
        &self,
        key: MappingKey,
        offset_bytes: u64,
        length_bytes: u64,
    ) -> Result<u64, VmmError> {
        offset_bytes
            .checked_add(length_bytes)
            .filter(|end| length_bytes > 0 && *end <= self.length_bytes)
            .ok_or(VmmError::ViewOutOfRange {
                key,
                offset_bytes,
                length_bytes,
                artifact_bytes: self.length_bytes,
            })
    }

    /// The batches holding bytes of `[offset, end)`, with their numbers.
    pub(super) fn covered(&self, offset_bytes: u64, end_bytes: u64) -> Vec<(u32, Slot)> {
        self.slots
            .iter()
            .zip(0u32..)
            .filter(|(slot, _)| {
                slot.offset_bytes < end_bytes
                    && offset_bytes < slot.offset_bytes.saturating_add(slot.length_bytes)
            })
            .map(|(slot, batch)| (batch, *slot))
            .collect()
    }

    /// Why work over `[offset, end)` cannot run now, if it cannot: only published batches
    /// of an active artifact are callable (§3.7).
    pub(super) fn not_callable(
        &self,
        offset_bytes: u64,
        end_bytes: u64,
    ) -> Option<NotCallableReason> {
        match self.lifecycle {
            Lifecycle::Active => {}
            Lifecycle::Draining => return Some(NotCallableReason::Draining),
            Lifecycle::Parked => return Some(NotCallableReason::Parked),
        }
        self.covered(offset_bytes, end_bytes)
            .into_iter()
            .find_map(|(batch, slot)| match slot.state {
                SlotState::Published(_) => None,
                SlotState::Empty => Some(NotCallableReason::Unmapped { batch }),
                _ => Some(NotCallableReason::NotPublished { batch }),
            })
    }
}

/// What a view is bound to.
#[derive(Clone, Copy, Debug)]
pub(super) enum ViewBinding {
    /// An offset in a VMM reservation, stable for the process lifetime (Appendix E step 4).
    Reservation,
    /// An offset in one pool or legacy allocation, which a re-allocation replaces.
    Allocation {
        physical: PhysicalId,
        generation: GpuAllocationGeneration,
        address: VirtualAddress,
    },
}

#[derive(Clone, Copy, Debug)]
pub(super) struct View {
    pub(super) key: MappingKey,
    pub(super) offset_bytes: u64,
    pub(super) length_bytes: u64,
    pub(super) binding: ViewBinding,
}

/// Enqueued work the model still waits on.
#[derive(Clone, Debug)]
pub(super) struct WorkRecord {
    /// Artifacts of the enqueuing process the work touches.
    pub(super) artifacts: BTreeSet<Digest>,
    pub(super) graph: Option<GraphId>,
}

/// What a process exit did to the ledger (GPU-T23).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ExitReport {
    /// Physical bytes whose last handle the exit closed.
    pub freed_bytes: u64,
    /// Shareable-handle exports the exit closed.
    pub closed_exports: Vec<ExportId>,
    /// Allocations the process created that other processes still hold. Their imports
    /// are no longer callable until the importer releases them.
    pub orphaned: Vec<PhysicalId>,
    /// The process's artifacts, gone with its reservations, pools and allocations.
    pub dropped_artifacts: Vec<MappingKey>,
}

/// What a park did (Appendix E step 5).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ParkReport {
    pub unmapped_bytes: u64,
    /// Physical bytes actually freed: only allocations whose last reference closed.
    pub released_bytes: u64,
    /// Bytes copied to the host because no verified canonical copy existed; zero for a
    /// clean drop.
    pub device_to_host_bytes: u64,
    /// Allocations still held after the park, and by what. They are released only by a
    /// deliberate [`VmmModel::close_physical`] once nothing holds them.
    pub retained: Vec<RetainedAllocation>,
}

/// An allocation a park could not release.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct RetainedAllocation {
    pub batch: u32,
    pub physical: PhysicalId,
    pub size_bytes: u64,
    pub references: ReferenceCount,
}

/// One batch as the model sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct BatchInfo {
    pub offset_bytes: u64,
    pub length_bytes: u64,
    pub allocation_bytes: u64,
    pub address: Option<VirtualAddress>,
    pub generation: Option<GpuAllocationGeneration>,
    pub state: BatchState,
    pub physical: Option<PhysicalId>,
}

/// The CUDA VMM and allocation lifetime model of one host (GPU part §3.7, Appendix E).
///
/// The model is the governor's ledger: it decides which driver calls may be made, makes
/// them through a [`VmmDriver`] in Appendix E's order, and records physical ownership
/// apart from mappings. It is synchronous and deterministic; time comes only from the
/// evidence registry's clock.
#[derive(Debug, Default)]
pub struct VmmModel {
    pub(super) contexts: BTreeMap<ProcessId, ProcessContext>,
    /// Processes that exited; nothing more is done on their behalf.
    pub(super) exited: BTreeSet<ProcessId>,
    /// Each process's latest Appendix E step-1 answer per set of allocation properties.
    pub(super) queries: BTreeMap<(ProcessId, AllocationProperties), DriverGranularityReport>,
    pub(super) artifacts: BTreeMap<MappingKey, Artifact>,
    pub(super) physical: BTreeMap<PhysicalId, PhysicalEntry>,
    pub(super) exports: BTreeMap<ExportId, ExportRecord>,
    pub(super) views: BTreeMap<ViewId, View>,
    pub(super) graphs: BTreeMap<GraphId, CapturedGraph>,
    pub(super) workspaces: BTreeMap<WorkspaceId, Workspace>,
    pub(super) in_flight: BTreeMap<(ProcessId, EventId), WorkRecord>,
    /// The CORE-01 gate's loader plan for each process's runtime profile (INT-06).
    pub(super) plans: BTreeMap<ProcessId, LoaderPlan>,
    next_id: u64,
}

impl VmmModel {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a runner process and how its reports are judged.
    pub fn register_process(&mut self, context: ProcessContext) -> Result<(), VmmError> {
        if self.contexts.contains_key(&context.process) {
            return Err(VmmError::ProcessExists {
                process: context.process,
            });
        }
        self.contexts.insert(context.process, context);
        Ok(())
    }

    /// Records the configuration now in force. Evidence observed under the previous
    /// fingerprint no longer applies (CORE-01), so granularity must be probed again.
    pub fn set_configuration(
        &mut self,
        process: ProcessId,
        configuration: ConfigurationFingerprint,
    ) -> Result<(), VmmError> {
        self.contexts
            .get_mut(&process)
            .ok_or(VmmError::UnknownProcess { process })?
            .configuration = configuration;
        Ok(())
    }

    pub fn process_context(&self, process: ProcessId) -> Option<&ProcessContext> {
        self.contexts.get(&process)
    }

    /// Records that a runner process exited or was killed; the driver closed its handles,
    /// mappings, exports and pending work with it (GPU-T23).
    ///
    /// Nothing more is done on the process's behalf. Its artifacts, views, graphs and
    /// workspaces are gone, and its exports are closed, so no new import of them is made.
    /// Memory it created that another process still holds stays allocated but is no
    /// longer callable there: recovery after an exporter's death is not defined per IPC
    /// family, so the strict reading keeps every import of it, of either family, from
    /// running until the importer releases it and imports a live exporter's export.
    pub fn process_exited(&mut self, process: ProcessId) -> Result<ExitReport, VmmError> {
        self.context_of(process)?;
        self.exited.insert(process);
        self.queries.retain(|(holder, _), _| *holder != process);
        self.plans.remove(&process);
        self.in_flight.retain(|(holder, _), _| *holder != process);
        self.views.retain(|_, view| view.key.process != process);
        self.graphs.retain(|_, graph| graph.process != process);
        self.workspaces
            .retain(|_, workspace| workspace.process != process);
        let mut report = ExitReport::default();
        let held: Vec<MappingKey> = self
            .artifacts
            .keys()
            .filter(|key| key.process == process)
            .copied()
            .collect();
        for key in held {
            self.artifacts.remove(&key);
            report.dropped_artifacts.push(key);
        }
        for (export, record) in &mut self.exports {
            if record.exporter == process && record.close() {
                report.closed_exports.push(*export);
            }
        }
        for (physical, entry) in &mut self.physical {
            if entry.freed {
                continue;
            }
            let Some(handle) = entry.handles.get_mut(&process) else {
                continue;
            };
            if handle.released {
                continue;
            }
            handle.released = true;
            handle.mappings.clear();
            handle.views.clear();
            handle.graphs.clear();
            if entry.owner == process {
                entry.exports.clear();
            }
            if entry.handles.values().all(|handle| handle.released) {
                entry.freed = true;
                report.freed_bytes = report.freed_bytes.saturating_add(entry.size_bytes);
            } else if entry.owner == process {
                entry.orphaned_by = Some(process);
                report.orphaned.push(*physical);
            }
        }
        Ok(report)
    }

    /// Whether the process exited.
    pub fn has_exited(&self, process: ProcessId) -> bool {
        self.exited.contains(&process)
    }

    /// Appendix E step 1: asks the process's driver for the granularity of exactly
    /// `properties` and checks the answer against fresh CORE-01 `CudaVmmAllocation`
    /// evidence for the same runtime, device and handle type, which is the only source of
    /// the value. Without usable evidence the driver is not asked. An answer that
    /// contradicts the evidence is refused and not kept; an agreeing one is kept for
    /// `fresh_for`, after which step 1 must be asked again. Unsupported is the result only
    /// when the evidence and the driver both say so.
    pub fn probe_granularity<C: Clock>(
        &mut self,
        driver: &mut dyn VmmDriver,
        evidence: &ProbeRegistry<C>,
        process: ProcessId,
        properties: AllocationProperties,
        fresh_for: Duration,
    ) -> Result<GranularityResult, VmmError> {
        let context = self.context_of(process)?;
        check_device(context, properties.device)?;
        // Dated when the query starts, as CORE-01 dates an observation, so a slow query
        // never makes its answer look fresher than it is.
        let started = evidence.now();
        let evidenced = match evidenced_granularity(evidence, context, properties) {
            Ok(granularity) => Some(granularity),
            Err(EvidenceRefusal::Unsupported { .. }) => None,
            Err(cause) => return Err(GranularityRefusal::Evidence { properties, cause }.into()),
        };
        let answer = match driver.allocation_granularity(process, &properties) {
            Ok(bytes) => GranularityResult::Reported {
                granularity: Granularity::reported(bytes).ok_or(VmmError::InvalidDriverReport {
                    what: "a zero allocation granularity",
                })?,
            },
            Err(DriverError::NotSupported) => GranularityResult::NotSupported,
            Err(error) => return Err(error.into()),
        };
        let agrees = match (evidenced, answer) {
            (Some(shown), GranularityResult::Reported { granularity }) => shown == granularity,
            (None, GranularityResult::NotSupported) => true,
            _ => false,
        };
        if !agrees {
            return Err(GranularityRefusal::DriverContradicts {
                properties,
                evidence_bytes: evidenced.map(Granularity::bytes),
                driver_bytes: answer_bytes(answer),
            }
            .into());
        }
        let record =
            DriverGranularityReport::stamp(context, properties, fresh_for, answer, started);
        self.queries.insert((process, properties), record);
        Ok(answer)
    }

    /// The process's latest agreeing step-1 answer for exactly these properties, whatever
    /// its freshness.
    pub fn granularity_query(
        &self,
        process: ProcessId,
        properties: AllocationProperties,
    ) -> Option<&DriverGranularityReport> {
        self.queries.get(&(process, properties))
    }

    /// Appendix E step 2: lays the artifact out in whole granules of the reported
    /// granularity and reserves its mapped size once, for the process lifetime.
    ///
    /// Every batch but the last must be a whole number of granules, so batch offsets in
    /// the reservation equal artifact offsets and views by offset stay contiguous. Refused
    /// without fresh granularity evidence for exactly `properties`.
    pub fn plan_vmm<C: Clock>(
        &mut self,
        driver: &mut dyn VmmDriver,
        evidence: &ProbeRegistry<C>,
        process: ProcessId,
        layout: &ArtifactLayout,
        properties: AllocationProperties,
        origin: VmmOrigin,
    ) -> Result<MappingKey, VmmError> {
        check_device(self.context_of(process)?, properties.device)?;
        let key = MappingKey {
            process,
            artifact: layout.artifact,
        };
        if self.artifacts.contains_key(&key) {
            return Err(VmmError::AlreadyPlanned { key });
        }
        let granularity = self.granularity_for(evidence, process, properties)?;
        let (slots, length_bytes, mapped_bytes) = vmm_slots(layout, granularity)?;
        let start = driver.address_reserve(process, &properties, mapped_bytes)?;
        if !granularity.is_multiple(start.get()) {
            return Err(VmmError::InvalidDriverReport {
                what: "a reservation that is not aligned to the granularity",
            });
        }
        if start.checked_add(mapped_bytes).is_none() {
            return Err(VmmError::SizeOverflow);
        }
        self.artifacts.insert(
            key,
            Artifact {
                length_bytes,
                content: layout.content,
                backing: Backing::Vmm {
                    properties,
                    granularity,
                    reservation: AddressRange::new(start, mapped_bytes),
                    origin,
                },
                lifecycle: Lifecycle::Active,
                device_to_host_bytes: 0,
                slots,
                canonical: None,
            },
        );
        Ok(key)
    }

    /// Appendix E step 9: plans one backend allocation for the whole artifact, whose bytes
    /// have the content key `content`, in a private pool, with `expandable_segments:True`
    /// when asked.
    pub fn plan_pool(
        &mut self,
        process: ProcessId,
        artifact: Digest,
        content: ContentKey,
        whole: BatchSpec,
        expandable_segments: bool,
    ) -> Result<MappingKey, VmmError> {
        self.plan_single(
            process,
            artifact,
            content,
            whole,
            Backing::Pool {
                expandable_segments,
            },
        )
    }

    /// Appendix E step 8: plans one dedicated `cudaMalloc` allocation for the whole
    /// artifact, whose bytes have the content key `content`, for legacy IPC.
    pub fn plan_legacy(
        &mut self,
        process: ProcessId,
        artifact: Digest,
        content: ContentKey,
        whole: BatchSpec,
    ) -> Result<MappingKey, VmmError> {
        self.plan_single(process, artifact, content, whole, Backing::Legacy)
    }

    fn plan_single(
        &mut self,
        process: ProcessId,
        artifact: Digest,
        content: ContentKey,
        whole: BatchSpec,
        backing: Backing,
    ) -> Result<MappingKey, VmmError> {
        self.context_of(process)?;
        let key = MappingKey { process, artifact };
        if self.artifacts.contains_key(&key) {
            return Err(VmmError::AlreadyPlanned { key });
        }
        if whole.length_bytes == 0 {
            return Err(VmmError::EmptyBatch { batch: 0 });
        }
        self.artifacts.insert(
            key,
            Artifact {
                length_bytes: whole.length_bytes,
                content,
                backing,
                lifecycle: Lifecycle::Active,
                device_to_host_bytes: 0,
                canonical: None,
                slots: vec![Slot {
                    offset_bytes: 0,
                    length_bytes: whole.length_bytes,
                    allocation_bytes: whole.length_bytes,
                    digest: whole.digest,
                    generation: None,
                    address: None,
                    state: SlotState::Empty,
                }],
            },
        );
        Ok(key)
    }

    /// Appendix E step 3 (and step 6 on wake): gives a batch new physical memory with a
    /// new allocation generation. For a VMM batch: `cuMemCreate`, `cuMemMap` at the
    /// batch's offset and `cuMemSetAccess` for device k, after checking the granularity
    /// evidence is still fresh and unchanged. For a pool or legacy artifact: its one
    /// allocation.
    pub fn back_batch<C: Clock>(
        &mut self,
        driver: &mut dyn VmmDriver,
        evidence: &ProbeRegistry<C>,
        key: MappingKey,
        batch: u32,
    ) -> Result<PhysicalId, VmmError> {
        let (backing, slot) = self.active_slot(key, batch)?;
        if let Backing::Vmm {
            origin: VmmOrigin::Import,
            ..
        } = backing
        {
            return Err(VmmError::WrongBacking {
                key,
                operation: "create memory for a batch this process imports",
            });
        }
        if slot.state != SlotState::Empty {
            return Err(batch_state(key, batch, slot.state, "map the batch"));
        }
        let generation = next_generation(slot.generation)?;
        let physical = PhysicalId::new(self.allocate_id()?);
        let (kind, handle, address) = match backing {
            // An imported reservation was refused above.
            Backing::Vmm {
                properties,
                granularity,
                reservation,
                ..
            } => {
                self.require_granularity(evidence, key.process, properties, granularity)?;
                let address = reservation
                    .start
                    .checked_add(slot.offset_bytes)
                    .ok_or(VmmError::SizeOverflow)?;
                let handle = driver.create(key.process, &properties, slot.allocation_bytes)?;
                map_with_access(
                    driver,
                    key.process,
                    AddressRange::new(address, slot.allocation_bytes),
                    handle,
                    properties.device,
                )?;
                (
                    AllocationKind::Vmm { properties },
                    DriverHandle::Vmm(handle),
                    address,
                )
            }
            Backing::Pool {
                expandable_segments,
            } => {
                let address = driver.pool_allocate(
                    key.process,
                    slot.allocation_bytes,
                    expandable_segments,
                )?;
                (
                    AllocationKind::BackendPool {
                        expandable_segments,
                    },
                    DriverHandle::Pool(address),
                    address,
                )
            }
            Backing::Legacy => {
                let address = driver.malloc(key.process, slot.allocation_bytes)?;
                (
                    AllocationKind::LegacyMalloc,
                    DriverHandle::Malloc(address),
                    address,
                )
            }
        };
        self.physical.insert(
            physical,
            PhysicalEntry {
                kind,
                contents: AllocationContents::Dedicated {
                    artifact: key.artifact,
                    batch,
                },
                size_bytes: slot.allocation_bytes,
                generation,
                owner: key.process,
                handles: BTreeMap::from([(key.process, HandleEntry::new(handle, address))]),
                exports: BTreeSet::new(),
                freed: false,
                orphaned_by: None,
            },
        );
        let slot = self.slot_mut(key, batch)?;
        slot.generation = Some(generation);
        slot.address = Some(address);
        slot.state = SlotState::Ready(physical);
        Ok(physical)
    }

    /// Appendix E steps 4 and 6: enqueues the copy that fills a mapped batch from the
    /// chosen source on `stream`. Imported batches are never populated by the receiver.
    pub fn populate_batch(
        &mut self,
        driver: &mut dyn VmmDriver,
        key: MappingKey,
        batch: u32,
        stream: StreamId,
    ) -> Result<EventId, VmmError> {
        let (backing, slot) = self.active_slot(key, batch)?;
        if let Backing::Vmm {
            origin: VmmOrigin::Import,
            ..
        } = backing
        {
            return Err(VmmError::WrongBacking {
                key,
                operation: "populate an imported batch, whose content comes from the exporter",
            });
        }
        let physical = match slot.state {
            SlotState::Ready(physical) | SlotState::Rejected(physical) => physical,
            state => return Err(batch_state(key, batch, state, "populate the batch")),
        };
        let start = slot
            .address
            .ok_or_else(|| batch_state(key, batch, slot.state, "populate the batch"))?;
        let event = driver.enqueue(
            key.process,
            stream,
            WorkKind::CopyToDevice,
            &[AddressRange::new(start, slot.length_bytes)],
        )?;
        self.track(key.process, event, BTreeSet::from([key.artifact]), None);
        self.slot_mut(key, batch)?.state = SlotState::Populating(physical, event);
        Ok(event)
    }

    /// Appendix E step 4: publishes a batch only after its completion event and a
    /// verification that found `verified`, the batch's digest. A mismatch rejects the
    /// batch; it is never used and must be populated again. An imported batch has no copy
    /// of its own and is published on the receiver's verification alone.
    pub fn publish_batch(
        &mut self,
        driver: &mut dyn VmmDriver,
        key: MappingKey,
        batch: u32,
        verified: Digest,
    ) -> Result<(), VmmError> {
        let (backing, slot) = self.active_slot(key, batch)?;
        let imported = matches!(
            backing,
            Backing::Vmm {
                origin: VmmOrigin::Import,
                ..
            }
        );
        let physical = match (slot.state, imported) {
            (SlotState::Populating(physical, event), false) => {
                if !driver.event_complete(key.process, event)? {
                    return Err(VmmError::NotComplete { event });
                }
                physical
            }
            (SlotState::Ready(physical) | SlotState::Rejected(physical), true) => physical,
            (state, _) => return Err(batch_state(key, batch, state, "publish the batch")),
        };
        let target = self.slot_mut(key, batch)?;
        if verified != slot.digest {
            target.state = SlotState::Rejected(physical);
            return Err(VmmError::DigestMismatch {
                key,
                batch,
                expected: slot.digest,
                found: verified,
            });
        }
        target.state = SlotState::Published(physical);
        Ok(())
    }

    /// Appendix E step 4: a tensor view by offset. A VMM view is bound to the reservation
    /// and survives parks as a retained tensor; a pool or legacy view is bound to the
    /// current allocation and holds it until the view is destroyed.
    pub fn create_view(
        &mut self,
        key: MappingKey,
        offset_bytes: u64,
        length_bytes: u64,
    ) -> Result<ViewId, VmmError> {
        let artifact = self.artifact(key)?;
        artifact.check_range(key, offset_bytes, length_bytes)?;
        let binding = match artifact.backing {
            Backing::Vmm { .. } => ViewBinding::Reservation,
            Backing::Pool { .. } | Backing::Legacy => {
                let slot = artifact.slot(key, 0)?;
                let (Some(physical), Some(generation), Some(start)) =
                    (slot.state.physical(), slot.generation, slot.address)
                else {
                    return Err(batch_state(key, 0, slot.state, "bind a view"));
                };
                ViewBinding::Allocation {
                    physical,
                    generation,
                    address: start
                        .checked_add(offset_bytes)
                        .ok_or(VmmError::SizeOverflow)?,
                }
            }
        };
        let view = ViewId::new(self.allocate_id()?);
        if let ViewBinding::Allocation { physical, .. } = binding {
            self.handle_mut(physical, key.process)?.views.insert(view);
        }
        self.views.insert(
            view,
            View {
                key,
                offset_bytes,
                length_bytes,
                binding,
            },
        );
        Ok(view)
    }

    /// Runs a kernel through `view` on `stream`. Refused unless every batch the view
    /// covers is published and the view's allocation is still the current one: a retained
    /// tensor is never callable while its addresses are unmapped (§3.7).
    pub fn call_view(
        &mut self,
        driver: &mut dyn VmmDriver,
        view: ViewId,
        stream: StreamId,
    ) -> Result<EventId, VmmError> {
        let entry = *self
            .views
            .get(&view)
            .ok_or(VmmError::UnknownView { view })?;
        let range = self.view_range(&entry)?;
        let event = driver.enqueue(entry.key.process, stream, WorkKind::Kernel, &[range])?;
        self.track(
            entry.key.process,
            event,
            BTreeSet::from([entry.key.artifact]),
            None,
        );
        Ok(event)
    }

    /// Destroys a view explicitly; a pool or legacy view releases its hold on the
    /// allocation (§3.7: explicit destruction of tensor views).
    pub fn destroy_view(&mut self, view: ViewId) -> Result<(), VmmError> {
        let removed = self
            .views
            .remove(&view)
            .ok_or(VmmError::UnknownView { view })?;
        if let ViewBinding::Allocation { physical, .. } = removed.binding {
            if let Some(handle) = self
                .physical
                .get_mut(&physical)
                .and_then(|entry| entry.handles.get_mut(&removed.key.process))
            {
                handle.views.remove(&view);
            }
        }
        Ok(())
    }

    /// Appendix E step 5, first half: stops admitting work over the artifact.
    ///
    /// A clean drop copies nothing back. It needs a verified canonical copy of exactly the
    /// artifact's content, which only a catalog or residency check makes. A catalog proof
    /// then stays with the artifact, holding its lease, until the artifact is refilled; a
    /// later park before that uses [`ParkSource::HeldCopy`]. Otherwise every published
    /// batch is copied to the host, and the park waits for it. A refused clean drop drops
    /// its proof, and a lease the proof held lapses when it expires.
    pub fn begin_park(
        &mut self,
        driver: &mut dyn VmmDriver,
        key: MappingKey,
        source: ParkSource,
    ) -> Result<(), VmmError> {
        let artifact = self.artifact(key)?;
        artifact.require(key, Lifecycle::Active)?;
        let mut device_to_host_bytes = 0u64;
        let mut hold = None;
        match source {
            ParkSource::CleanDrop { copy } => {
                if copy.content() != artifact.content {
                    return Err(VmmError::CanonicalCopyMismatch {
                        expected: artifact.content,
                        copy: copy.content(),
                    });
                }
                match (copy.source(), copy.lease()) {
                    (CanonicalSource::Catalog { .. }, None) => {
                        return Err(VmmError::DetachedCanonicalCopy { key });
                    }
                    (_, Some(_)) => {
                        if artifact.canonical.is_some() {
                            return Err(VmmError::CanonicalCopyHeld { key });
                        }
                        hold = Some(copy);
                    }
                    (CanonicalSource::Reconstructible { .. }, None) => {}
                }
            }
            ParkSource::HeldCopy => {
                if artifact.canonical.is_none() {
                    return Err(VmmError::NoCanonicalCopy { key });
                }
            }
            ParkSource::CopyBack { stream } => {
                let ranges: Vec<AddressRange> = artifact
                    .slots
                    .iter()
                    .filter(|slot| matches!(slot.state, SlotState::Published(_)))
                    .filter_map(|slot| {
                        slot.address
                            .map(|start| AddressRange::new(start, slot.length_bytes))
                    })
                    .collect();
                for range in ranges {
                    let event =
                        driver.enqueue(key.process, stream, WorkKind::CopyToHost, &[range])?;
                    self.track(key.process, event, BTreeSet::from([key.artifact]), None);
                    device_to_host_bytes = device_to_host_bytes
                        .checked_add(range.length_bytes)
                        .ok_or(VmmError::SizeOverflow)?;
                }
            }
        }
        let artifact = self.artifact_mut(key)?;
        artifact.lifecycle = Lifecycle::Draining;
        artifact.device_to_host_bytes = device_to_host_bytes;
        if hold.is_some() {
            artifact.canonical = hold;
        }
        Ok(())
    }

    /// Appendix E step 5, second half: once every stream and graph touching the artifact
    /// is quiescent, unmaps each VMM batch (`cuMemUnmap`) and releases each allocation
    /// whose reference count reached zero. An allocation still held by an export, an
    /// import, a graph, another mapping or a live pool view is retained and reported;
    /// unmapping never counts as freeing.
    pub fn finish_park(
        &mut self,
        driver: &mut dyn VmmDriver,
        key: MappingKey,
    ) -> Result<ParkReport, VmmError> {
        let (backing, slots, device_to_host_bytes) = {
            let artifact = self.artifact(key)?;
            artifact.require(key, Lifecycle::Draining)?;
            (
                artifact.backing,
                artifact.slots.clone(),
                artifact.device_to_host_bytes,
            )
        };
        let pending = self.pending(driver, |process, work| {
            process == key.process && work.artifacts.contains(&key.artifact)
        })?;
        if !pending.is_empty() {
            return Err(VmmError::NotQuiescent { events: pending });
        }
        let mut report = ParkReport {
            device_to_host_bytes,
            ..ParkReport::default()
        };
        for (slot, batch) in slots.iter().zip(0u32..) {
            let Some(physical) = slot.state.physical() else {
                continue;
            };
            let start = slot
                .address
                .ok_or_else(|| batch_state(key, batch, slot.state, "park the batch"))?;
            let vmm = matches!(backing, Backing::Vmm { .. });
            if vmm {
                driver.unmap(key.process, AddressRange::new(start, slot.allocation_bytes))?;
                report.unmapped_bytes = report.unmapped_bytes.saturating_add(slot.allocation_bytes);
            }
            self.handle_mut(physical, key.process)?
                .mappings
                .remove(&start);
            let target = self.slot_mut(key, batch)?;
            target.state = SlotState::Empty;
            if !vmm {
                target.address = None;
            }
            let references = self.references_of(physical, key.process)?;
            if references.is_zero() {
                let freed = self.release_handle(driver, physical, key.process)?;
                report.released_bytes = report.released_bytes.saturating_add(freed);
            } else {
                report.retained.push(RetainedAllocation {
                    batch,
                    physical,
                    size_bytes: slot.allocation_bytes,
                    references,
                });
            }
        }
        self.artifact_mut(key)?.lifecycle = Lifecycle::Parked;
        Ok(report)
    }

    /// Appendix E step 6: readies a parked artifact for new memory. A VMM artifact keeps
    /// its reservation, so [`Self::back_batch`] maps every batch at its old offset; a pool
    /// artifact gets a new allocation, so views are rebuilt and graphs recaptured.
    pub fn wake(&mut self, key: MappingKey) -> Result<(), VmmError> {
        let artifact = self.artifact_mut(key)?;
        artifact.require(key, Lifecycle::Parked)?;
        artifact.lifecycle = Lifecycle::Active;
        artifact.device_to_host_bytes = 0;
        Ok(())
    }

    /// Creates a private allocation for scratch space or packed suballocations. It is
    /// sized in granules of the reported granularity and is never exported (§3.7).
    pub fn allocate_private<C: Clock>(
        &mut self,
        driver: &mut dyn VmmDriver,
        evidence: &ProbeRegistry<C>,
        process: ProcessId,
        properties: AllocationProperties,
        size_bytes: u64,
        label: Digest,
    ) -> Result<PhysicalId, VmmError> {
        check_device(self.context_of(process)?, properties.device)?;
        let granularity = self.granularity_for(evidence, process, properties)?;
        if size_bytes == 0 || !granularity.is_multiple(size_bytes) {
            return Err(VmmError::NotGranularityMultiple {
                size_bytes,
                granularity_bytes: granularity.bytes(),
            });
        }
        let physical = PhysicalId::new(self.allocate_id()?);
        let handle = driver.create(process, &properties, size_bytes)?;
        self.physical.insert(
            physical,
            PhysicalEntry {
                kind: AllocationKind::Vmm { properties },
                contents: AllocationContents::Private { label },
                size_bytes,
                generation: GpuAllocationGeneration::FIRST,
                owner: process,
                handles: BTreeMap::from([(
                    process,
                    HandleEntry::unmapped(DriverHandle::Vmm(handle)),
                )]),
                exports: BTreeSet::new(),
                freed: false,
                orphaned_by: None,
            },
        );
        Ok(physical)
    }

    /// Closes `process`'s handle to `physical` deliberately (Appendix E step 5), once
    /// nothing holds it. With no mapping and no other holder, no work can reach it: the
    /// park that unmapped it waited for quiescence. Returns the bytes freed: the
    /// allocation's size when this was the last handle, otherwise zero.
    pub fn close_physical(
        &mut self,
        driver: &mut dyn VmmDriver,
        process: ProcessId,
        physical: PhysicalId,
    ) -> Result<u64, VmmError> {
        self.context_of(process)?;
        let entry = self
            .physical
            .get(&physical)
            .ok_or(VmmError::UnknownPhysical { physical })?;
        if entry.freed {
            return Err(VmmError::AlreadyFreed { physical });
        }
        match entry.handles.get(&process) {
            None => return Err(VmmError::NoHandle { physical, process }),
            Some(handle) if handle.released => {
                return Err(VmmError::AlreadyReleased { physical, process })
            }
            Some(_) => {}
        }
        let references = entry.references(process);
        if !references.is_zero() {
            return Err(VmmError::StillReferenced {
                physical,
                references,
            });
        }
        self.release_handle(driver, physical, process)
    }

    pub fn lifecycle(&self, key: MappingKey) -> Option<Lifecycle> {
        self.artifacts.get(&key).map(|artifact| artifact.lifecycle)
    }

    /// The content key the artifact was planned with: what a clean-drop park's canonical
    /// copy must hold.
    pub fn artifact_content(&self, key: MappingKey) -> Option<ContentKey> {
        self.artifacts.get(&key).map(|artifact| artifact.content)
    }

    /// The catalog proof the artifact holds from its last clean drop, if any.
    pub fn canonical_copy(&self, key: MappingKey) -> Option<&VerifiedCanonicalCopy> {
        self.artifacts.get(&key)?.canonical.as_ref()
    }

    /// Extends the held catalog proof's lease by `hold_for` from now, so the canonical copy
    /// stays while the artifact is parked; returns when the lease ends.
    pub fn renew_canonical_copy(
        &mut self,
        catalog: &mut Catalog,
        key: MappingKey,
        hold_for: Duration,
    ) -> Result<MonotonicTime, VmmError> {
        let copy = self
            .artifact(key)?
            .canonical
            .as_ref()
            .ok_or(VmmError::NoCanonicalCopy { key })?;
        copy.renew(catalog, hold_for)
            .map_err(VmmError::CanonicalCopy)
    }

    /// Releases the held catalog proof and its lease once the artifact is refilled: active
    /// again with every batch published (Appendix E step 6). Until then the copy may be
    /// the refill's source, so the lease is kept.
    pub fn release_canonical_copy(
        &mut self,
        catalog: &mut Catalog,
        key: MappingKey,
    ) -> Result<(), VmmError> {
        let artifact = self.artifact_mut(key)?;
        if artifact.canonical.is_none() {
            return Err(VmmError::NoCanonicalCopy { key });
        }
        let refilled = artifact.lifecycle == Lifecycle::Active
            && artifact
                .slots
                .iter()
                .all(|slot| matches!(slot.state, SlotState::Published(_)));
        if !refilled {
            return Err(VmmError::NotRefilled { key });
        }
        let copy = artifact
            .canonical
            .take()
            .ok_or(VmmError::NoCanonicalCopy { key })?;
        copy.release(catalog).map_err(VmmError::CanonicalCopy)
    }

    /// Installs the loader plan the CORE-01 gate made for this process's runtime profile
    /// (INT-06), replacing an earlier one. CUDA IPC of either API family is exported,
    /// imported or opened only where this plan enabled it, and only while the evidence
    /// behind it still holds.
    pub fn set_loader_plan(
        &mut self,
        process: ProcessId,
        plan: LoaderPlan,
    ) -> Result<(), VmmError> {
        let context = self.context_of(process)?;
        if plan.runtime() != &context.runtime || plan.configuration() != context.configuration {
            return Err(VmmError::LoaderPlanMismatch { process });
        }
        self.plans.insert(process, plan);
        Ok(())
    }

    /// The loader plan installed for a process.
    pub fn loader_plan(&self, process: ProcessId) -> Option<&LoaderPlan> {
        self.plans.get(&process)
    }

    /// The process's loader plan enabled `optimization` for the process's runtime and
    /// configuration, and the evidence behind it still holds (INT-06).
    pub(super) fn require_permitted<C: Clock>(
        &self,
        evidence: &ProbeRegistry<C>,
        process: ProcessId,
        optimization: Optimization,
    ) -> Result<(), VmmError> {
        let context = self.context_of(process)?;
        let plan = self
            .plans
            .get(&process)
            .ok_or(VmmError::NoLoaderPlan { process })?;
        if plan.runtime() != &context.runtime || plan.configuration() != context.configuration {
            return Err(VmmError::LoaderPlanMismatch { process });
        }
        if !plan.is_enabled(optimization) {
            return Err(VmmError::NotPermitted {
                process,
                optimization,
                reason: plan.ordinary().get(&optimization).cloned(),
            });
        }
        plan.recheck(optimization, evidence)
            .map(|_| ())
            .map_err(|refusal| VmmError::LoaderPlanLapsed {
                process,
                optimization,
                refusal,
            })
    }

    /// The VMM reservation of an artifact.
    pub fn reservation(&self, key: MappingKey) -> Option<AddressRange> {
        match self.artifacts.get(&key)?.backing {
            Backing::Vmm { reservation, .. } => Some(reservation),
            Backing::Pool { .. } | Backing::Legacy => None,
        }
    }

    pub fn batch(&self, key: MappingKey, batch: u32) -> Option<BatchInfo> {
        let slot = self.artifacts.get(&key)?.slot(key, batch).ok()?;
        Some(BatchInfo {
            offset_bytes: slot.offset_bytes,
            length_bytes: slot.length_bytes,
            allocation_bytes: slot.allocation_bytes,
            address: slot.address,
            generation: slot.generation,
            state: slot.state.public(),
            physical: slot.state.physical(),
        })
    }

    pub fn physical(&self, physical: PhysicalId) -> Option<PhysicalInfo> {
        self.physical.get(&physical).map(PhysicalEntry::info)
    }

    /// What holds `physical` through `process`'s handle.
    pub fn references(&self, physical: PhysicalId, process: ProcessId) -> Option<ReferenceCount> {
        self.physical
            .get(&physical)
            .map(|entry| entry.references(process))
    }

    /// The context of a registered process that has not exited.
    pub(super) fn context_of(&self, process: ProcessId) -> Result<&ProcessContext, VmmError> {
        if self.exited.contains(&process) {
            return Err(VmmError::ProcessExited { process });
        }
        self.contexts
            .get(&process)
            .ok_or(VmmError::UnknownProcess { process })
    }

    /// The granularity for exactly `properties` in `process`: from fresh CORE-01 evidence,
    /// with a fresh step-1 answer of the process's driver that agrees with it.
    pub(super) fn granularity_for<C: Clock>(
        &self,
        evidence: &ProbeRegistry<C>,
        process: ProcessId,
        properties: AllocationProperties,
    ) -> Result<Granularity, VmmError> {
        let context = self.context_of(process)?;
        let evidenced = evidenced_granularity(evidence, context, properties)
            .map_err(|cause| GranularityRefusal::Evidence { properties, cause })?;
        let query = self
            .queries
            .get(&(process, properties))
            .ok_or(GranularityRefusal::NotQueried { properties })?;
        if let Some(staleness) = query.staleness(evidence.now()) {
            return Err(GranularityRefusal::QueryStale {
                properties,
                staleness,
            }
            .into());
        }
        match query.answer() {
            GranularityResult::Reported { granularity } if granularity == evidenced => {
                Ok(evidenced)
            }
            answer => Err(GranularityRefusal::DriverContradicts {
                properties,
                evidence_bytes: Some(evidenced.bytes()),
                driver_bytes: answer_bytes(answer),
            }
            .into()),
        }
    }

    /// Fresh granularity evidence that still reports what the reservation was laid out
    /// with.
    pub(super) fn require_granularity<C: Clock>(
        &self,
        evidence: &ProbeRegistry<C>,
        process: ProcessId,
        properties: AllocationProperties,
        laid_out: Granularity,
    ) -> Result<(), VmmError> {
        let reported = self.granularity_for(evidence, process, properties)?;
        if reported != laid_out {
            return Err(GranularityRefusal::Changed {
                laid_out_bytes: laid_out.bytes(),
                reported_bytes: reported.bytes(),
            }
            .into());
        }
        Ok(())
    }

    pub(super) fn artifact(&self, key: MappingKey) -> Result<&Artifact, VmmError> {
        self.artifacts
            .get(&key)
            .ok_or(VmmError::UnknownArtifact { key })
    }

    pub(super) fn artifact_mut(&mut self, key: MappingKey) -> Result<&mut Artifact, VmmError> {
        self.artifacts
            .get_mut(&key)
            .ok_or(VmmError::UnknownArtifact { key })
    }

    /// The backing and a copy of one batch of an active artifact.
    pub(super) fn active_slot(
        &self,
        key: MappingKey,
        batch: u32,
    ) -> Result<(Backing, Slot), VmmError> {
        let artifact = self.artifact(key)?;
        artifact.require(key, Lifecycle::Active)?;
        Ok((artifact.backing, artifact.slot(key, batch)?))
    }

    pub(super) fn slot_mut(&mut self, key: MappingKey, batch: u32) -> Result<&mut Slot, VmmError> {
        self.artifact_mut(key)?
            .slots
            .get_mut(usize::try_from(batch).unwrap_or(usize::MAX))
            .ok_or(VmmError::UnknownBatch { key, batch })
    }

    /// Whether `physical` is the published memory of that batch.
    pub(super) fn is_published(&self, key: MappingKey, batch: u32, physical: PhysicalId) -> bool {
        self.artifacts
            .get(&key)
            .and_then(|artifact| artifact.slot(key, batch).ok())
            .is_some_and(|slot| slot.state == SlotState::Published(physical))
    }

    /// Why work over `[offset, end)` of `artifact` cannot run because the process that
    /// exported memory behind it exited, if so (GPU-T23).
    pub(super) fn exporter_gone(
        &self,
        artifact: &Artifact,
        offset_bytes: u64,
        end_bytes: u64,
    ) -> Option<NotCallableReason> {
        artifact
            .covered(offset_bytes, end_bytes)
            .into_iter()
            .find_map(|(_, slot)| {
                let exporter = self.physical.get(&slot.state.physical()?)?.orphaned_by?;
                Some(NotCallableReason::ExporterGone { exporter })
            })
    }

    /// The addresses work through `view` touches now, or why it cannot run.
    pub(super) fn view_range(&self, view: &View) -> Result<AddressRange, VmmError> {
        let key = view.key;
        let artifact = self.artifact(key)?;
        let end = artifact.check_range(key, view.offset_bytes, view.length_bytes)?;
        if let Some(reason) = artifact
            .not_callable(view.offset_bytes, end)
            .or_else(|| self.exporter_gone(artifact, view.offset_bytes, end))
        {
            return Err(VmmError::NotCallable { key, reason });
        }
        match (view.binding, artifact.backing) {
            (ViewBinding::Reservation, Backing::Vmm { reservation, .. }) => Ok(AddressRange::new(
                reservation
                    .start
                    .checked_add(view.offset_bytes)
                    .ok_or(VmmError::SizeOverflow)?,
                view.length_bytes,
            )),
            (
                ViewBinding::Allocation {
                    physical,
                    generation,
                    address,
                },
                Backing::Pool { .. } | Backing::Legacy,
            ) => {
                let slot = artifact.slot(key, 0)?;
                if slot.state.physical() != Some(physical) || slot.generation != Some(generation) {
                    return Err(VmmError::NotCallable {
                        key,
                        reason: NotCallableReason::StaleAllocation {
                            bound: generation,
                            current: slot.generation,
                        },
                    });
                }
                Ok(AddressRange::new(address, view.length_bytes))
            }
            _ => Err(VmmError::WrongBacking {
                key,
                operation: "use a view bound to another kind of memory",
            }),
        }
    }

    pub(super) fn allocate_id(&mut self) -> Result<u64, VmmError> {
        let id = self.next_id.checked_add(1).ok_or(VmmError::IdsExhausted)?;
        self.next_id = id;
        Ok(id)
    }

    pub(super) fn track(
        &mut self,
        process: ProcessId,
        event: EventId,
        artifacts: BTreeSet<Digest>,
        graph: Option<GraphId>,
    ) {
        self.in_flight
            .insert((process, event), WorkRecord { artifacts, graph });
    }

    /// The incomplete events among the tracked work `matches` selects; completed work is
    /// forgotten.
    pub(super) fn pending(
        &mut self,
        driver: &mut dyn VmmDriver,
        matches: impl Fn(ProcessId, &WorkRecord) -> bool,
    ) -> Result<Vec<EventId>, VmmError> {
        let candidates: Vec<(ProcessId, EventId)> = self
            .in_flight
            .iter()
            .filter(|((process, _), work)| matches(*process, work))
            .map(|(key, _)| *key)
            .collect();
        let mut pending = Vec::new();
        for (process, event) in candidates {
            if driver.event_complete(process, event)? {
                self.in_flight.remove(&(process, event));
            } else {
                pending.push(event);
            }
        }
        Ok(pending)
    }

    pub(super) fn handle_mut(
        &mut self,
        physical: PhysicalId,
        process: ProcessId,
    ) -> Result<&mut HandleEntry, VmmError> {
        self.physical
            .get_mut(&physical)
            .ok_or(VmmError::UnknownPhysical { physical })?
            .handles
            .get_mut(&process)
            .ok_or(VmmError::NoHandle { physical, process })
    }

    pub(super) fn references_of(
        &self,
        physical: PhysicalId,
        process: ProcessId,
    ) -> Result<ReferenceCount, VmmError> {
        self.references(physical, process)
            .ok_or(VmmError::UnknownPhysical { physical })
    }

    /// Releases `process`'s handle through the matching driver call. Callers check that
    /// nothing holds it. Returns the bytes freed when this was the last handle.
    pub(super) fn release_handle(
        &mut self,
        driver: &mut dyn VmmDriver,
        physical: PhysicalId,
        process: ProcessId,
    ) -> Result<u64, VmmError> {
        let entry = self
            .physical
            .get(&physical)
            .ok_or(VmmError::UnknownPhysical { physical })?;
        let handle = entry
            .handles
            .get(&process)
            .ok_or(VmmError::NoHandle { physical, process })?;
        if handle.released {
            return Err(VmmError::AlreadyReleased { physical, process });
        }
        match handle.driver {
            DriverHandle::Vmm(handle) => driver.release(process, handle)?,
            DriverHandle::Malloc(pointer) => driver.free(process, pointer)?,
            DriverHandle::Pool(pointer) => driver.pool_free(process, pointer)?,
            DriverHandle::IpcOpened(pointer) => driver.ipc_close_mem_handle(process, pointer)?,
        }
        let entry = self
            .physical
            .get_mut(&physical)
            .ok_or(VmmError::UnknownPhysical { physical })?;
        if let Some(handle) = entry.handles.get_mut(&process) {
            handle.released = true;
        }
        if entry.handles.values().all(|handle| handle.released) {
            entry.freed = true;
            return Ok(entry.size_bytes);
        }
        Ok(0)
    }
}

pub(super) fn check_device(
    context: &ProcessContext,
    device: DeviceOrdinal,
) -> Result<(), VmmError> {
    if device != context.device {
        return Err(VmmError::WrongDevice {
            process: context.process,
            expected: context.device,
            found: device,
        });
    }
    Ok(())
}

/// The granularity a step-1 answer names; `None` for unsupported.
fn answer_bytes(answer: GranularityResult) -> Option<u64> {
    match answer {
        GranularityResult::Reported { granularity } => Some(granularity.bytes()),
        GranularityResult::NotSupported => None,
    }
}

/// The generation after `previous`, or the first; never wraps (S3.1).
pub(super) fn next_generation(
    previous: Option<GpuAllocationGeneration>,
) -> Result<GpuAllocationGeneration, VmmError> {
    match previous {
        None => Ok(GpuAllocationGeneration::FIRST),
        Some(previous) => previous.next().ok_or(VmmError::GenerationExhausted),
    }
}

pub(super) fn batch_state(
    key: MappingKey,
    batch: u32,
    state: SlotState,
    operation: &'static str,
) -> VmmError {
    VmmError::BatchState {
        key,
        batch,
        state: state.public(),
        operation,
    }
}

/// `cuMemMap` then `cuMemSetAccess` for device k (Appendix E step 3). On failure the
/// handle is unmapped and released again, so no half-mapped batch remains.
pub(super) fn map_with_access(
    driver: &mut dyn VmmDriver,
    process: ProcessId,
    range: AddressRange,
    handle: PhysicalHandle,
    device: DeviceOrdinal,
) -> Result<(), VmmError> {
    if let Err(error) = driver.map(process, range, handle) {
        let _ = driver.release(process, handle);
        return Err(error.into());
    }
    if let Err(error) = driver.set_access(process, range, device) {
        let _ = driver.unmap(process, range);
        let _ = driver.release(process, handle);
        return Err(error.into());
    }
    Ok(())
}

/// The batches laid out in granules: offsets, the artifact length and the mapped size.
fn vmm_slots(
    layout: &ArtifactLayout,
    granularity: Granularity,
) -> Result<(Vec<Slot>, u64, u64), VmmError> {
    let last = layout
        .batches
        .len()
        .checked_sub(1)
        .ok_or(VmmError::EmptyLayout)?;
    if u32::try_from(layout.batches.len()).is_err() {
        return Err(VmmError::TooManyBatches);
    }
    let mut slots = Vec::with_capacity(layout.batches.len());
    let mut offset_bytes = 0u64;
    let mut length_bytes = 0u64;
    for ((index, spec), batch) in layout.batches.iter().enumerate().zip(0u32..) {
        if spec.length_bytes == 0 {
            return Err(VmmError::EmptyBatch { batch });
        }
        if index != last && !granularity.is_multiple(spec.length_bytes) {
            return Err(VmmError::BatchNotAligned {
                batch,
                length_bytes: spec.length_bytes,
                granularity_bytes: granularity.bytes(),
            });
        }
        let allocation_bytes = granularity
            .align_up(spec.length_bytes)
            .ok_or(VmmError::SizeOverflow)?;
        slots.push(Slot {
            offset_bytes,
            length_bytes: spec.length_bytes,
            allocation_bytes,
            digest: spec.digest,
            generation: None,
            address: None,
            state: SlotState::Empty,
        });
        offset_bytes = offset_bytes
            .checked_add(allocation_bytes)
            .ok_or(VmmError::SizeOverflow)?;
        length_bytes = length_bytes
            .checked_add(spec.length_bytes)
            .ok_or(VmmError::SizeOverflow)?;
    }
    Ok((slots, length_bytes, offset_bytes))
}
