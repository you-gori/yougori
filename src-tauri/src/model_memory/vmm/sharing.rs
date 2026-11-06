//! Sharing dedicated allocations between processes of one runtime (GPU part §3.7;
//! Appendix E steps 7 and 8).
//!
//! Only whole, dedicated, published allocations are shared: one batch of one immutable
//! artifact, created for the exact handle type and sized in granules of the granularity
//! reported for those properties, so no neighbouring private data is ever exposed. Every
//! export and import needs fresh CORE-01 evidence for its own API family, and every
//! export and import holds the physical allocation until it is closed.

use super::driver::VmmDriver;
use super::error::VmmError;
use super::evidence::{require_legacy_ipc, require_shareable_handle, runtime_identity};
use super::ledger::{AllocationContents, AllocationKind, DriverHandle, HandleEntry};
use super::model::VmmOrigin;
use super::model::{batch_state, map_with_access, next_generation, Backing, SlotState, VmmModel};
use super::types::{
    AddressRange, ExportId, IpcMemHandle, MappingKey, PhysicalId, ProcessId, SharedHandle,
    VirtualAddress,
};
use crate::foundation::evidence::{Optimization, ProbeRegistry, Satisfied, ShareableHandle};
use crate::foundation::ids::Clock;

/// How an allocation was exported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ExportChannel {
    /// A CUDA VMM shareable handle, open until closed (step 7).
    Shareable {
        kind: ShareableHandle,
        shared: SharedHandle,
        open: bool,
    },
    /// A legacy IPC handle (step 8).
    LegacyIpc { handle: IpcMemHandle },
}

#[derive(Clone, Debug)]
pub(super) struct ExportRecord {
    pub(super) exporter: ProcessId,
    pub(super) physical: PhysicalId,
    pub(super) channel: ExportChannel,
    /// The evidence that allowed the export.
    pub(super) evidence: Satisfied,
}

impl ExportRecord {
    /// Closes an open shareable-handle export; true if it was open. A legacy IPC handle
    /// has nothing to close: it ends with its producer.
    pub(super) fn close(&mut self) -> bool {
        match &mut self.channel {
            ExportChannel::Shareable { open, .. } if *open => {
                *open = false;
                true
            }
            ExportChannel::Shareable { .. } | ExportChannel::LegacyIpc { .. } => false,
        }
    }
}

impl VmmModel {
    /// Appendix E step 7, exporter side: `cuMemExportToShareableHandle` of one whole
    /// allocation as `kind`.
    ///
    /// Refused unless the allocation is a dedicated, published artifact batch created by
    /// this process for exactly `kind`, its size is a whole number of the granules
    /// reported for those properties, fresh CORE-01 evidence shows CUDA VMM sharing with
    /// `kind` handles in this runtime, and the runtime profile's loader plan enabled it
    /// ([`Self::set_loader_plan`], INT-06). The open export holds the allocation until
    /// [`Self::close_export`].
    pub fn export_allocation<C: Clock>(
        &mut self,
        driver: &mut dyn VmmDriver,
        evidence: &ProbeRegistry<C>,
        process: ProcessId,
        physical: PhysicalId,
        kind: ShareableHandle,
    ) -> Result<ExportId, VmmError> {
        self.context_of(process)?;
        let entry = self
            .physical
            .get(&physical)
            .ok_or(VmmError::UnknownPhysical { physical })?;
        if entry.freed {
            return Err(VmmError::AlreadyFreed { physical });
        }
        if entry.owner != process {
            return Err(VmmError::NotOwner { physical, process });
        }
        let handle = match entry.handles.get(&process) {
            Some(handle) if !handle.released => handle.driver,
            Some(_) => return Err(VmmError::AlreadyReleased { physical, process }),
            None => return Err(VmmError::NoHandle { physical, process }),
        };
        let AllocationContents::Dedicated { artifact, batch } = entry.contents else {
            return Err(VmmError::NotDedicated { physical });
        };
        let (AllocationKind::Vmm { properties }, DriverHandle::Vmm(handle)) = (entry.kind, handle)
        else {
            return Err(VmmError::NotVmmAllocation { physical });
        };
        if properties.requested_handle != Some(kind) {
            return Err(VmmError::NotCreatedForHandleType {
                physical,
                requested: kind,
                created: properties.requested_handle,
            });
        }
        let size_bytes = entry.size_bytes;
        let granularity = self.granularity_for(evidence, process, properties)?;
        if !granularity.is_multiple(size_bytes) {
            return Err(VmmError::NotGranularityMultiple {
                size_bytes,
                granularity_bytes: granularity.bytes(),
            });
        }
        if !self.is_published(MappingKey { process, artifact }, batch, physical) {
            return Err(VmmError::NotPublished { physical });
        }
        let satisfied = require_shareable_handle(evidence, self.context_of(process)?, kind)?;
        self.require_permitted(evidence, process, Optimization::CudaIpcVmmShareableHandle)?;
        let export = ExportId::new(self.allocate_id()?);
        let shared = driver.export_shareable(process, handle, kind)?;
        if let Some(entry) = self.physical.get_mut(&physical) {
            entry.exports.insert(export);
        }
        self.exports.insert(
            export,
            ExportRecord {
                exporter: process,
                physical,
                channel: ExportChannel::Shareable {
                    kind,
                    shared,
                    open: true,
                },
                evidence: satisfied,
            },
        );
        Ok(export)
    }

    /// Appendix E step 7, receiver side: `cuMemImportFromShareableHandle`, then
    /// `cuMemMap` and `cuMemSetAccess` in the receiver's own reservation, at the batch's
    /// offset. The receiver then publishes the batch on its own verification.
    ///
    /// The receiver's reservation must be planned with [`VmmOrigin::Import`] for the
    /// export's exact properties, both processes must run in the same runtime, fresh
    /// CORE-01 evidence must show the handle type in the receiver's runtime, and the
    /// receiver's loader plan must enable it (INT-06). The import holds the exporter's
    /// allocation until the receiver releases it.
    pub fn import_batch<C: Clock>(
        &mut self,
        driver: &mut dyn VmmDriver,
        evidence: &ProbeRegistry<C>,
        key: MappingKey,
        batch: u32,
        export: ExportId,
    ) -> Result<PhysicalId, VmmError> {
        let (backing, slot) = self.active_slot(key, batch)?;
        let Backing::Vmm {
            properties,
            granularity,
            reservation,
            origin: VmmOrigin::Import,
        } = backing
        else {
            return Err(VmmError::WrongBacking {
                key,
                operation: "import into memory this process does not plan to import",
            });
        };
        if slot.state != SlotState::Empty {
            return Err(batch_state(key, batch, slot.state, "import the batch"));
        }
        let record = self
            .exports
            .get(&export)
            .ok_or(VmmError::UnknownExport { export })?;
        let ExportChannel::Shareable { kind, shared, open } = record.channel else {
            return Err(VmmError::WrongExportKind { export });
        };
        if !open {
            return Err(VmmError::ExportClosed { export });
        }
        let (exporter, physical) = (record.exporter, record.physical);
        if exporter == key.process {
            return Err(VmmError::SameProcess {
                process: key.process,
            });
        }
        self.same_runtime(exporter, key.process)?;
        let entry = self
            .physical
            .get(&physical)
            .ok_or(VmmError::UnknownPhysical { physical })?;
        if entry.freed {
            return Err(VmmError::AlreadyFreed { physical });
        }
        // Only a live handle blocks: one the receiver released, such as at its own park,
        // is replaced by the new import (GPU-T22).
        if entry.holds_live_handle(key.process) {
            return Err(VmmError::AlreadyImported {
                physical,
                process: key.process,
            });
        }
        if properties.requested_handle != Some(kind) {
            return Err(VmmError::NotCreatedForHandleType {
                physical,
                requested: kind,
                created: properties.requested_handle,
            });
        }
        let expected = AllocationContents::Dedicated {
            artifact: key.artifact,
            batch,
        };
        if entry.contents != expected
            || entry.kind != (AllocationKind::Vmm { properties })
            || entry.size_bytes != slot.allocation_bytes
        {
            return Err(VmmError::ImportMismatch { export, key, batch });
        }
        self.require_granularity(evidence, key.process, properties, granularity)?;
        require_shareable_handle(evidence, self.context_of(key.process)?, kind)?;
        self.require_permitted(
            evidence,
            key.process,
            Optimization::CudaIpcVmmShareableHandle,
        )?;
        let generation = next_generation(slot.generation)?;
        let start = reservation
            .start
            .checked_add(slot.offset_bytes)
            .ok_or(VmmError::SizeOverflow)?;
        let handle = driver.import_shareable(key.process, shared, kind)?;
        map_with_access(
            driver,
            key.process,
            AddressRange::new(start, slot.allocation_bytes),
            handle,
            properties.device,
        )?;
        if let Some(entry) = self.physical.get_mut(&physical) {
            entry.handles.insert(
                key.process,
                HandleEntry::new(DriverHandle::Vmm(handle), start),
            );
        }
        let target = self.slot_mut(key, batch)?;
        target.generation = Some(generation);
        target.address = Some(start);
        target.state = SlotState::Ready(physical);
        Ok(physical)
    }

    /// Closes an exported shareable handle, such as the file descriptor sent with
    /// `SCM_RIGHTS`, dropping the export's hold on the allocation.
    pub fn close_export(
        &mut self,
        driver: &mut dyn VmmDriver,
        export: ExportId,
    ) -> Result<(), VmmError> {
        let record = self
            .exports
            .get(&export)
            .ok_or(VmmError::UnknownExport { export })?;
        let ExportChannel::Shareable { kind, shared, open } = record.channel else {
            return Err(VmmError::WrongExportKind { export });
        };
        if !open {
            return Err(VmmError::ExportClosed { export });
        }
        let (exporter, physical) = (record.exporter, record.physical);
        driver.close_shared(exporter, shared)?;
        if let Some(record) = self.exports.get_mut(&export) {
            record.channel = ExportChannel::Shareable {
                kind,
                shared,
                open: false,
            };
        }
        if let Some(entry) = self.physical.get_mut(&physical) {
            entry.exports.remove(&export);
        }
        Ok(())
    }

    /// Appendix E step 8, producer side: `cudaIpcGetMemHandle` on the artifact's
    /// dedicated `cudaMalloc` allocation, once it is published, fresh CORE-01 evidence
    /// shows legacy CUDA IPC in this runtime, and the runtime profile's loader plan
    /// enabled it ([`Self::set_loader_plan`], INT-06).
    pub fn legacy_export<C: Clock>(
        &mut self,
        driver: &mut dyn VmmDriver,
        evidence: &ProbeRegistry<C>,
        key: MappingKey,
    ) -> Result<ExportId, VmmError> {
        let (backing, slot) = self.active_slot(key, 0)?;
        if !matches!(backing, Backing::Legacy) {
            return Err(VmmError::WrongBacking {
                key,
                operation: "share through legacy IPC memory that is not a dedicated cudaMalloc \
                            allocation",
            });
        }
        let (SlotState::Published(physical), Some(pointer)) = (slot.state, slot.address) else {
            return Err(batch_state(key, 0, slot.state, "export the allocation"));
        };
        let satisfied = require_legacy_ipc(evidence, self.context_of(key.process)?)?;
        self.require_permitted(evidence, key.process, Optimization::CudaIpcLegacy)?;
        let export = ExportId::new(self.allocate_id()?);
        let handle = driver.ipc_get_mem_handle(key.process, pointer)?;
        self.exports.insert(
            export,
            ExportRecord {
                exporter: key.process,
                physical,
                channel: ExportChannel::LegacyIpc { handle },
                evidence: satisfied,
            },
        );
        Ok(export)
    }

    /// Appendix E step 8, consumer side: `cudaIpcOpenMemHandle` in another process of the
    /// same runtime, whose loader plan must enable legacy CUDA IPC too (INT-06). The
    /// container boundary and the handle lifetime are not relied on: the producer's
    /// allocation stays held until every consumer closes it.
    pub fn legacy_open<C: Clock>(
        &mut self,
        driver: &mut dyn VmmDriver,
        evidence: &ProbeRegistry<C>,
        consumer: ProcessId,
        export: ExportId,
    ) -> Result<VirtualAddress, VmmError> {
        let record = self
            .exports
            .get(&export)
            .ok_or(VmmError::UnknownExport { export })?;
        let ExportChannel::LegacyIpc { handle } = record.channel else {
            return Err(VmmError::WrongExportKind { export });
        };
        let (exporter, physical) = (record.exporter, record.physical);
        if consumer == exporter {
            return Err(VmmError::SameProcess { process: consumer });
        }
        self.same_runtime(exporter, consumer)?;
        let entry = self
            .physical
            .get(&physical)
            .ok_or(VmmError::UnknownPhysical { physical })?;
        if entry.freed {
            return Err(VmmError::AlreadyFreed { physical });
        }
        // Only a live handle blocks: one the consumer closed is replaced by the new open.
        if entry.holds_live_handle(consumer) {
            return Err(VmmError::AlreadyImported {
                physical,
                process: consumer,
            });
        }
        let AllocationContents::Dedicated { artifact, batch } = entry.contents else {
            return Err(VmmError::NotDedicated { physical });
        };
        let producer = MappingKey {
            process: exporter,
            artifact,
        };
        if !self.is_published(producer, batch, physical) {
            return Err(VmmError::NotPublished { physical });
        }
        require_legacy_ipc(evidence, self.context_of(consumer)?)?;
        self.require_permitted(evidence, consumer, Optimization::CudaIpcLegacy)?;
        let pointer = driver.ipc_open_mem_handle(consumer, handle)?;
        if let Some(entry) = self.physical.get_mut(&physical) {
            entry.handles.insert(
                consumer,
                HandleEntry::new(DriverHandle::IpcOpened(pointer), pointer),
            );
        }
        Ok(pointer)
    }

    /// Appendix E step 8: the consumer closes its opened mapping
    /// (`cudaIpcCloseMemHandle`), dropping its hold on the producer's allocation.
    pub fn legacy_close(
        &mut self,
        driver: &mut dyn VmmDriver,
        consumer: ProcessId,
        export: ExportId,
    ) -> Result<(), VmmError> {
        let record = self
            .exports
            .get(&export)
            .ok_or(VmmError::UnknownExport { export })?;
        if !matches!(record.channel, ExportChannel::LegacyIpc { .. }) {
            return Err(VmmError::WrongExportKind { export });
        }
        let physical = record.physical;
        let handle = self
            .physical
            .get(&physical)
            .and_then(|entry| entry.handles.get(&consumer))
            .ok_or(VmmError::NoHandle {
                physical,
                process: consumer,
            })?;
        let DriverHandle::IpcOpened(pointer) = handle.driver else {
            return Err(VmmError::NoHandle {
                physical,
                process: consumer,
            });
        };
        self.release_handle(driver, physical, consumer)?;
        self.handle_mut(physical, consumer)?
            .mappings
            .remove(&pointer);
        Ok(())
    }

    /// The CORE-01 evidence that allowed an export.
    pub fn export_evidence(&self, export: ExportId) -> Option<&Satisfied> {
        self.exports.get(&export).map(|record| &record.evidence)
    }

    /// Memory is shared only between processes of one runtime instance: the container or
    /// VM boundary has not been probed, so it is never crossed.
    fn same_runtime(&self, exporter: ProcessId, importer: ProcessId) -> Result<(), VmmError> {
        let exporter_runtime = runtime_identity(&self.context_of(exporter)?.runtime);
        let importer_runtime = runtime_identity(&self.context_of(importer)?.runtime);
        if exporter_runtime != importer_runtime {
            return Err(VmmError::CrossesRuntimeBoundary { exporter, importer });
        }
        Ok(())
    }
}
