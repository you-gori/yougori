//! Boundary 3 over P03's portable path ([`crate::model_memory::executor`], GPU §3.5).
//!
//! [`PortableExecutor`] turns one [`TransferOrder`] into one P03 job per stored object the
//! order reads, named by the content keys the catalog store names them by
//! ([`StoredExtent`]): the artifact's sidecar and the source file. Every extent is its own
//! dependency, so each is usable as soon as its whole chain has completed (§3.5 step 7),
//! which is what lets loading overlap reconstruction and computation (GPU §1 path 3).
//! Each job writes into the GPU allocation the activation holds for its extents
//! ([`TransferDestination`]): weights into their own holding, other state into the
//! activation's own memory. Each destination gets one region per stored object, and the
//! job's destination reservations are carved from that allocation's own ledger
//! reservation ([`submit_within`](Portable::submit_within)), so the memory is never
//! counted twice.
//!
//! The adapter chooses nothing: it passes P03 exactly the order's objects, and P03
//! resolves their verified manifest through its catalog port and refuses any source that
//! is never a read source (Appendix A.3). A completion reports the content key the order
//! expected: P03 has checked the decoded bytes against the manifest of the sidecar the
//! order names by content key, which is the sidecar the catalog read that key from, so a
//! mismatch is a failure, never a delivery. Bytes read are the extent's true length per
//! attempt, retries included, and the source is the kind of the source P03's own read
//! stages report for the job, observed through its event port.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use super::catalog::{ExtentRef, StoredExtent};
use super::executor::{
    ExtentCompletion, TransferExecutor, TransferFailure, TransferOrder, TransferRefusal,
    TransferTicket,
};
use super::governor::TransferDestination;
use crate::foundation::ids::{
    Clock, ContentKey, Digest, DigestBuilder, GpuAllocationGeneration, GpuDeviceKey, OperationId,
};
use crate::foundation::ledger::ReservationId;
use crate::model_memory::executor::{
    AllocationKey, AttemptFailure, DependencyId, DependencySpec, Destination, EventPort,
    ExecutorConfig, ExecutorPorts, FlightPhase, JobFailure, JobPriority, JobStatus,
    LoaderPermissions, PumpReport, RetireError, SourceKind, Stage, StartError, TransferEvent,
    TransferEventKind, TransferExecutor as Portable, TransferRequest,
};
use crate::model_memory::math::SourceId;

/// The most pump passes one wait or one cancellation takes before the executor is
/// reported stalled.
pub const MAX_PUMPS: usize = 4_096;

/// Digest domain of the allocation digest a destination is named by in P03.
pub const ALLOCATION_DOMAIN: &str = "yougori/model-memory/boundaries/allocation/v1";

/// Digest domain of the operation each P03 job of an order runs under.
pub const JOB_DOMAIN: &str = "yougori/model-memory/boundaries/transfer-job/v1";

/// P03's name for the allocation of generation `allocation` on `device`.
pub fn allocation_key(device: GpuDeviceKey, allocation: GpuAllocationGeneration) -> AllocationKey {
    AllocationKey {
        device,
        allocation: allocation_digest(device, allocation),
        generation: allocation,
    }
}

fn allocation_digest(device: GpuDeviceKey, allocation: GpuAllocationGeneration) -> Digest {
    DigestBuilder::new(ALLOCATION_DOMAIN)
        .digest(&device.machine)
        .digest(&device.device)
        .u64(allocation.get())
        .finish()
}

/// The sources each job's read stages reported, in order.
#[derive(Clone, Default)]
struct ReadLog(Arc<Mutex<BTreeMap<OperationId, Vec<SourceId>>>>);

impl ReadLog {
    fn lock(&self) -> MutexGuard<'_, BTreeMap<OperationId, Vec<SourceId>>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// P03's event port, with every read stage noted on the way.
struct Tee {
    inner: Box<dyn EventPort + Send>,
    reads: ReadLog,
}

impl EventPort for Tee {
    fn emit(&mut self, event: TransferEvent) {
        if let TransferEventKind::StageMeasured(measurement) = &event.kind {
            if let (Stage::Read, Some(source)) = (measurement.stage, &measurement.source) {
                self.reads
                    .lock()
                    .entry(event.operation.clone())
                    .or_default()
                    .push(source.clone());
            }
        }
        self.inner.emit(event);
    }
}

/// One ordered extent in its P03 job.
#[derive(Clone)]
struct Delivery {
    operation: OperationId,
    dependency: DependencyId,
    index: u64,
    length_bytes: u64,
    digest: ContentKey,
}

/// One submitted order: its jobs and where each extent is in them.
struct Submitted {
    jobs: Vec<OperationId>,
    extents: BTreeMap<ExtentRef, Delivery>,
    delivered: BTreeSet<ExtentRef>,
}

/// One stored object an order reads, with its region in the allocation.
struct Region {
    destination: TransferDestination,
    artifact: ContentKey,
    representation: ContentKey,
    members: Vec<(ExtentRef, StoredExtent, u64, ContentKey)>,
    base_offset_bytes: u64,
    capacity_bytes: u64,
}

/// The stored objects one destination receives, each with its members.
type DestinationObjects = (
    TransferDestination,
    BTreeMap<(ContentKey, ContentKey), Vec<(ExtentRef, StoredExtent, u64, ContentKey)>>,
);

/// The transfer-executor boundary over P03's portable path.
pub struct PortableExecutor<C: Clock> {
    executor: Portable<C>,
    clock: C,
    reads: ReadLog,
    kinds: BTreeMap<SourceId, SourceKind>,
    orders: BTreeMap<TransferTicket, Submitted>,
    next: u64,
}

impl<C: Clock + Clone> PortableExecutor<C> {
    /// Starts P03's executor with `config` over `ports`, noting its read stages. `kinds`
    /// are the kinds of the sources the catalog port offers.
    pub fn start(
        config: ExecutorConfig,
        clock: C,
        ports: ExecutorPorts,
        kinds: BTreeMap<SourceId, SourceKind>,
    ) -> Result<Self, StartError> {
        let reads = ReadLog::default();
        let ExecutorPorts {
            backend,
            catalog,
            batches,
            reservations,
            events,
        } = ports;
        let executor = Portable::new(
            config,
            clock.clone(),
            ExecutorPorts {
                backend,
                catalog,
                batches,
                reservations,
                events: Box::new(Tee {
                    inner: events,
                    reads: reads.clone(),
                }),
            },
        )?;
        Ok(Self {
            executor,
            clock,
            reads,
            kinds,
            orders: BTreeMap::new(),
            next: 1,
        })
    }

    /// P03's executor, for its status, progress and staging.
    pub fn portable(&self) -> &Portable<C> {
        &self.executor
    }

    /// Forgets the regions delivered into `destination` on `device` once the placement's
    /// memory is reclaimed, so a later order transfers them again (P03).
    pub fn retire(
        &mut self,
        device: GpuDeviceKey,
        destination: TransferDestination,
    ) -> Result<usize, RetireError> {
        self.executor
            .retire_destination(&allocation_key(device, destination.allocation))
    }

    /// The operation of job `number` of the order `ticket` under `operation`.
    fn job(operation: &OperationId, ticket: TransferTicket, number: u64) -> OperationId {
        let digest = DigestBuilder::new(JOB_DOMAIN)
            .str(operation.as_str())
            .u64(ticket.get())
            .u64(number)
            .finish();
        OperationId::new(format!("xfer-{}", digest.to_hex()))
            .unwrap_or_else(|_| OperationId::generate())
    }

    /// The stored objects `order` reads, by destination: each with its region in the
    /// destination's allocation, in content-key order, laid out from the allocation's
    /// start. A destination too small for its regions refuses the order.
    fn regions(order: &TransferOrder) -> Result<Vec<Region>, TransferRefusal> {
        let mut grouped: BTreeMap<(GpuAllocationGeneration, ReservationId), DestinationObjects> =
            BTreeMap::new();
        for ordered in order.extents() {
            let stored = ordered.stored.ok_or(TransferRefusal::NotStored {
                extent: ordered.extent,
            })?;
            let destination = order
                .destination_of(&ordered.extent)
                .ok_or(TransferRefusal::NoDestination)?;
            grouped
                .entry((destination.allocation, destination.reservation))
                .or_insert_with(|| (destination, BTreeMap::new()))
                .1
                .entry((stored.artifact, stored.representation))
                .or_default()
                .push((ordered.extent, stored, ordered.length_bytes, ordered.digest));
        }
        let overflow = || TransferRefusal::Rejected {
            reason: "the order's regions do not fit in 64 bits".to_owned(),
        };
        let mut regions = Vec::new();
        for (destination, objects) in grouped.into_values() {
            let mut base_offset_bytes = 0u64;
            for ((artifact, representation), members) in objects {
                let capacity_bytes = members
                    .iter()
                    .map(|(_, stored, length, _)| stored.offset_bytes.checked_add(*length))
                    .try_fold(0u64, |end, member| member.map(|member| end.max(member)))
                    .ok_or_else(overflow)?;
                regions.push(Region {
                    destination,
                    artifact,
                    representation,
                    members,
                    base_offset_bytes,
                    capacity_bytes,
                });
                base_offset_bytes = base_offset_bytes
                    .checked_add(capacity_bytes)
                    .ok_or_else(overflow)?;
            }
            if base_offset_bytes > destination.capacity_bytes {
                return Err(TransferRefusal::Rejected {
                    reason: format!(
                        "the order needs {base_offset_bytes} bytes of a destination, which \
                         holds {}",
                        destination.capacity_bytes
                    ),
                });
            }
        }
        Ok(regions)
    }

    /// Cancels `jobs` and lets their reads and copies in flight drain, then forgets them.
    fn withdraw(&mut self, jobs: &[OperationId], extents: &BTreeMap<ExtentRef, Delivery>) {
        for operation in jobs {
            let _cancelled = self.executor.cancel(operation);
        }
        for _ in 0..MAX_PUMPS {
            let draining = extents.values().any(|delivery| {
                self.executor
                    .flight_of(&delivery.operation, delivery.index)
                    .and_then(|flight| self.executor.flight_phase(flight))
                    .is_some_and(|phase| {
                        matches!(phase, FlightPhase::Reading | FlightPhase::Copying)
                    })
            });
            if !draining || self.executor.pump().is_err() {
                break;
            }
        }
        let mut reads = self.reads.lock();
        for operation in jobs {
            let _forgotten = self.executor.forget(operation);
            reads.remove(operation);
        }
    }

    /// The completion of a delivered extent.
    fn completion(
        &mut self,
        ticket: TransferTicket,
        extent: ExtentRef,
        delivery: &Delivery,
    ) -> Result<ExtentCompletion, TransferFailure> {
        let failed_attempts = self
            .executor
            .flight_of(&delivery.operation, delivery.index)
            .and_then(|flight| self.executor.attempts(flight))
            .map_or(0, <[_]>::len) as u64;
        let bytes_read = delivery
            .length_bytes
            .checked_mul(failed_attempts.saturating_add(1))
            .ok_or_else(|| TransferFailure::Failed {
                extent,
                reason: "the bytes read do not fit in 64 bits".to_owned(),
            })?;
        let source = self
            .reads
            .lock()
            .get(&delivery.operation)
            .and_then(|sources| sources.last())
            .and_then(|source| self.kinds.get(source))
            .copied()
            .ok_or_else(|| TransferFailure::Failed {
                extent,
                reason: "no read of this order from a known source was observed".to_owned(),
            })?;
        let (job_done, order_done) = match self.orders.get_mut(&ticket) {
            Some(order) => {
                order.delivered.insert(extent);
                let job_done = order
                    .extents
                    .iter()
                    .filter(|(_, other)| other.operation == delivery.operation)
                    .all(|(other, _)| order.delivered.contains(other));
                (job_done, order.delivered.len() == order.extents.len())
            }
            None => (false, false),
        };
        // A job whose every extent was delivered is forgotten, and an order whose every
        // job was, with it.
        if job_done
            && self.executor.status(&delivery.operation) == Some(&JobStatus::Completed)
            && self.executor.forget(&delivery.operation).is_ok()
        {
            self.reads.lock().remove(&delivery.operation);
        }
        if order_done {
            self.orders.remove(&ticket);
        }
        Ok(ExtentCompletion {
            extent,
            verified_digest: delivery.digest,
            bytes_read,
            source,
            completed_at: self.clock.now(),
        })
    }
}

/// A failed job, as the boundary reports it for one of its extents: a mismatch of the
/// extent's stored or decoded digest is a hash mismatch, anything else a failure.
fn job_failure(extent: ExtentRef, index: u64, failure: &JobFailure) -> TransferFailure {
    if failure.extent == index {
        let last = failure
            .failure
            .attempts()
            .last()
            .map(|attempt| &attempt.failure);
        match last {
            Some(AttemptFailure::DecodedMismatch { expected, found }) => {
                return TransferFailure::HashMismatch {
                    extent,
                    expected: *expected,
                    actual: *found,
                };
            }
            Some(AttemptFailure::StoredMismatch { expected, found }) => {
                return TransferFailure::HashMismatch {
                    extent,
                    expected: ContentKey::from_digest(*expected),
                    actual: ContentKey::from_digest(*found),
                };
            }
            _ => {}
        }
    }
    TransferFailure::Failed {
        extent,
        reason: failure.to_string(),
    }
}

impl<C: Clock + Clone> TransferExecutor for PortableExecutor<C> {
    fn submit(&mut self, order: &TransferOrder) -> Result<TransferTicket, TransferRefusal> {
        let regions = Self::regions(order)?;
        let ticket = TransferTicket::new(self.next);
        self.next = self.next.saturating_add(1);
        let mut submitted = Submitted {
            jobs: Vec::new(),
            extents: BTreeMap::new(),
            delivered: BTreeSet::new(),
        };
        for (region, number) in regions.into_iter().zip(0u64..) {
            let operation = Self::job(order.operation(), ticket, number);
            let allocation = allocation_key(order.recipient(), region.destination.allocation);
            let request = TransferRequest {
                operation: operation.clone(),
                execution: order.execution().clone(),
                tenant: order.tenant().clone(),
                artifact: region.artifact,
                representation: region.representation,
                destination: Destination {
                    allocation,
                    base_offset_bytes: region.base_offset_bytes,
                    capacity_bytes: region.capacity_bytes,
                },
                dependencies: region
                    .members
                    .iter()
                    .zip(0u64..)
                    .map(|((_, stored, _, _), id)| DependencySpec {
                        id: DependencyId(id),
                        extents: vec![stored.index],
                        requires: Vec::new(),
                    })
                    .collect(),
                priority: JobPriority::Foreground,
                loader: LoaderPermissions::ordinary(),
            };
            if let Err(error) = self
                .executor
                .submit_within(request, region.destination.reservation)
            {
                self.withdraw(&submitted.jobs, &submitted.extents);
                return Err(TransferRefusal::Rejected {
                    reason: error.to_string(),
                });
            }
            for ((extent, stored, length_bytes, digest), id) in
                region.members.into_iter().zip(0u64..)
            {
                submitted.extents.insert(
                    extent,
                    Delivery {
                        operation: operation.clone(),
                        dependency: DependencyId(id),
                        index: stored.index,
                        length_bytes,
                        digest,
                    },
                );
            }
            submitted.jobs.push(operation);
        }
        self.orders.insert(ticket, submitted);
        Ok(ticket)
    }

    fn await_extent(
        &mut self,
        ticket: TransferTicket,
        extent: &ExtentRef,
    ) -> Result<ExtentCompletion, TransferFailure> {
        let delivery = self
            .orders
            .get(&ticket)
            .ok_or(TransferFailure::UnknownTicket { ticket })?
            .extents
            .get(extent)
            .cloned()
            .ok_or(TransferFailure::NotOrdered { extent: *extent })?;
        for _ in 0..MAX_PUMPS {
            if self
                .executor
                .is_usable(&delivery.operation, delivery.dependency)
            {
                return self.completion(ticket, *extent, &delivery);
            }
            match self.executor.status(&delivery.operation) {
                None => return Err(TransferFailure::UnknownTicket { ticket }),
                Some(JobStatus::Failed { failure }) => {
                    return Err(job_failure(*extent, delivery.index, failure));
                }
                Some(JobStatus::Cancelled { .. }) => return Err(TransferFailure::Cancelled),
                Some(JobStatus::Running | JobStatus::Completed) => {}
            }
            let report = self
                .executor
                .pump()
                .map_err(|error| TransferFailure::Failed {
                    extent: *extent,
                    reason: error.to_string(),
                })?;
            if report == PumpReport::default() && self.executor.is_idle() {
                break;
            }
        }
        if self
            .executor
            .is_usable(&delivery.operation, delivery.dependency)
        {
            return self.completion(ticket, *extent, &delivery);
        }
        Err(TransferFailure::Stalled { extent: *extent })
    }

    fn cancel(&mut self, ticket: TransferTicket) {
        if let Some(order) = self.orders.remove(&ticket) {
            self.withdraw(&order.jobs, &order.extents);
        }
    }
}
