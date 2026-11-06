//! The transfer executor (GPU §3.5): construction, submission, cancellation, promotion,
//! retirement and queries. The steps that move bytes are in `pump`.

use std::collections::{BTreeMap, BTreeSet};

use super::backend::{BackendError, EventId, ReadTicket, StagingBuffer, TransferBackend};
use super::config::{pool_bytes, ExecutorConfig};
use super::error::{
    Attempt, AttemptFailure, CancelError, CloseError, ExecutorFault, ExtentFailure, ForgetError,
    JobFailure, MethodUnavailable, PromoteError, RetireError, StartError, SubmitError, Unavailable,
};
use super::job::{
    CancelReason, DependencyId, JobPriority, JobProgress, JobStatus, ProgressSnapshot,
    SubmitOptions, TransferRequest,
};
use super::model::{
    AllocationKey, CopyApi, DirectIo, ExtentId, FlightKey, ManifestExtent, PeerAccessPolicy,
    Priority, ReadMethod, SourceCandidate, SourceKind, StagingPlace,
};
use super::network::NetworkTransfers;
use super::ports::{
    Anomaly, BatchLimits, BatchPort, CatalogPort, EventPort, EvidencePort, NoEvidence,
    ProgressPort, ReservationId, ReservationPort, ReservationPurpose, ReservationRefusal,
    ReservationRequest, ReservedResource, ResolveRequest, StageMeasurement, TransferEvent,
    TransferEventKind,
};
use super::staging::{StagingPool, StagingUsage};
use super::state::{
    slots_needed, CopyInFlight, DependencyState, Flight, FlightId, FlightPhase, FlightState, Job,
    Load, LoadId, ReadInFlight,
};
use super::validate::{aligned_cover, check_destination, check_manifest, shape_job};
use crate::foundation::coordination::RevocationNotice;
use crate::foundation::ids::{
    AuthorizationEpoch, Clock, ContentKey, ExecutionId, GpuDeviceKey, OperationId,
};
use crate::foundation::ledger;
use crate::model_memory::math::calibration::SchedulingMode;
use crate::model_memory::math::prefetch::{PrefetchScheduler, TransferState};
use crate::model_memory::math::SourceId;

/// The prefetch scheduler's cancellation block for jobs (GPU §2.9). The executor itself
/// cancels only between batches and lets every read and copy in flight drain, so each
/// byte count it records is a safe boundary.
const CANCEL_BLOCK_BYTES: u64 = 1;

/// The executor's ports: the backend and the modules it does not own.
pub struct ExecutorPorts {
    pub backend: Box<dyn TransferBackend + Send>,
    pub catalog: Box<dyn CatalogPort + Send>,
    pub batches: Box<dyn BatchPort + Send>,
    pub reservations: Box<dyn ReservationPort + Send>,
    pub events: Box<dyn EventPort + Send>,
}

/// Whether the executor takes work.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lifecycle {
    Running,
    /// A backend contract was broken; nothing starts and no staging is recycled.
    Faulted {
        fault: ExecutorFault,
    },
    Closed,
}

/// What cancelling a job did to the operations it subscribed to.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CancelReport {
    /// Operations that continue for other subscribers.
    pub shared: usize,
    /// Operations reclaimed at once: nothing of theirs was in flight.
    pub reclaimed: usize,
    /// Operations reclaimed once their read or copy in flight drains.
    pub draining: usize,
    /// Operations already delivered; their regions stay until retired.
    pub resident: usize,
}

impl CancelReport {
    fn add(&mut self, other: Self) {
        self.shared += other.shared;
        self.reclaimed += other.reclaimed;
        self.draining += other.draining;
        self.resident += other.resident;
    }
}

/// What propagating a revocation did (INT-02).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RevocationReport {
    /// The execution's jobs that were running, now cancelled.
    pub cancelled: Vec<OperationId>,
    /// What leaving their operations did, over all of them.
    pub operations: CancelReport,
}

/// How a failed operation is tried again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Retry {
    /// Planned again from scratch, on the sources still eligible for it.
    Replan,
    /// In its batch of a live load, which the planner placed on a source again (GPU
    /// §2.5).
    InBatch { load: LoadId, batch: usize },
}

/// One extent report to the progress publisher (P08).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ExtentReport {
    Started,
    Arrived,
    Committed,
    Discarded,
}

/// The transfer executor's portable path (GPU §3.5) as a state machine.
///
/// [`TransferExecutor::submit`] resolves, checks, admits and reserves before anything
/// starts; [`TransferExecutor::pump`] moves the work forward. Time comes from the
/// injected clock.
pub struct TransferExecutor<C: Clock> {
    pub(super) config: ExecutorConfig,
    pub(super) clock: C,
    pub(super) ports: ExecutorPorts,
    /// Where gated read methods are rechecked; [`NoEvidence`] until given the registry.
    pub(super) evidence: Box<dyn EvidencePort + Send>,
    /// Where extent progress goes; nowhere until given the publisher.
    pub(super) progress: Option<Box<dyn ProgressPort + Send>>,
    /// Executions whose authorization was revoked, with the epoch no longer honoured.
    pub(super) revoked: BTreeMap<ExecutionId, AuthorizationEpoch>,
    /// What GPU-peer reads need from CORE-01; without it no GPU peer is read.
    pub(super) peer_access: Option<PeerAccessPolicy>,
    /// Direct I/O for local files, when asked for.
    pub(super) direct_io: Option<DirectIo>,
    /// Stored objects whose source refused a direct read, with the refusal; they are read
    /// buffered from then on.
    pub(super) direct_refused: BTreeMap<(SourceId, ContentKey), BackendError>,
    /// CORE-05 transfers for network sources, when asked for (GPU-W09).
    pub(super) transfers: Option<NetworkTransfers>,
    pub(super) copy_api: CopyApi,
    pub(super) read_methods: BTreeSet<ReadMethod>,
    pub(super) host: StagingPool,
    pub(super) devices: BTreeMap<GpuDeviceKey, StagingPool>,
    pub(super) scheduler: PrefetchScheduler,
    pub(super) jobs: BTreeMap<OperationId, Job>,
    pub(super) flights: BTreeMap<FlightId, Flight>,
    pub(super) keys: BTreeMap<FlightKey, FlightId>,
    /// Occupied destination regions per allocation: start to (end, operation).
    pub(super) regions: BTreeMap<AllocationKey, BTreeMap<u64, (u64, FlightId)>>,
    pub(super) loads: BTreeMap<LoadId, Load>,
    /// Batches dispatched to a source and waiting for staging.
    pub(super) ready: Vec<(LoadId, usize)>,
    pub(super) reads: BTreeMap<ReadTicket, ReadInFlight>,
    pub(super) copies: BTreeMap<EventId, CopyInFlight>,
    /// Operations to plan again after a failed attempt or a source change.
    pub(super) replan: BTreeSet<FlightId>,
    /// Measured read rates, which replace catalog figures in later plans.
    pub(super) observed_rates: BTreeMap<SourceId, f64>,
    pub(super) next_flight: u64,
    pub(super) next_load: u64,
    pub(super) next_sequence: u64,
    pub(super) lifecycle: Lifecycle,
}

impl<C: Clock> TransferExecutor<C> {
    /// Checks the configuration and reserves the host ring and every device staging
    /// pool before anything starts (§3.5 step 2), then marks them in use. A refusal
    /// releases those already made and starts nothing.
    pub fn new(
        config: ExecutorConfig,
        clock: C,
        mut ports: ExecutorPorts,
    ) -> Result<Self, StartError> {
        let copy_api = ports.backend.copy_api();
        let read_methods = ports.backend.read_methods();
        config.validate(&read_methods).map_err(StartError::Config)?;
        let scheduler =
            PrefetchScheduler::new(config.prefetch_budget).map_err(StartError::Prefetch)?;
        let mut wanted = vec![(
            StagingPlace::Host,
            config.host_staging.memory.resource(),
            ReservationPurpose::HostStaging,
            config.host_staging.slots,
            config.host_staging.slot_bytes,
        )];
        for (device, pool) in &config.device_staging {
            wanted.push((
                StagingPlace::Device { device: *device },
                ReservedResource::DeviceMemory { device: *device },
                ReservationPurpose::DeviceStaging { device: *device },
                pool.slots,
                pool.slot_bytes,
            ));
        }
        let mut host = None;
        let mut devices = BTreeMap::new();
        let mut made = Vec::new();
        for (place, resource, purpose, slots, slot_bytes) in wanted {
            let request = ReservationRequest {
                operation: config.operation.clone(),
                execution: None,
                tenant: None,
                priority: Priority::Foreground,
                resource,
                purpose,
                bytes: pool_bytes(slots, slot_bytes).unwrap_or(u64::MAX),
                parent: None,
            };
            let reservation = match ports.reservations.reserve(&request) {
                Ok(reservation) => reservation,
                Err(refusal) => {
                    release_on_start(&mut ports, &config, &clock, &made);
                    return Err(StartError::Reservation(refusal));
                }
            };
            made.push(reservation);
            let pool = StagingPool::new(place, slots, slot_bytes, reservation);
            match place {
                StagingPlace::Host => host = Some(pool),
                StagingPlace::Device { device } => {
                    devices.insert(device, pool);
                }
            }
        }
        for reservation in &made {
            if let Err(lost) = ports.reservations.begin_use(*reservation) {
                release_on_start(&mut ports, &config, &clock, &made);
                return Err(StartError::Reservation(ReservationRefusal::Rejected {
                    reason: lost.to_string(),
                }));
            }
        }
        let host = host.ok_or(StartError::Config(super::error::ConfigError::NoSlots {
            place: StagingPlace::Host,
        }))?;
        Ok(Self {
            config,
            clock,
            ports,
            evidence: Box::new(NoEvidence),
            progress: None,
            revoked: BTreeMap::new(),
            peer_access: None,
            direct_io: None,
            direct_refused: BTreeMap::new(),
            transfers: None,
            copy_api,
            read_methods,
            host,
            devices,
            scheduler,
            jobs: BTreeMap::new(),
            flights: BTreeMap::new(),
            keys: BTreeMap::new(),
            regions: BTreeMap::new(),
            loads: BTreeMap::new(),
            ready: Vec::new(),
            reads: BTreeMap::new(),
            copies: BTreeMap::new(),
            replan: BTreeSet::new(),
            observed_rates: BTreeMap::new(),
            next_flight: 0,
            next_load: 0,
            next_sequence: 0,
            lifecycle: Lifecycle::Running,
        })
    }

    /// Rechecks gated read methods in `evidence`, the live registry the loader plans were
    /// made with (CORE-01, INT-06). Without it no gated method is ever used.
    pub fn with_evidence(mut self, evidence: Box<dyn EvidencePort + Send>) -> Self {
        self.evidence = evidence;
        self
    }

    /// Reports extent progress of every job to `progress` (P08, §3.10 line 650).
    pub fn with_progress(mut self, progress: Box<dyn ProgressPort + Send>) -> Self {
        self.progress = Some(progress);
        self
    }

    /// Reads GPU peers where CORE-01 evidence in the registry ([`Self::with_evidence`])
    /// shows peer access for the exact direction under `policy` (FAST-02: probed, never
    /// assumed). Without a policy no GPU peer is read.
    pub fn with_peer_access(mut self, policy: PeerAccessPolicy) -> Self {
        self.peer_access = Some(policy);
        self
    }

    /// Replaces the GPU-peer policy, such as after the GPU configuration changed; `None`
    /// stops GPU-peer reads that have not started.
    pub fn set_peer_access(&mut self, policy: Option<PeerAccessPolicy>) {
        self.peer_access = policy;
    }

    /// Reads local files with direct I/O where the backend implements it and a read is
    /// aligned to the block, and buffered otherwise, reporting why (GPU-W04, GPU-T20).
    pub fn with_direct_io(mut self, direct: DirectIo) -> Self {
        self.direct_io = Some(direct);
        self
    }

    /// Admits one job (§3.5 steps 1–3): resolves the verified manifest, checks it with
    /// the dependencies and the destination, admits the job under the prefetch budget,
    /// reserves the destination of every new operation, then coalesces and plans the
    /// new extents onto sources. Extents another job already moves into the same region
    /// in the same representation join that operation. Any refusal undoes what this
    /// call did; reads start only in [`TransferExecutor::pump`]. Destination
    /// reservations charge host capacity; see [`Self::submit_within`].
    pub fn submit(&mut self, request: TransferRequest) -> Result<(), SubmitError> {
        self.submit_with(request, SubmitOptions::default())
    }

    /// [`Self::submit`], with each new destination reservation carved from `parent`, the
    /// placement's reservation of the destination (P04; CORE-03 parent and child), so
    /// the destination's memory is never counted twice. The ledger refuses a child whose
    /// execution, tenant or priority differs from its parent's, or that does not fit the
    /// parent's room.
    pub fn submit_within(
        &mut self,
        request: TransferRequest,
        parent: ledger::ReservationId,
    ) -> Result<(), SubmitError> {
        self.submit_with(
            request,
            SubmitOptions {
                within: Some(parent),
                ..SubmitOptions::default()
            },
        )
    }

    /// [`Self::submit`] with `options`: destinations carved from a parent reservation, as
    /// [`Self::submit_within`] does, and CORE-05 grants for the job's network sources
    /// (GPU-W09, [`Self::with_transfers`]). Where the executor reads through transfers, a
    /// remote store or authorized peer is a source of the job only with a grant bound to
    /// this executor, this job and that source; each grant is checked before anything is
    /// reserved and opened, reserving its byte budget and network slot, after everything
    /// else, and a refusal undoes the submission.
    pub fn submit_with(
        &mut self,
        request: TransferRequest,
        options: SubmitOptions,
    ) -> Result<(), SubmitError> {
        self.admit(request, options)
    }

    fn admit(
        &mut self,
        request: TransferRequest,
        options: SubmitOptions,
    ) -> Result<(), SubmitError> {
        let SubmitOptions {
            within: parent,
            transfers: grants,
        } = options;
        self.available().map_err(SubmitError::Unavailable)?;
        let operation = request.operation.clone();
        if self.jobs.contains_key(&operation) || operation == self.config.operation {
            return Err(SubmitError::DuplicateOperation { operation });
        }
        if let Some(revoked) = self.revoked.get(&request.execution) {
            return Err(SubmitError::ExecutionRevoked {
                execution: request.execution.clone(),
                revoked: *revoked,
            });
        }
        let resolve_started = self.clock.now();
        let manifest = self
            .ports
            .catalog
            .resolve(&ResolveRequest {
                execution: request.execution.clone(),
                tenant: request.tenant.clone(),
                artifact: request.artifact,
                representation: request.representation,
            })
            .map_err(SubmitError::Catalog)?;
        let resolved_at = self.clock.now();
        check_manifest(&request, &manifest).map_err(SubmitError::Manifest)?;
        let shape = shape_job(&request.dependencies, &manifest).map_err(SubmitError::Dependency)?;
        check_destination(&request.destination, &shape.needed)?;
        let decodes = shape
            .needed
            .iter()
            .any(|extent| extent.stored.needs_decode());
        let allocation = request.destination.allocation;
        let limits = self.batch_limits(allocation.device, manifest.object_length_bytes);
        self.check_staging_fit(&shape.needed, &limits, decodes)?;
        let required = self.check_required_method(&request, decodes)?;
        // Where reads cross the network only through CORE-05, a network source without
        // a grant is no source of the job (GPU-W09).
        let sessions_required = self.transfers.is_some();
        let granted: BTreeSet<&SourceId> = grants.iter().map(|grant| &grant.source).collect();
        let mut usable = Vec::new();
        for candidate in &manifest.sources {
            if candidate.kind.is_read_source()
                && (required.is_none() || candidate.kind == SourceKind::LocalFile)
                && self.path_possible(candidate.kind, allocation.device, decodes)
                && (!sessions_required
                    || !candidate.kind.is_network()
                    || granted.contains(&candidate.spec.id))
            {
                usable.push(candidate.clone());
            }
        }
        self.check_grants(
            &request,
            manifest.representation,
            &shape.needed,
            &usable,
            &grants,
        )?;
        if usable.is_empty() {
            return Err(match required {
                Some(method) => SubmitError::RequiredMethodUnavailable {
                    method,
                    reason: MethodUnavailable::WrongSource,
                },
                None => SubmitError::NoReadableSource,
            });
        }

        let mut joins: Vec<(u64, FlightId)> = Vec::new();
        let mut creates: Vec<(FlightKey, ManifestExtent)> = Vec::new();
        for extent in &shape.needed {
            let index = extent.index;
            let offset_bytes = request
                .destination
                .base_offset_bytes
                .checked_add(extent.decoded_offset_bytes)
                .ok_or(SubmitError::DestinationOutOfBounds { index })?;
            let key = FlightKey {
                extent: ExtentId {
                    artifact: request.artifact,
                    index,
                },
                representation: request.representation,
                allocation,
                offset_bytes,
            };
            if let Some(flight_id) = self.keys.get(&key).copied() {
                let Some(flight) = self.flights.get(&flight_id) else {
                    return Err(SubmitError::ManifestMismatch { index });
                };
                if flight.extent != *extent
                    || flight.object_length_bytes != manifest.object_length_bytes
                {
                    return Err(SubmitError::ManifestMismatch { index });
                }
                // A delivered region is read no more, so only its manifest entry matters.
                if flight.state != FlightState::Delivered {
                    let compatible = flight.subscribers.iter().all(|operation| {
                        self.jobs
                            .get(operation)
                            .is_some_and(|job| job.loader.compatible_with(&request.loader))
                    });
                    if !compatible {
                        return Err(SubmitError::LoaderConflict { index });
                    }
                    if !self.shares_source(flight, &usable) {
                        return Err(SubmitError::NoCommonSource { index });
                    }
                }
                joins.push((index, flight_id));
            } else {
                if self.region_taken(&allocation, offset_bytes, extent.decoded_length_bytes) {
                    return Err(SubmitError::DestinationConflict { index });
                }
                creates.push((key, *extent));
            }
        }
        let total_bytes = shape.needed.iter().fold(0u64, |total, extent| {
            total.saturating_add(extent.decoded_length_bytes)
        });

        let admitted = match &request.priority {
            JobPriority::Foreground => {
                self.scheduler
                    .start_demand(operation.clone(), total_bytes, CANCEL_BLOCK_BYTES)
            }
            JobPriority::Speculative { value } => {
                if value.bytes != total_bytes {
                    return Err(SubmitError::SpeculativeBytesMismatch {
                        value_bytes: value.bytes,
                        job_bytes: total_bytes,
                    });
                }
                self.scheduler
                    .start_speculative(operation.clone(), value, CANCEL_BLOCK_BYTES)
            }
        };
        admitted.map_err(SubmitError::Admission)?;

        let reserve_started = self.clock.now();
        let mut reserved = Vec::with_capacity(creates.len());
        for (key, extent) in &creates {
            let reservation = ReservationRequest {
                operation: operation.clone(),
                execution: Some(request.execution.clone()),
                tenant: Some(request.tenant.clone()),
                priority: request.priority.priority(),
                resource: ReservedResource::DeviceMemory {
                    device: allocation.device,
                },
                purpose: ReservationPurpose::Destination { key: *key },
                bytes: extent.decoded_length_bytes,
                parent,
            };
            match self.ports.reservations.reserve(&reservation) {
                Ok(id) => reserved.push(id),
                Err(refusal) => {
                    self.abandon_submission(&operation, reserved);
                    return Err(SubmitError::Reservation(refusal));
                }
            }
        }
        let reserved_at = self.clock.now();

        let flight_ids: Vec<FlightId> = creates.iter().map(|_| self.allocate_flight()).collect();
        let members: Vec<(FlightId, ManifestExtent)> = flight_ids
            .iter()
            .copied()
            .zip(creates.iter().map(|(_, extent)| *extent))
            .collect();
        let load = if members.is_empty() {
            None
        } else {
            match self.build_load(super::planning::LoadInput {
                artifact: request.artifact,
                representation: manifest.representation,
                allocation,
                members: &members,
                sources: &usable,
                cuts: &manifest.cuts,
                limits,
            }) {
                Ok(load) => Some(load),
                Err(failure) => {
                    self.abandon_submission(&operation, reserved);
                    return Err(SubmitError::Plan(failure));
                }
            }
        };
        let coalesced_at = self.clock.now();
        // The regions now belong to this transfer: from here their amounts count until
        // the host observes their release.
        for reservation in &reserved {
            if let Err(lost) = self.ports.reservations.begin_use(*reservation) {
                self.abandon_submission(&operation, reserved);
                return Err(SubmitError::Reservation(ReservationRefusal::Rejected {
                    reason: lost.to_string(),
                }));
            }
        }
        // Last, the grants open: each reserves its byte budget and network slot, and a
        // replayed or refused envelope undoes the submission (CORE-05, GPU-W09).
        let transfers = match self.open_grants(
            &request.tenant,
            &request.execution,
            manifest.representation,
            grants,
        ) {
            Ok(transfers) => transfers,
            Err(refused) => {
                self.abandon_submission(&operation, reserved);
                return Err(refused);
            }
        };

        let mut job_flights = BTreeMap::new();
        for (((key, extent), flight_id), reservation) in
            creates.iter().zip(flight_ids.iter()).zip(reserved.iter())
        {
            self.flights.insert(
                *flight_id,
                Flight {
                    key: *key,
                    extent: *extent,
                    object_length_bytes: manifest.object_length_bytes,
                    subscribers: BTreeSet::from([operation.clone()]),
                    reservation: Some(*reservation),
                    state: FlightState::Unplanned,
                    attempts: Vec::new(),
                },
            );
            self.keys.insert(*key, *flight_id);
            self.regions.entry(allocation).or_default().insert(
                key.offset_bytes,
                (
                    key.offset_bytes.saturating_add(extent.decoded_length_bytes),
                    *flight_id,
                ),
            );
            job_flights.insert(extent.index, *flight_id);
        }
        if let Some(load) = load {
            self.register_load(load);
        }
        let mut delivered = Vec::new();
        for (index, flight_id) in &joins {
            job_flights.insert(*index, *flight_id);
            if let Some(flight) = self.flights.get_mut(flight_id) {
                flight.subscribers.insert(operation.clone());
                if flight.state == FlightState::Delivered {
                    delivered.push((*index, flight.extent.decoded_length_bytes));
                }
            }
        }

        let mut progress = JobProgress {
            snapshot: ProgressSnapshot {
                total_bytes,
                total_dependencies: shape.ordered.len(),
                ..ProgressSnapshot::default()
            },
            ..JobProgress::default()
        };
        let new_bytes = creates.iter().fold(0u64, |total, (_, extent)| {
            total.saturating_add(extent.decoded_length_bytes)
        });
        let stages = [
            (
                super::model::Stage::Resolve,
                0,
                resolve_started,
                resolved_at,
            ),
            (
                super::model::Stage::Reserve,
                new_bytes,
                reserve_started,
                reserved_at,
            ),
            (
                super::model::Stage::Coalesce,
                new_bytes,
                reserved_at,
                coalesced_at,
            ),
        ];
        for (stage, bytes, started, finished) in stages {
            progress.add_stage(stage, bytes, finished.saturating_duration_since(started));
        }
        self.jobs.insert(
            operation.clone(),
            Job {
                execution: request.execution,
                priority: request.priority.priority(),
                destination: request.destination,
                loader: request.loader,
                sources: usable,
                cuts: manifest.cuts.clone(),
                blacklist: BTreeSet::new(),
                dependencies: shape
                    .ordered
                    .iter()
                    .map(|dependency| DependencyState {
                        id: dependency.id,
                        extents: dependency.extents.clone(),
                        requires: dependency.requires.clone(),
                        usable: false,
                    })
                    .collect(),
                flights: job_flights,
                committed: BTreeSet::new(),
                status: JobStatus::Running,
                progress,
                progress_dirty: true,
                sessions_required,
                transfers,
            },
        );
        for (index, bytes) in delivered {
            self.commit_extent(&operation, index, bytes);
        }
        self.emit(
            &operation,
            TransferEventKind::Submitted {
                total_bytes,
                new_operations: creates.len(),
                shared_operations: joins.len(),
            },
        );
        for (stage, bytes, started, finished) in stages {
            self.emit(
                &operation,
                TransferEventKind::StageMeasured(StageMeasurement {
                    stage,
                    bytes,
                    started_at: started,
                    duration: finished.saturating_duration_since(started),
                    path: None,
                    method: None,
                    api: None,
                    source: None,
                }),
            );
        }
        Ok(())
    }

    /// Cancels a running job (§3.5). Its operations that other jobs subscribe to
    /// continue untouched; the rest are reclaimed at once when nothing of theirs is in
    /// flight, or once their read or copy drains. Delivered regions stay until retired.
    pub fn cancel(&mut self, operation: &OperationId) -> Result<CancelReport, CancelError> {
        self.available().map_err(CancelError::Unavailable)?;
        let job = self
            .jobs
            .get_mut(operation)
            .ok_or_else(|| CancelError::UnknownJob {
                operation: operation.clone(),
            })?;
        if !job.status.is_running() {
            return Err(CancelError::NotRunning {
                operation: operation.clone(),
            });
        }
        Ok(self.cancel_job(operation, CancelReason::Requested))
    }

    /// Propagates a revocation into running jobs (INT-02; VM part §6.3 steps 1–2):
    /// every running job of the revoked execution is cancelled as [`Self::cancel`]
    /// cancels one, so its operations that other jobs share continue and the rest are
    /// reclaimed at once or once their read or copy drains, and nothing more is
    /// admitted for the execution. It applies whatever the executor's state, since a
    /// revocation reaches every path. Revoking again cancels nothing more.
    pub fn cancel_execution(&mut self, notice: &RevocationNotice) -> RevocationReport {
        let revoked = *self
            .revoked
            .entry(notice.execution.clone())
            .or_insert(notice.revoked);
        let running: Vec<OperationId> = self
            .jobs
            .iter()
            .filter(|(_, job)| job.execution == notice.execution && job.status.is_running())
            .map(|(operation, _)| operation.clone())
            .collect();
        let mut report = RevocationReport::default();
        for operation in running {
            let left = self.cancel_job(&operation, CancelReason::Revoked { revoked });
            report.operations.add(left);
            report.cancelled.push(operation);
        }
        report
    }

    /// Whether the execution's authorization was revoked, and at which epoch.
    pub fn revoked(&self, execution: &ExecutionId) -> Option<AuthorizationEpoch> {
        self.revoked.get(execution).copied()
    }

    /// Cancels a running job at a safe boundary: it leaves the prefetch scheduler and
    /// every operation it subscribes to, and its CORE-05 sessions end.
    pub(super) fn cancel_job(
        &mut self,
        operation: &OperationId,
        reason: CancelReason,
    ) -> CancelReport {
        if let Some(job) = self.jobs.get_mut(operation) {
            job.status = JobStatus::Cancelled { reason };
        }
        self.drop_from_scheduler(operation);
        self.close_transfers(operation, false);
        let report = self.unsubscribe_all(operation);
        self.emit(operation, TransferEventKind::Cancelled { reason });
        report
    }

    /// Turns a speculative job into foreground work in place (GPU §2.9, §3.5): the same
    /// operations, reads and copies continue with raised priority, and the prefetch
    /// scheduler keeps the same transfer. A finished speculative job's bytes count as
    /// used.
    pub fn promote(&mut self, operation: &OperationId) -> Result<(), PromoteError> {
        self.available().map_err(PromoteError::Unavailable)?;
        let job = self
            .jobs
            .get(operation)
            .ok_or_else(|| PromoteError::UnknownJob {
                operation: operation.clone(),
            })?;
        if job.priority == Priority::Foreground {
            return Err(PromoteError::NotSpeculative {
                operation: operation.clone(),
            });
        }
        let completed = match job.status {
            JobStatus::Running => false,
            JobStatus::Completed => true,
            JobStatus::Failed { .. } | JobStatus::Cancelled { .. } => {
                return Err(PromoteError::Finished {
                    operation: operation.clone(),
                })
            }
        };
        self.scheduler
            .promote(operation)
            .map_err(PromoteError::Scheduler)?;
        if let Some(job) = self.jobs.get_mut(operation) {
            job.priority = Priority::Foreground;
        }
        if completed {
            if let Err(error) = self.scheduler.release(operation) {
                self.anomaly(Anomaly::SchedulerRefused {
                    operation: operation.clone(),
                    error,
                });
            }
        }
        self.emit(operation, TransferEventKind::Promoted);
        Ok(())
    }

    /// Applies a scheduling mode from the demand-only controller (GPU §2.9). Entering
    /// demand-only cancels every running speculative job at a safe boundary; their
    /// operations that foreground jobs share continue. Returns the cancelled jobs.
    pub fn set_scheduling_mode(
        &mut self,
        mode: SchedulingMode,
    ) -> Result<Vec<OperationId>, Unavailable> {
        self.available()?;
        let mut cancelled = Vec::new();
        for (operation, _) in self.scheduler.set_mode(mode) {
            if !self
                .jobs
                .get(&operation)
                .is_some_and(|job| job.status.is_running())
            {
                continue;
            }
            self.cancel_job(&operation, CancelReason::DemandOnly);
            cancelled.push(operation);
        }
        Ok(cancelled)
    }

    /// Forgets a finished job and takes it off every operation it still subscribes to,
    /// so no later job is held to its loader plan or sources. A completed speculative
    /// job's bytes, never used, are dropped from the speculative budget.
    pub fn forget(&mut self, operation: &OperationId) -> Result<(), ForgetError> {
        let job = self
            .jobs
            .get(operation)
            .ok_or_else(|| ForgetError::UnknownJob {
                operation: operation.clone(),
            })?;
        if job.status.is_running() {
            return Err(ForgetError::StillRunning {
                operation: operation.clone(),
            });
        }
        self.drop_from_scheduler(operation);
        self.unsubscribe_all(operation);
        self.jobs.remove(operation);
        Ok(())
    }

    /// Forgets the delivered regions of an allocation the placement no longer uses, such
    /// as after eviction or reallocation, so later jobs transfer them again instead of
    /// joining stale data. Their reservations went back when they were delivered.
    /// Refused while a running job or an undelivered operation targets the allocation.
    /// Returns how many regions were forgotten.
    pub fn retire_destination(&mut self, allocation: &AllocationKey) -> Result<usize, RetireError> {
        self.available().map_err(RetireError::Unavailable)?;
        let busy_job = self
            .jobs
            .values()
            .any(|job| job.status.is_running() && job.destination.allocation == *allocation);
        let flights: Vec<FlightId> = self
            .flights
            .iter()
            .filter(|(_, flight)| flight.key.allocation == *allocation)
            .map(|(id, _)| *id)
            .collect();
        let busy_flight = flights.iter().any(|id| {
            self.flights
                .get(id)
                .is_some_and(|flight| flight.state != FlightState::Delivered)
        });
        if busy_job || busy_flight {
            return Err(RetireError::InUse {
                allocation: *allocation,
            });
        }
        for id in &flights {
            self.remove_flight(*id);
        }
        Ok(flights.len())
    }

    /// Releases the staging pools and stops taking work. Refused while anything is
    /// known or in flight, and after a fault, when staging may still be in use.
    pub fn close(&mut self) -> Result<(), CloseError> {
        match &self.lifecycle {
            Lifecycle::Closed => return Err(CloseError::AlreadyClosed),
            Lifecycle::Faulted { fault } => {
                return Err(CloseError::Faulted {
                    fault: fault.clone(),
                })
            }
            Lifecycle::Running => {}
        }
        let busy = self.jobs.values().any(|job| job.status.is_running())
            || !self.flights.is_empty()
            || !self.reads.is_empty()
            || !self.copies.is_empty();
        if busy {
            return Err(CloseError::Busy);
        }
        let mut reservations = vec![self.host.reservation()];
        reservations.extend(self.devices.values().map(StagingPool::reservation));
        for reservation in reservations {
            self.release_reservation(reservation);
        }
        self.lifecycle = Lifecycle::Closed;
        Ok(())
    }

    /// Whether the executor takes work, stopped after a fault, or is closed.
    pub fn lifecycle(&self) -> &Lifecycle {
        &self.lifecycle
    }

    /// The copy API the backend uses.
    pub fn copy_api(&self) -> CopyApi {
        self.copy_api
    }

    /// Where a job is; `None` for a job never submitted or already forgotten.
    pub fn status(&self, operation: &OperationId) -> Option<&JobStatus> {
        self.jobs.get(operation).map(|job| &job.status)
    }

    /// A job's progress and measured stage totals (§3.5 step 9).
    pub fn progress(&self, operation: &OperationId) -> Option<&JobProgress> {
        self.jobs.get(operation).map(|job| &job.progress)
    }

    /// Whether the dependency was published as usable.
    pub fn is_usable(&self, operation: &OperationId, dependency: DependencyId) -> bool {
        self.jobs.get(operation).is_some_and(|job| {
            job.dependencies
                .iter()
                .any(|state| state.id == dependency && state.usable)
        })
    }

    /// Sources the job no longer uses because they failed it.
    pub fn blacklist(&self, operation: &OperationId) -> Option<&BTreeSet<SourceId>> {
        self.jobs.get(operation).map(|job| &job.blacklist)
    }

    /// The operation that moves one of the job's extents.
    pub fn flight_of(&self, operation: &OperationId, extent: u64) -> Option<FlightId> {
        self.jobs
            .get(operation)
            .and_then(|job| job.flights.get(&extent).copied())
    }

    /// Where a shared operation is; `None` once it is reclaimed, given up or retired.
    pub fn flight_phase(&self, flight: FlightId) -> Option<FlightPhase> {
        let state = self.flights.get(&flight)?.state;
        Some(match state {
            FlightState::Unplanned => FlightPhase::Queued,
            FlightState::Planned { load, batch } => {
                let ready = self
                    .loads
                    .get(&load)
                    .and_then(|load| load.batches.get(batch))
                    .is_some_and(|batch| {
                        matches!(batch.state, super::state::BatchState::Ready { .. })
                    });
                if ready {
                    FlightPhase::Ready
                } else {
                    FlightPhase::Queued
                }
            }
            FlightState::Reading => FlightPhase::Reading,
            FlightState::Copying => FlightPhase::Copying,
            FlightState::Delivered => FlightPhase::Delivered,
        })
    }

    /// How many jobs subscribe to the operation.
    pub fn subscribers(&self, flight: FlightId) -> Option<usize> {
        self.flights
            .get(&flight)
            .map(|flight| flight.subscribers.len())
    }

    /// Every failed attempt at the operation's extent.
    pub fn attempts(&self, flight: FlightId) -> Option<&[Attempt]> {
        self.flights
            .get(&flight)
            .map(|flight| flight.attempts.as_slice())
    }

    /// How a staging pool is used; `None` for a GPU without a pool.
    pub fn staging_usage(&self, place: StagingPlace) -> Option<StagingUsage> {
        self.pool(place).map(StagingPool::usage)
    }

    /// The prefetch scheduler's view of the jobs (GPU §2.9).
    pub fn scheduler(&self) -> &PrefetchScheduler {
        &self.scheduler
    }

    /// True when nothing is queued, planned or in flight.
    pub fn is_idle(&self) -> bool {
        self.reads.is_empty()
            && self.copies.is_empty()
            && self.ready.is_empty()
            && self.replan.is_empty()
            && self.loads.is_empty()
    }

    pub(super) fn available(&self) -> Result<(), Unavailable> {
        match &self.lifecycle {
            Lifecycle::Running => Ok(()),
            Lifecycle::Closed => Err(Unavailable::Closed),
            Lifecycle::Faulted { fault } => Err(Unavailable::Faulted {
                fault: fault.clone(),
            }),
        }
    }

    pub(super) fn emit(&mut self, operation: &OperationId, kind: TransferEventKind) {
        self.next_sequence = self.next_sequence.saturating_add(1);
        let event = TransferEvent {
            sequence: self.next_sequence,
            at: self.clock.now(),
            operation: operation.clone(),
            kind,
        };
        self.ports.events.emit(event);
    }

    pub(super) fn anomaly(&mut self, anomaly: Anomaly) {
        let operation = self.config.operation.clone();
        self.emit(&operation, TransferEventKind::Anomaly(anomaly));
    }

    pub(super) fn release_reservation(&mut self, reservation: ReservationId) {
        if self.ports.reservations.release(reservation).is_err() {
            self.anomaly(Anomaly::ReleaseRefused { reservation });
        }
    }

    /// Hands a delivered destination's reservation over to the reservation it was carved
    /// from ([`ReservationPort::hand_over`]).
    pub(super) fn hand_over_reservation(&mut self, reservation: ReservationId) {
        if self.ports.reservations.hand_over(reservation).is_err() {
            self.anomaly(Anomaly::ReleaseRefused { reservation });
        }
    }

    pub(super) fn pool(&self, place: StagingPlace) -> Option<&StagingPool> {
        match place {
            StagingPlace::Host => Some(&self.host),
            StagingPlace::Device { device } => self.devices.get(&device),
        }
    }

    pub(super) fn pool_mut(&mut self, place: StagingPlace) -> Option<&mut StagingPool> {
        match place {
            StagingPlace::Host => Some(&mut self.host),
            StagingPlace::Device { device } => self.devices.get_mut(&device),
        }
    }

    /// Adds a holder to a staging slot: a consumer whose completion is not yet observed.
    pub(super) fn hold(&mut self, buffer: StagingBuffer) -> Result<(), ExecutorFault> {
        self.pool_mut(buffer.place)
            .ok_or(ExecutorFault::StagingMisuse { buffer })?
            .hold(buffer.slot)
            .map_err(|_| ExecutorFault::StagingMisuse { buffer })
    }

    /// Drops one holder of a staging slot; the slot is recycled when none remain.
    pub(super) fn let_go(&mut self, buffer: StagingBuffer) -> Result<(), ExecutorFault> {
        self.pool_mut(buffer.place)
            .ok_or(ExecutorFault::StagingMisuse { buffer })?
            .let_go(buffer.slot)
            .map(|_| ())
            .map_err(|_| ExecutorFault::StagingMisuse { buffer })
    }

    /// Batch limits for a destination GPU: one slot of the host ring and, where the GPU
    /// has a staging pool, of that pool too, so a batch fits any path.
    pub(super) fn batch_limits(
        &self,
        device: GpuDeviceKey,
        object_length_bytes: u64,
    ) -> BatchLimits {
        let slot_bytes = self
            .devices
            .get(&device)
            .map_or(self.host.slot_bytes(), |pool| {
                pool.slot_bytes().min(self.host.slot_bytes())
            });
        BatchLimits {
            alignment_bytes: self.config.alignment_bytes,
            max_read_bytes: slot_bytes,
            max_decoded_bytes: slot_bytes,
            object_length_bytes,
        }
    }

    fn check_staging_fit(
        &self,
        needed: &[ManifestExtent],
        limits: &BatchLimits,
        decodes: bool,
    ) -> Result<(), SubmitError> {
        let needed_slots = slots_needed(decodes);
        if self.host.slots() < needed_slots {
            return Err(SubmitError::StagingTooSmall {
                place: StagingPlace::Host,
                slots: self.host.slots(),
                needed_slots,
            });
        }
        for extent in needed {
            let index = extent.index;
            let read_bytes = aligned_cover(
                extent.stored_offset_bytes,
                extent.stored_length_bytes,
                limits.alignment_bytes,
            )
            .map_or(u64::MAX, |(_, length)| length);
            if read_bytes > limits.max_read_bytes {
                return Err(SubmitError::ExtentExceedsStaging {
                    index,
                    needed_bytes: read_bytes,
                    limit_bytes: limits.max_read_bytes,
                });
            }
            if extent.decode_bytes() > limits.max_decoded_bytes {
                return Err(SubmitError::ExtentExceedsStaging {
                    index,
                    needed_bytes: extent.decode_bytes(),
                    limit_bytes: limits.max_decoded_bytes,
                });
            }
        }
        Ok(())
    }

    /// A gated method the request requires must be usable now: implemented, with a
    /// device staging pool for GPUDirect Storage, on CUDA when it is a CUDA mechanism,
    /// and with its plan's evidence still holding in the registry; two required methods
    /// cannot both read the same bytes. Returns the required method.
    fn check_required_method(
        &self,
        request: &TransferRequest,
        decodes: bool,
    ) -> Result<Option<ReadMethod>, SubmitError> {
        let mut required = request.loader.required().into_iter();
        let Some(method) = required.next() else {
            return Ok(None);
        };
        let device_fits = self
            .devices
            .get(&request.destination.allocation.device)
            .is_some_and(|pool| pool.slots() >= slots_needed(decodes));
        let refusal = if let Some(other) = required.next() {
            Some(MethodUnavailable::ConflictsWith { other })
        } else if !self.read_methods.contains(&method) {
            Some(MethodUnavailable::NotImplemented)
        } else if method == ReadMethod::GpuDirectStorage && !device_fits {
            Some(MethodUnavailable::NoDeviceStaging)
        } else {
            request.loader.unavailable(method, &*self.evidence)
        };
        match refusal {
            Some(reason) => Err(SubmitError::RequiredMethodUnavailable { method, reason }),
            None => Ok(Some(method)),
        }
    }

    /// Whether a source of this kind can be read into this GPU at all. A GPU peer is
    /// used only where the GPU has device staging and CORE-01 evidence shows peer access
    /// for the exact direction now ([`Self::peer_access_holds`]).
    pub(super) fn path_possible(
        &self,
        kind: SourceKind,
        device: GpuDeviceKey,
        decodes: bool,
    ) -> bool {
        match kind {
            SourceKind::LocalFile => true,
            SourceKind::Remote | SourceKind::AuthorizedPeer => {
                self.read_methods.contains(&ReadMethod::RangeRequest)
            }
            SourceKind::GpuPeer { device: from } => {
                let fits = self
                    .devices
                    .get(&device)
                    .is_some_and(|pool| pool.slots() >= slots_needed(decodes));
                fits && self.read_methods.contains(&ReadMethod::PeerCopy)
                    && self.peer_access_holds(from, device)
            }
            SourceKind::ImportOnlyBind => false,
        }
    }

    /// Whether fresh CORE-01 evidence shows that `from` can copy into `to` (FAST-02:
    /// probed, never assumed): `GpuPeerAccess` for exactly that direction on one machine,
    /// within the peer policy. Without a policy or evidence, no.
    pub(super) fn peer_access_holds(&self, from: GpuDeviceKey, to: GpuDeviceKey) -> bool {
        self.peer_access
            .and_then(|policy| policy.requirement(from, to))
            .is_some_and(|requirement| self.evidence.evaluate(&requirement).is_ok())
    }

    /// Whether a new job could read `flight` from a source its current subscribers may
    /// all use and none has blacklisted.
    fn shares_source(&self, flight: &Flight, usable: &[SourceCandidate]) -> bool {
        usable
            .iter()
            .any(|candidate| self.source_allowed_for(flight, &candidate.spec.id, candidate.kind))
    }

    /// Whether every subscriber of `flight` may read it from `source`
    /// ([`Job::allows`]).
    pub(super) fn source_allowed_for(
        &self,
        flight: &Flight,
        source: &SourceId,
        kind: SourceKind,
    ) -> bool {
        flight.subscribers.iter().all(|operation| {
            self.jobs
                .get(operation)
                .is_some_and(|job| job.allows(source, kind))
        })
    }

    fn region_taken(
        &self,
        allocation: &AllocationKey,
        offset_bytes: u64,
        length_bytes: u64,
    ) -> bool {
        let Some(regions) = self.regions.get(allocation) else {
            return false;
        };
        let end = offset_bytes.saturating_add(length_bytes);
        regions
            .range(..end)
            .next_back()
            .is_some_and(|(_, (region_end, _))| *region_end > offset_bytes)
    }

    fn allocate_flight(&mut self) -> FlightId {
        self.next_flight = self.next_flight.saturating_add(1);
        FlightId(self.next_flight)
    }

    pub(super) fn register_load(&mut self, load: Load) -> LoadId {
        self.next_load = self.next_load.saturating_add(1);
        let id = LoadId(self.next_load);
        for (batch_index, batch) in load.batches.iter().enumerate() {
            for member in &batch.members {
                if let Some(flight) = self.flights.get_mut(member) {
                    flight.state = FlightState::Planned {
                        load: id,
                        batch: batch_index,
                    };
                }
            }
        }
        self.loads.insert(id, load);
        id
    }

    /// Undoes a submission's admission and reservations.
    fn abandon_submission(&mut self, operation: &OperationId, reserved: Vec<ReservationId>) {
        for reservation in reserved {
            self.release_reservation(reservation);
        }
        self.drop_from_scheduler(operation);
    }

    /// Removes a job from the prefetch scheduler, whatever its state there.
    pub(super) fn drop_from_scheduler(&mut self, operation: &OperationId) {
        let result = match self
            .scheduler
            .transfer(operation)
            .map(|transfer| transfer.state())
        {
            None => return,
            Some(TransferState::Complete) => self.scheduler.release(operation),
            Some(TransferState::Running | TransferState::CancelRequested) => {
                self.scheduler.request_cancel(operation).map(|_| ())
            }
        };
        if let Err(error) = result {
            self.anomaly(Anomaly::SchedulerRefused {
                operation: operation.clone(),
                error,
            });
        }
    }

    /// Removes an operation and releases its region.
    pub(super) fn remove_flight(&mut self, id: FlightId) {
        let Some(flight) = self.flights.remove(&id) else {
            return;
        };
        if self.keys.get(&flight.key) == Some(&id) {
            self.keys.remove(&flight.key);
        }
        if let Some(regions) = self.regions.get_mut(&flight.key.allocation) {
            if regions
                .get(&flight.key.offset_bytes)
                .is_some_and(|(_, owner)| *owner == id)
            {
                regions.remove(&flight.key.offset_bytes);
            }
            if regions.is_empty() {
                self.regions.remove(&flight.key.allocation);
            }
        }
        self.replan.remove(&id);
        if let Some(reservation) = flight.reservation {
            self.release_reservation(reservation);
        }
    }

    /// Takes a job off every operation it subscribes to (§3.5): one subscriber leaving
    /// never cancels another's work, and the last one leaving permits reclamation.
    pub(super) fn unsubscribe_all(&mut self, operation: &OperationId) -> CancelReport {
        let mut report = CancelReport::default();
        let flights: BTreeSet<FlightId> = self
            .jobs
            .get(operation)
            .map(|job| job.flights.values().copied().collect())
            .unwrap_or_default();
        for id in flights {
            let Some(flight) = self.flights.get_mut(&id) else {
                continue;
            };
            if !flight.subscribers.remove(operation) {
                continue;
            }
            if !flight.subscribers.is_empty() {
                report.shared += 1;
                continue;
            }
            match flight.state {
                FlightState::Unplanned | FlightState::Planned { .. } => {
                    self.remove_flight(id);
                    report.reclaimed += 1;
                }
                FlightState::Reading | FlightState::Copying => report.draining += 1,
                FlightState::Delivered => report.resident += 1,
            }
        }
        report
    }

    /// Records an extent's chain as complete for one job.
    pub(super) fn commit_extent(&mut self, operation: &OperationId, index: u64, bytes: u64) {
        let Some(job) = self.jobs.get_mut(operation) else {
            return;
        };
        if !job.status.is_running() || !job.committed.insert(index) {
            return;
        }
        job.progress.snapshot.committed_bytes =
            job.progress.snapshot.committed_bytes.saturating_add(bytes);
        job.progress_dirty = true;
        let verified = job
            .flights
            .get(&index)
            .and_then(|flight| self.flights.get(flight))
            .map(|flight| (flight.key.representation, flight.extent));
        if let Some((object, extent)) = verified {
            self.record_verified(operation, object, &extent);
        }
        if let Err(error) = self.scheduler.record_progress(operation, bytes) {
            self.anomaly(Anomaly::SchedulerRefused {
                operation: operation.clone(),
                error,
            });
        }
        self.report_extent(
            std::slice::from_ref(operation),
            index,
            bytes,
            ExtentReport::Committed,
        );
    }

    /// Reports one extent of `length_bytes` decoded bytes to the progress publisher for
    /// each of `operations` (P08). A commit first reports the extent arrived, which
    /// changes nothing when it did, so a job that joined after the read still counts
    /// it. A refusal is reported as an anomaly and the transfer goes on.
    pub(super) fn report_extent(
        &mut self,
        operations: &[OperationId],
        index: u64,
        length_bytes: u64,
        report: ExtentReport,
    ) {
        let Some(progress) = self.progress.as_mut() else {
            return;
        };
        let mut refused = Vec::new();
        for operation in operations {
            let reported = match report {
                ExtentReport::Started => progress.extent_started(operation, index, length_bytes),
                ExtentReport::Arrived => progress.extent_arrived(operation, index, length_bytes),
                ExtentReport::Committed => progress
                    .extent_arrived(operation, index, length_bytes)
                    .and_then(|()| progress.extent_committed(operation, index)),
                ExtentReport::Discarded => progress.extent_discarded(operation, index),
            };
            if let Err(error) = reported {
                refused.push(Anomaly::ProgressRefused {
                    operation: operation.clone(),
                    extent: index,
                    error,
                });
            }
        }
        for anomaly in refused {
            self.anomaly(anomaly);
        }
    }

    /// Reports one extent of a shared operation for each of its subscribers.
    pub(super) fn report_flight(&mut self, id: FlightId, report: ExtentReport) {
        if self.progress.is_none() {
            return;
        }
        let Some(flight) = self.flights.get(&id) else {
            return;
        };
        let subscribers: Vec<OperationId> = flight.subscribers.iter().cloned().collect();
        let (index, length_bytes) = (flight.extent.index, flight.extent.decoded_length_bytes);
        self.report_extent(&subscribers, index, length_bytes, report);
    }

    /// Adds a measured stage to a job and emits it (§3.5 step 9).
    pub(super) fn record_stage(&mut self, operation: &OperationId, measurement: StageMeasurement) {
        let Some(job) = self.jobs.get_mut(operation) else {
            return;
        };
        if !job.status.is_running() {
            return;
        }
        job.progress
            .add_stage(measurement.stage, measurement.bytes, measurement.duration);
        self.emit(operation, TransferEventKind::StageMeasured(measurement));
    }

    /// Records a failed attempt (§3.5) and plans the operation again from scratch.
    pub(super) fn attempt_failed(
        &mut self,
        id: FlightId,
        source: Option<SourceId>,
        failure: AttemptFailure,
    ) {
        self.attempt_failed_in(id, source, failure, Retry::Replan);
    }

    /// Records a failed attempt (§3.5). A source at fault is blacklisted for every job
    /// the operation serves; the operation is retried as `retry` says until its attempts
    /// run out, and a mismatching extent is never used.
    pub(super) fn attempt_failed_in(
        &mut self,
        id: FlightId,
        source: Option<SourceId>,
        failure: AttemptFailure,
        retry: Retry,
    ) {
        let max_attempts = self.config.max_attempts as usize;
        self.report_flight(id, ExtentReport::Discarded);
        let Some(flight) = self.flights.get_mut(&id) else {
            return;
        };
        let number = u32::try_from(flight.attempts.len().saturating_add(1)).unwrap_or(u32::MAX);
        flight.attempts.push(Attempt {
            number,
            source: source.clone(),
            failure: failure.clone(),
        });
        let subscribers: Vec<OperationId> = flight.subscribers.iter().cloned().collect();
        let index = flight.key.extent.index;
        let attempts = flight.attempts.clone();
        for operation in &subscribers {
            self.emit(
                operation,
                TransferEventKind::AttemptFailed {
                    extent: index,
                    attempt: number,
                    source: source.clone(),
                    failure: failure.clone(),
                },
            );
        }
        if let (true, Some(source)) = (failure.is_source_fault(), source) {
            for operation in &subscribers {
                let newly = self
                    .jobs
                    .get_mut(operation)
                    .is_some_and(|job| job.blacklist.insert(source.clone()));
                if newly {
                    self.emit(
                        operation,
                        TransferEventKind::SourceBlacklisted {
                            source: source.clone(),
                        },
                    );
                    // A blacklisted network source moves no more of the job's bytes.
                    self.end_transfer(operation, &source);
                }
            }
        }
        if subscribers.is_empty() {
            self.remove_flight(id);
        } else if failure.is_permanent() {
            self.fail_flight(id, ExtentFailure::Permanent { attempts });
        } else if attempts.len() >= max_attempts {
            self.fail_flight(id, ExtentFailure::RetriesExhausted { attempts });
        } else if let Some(flight) = self.flights.get_mut(&id) {
            match retry {
                Retry::Replan => {
                    flight.state = FlightState::Unplanned;
                    self.replan.insert(id);
                }
                Retry::InBatch { load, batch } => {
                    flight.state = FlightState::Planned { load, batch };
                }
            }
        }
    }

    /// Gives an operation up and fails every job it serves.
    pub(super) fn fail_flight(&mut self, id: FlightId, failure: ExtentFailure) {
        let Some(flight) = self.flights.get(&id) else {
            return;
        };
        let subscribers: Vec<OperationId> = flight.subscribers.iter().cloned().collect();
        let extent = flight.key.extent.index;
        self.remove_flight(id);
        for operation in subscribers {
            self.fail_job(
                &operation,
                JobFailure {
                    extent,
                    failure: failure.clone(),
                },
            );
        }
    }

    /// Fails one subscriber of a shared operation whose required read method this read
    /// cannot use; the others keep the operation (§3.5: one subscriber never fails
    /// another's work). The operation's attempts are not charged, so their retries stay.
    pub(super) fn shed_requirer(
        &mut self,
        operation: &OperationId,
        id: FlightId,
        method: ReadMethod,
        reason: MethodUnavailable,
    ) {
        let Some(flight) = self.flights.get(&id) else {
            return;
        };
        let extent = flight.key.extent.index;
        let mut attempts = flight.attempts.clone();
        let number = u32::try_from(attempts.len().saturating_add(1)).unwrap_or(u32::MAX);
        let failure = AttemptFailure::RequiredMethodUnavailable { method, reason };
        attempts.push(Attempt {
            number,
            source: None,
            failure: failure.clone(),
        });
        self.emit(
            operation,
            TransferEventKind::AttemptFailed {
                extent,
                attempt: number,
                source: None,
                failure,
            },
        );
        self.fail_job(
            operation,
            JobFailure {
                extent,
                failure: ExtentFailure::Permanent { attempts },
            },
        );
    }

    /// Fails one subscriber of a shared operation that no usable source serves on its
    /// own; the others keep the operation (§3.5).
    pub(super) fn strand_subscriber(&mut self, operation: &OperationId, id: FlightId) {
        let Some(flight) = self.flights.get(&id) else {
            return;
        };
        let extent = flight.key.extent.index;
        let attempts = flight.attempts.clone();
        self.fail_job(
            operation,
            JobFailure {
                extent,
                failure: ExtentFailure::NoEligibleSource { attempts },
            },
        );
    }

    fn fail_job(&mut self, operation: &OperationId, failure: JobFailure) {
        let Some(job) = self.jobs.get_mut(operation) else {
            return;
        };
        if !job.status.is_running() {
            return;
        }
        job.status = JobStatus::Failed {
            failure: failure.clone(),
        };
        self.drop_from_scheduler(operation);
        self.close_transfers(operation, false);
        self.unsubscribe_all(operation);
        self.emit(operation, TransferEventKind::Failed { failure });
    }
}

/// Releases the staging reservations of an executor that could not start; a release the
/// ledger refuses is reported as an anomaly.
fn release_on_start<C: Clock>(
    ports: &mut ExecutorPorts,
    config: &ExecutorConfig,
    clock: &C,
    made: &[ReservationId],
) {
    let unreleased: Vec<ReservationId> = made
        .iter()
        .copied()
        .filter(|reservation| ports.reservations.release(*reservation).is_err())
        .collect();
    for (sequence, reservation) in (1..).zip(unreleased) {
        ports.events.emit(TransferEvent {
            sequence,
            at: clock.now(),
            operation: config.operation.clone(),
            kind: TransferEventKind::Anomaly(Anomaly::ReleaseRefused { reservation }),
        });
    }
}
