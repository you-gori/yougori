//! One pass of the executor (GPU §3.5 steps 4–9): observe finished copies and reads;
//! verify, decode and validate each extent; enqueue copies with completion events;
//! publish dependencies whose whole chain completed; plan retries; start reads within
//! the staging bounds; and report progress.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use super::backend::{
    BackendError, BackendErrorKind, CopyRequest, DecodeRequest, DestinationRange, EventId,
    EventStatus, ReadRequest, ReadStatus, ReadTicket, StagedRange,
};
use super::error::{
    AttemptFailure, DirectIoUnavailable, ExecutorFault, ExtentFailure, Unavailable,
};
use super::job::{DependencyId, JobStatus};
use super::machine::{ExtentReport, Lifecycle, Retry, TransferExecutor};
use super::model::{
    AllocationKey, DirectIo, ManifestExtent, Priority, ReadMethod, SourceCandidate, SourceKind,
    Stage, StoredForm,
};
use super::network::ChunkAdmission;
use super::planning::{LoadInput, Route};
use super::ports::{Anomaly, StageMeasurement, TransferEventKind};
use super::staging::StagingPool;
use super::state::{
    slots_needed, BatchState, CopyInFlight, Flight, FlightId, FlightState, LoadId, ReadInFlight,
};
use crate::foundation::ids::{Clock, ContentKey, MonotonicTime, OperationId};
use crate::foundation::transfer::{ByteRange, ChunkPermit, TransferRefusal};
use crate::model_memory::math::bounds::BandwidthRating;
use crate::model_memory::math::sources::{
    BatchStatus as PlannedStatus, MultiSourceLoad, SharedSourceCaps, SourcesError,
};
use crate::model_memory::math::SourceId;

/// What one pass did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PumpReport {
    pub reads_started: usize,
    pub reads_finished: usize,
    pub copies_enqueued: usize,
    /// Copies whose completion event was observed.
    pub copies_finished: usize,
    /// Dependencies published as usable in this pass.
    pub published: Vec<(OperationId, DependencyId)>,
    /// Operations reclaimed after their last subscriber left.
    pub reclaimed: usize,
    /// Reads whose batch the planner took back from their source, which was excluded
    /// from the load: their bytes were discarded, never used (GPU §2.5).
    pub reads_discarded: usize,
}

enum Start {
    Started,
    /// No staging slot is free; the batch stays ready.
    Waiting,
    Dropped,
}

/// Sums one stage over the extents of a batch.
struct StageClock {
    stage: Stage,
    count: u64,
    bytes: u64,
    started_at: Option<MonotonicTime>,
    duration: Duration,
}

impl StageClock {
    fn new(stage: Stage) -> Self {
        Self {
            stage,
            count: 0,
            bytes: 0,
            started_at: None,
            duration: Duration::ZERO,
        }
    }

    fn add(&mut self, bytes: u64, started: MonotonicTime, finished: MonotonicTime) {
        self.count += 1;
        self.bytes = self.bytes.saturating_add(bytes);
        self.started_at.get_or_insert(started);
        self.duration = self
            .duration
            .saturating_add(finished.saturating_duration_since(started));
    }

    fn measurement(&self, read: &ReadInFlight) -> Option<StageMeasurement> {
        Some(StageMeasurement {
            stage: self.stage,
            bytes: self.bytes,
            started_at: self.started_at?,
            duration: self.duration,
            path: Some(read.path),
            method: Some(read.method),
            api: None,
            source: Some(read.source.clone()),
        })
    }
}

impl<C: Clock> TransferExecutor<C> {
    /// Runs one pass. A broken backend contract stops the executor: it starts nothing
    /// new and recycles no staging from then on.
    pub fn pump(&mut self) -> Result<PumpReport, Unavailable> {
        self.available()?;
        let mut report = PumpReport::default();
        if let Err(fault) = self.pass(&mut report) {
            self.lifecycle = Lifecycle::Faulted {
                fault: fault.clone(),
            };
            return Err(Unavailable::Faulted { fault });
        }
        Ok(report)
    }

    fn pass(&mut self, report: &mut PumpReport) -> Result<(), ExecutorFault> {
        self.poll_transfers();
        self.poll_copies(report)?;
        self.poll_reads(report)?;
        self.publish(report);
        self.plan_retries();
        self.dispatch_loads();
        self.start_reads(report)?;
        self.loads.retain(|_, load| {
            load.batches
                .iter()
                .any(|batch| batch.state != BatchState::Done)
        });
        self.report_progress();
        Ok(())
    }

    /// Steps 7–8: a finished copy commits its extent, and its staging slot is let go
    /// only now that its completion event was observed.
    fn poll_copies(&mut self, report: &mut PumpReport) -> Result<(), ExecutorFault> {
        let events: Vec<EventId> = self.copies.keys().copied().collect();
        for event in events {
            let status = self
                .ports
                .backend
                .query_event(event)
                .map_err(|error| ExecutorFault::EventQueryFailed { event, error })?;
            let succeeded = match status {
                EventStatus::Pending => continue,
                EventStatus::Complete => true,
                EventStatus::Failed => false,
            };
            let Some(copy) = self.copies.remove(&event) else {
                continue;
            };
            if let Err(error) = self.ports.backend.release_event(event) {
                self.anomaly(Anomaly::EventReleaseFailed { event, error });
            }
            self.let_go(copy.buffer)?;
            report.copies_finished += 1;
            self.finish_copy(copy, succeeded, report);
        }
        Ok(())
    }

    fn finish_copy(&mut self, copy: CopyInFlight, succeeded: bool, report: &mut PumpReport) {
        let now = self.clock.now();
        let Some(flight) = self.flights.get(&copy.flight) else {
            return;
        };
        if flight.subscribers.is_empty() {
            self.remove_flight(copy.flight);
            report.reclaimed += 1;
            return;
        }
        if !succeeded {
            self.attempt_failed(copy.flight, Some(copy.source), AttemptFailure::CopyFailed);
            return;
        }
        let subscribers: Vec<OperationId> = flight.subscribers.iter().cloned().collect();
        let index = flight.key.extent.index;
        let mut delivered = None;
        if let Some(flight) = self.flights.get_mut(&copy.flight) {
            flight.state = FlightState::Delivered;
            delivered = flight.reservation.take();
        }
        // The transfer of this extent is complete and its region belongs to whatever it
        // was carved from: a child reservation goes back to its parent at once, a
        // host-level one counts until the host observes its release (T15).
        if let Some(reservation) = delivered {
            self.hand_over_reservation(reservation);
        }
        let measurement = StageMeasurement {
            stage: Stage::Copy,
            bytes: copy.bytes,
            started_at: copy.enqueued_at,
            duration: now.saturating_duration_since(copy.enqueued_at),
            path: Some(copy.path),
            method: None,
            api: Some(self.copy_api),
            source: Some(copy.source),
        };
        for operation in &subscribers {
            self.record_stage(operation, measurement.clone());
            self.commit_extent(operation, index, copy.bytes);
        }
    }

    /// Step 4 ends: a finished read is checked against the planner and processed, and a
    /// failed one fails its batch on its source. The path a backend reports is the one
    /// recorded (GPU-T21). A late report from a source the batch has left, since the
    /// source was excluded from the load, is refused by the planner (`complete_from`) and
    /// its bytes are discarded (GPU §2.5).
    fn poll_reads(&mut self, report: &mut PumpReport) -> Result<(), ExecutorFault> {
        let tickets: Vec<ReadTicket> = self.reads.keys().copied().collect();
        for ticket in tickets {
            let outcome = match self.ports.backend.poll_read(ticket) {
                Ok(ReadStatus::Pending) => continue,
                Ok(ReadStatus::Complete { bytes_read }) => Ok((bytes_read, None)),
                Ok(ReadStatus::Served { bytes_read, path }) => Ok((bytes_read, Some(path))),
                Err(error) => Err(error),
            };
            let Some(mut read) = self.reads.remove(&ticket) else {
                continue;
            };
            report.reads_finished += 1;
            let duration = self.clock.now().saturating_duration_since(read.started_at);
            match outcome {
                Ok((bytes_read, _)) if bytes_read > read.read_length_bytes => {
                    return Err(ExecutorFault::ReadOverrun {
                        ticket,
                        requested_bytes: read.read_length_bytes,
                        reported_bytes: bytes_read,
                    });
                }
                Ok((_, Some(served))) if !served.serves(read.path) => {
                    return Err(ExecutorFault::PathNotRequested {
                        ticket,
                        requested: read.path,
                        reported: served,
                    });
                }
                Ok((bytes_read, served)) => {
                    if let Some(served) = served {
                        read.path = served;
                    }
                    if !read.permits.is_empty() {
                        let permits = std::mem::take(&mut read.permits);
                        if !self.in_flight_on(read.load, read.batch, &read.source) {
                            // The bytes moved, so the sessions take the chunk, which never
                            // stays in flight; the batch was taken back, so none is used.
                            self.deliver_chunk(&read.source, permits);
                            self.discard_read(&read, report)?;
                            continue;
                        }
                        let (accepted, refusal) = self.deliver_chunk(&read.source, permits);
                        if accepted == 0 {
                            // No session took the chunk, so none of its bytes is used: the
                            // batch is read again, counted as a failure (GPU-W09).
                            self.discard_read(&read, report)?;
                            let live = self.live_members(&read.members, report);
                            let failure = refusal.map_or_else(
                                || AttemptFailure::ChunkRefused {
                                    refusal: TransferRefusal::UnknownChunk,
                                },
                                |refusal| AttemptFailure::ChunkRefused { refusal },
                            );
                            self.batch_failed(read.load, read.batch, &read.source, &live, failure);
                            continue;
                        }
                    }
                    if !self.finish_batch_in_load(read.load, read.batch, &read.source) {
                        self.discard_read(&read, report)?;
                        continue;
                    }
                    let measurement = read_measurement(&read, bytes_read, duration);
                    self.record_batch_stage(&read.members, measurement);
                    self.observe_rate(&read.source, bytes_read, duration);
                    self.process_batch(read, bytes_read, report)?;
                }
                Err(error) => {
                    // A failed network read interrupts its sessions even when its batch
                    // was taken back, so no admitted chunk stays in flight.
                    let permits = std::mem::take(&mut read.permits);
                    let failure = self.read_failure(&read.source, permits, error);
                    if !self.in_flight_on(read.load, read.batch, &read.source) {
                        self.discard_read(&read, report)?;
                        continue;
                    }
                    let measurement = read_measurement(&read, 0, duration);
                    self.record_batch_stage(&read.members, measurement);
                    self.let_go(read.read_slot)?;
                    if let Some(slot) = read.decode_slot {
                        self.let_go(slot)?;
                    }
                    let live = self.live_members(&read.members, report);
                    self.batch_failed(read.load, read.batch, &read.source, &live, failure);
                }
            }
        }
        Ok(())
    }

    /// Steps 5–7 for one batch: each extent is verified on its own, decoded and
    /// validated; only then is its copy enqueued, followed by a completion event that
    /// holds the staging slot. A mismatch fails the attempt and nothing of it is used;
    /// the batch's other verified extents are kept.
    fn process_batch(
        &mut self,
        read: ReadInFlight,
        bytes_read: u64,
        report: &mut PumpReport,
    ) -> Result<(), ExecutorFault> {
        let read_end = read.read_offset_bytes.saturating_add(bytes_read);
        let mut verify = StageClock::new(Stage::Verify);
        let mut decode = StageClock::new(Stage::Decode);
        let mut validate = StageClock::new(Stage::Validate);
        let mut cursor: u64 = 0;
        let mut verified: Vec<(FlightId, StagedRange)> = Vec::new();
        let mut source_at_fault = false;
        for &member in &read.members {
            if !self.live_member(member, report) {
                continue;
            }
            let Some(extent) = self.flights.get(&member).map(|flight| flight.extent) else {
                continue;
            };
            let source = Some(read.source.clone());
            let needed_end_bytes = extent.stored_end_bytes().unwrap_or(u64::MAX);
            if needed_end_bytes > read_end {
                source_at_fault = true;
                self.attempt_failed(
                    member,
                    source,
                    AttemptFailure::Truncated {
                        needed_end_bytes,
                        read_end_bytes: read_end,
                    },
                );
                continue;
            }
            // Its stored bytes are staged, not yet verified.
            self.report_flight(member, ExtentReport::Arrived);
            let stored = StagedRange {
                buffer: read.read_slot,
                offset_bytes: extent
                    .stored_offset_bytes
                    .saturating_sub(read.read_offset_bytes),
                length_bytes: extent.stored_length_bytes,
            };
            let started = self.clock.now();
            let found = self.ports.backend.stored_digest(&stored, &extent.stored);
            verify.add(extent.stored_length_bytes, started, self.clock.now());
            let expected = extent.stored_digest();
            match found {
                Err(error) => {
                    self.attempt_failed(member, source, AttemptFailure::Verify { error });
                    continue;
                }
                Ok(found) if found != expected => {
                    source_at_fault = true;
                    self.attempt_failed(
                        member,
                        source,
                        AttemptFailure::StoredMismatch { expected, found },
                    );
                    continue;
                }
                Ok(_) => {}
            }
            // A raw extent's stored bytes are its decoded bytes, just checked against the
            // decoded content key.
            let StoredForm::Encoded {
                codec, dictionary, ..
            } = extent.stored
            else {
                self.add_verified_bytes(member, extent.decoded_length_bytes);
                verified.push((member, stored));
                continue;
            };
            let Some(slot) = read.decode_slot else {
                return Err(ExecutorFault::StagingMisuse {
                    buffer: read.read_slot,
                });
            };
            let into = StagedRange {
                buffer: slot,
                offset_bytes: cursor,
                length_bytes: extent.decoded_length_bytes,
            };
            let started = self.clock.now();
            let produced = self.ports.backend.decode(&DecodeRequest {
                codec,
                dictionary,
                from: stored,
                into,
            });
            decode.add(extent.decoded_length_bytes, started, self.clock.now());
            match produced {
                Err(error) => {
                    self.attempt_failed(member, source, AttemptFailure::Decode { error });
                    continue;
                }
                Ok(found_bytes) if found_bytes != extent.decoded_length_bytes => {
                    self.attempt_failed(
                        member,
                        source,
                        AttemptFailure::DecodedLengthMismatch {
                            expected_bytes: extent.decoded_length_bytes,
                            found_bytes,
                        },
                    );
                    continue;
                }
                Ok(_) => {}
            }
            cursor = cursor.saturating_add(extent.decoded_length_bytes);
            let started = self.clock.now();
            let found = self.ports.backend.content_key(&into);
            validate.add(extent.decoded_length_bytes, started, self.clock.now());
            match found {
                Err(error) => {
                    self.attempt_failed(member, source, AttemptFailure::Validate { error });
                    continue;
                }
                Ok(found) if found != extent.decoded_key => {
                    self.attempt_failed(
                        member,
                        source,
                        AttemptFailure::DecodedMismatch {
                            expected: extent.decoded_key,
                            found,
                        },
                    );
                    continue;
                }
                Ok(_) => {}
            }
            self.add_verified_bytes(member, extent.decoded_length_bytes);
            verified.push((member, into));
        }
        for clock in [&verify, &decode, &validate] {
            if let Some(measurement) = clock.measurement(&read) {
                self.record_batch_stage(&read.members, measurement);
            }
        }
        for (member, from) in verified {
            let Some(flight) = self.flights.get(&member) else {
                continue;
            };
            let bytes = flight.extent.decoded_length_bytes;
            let to = DestinationRange {
                allocation: flight.key.allocation,
                offset_bytes: flight.key.offset_bytes,
                length_bytes: bytes,
            };
            let request = CopyRequest {
                api: self.copy_api,
                from,
                to,
            };
            if let Err(error) = self.ports.backend.enqueue_copy(&request) {
                self.attempt_failed(
                    member,
                    Some(read.source.clone()),
                    AttemptFailure::Copy { error },
                );
                continue;
            }
            let enqueued_at = self.clock.now();
            // The copy reads the slot until its completion event is observed.
            self.hold(from.buffer)?;
            let event = self
                .ports
                .backend
                .record_event(read.device)
                .map_err(|error| ExecutorFault::EventNotRecorded { error })?;
            if self.copies.contains_key(&event) {
                return Err(ExecutorFault::EventReused { event });
            }
            self.copies.insert(
                event,
                CopyInFlight {
                    flight: member,
                    buffer: from.buffer,
                    source: read.source.clone(),
                    path: read.path,
                    enqueued_at,
                    bytes,
                },
            );
            if let Some(flight) = self.flights.get_mut(&member) {
                flight.state = FlightState::Copying;
            }
            report.copies_enqueued += 1;
        }
        self.let_go(read.read_slot)?;
        if let Some(slot) = read.decode_slot {
            self.let_go(slot)?;
        }
        // A source that served bytes not the manifest's is excluded from the rest of the
        // live load; its other batches move to the sources left (GPU §2.5, §1.1).
        if source_at_fault {
            self.exclude_from_load(read.load, &read.source);
        }
        Ok(())
    }

    /// Step 7: a dependency is published only when every one of its extents completed
    /// its whole chain for this job and every prerequisite is usable.
    fn publish(&mut self, report: &mut PumpReport) {
        let running: Vec<OperationId> = self
            .jobs
            .iter()
            .filter(|(_, job)| job.status.is_running())
            .map(|(operation, _)| operation.clone())
            .collect();
        for operation in running {
            let Some(job) = self.jobs.get_mut(&operation) else {
                continue;
            };
            let mut usable: BTreeSet<DependencyId> = job
                .dependencies
                .iter()
                .filter(|dependency| dependency.usable)
                .map(|dependency| dependency.id)
                .collect();
            let mut newly = Vec::new();
            for dependency in &mut job.dependencies {
                if dependency.usable {
                    continue;
                }
                let chain_complete = dependency
                    .extents
                    .iter()
                    .all(|index| job.committed.contains(index));
                let prerequisites_usable = dependency
                    .requires
                    .iter()
                    .all(|requires| usable.contains(requires));
                if chain_complete && prerequisites_usable {
                    dependency.usable = true;
                    usable.insert(dependency.id);
                    newly.push(dependency.id);
                }
            }
            if !newly.is_empty() {
                job.progress.snapshot.usable_dependencies = job
                    .progress
                    .snapshot
                    .usable_dependencies
                    .saturating_add(newly.len());
                job.progress_dirty = true;
            }
            let complete = job.dependencies.iter().all(|dependency| dependency.usable);
            if complete {
                job.status = JobStatus::Completed;
            }
            let foreground = job.priority == Priority::Foreground;
            for dependency in newly {
                report.published.push((operation.clone(), dependency));
                self.emit(
                    &operation,
                    TransferEventKind::DependencyUsable { dependency },
                );
            }
            if complete {
                if foreground {
                    if let Err(error) = self.scheduler.release(&operation) {
                        self.anomaly(Anomaly::SchedulerRefused {
                            operation: operation.clone(),
                            error,
                        });
                    }
                }
                self.emit(&operation, TransferEventKind::Completed);
                self.close_transfers(&operation, true);
                // Its operations are delivered and stay resident until retired; a finished
                // job no longer holds later joiners to its loader plan or sources.
                self.unsubscribe_all(&operation);
            }
        }
    }

    /// Plans failed or moved operations again, on the sources still eligible for them. A
    /// subscriber that no source serves on its own fails alone and the operation stays
    /// with the others; an operation no source serves for anyone is given up (§3.5).
    fn plan_retries(&mut self) {
        type GroupKey = (ContentKey, ContentKey, AllocationKey, Vec<SourceId>);
        let pending: Vec<FlightId> = std::mem::take(&mut self.replan).into_iter().collect();
        let mut groups: BTreeMap<GroupKey, (Vec<SourceCandidate>, Vec<FlightId>)> = BTreeMap::new();
        for id in pending {
            let Some(flight) = self.flights.get(&id) else {
                continue;
            };
            if flight.state != FlightState::Unplanned {
                continue;
            }
            if flight.subscribers.is_empty() {
                self.remove_flight(id);
                continue;
            }
            let eligible = self.eligible_sources(id);
            if eligible.is_empty() {
                let subscribers = self
                    .flights
                    .get(&id)
                    .map_or(0, |flight| flight.subscribers.len());
                let stranded = self.stranded_subscribers(id);
                if !stranded.is_empty() && stranded.len() < subscribers {
                    for operation in &stranded {
                        self.strand_subscriber(operation, id);
                    }
                    self.replan.insert(id);
                    continue;
                }
                let attempts = self
                    .flights
                    .get(&id)
                    .map(|flight| flight.attempts.clone())
                    .unwrap_or_default();
                self.fail_flight(id, ExtentFailure::NoEligibleSource { attempts });
                continue;
            }
            let Some(flight) = self.flights.get(&id) else {
                continue;
            };
            let key = (
                flight.key.extent.artifact,
                flight.key.representation,
                flight.key.allocation,
                eligible
                    .iter()
                    .map(|candidate| candidate.spec.id.clone())
                    .collect(),
            );
            groups
                .entry(key)
                .or_insert_with(|| (eligible, Vec::new()))
                .1
                .push(id);
        }
        for ((artifact, representation, allocation, _), (sources, members)) in groups {
            let Some(first) = members.first().and_then(|id| self.flights.get(id)) else {
                continue;
            };
            let object_length_bytes = first.object_length_bytes;
            let cuts = first
                .subscribers
                .iter()
                .next()
                .and_then(|operation| self.jobs.get(operation))
                .map(|job| job.cuts.clone())
                .unwrap_or_default();
            let extents: Vec<(FlightId, ManifestExtent)> = members
                .iter()
                .filter_map(|id| self.flights.get(id).map(|flight| (*id, flight.extent)))
                .collect();
            let limits = self.batch_limits(allocation.device, object_length_bytes);
            let started = self.clock.now();
            let built = self.build_load(LoadInput {
                artifact,
                representation,
                allocation,
                members: &extents,
                sources: &sources,
                cuts: &cuts,
                limits,
            });
            let finished = self.clock.now();
            match built {
                Ok(load) => {
                    self.register_load(load);
                    let bytes = extents.iter().fold(0u64, |total, (_, extent)| {
                        total.saturating_add(extent.stored_length_bytes)
                    });
                    let measurement = StageMeasurement {
                        stage: Stage::Coalesce,
                        bytes,
                        started_at: started,
                        duration: finished.saturating_duration_since(started),
                        path: None,
                        method: None,
                        api: None,
                        source: None,
                    };
                    self.record_batch_stage(&members, measurement);
                }
                Err(failure) => {
                    for id in members {
                        let attempts = self
                            .flights
                            .get(&id)
                            .map(|flight| flight.attempts.clone())
                            .unwrap_or_default();
                        self.fail_flight(
                            id,
                            ExtentFailure::Unplannable {
                                failure: failure.clone(),
                                attempts,
                            },
                        );
                    }
                }
            }
        }
    }

    /// Lets each load rebalance with hysteresis and dispatches batches, older loads first,
    /// within each source's cap counted across every load of the executor (GPU §2.5,
    /// [`SharedSourceCaps`]): a source serves at most its `max_in_flight` batches whatever
    /// it is loading.
    fn dispatch_loads(&mut self) {
        let mut lowest: BTreeMap<SourceId, u32> = BTreeMap::new();
        for load in self.loads.values_mut() {
            load.plan.rebalance();
            for (source, cap) in &load.caps {
                let entry = lowest.entry(source.clone()).or_insert(*cap);
                *entry = (*entry).min(*cap);
            }
        }
        let mut caps = SharedSourceCaps::new();
        let mut refused = Vec::new();
        for (source, cap) in lowest {
            if let Err(error) = caps.set_cap(source, cap) {
                refused.push(error);
            }
        }
        let ids: Vec<LoadId> = self.loads.keys().copied().collect();
        let mut plans: Vec<&mut MultiSourceLoad> =
            self.loads.values_mut().map(|load| &mut load.plan).collect();
        let started = caps.dispatch(&mut plans);
        let mut dispatched = Vec::new();
        for (position, dispatch) in started {
            let Some(id) = ids.get(position).copied() else {
                continue;
            };
            let Some(load) = self.loads.get_mut(&id) else {
                continue;
            };
            match load.batches.get_mut(dispatch.batch) {
                Some(batch) if batch.state == BatchState::Queued => {
                    batch.state = BatchState::Ready {
                        source: dispatch.source,
                    };
                    dispatched.push((id, dispatch.batch));
                }
                // A batch the executor no longer reads, such as one no source could take,
                // is finished in the planner at once and holds no slot of its source.
                Some(batch) if batch.state == BatchState::Done => {
                    if let Err(error) = load.plan.complete_from(dispatch.batch, &dispatch.source) {
                        refused.push(error);
                    }
                }
                _ => {}
            }
        }
        self.ready.extend(dispatched);
        for error in refused {
            self.anomaly(Anomaly::PlannerRefused { error });
        }
    }

    /// Step 4 begins: dispatched batches start, foreground work first, while the
    /// staging pools have room; the rest wait.
    fn start_reads(&mut self, report: &mut PumpReport) -> Result<(), ExecutorFault> {
        let ready = std::mem::take(&mut self.ready);
        let mut ranked: Vec<((Reverse<Priority>, FlightId), (LoadId, usize))> = ready
            .into_iter()
            .map(|entry| (self.batch_rank(entry), entry))
            .collect();
        ranked.sort();
        let mut waiting = Vec::new();
        for (_, (load, batch)) in ranked {
            if let Start::Waiting = self.try_start(load, batch, report)? {
                waiting.push((load, batch));
            }
        }
        self.ready.extend(waiting);
        Ok(())
    }

    fn try_start(
        &mut self,
        load_id: LoadId,
        batch_index: usize,
        report: &mut PumpReport,
    ) -> Result<Start, ExecutorFault> {
        let Some(load) = self.loads.get(&load_id) else {
            return Ok(Start::Dropped);
        };
        let Some(batch) = load.batches.get(batch_index) else {
            return Ok(Start::Dropped);
        };
        let BatchState::Ready { source } = &batch.state else {
            return Ok(Start::Dropped);
        };
        let source = source.clone();
        let kind = load.kinds.get(&source).copied();
        let members = batch.members.clone();
        let artifact = load.artifact;
        let representation = load.representation;
        let device = load.allocation.device;
        let read_offset_bytes = batch.read_offset_bytes;
        let read_length_bytes = batch.read_length_bytes;
        let planned = FlightState::Planned {
            load: load_id,
            batch: batch_index,
        };
        let mut live = Vec::new();
        let mut moved = Vec::new();
        for member in members {
            let Some(flight) = self.flights.get(&member) else {
                continue;
            };
            if flight.state != planned {
                continue;
            }
            if flight.subscribers.is_empty() {
                self.remove_flight(member);
                report.reclaimed += 1;
                continue;
            }
            if kind.is_some_and(|kind| self.source_allowed_for(flight, &source, kind)) {
                live.push(member);
            } else {
                moved.push(member);
            }
        }
        let subscribers: BTreeSet<OperationId> = live
            .iter()
            .filter_map(|id| self.flights.get(id))
            .flat_map(|flight| flight.subscribers.iter().cloned())
            .collect();
        let decodes = live
            .iter()
            .filter_map(|id| self.flights.get(id))
            .any(|flight| flight.extent.stored.needs_decode());
        let route = match kind {
            Some(kind) if !live.is_empty() => self.choose_path(kind, &subscribers, device, decodes),
            _ => Route::Unusable,
        };
        let (kind, path, method, place) = match (kind, route) {
            (
                Some(kind),
                Route::Use {
                    path,
                    method,
                    place,
                },
            ) => (kind, path, method, place),
            (_, Route::Shed { jobs }) => {
                // Only the jobs whose requirement this read cannot meet fail; the
                // operations are planned again for their other subscribers (§3.5).
                self.finish_batch_in_load(load_id, batch_index, &source);
                for (operation, method, reason) in jobs {
                    let shared = live.iter().copied().find(|id| {
                        self.flights
                            .get(id)
                            .is_some_and(|flight| flight.subscribers.contains(&operation))
                    });
                    if let Some(id) = shared {
                        self.shed_requirer(&operation, id, method, reason);
                    }
                }
                moved.extend(live);
                self.unplan(&moved);
                return Ok(Start::Dropped);
            }
            _ => {
                moved.extend(live);
                self.unplan(&moved);
                self.finish_batch_in_load(load_id, batch_index, &source);
                return Ok(Start::Dropped);
            }
        };
        self.unplan(&moved);
        // Direct I/O replaces the ordinary loader where it can, and the ordinary loader
        // reads buffered with the reason where it cannot (GPU-T20).
        let mut method = method;
        let mut buffered = None;
        if let (Some(direct), SourceKind::LocalFile) = (self.direct_io, kind) {
            if method == self.config.local_read_method {
                match self.direct_io_unavailable(
                    direct,
                    &source,
                    representation,
                    read_offset_bytes,
                    read_length_bytes,
                ) {
                    None => method = ReadMethod::DirectRead,
                    Some(reason) => buffered = Some(reason),
                }
            }
        }
        if self.pool(place).map_or(0, StagingPool::free) < slots_needed(decodes) {
            return Ok(Start::Waiting);
        }
        let Some(read_slot) = self.pool_mut(place).and_then(StagingPool::acquire) else {
            return Ok(Start::Waiting);
        };
        let decode_slot = if decodes {
            match self.pool_mut(place).and_then(StagingPool::acquire) {
                Some(slot) => Some(slot),
                None => {
                    self.let_go(read_slot)?;
                    return Ok(Start::Waiting);
                }
            }
        } else {
            None
        };
        // A network source moves bytes only through its subscribers' CORE-05 sessions:
        // the batch is one chunk covering exactly its extents, admitted, and charged,
        // before the read starts (GPU-W09).
        let mut read_offset_bytes = read_offset_bytes;
        let mut read_length_bytes = read_length_bytes;
        let mut permits = Vec::new();
        if self.transfers.is_some() && kind.is_network() {
            let admission = match self.extents_span(&live) {
                Some(span) => {
                    read_offset_bytes = span.start_bytes();
                    read_length_bytes = span.length_bytes();
                    self.admit_chunk(&subscribers, &source, representation, span)
                }
                None => ChunkAdmission::Refused,
            };
            match admission {
                ChunkAdmission::Admitted(admitted) => permits = admitted,
                ChunkAdmission::Wait => {
                    self.let_go(read_slot)?;
                    if let Some(slot) = decode_slot {
                        self.let_go(slot)?;
                    }
                    return Ok(Start::Waiting);
                }
                ChunkAdmission::Refused => {
                    self.let_go(read_slot)?;
                    if let Some(slot) = decode_slot {
                        self.let_go(slot)?;
                    }
                    self.unplan(&live);
                    self.finish_batch_in_load(load_id, batch_index, &source);
                    return Ok(Start::Dropped);
                }
            }
        }
        let mut request = ReadRequest {
            source: source.clone(),
            kind,
            method,
            artifact,
            representation,
            offset_bytes: read_offset_bytes,
            length_bytes: read_length_bytes,
            into: read_slot,
        };
        let started_at = self.clock.now();
        let mut begun = self.ports.backend.begin_read(&request);
        if let Err(error) = &begun {
            if method == ReadMethod::DirectRead && error.kind == BackendErrorKind::Unsupported {
                // The file's filesystem refused direct I/O: it is read buffered, now and
                // from then on, with the reason.
                self.direct_refused
                    .insert((source.clone(), representation), error.clone());
                buffered = Some(DirectIoUnavailable::Refused {
                    error: error.clone(),
                });
                method = self.config.local_read_method;
                request.method = method;
                begun = self.ports.backend.begin_read(&request);
            }
        }
        match begun {
            Err(error) => {
                self.let_go(read_slot)?;
                if let Some(slot) = decode_slot {
                    self.let_go(slot)?;
                }
                let failure = self.read_failure(&source, permits, error);
                self.batch_failed(load_id, batch_index, &source, &live, failure);
                Ok(Start::Dropped)
            }
            Ok(ticket) => {
                if self.reads.contains_key(&ticket) {
                    let operations = permits.into_iter().map(|(operation, _)| operation);
                    self.interrupt_transfers(&source, operations);
                    return Err(ExecutorFault::ReadTicketReused { ticket });
                }
                for member in &live {
                    if let Some(flight) = self.flights.get_mut(member) {
                        flight.state = FlightState::Reading;
                    }
                    self.report_flight(*member, ExtentReport::Started);
                }
                if let Some(reason) = buffered {
                    for operation in &subscribers {
                        self.emit(
                            operation,
                            TransferEventKind::BufferedRead {
                                reason: reason.clone(),
                            },
                        );
                    }
                }
                if let Some(batch) = self
                    .loads
                    .get_mut(&load_id)
                    .and_then(|load| load.batches.get_mut(batch_index))
                {
                    batch.state = BatchState::Reading;
                }
                self.reads.insert(
                    ticket,
                    ReadInFlight {
                        permits,
                        load: load_id,
                        batch: batch_index,
                        source,
                        path,
                        method,
                        device,
                        read_slot,
                        decode_slot,
                        started_at,
                        members: live,
                        read_offset_bytes,
                        read_length_bytes,
                    },
                );
                report.reads_started += 1;
                Ok(Start::Started)
            }
        }
    }

    /// Step 9: one progress snapshot per job whose progress changed.
    fn report_progress(&mut self) {
        let changed: Vec<OperationId> = self
            .jobs
            .iter()
            .filter(|(_, job)| job.progress_dirty)
            .map(|(operation, _)| operation.clone())
            .collect();
        for operation in changed {
            let Some(job) = self.jobs.get_mut(&operation) else {
                continue;
            };
            job.progress_dirty = false;
            let snapshot = job.progress.snapshot;
            self.emit(&operation, TransferEventKind::Progress(snapshot));
        }
    }

    /// Foreground before speculative, then the oldest operation first.
    fn batch_rank(&self, (load, batch): (LoadId, usize)) -> (Reverse<Priority>, FlightId) {
        let members = self
            .loads
            .get(&load)
            .and_then(|load| load.batches.get(batch))
            .map_or(&[][..], |batch| batch.members.as_slice());
        let priority = members
            .iter()
            .filter_map(|id| self.flights.get(id))
            .map(|flight| self.flight_priority(flight))
            .max()
            .unwrap_or(Priority::Speculative);
        let oldest = members.iter().min().copied().unwrap_or(FlightId(u64::MAX));
        (Reverse(priority), oldest)
    }

    /// The highest priority among the operation's subscribers.
    pub(super) fn flight_priority(&self, flight: &Flight) -> Priority {
        flight
            .subscribers
            .iter()
            .filter_map(|operation| self.jobs.get(operation))
            .map(|job| job.priority)
            .max()
            .unwrap_or(Priority::Speculative)
    }

    /// Whether a batch member still has subscribers; an orphan is reclaimed.
    fn live_member(&mut self, member: FlightId, report: &mut PumpReport) -> bool {
        match self.flights.get(&member) {
            None => false,
            Some(flight) if flight.subscribers.is_empty() => {
                self.remove_flight(member);
                report.reclaimed += 1;
                false
            }
            Some(_) => true,
        }
    }

    fn unplan(&mut self, members: &[FlightId]) {
        for member in members {
            if let Some(flight) = self.flights.get_mut(member) {
                flight.state = FlightState::Unplanned;
                self.replan.insert(*member);
            }
        }
    }

    /// Marks a dispatched batch finished in its load and, through `complete_from`, in the
    /// multi-source planner (GPU §2.5). A late report from a source the batch has left
    /// is refused and changes nothing; `false` then.
    fn finish_batch_in_load(
        &mut self,
        load_id: LoadId,
        batch_index: usize,
        source: &SourceId,
    ) -> bool {
        let completed = match self.loads.get_mut(&load_id) {
            None => return false,
            Some(load) => {
                let completed = load.plan.complete_from(batch_index, source);
                if completed.is_ok() {
                    if let Some(batch) = load.batches.get_mut(batch_index) {
                        batch.state = BatchState::Done;
                    }
                }
                completed
            }
        };
        match completed {
            Ok(()) => true,
            Err(SourcesError::BatchNotInFlight { .. } | SourcesError::SourceExcluded { .. }) => {
                false
            }
            Err(error) => {
                self.anomaly(Anomaly::PlannerRefused { error });
                false
            }
        }
    }

    /// The members that still have subscribers; orphans are reclaimed.
    fn live_members(&mut self, members: &[FlightId], report: &mut PumpReport) -> Vec<FlightId> {
        members
            .iter()
            .copied()
            .filter(|member| self.live_member(*member, report))
            .collect()
    }

    /// The stored bytes the members' extents cover, from the first one's start to the
    /// last one's end: a network read moves exactly them, not the aligned batch.
    fn extents_span(&self, members: &[FlightId]) -> Option<ByteRange> {
        let extents: Vec<ManifestExtent> = members
            .iter()
            .filter_map(|id| self.flights.get(id).map(|flight| flight.extent))
            .collect();
        let start = extents
            .iter()
            .map(|extent| extent.stored_offset_bytes)
            .min()?;
        let end = extents
            .iter()
            .map(|extent| extent.stored_end_bytes())
            .collect::<Option<Vec<u64>>>()?
            .into_iter()
            .max()?;
        ByteRange::new(start, end).ok()
    }

    /// What a failed read was: for a read admitted into CORE-05 sessions, a transport
    /// interruption, which ends the sessions' attempts and is not the source's fault
    /// (INT-08); otherwise the read failure itself.
    fn read_failure(
        &mut self,
        source: &SourceId,
        permits: Vec<(OperationId, ChunkPermit)>,
        error: BackendError,
    ) -> AttemptFailure {
        if permits.is_empty() {
            return AttemptFailure::Read { error };
        }
        let operations = permits.into_iter().map(|(operation, _)| operation);
        self.interrupt_transfers(source, operations);
        AttemptFailure::TransportInterrupted { error }
    }

    /// Whether the planner still has the batch in flight on `source`.
    fn in_flight_on(&self, load_id: LoadId, batch: usize, source: &SourceId) -> bool {
        self.loads.get(&load_id).is_some_and(|load| {
            load.plan.status(batch) == Some(PlannedStatus::InFlight)
                && load.plan.owner(batch) == Some(source)
        })
    }

    /// Lets go of the staging of a read whose batch was taken back from its source: its
    /// bytes are never used.
    fn discard_read(
        &mut self,
        read: &ReadInFlight,
        report: &mut PumpReport,
    ) -> Result<(), ExecutorFault> {
        self.let_go(read.read_slot)?;
        if let Some(slot) = read.decode_slot {
            self.let_go(slot)?;
        }
        report.reads_discarded += 1;
        Ok(())
    }

    /// A whole batch failed on `source` (GPU §2.5). A source at fault is excluded from the
    /// live load, which takes back its batches in flight and moves its unfinished ones to
    /// the source predicted to finish them earliest; any other failure requeues the batch,
    /// counted as a failure and not a steal, maybe on the same source. Each member's
    /// attempt is recorded: a member that may be retried waits in its batch for the
    /// planner's source, or is planned again from scratch when no source of the load can
    /// take the batch.
    fn batch_failed(
        &mut self,
        load_id: LoadId,
        batch: usize,
        source: &SourceId,
        members: &[FlightId],
        failure: AttemptFailure,
    ) {
        let placed = if failure.is_source_fault() {
            self.exclude_from_load(load_id, source);
            self.loads
                .get(&load_id)
                .is_some_and(|load| load.plan.owner(batch).is_some())
        } else {
            self.requeue_failed(load_id, batch, source)
        };
        let retry = if placed {
            Retry::InBatch {
                load: load_id,
                batch,
            }
        } else {
            Retry::Replan
        };
        for member in members {
            self.attempt_failed_in(*member, Some(source.clone()), failure.clone(), retry);
        }
    }

    /// Requeues a batch that failed on `source` without the source being at fault; the
    /// planner places it again (GPU §2.5). Whether a source took it.
    fn requeue_failed(&mut self, load_id: LoadId, batch: usize, source: &SourceId) -> bool {
        let placed = match self.loads.get_mut(&load_id) {
            None => return false,
            Some(load) => {
                let placed = load.plan.requeue_failed(batch, source);
                if let Some(entry) = load.batches.get_mut(batch) {
                    entry.state = if placed.is_ok() {
                        BatchState::Queued
                    } else {
                        BatchState::Done
                    };
                }
                placed
            }
        };
        match placed {
            Ok(_) => true,
            Err(SourcesError::NoAuthorizedSource) => false,
            Err(error) => {
                self.anomaly(Anomaly::PlannerRefused { error });
                false
            }
        }
    }

    /// Excludes `source` from a live load for the rest of it, as once it served bytes not
    /// the manifest's or failed outright (GPU §2.5, §1.1): the planner takes back its
    /// batches in flight, whose reads are abandoned (their late reports are refused and
    /// their bytes discarded), and moves every unfinished batch it held to the source
    /// predicted to finish it earliest. A batch no source of the load can take is planned
    /// again from scratch.
    pub(super) fn exclude_from_load(&mut self, load_id: LoadId, source: &SourceId) {
        let excluded = match self.loads.get_mut(&load_id) {
            None => return,
            Some(load) => load.plan.exclude_source(source),
        };
        let exclusion = match excluded {
            Ok(exclusion) => exclusion,
            Err(error) => {
                self.anomaly(Anomaly::PlannerRefused { error });
                return;
            }
        };
        for placement in &exclusion.reassigned {
            self.requeue_batch(load_id, placement.batch, false);
        }
        for batch in &exclusion.stranded {
            self.requeue_batch(load_id, *batch, true);
        }
    }

    /// Queues a batch the planner took back again: its members wait for the planner's new
    /// source, or are planned again from scratch when `stranded`. Members of its read in
    /// flight, now abandoned, are discarded from progress and wait as well.
    fn requeue_batch(&mut self, load_id: LoadId, batch: usize, stranded: bool) {
        let planned = FlightState::Planned {
            load: load_id,
            batch,
        };
        let abandoned: BTreeSet<FlightId> = self
            .reads
            .values()
            .filter(|read| read.load == load_id && read.batch == batch)
            .flat_map(|read| read.members.iter().copied())
            .collect();
        let members = match self
            .loads
            .get_mut(&load_id)
            .and_then(|load| load.batches.get_mut(batch))
        {
            None => return,
            Some(entry) => {
                entry.state = if stranded {
                    BatchState::Done
                } else {
                    BatchState::Queued
                };
                entry.members.clone()
            }
        };
        for member in members {
            let Some(flight) = self.flights.get_mut(&member) else {
                continue;
            };
            let reading = flight.state == FlightState::Reading && abandoned.contains(&member);
            if flight.state != planned && !reading {
                continue;
            }
            if stranded {
                flight.state = FlightState::Unplanned;
                self.replan.insert(member);
            } else {
                flight.state = planned;
            }
            if reading {
                self.report_flight(member, ExtentReport::Discarded);
            }
        }
    }

    /// Why a read of `length_bytes` at `offset_bytes` from `source` cannot use direct I/O;
    /// `None` when it can (GPU-T20).
    fn direct_io_unavailable(
        &self,
        direct: DirectIo,
        source: &SourceId,
        representation: ContentKey,
        offset_bytes: u64,
        length_bytes: u64,
    ) -> Option<DirectIoUnavailable> {
        if !self.read_methods.contains(&ReadMethod::DirectRead) {
            return Some(DirectIoUnavailable::NotImplemented);
        }
        if let Some(error) = self.direct_refused.get(&(source.clone(), representation)) {
            return Some(DirectIoUnavailable::Refused {
                error: error.clone(),
            });
        }
        let block_bytes = direct.block_bytes.get();
        if offset_bytes % block_bytes != 0 || length_bytes % block_bytes != 0 {
            return Some(DirectIoUnavailable::Unaligned {
                offset_bytes,
                length_bytes,
                block_bytes,
            });
        }
        None
    }

    /// Records one stage for every job a batch's operations serve.
    fn record_batch_stage(&mut self, members: &[FlightId], measurement: StageMeasurement) {
        let subscribers: BTreeSet<OperationId> = members
            .iter()
            .filter_map(|id| self.flights.get(id))
            .flat_map(|flight| flight.subscribers.iter().cloned())
            .collect();
        for operation in &subscribers {
            self.record_stage(operation, measurement.clone());
        }
    }

    fn add_verified_bytes(&mut self, member: FlightId, bytes: u64) {
        let subscribers: Vec<OperationId> = self
            .flights
            .get(&member)
            .map(|flight| flight.subscribers.iter().cloned().collect())
            .unwrap_or_default();
        for operation in subscribers {
            if let Some(job) = self.jobs.get_mut(&operation) {
                job.progress.snapshot.verified_bytes =
                    job.progress.snapshot.verified_bytes.saturating_add(bytes);
                job.progress_dirty = true;
            }
        }
    }

    /// Feeds a measured read rate to every load using the source (GPU §2.5: measured,
    /// never advertised).
    fn observe_rate(&mut self, source: &SourceId, bytes: u64, duration: Duration) {
        let seconds = duration.as_secs_f64();
        if bytes == 0 || seconds <= 0.0 {
            return;
        }
        let rate = bytes as f64 / seconds;
        let Ok(rating) = BandwidthRating::measured_directional(rate) else {
            return;
        };
        self.observed_rates.insert(source.clone(), rate);
        let mut refused = Vec::new();
        for load in self.loads.values_mut() {
            if load.plan.rate_bytes_per_second(source).is_some() {
                if let Err(error) = load.plan.observe_rate(source, rating.clone()) {
                    refused.push(error);
                }
            }
        }
        for error in refused {
            self.anomaly(Anomaly::PlannerRefused { error });
        }
    }
}

fn read_measurement(read: &ReadInFlight, bytes: u64, duration: Duration) -> StageMeasurement {
    StageMeasurement {
        stage: Stage::Read,
        bytes,
        started_at: read.started_at,
        duration,
        path: Some(read.path),
        method: Some(read.method),
        api: None,
        source: Some(read.source.clone()),
    }
}
