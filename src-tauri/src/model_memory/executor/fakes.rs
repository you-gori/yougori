//! Fakes for the executor's backend and ports. The backend keeps real bytes: reads land
//! in staging slots, copies land in destination memory when their time comes, and a
//! read into a slot that a pending copy still reads is recorded as a violation. Every
//! fake appends to one shared journal, so tests can check the order of the steps.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use super::{
    AllocationKey, BackendError, BackendErrorKind, BatchLimits, BatchPlan, BatchPort,
    CapacityLimit, CapacityRefusal, CatalogPort, CatalogRefusal, CopyApi, CopyRequest,
    DecodeRequest, DestinationRange, EventId, EventPort, EventStatus, ExecutorConfig,
    ExecutorPorts, ExtentSpan, PeerAccessPolicy, ReadMethod, ReadRequest, ReadStatus, ReadTicket,
    ReservationId, ReservationPort, ReservationPurpose, ReservationRefusal, ReservationRequest,
    ReservedResource, ResolveRequest, ResolvedManifest, RetryAdvice, StagedRange, StagingBuffer,
    StartError, StoredForm, TransferBackend, TransferEvent, TransferExecutor, TransferPath,
    UnknownReservation,
};
use crate::foundation::evidence::fakes::FakeProbe;
use crate::foundation::evidence::{
    Capability, ConfigurationFingerprint, EvidencePolicy, ProbeRegistry, SourceClass,
};
use crate::foundation::ids::{Clock, ContentKey, Digest, GpuDeviceKey, ManualClock, MonotonicTime};
use crate::model_memory::manifest::EncodedDigest;
use crate::model_memory::math::SourceId;

const XOR_KEY: u8 = 0x5a;

/// The fake codec, standing in for zstd: a 4-byte big-endian decoded length, then the
/// bytes XORed with a key.
pub(super) fn fake_encode(decoded: &[u8]) -> Vec<u8> {
    let mut encoded = (decoded.len() as u32).to_be_bytes().to_vec();
    encoded.extend(decoded.iter().map(|byte| byte ^ XOR_KEY));
    encoded
}

fn fake_decode(encoded: &[u8]) -> Option<Vec<u8>> {
    let (header, body) = encoded.split_at_checked(4)?;
    let length = u32::from_be_bytes(header.try_into().ok()?) as usize;
    (length == body.len()).then(|| body.iter().map(|byte| byte ^ XOR_KEY).collect())
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// One step any fake took, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Entry {
    Resolve,
    Reserve {
        purpose: ReservationPurpose,
        resource: ReservedResource,
        bytes: u64,
        reservation: ReservationId,
    },
    Refuse {
        purpose: ReservationPurpose,
    },
    BeginUse {
        reservation: ReservationId,
    },
    Release {
        reservation: ReservationId,
    },
    /// A delivered child reservation went back to its parent.
    HandOver {
        reservation: ReservationId,
    },
    Coalesce {
        spans: usize,
    },
    BeginRead {
        source: String,
        artifact: ContentKey,
        method: ReadMethod,
        into: StagingBuffer,
        offset: u64,
        length: u64,
        ticket: u64,
    },
    ReadDone {
        ticket: u64,
        bytes: u64,
    },
    Hash {
        range: StagedRange,
    },
    Decode {
        from: StagedRange,
        into: StagedRange,
    },
    EnqueueCopy {
        from: StagedRange,
        to: DestinationRange,
        api: CopyApi,
    },
    RecordEvent {
        event: u64,
    },
    EventDone {
        event: u64,
    },
    ReleaseEvent {
        event: u64,
    },
}

pub(super) type Journal = Arc<Mutex<Vec<Entry>>>;

struct FakeRead {
    request: ReadRequest,
    complete_at: u64,
}

struct FakeCopy {
    from: StagedRange,
    to: DestinationRange,
    complete_at: u64,
    applied: bool,
}

struct FakeEvent {
    complete_at: u64,
    failed: bool,
}

/// One write that landed in destination memory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Landed {
    pub(super) allocation: AllocationKey,
    pub(super) offset: u64,
    pub(super) bytes: Vec<u8>,
}

pub(super) struct BackendState {
    clock: Arc<ManualClock>,
    journal: Journal,
    pub(super) copy_api: CopyApi,
    pub(super) methods: BTreeSet<ReadMethod>,
    /// What the live peer query answers; the executor never asks it.
    pub(super) peer_access: BTreeSet<(GpuDeviceKey, GpuDeviceKey)>,
    /// Sources whose filesystem refuses direct reads.
    pub(super) refuse_direct: BTreeSet<SourceId>,
    /// The path reads made with a method report they took, as the driver tells it.
    pub(super) serve_as: BTreeMap<ReadMethod, TransferPath>,
    /// The kind of an injected read failure.
    pub(super) read_error: BackendErrorKind,
    /// Reads, by ticket, that fail when polled to completion.
    pub(super) fail_tickets: BTreeSet<u64>,
    objects: BTreeMap<(SourceId, ContentKey, ContentKey), Vec<u8>>,
    /// Per source: latency and nanoseconds per byte.
    pub(super) timing: BTreeMap<SourceId, (u64, u64)>,
    busy_until: BTreeMap<SourceId, u64>,
    staging: BTreeMap<StagingBuffer, Vec<u8>>,
    reads: BTreeMap<u64, FakeRead>,
    copies: Vec<FakeCopy>,
    events: BTreeMap<u64, FakeEvent>,
    stream_until: BTreeMap<GpuDeviceKey, u64>,
    pub(super) memory: BTreeMap<AllocationKey, Vec<u8>>,
    pub(super) landed: Vec<Landed>,
    next_ticket: u64,
    next_event: u64,
    pub(super) violations: Vec<String>,
    pub(super) hash_ns_per_byte: u64,
    pub(super) decode_ns_per_byte: u64,
    pub(super) copy_ns_per_byte: u64,
    /// Reads from these sources fail when polled, this many more times.
    pub(super) fail_reads: BTreeMap<SourceId, u32>,
    /// Bytes a source flips: the source, the artifact and the encoded offset.
    pub(super) corrupt: BTreeSet<(SourceId, ContentKey, u64)>,
    /// Where a source's copy of the object ends early.
    pub(super) truncate_at: BTreeMap<SourceId, u64>,
    pub(super) fail_enqueue: Vec<BackendErrorKind>,
    pub(super) fail_events: u32,
    pub(super) fail_record: bool,
    pub(super) duplicate_event: bool,
}

impl BackendState {
    fn now(&self) -> u64 {
        self.clock.now().as_nanos()
    }

    fn note(&self, entry: Entry) {
        lock(&self.journal).push(entry);
    }

    /// Lands every copy whose time has come, reading its staging bytes now.
    fn settle(&mut self) {
        let now = self.now();
        let mut landed = Vec::new();
        for copy in &mut self.copies {
            if copy.applied || copy.complete_at > now {
                continue;
            }
            copy.applied = true;
            let start = copy.from.offset_bytes as usize;
            let end = start + copy.from.length_bytes as usize;
            let bytes = self
                .staging
                .get(&copy.from.buffer)
                .and_then(|buffer| buffer.get(start..end))
                .map(<[u8]>::to_vec)
                .unwrap_or_default();
            landed.push((copy.to, bytes));
        }
        for (to, bytes) in landed {
            let memory = self.memory.entry(to.allocation).or_default();
            let end = to.offset_bytes as usize + bytes.len();
            if memory.len() < end {
                memory.resize(end, 0);
            }
            memory[to.offset_bytes as usize..end].copy_from_slice(&bytes);
            self.landed.push(Landed {
                allocation: to.allocation,
                offset: to.offset_bytes,
                bytes,
            });
        }
    }

    fn check_free(&mut self, buffer: StagingBuffer, what: &str) {
        if self
            .copies
            .iter()
            .any(|copy| !copy.applied && copy.from.buffer == buffer)
        {
            self.violations.push(format!(
                "{what} into slot {} of {:?} while a pending copy reads it",
                buffer.slot, buffer.place
            ));
        }
    }

    fn staged(&self, range: &StagedRange) -> Result<Vec<u8>, BackendError> {
        let start = range.offset_bytes as usize;
        let end = start + range.length_bytes as usize;
        self.staging
            .get(&range.buffer)
            .and_then(|buffer| buffer.get(start..end))
            .map(<[u8]>::to_vec)
            .ok_or_else(|| {
                BackendError::new(BackendErrorKind::Digest, "range outside staged bytes")
            })
    }

    fn advance(&self, nanos: u64) {
        self.clock.advance(Duration::from_nanos(nanos));
    }
}

/// A backend over in-memory objects, staging and destinations.
#[derive(Clone)]
pub(super) struct FakeBackend {
    pub(super) state: Arc<Mutex<BackendState>>,
}

impl FakeBackend {
    fn new(clock: Arc<ManualClock>, journal: Journal) -> Self {
        Self {
            state: Arc::new(Mutex::new(BackendState {
                clock,
                journal,
                copy_api: CopyApi::CudaMemcpyAsync,
                methods: BTreeSet::from([
                    ReadMethod::PositionedRead,
                    ReadMethod::MemoryMap,
                    ReadMethod::RangeRequest,
                ]),
                peer_access: BTreeSet::new(),
                refuse_direct: BTreeSet::new(),
                serve_as: BTreeMap::new(),
                read_error: BackendErrorKind::Io,
                fail_tickets: BTreeSet::new(),
                objects: BTreeMap::new(),
                timing: BTreeMap::new(),
                busy_until: BTreeMap::new(),
                staging: BTreeMap::new(),
                reads: BTreeMap::new(),
                copies: Vec::new(),
                events: BTreeMap::new(),
                stream_until: BTreeMap::new(),
                memory: BTreeMap::new(),
                landed: Vec::new(),
                next_ticket: 0,
                next_event: 0,
                violations: Vec::new(),
                hash_ns_per_byte: 1,
                decode_ns_per_byte: 2,
                copy_ns_per_byte: 1,
                fail_reads: BTreeMap::new(),
                corrupt: BTreeSet::new(),
                truncate_at: BTreeMap::new(),
                fail_enqueue: Vec::new(),
                fail_events: 0,
                fail_record: false,
                duplicate_event: false,
            })),
        }
    }

    pub(super) fn state(&self) -> MutexGuard<'_, BackendState> {
        lock(&self.state)
    }

    /// Makes `source` hold the stored bytes of one representation.
    pub(super) fn store(
        &self,
        source: &SourceId,
        artifact: ContentKey,
        representation: ContentKey,
        bytes: Vec<u8>,
    ) {
        self.state()
            .objects
            .insert((source.clone(), artifact, representation), bytes);
    }

    /// Destination bytes at `[offset, offset + length)`.
    pub(super) fn destination(
        &self,
        allocation: &AllocationKey,
        offset: u64,
        length: u64,
    ) -> Vec<u8> {
        let state = self.state();
        let memory = state.memory.get(allocation).cloned().unwrap_or_default();
        let start = offset as usize;
        let end = start + length as usize;
        memory
            .get(start..end)
            .map(<[u8]>::to_vec)
            .unwrap_or_default()
    }
}

impl TransferBackend for FakeBackend {
    fn copy_api(&self) -> CopyApi {
        self.state().copy_api
    }

    fn read_methods(&self) -> BTreeSet<ReadMethod> {
        self.state().methods.clone()
    }

    fn can_access_peer(
        &mut self,
        from: GpuDeviceKey,
        to: GpuDeviceKey,
    ) -> Result<bool, BackendError> {
        Ok(self.state().peer_access.contains(&(from, to)))
    }

    fn begin_read(&mut self, request: &ReadRequest) -> Result<ReadTicket, BackendError> {
        let mut state = self.state();
        state.settle();
        if !state.methods.contains(&request.method) {
            return Err(BackendError::new(BackendErrorKind::Unsupported, "method"));
        }
        if request.method == ReadMethod::DirectRead && state.refuse_direct.contains(&request.source)
        {
            return Err(BackendError::new(
                BackendErrorKind::Unsupported,
                "O_DIRECT: invalid argument",
            ));
        }
        state.check_free(request.into, "a read was started");
        let (latency, per_byte) = state
            .timing
            .get(&request.source)
            .copied()
            .unwrap_or((100, 1));
        let now = state.now();
        let start = state
            .busy_until
            .get(&request.source)
            .copied()
            .unwrap_or(0)
            .max(now);
        let complete_at = start + latency + per_byte * request.length_bytes;
        state.busy_until.insert(request.source.clone(), complete_at);
        state.next_ticket += 1;
        let ticket = state.next_ticket;
        state.reads.insert(
            ticket,
            FakeRead {
                request: request.clone(),
                complete_at,
            },
        );
        state.note(Entry::BeginRead {
            source: request.source.to_string(),
            artifact: request.artifact,
            method: request.method,
            into: request.into,
            offset: request.offset_bytes,
            length: request.length_bytes,
            ticket,
        });
        Ok(ReadTicket(ticket))
    }

    fn poll_read(&mut self, ticket: ReadTicket) -> Result<ReadStatus, BackendError> {
        let mut state = self.state();
        state.settle();
        let now = state.now();
        let Some(read) = state.reads.get(&ticket.0) else {
            return Err(BackendError::new(BackendErrorKind::Io, "unknown ticket"));
        };
        if now < read.complete_at {
            return Ok(ReadStatus::Pending);
        }
        let Some(read) = state.reads.remove(&ticket.0) else {
            return Err(BackendError::new(BackendErrorKind::Io, "unknown ticket"));
        };
        let request = read.request;
        let kind = state.read_error;
        if state.fail_tickets.remove(&ticket.0) {
            return Err(BackendError::new(kind, "injected read error"));
        }
        if let Some(remaining) = state.fail_reads.get_mut(&request.source) {
            if *remaining > 0 {
                *remaining -= 1;
                return Err(BackendError::new(kind, "injected read error"));
            }
        }
        state.check_free(request.into, "read data landed");
        let key = (
            request.source.clone(),
            request.artifact,
            request.representation,
        );
        let Some(object) = state.objects.get(&key).cloned() else {
            return Err(BackendError::new(
                BackendErrorKind::SourceUnavailable,
                "no such object",
            ));
        };
        let object_end = state
            .truncate_at
            .get(&request.source)
            .map_or(object.len() as u64, |end| (*end).min(object.len() as u64));
        let available = object_end
            .saturating_sub(request.offset_bytes)
            .min(request.length_bytes);
        let start = request.offset_bytes as usize;
        let mut data = if available == 0 {
            Vec::new()
        } else {
            object[start..start + available as usize].to_vec()
        };
        for (source, artifact, offset) in &state.corrupt {
            if *source == request.source
                && *artifact == request.artifact
                && *offset >= request.offset_bytes
                && *offset < request.offset_bytes + available
            {
                data[(*offset - request.offset_bytes) as usize] ^= 0xff;
            }
        }
        state.staging.insert(request.into, data);
        state.note(Entry::ReadDone {
            ticket: ticket.0,
            bytes: available,
        });
        Ok(match state.serve_as.get(&request.method) {
            Some(path) => ReadStatus::Served {
                bytes_read: available,
                path: *path,
            },
            None => ReadStatus::Complete {
                bytes_read: available,
            },
        })
    }

    fn stored_digest(
        &mut self,
        range: &StagedRange,
        form: &StoredForm,
    ) -> Result<Digest, BackendError> {
        let mut state = self.state();
        state.settle();
        let bytes = state.staged(range)?;
        state.advance(state.hash_ns_per_byte * bytes.len() as u64);
        state.note(Entry::Hash { range: *range });
        Ok(match form {
            StoredForm::Raw => *ContentKey::of(&bytes).digest(),
            StoredForm::Encoded {
                codec, dictionary, ..
            } => EncodedDigest::of(*codec, *dictionary, &bytes).digest(),
        })
    }

    fn content_key(&mut self, range: &StagedRange) -> Result<ContentKey, BackendError> {
        let mut state = self.state();
        state.settle();
        let bytes = state.staged(range)?;
        state.advance(state.hash_ns_per_byte * bytes.len() as u64);
        state.note(Entry::Hash { range: *range });
        Ok(ContentKey::of(&bytes))
    }

    fn decode(&mut self, request: &DecodeRequest) -> Result<u64, BackendError> {
        let mut state = self.state();
        state.settle();
        let encoded = state.staged(&request.from)?;
        let decoded = fake_decode(&encoded)
            .ok_or_else(|| BackendError::new(BackendErrorKind::Decode, "bad frame"))?;
        if decoded.len() as u64 > request.into.length_bytes {
            return Err(BackendError::new(
                BackendErrorKind::Decode,
                "output too small",
            ));
        }
        state.check_free(request.into.buffer, "decoded bytes were written");
        let buffer = state.staging.entry(request.into.buffer).or_default();
        let start = request.into.offset_bytes as usize;
        let end = start + decoded.len();
        if buffer.len() < end {
            buffer.resize(end, 0);
        }
        buffer[start..end].copy_from_slice(&decoded);
        state.advance(state.decode_ns_per_byte * decoded.len() as u64);
        state.note(Entry::Decode {
            from: request.from,
            into: request.into,
        });
        Ok(decoded.len() as u64)
    }

    fn enqueue_copy(&mut self, request: &CopyRequest) -> Result<(), BackendError> {
        let mut state = self.state();
        state.settle();
        if !state.fail_enqueue.is_empty() {
            let kind = state.fail_enqueue.remove(0);
            return Err(BackendError::new(kind, "injected copy failure"));
        }
        if request.api != state.copy_api {
            let message = format!("copy used {} instead of {}", request.api, state.copy_api);
            state.violations.push(message);
        }
        let device = request.to.allocation.device;
        let now = state.now();
        let start = state
            .stream_until
            .get(&device)
            .copied()
            .unwrap_or(0)
            .max(now);
        let complete_at = start + state.copy_ns_per_byte * request.from.length_bytes;
        state.stream_until.insert(device, complete_at);
        state.copies.push(FakeCopy {
            from: request.from,
            to: request.to,
            complete_at,
            applied: false,
        });
        state.note(Entry::EnqueueCopy {
            from: request.from,
            to: request.to,
            api: request.api,
        });
        Ok(())
    }

    fn record_event(&mut self, device: GpuDeviceKey) -> Result<EventId, BackendError> {
        let mut state = self.state();
        state.settle();
        if state.fail_record {
            return Err(BackendError::new(BackendErrorKind::Event, "record failed"));
        }
        let reused = state
            .duplicate_event
            .then(|| state.events.keys().next_back().copied())
            .flatten();
        let event = match reused {
            Some(event) => event,
            None => {
                state.next_event += 1;
                state.next_event
            }
        };
        let now = state.now();
        let complete_at = state
            .stream_until
            .get(&device)
            .copied()
            .unwrap_or(0)
            .max(now);
        let failed = state.fail_events > 0;
        if failed {
            state.fail_events -= 1;
        }
        state.events.insert(
            event,
            FakeEvent {
                complete_at,
                failed,
            },
        );
        state.note(Entry::RecordEvent { event });
        Ok(EventId(event))
    }

    fn query_event(&mut self, event: EventId) -> Result<EventStatus, BackendError> {
        let mut state = self.state();
        state.settle();
        let now = state.now();
        let Some(recorded) = state.events.get(&event.0) else {
            return Err(BackendError::new(BackendErrorKind::Event, "unknown event"));
        };
        if now < recorded.complete_at {
            return Ok(EventStatus::Pending);
        }
        let failed = recorded.failed;
        state.note(Entry::EventDone { event: event.0 });
        Ok(if failed {
            EventStatus::Failed
        } else {
            EventStatus::Complete
        })
    }

    fn release_event(&mut self, event: EventId) -> Result<(), BackendError> {
        let mut state = self.state();
        let now = state.now();
        match state.events.get(&event.0) {
            Some(recorded) if recorded.complete_at <= now => {
                state.events.remove(&event.0);
                state.note(Entry::ReleaseEvent { event: event.0 });
                Ok(())
            }
            _ => Err(BackendError::new(
                BackendErrorKind::Event,
                "event not finished",
            )),
        }
    }
}

type Resolution = Result<ResolvedManifest, CatalogRefusal>;

/// A catalog with scripted resolutions.
#[derive(Clone)]
pub(super) struct FakeCatalog {
    manifests: Arc<Mutex<BTreeMap<(ContentKey, ContentKey), Resolution>>>,
    /// Per execution: a different resolution, for tests of joining.
    per_execution: Arc<Mutex<BTreeMap<String, ResolvedManifest>>>,
    journal: Journal,
}

impl FakeCatalog {
    pub(super) fn publish(&self, manifest: ResolvedManifest) {
        lock(&self.manifests).insert((manifest.artifact, manifest.representation), Ok(manifest));
    }

    pub(super) fn refuse(
        &self,
        artifact: ContentKey,
        representation: ContentKey,
        refusal: CatalogRefusal,
    ) {
        lock(&self.manifests).insert((artifact, representation), Err(refusal));
    }

    /// What `execution` alone resolves, whatever the artifact.
    pub(super) fn publish_for(&self, execution: &str, manifest: ResolvedManifest) {
        lock(&self.per_execution).insert(execution.to_owned(), manifest);
    }
}

impl CatalogPort for FakeCatalog {
    fn resolve(&self, request: &ResolveRequest) -> Result<ResolvedManifest, CatalogRefusal> {
        lock(&self.journal).push(Entry::Resolve);
        if let Some(manifest) = lock(&self.per_execution).get(request.execution.as_str()) {
            return Ok(manifest.clone());
        }
        lock(&self.manifests)
            .get(&(request.artifact, request.representation))
            .cloned()
            .unwrap_or(Err(CatalogRefusal::NotFound))
    }
}

/// How the fake batching port behaves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Batching {
    /// Greedy coalescing of adjacent extents into canonical aligned batches.
    Canonical,
    /// Puts the first and third extents together, skipping the second.
    SkipsAnExtent,
    /// Reads the second extent from its own offset instead of the aligned one.
    UnalignedStart,
    /// One batch with every extent, whatever the slot size.
    IgnoresTheSlot,
    /// Leaves the last extent out.
    DropsTheLast,
    /// Puts the first extent in two batches.
    Repeats,
}

#[derive(Clone)]
pub(super) struct FakeBatcher {
    pub(super) mode: Arc<Mutex<Batching>>,
    journal: Journal,
}

fn align_down(value: u64, alignment: u64) -> u64 {
    value / alignment * alignment
}

fn align_up(value: u64, alignment: u64) -> u64 {
    value.div_ceil(alignment) * alignment
}

fn plan_of(members: &[&ExtentSpan], alignment: u64) -> BatchPlan {
    let first = members[0];
    let last = members[members.len() - 1];
    let start = align_down(first.offset_bytes, alignment);
    let end = align_up(last.offset_bytes + last.length_bytes, alignment);
    BatchPlan {
        members: members.iter().map(|span| span.index).collect(),
        read_offset_bytes: start,
        read_length_bytes: end - start,
    }
}

impl BatchPort for FakeBatcher {
    fn coalesce(&self, spans: &[ExtentSpan], limits: &BatchLimits) -> Vec<BatchPlan> {
        lock(&self.journal).push(Entry::Coalesce { spans: spans.len() });
        let alignment = limits.alignment_bytes;
        let all: Vec<&ExtentSpan> = spans.iter().collect();
        let singles =
            || -> Vec<BatchPlan> { all.iter().map(|span| plan_of(&[span], alignment)).collect() };
        match *lock(&self.mode) {
            Batching::Canonical => {
                let mut plans = Vec::new();
                let mut current: Vec<&ExtentSpan> = Vec::new();
                let mut decoded = 0;
                for span in spans {
                    if let Some(last) = current.last() {
                        let adjacent = last.offset_bytes + last.length_bytes == span.offset_bytes;
                        let read = align_up(span.offset_bytes + span.length_bytes, alignment)
                            - align_down(current[0].offset_bytes, alignment);
                        let fits = read <= limits.max_read_bytes
                            && decoded + span.decode_bytes <= limits.max_decoded_bytes;
                        if !(adjacent && fits) {
                            plans.push(plan_of(&current, alignment));
                            current.clear();
                            decoded = 0;
                        }
                    }
                    decoded += span.decode_bytes;
                    current.push(span);
                }
                if !current.is_empty() {
                    plans.push(plan_of(&current, alignment));
                }
                plans
            }
            Batching::SkipsAnExtent => {
                let mut plans = vec![plan_of(&[all[0], all[2]], alignment)];
                plans.extend(
                    all[1..2]
                        .iter()
                        .chain(&all[3..])
                        .map(|span| plan_of(&[span], alignment)),
                );
                plans
            }
            Batching::UnalignedStart => {
                let mut plans = singles();
                plans[1].read_offset_bytes = all[1].offset_bytes;
                plans
            }
            Batching::IgnoresTheSlot => vec![plan_of(&all, alignment)],
            Batching::DropsTheLast => {
                let mut plans = singles();
                plans.pop();
                plans
            }
            Batching::Repeats => {
                let mut plans = singles();
                plans.push(plan_of(&[all[0]], alignment));
                plans
            }
        }
    }
}

pub(super) struct LedgerState {
    capacity: BTreeMap<ReservedResource, u64>,
    used: BTreeMap<ReservedResource, u64>,
    held: BTreeMap<ReservationId, (ReservedResource, u64, ReservationPurpose)>,
    in_use: BTreeSet<ReservationId>,
    /// Released after use: still counted until the host observes the release.
    releasing: BTreeMap<ReservationId, (ReservedResource, u64)>,
    next: u64,
    requests: Vec<ReservationRequest>,
    /// Reservations carved from a parent.
    children: BTreeSet<ReservationId>,
}

/// A ledger with per-resource capacities; unknown resources are unlimited. Like the host
/// ledger, a reservation released after it was in use keeps counting until the host
/// observes the release.
#[derive(Clone)]
pub(super) struct FakeLedger {
    state: Arc<Mutex<LedgerState>>,
    journal: Journal,
}

impl FakeLedger {
    pub(super) fn set_capacity(&self, resource: ReservedResource, bytes: u64) {
        lock(&self.state).capacity.insert(resource, bytes);
    }

    /// Reservations granted and not released.
    pub(super) fn held(
        &self,
    ) -> BTreeMap<ReservationId, (ReservedResource, u64, ReservationPurpose)> {
        lock(&self.state).held.clone()
    }

    /// Released after use and still counted.
    pub(super) fn releasing(&self) -> BTreeSet<ReservationId> {
        lock(&self.state).releasing.keys().copied().collect()
    }

    /// Bytes counted against `resource`.
    pub(super) fn used(&self, resource: ReservedResource) -> u64 {
        lock(&self.state).used.get(&resource).copied().unwrap_or(0)
    }

    /// The host observed every pending release.
    pub(super) fn observe_releases(&self) {
        let mut state = lock(&self.state);
        for (resource, bytes) in std::mem::take(&mut state.releasing).into_values() {
            for (charged, amount) in charges(resource, bytes) {
                *state.used.entry(charged).or_default() -= amount;
            }
        }
    }

    pub(super) fn requests(&self) -> Vec<ReservationRequest> {
        lock(&self.state).requests.clone()
    }
}

/// What a reservation is charged to: pinned bytes are host RAM too (GPU §2.7).
fn charges(resource: ReservedResource, bytes: u64) -> Vec<(ReservedResource, u64)> {
    match resource {
        ReservedResource::PinnedHostMemory => {
            vec![(resource, bytes), (ReservedResource::HostMemory, bytes)]
        }
        ReservedResource::DeviceMemory { .. } | ReservedResource::HostMemory => {
            vec![(resource, bytes)]
        }
    }
}

impl ReservationPort for FakeLedger {
    fn reserve(
        &mut self,
        request: &ReservationRequest,
    ) -> Result<ReservationId, ReservationRefusal> {
        let mut state = lock(&self.state);
        state.requests.push(request.clone());
        let charged = charges(request.resource, request.bytes);
        for (resource, bytes) in &charged {
            let capacity = state.capacity.get(resource).copied().unwrap_or(u64::MAX);
            let used = state.used.get(resource).copied().unwrap_or(0);
            let available = capacity - used;
            if *bytes > available {
                lock(&self.journal).push(Entry::Refuse {
                    purpose: request.purpose,
                });
                return Err(ReservationRefusal::Capacity(CapacityRefusal {
                    resource: *resource,
                    limit: CapacityLimit::PhysicalCapacity,
                    requested_bytes: *bytes,
                    available_bytes: available,
                    retry: if *bytes > capacity {
                        RetryAdvice::CannotProgress
                    } else {
                        RetryAdvice::CanProgress
                    },
                }));
            }
        }
        state.next += 1;
        let reservation = ReservationId(state.next);
        for (resource, bytes) in charged {
            *state.used.entry(resource).or_default() += bytes;
        }
        state.held.insert(
            reservation,
            (request.resource, request.bytes, request.purpose),
        );
        if request.parent.is_some() {
            state.children.insert(reservation);
        }
        lock(&self.journal).push(Entry::Reserve {
            purpose: request.purpose,
            resource: request.resource,
            bytes: request.bytes,
            reservation,
        });
        Ok(reservation)
    }

    fn begin_use(&mut self, reservation: ReservationId) -> Result<(), UnknownReservation> {
        let mut state = lock(&self.state);
        if !state.held.contains_key(&reservation) {
            return Err(UnknownReservation { reservation });
        }
        state.in_use.insert(reservation);
        lock(&self.journal).push(Entry::BeginUse { reservation });
        Ok(())
    }

    fn release(&mut self, reservation: ReservationId) -> Result<(), UnknownReservation> {
        let mut state = lock(&self.state);
        let (resource, bytes, _) = state
            .held
            .remove(&reservation)
            .ok_or(UnknownReservation { reservation })?;
        if state.in_use.remove(&reservation) {
            state.releasing.insert(reservation, (resource, bytes));
        } else {
            for (charged, amount) in charges(resource, bytes) {
                *state.used.entry(charged).or_default() -= amount;
            }
        }
        lock(&self.journal).push(Entry::Release { reservation });
        Ok(())
    }

    /// A child goes back to its parent at once; anything else is released.
    fn hand_over(&mut self, reservation: ReservationId) -> Result<(), UnknownReservation> {
        let mut state = lock(&self.state);
        if !state.children.remove(&reservation) {
            drop(state);
            return self.release(reservation);
        }
        let (resource, bytes, _) = state
            .held
            .remove(&reservation)
            .ok_or(UnknownReservation { reservation })?;
        state.in_use.remove(&reservation);
        for (charged, amount) in charges(resource, bytes) {
            *state.used.entry(charged).or_default() -= amount;
        }
        lock(&self.journal).push(Entry::HandOver { reservation });
        Ok(())
    }
}

/// Records every event.
#[derive(Clone, Default)]
pub(super) struct FakeEvents {
    pub(super) events: Arc<Mutex<Vec<TransferEvent>>>,
}

impl EventPort for FakeEvents {
    fn emit(&mut self, event: TransferEvent) {
        lock(&self.events).push(event);
    }
}

/// The GPU and driver configuration every test runtime and GPU runs under.
pub(super) fn gpu_configuration() -> ConfigurationFingerprint {
    ConfigurationFingerprint::from_settings([("driver", "580.1")]).expect("a valid configuration")
}

/// How the world's executors judge GPU peer access: a guest report, an hour old at most,
/// under the world's GPU configuration.
pub(super) fn peer_policy() -> PeerAccessPolicy {
    PeerAccessPolicy {
        evidence: EvidencePolicy {
            minimum_source: SourceClass::GuestReport,
            max_age: Duration::from_secs(3_600),
        },
        configuration: gpu_configuration(),
    }
}

/// Every fake, sharing one clock and one journal, and the host's evidence registry on
/// that clock, which every executor of the world rechecks gated methods in.
pub(super) struct World {
    pub(super) clock: Arc<ManualClock>,
    pub(super) journal: Journal,
    pub(super) backend: FakeBackend,
    pub(super) catalog: FakeCatalog,
    pub(super) batcher: FakeBatcher,
    pub(super) ledger: FakeLedger,
    pub(super) events: FakeEvents,
    pub(super) registry: Arc<Mutex<ProbeRegistry<Arc<ManualClock>>>>,
    /// One guest-report probe per capability, answering for every runtime planned for.
    pub(super) probes: Mutex<BTreeMap<Capability, Arc<FakeProbe>>>,
    /// Runtimes planned for so far; each plan gets a runtime of its own.
    pub(super) runtimes: Mutex<u64>,
}

impl World {
    pub(super) fn new() -> Self {
        let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(1_000)));
        let journal: Journal = Arc::default();
        Self {
            backend: FakeBackend::new(Arc::clone(&clock), Arc::clone(&journal)),
            catalog: FakeCatalog {
                manifests: Arc::default(),
                per_execution: Arc::default(),
                journal: Arc::clone(&journal),
            },
            batcher: FakeBatcher {
                mode: Arc::new(Mutex::new(Batching::Canonical)),
                journal: Arc::clone(&journal),
            },
            ledger: FakeLedger {
                state: Arc::new(Mutex::new(LedgerState {
                    capacity: BTreeMap::new(),
                    used: BTreeMap::new(),
                    held: BTreeMap::new(),
                    in_use: BTreeSet::new(),
                    releasing: BTreeMap::new(),
                    next: 0,
                    requests: Vec::new(),
                    children: BTreeSet::new(),
                })),
                journal: Arc::clone(&journal),
            },
            events: FakeEvents::default(),
            registry: Arc::new(Mutex::new(ProbeRegistry::new(Arc::clone(&clock)))),
            probes: Mutex::new(BTreeMap::new()),
            runtimes: Mutex::new(0),
            clock,
            journal,
        }
    }

    /// The ports, with the fake ledger as the reservation port.
    pub(super) fn ports(&self) -> ExecutorPorts {
        self.ports_with(Box::new(self.ledger.clone()))
    }

    /// The ports with another reservation port, such as the host ledger's adapter.
    pub(super) fn ports_with(
        &self,
        reservations: Box<dyn ReservationPort + Send>,
    ) -> ExecutorPorts {
        ExecutorPorts {
            backend: Box::new(self.backend.clone()),
            catalog: Box::new(self.catalog.clone()),
            batches: Box::new(self.batcher.clone()),
            reservations,
            events: Box::new(self.events.clone()),
        }
    }

    /// An executor on the fake ports that rechecks gated methods and GPU peer access in
    /// the world's registry.
    pub(super) fn try_executor(
        &self,
        config: ExecutorConfig,
    ) -> Result<TransferExecutor<Arc<ManualClock>>, StartError> {
        TransferExecutor::new(config, Arc::clone(&self.clock), self.ports()).map(|executor| {
            executor
                .with_evidence(Box::new(Arc::clone(&self.registry)))
                .with_peer_access(peer_policy())
        })
    }

    /// The world's probe of `capability`, registered on first use.
    pub(super) fn probe(&self, capability: Capability) -> Arc<FakeProbe> {
        let mut probes = lock(&self.probes);
        if let Some(probe) = probes.get(&capability) {
            return Arc::clone(probe);
        }
        let probe = Arc::new(FakeProbe::guest_report(capability));
        lock(&self.registry)
            .register(Box::new(Arc::clone(&probe)))
            .expect("one probe per capability");
        probes.insert(capability, Arc::clone(&probe));
        probe
    }

    /// A number no earlier runtime of the world has.
    pub(super) fn next_runtime(&self) -> u64 {
        let mut runtimes = lock(&self.runtimes);
        *runtimes += 1;
        *runtimes
    }

    pub(super) fn executor(&self, config: ExecutorConfig) -> TransferExecutor<Arc<ManualClock>> {
        self.try_executor(config).expect("the executor starts")
    }

    pub(super) fn journal(&self) -> Vec<Entry> {
        lock(&self.journal).clone()
    }

    pub(super) fn events(&self) -> Vec<TransferEvent> {
        lock(&self.events.events).clone()
    }

    pub(super) fn advance(&self, nanos: u64) {
        self.clock.advance(Duration::from_nanos(nanos));
    }
}
