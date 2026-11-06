//! Tests of the transfer executor (GPU §3.5, GPU-W04): one or more per rule, on fakes
//! driven by a manual clock, and one through the host ledger.

use std::collections::{BTreeMap, BTreeSet};
use std::num::{NonZeroU32, NonZeroU64};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::fakes::{fake_encode, gpu_configuration, Batching, Entry, World};
use super::*;
use crate::foundation::events::{
    EventHub, HubConfig, MetricsConfig, Phase, ProducerId, ProducerIncarnation, ProgressConfig,
    ResourceKind, RevocationConfig, TrackedResourceId,
};
use crate::foundation::evidence::{
    Backend, BackendRelease, Capability, ComputePlatform as ObservedPlatform,
    ConfigurationFingerprint, EvidencePolicy, EvidenceRefusal, GpuPairSubject, HostSubject,
    LoaderGate, LoaderPlan, LoaderRequest, Necessity, Observation, Optimization, RuntimeProfile,
    RuntimeSubject, SourceClass, Subject, SupportDetail, UnsupportedReason,
};
use crate::foundation::ids::{
    digest, ContentKey, ExecutionCategory, ExecutionId, GpuAllocationGeneration, GpuDeviceKey,
    Incarnation, ManualClock, OperationId, TenantId,
};
use crate::foundation::ledger::{
    self as host, Admission, Amounts, CapacityDeclaration, CostPurpose, Ledger, LedgerConfig,
    Provenance, QueueLimits, Requester, ReservationState,
};
use crate::foundation::report::{ClockId, Label as ReportLabel};
use crate::foundation::transfer::fakes as tf;
use crate::foundation::transfer::{
    ByteBudgetPort, ByteRange, Connection, Direction, Endpoint, EnvelopeFields, LedgerByteBudget,
    ObjectGrant, ProgressPhase, RangeSet, StopBounds, StopReason, TransferEnvelope, TransferKey,
    TransferPorts, TransferRefusal, TransferScope, TransferStatus, NETWORK_SLOT_RESOURCE,
};
use crate::model_memory::backends::{
    BackendRuntime, ComputePlatform, PinnedCapabilities, PlatformRefusal, QueriedCapabilities,
    RuntimeRefusal,
};
use crate::model_memory::manifest::{CodecFormat, EncodedDigest, ZstdFrameParameters};
use crate::model_memory::math::bounds::BandwidthRating;
use crate::model_memory::math::calibration::SchedulingMode;
use crate::model_memory::math::prefetch::{
    expected_value, AdmissionRefusal, CandidateOrigin, Objective, PrefetchBudget,
    PrefetchCandidate, PrefetchError, PrefetchValue, RawCost, TransferClass,
};
use crate::model_memory::math::sources::{
    SourceAuthorization, SourceSpec, SourcesError, StealPolicy,
};
use crate::model_memory::math::{CandidateId, SourceId};
use crate::model_memory::progress::fakes as progress_fakes;
use crate::model_memory::progress::{
    ProgressPublisher, PublishError, PublishPolicy, Stage as ProgressStage, TrackRequest,
};

type Exec = TransferExecutor<Arc<ManualClock>>;

const ALIGN: u64 = 16;

fn device(name: &str) -> GpuDeviceKey {
    GpuDeviceKey {
        machine: digest("yougori/test/machine/v1", &[b"host"]),
        device: digest("yougori/test/device/v1", &[name.as_bytes()]),
    }
}

fn gpu0() -> GpuDeviceKey {
    device("gpu-0")
}

fn gpu1() -> GpuDeviceKey {
    device("gpu-1")
}

fn source(name: &str) -> SourceId {
    SourceId::new(name).unwrap()
}

fn spec(name: &str, bytes_per_second: f64) -> SourceSpec {
    SourceSpec {
        id: source(name),
        authorization: SourceAuthorization::Authorized,
        startup_seconds: 0.0,
        bandwidth: BandwidthRating::measured_directional(bytes_per_second).unwrap(),
        cuts: vec![],
        max_in_flight: 4,
        interference_seconds_per_byte: 0.0,
    }
}

fn candidate(name: &str, kind: SourceKind, bytes_per_second: f64) -> SourceCandidate {
    SourceCandidate {
        kind,
        spec: spec(name, bytes_per_second),
    }
}

fn local(name: &str) -> SourceCandidate {
    candidate(name, SourceKind::LocalFile, 1e9)
}

/// The codec format the fake codec's extents declare; the fake codec stands in for zstd.
const FAKE_FORMAT: CodecFormat = CodecFormat::ZstdRfc8878(ZstdFrameParameters {
    dictionary_id: 0,
    content_checksum: false,
    max_window_bytes: 1 << 20,
});

/// An artifact with deterministic bytes, stored raw or with the fake codec.
struct Artifact {
    key: ContentKey,
    representation: ContentKey,
    decoded: Vec<u8>,
    stored: Vec<u8>,
    extents: Vec<ManifestExtent>,
}

impl Artifact {
    fn new(name: &str, lengths: &[u64], encoded: bool) -> Self {
        let seed = name
            .bytes()
            .fold(7u8, |acc, byte| acc.wrapping_mul(31).wrapping_add(byte));
        let total: u64 = lengths.iter().sum();
        let decoded: Vec<u8> = (0..total)
            .map(|i| (i as u8).wrapping_mul(37).wrapping_add(seed))
            .collect();
        let mut stored = Vec::new();
        let mut extents = Vec::new();
        let mut offset = 0u64;
        for (index, length) in lengths.iter().enumerate() {
            let slice = &decoded[offset as usize..(offset + length) as usize];
            let (bytes, form) = if encoded {
                let bytes = fake_encode(slice);
                let form = StoredForm::Encoded {
                    codec: FAKE_FORMAT,
                    dictionary: None,
                    digest: EncodedDigest::of(FAKE_FORMAT, None, &bytes),
                };
                (bytes, form)
            } else {
                (slice.to_vec(), StoredForm::Raw)
            };
            extents.push(ManifestExtent {
                index: index as u64,
                stored_offset_bytes: stored.len() as u64,
                stored_length_bytes: bytes.len() as u64,
                stored: form,
                decoded_offset_bytes: offset,
                decoded_length_bytes: *length,
                decoded_key: ContentKey::of(slice),
            });
            stored.extend_from_slice(&bytes);
            offset += length;
        }
        Self {
            key: ContentKey::of(name.as_bytes()),
            representation: ContentKey::of(&stored),
            decoded,
            stored,
            extents,
        }
    }

    fn manifest(&self, sources: Vec<SourceCandidate>) -> ResolvedManifest {
        ResolvedManifest {
            manifest: ContentKey::of(b"manifest"),
            artifact: self.key,
            representation: self.representation,
            object_length_bytes: self.stored.len() as u64,
            extents: self.extents.clone(),
            sources,
            cuts: vec![],
        }
    }

    fn all(&self) -> Vec<u64> {
        (0..self.extents.len() as u64).collect()
    }

    fn decoded_of(&self, index: usize) -> &[u8] {
        let extent = &self.extents[index];
        let start = extent.decoded_offset_bytes as usize;
        &self.decoded[start..start + extent.decoded_length_bytes as usize]
    }
}

/// Stores the artifact on every source and publishes its manifest.
fn publish(world: &World, artifact: &Artifact, sources: Vec<SourceCandidate>) {
    for candidate in &sources {
        world.backend.store(
            &candidate.spec.id,
            artifact.key,
            artifact.representation,
            artifact.stored.clone(),
        );
    }
    world.catalog.publish(artifact.manifest(sources));
}

fn allocation(device: GpuDeviceKey, name: &str) -> AllocationKey {
    AllocationKey {
        device,
        allocation: digest("yougori/test/allocation/v1", &[name.as_bytes()]),
        generation: GpuAllocationGeneration::FIRST,
    }
}

fn destination(name: &str) -> Destination {
    Destination {
        allocation: allocation(gpu0(), name),
        base_offset_bytes: 0,
        capacity_bytes: 1 << 20,
    }
}

fn op(name: &str) -> OperationId {
    OperationId::new(name).unwrap()
}

fn dependency(id: u64, extents: &[u64], requires: &[u64]) -> DependencySpec {
    DependencySpec {
        id: DependencyId(id),
        extents: extents.to_vec(),
        requires: requires.iter().map(|id| DependencyId(*id)).collect(),
    }
}

/// A foreground job for every extent of `artifact`, as one dependency.
fn request(name: &str, artifact: &Artifact, destination: Destination) -> TransferRequest {
    TransferRequest {
        operation: op(name),
        execution: ExecutionId::new(format!("exe-{name}")).unwrap(),
        tenant: TenantId::new("tenant-a").unwrap(),
        artifact: artifact.key,
        representation: artifact.representation,
        destination,
        dependencies: vec![dependency(1, &artifact.all(), &[])],
        priority: JobPriority::Foreground,
        loader: LoaderPermissions::ordinary(),
    }
}

fn config() -> ExecutorConfig {
    ExecutorConfig {
        operation: op("executor"),
        host_staging: HostStagingConfig {
            memory: HostStagingMemory::Pinned,
            slots: 4,
            slot_bytes: 64,
        },
        device_staging: BTreeMap::new(),
        alignment_bytes: ALIGN,
        max_attempts: 3,
        local_read_method: ReadMethod::PositionedRead,
        steal_policy: StealPolicy {
            min_gain_seconds: 1.0,
            min_gain_fraction: 0.5,
            max_moves_per_batch: 1,
            max_moves_per_rebalance: 1,
        },
        prefetch_budget: PrefetchBudget {
            max_speculative_bytes: 1 << 20,
            capacity_bytes: 1 << 30,
            reserved_foreground_bytes: 1 << 10,
        },
    }
}

fn with_device_staging(mut config: ExecutorConfig, slots: u32, slot_bytes: u64) -> ExecutorConfig {
    config
        .device_staging
        .insert(gpu0(), DeviceStagingConfig { slots, slot_bytes });
    config
}

/// Pumps until nothing is queued or in flight, 50 ns at a time.
fn drive(executor: &mut Exec, world: &World) {
    for _ in 0..10_000 {
        executor.pump().expect("the pump runs");
        if executor.is_idle() {
            return;
        }
        world.advance(50);
    }
    panic!("the executor did not go idle");
}

/// Every read started: source, artifact, method, buffer, offset and length.
fn reads(world: &World) -> Vec<(String, ContentKey, ReadMethod, StagingBuffer, u64, u64)> {
    world
        .journal()
        .into_iter()
        .filter_map(|entry| match entry {
            Entry::BeginRead {
                source,
                artifact,
                method,
                into,
                offset,
                length,
                ..
            } => Some((source, artifact, method, into, offset, length)),
            _ => None,
        })
        .collect()
}

fn position(journal: &[Entry], wanted: impl Fn(&Entry) -> bool) -> usize {
    journal.iter().position(wanted).expect("the entry exists")
}

fn count(journal: &[Entry], wanted: impl Fn(&Entry) -> bool) -> usize {
    journal.iter().filter(|entry| wanted(entry)).count()
}

fn is_destination_reserve(entry: &Entry) -> bool {
    matches!(
        entry,
        Entry::Reserve {
            purpose: ReservationPurpose::Destination { .. },
            ..
        }
    )
}

fn stages(world: &World, operation: &OperationId) -> Vec<StageMeasurement> {
    world
        .events()
        .into_iter()
        .filter(|event| event.operation == *operation)
        .filter_map(|event| match event.kind {
            TransferEventKind::StageMeasured(measurement) => Some(measurement),
            _ => None,
        })
        .collect()
}

fn kinds(world: &World, operation: &OperationId) -> Vec<TransferEventKind> {
    world
        .events()
        .into_iter()
        .filter(|event| event.operation == *operation)
        .map(|event| event.kind)
        .collect()
}

fn failure_of(executor: &Exec, operation: &OperationId) -> JobFailure {
    match executor.status(operation) {
        Some(JobStatus::Failed { failure }) => failure.clone(),
        other => panic!("the job did not fail: {other:?}"),
    }
}

/// The configuration every test runtime runs under.
fn loader_configuration() -> ConfigurationFingerprint {
    gpu_configuration()
}

/// The world's registry observes `capability` of `subject`, fresh for `fresh_for`.
fn observe(world: &World, capability: Capability, subject: &Subject, observation: Observation) {
    world.probe(capability).respond(subject, observation);
    world
        .registry
        .lock()
        .unwrap()
        .refresh(capability, subject)
        .unwrap();
}

/// The world's registry observes the runtime of `profile` computing on `platform`
/// (CORE-01 `ComputePlatform`), fresh for `fresh_for`.
fn show_platform(
    world: &World,
    profile: &RuntimeProfile,
    platform: ObservedPlatform,
    fresh_for: Duration,
) {
    observe(
        world,
        Capability::ComputePlatform,
        &Subject::Runtime(profile.runtime.clone()),
        Observation::supported(
            loader_configuration(),
            fresh_for,
            SupportDetail::ComputePlatform { platform },
        ),
    );
}

/// The world's registry observes a peer copy from `from` into `to` (CORE-01
/// `GpuPeerAccess`), succeeding or not, fresh for `fresh_for`.
fn show_peer_access(
    world: &World,
    from: GpuDeviceKey,
    to: GpuDeviceKey,
    supported: bool,
    fresh_for: Duration,
) {
    let observation = if supported {
        Observation::supported(
            loader_configuration(),
            fresh_for,
            SupportDetail::GpuPeerAccess,
        )
    } else {
        Observation::unsupported(
            loader_configuration(),
            fresh_for,
            UnsupportedReason::OperationFailed,
        )
    };
    observe(
        world,
        Capability::GpuPeerAccess,
        &Subject::GpuPair(GpuPairSubject {
            machine: from.machine,
            from: from.device,
            to: to.device,
        }),
        observation,
    );
}

/// Why a CUDA mechanism is refused when no platform evidence is left, such as after a
/// configuration change or without the registry.
fn platform_missing() -> MethodUnavailable {
    MethodUnavailable::PlatformNotShown {
        refusal: PlatformRefusal::Evidence {
            cause: EvidenceRefusal::Missing {
                capability: Capability::ComputePlatform,
            },
        },
    }
}

/// How test runtimes judge their platform: a guest report an hour old at most.
fn platform_policy() -> EvidencePolicy {
    EvidencePolicy {
        minimum_source: SourceClass::GuestReport,
        max_age: Duration::from_secs(3_600),
    }
}

/// A runtime of its own on the world's host and the real evidence gate's plan for it,
/// made with the world's registry. With `evidence`, the registry first observes each
/// optimization as supported for `fresh_for`.
fn planned(
    world: &World,
    optimizations: &[(Optimization, Necessity)],
    evidence: bool,
    fresh_for: Duration,
) -> (RuntimeProfile, LoaderPlan) {
    let instance = format!("gpu-{}", world.next_runtime());
    let runtime = RuntimeSubject {
        category: ExecutionCategory::SharedKernelGpuRuntime,
        release: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
        instance: digest("yougori/test/instance/v1", &[instance.as_bytes()]),
    };
    let subject = Subject::Runtime(runtime.clone());
    let configuration = loader_configuration();
    if evidence {
        for (optimization, _) in optimizations {
            let capability = optimization.capability();
            world.probe(capability).respond(
                &subject,
                Observation::supported(configuration, fresh_for, SupportDetail::Plain),
            );
            world
                .registry
                .lock()
                .unwrap()
                .refresh(capability, &subject)
                .unwrap();
        }
    }
    let profile = RuntimeProfile {
        runtime,
        configuration,
        permitted: optimizations
            .iter()
            .map(|(optimization, _)| {
                (
                    *optimization,
                    EvidencePolicy {
                        minimum_source: SourceClass::GuestReport,
                        max_age: Duration::from_secs(3_600),
                    },
                )
            })
            .collect(),
    };
    let request = LoaderRequest {
        optimizations: optimizations.iter().copied().collect(),
    };
    let plan = LoaderGate::recorded()
        .plan(&profile, &request, &world.registry.lock().unwrap())
        .unwrap();
    (profile, plan)
}

/// A loader plan from the real evidence gate, made with the world's registry.
fn loader_plan(
    world: &World,
    optimizations: &[(Optimization, Necessity)],
    evidence: bool,
    fresh_for: Duration,
) -> LoaderPlan {
    planned(world, optimizations, evidence, fresh_for).1
}

/// The backend runtime assembled from a planned runtime on `platform` (P06).
fn backend_runtime(
    (profile, plan): &(RuntimeProfile, LoaderPlan),
    platform: ComputePlatform,
) -> Result<BackendRuntime, RuntimeRefusal> {
    let gate = LoaderGate::recorded();
    let pinned = PinnedCapabilities::new(
        QueriedCapabilities {
            release: profile.runtime.release.clone(),
            source: SourceClass::HostProbe,
            sleep_levels: BTreeMap::new(),
            features: BTreeSet::new(),
        },
        gate.rules(),
    )
    .unwrap();
    BackendRuntime::new(profile, platform, plan, gate.rules(), pinned)
        .map(|runtime| runtime.with_platform_policy(platform_policy()))
}

/// The permissions of a runtime on CUDA whose plan asked for `optimizations`, with the
/// world's registry showing it on CUDA for an hour.
fn on_cuda(
    world: &World,
    optimizations: &[(Optimization, Necessity)],
    evidence: bool,
    fresh_for: Duration,
) -> LoaderPermissions {
    let planned = planned(world, optimizations, evidence, fresh_for);
    show_platform(
        world,
        &planned.0,
        ObservedPlatform::Cuda,
        Duration::from_secs(3_600),
    );
    let runtime = backend_runtime(&planned, ComputePlatform::Cuda).unwrap();
    LoaderPermissions::from_runtime(&runtime)
}

fn value(bytes: u64) -> PrefetchValue {
    let candidate = PrefetchCandidate {
        id: CandidateId::new("next-layers").unwrap(),
        origin: CandidateOrigin::QueuedWork,
        probability: 0.9,
        bytes,
        saved_if_used: RawCost {
            milliseconds: 100.0,
            ..RawCost::default()
        },
        waste_if_unused: RawCost {
            milliseconds: 1.0,
            ..RawCost::default()
        },
        interference: RawCost::default(),
        retention: RawCost::default(),
    };
    expected_value(&candidate, &Objective::new(1.0, 0.0, 0.0, 0.0).unwrap()).unwrap()
}

fn speculative(name: &str, artifact: &Artifact, destination: Destination) -> TransferRequest {
    let total = artifact.decoded.len() as u64;
    TransferRequest {
        priority: JobPriority::Speculative {
            value: value(total),
        },
        ..request(name, artifact, destination)
    }
}

// §3.5 steps 1–9: the portable path.

#[test]
fn the_nine_steps_run_in_order_with_measured_stage_durations() {
    let world = World::new();
    let artifact = Artifact::new("weights", &[20, 20], true);
    publish(&world, &artifact, vec![local("nvme")]);
    let mut executor = world.executor(config());
    let job = op("load");
    executor
        .submit(request("load", &artifact, destination("placement")))
        .unwrap();

    executor.pump().unwrap();
    let flight = executor.flight_of(&job, 0).unwrap();
    assert_eq!(executor.flight_phase(flight), Some(FlightPhase::Reading));
    assert_eq!(
        executor.staging_usage(StagingPlace::Host).unwrap().in_use,
        2
    );

    world.advance(148);
    executor.pump().unwrap();
    assert_eq!(executor.flight_phase(flight), Some(FlightPhase::Copying));
    assert!(!executor.is_usable(&job, DependencyId(1)));
    assert_eq!(
        executor.staging_usage(StagingPlace::Host).unwrap().in_use,
        1
    );

    world.advance(20);
    executor.pump().unwrap();
    assert_eq!(executor.flight_phase(flight), Some(FlightPhase::Delivered));
    assert!(!executor.is_usable(&job, DependencyId(1)));

    world.advance(20);
    let report = executor.pump().unwrap();
    assert_eq!(report.published, vec![(job.clone(), DependencyId(1))]);
    assert!(executor.is_usable(&job, DependencyId(1)));
    assert_eq!(executor.status(&job), Some(&JobStatus::Completed));
    assert_eq!(
        executor.staging_usage(StagingPlace::Host).unwrap().in_use,
        0
    );

    let measured = stages(&world, &job);
    let order: Vec<Stage> = measured.iter().map(|stage| stage.stage).collect();
    assert_eq!(
        order,
        [
            Stage::Resolve,
            Stage::Reserve,
            Stage::Coalesce,
            Stage::Read,
            Stage::Verify,
            Stage::Decode,
            Stage::Validate,
            Stage::Copy,
            Stage::Copy
        ]
    );
    assert!(order
        .windows(2)
        .all(|pair| pair[0].step() <= pair[1].step()));
    let nanos = |stage: &StageMeasurement| stage.duration.as_nanos();
    assert_eq!((nanos(&measured[3]), measured[3].bytes), (148, 48));
    assert_eq!((nanos(&measured[4]), measured[4].bytes), (48, 48));
    assert_eq!((nanos(&measured[5]), measured[5].bytes), (80, 40));
    assert_eq!((nanos(&measured[6]), measured[6].bytes), (40, 40));
    assert_eq!(nanos(&measured[7]), 20);
    assert_eq!(nanos(&measured[8]), 40);
    assert_eq!(measured[7].api, Some(CopyApi::CudaMemcpyAsync));
    assert_eq!(measured[3].method, Some(ReadMethod::PositionedRead));
    assert_eq!(measured[3].path, Some(TransferPath::HostRing));

    let journal = world.journal();
    let staging = position(&journal, |entry| {
        matches!(
            entry,
            Entry::Reserve {
                purpose: ReservationPurpose::HostStaging,
                ..
            }
        )
    });
    let resolve = position(&journal, |entry| *entry == Entry::Resolve);
    let reserve = position(&journal, is_destination_reserve);
    let coalesce = position(&journal, |entry| matches!(entry, Entry::Coalesce { .. }));
    let read = position(&journal, |entry| matches!(entry, Entry::BeginRead { .. }));
    let landed = position(&journal, |entry| matches!(entry, Entry::ReadDone { .. }));
    let decode = position(&journal, |entry| matches!(entry, Entry::Decode { .. }));
    let copy = position(&journal, |entry| matches!(entry, Entry::EnqueueCopy { .. }));
    let event = position(&journal, |entry| matches!(entry, Entry::RecordEvent { .. }));
    let done = position(&journal, |entry| matches!(entry, Entry::EventDone { .. }));
    assert!(staging < resolve);
    assert!(resolve < reserve && reserve < coalesce && coalesce < read);
    assert!(read < landed && landed < decode && decode < copy);
    assert!(copy < event && event < done);

    let placement = allocation(gpu0(), "placement");
    assert_eq!(
        world.backend.destination(&placement, 0, 40),
        artifact.decoded
    );
    let progress = executor.progress(&job).unwrap().snapshot;
    assert_eq!(
        progress,
        ProgressSnapshot {
            total_bytes: 40,
            verified_bytes: 40,
            committed_bytes: 40,
            usable_dependencies: 1,
            total_dependencies: 1,
        }
    );
    assert!(executor.scheduler().transfer(&job).is_none());
    assert!(world.backend.state().violations.is_empty());
}

#[test]
fn a_refused_destination_reservation_starts_nothing() {
    let world = World::new();
    let artifact = Artifact::new("weights", &[20, 20], false);
    publish(&world, &artifact, vec![local("nvme")]);
    world
        .ledger
        .set_capacity(ReservedResource::DeviceMemory { device: gpu0() }, 30);
    let mut executor = world.executor(config());
    let job = op("load");
    let refused = executor
        .submit(request("load", &artifact, destination("placement")))
        .unwrap_err();
    assert_eq!(
        refused,
        SubmitError::Reservation(ReservationRefusal::Capacity(CapacityRefusal {
            resource: ReservedResource::DeviceMemory { device: gpu0() },
            limit: CapacityLimit::PhysicalCapacity,
            requested_bytes: 20,
            available_bytes: 10,
            retry: RetryAdvice::CanProgress,
        }))
    );
    let journal = world.journal();
    let reserved = position(&journal, is_destination_reserve);
    let refusal = position(&journal, |entry| matches!(entry, Entry::Refuse { .. }));
    let release = position(&journal, |entry| matches!(entry, Entry::Release { .. }));
    assert!(reserved < refusal && refusal < release);
    assert_eq!(world.ledger.held().len(), 1);
    assert_eq!(
        world
            .ledger
            .used(ReservedResource::DeviceMemory { device: gpu0() }),
        0
    );
    executor.pump().unwrap();
    assert!(reads(&world).is_empty());
    assert!(executor.status(&job).is_none());
    assert!(executor.scheduler().transfer(&job).is_none());

    let world = World::new();
    publish(&world, &artifact, vec![local("nvme")]);
    world
        .ledger
        .set_capacity(ReservedResource::DeviceMemory { device: gpu0() }, 10);
    let mut executor = world.executor(config());
    let refused = executor
        .submit(request("load", &artifact, destination("placement")))
        .unwrap_err();
    assert!(matches!(
        refused,
        SubmitError::Reservation(ReservationRefusal::Capacity(CapacityRefusal {
            retry: RetryAdvice::CannotProgress,
            ..
        }))
    ));
    assert!(refused.to_string().contains("can never fit"));
}

#[test]
fn staging_is_reserved_and_in_use_before_anything_starts() {
    let world = World::new();
    world
        .ledger
        .set_capacity(ReservedResource::PinnedHostMemory, 100);
    let refused = world.try_executor(config()).err().unwrap();
    assert_eq!(
        refused,
        StartError::Reservation(ReservationRefusal::Capacity(CapacityRefusal {
            resource: ReservedResource::PinnedHostMemory,
            limit: CapacityLimit::PhysicalCapacity,
            requested_bytes: 256,
            available_bytes: 100,
            retry: RetryAdvice::CannotProgress,
        }))
    );
    assert!(world.ledger.held().is_empty());
    assert!(!world.journal().contains(&Entry::Resolve));

    let mut pageable = config();
    pageable.host_staging.memory = HostStagingMemory::Pageable;
    let executor = world.executor(pageable);
    let request = &world.ledger.requests()[1];
    assert_eq!(request.resource, ReservedResource::HostMemory);
    assert_eq!(request.purpose, ReservationPurpose::HostStaging);
    assert_eq!(request.priority, Priority::Foreground);
    assert_eq!(request.execution, None);
    let journal = world.journal();
    let reserve = position(&journal, |entry| {
        matches!(
            entry,
            Entry::Reserve {
                resource: ReservedResource::HostMemory,
                ..
            }
        )
    });
    let in_use = position(&journal, |entry| matches!(entry, Entry::BeginUse { .. }));
    assert!(reserve < in_use);
    assert_eq!(executor.staging_usage(StagingPlace::Host).unwrap().slots, 4);

    let world = World::new();
    world
        .ledger
        .set_capacity(ReservedResource::DeviceMemory { device: gpu0() }, 10);
    let refused = world
        .try_executor(with_device_staging(config(), 2, 64))
        .err()
        .unwrap();
    assert!(matches!(
        refused,
        StartError::Reservation(ReservationRefusal::Capacity(CapacityRefusal {
            resource: ReservedResource::DeviceMemory { .. },
            ..
        }))
    ));
    assert!(world.ledger.held().is_empty());
    assert_eq!(world.ledger.used(ReservedResource::PinnedHostMemory), 0);
    assert_eq!(
        count(&world.journal(), |entry| matches!(
            entry,
            Entry::Release { .. }
        )),
        1
    );
}

#[test]
fn configurations_are_checked() {
    let world = World::new();
    let refused = |change: &dyn Fn(&mut ExecutorConfig)| {
        let mut config = config();
        change(&mut config);
        world.try_executor(config).err().unwrap()
    };
    for alignment_bytes in [0, 3, 24] {
        assert_eq!(
            refused(&|config| config.alignment_bytes = alignment_bytes),
            StartError::Config(ConfigError::AlignmentNotPowerOfTwo { alignment_bytes })
        );
    }
    assert_eq!(
        refused(&|config| config.host_staging.slots = 0),
        StartError::Config(ConfigError::NoSlots {
            place: StagingPlace::Host
        })
    );
    assert_eq!(
        refused(&|config| config.host_staging.slot_bytes = 8),
        StartError::Config(ConfigError::SlotSmallerThanAlignment {
            place: StagingPlace::Host,
            slot_bytes: 8,
            alignment_bytes: 16
        })
    );
    assert_eq!(
        refused(&|config| {
            config.host_staging.slots = u32::MAX;
            config.host_staging.slot_bytes = u64::MAX;
        }),
        StartError::Config(ConfigError::PoolTooLarge {
            place: StagingPlace::Host
        })
    );
    assert_eq!(
        refused(&|config| {
            config.device_staging.insert(
                gpu0(),
                DeviceStagingConfig {
                    slots: 0,
                    slot_bytes: 64,
                },
            );
        }),
        StartError::Config(ConfigError::NoSlots {
            place: StagingPlace::Device { device: gpu0() }
        })
    );
    assert_eq!(
        refused(&|config| config.max_attempts = 0),
        StartError::Config(ConfigError::ZeroAttempts)
    );
    assert_eq!(
        refused(&|config| config.local_read_method = ReadMethod::IoUring),
        StartError::Config(ConfigError::NotAnOrdinaryLocalMethod {
            method: ReadMethod::IoUring
        })
    );
    assert_eq!(
        refused(&|config| config.local_read_method = ReadMethod::UpstreamLoader),
        StartError::Config(ConfigError::MethodNotImplemented {
            method: ReadMethod::UpstreamLoader
        })
    );
    assert!(matches!(
        refused(&|config| config.prefetch_budget.reserved_foreground_bytes = u64::MAX),
        StartError::Prefetch(_)
    ));
    assert!(world.ledger.held().is_empty());
}

#[test]
fn adjacent_extents_coalesce_into_aligned_batches_that_keep_their_identities() {
    let world = World::new();
    let artifact = Artifact::new("weights", &[24; 6], false);
    publish(&world, &artifact, vec![local("nvme")]);
    let mut executor = world.executor(config());
    let job = op("load");
    executor
        .submit(request("load", &artifact, destination("placement")))
        .unwrap();
    drive(&mut executor, &world);

    let ranges: Vec<(u64, u64)> = reads(&world)
        .into_iter()
        .map(|(_, _, _, _, offset, length)| (offset, length))
        .collect();
    assert_eq!(ranges, [(0, 48), (48, 48), (96, 48)]);
    assert!(ranges
        .iter()
        .all(|(offset, length)| offset % ALIGN == 0 && length % ALIGN == 0));
    let journal = world.journal();
    let hashed: Vec<u64> = journal
        .iter()
        .filter_map(|entry| match entry {
            Entry::Hash { range } => Some(range.length_bytes),
            _ => None,
        })
        .collect();
    assert_eq!(hashed, [24; 6]);
    assert!(journal.contains(&Entry::Coalesce { spans: 6 }));
    let flights: BTreeSet<FlightId> = (0..6)
        .map(|index| executor.flight_of(&job, index).unwrap())
        .collect();
    assert_eq!(flights.len(), 6);
    assert_eq!(
        world
            .backend
            .destination(&allocation(gpu0(), "placement"), 0, 144),
        artifact.decoded
    );
    assert_eq!(executor.status(&job), Some(&JobStatus::Completed));
}

#[test]
fn an_aligned_read_past_the_end_is_accepted_and_a_truncated_source_is_not() {
    let world = World::new();
    let artifact = Artifact::new("weights", &[20, 20, 20], false);
    publish(&world, &artifact, vec![local("nvme")]);
    let mut executor = world.executor(config());
    executor
        .submit(request("load", &artifact, destination("placement")))
        .unwrap();
    drive(&mut executor, &world);
    assert_eq!(reads(&world)[0].4..reads(&world)[0].5, 0..64);
    assert!(world
        .journal()
        .iter()
        .any(|entry| matches!(entry, Entry::ReadDone { bytes: 60, .. })));
    assert_eq!(executor.status(&op("load")), Some(&JobStatus::Completed));

    let world = World::new();
    publish(
        &world,
        &artifact,
        vec![
            local("short"),
            candidate("full", SourceKind::LocalFile, 1e8),
        ],
    );
    world
        .backend
        .state()
        .truncate_at
        .insert(source("short"), 50);
    let mut executor = world.executor(config());
    let job = op("load");
    executor
        .submit(request("load", &artifact, destination("placement")))
        .unwrap();
    drive(&mut executor, &world);
    assert_eq!(executor.status(&job), Some(&JobStatus::Completed));
    let started: Vec<(String, u64, u64)> = reads(&world)
        .into_iter()
        .map(|(source, _, _, _, offset, length)| (source, offset, length))
        .collect();
    assert_eq!(
        started,
        [("short".to_owned(), 0, 64), ("full".to_owned(), 32, 32)]
    );
    let flight = executor.flight_of(&job, 2).unwrap();
    assert_eq!(
        executor.attempts(flight).unwrap(),
        [Attempt {
            number: 1,
            source: Some(source("short")),
            failure: AttemptFailure::Truncated {
                needed_end_bytes: 60,
                read_end_bytes: 50
            },
        }]
    );
    for index in [0, 1] {
        let flight = executor.flight_of(&job, index).unwrap();
        assert_eq!(executor.attempts(flight).unwrap(), []);
    }
    assert_eq!(
        executor.blacklist(&job).unwrap(),
        &BTreeSet::from([source("short")])
    );
    assert_eq!(
        world
            .backend
            .destination(&allocation(gpu0(), "placement"), 0, 60),
        artifact.decoded
    );
}

#[test]
fn batch_plans_that_break_the_rules_are_refused() {
    let cases = [
        (
            Batching::SkipsAnExtent,
            BatchPlanError::NotAdjacent { index: 2 },
        ),
        (
            Batching::UnalignedStart,
            BatchPlanError::NotCanonical {
                read_offset_bytes: 24,
                read_length_bytes: 32,
                expected_offset_bytes: 16,
                expected_length_bytes: 32,
            },
        ),
        (
            Batching::IgnoresTheSlot,
            BatchPlanError::TooLarge {
                read_length_bytes: 96,
                limit_bytes: 64,
            },
        ),
        (
            Batching::DropsTheLast,
            BatchPlanError::Uncovered { index: 3 },
        ),
        (
            Batching::Repeats,
            BatchPlanError::RepeatedExtent { index: 0 },
        ),
    ];
    for (mode, expected) in cases {
        let world = World::new();
        let artifact = Artifact::new("weights", &[24; 4], false);
        publish(&world, &artifact, vec![local("nvme")]);
        *world.batcher.mode.lock().unwrap() = mode;
        let mut executor = world.executor(config());
        let refused = executor
            .submit(request("load", &artifact, destination("placement")))
            .unwrap_err();
        assert_eq!(refused, SubmitError::Plan(PlanFailure::Batch(expected)));
        assert_eq!(world.ledger.held().len(), 1);
        assert_eq!(
            count(&world.journal(), |entry| matches!(
                entry,
                Entry::Release { .. }
            )),
            4
        );
        executor.pump().unwrap();
        assert!(reads(&world).is_empty());
    }
}

#[test]
fn an_extent_larger_than_a_slot_is_refused_before_anything_is_reserved() {
    let world = World::new();
    let artifact = Artifact::new("weights", &[100], false);
    publish(&world, &artifact, vec![local("nvme")]);
    let mut executor = world.executor(config());
    assert_eq!(
        executor
            .submit(request("load", &artifact, destination("placement")))
            .unwrap_err(),
        SubmitError::ExtentExceedsStaging {
            index: 0,
            needed_bytes: 112,
            limit_bytes: 64
        }
    );
    assert!(!world.journal().iter().any(is_destination_reserve));

    let world = World::new();
    let encoded = Artifact::new("weights", &[16], true);
    publish(&world, &encoded, vec![local("nvme")]);
    let mut one_slot = config();
    one_slot.host_staging.slots = 1;
    let mut executor = world.executor(one_slot);
    assert_eq!(
        executor
            .submit(request("load", &encoded, destination("placement")))
            .unwrap_err(),
        SubmitError::StagingTooSmall {
            place: StagingPlace::Host,
            slots: 1,
            needed_slots: 2
        }
    );
}

#[test]
fn a_dependency_is_usable_only_after_its_whole_chain_completes() {
    let world = World::new();
    let artifact = Artifact::new("weights", &[16, 16, 16], false);
    publish(&world, &artifact, vec![local("nvme")]);
    let mut executor = world.executor(config());
    let job = op("load");
    let mut load = request("load", &artifact, destination("placement"));
    load.dependencies = vec![
        dependency(1, &[0, 1], &[]),
        dependency(2, &[2], &[]),
        dependency(3, &[0], &[2]),
    ];
    executor.submit(load).unwrap();
    executor.pump().unwrap();
    world.advance(148);
    let report = executor.pump().unwrap();
    assert!(report.published.is_empty());
    assert_eq!(report.copies_enqueued, 3);
    for index in 0..3 {
        let flight = executor.flight_of(&job, index).unwrap();
        assert_eq!(executor.flight_phase(flight), Some(FlightPhase::Copying));
    }

    world.advance(16);
    let report = executor.pump().unwrap();
    assert_eq!(report.copies_finished, 1);
    assert!(report.published.is_empty());

    world.advance(16);
    let report = executor.pump().unwrap();
    assert_eq!(report.published, vec![(job.clone(), DependencyId(1))]);
    assert!(!executor.is_usable(&job, DependencyId(3)));

    world.advance(16);
    let report = executor.pump().unwrap();
    assert_eq!(
        report.published,
        vec![
            (job.clone(), DependencyId(2)),
            (job.clone(), DependencyId(3))
        ]
    );
    assert_eq!(executor.status(&job), Some(&JobStatus::Completed));
}

#[test]
fn a_staging_slot_is_recycled_after_its_last_consumer_event_not_after_enqueueing() {
    let world = World::new();
    let artifact = Artifact::new("weights", &[16; 4], false);
    publish(&world, &artifact, vec![local("nvme")]);
    let mut one_slot = config();
    one_slot.host_staging.slots = 1;
    one_slot.host_staging.slot_bytes = 32;
    let mut executor = world.executor(one_slot);
    executor
        .submit(request("load", &artifact, destination("placement")))
        .unwrap();
    executor.pump().unwrap();
    assert_eq!(reads(&world).len(), 1);

    world.advance(132);
    let report = executor.pump().unwrap();
    assert_eq!(report.copies_enqueued, 2);
    assert_eq!(
        executor.staging_usage(StagingPlace::Host).unwrap().in_use,
        1
    );
    assert_eq!(reads(&world).len(), 1);

    world.advance(16);
    let report = executor.pump().unwrap();
    assert_eq!(report.copies_finished, 1);
    assert_eq!(
        executor.staging_usage(StagingPlace::Host).unwrap().in_use,
        1
    );
    assert_eq!(reads(&world).len(), 1);

    world.advance(16);
    let report = executor.pump().unwrap();
    assert_eq!(report.copies_finished, 1);
    assert_eq!(report.reads_started, 1);
    let journal = world.journal();
    let last_event = position(&journal, |entry| *entry == Entry::ReleaseEvent { event: 2 });
    let second_read = journal
        .iter()
        .enumerate()
        .filter(|(_, entry)| matches!(entry, Entry::BeginRead { .. }))
        .nth(1)
        .map(|(index, _)| index)
        .unwrap();
    assert!(last_event < second_read);
    assert_eq!(reads(&world)[1].3.slot, 0);

    drive(&mut executor, &world);
    assert!(world.backend.state().violations.is_empty());
    assert_eq!(
        world
            .backend
            .destination(&allocation(gpu0(), "placement"), 0, 64),
        artifact.decoded
    );
    assert_eq!(
        executor
            .staging_usage(StagingPlace::Host)
            .unwrap()
            .peak_in_use,
        1
    );
}

#[test]
fn staging_is_never_overwritten_under_pressure() {
    for (encoded, slots, lengths) in [
        (false, 2, vec![16, 8, 24, 16, 32, 8, 16, 24, 8, 16, 32, 16]),
        (true, 4, vec![12, 20, 8, 16, 24, 10]),
    ] {
        let world = World::new();
        let artifact = Artifact::new("pressure", &lengths, encoded);
        publish(
            &world,
            &artifact,
            vec![
                local("a"),
                candidate("b", SourceKind::LocalFile, 5e8),
                candidate("c", SourceKind::LocalFile, 2e9),
            ],
        );
        {
            let mut state = world.backend.state();
            state.timing.insert(source("a"), (100, 1));
            state.timing.insert(source("b"), (300, 3));
            state.timing.insert(source("c"), (50, 2));
        }
        let mut pressured = config();
        pressured.host_staging.slots = slots;
        pressured.host_staging.slot_bytes = 64;
        let mut executor = world.executor(pressured);
        let job = op("load");
        executor
            .submit(request("load", &artifact, destination("placement")))
            .unwrap();
        drive(&mut executor, &world);
        assert_eq!(executor.status(&job), Some(&JobStatus::Completed));
        assert!(world.backend.state().violations.is_empty());
        assert_eq!(
            world.backend.destination(
                &allocation(gpu0(), "placement"),
                0,
                artifact.decoded.len() as u64
            ),
            artifact.decoded
        );
        assert!(
            executor
                .staging_usage(StagingPlace::Host)
                .unwrap()
                .peak_in_use
                <= slots
        );
    }
}

#[test]
fn the_copy_api_is_a_real_backend_api() {
    let invented = CopyApi::from_name("torch.cuda.memcpy_async").unwrap_err();
    assert_eq!(invented.name, "torch.cuda.memcpy_async");
    assert!(invented.to_string().contains("not a supported copy API"));
    assert_eq!(
        CopyApi::ALL.map(CopyApi::name),
        [
            "cudaMemcpyAsync",
            "cuMemcpyAsync",
            "torch.Tensor.copy_(non_blocking=True)"
        ]
    );
    for api in CopyApi::ALL {
        assert_eq!(CopyApi::from_name(api.name()), Ok(api));
    }
    assert_eq!(ReadMethod::GpuDirectStorage.api_name(), Some("cuFileRead"));
    assert_eq!(ReadMethod::PeerCopy.api_name(), Some("cudaMemcpyPeerAsync"));

    let world = World::new();
    world.backend.state().copy_api = CopyApi::TorchTensorCopyNonBlocking;
    let artifact = Artifact::new("weights", &[16, 16], false);
    publish(&world, &artifact, vec![local("nvme")]);
    let mut executor = world.executor(config());
    assert_eq!(executor.copy_api(), CopyApi::TorchTensorCopyNonBlocking);
    let job = op("load");
    executor
        .submit(request("load", &artifact, destination("placement")))
        .unwrap();
    drive(&mut executor, &world);
    let journal = world.journal();
    assert_eq!(
        count(&journal, |entry| matches!(
            entry,
            Entry::EnqueueCopy {
                api: CopyApi::TorchTensorCopyNonBlocking,
                ..
            }
        )),
        2
    );
    assert!(stages(&world, &job)
        .iter()
        .filter(|stage| stage.stage == Stage::Copy)
        .all(|stage| stage.api == Some(CopyApi::TorchTensorCopyNonBlocking)));
    assert!(world.backend.state().violations.is_empty());
}

#[test]
fn every_backend_error_is_checked() {
    let world = World::new();
    let artifact = Artifact::new("weights", &[16], false);
    publish(&world, &artifact, vec![local("nvme")]);
    world
        .backend
        .state()
        .fail_enqueue
        .push(BackendErrorKind::Copy);
    let mut executor = world.executor(config());
    let job = op("load");
    executor
        .submit(request("load", &artifact, destination("placement")))
        .unwrap();
    drive(&mut executor, &world);
    assert_eq!(executor.status(&job), Some(&JobStatus::Completed));
    let flight = executor.flight_of(&job, 0).unwrap();
    let attempts = executor.attempts(flight).unwrap();
    assert_eq!(attempts.len(), 1);
    assert!(matches!(
        &attempts[0].failure,
        AttemptFailure::Copy { error } if error.kind == BackendErrorKind::Copy
    ));
    assert!(executor.blacklist(&job).unwrap().is_empty());
    assert_eq!(reads(&world).len(), 2);

    let world = World::new();
    publish(&world, &artifact, vec![local("nvme")]);
    world
        .backend
        .state()
        .fail_enqueue
        .push(BackendErrorKind::StaleDestination);
    let mut executor = world.executor(config());
    executor
        .submit(request("load", &artifact, destination("placement")))
        .unwrap();
    drive(&mut executor, &world);
    let failure = failure_of(&executor, &job);
    assert_eq!(failure.extent, 0);
    assert!(
        matches!(failure.failure, ExtentFailure::Permanent { ref attempts } if attempts.len() == 1)
    );
    assert_eq!(reads(&world).len(), 1);

    let world = World::new();
    publish(&world, &artifact, vec![local("nvme")]);
    world.backend.state().fail_events = 1;
    let mut executor = world.executor(config());
    executor
        .submit(request("load", &artifact, destination("placement")))
        .unwrap();
    drive(&mut executor, &world);
    assert_eq!(executor.status(&job), Some(&JobStatus::Completed));
    let flight = executor.flight_of(&job, 0).unwrap();
    assert_eq!(
        executor.attempts(flight).unwrap()[0].failure,
        AttemptFailure::CopyFailed
    );
    assert_eq!(reads(&world).len(), 2);
}

#[test]
fn an_event_that_cannot_be_recorded_stops_the_executor_with_staging_held() {
    let world = World::new();
    let artifact = Artifact::new("weights", &[16], false);
    publish(&world, &artifact, vec![local("nvme")]);
    world.backend.state().fail_record = true;
    let mut executor = world.executor(config());
    let job = op("load");
    executor
        .submit(request("load", &artifact, destination("placement")))
        .unwrap();
    executor.pump().unwrap();
    world.advance(116);
    let stopped = executor.pump().unwrap_err();
    assert!(matches!(
        stopped,
        Unavailable::Faulted {
            fault: ExecutorFault::EventNotRecorded { .. }
        }
    ));
    assert!(matches!(executor.lifecycle(), Lifecycle::Faulted { .. }));
    world.advance(1_000);
    assert!(executor.pump().is_err());
    assert_eq!(
        executor.staging_usage(StagingPlace::Host).unwrap().in_use,
        1
    );
    assert!(!executor.is_usable(&job, DependencyId(1)));
    let other = Artifact::new("other", &[16], false);
    publish(&world, &other, vec![local("nvme")]);
    assert!(matches!(
        executor.submit(request("other", &other, destination("elsewhere"))),
        Err(SubmitError::Unavailable(Unavailable::Faulted { .. }))
    ));
    assert!(matches!(
        executor.cancel(&job),
        Err(CancelError::Unavailable(_))
    ));
    assert!(matches!(executor.close(), Err(CloseError::Faulted { .. })));
}

#[test]
fn an_event_reused_before_its_completion_is_refused() {
    let world = World::new();
    let artifact = Artifact::new("weights", &[16, 16], false);
    publish(&world, &artifact, vec![local("nvme")]);
    world.backend.state().duplicate_event = true;
    let mut executor = world.executor(config());
    let job = op("load");
    executor
        .submit(request("load", &artifact, destination("placement")))
        .unwrap();
    executor.pump().unwrap();
    world.advance(132);
    assert_eq!(
        executor.pump().unwrap_err(),
        Unavailable::Faulted {
            fault: ExecutorFault::EventReused { event: EventId(1) }
        }
    );
    world.advance(1_000);
    assert!(executor.pump().is_err());
    assert_eq!(
        executor.staging_usage(StagingPlace::Host).unwrap().in_use,
        1
    );
    assert!(!executor.is_usable(&job, DependencyId(1)));
}

// §3.5: direct GPU storage and GPU-peer paths.

#[test]
fn gpu_direct_storage_bypasses_the_host_ring_only_where_the_gate_enables_it() {
    let world = World::new();
    let artifact = Artifact::new("weights", &[16, 16], false);
    publish(&world, &artifact, vec![local("nvme")]);
    world
        .backend
        .state()
        .methods
        .insert(ReadMethod::GpuDirectStorage);
    let cuda = planned(
        &world,
        &[(Optimization::GpuDirectStorage, Necessity::Optional)],
        true,
        Duration::from_secs(60),
    );
    assert!(cuda.1.is_enabled(Optimization::GpuDirectStorage));
    show_platform(
        &world,
        &cuda.0,
        ObservedPlatform::Cuda,
        Duration::from_secs(3_600),
    );
    let permissions =
        LoaderPermissions::from_runtime(&backend_runtime(&cuda, ComputePlatform::Cuda).unwrap());
    assert!(permissions.permits(ReadMethod::GpuDirectStorage, &world.registry));
    assert!(permissions.permits(ReadMethod::PositionedRead, &world.registry));
    assert!(permissions.required().is_empty());
    let mut executor = world.executor(with_device_staging(config(), 2, 64));
    let job = op("load");
    executor
        .submit(TransferRequest {
            loader: permissions,
            ..request("load", &artifact, destination("placement"))
        })
        .unwrap();
    executor.pump().unwrap();
    world.advance(132);
    executor.pump().unwrap();
    assert!(!executor.is_usable(&job, DependencyId(1)));
    drive(&mut executor, &world);
    assert!(executor.is_usable(&job, DependencyId(1)));
    let started = reads(&world);
    assert_eq!(started.len(), 1);
    assert_eq!(started[0].2, ReadMethod::GpuDirectStorage);
    assert_eq!(started[0].3.place, StagingPlace::Device { device: gpu0() });
    assert_eq!(
        executor
            .staging_usage(StagingPlace::Host)
            .unwrap()
            .peak_in_use,
        0
    );
    assert_eq!(
        executor
            .staging_usage(StagingPlace::Device { device: gpu0() })
            .unwrap()
            .peak_in_use,
        1
    );
    assert!(stages(&world, &job)
        .iter()
        .filter(|stage| stage.stage == Stage::Copy)
        .all(|stage| stage.path == Some(TransferPath::DirectStorage)));
    assert_eq!(
        world
            .backend
            .destination(&allocation(gpu0(), "placement"), 0, 32),
        artifact.decoded
    );
    assert!(world
        .ledger
        .requests()
        .iter()
        .any(|request| request.purpose == ReservationPurpose::DeviceStaging { device: gpu0() }));

    for loader in [
        LoaderPermissions::ordinary(),
        on_cuda(
            &world,
            &[(Optimization::GpuDirectStorage, Necessity::Optional)],
            false,
            Duration::from_secs(60),
        ),
    ] {
        let world = World::new();
        publish(&world, &artifact, vec![local("nvme")]);
        world
            .backend
            .state()
            .methods
            .insert(ReadMethod::GpuDirectStorage);
        let mut executor = world.executor(with_device_staging(config(), 2, 64));
        executor
            .submit(TransferRequest {
                loader,
                ..request("load", &artifact, destination("placement"))
            })
            .unwrap();
        drive(&mut executor, &world);
        let started = reads(&world);
        assert_eq!(started[0].2, ReadMethod::PositionedRead);
        assert_eq!(started[0].3.place, StagingPlace::Host);
        assert_eq!(executor.status(&job), Some(&JobStatus::Completed));
    }
}

#[test]
fn a_stale_optional_method_gives_way_and_a_stale_required_one_is_refused() {
    let world = World::new();
    world
        .backend
        .state()
        .methods
        .insert(ReadMethod::GpuDirectStorage);
    let optional = on_cuda(
        &world,
        &[(Optimization::GpuDirectStorage, Necessity::Optional)],
        true,
        Duration::from_nanos(150),
    );
    let first = Artifact::new("first", &[16, 16], false);
    let second = Artifact::new("second", &[16, 16], false);
    publish(&world, &first, vec![local("nvme")]);
    publish(&world, &second, vec![local("nvme")]);
    let mut executor = world.executor(with_device_staging(config(), 2, 64));
    executor
        .submit(TransferRequest {
            loader: optional.clone(),
            ..request("first", &first, destination("one"))
        })
        .unwrap();
    drive(&mut executor, &world);
    world.advance(1_000);
    executor
        .submit(TransferRequest {
            loader: optional,
            ..request("second", &second, destination("two"))
        })
        .unwrap();
    drive(&mut executor, &world);
    let methods: Vec<(ContentKey, ReadMethod)> = reads(&world)
        .into_iter()
        .map(|(_, artifact, method, ..)| (artifact, method))
        .collect();
    assert_eq!(
        methods,
        [
            (first.key, ReadMethod::GpuDirectStorage),
            (second.key, ReadMethod::PositionedRead)
        ]
    );
    assert_eq!(executor.status(&op("second")), Some(&JobStatus::Completed));

    let world = World::new();
    world
        .backend
        .state()
        .methods
        .insert(ReadMethod::GpuDirectStorage);
    let required = on_cuda(
        &world,
        &[(Optimization::GpuDirectStorage, Necessity::Required)],
        true,
        Duration::from_nanos(150),
    );
    assert_eq!(required.required(), [ReadMethod::GpuDirectStorage]);
    let artifact = Artifact::new("weights", &[16; 4], false);
    publish(&world, &artifact, vec![local("nvme")]);
    let mut executor = world.executor(with_device_staging(config(), 1, 32));
    let job = op("load");
    executor
        .submit(TransferRequest {
            loader: required.clone(),
            ..request("load", &artifact, destination("placement"))
        })
        .unwrap();
    executor.pump().unwrap();
    world.advance(132);
    executor.pump().unwrap();
    let failure = failure_of(&executor, &job);
    assert_eq!(failure.extent, 2);
    assert!(matches!(
        failure.failure,
        ExtentFailure::Permanent { ref attempts } if attempts[0].failure
            == AttemptFailure::RequiredMethodUnavailable {
                method: ReadMethod::GpuDirectStorage,
                reason: MethodUnavailable::EvidenceExpired,
            }
    ));
    drive(&mut executor, &world);
    assert!(reads(&world)
        .iter()
        .all(|read| read.2 == ReadMethod::GpuDirectStorage));

    let later = Artifact::new("later", &[16], false);
    publish(&world, &later, vec![local("nvme")]);
    assert_eq!(
        executor
            .submit(TransferRequest {
                loader: required,
                ..request("later", &later, destination("later"))
            })
            .unwrap_err(),
        SubmitError::RequiredMethodUnavailable {
            method: ReadMethod::GpuDirectStorage,
            reason: MethodUnavailable::EvidenceExpired
        }
    );
}

#[test]
fn a_required_gated_method_is_refused_rather_than_replaced() {
    let artifact = Artifact::new("weights", &[16], false);
    let required = |world: &World, optimizations: &[(Optimization, Necessity)]| {
        on_cuda(world, optimizations, true, Duration::from_secs(60))
    };
    let gds = [(Optimization::GpuDirectStorage, Necessity::Required)];

    let world = World::new();
    publish(&world, &artifact, vec![local("nvme")]);
    let loader = required(&world, &gds);
    let mut executor = world.executor(with_device_staging(config(), 2, 64));
    assert_eq!(
        executor
            .submit(TransferRequest {
                loader,
                ..request("load", &artifact, destination("placement"))
            })
            .unwrap_err(),
        SubmitError::RequiredMethodUnavailable {
            method: ReadMethod::GpuDirectStorage,
            reason: MethodUnavailable::NotImplemented
        }
    );

    let world = World::new();
    publish(&world, &artifact, vec![local("nvme")]);
    world
        .backend
        .state()
        .methods
        .insert(ReadMethod::GpuDirectStorage);
    let loader = required(&world, &gds);
    let mut executor = world.executor(config());
    assert_eq!(
        executor
            .submit(TransferRequest {
                loader,
                ..request("load", &artifact, destination("placement"))
            })
            .unwrap_err(),
        SubmitError::RequiredMethodUnavailable {
            method: ReadMethod::GpuDirectStorage,
            reason: MethodUnavailable::NoDeviceStaging
        }
    );

    let world = World::new();
    publish(
        &world,
        &artifact,
        vec![candidate("mirror", SourceKind::Remote, 1e9)],
    );
    world
        .backend
        .state()
        .methods
        .insert(ReadMethod::GpuDirectStorage);
    let loader = required(&world, &gds);
    let mut executor = world.executor(with_device_staging(config(), 2, 64));
    assert_eq!(
        executor
            .submit(TransferRequest {
                loader,
                ..request("load", &artifact, destination("placement"))
            })
            .unwrap_err(),
        SubmitError::RequiredMethodUnavailable {
            method: ReadMethod::GpuDirectStorage,
            reason: MethodUnavailable::WrongSource
        }
    );

    let world = World::new();
    publish(&world, &artifact, vec![local("nvme")]);
    {
        let mut state = world.backend.state();
        state.methods.insert(ReadMethod::GpuDirectStorage);
        state.methods.insert(ReadMethod::IoUring);
    }
    let both = required(
        &world,
        &[
            (Optimization::GpuDirectStorage, Necessity::Required),
            (Optimization::IoUring, Necessity::Required),
        ],
    );
    let mut executor = world.executor(with_device_staging(config(), 2, 64));
    assert_eq!(
        executor
            .submit(TransferRequest {
                loader: both,
                ..request("load", &artifact, destination("placement"))
            })
            .unwrap_err(),
        SubmitError::RequiredMethodUnavailable {
            method: ReadMethod::GpuDirectStorage,
            reason: MethodUnavailable::ConflictsWith {
                other: ReadMethod::IoUring
            }
        }
    );

    let gds_only = required(&world, &gds);
    executor
        .submit(TransferRequest {
            loader: gds_only.clone(),
            ..request("load", &artifact, destination("placement"))
        })
        .unwrap();
    assert!(!gds_only.compatible_with(&LoaderPermissions::ordinary()));
    assert_eq!(
        executor
            .submit(request("plain", &artifact, destination("placement")))
            .unwrap_err(),
        SubmitError::LoaderConflict { index: 0 }
    );
    drive(&mut executor, &world);
    assert_eq!(reads(&world)[0].2, ReadMethod::GpuDirectStorage);
}

#[test]
fn unverified_bytes_in_device_staging_are_never_copied_out() {
    let world = World::new();
    let artifact = Artifact::new("weights", &[16, 16], false);
    publish(
        &world,
        &artifact,
        vec![local("nvme"), candidate("mirror", SourceKind::Remote, 1e8)],
    );
    {
        let mut state = world.backend.state();
        state.methods.insert(ReadMethod::GpuDirectStorage);
        state.corrupt.insert((source("nvme"), artifact.key, 0));
    }
    let loader = on_cuda(
        &world,
        &[(Optimization::GpuDirectStorage, Necessity::Optional)],
        true,
        Duration::from_secs(60),
    );
    let mut executor = world.executor(with_device_staging(config(), 2, 64));
    let job = op("load");
    executor
        .submit(TransferRequest {
            loader,
            ..request("load", &artifact, destination("placement"))
        })
        .unwrap();
    drive(&mut executor, &world);
    assert_eq!(executor.status(&job), Some(&JobStatus::Completed));
    let journal = world.journal();
    let copies_into_first: Vec<StagingPlace> = journal
        .iter()
        .filter_map(|entry| match entry {
            Entry::EnqueueCopy { from, to, .. } if to.offset_bytes == 0 => Some(from.buffer.place),
            _ => None,
        })
        .collect();
    assert_eq!(copies_into_first, [StagingPlace::Host]);
    assert!(journal.iter().any(|entry| matches!(
        entry,
        Entry::EnqueueCopy { from, to, .. }
            if to.offset_bytes == 16 && from.buffer.place == StagingPlace::Device { device: gpu0() }
    )));
    let landed = world.backend.state().landed.clone();
    assert!(landed
        .iter()
        .filter(|write| write.offset == 0)
        .all(|write| write.bytes == artifact.decoded_of(0)));
    let flight = executor.flight_of(&job, 0).unwrap();
    assert!(matches!(
        executor.attempts(flight).unwrap(),
        [Attempt {
            failure: AttemptFailure::StoredMismatch { .. },
            ..
        }]
    ));
    assert_eq!(
        world
            .backend
            .destination(&allocation(gpu0(), "placement"), 0, 32),
        artifact.decoded
    );
}

/// FAST-02 (peer access is probed, never assumed): a GPU peer is read only where CORE-01
/// evidence shows peer access for exactly that direction, rechecked at every read. The
/// backend's live query is no evidence and is never asked.
#[test]
fn a_gpu_peer_is_read_only_where_core01_evidence_shows_peer_access() {
    let artifact = Artifact::new("weights", &[16, 16], false);
    let peer = candidate("gpu1", SourceKind::GpuPeer { device: gpu1() }, 1e10);
    let peer_world = |sources: Vec<SourceCandidate>| {
        let world = World::new();
        publish(&world, &artifact, sources);
        world.backend.state().methods.insert(ReadMethod::PeerCopy);
        world
    };

    let world = peer_world(vec![peer.clone()]);
    show_peer_access(&world, gpu1(), gpu0(), true, Duration::from_secs(60));
    let mut executor = world.executor(with_device_staging(config(), 2, 64));
    executor
        .submit(request("load", &artifact, destination("placement")))
        .unwrap();
    drive(&mut executor, &world);
    let started = reads(&world);
    assert_eq!(started[0].0, "gpu1");
    assert_eq!(started[0].2, ReadMethod::PeerCopy);
    assert_eq!(started[0].3.place, StagingPlace::Device { device: gpu0() });
    assert_eq!(
        executor
            .staging_usage(StagingPlace::Host)
            .unwrap()
            .peak_in_use,
        0
    );
    assert_eq!(executor.status(&op("load")), Some(&JobStatus::Completed));
    assert!(stages(&world, &op("load"))
        .iter()
        .filter(|stage| stage.stage == Stage::Copy)
        .all(|stage| stage.path == Some(TransferPath::GpuPeer { from: gpu1() })));

    // The live query answers yes, but there is no evidence, evidence only for the other
    // direction, or evidence that the copy failed: the peer is never read.
    for shown in [
        None,
        Some((gpu0(), gpu1(), true)),
        Some((gpu1(), gpu0(), false)),
    ] {
        let world = peer_world(vec![peer.clone()]);
        world.backend.state().peer_access.insert((gpu1(), gpu0()));
        if let Some((from, to, supported)) = shown {
            show_peer_access(&world, from, to, supported, Duration::from_secs(60));
        }
        let mut executor = world.executor(with_device_staging(config(), 2, 64));
        assert_eq!(
            executor
                .submit(request("load", &artifact, destination("placement")))
                .unwrap_err(),
            SubmitError::NoReadableSource
        );
    }

    // Without a peer policy nothing shows peer access.
    let world = peer_world(vec![peer.clone()]);
    show_peer_access(&world, gpu1(), gpu0(), true, Duration::from_secs(60));
    let mut executor = TransferExecutor::new(
        with_device_staging(config(), 2, 64),
        Arc::clone(&world.clock),
        world.ports(),
    )
    .unwrap()
    .with_evidence(Box::new(Arc::clone(&world.registry)));
    assert_eq!(
        executor
            .submit(request("load", &artifact, destination("placement")))
            .unwrap_err(),
        SubmitError::NoReadableSource
    );

    // Evidence that lapses between the plan and the read: the reads go to the local file.
    let world = peer_world(vec![peer, local("nvme")]);
    show_peer_access(&world, gpu1(), gpu0(), true, Duration::from_nanos(100));
    let mut executor = world.executor(with_device_staging(config(), 2, 64));
    executor
        .submit(request("load", &artifact, destination("placement")))
        .unwrap();
    world.advance(200);
    drive(&mut executor, &world);
    assert!(reads(&world).iter().all(|read| read.0 == "nvme"));
    assert_eq!(executor.status(&op("load")), Some(&JobStatus::Completed));
}

#[test]
fn io_uring_is_used_only_behind_its_gate() {
    let artifact = Artifact::new("weights", &[16], false);
    for gated in [false, true] {
        let world = World::new();
        publish(&world, &artifact, vec![local("nvme")]);
        world.backend.state().methods.insert(ReadMethod::IoUring);
        let loader = if gated {
            LoaderPermissions::from_plan(&loader_plan(
                &world,
                &[(Optimization::IoUring, Necessity::Optional)],
                true,
                Duration::from_secs(60),
            ))
        } else {
            LoaderPermissions::ordinary()
        };
        let mut executor = world.executor(config());
        executor
            .submit(TransferRequest {
                loader,
                ..request("load", &artifact, destination("placement"))
            })
            .unwrap();
        drive(&mut executor, &world);
        let expected = if gated {
            ReadMethod::IoUring
        } else {
            ReadMethod::PositionedRead
        };
        assert_eq!(reads(&world)[0].2, expected);
    }
}

#[test]
fn direct_paths_keep_bounded_device_staging_and_completion_events() {
    let world = World::new();
    let artifact = Artifact::new("weights", &[16; 4], false);
    publish(&world, &artifact, vec![local("nvme")]);
    world
        .backend
        .state()
        .methods
        .insert(ReadMethod::GpuDirectStorage);
    let loader = on_cuda(
        &world,
        &[(Optimization::GpuDirectStorage, Necessity::Optional)],
        true,
        Duration::from_secs(60),
    );
    let mut executor = world.executor(with_device_staging(config(), 1, 32));
    executor
        .submit(TransferRequest {
            loader,
            ..request("load", &artifact, destination("placement"))
        })
        .unwrap();
    executor.pump().unwrap();
    assert_eq!(reads(&world).len(), 1);
    drive(&mut executor, &world);
    let journal = world.journal();
    let first_batch_done = position(&journal, |entry| *entry == Entry::ReleaseEvent { event: 2 });
    let second_read = journal
        .iter()
        .enumerate()
        .filter(|(_, entry)| matches!(entry, Entry::BeginRead { .. }))
        .nth(1)
        .map(|(index, _)| index)
        .unwrap();
    assert!(first_batch_done < second_read);
    assert!(reads(&world)
        .iter()
        .all(|read| read.3.place == StagingPlace::Device { device: gpu0() }));
    assert_eq!(
        executor
            .staging_usage(StagingPlace::Device { device: gpu0() })
            .unwrap()
            .peak_in_use,
        1
    );
    assert_eq!(
        executor
            .staging_usage(StagingPlace::Host)
            .unwrap()
            .peak_in_use,
        0
    );
    assert!(world.backend.state().violations.is_empty());
}

// §3.5: single flight keyed by extent and representation.

#[test]
fn one_operation_serves_every_request_for_the_same_extent_and_representation() {
    let world = World::new();
    let artifact = Artifact::new("weights", &[16; 4], false);
    publish(&world, &artifact, vec![local("nvme")]);
    let mut executor = world.executor(config());
    let (first, second) = (op("first"), op("second"));
    let mut partial = request("first", &artifact, destination("placement"));
    partial.dependencies = vec![dependency(1, &[0, 1], &[])];
    executor.submit(partial).unwrap();
    executor
        .submit(request("second", &artifact, destination("placement")))
        .unwrap();
    for index in [0, 1] {
        let shared = executor.flight_of(&first, index).unwrap();
        assert_eq!(executor.flight_of(&second, index), Some(shared));
        assert_eq!(executor.subscribers(shared), Some(2));
    }
    assert!(
        kinds(&world, &second).contains(&TransferEventKind::Submitted {
            total_bytes: 64,
            new_operations: 2,
            shared_operations: 2
        })
    );
    drive(&mut executor, &world);
    assert_eq!(executor.status(&first), Some(&JobStatus::Completed));
    assert_eq!(executor.status(&second), Some(&JobStatus::Completed));
    let ranges: BTreeSet<(u64, u64)> = reads(&world)
        .into_iter()
        .map(|(_, _, _, _, offset, length)| (offset, length))
        .collect();
    assert_eq!(ranges, BTreeSet::from([(0, 32), (32, 32)]));
    assert_eq!(count(&world.journal(), is_destination_reserve), 4);

    let encoded = Artifact::new("weights", &[16; 4], true);
    publish(&world, &encoded, vec![local("nvme")]);
    assert_eq!(encoded.key, artifact.key);
    assert_ne!(encoded.representation, artifact.representation);
    let mut other_form = request("third", &encoded, destination("placement"));
    other_form.dependencies = vec![dependency(1, &[0], &[])];
    assert_eq!(
        executor.submit(other_form).unwrap_err(),
        SubmitError::DestinationConflict { index: 0 }
    );
    executor
        .submit(request("fourth", &encoded, destination("elsewhere")))
        .unwrap();
    assert_ne!(
        executor.flight_of(&op("fourth"), 0),
        executor.flight_of(&first, 0)
    );
}

#[test]
fn one_subscribers_cancellation_never_cancels_anothers_work() {
    let world = World::new();
    let artifact = Artifact::new("weights", &[16; 4], false);
    publish(&world, &artifact, vec![local("nvme")]);
    let mut executor = world.executor(config());
    let (first, second) = (op("first"), op("second"));
    executor
        .submit(request("first", &artifact, destination("placement")))
        .unwrap();
    executor
        .submit(request("second", &artifact, destination("placement")))
        .unwrap();
    executor.pump().unwrap();
    let report = executor.cancel(&first).unwrap();
    assert_eq!(
        report,
        CancelReport {
            shared: 4,
            reclaimed: 0,
            draining: 0,
            resident: 0
        }
    );
    assert_eq!(
        count(&world.journal(), |entry| matches!(
            entry,
            Entry::Release { .. }
        )),
        0
    );
    drive(&mut executor, &world);
    assert_eq!(executor.status(&second), Some(&JobStatus::Completed));
    assert_eq!(
        executor.status(&first),
        Some(&JobStatus::Cancelled {
            reason: CancelReason::Requested
        })
    );
    assert_eq!(reads(&world).len(), 1);
    assert!(executor.scheduler().transfer(&first).is_none());
    assert_eq!(
        world
            .backend
            .destination(&allocation(gpu0(), "placement"), 0, 64),
        artifact.decoded
    );
}

#[test]
fn the_last_subscribers_cancellation_permits_reclamation() {
    let world = World::new();
    let artifact = Artifact::new("weights", &[16; 4], false);
    publish(&world, &artifact, vec![local("nvme")]);
    let mut one_slot = config();
    one_slot.host_staging.slots = 1;
    one_slot.host_staging.slot_bytes = 32;
    let mut executor = world.executor(one_slot);
    let (first, second) = (op("first"), op("second"));
    executor
        .submit(request("first", &artifact, destination("placement")))
        .unwrap();
    executor
        .submit(request("second", &artifact, destination("placement")))
        .unwrap();
    executor.pump().unwrap();
    assert_eq!(executor.cancel(&first).unwrap().shared, 4);
    let releases = |world: &World| {
        count(&world.journal(), |entry| {
            matches!(entry, Entry::Release { .. })
        })
    };
    assert_eq!(releases(&world), 0);
    assert_eq!(
        executor.cancel(&second).unwrap(),
        CancelReport {
            shared: 0,
            reclaimed: 2,
            draining: 2,
            resident: 0
        }
    );
    assert_eq!(releases(&world), 2);
    world.advance(132);
    let report = executor.pump().unwrap();
    assert_eq!(report.reclaimed, 2);
    assert_eq!(releases(&world), 4);
    let journal = world.journal();
    assert_eq!(
        count(&journal, |entry| matches!(entry, Entry::Hash { .. })),
        0
    );
    assert_eq!(
        count(&journal, |entry| matches!(entry, Entry::EnqueueCopy { .. })),
        0
    );
    assert!(executor.is_idle());
    assert_eq!(
        executor.staging_usage(StagingPlace::Host).unwrap().in_use,
        0
    );
    assert_eq!(world.ledger.held().len(), 1);
    let vram = ReservedResource::DeviceMemory { device: gpu0() };
    assert_eq!(world.ledger.releasing().len(), 4);
    assert_eq!(world.ledger.used(vram), 64);
    world.ledger.observe_releases();
    assert_eq!(world.ledger.used(vram), 0);
    assert!(world.backend.state().landed.is_empty());

    let world = World::new();
    let single = Artifact::new("single", &[16], false);
    publish(&world, &single, vec![local("nvme")]);
    let mut executor = world.executor(config());
    let job = op("load");
    executor
        .submit(request("load", &single, destination("placement")))
        .unwrap();
    executor.pump().unwrap();
    world.advance(116);
    executor.pump().unwrap();
    let flight = executor.flight_of(&job, 0).unwrap();
    assert_eq!(executor.flight_phase(flight), Some(FlightPhase::Copying));
    assert_eq!(executor.cancel(&job).unwrap().draining, 1);
    assert_eq!(releases(&world), 0);
    world.advance(16);
    executor.pump().unwrap();
    let journal = world.journal();
    let done = position(&journal, |entry| matches!(entry, Entry::EventDone { .. }));
    let release = position(&journal, |entry| matches!(entry, Entry::Release { .. }));
    assert!(done < release);
    assert!(executor.flight_phase(flight).is_none());
}

#[test]
fn promotion_raises_priority_and_reuses_the_same_transfer() {
    let world = World::new();
    let first = Artifact::new("s1", &[16; 4], false);
    let second = Artifact::new("s2", &[16; 4], false);
    publish(&world, &first, vec![local("nvme")]);
    publish(&world, &second, vec![local("nvme")]);
    let mut one_slot = config();
    one_slot.host_staging.slots = 1;
    one_slot.host_staging.slot_bytes = 32;
    let mut executor = world.executor(one_slot);
    let (s1, s2) = (op("s1"), op("s2"));
    executor
        .submit(speculative("s1", &first, destination("d1")))
        .unwrap();
    executor
        .submit(speculative("s2", &second, destination("d2")))
        .unwrap();
    executor.pump().unwrap();
    let before: Vec<FlightId> = (0..4)
        .map(|index| executor.flight_of(&s2, index).unwrap())
        .collect();
    assert_eq!(executor.scheduler().transfers_started(), 2);
    executor.promote(&s2).unwrap();
    assert_eq!(executor.scheduler().transfers_started(), 2);
    assert_eq!(
        executor.scheduler().transfer(&s2).unwrap().class(),
        TransferClass::Demand
    );
    assert!(kinds(&world, &s2).contains(&TransferEventKind::Promoted));
    drive(&mut executor, &world);
    let order: Vec<(ContentKey, u64)> = reads(&world)
        .into_iter()
        .map(|(_, artifact, _, _, offset, _)| (artifact, offset))
        .collect();
    assert_eq!(
        order,
        [
            (first.key, 0),
            (second.key, 0),
            (second.key, 32),
            (first.key, 32)
        ]
    );
    let after: Vec<FlightId> = (0..4)
        .map(|index| executor.flight_of(&s2, index).unwrap())
        .collect();
    assert_eq!(before, after);
    assert_eq!(executor.status(&s1), Some(&JobStatus::Completed));
    assert_eq!(executor.status(&s2), Some(&JobStatus::Completed));
    assert!(matches!(
        executor.promote(&s2),
        Err(PromoteError::NotSpeculative { .. })
    ));
    assert_eq!(executor.scheduler().speculative_bytes(), 64);
    executor.promote(&s1).unwrap();
    assert_eq!(executor.scheduler().speculative_bytes(), 0);
}

#[test]
fn a_foreground_subscriber_raises_a_shared_speculative_operation() {
    let world = World::new();
    let earlier = Artifact::new("t", &[16; 4], false);
    let shared = Artifact::new("s", &[16; 4], false);
    publish(&world, &earlier, vec![local("nvme")]);
    publish(&world, &shared, vec![local("nvme")]);
    let mut one_slot = config();
    one_slot.host_staging.slots = 1;
    one_slot.host_staging.slot_bytes = 32;
    let mut executor = world.executor(one_slot);
    executor
        .submit(speculative("t", &earlier, destination("dt")))
        .unwrap();
    executor
        .submit(speculative("s", &shared, destination("ds")))
        .unwrap();
    let mut foreground = request("f", &shared, destination("ds"));
    foreground.dependencies = vec![dependency(1, &[2, 3], &[])];
    executor.submit(foreground).unwrap();
    executor.pump().unwrap();
    let first = &reads(&world)[0];
    assert_eq!((first.1, first.4), (shared.key, 32));
}

#[test]
fn speculative_work_is_bounded_and_demand_only_cancels_it() {
    let world = World::new();
    let artifact = Artifact::new("x", &[16; 4], false);
    publish(&world, &artifact, vec![local("nvme")]);
    let mut executor = world.executor(config());
    let mut mismatched = speculative("s0", &artifact, destination("d"));
    mismatched.priority = JobPriority::Speculative { value: value(10) };
    assert_eq!(
        executor.submit(mismatched).unwrap_err(),
        SubmitError::SpeculativeBytesMismatch {
            value_bytes: 10,
            job_bytes: 64
        }
    );
    let mut worthless = speculative("s0", &artifact, destination("d"));
    let mut poor = value(64);
    poor.expected_value = -1.0;
    worthless.priority = JobPriority::Speculative { value: poor };
    assert!(matches!(
        executor.submit(worthless).unwrap_err(),
        SubmitError::Admission(PrefetchError::Refused(AdmissionRefusal::NotWorthIt { .. }))
    ));

    let world = World::new();
    let other = Artifact::new("y", &[16; 4], false);
    publish(&world, &artifact, vec![local("nvme")]);
    publish(&world, &other, vec![local("nvme")]);
    let mut bounded = config();
    bounded.prefetch_budget.max_speculative_bytes = 100;
    let mut executor = world.executor(bounded);
    executor
        .submit(speculative("s1", &artifact, destination("d1")))
        .unwrap();
    assert_eq!(
        executor
            .submit(speculative("s2", &other, destination("d2")))
            .unwrap_err(),
        SubmitError::Admission(PrefetchError::Refused(
            AdmissionRefusal::SpeculativeBudget {
                requested_bytes: 64,
                held_bytes: 64,
                limit_bytes: 100
            }
        ))
    );
    assert!(!world
        .ledger
        .requests()
        .iter()
        .any(|request| request.operation == op("s2")));
    executor
        .submit(request("f", &artifact, destination("d1")))
        .unwrap();
    assert_eq!(
        executor
            .set_scheduling_mode(SchedulingMode::DemandOnly)
            .unwrap(),
        vec![op("s1")]
    );
    assert_eq!(
        executor.status(&op("s1")),
        Some(&JobStatus::Cancelled {
            reason: CancelReason::DemandOnly
        })
    );
    assert!(matches!(
        executor
            .submit(speculative("s3", &other, destination("d3")))
            .unwrap_err(),
        SubmitError::Admission(PrefetchError::Refused(AdmissionRefusal::DemandOnly))
    ));
    drive(&mut executor, &world);
    assert_eq!(executor.status(&op("f")), Some(&JobStatus::Completed));
    assert!(executor
        .set_scheduling_mode(SchedulingMode::Speculative)
        .unwrap()
        .is_empty());
}

#[test]
fn joining_needs_the_same_manifest_entry_and_a_shared_source() {
    let world = World::new();
    let artifact = Artifact::new("weights", &[16, 16], false);
    publish(&world, &artifact, vec![local("nvme")]);
    let mut changed = artifact.manifest(vec![local("nvme")]);
    changed.extents[0].decoded_key = ContentKey::of(b"other bytes");
    world.catalog.publish_for("exe-b", changed);
    world.catalog.publish_for(
        "exe-c",
        artifact.manifest(vec![candidate("mirror", SourceKind::Remote, 1e9)]),
    );
    let mut executor = world.executor(config());
    executor
        .submit(request("a", &artifact, destination("placement")))
        .unwrap();
    assert_eq!(
        executor
            .submit(request("b", &artifact, destination("placement")))
            .unwrap_err(),
        SubmitError::ManifestMismatch { index: 0 }
    );
    assert_eq!(
        executor
            .submit(request("c", &artifact, destination("placement")))
            .unwrap_err(),
        SubmitError::NoCommonSource { index: 0 }
    );
}

// §3.5: failures.

#[test]
fn retries_are_bounded_and_the_failing_source_is_blacklisted_for_that_job() {
    let artifact = Artifact::new("weights", &[16; 3], false);
    let sources = || {
        vec![
            local("s1"),
            candidate("s2", SourceKind::LocalFile, 1e8),
            candidate("s3", SourceKind::LocalFile, 1e7),
        ]
    };
    let world = World::new();
    publish(&world, &artifact, sources());
    {
        let mut state = world.backend.state();
        state.corrupt.insert((source("s1"), artifact.key, 16));
        state.fail_reads.insert(source("s2"), 1);
    }
    let mut executor = world.executor(config());
    let job = op("load");
    executor
        .submit(request("load", &artifact, destination("placement")))
        .unwrap();
    drive(&mut executor, &world);
    assert_eq!(executor.status(&job), Some(&JobStatus::Completed));
    let flight = executor.flight_of(&job, 1).unwrap();
    let attempts = executor.attempts(flight).unwrap();
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[0].source, Some(source("s1")));
    assert!(matches!(
        attempts[0].failure,
        AttemptFailure::StoredMismatch { .. }
    ));
    assert_eq!(attempts[1].source, Some(source("s2")));
    assert!(matches!(
        &attempts[1].failure,
        AttemptFailure::Read { error } if error.kind == BackendErrorKind::Io
    ));
    assert_eq!(
        executor.blacklist(&job).unwrap(),
        &BTreeSet::from([source("s1"), source("s2")])
    );
    let started: Vec<(String, u64, u64)> = reads(&world)
        .into_iter()
        .map(|(source, _, _, _, offset, length)| (source, offset, length))
        .collect();
    assert_eq!(
        started,
        [
            ("s1".to_owned(), 0, 48),
            ("s2".to_owned(), 16, 16),
            ("s3".to_owned(), 16, 16)
        ]
    );
    let blacklisted: Vec<SourceId> = kinds(&world, &job)
        .into_iter()
        .filter_map(|kind| match kind {
            TransferEventKind::SourceBlacklisted { source } => Some(source),
            _ => None,
        })
        .collect();
    assert_eq!(blacklisted, [source("s1"), source("s2")]);

    let world = World::new();
    publish(&world, &artifact, sources());
    {
        let mut state = world.backend.state();
        state.corrupt.insert((source("s1"), artifact.key, 16));
        state.fail_reads.insert(source("s2"), 1);
        state.timing.insert(source("s2"), (5_000, 1));
    }
    let mut twice = config();
    twice.max_attempts = 2;
    let mut executor = world.executor(twice);
    let mut load = request("load", &artifact, destination("placement"));
    load.dependencies = vec![
        dependency(0, &[0], &[]),
        dependency(1, &[1], &[]),
        dependency(2, &[2], &[]),
    ];
    executor.submit(load).unwrap();
    executor.pump().unwrap();
    world.advance(148);
    executor.pump().unwrap();
    world.advance(100);
    executor.pump().unwrap();
    assert!(executor.is_usable(&job, DependencyId(0)));
    assert!(executor.is_usable(&job, DependencyId(2)));
    world.advance(6_000);
    executor.pump().unwrap();
    let failure = failure_of(&executor, &job);
    assert_eq!(failure.extent, 1);
    assert!(matches!(
        failure.failure,
        ExtentFailure::RetriesExhausted { ref attempts } if attempts.len() == 2
    ));
    assert!(executor.is_usable(&job, DependencyId(0)));
    assert!(!executor.is_usable(&job, DependencyId(1)));
}

#[test]
fn a_hash_mismatch_is_never_a_warning_followed_by_use() {
    let world = World::new();
    let artifact = Artifact::new("weights", &[16, 16], false);
    publish(&world, &artifact, vec![local("nvme")]);
    world
        .backend
        .state()
        .corrupt
        .insert((source("nvme"), artifact.key, 0));
    let mut executor = world.executor(config());
    let job = op("load");
    executor
        .submit(request("load", &artifact, destination("placement")))
        .unwrap();
    drive(&mut executor, &world);
    let failure = failure_of(&executor, &job);
    assert_eq!(failure.extent, 0);
    assert!(matches!(
        failure.failure,
        ExtentFailure::NoEligibleSource { ref attempts } if attempts.len() == 1
    ));
    let journal = world.journal();
    assert!(!journal.iter().any(|entry| matches!(
        entry,
        Entry::EnqueueCopy { to, .. } if to.offset_bytes == 0
    )));
    assert!(world
        .backend
        .state()
        .landed
        .iter()
        .all(|write| write.offset != 0));
    let events = kinds(&world, &job);
    let mismatch = events
        .iter()
        .find_map(|kind| match kind {
            TransferEventKind::AttemptFailed { failure, .. } => Some(failure.clone()),
            _ => None,
        })
        .unwrap();
    assert!(matches!(mismatch, AttemptFailure::StoredMismatch { .. }));
    let message = mismatch.to_string();
    assert!(message.contains("hash mismatch") && message.contains("not used"));
    assert!(events
        .iter()
        .any(|kind| matches!(kind, TransferEventKind::Failed { .. })));
    assert!(!events
        .iter()
        .any(|kind| matches!(kind, TransferEventKind::DependencyUsable { .. })));

    let world = World::new();
    let all_corrupt = vec![
        local("c1"),
        candidate("c2", SourceKind::LocalFile, 1e8),
        candidate("c3", SourceKind::LocalFile, 1e7),
    ];
    publish(&world, &artifact, all_corrupt);
    for name in ["c1", "c2", "c3"] {
        world
            .backend
            .state()
            .corrupt
            .insert((source(name), artifact.key, 0));
    }
    let mut twice = config();
    twice.max_attempts = 2;
    let mut executor = world.executor(twice);
    executor
        .submit(request("load", &artifact, destination("placement")))
        .unwrap();
    drive(&mut executor, &world);
    assert!(matches!(
        failure_of(&executor, &job).failure,
        ExtentFailure::RetriesExhausted { ref attempts } if attempts.len() == 2
    ));
}

#[test]
fn a_blacklist_is_scoped_to_its_job() {
    let world = World::new();
    let one = Artifact::new("one", &[16, 16], false);
    let two = Artifact::new("two", &[16, 16], false);
    let sources = || vec![local("s1"), candidate("s2", SourceKind::LocalFile, 1e8)];
    publish(&world, &one, sources());
    publish(&world, &two, sources());
    world
        .backend
        .state()
        .corrupt
        .insert((source("s1"), one.key, 0));
    let mut executor = world.executor(config());
    executor
        .submit(request("one", &one, destination("d1")))
        .unwrap();
    executor
        .submit(request("two", &two, destination("d2")))
        .unwrap();
    drive(&mut executor, &world);
    assert_eq!(executor.status(&op("one")), Some(&JobStatus::Completed));
    assert_eq!(executor.status(&op("two")), Some(&JobStatus::Completed));
    assert_eq!(
        executor.blacklist(&op("one")).unwrap(),
        &BTreeSet::from([source("s1")])
    );
    assert!(executor.blacklist(&op("two")).unwrap().is_empty());
    assert!(reads(&world)
        .iter()
        .filter(|read| read.1 == two.key)
        .all(|read| read.0 == "s1"));
}

#[test]
fn a_decoded_identity_mismatch_is_retried_without_blaming_the_source() {
    let world = World::new();
    let artifact = Artifact::new("weights", &[16], true);
    for candidate in [local("nvme")] {
        world.backend.store(
            &candidate.spec.id,
            artifact.key,
            artifact.representation,
            artifact.stored.clone(),
        );
    }
    let mut wrong = artifact.manifest(vec![local("nvme")]);
    wrong.extents[0].decoded_key = ContentKey::of(b"other bytes");
    world.catalog.publish(wrong);
    let mut executor = world.executor(config());
    let job = op("load");
    executor
        .submit(request("load", &artifact, destination("placement")))
        .unwrap();
    drive(&mut executor, &world);
    let failure = failure_of(&executor, &job);
    let ExtentFailure::RetriesExhausted { attempts } = failure.failure else {
        panic!("the extent was not retried to the bound");
    };
    assert_eq!(attempts.len(), 3);
    assert!(attempts.iter().all(|attempt| matches!(
        attempt.failure,
        AttemptFailure::DecodedMismatch { .. }
    ) && attempt.source == Some(source("nvme"))));
    assert!(executor.blacklist(&job).unwrap().is_empty());
    assert_eq!(reads(&world).len(), 3);
    assert_eq!(
        count(&world.journal(), |entry| matches!(
            entry,
            Entry::EnqueueCopy { .. }
        )),
        0
    );
}

// Checks before anything is reserved.

#[test]
fn manifests_and_dependencies_are_checked_before_anything_is_reserved() {
    let artifact = Artifact::new("weights", &[16, 16], false);
    let refused_manifest = |change: &dyn Fn(&mut ResolvedManifest)| {
        let world = World::new();
        let mut manifest = artifact.manifest(vec![local("nvme")]);
        change(&mut manifest);
        world.catalog.publish_for("exe-load", manifest);
        let mut executor = world.executor(config());
        let refused = executor
            .submit(request("load", &artifact, destination("placement")))
            .unwrap_err();
        assert!(!world.journal().iter().any(is_destination_reserve));
        refused
    };
    let manifest_error = |change: &dyn Fn(&mut ResolvedManifest)| match refused_manifest(change) {
        SubmitError::Manifest(error) => error,
        other => panic!("not a manifest refusal: {other:?}"),
    };
    assert!(matches!(
        manifest_error(&|manifest| manifest.artifact = ContentKey::of(b"x")),
        ManifestError::WrongArtifact { .. }
    ));
    assert!(matches!(
        manifest_error(&|manifest| manifest.representation = ContentKey::of(b"x")),
        ManifestError::WrongRepresentation { .. }
    ));
    assert_eq!(
        manifest_error(&|manifest| manifest.extents.clear()),
        ManifestError::NoExtents
    );
    assert_eq!(
        manifest_error(&|manifest| manifest.extents[1].index = 0),
        ManifestError::DuplicateIndex { index: 0 }
    );
    assert_eq!(
        manifest_error(&|manifest| manifest.extents[0].stored_length_bytes = 0),
        ManifestError::EmptyExtent { index: 0 }
    );
    assert_eq!(
        manifest_error(&|manifest| manifest.extents[0].stored_offset_bytes = u64::MAX - 1),
        ManifestError::Overflow { index: 0 }
    );
    assert_eq!(
        manifest_error(&|manifest| manifest.object_length_bytes = 20),
        ManifestError::StoredOutsideObject { index: 1 }
    );
    assert_eq!(
        manifest_error(&|manifest| manifest.extents[1].stored_offset_bytes = 8),
        ManifestError::StoredOverlap { index: 1 }
    );
    assert_eq!(
        manifest_error(&|manifest| manifest.extents[1].decoded_offset_bytes = 8),
        ManifestError::DecodedOverlap { index: 1 }
    );
    assert_eq!(
        manifest_error(&|manifest| manifest.extents[0].decoded_length_bytes = 17),
        ManifestError::RawLengthMismatch { index: 0 }
    );

    let refused_dependencies = |dependencies: Vec<DependencySpec>| {
        let world = World::new();
        publish(&world, &artifact, vec![local("nvme")]);
        let mut executor = world.executor(config());
        let mut load = request("load", &artifact, destination("placement"));
        load.dependencies = dependencies;
        let refused = executor.submit(load).unwrap_err();
        assert!(!world.journal().iter().any(is_destination_reserve));
        match refused {
            SubmitError::Dependency(error) => error,
            other => panic!("not a dependency refusal: {other:?}"),
        }
    };
    let id = DependencyId;
    assert_eq!(
        refused_dependencies(vec![]),
        DependencyError::NoDependencies
    );
    assert_eq!(
        refused_dependencies(vec![dependency(1, &[0], &[]), dependency(1, &[1], &[])]),
        DependencyError::DuplicateId { id: id(1) }
    );
    assert_eq!(
        refused_dependencies(vec![dependency(1, &[], &[])]),
        DependencyError::Empty { id: id(1) }
    );
    assert_eq!(
        refused_dependencies(vec![dependency(1, &[0, 0], &[])]),
        DependencyError::RepeatedExtent {
            id: id(1),
            index: 0
        }
    );
    assert_eq!(
        refused_dependencies(vec![dependency(1, &[9], &[])]),
        DependencyError::UnknownExtent {
            id: id(1),
            index: 9
        }
    );
    assert_eq!(
        refused_dependencies(vec![dependency(1, &[0], &[7])]),
        DependencyError::UnknownPrerequisite {
            id: id(1),
            requires: id(7)
        }
    );
    assert_eq!(
        refused_dependencies(vec![dependency(1, &[0], &[1])]),
        DependencyError::Cycle { id: id(1) }
    );
    assert_eq!(
        refused_dependencies(vec![dependency(1, &[0], &[2]), dependency(2, &[1], &[1])]),
        DependencyError::Cycle { id: id(1) }
    );

    let world = World::new();
    publish(&world, &artifact, vec![local("nvme")]);
    let mut executor = world.executor(config());
    let mut narrow = destination("placement");
    narrow.capacity_bytes = 16;
    assert_eq!(
        executor
            .submit(request("load", &artifact, narrow))
            .unwrap_err(),
        SubmitError::DestinationOutOfBounds { index: 1 }
    );
    world.catalog.refuse(
        artifact.key,
        artifact.representation,
        CatalogRefusal::NotAuthorized,
    );
    assert_eq!(
        executor
            .submit(request("load", &artifact, destination("placement")))
            .unwrap_err(),
        SubmitError::Catalog(CatalogRefusal::NotAuthorized)
    );
    assert_eq!(
        executor
            .submit(request("executor", &artifact, destination("placement")))
            .unwrap_err(),
        SubmitError::DuplicateOperation {
            operation: op("executor")
        }
    );
    assert!(!world.journal().iter().any(is_destination_reserve));
}

#[test]
fn an_import_only_bind_is_never_a_read_source() {
    let artifact = Artifact::new("weights", &[16, 16], false);
    let bind = candidate("bind", SourceKind::ImportOnlyBind, 1e10);
    let world = World::new();
    publish(&world, &artifact, vec![bind.clone()]);
    let mut executor = world.executor(config());
    assert_eq!(
        executor
            .submit(request("load", &artifact, destination("placement")))
            .unwrap_err(),
        SubmitError::NoReadableSource
    );
    assert!(SubmitError::NoReadableSource
        .to_string()
        .contains("import-only bind"));

    let world = World::new();
    publish(&world, &artifact, vec![local("nvme"), bind]);
    world
        .backend
        .state()
        .corrupt
        .insert((source("nvme"), artifact.key, 0));
    let mut executor = world.executor(config());
    let job = op("load");
    executor
        .submit(request("load", &artifact, destination("placement")))
        .unwrap();
    drive(&mut executor, &world);
    assert!(matches!(
        failure_of(&executor, &job).failure,
        ExtentFailure::NoEligibleSource { .. }
    ));
    assert!(reads(&world).iter().all(|read| read.0 != "bind"));
}

// Lifecycle, events and source choice.

#[test]
fn retiring_and_closing_release_everything_exactly_once() {
    let world = World::new();
    let artifact = Artifact::new("weights", &[16, 16], false);
    publish(&world, &artifact, vec![local("nvme")]);
    let mut executor = world.executor(config());
    let job = op("load");
    executor
        .submit(request("load", &artifact, destination("placement")))
        .unwrap();
    let placement = allocation(gpu0(), "placement");
    assert!(matches!(
        executor.retire_destination(&placement),
        Err(RetireError::InUse { .. })
    ));
    assert_eq!(executor.close(), Err(CloseError::Busy));
    assert!(matches!(
        executor.forget(&job),
        Err(ForgetError::StillRunning { .. })
    ));
    drive(&mut executor, &world);
    assert_eq!(executor.status(&job), Some(&JobStatus::Completed));

    let vram = ReservedResource::DeviceMemory { device: gpu0() };
    assert_eq!(world.ledger.held().len(), 1);
    assert_eq!(world.ledger.releasing().len(), 2);
    assert_eq!(world.ledger.used(vram), 32);
    world.ledger.observe_releases();
    assert_eq!(world.ledger.used(vram), 0);

    let releases = |world: &World| {
        count(&world.journal(), |entry| {
            matches!(entry, Entry::Release { .. })
        })
    };
    assert_eq!(releases(&world), 2);
    assert_eq!(executor.retire_destination(&placement), Ok(2));
    assert_eq!(executor.retire_destination(&placement), Ok(0));
    assert_eq!(releases(&world), 2);
    executor.forget(&job).unwrap();
    assert!(executor.status(&job).is_none());
    assert_eq!(
        executor.forget(&job),
        Err(ForgetError::UnknownJob {
            operation: job.clone()
        })
    );
    executor.close().unwrap();
    assert_eq!(releases(&world), 3);
    assert!(world.ledger.held().is_empty());
    assert_eq!(executor.close(), Err(CloseError::AlreadyClosed));
    assert_eq!(
        executor
            .submit(request("again", &artifact, destination("placement")))
            .unwrap_err(),
        SubmitError::Unavailable(Unavailable::Closed)
    );
    assert_eq!(executor.pump().unwrap_err(), Unavailable::Closed);
}

#[test]
fn unknown_and_finished_jobs_are_refused_by_name() {
    let world = World::new();
    let artifact = Artifact::new("weights", &[16], false);
    publish(&world, &artifact, vec![local("nvme")]);
    let mut executor = world.executor(config());
    let job = op("load");
    assert_eq!(
        executor.cancel(&job),
        Err(CancelError::UnknownJob {
            operation: job.clone()
        })
    );
    assert!(matches!(
        executor.promote(&job),
        Err(PromoteError::UnknownJob { .. })
    ));
    executor
        .submit(request("load", &artifact, destination("placement")))
        .unwrap();
    assert!(matches!(
        executor.promote(&job),
        Err(PromoteError::NotSpeculative { .. })
    ));
    assert_eq!(
        executor
            .submit(request("load", &artifact, destination("placement")))
            .unwrap_err(),
        SubmitError::DuplicateOperation {
            operation: job.clone()
        }
    );
    drive(&mut executor, &world);
    assert_eq!(
        executor.cancel(&job),
        Err(CancelError::NotRunning {
            operation: job.clone()
        })
    );
}

#[test]
fn events_carry_a_growing_sequence_on_their_streams() {
    let world = World::new();
    let artifact = Artifact::new("weights", &[16, 16], false);
    publish(&world, &artifact, vec![local("nvme")]);
    let mut executor = world.executor(config());
    let job = op("load");
    executor
        .submit(request("load", &artifact, destination("placement")))
        .unwrap();
    drive(&mut executor, &world);
    let events = world.events();
    let sequences: Vec<u64> = events.iter().map(|event| event.sequence).collect();
    assert_eq!(sequences, (1..=events.len() as u64).collect::<Vec<_>>());
    assert!(events.windows(2).all(|pair| pair[0].at <= pair[1].at));
    assert!(events.iter().all(|event| event.operation == job));
    for event in &events {
        let expected = match event.kind {
            TransferEventKind::Progress(_) | TransferEventKind::DependencyUsable { .. } => {
                EventStream::Progress
            }
            TransferEventKind::StageMeasured(_) => EventStream::Metrics,
            _ => EventStream::Audit,
        };
        assert_eq!(event.kind.stream(), expected);
    }
    let progress: Vec<ProgressSnapshot> = events
        .iter()
        .filter_map(|event| match event.kind {
            TransferEventKind::Progress(snapshot) => Some(snapshot),
            _ => None,
        })
        .collect();
    assert!(progress
        .windows(2)
        .all(|pair| pair[0].committed_bytes <= pair[1].committed_bytes));
    assert_eq!(progress.last().unwrap().committed_bytes, 32);
    assert!(events
        .iter()
        .any(|event| event.kind == TransferEventKind::Completed));
}

#[test]
fn measured_rates_steer_later_plans() {
    let world = World::new();
    let first = Artifact::new("a", &[16; 4], false);
    let second = Artifact::new("b", &[16; 4], false);
    let sources = || {
        vec![
            candidate("slow", SourceKind::LocalFile, 1e9),
            candidate("fast", SourceKind::LocalFile, 1e9),
        ]
    };
    publish(&world, &first, sources());
    publish(&world, &second, sources());
    {
        let mut state = world.backend.state();
        state.timing.insert(source("slow"), (100, 100));
        state.timing.insert(source("fast"), (100, 1));
    }
    let mut small = config();
    small.host_staging.slot_bytes = 32;
    let mut executor = world.executor(small);
    executor
        .submit(request("a", &first, destination("da")))
        .unwrap();
    drive(&mut executor, &world);
    let first_sources: BTreeSet<String> = reads(&world).into_iter().map(|read| read.0).collect();
    assert_eq!(
        first_sources,
        BTreeSet::from(["fast".to_owned(), "slow".to_owned()])
    );
    executor
        .submit(request("b", &second, destination("db")))
        .unwrap();
    drive(&mut executor, &world);
    assert!(reads(&world)
        .iter()
        .filter(|read| read.1 == second.key)
        .all(|read| read.0 == "fast"));
    assert_eq!(executor.status(&op("b")), Some(&JobStatus::Completed));
}

#[test]
fn unauthorized_or_advertised_sources_are_refused_by_the_planner() {
    let artifact = Artifact::new("weights", &[16], false);
    let mut unauthorized = local("nvme");
    unauthorized.spec.authorization = SourceAuthorization::Unauthorized;
    let world = World::new();
    publish(&world, &artifact, vec![unauthorized]);
    let mut executor = world.executor(config());
    assert_eq!(
        executor
            .submit(request("load", &artifact, destination("placement")))
            .unwrap_err(),
        SubmitError::Plan(PlanFailure::Sources(SourcesError::NoAuthorizedSource))
    );
    assert_eq!(world.ledger.held().len(), 1);

    let mut advertised = local("nvme");
    advertised.spec.bandwidth = BandwidthRating::advertised(1e9).unwrap();
    let world = World::new();
    publish(&world, &artifact, vec![advertised]);
    let mut executor = world.executor(config());
    assert!(matches!(
        executor
            .submit(request("load", &artifact, destination("placement")))
            .unwrap_err(),
        SubmitError::Plan(PlanFailure::Sources(SourcesError::UnusableBandwidth { .. }))
    ));
}

// The reservation port over the host ledger (T04).

type HostLedger = Arc<Mutex<Ledger<Arc<ManualClock>>>>;

/// A host ledger on the world's clock with these capacities, each a host observation,
/// and a budget for every resource for the executor and for "tenant-a".
fn host_ledger(world: &World, capacities: &[(ReservedResource, u64)]) -> HostLedger {
    let ledger = Arc::new(Mutex::new(Ledger::new(
        Arc::clone(&world.clock),
        HostSubject {
            machine: digest("yougori/test/machine/v1", &[b"host"]),
        },
        LedgerConfig {
            queue: QueueLimits {
                max_entries: 8,
                max_entries_per_tenant: 4,
                max_wait: Duration::from_secs(1),
            },
            grant_ttl: Duration::from_secs(3_600),
            unmanaged_usage_max_age: Duration::from_secs(3_600),
        },
    )));
    {
        let mut host = ledger.lock().unwrap();
        for (resource, total) in capacities {
            let key = resource_key(*resource);
            host.declare_capacity(
                key,
                CapacityDeclaration {
                    total: *total,
                    supervisor_reserve: 0,
                    unmanaged_in_use: 0,
                    source: SourceClass::HostProbe,
                },
            )
            .unwrap();
            for tenant in ["executor", "tenant-a"] {
                host.set_tenant_budget(TenantId::new(tenant).unwrap(), key, 1 << 20)
                    .unwrap();
            }
        }
    }
    ledger
}

fn staging_account() -> StagingAccount {
    StagingAccount {
        execution: ExecutionId::new("exe-executor").unwrap(),
        tenant: TenantId::new("executor").unwrap(),
    }
}

#[test]
fn the_host_ledger_reserves_before_start_and_releases_on_completion_or_cancel() {
    let world = World::new();
    let artifact = Artifact::new("weights", &[16, 16], false);
    let second = Artifact::new("second", &[16, 16], false);
    publish(&world, &artifact, vec![local("nvme")]);
    publish(&world, &second, vec![local("nvme")]);
    let ledger = host_ledger(
        &world,
        &[
            (ReservedResource::DeviceMemory { device: gpu0() }, 1 << 20),
            (ReservedResource::PinnedHostMemory, 1 << 20),
            (ReservedResource::HostMemory, 1 << 20),
        ],
    );
    let vram = resource_key(ReservedResource::DeviceMemory { device: gpu0() });
    let pinned = resource_key(ReservedResource::PinnedHostMemory);
    let ram = resource_key(ReservedResource::HostMemory);
    ledger
        .lock()
        .unwrap()
        .set_tenant_budget(TenantId::new("tenant-a").unwrap(), vram, 48)
        .unwrap();
    let adapter = LedgerReservations::new(Arc::clone(&ledger), staging_account());
    let mut executor = TransferExecutor::new(
        config(),
        Arc::clone(&world.clock),
        world.ports_with(Box::new(adapter)),
    )
    .unwrap();
    let states = |ledger: &Arc<Mutex<Ledger<Arc<ManualClock>>>>| -> Vec<ReservationState> {
        ledger
            .lock()
            .unwrap()
            .open_reservations()
            .map(|record| record.state())
            .collect()
    };
    assert_eq!(ledger.lock().unwrap().reserved(pinned), 256);
    assert_eq!(ledger.lock().unwrap().reserved(ram), 256);
    assert_eq!(states(&ledger), [ReservationState::InUse]);

    let job = op("load");
    executor
        .submit(request("load", &artifact, destination("placement")))
        .unwrap();
    assert_eq!(ledger.lock().unwrap().reserved(vram), 32);
    assert_eq!(states(&ledger), [ReservationState::InUse; 3]);
    assert!(ledger
        .lock()
        .unwrap()
        .open_reservations()
        .all(|record| record.provenance().requester == Requester::Transfer));
    drive(&mut executor, &world);
    assert_eq!(executor.status(&job), Some(&JobStatus::Completed));
    let releasing: Vec<_> = ledger
        .lock()
        .unwrap()
        .open_reservations()
        .filter(|record| record.state() == ReservationState::Releasing)
        .map(|record| record.id())
        .collect();
    assert_eq!(releasing.len(), 2);
    assert_eq!(ledger.lock().unwrap().reserved(vram), 32);

    let refused = executor
        .submit(request("again", &second, destination("other")))
        .unwrap_err();
    assert_eq!(
        refused,
        SubmitError::Reservation(ReservationRefusal::Capacity(CapacityRefusal {
            resource: ReservedResource::DeviceMemory { device: gpu0() },
            limit: CapacityLimit::TenantBudget,
            requested_bytes: 16,
            available_bytes: 0,
            retry: RetryAdvice::CanProgress,
        }))
    );
    assert_eq!(ledger.lock().unwrap().reserved(vram), 32);

    {
        let mut host = ledger.lock().unwrap();
        for reservation in releasing {
            host.confirm_release(reservation, SourceClass::HostProbe)
                .unwrap();
        }
        assert_eq!(host.reserved(vram), 0);
    }
    let again = op("again");
    executor
        .submit(request("again", &second, destination("other")))
        .unwrap();
    assert_eq!(ledger.lock().unwrap().reserved(vram), 32);
    assert_eq!(
        executor.cancel(&again).unwrap(),
        CancelReport {
            shared: 0,
            reclaimed: 2,
            draining: 0,
            resident: 0
        }
    );
    let cancelled: Vec<_> = ledger
        .lock()
        .unwrap()
        .open_reservations()
        .filter(|record| record.state() == ReservationState::Releasing)
        .map(|record| record.id())
        .collect();
    assert_eq!(cancelled.len(), 2);
    let mut host = ledger.lock().unwrap();
    for reservation in cancelled {
        host.confirm_release(reservation, SourceClass::HostProbe)
            .unwrap();
    }
    assert_eq!(host.reserved(vram), 0);
}

// Value types.

#[test]
fn loader_permissions_follow_the_plan_and_never_enable_a_method_by_hand() {
    let ordinary = LoaderPermissions::ordinary();
    for method in ReadMethod::ALL {
        assert_eq!(
            ordinary.permits(method, &NoEvidence),
            method.gate().is_none()
        );
        assert_eq!(
            method.is_ordinary_local(),
            matches!(
                method,
                ReadMethod::PositionedRead | ReadMethod::MemoryMap | ReadMethod::UpstreamLoader
            )
        );
    }
    assert!(ordinary.required().is_empty());
    assert!(ordinary.compatible_with(&ordinary));
    assert_eq!(
        ReadMethod::GpuDirectStorage.gate(),
        Some(Optimization::GpuDirectStorage)
    );
    assert_eq!(ReadMethod::IoUring.gate(), Some(Optimization::IoUring));
    assert!(TransferPath::DirectStorage.bypasses_host_ring());
    assert!(TransferPath::GpuPeer { from: gpu1() }.bypasses_host_ring());
    assert!(!TransferPath::HostRing.bypasses_host_ring());
    assert!(!SourceKind::ImportOnlyBind.is_read_source());
    assert!(Priority::Foreground > Priority::Speculative);
    assert_eq!(Stage::ALL.map(Stage::step), [1, 2, 3, 4, 5, 5, 5, 6]);
    let raw = Artifact::new("weights", &[16], false).extents[0];
    assert_eq!(raw.stored_digest(), *raw.decoded_key.digest());
    assert_eq!(raw.decode_bytes(), 0);
    let encoded = Artifact::new("weights", &[16], true).extents[0];
    assert_ne!(encoded.stored_digest(), *encoded.decoded_key.digest());
    assert_eq!(encoded.decode_bytes(), 16);
}

// Review findings (R1-d): one subscriber never fails another's work (§3.5 line 572).

fn gds_permissions(world: &World, necessity: Necessity, fresh_for: Duration) -> LoaderPermissions {
    on_cuda(
        world,
        &[(Optimization::GpuDirectStorage, necessity)],
        true,
        fresh_for,
    )
}

/// R1-d probe 1, refused: a job whose required method lapses fails alone; a job sharing
/// the operation that only accepted the method keeps its work.
#[test]
fn a_stale_requirement_fails_only_the_job_that_holds_it() {
    let world = World::new();
    world
        .backend
        .state()
        .methods
        .insert(ReadMethod::GpuDirectStorage);
    let required = gds_permissions(&world, Necessity::Required, Duration::from_nanos(150));
    let optional = gds_permissions(&world, Necessity::Optional, Duration::from_secs(60));
    assert!(required.compatible_with(&optional));
    let artifact = Artifact::new("weights", &[16; 4], false);
    publish(&world, &artifact, vec![local("nvme")]);
    let mut executor = world.executor(with_device_staging(config(), 1, 32));
    let (holder, sharer) = (op("a"), op("b"));
    executor
        .submit(TransferRequest {
            loader: required,
            ..request("a", &artifact, destination("placement"))
        })
        .unwrap();
    executor
        .submit(TransferRequest {
            loader: optional,
            ..request("b", &artifact, destination("placement"))
        })
        .unwrap();
    executor.pump().unwrap();
    world.advance(132);
    executor.pump().unwrap();
    let failure = failure_of(&executor, &holder);
    assert_eq!(failure.extent, 2);
    assert!(matches!(
        failure.failure,
        ExtentFailure::Permanent { ref attempts } if attempts.last().unwrap().failure
            == AttemptFailure::RequiredMethodUnavailable {
                method: ReadMethod::GpuDirectStorage,
                reason: MethodUnavailable::EvidenceExpired,
            }
    ));
    let flight = executor.flight_of(&sharer, 2).unwrap();
    assert_eq!(executor.attempts(flight).unwrap(), []);
    assert_eq!(executor.subscribers(flight), Some(1));
    drive(&mut executor, &world);
    assert_eq!(executor.status(&sharer), Some(&JobStatus::Completed));
    assert!(reads(&world)
        .iter()
        .all(|read| read.2 == ReadMethod::GpuDirectStorage));
    assert_eq!(
        world
            .backend
            .destination(&allocation(gpu0(), "placement"), 0, 64),
        artifact.decoded
    );
}

/// R1-d probe 2, refused: a subscriber's lapsed optional evidence never fails a job whose
/// own requirement is fresh; the read keeps the required method.
#[test]
fn a_lapsed_optional_permission_never_fails_a_fresh_requirement() {
    let world = World::new();
    world
        .backend
        .state()
        .methods
        .insert(ReadMethod::GpuDirectStorage);
    let required = gds_permissions(&world, Necessity::Required, Duration::from_secs(60));
    let optional = gds_permissions(&world, Necessity::Optional, Duration::from_nanos(150));
    let artifact = Artifact::new("weights", &[16; 4], false);
    publish(&world, &artifact, vec![local("nvme")]);
    let mut executor = world.executor(with_device_staging(config(), 1, 32));
    executor
        .submit(TransferRequest {
            loader: required,
            ..request("a", &artifact, destination("placement"))
        })
        .unwrap();
    executor
        .submit(TransferRequest {
            loader: optional,
            ..request("b", &artifact, destination("placement"))
        })
        .unwrap();
    executor.pump().unwrap();
    world.advance(132);
    drive(&mut executor, &world);
    assert_eq!(executor.status(&op("a")), Some(&JobStatus::Completed));
    assert_eq!(executor.status(&op("b")), Some(&JobStatus::Completed));
    let started = reads(&world);
    assert_eq!(started.len(), 2);
    assert!(started
        .iter()
        .all(|read| read.2 == ReadMethod::GpuDirectStorage));
}

/// A subscriber that no source serves fails alone (here a job that requires GPUDirect
/// Storage once its only local file failed); the operation stays with the others.
#[test]
fn a_subscriber_no_source_serves_fails_alone() {
    let world = World::new();
    let artifact = Artifact::new("weights", &[16, 16], false);
    publish(
        &world,
        &artifact,
        vec![local("nvme"), candidate("mirror", SourceKind::Remote, 1e8)],
    );
    {
        let mut state = world.backend.state();
        state.methods.insert(ReadMethod::GpuDirectStorage);
        state.corrupt.insert((source("nvme"), artifact.key, 0));
    }
    let required = gds_permissions(&world, Necessity::Required, Duration::from_secs(60));
    let optional = gds_permissions(&world, Necessity::Optional, Duration::from_secs(60));
    let mut executor = world.executor(with_device_staging(config(), 2, 64));
    let (holder, sharer) = (op("a"), op("b"));
    executor
        .submit(TransferRequest {
            loader: required,
            ..request("a", &artifact, destination("placement"))
        })
        .unwrap();
    executor
        .submit(TransferRequest {
            loader: optional,
            ..request("b", &artifact, destination("placement"))
        })
        .unwrap();
    drive(&mut executor, &world);
    let failure = failure_of(&executor, &holder);
    assert_eq!(failure.extent, 0);
    assert!(matches!(
        failure.failure,
        ExtentFailure::NoEligibleSource { ref attempts } if attempts.len() == 1
    ));
    assert_eq!(executor.status(&sharer), Some(&JobStatus::Completed));
    assert!(reads(&world).iter().any(|read| read.0 == "mirror"));
    assert_eq!(
        world
            .backend
            .destination(&allocation(gpu0(), "placement"), 0, 32),
        artifact.decoded
    );
}

/// Two loads that require different methods cannot share one read, so the second is
/// refused when it would join.
#[test]
fn loads_that_require_different_methods_never_share_a_read() {
    let world = World::new();
    {
        let mut state = world.backend.state();
        state.methods.insert(ReadMethod::GpuDirectStorage);
        state.methods.insert(ReadMethod::IoUring);
    }
    let plan = |gds: Necessity, io_uring: Necessity| {
        on_cuda(
            &world,
            &[
                (Optimization::GpuDirectStorage, gds),
                (Optimization::IoUring, io_uring),
            ],
            true,
            Duration::from_secs(60),
        )
    };
    let gds = plan(Necessity::Required, Necessity::Optional);
    let io_uring = plan(Necessity::Optional, Necessity::Required);
    let either = plan(Necessity::Optional, Necessity::Optional);
    assert!(!gds.compatible_with(&io_uring));
    assert!(gds.compatible_with(&gds));
    assert!(gds.compatible_with(&either) && io_uring.compatible_with(&either));
    let artifact = Artifact::new("weights", &[16], false);
    publish(&world, &artifact, vec![local("nvme")]);
    let mut executor = world.executor(with_device_staging(config(), 2, 64));
    executor
        .submit(TransferRequest {
            loader: gds,
            ..request("a", &artifact, destination("placement"))
        })
        .unwrap();
    assert_eq!(
        executor
            .submit(TransferRequest {
                loader: io_uring,
                ..request("b", &artifact, destination("placement"))
            })
            .unwrap_err(),
        SubmitError::LoaderConflict { index: 0 }
    );
}

/// R1-d probe 3, refused: a finished or forgotten job never holds later jobs to its loader
/// plan; a delivered region is joined without reading it again.
#[test]
fn a_finished_job_never_blocks_its_delivered_region() {
    let world = World::new();
    world
        .backend
        .state()
        .methods
        .insert(ReadMethod::GpuDirectStorage);
    let artifact = Artifact::new("weights", &[16, 16], false);
    publish(&world, &artifact, vec![local("nvme")]);
    let mut executor = world.executor(with_device_staging(config(), 2, 64));
    let first = op("first");
    executor
        .submit(TransferRequest {
            loader: gds_permissions(&world, Necessity::Required, Duration::from_secs(60)),
            ..request("first", &artifact, destination("placement"))
        })
        .unwrap();
    drive(&mut executor, &world);
    assert_eq!(executor.status(&first), Some(&JobStatus::Completed));
    let flight = executor.flight_of(&first, 0).unwrap();
    assert_eq!(executor.subscribers(flight), Some(0));
    assert_eq!(executor.flight_phase(flight), Some(FlightPhase::Delivered));

    let second = op("second");
    executor
        .submit(request("second", &artifact, destination("placement")))
        .unwrap();
    assert!(
        kinds(&world, &second).contains(&TransferEventKind::Submitted {
            total_bytes: 32,
            new_operations: 0,
            shared_operations: 2
        })
    );
    drive(&mut executor, &world);
    assert_eq!(executor.status(&second), Some(&JobStatus::Completed));

    executor.forget(&first).unwrap();
    executor.forget(&second).unwrap();
    let third = op("third");
    executor
        .submit(request("third", &artifact, destination("placement")))
        .unwrap();
    drive(&mut executor, &world);
    assert_eq!(executor.status(&third), Some(&JobStatus::Completed));
    assert_eq!(reads(&world).len(), 1);
}

/// R1-d scratch proof, refused: pinned bytes are host RAM too, so a pinned reservation is
/// charged to both, and a host with too little RAM refuses it (GPU §2.7).
#[test]
fn pinned_staging_is_charged_to_host_ram_too() {
    let world = World::new();
    let pinned = resource_key(ReservedResource::PinnedHostMemory);
    let ram = resource_key(ReservedResource::HostMemory);
    assert_eq!(
        ledger_demand(ReservedResource::PinnedHostMemory, 4_096)
            .iter()
            .collect::<Vec<_>>(),
        [(ram, 4_096), (pinned, 4_096)]
    );
    let request = |resource, bytes| ReservationRequest {
        operation: op("staging"),
        execution: None,
        tenant: None,
        priority: Priority::Foreground,
        resource,
        purpose: ReservationPurpose::HostStaging,
        bytes,
        parent: None,
    };

    let small = host_ledger(
        &world,
        &[
            (ReservedResource::HostMemory, 100),
            (ReservedResource::PinnedHostMemory, 1 << 20),
        ],
    );
    let mut adapter = LedgerReservations::new(Arc::clone(&small), staging_account());
    assert_eq!(
        adapter
            .reserve(&request(ReservedResource::PinnedHostMemory, 4_096))
            .unwrap_err(),
        ReservationRefusal::Capacity(CapacityRefusal {
            resource: ReservedResource::HostMemory,
            limit: CapacityLimit::PhysicalCapacity,
            requested_bytes: 4_096,
            available_bytes: 100,
            retry: RetryAdvice::CannotProgress,
        })
    );
    assert_eq!(small.lock().unwrap().reserved(pinned), 0);
    adapter
        .reserve(&request(ReservedResource::HostMemory, 100))
        .unwrap();
    assert_eq!(small.lock().unwrap().reserved(ram), 100);
    assert_eq!(small.lock().unwrap().reserved(pinned), 0);

    let roomy = host_ledger(
        &world,
        &[
            (ReservedResource::HostMemory, 1 << 20),
            (ReservedResource::PinnedHostMemory, 1 << 20),
        ],
    );
    let mut adapter = LedgerReservations::new(Arc::clone(&roomy), staging_account());
    adapter
        .reserve(&request(ReservedResource::PinnedHostMemory, 4_096))
        .unwrap();
    assert_eq!(roomy.lock().unwrap().reserved(pinned), 4_096);
    assert_eq!(roomy.lock().unwrap().reserved(ram), 4_096);

    let world = World::new();
    world.ledger.set_capacity(ReservedResource::HostMemory, 100);
    assert!(matches!(
        world.try_executor(config()).err().unwrap(),
        StartError::Reservation(ReservationRefusal::Capacity(CapacityRefusal {
            resource: ReservedResource::HostMemory,
            ..
        }))
    ));
    let world = World::new();
    world.executor(config());
    assert_eq!(world.ledger.used(ReservedResource::PinnedHostMemory), 256);
    assert_eq!(world.ledger.used(ReservedResource::HostMemory), 256);
}

// Integration: evidence rechecked live (G7), CUDA only on CUDA (G8), revocation into
// running jobs (INT-02), destinations inside the placement (P04) and progress (P08).

/// G7 (INT-06, CORE-01): a configuration change invalidates the evidence behind a plan,
/// so the gated methods it enabled end at once, in the permissions and in the executor:
/// an optional one gives way to the ordinary loader, and a required one fails the job at
/// its next read and refuses later loads.
#[test]
fn gated_methods_end_when_a_configuration_change_invalidates_their_evidence() {
    let world = World::new();
    {
        let mut state = world.backend.state();
        state.methods.insert(ReadMethod::IoUring);
        state.methods.insert(ReadMethod::GpuDirectStorage);
    }
    let before = Artifact::new("before", &[16], false);
    let after = Artifact::new("after", &[16], false);
    let held = Artifact::new("held", &[16; 4], false);
    for artifact in [&before, &after, &held] {
        publish(&world, artifact, vec![local("nvme")]);
    }
    let plan = loader_plan(
        &world,
        &[(Optimization::IoUring, Necessity::Optional)],
        true,
        Duration::from_secs(60),
    );
    let optional = LoaderPermissions::from_plan(&plan);
    let required = gds_permissions(&world, Necessity::Required, Duration::from_secs(60));
    assert!(optional.permits(ReadMethod::IoUring, &world.registry));
    assert_eq!(
        required.unavailable(ReadMethod::GpuDirectStorage, &world.registry),
        None
    );
    let mut executor = world.executor(with_device_staging(config(), 1, 32));
    executor
        .submit(TransferRequest {
            loader: optional.clone(),
            ..request("before", &before, destination("before"))
        })
        .unwrap();
    drive(&mut executor, &world);
    executor
        .submit(TransferRequest {
            loader: required.clone(),
            ..request("held", &held, destination("held"))
        })
        .unwrap();
    executor.pump().unwrap();

    let dropped = world
        .registry
        .lock()
        .unwrap()
        .invalidate_configuration(loader_configuration());
    // The two plans' evidence and the runtime's platform evidence.
    assert_eq!(dropped, 3);
    assert!(plan
        .recheck(Optimization::IoUring, &*world.registry.lock().unwrap())
        .is_err());
    assert!(!optional.permits(ReadMethod::IoUring, &world.registry));
    assert_eq!(
        required.unavailable(ReadMethod::GpuDirectStorage, &world.registry),
        Some(platform_missing())
    );
    drive(&mut executor, &world);
    let failure = failure_of(&executor, &op("held"));
    assert_eq!(failure.extent, 2);
    assert!(matches!(
        failure.failure,
        ExtentFailure::Permanent { ref attempts } if attempts.last().unwrap().failure
            == AttemptFailure::RequiredMethodUnavailable {
                method: ReadMethod::GpuDirectStorage,
                reason: platform_missing(),
            }
    ));
    executor
        .submit(TransferRequest {
            loader: optional,
            ..request("after", &after, destination("after"))
        })
        .unwrap();
    drive(&mut executor, &world);
    assert_eq!(executor.status(&op("after")), Some(&JobStatus::Completed));
    let methods: Vec<(ContentKey, ReadMethod)> = reads(&world)
        .into_iter()
        .map(|(_, artifact, method, ..)| (artifact, method))
        .collect();
    assert_eq!(
        methods,
        [
            (before.key, ReadMethod::IoUring),
            (held.key, ReadMethod::GpuDirectStorage),
            (after.key, ReadMethod::PositionedRead)
        ]
    );
    assert_eq!(
        executor
            .submit(TransferRequest {
                loader: required,
                ..request("again", &after, destination("again"))
            })
            .unwrap_err(),
        SubmitError::RequiredMethodUnavailable {
            method: ReadMethod::GpuDirectStorage,
            reason: platform_missing()
        }
    );
}

/// G8 (GPU §3.8, INT-06): a CUDA mechanism needs a runtime known to compute on CUDA. A
/// Metal runtime whose probe claims GPUDirect Storage gets no backend runtime with it,
/// and a bare plan, whose platform is not known, never permits it: optional, it gives way
/// to the ordinary loader; required, the load is refused. io_uring needs no CUDA.
#[test]
fn cuda_mechanisms_need_a_runtime_known_to_compute_on_cuda() {
    let world = World::new();
    world
        .backend
        .state()
        .methods
        .insert(ReadMethod::GpuDirectStorage);
    let artifact = Artifact::new("weights", &[16, 16], false);
    publish(&world, &artifact, vec![local("nvme")]);
    let optional = planned(
        &world,
        &[(Optimization::GpuDirectStorage, Necessity::Optional)],
        true,
        Duration::from_secs(60),
    );
    assert!(optional.1.is_enabled(Optimization::GpuDirectStorage));
    assert_eq!(
        backend_runtime(&optional, ComputePlatform::Metal).unwrap_err(),
        RuntimeRefusal::CudaOnOtherPlatform {
            optimization: Optimization::GpuDirectStorage,
            platform: ComputePlatform::Metal,
        }
    );
    let bare = LoaderPermissions::from_plan(&optional.1);
    assert_eq!(bare.platform(), ComputePlatform::Other);
    assert!(!bare.permits(ReadMethod::GpuDirectStorage, &world.registry));
    assert_eq!(
        bare.unavailable(ReadMethod::GpuDirectStorage, &world.registry),
        Some(MethodUnavailable::NotOnCuda {
            platform: ComputePlatform::Other
        })
    );
    show_platform(
        &world,
        &optional.0,
        ObservedPlatform::Cuda,
        Duration::from_secs(3_600),
    );
    let cuda = LoaderPermissions::from_runtime(
        &backend_runtime(&optional, ComputePlatform::Cuda).unwrap(),
    );
    assert_eq!(cuda.platform(), ComputePlatform::Cuda);
    assert!(cuda.permits(ReadMethod::GpuDirectStorage, &world.registry));

    let mut executor = world.executor(with_device_staging(config(), 2, 64));
    executor
        .submit(TransferRequest {
            loader: bare,
            ..request("bare", &artifact, destination("bare"))
        })
        .unwrap();
    drive(&mut executor, &world);
    assert_eq!(executor.status(&op("bare")), Some(&JobStatus::Completed));
    assert!(reads(&world)
        .iter()
        .all(|read| read.2 == ReadMethod::PositionedRead && read.3.place == StagingPlace::Host));
    let required = loader_plan(
        &world,
        &[(Optimization::GpuDirectStorage, Necessity::Required)],
        true,
        Duration::from_secs(60),
    );
    assert_eq!(
        executor
            .submit(TransferRequest {
                loader: LoaderPermissions::from_plan(&required),
                ..request("required", &artifact, destination("required"))
            })
            .unwrap_err(),
        SubmitError::RequiredMethodUnavailable {
            method: ReadMethod::GpuDirectStorage,
            reason: MethodUnavailable::NotOnCuda {
                platform: ComputePlatform::Other
            }
        }
    );
    let io_uring = LoaderPermissions::from_plan(&loader_plan(
        &world,
        &[(Optimization::IoUring, Necessity::Required)],
        true,
        Duration::from_secs(60),
    ));
    assert!(io_uring.permits(ReadMethod::IoUring, &world.registry));
}

/// Without the registry an executor can recheck nothing, so it never uses a gated
/// method: an optional one gives way, and a required one is refused (CORE-01).
#[test]
fn an_executor_without_the_registry_never_uses_a_gated_method() {
    let world = World::new();
    world
        .backend
        .state()
        .methods
        .insert(ReadMethod::GpuDirectStorage);
    let artifact = Artifact::new("weights", &[16, 16], false);
    publish(&world, &artifact, vec![local("nvme")]);
    let mut executor = TransferExecutor::new(
        with_device_staging(config(), 2, 64),
        Arc::clone(&world.clock),
        world.ports(),
    )
    .unwrap();
    executor
        .submit(TransferRequest {
            loader: gds_permissions(&world, Necessity::Optional, Duration::from_secs(60)),
            ..request("optional", &artifact, destination("optional"))
        })
        .unwrap();
    drive(&mut executor, &world);
    assert_eq!(
        executor.status(&op("optional")),
        Some(&JobStatus::Completed)
    );
    assert!(reads(&world)
        .iter()
        .all(|read| read.2 == ReadMethod::PositionedRead));
    assert_eq!(
        executor
            .submit(TransferRequest {
                loader: gds_permissions(&world, Necessity::Required, Duration::from_secs(60)),
                ..request("required", &artifact, destination("required"))
            })
            .unwrap_err(),
        SubmitError::RequiredMethodUnavailable {
            method: ReadMethod::GpuDirectStorage,
            reason: platform_missing()
        }
    );
}

/// INT-02 (VM part §6.3 steps 1–2): the CORE-04 coordinator's revocation reaches running
/// jobs. The revoked execution's jobs are cancelled at a safe boundary: the read in flight
/// for its own work drains and nothing of it is copied, while an operation it shares with
/// another execution's job continues for that job. Nothing more is admitted for the
/// execution, and revoking again cancels nothing more.
#[test]
fn a_revocation_cancels_the_executions_running_jobs_and_admits_nothing_more() {
    let world = World::new();
    let mut sandbox = progress_fakes::SandboxHost::launch(&world.clock);
    let owner = progress_fakes::owner();
    let other = ExecutionId::new("exe-other").unwrap();
    let shared = Artifact::new("shared", &[16; 4], false);
    let own = Artifact::new("own", &[16; 4], false);
    publish(&world, &shared, vec![local("nvme")]);
    publish(&world, &own, vec![local("nvme")]);
    let of =
        |name: &str, artifact: &Artifact, into: &str, execution: &ExecutionId| TransferRequest {
            execution: execution.clone(),
            ..request(name, artifact, destination(into))
        };
    let mut executor = world.executor(config());
    executor
        .submit(of("revoked-own", &own, "own", &owner))
        .unwrap();
    executor
        .submit(of("revoked-shared", &shared, "shared", &owner))
        .unwrap();
    executor
        .submit(of("other", &shared, "shared", &other))
        .unwrap();
    assert_eq!(executor.pump().unwrap().reads_started, 2);

    let notice = sandbox.host.revoke(&owner).unwrap();
    assert_eq!(notice.execution, owner);
    let report = executor.cancel_execution(&notice);
    assert_eq!(report.cancelled, [op("revoked-own"), op("revoked-shared")]);
    assert_eq!(
        report.operations,
        CancelReport {
            shared: 4,
            reclaimed: 0,
            draining: 4,
            resident: 0
        }
    );
    let revoked = CancelReason::Revoked {
        revoked: notice.revoked,
    };
    for job in ["revoked-own", "revoked-shared"] {
        assert_eq!(
            executor.status(&op(job)),
            Some(&JobStatus::Cancelled { reason: revoked })
        );
        assert!(kinds(&world, &op(job)).contains(&TransferEventKind::Cancelled { reason: revoked }));
    }
    assert_eq!(executor.revoked(&owner), Some(notice.revoked));
    assert_eq!(executor.revoked(&other), None);
    assert_eq!(
        executor
            .submit(of("more", &own, "more", &owner))
            .unwrap_err(),
        SubmitError::ExecutionRevoked {
            execution: owner.clone(),
            revoked: notice.revoked
        }
    );

    drive(&mut executor, &world);
    assert_eq!(executor.status(&op("other")), Some(&JobStatus::Completed));
    assert_eq!(
        world
            .backend
            .destination(&allocation(gpu0(), "shared"), 0, 64),
        shared.decoded
    );
    let own_destination = allocation(gpu0(), "own");
    assert_eq!(
        count(&world.journal(), |entry| matches!(
            entry,
            Entry::EnqueueCopy { to, .. } if to.allocation == own_destination
        )),
        0,
        "nothing of the revoked execution's own read is used"
    );
    assert!(
        world
            .ledger
            .held()
            .values()
            .all(|(_, _, purpose)| !matches!(purpose, ReservationPurpose::Destination { .. })),
        "every destination reservation went back"
    );
    assert_eq!(
        executor.cancel_execution(&notice),
        RevocationReport::default()
    );
}

/// P04 (CORE-03 parent and child): a job submitted within the placement's reservation
/// carves its destinations from it, so the destination's memory is counted once. A job
/// that does not fit the parent's room, or of another execution, is refused and keeps
/// nothing reserved.
#[test]
fn destinations_are_carved_from_the_placements_reservation() {
    let world = World::new();
    let artifact = Artifact::new("weights", &[16, 16], false);
    let large = Artifact::new("large", &[16; 4], false);
    publish(&world, &artifact, vec![local("nvme")]);
    publish(&world, &large, vec![local("nvme")]);
    let gpu = ReservedResource::DeviceMemory { device: gpu0() };
    let ledger = host_ledger(
        &world,
        &[
            (gpu, 1 << 20),
            (ReservedResource::PinnedHostMemory, 1 << 20),
            (ReservedResource::HostMemory, 1 << 20),
        ],
    );
    let vram = resource_key(gpu);
    let execution = ExecutionId::new("exe-load").unwrap();
    // The placement's steady-state reservation, filed and created as P04 files it.
    let parent = {
        let mut host = ledger.lock().unwrap();
        let admission = host
            .reserve(host::ReservationRequest::new(
                Provenance {
                    requester: Requester::ModelPlacement,
                    execution: execution.clone(),
                    operation: op("placement"),
                    tenant: TenantId::new("tenant-a").unwrap(),
                    purpose: CostPurpose::Compute,
                    retry_number: 0,
                },
                host::Priority::Foreground,
                Amounts::new().with(vram, 48),
            ))
            .unwrap();
        let Admission::Granted(parent) = admission else {
            panic!("the placement is granted, got {admission:?}");
        };
        host.begin_create(parent).unwrap();
        parent
    };
    let adapter = LedgerReservations::new(Arc::clone(&ledger), staging_account());
    let mut executor = TransferExecutor::new(
        config(),
        Arc::clone(&world.clock),
        world.ports_with(Box::new(adapter)),
    )
    .unwrap();
    let job = op("load");
    executor
        .submit_within(request("load", &artifact, destination("placement")), parent)
        .unwrap();
    let children = |ledger: &Arc<Mutex<Ledger<Arc<ManualClock>>>>| -> usize {
        ledger
            .lock()
            .unwrap()
            .open_reservations()
            .filter(|record| record.parent() == Some(parent))
            .count()
    };
    assert_eq!(children(&ledger), 2);
    assert_eq!(ledger.lock().unwrap().reserved(vram), 48, "counted once");
    assert_eq!(
        ledger.lock().unwrap().parent_room(parent, vram).unwrap(),
        16
    );

    let refused = executor
        .submit_within(
            TransferRequest {
                execution: execution.clone(),
                ..request("more", &large, destination("more"))
            },
            parent,
        )
        .unwrap_err();
    assert!(matches!(
        refused,
        SubmitError::Reservation(ReservationRefusal::Capacity(CapacityRefusal {
            resource: ReservedResource::DeviceMemory { .. },
            limit: CapacityLimit::ParentReservation,
            requested_bytes: 16,
            available_bytes: 0,
            ..
        }))
    ));
    assert!(matches!(
        executor
            .submit_within(
                request("stranger", &artifact, destination("stranger")),
                parent
            )
            .unwrap_err(),
        SubmitError::Reservation(ReservationRefusal::Rejected { .. })
    ));
    assert_eq!(
        ledger.lock().unwrap().parent_room(parent, vram).unwrap(),
        16
    );
    assert_eq!(children(&ledger), 2);

    drive(&mut executor, &world);
    assert_eq!(executor.status(&job), Some(&JobStatus::Completed));
    // Delivered, each destination went back to the placement at once, its release
    // confirmed by the transfer's own report (T15): nothing stays counted twice until the
    // placement closes.
    assert_eq!(children(&ledger), 0);
    assert_eq!(
        ledger.lock().unwrap().parent_room(parent, vram).unwrap(),
        48
    );
    assert_eq!(ledger.lock().unwrap().reserved(vram), 48);

    // A cancelled job's destinations are released as before: they count in the parent
    // until their release is observed.
    let later = Artifact::new("later", &[16], false);
    publish(&world, &later, vec![local("nvme")]);
    executor
        .submit_within(
            TransferRequest {
                execution: execution.clone(),
                ..request("later", &later, destination("later"))
            },
            parent,
        )
        .unwrap();
    executor.cancel(&op("later")).unwrap();
    let host = ledger.lock().unwrap();
    assert!(host
        .open_reservations()
        .filter(|record| record.parent() == Some(parent))
        .all(|record| record.state() == ReservationState::Releasing));
    assert_eq!(host.parent_room(parent, vram).unwrap(), 32);
    assert_eq!(host.reserved(vram), 48);
}

/// A CORE-06 event hub on the world's clock, as P08's tests make one.
fn event_hub(world: &World) -> EventHub<Arc<ManualClock>> {
    EventHub::new(
        Arc::clone(&world.clock),
        HubConfig {
            metrics: MetricsConfig {
                capacity_events: 256,
                sample_above_events: 192,
                keep_one_in: NonZeroU32::new(8).unwrap(),
                retention: Duration::from_secs(60),
                max_series: 16,
            },
            progress: ProgressConfig {
                max_tracked: 64,
                terminal_retention: Duration::from_secs(60),
            },
            revocation: RevocationConfig {
                max_pending_executions: 16,
            },
            first_incarnation: ProducerIncarnation::new(1).unwrap(),
        },
    )
    .unwrap()
}

/// P08's publisher, registered on `hub`.
fn progress_publisher(
    world: &World,
    hub: &Mutex<EventHub<Arc<ManualClock>>>,
) -> ProgressPublisher<Arc<ManualClock>> {
    let producer = hub
        .lock()
        .unwrap()
        .register_progress(
            ProducerId::new("engine.progress").unwrap(),
            SourceClass::HostProbe,
            None,
        )
        .unwrap();
    ProgressPublisher::new(
        producer,
        Incarnation::new(1),
        Arc::clone(&world.clock),
        ClockId::new(ReportLabel::new("host-monotonic").unwrap()),
        PublishPolicy::default(),
    )
    .unwrap()
}

/// P08 (§3.10 line 650): each extent of each batch in flight reaches the progress
/// publisher for the job it serves; it arrives when its read finished, is committed once
/// verified and its copy's completion event was observed, and a failed attempt discards
/// it, so its bytes never count twice. A report the publisher refuses is an anomaly and
/// never stops the transfer.
#[test]
fn extent_progress_reaches_the_publisher_for_every_batch_in_flight() {
    let world = World::new();
    let artifact = Artifact::new("weights", &[16; 4], false);
    publish(
        &world,
        &artifact,
        vec![local("nvme"), candidate("mirror", SourceKind::Remote, 1e3)],
    );
    world
        .backend
        .state()
        .corrupt
        .insert((source("nvme"), artifact.key, 16));
    let hub = Arc::new(Mutex::new(event_hub(&world)));
    let publisher = Arc::new(Mutex::new(progress_publisher(&world, &hub)));
    let job = op("load");
    let total = artifact.decoded.len() as u64;
    publisher
        .lock()
        .unwrap()
        .track(
            &mut hub.lock().unwrap(),
            &job,
            TrackRequest {
                resource: TrackedResourceId::new(*artifact.key.digest()),
                kind: ResourceKind::Weights,
                total_bytes: total,
                stage: ProgressStage::at(Phase::Transferring),
            },
        )
        .unwrap();
    let mut executor = world
        .executor(config())
        .with_progress(Box::new(PublisherProgress::new(
            Arc::clone(&publisher),
            Arc::clone(&hub),
        )));
    executor
        .submit(request("load", &artifact, destination("placement")))
        .unwrap();
    assert_eq!(executor.pump().unwrap().reads_started, 1);
    let running = ProgressStage::at(Phase::Running);
    assert_eq!(
        publisher
            .lock()
            .unwrap()
            .set_stage(&mut hub.lock().unwrap(), &job, running),
        Err(PublishError::CopiesInFlight {
            in_flight_bytes: total
        }),
        "every extent of the batch is in flight"
    );

    let flight = executor.flight_of(&job, 1).unwrap();
    while executor.attempts(flight).unwrap().is_empty() {
        world.advance(50);
        executor.pump().unwrap();
    }
    let (_, update) = publisher.lock().unwrap().progress(&job).unwrap();
    assert_eq!(
        update.completed_bytes(),
        48,
        "the mismatching extent was discarded"
    );
    drive(&mut executor, &world);
    assert_eq!(executor.status(&job), Some(&JobStatus::Completed));
    assert!(reads(&world).iter().any(|read| read.0 == "mirror"));
    let (_, update) = publisher.lock().unwrap().progress(&job).unwrap();
    assert_eq!(update.completed_bytes(), total);
    assert_eq!(update.committed_usable_bytes(), total);
    publisher
        .lock()
        .unwrap()
        .set_stage(&mut hub.lock().unwrap(), &job, running)
        .unwrap();
    assert!(!world
        .events()
        .iter()
        .any(|event| matches!(event.kind, TransferEventKind::Anomaly(_))));

    let untracked = op("untracked");
    let other = Artifact::new("other", &[16, 16], false);
    publish(&world, &other, vec![local("nvme")]);
    executor
        .submit(request("untracked", &other, destination("other")))
        .unwrap();
    drive(&mut executor, &world);
    assert_eq!(executor.status(&untracked), Some(&JobStatus::Completed));
    let refused: Vec<(OperationId, u64)> = world
        .events()
        .into_iter()
        .filter_map(|event| match event.kind {
            TransferEventKind::Anomaly(Anomaly::ProgressRefused {
                operation,
                extent,
                error: PublishError::UnknownOperation,
            }) => Some((operation, extent)),
            _ => None,
        })
        .collect();
    assert!(!refused.is_empty());
    assert!(refused.iter().all(|(operation, _)| *operation == untracked));
}

// Integration round 2: the live multi-source load (math 0a6261e), platform evidence on
// every use (P06), the path a read took (GPU-T21) and direct I/O (GPU-T20).

/// Runs the executor until nothing is queued or in flight, 50 ns at a time, adding up the
/// reads whose bytes were discarded.
fn drive_counting_discards(executor: &mut Exec, world: &World) -> usize {
    let mut discarded = 0;
    for _ in 0..10_000 {
        discarded += executor.pump().expect("the pump runs").reads_discarded;
        if executor.is_idle() {
            return discarded;
        }
        world.advance(50);
    }
    panic!("the executor did not go idle");
}

/// GPU §2.5 (math 0a6261e): a source that fails mid-load is excluded from the live load.
/// Its batches in flight are taken back, so their reads are abandoned: each late report
/// is refused and its bytes are never used. Every batch it held moves to the source left
/// in the same load, without planning anything again.
#[test]
fn a_source_failing_mid_load_is_excluded_and_its_late_reads_are_discarded() {
    let world = World::new();
    let artifact = Artifact::new("weights", &[16; 4], false);
    publish(
        &world,
        &artifact,
        vec![local("s1"), candidate("s2", SourceKind::LocalFile, 1e8)],
    );
    world.backend.state().fail_reads.insert(source("s1"), 1);
    let mut small = config();
    small.host_staging.slot_bytes = 16;
    let mut executor = world.executor(small);
    let job = op("load");
    executor
        .submit(request("load", &artifact, destination("placement")))
        .unwrap();
    let discarded = drive_counting_discards(&mut executor, &world);
    assert_eq!(executor.status(&job), Some(&JobStatus::Completed));
    let started: Vec<String> = reads(&world).into_iter().map(|read| read.0).collect();
    assert_eq!(started, ["s1", "s1", "s1", "s1", "s2", "s2", "s2", "s2"]);
    assert_eq!(discarded, 3);
    assert_eq!(
        count(&world.journal(), |entry| matches!(
            entry,
            Entry::Coalesce { .. }
        )),
        1,
        "the live load moved the batches; nothing was planned again"
    );
    assert_eq!(
        executor.blacklist(&job).unwrap(),
        &BTreeSet::from([source("s1")])
    );
    let failed = executor.flight_of(&job, 0).unwrap();
    assert!(matches!(
        executor.attempts(failed).unwrap(),
        [Attempt {
            source: Some(from),
            failure: AttemptFailure::Read { .. },
            ..
        }] if *from == source("s1")
    ));
    for index in 1..4 {
        let flight = executor.flight_of(&job, index).unwrap();
        assert!(executor.attempts(flight).unwrap().is_empty());
    }
    assert!(stages(&world, &job)
        .iter()
        .filter(|stage| stage.stage == Stage::Copy)
        .all(|stage| stage.source == Some(source("s2"))));
    assert_eq!(
        world
            .backend
            .destination(&allocation(gpu0(), "placement"), 0, 64),
        artifact.decoded
    );
}

/// GPU §2.5: a batch that failed without its source being to blame is requeued in the
/// live load, here on the same source, and counted as a failure; the source is not
/// blacklisted and nothing is planned again.
#[test]
fn a_batch_that_failed_without_blaming_its_source_is_requeued_in_the_live_load() {
    let world = World::new();
    let artifact = Artifact::new("weights", &[16, 16], false);
    publish(&world, &artifact, vec![local("s1")]);
    {
        let mut state = world.backend.state();
        state.fail_reads.insert(source("s1"), 1);
        state.read_error = BackendErrorKind::Unsupported;
    }
    let mut small = config();
    small.host_staging.slot_bytes = 16;
    let mut executor = world.executor(small);
    let job = op("load");
    executor
        .submit(request("load", &artifact, destination("placement")))
        .unwrap();
    drive(&mut executor, &world);
    assert_eq!(executor.status(&job), Some(&JobStatus::Completed));
    let flight = executor.flight_of(&job, 0).unwrap();
    assert!(matches!(
        executor.attempts(flight).unwrap(),
        [Attempt {
            failure: AttemptFailure::Read { error },
            ..
        }] if error.kind == BackendErrorKind::Unsupported
    ));
    assert!(executor.blacklist(&job).unwrap().is_empty());
    let started: Vec<(String, u64)> = reads(&world)
        .into_iter()
        .map(|read| (read.0, read.4))
        .collect();
    assert_eq!(
        started,
        [
            ("s1".to_owned(), 0),
            ("s1".to_owned(), 16),
            ("s1".to_owned(), 0)
        ]
    );
    assert_eq!(
        count(&world.journal(), |entry| matches!(
            entry,
            Entry::Coalesce { .. }
        )),
        1
    );
}

/// GPU §2.5 (`SharedSourceCaps`): a source's cap holds across every load of the
/// executor, so two jobs reading one source never have more batches in flight there than
/// it serves.
#[test]
fn a_sources_cap_holds_across_loads() {
    let world = World::new();
    let one = Artifact::new("one", &[16], false);
    let two = Artifact::new("two", &[16], false);
    let mut nas = local("nas");
    nas.spec.max_in_flight = 1;
    publish(&world, &one, vec![nas.clone()]);
    publish(&world, &two, vec![nas]);
    let mut executor = world.executor(config());
    executor
        .submit(request("one", &one, destination("one")))
        .unwrap();
    executor
        .submit(request("two", &two, destination("two")))
        .unwrap();
    assert_eq!(executor.pump().unwrap().reads_started, 1);
    drive(&mut executor, &world);
    assert_eq!(executor.status(&op("one")), Some(&JobStatus::Completed));
    assert_eq!(executor.status(&op("two")), Some(&JobStatus::Completed));
    let journal = world.journal();
    let first_done = position(&journal, |entry| {
        matches!(entry, Entry::ReadDone { ticket: 1, .. })
    });
    let second_started = position(&journal, |entry| {
        matches!(entry, Entry::BeginRead { ticket: 2, .. })
    });
    assert!(first_done < second_started);
}

/// The backend runtime assembled from a planned runtime on `platform` (P06), with no
/// platform policy.
fn assembled(
    (profile, plan): &(RuntimeProfile, LoaderPlan),
    platform: ComputePlatform,
) -> BackendRuntime {
    let gate = LoaderGate::recorded();
    let pinned = PinnedCapabilities::new(
        QueriedCapabilities {
            release: profile.runtime.release.clone(),
            source: SourceClass::HostProbe,
            sleep_levels: BTreeMap::new(),
            features: BTreeSet::new(),
        },
        gate.rules(),
    )
    .unwrap();
    BackendRuntime::new(profile, platform, plan, gate.rules(), pinned).unwrap()
}

/// GPU §3.8 (P06's platform judgement): a CUDA read method rests on fresh CORE-01
/// `ComputePlatform` evidence about its runtime on every use, never on the runtime's
/// declaration. Without a platform policy, without evidence or with evidence of another
/// platform it is refused with the reason, and a requirement fails its job at the first
/// read after the evidence lapsed.
#[test]
fn cuda_read_methods_need_platform_evidence_on_every_use() {
    let world = World::new();
    world
        .backend
        .state()
        .methods
        .insert(ReadMethod::GpuDirectStorage);
    let gds = planned(
        &world,
        &[(Optimization::GpuDirectStorage, Necessity::Required)],
        true,
        Duration::from_secs(60),
    );
    let gds_method = ReadMethod::GpuDirectStorage;
    let declared = LoaderPermissions::from_runtime(&assembled(&gds, ComputePlatform::Cuda));
    assert_eq!(declared.platform(), ComputePlatform::Cuda);
    assert_eq!(
        declared.unavailable(gds_method, &world.registry),
        Some(MethodUnavailable::PlatformNotShown {
            refusal: PlatformRefusal::NoPolicy
        })
    );
    let judged =
        LoaderPermissions::from_runtime(&backend_runtime(&gds, ComputePlatform::Cuda).unwrap());
    assert_eq!(
        judged.unavailable(gds_method, &world.registry),
        Some(platform_missing())
    );
    show_platform(
        &world,
        &gds.0,
        ObservedPlatform::Metal,
        Duration::from_secs(3_600),
    );
    assert_eq!(
        judged.unavailable(gds_method, &world.registry),
        Some(MethodUnavailable::PlatformNotShown {
            refusal: PlatformRefusal::Contradicted {
                declared: ComputePlatform::Cuda,
                observed: ComputePlatform::Metal,
            }
        })
    );
    show_platform(
        &world,
        &gds.0,
        ObservedPlatform::Cuda,
        Duration::from_nanos(150),
    );
    assert_eq!(judged.unavailable(gds_method, &world.registry), None);

    let artifact = Artifact::new("weights", &[16; 4], false);
    publish(&world, &artifact, vec![local("nvme")]);
    let mut executor = world.executor(with_device_staging(config(), 1, 32));
    let job = op("load");
    executor
        .submit(TransferRequest {
            loader: judged,
            ..request("load", &artifact, destination("placement"))
        })
        .unwrap();
    executor.pump().unwrap();
    world.advance(132);
    executor.pump().unwrap();
    let failure = failure_of(&executor, &job);
    assert_eq!(failure.extent, 2);
    assert!(matches!(
        failure.failure,
        ExtentFailure::Permanent { ref attempts } if matches!(
            &attempts.last().unwrap().failure,
            AttemptFailure::RequiredMethodUnavailable {
                method: ReadMethod::GpuDirectStorage,
                reason: MethodUnavailable::PlatformNotShown {
                    refusal: PlatformRefusal::Evidence {
                        cause: EvidenceRefusal::Stale { .. }
                    }
                },
            }
        )
    ));
    assert!(reads(&world).iter().all(|read| read.2 == gds_method));
}

/// GPU-T21: the path a read actually took is the one recorded. A GPUDirect Storage read
/// that cuFile served in its compatibility mode is labelled so, never as a direct
/// transfer, and a path that is no fallback of the one asked for breaks the backend
/// contract.
#[test]
fn the_measured_path_is_the_one_the_backend_reports() {
    let world = World::new();
    {
        let mut state = world.backend.state();
        state.methods.insert(ReadMethod::GpuDirectStorage);
        state.serve_as.insert(
            ReadMethod::GpuDirectStorage,
            TransferPath::DirectStorageCompatibility,
        );
    }
    let artifact = Artifact::new("weights", &[16, 16], false);
    publish(&world, &artifact, vec![local("nvme")]);
    let loader = on_cuda(
        &world,
        &[(Optimization::GpuDirectStorage, Necessity::Optional)],
        true,
        Duration::from_secs(60),
    );
    let mut executor = world.executor(with_device_staging(config(), 2, 64));
    let job = op("load");
    executor
        .submit(TransferRequest {
            loader,
            ..request("load", &artifact, destination("placement"))
        })
        .unwrap();
    drive(&mut executor, &world);
    assert_eq!(executor.status(&job), Some(&JobStatus::Completed));
    assert!(reads(&world)
        .iter()
        .all(|read| read.2 == ReadMethod::GpuDirectStorage));
    let paths: Vec<TransferPath> = stages(&world, &job)
        .iter()
        .filter_map(|stage| stage.path)
        .collect();
    assert!(!paths.is_empty());
    assert!(paths
        .iter()
        .all(|path| *path == TransferPath::DirectStorageCompatibility));
    assert!(!TransferPath::DirectStorageCompatibility.bypasses_host_ring());
    assert!(TransferPath::DirectStorageCompatibility.serves(TransferPath::DirectStorage));
    assert!(TransferPath::GpuPeerThroughHost { from: gpu1() }
        .serves(TransferPath::GpuPeer { from: gpu1() }));
    assert!(!TransferPath::DirectStorage.serves(TransferPath::HostRing));

    let world = World::new();
    world
        .backend
        .state()
        .serve_as
        .insert(ReadMethod::PositionedRead, TransferPath::DirectStorage);
    publish(&world, &artifact, vec![local("nvme")]);
    let mut executor = world.executor(config());
    executor
        .submit(request("load", &artifact, destination("placement")))
        .unwrap();
    executor.pump().unwrap();
    world.advance(200);
    assert!(matches!(
        executor.pump().unwrap_err(),
        Unavailable::Faulted {
            fault: ExecutorFault::PathNotRequested {
                requested: TransferPath::HostRing,
                reported: TransferPath::DirectStorage,
                ..
            }
        }
    ));
}

/// GPU-T20 and GPU-W04: direct I/O is a gated read method with a typed fallback. Where
/// the backend implements it and a read is aligned to the block it is used; otherwise,
/// and from then on for a file whose filesystem refused it, the read is buffered and each
/// job hears why.
#[test]
fn direct_io_is_used_where_it_can_be_and_buffered_reads_say_why() {
    let artifact = Artifact::new("weights", &[16, 16], false);
    let block = |bytes: u64| DirectIo {
        block_bytes: NonZeroU64::new(bytes).unwrap(),
    };
    let buffered = |world: &World| -> Vec<DirectIoUnavailable> {
        kinds(world, &op("load"))
            .into_iter()
            .filter_map(|kind| match kind {
                TransferEventKind::BufferedRead { reason } => Some(reason),
                _ => None,
            })
            .collect()
    };
    let load = |world: &World, slot_bytes: u64, direct: DirectIo| {
        let mut sized = config();
        sized.host_staging.slot_bytes = slot_bytes;
        let mut executor = world.executor(sized).with_direct_io(direct);
        executor
            .submit(request("load", &artifact, destination("placement")))
            .unwrap();
        drive(&mut executor, world);
        assert_eq!(executor.status(&op("load")), Some(&JobStatus::Completed));
        assert_eq!(
            world
                .backend
                .destination(&allocation(gpu0(), "placement"), 0, 32),
            artifact.decoded
        );
    };
    assert_eq!(ReadMethod::DirectRead.gate(), None);
    assert!(!ReadMethod::DirectRead.is_ordinary_local());

    // Implemented and aligned: direct reads, and no fallback.
    let world = World::new();
    world.backend.state().methods.insert(ReadMethod::DirectRead);
    publish(&world, &artifact, vec![local("nvme")]);
    load(&world, 64, block(16));
    assert!(reads(&world)
        .iter()
        .all(|read| read.2 == ReadMethod::DirectRead));
    assert!(buffered(&world).is_empty());

    // Not implemented: buffered, and the job hears why.
    let world = World::new();
    publish(&world, &artifact, vec![local("nvme")]);
    load(&world, 64, block(16));
    assert!(reads(&world)
        .iter()
        .all(|read| read.2 == ReadMethod::PositionedRead));
    assert_eq!(buffered(&world), [DirectIoUnavailable::NotImplemented]);

    // Not aligned to the block: buffered.
    let world = World::new();
    world.backend.state().methods.insert(ReadMethod::DirectRead);
    publish(&world, &artifact, vec![local("nvme")]);
    load(&world, 64, block(64));
    assert!(reads(&world)
        .iter()
        .all(|read| read.2 == ReadMethod::PositionedRead));
    assert_eq!(
        buffered(&world),
        [DirectIoUnavailable::Unaligned {
            offset_bytes: 0,
            length_bytes: 32,
            block_bytes: 64,
        }]
    );

    // The filesystem refuses direct reads: the read is made buffered at once, and every
    // later read of that file is buffered without asking again.
    let world = World::new();
    {
        let mut state = world.backend.state();
        state.methods.insert(ReadMethod::DirectRead);
        state.refuse_direct.insert(source("nvme"));
    }
    publish(&world, &artifact, vec![local("nvme")]);
    load(&world, 16, block(16));
    assert!(reads(&world)
        .iter()
        .all(|read| read.2 == ReadMethod::PositionedRead));
    let reasons = buffered(&world);
    assert_eq!(reasons.len(), 2);
    assert!(reasons.iter().all(|reason| matches!(
        reason,
        DirectIoUnavailable::Refused { error } if error.kind == BackendErrorKind::Unsupported
    )));
}

// GPU-W09: the model-extent payload adapter. Network sources move their bytes only
// through CORE-05 sessions bound to the executor, the job and the source.

/// CORE-05 around a world: the parents' authority, a byte budget, progress and the host's
/// transfer key, on the world's clock.
struct Net {
    authority: Arc<tf::FakeAuthority>,
    progress: Arc<tf::FakeProgress>,
    key: TransferKey,
    ports: TransferPorts,
}

impl Net {
    fn new(world: &World, budget: Arc<dyn ByteBudgetPort>) -> Self {
        let authority = Arc::new(tf::FakeAuthority::default());
        let progress = Arc::new(tf::FakeProgress::default());
        let ports = TransferPorts {
            clock: world.clock.clone(),
            clock_session: tf::SESSION,
            authority: authority.clone(),
            budget,
            extents: Arc::new(tf::FakeExtents::default()),
            progress: progress.clone(),
        };
        Self {
            authority,
            progress,
            key: tf::test_key(),
            ports,
        }
    }

    /// An executor of the world reading network sources through CORE-05.
    fn executor(&self, world: &World, config: ExecutorConfig) -> Exec {
        world
            .executor(config)
            .with_transfers(self.key.clone(), self.ports.clone())
    }

    /// The parent execution of job `name` holds epoch 4 for a day.
    fn authorize(&self, name: &str) {
        self.authority
            .grant(&parent_of(name), tf::EPOCH, tf::at(24 * tf::HOUR));
    }

    /// The ranges of every chunk delivered, in order.
    fn delivered(&self) -> Vec<ByteRange> {
        self.progress
            .events()
            .into_iter()
            .filter_map(|event| match event.phase {
                ProgressPhase::ChunkDelivered { range, .. } => Some(range),
                _ => None,
            })
            .collect()
    }
}

/// The execution [`request`] makes job `name` run under.
fn parent_of(name: &str) -> ExecutionId {
    ExecutionId::new(format!("exe-{name}")).unwrap()
}

/// The authorized peer `donor`.
fn donor() -> SourceCandidate {
    candidate("donor", SourceKind::AuthorizedPeer, 1e9)
}

/// A peer grant bound to the executor `executor` for job `name`'s reads of `artifact`
/// from `donor`: the whole stored object, `budget_bytes`, 1 MiB in flight, 10 s per chunk,
/// for an hour.
fn peer_fields(
    executor: &str,
    name: &str,
    artifact: &Artifact,
    budget_bytes: u64,
) -> EnvelopeFields {
    let parent = parent_of(name);
    EnvelopeFields {
        operation: session_operation(&op(executor), &op(name), &source("donor")).unwrap(),
        tenant: TenantId::new("tenant-a").unwrap(),
        parent: parent.clone(),
        epoch: tf::EPOCH,
        direction: Direction::Peer,
        source: tf::peer("donor"),
        recipient: Endpoint::Execution { execution: parent },
        credential: None,
        scope: TransferScope::single(
            artifact.representation,
            ObjectGrant::whole(artifact.stored.len() as u64).unwrap(),
        ),
        budget_bytes,
        stop_bounds: StopBounds {
            max_in_flight_bytes: 1 << 20,
            max_chunk_duration: 10 * tf::SECOND,
        },
        clock: tf::SESSION,
        expires_at: tf::at(tf::HOUR),
    }
}

/// `fields` sealed with `key`, for `donor`, with the connection that matches them.
fn grant_of(key: &TransferKey, fields: EnvelopeFields) -> SourceGrant {
    let connection = Connection {
        source: fields.source.clone(),
        recipient: fields.recipient.clone(),
        credential: fields.credential,
    };
    SourceGrant {
        source: source("donor"),
        sealed: key.seal(TransferEnvelope::new(fields).unwrap()),
        connection,
    }
}

fn with_grant(grant: SourceGrant) -> SubmitOptions {
    SubmitOptions {
        transfers: vec![grant],
        ..SubmitOptions::default()
    }
}

fn slots_of(slot_bytes: u64) -> ExecutorConfig {
    let mut sized = config();
    sized.host_staging.slot_bytes = slot_bytes;
    sized
}

#[test]
fn a_peer_source_is_served_through_a_core05_session() {
    let world = World::new();
    let artifact = Artifact::new("weights", &[16; 4], false);
    publish(&world, &artifact, vec![donor()]);
    let budget = Arc::new(tf::FakeByteLedger::new(1 << 30));
    let net = Net::new(&world, budget.clone());
    net.authorize("load");
    let mut executor = net.executor(&world, slots_of(32));
    let job = op("load");
    executor
        .submit_with(
            request("load", &artifact, destination("placement")),
            with_grant(grant_of(
                &net.key,
                peer_fields("executor", "load", &artifact, 1 << 20),
            )),
        )
        .unwrap();
    {
        let session = executor.transfer(&job, &source("donor")).unwrap();
        assert_eq!(*session.status(), TransferStatus::Active);
        assert_eq!(
            budget.held_bytes(),
            1 << 20,
            "the whole budget is reserved before any byte moves"
        );
    }
    drive(&mut executor, &world);
    assert_eq!(executor.status(&job), Some(&JobStatus::Completed));
    assert_eq!(
        world
            .backend
            .destination(&allocation(gpu0(), "placement"), 0, 64),
        artifact.decoded
    );
    let started: Vec<(String, ReadMethod, u64, u64)> = reads(&world)
        .into_iter()
        .map(|read| (read.0, read.2, read.4, read.5))
        .collect();
    assert_eq!(
        started,
        [
            ("donor".to_owned(), ReadMethod::RangeRequest, 0, 32),
            ("donor".to_owned(), ReadMethod::RangeRequest, 32, 32)
        ]
    );
    assert_eq!(
        net.delivered(),
        [
            ByteRange::new(0, 32).unwrap(),
            ByteRange::new(32, 64).unwrap()
        ]
    );
    let session = executor.transfer(&job, &source("donor")).unwrap();
    assert_eq!(*session.status(), TransferStatus::Completed);
    assert_eq!(
        session.used_bytes(),
        64,
        "each byte moved and was charged once"
    );
    assert_eq!(
        budget.held_bytes(),
        0,
        "the reservation went back at the end"
    );
    assert_eq!(budget.releases().len(), 1);
}

#[test]
fn an_interrupted_transfer_resumes_and_reuses_the_extents_already_verified() {
    let world = World::new();
    let artifact = Artifact::new("weights", &[16; 4], false);
    publish(&world, &artifact, vec![donor()]);
    world.backend.state().fail_tickets.insert(2);
    let budget = Arc::new(tf::FakeByteLedger::new(1 << 30));
    let net = Net::new(&world, budget.clone());
    net.authorize("load");
    let mut executor = net.executor(&world, slots_of(32));
    let job = op("load");
    executor
        .submit_with(
            request("load", &artifact, destination("placement")),
            with_grant(grant_of(
                &net.key,
                peer_fields("executor", "load", &artifact, 1 << 20),
            )),
        )
        .unwrap();
    drive(&mut executor, &world);
    assert_eq!(executor.status(&job), Some(&JobStatus::Completed));
    assert_eq!(
        world
            .backend
            .destination(&allocation(gpu0(), "placement"), 0, 64),
        artifact.decoded
    );
    let started: Vec<(u64, u64)> = reads(&world)
        .into_iter()
        .map(|read| (read.4, read.5))
        .collect();
    assert_eq!(started, [(0, 32), (32, 32), (32, 32)]);
    let session = executor.transfer(&job, &source("donor")).unwrap();
    assert_eq!(session.attempt(), 2);
    assert_eq!(*session.status(), TransferStatus::Completed);
    assert_eq!(
        session.used_bytes(),
        96,
        "every attempt counts against the budget"
    );
    let resumed = net
        .progress
        .events()
        .into_iter()
        .find(|event| event.phase == ProgressPhase::Resumed)
        .unwrap();
    assert_eq!(
        resumed.verified_bytes, 32,
        "the resumed attempt reused the extents already verified"
    );
    let flight = executor.flight_of(&job, 2).unwrap();
    assert!(matches!(
        executor.attempts(flight).unwrap(),
        [Attempt {
            failure: AttemptFailure::TransportInterrupted { .. },
            ..
        }]
    ));
    assert!(
        executor.blacklist(&job).unwrap().is_empty(),
        "an interrupted transport does not blame the source"
    );
    assert_eq!(
        count(&world.journal(), |entry| matches!(
            entry,
            Entry::Coalesce { .. }
        )),
        1,
        "the batch was read again in its live load"
    );
}

#[test]
fn a_replayed_foreign_or_cross_process_envelope_is_refused() {
    let world = World::new();
    let artifact = Artifact::new("weights", &[16; 4], false);
    publish(&world, &artifact, vec![donor()]);
    let budget = Arc::new(tf::FakeByteLedger::new(1 << 30));
    let net = Net::new(&world, budget.clone());
    net.authorize("load");
    let mut executor = net.executor(&world, slots_of(32));
    let submit = |executor: &mut Exec, grant: SourceGrant| {
        executor.submit_with(
            request("load", &artifact, destination("placement")),
            with_grant(grant),
        )
    };
    let refused = |error| SubmitError::Transfer {
        source: source("donor"),
        error,
    };
    // Issued for another executor, or another job: not bound to this one.
    for (executor_name, job) in [("executor-b", "load"), ("executor", "other")] {
        let mut fields = peer_fields(executor_name, job, &artifact, 1 << 20);
        fields.parent = parent_of("load");
        fields.recipient = Endpoint::Execution {
            execution: parent_of("load"),
        };
        assert_eq!(
            submit(&mut executor, grant_of(&net.key, fields)).unwrap_err(),
            refused(TransferBindingError::NotBound {
                field: BindingField::Operation
            })
        );
    }
    // Stamped on another clock session, such as another process's or one before a restart.
    let mut elsewhere = peer_fields("executor", "load", &artifact, 1 << 20);
    elsewhere.clock = tf::OTHER_SESSION;
    assert_eq!(
        submit(&mut executor, grant_of(&net.key, elsewhere)).unwrap_err(),
        refused(TransferBindingError::Refused {
            refusal: TransferRefusal::Stopped {
                reason: StopReason::EnvelopeOnOtherClock
            }
        })
    );
    // Sealed by another key.
    let forger = TransferKey::from_bytes(&[9u8; 32]).unwrap();
    assert_eq!(
        submit(
            &mut executor,
            grant_of(&forger, peer_fields("executor", "load", &artifact, 1 << 20))
        )
        .unwrap_err(),
        refused(TransferBindingError::Refused {
            refusal: TransferRefusal::Tampered
        })
    );
    assert!(
        budget.requests().is_empty(),
        "no refused envelope reserved a byte"
    );
    assert!(world
        .ledger
        .held()
        .values()
        .all(|(_, _, purpose)| !matches!(purpose, ReservationPurpose::Destination { .. })));

    // The bound envelope opens once.
    let grant = grant_of(
        &net.key,
        peer_fields("executor", "load", &artifact, 1 << 20),
    );
    submit(&mut executor, grant.clone()).unwrap();
    drive(&mut executor, &world);
    assert_eq!(executor.status(&op("load")), Some(&JobStatus::Completed));
    executor.forget(&op("load")).unwrap();
    // Replayed, it never opens again while unexpired, even for the job it is bound to.
    let operation = session_operation(&op("executor"), &op("load"), &source("donor")).unwrap();
    assert_eq!(
        submit(&mut executor, grant.clone()).unwrap_err(),
        refused(TransferBindingError::Refused {
            refusal: TransferRefusal::AlreadyOpened { operation }
        })
    );
    // Another executor, here with a key made again from the same bytes and so without the
    // first key's replay registry, is not the executor the envelope is bound to.
    let mut other_config = slots_of(32);
    other_config.operation = op("executor-b");
    let mut other = world.executor(other_config).with_transfers(
        TransferKey::from_bytes(&[7u8; 32]).unwrap(),
        net.ports.clone(),
    );
    assert_eq!(
        submit(&mut other, grant).unwrap_err(),
        refused(TransferBindingError::NotBound {
            field: BindingField::Operation
        })
    );
}

#[test]
fn a_grant_must_fit_the_job_and_a_network_source_needs_one() {
    let world = World::new();
    let artifact = Artifact::new("weights", &[16; 4], false);
    publish(&world, &artifact, vec![donor(), local("nvme")]);
    let budget = Arc::new(tf::FakeByteLedger::new(1 << 30));
    let net = Net::new(&world, budget.clone());
    net.authorize("load");
    let grant = || {
        grant_of(
            &net.key,
            peer_fields("executor", "load", &artifact, 1 << 20),
        )
    };
    let load = || request("load", &artifact, destination("placement"));
    let refused = |error| SubmitError::Transfer {
        source: source("donor"),
        error,
    };

    // An executor that reads nothing through transfers takes no grant.
    let mut plain = world.executor(slots_of(32));
    assert_eq!(
        plain.submit_with(load(), with_grant(grant())).unwrap_err(),
        refused(TransferBindingError::NoTransfers)
    );

    let mut executor = net.executor(&world, slots_of(32));
    let mut local_grant = grant();
    local_grant.source = source("nvme");
    assert_eq!(
        executor
            .submit_with(load(), with_grant(local_grant))
            .unwrap_err(),
        SubmitError::Transfer {
            source: source("nvme"),
            error: TransferBindingError::NotNetworkSource
        }
    );
    assert_eq!(
        executor
            .submit_with(
                load(),
                SubmitOptions {
                    transfers: vec![grant(), grant()],
                    ..SubmitOptions::default()
                }
            )
            .unwrap_err(),
        refused(TransferBindingError::DuplicateGrant)
    );
    let mut into_catalog = peer_fields("executor", "load", &artifact, 1 << 20);
    into_catalog.recipient = Endpoint::HostCatalog;
    let mut partial = peer_fields("executor", "load", &artifact, 1 << 20);
    partial.scope = TransferScope::single(
        artifact.representation,
        ObjectGrant::ranges(64, RangeSet::single(ByteRange::new(0, 48).unwrap())).unwrap(),
    );
    let mut other_object = peer_fields("executor", "load", &artifact, 1 << 20);
    other_object.scope =
        TransferScope::single(ContentKey::of(b"other"), ObjectGrant::whole(64).unwrap());
    let mut other_tenant = peer_fields("executor", "load", &artifact, 1 << 20);
    other_tenant.tenant = TenantId::new("tenant-b").unwrap();
    for (fields, field) in [
        (into_catalog, BindingField::Recipient),
        (partial, BindingField::Scope),
        (other_object, BindingField::Object),
        (other_tenant, BindingField::Tenant),
    ] {
        let mut sealed = grant_of(&net.key, fields);
        sealed.connection.recipient = Endpoint::Execution {
            execution: parent_of("load"),
        };
        assert_eq!(
            executor
                .submit_with(load(), with_grant(sealed))
                .unwrap_err(),
            refused(TransferBindingError::NotBound { field })
        );
    }

    // Without a grant the peer is no source of the job: the local file serves it.
    executor.submit(load()).unwrap();
    drive(&mut executor, &world);
    assert_eq!(executor.status(&op("load")), Some(&JobStatus::Completed));
    assert!(reads(&world).iter().all(|read| read.0 == "nvme"));
    assert!(budget.requests().is_empty());
}

#[test]
fn a_revocation_of_the_transfers_authority_cancels_the_jobs_reads() {
    let world = World::new();
    let artifact = Artifact::new("weights", &[16; 4], false);
    publish(&world, &artifact, vec![donor()]);
    world
        .backend
        .state()
        .timing
        .insert(source("donor"), (1_000, 1));
    let budget = Arc::new(tf::FakeByteLedger::new(1 << 30));
    let net = Net::new(&world, budget.clone());
    net.authorize("load");
    let mut executor = net.executor(&world, slots_of(32));
    let job = op("load");
    executor
        .submit_with(
            request("load", &artifact, destination("placement")),
            with_grant(grant_of(
                &net.key,
                peer_fields("executor", "load", &artifact, 1 << 20),
            )),
        )
        .unwrap();
    assert_eq!(executor.pump().unwrap().reads_started, 2);
    let current = net.authority.revoke(&parent_of("load")).unwrap();
    assert!(current > tf::EPOCH);
    executor.pump().unwrap();
    assert_eq!(
        executor.status(&job),
        Some(&JobStatus::Cancelled {
            reason: CancelReason::Revoked { revoked: tf::EPOCH }
        })
    );
    assert!(matches!(
        executor.transfer(&job, &source("donor")).unwrap().status(),
        TransferStatus::Stopped(record) if record.reason.is_revocation()
    ));
    drive(&mut executor, &world);
    // The reads in flight landed and nothing of them was used; nothing more was read.
    assert_eq!(reads(&world).len(), 2);
    assert_eq!(
        count(&world.journal(), |entry| matches!(
            entry,
            Entry::EnqueueCopy { .. }
        )),
        0
    );
    assert!(!kinds(&world, &job)
        .iter()
        .any(|kind| matches!(kind, TransferEventKind::DependencyUsable { .. })));
    assert_eq!(budget.held_bytes(), 0);
}

/// A host ledger for transfers: 10,000 bytes of storage quota, which peer transfers are
/// charged to, and four network slots, tenant-a holding at most all of them.
fn transfer_ledger(world: &World) -> Arc<Mutex<Ledger<Arc<ManualClock>>>> {
    let mut ledger = Ledger::new(
        world.clock.clone(),
        HostSubject {
            machine: digest("yougori/test/machine/v1", &[b"workstation"]),
        },
        LedgerConfig {
            queue: QueueLimits {
                max_entries: 4,
                max_entries_per_tenant: 2,
                max_wait: Duration::from_secs(60),
            },
            grant_ttl: Duration::from_secs(300),
            unmanaged_usage_max_age: Duration::from_secs(3_600),
        },
    );
    let tenant = TenantId::new("tenant-a").unwrap();
    for (resource, total) in [(STORAGE, 10_000), (NETWORK_SLOT_RESOURCE, 4)] {
        ledger
            .declare_capacity(
                resource,
                CapacityDeclaration {
                    total,
                    supervisor_reserve: 0,
                    unmanaged_in_use: 0,
                    source: SourceClass::HostProbe,
                },
            )
            .unwrap();
        ledger
            .set_tenant_budget(tenant.clone(), resource, total)
            .unwrap();
    }
    Arc::new(Mutex::new(ledger))
}

const STORAGE: host::ResourceKey = host::ResourceKey::Host(host::HostResource::StorageQuota);

#[test]
fn a_budget_exhausted_mid_transfer_ends_the_source_for_the_job() {
    let world = World::new();
    let artifact = Artifact::new("weights", &[16; 4], false);
    publish(&world, &artifact, vec![donor()]);
    let ledger = transfer_ledger(&world);
    let budget = Arc::new(
        LedgerByteBudget::new(
            ledger.clone(),
            world.clock.clone(),
            BTreeMap::from([(Direction::Peer, STORAGE)]),
            host::Priority::Foreground,
        )
        .unwrap()
        .holding_network_slot(),
    );
    let net = Net::new(&world, budget.clone());
    net.authorize("load");
    let mut executor = net.executor(&world, slots_of(32));
    let job = op("load");
    executor
        .submit_with(
            request("load", &artifact, destination("placement")),
            with_grant(grant_of(
                &net.key,
                peer_fields("executor", "load", &artifact, 32),
            )),
        )
        .unwrap();
    // CORE-05's ledger budget holds the grant's bytes and one network slot.
    assert_eq!(ledger.lock().unwrap().reserved(STORAGE), 32);
    assert_eq!(ledger.lock().unwrap().reserved(NETWORK_SLOT_RESOURCE), 1);
    drive(&mut executor, &world);
    let failure = failure_of(&executor, &job);
    assert!(matches!(
        failure.failure,
        ExtentFailure::NoEligibleSource { .. }
    ));
    assert!(
        kinds(&world, &job).contains(&TransferEventKind::TransferRefused {
            source: source("donor"),
            refusal: TransferRefusal::BudgetExhausted {
                budget_bytes: 32,
                used_bytes: 32,
                requested_bytes: 32,
            },
        })
    );
    let session = executor.transfer(&job, &source("donor")).unwrap();
    assert_eq!(session.used_bytes(), 32, "never past the budget");
    assert!(matches!(
        session.status(),
        TransferStatus::Stopped(record) if record.reason == StopReason::Cancelled
    ));
    // The slot and bytes count until the chunk that may still move has settled.
    world.advance(11_000_000_000);
    budget.settle_due();
    assert_eq!(ledger.lock().unwrap().reserved(NETWORK_SLOT_RESOURCE), 0);
    assert_eq!(ledger.lock().unwrap().reserved(STORAGE), 0);
}

#[test]
fn a_corrupted_extent_from_a_session_is_refused_before_use() {
    let world = World::new();
    let artifact = Artifact::new("weights", &[16; 4], false);
    publish(&world, &artifact, vec![donor()]);
    world
        .backend
        .state()
        .corrupt
        .insert((source("donor"), artifact.key, 16));
    let budget = Arc::new(tf::FakeByteLedger::new(1 << 30));
    let net = Net::new(&world, budget.clone());
    net.authorize("load");
    let mut executor = net.executor(&world, slots_of(32));
    let job = op("load");
    executor
        .submit_with(
            request("load", &artifact, destination("placement")),
            with_grant(grant_of(
                &net.key,
                peer_fields("executor", "load", &artifact, 1 << 20),
            )),
        )
        .unwrap();
    drive(&mut executor, &world);
    let failure = failure_of(&executor, &job);
    assert_eq!(failure.extent, 1);
    assert!(matches!(
        failure.failure,
        ExtentFailure::NoEligibleSource { ref attempts } if matches!(
            attempts.as_slice(),
            [Attempt { source: Some(from), failure: AttemptFailure::StoredMismatch { .. }, .. }]
                if *from == source("donor")
        )
    ));
    // Nothing of the mismatching extent reached its destination, and nothing was
    // published.
    assert!(!world.journal().iter().any(|entry| matches!(
        entry,
        Entry::EnqueueCopy { to, .. } if to.offset_bytes == 16
    )));
    assert!(!kinds(&world, &job)
        .iter()
        .any(|kind| matches!(kind, TransferEventKind::DependencyUsable { .. })));
    assert_eq!(
        executor.blacklist(&job).unwrap(),
        &BTreeSet::from([source("donor")])
    );
    assert!(matches!(
        executor.transfer(&job, &source("donor")).unwrap().status(),
        TransferStatus::Stopped(record) if record.reason == StopReason::Cancelled
    ));
    assert_eq!(budget.held_bytes(), 0);
}

#[test]
fn a_session_keeps_p03s_batching_verification_and_completion_events() {
    let world = World::new();
    let artifact = Artifact::new("weights", &[16; 6], true);
    publish(&world, &artifact, vec![donor()]);
    let budget = Arc::new(tf::FakeByteLedger::new(1 << 30));
    let net = Net::new(&world, budget.clone());
    net.authorize("load");
    let mut executor = net.executor(&world, config());
    let job = op("load");
    let mut load = request("load", &artifact, destination("placement"));
    load.dependencies = (0..6)
        .map(|index| dependency(index, &[index], &[]))
        .collect();
    executor
        .submit_with(
            load,
            with_grant(grant_of(
                &net.key,
                peer_fields("executor", "load", &artifact, 1 << 20),
            )),
        )
        .unwrap();
    drive(&mut executor, &world);
    assert_eq!(executor.status(&job), Some(&JobStatus::Completed));
    assert_eq!(
        world
            .backend
            .destination(&allocation(gpu0(), "placement"), 0, 96),
        artifact.decoded
    );
    // P03's batches are the chunks: one per batch, each exactly its extents' stored bytes.
    assert_eq!(
        net.delivered(),
        [
            ByteRange::new(0, 60).unwrap(),
            ByteRange::new(60, 100).unwrap(),
            ByteRange::new(100, 120).unwrap()
        ]
    );
    // Each extent was verified, decoded, validated and copied with its own completion
    // event, and each dependency was published once.
    let journal = world.journal();
    assert_eq!(
        count(&journal, |entry| matches!(entry, Entry::Decode { .. })),
        6
    );
    assert_eq!(
        count(&journal, |entry| matches!(entry, Entry::RecordEvent { .. })),
        6
    );
    let published = kinds(&world, &job)
        .into_iter()
        .filter(|kind| matches!(kind, TransferEventKind::DependencyUsable { .. }))
        .count();
    assert_eq!(published, 6);
    let measured = stages(&world, &job);
    for stage in [
        Stage::Read,
        Stage::Verify,
        Stage::Decode,
        Stage::Validate,
        Stage::Copy,
    ] {
        assert!(measured.iter().any(|measurement| measurement.stage == stage
            && measurement.path == Some(TransferPath::HostRing)));
    }
    assert!(measured
        .iter()
        .filter(|measurement| measurement.stage == Stage::Read)
        .all(|measurement| measurement.method == Some(ReadMethod::RangeRequest)));
    let session = executor.transfer(&job, &source("donor")).unwrap();
    assert_eq!(*session.status(), TransferStatus::Completed);
    assert_eq!(session.used_bytes(), 120);
}

#[test]
fn the_session_operation_names_the_executor_the_job_and_the_source() {
    let operation = session_operation(&op("executor"), &op("load"), &source("donor")).unwrap();
    assert!(operation.as_str().starts_with("op-"));
    assert_eq!(
        session_operation(&op("executor"), &op("load"), &source("donor")).unwrap(),
        operation
    );
    for other in [
        session_operation(&op("executor-b"), &op("load"), &source("donor")),
        session_operation(&op("executor"), &op("other"), &source("donor")),
        session_operation(&op("executor"), &op("load"), &source("mirror")),
    ] {
        assert_ne!(other.unwrap(), operation);
    }
    assert!(SourceKind::AuthorizedPeer.is_network());
    assert!(SourceKind::Remote.is_network());
    assert!(!SourceKind::LocalFile.is_network());
    assert!(!SourceKind::GpuPeer { device: gpu1() }.is_network());
}

#[test]
fn a_remote_store_is_served_through_a_download_session() {
    let world = World::new();
    let artifact = Artifact::new("weights", &[16; 4], false);
    publish(
        &world,
        &artifact,
        vec![candidate("mirror", SourceKind::Remote, 1e9)],
    );
    let budget = Arc::new(tf::FakeByteLedger::new(1 << 30));
    let net = Net::new(&world, budget.clone());
    net.authorize("load");
    let mut executor = net.executor(&world, slots_of(32));
    let job = op("load");
    let mut fields = peer_fields("executor", "load", &artifact, 1 << 20);
    fields.operation = session_operation(&op("executor"), &job, &source("mirror")).unwrap();
    fields.direction = Direction::Download;
    fields.source = tf::route("mirror");
    fields.credential = Some(tf::credential("mirror-token"));
    let mirror = |fields: EnvelopeFields| SourceGrant {
        source: source("mirror"),
        ..grant_of(&net.key, fields)
    };
    // A peer transfer never carries a remote store's bytes.
    let mut as_peer = fields.clone();
    as_peer.direction = Direction::Peer;
    as_peer.source = tf::peer("mirror");
    as_peer.credential = None;
    assert_eq!(
        executor
            .submit_with(
                request("load", &artifact, destination("placement")),
                with_grant(mirror(as_peer))
            )
            .unwrap_err(),
        SubmitError::Transfer {
            source: source("mirror"),
            error: TransferBindingError::NotBound {
                field: BindingField::Direction
            }
        }
    );
    executor
        .submit_with(
            request("load", &artifact, destination("placement")),
            with_grant(mirror(fields)),
        )
        .unwrap();
    drive(&mut executor, &world);
    assert_eq!(executor.status(&job), Some(&JobStatus::Completed));
    assert_eq!(
        world
            .backend
            .destination(&allocation(gpu0(), "placement"), 0, 64),
        artifact.decoded
    );
    assert!(reads(&world)
        .iter()
        .all(|read| read.0 == "mirror" && read.2 == ReadMethod::RangeRequest));
    assert_eq!(
        net.delivered(),
        [
            ByteRange::new(0, 32).unwrap(),
            ByteRange::new(32, 64).unwrap()
        ]
    );
    let session = executor.transfer(&job, &source("mirror")).unwrap();
    assert_eq!(*session.status(), TransferStatus::Completed);
    assert_eq!(session.envelope().fields().direction, Direction::Download);
}

#[test]
fn jobs_sharing_a_read_each_take_its_chunk_through_their_own_sessions() {
    let world = World::new();
    let artifact = Artifact::new("weights", &[16; 4], false);
    publish(&world, &artifact, vec![donor()]);
    let budget = Arc::new(tf::FakeByteLedger::new(1 << 30));
    let net = Net::new(&world, budget.clone());
    let mut executor = net.executor(&world, slots_of(32));
    for name in ["first", "second"] {
        net.authorize(name);
        executor
            .submit_with(
                request(name, &artifact, destination("placement")),
                with_grant(grant_of(
                    &net.key,
                    peer_fields("executor", name, &artifact, 1 << 20),
                )),
            )
            .unwrap();
    }
    drive(&mut executor, &world);
    // Each batch was read once, and each job's session took it.
    assert_eq!(reads(&world).len(), 2);
    assert_eq!(net.delivered().len(), 4);
    for name in ["first", "second"] {
        assert_eq!(executor.status(&op(name)), Some(&JobStatus::Completed));
        let session = executor.transfer(&op(name), &source("donor")).unwrap();
        assert_eq!(*session.status(), TransferStatus::Completed);
        assert_eq!(session.used_bytes(), 64);
    }
    assert_eq!(
        world
            .backend
            .destination(&allocation(gpu0(), "placement"), 0, 64),
        artifact.decoded
    );
    assert_eq!(budget.held_bytes(), 0);
    assert_eq!(budget.releases().len(), 2);
}

#[test]
fn one_jobs_exhausted_budget_never_stops_anothers_shared_reads() {
    let world = World::new();
    let artifact = Artifact::new("weights", &[16; 4], false);
    publish(&world, &artifact, vec![donor()]);
    let budget = Arc::new(tf::FakeByteLedger::new(1 << 30));
    let net = Net::new(&world, budget.clone());
    let mut executor = net.executor(&world, slots_of(32));
    for (name, budget_bytes) in [("first", 1 << 20), ("second", 32)] {
        net.authorize(name);
        executor
            .submit_with(
                request(name, &artifact, destination("placement")),
                with_grant(grant_of(
                    &net.key,
                    peer_fields("executor", name, &artifact, budget_bytes),
                )),
            )
            .unwrap();
    }
    drive(&mut executor, &world);
    let (first, second) = (op("first"), op("second"));
    assert_eq!(executor.status(&first), Some(&JobStatus::Completed));
    assert!(matches!(
        failure_of(&executor, &second).failure,
        ExtentFailure::NoEligibleSource { .. }
    ));
    assert!(
        kinds(&world, &second).contains(&TransferEventKind::TransferRefused {
            source: source("donor"),
            refusal: TransferRefusal::BudgetExhausted {
                budget_bytes: 32,
                used_bytes: 32,
                requested_bytes: 32,
            },
        })
    );
    assert!(!kinds(&world, &first)
        .iter()
        .any(|kind| matches!(kind, TransferEventKind::TransferRefused { .. })));
    // The refused chunk was never read: each byte was read once, the first job's last
    // extents alone after the refusal.
    let mut read: Vec<(u64, u64)> = reads(&world)
        .into_iter()
        .map(|read| (read.4, read.5))
        .collect();
    read.sort_unstable();
    assert_eq!(read, [(0, 32), (32, 16), (48, 16)]);
    assert_eq!(
        world
            .backend
            .destination(&allocation(gpu0(), "placement"), 0, 64),
        artifact.decoded
    );
    let session = executor.transfer(&first, &source("donor")).unwrap();
    assert_eq!(*session.status(), TransferStatus::Completed);
    assert_eq!(session.used_bytes(), 64);
    assert_eq!(
        executor
            .transfer(&second, &source("donor"))
            .unwrap()
            .used_bytes(),
        32
    );
    assert_eq!(budget.held_bytes(), 0);
}

/// GPU §2.5 with CORE-05: a source that served the first job a mismatching extent is
/// excluded from the load, which takes back the batch the second job shares with it while
/// that batch is read. The late read's chunk still settles in the second job's session, so
/// when the batch is read again for the second job alone, its session resumes instead of
/// waiting for a chunk that never lands.
#[test]
fn a_chunk_whose_batch_was_taken_back_never_stalls_its_session() {
    let world = World::new();
    let artifact = Artifact::new("weights", &[16; 4], false);
    publish(&world, &artifact, vec![donor()]);
    world
        .backend
        .state()
        .corrupt
        .insert((source("donor"), artifact.key, 0));
    let budget = Arc::new(tf::FakeByteLedger::new(1 << 30));
    let net = Net::new(&world, budget.clone());
    let mut executor = net.executor(&world, slots_of(32));
    let upper = ObjectGrant::ranges(64, RangeSet::single(ByteRange::new(32, 64).unwrap())).unwrap();
    for (name, extents, grant) in [
        ("first", artifact.all(), ObjectGrant::whole(64).unwrap()),
        ("second", vec![2, 3], upper),
    ] {
        net.authorize(name);
        let mut load = request(name, &artifact, destination("placement"));
        load.dependencies = vec![dependency(1, &extents, &[])];
        let mut fields = peer_fields("executor", name, &artifact, 1 << 20);
        fields.scope = TransferScope::single(artifact.representation, grant);
        executor
            .submit_with(load, with_grant(grant_of(&net.key, fields)))
            .unwrap();
    }
    drive(&mut executor, &world);
    let (first, second) = (op("first"), op("second"));
    assert!(matches!(
        failure_of(&executor, &first).failure,
        ExtentFailure::NoEligibleSource { ref attempts } if matches!(
            attempts.as_slice(),
            [Attempt { failure: AttemptFailure::StoredMismatch { .. }, .. }]
        )
    ));
    assert_eq!(executor.status(&second), Some(&JobStatus::Completed));
    // The shared batch was read twice: taken back from the excluded source, then again
    // for the second job alone.
    let started: Vec<(u64, u64)> = reads(&world)
        .into_iter()
        .map(|read| (read.4, read.5))
        .collect();
    assert_eq!(started, [(0, 32), (32, 32), (32, 32)]);
    let session = executor.transfer(&second, &source("donor")).unwrap();
    assert_eq!(*session.status(), TransferStatus::Completed);
    assert_eq!(session.attempt(), 2);
    assert_eq!(
        session.used_bytes(),
        64,
        "the late chunk moved and was charged"
    );
    assert_eq!(
        world
            .backend
            .destination(&allocation(gpu0(), "placement"), 32, 32),
        artifact.decoded[32..]
    );
}

/// INT-08: a grant never outlives its expiry. One that lapses ends the peer for the job,
/// with an event, and the job's extents go to its other source.
#[test]
fn an_expired_grant_ends_the_peer_for_the_job_and_another_source_serves_it() {
    let world = World::new();
    let artifact = Artifact::new("weights", &[16; 4], false);
    publish(
        &world,
        &artifact,
        vec![donor(), candidate("nvme", SourceKind::LocalFile, 1e3)],
    );
    let budget = Arc::new(tf::FakeByteLedger::new(1 << 30));
    let net = Net::new(&world, budget.clone());
    net.authorize("load");
    let mut executor = net.executor(&world, slots_of(32));
    let job = op("load");
    executor
        .submit_with(
            request("load", &artifact, destination("placement")),
            with_grant(grant_of(
                &net.key,
                peer_fields("executor", "load", &artifact, 1 << 20),
            )),
        )
        .unwrap();
    // The grant lapses before a byte moves.
    world.advance(2 * 3_600_000_000_000);
    drive(&mut executor, &world);
    assert_eq!(executor.status(&job), Some(&JobStatus::Completed));
    assert!(reads(&world).iter().all(|read| read.0 == "nvme"));
    assert!(kinds(&world, &job).iter().any(|kind| matches!(
        kind,
        TransferEventKind::TransferRefused {
            source: from,
            refusal: TransferRefusal::Stopped {
                reason: StopReason::Expired { .. }
            }
        } if *from == source("donor")
    )));
    let session = executor.transfer(&job, &source("donor")).unwrap();
    assert!(matches!(
        session.status(),
        TransferStatus::Stopped(record) if matches!(record.reason, StopReason::Expired { .. })
    ));
    assert_eq!(session.used_bytes(), 0);
    assert!(net.delivered().is_empty());
    assert_eq!(budget.held_bytes(), 0);
    assert_eq!(
        world
            .backend
            .destination(&allocation(gpu0(), "placement"), 0, 64),
        artifact.decoded
    );
}
