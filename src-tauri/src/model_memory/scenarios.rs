//! The GPU scenario and failure checklist GPU-T01 to GPU-T48
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md, §8.4 lines 1279–1332; task P16).
//!
//! Test-only. One test per row of the §8.4 table, named after its ID, asserting the row's
//! "Required result". Each test drives the committed modules through their public APIs:
//! the CORE-02 catalog, CORE-03 ledger, CORE-04 coordinator, CORE-06 event plane and
//! CORE-01 evidence gate, with the model-memory modules (manifest, identity, executor,
//! placement, VMM, residency, tiers, adapters, math, backends, progress, boundaries) on
//! top. Fakes stand only at the edges: the native transfer backend (`EdgeBackend`), the
//! executor's manifest and batching ports, which no committed adapter serves yet
//! (`ManifestPort`, `Coalescer`), P05's fake CUDA driver, CORE-01 fake probes, P04's
//! fake CORE-04 lease port in the placement cases (`Slot`; INT-03 and GPU-T42 drive the
//! real coordinator), P08's fake loader, a full disk injected at one catalog call, and
//! bytes held in memory. Catalogs live in temporary directories. Time is a manual clock;
//! the only randomness is a seeded SplitMix64.
//!
//! "Neither a mock test nor a successful allocation proves the complete production path"
//! (line 1332): where real hardware, drivers or hosts would have to establish more, the
//! test's doc comment says what is not covered and why. T16's INT-01 to INT-10 (`foundation/scenarios.rs`) are not
//! repeated; GPU-T29 and GPU-T42 reference INT-03 and INT-04.
//!
//! | ID | Test | Modules exercised | Not covered |
//! | --- | --- | --- | --- |
//! | GPU-T01 | `gpu_t01_first_import_reports_truthful_progress_and_no_readiness_before_validation` | catalog import protocol, events hub, progress publisher | ETA accuracy on real storage |
//! | GPU-T02 | `gpu_t02_second_request_joins_the_import` | catalog single flight and subscribers, executor flights, ledger | — |
//! | GPU-T03 | `gpu_t03_first_subscriber_cancels_and_the_other_continues` | catalog tickets, executor cancellation, ledger | — |
//! | GPU-T04 | `gpu_t04_all_subscribers_cancel_within_bounds_and_leak_no_reservation` | catalog cancellation and garbage collection, executor, ledger | — |
//! | GPU-T05 | `gpu_t05_a_changed_revision_gets_a_new_identity_and_no_stale_weights` | identity layers and advertisements, catalog | — |
//! | GPU-T06 | `gpu_t06_another_tokenizer_rope_or_adapter_never_reuses_sessions_or_executions` | identity (logical, session, KV scope, graph key), adapters KV | — |
//! | GPU-T07 | `gpu_t07_another_layout_needs_its_own_validated_representation` | identity, manifest rank plans | converting real weights to another layout |
//! | GPU-T08 | `gpu_t08_corrupt_or_truncated_extents_are_rejected_and_retried_within_bounds` | catalog import, executor retries, ledger | — |
//! | GPU-T09 | `gpu_t09_malicious_metadata_is_refused_before_allocation` | manifest seal and validation, safetensors indexer | GGUF headers (manifest's own tests) |
//! | GPU-T10 | `gpu_t10_valid_encoded_checksums_never_excuse_corrupt_decoded_content` | manifest extent verification, executor | — |
//! | GPU-T11 | `gpu_t11_an_importer_crash_before_commit_leaves_nothing_visible` | catalog reopen and resume | a crash inside one write |
//! | GPU-T12 | `gpu_t12_disk_full_preserves_originals_and_releases_reservations` | catalog quota, manifest importer over the catalog adapter | a real `ENOSPC` |
//! | GPU-T13 | `gpu_t13_a_consumer_cannot_write_the_shared_cache` | catalog grants, leases, read handles, verification | OS enforcement against a privileged process |
//! | GPU-T14 | `gpu_t14_adapters_share_one_eligible_base_and_keep_their_own_identities` | adapters graph and KV, residency VRAM | — |
//! | GPU-T15 | `gpu_t15_merged_adapters_switch_without_touching_or_drifting_the_base` | adapters graph, merge and eviction, residency retention | kernel outputs of merged weights |
//! | GPU-T16 | `gpu_t16_admission_counts_the_actual_peak_not_the_weights` | residency VRAM and ledger adapter, ledger | — |
//! | GPU-T17 | `gpu_t17_fully_held_memory_queues_fairly_without_an_eviction_loop` | adapters eviction, ledger queue | — |
//! | GPU-T18 | `gpu_t18_host_limits_cap_the_cache_and_never_overcommit` | tiers pinned, residency host, ledger | the real WSL memory setting |
//! | GPU-T19 | `gpu_t19_reclaimed_page_cache_is_replanned_never_claimed_ready` | catalog, tiers host, local and source choice, ledger | mincore and kernel reclaim |
//! | GPU-T20 | `gpu_t20_unavailable_io_paths_fall_back_with_a_reason` | evidence gate, executor (io_uring, direct I/O), tiers pinned, ledger | whether io_uring, `O_DIRECT` and page locking work on the host |
//! | GPU-T21 | `gpu_t21_the_measured_path_never_claims_direct_transfer_without_the_gate` | evidence gate, executor read paths | cuFile's own report on hardware |
//! | GPU-T22 | `gpu_t22_wrong_or_stale_ipc_handles_are_refused_and_rebuilt` | VMM sharing, evidence, native handles | the same receiver importing again (finding) |
//! | GPU-T23 | `gpu_t23_a_dead_exporter_leaves_no_stale_handle_to_execute` | VMM ownership, placement, ledger | driver-level process death (finding) |
//! | GPU-T24 | `gpu_t24_unmapping_waits_for_kernels_and_graphs_to_drain` | VMM parking and graphs | real kernel timing |
//! | GPU-T25 | `gpu_t25_a_changed_graph_abi_at_the_same_address_is_recaptured` | VMM graphs, identity graph key | — |
//! | GPU-T26 | `gpu_t26_a_failed_activation_leaves_the_old_generation_serving` | placement activation, ledger | — |
//! | GPU-T27 | `gpu_t27_drain_then_load_reports_an_honest_pause_and_recovers_by_reload` | placement drain-first handover, ledger | — |
//! | GPU-T28 | `gpu_t28_a_failed_rank_never_leaves_a_partial_serving_epoch` | placement rank barrier, ledger | communicators on real ranks |
//! | GPU-T29 | `gpu_t29_an_in_flight_request_keeps_one_generation` | placement router, ledger (INT-03 for the coordinator) | — |
//! | GPU-T30 | `gpu_t30_a_late_group_is_waited_for_and_its_stall_measured` | math overlap, executor events | copy-engine timing |
//! | GPU-T31 | `gpu_t31_tied_weights_and_runtime_buffers_join_one_dependency_group` | manifest aliases and buffers, backends materialization, math first token | — |
//! | GPU-T32 | `gpu_t32_no_first_token_before_the_whole_chain_and_publication` | placement execute-while-load, math first token | — |
//! | GPU-T33 | `gpu_t33_a_mispredicted_expert_is_fetched_exactly` | math MoE step, placement execute-while-load | — |
//! | GPU-T34 | `gpu_t34_special_float_patterns_round_trip_bit_exactly` | manifest extent verification, representation zstd codec | GPU decoders; codecs other than zstd |
//! | GPU-T35 | `gpu_t35_malformed_codec_streams_are_refused_within_bounds` | manifest codec bounds and validation, representation zstd codec | GPU decoders; codecs other than zstd |
//! | GPU-T36 | `gpu_t36_background_decoding_yields_to_the_foreground_budget` | ledger holds, executor, math prefetch budget | decoder and SM contention on a GPU |
//! | GPU-T37 | `gpu_t37_hostile_prediction_is_bounded_and_falls_back_to_demand_only` | math calibration and mode control, executor | — |
//! | GPU-T38 | `gpu_t38_stale_or_vanished_donors_are_replanned_within_bounds` | identity advertisements, tiers peer, executor | the timeout before a silent donor is gone |
//! | GPU-T39 | `gpu_t39_a_busy_donor_serves_only_within_its_budget` | tiers peer and source choice, math sources, catalog | donor tail latency on two machines |
//! | GPU-T40 | `gpu_t40_foreign_kv_is_never_reused_and_the_own_state_is_recomputed` | adapters KV and placement, math recompute | — |
//! | GPU-T41 | `gpu_t41_the_cheaper_valid_restore_wins_with_queues_counted` | adapters placement, math recompute | — |
//! | GPU-T42 | `gpu_t42_a_restart_reconciles_artifacts_and_invalidates_device_leases` | coordinator recovery, progress job control, catalog (INT-04) | — |
//! | GPU-T43 | `gpu_t43_events_apply_idempotently_and_reconnects_use_the_snapshot` | events hub and reconciler, progress public view | — |
//! | GPU-T44 | `gpu_t44_upgrades_invalidate_capability_and_abi_caches` | evidence, executor permissions, VMM, identity, native ABI | a real driver upgrade |
//! | GPU-T45 | `gpu_t45_old_contracts_keep_working_without_migration` | progress public view, evidence, VMM fallback, manifest | today's runner processes |
//! | GPU-T46 | `gpu_t46_disabling_optional_acceleration_keeps_ordinary_runs_working` | evidence, executor, VMM fallback, placement, ledger | — |
//! | GPU-T47 | `gpu_t47_tiny_requests_keep_control_plane_state_bounded` | events, progress publisher, ledger queue, executor | CPU time |
//! | GPU-T48 | `gpu_t48_the_shared_cache_discloses_nothing_across_trust_scopes` | catalog visibility and grants, tiers peer and source choice | hardware timing channels |

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::num::{NonZeroU32, NonZeroU64};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use crate::foundation::catalog::{
    ArtifactClass, ArtifactVerifier, CancelOutcome, Catalog, CatalogConfig, Checkpoint,
    ContentDescriptor, FailureReason as CatalogFailure, GrantRequest, ImportControl,
    ImportManifest, ImportRefusal, ImportRequest as CatalogImport, ImportSource, ImportStage,
    ImportStart, ImportStatus, ImportTicket, ObjectBytes, ObjectId, ObjectMetadata, ObjectRole,
    ObjectStatus, Proceed, PublisherId, QuotaRefusal, ReadError, ReadRefusal, Scope, SourceError,
    SourceIdentity as CatalogSource, TrustClaim, TrustPolicy, Uninterrupted, VerifierRegistry,
    VerifierRejection, VerifyError,
};
use crate::foundation::coordination::{LeaseRefusal, RecoveryReport as CoordinatorRecovery};
use crate::foundation::events::{
    Arrival, CancellationBoundary, EmitError, EventContext, EventEnvelope, EventHub, HubConfig,
    LossReason, MetricsConfig, Phase, ProducerId, ProducerIncarnation, ProgressConfig,
    ProgressRefusal, ProgressUpdate, ReconcileConfig, Reconciler, Resolution,
    ResourceKind as EventResource, RevocationConfig, TrackedResourceId,
};
use crate::foundation::evidence::fakes::FakeProbe;
use crate::foundation::evidence::{
    Backend, BackendRelease, Capability, ConfigurationFingerprint, CudaAllocationSubject,
    EvidencePolicy, EvidenceRefusal, HostSubject, LoaderGate, LoaderPlan, LoaderRefusal,
    LoaderRequest, Necessity, NotEnabled, Observation, Optimization, ProbeRegistry, RuntimeProfile,
    RuntimeSubject, ShareableHandle, SourceClass, Subject, SupportDetail,
};
use crate::foundation::ids::{
    digest, AuthorizationEpoch, Clock, ContentKey, Digest, DigestBuilder, ExecutionCategory,
    ExecutionId, GpuAllocationGeneration, GpuDeviceKey, Incarnation, LeaseId, ManualClock,
    ModelActivationGeneration, MonotonicTime, OperationId, TenantId, TrustScope,
};
use crate::foundation::ledger::{
    Admission as LedgerAdmission, Amounts, CapacityDeclaration, CostPurpose, HostResource, Ledger,
    LedgerConfig, LedgerError, LedgerEvent, Priority, Provenance, QueueLimits, QueueRefusal,
    QueueTicket, Requester, ReservationRequest as LedgerRequest, ReservationState, ResourceKey,
};
use crate::foundation::report::{ClockId, Label as ReportLabel};
use crate::model_memory::adapters::eviction::{
    plan_eviction, EvictionOutcome, EvictionPolicy, EvictionRequest,
};
use crate::model_memory::adapters::fakes as kv_fixtures;
use crate::model_memory::adapters::graph::{
    DependencyGraph, GraphError as AdaptersGraphError, Hold, NodeData, WithoutMerge,
};
use crate::model_memory::adapters::kv::{
    check_kv_reuse as adapter_kv_reuse, kv_state_key, EngineKvProfile, KvRequest,
    KvReuseRefusal as AdapterKvRefusal, KvReuseSpec, KvSharing, PublicPrefixSharing, RankPosition,
    StoredKv,
};
use crate::model_memory::adapters::placement::{
    decide_kv_placement, KvPlacement, KvPlacementError, KvRecomputeEstimate, KvTransferEstimate,
    MoveToTarget, StayOnCurrent,
};
use crate::model_memory::backends::{
    check_materialization, Materialization, MaterializationPlan, MaterializationRefusal,
    ModelInventory, TensorName, TensorRole,
};
use crate::model_memory::backends::{
    BackendRuntime, ComputePlatform, PinnedCapabilities, QueriedCapabilities,
};
use crate::model_memory::boundaries::{
    AbiDeclaration, AbiRefusal, NativeAbi, NativeAbiVersion, NativeHandle, NativeHandleKind,
    NativeOperation, NATIVE_ABI_VERSION,
};
use crate::model_memory::executor::{
    resource_key, AllocationKey, AttemptFailure, BackendError, BackendErrorKind, BatchLimits,
    BatchPlan, BatchPort, CancelReason, CapacityLimit, CapacityRefusal, CatalogPort,
    CatalogRefusal, CopyApi, CopyRequest, DecodeRequest, DependencyId, DependencySpec, Destination,
    DestinationRange, DeviceStagingConfig, EventId, EventPort, EventStatus, ExecutorConfig,
    ExecutorPorts, ExtentFailure, ExtentSpan, HostStagingConfig, HostStagingMemory, JobPriority,
    JobStatus, LedgerReservations, LoaderPermissions, ManifestExtent, ReadMethod, ReadRequest,
    ReadStatus, ReadTicket, ReservationRefusal as ExecutorReservationRefusal, ReservedResource,
    ResolveRequest, ResolvedManifest, SourceCandidate, SourceKind, Stage as ExecutorStage,
    StagedRange, StagingAccount, StagingBuffer, StagingPlace, StoredForm, SubmitError,
    TransferBackend, TransferEvent, TransferEventKind, TransferExecutor, TransferPath,
    TransferRequest,
};
use crate::model_memory::executor::{DirectIo, DirectIoUnavailable, NoEvidence};
use crate::model_memory::identity::fakes::{checked_grant, scope_enforcement};
use crate::model_memory::identity::{
    check_kv_reuse, AdapterIdentity, AdapterRecipe, AdapterSpec, AdvertisementPurpose,
    AdvertisementRefusal, AdvertisementRequest, ArtifactIdentity, AuthorityBinding, CaptureShape,
    CodePolicy, CommitId, CompileConfiguration, CurrentResidency, Dtype, ExecutionIdentity,
    ExecutionSpec, GrantedUse, GraphCaptureSpec, GraphDifference, GraphResource as IdGraphResource,
    GraphResourceField, GraphResourceKind, GraphReuseRefusal, ImmutableRevision, KvAuthority,
    KvPosition, KvRepresentation, KvReuseRefusal, KvScopeComponent, KvScopeSpec, Label,
    LogicalModelSpec, PositionalEncoding, Quantization, RankTopology, RelativePath, Residency,
    ResidentAdvertisement, ScopeEnforcement, SessionSpec, SourceFile, SourceIdentity,
    SourceLocation, SourceSpec, TokenPrefix, TokenState, VersionedName,
};
use crate::model_memory::identity::{GrantTerms, RevokedAuthorities};
use crate::model_memory::manifest::{self as mf, Codec, CodecVersion, EncodedDigest};
use crate::model_memory::math::bounds::BandwidthRating;
use crate::model_memory::math::calibration::{
    CalibrationTracker, DemandOnlyReason, ModeController, ModeSignals, ModeThresholds,
    SchedulingMode,
};
use crate::model_memory::math::overlap::{
    finish_times, first_token, ideal_finish_seconds, no_stall, CriticalInput, Dependency,
    DependencyKind, ExpertCache, ExpertId, GroupRef, GroupRequirement, GroupTiming, MoeStep,
    NoStall, OverlapError, WaitCause,
};
use crate::model_memory::math::prefetch::{
    expected_value, AdmissionRefusal, CandidateOrigin, Objective, PrefetchBudget,
    PrefetchCandidate, PrefetchError, PrefetchValue, RawCost,
};
use crate::model_memory::math::recompute::{KvRequirement, RecomputeRefusal};
use crate::model_memory::math::sources::{
    SourceAuthorization, SourceSpec as PlannedSource, StealPolicy,
};
use crate::model_memory::math::{CandidateId, SourceId};
use crate::model_memory::placement::fakes::FakeCoordination;
use crate::model_memory::placement::{
    ledger_device, ActivationError, ActivationIdentity, ActivationRequest, ActivationStarted,
    AdmissionRequest, ArtifactValidity, AssignedRequest, Component, EarlyRefusal, ExtentKey,
    ExtentProgress, ExtentSpec, FailureReason as PlacementFailure, LedgerPlacementConfig,
    LedgerReservations as PlacementReservations, PauseOutcome, PauseReason, PlacementChoice,
    PlacementKey, PlacementSlot, Ports, ProcessInstance, PublishReport, Rank, ReadinessReport,
    ReclaimReport, RequestShape, RequestTicket, ResourceDemand, RollbackOutlook, RouteRefusal,
    SlotId, SlotSpec, StateKind, SupportedShape, TicketError, TransientStage, TransitionMode,
    TransitionPreference, ValidationCheck, ValidationReport, WeightPosition,
};
use crate::model_memory::progress::fakes::{
    model as sandbox_model, owner as sandbox_owner, tenant as sandbox_tenant, FakeLoader,
    SandboxHost,
};
use crate::model_memory::progress::{
    client_state, ClientState, JobControl, JobIntent, JobKind, ProgressPublisher, PublicProgress,
    PublishError, PublishPolicy, Stage, Submission, TrackRequest,
};
use crate::model_memory::representation::codec::{
    decode_frame, inspect_frame_header, zstd_format, CodecError, DEFAULT_LEVEL, ZSTD_MAGIC,
};
use crate::model_memory::representation::{decode_bounded, encode as codec_encode, ZstdDecoder};
use crate::model_memory::residency::eviction::{
    Content, CopyTier, ReconstructibleCopy, Verification as CopyVerification,
};
use crate::model_memory::residency::host::{
    admit_host, HostBacking, HostDemand, HostError, HostPlan, HostScope, HostScopeKind,
    ScopeOccupancy,
};
use crate::model_memory::residency::reservation::{vram_resource, PlacementReservation};
use crate::model_memory::residency::retention::Lru;
use crate::model_memory::residency::vram::{
    admit_vram, evaluate_vram, ImmutableAllocation, ImmutableKind, KvBound, ProcessVram,
    TransientDemand, TransientKind, VramError, VramPlan,
};
use crate::model_memory::residency::{Capacity, Interval};
use crate::model_memory::tiers::{
    choose_source, Consumer, ExcludedSource, ExclusionReason, HostContent, HostRefusal,
    LedgerCharge, LocalStorageTier, MemlockLimit, ObjectRef, OfferRefusal, PeerAuthorization,
    PeerContent, PeerRefusal, PeerSource, PinnedHostTier, PinnedLimits, PinnedRefusal, PoolId,
    PoolPresence, PoolSelection, ReclaimableHostTier, SourceChoiceError, SourcePath, SourceRequest,
    StoragePool, Tier, TierRefusal, Verification as HostVerification, WslLimit,
};
use crate::model_memory::vmm::{self, NotCallableReason, VmmError};

// ---------------------------------------------------------------------------------------
// Shared fixtures: units, names, the clock, a seeded generator and the host ledger.
// ---------------------------------------------------------------------------------------

const KIB: u64 = 1 << 10;
const MIB: u64 = 1 << 20;
const GIB: u64 = 1 << 30;
const SECOND: Duration = Duration::from_secs(1);
const MINUTE: Duration = Duration::from_secs(60);
const HOUR: Duration = Duration::from_secs(3_600);

type TestClock = Arc<ManualClock>;

/// A manual clock standing at one second.
fn test_clock() -> TestClock {
    Arc::new(ManualClock::new(MonotonicTime::from_nanos(1_000_000_000)))
}

fn named(kind: &str, name: &str) -> Digest {
    digest(
        &format!("yougori/test/gpu-scenarios/{kind}/v1"),
        &[name.as_bytes()],
    )
}

fn machine() -> Digest {
    named("machine", "workstation")
}

fn gpu(index: u8) -> GpuDeviceKey {
    GpuDeviceKey {
        machine: machine(),
        device: named("device", &index.to_string()),
    }
}

fn tenant(name: &str) -> TenantId {
    TenantId::new(name).unwrap()
}

fn execution(name: &str) -> ExecutionId {
    ExecutionId::new(name).unwrap()
}

fn operation(name: &str) -> OperationId {
    OperationId::new(name).unwrap()
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// SplitMix64 with an explicit seed: the only source of randomness in these scenarios.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut mixed = self.0;
        mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        mixed ^ (mixed >> 31)
    }

    fn bytes(&mut self, length: usize) -> Vec<u8> {
        (0..length)
            .map(|_| self.next_u64().to_le_bytes()[0])
            .collect()
    }
}

/// `length` deterministic bytes drawn from `seed`.
fn payload(seed: u64, length: usize) -> Vec<u8> {
    SplitMix64(seed).bytes(length)
}

/// The host's CORE-03 ledger with `capacities`, each fully in the budget of `tenants`.
fn host_ledger(
    clock: &TestClock,
    capacities: &[(ResourceKey, u64)],
    tenants: &[&str],
) -> Ledger<TestClock> {
    let mut ledger = Ledger::new(
        Arc::clone(clock),
        HostSubject { machine: machine() },
        LedgerConfig {
            queue: QueueLimits {
                max_entries: 4,
                max_entries_per_tenant: 2,
                max_wait: MINUTE,
            },
            grant_ttl: HOUR,
            unmanaged_usage_max_age: HOUR,
        },
    );
    for (key, total) in capacities {
        ledger
            .declare_capacity(
                *key,
                CapacityDeclaration {
                    total: *total,
                    supervisor_reserve: 0,
                    unmanaged_in_use: 0,
                    source: SourceClass::HostProbe,
                },
            )
            .unwrap();
        for name in tenants {
            ledger
                .set_tenant_budget(tenant(name), *key, *total)
                .unwrap();
        }
    }
    ledger
}

// ---------------------------------------------------------------------------------------
// Catalog fixtures: a CORE-02 catalog in a temporary directory and in-memory sources.
// ---------------------------------------------------------------------------------------

/// Bytes held in memory as an import source; it can end early or flip a byte, as a
/// truncated download or a corrupted mirror would.
struct MemorySource {
    name: String,
    bytes: Vec<u8>,
    /// The source delivers nothing at or past this offset.
    ends_at: Option<usize>,
    /// The byte at this offset is delivered flipped.
    flips: Option<usize>,
    delivered_bytes: u64,
}

impl MemorySource {
    fn new(name: &str, bytes: &[u8]) -> Self {
        Self {
            name: name.to_owned(),
            bytes: bytes.to_vec(),
            ends_at: None,
            flips: None,
            delivered_bytes: 0,
        }
    }
}

impl ImportSource for MemorySource {
    fn identity(&self) -> CatalogSource {
        CatalogSource::describe("test-memory", &self.name)
    }

    fn length_bytes(&mut self) -> Result<u64, SourceError> {
        Ok(self.bytes.len() as u64)
    }

    fn read_at(&mut self, offset_bytes: u64, buffer: &mut [u8]) -> Result<usize, SourceError> {
        let start = usize::try_from(offset_bytes).unwrap_or(usize::MAX);
        let end = self
            .ends_at
            .unwrap_or(self.bytes.len())
            .min(self.bytes.len());
        let available = self.bytes.get(start..end).unwrap_or(&[]);
        let count = available.len().min(buffer.len());
        buffer[..count].copy_from_slice(&available[..count]);
        if let Some(flipped) = self.flips {
            if (start..start + count).contains(&flipped) {
                buffer[flipped - start] ^= 0xff;
            }
        }
        self.delivered_bytes += count as u64;
        Ok(count)
    }
}

/// The responsible verifier of model weights here: no publisher is authenticated, and any
/// bytes are structurally acceptable.
struct WeightsVerifier;

impl ArtifactVerifier for WeightsVerifier {
    fn class(&self) -> ArtifactClass {
        ArtifactClass::ModelWeights
    }

    fn authenticate(
        &self,
        _content: &ContentDescriptor,
        _publisher: &PublisherId,
        _attestation: &[u8],
    ) -> Result<(), VerifierRejection> {
        Err(VerifierRejection::AttestationInvalid)
    }

    fn validate(
        &self,
        _content: &ContentDescriptor,
        _bytes: &mut ObjectBytes,
    ) -> Result<(), VerifierRejection> {
        Ok(())
    }
}

/// Extent size of catalog imports in these scenarios.
const CATALOG_EXTENT: u64 = 64;

/// A CORE-02 catalog in its own temporary directory. Committed files are read-only, so
/// dropping it makes them writable first and the directory can be removed.
struct Store {
    catalog: Option<Catalog>,
    clock: TestClock,
    quotas: Vec<(Scope, u64)>,
    dir: tempfile::TempDir,
}

impl Store {
    /// A catalog where each named tenant may store `quota_bytes` and user-selected weights
    /// are trusted.
    fn open(clock: &TestClock, tenants: &[&str], quota_bytes: u64) -> Self {
        let quotas = tenants
            .iter()
            .map(|name| (Scope::tenant(tenant(name)), quota_bytes))
            .collect();
        let mut store = Self {
            catalog: None,
            clock: Arc::clone(clock),
            quotas,
            dir: tempfile::tempdir().unwrap(),
        };
        store.reopen();
        store
    }

    /// Opens the catalog again on the same directory, as after a restart.
    fn reopen(&mut self) -> crate::foundation::catalog::OpenReport {
        self.catalog = None;
        let mut verifiers = VerifierRegistry::new();
        verifiers.register(Box::new(WeightsVerifier)).unwrap();
        let config = self.quotas.iter().fold(
            CatalogConfig::new(MINUTE).with_trust(
                ArtifactClass::ModelWeights,
                TrustPolicy::new().accept_user_selected(),
            ),
            |config, (scope, bytes)| config.with_quota(scope.clone(), *bytes),
        );
        let (catalog, report) = Catalog::open(
            self.dir.path(),
            config,
            verifiers,
            Arc::clone(&self.clock) as Arc<dyn Clock>,
        )
        .unwrap();
        self.catalog = Some(catalog);
        report
    }

    fn catalog(&mut self) -> &mut Catalog {
        self.catalog.as_mut().expect("the catalog is open")
    }

    fn view(&self) -> &Catalog {
        self.catalog.as_ref().expect("the catalog is open")
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        self.catalog = None;
        make_writable(self.dir.path());
    }
}

fn make_writable(path: &Path) {
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            make_writable(&entry.path());
        }
    }
    if let Ok(metadata) = std::fs::metadata(path) {
        let mut permissions = metadata.permissions();
        if permissions.readonly() {
            #[allow(clippy::permissions_set_readonly_false)]
            permissions.set_readonly(false);
            let _ = std::fs::set_permissions(path, permissions);
        }
    }
}

/// An import of `bytes` as `owner`'s original model weights, made by `by`.
fn weights_import(
    owner: &str,
    by: &str,
    name: &str,
    bytes: &[u8],
) -> (CatalogImport, CatalogSource) {
    let request = CatalogImport {
        operation: operation(&format!("op-import-{name}")),
        execution: execution(by),
        scope: Scope::tenant(tenant(owner)),
        class: ArtifactClass::ModelWeights,
        role: ObjectRole::Original,
        manifest: ImportManifest::describe(bytes, NonZeroU64::new(CATALOG_EXTENT).unwrap()),
        trust: TrustClaim::UserSelected,
        depends_on: BTreeSet::new(),
        metadata: ObjectMetadata::new(),
    };
    (request, MemorySource::new(name, bytes).identity())
}

/// The ticket of a started or attached import.
fn ticket_of(start: ImportStart) -> ImportTicket {
    match start {
        ImportStart::Started(ticket) | ImportStart::Attached(ticket) => ticket,
        ImportStart::AlreadyPublished(object) => panic!("{object} was already published"),
    }
}

/// Interrupts an import once at each listed checkpoint, as a caller pausing to look.
struct PauseAt {
    remaining: Vec<Checkpoint>,
    seen: Vec<Checkpoint>,
}

impl PauseAt {
    fn new(at: &[Checkpoint]) -> Self {
        Self {
            remaining: at.to_vec(),
            seen: Vec::new(),
        }
    }
}

impl ImportControl for PauseAt {
    fn proceed(&mut self, at: Checkpoint) -> Proceed {
        self.seen.push(at);
        match self.remaining.iter().position(|pause| *pause == at) {
            Some(index) => {
                self.remaining.remove(index);
                Proceed::Interrupt
            }
            None => Proceed::Continue,
        }
    }
}

// ---------------------------------------------------------------------------------------
// Transfer fixtures: the GPU §3.5 executor over the host ledger, with the native backend,
// the manifest port and the batching port as fakes at the edge.
// ---------------------------------------------------------------------------------------

/// Alignment and staging slot size of the executor in these scenarios.
const ALIGN: u64 = 16;
const SLOT: u64 = 64;

/// Encodes like the fake codec of the edge backend: a 4-byte big-endian length, then the
/// bytes XORed with a key. It stands in for zstd; the manifest names the codec.
fn edge_encode(decoded: &[u8]) -> Vec<u8> {
    let mut encoded = (decoded.len() as u32).to_be_bytes().to_vec();
    encoded.extend(decoded.iter().map(|byte| byte ^ 0x5a));
    encoded
}

fn edge_decode(encoded: &[u8]) -> Option<Vec<u8>> {
    let (header, body) = encoded.split_at_checked(4)?;
    let length = u32::from_be_bytes(header.try_into().ok()?) as usize;
    (length == body.len()).then(|| body.iter().map(|byte| byte ^ 0x5a).collect())
}

/// What the native side of the executor holds: stored objects per source, staging
/// slots, pending copies and destination memory. Reads finish when polled; copies land
/// `copy_nanos` after they are enqueued, and their completion event waits for them.
#[derive(Default)]
struct EdgeState {
    objects: BTreeMap<(SourceId, ContentKey), Vec<u8>>,
    methods: BTreeSet<ReadMethod>,
    staging: BTreeMap<StagingBuffer, Vec<u8>>,
    reads: BTreeMap<u64, ReadRequest>,
    events: BTreeMap<u64, u64>,
    pending: Vec<(u64, StagedRange, DestinationRange)>,
    memory: BTreeMap<AllocationKey, Vec<u8>>,
    next: u64,
    copy_nanos: u64,
    /// Copies run one after another on the device's copy stream, this long per byte.
    copy_nanos_per_byte: u64,
    stream_until: u64,
    /// Sources whose reads fail from now on, as a donor that disappeared.
    gone: BTreeSet<SourceId>,
    /// Offsets of stored bytes a source delivers flipped.
    corrupt: BTreeSet<(SourceId, u64)>,
    /// Where a source's copy of the object ends early.
    truncate_at: BTreeMap<SourceId, u64>,
    /// cuFile serves GPUDirect Storage reads in its compatibility mode, through its own
    /// host bounce buffer, and says so.
    gds_compatibility: bool,
    /// Sources whose filesystem refuses direct reads (no `O_DIRECT`).
    refuses_direct: BTreeSet<SourceId>,
    /// Every read started: source, method, staging place, offset and length.
    read_log: Vec<(SourceId, ReadMethod, StagingPlace, u64, u64)>,
    copies_enqueued: u64,
}

impl EdgeState {
    fn settle(&mut self, now: u64) {
        let (due, waiting): (Vec<_>, Vec<_>) = std::mem::take(&mut self.pending)
            .into_iter()
            .partition(|(at, _, _)| *at <= now);
        self.pending = waiting;
        for (_, from, to) in due {
            let start = from.offset_bytes as usize;
            let bytes = self
                .staging
                .get(&from.buffer)
                .and_then(|buffer| buffer.get(start..start + from.length_bytes as usize))
                .map(<[u8]>::to_vec)
                .unwrap_or_default();
            let memory = self.memory.entry(to.allocation).or_default();
            let end = to.offset_bytes as usize + bytes.len();
            if memory.len() < end {
                memory.resize(end, 0);
            }
            memory[to.offset_bytes as usize..end].copy_from_slice(&bytes);
        }
    }

    fn staged(&self, range: &StagedRange) -> Result<Vec<u8>, BackendError> {
        let start = range.offset_bytes as usize;
        self.staging
            .get(&range.buffer)
            .and_then(|buffer| buffer.get(start..start + range.length_bytes as usize))
            .map(<[u8]>::to_vec)
            .ok_or_else(|| BackendError::new(BackendErrorKind::Digest, "outside staged bytes"))
    }
}

struct EdgeBackend {
    clock: TestClock,
    state: Arc<Mutex<EdgeState>>,
}

impl EdgeBackend {
    fn now(&self) -> u64 {
        self.clock.now().as_nanos()
    }

    fn state(&self) -> MutexGuard<'_, EdgeState> {
        lock(&self.state)
    }
}

impl TransferBackend for EdgeBackend {
    fn copy_api(&self) -> CopyApi {
        CopyApi::CudaMemcpyAsync
    }

    fn read_methods(&self) -> BTreeSet<ReadMethod> {
        self.state().methods.clone()
    }

    fn begin_read(&mut self, request: &ReadRequest) -> Result<ReadTicket, BackendError> {
        let mut state = self.state();
        if !state.methods.contains(&request.method) {
            return Err(BackendError::new(BackendErrorKind::Unsupported, "method"));
        }
        if request.method == ReadMethod::DirectRead
            && state.refuses_direct.contains(&request.source)
        {
            return Err(BackendError::new(
                BackendErrorKind::Unsupported,
                "the filesystem refused O_DIRECT",
            ));
        }
        state.next += 1;
        let ticket = state.next;
        state.read_log.push((
            request.source.clone(),
            request.method,
            request.into.place,
            request.offset_bytes,
            request.length_bytes,
        ));
        state.reads.insert(ticket, request.clone());
        Ok(ReadTicket(ticket))
    }

    fn poll_read(&mut self, ticket: ReadTicket) -> Result<ReadStatus, BackendError> {
        let now = self.now();
        let mut state = self.state();
        state.settle(now);
        let request = state
            .reads
            .remove(&ticket.0)
            .ok_or_else(|| BackendError::new(BackendErrorKind::Io, "unknown ticket"))?;
        if state.gone.contains(&request.source) {
            return Err(BackendError::new(
                BackendErrorKind::SourceUnavailable,
                "the source disappeared",
            ));
        }
        let object = state
            .objects
            .get(&(request.source.clone(), request.representation))
            .cloned()
            .ok_or_else(|| BackendError::new(BackendErrorKind::SourceUnavailable, "no object"))?;
        let end = state
            .truncate_at
            .get(&request.source)
            .map_or(object.len() as u64, |end| (*end).min(object.len() as u64));
        let available = end
            .saturating_sub(request.offset_bytes)
            .min(request.length_bytes);
        let start = request.offset_bytes as usize;
        let mut data = object[start..start + available as usize].to_vec();
        for (source, offset) in &state.corrupt {
            if *source == request.source
                && (request.offset_bytes..request.offset_bytes + available).contains(offset)
            {
                data[(*offset - request.offset_bytes) as usize] ^= 0xff;
            }
        }
        state.staging.insert(request.into, data);
        if request.method == ReadMethod::GpuDirectStorage && state.gds_compatibility {
            return Ok(ReadStatus::Served {
                bytes_read: available,
                path: TransferPath::DirectStorageCompatibility,
            });
        }
        Ok(ReadStatus::Complete {
            bytes_read: available,
        })
    }

    fn stored_digest(
        &mut self,
        range: &StagedRange,
        form: &StoredForm,
    ) -> Result<Digest, BackendError> {
        let bytes = self.state().staged(range)?;
        Ok(match form {
            StoredForm::Raw => *ContentKey::of(&bytes).digest(),
            StoredForm::Encoded {
                codec, dictionary, ..
            } => EncodedDigest::of(*codec, *dictionary, &bytes).digest(),
        })
    }

    fn content_key(&mut self, range: &StagedRange) -> Result<ContentKey, BackendError> {
        Ok(ContentKey::of(&self.state().staged(range)?))
    }

    fn decode(&mut self, request: &DecodeRequest) -> Result<u64, BackendError> {
        let mut state = self.state();
        let encoded = state.staged(&request.from)?;
        let decoded = edge_decode(&encoded)
            .ok_or_else(|| BackendError::new(BackendErrorKind::Decode, "bad frame"))?;
        if decoded.len() as u64 > request.into.length_bytes {
            return Err(BackendError::new(BackendErrorKind::Decode, "output bound"));
        }
        let buffer = state.staging.entry(request.into.buffer).or_default();
        let start = request.into.offset_bytes as usize;
        if buffer.len() < start + decoded.len() {
            buffer.resize(start + decoded.len(), 0);
        }
        buffer[start..start + decoded.len()].copy_from_slice(&decoded);
        Ok(decoded.len() as u64)
    }

    fn enqueue_copy(&mut self, request: &CopyRequest) -> Result<(), BackendError> {
        let now = self.now();
        let mut state = self.state();
        state.settle(now);
        let at = state.stream_until.max(now)
            + state.copy_nanos
            + state.copy_nanos_per_byte * request.from.length_bytes;
        state.stream_until = at;
        state.pending.push((at, request.from, request.to));
        state.copies_enqueued += 1;
        Ok(())
    }

    fn record_event(&mut self, _device: GpuDeviceKey) -> Result<EventId, BackendError> {
        let now = self.now();
        let mut state = self.state();
        let at = state
            .pending
            .iter()
            .map(|(at, _, _)| *at)
            .max()
            .unwrap_or(now)
            .max(now);
        state.next += 1;
        let event = state.next;
        state.events.insert(event, at);
        Ok(EventId(event))
    }

    fn query_event(&mut self, event: EventId) -> Result<EventStatus, BackendError> {
        let now = self.now();
        let mut state = self.state();
        state.settle(now);
        let at = *state
            .events
            .get(&event.0)
            .ok_or_else(|| BackendError::new(BackendErrorKind::Event, "unknown event"))?;
        Ok(if now >= at {
            EventStatus::Complete
        } else {
            EventStatus::Pending
        })
    }

    fn release_event(&mut self, event: EventId) -> Result<(), BackendError> {
        self.state()
            .events
            .remove(&event.0)
            .map(|_| ())
            .ok_or_else(|| BackendError::new(BackendErrorKind::Event, "unknown event"))
    }
}

type Manifests = Arc<Mutex<BTreeMap<(ContentKey, ContentKey), ResolvedManifest>>>;

/// The verified manifests the catalog would resolve, keyed by artifact and
/// representation. The executor's catalog port has no adapter over CORE-02 yet (P03
/// integration item), so it stays a port here.
struct ManifestPort(Manifests);

impl CatalogPort for ManifestPort {
    fn resolve(&self, request: &ResolveRequest) -> Result<ResolvedManifest, CatalogRefusal> {
        lock(&self.0)
            .get(&(request.artifact, request.representation))
            .cloned()
            .ok_or(CatalogRefusal::NotFound)
    }
}

/// Greedy coalescing of adjacent extents into aligned batches that fit one slot: the
/// T06 granularity rule the executor checks every plan against.
struct Coalescer;

impl BatchPort for Coalescer {
    fn coalesce(&self, spans: &[ExtentSpan], limits: &BatchLimits) -> Vec<BatchPlan> {
        let align = limits.alignment_bytes;
        let down = |value: u64| value / align * align;
        let up = |value: u64| value.div_ceil(align) * align;
        let mut plans: Vec<BatchPlan> = Vec::new();
        let mut current: Vec<&ExtentSpan> = Vec::new();
        let mut decoded = 0;
        let close = |members: &[&ExtentSpan]| {
            let start = down(members[0].offset_bytes);
            let last = members[members.len() - 1];
            BatchPlan {
                members: members.iter().map(|span| span.index).collect(),
                read_offset_bytes: start,
                read_length_bytes: up(last.offset_bytes + last.length_bytes) - start,
            }
        };
        for span in spans {
            if let Some(last) = current.last() {
                let adjacent = last.offset_bytes + last.length_bytes == span.offset_bytes;
                let read =
                    up(span.offset_bytes + span.length_bytes) - down(current[0].offset_bytes);
                let fits = read <= limits.max_read_bytes
                    && decoded + span.decode_bytes <= limits.max_decoded_bytes;
                if !(adjacent && fits) {
                    plans.push(close(&current));
                    current.clear();
                    decoded = 0;
                }
            }
            decoded += span.decode_bytes;
            current.push(span);
        }
        if !current.is_empty() {
            plans.push(close(&current));
        }
        plans
    }
}

#[derive(Clone, Default)]
struct Recorder(Arc<Mutex<Vec<TransferEvent>>>);

impl EventPort for Recorder {
    fn emit(&mut self, event: TransferEvent) {
        lock(&self.0).push(event);
    }
}

type Executor = TransferExecutor<TestClock>;

/// The executor's world: the edge backend, the manifest port, recorded events and the
/// host's one CORE-03 ledger, reached through the executor's ledger adapter.
struct Transfers {
    clock: TestClock,
    edge: Arc<Mutex<EdgeState>>,
    manifests: Manifests,
    events: Recorder,
    ledger: Arc<Mutex<Ledger<TestClock>>>,
}

impl Transfers {
    /// A host with 1 MiB of RAM, pinned RAM and VRAM on GPU 0, budgeted to the executor's
    /// staging account and to tenants A and B.
    fn new(clock: &TestClock) -> Self {
        let ledger = host_ledger(
            clock,
            &[
                (ResourceKey::Host(HostResource::Ram), MIB),
                (ResourceKey::Host(HostResource::PinnedRam), MIB),
                (
                    resource_key(ReservedResource::DeviceMemory { device: gpu(0) }),
                    MIB,
                ),
            ],
            &["executor", "tenant-a", "tenant-b"],
        );
        let edge = EdgeState {
            methods: BTreeSet::from([ReadMethod::PositionedRead, ReadMethod::RangeRequest]),
            copy_nanos: 16,
            ..EdgeState::default()
        };
        Self {
            clock: Arc::clone(clock),
            edge: Arc::new(Mutex::new(edge)),
            manifests: Arc::default(),
            events: Recorder::default(),
            ledger: Arc::new(Mutex::new(ledger)),
        }
    }

    fn edge(&self) -> MutexGuard<'_, EdgeState> {
        lock(&self.edge)
    }

    fn config(&self) -> ExecutorConfig {
        ExecutorConfig {
            operation: operation("executor"),
            host_staging: HostStagingConfig {
                memory: HostStagingMemory::Pinned,
                slots: 4,
                slot_bytes: SLOT,
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
                max_speculative_bytes: 4 * KIB,
                capacity_bytes: MIB,
                reserved_foreground_bytes: KIB,
            },
        }
    }

    fn executor_with(&self, config: ExecutorConfig) -> Executor {
        let ports = ExecutorPorts {
            backend: Box::new(EdgeBackend {
                clock: Arc::clone(&self.clock),
                state: Arc::clone(&self.edge),
            }),
            catalog: Box::new(ManifestPort(Arc::clone(&self.manifests))),
            batches: Box::new(Coalescer),
            reservations: Box::new(LedgerReservations::new(
                Arc::clone(&self.ledger),
                StagingAccount {
                    execution: execution("exe-executor"),
                    tenant: tenant("executor"),
                },
            )),
            events: Box::new(self.events.clone()),
        };
        TransferExecutor::new(config, Arc::clone(&self.clock), ports).expect("the executor starts")
    }

    fn executor(&self) -> Executor {
        self.executor_with(self.config())
    }

    /// Stores `weights` on every source and publishes its manifest.
    fn publish(&self, weights: &Weights, sources: &[SourceCandidate]) {
        for candidate in sources {
            self.edge().objects.insert(
                (candidate.spec.id.clone(), weights.representation),
                weights.stored.clone(),
            );
        }
        lock(&self.manifests).insert(
            (weights.key, weights.representation),
            weights.manifest(sources.to_vec()),
        );
    }

    /// Pumps until nothing is queued or in flight, 50 ns at a time; never unbounded.
    fn drive(&self, executor: &mut Executor) {
        for _ in 0..10_000 {
            executor.pump().expect("the pump runs");
            if executor.is_idle() {
                return;
            }
            self.clock.advance(Duration::from_nanos(50));
        }
        panic!("the executor did not go idle");
    }

    fn events_of(
        &self,
        job: &OperationId,
    ) -> Vec<crate::model_memory::executor::TransferEventKind> {
        lock(&self.events.0)
            .iter()
            .filter(|event| event.operation == *job)
            .map(|event| event.kind.clone())
            .collect()
    }

    /// Destination bytes `[offset, offset + length)` of `allocation`.
    fn landed(&self, allocation: &AllocationKey, offset: u64, length: u64) -> Vec<u8> {
        let mut state = self.edge();
        let now = self.clock.now().as_nanos();
        state.settle(now);
        state
            .memory
            .get(allocation)
            .and_then(|memory| memory.get(offset as usize..(offset + length) as usize))
            .map(<[u8]>::to_vec)
            .unwrap_or_default()
    }

    /// VRAM the host ledger still counts on GPU 0.
    fn vram_reserved(&self) -> u64 {
        lock(&self.ledger).reserved(resource_key(ReservedResource::DeviceMemory {
            device: gpu(0),
        }))
    }
}

/// Model weights split into extents, stored raw or encoded with the edge codec.
struct Weights {
    key: ContentKey,
    representation: ContentKey,
    decoded: Vec<u8>,
    stored: Vec<u8>,
    extents: Vec<ManifestExtent>,
}

impl Weights {
    fn new(name: &str, lengths: &[u64], encoded: bool) -> Self {
        let total: u64 = lengths.iter().sum();
        let decoded = payload(u64::from(name.len() as u32) * 7919 + total, total as usize);
        let mut stored = Vec::new();
        let mut extents = Vec::new();
        let mut offset = 0u64;
        for (index, length) in lengths.iter().enumerate() {
            let slice = &decoded[offset as usize..(offset + length) as usize];
            let (bytes, form) = if encoded {
                let bytes = edge_encode(slice);
                let form = StoredForm::Encoded {
                    codec: zstd_format(G),
                    dictionary: None,
                    digest: EncodedDigest::of(zstd_format(G), None, &bytes),
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
            manifest: ContentKey::of(b"verified manifest"),
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
}

fn source_id(name: &str) -> SourceId {
    SourceId::new(name).unwrap()
}

fn candidate(name: &str, kind: SourceKind, bytes_per_second: f64) -> SourceCandidate {
    SourceCandidate {
        kind,
        spec: PlannedSource {
            id: source_id(name),
            authorization: SourceAuthorization::Authorized,
            startup_seconds: 0.0,
            bandwidth: BandwidthRating::measured_directional(bytes_per_second).unwrap(),
            cuts: vec![],
            max_in_flight: 4,
            interference_seconds_per_byte: 0.0,
        },
    }
}

fn local(name: &str) -> SourceCandidate {
    candidate(name, SourceKind::LocalFile, 1e9)
}

fn allocation(name: &str) -> AllocationKey {
    AllocationKey {
        device: gpu(0),
        allocation: named("allocation", name),
        generation: GpuAllocationGeneration::FIRST,
    }
}

fn destination(name: &str) -> Destination {
    Destination {
        allocation: allocation(name),
        base_offset_bytes: 0,
        capacity_bytes: 64 * KIB,
    }
}

/// A foreground job of `owner` loading every extent of `weights` as one dependency.
fn load_job(name: &str, owner: &str, weights: &Weights, into: &str) -> TransferRequest {
    TransferRequest {
        operation: operation(name),
        execution: execution(&format!("exe-{name}")),
        tenant: tenant(owner),
        artifact: weights.key,
        representation: weights.representation,
        destination: destination(into),
        dependencies: vec![DependencySpec {
            id: DependencyId(1),
            extents: weights.all(),
            requires: vec![],
        }],
        priority: JobPriority::Foreground,
        loader: LoaderPermissions::ordinary(),
    }
}

/// The CORE-06 event plane with room for 64 tracked progress states.
fn event_hub(clock: &TestClock, incarnation: u64) -> EventHub<TestClock> {
    EventHub::new(
        Arc::clone(clock),
        HubConfig {
            metrics: MetricsConfig {
                capacity_events: 256,
                sample_above_events: 192,
                keep_one_in: NonZeroU32::new(8).unwrap(),
                retention: MINUTE,
                max_series: 16,
            },
            progress: ProgressConfig {
                max_tracked: 64,
                terminal_retention: MINUTE,
            },
            revocation: RevocationConfig {
                max_pending_executions: 16,
            },
            first_incarnation: ProducerIncarnation::new(incarnation).unwrap(),
        },
    )
    .unwrap()
}

/// P08's progress publisher for incarnation `incarnation` on `hub`.
fn progress_publisher(
    hub: &mut EventHub<TestClock>,
    clock: &TestClock,
    incarnation: u64,
) -> ProgressPublisher<TestClock> {
    let producer = hub
        .register_progress(
            ProducerId::new("engine.progress").unwrap(),
            SourceClass::HostProbe,
            None,
        )
        .unwrap();
    ProgressPublisher::new(
        producer,
        Incarnation::new(incarnation),
        Arc::clone(clock),
        ClockId::new(ReportLabel::new("host-monotonic").unwrap()),
        PublishPolicy::default(),
    )
    .unwrap()
}

// ---------------------------------------------------------------------------------------
// GPU-T01 to GPU-T04, GPU-T11 to GPU-T13: imports, subscribers and the catalog boundary.
// ---------------------------------------------------------------------------------------

/// GPU-T01 (line 1283): empty cache, first import; truthful preparation progress and no
/// readiness before validation.
///
/// The CORE-02 importer runs the line 533 protocol, paused at an extent, before read-back
/// validation and before publication. At every pause the object is neither found nor
/// readable, and P08's publisher reports arrived bytes with none usable, refusing a move
/// to `Running`. Only after publication are the bytes committed and the model may run.
/// Not covered: ETA accuracy on real storage (§8.1: absent hardware is "not measured").
#[test]
fn gpu_t01_first_import_reports_truthful_progress_and_no_readiness_before_validation() {
    let clock = test_clock();
    let mut store = Store::open(&clock, &["tenant-a"], MIB);
    let scope = Scope::tenant(tenant("tenant-a"));
    let bytes = payload(1, 4 * CATALOG_EXTENT as usize);
    let content = ContentKey::of(&bytes);
    let object = ObjectId::new(&scope, ArtifactClass::ModelWeights, content);
    assert_eq!(
        store
            .view()
            .find(&scope, ArtifactClass::ModelWeights, content),
        None,
        "the cache starts empty"
    );

    let mut hub = event_hub(&clock, 1);
    let mut publisher = progress_publisher(&mut hub, &clock, 1);
    let load = operation("op-load");
    publisher
        .track(
            &mut hub,
            &load,
            TrackRequest {
                resource: TrackedResourceId::new(*content.digest()),
                kind: EventResource::Weights,
                total_bytes: bytes.len() as u64,
                stage: Stage::at(Phase::Transferring),
            },
        )
        .unwrap();

    let (request, identity) = weights_import("tenant-a", "exe-a", "model", &bytes);
    let mut source = MemorySource::new("model", &bytes);
    let ticket = ticket_of(store.catalog().begin_import(request, identity).unwrap());
    let mut control = PauseAt::new(&[
        Checkpoint::Extent { extent: 2 },
        Checkpoint::Stage {
            stage: ImportStage::ReadBackValidation,
        },
        Checkpoint::Stage {
            stage: ImportStage::CatalogPublication,
        },
    ]);
    let mut arrived = 0u32;
    let mut pauses = 0;
    let published = loop {
        clock.advance(SECOND);
        let status = store
            .catalog()
            .drive_import(&ticket, &mut source, &mut control)
            .unwrap();
        let progress = match status {
            ImportStatus::Pending { progress, .. } => progress,
            ImportStatus::Published { object, progress } => break (object, progress),
            ImportStatus::Failed { failure } => panic!("the import failed: {failure:?}"),
        };
        pauses += 1;
        assert_eq!(
            store
                .view()
                .find(&scope, ArtifactClass::ModelWeights, content),
            None
        );
        assert_eq!(store.view().status(&scope, object), ObjectStatus::Absent);
        let verified = progress.verified_extents;
        for index in arrived..verified {
            publisher
                .extent_arrived(&mut hub, &load, u64::from(index), CATALOG_EXTENT)
                .unwrap();
        }
        arrived = arrived.max(verified);
        let (_, update) = publisher.progress(&load).unwrap();
        assert_eq!(
            update.completed_bytes(),
            u64::from(arrived) * CATALOG_EXTENT
        );
        assert_eq!(update.committed_usable_bytes(), 0, "nothing is usable yet");
        assert!(matches!(
            publisher.set_stage(&mut hub, &load, Stage::at(Phase::Running)),
            Err(PublishError::NotAllUsable { .. })
        ));
    };
    assert_eq!(pauses, 3);
    assert!(control.remaining.is_empty());
    let (published_object, progress) = published;
    assert_eq!(published_object, object);
    assert_eq!(progress.fetched_bytes, bytes.len() as u64, "each byte once");

    publisher
        .set_stage(&mut hub, &load, Stage::at(Phase::Verifying))
        .unwrap();
    for index in 0..4 {
        publisher
            .extent_arrived(&mut hub, &load, index, CATALOG_EXTENT)
            .unwrap();
        publisher.extent_committed(&mut hub, &load, index).unwrap();
    }
    let (_, update) = publisher.progress(&load).unwrap();
    assert_eq!(update.committed_usable_bytes(), bytes.len() as u64);
    publisher
        .set_stage(&mut hub, &load, Stage::at(Phase::Running))
        .unwrap();
    assert_eq!(
        store
            .view()
            .find(&scope, ArtifactClass::ModelWeights, content),
        Some(object)
    );
}

/// GPU-T02 (line 1284): a second request during an import gets one import with two
/// subscribers.
///
/// In the CORE-02 catalog a second request from another execution of the same tenant
/// attaches to the import in flight (single flight per tenant scope and source, line
/// 533): one quota reservation, every byte fetched once, both executions listed as the
/// import's subscribers, and each reads the published object under its own execution. In
/// the GPU §3.5 executor two jobs for the same extents, representation and destination
/// share one operation with two subscribers and one read per batch.
#[test]
fn gpu_t02_second_request_joins_the_import() {
    let clock = test_clock();
    let mut store = Store::open(&clock, &["tenant-a"], MIB);
    let scope = Scope::tenant(tenant("tenant-a"));
    let bytes = payload(2, 4 * CATALOG_EXTENT as usize);
    let mut source = MemorySource::new("model", &bytes);

    let (request, identity) = weights_import("tenant-a", "exe-a", "model", &bytes);
    let first = match store.catalog().begin_import(request, identity).unwrap() {
        ImportStart::Started(ticket) => ticket,
        other => panic!("the first request starts the import: {other:?}"),
    };
    let mut pause = PauseAt::new(&[Checkpoint::Extent { extent: 2 }]);
    assert!(matches!(
        store
            .catalog()
            .drive_import(&first, &mut source, &mut pause)
            .unwrap(),
        ImportStatus::Pending { .. }
    ));
    let (mut request_b, _) = weights_import("tenant-a", "exe-b", "model", &bytes);
    request_b.operation = operation("op-import-model-b");
    let second = match store.catalog().begin_import(request_b, identity).unwrap() {
        ImportStart::Attached(ticket) => ticket,
        other => panic!("another execution of the tenant attaches: {other:?}"),
    };
    let both = vec![execution("exe-a"), execution("exe-b")];
    assert_eq!(store.view().import_subscribers(&first), Some(both.clone()));
    assert_eq!(store.view().import_subscribers(&second), Some(both));
    assert_eq!(
        store.view().quota_usage(&scope).reserved_bytes,
        bytes.len() as u64,
        "one reservation for both requests"
    );
    let status = store
        .catalog()
        .drive_import(&second, &mut source, &mut Uninterrupted)
        .unwrap();
    let ImportStatus::Published { object, .. } = status else {
        panic!("the shared import publishes: {status:?}");
    };
    assert_eq!(
        source.delivered_bytes,
        bytes.len() as u64,
        "nothing fetched twice"
    );
    assert!(matches!(
        store.view().import_status(&first),
        Some(ImportStatus::Published { object: seen, .. }) if seen == object
    ));
    for reader in ["exe-a", "exe-b"] {
        assert_eq!(
            read_object(store.catalog(), &scope, reader, object).unwrap(),
            bytes,
            "{reader} reads the shared result"
        );
    }

    let transfers = Transfers::new(&clock);
    let weights = Weights::new("weights", &[16; 4], false);
    transfers.publish(&weights, &[local("nvme")]);
    let mut executor = transfers.executor();
    let (a, b) = (operation("job-a"), operation("job-b"));
    executor
        .submit(load_job("job-a", "tenant-a", &weights, "slot"))
        .unwrap();
    executor
        .submit(load_job("job-b", "tenant-a", &weights, "slot"))
        .unwrap();
    for extent in weights.all() {
        let shared = executor.flight_of(&a, extent).unwrap();
        assert_eq!(executor.flight_of(&b, extent), Some(shared));
        assert_eq!(executor.subscribers(shared), Some(2));
    }
    transfers.drive(&mut executor);
    assert_eq!(executor.status(&a), Some(&JobStatus::Completed));
    assert_eq!(executor.status(&b), Some(&JobStatus::Completed));
    let reads = transfers.edge().read_log.clone();
    let ranges: BTreeSet<(u64, u64)> = reads.iter().map(|read| (read.3, read.4)).collect();
    assert_eq!(reads.len(), ranges.len(), "each batch is read once");
    assert_eq!(
        transfers.landed(&allocation("slot"), 0, 64),
        weights.decoded
    );
}

/// GPU-T03 (line 1285): the first subscriber cancels and the remaining one continues.
///
/// Detaching the first execution's catalog ticket leaves the import running for the
/// other execution of the tenant, which publishes and reads the result. In the executor,
/// cancelling the first job leaves every shared operation to the second job, which
/// completes with the right bytes and nothing released in between.
#[test]
fn gpu_t03_first_subscriber_cancels_and_the_other_continues() {
    let clock = test_clock();
    let mut store = Store::open(&clock, &["tenant-a"], MIB);
    let scope = Scope::tenant(tenant("tenant-a"));
    let bytes = payload(3, 4 * CATALOG_EXTENT as usize);
    let mut source = MemorySource::new("model", &bytes);
    let (request, identity) = weights_import("tenant-a", "exe-a", "model", &bytes);
    let first = ticket_of(store.catalog().begin_import(request, identity).unwrap());
    let mut pause = PauseAt::new(&[Checkpoint::Extent { extent: 1 }]);
    store
        .catalog()
        .drive_import(&first, &mut source, &mut pause)
        .unwrap();
    let (mut request_b, _) = weights_import("tenant-a", "exe-b", "model", &bytes);
    request_b.operation = operation("op-import-model-b");
    let second = match store.catalog().begin_import(request_b, identity).unwrap() {
        ImportStart::Attached(ticket) => ticket,
        other => panic!("another execution of the tenant attaches: {other:?}"),
    };
    assert_eq!(
        store.catalog().cancel_import(first),
        CancelOutcome::Continuing {
            remaining_tickets: 1
        }
    );
    assert_eq!(
        store.view().import_subscribers(&second),
        Some(vec![execution("exe-b")])
    );
    let status = store
        .catalog()
        .drive_import(&second, &mut source, &mut Uninterrupted)
        .unwrap();
    let ImportStatus::Published { object, .. } = status else {
        panic!("the remaining subscriber publishes: {status:?}");
    };
    assert_eq!(
        read_object(store.catalog(), &scope, "exe-b", object).unwrap(),
        bytes
    );

    let transfers = Transfers::new(&clock);
    let weights = Weights::new("weights", &[16; 4], false);
    transfers.publish(&weights, &[local("nvme")]);
    let mut executor = transfers.executor();
    let (a, b) = (operation("job-a"), operation("job-b"));
    executor
        .submit(load_job("job-a", "tenant-a", &weights, "slot"))
        .unwrap();
    executor
        .submit(load_job("job-b", "tenant-a", &weights, "slot"))
        .unwrap();
    executor.pump().unwrap();
    let vram_before = transfers.vram_reserved();
    let report = executor.cancel(&a).unwrap();
    assert_eq!(report.shared, 4);
    assert_eq!(report.reclaimed + report.draining, 0);
    assert_eq!(transfers.vram_reserved(), vram_before, "nothing released");
    transfers.drive(&mut executor);
    assert_eq!(
        executor.status(&a),
        Some(&JobStatus::Cancelled {
            reason: CancelReason::Requested
        })
    );
    assert_eq!(executor.status(&b), Some(&JobStatus::Completed));
    assert_eq!(
        transfers.landed(&allocation("slot"), 0, 64),
        weights.decoded
    );
}

/// GPU-T04 (line 1286): every subscriber cancels; cancellation is bounded and leaks no
/// reservation.
///
/// When the last catalog ticket detaches, nothing is published and the quota
/// reservation returns at once; the verified staged extents stay charged as unpublished
/// only until garbage collection after the grace period. In the executor the last
/// cancellation reclaims at once what is not in flight and lets the rest drain within a
/// bounded number of pumps; every destination reservation ends in the host ledger once
/// the host observes the release, so no VRAM stays counted.
#[test]
fn gpu_t04_all_subscribers_cancel_within_bounds_and_leak_no_reservation() {
    let clock = test_clock();
    let mut store = Store::open(&clock, &["tenant-a"], MIB);
    let scope = Scope::tenant(tenant("tenant-a"));
    let bytes = payload(4, 4 * CATALOG_EXTENT as usize);
    let mut source = MemorySource::new("model", &bytes);
    let (request, identity) = weights_import("tenant-a", "exe-a", "model", &bytes);
    let first = ticket_of(
        store
            .catalog()
            .begin_import(request.clone(), identity)
            .unwrap(),
    );
    let mut pause = PauseAt::new(&[Checkpoint::Extent { extent: 2 }]);
    store
        .catalog()
        .drive_import(&first, &mut source, &mut pause)
        .unwrap();
    let second = ticket_of(store.catalog().begin_import(request, identity).unwrap());
    assert!(matches!(
        store.catalog().cancel_import(first),
        CancelOutcome::Continuing { .. }
    ));
    assert_eq!(
        store.catalog().cancel_import(second),
        CancelOutcome::Cancelled
    );
    let usage = store.view().quota_usage(&scope);
    assert_eq!(usage.reserved_bytes, 0);
    assert_eq!(usage.published_bytes, 0);
    clock.advance(2 * MINUTE);
    store.catalog().collect_garbage().unwrap();
    assert_eq!(
        store.view().quota_usage(&scope).charged_bytes(),
        0,
        "staged extents are collected after the grace period"
    );

    let transfers = Transfers::new(&clock);
    let weights = Weights::new("weights", &[16; 4], false);
    transfers.publish(&weights, &[local("nvme")]);
    let mut config = transfers.config();
    config.host_staging.slots = 1;
    config.host_staging.slot_bytes = 32;
    let mut executor = transfers.executor_with(config);
    let (a, b) = (operation("job-a"), operation("job-b"));
    executor
        .submit(load_job("job-a", "tenant-a", &weights, "slot"))
        .unwrap();
    executor
        .submit(load_job("job-b", "tenant-a", &weights, "slot"))
        .unwrap();
    executor.pump().unwrap();
    assert_eq!(transfers.vram_reserved(), 64);
    assert_eq!(executor.cancel(&a).unwrap().shared, 4);
    let last = executor.cancel(&b).unwrap();
    assert_eq!(last.shared, 0);
    assert_eq!(last.reclaimed + last.draining + last.resident, 4);
    let mut pumps = 0;
    while !executor.is_idle() {
        pumps += 1;
        assert!(pumps <= 8, "cancellation is bounded");
        clock.advance(Duration::from_nanos(50));
        executor.pump().unwrap();
    }
    let releasing: Vec<_> = lock(&transfers.ledger)
        .open_reservations()
        .filter(|record| record.state() == ReservationState::Releasing)
        .map(|record| record.id())
        .collect();
    for reservation in releasing {
        lock(&transfers.ledger)
            .confirm_release(reservation, SourceClass::HostProbe)
            .unwrap();
    }
    assert_eq!(
        transfers.vram_reserved(),
        0,
        "no destination stays reserved"
    );
}

/// GPU-T11 (line 1293): the importer crashes before commit; no half-artifact is visible and
/// temporary state is recovered.
///
/// A crash is the catalog dropped without cancelling and opened again on the same
/// directory. Before the durable commit the reopened catalog reports the staging as
/// untrusted, never publishes it, and a resumed import re-verifies and reuses every
/// staged extent instead of fetching it. After the commit but before publication the
/// object is reported unpublished, stays unreadable, and is validated in full before a
/// resumed import publishes it. Not covered: a process killed inside a write; the crash
/// here falls between protocol stages.
#[test]
fn gpu_t11_an_importer_crash_before_commit_leaves_nothing_visible() {
    let clock = test_clock();
    let mut store = Store::open(&clock, &["tenant-a"], MIB);
    let scope = Scope::tenant(tenant("tenant-a"));
    let bytes = payload(11, 4 * CATALOG_EXTENT as usize);
    let content = ContentKey::of(&bytes);
    let object = ObjectId::new(&scope, ArtifactClass::ModelWeights, content);
    let (request, identity) = weights_import("tenant-a", "exe-a", "model", &bytes);
    let ticket = ticket_of(
        store
            .catalog()
            .begin_import(request.clone(), identity)
            .unwrap(),
    );
    let mut before_commit = PauseAt::new(&[Checkpoint::Stage {
        stage: ImportStage::DurableCommit,
    }]);
    let mut source = MemorySource::new("model", &bytes);
    assert!(matches!(
        store
            .catalog()
            .drive_import(&ticket, &mut source, &mut before_commit)
            .unwrap(),
        ImportStatus::Pending { .. }
    ));
    drop(ticket);

    let report = store.reopen();
    assert_eq!(report.published, 0);
    assert_eq!(report.staging, 1, "the staging is found and not trusted");
    assert!(report.unpublished.is_empty());
    assert_eq!(
        store
            .view()
            .find(&scope, ArtifactClass::ModelWeights, content),
        None
    );
    let ticket = ticket_of(
        store
            .catalog()
            .begin_import(request.clone(), identity)
            .unwrap(),
    );
    let mut resumed = MemorySource::new("model", &bytes);
    let mut before_publication = PauseAt::new(&[Checkpoint::Stage {
        stage: ImportStage::CatalogPublication,
    }]);
    let status = store
        .catalog()
        .drive_import(&ticket, &mut resumed, &mut before_publication)
        .unwrap();
    let ImportStatus::Pending { progress, .. } = status else {
        panic!("paused before publication: {status:?}");
    };
    assert_eq!(progress.reused_extents, 4, "verified extents are reused");
    assert_eq!(resumed.delivered_bytes, 0, "nothing is fetched again");
    drop(ticket);

    let report = store.reopen();
    assert_eq!(report.unpublished, vec![object]);
    assert_eq!(store.view().status(&scope, object), ObjectStatus::Absent);
    let ticket = ticket_of(store.catalog().begin_import(request, identity).unwrap());
    let mut control = PauseAt::new(&[]);
    let status = store
        .catalog()
        .drive_import(
            &ticket,
            &mut MemorySource::new("model", &bytes),
            &mut control,
        )
        .unwrap();
    assert!(matches!(status, ImportStatus::Published { object: seen, .. } if seen == object));
    assert!(control.seen.contains(&Checkpoint::Stage {
        stage: ImportStage::ReadBackValidation
    }));
    assert_eq!(store.view().status(&scope, object), ObjectStatus::Published);
}

// Manifest importer fixtures: in-memory model files, identities and integrity extents.

/// Model files held in memory; the importer reads each once through this port.
struct MemoryFiles(BTreeMap<String, Vec<u8>>);

impl mf::SourceFiles for MemoryFiles {
    fn open(&self, path: &mf::RelativePath) -> Result<(Box<dyn Read + '_>, u64), mf::SourceError> {
        let bytes = self
            .0
            .get(path.as_str())
            .ok_or_else(|| mf::SourceError::MissingFile { path: path.clone() })?;
        Ok((Box::new(bytes.as_slice()), bytes.len() as u64))
    }
}

/// Identities over the fields T07 binds, under test domains: the importer's identity port
/// only needs them to be stable and distinct.
struct ListingIdentities;

impl ListingIdentities {
    fn source_for(listing: &mf::SourceListing) -> mf::SourceIdentity {
        let files = listing.sorted_files();
        let builder = DigestBuilder::new("yougori/test/gpu-scenarios/source-identity/v1")
            .str(&format!("{:?}", listing.origin))
            .str(&format!("{:?}", listing.revision));
        mf::SourceIdentity(
            files
                .iter()
                .fold(builder, |builder, file| {
                    builder
                        .str(file.path.as_str())
                        .u64(file.length_bytes)
                        .digest(file.content.digest())
                })
                .finish(),
        )
    }

    fn execution_for(
        source: &mf::SourceIdentity,
        abi: &mf::ExecutionAbi,
        distribution: &mf::Distribution,
    ) -> mf::ExecutionIdentity {
        mf::ExecutionIdentity(
            DigestBuilder::new("yougori/test/gpu-scenarios/execution-identity/v1")
                .digest(&source.0)
                .str(&format!("{abi:?}"))
                .str(&format!("{distribution:?}"))
                .finish(),
        )
    }
}

impl mf::ModelIdentities for ListingIdentities {
    type Context = ();

    fn source_identity(
        &self,
        listing: &mf::SourceListing,
        _configuration: &Digest,
        _context: &(),
    ) -> Result<mf::SourceIdentity, mf::IdentityError> {
        Ok(Self::source_for(listing))
    }

    fn execution_identity(
        &self,
        source: &mf::SourceIdentity,
        manifest: &mf::ValidatedManifest,
        _context: &(),
    ) -> Result<mf::ExecutionIdentity, mf::IdentityError> {
        let manifest = manifest.manifest();
        Ok(Self::execution_for(
            source,
            &manifest.execution_abi,
            &manifest.distribution,
        ))
    }

    fn artifact_identity(&self, manifest: &mf::ManifestDigest) -> mf::ArtifactIdentity {
        mf::ArtifactIdentity(
            DigestBuilder::new("yougori/test/gpu-scenarios/artifact-identity/v1")
                .digest(&manifest.digest())
                .finish(),
        )
    }
}

/// Integrity extents of a fixed size, the last one shorter (T06's g_h tiling).
struct FixedTiles;

impl mf::ExtentPlanner for FixedTiles {
    fn integrity_extents(
        &self,
        logical_length_bytes: u64,
        integrity_extent_bytes: u64,
    ) -> Result<Vec<mf::ExtentSpan>, mf::ExtentPlanError> {
        if integrity_extent_bytes == 0 {
            return Err(mf::ExtentPlanError::Refused);
        }
        let mut spans = Vec::new();
        let mut offset_bytes = 0;
        while offset_bytes < logical_length_bytes {
            let true_length_bytes = integrity_extent_bytes.min(logical_length_bytes - offset_bytes);
            spans.push(mf::ExtentSpan {
                offset_bytes,
                true_length_bytes,
            });
            offset_bytes += true_length_bytes;
        }
        Ok(spans)
    }
}

fn token(text: &str) -> mf::Token {
    mf::Token::new(text).unwrap()
}

fn manifest_path(text: &str) -> mf::RelativePath {
    mf::RelativePath::new(text).unwrap()
}

fn tensor_name(text: &str) -> mf::TensorName {
    mf::TensorName::new(text).unwrap()
}

/// The execution ABI of a vLLM 0.31.0 Llama checkpoint in its original layout.
fn execution_abi() -> mf::ExecutionAbi {
    mf::ExecutionAbi {
        runner: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
        architecture_adapter: mf::VersionedName {
            name: token("LlamaForCausalLM"),
            version: token("1"),
        },
        layout: token("original"),
        kernels: Vec::new(),
        hardware: mf::HardwareRestriction::Unrestricted,
    }
}

fn artifact_description(integrity_extent_bytes: u64) -> mf::ArtifactDescription {
    mf::ArtifactDescription {
        bounds: mf::ManifestBounds::DEFAULT,
        compute_dtype: mf::ElementType::Bf16,
        quantization: mf::Quantization::None,
        adapters: Vec::new(),
        execution_abi: execution_abi(),
        distribution: mf::Distribution::SINGLE,
        integrity_extent_bytes,
    }
}

/// A safetensors file holding `tensors` in order, its header padded with spaces to a
/// multiple of eight bytes as the reference writer does.
fn safetensors_file(tensors: &[(&str, &str, &[u64], &[u8])]) -> Vec<u8> {
    let mut header = serde_json::Map::new();
    header.insert(
        "__metadata__".to_owned(),
        serde_json::json!({ "format": "pt" }),
    );
    let mut data = Vec::new();
    for (name, dtype, shape, bytes) in tensors {
        let begin = data.len();
        data.extend_from_slice(bytes);
        header.insert(
            (*name).to_owned(),
            serde_json::json!({ "dtype": dtype, "shape": shape, "data_offsets": [begin, data.len()] }),
        );
    }
    let mut json = serde_json::to_vec(&header).unwrap();
    while !json.len().is_multiple_of(8) {
        json.push(b' ');
    }
    let mut file = (json.len() as u64).to_le_bytes().to_vec();
    file.extend_from_slice(&json);
    file.extend_from_slice(&data);
    file
}

/// A small model folder: configuration, tokenizer and one safetensors file.
fn model_files(seed: u64) -> BTreeMap<String, Vec<u8>> {
    let weights = safetensors_file(&[
        (
            "model.embed_tokens.weight",
            "F32",
            &[4, 4],
            &payload(seed, 64),
        ),
        ("model.norm.weight", "BF16", &[4], &payload(seed + 1, 8)),
    ]);
    BTreeMap::from([
        (
            "config.json".to_owned(),
            br#"{"architectures":["LlamaForCausalLM"],"hidden_size":4}"#.to_vec(),
        ),
        (
            "tokenizer.json".to_owned(),
            br#"{"model":{"type":"BPE","vocab":{}}}"#.to_vec(),
        ),
        ("model.safetensors".to_owned(), weights),
    ])
}

fn listing_of(files: &BTreeMap<String, Vec<u8>>) -> mf::SourceListing {
    let listed: Vec<mf::ListedFile> = files
        .iter()
        .map(|(path, bytes)| mf::ListedFile {
            path: manifest_path(path),
            length_bytes: bytes.len() as u64,
            content: ContentKey::of(bytes),
            role: match path.as_str() {
                "config.json" => mf::FileRole::Configuration,
                "tokenizer.json" => mf::FileRole::Tokenizer,
                _ => mf::FileRole::Weights {
                    format: mf::WeightFormat::Safetensors,
                    rank: None,
                },
            },
        })
        .collect();
    mf::SourceListing {
        origin: mf::SourceOrigin::LocalFolder,
        revision: mf::SourceListing::content_revision(&listed),
        files: listed,
    }
}

/// The importer's request for `files`, keyed by the listing identities.
fn sidecar_request<C>(files: &BTreeMap<String, Vec<u8>>, catalog: C) -> mf::ImportRequest<(), C> {
    let listing = listing_of(files);
    let description = artifact_description(16);
    let source = ListingIdentities::source_for(&listing);
    let execution = ListingIdentities::execution_for(
        &source,
        &description.execution_abi,
        &description.distribution,
    );
    mf::ImportRequest {
        key: mf::ImportKey { source, execution },
        listing,
        description,
        state: mf::StateGroup::default(),
        aliases: Vec::new(),
        owners: Vec::new(),
        identity: (),
        catalog,
    }
}

/// A sidecar catalog over the committed CORE-02 catalog whose durable commit hits a full
/// disk: every other call goes to the real adapter, so the catalog's own import, quota
/// reservation and cancellation run unchanged. Only the disk is faked.
struct FullDiskAtCommit {
    inner: mf::CatalogArtifacts,
    scope: Scope,
    reserved_at_commit: Mutex<Option<u64>>,
}

impl mf::ArtifactCatalog for FullDiskAtCommit {
    type Context = mf::CatalogContext;

    fn published(
        &self,
        key: &mf::ImportKey,
        context: &mf::CatalogContext,
    ) -> Result<Option<mf::PublishedArtifact>, mf::CatalogError> {
        self.inner.published(key, context)
    }

    fn begin_staging(
        &self,
        key: &mf::ImportKey,
        reserved_bytes: u64,
        context: &mf::CatalogContext,
    ) -> Result<mf::StagingId, mf::CatalogError> {
        self.inner.begin_staging(key, reserved_bytes, context)
    }

    fn write_staged(
        &self,
        staging: mf::StagingId,
        sidecar: &[u8],
        artifact: &mf::PublishedArtifact,
    ) -> Result<(), mf::CatalogError> {
        self.inner.write_staged(staging, sidecar, artifact)
    }

    fn read_staged(
        &self,
        staging: mf::StagingId,
        max_bytes: u64,
    ) -> Result<Vec<u8>, mf::CatalogError> {
        self.inner.read_staged(staging, max_bytes)
    }

    fn commit(&self, _staging: mf::StagingId) -> Result<(), mf::CatalogError> {
        let reserved = self.inner.catalog().quota_usage(&self.scope).reserved_bytes;
        *lock(&self.reserved_at_commit) = Some(reserved);
        Err(mf::CatalogError::Storage {
            kind: std::io::ErrorKind::StorageFull,
        })
    }

    fn publish(&self, staging: mf::StagingId) -> Result<mf::PublishedArtifact, mf::CatalogError> {
        self.inner.publish(staging)
    }

    fn discard(&self, staging: mf::StagingId) -> Result<(), mf::CatalogError> {
        self.inner.discard(staging)
    }
}

/// Imports `bytes` into `catalog` as an original of `scope` and returns its object.
fn publish_original(
    catalog: &mut Catalog,
    scope: &Scope,
    by: &str,
    path: &str,
    bytes: &[u8],
) -> ObjectId {
    let manifest = ImportManifest::describe(bytes, NonZeroU64::new(CATALOG_EXTENT).unwrap());
    let object = ObjectId::new(scope, ArtifactClass::ModelWeights, manifest.content_key);
    let mut source = MemorySource::new(path, bytes);
    let request = CatalogImport {
        operation: operation("op-original"),
        execution: execution(by),
        scope: scope.clone(),
        class: ArtifactClass::ModelWeights,
        role: ObjectRole::Original,
        manifest,
        trust: TrustClaim::UserSelected,
        depends_on: BTreeSet::new(),
        metadata: ObjectMetadata::new(),
    };
    let ticket = ticket_of(catalog.begin_import(request, source.identity()).unwrap());
    let status = catalog
        .drive_import(&ticket, &mut source, &mut Uninterrupted)
        .unwrap();
    assert!(matches!(status, ImportStatus::Published { object: seen, .. } if seen == object));
    catalog.cancel_import(ticket);
    object
}

/// Reads `object` whole through a lease and a read-only handle, as a consumer does.
fn read_object(
    catalog: &mut Catalog,
    reader: &Scope,
    by: &str,
    object: ObjectId,
) -> Result<Vec<u8>, String> {
    let lease = catalog
        .acquire_lease(reader, &execution(by), object, MINUTE)
        .map_err(|refusal| format!("{refusal:?}"))?;
    let mut handle = catalog
        .open_read(reader, &execution(by), lease)
        .map_err(|refusal| format!("{refusal:?}"))?;
    handle.read_all().map_err(|error| format!("{error:?}"))
}

/// GPU-T12 (line 1294): disk full during conversion or download; originals are preserved,
/// reservations released and the error is actionable.
///
/// A download that does not fit the scope's budget is refused before a byte is written:
/// the refusal names the budget, what is charged, what was asked and what cache eviction
/// could free (never the original), and leaves a failure record. A conversion whose
/// durable commit hits a full disk (the manifest importer over the committed catalog
/// adapter, with the disk failure injected at the commit) discards its temporary area:
/// the catalog's sidecar reservation is released, nothing is published, and the
/// originals stay published and byte-identical. Not covered: a real `ENOSPC` from the
/// filesystem mid-write, which a test cannot provoke without a fake filesystem.
#[test]
fn gpu_t12_disk_full_preserves_originals_and_releases_reservations() {
    let clock = test_clock();
    let mut store = Store::open(&clock, &["tenant-a"], 6 * CATALOG_EXTENT);
    let scope = Scope::tenant(tenant("tenant-a"));
    let original = payload(12, 4 * CATALOG_EXTENT as usize);
    let kept = publish_original(store.catalog(), &scope, "exe-a", "kept", &original);
    let bigger = payload(13, 4 * CATALOG_EXTENT as usize);
    let (request, identity) = weights_import("tenant-a", "exe-a", "download", &bigger);
    let refusal = store.catalog().begin_import(request, identity).unwrap_err();
    let ImportRefusal::Quota {
        refusal:
            QuotaRefusal::Exceeded {
                limit_bytes,
                charged_bytes,
                requested_bytes,
                evictable_bytes,
                ..
            },
    } = &refusal
    else {
        panic!("the download is refused for its budget: {refusal:?}");
    };
    assert_eq!(
        (
            *limit_bytes,
            *charged_bytes,
            *requested_bytes,
            *evictable_bytes
        ),
        (384, 256, 256, 0),
        "an original is never counted as evictable"
    );
    let message = refusal.to_string();
    assert!(message.contains("384") && message.contains("raise the budget"));
    assert_eq!(store.view().quota_usage(&scope).reserved_bytes, 0);
    assert!(store.view().failures_in(&scope).any(|record| matches!(
        record.reason,
        crate::foundation::catalog::FailureReason::Refused { .. }
    )));
    assert_eq!(
        read_object(store.catalog(), &scope, "exe-a", kept).unwrap(),
        original
    );

    let dir = tempfile::tempdir().unwrap();
    let mut verifiers = VerifierRegistry::new();
    verifiers.register(Box::new(WeightsVerifier)).unwrap();
    let config = CatalogConfig::new(MINUTE)
        .with_quota(scope.clone(), MIB)
        .with_trust(
            ArtifactClass::ModelWeights,
            TrustPolicy::new().accept_user_selected(),
        )
        .with_trust(
            ArtifactClass::ModelSidecar,
            TrustPolicy::new().accept_user_selected(),
        );
    let (adapter, _) = mf::CatalogArtifacts::open(
        dir.path(),
        config,
        verifiers,
        Arc::clone(&clock) as Arc<dyn Clock>,
        mf::ImportLimits::DEFAULT.max_sidecar_bytes,
    )
    .unwrap();
    let files = model_files(14);
    let originals: Vec<ObjectId> = files
        .iter()
        .map(|(path, bytes)| publish_original(&mut adapter.catalog(), &scope, "exe-a", path, bytes))
        .collect();
    let catalog = FullDiskAtCommit {
        inner: adapter,
        scope: scope.clone(),
        reserved_at_commit: Mutex::new(None),
    };
    let request = sidecar_request(
        &files,
        mf::CatalogContext {
            scope: scope.clone(),
            execution: execution("exe-a"),
            operation: operation("op-sidecar"),
            trust: TrustClaim::UserSelected,
            dependencies: BTreeMap::new(),
        },
    );
    let importer = mf::Importer::new(
        catalog,
        ListingIdentities,
        FixedTiles,
        mf::ImportLimits::DEFAULT,
    );
    let error = importer
        .import(
            &request,
            &MemoryFiles(files.clone()),
            &mf::CancellationToken::new(),
        )
        .unwrap_err();
    assert!(matches!(
        error,
        mf::ImportError::Catalog {
            error: mf::CatalogError::Storage {
                kind: std::io::ErrorKind::StorageFull
            },
            ..
        }
    ));
    assert!(!error.to_string().is_empty());
    let catalog = importer.catalog();
    assert!(
        lock(&catalog.reserved_at_commit).is_some_and(|bytes| bytes > 0),
        "the sidecar was reserved when the disk filled"
    );
    assert!(!importer.in_flight(&request.key));
    let mut objects = catalog.inner.catalog();
    assert_eq!(objects.quota_usage(&scope).reserved_bytes, 0, "released");
    for (object, (path, bytes)) in originals.iter().zip(&files) {
        assert_eq!(
            objects.status(&scope, *object),
            ObjectStatus::Published,
            "{path} is preserved"
        );
        assert_eq!(
            read_object(&mut objects, &scope, "exe-a", *object).unwrap(),
            *bytes
        );
    }
    let sidecars = objects
        .objects(&scope)
        .into_iter()
        .filter(|object| {
            objects
                .private_metadata(&scope, *object)
                .is_ok_and(|private| private.class == ArtifactClass::ModelSidecar)
        })
        .count();
    assert_eq!(sidecars, 0, "nothing was published");
}

/// Every file under `dir` whose bytes are exactly `bytes`.
fn files_holding(dir: &Path, bytes: &[u8]) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                found.extend(files_holding(&path, bytes));
            } else if std::fs::read(&path).is_ok_and(|content| content == bytes) {
                found.push(path);
            }
        }
    }
    found
}

/// GPU-T13 (line 1295): a consumer attempts a cache write; the read-only boundary blocks
/// it.
///
/// A consumer reaches committed bytes only through a lease and a read-only handle, which
/// has no write operation, and the committed data file is read-only on disk. A consumer
/// that forces a write anyway (the read-only flag cleared and a byte flipped, standing
/// for a compromised process) is never served the altered bytes: the handle's
/// per-extent verification refuses them, and the owner's verification quarantines the
/// object and refuses every new read. Not covered: OS-level enforcement against a
/// process with the rights to change file permissions, which only a sandbox boundary
/// (VM part) provides.
#[test]
fn gpu_t13_a_consumer_cannot_write_the_shared_cache() {
    let clock = test_clock();
    let mut store = Store::open(&clock, &["tenant-a", "tenant-b"], MIB);
    let owner = Scope::tenant(tenant("tenant-a"));
    let consumer = Scope::tenant(tenant("tenant-b"));
    let bytes = payload(130, 4 * CATALOG_EXTENT as usize);
    let object = publish_original(store.catalog(), &owner, "exe-a", "weights", &bytes);
    let expires_at = clock.now().saturating_add(HOUR);
    store
        .catalog()
        .grant(
            &owner,
            GrantRequest {
                object,
                grantee: consumer.clone(),
                execution: Some(execution("exe-b")),
                expires_at,
            },
        )
        .unwrap();
    let lease = store
        .catalog()
        .acquire_lease(&consumer, &execution("exe-b"), object, MINUTE)
        .unwrap();
    let mut handle = store
        .catalog()
        .open_read(&consumer, &execution("exe-b"), lease)
        .unwrap();
    assert_eq!(handle.read_all().unwrap(), bytes);

    let committed = files_holding(store.dir.path(), &bytes);
    assert_eq!(committed.len(), 1, "one committed copy");
    let data = &committed[0];
    assert!(std::fs::metadata(data).unwrap().permissions().readonly());

    make_writable(data);
    let mut altered = bytes.clone();
    altered[CATALOG_EXTENT as usize + 3] ^= 0x01;
    std::fs::write(data, &altered).unwrap();
    assert!(matches!(
        handle.read_all(),
        Err(ReadError::ExtentCorrupt { extent: 1 })
    ));
    assert!(matches!(
        store.catalog().verify_object(&owner, object),
        Err(VerifyError::Quarantined { .. })
    ));
    assert!(matches!(
        store.view().status(&owner, object),
        ObjectStatus::Quarantined { .. }
    ));
    assert!(matches!(
        store
            .catalog()
            .acquire_lease(&consumer, &execution("exe-b"), object, MINUTE),
        Err(ReadRefusal::Quarantined { .. })
    ));
}

// ---------------------------------------------------------------------------------------
// Identity fixtures: T07 source, logical and execution identities.
// ---------------------------------------------------------------------------------------

const COMMIT_A: &str = "0123456789abcdef0123456789abcdef01234567";
const COMMIT_B: &str = "89abcdef0123456789abcdef0123456789abcdef";

fn label(value: &str) -> Label {
    Label::new(value).unwrap()
}

fn versioned(name: &str, version: &str) -> VersionedName {
    VersionedName::new(name, version).unwrap()
}

/// The T07 source identity of `repository` at `commit` whose weights file holds `weights`.
fn hub_source(repository: &str, commit: &str, weights: &[u8]) -> SourceIdentity {
    SourceSpec {
        location: SourceLocation::Repository {
            host: label("huggingface.co"),
            repository: label(repository),
        },
        revision: ImmutableRevision::Commit(CommitId::new(commit).unwrap()),
        files: vec![SourceFile {
            path: RelativePath::new("model.safetensors").unwrap(),
            length_bytes: weights.len() as u64,
            content: ContentKey::of(weights),
        }],
        configuration: named("configuration", repository),
        published_dtype: Dtype::BFloat16,
        license: label("apache-2.0"),
        provenance: None,
    }
    .identity()
    .unwrap()
}

fn logical_of(source: SourceIdentity, tokenizer: &str) -> LogicalModelSpec {
    LogicalModelSpec {
        source,
        dtype: Dtype::BFloat16,
        quantization: Quantization::None,
        tokenizer: named("tokenizer", tokenizer),
        generation_config: named("generation", "default"),
        adapters: AdapterRecipe::None,
        code_policy: CodePolicy::BuiltInOnly,
    }
}

/// The execution identity of `logical` over `tensor_parallel` ranks with `kernels`.
fn execution_of(
    logical: &LogicalModelSpec,
    tensor_parallel: u32,
    kernels: &str,
) -> ExecutionIdentity {
    ExecutionSpec {
        logical: logical.identity(),
        runner: versioned("vllm", "0.31.0"),
        architecture_adapter: versioned("llama", "1"),
        kernel_layout: versioned(kernels, "1"),
        gpu_architectures: BTreeSet::from([label("sm_90a")]),
        topology: RankTopology::new(tensor_parallel, 1, 1).unwrap(),
        processed_weights: versioned("vllm-bf16", "1"),
        compile: CompileConfiguration::Eager,
    }
    .identity()
    .unwrap()
}

fn rope(theta: &str) -> PositionalEncoding {
    PositionalEncoding {
        scheme: versioned("rope", "1"),
        parameters: named("rope", theta),
    }
}

fn session_authority(name: &str) -> AuthorityBinding {
    AuthorityBinding::new(
        execution(&format!("exe-{name}")),
        ExecutionCategory::VmSandbox,
        Some(AuthorizationEpoch::FIRST),
    )
    .unwrap()
}

fn paged_kv() -> KvRepresentation {
    KvRepresentation::new(
        Dtype::BFloat16,
        Quantization::None,
        16,
        versioned("paged", "1"),
    )
    .unwrap()
}

/// The FAST-03 scope of KV computed by `model` for `owner`.
fn kv_scope(model: ExecutionIdentity, tokenizer: &str, theta: &str, owner: &str) -> KvScopeSpec {
    KvScopeSpec {
        model,
        tokenizer: named("tokenizer", tokenizer),
        adapter: None,
        prefix: TokenPrefix::from_token_ids(&[101, 2023, 2003, 1037]),
        position: KvPosition {
            encoding: rope(theta),
            first_position: 0,
        },
        cache: paged_kv(),
        authority: KvAuthority {
            tenant: tenant(owner),
            session: session_authority(owner),
        },
    }
}

/// Scope enforcement shown by CORE-01 evidence a probe registry evaluated (T07's fixture).
fn verified_enforcement() -> ScopeEnforcement {
    scope_enforcement(MonotonicTime::ZERO, HOUR)
}

// ---------------------------------------------------------------------------------------
// GPU-T05, GPU-T06, GPU-T40, GPU-T41: identities, sessions and KV.
// ---------------------------------------------------------------------------------------

/// GPU-T05 (line 1287): same name, changed revision; a new identity and no stale weights.
///
/// Two commits of one repository name give different source, logical and execution
/// identities. The CORE-02 catalog keys objects by content, so the first revision's
/// published weights never answer a lookup for the second, and a resident advertisement
/// of the first revision is refused for a request that requires the second.
#[test]
fn gpu_t05_a_changed_revision_gets_a_new_identity_and_no_stale_weights() {
    let old_bytes = payload(50, 4 * CATALOG_EXTENT as usize);
    let new_bytes = payload(51, 4 * CATALOG_EXTENT as usize);
    let old_source = hub_source("example-org/chat", COMMIT_A, &old_bytes);
    let new_source = hub_source("example-org/chat", COMMIT_B, &new_bytes);
    let same_bytes_new_commit = hub_source("example-org/chat", COMMIT_B, &old_bytes);
    assert_ne!(old_source, new_source);
    assert_ne!(
        old_source, same_bytes_new_commit,
        "the revision alone changes it"
    );
    let old_logical = logical_of(old_source, "llama-tokenizer");
    let new_logical = logical_of(new_source, "llama-tokenizer");
    assert_ne!(old_logical.identity(), new_logical.identity());
    let old_execution = execution_of(&old_logical, 1, "flash-attn");
    let new_execution = execution_of(&new_logical, 1, "flash-attn");
    assert_ne!(old_execution, new_execution);

    let clock = test_clock();
    let mut store = Store::open(&clock, &["tenant-a"], MIB);
    let scope = Scope::tenant(tenant("tenant-a"));
    let old_object = publish_original(store.catalog(), &scope, "exe-a", "chat", &old_bytes);
    assert_eq!(
        store.view().find(
            &scope,
            ArtifactClass::ModelWeights,
            ContentKey::of(&new_bytes)
        ),
        None,
        "the old revision's weights never answer for the new one"
    );
    let new_object = publish_original(store.catalog(), &scope, "exe-a", "chat", &new_bytes);
    assert_ne!(old_object, new_object);

    let owner = tenant("tenant-a");
    let trust = TrustScope::named(ExecutionCategory::VmSandbox, "models");
    let residency = Residency {
        execution: old_execution,
        artifact: ArtifactIdentity::from_manifest_digest(&named("manifest", "chat-a")),
        owner: owner.clone(),
        scope: trust,
        device: gpu(0),
        authority: session_authority("tenant-a"),
    };
    let advertisement = ResidentAdvertisement {
        residency: residency.clone(),
        generation: ModelActivationGeneration::FIRST,
        expires_at: clock.now().saturating_add(MINUTE),
    };
    let current = CurrentResidency {
        residency: residency.clone(),
        generation: ModelActivationGeneration::FIRST,
    };
    let grant = checked_grant(
        &execution("exe-tenant-a"),
        GrantTerms {
            grantor: owner.clone(),
            grantee: owner.clone(),
            artifact: residency.artifact,
            scope: trust,
            uses: BTreeSet::from([GrantedUse::Serve]),
            expires_at: clock.now().saturating_add(HOUR),
        },
    );
    let request = |required| AdvertisementRequest {
        requester: owner.clone(),
        required,
        purpose: AdvertisementPurpose::Serve,
    };
    assert!(advertisement
        .recheck(&current, &request(old_execution), Some(&grant), &*clock)
        .is_ok());
    assert_eq!(
        advertisement.recheck(&current, &request(new_execution), Some(&grant), &*clock),
        Err(AdvertisementRefusal::Incompatible)
    );
}

/// GPU-T06 (line 1288): same weights with another tokenizer, RoPE or adapter; no invalid
/// session or execution reuse.
///
/// Identical source bytes under another tokenizer give another logical and execution
/// identity. A session under other RoPE parameters or another adapter has another
/// session identity, the FAST-03 KV scope names the differing component, an engine
/// profile refuses the KV, and a captured graph of the first execution is refused for
/// the second.
#[test]
fn gpu_t06_another_tokenizer_rope_or_adapter_never_reuses_sessions_or_executions() {
    let weights = payload(60, 256);
    let source = hub_source("example-org/chat", COMMIT_A, &weights);
    let base = logical_of(source, "tokenizer-a");
    let retokenized = logical_of(source, "tokenizer-b");
    assert_ne!(base.identity(), retokenized.identity());
    let model = execution_of(&base, 1, "flash-attn");
    let other_model = execution_of(&retokenized, 1, "flash-attn");
    assert_ne!(model, other_model);

    let adapter = AdapterSpec {
        source: hub_source("example-org/chat-lora", COMMIT_A, b"lora"),
        method: versioned("lora", "1"),
        dtype: Dtype::BFloat16,
    }
    .identity();
    let session = |theta: &str, adapter: Option<AdapterIdentity>| {
        SessionSpec {
            execution: model,
            state: TokenState::Prefix(TokenPrefix::from_token_ids(&[1, 2, 3])),
            adapter,
            positional_encoding: rope(theta),
            kv: paged_kv(),
            tenant: tenant("tenant-a"),
            authority: session_authority("tenant-a"),
        }
        .identity()
    };
    let original = session("theta-1e4", None);
    assert_ne!(original, session("theta-1e6", None));
    assert_ne!(original, session("theta-1e4", Some(adapter)));

    let stored = kv_scope(model, "tokenizer-a", "theta-1e4", "tenant-a");
    let enforcement = verified_enforcement();
    let cases = [
        (
            KvScopeSpec {
                tokenizer: named("tokenizer", "tokenizer-b"),
                ..stored.clone()
            },
            vec![KvScopeComponent::Tokenizer],
        ),
        (
            KvScopeSpec {
                position: KvPosition {
                    encoding: rope("theta-1e6"),
                    first_position: 0,
                },
                ..stored.clone()
            },
            vec![KvScopeComponent::Position],
        ),
        (
            KvScopeSpec {
                adapter: Some(adapter),
                ..stored.clone()
            },
            vec![KvScopeComponent::Adapter],
        ),
        (
            KvScopeSpec {
                model: other_model,
                tokenizer: named("tokenizer", "tokenizer-b"),
                ..stored.clone()
            },
            vec![KvScopeComponent::Model, KvScopeComponent::Tokenizer],
        ),
    ];
    for (request, differing) in cases {
        assert_eq!(
            check_kv_reuse(&stored, &request, &enforcement),
            Err(KvReuseRefusal::ScopeMismatch {
                components: differing
            })
        );
    }
    assert!(check_kv_reuse(&stored, &stored, &enforcement).is_ok());

    let engine = EngineKvProfile {
        model,
        tokenizer: named("tokenizer", "tokenizer-a"),
        positional_encoding: rope("theta-1e6"),
        cache: paged_kv(),
        attention_semantics: named("attention", "causal"),
        rank: RankPosition::new(0, 1).unwrap(),
        reuses_prefix_kv: true,
        enforcement,
    };
    let kv = KvReuseSpec {
        scope: stored,
        attention_semantics: named("attention", "causal"),
        rank: RankPosition::new(0, 1).unwrap(),
    };
    assert!(!engine.can_use(&kv), "another RoPE never reads this KV");

    let capture = |execution| GraphCaptureSpec {
        execution,
        device: gpu(0),
        shape: CaptureShape {
            sequences: 1,
            tokens: 128,
        },
        resources: vec![IdGraphResource {
            role: label("weights"),
            kind: GraphResourceKind::Weights,
            content: named("weights", "chat"),
            allocation: GpuAllocationGeneration::FIRST,
            device_address: 0x7000_0000,
            length_bytes: 256,
            layout: label("row-major"),
        }],
    };
    assert_eq!(
        capture(model).check_reuse(&capture(other_model)),
        Err(GraphReuseRefusal::Mismatch {
            differences: vec![GraphDifference::Execution]
        })
    );
}

/// The adapters module's KV fixture: KV of `owner` for `model` over `tokens` tokens of
/// `prefix`, optionally under `adapter`.
fn stored_kv(
    model: ExecutionIdentity,
    adapter: Option<AdapterIdentity>,
    prefix: &str,
    owner: &str,
) -> StoredKv {
    StoredKv {
        spec: kv_fixtures::kv_spec(model, adapter, 512, prefix, owner),
        trust_scope: kv_fixtures::trust(),
        sharing: KvSharing::TenantScoped,
    }
}

/// GPU-T40 (line 1322): KV of another tenant, adapter or prefix; reuse is denied and the
/// state is recomputed or loaded correctly.
///
/// Stored KV is refused for another tenant (tenant and session authority differ), another
/// adapter, another prefix and another trust scope, so no reuse grant exists for it and
/// no transfer of it can be offered. The placement decision then recomputes the
/// requester's own exact prefix where that is authorized under the current epoch, and
/// reports the state as lost (to be loaded or rebuilt from the request) where it is not.
#[test]
fn gpu_t40_foreign_kv_is_never_reused_and_the_own_state_is_recomputed() {
    let model = kv_fixtures::execution_identity("base");
    let stored = stored_kv(model, None, "system-prompt", "acme");
    let enforcement = kv_fixtures::verified();
    let sharing = PublicPrefixSharing::none();
    let standing = RevokedAuthorities::new();
    let now = kv_fixtures::NOW;
    let request = |spec: KvReuseSpec| KvRequest {
        spec,
        trust_scope: kv_fixtures::trust(),
    };

    let other_tenant = kv_fixtures::kv_spec(model, None, 512, "system-prompt", "globex");
    assert_eq!(
        adapter_kv_reuse(
            &stored,
            &request(other_tenant),
            &sharing,
            &standing,
            &enforcement,
            now
        ),
        Err(AdapterKvRefusal::Scope(KvReuseRefusal::ScopeMismatch {
            components: vec![KvScopeComponent::Tenant, KvScopeComponent::SessionAuthority]
        }))
    );
    let other_adapter = kv_fixtures::kv_spec(
        model,
        Some(kv_fixtures::adapter_identity("legal")),
        512,
        "system-prompt",
        "acme",
    );
    assert_eq!(
        adapter_kv_reuse(
            &stored,
            &request(other_adapter),
            &sharing,
            &standing,
            &enforcement,
            now
        ),
        Err(AdapterKvRefusal::Scope(KvReuseRefusal::ScopeMismatch {
            components: vec![KvScopeComponent::Adapter]
        }))
    );
    let other_prefix = kv_fixtures::kv_spec(model, None, 512, "another-prompt", "acme");
    assert_eq!(
        adapter_kv_reuse(
            &stored,
            &request(other_prefix.clone()),
            &sharing,
            &standing,
            &enforcement,
            now
        ),
        Err(AdapterKvRefusal::Scope(KvReuseRefusal::ScopeMismatch {
            components: vec![KvScopeComponent::Prefix]
        }))
    );
    let elsewhere = KvRequest {
        spec: stored.spec.clone(),
        trust_scope: TrustScope::named(ExecutionCategory::VmSandbox, "other-models"),
    };
    assert_eq!(
        adapter_kv_reuse(&stored, &elsewhere, &sharing, &standing, &enforcement, now),
        Err(AdapterKvRefusal::Scope(KvReuseRefusal::OtherTrustScope))
    );

    let own = StoredKv {
        spec: other_prefix,
        trust_scope: kv_fixtures::trust(),
        sharing: KvSharing::TenantScoped,
    };
    let requirement = KvRequirement {
        state_identity: kv_state_key(&own),
        prefix_identity: named("prefix", "another-prompt"),
        current_epoch: AuthorizationEpoch::new(2),
    };
    let recompute = |epoch: u64| MoveToTarget {
        target_queue_seconds: 0.5,
        serve_seconds: 1.0,
        transfer: None,
        recompute: Some(KvRecomputeEstimate {
            held_prefix: Some(named("prefix", "another-prompt")),
            produces_state: kv_state_key(&own),
            authorized_epoch: Some(AuthorizationEpoch::new(epoch)),
            prefix_tokens: 512,
            prefill_tokens_per_second: 1_024.0,
        }),
    };
    let decision = decide_kv_placement(&requirement, None, Some(&recompute(2))).unwrap();
    assert_eq!(decision.placement, KvPlacement::Recompute);
    assert_eq!(decision.completion_seconds, 0.5 + 0.5 + 1.0);
    assert_eq!(
        decide_kv_placement(&requirement, None, Some(&recompute(1))),
        Err(KvPlacementError::NoOption {
            recompute_refusal: Some(RecomputeRefusal::NotAuthorized)
        }),
        "a recomputation authorized under an older epoch never stands in"
    );
}

/// GPU-T41 (line 1323): KV transfer slower than exact recompute; the valid cheaper path is
/// chosen with queues counted.
///
/// 8 GiB over a 1 GiB/s link after a 2 s link queue arrives at 10 s; recomputing 4,096
/// prefix tokens at 2,048 tokens/s on a target with a 1 s queue is ready at 3 s, so the
/// request is recomputed. With a 20 s target queue the transfer arrives before the queue
/// clears and wins. A recomputation that would not produce the exact state is never
/// chosen however fast, and on equal completion the request stays where it is.
#[test]
fn gpu_t41_the_cheaper_valid_restore_wins_with_queues_counted() {
    let model = kv_fixtures::execution_identity("base");
    let kv = stored_kv(model, None, "long-prompt", "acme");
    let state = kv_state_key(&kv);
    let enforcement = kv_fixtures::verified();
    let grant = adapter_kv_reuse(
        &kv,
        &KvRequest {
            spec: kv.spec.clone(),
            trust_scope: kv_fixtures::trust(),
        },
        &PublicPrefixSharing::none(),
        &RevokedAuthorities::new(),
        &enforcement,
        kv_fixtures::NOW,
    )
    .unwrap();
    let requirement = KvRequirement {
        state_identity: state,
        prefix_identity: named("prefix", "long-prompt"),
        current_epoch: AuthorizationEpoch::FIRST,
    };
    let target = |queue: f64, produces: Digest| MoveToTarget {
        target_queue_seconds: queue,
        serve_seconds: 1.0,
        transfer: Some(KvTransferEstimate {
            grant: grant.clone(),
            kv_bytes: 8 * GIB,
            link_bytes_per_second: GIB as f64,
            link_queue_seconds: 2.0,
        }),
        recompute: Some(KvRecomputeEstimate {
            held_prefix: Some(named("prefix", "long-prompt")),
            produces_state: produces,
            authorized_epoch: Some(AuthorizationEpoch::FIRST),
            prefix_tokens: 4_096,
            prefill_tokens_per_second: 2_048.0,
        }),
    };
    let short_queue = decide_kv_placement(&requirement, None, Some(&target(1.0, state))).unwrap();
    assert_eq!(short_queue.placement, KvPlacement::Recompute);
    assert_eq!(
        short_queue.recompute_completion_seconds,
        Some(1.0 + 2.0 + 1.0)
    );
    assert_eq!(short_queue.transfer_completion_seconds, Some(10.0 + 1.0));

    let long_queue = decide_kv_placement(&requirement, None, Some(&target(20.0, state))).unwrap();
    assert_eq!(long_queue.placement, KvPlacement::Transfer);
    assert_eq!(long_queue.completion_seconds, 20.0 + 1.0);

    let wrong_state = decide_kv_placement(
        &requirement,
        None,
        Some(&target(1.0, named("kv-state", "another model"))),
    )
    .unwrap();
    assert_eq!(wrong_state.placement, KvPlacement::Transfer);
    assert_eq!(
        wrong_state.recompute_refusal,
        Some(RecomputeRefusal::NotSemanticallyIdentical)
    );

    let stay = StayOnCurrent {
        grant: grant.clone(),
        queue_seconds: 3.0,
        serve_seconds: 1.0,
    };
    let tie = decide_kv_placement(&requirement, Some(&stay), Some(&target(1.0, state))).unwrap();
    assert_eq!(tie.placement, KvPlacement::Stay, "moving adds work");
}

// ---------------------------------------------------------------------------------------
// GPU-T08, GPU-T20, GPU-T21, GPU-T36 to GPU-T39: the transfer path.
// ---------------------------------------------------------------------------------------

/// GPU-T08 (line 1290): a truncated or corrupted extent is rejected before computation,
/// with a bounded retry from another source.
///
/// The CORE-02 importer pauses on a truncated source and on a source that keeps flipping
/// a byte, and publishes nothing. In the executor one source flips a byte and another
/// ends early: each attempt is rejected before any copy, the faulty sources are
/// blacklisted for the job, a third source supplies the extent, and the destination holds
/// exactly the verified bytes. When every source is corrupt the retries stop at the bound
/// and the dependency is never usable.
#[test]
fn gpu_t08_corrupt_or_truncated_extents_are_rejected_and_retried_within_bounds() {
    let clock = test_clock();
    let mut store = Store::open(&clock, &["tenant-a"], MIB);
    let scope = Scope::tenant(tenant("tenant-a"));
    let bytes = payload(80, 4 * CATALOG_EXTENT as usize);
    for (case, ends_at, flips) in [("truncated", Some(100), None), ("corrupt", None, Some(70))] {
        let (request, identity) = weights_import("tenant-a", "exe-a", case, &bytes);
        let ticket = ticket_of(store.catalog().begin_import(request, identity).unwrap());
        let mut source = MemorySource::new(case, &bytes);
        source.ends_at = ends_at;
        source.flips = flips;
        let status = store
            .catalog()
            .drive_import(&ticket, &mut source, &mut Uninterrupted)
            .unwrap();
        let ImportStatus::Pending {
            last_failure: Some(failure),
            ..
        } = status
        else {
            panic!("the {case} source is not published: {status:?}");
        };
        assert!(matches!(
            failure.reason,
            CatalogFailure::SourceFailed { .. } | CatalogFailure::ExtentDigestMismatch { .. }
        ));
        assert_eq!(
            store
                .view()
                .find(&scope, ArtifactClass::ModelWeights, ContentKey::of(&bytes)),
            None
        );
        store.catalog().cancel_import(ticket);
    }

    let transfers = Transfers::new(&clock);
    let weights = Weights::new("weights", &[16; 3], false);
    let sources = [
        local("s1"),
        candidate("s2", SourceKind::LocalFile, 1e8),
        candidate("s3", SourceKind::LocalFile, 1e7),
    ];
    transfers.publish(&weights, &sources);
    {
        let mut edge = transfers.edge();
        edge.corrupt.insert((source_id("s1"), 20));
        edge.truncate_at.insert(source_id("s2"), 20);
    }
    let mut executor = transfers.executor();
    let job = operation("load");
    executor
        .submit(load_job("load", "tenant-a", &weights, "slot"))
        .unwrap();
    transfers.drive(&mut executor);
    assert_eq!(executor.status(&job), Some(&JobStatus::Completed));
    let flight = executor.flight_of(&job, 1).unwrap();
    let attempts = executor.attempts(flight).unwrap();
    assert_eq!(attempts.len(), 2);
    assert!(matches!(
        attempts[0].failure,
        AttemptFailure::StoredMismatch { .. }
    ));
    assert!(matches!(
        attempts[1].failure,
        AttemptFailure::Truncated { .. }
    ));
    assert_eq!(
        executor.blacklist(&job).unwrap(),
        &BTreeSet::from([source_id("s1"), source_id("s2")])
    );
    assert_eq!(
        transfers.landed(&allocation("slot"), 0, 48),
        weights.decoded
    );

    let transfers = Transfers::new(&clock);
    transfers.publish(&weights, &sources);
    for name in ["s1", "s2", "s3"] {
        transfers.edge().corrupt.insert((source_id(name), 20));
    }
    let mut config = transfers.config();
    config.max_attempts = 2;
    let mut executor = transfers.executor_with(config);
    executor
        .submit(load_job("load", "tenant-a", &weights, "slot"))
        .unwrap();
    transfers.drive(&mut executor);
    let Some(JobStatus::Failed { failure }) = executor.status(&job) else {
        panic!("the extent fails at the bound");
    };
    assert_eq!(failure.extent, 1);
    assert!(matches!(
        &failure.failure,
        ExtentFailure::RetriesExhausted { attempts } if attempts.len() == 2
    ));
    assert!(!executor.is_usable(&job, DependencyId(1)));
    assert!(
        transfers.landed(&allocation("slot"), 16, 16) != weights.decoded[16..32].to_vec(),
        "the corrupt extent never lands"
    );
}

/// A loader plan from the real CORE-01 gate for `optimizations` on a vLLM 0.31.0 GPU
/// runtime, with evidence from a guest report when `evidence` is set.
fn loader_plan(
    clock: &TestClock,
    optimizations: &[(Optimization, Necessity)],
    evidence: bool,
) -> Result<LoaderPlan, LoaderRefusal> {
    planned(clock, optimizations, evidence).1
}

/// The runtime profile, the CORE-01 gate's plan for it and the live registry the plan was
/// made with.
fn planned(
    clock: &TestClock,
    optimizations: &[(Optimization, Necessity)],
    evidence: bool,
) -> (
    RuntimeProfile,
    Result<LoaderPlan, LoaderRefusal>,
    ProbeRegistry<TestClock>,
) {
    let mut registry = ProbeRegistry::new(Arc::clone(clock));
    let runtime = gpu_runtime();
    let subject = Subject::Runtime(runtime.clone());
    let configuration = driver_configuration("580.1");
    if evidence {
        for (optimization, _) in optimizations {
            let probe = FakeProbe::guest_report(optimization.capability());
            probe.respond(
                &subject,
                Observation::supported(configuration, HOUR, SupportDetail::Plain),
            );
            registry.register(Box::new(probe)).unwrap();
            registry
                .refresh(optimization.capability(), &subject)
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
                        max_age: HOUR,
                    },
                )
            })
            .collect(),
    };
    let request = LoaderRequest {
        optimizations: optimizations.iter().copied().collect(),
    };
    let plan = LoaderGate::recorded().plan(&profile, &request, &registry);
    (profile, plan, registry)
}

/// The P06 backend runtime of `profile` and `plan` on `platform`, with no queried sleep
/// levels or features.
fn backend_runtime(
    profile: &RuntimeProfile,
    plan: &LoaderPlan,
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

fn gpu_runtime() -> RuntimeSubject {
    RuntimeSubject {
        category: ExecutionCategory::SharedKernelGpuRuntime,
        release: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
        instance: named("instance", "gpu-runtime"),
    }
}

fn driver_configuration(driver: &str) -> ConfigurationFingerprint {
    ConfigurationFingerprint::from_settings([("driver", driver)]).unwrap()
}

/// A pinned tier on a host with `host_bytes` of RAM, a host-wide pinned cap of
/// `cap_bytes` and the WSL VM limit `wsl`.
fn pinned_tier(host_bytes: u64, cap_bytes: u64, wsl: WslLimit) -> PinnedHostTier {
    PinnedHostTier::new(PinnedLimits {
        host_ram: host_scope("host-ram", HostScopeKind::HostRam, None, host_bytes),
        wsl,
        host_wide_cap: host_scope("pinned-cap", HostScopeKind::PinnedRam, None, cap_bytes),
        memlock_reserve_bytes: KIB,
        max_ring_bytes: 64 * MIB,
    })
}

fn host_scope(name: &str, kind: HostScopeKind, parent: Option<&str>, bytes: u64) -> HostScope {
    HostScope {
        name: name.to_owned(),
        kind,
        parent: parent.map(str::to_owned),
        capacity: Capacity::Physical { bytes },
        safety_reserve_bytes: KIB,
        occupancy: ScopeOccupancy::default(),
    }
}

fn consumer(owner: &str, by: &str) -> Consumer {
    Consumer {
        tenant: tenant(owner),
        execution: execution(by),
        trust: TrustScope::named(ExecutionCategory::VmSandbox, "models"),
    }
}

fn charge(name: &str) -> LedgerCharge {
    LedgerCharge {
        operation: operation(name),
        priority: Priority::Foreground,
        retry_number: 0,
    }
}

/// GPU-T20 (line 1302): pinning, direct I/O or io_uring unavailable; a supported fallback
/// with a diagnostic reason.
///
/// Without evidence the CORE-01 gate leaves optional io_uring to the ordinary loader and
/// records why, with a remedy; the executor then reads with positioned reads although the
/// backend implements io_uring, and completes. A required io_uring is refused with its
/// reason instead of being replaced. Pinning with an unobserved memlock limit is refused,
/// and the executor runs with a pageable staging ring charged to host RAM only. With
/// direct I/O configured, aligned reads use `O_DIRECT`; a backend without direct reads, a
/// read off the direct-I/O block and a filesystem that refuses `O_DIRECT` each fall back
/// to buffered reads, every one reported with its reason, and the load completes. Not
/// covered: whether io_uring, `O_DIRECT` or page locking work on this host, which needs
/// the host.
#[test]
fn gpu_t20_unavailable_io_paths_fall_back_with_a_reason() {
    let clock = test_clock();
    let optional = loader_plan(
        &clock,
        &[(Optimization::IoUring, Necessity::Optional)],
        false,
    )
    .unwrap();
    assert!(optional.is_ordinary_loader());
    let reason = optional.ordinary().get(&Optimization::IoUring).unwrap();
    assert!(matches!(reason, NotEnabled::Evidence { .. }));
    assert!(!reason.to_string().is_empty());
    let _remedy = reason.remedy();
    let refusal = loader_plan(
        &clock,
        &[(Optimization::IoUring, Necessity::Required)],
        false,
    )
    .unwrap_err();
    assert_eq!(refusal.optimization, Optimization::IoUring);
    assert!(matches!(refusal.reason, NotEnabled::Evidence { .. }));

    let transfers = Transfers::new(&clock);
    transfers.edge().methods.insert(ReadMethod::IoUring);
    let weights = Weights::new("weights", &[16; 2], false);
    transfers.publish(&weights, &[local("nvme")]);
    let mut executor = transfers.executor();
    let permissions = LoaderPermissions::from_plan(&optional);
    assert!(!permissions.permits(ReadMethod::IoUring, &NoEvidence));
    executor
        .submit(TransferRequest {
            loader: permissions,
            ..load_job("load", "tenant-a", &weights, "slot")
        })
        .unwrap();
    transfers.drive(&mut executor);
    assert_eq!(
        executor.status(&operation("load")),
        Some(&JobStatus::Completed)
    );
    assert!(transfers
        .edge()
        .read_log
        .iter()
        .all(|read| read.1 == ReadMethod::PositionedRead));

    let mut ledger = host_ledger(
        &clock,
        &[
            (ResourceKey::Host(HostResource::Ram), GIB),
            (ResourceKey::Host(HostResource::PinnedRam), GIB),
        ],
        &["tenant-a"],
    );
    let mut pinned = pinned_tier(GIB, 512 * MIB, WslLimit::NotWsl);
    let owner = consumer("tenant-a", "exe-a");
    pinned.register_execution(owner.execution.clone(), MemlockLimit::Unknown);
    assert!(matches!(
        pinned.pin_ring(&owner, MIB, &charge("ring"), &mut ledger, &*clock),
        Err(PinnedRefusal::MemlockUnknown { .. })
    ));
    assert_eq!(pinned.pinned_bytes(), 0);

    let transfers = Transfers::new(&clock);
    transfers.publish(&weights, &[local("nvme")]);
    let mut config = transfers.config();
    config.host_staging.memory = HostStagingMemory::Pageable;
    let mut executor = transfers.executor_with(config);
    let pinned_key = ResourceKey::Host(HostResource::PinnedRam);
    assert_eq!(lock(&transfers.ledger).reserved(pinned_key), 0);
    assert_eq!(
        lock(&transfers.ledger).reserved(ResourceKey::Host(HostResource::Ram)),
        4 * SLOT
    );
    executor
        .submit(load_job("load", "tenant-a", &weights, "slot"))
        .unwrap();
    transfers.drive(&mut executor);
    assert_eq!(
        executor.status(&operation("load")),
        Some(&JobStatus::Completed)
    );
    assert_eq!(
        transfers.landed(&allocation("slot"), 0, 32),
        weights.decoded
    );

    let direct_run = |implements: bool, refuses: bool, block_bytes: u64| {
        let transfers = Transfers::new(&clock);
        {
            let mut edge = transfers.edge();
            if implements {
                edge.methods.insert(ReadMethod::DirectRead);
            }
            if refuses {
                edge.refuses_direct.insert(source_id("nvme"));
            }
        }
        let weights = Weights::new("direct", &[16; 8], false);
        transfers.publish(&weights, &[local("nvme")]);
        let mut executor = transfers.executor().with_direct_io(DirectIo {
            block_bytes: NonZeroU64::new(block_bytes).unwrap(),
        });
        let job = operation("direct");
        executor
            .submit(load_job("direct", "tenant-a", &weights, "slot"))
            .unwrap();
        transfers.drive(&mut executor);
        assert_eq!(executor.status(&job), Some(&JobStatus::Completed));
        assert_eq!(
            transfers.landed(&allocation("slot"), 0, 128),
            weights.decoded
        );
        let methods: Vec<ReadMethod> = transfers
            .edge()
            .read_log
            .iter()
            .map(|read| read.1)
            .collect();
        let reasons: Vec<DirectIoUnavailable> = transfers
            .events_of(&job)
            .into_iter()
            .filter_map(|kind| match kind {
                TransferEventKind::BufferedRead { reason } => Some(reason),
                _ => None,
            })
            .collect();
        (methods, reasons)
    };
    let (methods, reasons) = direct_run(true, false, ALIGN);
    assert!(
        !methods.is_empty()
            && methods
                .iter()
                .all(|method| *method == ReadMethod::DirectRead)
    );
    assert!(reasons.is_empty());
    let (methods, reasons) = direct_run(false, false, ALIGN);
    assert!(methods
        .iter()
        .all(|method| *method == ReadMethod::PositionedRead));
    assert!(!reasons.is_empty());
    assert!(reasons
        .iter()
        .all(|reason| *reason == DirectIoUnavailable::NotImplemented));
    let (methods, reasons) = direct_run(true, false, 4_096);
    assert!(methods
        .iter()
        .all(|method| *method == ReadMethod::PositionedRead));
    assert!(!reasons.is_empty());
    assert!(reasons.iter().all(|reason| matches!(
        reason,
        DirectIoUnavailable::Unaligned {
            block_bytes: 4_096,
            ..
        }
    )));
    let (methods, reasons) = direct_run(true, true, ALIGN);
    assert!(methods
        .iter()
        .all(|method| *method == ReadMethod::PositionedRead));
    assert!(!reasons.is_empty());
    assert!(reasons.iter().all(|reason| matches!(
        reason,
        DirectIoUnavailable::Refused { error } if error.kind == BackendErrorKind::Unsupported
    )));
}

/// GPU-T21 (line 1303): GDS falls back internally; the actual path is labelled and direct
/// transfer is never claimed.
///
/// Where the CORE-01 gate does not enable GPUDirect Storage the executor reads into the
/// host ring and every measured stage says so; a plan without its runtime's platform never
/// permits it either. Where the gate enables it for a runtime on CUDA and the executor
/// rechecks the evidence in the live registry, reads go to device staging and the copies
/// are labelled with the direct path. When cuFile serves those reads in its compatibility
/// mode and says so, every measured stage is labelled `DirectStorageCompatibility`, never
/// `DirectStorage`, and none claims to bypass the host. Not covered: cuFile itself, whose
/// report of the path it took needs real hardware.
#[test]
fn gpu_t21_the_measured_path_never_claims_direct_transfer_without_the_gate() {
    let clock = test_clock();
    let weights = Weights::new("weights", &[16; 2], false);
    let paths_of = |transfers: &Transfers, job: &OperationId| -> Vec<TransferPath> {
        transfers
            .events_of(job)
            .into_iter()
            .filter_map(|kind| match kind {
                TransferEventKind::StageMeasured(measurement) => measurement.path,
                _ => None,
            })
            .collect()
    };
    let with_device_staging = |transfers: &Transfers| {
        let mut config = transfers.config();
        config.device_staging.insert(
            gpu(0),
            DeviceStagingConfig {
                slots: 2,
                slot_bytes: SLOT,
            },
        );
        config
    };

    let ungated = loader_plan(
        &clock,
        &[(Optimization::GpuDirectStorage, Necessity::Optional)],
        false,
    )
    .unwrap();
    let transfers = Transfers::new(&clock);
    transfers
        .edge()
        .methods
        .insert(ReadMethod::GpuDirectStorage);
    transfers.publish(&weights, &[local("nvme")]);
    let mut executor = transfers.executor_with(with_device_staging(&transfers));
    let job = operation("load");
    executor
        .submit(TransferRequest {
            loader: LoaderPermissions::from_plan(&ungated),
            ..load_job("load", "tenant-a", &weights, "slot")
        })
        .unwrap();
    transfers.drive(&mut executor);
    assert_eq!(executor.status(&job), Some(&JobStatus::Completed));
    let paths = paths_of(&transfers, &job);
    assert!(!paths.is_empty());
    assert!(paths.iter().all(|path| *path == TransferPath::HostRing));
    assert!(transfers
        .edge()
        .read_log
        .iter()
        .all(|read| read.1 == ReadMethod::PositionedRead && read.2 == StagingPlace::Host));

    // That the runtime computes on CUDA is CORE-01 evidence, not its declaration (P06).
    let gds_on_cuda = || {
        let (profile, gated, mut registry) = planned(
            &clock,
            &[(Optimization::GpuDirectStorage, Necessity::Optional)],
            true,
        );
        let gated = gated.unwrap();
        let runtime = Subject::Runtime(profile.runtime.clone());
        let platform = FakeProbe::guest_report(Capability::ComputePlatform);
        platform.respond(
            &runtime,
            Observation::supported(
                profile.configuration,
                HOUR,
                SupportDetail::ComputePlatform {
                    platform: crate::foundation::evidence::ComputePlatform::Cuda,
                },
            ),
        );
        registry.register(Box::new(platform)).unwrap();
        registry
            .refresh(Capability::ComputePlatform, &runtime)
            .unwrap();
        let on_cuda = LoaderPermissions::from_runtime(
            &backend_runtime(&profile, &gated, ComputePlatform::Cuda).with_platform_policy(
                EvidencePolicy {
                    minimum_source: SourceClass::GuestReport,
                    max_age: HOUR,
                },
            ),
        );
        (gated, on_cuda, registry)
    };
    let (gated, _, registry) = gds_on_cuda();
    assert!(
        !LoaderPermissions::from_plan(&gated).permits(ReadMethod::GpuDirectStorage, &registry),
        "a plan alone never says the runtime computes on CUDA"
    );
    for compatibility in [false, true] {
        let (_, on_cuda, registry) = gds_on_cuda();
        let transfers = Transfers::new(&clock);
        {
            let mut edge = transfers.edge();
            edge.methods.insert(ReadMethod::GpuDirectStorage);
            edge.gds_compatibility = compatibility;
        }
        transfers.publish(&weights, &[local("nvme")]);
        let mut executor = transfers
            .executor_with(with_device_staging(&transfers))
            .with_evidence(Box::new(registry));
        executor
            .submit(TransferRequest {
                loader: on_cuda,
                ..load_job("load", "tenant-a", &weights, "slot")
            })
            .unwrap();
        transfers.drive(&mut executor);
        assert_eq!(executor.status(&job), Some(&JobStatus::Completed));
        assert!(transfers
            .edge()
            .read_log
            .iter()
            .all(|read| read.1 == ReadMethod::GpuDirectStorage
                && read.2 == StagingPlace::Device { device: gpu(0) }));
        let paths = paths_of(&transfers, &job);
        let actual = if compatibility {
            TransferPath::DirectStorageCompatibility
        } else {
            TransferPath::DirectStorage
        };
        assert!(!paths.is_empty());
        assert!(paths.iter().all(|path| *path == actual), "{paths:?}");
        assert_eq!(
            paths.iter().any(|path| path.bypasses_host_ring()),
            !compatibility,
            "a compatibility-mode read never claims a direct transfer"
        );
        assert_eq!(
            transfers.landed(&allocation("slot"), 0, 32),
            weights.decoded
        );
    }
}

/// A speculative job: the expected value of prefetching `bytes` that queued work will
/// probably use (GPU §2.9).
fn speculative_value(bytes: u64) -> PrefetchValue {
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

fn speculative_job(name: &str, weights: &Weights, into: &str) -> TransferRequest {
    TransferRequest {
        priority: JobPriority::Speculative {
            value: speculative_value(weights.decoded.len() as u64),
        },
        ..load_job(name, "tenant-a", weights, into)
    }
}

/// GPU-T36 (line 1318): a decoder competes with active inference; the governor respects
/// the foreground budget.
///
/// While the owner's foreground work holds GPU memory (a CORE-03 resource-return hold),
/// background reservations of that GPU are denied: a speculative decode-and-copy job is
/// refused with the hold named, and a foreground job of the same model proceeds. The
/// prefetch budget also keeps a foreground reserve that speculative work never takes.
/// When the hold ends, speculative work is admitted again. Not covered: decoder and SM
/// contention, copy-engine interference and foreground latency on a real GPU, which need
/// hardware (§8.2 item 11).
#[test]
fn gpu_t36_background_decoding_yields_to_the_foreground_budget() {
    let clock = test_clock();
    let transfers = Transfers::new(&clock);
    let weights = Weights::new("weights", &[16; 2], true);
    let other = Weights::new("other-weights", &[16; 2], true);
    transfers.publish(&weights, &[local("nvme")]);
    transfers.publish(&other, &[local("nvme")]);
    let mut executor = transfers.executor();
    let vram = resource_key(ReservedResource::DeviceMemory { device: gpu(0) });
    let hold = lock(&transfers.ledger)
        .begin_hold(BTreeSet::from([vram]))
        .unwrap();
    let refused = executor
        .submit(speculative_job("prefetch", &other, "spare"))
        .unwrap_err();
    assert!(matches!(
        refused,
        SubmitError::Reservation(ExecutorReservationRefusal::Capacity(CapacityRefusal {
            limit: CapacityLimit::OwnerReturnHold,
            ..
        }))
    ));
    executor
        .submit(load_job("serve", "tenant-a", &weights, "slot"))
        .unwrap();
    transfers.drive(&mut executor);
    assert_eq!(
        executor.status(&operation("serve")),
        Some(&JobStatus::Completed)
    );
    assert_eq!(
        transfers.landed(&allocation("slot"), 0, 32),
        weights.decoded
    );

    lock(&transfers.ledger).end_hold(hold.hold).unwrap();
    executor
        .submit(speculative_job("prefetch-later", &other, "spare"))
        .unwrap();
    transfers.drive(&mut executor);
    assert_eq!(
        executor.status(&operation("prefetch-later")),
        Some(&JobStatus::Completed)
    );

    let mut tight = transfers.config();
    tight.prefetch_budget = PrefetchBudget {
        max_speculative_bytes: KIB,
        capacity_bytes: 48,
        reserved_foreground_bytes: 32,
    };
    let transfers = Transfers::new(&clock);
    transfers.publish(&other, &[local("nvme")]);
    let mut executor = transfers.executor_with(tight);
    assert!(matches!(
        executor.submit(speculative_job("prefetch", &other, "spare")),
        Err(SubmitError::Admission(PrefetchError::Refused(
            AdmissionRefusal::ForegroundReserve { .. }
        )))
    ));
}

/// GPU-T37 (line 1319): the predictor sees a phase change or hostile alternation; wasted
/// bytes are bounded and scheduling falls back to demand only.
///
/// A predictor that claims 0.9 while its predictions alternate used and unused is
/// miscalibrated: its expected calibration error crosses the threshold and the mode
/// controller enters demand-only for drift; a phase change that drops confidence does the
/// same for low confidence. Before the fallback the speculative budget caps what the
/// predictor can waste; entering demand-only cancels speculative jobs, refuses new ones
/// and lets foreground work finish. Leaving demand-only needs the stricter thresholds for
/// the whole recovery dwell.
#[test]
fn gpu_t37_hostile_prediction_is_bounded_and_falls_back_to_demand_only() {
    let mut tracker = CalibrationTracker::new(10).unwrap();
    for step in 0..40 {
        tracker.record(0.9, step % 2 == 0).unwrap();
    }
    let error = tracker.expected_calibration_error().unwrap();
    assert!((error - 0.4).abs() < 1e-9);
    let thresholds = ModeThresholds {
        enter_below_confidence: 0.3,
        exit_at_confidence: 0.6,
        enter_above_load_fraction: 0.9,
        exit_at_load_fraction: 0.7,
        enter_above_calibration_error: 0.2,
        exit_at_calibration_error: 0.1,
        recovery_dwell: MINUTE,
    };
    let at = |seconds: u64| MonotonicTime::from_nanos(seconds * 1_000_000_000);
    let healthy = ModeSignals {
        confidence: 0.8,
        load_fraction: 0.5,
        calibration_error: 0.05,
    };
    let mut drift = ModeController::new(thresholds).unwrap();
    assert_eq!(
        drift
            .observe(
                at(1),
                ModeSignals {
                    calibration_error: error,
                    ..healthy
                }
            )
            .unwrap(),
        SchedulingMode::DemandOnly
    );
    assert_eq!(drift.reason(), Some(DemandOnlyReason::Drift));
    let mut phase = ModeController::new(thresholds).unwrap();
    phase
        .observe(
            at(1),
            ModeSignals {
                confidence: 0.1,
                ..healthy
            },
        )
        .unwrap();
    assert_eq!(phase.reason(), Some(DemandOnlyReason::LowConfidence));
    assert_eq!(
        drift.observe(at(30), healthy).unwrap(),
        SchedulingMode::DemandOnly
    );
    assert_eq!(
        drift.observe(at(89), healthy).unwrap(),
        SchedulingMode::DemandOnly
    );
    assert_eq!(
        drift.observe(at(90), healthy).unwrap(),
        SchedulingMode::Speculative
    );

    let clock = test_clock();
    let transfers = Transfers::new(&clock);
    let models: Vec<Weights> = (0..3)
        .map(|index| Weights::new(&format!("guess-{index}"), &[16; 2], false))
        .collect();
    for weights in &models {
        transfers.publish(weights, &[local("nvme")]);
    }
    let mut config = transfers.config();
    config.prefetch_budget.max_speculative_bytes = 64;
    let mut executor = transfers.executor_with(config);
    executor
        .submit(speculative_job("guess-0", &models[0], "spare-0"))
        .unwrap();
    executor
        .submit(speculative_job("guess-1", &models[1], "spare-1"))
        .unwrap();
    assert!(matches!(
        executor.submit(speculative_job("guess-2", &models[2], "spare-2")),
        Err(SubmitError::Admission(PrefetchError::Refused(
            AdmissionRefusal::SpeculativeBudget {
                limit_bytes: 64,
                ..
            }
        )))
    ));
    assert!(
        executor.scheduler().speculative_bytes() <= 64,
        "waste is capped"
    );
    executor
        .submit(load_job("demand", "tenant-a", &models[2], "slot"))
        .unwrap();
    let cancelled = executor
        .set_scheduling_mode(SchedulingMode::DemandOnly)
        .unwrap();
    assert_eq!(cancelled, vec![operation("guess-0"), operation("guess-1")]);
    assert!(matches!(
        executor.submit(speculative_job("guess-3", &models[0], "spare-3")),
        Err(SubmitError::Admission(PrefetchError::Refused(
            AdmissionRefusal::DemandOnly
        )))
    ));
    transfers.drive(&mut executor);
    assert_eq!(
        executor.status(&operation("demand")),
        Some(&JobStatus::Completed)
    );
    for name in ["guess-0", "guess-1"] {
        assert_eq!(
            executor.status(&operation(name)),
            Some(&JobStatus::Cancelled {
                reason: CancelReason::DemandOnly
            })
        );
    }
}

fn weights_ref(owner: &str, bytes: &[u8]) -> ObjectRef {
    ObjectRef {
        scope: Scope::tenant(tenant(owner)),
        class: ArtifactClass::ModelWeights,
        content: ContentKey::of(bytes),
    }
}

fn peer_path(bytes_per_second: f64, interference_seconds_per_byte: f64) -> SourcePath {
    SourcePath {
        startup_seconds: 0.0,
        bandwidth: BandwidthRating::measured_directional(bytes_per_second).unwrap(),
        cuts: Vec::new(),
        max_in_flight: 4,
        interference_seconds_per_byte,
    }
}

fn steal_policy() -> StealPolicy {
    StealPolicy {
        min_gain_seconds: 1.0,
        min_gain_fraction: 0.5,
        max_moves_per_batch: 1,
        max_moves_per_rebalance: 1,
    }
}

/// GPU-T38 (line 1320): a stale peer advertisement or a donor that disappears; retry or
/// re-plan without an unbounded wait.
///
/// An expired resident advertisement is refused at its recheck, and a peer whose
/// authorization expired refuses to offer at once, so nothing waits on either. A donor
/// that disappears in the middle of a load fails its read, is blacklisted for the job,
/// and the remaining extents are re-planned onto local storage within the attempt bound.
/// Not covered: the network timeout before a silent donor is declared gone; the fake
/// donor fails fast, as a closed connection does.
#[test]
fn gpu_t38_stale_or_vanished_donors_are_replanned_within_bounds() {
    let clock = test_clock();
    let owner = tenant("tenant-a");
    let model = execution_of(
        &logical_of(hub_source("example-org/chat", COMMIT_A, b"w"), "t"),
        1,
        "flash-attn",
    );
    let trust = TrustScope::named(ExecutionCategory::VmSandbox, "models");
    let residency = Residency {
        execution: model,
        artifact: ArtifactIdentity::from_manifest_digest(&named("manifest", "chat")),
        owner: owner.clone(),
        scope: trust,
        device: gpu(1),
        authority: session_authority("tenant-a"),
    };
    let advertisement = ResidentAdvertisement {
        residency: residency.clone(),
        generation: ModelActivationGeneration::FIRST,
        expires_at: clock.now().saturating_add(SECOND),
    };
    clock.advance(2 * SECOND);
    let grant = checked_grant(
        &execution("exe-tenant-a"),
        GrantTerms {
            grantor: owner.clone(),
            grantee: owner.clone(),
            artifact: residency.artifact,
            scope: trust,
            uses: BTreeSet::from([GrantedUse::Serve]),
            expires_at: clock.now().saturating_add(HOUR),
        },
    );
    assert!(matches!(
        advertisement.recheck(
            &CurrentResidency {
                residency,
                generation: ModelActivationGeneration::FIRST,
            },
            &AdvertisementRequest {
                requester: owner,
                required: model,
                purpose: AdvertisementPurpose::Serve,
            },
            Some(&grant),
            &*clock,
        ),
        Err(AdvertisementRefusal::Expired { .. })
    ));

    let bytes = payload(38, 256);
    let object = weights_ref("tenant-a", &bytes);
    let mut peer = PeerSource::new(
        PeerAuthorization {
            scopes: BTreeSet::from([object.scope.clone()]),
            expires_at: clock.now().saturating_add(SECOND),
            donor_budget_bytes: MIB,
        },
        Vec::new(),
    );
    peer.hold(object.clone(), PeerContent::ImmutableWeights, 256)
        .unwrap();
    let requester = consumer("tenant-a", "exe-a");
    assert!(peer
        .offer(
            source_id("peer"),
            &object,
            &requester,
            peer_path(1e9, 0.0),
            &*clock
        )
        .is_ok());
    clock.advance(SECOND);
    let refused = peer
        .offer(
            source_id("peer"),
            &object,
            &requester,
            peer_path(1e9, 0.0),
            &*clock,
        )
        .unwrap_err();
    assert!(matches!(
        refused.reason,
        TierRefusal::Peer(PeerRefusal::Expired { .. })
    ));

    let transfers = Transfers::new(&clock);
    let weights = Weights::new("weights", &[16; 4], false);
    transfers.publish(
        &weights,
        &[
            candidate("donor", SourceKind::AuthorizedPeer, 1e9),
            candidate("nvme", SourceKind::LocalFile, 1e7),
        ],
    );
    transfers.edge().gone.insert(source_id("donor"));
    let mut executor = transfers.executor();
    let job = operation("load");
    executor
        .submit(load_job("load", "tenant-a", &weights, "slot"))
        .unwrap();
    transfers.drive(&mut executor);
    assert_eq!(executor.status(&job), Some(&JobStatus::Completed));
    assert_eq!(
        executor.blacklist(&job).unwrap(),
        &BTreeSet::from([source_id("donor")])
    );
    for extent in weights.all() {
        let flight = executor.flight_of(&job, extent).unwrap();
        assert!(executor.attempts(flight).unwrap().len() <= 1);
    }
    assert_eq!(
        transfers.landed(&allocation("slot"), 0, 64),
        weights.decoded
    );
}

/// GPU-T39 (line 1321): a fast donor is serving latency-sensitive traffic; the donor budget
/// is enforced.
///
/// The busy donor agreed to serve only 256 bytes. Its offer covers no more than that, so
/// the source choice excludes it for a 512-byte load and plans the slower idle donor;
/// charging the busy donor past its budget is refused, and once spent it offers nothing.
/// Between two eligible donors the planner counts the busy one's interference cost per
/// byte and assigns it nothing. Not covered: the donor's own measured tail latency while
/// it serves, which needs two machines (§8.1 matrix).
#[test]
fn gpu_t39_a_busy_donor_serves_only_within_its_budget() {
    let clock = test_clock();
    let store = Store::open(&clock, &["tenant-a"], MIB);
    let bytes = payload(39, 512);
    let object = weights_ref("tenant-a", &bytes);
    let requester = consumer("tenant-a", "exe-a");
    let donor = |budget: u64| {
        let mut peer = PeerSource::new(
            PeerAuthorization {
                scopes: BTreeSet::from([object.scope.clone()]),
                expires_at: clock.now().saturating_add(HOUR),
                donor_budget_bytes: budget,
            },
            Vec::new(),
        );
        peer.hold(object.clone(), PeerContent::ImmutableWeights, 512)
            .unwrap();
        peer
    };
    let mut busy = donor(256);
    let idle = donor(MIB);
    let request = SourceRequest {
        requester: requester.clone(),
        content: object.content,
        batches_bytes: vec![64; 8],
        cuts: Vec::new(),
        policy: steal_policy(),
    };
    let offers = vec![
        busy.offer(
            source_id("busy"),
            &object,
            &requester,
            peer_path(1e9, 0.0),
            &*clock,
        ),
        idle.offer(
            source_id("idle"),
            &object,
            &requester,
            peer_path(1e8, 0.0),
            &*clock,
        ),
    ];
    let choice = choose_source(&request, offers, store.view()).unwrap();
    assert_eq!(
        choice.excluded(),
        &[ExcludedSource {
            source: source_id("busy"),
            tier: Tier::AuthorizedPeer,
            reason: ExclusionReason::CannotCover {
                covers_bytes: 256,
                needed_bytes: 512
            }
        }]
    );
    assert_eq!(choice.assigned_bytes(&source_id("idle")), 512);
    assert_eq!(choice.assigned_bytes(&source_id("busy")), 0);

    busy.charge(256, &*clock).unwrap();
    assert!(matches!(
        busy.charge(1, &*clock),
        Err(PeerRefusal::DonorBudgetExhausted { .. })
    ));
    assert!(matches!(
        busy.offer(
            source_id("busy"),
            &object,
            &requester,
            peer_path(1e9, 0.0),
            &*clock
        ),
        Err(OfferRefusal {
            reason: TierRefusal::Peer(PeerRefusal::DonorBudgetExhausted { .. }),
            ..
        })
    ));

    let generous_but_busy = donor(MIB);
    let offers = vec![
        generous_but_busy.offer(
            source_id("busy"),
            &object,
            &requester,
            peer_path(1e9, 1.0),
            &*clock,
        ),
        idle.offer(
            source_id("idle"),
            &object,
            &requester,
            peer_path(1e8, 0.0),
            &*clock,
        ),
    ];
    let choice = choose_source(&request, offers, store.view()).unwrap();
    assert!(choice.excluded().is_empty());
    assert_eq!(
        choice.assigned_bytes(&source_id("busy")),
        0,
        "interference outweighs bandwidth"
    );
    assert_eq!(choice.assigned_bytes(&source_id("idle")), 512);
}

// ---------------------------------------------------------------------------------------
// Manifest fixtures: a sidecar over a config file and a 192-byte weights file.
// ---------------------------------------------------------------------------------------

/// Integrity-extent size g_h of these manifests.
const G: u64 = 64;
const SAFETENSORS_HEADER: mf::FileFormat = mf::FileFormat::Safetensors {
    header_length_bytes: 56,
};
const SAFETENSORS_WEIGHTS: mf::FileRole = mf::FileRole::Weights {
    format: mf::WeightFormat::Safetensors,
    rank: None,
};

fn chunks(bytes: &[u8]) -> Vec<Vec<u8>> {
    bytes.chunks(G as usize).map(<[u8]>::to_vec).collect()
}

/// A run-length codec standing in for zstd in manifest checks: pairs of (count, byte).
/// It is lossless on bytes, whatever they encode.
fn rle_encode(data: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::new();
    let mut rest = data;
    while let Some(&byte) = rest.first() {
        let run = rest
            .iter()
            .take(255)
            .take_while(|candidate| **candidate == byte)
            .count();
        encoded.push(run as u8);
        encoded.push(byte);
        rest = &rest[run..];
    }
    encoded
}

fn rle_decode(encoded: &[u8], output: &mut mf::BoundedOutput) -> Result<(), mf::DecodeError> {
    if !encoded.len().is_multiple_of(2) {
        return Err(mf::DecodeError::Corrupt);
    }
    for pair in encoded.chunks_exact(2) {
        output.write(&vec![pair[1]; usize::from(pair[0])])?;
    }
    Ok(())
}

/// The lossless decoder; it counts its calls, so a test sees whether it ran.
#[derive(Default)]
struct RunLength {
    calls: AtomicUsize,
}

impl mf::ExtentDecoder for RunLength {
    fn codec(&self) -> Codec {
        Codec::Zstd
    }

    fn versions(&self) -> &[CodecVersion] {
        &[CodecVersion::ZstdRfc8878]
    }

    fn decode(
        &self,
        _format: &mf::CodecFormat,
        encoded: &[u8],
        _dictionary: Option<&[u8]>,
        output: &mut mf::BoundedOutput,
    ) -> Result<(), mf::DecodeError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        rle_decode(encoded, output)
    }
}

/// P15's zstd decoder behind the manifest's decoder port, counting its calls so a test
/// sees whether a stream reached it.
#[derive(Default)]
struct CountedZstd {
    calls: AtomicUsize,
}

impl mf::ExtentDecoder for CountedZstd {
    fn codec(&self) -> Codec {
        Codec::Zstd
    }

    fn versions(&self) -> &[CodecVersion] {
        &[CodecVersion::ZstdRfc8878]
    }

    fn decode(
        &self,
        format: &mf::CodecFormat,
        encoded: &[u8],
        dictionary: Option<&[u8]>,
        output: &mut mf::BoundedOutput,
    ) -> Result<(), mf::DecodeError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        ZstdDecoder.decode(format, encoded, dictionary, output)
    }
}

/// A zstd decoder that "normalizes" BF16 values as a careless float-typed kernel would:
/// every NaN becomes the canonical quiet NaN and negative zero becomes positive zero.
struct CanonicalizingZstd;

impl mf::ExtentDecoder for CanonicalizingZstd {
    fn codec(&self) -> Codec {
        Codec::Zstd
    }

    fn versions(&self) -> &[CodecVersion] {
        &[CodecVersion::ZstdRfc8878]
    }

    fn decode(
        &self,
        _format: &mf::CodecFormat,
        encoded: &[u8],
        dictionary: Option<&[u8]>,
        output: &mut mf::BoundedOutput,
    ) -> Result<(), mf::DecodeError> {
        let limit_bytes = output.remaining_bytes() as u64;
        let mut decoded =
            decode_bounded(encoded, dictionary, limit_bytes).map_err(|error| match error {
                CodecError::Decode(error) => error,
                _ => mf::DecodeError::Corrupt,
            })?;
        for value in decoded.chunks_exact_mut(2) {
            let bits = u16::from_le_bytes([value[0], value[1]]);
            let normalized = match bits {
                nan if nan & 0x7f80 == 0x7f80 && nan & 0x007f != 0 => 0x7fc0,
                0x8000 => 0,
                other => other,
            };
            value.copy_from_slice(&normalized.to_le_bytes());
        }
        output.write(&decoded)
    }
}

/// One real zstd frame per extent, at P15's default level.
fn zstd_frame(_index: usize, decoded: &[u8]) -> Vec<u8> {
    codec_encode(decoded, DEFAULT_LEVEL, None).unwrap()
}

/// A zstd block header: the last-block flag, the block type and its size (RFC 8878
/// §3.1.1.2).
fn block_header(last: bool, block_type: u32, size: u32) -> [u8; 3] {
    let value = u32::from(last) | (block_type << 1) | (size << 3);
    [value as u8, (value >> 8) as u8, (value >> 16) as u8]
}

/// A hand-made zstd frame: the magic number, `descriptor`, the header `fields` that
/// follow it, then `blocks` (RFC 8878 §3.1.1).
fn hand_made_frame(descriptor: u8, fields: &[u8], blocks: &[u8]) -> Vec<u8> {
    let mut frame = ZSTD_MAGIC.to_le_bytes().to_vec();
    frame.push(descriptor);
    frame.extend_from_slice(fields);
    frame.extend_from_slice(blocks);
    frame
}

fn manifest_builder(distribution: mf::Distribution) -> mf::ManifestBuilder {
    let mut description = artifact_description(G);
    description.distribution = distribution;
    mf::ManifestBuilder::new(
        mf::SourceOrigin::LocalFolder,
        mf::sidecar_converter().unwrap(),
        description,
    )
}

fn source_input(
    file: &str,
    bytes: &[u8],
    role: mf::FileRole,
    format: mf::FileFormat,
) -> mf::SourceFileInput {
    mf::SourceFileInput {
        path: manifest_path(file),
        length_bytes: bytes.len() as u64,
        content: ContentKey::of(bytes),
        role,
        format,
    }
}

/// Adds a file and its raw extents of `G` bytes; returns the extents' stored bytes.
fn add_raw_file(
    builder: &mut mf::ManifestBuilder,
    file: &str,
    bytes: &[u8],
    role: mf::FileRole,
    format: mf::FileFormat,
) -> Vec<Vec<u8>> {
    builder
        .add_source_file(source_input(file, bytes, role, format))
        .unwrap();
    let stored = chunks(bytes);
    for (index, chunk) in stored.iter().enumerate() {
        builder.add_extent(mf::ExtentInput {
            file: manifest_path(file),
            logical_offset_bytes: index as u64 * G,
            true_length_bytes: chunk.len() as u64,
            content_key: ContentKey::of(chunk),
            encoding: mf::EncodingInput::Raw,
        });
    }
    stored
}

/// Adds the weights file with every extent stored run-length encoded in `prepared`, the
/// stored form of extent `i` being `encode(i, decoded)`; returns the stored bytes.
fn add_encoded_weights(
    builder: &mut mf::ManifestBuilder,
    bytes: &[u8],
    dictionary: Option<&[u8]>,
    encode: impl Fn(usize, &[u8]) -> Vec<u8>,
) -> Vec<Vec<u8>> {
    builder
        .add_source_file(source_input(
            "model.safetensors",
            bytes,
            SAFETENSORS_WEIGHTS,
            SAFETENSORS_HEADER,
        ))
        .unwrap();
    let dictionary = dictionary.map(mf::DictionaryId::of);
    let decoded = chunks(bytes);
    let stored: Vec<Vec<u8>> = decoded
        .iter()
        .enumerate()
        .map(|(index, chunk)| encode(index, chunk))
        .collect();
    let total: usize = stored.iter().map(Vec::len).sum();
    builder
        .add_prepared_file(manifest_path("prepared/model.enc"), total as u64)
        .unwrap();
    builder.set_codec_block_bytes(G);
    let mut offset_bytes = 0u64;
    for (index, (chunk, encoded)) in decoded.iter().zip(&stored).enumerate() {
        builder.add_extent(mf::ExtentInput {
            file: manifest_path("model.safetensors"),
            logical_offset_bytes: index as u64 * G,
            true_length_bytes: chunk.len() as u64,
            content_key: ContentKey::of(chunk),
            encoding: mf::EncodingInput::Encoded {
                format: zstd_format(G),
                dictionary,
                prepared_file: manifest_path("prepared/model.enc"),
                offset_bytes,
                length_bytes: encoded.len() as u64,
                digest: EncodedDigest::of(zstd_format(G), dictionary, encoded),
            },
        });
        offset_bytes += encoded.len() as u64;
    }
    stored
}

fn tensor_input(
    name: &str,
    file: &str,
    offset_bytes: u64,
    shape: &[u64],
    owner: mf::TensorOwner,
) -> mf::TensorInput {
    let dtype = mf::TensorDtype::Element(mf::ElementType::F32);
    mf::TensorInput {
        name: tensor_name(name),
        file: manifest_path(file),
        offset_bytes,
        true_length_bytes: mf::tensor_bytes(dtype, mf::TensorLayout::RowMajor, shape).unwrap(),
        dtype,
        shape: shape.to_vec(),
        layout: mf::TensorLayout::RowMajor,
        owner,
    }
}

/// 192 bytes: an 8-byte prefix and a 56-byte header region, then the embedding `a`
/// (F32 4×4 at 64) and `b` (F32 16 at 128) whose bytes are `data`.
fn weights_file(data: &[u8; 128]) -> Vec<u8> {
    let mut bytes = payload(190, 64);
    bytes.extend_from_slice(data);
    bytes
}

fn add_tensors(builder: &mut mf::ManifestBuilder, file: &str) {
    builder
        .add_tensor(tensor_input(
            "a",
            file,
            64,
            &[4, 4],
            mf::TensorOwner::Replicated,
        ))
        .unwrap();
    builder
        .add_tensor(tensor_input(
            "b",
            file,
            128,
            &[16],
            mf::TensorOwner::Replicated,
        ))
        .unwrap();
}

/// config.json (100 bytes, extents 0–1) and model.safetensors (192 bytes, extents 2–4)
/// holding `data`, stored raw.
fn raw_manifest_builder(data: &[u8; 128]) -> mf::ManifestBuilder {
    let mut builder = manifest_builder(mf::Distribution::SINGLE);
    add_raw_file(
        &mut builder,
        "config.json",
        &payload(191, 100),
        mf::FileRole::Configuration,
        mf::FileFormat::Opaque,
    );
    add_raw_file(
        &mut builder,
        "model.safetensors",
        &weights_file(data),
        SAFETENSORS_WEIGHTS,
        SAFETENSORS_HEADER,
    );
    add_tensors(&mut builder, "model.safetensors");
    builder
}

/// The same files with the weights run-length encoded, extent `i` stored as
/// `encode(i, decoded)`; returns every extent's stored bytes in extent order.
fn encoded_manifest(
    data: &[u8; 128],
    dictionary: Option<&[u8]>,
    encode: impl Fn(usize, &[u8]) -> Vec<u8>,
) -> (mf::ValidatedManifest, Vec<Vec<u8>>) {
    let mut builder = manifest_builder(mf::Distribution::SINGLE);
    let mut stored = add_raw_file(
        &mut builder,
        "config.json",
        &payload(191, 100),
        mf::FileRole::Configuration,
        mf::FileFormat::Opaque,
    );
    stored.extend(add_encoded_weights(
        &mut builder,
        &weights_file(data),
        dictionary,
        encode,
    ));
    add_tensors(&mut builder, "model.safetensors");
    (builder.finish().unwrap(), stored)
}

fn honest_rle(_index: usize, decoded: &[u8]) -> Vec<u8> {
    rle_encode(decoded)
}

/// A weights file: 64 header bytes, 16 f32 IEEE special values (quiet and signalling NaNs
/// with payloads and both signs, infinities, subnormals, both zeros and extremes), then
/// every one of the 65,536 BF16 bit patterns in ascending order.
fn special_weights() -> Vec<u8> {
    let f32_bits: [u32; 16] = [
        0x7fc0_0000,
        0x7fc0_0001,
        0xffc0_0000,
        0x7f80_0001,
        0x7f80_0000,
        0xff80_0000,
        0x0000_0001,
        0x807f_ffff,
        0x8000_0000,
        0x0000_0000,
        0x3f80_0000,
        0x7f7f_ffff,
        0x0080_0000,
        0xff7f_ffff,
        0x7fff_ffff,
        0x8000_0001,
    ];
    let mut bytes = payload(190, 64);
    for bits in f32_bits {
        bytes.extend_from_slice(&bits.to_le_bytes());
    }
    for pattern in 0..=u16::MAX {
        bytes.extend_from_slice(&pattern.to_le_bytes());
    }
    bytes
}

/// config.json stored raw (extents 0–1) and `weights` stored as one real zstd frame per
/// 64-byte extent, holding the f32 specials at 64 and every BF16 pattern at 128; returns
/// every extent's stored bytes in extent order.
fn zstd_manifest(weights: &[u8]) -> (mf::ValidatedManifest, Vec<Vec<u8>>) {
    let mut builder = manifest_builder(mf::Distribution::SINGLE);
    let mut stored = add_raw_file(
        &mut builder,
        "config.json",
        &payload(191, 100),
        mf::FileRole::Configuration,
        mf::FileFormat::Opaque,
    );
    stored.extend(add_encoded_weights(&mut builder, weights, None, zstd_frame));
    for (name, element, offset_bytes, shape) in [
        ("f32.special", mf::ElementType::F32, 64, 16),
        ("bf16.all", mf::ElementType::Bf16, 128, 65_536),
    ] {
        let dtype = mf::TensorDtype::Element(element);
        builder
            .add_tensor(mf::TensorInput {
                name: tensor_name(name),
                file: manifest_path("model.safetensors"),
                offset_bytes,
                true_length_bytes: mf::tensor_bytes(dtype, mf::TensorLayout::RowMajor, &[shape])
                    .unwrap(),
                dtype,
                shape: vec![shape],
                layout: mf::TensorLayout::RowMajor,
                owner: mf::TensorOwner::Replicated,
            })
            .unwrap();
    }
    (builder.finish().unwrap(), stored)
}

fn plain_floats() -> [u8; 128] {
    let mut data = [0u8; 128];
    data.copy_from_slice(&payload(192, 128));
    data
}

// ---------------------------------------------------------------------------------------
// GPU-T07, GPU-T09, GPU-T10, GPU-T31, GPU-T34, GPU-T35: manifests, layouts and codecs.
// ---------------------------------------------------------------------------------------

/// GPU-T07 (line 1289): the same model under another TP/EP, layout or kernel; a compatible
/// representation is validated or rebuilt.
///
/// Changing tensor or expert parallelism, the kernel layout or the processed-weight
/// layout gives another execution identity, and a graph captured for one is refused for
/// another. A single-rank artifact refuses to plan a rank of a two-rank layout, so the
/// two-rank representation must be built for it; that one validates and plans only each
/// rank's own shards.
#[test]
fn gpu_t07_another_layout_needs_its_own_validated_representation() {
    let source = hub_source("example-org/chat", COMMIT_A, b"weights");
    let logical = logical_of(source, "tokenizer");
    let single = execution_of(&logical, 1, "flash-attn");
    let spec = |tensor_parallel: u32, expert_parallel: u32, kernels: &str, processed: &str| {
        ExecutionSpec {
            logical: logical.identity(),
            runner: versioned("vllm", "0.31.0"),
            architecture_adapter: versioned("llama", "1"),
            kernel_layout: versioned(kernels, "1"),
            gpu_architectures: BTreeSet::from([label("sm_90a")]),
            topology: RankTopology::new(tensor_parallel, 1, expert_parallel).unwrap(),
            processed_weights: versioned(processed, "1"),
            compile: CompileConfiguration::Eager,
        }
        .identity()
        .unwrap()
    };
    assert_eq!(spec(1, 1, "flash-attn", "vllm-bf16"), single);
    let variants = [
        spec(2, 1, "flash-attn", "vllm-bf16"),
        spec(2, 2, "flash-attn", "vllm-bf16"),
        spec(1, 1, "flashinfer", "vllm-bf16"),
        spec(1, 1, "flash-attn", "marlin-repacked"),
    ];
    for (index, variant) in variants.iter().enumerate() {
        assert_ne!(*variant, single, "variant {index}");
        for other in &variants[index + 1..] {
            assert_ne!(variant, other);
        }
    }
    let capture = |execution| GraphCaptureSpec {
        execution,
        device: gpu(0),
        shape: CaptureShape {
            sequences: 4,
            tokens: 512,
        },
        resources: vec![IdGraphResource {
            role: label("weights"),
            kind: GraphResourceKind::Weights,
            content: named("weights", "chat"),
            allocation: GpuAllocationGeneration::FIRST,
            device_address: 0x7000_0000,
            length_bytes: 192,
            layout: label("row-major"),
        }],
    };
    assert!(capture(single).check_reuse(&capture(variants[2])).is_err());

    let two_ranks = mf::Distribution {
        tensor_parallel_size: 2,
        ..mf::Distribution::SINGLE
    };
    let single_artifact = raw_manifest_builder(&plain_floats()).finish().unwrap();
    assert_eq!(
        single_artifact.rank_plan(&two_ranks, 0),
        Err(mf::RankRefusal::LayoutMismatch {
            manifest: mf::Distribution::SINGLE,
            requested: two_ranks,
        })
    );
    let mut builder = manifest_builder(two_ranks);
    add_raw_file(
        &mut builder,
        "config.json",
        &payload(191, 100),
        mf::FileRole::Configuration,
        mf::FileFormat::Opaque,
    );
    for rank in 0..2u32 {
        let file = format!("model-rank-{rank}.safetensors");
        add_raw_file(
            &mut builder,
            &file,
            &weights_file(&plain_floats()),
            mf::FileRole::Weights {
                format: mf::WeightFormat::Safetensors,
                rank: Some(rank),
            },
            SAFETENSORS_HEADER,
        );
        builder
            .add_tensor(tensor_input(
                &format!("q.{rank}"),
                &file,
                64,
                &[16],
                mf::TensorOwner::Rank(rank),
            ))
            .unwrap();
        builder
            .add_tensor(tensor_input(
                &format!("k.{rank}"),
                &file,
                128,
                &[16],
                mf::TensorOwner::Rank(rank),
            ))
            .unwrap();
    }
    let sharded = builder.finish().unwrap();
    assert_ne!(sharded.digest(), single_artifact.digest());
    let rank1 = sharded.rank_plan(&two_ranks, 1).unwrap();
    assert_eq!(rank1.tensors, vec![tensor_name("k.1"), tensor_name("q.1")]);
    assert!(sharded.rank_plan(&mf::Distribution::SINGLE, 0).is_err());
    assert!(matches!(
        sharded.rank_plan(&two_ranks, 2),
        Err(mf::RankRefusal::RankOutOfRange { rank: 2, .. })
    ));
}

/// GPU-T09 (line 1291): valid data with malicious shape, offset or codec metadata; the
/// authenticated manifest or a bounds check refuses it.
///
/// The payload bytes are untouched in every case. A sidecar whose body changed after it
/// was sealed fails its digest. A re-sealed manifest with a reshaped tensor, an offset
/// into the header or onto another tensor, an encoded range past its prepared file or a
/// decoded length past the decompression bound fails validation before anything is
/// allocated. The safetensors indexer refuses offsets past the data and lengths that do
/// not match the shape.
#[test]
fn gpu_t09_malicious_metadata_is_refused_before_allocation() {
    let manifest = raw_manifest_builder(&plain_floats()).finish().unwrap();
    let mut sidecar = manifest.sidecar_bytes();
    assert!(mf::ValidatedManifest::from_sidecar_bytes(&sidecar).is_ok());
    sidecar[40] ^= 0x01;
    assert_eq!(
        mf::ValidatedManifest::from_sidecar_bytes(&sidecar).map(|_| ()),
        Err(mf::ManifestError::DigestMismatch)
    );

    let tampered = |change: &dyn Fn(&mut mf::Manifest)| {
        let mut edited = manifest.manifest().clone();
        change(&mut edited);
        edited.validate().map(|_| ())
    };
    assert!(matches!(
        tampered(&|m| m.tensor_index.tensors[0].shape = vec![4, 8]),
        Err(mf::ManifestError::TensorLength { .. })
    ));
    assert!(matches!(
        tampered(&|m| m.tensor_index.tensors[0].offset_bytes = 8),
        Err(mf::ManifestError::TensorOutOfBounds { .. })
    ));
    assert!(matches!(
        tampered(&|m| m.tensor_index.tensors[1].offset_bytes = 100),
        Err(mf::ManifestError::OverlappingRanges { .. })
    ));
    let (encoded, _) = encoded_manifest(&plain_floats(), None, honest_rle);
    let tampered_encoding = |change: &dyn Fn(&mut mf::Manifest)| {
        let mut edited = encoded.manifest().clone();
        change(&mut edited);
        edited.validate().map(|_| ())
    };
    assert!(matches!(
        tampered_encoding(&|m| {
            if let mf::ExtentEncoding::Encoded(representation) = &mut m.extents.extents[4].encoding
            {
                representation.location.length_bytes += 4_096;
            }
        }),
        Err(mf::ManifestError::EncodedOutOfBounds { .. })
    ));
    assert!(matches!(
        tampered_encoding(&|m| m.extents.extents[3].true_length_bytes = 1 << 40),
        Err(mf::ManifestError::DecompressionBound { .. })
    ));

    let data = vec![0u8; 64];
    let index = |header: serde_json::Value| {
        let mut json = serde_json::to_vec(&header).unwrap();
        while !json.len().is_multiple_of(8) {
            json.push(b' ');
        }
        let mut file = (json.len() as u64).to_le_bytes().to_vec();
        file.extend_from_slice(&json);
        file.extend_from_slice(&data);
        mf::index_safetensors(
            &mut file.as_slice(),
            file.len() as u64,
            &mf::IndexerBounds::DEFAULT,
        )
    };
    assert!(matches!(
        index(
            serde_json::json!({"w": {"dtype": "F32", "shape": [4, 4], "data_offsets": [0, 1000]}})
        ),
        Err(mf::IndexError::OutOfBounds { .. })
    ));
    assert!(matches!(
        index(serde_json::json!({"w": {"dtype": "F32", "shape": [4, 4], "data_offsets": [0, 32]}})),
        Err(mf::IndexError::LengthMismatch { .. })
    ));
    assert!(index(
        serde_json::json!({"w": {"dtype": "F32", "shape": [4, 4], "data_offsets": [0, 64]}})
    )
    .is_ok());
}

/// GPU-T10 (line 1292): decoded content is corrupt although the encoded checksum is
/// valid; the decoded identity or codec inconsistency is refused.
///
/// The stored bytes of one extent encode other content, and the manifest's encoded
/// digest is computed over those stored bytes, so the encoded check passes. The
/// manifest's own verification decodes them and refuses the decoded content key. The
/// executor does the same at its validate step: each attempt fails as a decoded identity
/// mismatch, it retries to the bound without blaming the source, and nothing is copied
/// to the GPU.
#[test]
fn gpu_t10_valid_encoded_checksums_never_excuse_corrupt_decoded_content() {
    let corrupt_third = |index: usize, decoded: &[u8]| {
        let mut wrong = decoded.to_vec();
        if index == 1 {
            wrong[5] ^= 0x10;
        }
        rle_encode(&wrong)
    };
    let (manifest, stored) = encoded_manifest(&plain_floats(), None, corrupt_third);
    let decoder = RunLength::default();
    assert!(manifest
        .verify_extent(2, &stored[2], None, &[&decoder])
        .is_ok());
    assert_eq!(
        manifest.verify_extent(3, &stored[3], None, &[&decoder]),
        Err(mf::ExtentError::ContentKeyMismatch)
    );
    assert_eq!(
        decoder.calls.load(Ordering::SeqCst),
        2,
        "the stored digest passed"
    );

    let clock = test_clock();
    let transfers = Transfers::new(&clock);
    let weights = Weights::with_corrupt_decoding("weights", &[16]);
    transfers.publish(&weights, &[local("nvme")]);
    let mut executor = transfers.executor();
    let job = operation("load");
    executor
        .submit(load_job("load", "tenant-a", &weights, "slot"))
        .unwrap();
    transfers.drive(&mut executor);
    let Some(JobStatus::Failed { failure }) = executor.status(&job) else {
        panic!("the extent is refused");
    };
    let ExtentFailure::RetriesExhausted { attempts } = &failure.failure else {
        panic!("retried to the bound: {failure:?}");
    };
    assert_eq!(attempts.len(), 3);
    assert!(attempts
        .iter()
        .all(|attempt| matches!(attempt.failure, AttemptFailure::DecodedMismatch { .. })));
    assert!(executor.blacklist(&job).unwrap().is_empty());
    assert_eq!(
        transfers.edge().copies_enqueued,
        0,
        "nothing reached the GPU"
    );
}

impl Weights {
    /// One encoded extent whose stored bytes encode other content under a valid encoded
    /// digest: the encoded checksum passes and the decoded content key does not.
    fn with_corrupt_decoding(name: &str, lengths: &[u64]) -> Self {
        let honest = Self::new(name, lengths, true);
        let mut stored = Vec::new();
        let mut extents = honest.extents.clone();
        for extent in &mut extents {
            let start = extent.decoded_offset_bytes as usize;
            let mut wrong =
                honest.decoded[start..start + extent.decoded_length_bytes as usize].to_vec();
            wrong[0] ^= 0xff;
            let bytes = edge_encode(&wrong);
            extent.stored_offset_bytes = stored.len() as u64;
            extent.stored_length_bytes = bytes.len() as u64;
            extent.stored = StoredForm::Encoded {
                codec: zstd_format(G),
                dictionary: None,
                digest: EncodedDigest::of(zstd_format(G), None, &bytes),
            };
            stored.extend_from_slice(&bytes);
        }
        Self {
            key: honest.key,
            representation: ContentKey::of(&stored),
            decoded: honest.decoded,
            stored,
            extents,
        }
    }
}

/// GPU-T31 (line 1313): a tied embedding and head, or a missing runtime buffer; the
/// dependency group includes both uses.
///
/// The manifest records the output head as an alias of the embedding, so a lookup of
/// either finds one tensor and one set of extents, and records the rotary frequencies as
/// a rematerialized buffer. The Transformers boundary refuses a plan that loads the head
/// separately, leaves the buffer on the meta device or reads it from the checkpoint. In
/// the §2.6 first-token recurrence the head waits for the embedding it shares.
#[test]
fn gpu_t31_tied_weights_and_runtime_buffers_join_one_dependency_group() {
    let mut builder = raw_manifest_builder(&plain_floats());
    builder
        .add_alias(mf::TensorAlias {
            name: tensor_name("lm_head.weight"),
            target: tensor_name("a"),
        })
        .unwrap();
    builder
        .add_rematerialized_buffer(mf::RematerializedBuffer {
            name: tensor_name("rotary.inv_freq"),
            dtype: mf::TensorDtype::Element(mf::ElementType::F32),
            shape: vec![32],
            reconstruction: mf::VersionedName {
                name: token("rotary-embedding"),
                version: token("1"),
            },
        })
        .unwrap();
    let manifest = builder.finish().unwrap();
    let embedding = manifest.tensor("a").unwrap().clone();
    let head = manifest.tensor("lm_head.weight").unwrap();
    assert_eq!(*head, embedding, "one tensor serves both uses");
    let extents = |tensor: &mf::TensorEntry| {
        manifest.extents_covering(tensor.file, tensor.offset_bytes, tensor.true_length_bytes)
    };
    assert_eq!(extents(head), extents(&embedding));
    assert_eq!(
        manifest.manifest().state.rematerialized_buffers[0].name,
        tensor_name("rotary.inv_freq")
    );

    let name = |text: &str| TensorName::new(text).unwrap();
    let inventory = ModelInventory::new(
        BTreeMap::from([
            (name("a"), TensorRole::Parameter),
            (name("lm_head.weight"), TensorRole::Parameter),
            (name("b"), TensorRole::Parameter),
            (name("rotary.inv_freq"), TensorRole::NonPersistentBuffer),
        ]),
        vec![BTreeSet::from([name("a"), name("lm_head.weight")])],
    )
    .unwrap();
    let plan = |head: Materialization, rotary: Option<Materialization>| {
        let mut tensors = BTreeMap::from([
            (name("a"), Materialization::LoadFromCheckpoint),
            (name("lm_head.weight"), head),
            (name("b"), Materialization::LoadFromCheckpoint),
        ]);
        if let Some(rotary) = rotary {
            tensors.insert(name("rotary.inv_freq"), rotary);
        }
        MaterializationPlan { tensors }
    };
    let tied = Materialization::TieTo { tensor: name("a") };
    assert_eq!(
        check_materialization(
            &inventory,
            &plan(tied.clone(), Some(Materialization::Rematerialize))
        ),
        Ok(())
    );
    assert!(matches!(
        check_materialization(
            &inventory,
            &plan(
                Materialization::LoadFromCheckpoint,
                Some(Materialization::Rematerialize)
            )
        ),
        Err(MaterializationRefusal::TiedWeightsNotPreserved { .. })
    ));
    assert!(matches!(
        check_materialization(&inventory, &plan(tied.clone(), None)),
        Err(MaterializationRefusal::LeftOnMeta { .. })
    ));
    assert!(matches!(
        check_materialization(
            &inventory,
            &plan(tied, Some(Materialization::LoadFromCheckpoint))
        ),
        Err(MaterializationRefusal::BufferNotRematerialized { .. })
    ));

    let layer = |usable: f64| GroupRequirement {
        weights_usable_at_seconds: usable,
        compute_seconds: 1.0,
        dependencies: Vec::new(),
    };
    let head = GroupRequirement {
        weights_usable_at_seconds: 0.0,
        compute_seconds: 0.5,
        dependencies: vec![Dependency {
            kind: DependencyKind::TiedEmbeddings,
            usable_at_seconds: 6.0,
        }],
    };
    let first = first_token(&[layer(1.0), layer(2.0)], &head).unwrap();
    assert_eq!(first.layers_finish_seconds, 3.0);
    assert_eq!(first.first_token_seconds, 6.5);
    assert_eq!(
        first.critical_input,
        Some(CriticalInput {
            group: GroupRef::OutputHead,
            cause: WaitCause::Dependency(DependencyKind::TiedEmbeddings),
            usable_at_seconds: 6.0,
        })
    );
}

/// GPU-T34 (line 1316): codec NaN, infinity, subnormal and signed-zero patterns are
/// reconstructed bit for bit.
///
/// The weights hold f32 quiet and signalling NaNs with payloads and both signs,
/// infinities, subnormals, both zeros and extremes, then all 65,536 BF16 bit patterns.
/// Each 64-byte extent is stored as a real zstd frame (P15's `representation` codec), and
/// the manifest's extent verification decodes it with `ZstdDecoder` through its bounded
/// output and checks the decoded content key: every extent comes back byte for byte and
/// every BF16 pattern sits in place. A decoder that canonicalizes NaNs or negative zero,
/// as a float-typed kernel might, changes bits and is refused, so a representation that is
/// only numerically equal never passes for exact. Not covered: decoders on the GPU, which
/// need hardware, and codecs other than zstd, none of which is linked.
#[test]
fn gpu_t34_special_float_patterns_round_trip_bit_exactly() {
    let weights = special_weights();
    let (manifest, stored) = zstd_manifest(&weights);
    let mut decoded = Vec::with_capacity(weights.len());
    for (offset, expected) in chunks(&weights).iter().enumerate() {
        let index = 2 + offset;
        assert!(
            stored[index].starts_with(&ZSTD_MAGIC.to_le_bytes()),
            "a zstd frame"
        );
        let bytes = manifest
            .verify_extent(index, &stored[index], None, &[&ZstdDecoder])
            .unwrap();
        assert_eq!(&bytes, expected, "extent {index} is bit-exact");
        decoded.extend(bytes);
    }
    assert_eq!(decoded, weights);
    for pattern in 0..=u16::MAX {
        let at = 128 + 2 * usize::from(pattern);
        assert_eq!(u16::from_le_bytes([decoded[at], decoded[at + 1]]), pattern);
    }
    let nan_bits = u32::from_le_bytes([decoded[68], decoded[69], decoded[70], decoded[71]]);
    assert_eq!(nan_bits, 0x7fc0_0001, "the f32 NaN payload survives");
    for pattern in [0x7fc1_usize, 0x8000] {
        let index = 2 + (128 + 2 * pattern) / G as usize;
        assert_eq!(
            manifest.verify_extent(index, &stored[index], None, &[&CanonicalizingZstd]),
            Err(mf::ExtentError::ContentKeyMismatch),
            "canonicalizing {pattern:#06x} is refused"
        );
    }
}

/// GPU-T35 (line 1317): a codec stream with a malformed length, table or dictionary is
/// rejected within bounds before any out-of-range access.
///
/// Every case goes through the manifest's extent verification with P15's `ZstdDecoder`,
/// the malformed frame sealed under a valid encoded digest so that it reaches the
/// decoder. A wrong magic number, a truncated header, a declared content size above the
/// extent's true length, a window above what that length allows, trailing bytes after
/// the frame, a frame that needs a dictionary the manifest does not supply, and a
/// decompression bomb of run-length blocks are each refused with a typed decode error,
/// and the same frame decoded alone never hands out a byte past the bound. A corrupted
/// compressed block, where zstd's literal and sequence tables live, is refused too.
/// Before the decoder runs, the manifest refuses a stored length that is wrong, a
/// missing, unexpected or different dictionary and a stored digest mismatch; validation
/// refuses a declared length past the per-extent bound. Not covered: decoders on the GPU,
/// which need hardware, and codecs other than zstd, none of which is linked.
#[test]
fn gpu_t35_malformed_codec_streams_are_refused_within_bounds() {
    let data = plain_floats();
    let first = chunks(&weights_file(&data))[0].clone();
    let valid = zstd_frame(0, &first);
    let mut wrong_magic = valid.clone();
    wrong_magic[0] ^= 0xff;
    let truncated = valid[..5].to_vec();
    let oversized = zstd_frame(0, &[0x5a; 128]);
    let wide_window = hand_made_frame(0x00, &[0x58], &block_header(true, 0, 0));
    let mut trailing = valid.clone();
    trailing.extend_from_slice(&[0xde, 0xad]);
    let mut raw_block = block_header(true, 0, G as u32).to_vec();
    raw_block.extend_from_slice(&first);
    let needs_dictionary = hand_made_frame(0x21, &[0x07, G as u8], &raw_block);
    let mut runs = Vec::new();
    for block in 0..64 {
        runs.extend_from_slice(&block_header(block == 63, 1, 1_024));
        runs.push(0xab);
    }
    let bomb = hand_made_frame(0x00, &[0x00], &runs);
    let bound = mf::DecodeError::BoundExceeded { limit_bytes: G };
    for (case, stream, refusal) in [
        ("wrong magic", wrong_magic, mf::DecodeError::Corrupt),
        ("truncated header", truncated, mf::DecodeError::Corrupt),
        ("content size above the bound", oversized, bound),
        ("window above the allowed size", wide_window, bound),
        ("trailing bytes", trailing, mf::DecodeError::Corrupt),
        (
            "missing dictionary",
            needs_dictionary,
            mf::DecodeError::DictionaryRequired,
        ),
        ("decompression bomb", bomb, bound),
    ] {
        let (manifest, stored) = encoded_manifest(&data, None, |index, chunk| {
            if index == 0 {
                stream.clone()
            } else {
                zstd_frame(index, chunk)
            }
        });
        assert_eq!(
            manifest.verify_extent(2, &stored[2], None, &[&ZstdDecoder]),
            Err(mf::ExtentError::Decode(refusal)),
            "{case}"
        );
        assert!(
            manifest
                .verify_extent(3, &stored[3], None, &[&ZstdDecoder])
                .is_ok(),
            "{case}: the honest extents still decode"
        );
        let mut received = 0u64;
        let alone = decode_frame(&stream, None, G, |piece| {
            received += piece.len() as u64;
            Ok(())
        });
        assert_eq!(alone, Err(refusal), "{case}");
        assert!(received <= G, "{case}: nothing past the bound");
    }

    let mut text = [0u8; 128];
    text.copy_from_slice(&b"abcd".repeat(32));
    let frame = zstd_frame(1, &text[..64]);
    let header = inspect_frame_header(&frame, G, None).unwrap();
    assert_eq!(
        (frame[header.header_bytes] >> 1) & 0x03,
        2,
        "a compressed block"
    );
    let mut damaged = frame.clone();
    damaged[header.header_bytes + 3] ^= 0xff;
    let (manifest, stored) = encoded_manifest(&text, None, |index, chunk| {
        if index == 1 {
            damaged.clone()
        } else {
            zstd_frame(index, chunk)
        }
    });
    assert!(matches!(
        manifest.verify_extent(3, &stored[3], None, &[&ZstdDecoder]),
        Err(mf::ExtentError::Decode(_)
            | mf::ExtentError::DecodedLength { .. }
            | mf::ExtentError::ContentKeyMismatch)
    ));
    let mut received = 0u64;
    let _ = decode_frame(&damaged, None, G, |piece| {
        received += piece.len() as u64;
        Ok(())
    });
    assert!(received <= G, "a damaged block never writes past the bound");

    let dictionary: &[u8] = b"a raw-content dictionary of model bytes, shared by extents";
    let (with_dictionary, stored) = encoded_manifest(&data, Some(dictionary), |_, chunk| {
        codec_encode(chunk, DEFAULT_LEVEL, Some(dictionary)).unwrap()
    });
    let decoder = CountedZstd::default();
    assert!(with_dictionary
        .verify_extent(2, &stored[2], Some(dictionary), &[&decoder])
        .is_ok());
    let before = decoder.calls.load(Ordering::SeqCst);
    assert!(matches!(
        with_dictionary.verify_extent(2, &stored[2][..4], Some(dictionary), &[&decoder]),
        Err(mf::ExtentError::StoredLength { .. })
    ));
    assert_eq!(
        with_dictionary.verify_extent(2, &stored[2], None, &[&decoder]),
        Err(mf::ExtentError::DictionaryMissing)
    );
    assert_eq!(
        with_dictionary.verify_extent(2, &stored[2], Some(b"another"), &[&decoder]),
        Err(mf::ExtentError::DictionaryMismatch)
    );
    let mut flipped = stored[2].clone();
    flipped[6] ^= 0x01;
    assert_eq!(
        with_dictionary.verify_extent(2, &flipped, Some(dictionary), &[&decoder]),
        Err(mf::ExtentError::EncodedDigestMismatch)
    );
    assert_eq!(
        decoder.calls.load(Ordering::SeqCst),
        before,
        "none of these reached the decoder"
    );
    let raw = raw_manifest_builder(&data).finish().unwrap();
    assert_eq!(
        raw.verify_extent(0, &payload(191, 100)[..64], Some(dictionary), &[]),
        Err(mf::ExtentError::UnexpectedDictionary)
    );
    let mut oversized = with_dictionary.manifest().clone();
    oversized.extents.extents[2].true_length_bytes =
        mf::ManifestBounds::DEFAULT.max_extent_bytes + 1;
    assert!(matches!(
        oversized.validate().map(|_| ()),
        Err(mf::ManifestError::DecompressionBound { .. })
    ));
}

// ---------------------------------------------------------------------------------------
// VMM fixtures: P05's model on its fake driver with CORE-01 evidence from fake probes.
// ---------------------------------------------------------------------------------------

const P1: vmm::ProcessId = vmm::ProcessId(1);
const P2: vmm::ProcessId = vmm::ProcessId(2);
const P3: vmm::ProcessId = vmm::ProcessId(3);
const DEVICE: vmm::DeviceOrdinal = vmm::DeviceOrdinal(0);
const STREAM: vmm::StreamId = vmm::StreamId(7);
const POSIX: ShareableHandle = ShareableHandle::PosixFileDescriptor;

fn vmm_runtime() -> RuntimeSubject {
    RuntimeSubject {
        category: ExecutionCategory::SharedKernelGpuRuntime,
        release: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
        instance: named("instance", "wsl"),
    }
}

fn private_memory() -> vmm::AllocationProperties {
    vmm::AllocationProperties {
        device: DEVICE,
        requested_handle: None,
    }
}

fn posix_memory() -> vmm::AllocationProperties {
    vmm::AllocationProperties {
        device: DEVICE,
        requested_handle: Some(POSIX),
    }
}

fn batch_digest(name: &str, batch: u32) -> Digest {
    named("batch", &format!("{name}/{batch}"))
}

fn vmm_layout(name: &str, lengths: &[u64]) -> vmm::ArtifactLayout {
    vmm::ArtifactLayout {
        artifact: named("artifact", name),
        content: ContentKey::of(name.as_bytes()),
        batches: lengths
            .iter()
            .zip(0u32..)
            .map(|(length_bytes, batch)| vmm::BatchSpec {
                length_bytes: *length_bytes,
                digest: batch_digest(name, batch),
            })
            .collect(),
    }
}

/// A clean drop on a verified local copy of `name`'s content (T08's clean-eviction rule).
fn clean_drop(name: &str) -> vmm::ParkSource {
    let content = ContentKey::of(name.as_bytes());
    vmm::ParkSource::CleanDrop {
        copy: vmm::VerifiedCanonicalCopy::reconstructing(
            &ReconstructibleCopy {
                tier: CopyTier::LocalStorage,
                verification: CopyVerification::Verified {
                    content: Content::Immutable(content),
                },
            },
            content,
        )
        .unwrap(),
    }
}

/// One GPU: processes P1 and P2 in one WSL2 runtime, CORE-01 probes for CUDA VMM
/// allocation and both CUDA IPC API families, and the fake driver at the edge.
struct Gpu {
    registry: ProbeRegistry<TestClock>,
    vmm_probe: Arc<FakeProbe>,
    legacy_probe: Arc<FakeProbe>,
    allocation_probe: Arc<FakeProbe>,
    driver: vmm::FakeDriver,
    model: vmm::VmmModel,
}

impl Gpu {
    fn new(clock: &TestClock) -> Self {
        let mut registry = ProbeRegistry::new(Arc::clone(clock));
        let vmm_probe = Arc::new(FakeProbe::cuda_vmm_shareable_handles());
        let legacy_probe = Arc::new(FakeProbe::legacy_cuda_ipc());
        let allocation_probe = Arc::new(FakeProbe::new(
            Capability::CudaVmmAllocation,
            SourceClass::HostProbe,
        ));
        registry.register(Box::new(Arc::clone(&vmm_probe))).unwrap();
        registry
            .register(Box::new(Arc::clone(&legacy_probe)))
            .unwrap();
        registry
            .register(Box::new(Arc::clone(&allocation_probe)))
            .unwrap();
        let mut driver = vmm::FakeDriver::new();
        driver.add_device(
            DEVICE,
            vmm::FakeDeviceSpec {
                capacity_bytes: GIB,
                granularity_bytes: BTreeMap::from([(None, 4 * MIB), (Some(POSIX), 8 * MIB)]),
            },
        );
        let mut gpu_host = Self {
            registry,
            vmm_probe,
            legacy_probe,
            allocation_probe,
            driver,
            model: vmm::VmmModel::new(),
        };
        for process in [P1, P2] {
            gpu_host.add_process(process);
        }
        gpu_host
    }

    /// Installs the CORE-01 gate's plan for `process` under a profile that permits both
    /// CUDA IPC families (INT-06); the gate enables each only where evidence shows it.
    fn permit_ipc(&mut self, process: vmm::ProcessId) {
        let context = self.model.process_context(process).unwrap();
        let policy = EvidencePolicy {
            minimum_source: SourceClass::HostProbe,
            max_age: HOUR,
        };
        let profile = RuntimeProfile {
            runtime: context.runtime.clone(),
            configuration: context.configuration,
            permitted: BTreeMap::from([
                (Optimization::CudaIpcLegacy, policy),
                (Optimization::CudaIpcVmmShareableHandle, policy),
            ]),
        };
        let request = LoaderRequest {
            optimizations: BTreeMap::from([
                (Optimization::CudaIpcLegacy, Necessity::Optional),
                (Optimization::CudaIpcVmmShareableHandle, Necessity::Optional),
            ]),
        };
        let plan = LoaderGate::recorded()
            .plan(&profile, &request, &self.registry)
            .unwrap();
        self.model.set_loader_plan(process, plan).unwrap();
    }

    /// Adds a process of the same WSL2 runtime on device 0.
    fn add_process(&mut self, process: vmm::ProcessId) {
        self.driver.add_process(process, DEVICE);
        self.model
            .register_process(vmm::ProcessContext {
                process,
                device: DEVICE,
                runtime: vmm_runtime(),
                configuration: driver_configuration("580.1"),
                reports_from: SourceClass::HostProbe,
                evidence_policy: EvidencePolicy {
                    minimum_source: SourceClass::HostProbe,
                    max_age: MINUTE,
                },
            })
            .unwrap();
    }

    fn show_vmm_handles(&mut self, handle: ShareableHandle) {
        let subject = Subject::Runtime(vmm_runtime());
        self.vmm_probe.respond(
            &subject,
            Observation::supported(
                driver_configuration("580.1"),
                HOUR,
                SupportDetail::CudaIpcVmmShareableHandle { handle },
            ),
        );
        self.registry
            .refresh(Capability::CudaIpcVmmShareableHandle, &subject)
            .unwrap();
    }

    fn show_legacy_ipc(&mut self) {
        let subject = Subject::Runtime(vmm_runtime());
        self.legacy_probe.respond(
            &subject,
            Observation::supported(
                driver_configuration("580.1"),
                HOUR,
                SupportDetail::CudaIpcLegacy,
            ),
        );
        self.registry
            .refresh(Capability::CudaIpcLegacy, &subject)
            .unwrap();
    }

    /// A host probe shows CUDA VMM allocation with exactly `properties` in `process`'s
    /// runtime, under its configuration now, at the granularity the fake device reports.
    fn show_allocation(&mut self, process: vmm::ProcessId, properties: vmm::AllocationProperties) {
        let context = self.model.process_context(process).unwrap();
        let subject = Subject::CudaAllocation(CudaAllocationSubject {
            runtime: context.runtime.clone(),
            device_ordinal: properties.device.0,
            requested_handle: properties.requested_handle,
        });
        let granularity_bytes = match properties.requested_handle {
            None => 4 * MIB,
            Some(_) => 8 * MIB,
        };
        self.allocation_probe.respond(
            &subject,
            Observation::supported(
                context.configuration,
                HOUR,
                SupportDetail::CudaVmmAllocation {
                    granularity_bytes: NonZeroU64::new(granularity_bytes).unwrap(),
                },
            ),
        );
        self.registry
            .refresh(Capability::CudaVmmAllocation, &subject)
            .unwrap();
    }

    fn plan(
        &mut self,
        process: vmm::ProcessId,
        name: &str,
        lengths: &[u64],
        properties: vmm::AllocationProperties,
        origin: vmm::VmmOrigin,
    ) -> vmm::MappingKey {
        self.show_allocation(process, properties);
        self.model
            .probe_granularity(&mut self.driver, &self.registry, process, properties, HOUR)
            .unwrap();
        self.model
            .plan_vmm(
                &mut self.driver,
                &self.registry,
                process,
                &vmm_layout(name, lengths),
                properties,
                origin,
            )
            .unwrap()
    }

    /// Maps, populates, completes and publishes one batch.
    fn fill(&mut self, key: vmm::MappingKey, name: &str, batch: u32) {
        self.model
            .back_batch(&mut self.driver, &self.registry, key, batch)
            .unwrap();
        let event = self
            .model
            .populate_batch(&mut self.driver, key, batch, STREAM)
            .unwrap();
        assert!(self.driver.complete(event));
        self.model
            .publish_batch(&mut self.driver, key, batch, batch_digest(name, batch))
            .unwrap();
    }

    /// Plans and fills an artifact `process` creates.
    fn load(
        &mut self,
        process: vmm::ProcessId,
        name: &str,
        lengths: &[u64],
        properties: vmm::AllocationProperties,
    ) -> vmm::MappingKey {
        let key = self.plan(process, name, lengths, properties, vmm::VmmOrigin::Create);
        for batch in 0..lengths.len() as u32 {
            self.fill(key, name, batch);
        }
        key
    }

    fn physical_of(&self, key: vmm::MappingKey, batch: u32) -> vmm::PhysicalId {
        self.model.batch(key, batch).unwrap().physical.unwrap()
    }

    fn count_calls(&self, name: &str) -> usize {
        self.driver
            .calls()
            .iter()
            .filter(|call| call.call.api_name() == name)
            .count()
    }
}

// ---------------------------------------------------------------------------------------
// GPU-T22, GPU-T24, GPU-T25: IPC handles, unmapping and graphs.
// ---------------------------------------------------------------------------------------

/// GPU-T22 (line 1304): a wrong IPC handle type or a stale generation is rejected and the
/// mapping is reconstructed safely.
///
/// An allocation created for POSIX descriptors refuses to export as a Win32 handle, a
/// legacy CUDA IPC handle is refused where a VMM shareable handle is expected, and a
/// closed export is refused as stale; none reaches the driver's import. A fresh export is
/// imported and published on the receiver's own verification. After its own park the
/// receiver imports a fresh export of the same allocation again: the handle it released
/// does not block it. When the exporter re-creates the memory after a park, the batch has
/// a newer GPU allocation generation, a handle recorded under the old one is recognisably
/// stale, the old export stays refused, and a fresh export of the new allocation is
/// imported by a receiver of the same runtime.
#[test]
fn gpu_t22_wrong_or_stale_ipc_handles_are_refused_and_rebuilt() {
    let clock = test_clock();
    let mut gpu_host = Gpu::new(&clock);
    gpu_host.add_process(P3);
    gpu_host.show_vmm_handles(POSIX);
    gpu_host.show_legacy_ipc();
    for process in [P1, P2, P3] {
        gpu_host.permit_ipc(process);
    }
    let key = gpu_host.load(P1, "a", &[8 * MIB], posix_memory());
    let physical = gpu_host.physical_of(key, 0);
    let first_generation = gpu_host.model.batch(key, 0).unwrap().generation.unwrap();
    assert_eq!(
        gpu_host.model.export_allocation(
            &mut gpu_host.driver,
            &gpu_host.registry,
            P1,
            physical,
            ShareableHandle::Win32Handle
        ),
        Err(VmmError::NotCreatedForHandleType {
            physical,
            requested: ShareableHandle::Win32Handle,
            created: Some(POSIX),
        })
    );
    let legacy = gpu_host
        .model
        .plan_legacy(
            P1,
            named("artifact", "legacy"),
            ContentKey::of(b"legacy"),
            vmm::BatchSpec {
                length_bytes: 4 * MIB,
                digest: batch_digest("legacy", 0),
            },
        )
        .unwrap();
    gpu_host.fill(legacy, "legacy", 0);
    let legacy_export = gpu_host
        .model
        .legacy_export(&mut gpu_host.driver, &gpu_host.registry, legacy)
        .unwrap();
    let receiver = gpu_host.plan(P2, "a", &[8 * MIB], posix_memory(), vmm::VmmOrigin::Import);
    assert_eq!(
        gpu_host.model.import_batch(
            &mut gpu_host.driver,
            &gpu_host.registry,
            receiver,
            0,
            legacy_export
        ),
        Err(VmmError::WrongExportKind {
            export: legacy_export
        })
    );
    let stale = gpu_host
        .model
        .export_allocation(
            &mut gpu_host.driver,
            &gpu_host.registry,
            P1,
            physical,
            POSIX,
        )
        .unwrap();
    gpu_host
        .model
        .close_export(&mut gpu_host.driver, stale)
        .unwrap();
    assert_eq!(
        gpu_host
            .model
            .import_batch(&mut gpu_host.driver, &gpu_host.registry, receiver, 0, stale),
        Err(VmmError::ExportClosed { export: stale })
    );
    assert_eq!(gpu_host.count_calls("cuMemImportFromShareableHandle"), 0);

    let fresh = gpu_host
        .model
        .export_allocation(
            &mut gpu_host.driver,
            &gpu_host.registry,
            P1,
            physical,
            POSIX,
        )
        .unwrap();
    gpu_host
        .model
        .import_batch(&mut gpu_host.driver, &gpu_host.registry, receiver, 0, fresh)
        .unwrap();
    gpu_host
        .model
        .publish_batch(&mut gpu_host.driver, receiver, 0, batch_digest("a", 0))
        .unwrap();
    let view = gpu_host.model.create_view(receiver, 0, 8 * MIB).unwrap();
    let event = gpu_host
        .model
        .call_view(&mut gpu_host.driver, view, STREAM)
        .unwrap();
    assert!(gpu_host.driver.complete(event));
    gpu_host
        .model
        .close_export(&mut gpu_host.driver, fresh)
        .unwrap();
    gpu_host
        .model
        .begin_park(&mut gpu_host.driver, receiver, clean_drop("a"))
        .unwrap();
    gpu_host
        .model
        .finish_park(&mut gpu_host.driver, receiver)
        .unwrap();
    gpu_host.model.wake(receiver).unwrap();
    let again = gpu_host
        .model
        .export_allocation(
            &mut gpu_host.driver,
            &gpu_host.registry,
            P1,
            physical,
            POSIX,
        )
        .unwrap();
    assert_eq!(
        gpu_host
            .model
            .import_batch(&mut gpu_host.driver, &gpu_host.registry, receiver, 0, again),
        Ok(physical),
        "the handle the park released does not block a fresh import"
    );
    gpu_host
        .model
        .publish_batch(&mut gpu_host.driver, receiver, 0, batch_digest("a", 0))
        .unwrap();
    let event = gpu_host
        .model
        .call_view(&mut gpu_host.driver, view, STREAM)
        .unwrap();
    assert!(gpu_host.driver.complete(event));
    gpu_host
        .model
        .close_export(&mut gpu_host.driver, again)
        .unwrap();
    gpu_host
        .model
        .begin_park(&mut gpu_host.driver, receiver, clean_drop("a"))
        .unwrap();
    gpu_host
        .model
        .finish_park(&mut gpu_host.driver, receiver)
        .unwrap();

    gpu_host
        .model
        .begin_park(&mut gpu_host.driver, key, clean_drop("a"))
        .unwrap();
    gpu_host
        .model
        .finish_park(&mut gpu_host.driver, key)
        .unwrap();
    gpu_host.model.wake(key).unwrap();
    gpu_host.fill(key, "a", 0);
    let second_generation = gpu_host.model.batch(key, 0).unwrap().generation.unwrap();
    assert!(second_generation > first_generation);
    let old_handle = NativeHandle::new(NativeHandleKind::IpcHandle, 0x42, first_generation);
    assert!(
        old_handle.allocation() < second_generation,
        "recognisably stale"
    );
    let newer = gpu_host.physical_of(key, 0);
    let late = gpu_host.plan(P3, "a", &[8 * MIB], posix_memory(), vmm::VmmOrigin::Import);
    assert_eq!(
        gpu_host
            .model
            .import_batch(&mut gpu_host.driver, &gpu_host.registry, late, 0, fresh),
        Err(VmmError::ExportClosed { export: fresh })
    );
    let rebuilt = gpu_host
        .model
        .export_allocation(&mut gpu_host.driver, &gpu_host.registry, P1, newer, POSIX)
        .unwrap();
    assert_eq!(
        gpu_host
            .model
            .import_batch(&mut gpu_host.driver, &gpu_host.registry, late, 0, rebuilt),
        Ok(newer)
    );
    gpu_host
        .model
        .publish_batch(&mut gpu_host.driver, late, 0, batch_digest("a", 0))
        .unwrap();
    assert!(gpu_host.driver.refusals().is_empty());
}

/// GPU-T24 (line 1306): unmapping requested during a kernel or graph replay waits until
/// quiescent; nothing uses memory after it is unmapped.
///
/// With a kernel and a graph replay in flight, the park cannot finish: it names both
/// events, the range stays mapped and no new work is admitted. Completing one event is
/// not enough. Once both complete the range is unmapped, and the view and the graph are
/// refused rather than run over unmapped memory. Not covered: real kernel timing and the
/// driver's own unmap behaviour, which need a GPU; the fake driver refuses any call out of
/// Appendix E's order.
#[test]
fn gpu_t24_unmapping_waits_for_kernels_and_graphs_to_drain() {
    let clock = test_clock();
    let mut gpu_host = Gpu::new(&clock);
    let key = gpu_host.load(P1, "a", &[4 * MIB], private_memory());
    let view = gpu_host.model.create_view(key, 0, 4 * MIB).unwrap();
    let kernel = gpu_host
        .model
        .call_view(&mut gpu_host.driver, view, STREAM)
        .unwrap();
    let graph_key = vmm::GraphExecutionKey {
        model: named("graph-model", "a"),
        kernels: named("graph-kernels", "v1"),
        shapes: named("graph-shapes", "4x512"),
        arguments: named("graph-arguments", "default"),
    };
    let resources = vec![vmm::GraphResource::Artifact {
        artifact: named("artifact", "a"),
        offset_bytes: 0,
        length_bytes: 4 * MIB,
    }];
    let graph = gpu_host
        .model
        .capture_graph(P1, graph_key, resources)
        .unwrap();
    let replay = gpu_host
        .model
        .launch_graph(&mut gpu_host.driver, graph, STREAM)
        .unwrap();
    gpu_host
        .model
        .begin_park(&mut gpu_host.driver, key, clean_drop("a"))
        .unwrap();
    let not_quiescent = gpu_host.model.finish_park(&mut gpu_host.driver, key);
    let Err(VmmError::NotQuiescent { events }) = not_quiescent else {
        panic!("the park waits: {not_quiescent:?}");
    };
    assert_eq!(
        events.iter().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([kernel, replay])
    );
    let start = gpu_host.model.reservation(key).unwrap().start;
    assert!(gpu_host.driver.is_mapped(P1, start), "still mapped");
    assert!(matches!(
        gpu_host.model.call_view(&mut gpu_host.driver, view, STREAM),
        Err(VmmError::NotCallable {
            reason: NotCallableReason::Draining,
            ..
        })
    ));
    assert!(gpu_host.driver.complete(kernel));
    assert!(matches!(
        gpu_host.model.finish_park(&mut gpu_host.driver, key),
        Err(VmmError::NotQuiescent { .. })
    ));
    assert!(gpu_host.driver.complete(replay));
    gpu_host
        .model
        .detach_graph(&mut gpu_host.driver, graph)
        .unwrap();
    gpu_host
        .model
        .finish_park(&mut gpu_host.driver, key)
        .unwrap();
    assert!(!gpu_host.driver.is_mapped(P1, start));
    let enqueued = gpu_host.count_calls("enqueue");
    assert!(matches!(
        gpu_host.model.call_view(&mut gpu_host.driver, view, STREAM),
        Err(VmmError::NotCallable {
            reason: NotCallableReason::Parked,
            ..
        })
    ));
    assert!(gpu_host
        .model
        .launch_graph(&mut gpu_host.driver, graph, STREAM)
        .is_err());
    assert_eq!(
        gpu_host.count_calls("enqueue"),
        enqueued,
        "nothing ran after the unmap"
    );
    assert!(gpu_host.driver.refusals().is_empty());
}

/// GPU-T25 (line 1307): the same address with a changed graph ABI is recaptured or
/// rebuilt, never replayed blindly.
///
/// A graph captured over an artifact is refused for another kernel set or capture shape
/// although every resource sits at the same address, and accepted only for its own key.
/// A recapture under the new key replays. In T07's graph execution key the same device
/// address with another layout or allocation generation is a differing resource, so the
/// identity refuses reuse as well.
#[test]
fn gpu_t25_a_changed_graph_abi_at_the_same_address_is_recaptured() {
    let clock = test_clock();
    let mut gpu_host = Gpu::new(&clock);
    let key = gpu_host.load(P1, "a", &[4 * MIB], private_memory());
    let captured = vmm::GraphExecutionKey {
        model: named("graph-model", "a"),
        kernels: named("graph-kernels", "v1"),
        shapes: named("graph-shapes", "4x512"),
        arguments: named("graph-arguments", "default"),
    };
    let resources = vec![vmm::GraphResource::Artifact {
        artifact: named("artifact", "a"),
        offset_bytes: 0,
        length_bytes: 4 * MIB,
    }];
    let graph = gpu_host
        .model
        .capture_graph(P1, captured, resources.clone())
        .unwrap();
    let new_kernels = vmm::GraphExecutionKey {
        kernels: named("graph-kernels", "v2"),
        ..captured
    };
    let new_shape = vmm::GraphExecutionKey {
        shapes: named("graph-shapes", "8x512"),
        ..captured
    };
    for (changed, mismatch) in [
        (new_kernels, vmm::GraphMismatch::Kernels),
        (new_shape, vmm::GraphMismatch::Shapes),
    ] {
        assert_eq!(
            gpu_host
                .model
                .reuse_graph(&mut gpu_host.driver, graph, changed, &resources),
            Err(VmmError::GraphIncompatible { graph, mismatch })
        );
    }
    gpu_host
        .model
        .reuse_graph(&mut gpu_host.driver, graph, captured, &resources)
        .unwrap();
    let recaptured = gpu_host
        .model
        .capture_graph(P1, new_kernels, resources)
        .unwrap();
    assert_ne!(recaptured, graph);
    let event = gpu_host
        .model
        .launch_graph(&mut gpu_host.driver, recaptured, STREAM)
        .unwrap();
    assert!(gpu_host.driver.complete(event));
    assert_eq!(
        gpu_host.model.reservation(key).unwrap().length_bytes,
        4 * MIB
    );

    let execution = execution_of(
        &logical_of(hub_source("example-org/chat", COMMIT_A, b"w"), "t"),
        1,
        "flash-attn",
    );
    let weights = |layout: &str, allocation: GpuAllocationGeneration| IdGraphResource {
        role: label("weights"),
        kind: GraphResourceKind::Weights,
        content: named("weights", "a"),
        allocation,
        device_address: 0x7000_0000,
        length_bytes: 4 * MIB,
        layout: label(layout),
    };
    let spec = |resource: IdGraphResource| GraphCaptureSpec {
        execution,
        device: gpu(0),
        shape: CaptureShape {
            sequences: 4,
            tokens: 512,
        },
        resources: vec![resource],
    };
    let original = spec(weights("row-major", GpuAllocationGeneration::FIRST));
    assert_eq!(
        original.check_reuse(&spec(weights(
            "marlin-tiled",
            GpuAllocationGeneration::FIRST
        ))),
        Err(GraphReuseRefusal::Mismatch {
            differences: vec![GraphDifference::ResourceChanged {
                role: label("weights"),
                fields: vec![GraphResourceField::Layout],
            }]
        })
    );
    assert_eq!(
        original.check_reuse(&spec(weights("row-major", GpuAllocationGeneration::new(2)))),
        Err(GraphReuseRefusal::Mismatch {
            differences: vec![GraphDifference::ResourceChanged {
                role: label("weights"),
                fields: vec![GraphResourceField::Allocation],
            }]
        })
    );
    assert!(original.check_reuse(&original).is_ok());
}

// ---------------------------------------------------------------------------------------
// Placement fixtures: one P04 model slot over the host's CORE-03 ledger, with P04's fake
// coordination port standing in for CORE-04 leases and generations.
// ---------------------------------------------------------------------------------------

const SHAPE: SupportedShape = SupportedShape {
    max_context_tokens: 8_192,
    max_batch_sequences: 4,
};

fn slot_owner() -> ExecutionId {
    execution("exe-owner")
}

/// One part of a model on one rank.
#[derive(Clone, Copy)]
struct Part {
    rank: u64,
    component: Component,
    content: &'static str,
    bytes: u64,
}

fn part(rank: u64, component: Component, content: &'static str, bytes: u64) -> Part {
    Part {
        rank,
        component,
        content,
        bytes,
    }
}

/// Model A: 10 GiB of weights in four parts on rank 0.
fn model_a() -> Vec<Part> {
    vec![
        part(0, Component::Embedding, "a-embed", GIB),
        part(0, Component::Layer(0), "a-layer-0", 4 * GIB),
        part(0, Component::Layer(1), "a-layer-1", 4 * GIB),
        part(0, Component::OutputHead, "a-head", GIB),
    ]
}

/// A weight update of model A: layer 1 changed, the other three parts shared.
fn model_b() -> Vec<Part> {
    let mut parts = model_a();
    parts[2] = part(0, Component::Layer(1), "b-layer-1", 4 * GIB);
    parts
}

fn extent_key(content: &str, device: GpuDeviceKey) -> ExtentKey {
    ExtentKey {
        content: ContentKey::of(content.as_bytes()),
        device,
    }
}

fn position(rank: u64, component: Component) -> WeightPosition {
    WeightPosition::new(Rank::new(rank), component)
}

/// Step 1 of GPU §3.6 for `model`: steady state of its weights plus 2 GiB per device and
/// a 1 GiB transition peak per device, one rank per GPU.
fn activation(model: &str, parts: &[Part]) -> ActivationRequest {
    let layout: BTreeMap<Rank, GpuDeviceKey> = parts
        .iter()
        .map(|part| (Rank::new(part.rank), gpu(part.rank as u8)))
        .collect();
    let mut steady = ResourceDemand::default();
    let mut peak = ResourceDemand::default();
    for part in parts {
        let device = gpu(part.rank as u8);
        *steady.vram_bytes.entry(device).or_insert(2 * GIB) += part.bytes;
        peak.vram_bytes.insert(device, GIB);
    }
    let logical = logical_of(
        hub_source(&format!("example-org/{model}"), COMMIT_A, model.as_bytes()),
        model,
    );
    let artifact = ArtifactIdentity::from_manifest_digest(&named("manifest", model));
    ActivationRequest {
        operation: operation(&format!("activate-{model}")),
        identity: ActivationIdentity {
            execution: execution_of(&logical, layout.len() as u32, "flash-attn"),
            artifact,
            adapters: BTreeMap::new(),
        },
        placement: PlacementChoice::New {
            process: ProcessInstance::new(1),
        },
        artifact: ArtifactValidity::Verified { artifact },
        layout,
        components: parts
            .iter()
            .map(|part| ExtentSpec {
                position: position(part.rank, part.component),
                extent: extent_key(part.content, gpu(part.rank as u8)),
                bytes: part.bytes,
            })
            .collect(),
        steady,
        transition_peak: peak,
        declared_shape: SHAPE,
        preference: TransitionPreference::OverlapOrPause,
    }
}

fn validation(generation: ModelActivationGeneration, rank: u64) -> ValidationReport {
    ValidationReport {
        generation,
        rank: Rank::new(rank),
        weights_verified: true,
        buffers_ready: true,
        graphs_compatible: true,
        coordination: named("communicator", "nccl"),
    }
}

/// A model slot of the VM sandbox `exe-owner` under authorization epoch 1.
struct Slot {
    clock: TestClock,
    ledger: Ledger<TestClock>,
    reservations: PlacementReservations,
    coordination: FakeCoordination,
    slot: PlacementSlot<TestClock>,
}

impl Slot {
    /// `gpus` GPUs of `vram_bytes` each, all in tenant A's budget.
    fn new(clock: &TestClock, gpus: u8, vram_bytes: u64) -> Self {
        let capacities: Vec<(ResourceKey, u64)> = (0..gpus)
            .map(|index| (ResourceKey::Vram(ledger_device(&gpu(index))), vram_bytes))
            .collect();
        let mut coordination = FakeCoordination::new();
        coordination.authorize(&slot_owner(), AuthorizationEpoch::FIRST);
        Self {
            clock: Arc::clone(clock),
            ledger: host_ledger(clock, &capacities, &["tenant-a"]),
            reservations: PlacementReservations::new(LedgerPlacementConfig {
                tenant: tenant("tenant-a"),
                priority: Priority::Foreground,
                parent: None,
                release_source: SourceClass::HostProbe,
            }),
            coordination,
            slot: PlacementSlot::new(
                SlotSpec {
                    slot: SlotId::new(named("slot", "chat")),
                    tenant: tenant("tenant-a"),
                    authority: AuthorityBinding::new(
                        slot_owner(),
                        ExecutionCategory::VmSandbox,
                        Some(AuthorizationEpoch::FIRST),
                    )
                    .unwrap(),
                },
                Arc::clone(clock),
            ),
        }
    }

    /// Runs `step` on the slot with the ledger's reservation port and the coordination port.
    fn with_ports<T>(
        &mut self,
        step: impl FnOnce(&mut PlacementSlot<TestClock>, &mut Ports<'_>) -> T,
    ) -> T {
        let Self {
            ledger,
            reservations,
            coordination,
            slot,
            ..
        } = self;
        let mut port = reservations.port(ledger);
        let mut ports = Ports {
            reservations: &mut port,
            coordination,
        };
        step(slot, &mut ports)
    }

    fn begin(&mut self, request: &ActivationRequest) -> ActivationStarted {
        self.with_ports(|slot, ports| slot.begin_activation(request, ports))
            .unwrap()
    }

    /// Step 2 to the end of loading: every allocated extent usable, runtime initialized,
    /// materialized.
    fn load(&mut self) -> ExtentProgress {
        let progress = self
            .with_ports(|slot, ports| slot.prepare_extents(ports))
            .unwrap();
        for (extent, _) in &progress.allocated {
            self.slot.record_extent_usable(*extent).unwrap();
        }
        self.slot.record_runtime_initialized().unwrap();
        self.slot.materialize().unwrap();
        progress
    }

    /// Steps 3 and 4 on every rank.
    fn validate_and_ready(&mut self) {
        self.slot.begin_activating().unwrap();
        let view = self.slot.activation().unwrap();
        for rank in view.waiting_ranks {
            let report = validation(view.generation, rank.get());
            self.with_ports(|slot, ports| slot.record_validation(&report, ports))
                .unwrap();
            self.with_ports(|slot, ports| {
                slot.record_readiness(
                    view.generation,
                    rank,
                    &ReadinessReport::Ready { supported: SHAPE },
                    ports,
                )
            })
            .unwrap();
        }
    }

    fn publish(&mut self) -> PublishReport {
        self.with_ports(|slot, ports| slot.publish(ports)).unwrap()
    }

    fn activate(&mut self, request: &ActivationRequest) -> PublishReport {
        let started = self.begin(request);
        assert_ne!(started.mode, TransitionMode::DrainFirst);
        self.load();
        self.validate_and_ready();
        self.publish()
    }

    fn admission(&self, name: &str) -> AdmissionRequest {
        AdmissionRequest {
            request: operation(name),
            execution: slot_owner(),
            epoch: AuthorizationEpoch::FIRST,
            shape: RequestShape {
                context_tokens: 4_096,
                batch_sequences: 1,
            },
            adapter: None,
            lease_expires_at: self.clock.now().saturating_add(HOUR),
        }
    }

    fn admit(&mut self, name: &str) -> Result<RequestTicket, RouteRefusal> {
        let admission = self.admission(name);
        self.slot.admit(&admission, &mut self.coordination)
    }

    fn finish(&mut self, ticket: &RequestTicket) {
        self.slot.finish(ticket, &mut self.coordination).unwrap();
    }

    fn park_and_reclaim(&mut self, placement: PlacementKey) -> ReclaimReport {
        assert!(self
            .slot
            .drain_status(placement, &self.coordination)
            .unwrap()
            .is_drained());
        self.slot.park(placement).unwrap();
        let Self {
            ledger,
            reservations,
            slot,
            ..
        } = self;
        let mut port = reservations.port(ledger);
        slot.reclaim(placement, &mut port).unwrap()
    }

    fn vram_reserved(&self, index: u8) -> u64 {
        self.ledger
            .reserved(ResourceKey::Vram(ledger_device(&gpu(index))))
    }

    fn state(&self, placement: PlacementKey) -> StateKind {
        self.slot.placement(placement).unwrap().state.kind()
    }

    fn published_generation(&self) -> Option<ModelActivationGeneration> {
        self.slot.published().map(|content| content.generation)
    }
}

// ---------------------------------------------------------------------------------------
// GPU-T23, GPU-T26 to GPU-T30, GPU-T32, GPU-T33: activation, generations and overlap.
// ---------------------------------------------------------------------------------------

/// GPU-T26 (line 1308): a new activation fails before commit; the old generation continues
/// while it is retained.
///
/// Model A serves. Model B's preparation fails on one extent, and in a second attempt its
/// rank check fails. Each time B ends failed, A stays published and serving, new requests
/// keep A's generation, and B's peak returns to the host ledger at once while its steady
/// share stays counted until B is reclaimed and retired.
#[test]
fn gpu_t26_a_failed_activation_leaves_the_old_generation_serving() {
    let clock = test_clock();
    let mut host = Slot::new(&clock, 1, 32 * GIB);
    let first = host.activate(&activation("model-a", &model_a()));
    assert_eq!(host.vram_reserved(0), 12 * GIB);
    host.admit("before").unwrap();

    let started = host.begin(&activation("model-b", &model_b()));
    assert_eq!(started.mode, TransitionMode::Overlap);
    host.with_ports(|slot, ports| slot.prepare_extents(ports))
        .unwrap();
    let report = host
        .with_ports(|slot, ports| slot.record_extent_failed(extent_key("b-layer-1", gpu(0)), ports))
        .unwrap();
    let failure = report.failure.unwrap();
    assert_eq!(failure.stage, TransientStage::Preparing);
    assert_eq!(host.state(started.placement), StateKind::Failed);
    assert_eq!(host.published_generation(), Some(first.generation));
    assert_eq!(host.state(first.placement), StateKind::Serving);
    assert_eq!(host.admit("after").unwrap().generation, first.generation);
    assert_eq!(host.vram_reserved(0), 24 * GIB, "the peak is back");
    {
        let Slot {
            ledger,
            reservations,
            slot,
            ..
        } = &mut host;
        let mut port = reservations.port(ledger);
        slot.reclaim(started.placement, &mut port).unwrap();
    }
    host.slot.retire(started.placement).unwrap();
    assert_eq!(host.vram_reserved(0), 12 * GIB);

    let again = host.begin(&activation("model-b", &model_b()));
    host.load();
    host.slot.begin_activating().unwrap();
    let unverified = ValidationReport {
        weights_verified: false,
        ..validation(again.generation, 0)
    };
    let error = host
        .with_ports(|slot, ports| slot.record_validation(&unverified, ports))
        .unwrap_err();
    let ActivationError::Failed { report } = error else {
        panic!("the activation fails: {error:?}");
    };
    assert_eq!(
        report.failure.map(|failure| failure.reason),
        Some(PlacementFailure::ValidationFailed {
            rank: Rank::new(0),
            check: ValidationCheck::Weights
        })
    );
    assert_eq!(host.published_generation(), Some(first.generation));
    assert_eq!(host.admit("still-a").unwrap().generation, first.generation);
}

/// GPU-T27 (line 1309): capacity allows only drain-then-load; an honest pause and reload
/// recovery.
///
/// On 20 GiB two versions of 12 GiB cannot overlap, so model B's activation drains model
/// A first and reports a pause with its reason and start. Requests during the pause are
/// refused naming it, the in-flight request finishes, A is reclaimed and its share passes
/// to B without returning to the pool, and the pause ends with B's publication and its
/// measured length. A's rollback is honestly a reload, not an instant switch. A drain-first
/// activation that fails ends the pause as failed and leaves nothing serving.
#[test]
fn gpu_t27_drain_then_load_reports_an_honest_pause_and_recovers_by_reload() {
    let clock = test_clock();
    let mut host = Slot::new(&clock, 1, 20 * GIB);
    let first = host.activate(&activation("model-a", &model_a()));
    let in_flight = host.admit("in-flight").unwrap();
    clock.advance(10 * SECOND);

    let started = host.begin(&activation("model-b", &model_b()));
    assert_eq!(started.mode, TransitionMode::DrainFirst);
    let pause = started.pause.clone().unwrap();
    assert_eq!(pause.started_at, clock.now());
    assert!(matches!(
        pause.reason,
        PauseReason::SingleGenerationCapacity { .. }
    ));
    assert_eq!(
        host.admit("during-pause"),
        Err(RouteRefusal::Paused {
            since: pause.started_at,
            reason: pause.reason
        })
    );
    assert_eq!(
        host.vram_reserved(0),
        13 * GIB,
        "only the new peak was added"
    );
    let progress = host
        .with_ports(|slot, ports| slot.prepare_extents(ports))
        .unwrap();
    assert_eq!(progress.acquired.len(), 3, "shared parts are kept");
    assert_eq!(
        progress.waiting_for_predecessor,
        vec![extent_key("b-layer-1", gpu(0))]
    );
    clock.advance(5 * SECOND);
    host.finish(&in_flight);
    let reclaimed = host.park_and_reclaim(first.placement);
    assert_eq!(reclaimed.freed.len(), 1, "only the changed layer is freed");
    assert_eq!(host.vram_reserved(0), 13 * GIB, "A's share passed to B");
    host.load();
    host.validate_and_ready();
    clock.advance(15 * SECOND);
    let report = host.publish();
    let pause = report.pause.unwrap();
    assert_eq!(pause.ended_at, Some(clock.now()));
    assert_eq!(
        pause.outcome,
        Some(PauseOutcome::Resumed {
            generation: report.generation
        })
    );
    assert_eq!(pause.duration(clock.now()), 20 * SECOND);
    assert!(matches!(
        report.predecessor_rollback,
        Some(RollbackOutlook::RequiresReload { .. })
    ));
    assert_eq!(host.admit("resumed").unwrap().generation, report.generation);
    assert_eq!(host.vram_reserved(0), 12 * GIB);

    let mut failing = Slot::new(&clock, 1, 20 * GIB);
    let first = failing.activate(&activation("model-a", &model_a()));
    let started = failing.begin(&activation("model-b", &model_b()));
    failing.park_and_reclaim(first.placement);
    failing.load();
    failing.slot.begin_activating().unwrap();
    let report = validation(started.generation, 0);
    failing
        .with_ports(|slot, ports| slot.record_validation(&report, ports))
        .unwrap();
    let error = failing
        .with_ports(|slot, ports| {
            slot.record_readiness(
                started.generation,
                Rank::new(0),
                &ReadinessReport::NotReady,
                ports,
            )
        })
        .unwrap_err();
    let ActivationError::Failed { report } = error else {
        panic!("the activation fails: {error:?}");
    };
    assert_eq!(
        report.pause.unwrap().outcome,
        Some(PauseOutcome::ActivationFailed)
    );
    assert_eq!(failing.admit("after"), Err(RouteRefusal::NotServing));
}

/// GPU-T28 (line 1310): one rank fails after the others prepared; no partial serving epoch.
///
/// A two-rank model on two GPUs: rank 0 validates and reports ready, so publication is
/// refused while rank 1 is missing; rank 1's validation then fails and the whole
/// activation fails. Nothing is published, requests are refused, and no rank's placement
/// identity of that generation is ever published. With an older two-rank generation
/// serving, the same failure leaves the older generation published on both ranks.
#[test]
fn gpu_t28_a_failed_rank_never_leaves_a_partial_serving_epoch() {
    let parts = |model: &'static str| -> Vec<Part> {
        let (embed, layer0, layer1, head) = match model {
            "model-m" => ("m-embed", "m-layer-0", "m-layer-1", "m-head"),
            _ => ("n-embed", "n-layer-0", "n-layer-1", "n-head"),
        };
        vec![
            part(0, Component::Embedding, embed, GIB),
            part(0, Component::Layer(0), layer0, 4 * GIB),
            part(1, Component::Layer(1), layer1, 4 * GIB),
            part(1, Component::OutputHead, head, GIB),
        ]
    };
    let clock = test_clock();
    let mut host = Slot::new(&clock, 2, 32 * GIB);
    let started = host.begin(&activation("model-m", &parts("model-m")));
    host.load();
    host.slot.begin_activating().unwrap();
    let rank0 = validation(started.generation, 0);
    host.with_ports(|slot, ports| slot.record_validation(&rank0, ports))
        .unwrap();
    host.with_ports(|slot, ports| {
        slot.record_readiness(
            started.generation,
            Rank::new(0),
            &ReadinessReport::Ready { supported: SHAPE },
            ports,
        )
    })
    .unwrap();
    assert!(matches!(
        host.with_ports(|slot, ports| slot.publish(ports)),
        Err(ActivationError::BarrierIncomplete { .. })
    ));
    let rank1 = ValidationReport {
        graphs_compatible: false,
        ..validation(started.generation, 1)
    };
    let error = host
        .with_ports(|slot, ports| slot.record_validation(&rank1, ports))
        .unwrap_err();
    assert!(matches!(
        error,
        ActivationError::Failed { report }
            if report.failure.map(|failure| failure.reason)
                == Some(PlacementFailure::ValidationFailed {
                    rank: Rank::new(1),
                    check: ValidationCheck::Graphs
                })
    ));
    assert_eq!(host.published_generation(), None);
    assert!(host.slot.placement_identities(started.generation).is_none());
    assert_eq!(host.admit("request"), Err(RouteRefusal::NotServing));

    let mut serving = Slot::new(&clock, 2, 32 * GIB);
    let old = serving.activate(&activation("model-m", &parts("model-m")));
    let started = serving.begin(&activation("model-n", &parts("model-n")));
    serving.load();
    serving.slot.begin_activating().unwrap();
    let report = validation(started.generation, 0);
    serving
        .with_ports(|slot, ports| slot.record_validation(&report, ports))
        .unwrap();
    let failing = ValidationReport {
        buffers_ready: false,
        ..validation(started.generation, 1)
    };
    assert!(serving
        .with_ports(|slot, ports| slot.record_validation(&failing, ports))
        .is_err());
    assert_eq!(serving.published_generation(), Some(old.generation));
    assert_eq!(
        serving
            .slot
            .placement_identities(old.generation)
            .unwrap()
            .len(),
        2,
        "both ranks of the old generation serve"
    );
    assert_eq!(serving.admit("request").unwrap().generation, old.generation);
}

/// GPU-T29 (line 1311): a request in flight during a weight update uses one generation for
/// the whole request.
///
/// A request admitted before model B's publication keeps generation A for every weight it
/// reads, a request admitted after reads B, shared parts are the same extents for both,
/// and offering a request the other generation's weights is refused. A drains only after
/// its last request finishes. T16's INT-03 drives the same rule through the CORE-04
/// coordinator; this case adds the per-position check.
#[test]
fn gpu_t29_an_in_flight_request_keeps_one_generation() {
    let clock = test_clock();
    let mut host = Slot::new(&clock, 1, 32 * GIB);
    let first = host.activate(&activation("model-a", &model_a()));
    let old = host.admit("old").unwrap();
    let second = host.activate(&activation("model-b", &model_b()));
    assert_eq!(second.previous, Some(first.generation));
    let new = host.admit("new").unwrap();
    assert_eq!(
        (old.generation, new.generation),
        (first.generation, second.generation)
    );
    let layer = position(0, Component::Layer(1));
    assert_eq!(
        host.slot.weight_for(&old, layer),
        Ok(extent_key("a-layer-1", gpu(0)))
    );
    assert_eq!(
        host.slot.weight_for(&new, layer),
        Ok(extent_key("b-layer-1", gpu(0)))
    );
    let shared = position(0, Component::Layer(0));
    assert_eq!(
        host.slot.weight_for(&old, shared),
        host.slot.weight_for(&new, shared)
    );
    assert!(matches!(
        host.slot
            .check_weight(&old, layer, extent_key("b-layer-1", gpu(0))),
        Err(TicketError::MixedGenerations { .. })
    ));
    assert!(matches!(
        host.slot
            .check_weight(&new, layer, extent_key("a-layer-1", gpu(0))),
        Err(TicketError::MixedGenerations { .. })
    ));
    assert!(!host
        .slot
        .drain_status(first.placement, &host.coordination)
        .unwrap()
        .is_drained());
    host.finish(&old);
    let reclaimed = host.park_and_reclaim(first.placement);
    assert_eq!(reclaimed.freed.len(), 1);
    assert_eq!(
        host.slot.weight_for(&new, layer),
        Ok(extent_key("b-layer-1", gpu(0)))
    );
}

/// GPU-T30 (line 1312): a decode group arrives late; the right event is waited for and the
/// stall is measured.
///
/// In the §2.6 recurrence, groups usable at 1 s and 11 s with 1 s and 10 s of compute
/// finish at 21 s, not the ideal 12 s, and the no-stall condition names the late group
/// and its deadline. In the executor the second dependency's copy completes later on the
/// same stream; it becomes usable only once its own completion event is observed, after
/// the first, and the measured copy stage records the wait. Not covered: real
/// copy-engine timing, which needs a GPU.
#[test]
fn gpu_t30_a_late_group_is_waited_for_and_its_stall_measured() {
    let groups = [
        GroupTiming {
            usable_at_seconds: 1.0,
            compute_seconds: 1.0,
        },
        GroupTiming {
            usable_at_seconds: 11.0,
            compute_seconds: 10.0,
        },
    ];
    assert_eq!(finish_times(&groups).unwrap(), vec![2.0, 21.0]);
    assert_eq!(ideal_finish_seconds(&groups).unwrap(), 12.0);
    assert_eq!(
        no_stall(&groups).unwrap(),
        NoStall::Stalls {
            group: 2,
            usable_at_seconds: 11.0,
            deadline_seconds: 2.0
        }
    );

    let clock = test_clock();
    let transfers = Transfers::new(&clock);
    {
        let mut edge = transfers.edge();
        edge.copy_nanos = 0;
        edge.copy_nanos_per_byte = 10;
    }
    let weights = Weights::new("weights", &[32, 48], false);
    transfers.publish(&weights, &[local("nvme")]);
    let mut executor = transfers.executor();
    let job = operation("load");
    let start = clock.now();
    executor
        .submit(TransferRequest {
            dependencies: vec![
                DependencySpec {
                    id: DependencyId(1),
                    extents: vec![0],
                    requires: vec![],
                },
                DependencySpec {
                    id: DependencyId(2),
                    extents: vec![1],
                    requires: vec![DependencyId(1)],
                },
            ],
            ..load_job("load", "tenant-a", &weights, "slot")
        })
        .unwrap();
    let mut first_usable = None;
    let mut second_usable = None;
    for _ in 0..200 {
        executor.pump().unwrap();
        let now = clock.now();
        if first_usable.is_none() && executor.is_usable(&job, DependencyId(1)) {
            first_usable = Some(now);
        }
        if second_usable.is_none() && executor.is_usable(&job, DependencyId(2)) {
            second_usable = Some(now);
        }
        if executor.is_idle() {
            break;
        }
        clock.advance(Duration::from_nanos(50));
    }
    let first_usable = first_usable.unwrap();
    let second_usable = second_usable.unwrap();
    assert!(first_usable.saturating_duration_since(start) >= Duration::from_nanos(320));
    assert!(second_usable.saturating_duration_since(start) >= Duration::from_nanos(800));
    assert!(second_usable > first_usable);
    let copies: Vec<Duration> = transfers
        .events_of(&job)
        .into_iter()
        .filter_map(|kind| match kind {
            TransferEventKind::StageMeasured(measurement)
                if measurement.stage == ExecutorStage::Copy =>
            {
                Some(measurement.duration)
            }
            _ => None,
        })
        .collect();
    assert_eq!(copies.len(), 2);
    assert!(
        copies[1] >= Duration::from_nanos(480),
        "the wait is measured"
    );
    assert_eq!(
        transfers.landed(&allocation("slot"), 0, 80),
        weights.decoded
    );
}

/// GPU-T32 (line 1314): a dense first-token request while later layers are missing; no
/// premature token or readiness claim.
///
/// The one request assigned to the preparing generation computes its layers as they
/// become usable, but its result is refused while the output head is missing and again
/// until the generation is published; the slot admits no other request meanwhile. The
/// §2.6 first-token recurrence names the late head as the critical input.
#[test]
fn gpu_t32_no_first_token_before_the_whole_chain_and_publication() {
    let clock = test_clock();
    let mut host = Slot::new(&clock, 1, 32 * GIB);
    let parts = vec![
        part(0, Component::Layer(0), "c-layer-0", 2 * GIB),
        part(0, Component::Layer(1), "c-layer-1", 2 * GIB),
        part(0, Component::OutputHead, "c-head", GIB),
    ];
    let chain: Vec<WeightPosition> = parts
        .iter()
        .map(|part| position(0, part.component))
        .collect();
    host.begin(&activation("model-c", &parts));
    host.with_ports(|slot, ports| slot.prepare_extents(ports))
        .unwrap();
    let assigned = AssignedRequest {
        request: operation("pending"),
        execution: slot_owner(),
        epoch: AuthorizationEpoch::FIRST,
        required: chain.iter().copied().collect(),
        lease_expires_at: clock.now().saturating_add(HOUR),
    };
    host.slot
        .assign_early_request(&assigned, &mut host.coordination)
        .unwrap();
    assert_eq!(host.admit("other"), Err(RouteRefusal::NotServing));
    let pending = operation("pending");
    for (content, layer) in [("c-layer-0", chain[0]), ("c-layer-1", chain[1])] {
        host.slot
            .record_extent_usable(extent_key(content, gpu(0)))
            .unwrap();
        host.slot.start_early_compute(&pending, layer).unwrap();
        host.slot.finish_early_compute(&pending, layer).unwrap();
    }
    assert_eq!(
        host.slot.release_early_result(&pending, &host.coordination),
        Err(EarlyRefusal::ChainIncomplete {
            waiting: vec![chain[2]]
        })
    );
    assert_eq!(
        host.slot.start_early_compute(&pending, chain[2]),
        Err(EarlyRefusal::DependencyNotUsable { position: chain[2] })
    );
    host.slot
        .record_extent_usable(extent_key("c-head", gpu(0)))
        .unwrap();
    host.slot.start_early_compute(&pending, chain[2]).unwrap();
    host.slot.finish_early_compute(&pending, chain[2]).unwrap();
    assert_eq!(
        host.slot.release_early_result(&pending, &host.coordination),
        Err(EarlyRefusal::AwaitingPublication)
    );
    host.slot.record_runtime_initialized().unwrap();
    host.slot.materialize().unwrap();
    host.validate_and_ready();
    host.publish();
    host.slot
        .release_early_result(&pending, &host.coordination)
        .unwrap();

    let layer = |usable: f64| GroupRequirement {
        weights_usable_at_seconds: usable,
        compute_seconds: 1.0,
        dependencies: Vec::new(),
    };
    let first = first_token(&[layer(0.0), layer(1.0)], &layer(9.0)).unwrap();
    assert_eq!(first.layers_finish_seconds, 2.0);
    assert_eq!(first.first_token_seconds, 10.0);
    assert_eq!(
        first.critical_input,
        Some(CriticalInput {
            group: GroupRef::OutputHead,
            cause: WaitCause::Weights,
            usable_at_seconds: 9.0,
        })
    );
}

/// GPU-T33 (line 1315): the MoE predicted expert is wrong; the exact expert is fetched and
/// nothing is substituted.
///
/// The prefetcher loaded expert 5 but the router chose expert 3. The §2.6 MoE step asks
/// for an exact load of expert 3, refuses to bind expert 5 and refuses to start until
/// expert 3 is usable. In the preparing placement, expert 5 is not part of the request's
/// chain, expert 3 stalls the computation, and the result waits for it.
#[test]
fn gpu_t33_a_mispredicted_expert_is_fetched_exactly() {
    let expert_3 = ExpertId {
        layer: 0,
        expert: 3,
    };
    let expert_5 = ExpertId {
        layer: 0,
        expert: 5,
    };
    let mut cache = ExpertCache::new();
    cache.insert(expert_5, 1.0).unwrap();
    let mut step = MoeStep::new(&[expert_3]).unwrap();
    let loads = step.resolve(&cache);
    assert_eq!(loads.len(), 1);
    assert_eq!(loads[0].expert(), expert_3);
    assert_eq!(
        step.start_seconds(2.0),
        Err(OverlapError::MissingExperts {
            experts: vec![expert_3]
        })
    );
    let predicted = cache.lookup(expert_5).unwrap();
    assert_eq!(
        step.bind(predicted),
        Err(OverlapError::ExpertNotRequired { expert: expert_5 })
    );
    let exact = cache.complete_load(loads[0], 4.5).unwrap();
    step.bind(exact).unwrap();
    assert_eq!(step.start_seconds(2.0), Ok(4.5));

    let clock = test_clock();
    let mut host = Slot::new(&clock, 1, 32 * GIB);
    let three = Component::Expert {
        layer: 0,
        expert: 3,
    };
    let five = Component::Expert {
        layer: 0,
        expert: 5,
    };
    let parts = vec![
        part(0, Component::Layer(0), "e-layer-0", 2 * GIB),
        part(0, three, "e-expert-3", GIB),
        part(0, five, "e-expert-5", GIB),
        part(0, Component::OutputHead, "e-head", GIB),
    ];
    host.begin(&activation("model-e", &parts));
    host.with_ports(|slot, ports| slot.prepare_extents(ports))
        .unwrap();
    let required = [
        position(0, Component::Layer(0)),
        position(0, three),
        position(0, Component::OutputHead),
    ];
    let assigned = AssignedRequest {
        request: operation("pending"),
        execution: slot_owner(),
        epoch: AuthorizationEpoch::FIRST,
        required: required.iter().copied().collect(),
        lease_expires_at: clock.now().saturating_add(HOUR),
    };
    host.slot
        .assign_early_request(&assigned, &mut host.coordination)
        .unwrap();
    let pending = operation("pending");
    for name in ["e-layer-0", "e-expert-5", "e-head"] {
        host.slot
            .record_extent_usable(extent_key(name, gpu(0)))
            .unwrap();
    }
    for done in [required[0], required[2]] {
        host.slot.start_early_compute(&pending, done).unwrap();
        host.slot.finish_early_compute(&pending, done).unwrap();
    }
    assert_eq!(
        host.slot.start_early_compute(&pending, required[1]),
        Err(EarlyRefusal::DependencyNotUsable {
            position: required[1]
        })
    );
    assert_eq!(
        host.slot.start_early_compute(&pending, position(0, five)),
        Err(EarlyRefusal::NotRequired {
            position: position(0, five)
        })
    );
    assert_eq!(
        host.slot.release_early_result(&pending, &host.coordination),
        Err(EarlyRefusal::ChainIncomplete {
            waiting: vec![required[1]]
        })
    );
    host.slot
        .record_extent_usable(extent_key("e-expert-3", gpu(0)))
        .unwrap();
    host.slot
        .start_early_compute(&pending, required[1])
        .unwrap();
    host.slot
        .finish_early_compute(&pending, required[1])
        .unwrap();
    host.slot.record_runtime_initialized().unwrap();
    host.slot.materialize().unwrap();
    host.validate_and_ready();
    host.publish();
    host.slot
        .release_early_result(&pending, &host.coordination)
        .unwrap();
}

/// GPU-T23 (line 1305): the exporter dies with active imports; backend-defined recovery
/// and no stale handle execution.
///
/// While an import holds the exporter's allocation, the exporter cannot free it, so the
/// importer's mapping never covers freed memory (CUDA VMM keeps imported memory alive).
/// The exporter's closed handle, as its exit closes it, admits no new import. When the
/// exporter's process exits, the importer's retained view is refused as `ExporterGone`,
/// nothing more is done on the dead process's behalf, and the importer's park frees the
/// memory. On the placement side the exporter's runner exits: its serving placement stops
/// admitting at once, fails with the reason and leaves the router, so no request runs on
/// it. Not covered: a real driver's process teardown, which needs hardware.
#[test]
fn gpu_t23_a_dead_exporter_leaves_no_stale_handle_to_execute() {
    let clock = test_clock();
    let mut gpu_host = Gpu::new(&clock);
    gpu_host.show_vmm_handles(POSIX);
    gpu_host.add_process(P3);
    for process in [P1, P2, P3] {
        gpu_host.permit_ipc(process);
    }
    let key = gpu_host.load(P1, "a", &[8 * MIB], posix_memory());
    let physical = gpu_host.physical_of(key, 0);
    let export = gpu_host
        .model
        .export_allocation(
            &mut gpu_host.driver,
            &gpu_host.registry,
            P1,
            physical,
            POSIX,
        )
        .unwrap();
    let receiver = gpu_host.plan(P2, "a", &[8 * MIB], posix_memory(), vmm::VmmOrigin::Import);
    gpu_host
        .model
        .import_batch(
            &mut gpu_host.driver,
            &gpu_host.registry,
            receiver,
            0,
            export,
        )
        .unwrap();
    gpu_host
        .model
        .publish_batch(&mut gpu_host.driver, receiver, 0, batch_digest("a", 0))
        .unwrap();
    gpu_host
        .model
        .close_export(&mut gpu_host.driver, export)
        .unwrap();
    let parked = {
        gpu_host
            .model
            .begin_park(&mut gpu_host.driver, key, clean_drop("a"))
            .unwrap();
        gpu_host
            .model
            .finish_park(&mut gpu_host.driver, key)
            .unwrap()
    };
    assert_eq!(parked.released_bytes, 0, "the import holds the memory");
    assert!(matches!(
        gpu_host
            .model
            .close_physical(&mut gpu_host.driver, P1, physical),
        Err(VmmError::StillReferenced { .. })
    ));
    assert_eq!(gpu_host.driver.used_bytes(DEVICE), 8 * MIB);
    let late = gpu_host.plan(P3, "a", &[8 * MIB], posix_memory(), vmm::VmmOrigin::Import);
    assert_eq!(
        gpu_host
            .model
            .import_batch(&mut gpu_host.driver, &gpu_host.registry, late, 0, export),
        Err(VmmError::ExportClosed { export })
    );
    let view = gpu_host.model.create_view(receiver, 0, 8 * MIB).unwrap();
    let event = gpu_host
        .model
        .call_view(&mut gpu_host.driver, view, STREAM)
        .unwrap();
    assert!(gpu_host.driver.complete(event));
    assert!(gpu_host.driver.exit_process(P1));
    let exit = gpu_host.model.process_exited(P1).unwrap();
    assert_eq!(exit.orphaned, vec![physical]);
    assert_eq!(exit.dropped_artifacts, vec![key]);
    assert_eq!(
        gpu_host.model.call_view(&mut gpu_host.driver, view, STREAM),
        Err(VmmError::NotCallable {
            key: receiver,
            reason: NotCallableReason::ExporterGone { exporter: P1 },
        }),
        "no stale handle executes"
    );
    assert_eq!(
        gpu_host
            .model
            .close_physical(&mut gpu_host.driver, P1, physical),
        Err(VmmError::ProcessExited { process: P1 })
    );
    gpu_host
        .model
        .begin_park(&mut gpu_host.driver, receiver, clean_drop("a"))
        .unwrap();
    let released = gpu_host
        .model
        .finish_park(&mut gpu_host.driver, receiver)
        .unwrap();
    assert_eq!(released.released_bytes, 8 * MIB);
    assert_eq!(gpu_host.driver.used_bytes(DEVICE), 0);
    assert!(gpu_host.driver.refusals().is_empty());

    let mut host = Slot::new(&clock, 1, 32 * GIB);
    let serving = host.activate(&activation("model-a", &model_a()));
    let ticket = host.admit("in-flight").unwrap();
    let failure = host
        .with_ports(|slot, ports| slot.record_process_exit(serving.placement, ports))
        .unwrap()
        .unwrap();
    assert_eq!(failure.reason, PlacementFailure::ProcessExited);
    assert_eq!(host.published_generation(), None);
    assert_eq!(host.admit("after-exit"), Err(RouteRefusal::NotServing));
    assert_eq!(host.state(serving.placement), StateKind::Failed);
    assert!(host
        .slot
        .weight_for(&ticket, position(0, Component::Layer(0)))
        .is_ok());
}

// ---------------------------------------------------------------------------------------
// GPU-T14 to GPU-T19: adapters, admission at peak, leased memory and host limits.
// ---------------------------------------------------------------------------------------

fn interval(start_seconds: u64, end_seconds: u64) -> Interval {
    Interval::new(
        MonotonicTime::from_nanos(start_seconds * 1_000_000_000),
        MonotonicTime::from_nanos(end_seconds * 1_000_000_000),
    )
    .unwrap()
}

/// One process on GPU 0 for the whole window, mapping `maps`, with a reserved KV pool and
/// one peak workspace during `[workspace_from, workspace_to)`.
fn runner(
    name: &str,
    scope: TrustScope,
    maps: &[&str],
    kv_bytes: u64,
    workspace: Option<(u64, u64, u64)>,
) -> ProcessVram {
    ProcessVram {
        process: name.to_owned(),
        sharing_domain: scope,
        lifetime: interval(0, 100),
        maps: maps.iter().map(|map| (*map).to_owned()).collect(),
        context_bytes: GIB / 2,
        graph_pool_bytes: 0,
        kv: KvBound::Reserved { bytes: kv_bytes },
        transients: workspace
            .map(|(bytes, from, to)| TransientDemand {
                kind: TransientKind::PeakWorkspace,
                bytes,
                during: interval(from, to),
            })
            .into_iter()
            .collect(),
    }
}

fn resident(key: &str, kind: ImmutableKind, bytes: u64, scope: TrustScope) -> ImmutableAllocation {
    ImmutableAllocation {
        key: key.to_owned(),
        kind,
        bytes,
        sharing_domain: scope,
        resident: interval(0, 100),
    }
}

/// GPU-T14 (line 1296): a shared base with several adapters; one physical eligible base and
/// isolated adapter identities.
///
/// The dependency graph holds the base once and refuses a second copy of the same
/// identity; two adapters depend on it with distinct identities, and the session KV of
/// one adapter never serves the other. In the §2.7 inequality two runners of one trust
/// scope map the base and count it once, each adapter separately, and a runner of another
/// trust scope may not map it at all.
#[test]
fn gpu_t14_adapters_share_one_eligible_base_and_keep_their_own_identities() {
    let mut graph = DependencyGraph::new();
    let base = graph
        .add_base(kv_fixtures::base_spec("base-8b", 16 * GIB, true))
        .unwrap();
    assert!(matches!(
        graph.add_base(kv_fixtures::base_spec("base-8b", 16 * GIB, true)),
        Err(AdaptersGraphError::DuplicateWeights { existing, .. }) if existing == base
    ));
    let admit = |graph: &mut DependencyGraph, name: &str| {
        graph
            .admit_adapter(
                base,
                kv_fixtures::adapter_reference(name, "base-8b"),
                &kv_fixtures::LIMITS,
                kv_fixtures::residency(name, 64 * MIB, true),
            )
            .unwrap()
    };
    let sql = admit(&mut graph, "adapter-sql");
    let legal = admit(&mut graph, "adapter-legal");
    assert_eq!(graph.prerequisites_of(sql), BTreeSet::from([base]));
    assert_eq!(graph.prerequisites_of(legal), BTreeSet::from([base]));
    assert_eq!(graph.resident_bytes().unwrap(), 16 * GIB + 2 * 64 * MIB);
    assert_eq!(graph.dependents(base), BTreeSet::from([sql, legal]));
    let sql_identity = kv_fixtures::adapter_identity("adapter-sql");
    let legal_identity = kv_fixtures::adapter_identity("adapter-legal");
    assert_ne!(sql_identity, legal_identity);
    let model = kv_fixtures::execution_identity("base-8b");
    let stored = StoredKv {
        spec: kv_fixtures::kv_spec(model, Some(sql_identity), 64, "chat", "acme"),
        trust_scope: kv_fixtures::trust(),
        sharing: KvSharing::TenantScoped,
    };
    assert_eq!(
        adapter_kv_reuse(
            &stored,
            &KvRequest {
                spec: kv_fixtures::kv_spec(model, Some(legal_identity), 64, "chat", "acme"),
                trust_scope: kv_fixtures::trust(),
            },
            &PublicPrefixSharing::none(),
            &RevokedAuthorities::new(),
            &kv_fixtures::verified(),
            kv_fixtures::NOW,
        ),
        Err(AdapterKvRefusal::Scope(KvReuseRefusal::ScopeMismatch {
            components: vec![KvScopeComponent::Adapter]
        }))
    );

    let scope = TrustScope::named(ExecutionCategory::VmSandbox, "tenant-a-models");
    let plan = |processes: Vec<ProcessVram>| VramPlan {
        device: gpu(0),
        usable_vram: Capacity::Physical { bytes: 40 * GIB },
        safety_reserve_bytes: GIB,
        allocations: vec![
            resident("base", ImmutableKind::Weights, 16 * GIB, scope),
            resident("adapter-sql", ImmutableKind::Adapter, 64 * MIB, scope),
            resident("adapter-legal", ImmutableKind::Adapter, 64 * MIB, scope),
        ],
        processes,
    };
    let evaluation = evaluate_vram(&plan(vec![
        runner("runner-sql", scope, &["base", "adapter-sql"], 2 * GIB, None),
        runner(
            "runner-legal",
            scope,
            &["base", "adapter-legal"],
            2 * GIB,
            None,
        ),
    ]))
    .unwrap();
    let peak = evaluation.peak().unwrap();
    assert_eq!(
        peak.demand.unique_resident_weights_bytes,
        16 * GIB,
        "counted once"
    );
    assert_eq!(peak.demand.adapters_bytes, 2 * 64 * MIB);
    assert_eq!(
        peak.demand.kv_bytes,
        4 * GIB,
        "each process's KV separately"
    );
    let outsider = TrustScope::named(ExecutionCategory::VmSandbox, "tenant-b-models");
    assert_eq!(
        evaluate_vram(&plan(vec![runner(
            "runner-b",
            outsider,
            &["base"],
            GIB,
            None
        )])),
        Err(VramError::CrossDomainSharing {
            allocation: "base".to_owned(),
            process: "runner-b".to_owned()
        })
    );
}

/// GPU-T15 (line 1297): a merged adapter switched in and out repeatedly; the canonical base
/// is unchanged and there is no numerical undo drift.
///
/// Each merge materializes a separate variant under its own identity from a one-use
/// proof, and the base and adapter nodes are byte-for-byte the same before and after.
/// Going back to the base is never subtraction: the graph names the untouched resident
/// base. After a switch back and a new merge, the variant has exactly the first
/// variant's identity, because nothing drifted. A variant has no reconstructible copy
/// until one of its own bytes is recorded, so dropping it costs a copy back.
#[test]
fn gpu_t15_merged_adapters_switch_without_touching_or_drifting_the_base() {
    let clock = test_clock();
    let mut graph = DependencyGraph::new();
    let base = graph
        .add_base(kv_fixtures::base_spec("base-8b", 16 * GIB, true))
        .unwrap();
    let adapter = graph
        .admit_adapter(
            base,
            kv_fixtures::adapter_reference("adapter-sql", "base-8b"),
            &kv_fixtures::LIMITS,
            kv_fixtures::residency("adapter-sql", 64 * MIB, true),
        )
        .unwrap();
    let base_before = graph.node(base).unwrap().clone();
    let adapter_before = graph.node(adapter).unwrap().clone();
    let merged_bytes = ContentKey::of(b"base-8b + adapter-sql, merged");
    let mut identities = Vec::new();
    for _ in 0..3 {
        let variant = graph
            .materialize_merged(
                base,
                adapter,
                kv_fixtures::versioned("merge-procedure"),
                merged_bytes,
                kv_fixtures::justified("base-8b", "adapter-sql", 16 * GIB),
            )
            .unwrap();
        let NodeData::MergedVariant { identity, .. } = graph.node(variant).unwrap().data() else {
            panic!("not a merged variant");
        };
        identities.push(*identity);
        assert_eq!(
            graph.without_merge(variant),
            Ok(WithoutMerge::Resident(base))
        );
        assert_eq!(graph.node(base).unwrap(), &base_before);
        assert_eq!(graph.node(adapter).unwrap(), &adapter_before);
        let plan = plan_eviction(
            &graph,
            &EvictionRequest {
                needed_bytes: GIB,
                uses: BTreeSet::from([base, adapter]),
            },
            &*clock,
            &EvictionPolicy {
                min_resume_probability: 0.5,
                min_restore_seconds: 5.0,
                min_prefix_tokens: 50_000,
                copy_back_tier: Some(CopyTier::LocalStorage),
            },
            &[],
            &mut Lru,
        )
        .unwrap();
        let EvictionOutcome::Release(plan) = plan else {
            panic!("the variant can be released: {plan:?}");
        };
        assert_eq!(
            plan.copy_back_bytes,
            16 * GIB,
            "no copy of its own bytes yet"
        );
        graph.release(&plan.nodes(), &*clock).unwrap();
        assert_eq!(graph.node(variant), None);
    }
    assert!(
        identities.windows(2).all(|pair| pair[0] == pair[1]),
        "no drift"
    );
    assert_ne!(identities[0], kv_fixtures::execution_identity("base-8b"));
    assert_eq!(graph.node(base).unwrap(), &base_before);
}

/// GPU-T16 (line 1298): two models fit by weights but not by peak workspace and KV;
/// admission accounts for the actual peak.
///
/// On a 24 GiB device two 8 GiB models fit by weights and even by their time-weighted
/// mean, but their peak workspaces overlap during [15, 20), where weights, KV, contexts,
/// both workspaces and the safety reserve exceed the device: admission refuses, names
/// that piece, and T08's ledger adapter builds no reservation. Staggered workspaces fit,
/// and the ledger reserves the peak demand, not the mean.
#[test]
fn gpu_t16_admission_counts_the_actual_peak_not_the_weights() {
    let scope = TrustScope::named(ExecutionCategory::VmSandbox, "models");
    let plan = |second_workspace: (u64, u64, u64)| VramPlan {
        device: gpu(0),
        usable_vram: Capacity::Physical { bytes: 24 * GIB },
        safety_reserve_bytes: GIB,
        allocations: vec![
            resident("model-a", ImmutableKind::Weights, 8 * GIB, scope),
            resident("model-b", ImmutableKind::Weights, 8 * GIB, scope),
        ],
        processes: vec![
            runner(
                "runner-a",
                scope,
                &["model-a"],
                2 * GIB,
                Some((3 * GIB, 10, 20)),
            ),
            runner("runner-b", scope, &["model-b"], GIB, Some(second_workspace)),
        ],
    };
    let overlapping = plan((3 * GIB, 15, 25));
    let evaluation = evaluate_vram(&overlapping).unwrap();
    let first_over = evaluation.first_over().unwrap();
    assert_eq!(first_over.during, interval(15, 20));
    assert_eq!(
        first_over.total_bytes,
        16 * GIB + 3 * GIB + GIB + 6 * GIB + GIB,
        "weights, KV, contexts, both workspaces and the reserve"
    );
    assert!(
        evaluation.average_total_bytes().unwrap() < 24 * GIB,
        "the mean would pass"
    );
    assert!(matches!(
        admit_vram(&overlapping),
        Err(VramError::DoesNotFit(_))
    ));
    let provenance = Provenance {
        requester: Requester::ModelPlacement,
        execution: execution("exe-load"),
        operation: operation("op-load"),
        tenant: tenant("tenant-a"),
        purpose: CostPurpose::Compute,
        retry_number: 0,
    };
    assert!(PlacementReservation::new(
        provenance.clone(),
        Priority::Foreground,
        &[overlapping],
        None
    )
    .is_err());

    let staggered = plan((3 * GIB, 20, 30));
    let evaluation = admit_vram(&staggered).unwrap();
    let peak = *evaluation.peak().unwrap();
    assert_eq!(peak.total_bytes, 16 * GIB + 3 * GIB + GIB + 3 * GIB + GIB);
    let clock = test_clock();
    let mut ledger = host_ledger(&clock, &[(vram_resource(gpu(0)), 24 * GIB)], &["tenant-a"]);
    let reservation =
        PlacementReservation::new(provenance, Priority::Foreground, &[staggered], None).unwrap();
    assert!(matches!(
        reservation.reserve(&mut ledger).unwrap(),
        LedgerAdmission::Granted(_)
    ));
    assert_eq!(ledger.reserved(vram_resource(gpu(0))), peak.demand_bytes());
}

/// GPU-T17 (line 1299): all memory is leased or pinned; requests queue or are refused
/// fairly, with no endless eviction loop.
///
/// With the base pinned and the session leased the eviction plan queues, names every
/// hold, releases nothing and gives the same answer when asked again. In the CORE-03
/// ledger requests for the full device wait in a bounded queue in order; a tenant's
/// third request is refused while another tenant still queues, and nothing waits past
/// the age limit. When capacity returns, the oldest request is granted.
#[test]
fn gpu_t17_fully_held_memory_queues_fairly_without_an_eviction_loop() {
    let clock = test_clock();
    let mut graph = DependencyGraph::new();
    let base = graph
        .add_base(kv_fixtures::base_spec("base-8b", 16 * GIB, true))
        .unwrap();
    graph.set_hold(base, Hold::Pinned).unwrap();
    let session = graph
        .add_session_kv(
            kv_fixtures::KvFixture::new(base, kv_fixtures::execution_identity("base-8b"), "chat")
                .spec(),
        )
        .unwrap();
    graph
        .set_hold(
            session,
            Hold::Leased {
                lease: LeaseId::new(7),
                until: clock.now().saturating_add(HOUR),
            },
        )
        .unwrap();
    let policy = EvictionPolicy {
        min_resume_probability: 0.5,
        min_restore_seconds: 5.0,
        min_prefix_tokens: 50_000,
        copy_back_tier: Some(CopyTier::LocalStorage),
    };
    let ask = |graph: &DependencyGraph| {
        plan_eviction(
            graph,
            &EvictionRequest::bytes(GIB),
            &*clock,
            &policy,
            &[],
            &mut Lru,
        )
        .unwrap()
    };
    let EvictionOutcome::Queue(reason) = ask(&graph) else {
        panic!("everything is held");
    };
    assert_eq!(reason.releasable_bytes, 0);
    assert_eq!(reason.held.len(), 2);
    assert_eq!(
        ask(&graph),
        EvictionOutcome::Queue(reason.clone()),
        "the same answer"
    );
    assert!(graph.node(base).is_some() && graph.node(session).is_some());

    let vram = vram_resource(gpu(0));
    let mut ledger = host_ledger(
        &clock,
        &[(vram, 24 * GIB)],
        &["tenant-a", "tenant-b", "tenant-c"],
    );
    let request = |owner: &str, name: &str| {
        LedgerRequest::new(
            Provenance {
                requester: Requester::ModelPlacement,
                execution: execution(&format!("exe-{name}")),
                operation: operation(name),
                tenant: tenant(owner),
                purpose: CostPurpose::Compute,
                retry_number: 0,
            },
            Priority::Foreground,
            Amounts::new().with(vram, 24 * GIB),
        )
        .wait_up_to(HOUR)
    };
    let LedgerAdmission::Granted(holder) = ledger.reserve(request("tenant-c", "holder")).unwrap()
    else {
        panic!("the first request takes the device");
    };
    ledger.begin_create(holder).unwrap();
    let mut tickets = Vec::new();
    for (owner, name) in [
        ("tenant-a", "a-1"),
        ("tenant-b", "b-1"),
        ("tenant-a", "a-2"),
    ] {
        let LedgerAdmission::Queued { ticket, ahead, .. } =
            ledger.reserve(request(owner, name)).unwrap()
        else {
            panic!("{name} waits");
        };
        assert_eq!(ahead, tickets.len());
        tickets.push(ticket);
    }
    let refused = ledger.reserve(request("tenant-a", "a-3")).unwrap_err();
    assert!(matches!(
        refused,
        LedgerError::Capacity(ref error)
            if error.queue_refusal() == Some(QueueRefusal::TenantFull { max_entries: 2 })
    ));
    assert!(matches!(
        ledger.reserve(request("tenant-b", "b-2")).unwrap(),
        LedgerAdmission::Queued { .. }
    ));
    assert_eq!(ledger.queue_len(), 4);

    ledger.cancel(holder).unwrap();
    ledger
        .confirm_release(holder, SourceClass::HostProbe)
        .unwrap();
    ledger.tick();
    let granted: Vec<QueueTicket> = ledger
        .drain_events()
        .into_iter()
        .filter_map(|event| match event {
            LedgerEvent::QueueGranted { ticket, .. } => Some(ticket),
            _ => None,
        })
        .collect();
    assert_eq!(granted, vec![tickets[0]], "the oldest request goes first");
    clock.advance(MINUTE + SECOND);
    ledger.tick();
    let expired = ledger
        .drain_events()
        .into_iter()
        .filter(|event| matches!(event, LedgerEvent::QueueRefused { .. }))
        .count();
    assert_eq!(expired, 3, "nothing waits past the age limit");
    assert_eq!(ledger.queue_len(), 0);
}

/// GPU-T18 (line 1300): the WSL or host memory limit is below the requested cache; the
/// cache is capped or falls back, and the host never runs out of memory.
///
/// A pinned staging ring larger than the WSL VM's memory is refused by T08's host check
/// before anything is pinned or reserved; a ring capped to what the VM scope has free is
/// pinned and charged to host RAM and pinned RAM alike. A WSL runtime whose limit was
/// never observed pins nothing. A page-cache plan above the VM's memory is refused naming
/// the VM scope, and the same plan capped to the scope's free bytes is admitted. Not
/// covered: the real WSL `memory=` setting and kernel reclaim, which need the host.
#[test]
fn gpu_t18_host_limits_cap_the_cache_and_never_overcommit() {
    let clock = test_clock();
    let wsl_vm = host_scope("wsl-vm", HostScopeKind::WslVm, Some("host-ram"), 48 * MIB);
    let mut ledger = host_ledger(
        &clock,
        &[
            (ResourceKey::Host(HostResource::Ram), GIB),
            (ResourceKey::Host(HostResource::PinnedRam), GIB),
        ],
        &["tenant-a"],
    );
    let mut pinned = pinned_tier(GIB, 512 * MIB, WslLimit::Vm(wsl_vm.clone()));
    let owner = consumer("tenant-a", "exe-a");
    pinned.register_execution(owner.execution.clone(), MemlockLimit::Unlimited);
    let refused = pinned
        .pin_ring(&owner, 60 * MIB, &charge("ring"), &mut ledger, &*clock)
        .unwrap_err();
    let PinnedRefusal::Host(HostError::DoesNotFit(overcommits)) = refused else {
        panic!("the WSL VM is too small: {refused:?}");
    };
    assert!(overcommits.iter().any(|over| over.scope == "wsl-vm"));
    assert_eq!(pinned.pinned_bytes(), 0);
    assert_eq!(ledger.reserved(ResourceKey::Host(HostResource::Ram)), 0);
    let capped = wsl_vm.free_bytes().unwrap();
    assert!(capped < 60 * MIB);
    pinned
        .pin_ring(&owner, capped, &charge("ring"), &mut ledger, &*clock)
        .unwrap();
    assert_eq!(pinned.pinned_bytes(), capped);
    assert_eq!(
        ledger.reserved(ResourceKey::Host(HostResource::Ram)),
        capped
    );
    assert_eq!(
        ledger.reserved(ResourceKey::Host(HostResource::PinnedRam)),
        capped
    );

    let mut unknown = pinned_tier(GIB, 512 * MIB, WslLimit::Unknown);
    unknown.register_execution(owner.execution.clone(), MemlockLimit::Unlimited);
    assert!(matches!(
        unknown.pin_ring(&owner, MIB, &charge("ring"), &mut ledger, &*clock),
        Err(PinnedRefusal::WslLimitUnknown)
    ));

    let cache = |bytes: u64| HostPlan {
        scopes: vec![
            host_scope("host-ram", HostScopeKind::HostRam, None, GIB),
            host_scope("wsl-vm", HostScopeKind::WslVm, Some("host-ram"), 48 * MIB),
        ],
        demands: vec![HostDemand {
            label: "page cache".to_owned(),
            backing: HostBacking::PageCache,
            bytes,
            during: interval(0, 10),
            memory_scope: "wsl-vm".to_owned(),
            pinned_scope: None,
        }],
    };
    let Err(HostError::DoesNotFit(overcommits)) = admit_host(&cache(64 * MIB)) else {
        panic!("the cache does not fit the VM");
    };
    assert_eq!(overcommits[0].scope, "wsl-vm");
    assert!(admit_host(&cache(capped)).is_ok());
}

/// GPU-T19 (line 1301): page cache reclaimed after a residency hint; the actual load is
/// re-planned and no instant readiness is claimed.
///
/// A verified page-cache entry never counts as guaranteed residency, even with a fresh
/// estimate that says it is all there. While the estimate is fresh and complete the host
/// tier offers the bytes; once the kernel reclaims part of them, or the estimate goes
/// stale, it refuses, and the source choice plans the load from local storage instead.
/// Not covered: mincore itself and the kernel's reclaim, which need the host.
#[test]
fn gpu_t19_reclaimed_page_cache_is_replanned_never_claimed_ready() {
    let clock = test_clock();
    let mut store = Store::open(&clock, &["tenant-a"], MIB);
    let scope = Scope::tenant(tenant("tenant-a"));
    let bytes = payload(19, 4 * CATALOG_EXTENT as usize);
    let object = weights_ref("tenant-a", &bytes);
    let mut ledger = host_ledger(
        &clock,
        &[
            (ResourceKey::Host(HostResource::Ram), GIB),
            (ResourceKey::Host(HostResource::StorageQuota), GIB),
        ],
        &["tenant-a"],
    );
    let mut local = LocalStorageTier::new();
    let pool = PoolId::new("nvme").unwrap();
    local
        .add_pool(StoragePool {
            id: pool.clone(),
            selection: PoolSelection::UserSelected,
            presence: PoolPresence::Present,
        })
        .unwrap();
    let reservation = local
        .reserve_import(
            &pool,
            object.clone(),
            bytes.len() as u64,
            &execution("exe-a"),
            &charge("store"),
            &mut ledger,
        )
        .unwrap();
    let published = publish_original(store.catalog(), &scope, "exe-a", "weights", &bytes);
    assert_eq!(published, object.id());
    local.record_published(reservation, store.view()).unwrap();

    let owner = consumer("tenant-a", "exe-a");
    let lease = store
        .catalog()
        .acquire_lease(&scope, &owner.execution, object.id(), MINUTE)
        .unwrap();
    let handle = store
        .catalog()
        .open_read(&scope, &owner.execution, lease)
        .unwrap();
    let mut host = ReclaimableHostTier::new(
        vec![host_scope("host-ram", HostScopeKind::HostRam, None, GIB)],
        "host-ram".to_owned(),
        SECOND,
    );
    host.admit(
        &owner,
        object.clone(),
        &handle,
        store.view(),
        HostContent::VerifiedPageCache,
        HostVerification::Verified,
        &charge("page-cache"),
        &mut ledger,
        &*clock,
    )
    .unwrap();
    host.observe(&object, bytes.len() as u64, &*clock).unwrap();
    assert_eq!(
        host.host_copy(&object, &*clock)
            .unwrap()
            .guaranteed_resident_bytes(),
        0,
        "a hint is never guaranteed residency"
    );
    let request = SourceRequest {
        requester: owner.clone(),
        content: object.content,
        batches_bytes: vec![64; 4],
        cuts: Vec::new(),
        policy: steal_policy(),
    };
    let offers = |host: &ReclaimableHostTier| {
        vec![
            host.offer(
                source_id("page-cache"),
                &object,
                &owner,
                peer_path(1e10, 0.0),
                &*clock,
            ),
            local.offer(
                source_id("nvme"),
                &object,
                &owner,
                peer_path(1e9, 0.0),
                store.view(),
            ),
        ]
    };
    let warm = choose_source(&request, offers(&host), store.view()).unwrap();
    assert!(warm.excluded().is_empty());
    assert_eq!(
        warm.tier_of(&source_id("page-cache")),
        Some(Tier::ReclaimableHost)
    );

    host.observe(&object, bytes.len() as u64 / 2, &*clock)
        .unwrap();
    let reclaimed = choose_source(&request, offers(&host), store.view()).unwrap();
    assert!(matches!(
        &reclaimed.excluded()[0].reason,
        ExclusionReason::Refused(TierRefusal::Host(HostRefusal::NotFullyResident { .. }))
    ));
    assert_eq!(reclaimed.assigned_bytes(&source_id("nvme")), 256);
    assert!(reclaimed.predicted_completion_seconds() > warm.predicted_completion_seconds());

    host.observe(&object, bytes.len() as u64, &*clock).unwrap();
    clock.advance(2 * SECOND);
    let stale = choose_source(&request, offers(&host), store.view()).unwrap();
    assert!(matches!(
        &stale.excluded()[0].reason,
        ExclusionReason::Refused(TierRefusal::Host(HostRefusal::StaleEstimate { .. }))
    ));
    assert_eq!(stale.assigned_bytes(&source_id("nvme")), 256);
}

// ---------------------------------------------------------------------------------------
// GPU-T42 to GPU-T48: restarts, events, upgrades, legacy paths, bounds and visibility.
// ---------------------------------------------------------------------------------------

/// GPU-T42 (line 1324): the process, engine or governor restarts; persistent artifacts are
/// reconciled and device leases invalidated.
///
/// Before the crash a model is active on the CORE-04 coordinator, P08 journals two load
/// jobs, one model's weights reach the catalog without a journaled commit and another's
/// import is staged. After the restart the catalog reopens with the published object
/// visible and the staging untrusted, the recovered coordinator retires the old GPU
/// allocation and refuses its handle, P08 refuses to start under the old incarnation,
/// and under the new one it takes the catalog's word for what is committed and resubmits
/// both jobs through the normal loader. T16's INT-04 covers the same restart across the
/// sandbox, leases and transfers.
#[test]
fn gpu_t42_a_restart_reconciles_artifacts_and_invalidates_device_leases() {
    let clock = test_clock();
    let mut sandbox = SandboxHost::launch(&clock);
    let handle = sandbox.activate(sandbox_model("chat"));
    assert!(sandbox.host.check_gpu_handle(&handle).is_ok());
    let owner_tenant = sandbox_tenant();
    let mut store = Store::open(&clock, &[owner_tenant.as_str()], MIB);
    let scope = Scope::tenant(owner_tenant.clone());
    let chat = payload(42, 4 * CATALOG_EXTENT as usize);
    let next = payload(43, 4 * CATALOG_EXTENT as usize);
    let journal = tempfile::tempdir().unwrap();
    let intent = |name: &str, bytes: &[u8]| JobIntent {
        operation: operation(name),
        execution: sandbox_owner(),
        tenant: owner_tenant.clone(),
        kind: JobKind::Load,
        class: ArtifactClass::ModelWeights,
        content: ContentKey::of(bytes),
        total_bytes: bytes.len() as u64,
    };
    {
        let mut loader = FakeLoader::default();
        let (mut control, _) = JobControl::start(
            journal.path(),
            Incarnation::FIRST,
            store.view(),
            &sandbox.host,
            &CoordinatorRecovery::default(),
            &mut loader,
        )
        .unwrap();
        for (name, bytes) in [("op-load-chat", &chat), ("op-load-next", &next)] {
            assert_eq!(
                control.submit(intent(name, bytes), &mut loader),
                Ok(Submission::Submitted)
            );
        }
    }
    publish_original(
        store.catalog(),
        &scope,
        sandbox_owner().as_str(),
        "chat",
        &chat,
    );
    let (request, identity) = weights_import(
        owner_tenant.as_str(),
        sandbox_owner().as_str(),
        "next",
        &next,
    );
    let ticket = ticket_of(store.catalog().begin_import(request, identity).unwrap());
    store
        .catalog()
        .drive_import(
            &ticket,
            &mut MemorySource::new("next", &next),
            &mut PauseAt::new(&[Checkpoint::Stage {
                stage: ImportStage::DurableCommit,
            }]),
        )
        .unwrap();
    drop(ticket);

    clock.advance(SECOND);
    let reopened = store.reopen();
    assert_eq!((reopened.published, reopened.staging), (1, 1));
    let (sandbox, recovered) = sandbox.restart(&clock);
    assert!(recovered.retired_activations.contains(&handle));
    assert!(matches!(
        sandbox.host.check_gpu_handle(&handle),
        Err(LeaseRefusal::StaleGpuAllocation { .. })
    ));
    let mut loader = FakeLoader::default();
    assert!(JobControl::start(
        journal.path(),
        Incarnation::FIRST,
        store.view(),
        &sandbox.host,
        &recovered,
        &mut loader,
    )
    .is_err());
    let (_control, restarted) = JobControl::start(
        journal.path(),
        Incarnation::new(2),
        store.view(),
        &sandbox.host,
        &recovered,
        &mut loader,
    )
    .unwrap();
    assert!(restarted.stale_allocations.contains(&handle));
    assert_eq!(restarted.found_committed, vec![operation("op-load-chat")]);
    assert_eq!(loader.submitted.len(), 2);
    for submitted in &loader.submitted {
        assert_eq!(submitted.incarnation, Incarnation::new(2));
        assert_eq!(
            submitted.resume.artifact_committed,
            submitted.intent.operation == operation("op-load-chat")
        );
    }
}

/// GPU-T43 (line 1325): lost, duplicate and out-of-order events; updates are idempotent
/// and a reconnect starts from a snapshot.
///
/// Six progress states of one load go out one per delivery. The receiver gets them out
/// of order, twice, and with one missing: duplicates are recognised and applied once, an
/// older state arriving late fills its gap without moving the client back, and the
/// missing state is polled for a bounded number of times and then reported lost. A
/// receiver that reconnects takes the hub's snapshot instead of a replay and has no gap.
#[test]
fn gpu_t43_events_apply_idempotently_and_reconnects_use_the_snapshot() {
    let clock = test_clock();
    let mut hub = event_hub(&clock, 1);
    let mut producer = hub
        .register_progress(
            ProducerId::new("engine.progress").unwrap(),
            SourceClass::HostProbe,
            None,
        )
        .unwrap();
    let resource = TrackedResourceId::new(named("resource", "weights"));
    let mut sent = Vec::new();
    for step in 1..=6u64 {
        hub.emit_progress(
            &mut producer,
            EventContext::new(operation("op-load"), Phase::Loading),
            ProgressUpdate::new(
                resource,
                EventResource::Weights,
                step * 10,
                Some(100),
                step * 10,
                CancellationBoundary::Anytime,
            ),
        )
        .unwrap();
        let delivery = hub.drain(0);
        assert_eq!(delivery.progress.updates.len(), 1);
        sent.push(delivery.progress.updates[0].clone());
    }
    let config = ReconcileConfig {
        max_streams: 4,
        window_sequences: 1_000,
        max_polls: 2,
        poll_interval: SECOND,
    };
    let mut receiver = Reconciler::new(config).unwrap();
    let mut shown: Option<(u64, u64)> = None;
    let mut apply = |receiver: &mut Reconciler, event: &EventEnvelope<ProgressUpdate>| {
        let observed = receiver.observe_event(event).unwrap();
        let sequence = event.sequence().get();
        if observed.arrival.is_new() && shown.is_none_or(|(seen, _)| sequence > seen) {
            shown = Some((sequence, event.payload().completed_bytes()));
        }
        (observed.arrival, shown.map(|(_, bytes)| bytes))
    };
    assert_eq!(apply(&mut receiver, &sent[0]), (Arrival::Fresh, Some(10)));
    let (arrival, bytes) = apply(&mut receiver, &sent[2]);
    assert!(matches!(arrival, Arrival::FreshAfterGap { missing } if missing.count() == 1));
    assert_eq!(bytes, Some(30));
    assert_eq!(
        apply(&mut receiver, &sent[2]),
        (Arrival::Duplicate, Some(30))
    );
    assert_eq!(
        apply(&mut receiver, &sent[1]),
        (Arrival::Recovered, Some(30)),
        "a late older state never moves the client back"
    );
    assert_eq!(
        apply(&mut receiver, &sent[0]),
        (Arrival::Duplicate, Some(30))
    );
    let (arrival, _) = apply(&mut receiver, &sent[4]);
    assert!(matches!(arrival, Arrival::FreshAfterGap { .. }));
    assert_eq!(receiver.gaps().len(), 1);
    for attempt in 1..=2 {
        let polling = receiver.poll(clock.now());
        assert_eq!(polling.requests.len(), 1);
        assert_eq!(polling.requests[0].attempt, attempt);
        clock.advance(SECOND);
    }
    let polling = receiver.poll(clock.now());
    assert!(polling.requests.is_empty());
    assert_eq!(polling.lost.len(), 1);
    assert_eq!(polling.lost[0].reason, LossReason::RecoveryExhausted);
    assert!(receiver.gaps().is_empty());
    assert_eq!(apply(&mut receiver, &sent[5]), (Arrival::Fresh, Some(60)));
    let totals = receiver.totals();
    assert_eq!(
        (totals.duplicates, totals.recovered, totals.lost),
        (2, 1, 1)
    );

    let mut reconnected = Reconciler::new(config).unwrap();
    let snapshot = hub.progress_snapshot();
    assert_eq!(snapshot.states.len(), 1);
    for state in &snapshot.states {
        assert!(reconnected.observe_event(state).unwrap().arrival.is_new());
        assert_eq!(state.payload().completed_bytes(), 60);
        assert_eq!(
            PublicProgress::from_event(state).state(),
            Some(ClientState::LoadingModel)
        );
    }
    for resolved in &snapshot.resolved {
        reconnected
            .resolve_through(resolved, Resolution::Superseded)
            .unwrap();
    }
    assert!(reconnected.gaps().is_empty());
    assert_eq!(reconnected.totals().lost, 0);
    assert_eq!(
        reconnected.observe_event(&sent[5]).unwrap().arrival,
        Arrival::Duplicate
    );
}

/// A runtime profile that permits io_uring on evidence from a guest report, under
/// `driver`.
fn io_uring_profile(driver: &str) -> RuntimeProfile {
    RuntimeProfile {
        runtime: gpu_runtime(),
        configuration: driver_configuration(driver),
        permitted: BTreeMap::from([(
            Optimization::IoUring,
            EvidencePolicy {
                minimum_source: SourceClass::GuestReport,
                max_age: HOUR,
            },
        )]),
    }
}

/// GPU-T44 (line 1326): a driver or backend upgrade invalidates capability and ABI caches
/// as it should.
///
/// A loader plan enabled io_uring on evidence observed under driver 580.1. After the
/// driver changes to 590.2 the plan's recheck fails, and only a new plan under the new
/// fingerprint enables io_uring again. VMM granularity evidence lapses with the
/// process's configuration and must be probed again. A runner upgrade gives a new
/// execution identity, so graphs captured for the old one are refused, and a runner built
/// for another native ABI version is refused. The transfer executor's permission to use
/// io_uring rechecks the live registry, so it lapses with the old evidence too.
#[test]
fn gpu_t44_upgrades_invalidate_capability_and_abi_caches() {
    let clock = test_clock();
    let mut registry = ProbeRegistry::new(Arc::clone(&clock));
    let probe = Arc::new(FakeProbe::guest_report(Optimization::IoUring.capability()));
    registry.register(Box::new(Arc::clone(&probe))).unwrap();
    let subject = Subject::Runtime(gpu_runtime());
    let observe = |registry: &mut ProbeRegistry<TestClock>, driver: &str| {
        probe.respond(
            &subject,
            Observation::supported(driver_configuration(driver), HOUR, SupportDetail::Plain),
        );
        registry
            .refresh(Optimization::IoUring.capability(), &subject)
            .unwrap();
    };
    let request = LoaderRequest {
        optimizations: BTreeMap::from([(Optimization::IoUring, Necessity::Optional)]),
    };
    observe(&mut registry, "580.1");
    let before = LoaderGate::recorded()
        .plan(&io_uring_profile("580.1"), &request, &registry)
        .unwrap();
    assert!(before.is_enabled(Optimization::IoUring));
    assert!(before.recheck(Optimization::IoUring, &registry).is_ok());
    let permissions = LoaderPermissions::from_plan(&before);
    assert!(permissions.permits(ReadMethod::IoUring, &registry));
    clock.advance(SECOND);
    observe(&mut registry, "590.2");
    assert!(before.recheck(Optimization::IoUring, &registry).is_err());
    assert!(!permissions.permits(ReadMethod::IoUring, &registry));
    let stale_profile = LoaderGate::recorded()
        .plan(&io_uring_profile("580.1"), &request, &registry)
        .unwrap();
    assert!(
        stale_profile.is_ordinary_loader(),
        "old-driver profile, new evidence"
    );
    let after = LoaderGate::recorded()
        .plan(&io_uring_profile("590.2"), &request, &registry)
        .unwrap();
    assert!(after.is_enabled(Optimization::IoUring));
    assert_ne!(after.configuration(), before.configuration());

    let mut gpu_host = Gpu::new(&clock);
    gpu_host.load(P1, "a", &[4 * MIB], private_memory());
    gpu_host
        .model
        .set_configuration(P1, driver_configuration("590.2"))
        .unwrap();
    assert!(matches!(
        gpu_host.model.plan_vmm(
            &mut gpu_host.driver,
            &gpu_host.registry,
            P1,
            &vmm_layout("b", &[4 * MIB]),
            private_memory(),
            vmm::VmmOrigin::Create,
        ),
        Err(VmmError::Granularity(vmm::GranularityRefusal::Evidence {
            cause: EvidenceRefusal::FingerprintChanged { .. },
            ..
        }))
    ));
    gpu_host.plan(
        P1,
        "b",
        &[4 * MIB],
        private_memory(),
        vmm::VmmOrigin::Create,
    );

    let logical = logical_of(hub_source("example-org/chat", COMMIT_A, b"w"), "t");
    let on = |runner: &str| {
        ExecutionSpec {
            logical: logical.identity(),
            runner: versioned("vllm", runner),
            architecture_adapter: versioned("llama", "1"),
            kernel_layout: versioned("flash-attn", "1"),
            gpu_architectures: BTreeSet::from([label("sm_90a")]),
            topology: RankTopology::SINGLE,
            processed_weights: versioned("vllm-bf16", "1"),
            compile: CompileConfiguration::Eager,
        }
        .identity()
        .unwrap()
    };
    let (old_runner, new_runner) = (on("0.31.0"), on("0.32.0"));
    assert_ne!(old_runner, new_runner);
    let capture = |execution| GraphCaptureSpec {
        execution,
        device: gpu(0),
        shape: CaptureShape {
            sequences: 1,
            tokens: 128,
        },
        resources: vec![IdGraphResource {
            role: label("weights"),
            kind: GraphResourceKind::Weights,
            content: named("weights", "chat"),
            allocation: GpuAllocationGeneration::FIRST,
            device_address: 0x7000_0000,
            length_bytes: MIB,
            layout: label("row-major"),
        }],
    };
    assert_eq!(
        capture(old_runner).check_reuse(&capture(new_runner)),
        Err(GraphReuseRefusal::Mismatch {
            differences: vec![GraphDifference::Execution]
        })
    );
    let upgraded = NativeAbi::new(
        NativeAbiVersion { major: 2, minor: 0 },
        NativeOperation::ALL.into_iter().collect(),
    );
    assert_eq!(
        upgraded.check(&AbiDeclaration {
            version: NATIVE_ABI_VERSION,
            operations: BTreeSet::from([NativeOperation::CopyToDeviceAsync]),
        }),
        Err(AbiRefusal::VersionMismatch {
            provided: NativeAbiVersion { major: 2, minor: 0 },
            declared: NATIVE_ABI_VERSION,
        })
    );
}

/// GPU-T45 (line 1327): a legacy setup or runner on the old contract gets a supported
/// fallback, with no forced migration.
///
/// Today's clients keep their five progress states, written exactly as before, with the
/// new detail beside them. A runner whose profile permits no optimization runs the
/// ordinary loader, each refusal explained. A runner without CUDA VMM serves from one
/// ordinary allocation per artifact. The importer never converts the user's files: a
/// sidecar over the originals migrates by re-indexing them, and the packaged format stays
/// a gated non-goal. Not covered: today's runner processes themselves (GPU-W01 and later).
#[test]
fn gpu_t45_old_contracts_keep_working_without_migration() {
    assert_eq!(
        ClientState::ALL.map(ClientState::as_str),
        [
            "queued",
            "freeing_memory",
            "loading_model",
            "generating",
            "retrying"
        ]
    );
    for (phase, state) in [
        (Phase::Queued, ClientState::Queued),
        (Phase::Reserving, ClientState::FreeingMemory),
        (Phase::Verifying, ClientState::LoadingModel),
        (Phase::Running, ClientState::Generating),
    ] {
        assert_eq!(client_state(phase), Some(state));
    }
    let update = ProgressUpdate::new(
        TrackedResourceId::new(named("resource", "weights")),
        EventResource::Weights,
        40,
        Some(100),
        0,
        CancellationBoundary::Anytime,
    );
    let public = serde_json::to_value(PublicProgress::new(Phase::Transferring, &update)).unwrap();
    assert_eq!(public["state"], "loading_model");

    let clock = test_clock();
    let legacy_profile = RuntimeProfile {
        runtime: gpu_runtime(),
        configuration: driver_configuration("580.1"),
        permitted: BTreeMap::new(),
    };
    let request = LoaderRequest {
        optimizations: BTreeMap::from([
            (Optimization::IoUring, Necessity::Optional),
            (Optimization::GpuDirectStorage, Necessity::Optional),
        ]),
    };
    let plan = LoaderGate::recorded()
        .plan(
            &legacy_profile,
            &request,
            &ProbeRegistry::new(Arc::clone(&clock)),
        )
        .unwrap();
    assert!(plan.is_ordinary_loader());
    assert!(plan
        .ordinary()
        .values()
        .all(|reason| *reason == NotEnabled::NotPermitted));

    let mut gpu_host = Gpu::new(&clock);
    let legacy = gpu_host
        .model
        .plan_legacy(
            P1,
            named("artifact", "chat"),
            ContentKey::of(b"chat"),
            vmm::BatchSpec {
                length_bytes: 4 * MIB,
                digest: batch_digest("chat", 0),
            },
        )
        .unwrap();
    gpu_host.fill(legacy, "chat", 0);
    let view = gpu_host.model.create_view(legacy, 0, 4 * MIB).unwrap();
    assert!(gpu_host
        .model
        .call_view(&mut gpu_host.driver, view, STREAM)
        .is_ok());

    let sidecar = raw_manifest_builder(&plain_floats()).finish().unwrap();
    assert_eq!(
        sidecar.manifest().lifecycle.migration,
        mf::MigrationRequirement::ReindexFromSources
    );
    assert_eq!(mf::PACKAGED_FORMAT.name, ".ywi packaged representation");
}

/// GPU-T46 (line 1328): optional acceleration disabled; an ordinary model run stays
/// functional.
///
/// With io_uring and GPUDirect Storage requested as optional and no evidence for either,
/// the plan is the ordinary loader; the executor, whose backend implements both and has
/// device staging, reads with positioned reads into the host ring and delivers exact
/// bytes. Without CUDA VMM granularity evidence the VMM plan is refused and the ordinary
/// allocation serves. A model slot activates and serves without any of them.
#[test]
fn gpu_t46_disabling_optional_acceleration_keeps_ordinary_runs_working() {
    let clock = test_clock();
    let plan = loader_plan(
        &clock,
        &[
            (Optimization::IoUring, Necessity::Optional),
            (Optimization::GpuDirectStorage, Necessity::Optional),
        ],
        false,
    )
    .unwrap();
    assert!(plan.is_ordinary_loader());
    let transfers = Transfers::new(&clock);
    {
        let mut edge = transfers.edge();
        edge.methods.insert(ReadMethod::IoUring);
        edge.methods.insert(ReadMethod::GpuDirectStorage);
    }
    let weights = Weights::new("weights", &[16; 4], true);
    transfers.publish(&weights, &[local("nvme")]);
    let mut config = transfers.config();
    config.device_staging.insert(
        gpu(0),
        DeviceStagingConfig {
            slots: 2,
            slot_bytes: SLOT,
        },
    );
    let mut executor = transfers.executor_with(config);
    executor
        .submit(TransferRequest {
            loader: LoaderPermissions::from_plan(&plan),
            ..load_job("load", "tenant-a", &weights, "slot")
        })
        .unwrap();
    transfers.drive(&mut executor);
    assert_eq!(
        executor.status(&operation("load")),
        Some(&JobStatus::Completed)
    );
    assert!(transfers
        .edge()
        .read_log
        .iter()
        .all(|read| read.1 == ReadMethod::PositionedRead && read.2 == StagingPlace::Host));
    assert_eq!(
        transfers.landed(&allocation("slot"), 0, 64),
        weights.decoded
    );

    let mut gpu_host = Gpu::new(&clock);
    assert!(matches!(
        gpu_host.model.plan_vmm(
            &mut gpu_host.driver,
            &gpu_host.registry,
            P1,
            &vmm_layout("a", &[4 * MIB]),
            private_memory(),
            vmm::VmmOrigin::Create,
        ),
        Err(VmmError::Granularity(vmm::GranularityRefusal::Evidence {
            cause: EvidenceRefusal::Missing {
                capability: Capability::CudaVmmAllocation
            },
            ..
        }))
    ));
    let ordinary = gpu_host
        .model
        .plan_legacy(
            P1,
            named("artifact", "a"),
            ContentKey::of(b"a"),
            vmm::BatchSpec {
                length_bytes: 4 * MIB,
                digest: batch_digest("a", 0),
            },
        )
        .unwrap();
    gpu_host.fill(ordinary, "a", 0);

    let mut host = Slot::new(&clock, 1, 32 * GIB);
    let published = host.activate(&activation("model-a", &model_a()));
    assert_eq!(
        host.admit("request").unwrap().generation,
        published.generation
    );
}

/// GPU-T47 (line 1329): many tiny requests or preparations; control-plane CPU and memory
/// stay bounded.
///
/// The progress stream tracks at most its bound of states and pushes back on the rest;
/// P08's publisher refuses operations beyond its bound instead of growing; the ledger's
/// queue refuses past its bound; and a load of 64 four-byte extents is coalesced into a
/// handful of aligned reads through a fixed staging pool. Not covered: CPU time, which
/// these fakes cannot measure; the bounds here are counts of work and of retained state.
#[test]
fn gpu_t47_tiny_requests_keep_control_plane_state_bounded() {
    let clock = test_clock();
    let mut hub = event_hub(&clock, 1);
    let mut producer = hub
        .register_progress(
            ProducerId::new("engine.progress").unwrap(),
            SourceClass::HostProbe,
            None,
        )
        .unwrap();
    let mut refused = 0;
    for index in 0..100u64 {
        let outcome = hub.emit_progress(
            &mut producer,
            EventContext::new(operation(&format!("op-{index}")), Phase::Loading),
            ProgressUpdate::new(
                TrackedResourceId::new(named("resource", &index.to_string())),
                EventResource::Weights,
                1,
                Some(4),
                1,
                CancellationBoundary::Anytime,
            ),
        );
        if matches!(
            outcome,
            Err(EmitError::Progress(ProgressRefusal::TooManyTracked {
                limit: 64
            }))
        ) {
            refused += 1;
        }
    }
    assert_eq!(refused, 36);
    assert_eq!(hub.progress().tracked(), 64);

    let mut publisher_hub = event_hub(&clock, 1);
    let producer = publisher_hub
        .register_progress(
            ProducerId::new("engine.progress").unwrap(),
            SourceClass::HostProbe,
            None,
        )
        .unwrap();
    let mut publisher = ProgressPublisher::new(
        producer,
        Incarnation::FIRST,
        Arc::clone(&clock),
        ClockId::new(ReportLabel::new("host-monotonic").unwrap()),
        PublishPolicy {
            max_operations: 8,
            ..PublishPolicy::default()
        },
    )
    .unwrap();
    for index in 0..9u64 {
        let tracked = publisher.track(
            &mut publisher_hub,
            &operation(&format!("op-{index}")),
            TrackRequest {
                resource: TrackedResourceId::new(named("resource", &index.to_string())),
                kind: EventResource::Weights,
                total_bytes: 4,
                stage: Stage::at(Phase::Transferring),
            },
        );
        if index < 8 {
            assert!(tracked.is_ok());
        } else {
            assert_eq!(tracked, Err(PublishError::TooManyOperations { max: 8 }));
        }
    }
    assert_eq!(publisher.tracked(), 8);

    let vram = vram_resource(gpu(0));
    let mut ledger = host_ledger(&clock, &[(vram, GIB)], &["t-0", "t-1", "t-2"]);
    let LedgerAdmission::Granted(holder) = ledger
        .reserve(LedgerRequest::new(
            Provenance {
                requester: Requester::ModelPlacement,
                execution: execution("exe-holder"),
                operation: operation("holder"),
                tenant: tenant("t-0"),
                purpose: CostPurpose::Compute,
                retry_number: 0,
            },
            Priority::Foreground,
            Amounts::new().with(vram, GIB),
        ))
        .unwrap()
    else {
        panic!("the holder takes the device");
    };
    ledger.begin_create(holder).unwrap();
    let mut full = 0;
    for index in 0..10u64 {
        let owner = format!("t-{}", 1 + index % 2);
        let result = ledger.reserve(
            LedgerRequest::new(
                Provenance {
                    requester: Requester::ModelPlacement,
                    execution: execution(&format!("exe-{index}")),
                    operation: operation(&format!("tiny-{index}")),
                    tenant: tenant(&owner),
                    purpose: CostPurpose::Compute,
                    retry_number: 0,
                },
                Priority::Foreground,
                Amounts::new().with(vram, MIB),
            )
            .wait_up_to(MINUTE),
        );
        if result.is_err() {
            full += 1;
        }
    }
    assert!(ledger.queue_len() <= 4);
    assert_eq!(full, 10 - ledger.queue_len());

    let transfers = Transfers::new(&clock);
    let weights = Weights::new("tiny", &[4; 64], false);
    transfers.publish(&weights, &[local("nvme")]);
    let mut executor = transfers.executor();
    executor
        .submit(load_job("tiny", "tenant-a", &weights, "slot"))
        .unwrap();
    transfers.drive(&mut executor);
    assert_eq!(
        executor.status(&operation("tiny")),
        Some(&JobStatus::Completed)
    );
    assert_eq!(
        transfers.edge().read_log.len(),
        4,
        "64 extents in four reads"
    );
    assert!(
        executor
            .staging_usage(StagingPlace::Host)
            .unwrap()
            .peak_in_use
            <= 4
    );
}

/// GPU-T48 (line 1330): shared-cache timing or catalog disclosure; the trust-scope
/// visibility policy holds.
///
/// Tenant B cannot find, see the status of, or read the metadata of tenant A's object,
/// and B's failure records never show A's. B's import of the same bytes starts its own
/// import and fetches every byte, so no instant hit reveals that A holds them. A peer copy
/// of A's object is excluded from B's source choice until A grants exactly that object to
/// exactly B's execution. Not covered: hardware timing channels such as page-cache or
/// last-level-cache timing, which these fakes cannot observe.
#[test]
fn gpu_t48_the_shared_cache_discloses_nothing_across_trust_scopes() {
    let clock = test_clock();
    let mut store = Store::open(&clock, &["tenant-a", "tenant-b"], 6 * CATALOG_EXTENT);
    let scope_a = Scope::tenant(tenant("tenant-a"));
    let scope_b = Scope::tenant(tenant("tenant-b"));
    let bytes = payload(48, 4 * CATALOG_EXTENT as usize);
    let object = publish_original(store.catalog(), &scope_a, "exe-a", "secret-model", &bytes);
    let too_big = payload(49, 4 * CATALOG_EXTENT as usize);
    let (request, identity) = weights_import("tenant-a", "exe-a", "too-big", &too_big);
    assert!(store.catalog().begin_import(request, identity).is_err());
    assert!(store.view().failures_in(&scope_a).count() > 0);

    let content = ContentKey::of(&bytes);
    assert_eq!(
        store
            .view()
            .find(&scope_b, ArtifactClass::ModelWeights, content),
        None
    );
    assert_eq!(store.view().status(&scope_b, object), ObjectStatus::Absent);
    assert!(store.view().private_metadata(&scope_b, object).is_err());
    assert_eq!(store.view().failures_in(&scope_b).count(), 0);
    assert!(matches!(
        store
            .view()
            .object_view(&scope_b, &execution("exe-b"), object),
        Err(ReadRefusal::NotGranted { .. })
    ));
    let (request, identity) = weights_import("tenant-b", "exe-b", "secret-model", &bytes);
    let start = store.catalog().begin_import(request, identity).unwrap();
    let ImportStart::Started(ticket) = start else {
        panic!("B starts its own import: {start:?}");
    };
    let mut source = MemorySource::new("secret-model", &bytes);
    assert!(matches!(
        store
            .catalog()
            .drive_import(&ticket, &mut source, &mut Uninterrupted)
            .unwrap(),
        ImportStatus::Published { object: own, .. } if own != object
    ));
    assert_eq!(
        source.delivered_bytes,
        bytes.len() as u64,
        "no cross-scope hit"
    );

    let object_a = weights_ref("tenant-a", &bytes);
    let mut peer = PeerSource::new(
        PeerAuthorization {
            scopes: BTreeSet::from([scope_a.clone()]),
            expires_at: clock.now().saturating_add(HOUR),
            donor_budget_bytes: MIB,
        },
        Vec::new(),
    );
    peer.hold(object_a.clone(), PeerContent::ImmutableWeights, 256)
        .unwrap();
    let reader = consumer("tenant-b", "exe-b");
    let request = SourceRequest {
        requester: reader.clone(),
        content,
        batches_bytes: vec![64; 4],
        cuts: Vec::new(),
        policy: steal_policy(),
    };
    let offer = || {
        peer.offer(
            source_id("peer"),
            &object_a,
            &reader,
            peer_path(1e9, 0.0),
            &*clock,
        )
    };
    assert!(matches!(
        choose_source(&request, vec![offer()], store.view()),
        Err(SourceChoiceError::NoEligibleSource { excluded })
            if matches!(excluded[0].reason, ExclusionReason::OutsideScope { .. })
    ));
    store
        .catalog()
        .grant(
            &scope_a,
            GrantRequest {
                object,
                grantee: scope_b.clone(),
                execution: Some(execution("exe-b")),
                expires_at: clock.now().saturating_add(HOUR),
            },
        )
        .unwrap();
    let granted = choose_source(&request, vec![offer()], store.view()).unwrap();
    assert_eq!(granted.assigned_bytes(&source_id("peer")), 256);
    assert!(
        store.view().private_metadata(&scope_b, object).is_err(),
        "content only"
    );
}
