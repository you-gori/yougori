//! Fakes for the five boundaries, for tests on a [`ManualClock`]: a catalog and importer,
//! a transfer executor whose transfers run in the background on a modelled link, a
//! runner that holds native handles and advertises T07 residencies, an API sink, and a
//! governor that wraps the real one and under-reserves. For the adapters over the
//! committed modules: an integrity-extent planner for P01's importer, and P03's native
//! backend, batching and event ports in memory.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use super::abi::{
    AbiDeclaration, NativeHandle, NativeHandleKind, NativeOperation, NATIVE_ABI_VERSION,
};
use super::api::ApiAdapter;
use super::catalog::{
    verify_submission, ArtifactCatalog, ArtifactImporter, CatalogRefusal, ExtentRef, ImportRefusal,
    ImportSubmission, VerifiedRepresentation,
};
use super::declaration::{
    DependencyNode, ExecutionDependencies, NodeId, SecurityPartition, StateIdentity, StateRef,
};
use super::executor::{
    ExtentCompletion, OrderedExtent, TransferExecutor, TransferFailure, TransferOrder,
    TransferRefusal, TransferTicket,
};
use super::flow::{FlowError, FlowEvent, FlowPhase};
use super::governor::{
    AbandonedActivation, Admission, AdmissionRefusal, AdmissionRequest, ExecutionLease,
    GovernorError, LedgerGrant, PendingActivation, PendingRefusal, PlacementGovernor, PlacementKey,
    PlacementOwner, PreparationLease, ReloadStatus, RequestAuthority, RuntimeView,
    TransferDestination,
};
use super::kv::{kv_bytes, KvLayout};
use super::preparation::PreparationToken;
use super::runner::{
    ActivationOrder, Compatibility, ComputeAssignment, DependencyEvent, Incompatibility,
    PublishedModel, ResidentState, RunnerAdapter, RunnerDiagnostics, RunnerProfile, RunnerRefusal,
    ServeOrder, ServeOutcome,
};
use crate::foundation::evidence::{Backend, SourceClass};
use crate::foundation::ids::{
    Clock, ContentKey, ExecutionCategory, GpuAllocationGeneration, ManualClock,
    ModelActivationGeneration, MonotonicTime, OperationId, TrustScope,
};
use crate::foundation::ids::{Digest, GpuDeviceKey};
use crate::model_memory::executor::SourceKind;
use crate::model_memory::executor::{
    BackendError, BackendErrorKind, BatchLimits, BatchPlan, BatchPort, CopyApi, CopyRequest,
    DecodeRequest, DestinationRange, EventId, EventPort, EventStatus, ExtentSpan, ReadMethod,
    ReadRequest, ReadStatus, ReadTicket, StagedRange, StagingBuffer, StoredForm, TransferBackend,
    TransferEvent,
};
use crate::model_memory::graph::node::NodeKind;
use crate::model_memory::identity::{
    ArtifactIdentity, CurrentResidency, ExecutionIdentity, Residency, ResidentAdvertisement,
};
use crate::model_memory::manifest::{ExtentPlanError, ExtentPlanner, ExtentSpan as IntegritySpan};
use crate::model_memory::math::SourceId;
use crate::model_memory::placement::{RequestShape, SupportedShape};
use crate::model_memory::residency::eviction::{CopyTier, EvictionAction};

/// A catalog and importer in memory. It keeps imported bytes so tests can hand them to
/// the executor as local storage.
#[derive(Debug, Default)]
pub struct FakeCatalog {
    published: BTreeMap<(ArtifactIdentity, TrustScope), VerifiedRepresentation>,
    contents: BTreeMap<ExtentRef, Vec<u8>>,
}

impl FakeCatalog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn content(&self, extent: &ExtentRef) -> Option<&[u8]> {
        self.contents.get(extent).map(Vec::as_slice)
    }

    pub fn contents(&self) -> impl Iterator<Item = (&ExtentRef, &Vec<u8>)> {
        self.contents.iter()
    }
}

impl ArtifactImporter for FakeCatalog {
    fn import(&mut self, submission: ImportSubmission) -> Result<ArtifactIdentity, ImportRefusal> {
        let representation = verify_submission(&submission)?;
        let artifact = representation.artifact();
        for imported in submission.extents {
            self.contents.insert(
                ExtentRef {
                    artifact,
                    extent: imported.extent,
                },
                imported.content,
            );
        }
        self.published
            .insert((artifact, representation.scope()), representation);
        Ok(artifact)
    }
}

impl ArtifactCatalog for FakeCatalog {
    fn representation(
        &self,
        artifact: &ArtifactIdentity,
        partition: &SecurityPartition,
    ) -> Result<VerifiedRepresentation, CatalogRefusal> {
        let mut exists = false;
        for ((published, scope), representation) in &self.published {
            if published == artifact {
                exists = true;
                if partition.allows(scope) {
                    return Ok(representation.clone());
                }
            }
        }
        Err(if exists {
            CatalogRefusal::OutsidePartition {
                artifact: *artifact,
            }
        } else {
            CatalogRefusal::UnknownArtifact {
                artifact: *artifact,
            }
        })
    }
}

/// How the fake executor behaves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutorMode {
    /// Reads, verifies and refuses a hash mismatch.
    Honest,
    /// Delivers `delivered` when asked for `requested`, without checking: an executor
    /// that chose a different model.
    Substitute {
        requested: ExtentRef,
        delivered: ExtentRef,
    },
    /// Labels the bytes of `content_of` as `requested`, without checking.
    Relabel {
        requested: ExtentRef,
        content_of: ExtentRef,
    },
    /// Reports reading this many bytes more than each extent's length.
    OverRead { extra_bytes: u64 },
}

#[derive(Debug)]
struct Ticket {
    expected: BTreeMap<ExtentRef, OrderedExtent>,
    usable_at: BTreeMap<ExtentRef, MonotonicTime>,
    cancelled: bool,
}

/// A transfer executor with one link of `bandwidth_bytes_per_second`. Transfers start at
/// `submit` and proceed in order in the background; `await_extent` moves the clock to
/// when that extent's chain completes, so work done meanwhile overlaps the transfer.
#[derive(Debug)]
pub struct FakeExecutor {
    clock: Arc<ManualClock>,
    bandwidth_bytes_per_second: u64,
    sources: BTreeMap<ExtentRef, (Vec<u8>, SourceKind)>,
    mode: ExecutorMode,
    tickets: BTreeMap<u64, Ticket>,
    next_ticket: u64,
    submitted: Vec<ExtentRef>,
    cancelled: Vec<TransferTicket>,
}

impl FakeExecutor {
    pub fn new(clock: Arc<ManualClock>, bandwidth_bytes_per_second: u64) -> Self {
        Self {
            clock,
            bandwidth_bytes_per_second,
            sources: BTreeMap::new(),
            mode: ExecutorMode::Honest,
            tickets: BTreeMap::new(),
            next_ticket: 0,
            submitted: Vec::new(),
            cancelled: Vec::new(),
        }
    }

    pub fn add_source(&mut self, extent: ExtentRef, content: Vec<u8>, kind: SourceKind) {
        self.sources.insert(extent, (content, kind));
    }

    /// Flips one byte of a source, as a corrupted local copy.
    pub fn corrupt(&mut self, extent: &ExtentRef) {
        if let Some((content, _)) = self.sources.get_mut(extent) {
            if let Some(byte) = content.first_mut() {
                *byte ^= 0xff;
            }
        }
    }

    pub fn set_mode(&mut self, mode: ExecutorMode) {
        self.mode = mode;
    }

    /// Every extent ordered so far, in order.
    pub fn submitted(&self) -> &[ExtentRef] {
        &self.submitted
    }

    pub fn cancelled(&self) -> &[TransferTicket] {
        &self.cancelled
    }

    fn duration(&self, length_bytes: u64) -> Duration {
        let nanos = u128::from(length_bytes) * 1_000_000_000
            / u128::from(self.bandwidth_bytes_per_second.max(1));
        Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
    }
}

impl TransferExecutor for FakeExecutor {
    fn submit(&mut self, order: &TransferOrder) -> Result<TransferTicket, TransferRefusal> {
        if order.total_bytes() > order.budget_bytes() {
            return Err(TransferRefusal::ExceedsBudget {
                total_bytes: order.total_bytes(),
                budget_bytes: order.budget_bytes(),
            });
        }
        if let Some(missing) = order
            .extents()
            .iter()
            .find(|ordered| !self.sources.contains_key(&ordered.extent))
        {
            return Err(TransferRefusal::SourceUnavailable {
                extent: missing.extent,
            });
        }
        let mut at = self.clock.now();
        let mut usable_at = BTreeMap::new();
        let mut expected = BTreeMap::new();
        for ordered in order.extents() {
            at = at.saturating_add(self.duration(ordered.length_bytes));
            usable_at.insert(ordered.extent, at);
            expected.insert(ordered.extent, *ordered);
            self.submitted.push(ordered.extent);
        }
        self.next_ticket += 1;
        self.tickets.insert(
            self.next_ticket,
            Ticket {
                expected,
                usable_at,
                cancelled: false,
            },
        );
        Ok(TransferTicket::new(self.next_ticket))
    }

    fn await_extent(
        &mut self,
        ticket: TransferTicket,
        extent: &ExtentRef,
    ) -> Result<ExtentCompletion, TransferFailure> {
        let state = self
            .tickets
            .get(&ticket.get())
            .ok_or(TransferFailure::UnknownTicket { ticket })?;
        if state.cancelled {
            return Err(TransferFailure::Cancelled);
        }
        let usable_at = *state
            .usable_at
            .get(extent)
            .ok_or(TransferFailure::NotOrdered { extent: *extent })?;
        let expected = *state
            .expected
            .get(extent)
            .ok_or(TransferFailure::NotOrdered { extent: *extent })?;
        self.clock.advance_to(usable_at);
        let (delivered, content_of, checked) = match self.mode {
            ExecutorMode::Substitute {
                requested,
                delivered,
            } if requested == *extent => (delivered, delivered, false),
            ExecutorMode::Relabel {
                requested,
                content_of,
            } if requested == *extent => (*extent, content_of, false),
            _ => (*extent, *extent, true),
        };
        let (content, source) = self
            .sources
            .get(&content_of)
            .ok_or(TransferFailure::SourceFailed { extent: *extent })?;
        let actual = ContentKey::of(content);
        if checked && actual != expected.digest {
            return Err(TransferFailure::HashMismatch {
                extent: *extent,
                expected: expected.digest,
                actual,
            });
        }
        let extra = match self.mode {
            ExecutorMode::OverRead { extra_bytes } => extra_bytes,
            _ => 0,
        };
        Ok(ExtentCompletion {
            extent: delivered,
            verified_digest: actual,
            bytes_read: (content.len() as u64).saturating_add(extra),
            source: *source,
            completed_at: self.clock.now(),
        })
    }

    fn cancel(&mut self, ticket: TransferTicket) {
        if let Some(state) = self.tickets.get_mut(&ticket.get()) {
            state.cancelled = true;
        }
        self.cancelled.push(ticket);
    }
}

/// One model a fake runner supports.
#[derive(Clone, Debug)]
pub struct FakeModel {
    pub dependencies: ExecutionDependencies,
    /// The largest shape the runner can be ready for with this model.
    pub max_shape: SupportedShape,
}

#[derive(Clone, Debug)]
struct Activation {
    residency: Residency,
    ready_for: SupportedShape,
}

/// What the fake runner was asked to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunnerCall {
    Reconstruct(StateIdentity),
    Usable(StateIdentity),
    ComputeAhead {
        operation: OperationId,
        group: u32,
    },
    Activate {
        model: ExecutionIdentity,
        generation: ModelActivationGeneration,
    },
    Serve {
        operation: OperationId,
        generation: ModelActivationGeneration,
    },
    ReleaseSession {
        operation: OperationId,
        action: EvictionAction,
    },
    Drop(Vec<StateRef>),
    Discard {
        generation: ModelActivationGeneration,
    },
    /// A drained generation's KV and contexts were freed for a reload.
    ReleaseGeneration {
        generation: ModelActivationGeneration,
        freed: Vec<StateIdentity>,
    },
}

/// The first raw value of the fake's native handles, so a test can search for them.
pub const HANDLE_SENTINEL: u64 = 0x7ead_beef_0000_0000;

/// A runner on a [`ManualClock`]: reconstruction takes each node's estimate, computing a
/// group takes its compute time, and activation takes `activation_time`. It allocates
/// native handles as a device-owning runtime would and keeps them to itself. It holds
/// every validated generation of a model until its state is dropped, so a request keeps
/// the generation it was admitted with (INT-03), and advertises the newest one.
#[derive(Debug)]
pub struct FakeRunner {
    clock: Arc<ManualClock>,
    profile: RunnerProfile,
    models: BTreeMap<ExecutionIdentity, FakeModel>,
    resident: BTreeMap<StateIdentity, u64>,
    sessions: BTreeMap<OperationId, u64>,
    written_back: Vec<(OperationId, u64)>,
    generations: BTreeMap<ExecutionIdentity, BTreeMap<ModelActivationGeneration, Activation>>,
    advertisement_ttl: Duration,
    activation_time: Duration,
    computed_ahead: BTreeMap<OperationId, u32>,
    handles: Vec<NativeHandle>,
    calls: Vec<RunnerCall>,
    tokens: Vec<PreparationToken>,
    kv_layout: Option<KvLayout>,
    /// Operations still serving on each generation, as a test holds them.
    serving: BTreeMap<ModelActivationGeneration, BTreeSet<OperationId>>,
}

impl FakeRunner {
    pub fn new(
        clock: Arc<ManualClock>,
        owner: PlacementOwner,
        scope: TrustScope,
        category: ExecutionCategory,
    ) -> Self {
        Self {
            clock,
            profile: RunnerProfile {
                abi: AbiDeclaration {
                    version: NATIVE_ABI_VERSION,
                    operations: BTreeSet::from([
                        NativeOperation::CopyToDeviceAsync,
                        NativeOperation::RecordCompletionEvent,
                        NativeOperation::QueryCompletionEvent,
                    ]),
                },
                owner,
                scope,
                category,
                backend: Backend::Vllm,
                execute_while_load: true,
                kv_write_back: Some(CopyTier::PinnedHost),
            },
            models: BTreeMap::new(),
            resident: BTreeMap::new(),
            sessions: BTreeMap::new(),
            written_back: Vec::new(),
            generations: BTreeMap::new(),
            advertisement_ttl: Duration::from_secs(60),
            activation_time: Duration::ZERO,
            computed_ahead: BTreeMap::new(),
            handles: Vec::new(),
            calls: Vec::new(),
            tokens: Vec::new(),
            kv_layout: None,
            serving: BTreeMap::new(),
        }
    }

    /// Declares the KV layout of the pinned backend, as its rules state it.
    pub fn set_kv_layout(&mut self, layout: Option<KvLayout>) {
        self.kv_layout = layout;
    }

    /// `operation` keeps running on `generation` until [`Self::finish_serving`], as an
    /// old-generation request does while serving pauses for a reload.
    pub fn hold_serving(&mut self, generation: ModelActivationGeneration, operation: OperationId) {
        self.serving
            .entry(generation)
            .or_default()
            .insert(operation);
    }

    /// `operation` finished on `generation`.
    pub fn finish_serving(
        &mut self,
        generation: ModelActivationGeneration,
        operation: &OperationId,
    ) {
        if let Some(operations) = self.serving.get_mut(&generation) {
            operations.remove(operation);
            if operations.is_empty() {
                self.serving.remove(&generation);
            }
        }
    }

    pub fn add_model(&mut self, model: ExecutionIdentity, spec: FakeModel) {
        self.models.insert(model, spec);
    }

    pub fn set_abi(&mut self, abi: AbiDeclaration) {
        self.profile.abi = abi;
    }

    pub fn set_execute_while_load(&mut self, supported: bool) {
        self.profile.execute_while_load = supported;
    }

    pub fn set_kv_write_back(&mut self, tier: Option<CopyTier>) {
        self.profile.kv_write_back = tier;
    }

    pub fn set_category(&mut self, category: ExecutionCategory) {
        self.profile.category = category;
    }

    pub fn set_advertisement_ttl(&mut self, ttl: Duration) {
        self.advertisement_ttl = ttl;
    }

    pub fn set_activation_time(&mut self, activation_time: Duration) {
        self.activation_time = activation_time;
    }

    /// Advertises a residency that coordination never recorded, as a forged hint.
    pub fn force_generation(
        &mut self,
        model: ExecutionIdentity,
        current: &CurrentResidency,
        ready_for: SupportedShape,
    ) {
        self.generations.entry(model).or_default().insert(
            current.generation,
            Activation {
                residency: current.residency.clone(),
                ready_for,
            },
        );
    }

    /// State already held, as before a request.
    pub fn make_resident(&mut self, identity: StateIdentity, device_bytes: u64) {
        self.resident.insert(identity, device_bytes);
    }

    pub fn is_resident(&self, identity: &StateIdentity) -> bool {
        self.resident.contains_key(identity)
    }

    pub fn has_session(&self, operation: &OperationId) -> bool {
        self.sessions.contains_key(operation)
    }

    pub fn written_back(&self) -> &[(OperationId, u64)] {
        &self.written_back
    }

    pub fn held_generations(&self, model: &ExecutionIdentity) -> Vec<ModelActivationGeneration> {
        self.generations
            .get(model)
            .map(|held| held.keys().copied().collect())
            .unwrap_or_default()
    }

    pub fn calls(&self) -> &[RunnerCall] {
        &self.calls
    }

    pub fn tokens(&self) -> &[PreparationToken] {
        &self.tokens
    }

    /// Raw values of the native handles the runner holds.
    pub fn handle_raws(&self) -> Vec<u64> {
        self.handles.iter().map(NativeHandle::raw).collect()
    }

    pub fn handles(&self) -> &[NativeHandle] {
        &self.handles
    }

    fn allocate(&mut self, kind: NativeHandleKind) {
        let raw = HANDLE_SENTINEL + self.handles.len() as u64;
        self.handles
            .push(NativeHandle::new(kind, raw, GpuAllocationGeneration::FIRST));
    }

    fn check_owner(&self, placement: &PlacementKey) -> Result<(), RunnerRefusal> {
        if placement.owner == self.profile.owner {
            Ok(())
        } else {
            Err(RunnerRefusal::OtherPlacement)
        }
    }

    fn spec(&self, model: &ExecutionIdentity) -> Result<&FakeModel, RunnerRefusal> {
        self.models.get(model).ok_or(RunnerRefusal::Incompatible {
            reason: Incompatibility::UnsupportedModel,
        })
    }

    fn identity_of(&self, model: &ExecutionIdentity, node: NodeId) -> Option<StateIdentity> {
        self.models
            .get(model)
            .and_then(|spec| spec.dependencies.node(node))
            .map(|declared| declared.identity)
    }

    fn usable(&self, model: &ExecutionIdentity, node: NodeId) -> bool {
        self.identity_of(model, node)
            .is_some_and(|identity| self.resident.contains_key(&identity))
    }
}

impl RunnerAdapter for FakeRunner {
    fn profile(&self) -> RunnerProfile {
        self.profile.clone()
    }

    fn compatibility(&self, model: &ExecutionIdentity, shape: &RequestShape) -> Compatibility {
        match self.models.get(model) {
            None => Compatibility::Incompatible {
                reason: Incompatibility::UnsupportedModel,
            },
            Some(spec) => match spec.max_shape.check(shape) {
                Ok(()) => Compatibility::Compatible,
                Err(refusal) => Compatibility::Incompatible {
                    reason: Incompatibility::ShapeTooLarge { refusal },
                },
            },
        }
    }

    fn dependencies(
        &self,
        model: &ExecutionIdentity,
        _shape: &RequestShape,
    ) -> Result<ExecutionDependencies, RunnerRefusal> {
        Ok(self.spec(model)?.dependencies.clone())
    }

    fn residencies(&self, now: MonotonicTime) -> Vec<ResidentState> {
        self.generations
            .iter()
            .filter_map(|(model, held)| {
                let (generation, activation) = held.iter().next_back()?;
                let spec = self.models.get(model)?;
                let resident = spec
                    .dependencies
                    .nodes
                    .iter()
                    .map(|node| node.identity)
                    .filter(|identity| self.resident.contains_key(identity))
                    .collect();
                Some(ResidentState {
                    advertisement: ResidentAdvertisement {
                        residency: activation.residency.clone(),
                        generation: *generation,
                        expires_at: now.saturating_add(self.advertisement_ttl),
                    },
                    resident,
                    ready_for: activation.ready_for,
                })
            })
            .collect()
    }

    fn reconstruct(
        &mut self,
        node: &DependencyNode,
        preparation: &PreparationToken,
    ) -> Result<(), RunnerRefusal> {
        self.check_owner(preparation.placement())?;
        let model = preparation.model();
        let declared = self
            .spec(&model)?
            .dependencies
            .node(node.id)
            .is_some_and(|declared| declared.identity == node.identity);
        if !declared {
            return Err(RunnerRefusal::UnknownNode { node: node.id });
        }
        if let Some(input) = node
            .depends_on
            .iter()
            .find(|input| !self.usable(&model, **input))
        {
            return Err(RunnerRefusal::DependencyNotUsable { node: *input });
        }
        self.clock.advance(node.estimate);
        self.resident.insert(node.identity, node.device_bytes);
        self.allocate(match node.kind {
            NodeKind::GraphCapture => NativeHandleKind::Graph,
            NodeKind::EngineInitialization => NativeHandleKind::Stream,
            _ => NativeHandleKind::PhysicalAllocation,
        });
        self.tokens.push(preparation.clone());
        self.calls.push(RunnerCall::Reconstruct(node.identity));
        Ok(())
    }

    fn dependency_usable(
        &mut self,
        event: &DependencyEvent,
        preparation: &PreparationToken,
    ) -> Result<(), RunnerRefusal> {
        self.check_owner(&event.placement)?;
        self.check_owner(preparation.placement())?;
        self.resident.insert(event.identity, event.device_bytes);
        self.allocate(NativeHandleKind::DevicePointer);
        self.tokens.push(preparation.clone());
        self.calls.push(RunnerCall::Usable(event.identity));
        Ok(())
    }

    fn compute_ahead(&mut self, assignment: &ComputeAssignment<'_>) -> Result<(), RunnerRefusal> {
        let lease = assignment.lease;
        self.check_owner(lease.placement())?;
        let model = lease.placement().model;
        let operation = lease.assigned_operation().clone();
        let expected = self.computed_ahead.get(&operation).copied().unwrap_or(0);
        if assignment.group != expected {
            return Err(RunnerRefusal::GroupOutOfOrder {
                expected,
                requested: assignment.group,
            });
        }
        let spec = self.spec(&model)?;
        let group = spec
            .dependencies
            .compute
            .get(expected as usize)
            .cloned()
            .ok_or(RunnerRefusal::GroupOutOfOrder {
                expected,
                requested: assignment.group,
            })?;
        let session_bytes = spec.dependencies.session_device_bytes;
        if let Some(input) = group
            .requires
            .iter()
            .find(|input| !self.usable(&model, **input))
        {
            return Err(RunnerRefusal::DependencyNotUsable { node: *input });
        }
        self.clock.advance(group.compute);
        self.computed_ahead.insert(operation.clone(), expected + 1);
        self.sessions.insert(operation.clone(), session_bytes);
        self.calls.push(RunnerCall::ComputeAhead {
            operation,
            group: assignment.group,
        });
        Ok(())
    }

    fn activate(
        &mut self,
        order: &ActivationOrder,
        preparation: &PreparationToken,
    ) -> Result<(), RunnerRefusal> {
        self.check_owner(&order.placement)?;
        self.check_owner(preparation.placement())?;
        let model = order.placement.model;
        let spec = self.spec(&model)?;
        let missing = self.missing_for_compute(spec);
        if !missing.is_empty() {
            return Err(RunnerRefusal::MissingDependency {
                identities: missing,
            });
        }
        if !spec.max_shape.covers(&order.declared) {
            return Err(RunnerRefusal::ReadinessFailed {
                declared: order.declared,
            });
        }
        self.clock.advance(self.activation_time);
        self.generations.entry(model).or_default().insert(
            order.generation,
            Activation {
                residency: order.residency.clone(),
                ready_for: order.declared,
            },
        );
        self.allocate(NativeHandleKind::Event);
        self.tokens.push(preparation.clone());
        self.calls.push(RunnerCall::Activate {
            model,
            generation: order.generation,
        });
        Ok(())
    }

    fn serve(&mut self, order: &ServeOrder<'_>) -> Result<ServeOutcome, RunnerRefusal> {
        let lease = order.lease;
        self.check_owner(lease.placement())?;
        let model = lease.placement().model;
        let activation = self
            .generations
            .get(&model)
            .and_then(|held| held.get(&lease.generation()))
            .cloned()
            .ok_or_else(|| RunnerRefusal::GenerationMismatch {
                lease: lease.generation(),
                held: self.held_generations(&model),
            })?;
        activation
            .ready_for
            .check(&order.shape)
            .map_err(|refusal| RunnerRefusal::ShapeNotReady { refusal })?;
        if let Some(layout) = self.kv_layout {
            let needed_bytes = kv_bytes(&order.shape, layout.bytes_per_token).unwrap_or(u64::MAX);
            if needed_bytes > lease.kv_bytes() {
                return Err(RunnerRefusal::KvBeyondLease {
                    needed_bytes,
                    leased_bytes: lease.kv_bytes(),
                });
            }
        }
        let operation = lease.operation().clone();
        let ahead = self.computed_ahead.remove(&operation).unwrap_or(0);
        if ahead != order.computed_ahead_groups {
            return Err(RunnerRefusal::GroupOutOfOrder {
                expected: ahead,
                requested: order.computed_ahead_groups,
            });
        }
        let spec = self.spec(&model)?;
        let remaining: Vec<Duration> = spec
            .dependencies
            .compute
            .iter()
            .skip(ahead as usize)
            .map(|group| group.compute)
            .collect();
        let session_bytes = spec.dependencies.session_device_bytes;
        for compute in remaining {
            self.clock.advance(compute);
        }
        self.sessions.insert(operation.clone(), session_bytes);
        self.calls.push(RunnerCall::Serve {
            operation,
            generation: lease.generation(),
        });
        Ok(ServeOutcome {
            generation: lease.generation(),
            first_token_at: self.clock.now(),
        })
    }

    fn release_session(
        &mut self,
        operation: &OperationId,
        action: &EvictionAction,
    ) -> Result<(), RunnerRefusal> {
        match action {
            EvictionAction::WriteBackThenDrop { d2h_bytes, .. } => {
                if self.profile.kv_write_back.is_none() {
                    return Err(RunnerRefusal::CannotEvict);
                }
                self.written_back.push((operation.clone(), *d2h_bytes));
            }
            // A session is never a graph pool, so a recapture frees it like a clean drop.
            EvictionAction::DropClean { .. } | EvictionAction::Recapture => {}
            EvictionAction::Retain { .. } => return Err(RunnerRefusal::CannotEvict),
        }
        self.sessions.remove(operation);
        self.calls.push(RunnerCall::ReleaseSession {
            operation: operation.clone(),
            action: *action,
        });
        Ok(())
    }

    fn drop_state(&mut self, states: &[StateRef]) -> Result<(), RunnerRefusal> {
        for state in states {
            match state {
                StateRef::Node { identity } => {
                    self.resident.remove(identity);
                }
                StateRef::Session { operation } => {
                    self.sessions.remove(operation);
                    self.computed_ahead.remove(operation);
                }
            }
        }
        let complete: BTreeSet<ExecutionIdentity> = self
            .models
            .iter()
            .filter(|(_, spec)| self.missing_for_compute(spec).is_empty())
            .map(|(model, _)| *model)
            .collect();
        self.generations.retain(|model, _| complete.contains(model));
        self.calls.push(RunnerCall::Drop(states.to_vec()));
        Ok(())
    }

    fn discard_activation(
        &mut self,
        placement: &PlacementKey,
        generation: ModelActivationGeneration,
    ) -> Result<(), RunnerRefusal> {
        self.check_owner(placement)?;
        if let Some(held) = self.generations.get_mut(&placement.model) {
            held.remove(&generation);
        }
        self.calls.push(RunnerCall::Discard { generation });
        Ok(())
    }

    fn kv_layout(&self, _model: &ExecutionIdentity, _shape: &RequestShape) -> Option<KvLayout> {
        self.kv_layout
    }

    fn release_generation(
        &mut self,
        placement: &PlacementKey,
        generation: ModelActivationGeneration,
    ) -> Result<Vec<StateIdentity>, RunnerRefusal> {
        self.check_owner(placement)?;
        if self.serving.contains_key(&generation) {
            return Err(RunnerRefusal::GenerationInUse { generation });
        }
        let model = placement.model;
        if let Some(held) = self.generations.get_mut(&model) {
            held.remove(&generation);
        }
        // State another model's generation still reads stays.
        let kept: BTreeSet<StateIdentity> = self
            .generations
            .iter()
            .filter(|(other, held)| **other != model && !held.is_empty())
            .filter_map(|(other, _)| self.models.get(other))
            .flat_map(|spec| spec.dependencies.nodes.iter().map(|node| node.identity))
            .collect();
        // The KV and contexts go; the immutable weights stay for the next generation.
        let freed: Vec<StateIdentity> = self
            .spec(&model)?
            .dependencies
            .nodes
            .iter()
            .filter(|node| {
                !matches!(
                    node.kind,
                    NodeKind::ArtifactExtent | NodeKind::RankLayout | NodeKind::Adapter
                )
            })
            .map(|node| node.identity)
            .filter(|identity| self.resident.contains_key(identity) && !kept.contains(identity))
            .collect();
        for identity in &freed {
            self.resident.remove(identity);
        }
        self.calls.push(RunnerCall::ReleaseGeneration {
            generation,
            freed: freed.clone(),
        });
        Ok(freed)
    }

    fn diagnostics(&self) -> RunnerDiagnostics {
        RunnerDiagnostics {
            backend: self.profile.backend,
            owner: self.profile.owner,
            category: self.profile.category,
            resident_device_bytes: self
                .resident
                .values()
                .chain(self.sessions.values())
                .fold(0u64, |total, bytes| total.saturating_add(*bytes)),
            published: self
                .generations
                .iter()
                .filter_map(|(model, held)| {
                    held.keys().next_back().map(|generation| PublishedModel {
                        model: *model,
                        generation: *generation,
                    })
                })
                .collect(),
        }
    }
}

impl FakeRunner {
    /// State the model's computation reads that is not resident, with what it would be
    /// made from; state consumed only by resident state is not needed (GPU §1 path 2).
    fn missing_for_compute(&self, spec: &FakeModel) -> BTreeSet<StateIdentity> {
        let dependencies = &spec.dependencies;
        let mut stack: Vec<NodeId> = dependencies
            .compute
            .iter()
            .flat_map(|group| group.requires.iter().copied())
            .collect();
        let mut seen = BTreeSet::new();
        let mut missing = BTreeSet::new();
        while let Some(id) = stack.pop() {
            if !seen.insert(id) {
                continue;
            }
            let Some(node) = dependencies.node(id) else {
                continue;
            };
            if !self.resident.contains_key(&node.identity) {
                missing.insert(node.identity);
                stack.extend(node.depends_on.iter().copied());
            }
        }
        missing
    }
}

/// Records everything the API, CLI and UI adapter receives.
#[derive(Debug, Default)]
pub struct FakeApi {
    pub events: Vec<FlowEvent>,
    pub refusals: Vec<(OperationId, FlowError)>,
    pub diagnostics: Vec<Vec<RunnerDiagnostics>>,
}

impl FakeApi {
    /// Phases and their times in seconds, for one operation.
    pub fn timeline(&self, operation: &OperationId) -> Vec<(FlowPhase, f64)> {
        self.events
            .iter()
            .filter(|event| event.operation == *operation)
            .map(|event| (event.phase, event.at.as_nanos() as f64 / 1e9))
            .collect()
    }

    pub fn phases(&self, operation: &OperationId) -> Vec<FlowPhase> {
        self.timeline(operation)
            .into_iter()
            .map(|(phase, _)| phase)
            .collect()
    }

    /// Everything received, serialized and in `Debug` form.
    pub fn transcript(&self) -> String {
        let mut text = String::new();
        for event in &self.events {
            text.push_str(&serde_json::to_string(event).unwrap_or_default());
            text.push_str(&format!("{event:?}"));
        }
        for (operation, refusal) in &self.refusals {
            text.push_str(&serde_json::to_string(refusal).unwrap_or_default());
            text.push_str(&format!("{operation:?}{refusal:?}{refusal}"));
        }
        for diagnostics in &self.diagnostics {
            text.push_str(&serde_json::to_string(diagnostics).unwrap_or_default());
            text.push_str(&format!("{diagnostics:?}"));
        }
        text
    }
}

impl ApiAdapter for FakeApi {
    fn progress(&mut self, event: &FlowEvent) {
        self.events.push(event.clone());
    }

    fn refusal(&mut self, operation: &OperationId, error: &FlowError) {
        self.refusals.push((operation.clone(), error.clone()));
    }

    fn diagnostics(&mut self, runners: &[RunnerDiagnostics]) {
        self.diagnostics.push(runners.to_vec());
    }
}

/// A governor that asks the ledger for an eighth less than every activation's demand and
/// hands the short admission on; every other call is the real governor's.
pub struct ShortGovernor<'g> {
    pub inner: &'g mut dyn PlacementGovernor,
}

impl PlacementGovernor for ShortGovernor<'_> {
    fn runtime(&self, owner: PlacementOwner) -> Result<RuntimeView, GovernorError> {
        self.inner.runtime(owner)
    }

    fn admit(&mut self, request: &AdmissionRequest) -> Result<Admission, AdmissionRefusal> {
        let mut short = request.clone();
        if let Some(demand) = short.activation.as_mut() {
            demand.device_bytes -= demand.device_bytes / 8;
        }
        self.inner.admit(&short)
    }

    fn begin_create(&mut self, grant: &LedgerGrant) -> Result<(), GovernorError> {
        self.inner.begin_create(grant)
    }

    fn release(&mut self, grant: LedgerGrant) -> Result<(), GovernorError> {
        self.inner.release(grant)
    }

    fn abandon(&mut self, grant: LedgerGrant) -> Result<(), GovernorError> {
        self.inner.abandon(grant)
    }

    fn hand_over(
        &mut self,
        pending: &PendingActivation,
        source: SourceClass,
    ) -> Result<(), GovernorError> {
        self.inner.hand_over(pending, source)
    }

    fn transfer_destinations(
        &self,
        pending: &PendingActivation,
        extents: &[ExtentRef],
    ) -> BTreeMap<ExtentRef, TransferDestination> {
        self.inner.transfer_destinations(pending, extents)
    }

    fn record_usable(
        &mut self,
        pending: &PendingActivation,
        identity: StateIdentity,
    ) -> Result<(), GovernorError> {
        self.inner.record_usable(pending, identity)
    }

    fn publish_activation(
        &mut self,
        pending: PendingActivation,
        residency: Residency,
    ) -> Result<ModelActivationGeneration, PendingRefusal> {
        self.inner.publish_activation(pending, residency)
    }

    fn abandon_activation(
        &mut self,
        pending: PendingActivation,
    ) -> Result<AbandonedActivation, PendingRefusal> {
        self.inner.abandon_activation(pending)
    }

    fn confirm_released(
        &mut self,
        placement: &PlacementKey,
        generation: ModelActivationGeneration,
        source: SourceClass,
    ) -> Result<bool, GovernorError> {
        self.inner.confirm_released(placement, generation, source)
    }

    fn current_residency(&self, placement: &PlacementKey) -> Option<CurrentResidency> {
        self.inner.current_residency(placement)
    }

    fn reload_status(&self, placement: &PlacementKey) -> Option<ReloadStatus> {
        self.inner.reload_status(placement)
    }

    fn lease_execution(
        &mut self,
        authority: &RequestAuthority,
        placement: &PlacementKey,
        generation: ModelActivationGeneration,
        shape: RequestShape,
    ) -> Result<ExecutionLease, GovernorError> {
        self.inner
            .lease_execution(authority, placement, generation, shape)
    }

    fn resize_execution_lease(
        &mut self,
        lease: &mut ExecutionLease,
        shape: RequestShape,
    ) -> Result<(), GovernorError> {
        self.inner.resize_execution_lease(lease, shape)
    }

    fn check_execution_lease(&self, lease: &ExecutionLease) -> Result<(), GovernorError> {
        self.inner.check_execution_lease(lease)
    }

    fn lease_preparation(
        &mut self,
        authority: &RequestAuthority,
        pending: &PendingActivation,
    ) -> Result<PreparationLease, GovernorError> {
        self.inner.lease_preparation(authority, pending)
    }

    fn start_compute_ahead(
        &mut self,
        lease: &PreparationLease,
        inputs: &[StateIdentity],
    ) -> Result<(), GovernorError> {
        self.inner.start_compute_ahead(lease, inputs)
    }

    fn finish_compute_ahead(
        &mut self,
        lease: &PreparationLease,
        inputs: &[StateIdentity],
    ) -> Result<(), GovernorError> {
        self.inner.finish_compute_ahead(lease, inputs)
    }

    fn check_preparation_lease(&self, lease: &PreparationLease) -> Result<(), GovernorError> {
        self.inner.check_preparation_lease(lease)
    }

    fn release_execution_lease(&mut self, lease: ExecutionLease) -> Result<(), GovernorError> {
        self.inner.release_execution_lease(lease)
    }

    fn release_preparation_lease(&mut self, lease: PreparationLease) -> Result<(), GovernorError> {
        self.inner.release_preparation_lease(lease)
    }

    fn active_leases(&self, placement: &PlacementKey) -> usize {
        self.inner.active_leases(placement)
    }
}

/// Integrity extents of one fixed size for P01's importer, the last keeping its true
/// length (§2.4 g_h): the T06 granularity port's role in these tests.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FixedExtents;

impl ExtentPlanner for FixedExtents {
    fn integrity_extents(
        &self,
        logical_length_bytes: u64,
        integrity_extent_bytes: u64,
    ) -> Result<Vec<IntegritySpan>, ExtentPlanError> {
        if integrity_extent_bytes == 0 {
            return Err(ExtentPlanError::Refused);
        }
        let mut spans = Vec::new();
        let mut offset_bytes = 0;
        while offset_bytes < logical_length_bytes {
            let true_length_bytes = integrity_extent_bytes.min(logical_length_bytes - offset_bytes);
            spans.push(IntegritySpan {
                offset_bytes,
                true_length_bytes,
            });
            offset_bytes += true_length_bytes;
        }
        Ok(spans)
    }
}

/// What P03's native side holds in memory: stored objects per source, staging slots,
/// reads in flight, completion events, and the verified bytes copied to the device.
#[derive(Debug, Default)]
pub struct BackendState {
    /// Stored objects by source and content key.
    pub objects: BTreeMap<(SourceId, ContentKey), Vec<u8>>,
    /// Stored offsets a source delivers with every bit flipped.
    pub corrupt: BTreeSet<(SourceId, u64)>,
    /// Every read started: source, offset and length.
    pub read_log: Vec<(SourceId, u64, u64)>,
    /// Every copy enqueued: the destination range and the bytes it held.
    pub copies: Vec<(DestinationRange, Vec<u8>)>,
    staging: BTreeMap<StagingBuffer, Vec<u8>>,
    reads: BTreeMap<u64, ReadRequest>,
    events: BTreeSet<u64>,
    next: u64,
}

impl BackendState {
    fn staged(&self, range: &StagedRange) -> Result<Vec<u8>, BackendError> {
        let start = range.offset_bytes as usize;
        let end = start.saturating_add(range.length_bytes as usize);
        self.staging
            .get(&range.buffer)
            .and_then(|buffer| buffer.get(start..end))
            .map(<[u8]>::to_vec)
            .ok_or_else(|| BackendError::new(BackendErrorKind::Digest, "outside staged bytes"))
    }
}

/// P03's native backend in memory: reads finish when polled, copies and their completion
/// events at once. Raw extents only; it has no codec.
#[derive(Clone, Debug, Default)]
pub struct BytesBackend {
    state: Arc<Mutex<BackendState>>,
}

impl BytesBackend {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn state(&self) -> MutexGuard<'_, BackendState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl TransferBackend for BytesBackend {
    fn copy_api(&self) -> CopyApi {
        CopyApi::CudaMemcpyAsync
    }

    fn read_methods(&self) -> BTreeSet<ReadMethod> {
        BTreeSet::from([ReadMethod::PositionedRead])
    }

    fn can_access_peer(
        &mut self,
        _from: GpuDeviceKey,
        _to: GpuDeviceKey,
    ) -> Result<bool, BackendError> {
        Ok(false)
    }

    fn begin_read(&mut self, request: &ReadRequest) -> Result<ReadTicket, BackendError> {
        if request.method != ReadMethod::PositionedRead {
            return Err(BackendError::new(BackendErrorKind::Unsupported, "method"));
        }
        let mut state = self.state();
        state.next += 1;
        let ticket = state.next;
        state.read_log.push((
            request.source.clone(),
            request.offset_bytes,
            request.length_bytes,
        ));
        state.reads.insert(ticket, request.clone());
        Ok(ReadTicket(ticket))
    }

    fn poll_read(&mut self, ticket: ReadTicket) -> Result<ReadStatus, BackendError> {
        let mut state = self.state();
        let request = state
            .reads
            .remove(&ticket.0)
            .ok_or_else(|| BackendError::new(BackendErrorKind::Io, "unknown ticket"))?;
        let object = state
            .objects
            .get(&(request.source.clone(), request.representation))
            .cloned()
            .ok_or_else(|| BackendError::new(BackendErrorKind::SourceUnavailable, "no object"))?;
        let start = (request.offset_bytes as usize).min(object.len());
        let end = start
            .saturating_add(request.length_bytes as usize)
            .min(object.len());
        let mut data = object[start..end].to_vec();
        for (source, offset) in &state.corrupt {
            let at = *offset as usize;
            if *source == request.source && (start..end).contains(&at) {
                data[at - start] ^= 0xff;
            }
        }
        let bytes_read = data.len() as u64;
        state.staging.insert(request.into, data);
        Ok(ReadStatus::Complete { bytes_read })
    }

    fn stored_digest(
        &mut self,
        range: &StagedRange,
        form: &StoredForm,
    ) -> Result<Digest, BackendError> {
        match form {
            StoredForm::Raw => Ok(*ContentKey::of(&self.state().staged(range)?).digest()),
            StoredForm::Encoded { .. } => {
                Err(BackendError::new(BackendErrorKind::Unsupported, "no codec"))
            }
        }
    }

    fn content_key(&mut self, range: &StagedRange) -> Result<ContentKey, BackendError> {
        Ok(ContentKey::of(&self.state().staged(range)?))
    }

    fn decode(&mut self, _request: &DecodeRequest) -> Result<u64, BackendError> {
        Err(BackendError::new(BackendErrorKind::Unsupported, "no codec"))
    }

    fn enqueue_copy(&mut self, request: &CopyRequest) -> Result<(), BackendError> {
        let mut state = self.state();
        let bytes = state.staged(&request.from)?;
        state.copies.push((request.to, bytes));
        Ok(())
    }

    fn record_event(&mut self, _device: GpuDeviceKey) -> Result<EventId, BackendError> {
        let mut state = self.state();
        state.next += 1;
        let event = state.next;
        state.events.insert(event);
        Ok(EventId(event))
    }

    fn query_event(&mut self, event: EventId) -> Result<EventStatus, BackendError> {
        if self.state().events.contains(&event.0) {
            Ok(EventStatus::Complete)
        } else {
            Err(BackendError::new(BackendErrorKind::Event, "unknown event"))
        }
    }

    fn release_event(&mut self, event: EventId) -> Result<(), BackendError> {
        if self.state().events.remove(&event.0) {
            Ok(())
        } else {
            Err(BackendError::new(BackendErrorKind::Event, "unknown event"))
        }
    }
}

/// Coalesces adjacent extents into aligned batches that fit one staging slot, as the T06
/// granularity rule P03 checks every plan against.
#[derive(Clone, Copy, Debug, Default)]
pub struct Coalescer;

impl BatchPort for Coalescer {
    fn coalesce(&self, spans: &[ExtentSpan], limits: &BatchLimits) -> Vec<BatchPlan> {
        let align = limits.alignment_bytes;
        let down = |value: u64| value / align * align;
        let up = |value: u64| value.div_ceil(align) * align;
        let close = |members: &[&ExtentSpan]| {
            let first = members.first().map_or(0, |span| span.offset_bytes);
            let end = members
                .last()
                .map_or(0, |span| span.offset_bytes + span.length_bytes);
            BatchPlan {
                members: members.iter().map(|span| span.index).collect(),
                read_offset_bytes: down(first),
                read_length_bytes: up(end) - down(first),
            }
        };
        let mut plans = Vec::new();
        let mut current: Vec<&ExtentSpan> = Vec::new();
        let mut decoded = 0;
        for span in spans {
            if let (Some(first), Some(last)) = (current.first(), current.last()) {
                let adjacent = last.offset_bytes + last.length_bytes == span.offset_bytes;
                let read = up(span.offset_bytes + span.length_bytes) - down(first.offset_bytes);
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

/// P03's events, kept for the test.
#[derive(Clone, Debug, Default)]
pub struct EventLog(Arc<Mutex<Vec<TransferEvent>>>);

impl EventLog {
    pub fn events(&self) -> MutexGuard<'_, Vec<TransferEvent>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl EventPort for EventLog {
    fn emit(&mut self, event: TransferEvent) {
        self.events().push(event);
    }
}
