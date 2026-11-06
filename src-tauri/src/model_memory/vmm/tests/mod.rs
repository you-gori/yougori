//! Tests of the CUDA VMM model on the fake driver, with CORE-01 evidence from fake probes
//! and time from a manual clock. One file per group of rules in GPU part §3.7 and
//! Appendix E.

use std::collections::BTreeMap;
use std::num::NonZeroU64;
use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::foundation::evidence::fakes::FakeProbe;
use crate::foundation::evidence::{
    Backend, BackendRelease, Capability, ConfigurationFingerprint, CudaAllocationSubject,
    EvidencePolicy, LoaderGate, LoaderPlan, LoaderRequest, Necessity, Observation, Optimization,
    ProbeRegistry, RuntimeProfile, RuntimeSubject, ShareableHandle, SourceClass, Subject,
    SupportDetail, UnsupportedReason,
};
use crate::foundation::ids::{
    digest, ContentKey, Digest, ExecutionCategory, ManualClock, MonotonicTime,
};
use crate::model_memory::residency::eviction::{
    Content, CopyTier, ReconstructibleCopy, Verification,
};

mod canonical;
mod evidence;
mod fake_driver;
mod fallback;
mod graphs;
mod mapping;
mod ownership;
mod permission;
mod recovery;
mod reports;
mod sharing;

const MIB: u64 = 1 << 20;
const MINUTE: Duration = Duration::from_secs(60);
const HOUR: Duration = Duration::from_secs(3_600);
const DEVICE: DeviceOrdinal = DeviceOrdinal(0);
const P1: ProcessId = ProcessId(1);
const P2: ProcessId = ProcessId(2);
const P3: ProcessId = ProcessId(3);
const STREAM: StreamId = StreamId(7);
/// What the fake device reports for private allocations: 4 MiB, deliberately not 2 MiB.
const PRIVATE_GRANULE: u64 = 4 * MIB;
/// What it reports for POSIX file descriptor sharing: 8 MiB.
const SHARED_GRANULE: u64 = 8 * MIB;

fn named(label: &str) -> Digest {
    digest("yougori/test/vmm/v1", &[label.as_bytes()])
}

/// The content key a test artifact's bytes are declared to have.
fn content_of(name: &str) -> ContentKey {
    ContentKey::of(name.as_bytes())
}

/// A copy in local storage verified for exactly `content`.
fn verified_copy(content: ContentKey) -> ReconstructibleCopy {
    ReconstructibleCopy {
        tier: CopyTier::LocalStorage,
        verification: Verification::Verified {
            content: Content::Immutable(content),
        },
    }
}

fn runtime(instance: &str) -> RuntimeSubject {
    RuntimeSubject {
        category: ExecutionCategory::SharedKernelGpuRuntime,
        release: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
        instance: named(instance),
    }
}

fn configuration(driver: &str) -> ConfigurationFingerprint {
    ConfigurationFingerprint::from_settings([("driver", driver)]).unwrap()
}

fn private() -> AllocationProperties {
    AllocationProperties {
        device: DEVICE,
        requested_handle: None,
    }
}

fn posix() -> AllocationProperties {
    AllocationProperties {
        device: DEVICE,
        requested_handle: Some(ShareableHandle::PosixFileDescriptor),
    }
}

/// A process of `instance` whose own driver reports and CORE-01 evidence must both come
/// from a host probe no older than a minute.
fn context(process: ProcessId, instance: &str) -> ProcessContext {
    ProcessContext {
        process,
        device: DEVICE,
        runtime: runtime(instance),
        configuration: configuration("580.1"),
        reports_from: SourceClass::HostProbe,
        evidence_policy: EvidencePolicy {
            minimum_source: SourceClass::HostProbe,
            max_age: MINUTE,
        },
    }
}

fn batch_digest(name: &str, batch: u32) -> Digest {
    named(&format!("{name}/{batch}"))
}

fn layout(name: &str, lengths: &[u64]) -> ArtifactLayout {
    ArtifactLayout {
        artifact: named(name),
        content: content_of(name),
        batches: lengths
            .iter()
            .zip(0u32..)
            .map(|(length_bytes, batch)| BatchSpec {
                length_bytes: *length_bytes,
                digest: batch_digest(name, batch),
            })
            .collect(),
    }
}

fn whole(name: &str, length_bytes: u64) -> BatchSpec {
    BatchSpec {
        length_bytes,
        digest: batch_digest(name, 0),
    }
}

/// A clean drop on a verified local copy of artifact `name`'s content, as the residency
/// rule of clean eviction accepts it.
fn clean_drop(name: &str) -> ParkSource {
    ParkSource::CleanDrop {
        copy: VerifiedCanonicalCopy::reconstructing(
            &verified_copy(content_of(name)),
            content_of(name),
        )
        .unwrap(),
    }
}

fn granule(result: GranularityResult) -> u64 {
    match result {
        GranularityResult::Reported { granularity } => granularity.bytes(),
        GranularityResult::NotSupported => 0,
    }
}

/// One host: device 0, processes P1 and P2 in the same WSL2 runtime, CORE-01 probes for
/// both CUDA IPC API families, and a manual clock.
struct World {
    clock: Arc<ManualClock>,
    registry: ProbeRegistry<Arc<ManualClock>>,
    vmm_probe: Arc<FakeProbe>,
    legacy_probe: Arc<FakeProbe>,
    allocation_probe: Arc<FakeProbe>,
    /// What the fake device reports per requested handle type, kept in step with the
    /// CORE-01 evidence `probe` shows.
    granules: BTreeMap<Option<ShareableHandle>, u64>,
    driver: FakeDriver,
    model: VmmModel,
}

impl World {
    fn new() -> Self {
        Self::with_allocation_source(SourceClass::HostProbe)
    }

    /// A world whose CUDA VMM allocation reports come from `source`.
    fn with_allocation_source(source: SourceClass) -> Self {
        let clock = Arc::new(ManualClock::new(MonotonicTime::ZERO));
        let mut registry = ProbeRegistry::new(Arc::clone(&clock));
        let vmm_probe = Arc::new(FakeProbe::cuda_vmm_shareable_handles());
        let legacy_probe = Arc::new(FakeProbe::legacy_cuda_ipc());
        let allocation_probe = Arc::new(FakeProbe::new(Capability::CudaVmmAllocation, source));
        for probe in [&vmm_probe, &legacy_probe, &allocation_probe] {
            registry.register(Box::new(Arc::clone(probe))).unwrap();
        }
        let granules = BTreeMap::from([
            (None, PRIVATE_GRANULE),
            (Some(ShareableHandle::PosixFileDescriptor), SHARED_GRANULE),
        ]);
        let mut driver = FakeDriver::new();
        driver.add_device(
            DEVICE,
            FakeDeviceSpec {
                capacity_bytes: 1 << 30,
                granularity_bytes: granules.clone(),
            },
        );
        let mut model = VmmModel::new();
        for process in [P1, P2] {
            driver.add_process(process, DEVICE);
            model.register_process(context(process, "wsl")).unwrap();
        }
        Self {
            clock,
            registry,
            vmm_probe,
            legacy_probe,
            allocation_probe,
            granules,
            driver,
            model,
        }
    }

    /// The fake device now reports `bytes` for `handle`, or no support for `None`; later
    /// probes show CORE-01 evidence to match.
    fn set_granule(&mut self, handle: Option<ShareableHandle>, bytes: Option<u64>) {
        self.driver.set_granularity(DEVICE, handle, bytes);
        match bytes {
            Some(bytes) => self.granules.insert(handle, bytes),
            None => self.granules.remove(&handle),
        };
    }

    /// A host probe reports CUDA VMM allocation in `process`'s runtime with exactly
    /// `properties`: at `granularity_bytes`, or unsupported for `None`.
    fn show_allocation(
        &mut self,
        process: ProcessId,
        properties: AllocationProperties,
        granularity_bytes: Option<u64>,
    ) {
        let context = self.model.process_context(process).unwrap().clone();
        let subject = Subject::CudaAllocation(CudaAllocationSubject {
            runtime: context.runtime,
            device_ordinal: properties.device.0,
            requested_handle: properties.requested_handle,
        });
        let observation = match granularity_bytes {
            Some(bytes) => Observation::supported(
                context.configuration,
                HOUR,
                SupportDetail::CudaVmmAllocation {
                    granularity_bytes: NonZeroU64::new(bytes).unwrap(),
                },
            ),
            None => Observation::unsupported(
                context.configuration,
                HOUR,
                UnsupportedReason::FeatureAbsent,
            ),
        };
        self.allocation_probe.respond(&subject, observation);
        self.registry
            .refresh(Capability::CudaVmmAllocation, &subject)
            .unwrap();
    }

    /// Adds P3 in another runtime instance.
    fn add_other_runtime(&mut self) {
        self.driver.add_process(P3, DEVICE);
        self.model.register_process(context(P3, "vm")).unwrap();
    }

    /// Shows CORE-01 evidence matching what the fake device reports for `properties`, then
    /// asks Appendix E step 1.
    fn probe(&mut self, process: ProcessId, properties: AllocationProperties) -> GranularityResult {
        let shown = self.granules.get(&properties.requested_handle).copied();
        self.show_allocation(process, properties, shown);
        self.model
            .probe_granularity(&mut self.driver, &self.registry, process, properties, HOUR)
            .unwrap()
    }

    fn plan(
        &mut self,
        process: ProcessId,
        layout: &ArtifactLayout,
        properties: AllocationProperties,
        origin: VmmOrigin,
    ) -> Result<MappingKey, VmmError> {
        self.model.plan_vmm(
            &mut self.driver,
            &self.registry,
            process,
            layout,
            properties,
            origin,
        )
    }

    fn back(&mut self, key: MappingKey, batch: u32) -> Result<PhysicalId, VmmError> {
        self.model
            .back_batch(&mut self.driver, &self.registry, key, batch)
    }

    fn populate(&mut self, key: MappingKey, batch: u32) -> Result<EventId, VmmError> {
        self.model
            .populate_batch(&mut self.driver, key, batch, STREAM)
    }

    fn publish(&mut self, key: MappingKey, batch: u32, verified: Digest) -> Result<(), VmmError> {
        self.model
            .publish_batch(&mut self.driver, key, batch, verified)
    }

    /// Maps, populates, completes and publishes every batch.
    fn fill(&mut self, key: MappingKey, name: &str, batches: u32) {
        for batch in 0..batches {
            self.back(key, batch).unwrap();
            let event = self.populate(key, batch).unwrap();
            assert!(self.driver.complete(event));
            self.publish(key, batch, batch_digest(name, batch)).unwrap();
        }
    }

    /// Probes, plans and fills an artifact this process creates.
    fn load(
        &mut self,
        process: ProcessId,
        name: &str,
        lengths: &[u64],
        properties: AllocationProperties,
    ) -> MappingKey {
        self.probe(process, properties);
        let key = self
            .plan(
                process,
                &layout(name, lengths),
                properties,
                VmmOrigin::Create,
            )
            .unwrap();
        self.fill(key, name, u32::try_from(lengths.len()).unwrap());
        key
    }

    fn physical_of(&self, key: MappingKey, batch: u32) -> PhysicalId {
        self.model.batch(key, batch).unwrap().physical.unwrap()
    }

    fn call(&mut self, view: ViewId) -> Result<EventId, VmmError> {
        self.model.call_view(&mut self.driver, view, STREAM)
    }

    fn park(&mut self, key: MappingKey, source: ParkSource) -> Result<ParkReport, VmmError> {
        self.model.begin_park(&mut self.driver, key, source)?;
        self.model.finish_park(&mut self.driver, key)
    }

    fn close(&mut self, process: ProcessId, physical: PhysicalId) -> Result<u64, VmmError> {
        self.model
            .close_physical(&mut self.driver, process, physical)
    }

    fn export(
        &mut self,
        process: ProcessId,
        physical: PhysicalId,
        kind: ShareableHandle,
    ) -> Result<ExportId, VmmError> {
        self.model
            .export_allocation(&mut self.driver, &self.registry, process, physical, kind)
    }

    fn import(
        &mut self,
        key: MappingKey,
        batch: u32,
        export: ExportId,
    ) -> Result<PhysicalId, VmmError> {
        self.model
            .import_batch(&mut self.driver, &self.registry, key, batch, export)
    }

    /// A host probe shows CUDA VMM sharing with `handle` handles in the WSL2 runtime.
    fn show_vmm_handles(&mut self, handle: ShareableHandle) {
        let subject = Subject::Runtime(runtime("wsl"));
        self.vmm_probe.respond(
            &subject,
            Observation::supported(
                configuration("580.1"),
                HOUR,
                SupportDetail::CudaIpcVmmShareableHandle { handle },
            ),
        );
        self.registry
            .refresh(Capability::CudaIpcVmmShareableHandle, &subject)
            .unwrap();
    }

    /// A host probe shows legacy CUDA IPC in the WSL2 runtime.
    fn show_legacy_ipc(&mut self) {
        let subject = Subject::Runtime(runtime("wsl"));
        self.legacy_probe.respond(
            &subject,
            Observation::supported(configuration("580.1"), HOUR, SupportDetail::CudaIpcLegacy),
        );
        self.registry
            .refresh(Capability::CudaIpcLegacy, &subject)
            .unwrap();
    }

    /// The CORE-01 gate's plan for `process`'s runtime under a profile that permits
    /// exactly `permitted`, asked for `requested`.
    fn gate(
        &self,
        process: ProcessId,
        permitted: &[Optimization],
        requested: &[Optimization],
    ) -> LoaderPlan {
        let context = self.model.process_context(process).unwrap();
        let profile = RuntimeProfile {
            runtime: context.runtime.clone(),
            configuration: context.configuration,
            permitted: permitted
                .iter()
                .map(|optimization| {
                    (
                        *optimization,
                        EvidencePolicy {
                            minimum_source: SourceClass::HostProbe,
                            max_age: MINUTE,
                        },
                    )
                })
                .collect(),
        };
        let request = LoaderRequest {
            optimizations: requested
                .iter()
                .map(|optimization| (*optimization, Necessity::Optional))
                .collect(),
        };
        LoaderGate::recorded()
            .plan(&profile, &request, &self.registry)
            .unwrap()
    }

    /// Installs a plan whose profile permits, and whose load asks for, `optimizations`.
    fn permit(&mut self, process: ProcessId, optimizations: &[Optimization]) {
        let plan = self.gate(process, optimizations, optimizations);
        self.model.set_loader_plan(process, plan).unwrap();
    }

    fn advance(&mut self, by: Duration) {
        self.clock.advance(by);
    }

    /// The CUDA function names of the accepted calls of `process`, in order.
    fn calls_of(&self, process: ProcessId) -> Vec<&'static str> {
        self.driver
            .calls()
            .iter()
            .filter(|call| call.process == process)
            .map(|call| call.call.api_name())
            .collect()
    }

    fn count_calls(&self, name: &str) -> usize {
        self.driver
            .calls()
            .iter()
            .filter(|call| call.call.api_name() == name)
            .count()
    }

    /// The model never asked the fake for a call outside Appendix E's order.
    fn assert_no_refusals(&self) {
        assert!(
            self.driver.refusals().is_empty(),
            "{:?}",
            self.driver.refusals()
        );
    }
}
