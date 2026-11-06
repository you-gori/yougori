//! Test doubles (tests only): a seeded generator, fixture identities and offerings, a
//! scripted provider, a vendor verifier that signs fixtures with HMAC, a clock that can
//! go backwards, and a host with a real CORE-04 coordinator whose parent execution holds
//! authority. Nothing here touches a network, a provider or the host.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use super::adapter::{
    AdapterConfig, AttemptId, BillingReport, LookupOutcome, ProviderInstance, ProvisionOutcome,
    ProvisionRequest, RemoteProviderPort, TerminationOutcome,
};
use super::attestation::{
    report_data, AttestationChallenge, AttestationPolicy, AttestationReport, ChainRejection,
    CoverageTarget, GpuReport, GpuReportBody, MeasuredImage, NonceSource, Portion, ReportBody,
    ReportOrigin, TcbComponent, TcbStatus, TeePlatform, VendorVerdict, VendorVerifier, VolumeName,
};
use super::control::{ControlKey, ControlSessionId, RemoteIdentity};
use super::lease::CoordinatorDelegation;
use super::offering::{
    CredentialPlacement, OfferingKind, OfferingName, OfferingPrice, OfferingShape, RegionName,
    RemoteOffering, RemoteRequest,
};
use super::ssh::{
    EnrollmentGeneration, EnrollmentPolicy, HostKey, HostKeyAlgorithm, RemoteHostId, RemoteVmId,
    TrustAssumption,
};
use crate::foundation::coordination::{
    BootRequest, CapacityPort, CapacityRefusal, CoordinationError, Coordinator,
    ExecutionCancellation, LabelledAuthorization, LaunchOutcome, LaunchPlan, LeaseTerms,
    ObservedVm, PerimeterId, PortFailure, PortOperation, Readiness, ReadinessReport,
    ReconcileReport, ReleaseOutcome, ReservationKey, ReservationPriority, ReservationRequest,
    ReserveOutcome, ResourceKind, RestoredVmReport, ReturnHold, SandboxPort, SettingsGrant,
    SnapshotManifest, VmInstanceId,
};
use crate::foundation::evidence::fakes::FakeProbe;
use crate::foundation::evidence::{
    AdmittedRuntime, AuthorityGrant, Backend, BackendRelease, Capability, ClockSession,
    ConfigurationFingerprint, Observation, ProbeRegistry, ProviderKind, RuntimeOffer,
    RuntimeRequirement, RuntimeSubject, SourceClass, Subject, SupportDetail,
};
use crate::foundation::ids::{
    digest, Clock, Digest, ExecutionCategory, ExecutionId, ManualClock, MonotonicTime,
    SandboxBootGeneration, TenantId,
};
use crate::foundation::transfer::{hmac_sha256, tags_equal, CredentialRef};
use crate::sandbox_contract::effects::{
    AccountRef, CostCeiling, Deadline, Destination, EffectDescription, EffectFields, Idempotency,
    IdempotencyKey, IdempotencyRequirement, IssuerId, OperationKey, OperationName, Parameters,
    ProviderId, ResourceRef, RouteRef, SandboxRef, TrustClass,
};
use crate::sandbox_contract::files::ClockSkewPolicy;

pub const SECOND: Duration = Duration::from_secs(1);
pub const MINUTE: Duration = Duration::from_secs(60);
pub const HOUR: Duration = Duration::from_secs(3_600);

pub fn at(seconds: u64) -> MonotonicTime {
    MonotonicTime::from_nanos(seconds * 1_000_000_000)
}

pub fn session(number: u128) -> ClockSession {
    ClockSession::from_uuid(uuid::Uuid::from_u128(number))
}

/// SplitMix64: a small seeded generator, so randomized tests replay exactly.
#[derive(Clone, Debug)]
pub struct SeededRng {
    state: u64,
}

impl SeededRng {
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    /// A value below `bound`; 0 when `bound` is 0.
    pub fn below(&mut self, bound: u64) -> u64 {
        if bound == 0 {
            0
        } else {
            self.next_u64() % bound
        }
    }
}

/// Nonces from a [`SeededRng`].
pub struct SeededNonces(pub SeededRng);

impl NonceSource for SeededNonces {
    fn next_nonce(&mut self) -> [u8; 32] {
        let mut nonce = [0u8; 32];
        for chunk in nonce.chunks_mut(8) {
            chunk.copy_from_slice(&self.0.next_u64().to_be_bytes());
        }
        nonce
    }
}

/// A broken nonce source that always repeats itself.
pub struct RepeatingNonces;

impl NonceSource for RepeatingNonces {
    fn next_nonce(&mut self) -> [u8; 32] {
        [7; 32]
    }
}

pub fn host_id(number: u8) -> RemoteHostId {
    RemoteHostId::of(
        ProviderKind::Crusoe,
        &RegionName::new("us-east-1").unwrap(),
        &digest("yougori/test/instance/v1", &[&[number]]),
    )
}

pub fn host_key(number: u8) -> HostKey {
    HostKey::new(HostKeyAlgorithm::Ed25519, vec![number; 32]).unwrap()
}

pub fn vm_id(number: u8) -> RemoteVmId {
    RemoteVmId::new(digest("yougori/test/remote-vm/v1", &[&[number]]))
}

pub fn mgmt_key() -> CredentialRef {
    CredentialRef::from_digest(digest("yougori/test/ssh-client-key/v1", &[b"mgmt"]))
}

pub fn control_key(number: u8) -> ControlKey {
    ControlKey::new(vec![number; 32]).unwrap()
}

pub fn session_id(number: u8) -> ControlSessionId {
    ControlSessionId::new(digest("yougori/test/control-session/v1", &[&[number]]))
}

pub fn session_key(number: u8) -> Digest {
    digest("yougori/test/session-key/v1", &[&[number]])
}

/// The identity of host 1 under enrollment generation `generation`.
pub fn identity(generation: u64) -> RemoteIdentity {
    RemoteIdentity {
        host: host_id(1),
        fingerprint: host_key(1).fingerprint(),
        enrollment: EnrollmentGeneration::new(generation),
        assumptions: BTreeSet::from([TrustAssumption::ProviderReportedKey]),
    }
}

pub fn account() -> AccountRef {
    AccountRef::new(digest("yougori/test/account/v1", &[b"crusoe-org"]))
}

fn offering(provider: ProviderKind, name: &str, kind: OfferingKind) -> RemoteOffering {
    RemoteOffering {
        provider,
        region: RegionName::new("us-east-1").unwrap(),
        offering: OfferingName::new(name).unwrap(),
        kind,
        account: account(),
        price: Some(OfferingPrice {
            per_hour_microunits: 2_000_000,
            billing_increment_seconds: 60,
            minimum_billed_seconds: 600,
        }),
        shape: OfferingShape {
            vcpus: 8,
            memory_bytes: 32 << 30,
            gpus: 1,
        },
    }
}

pub fn dedicated_offering() -> RemoteOffering {
    offering(ProviderKind::Crusoe, "l40s-1x", OfferingKind::DedicatedVm)
}

pub fn metal_offering() -> RemoteOffering {
    offering(ProviderKind::Latitude, "metal-gpu", OfferingKind::BareMetal)
}

pub fn container_offering() -> RemoteOffering {
    offering(
        ProviderKind::RunPod,
        "pod-a40",
        OfferingKind::ProviderContainer,
    )
}

pub fn vm_request() -> RemoteRequest {
    RemoteRequest {
        requirement: RuntimeRequirement::VmSandbox,
        credentials: CredentialPlacement::Home,
        gpus: 1,
    }
}

pub fn explicit_container() -> RemoteRequest {
    RemoteRequest {
        requirement: RuntimeRequirement::explicit([ExecutionCategory::ProviderContainerRuntime])
            .unwrap(),
        credentials: CredentialPlacement::Home,
        gpus: 1,
    }
}

pub fn attempt(number: u8) -> AttemptId {
    AttemptId::new(digest("yougori/test/attempt/v1", &[&[number]]))
}

/// Ten-minute grants within a two-hour lifetime; skew allowance 30 s.
pub fn config() -> AdapterConfig {
    AdapterConfig {
        terms: LeaseTerms {
            term: 10 * MINUTE,
            max_lifetime: 2 * HOUR,
            cancel_within: 30 * SECOND,
        },
        max_control_silence: MINUTE,
        skew: ClockSkewPolicy {
            max_skew_seconds: 30,
            max_remote_lifetime_seconds: 3_600,
        },
        termination_allowance_seconds: 600,
        escalate_after_attempts: 3,
        enrollment: EnrollmentPolicy::default(),
        confidential: None,
    }
}

/// The provisioning effect: create one instance on `account`, with a spend ceiling.
pub fn provision_effect(
    account: AccountRef,
    max_spend_microunits: u64,
    key: u8,
) -> EffectDescription {
    EffectDescription::new(EffectFields {
        principal: TenantId::new("tenant-a").unwrap(),
        sandbox: SandboxRef {
            issuer: IssuerId::new(digest("yougori/test/issuer/v1", &[b"home"])),
            execution: parent(),
        },
        operation: OperationKey {
            provider: ProviderId::new("crusoe").unwrap(),
            operation: OperationName::new("create_instance").unwrap(),
            contract_version: 1,
        },
        resource: ResourceRef {
            account,
            object: digest("yougori/test/object/v1", &[b"instance", &[key]]),
        },
        destination: Destination {
            route: RouteRef::new(digest("yougori/test/route/v1", &[b"crusoe-api"])),
            trust: TrustClass::RegisteredProvider,
        },
        parameters: Parameters::new(),
        payload: None,
        attachments: BTreeMap::new(),
        preconditions: BTreeSet::new(),
        max_cost: CostCeiling {
            max_spend_microunits,
            max_volume_units: 1,
        },
        max_wire_bytes_out: 4_096,
        deadline: Deadline {
            clock: session(1),
            at: at(3_600),
        },
        idempotency: Idempotency {
            key: IdempotencyKey::new(digest("yougori/test/idempotency/v1", &[&[key]])),
            requirement: IdempotencyRequirement::ProviderKey,
        },
    })
    .unwrap()
}

/// One call the fake provider received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProviderCall {
    Provision(ProvisionRequest),
    Terminate(ProviderInstance),
    Find(AttemptId),
    Bill(AttemptId),
}

/// A provider that answers from scripts, falling back to success, and records calls.
#[derive(Debug, Default)]
pub struct FakeProvider {
    pub provisions: VecDeque<ProvisionOutcome>,
    pub terminations: VecDeque<TerminationOutcome>,
    pub lookups: VecDeque<LookupOutcome>,
    pub bills: VecDeque<BillingReport>,
    pub default_cost_microunits: u64,
    pub calls: Vec<ProviderCall>,
}

impl FakeProvider {
    /// The instance a successful provisioning of `request` creates.
    pub fn instance_for(request: &ProvisionRequest) -> ProviderInstance {
        ProviderInstance {
            provider: request.provider,
            region: request.region.clone(),
            offering: request.offering.clone(),
            kind: request.kind,
            instance: digest(
                "yougori/test/provider-instance/v1",
                &[request.attempt.digest().as_bytes()],
            ),
        }
    }

    pub fn provision_calls(&self) -> usize {
        self.calls
            .iter()
            .filter(|call| matches!(call, ProviderCall::Provision(_)))
            .count()
    }

    pub fn terminate_calls(&self) -> usize {
        self.calls
            .iter()
            .filter(|call| matches!(call, ProviderCall::Terminate(_)))
            .count()
    }
}

impl RemoteProviderPort for FakeProvider {
    fn provision(&mut self, request: &ProvisionRequest) -> ProvisionOutcome {
        self.calls.push(ProviderCall::Provision(request.clone()));
        self.provisions
            .pop_front()
            .unwrap_or_else(|| ProvisionOutcome::Created {
                instance: Self::instance_for(request),
            })
    }

    fn terminate(&mut self, instance: &ProviderInstance) -> TerminationOutcome {
        self.calls.push(ProviderCall::Terminate(instance.clone()));
        self.terminations
            .pop_front()
            .unwrap_or(TerminationOutcome::Confirmed)
    }

    fn find(&mut self, request: &ProvisionRequest) -> LookupOutcome {
        self.calls.push(ProviderCall::Find(request.attempt));
        self.lookups
            .pop_front()
            .unwrap_or(LookupOutcome::ConfirmedAbsent)
    }

    fn final_bill(&mut self, attempt: &AttemptId) -> BillingReport {
        self.calls.push(ProviderCall::Bill(*attempt));
        self.bills.pop_front().unwrap_or(BillingReport::Final {
            cost_microunits: self.default_cost_microunits,
        })
    }
}

/// The fake vendor root's key; fixtures are "signed" with HMAC under it.
pub const ROOT_KEY: &[u8] = b"fake vendor root key, 32 bytes!!";

pub fn vendor_root() -> Digest {
    digest("yougori/test/vendor-root/v1", &[b"root"])
}

pub fn sign(body: &Digest) -> Vec<u8> {
    hmac_sha256(ROOT_KEY, body.as_bytes()).to_vec()
}

/// A vendor verifier over HMAC-signed fixtures, with per-chip TCB status.
#[derive(Clone, Debug)]
pub struct FakeVendor {
    pub roots: BTreeMap<Digest, Vec<u8>>,
    pub tcb: BTreeMap<Digest, TcbStatus>,
    pub available: bool,
}

impl FakeVendor {
    pub fn new() -> Self {
        Self {
            roots: BTreeMap::from([(vendor_root(), ROOT_KEY.to_vec())]),
            tcb: BTreeMap::new(),
            available: true,
        }
    }

    fn verify(
        &self,
        chain: &[Digest],
        signature: &[u8],
        body: &Digest,
        chip: &Digest,
    ) -> VendorVerdict {
        if !self.available {
            return VendorVerdict::Unavailable;
        }
        let Some(root) = chain.last() else {
            return VendorVerdict::Rejected {
                reason: ChainRejection::EmptyChain,
            };
        };
        let Some(key) = self.roots.get(root) else {
            return VendorVerdict::Rejected {
                reason: ChainRejection::UnknownRoot,
            };
        };
        let expected = hmac_sha256(key, body.as_bytes());
        let Ok(presented) = <[u8; 32]>::try_from(signature) else {
            return VendorVerdict::Rejected {
                reason: ChainRejection::BadSignature,
            };
        };
        if !tags_equal(&expected, &presented) {
            return VendorVerdict::Rejected {
                reason: ChainRejection::BadSignature,
            };
        }
        VendorVerdict::Verified {
            tcb: self.tcb.get(chip).copied().unwrap_or(TcbStatus::UpToDate),
        }
    }
}

impl VendorVerifier for FakeVendor {
    fn verify_cpu(&self, report: &AttestationReport) -> VendorVerdict {
        self.verify(
            &report.chain,
            &report.signature,
            &report.body.digest(),
            &report.body.chip,
        )
    }

    fn verify_gpu(&self, report: &GpuReport) -> VendorVerdict {
        self.verify(
            &report.chain,
            &report.signature,
            &report.body.digest(),
            &report.body.chip,
        )
    }
}

pub fn measurement() -> Digest {
    digest("yougori/test/measurement/v1", &[b"reviewed-image"])
}

pub fn gpu_measurement() -> Digest {
    digest("yougori/test/gpu-measurement/v1", &[b"h100-cc"])
}

pub fn chip() -> Digest {
    digest("yougori/test/chip/v1", &[b"chip-1"])
}

pub fn workload() -> Digest {
    digest("yougori/test/workload/v1", &[b"model-server"])
}

pub fn volume(name: &str) -> VolumeName {
    VolumeName::new(name).unwrap()
}

pub fn component(name: &str) -> TcbComponent {
    TcbComponent::new(name).unwrap()
}

pub const GIB: u64 = 1 << 30;
pub const MIB: u64 = 1 << 20;

/// 8 vCPUs, 32 GiB, volumes `root` and `data`, GPU 0.
pub fn target() -> CoverageTarget {
    CoverageTarget {
        vcpus: 8,
        memory_bytes: 32 * GIB,
        volumes: BTreeSet::from([volume("root"), volume("data")]),
        gpus: BTreeSet::from([0]),
    }
}

/// SEV-SNP, the reviewed image encrypting `root` and `data`, SNP ≥ 8 and microcode
/// ≥ 200, reports within 60 s, 64 MiB shared at most, CPU and memory required.
pub fn policy() -> AttestationPolicy {
    AttestationPolicy {
        platform: TeePlatform::AmdSevSnp,
        measurements: BTreeMap::from([(
            measurement(),
            MeasuredImage {
                encrypted_volumes: BTreeSet::from([volume("root"), volume("data")]),
            },
        )]),
        min_security_versions: BTreeMap::from([
            (component("snp"), 8),
            (component("microcode"), 200),
        ]),
        max_report_age_seconds: 60,
        allow_out_of_date_tcb: false,
        gpu_measurements: BTreeSet::from([gpu_measurement()]),
        max_shared_memory_bytes: 64 * MIB,
        required: BTreeSet::from([Portion::Cpu, Portion::Memory]),
    }
}

/// A report that answers `challenge` correctly, signed by the fake vendor root.
pub fn valid_report(challenge: &AttestationChallenge) -> AttestationReport {
    let body = ReportBody {
        platform: TeePlatform::AmdSevSnp,
        origin: ReportOrigin::HardwareSigned,
        report_data: report_data(
            &challenge.nonce,
            &challenge.session_key,
            &challenge.workload,
        ),
        bound_nonce: challenge.nonce,
        bound_session_key: challenge.session_key,
        bound_workload: challenge.workload,
        measurement: measurement(),
        security_versions: BTreeMap::from([(component("snp"), 9), (component("microcode"), 210)]),
        debug_enabled: false,
        chip: chip(),
        protected_vcpus: challenge.target.vcpus,
        private_memory_bytes: challenge.target.memory_bytes - 64 * MIB,
        shared_memory_bytes: 64 * MIB,
    };
    let signature = sign(&body.digest());
    AttestationReport {
        body,
        chain: vec![digest("yougori/test/vcek/v1", &[b"leaf"]), vendor_root()],
        signature,
        gpus: Vec::new(),
    }
}

/// A GPU report for `device` that answers `challenge` correctly.
pub fn valid_gpu_report(challenge: &AttestationChallenge, device: u32) -> GpuReport {
    let body = GpuReportBody {
        device,
        bound_nonce: challenge.nonce,
        bound_session_key: challenge.session_key,
        confidential_mode: true,
        debug_enabled: false,
        measurement: gpu_measurement(),
        chip: digest("yougori/test/gpu-chip/v1", &[&device.to_be_bytes()]),
    };
    let signature = sign(&body.digest());
    GpuReport {
        body,
        chain: vec![vendor_root()],
        signature,
    }
}

/// Signs `report` again after a test changed its body.
pub fn resign(report: &mut AttestationReport) {
    report.signature = sign(&report.body.digest());
}

pub fn resign_gpu(report: &mut GpuReport) {
    report.signature = sign(&report.body.digest());
}

/// A clock a test can set backwards, to model a misbehaving time source.
#[derive(Debug, Default)]
pub struct RewindableClock {
    nanos: AtomicU64,
}

impl RewindableClock {
    pub fn new(start: MonotonicTime) -> Self {
        Self {
            nanos: AtomicU64::new(start.as_nanos()),
        }
    }

    pub fn set(&self, to: MonotonicTime) {
        self.nanos.store(to.as_nanos(), Ordering::SeqCst);
    }
}

impl Clock for RewindableClock {
    fn now(&self) -> MonotonicTime {
        MonotonicTime::from_nanos(self.nanos.load(Ordering::SeqCst))
    }
}

/// A capacity port that grants every reservation.
#[derive(Debug, Default)]
pub struct GrantAll;

impl CapacityPort for GrantAll {
    fn reserve(
        &mut self,
        _request: &ReservationRequest,
    ) -> Result<ReserveOutcome, CapacityRefusal> {
        Ok(ReserveOutcome::Granted)
    }

    fn begin_create(&mut self, _key: &ReservationKey) -> Result<(), CapacityRefusal> {
        Ok(())
    }

    fn release(&mut self, _key: &ReservationKey) -> Result<ReleaseOutcome, CapacityRefusal> {
        Ok(ReleaseOutcome::Pending)
    }

    fn confirm_release(
        &mut self,
        _key: &ReservationKey,
        _source: SourceClass,
    ) -> Result<ReleaseOutcome, CapacityRefusal> {
        Ok(ReleaseOutcome::Released)
    }

    fn cancel_execution(
        &mut self,
        _execution: &ExecutionId,
    ) -> Result<ExecutionCancellation, CapacityRefusal> {
        Ok(ExecutionCancellation::default())
    }

    fn reconcile(
        &mut self,
        _execution: &ExecutionId,
        expected: &BTreeSet<ReservationKey>,
    ) -> Result<ReconcileReport, CapacityRefusal> {
        Ok(ReconcileReport {
            confirmed: expected.clone(),
            ..ReconcileReport::default()
        })
    }

    fn begin_hold(
        &mut self,
        _resources: &BTreeSet<ResourceKind>,
    ) -> Result<ReturnHold, CapacityRefusal> {
        Ok(ReturnHold::new(1))
    }

    fn end_hold(&mut self, _hold: ReturnHold) -> Result<(), CapacityRefusal> {
        Ok(())
    }
}

/// A local VM backend for the parent execution: fresh VMs, ready to a host probe.
#[derive(Debug, Default)]
pub struct QuietBackend {
    running: Vec<ObservedVm>,
}

impl SandboxPort for QuietBackend {
    fn prepare_perimeter(&mut self, request: &BootRequest) -> Result<PerimeterId, PortFailure> {
        Ok(PerimeterId::new(digest(
            "yougori/test/perimeter/v1",
            &[request.execution.as_str().as_bytes()],
        )))
    }

    fn create_vm(
        &mut self,
        request: &BootRequest,
        _perimeter: &PerimeterId,
    ) -> Result<VmInstanceId, PortFailure> {
        let vm = VmInstanceId::new(digest(
            "yougori/test/vm/v1",
            &[
                request.execution.as_str().as_bytes(),
                &request.generations.boot.get().to_be_bytes(),
            ],
        ));
        self.running.push(ObservedVm {
            vm,
            execution: request.execution.clone(),
            boot: request.generations.boot,
        });
        Ok(vm)
    }

    fn restore_vm(
        &mut self,
        _request: &BootRequest,
        _perimeter: &PerimeterId,
        _snapshot: &SnapshotManifest,
    ) -> Result<VmInstanceId, PortFailure> {
        Err(PortFailure {
            operation: PortOperation::RestoreVm,
            detail: "no snapshots in these tests".into(),
        })
    }

    fn observe_readiness(
        &mut self,
        _vm: &VmInstanceId,
        _boot: SandboxBootGeneration,
    ) -> ReadinessReport {
        ReadinessReport {
            source: SourceClass::HostProbe,
            readiness: Readiness::Ready,
        }
    }

    fn inspect_restored_vm(
        &mut self,
        _vm: &VmInstanceId,
        _boot: SandboxBootGeneration,
    ) -> RestoredVmReport {
        unreachable!("these tests never restore a VM")
    }

    fn terminate_vm(&mut self, vm: &VmInstanceId) -> Result<(), PortFailure> {
        self.running.retain(|observed| observed.vm != *vm);
        Ok(())
    }

    fn teardown_perimeter(&mut self, _perimeter: &PerimeterId) -> Result<(), PortFailure> {
        Ok(())
    }

    fn list_vms(&mut self) -> Result<Vec<ObservedVm>, PortFailure> {
        Ok(self.running.clone())
    }
}

pub fn parent() -> ExecutionId {
    ExecutionId::new("exe-parent").unwrap()
}

/// The execution a remote provider container's labelled-runtime record is kept under.
pub fn pod_execution() -> ExecutionId {
    ExecutionId::new("exe-pod").unwrap()
}

fn configuration() -> ConfigurationFingerprint {
    ConfigurationFingerprint::from_digest(digest("yougori/test/configuration/v1", &[b"remote"]))
}

pub type HostCoordinator<K> = Coordinator<K, GrantAll>;

/// The home host: a real CORE-04 coordinator on clock `K` whose parent execution holds
/// authority, and a CORE-01 registry with a provider-API probe for remote runtimes.
pub struct HostWorld<K: Clock + Clone> {
    pub clock: K,
    pub coordinator: Arc<Mutex<HostCoordinator<K>>>,
    remote_registry: ProbeRegistry<K>,
    remote_probe: Arc<FakeProbe>,
}

impl HostWorld<Arc<ManualClock>> {
    /// A host on a manual clock whose parent execution runs with authority for
    /// `authority_lifetime`.
    pub fn new(authority_lifetime: Duration) -> Self {
        Self::on(Arc::new(ManualClock::new(at(1_000))), authority_lifetime)
    }

    pub fn advance(&self, by: Duration) {
        self.clock.advance(by);
    }
}

impl<K: Clock + Clone> HostWorld<K> {
    pub fn on(clock: K, authority_lifetime: Duration) -> Self {
        let mut registry = ProbeRegistry::new(clock.clone());
        let category = Arc::new(FakeProbe::runtime_category(SourceClass::HostProbe));
        registry.register(Box::new(Arc::clone(&category))).unwrap();
        let mut coordinator = Coordinator::new(clock.clone(), registry.session(), GrantAll);
        let runtime = RuntimeSubject {
            category: ExecutionCategory::VmSandbox,
            release: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
            instance: digest("yougori/test/instance/v1", &[b"home-vm"]),
        };
        let subject = Subject::Runtime(runtime.clone());
        category.respond(
            &subject,
            Observation::supported(
                configuration(),
                HOUR,
                SupportDetail::RuntimeCategory {
                    category: ExecutionCategory::VmSandbox,
                },
            ),
        );
        registry
            .refresh(Capability::RuntimeCategory, &subject)
            .unwrap();
        let offer = RuntimeOffer::observe(&registry, runtime, HOUR, configuration()).unwrap();
        let plan = LaunchPlan {
            execution: parent(),
            tenant: TenantId::new("tenant-a").unwrap(),
            runtime: RuntimeRequirement::VmSandbox.admit(&offer).unwrap(),
            demand: BTreeMap::from([(ResourceKind::HostMemoryBytes, 1 << 30)]),
            priority: ReservationPriority::Background,
            authority_lifetime,
            readiness_max_age: 5 * SECOND,
            runtime_evidence_max_age: HOUR,
        };
        let mut port = QuietBackend::default();
        let outcome = coordinator
            .launch_with(plan, SettingsGrant::default(), &mut port, &registry)
            .unwrap();
        assert!(
            matches!(outcome, LaunchOutcome::AuthorityActive { .. }),
            "{outcome:?}"
        );
        coordinator.start_running(&parent()).unwrap();
        let mut remote_registry = ProbeRegistry::new(clock.clone());
        let remote_probe = Arc::new(FakeProbe::runtime_category(SourceClass::ProviderApi));
        remote_registry
            .register(Box::new(Arc::clone(&remote_probe)))
            .unwrap();
        Self {
            clock,
            coordinator: Arc::new(Mutex::new(coordinator)),
            remote_registry,
            remote_probe,
        }
    }

    pub fn delegation(&self) -> CoordinatorDelegation<K, GrantAll> {
        CoordinatorDelegation::new(Arc::clone(&self.coordinator))
    }

    pub fn now(&self) -> MonotonicTime {
        self.clock.now()
    }

    pub fn session(&self) -> ClockSession {
        self.coordinator
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .session()
    }

    pub fn revoke_parent(&self) {
        self.coordinator
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .revoke(&parent())
            .unwrap();
    }

    /// Grants the labelled runtime `execution` authority for `admitted` through the
    /// coordinator, rechecking its evidence on the provider-API registry (VM-D5).
    pub fn authorize_labelled(
        &self,
        execution: ExecutionId,
        admitted: AdmittedRuntime,
        authority_lifetime: Duration,
    ) -> Result<AuthorityGrant, CoordinationError> {
        self.coordinator
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .authorize_labelled(
                LabelledAuthorization {
                    execution,
                    tenant: TenantId::new("tenant-a").unwrap(),
                    runtime: admitted,
                    authority_lifetime,
                    runtime_evidence_max_age: HOUR,
                    settings: SettingsGrant::default(),
                },
                &self.remote_registry,
            )
    }

    pub fn revoke_labelled(&self, execution: &ExecutionId) {
        self.coordinator
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .revoke_labelled(execution)
            .unwrap();
    }

    /// CORE-01 provider-API evidence that `instance` runs as `category`.
    pub fn remote_offer(&mut self, instance: Digest, category: ExecutionCategory) -> RuntimeOffer {
        let runtime = RuntimeSubject {
            category,
            release: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
            instance,
        };
        let subject = Subject::Runtime(runtime.clone());
        self.remote_probe.respond(
            &subject,
            Observation::supported(
                configuration(),
                HOUR,
                SupportDetail::RuntimeCategory { category },
            ),
        );
        self.remote_registry
            .refresh(Capability::RuntimeCategory, &subject)
            .unwrap();
        RuntimeOffer::observe(&self.remote_registry, runtime, HOUR, configuration()).unwrap()
    }
}
