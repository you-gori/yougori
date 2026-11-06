//! Test doubles (tests only): an in-memory duplex for the stream port, a verifier that
//! knows a table of tokens, a launched CORE-04 coordinator on a shared manual clock, an
//! authority whose clock can be told to read earlier, and builders. Nothing here touches
//! the host. A test launch grants a service the grant the gate derives for it
//! ([`published_grant`]).

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::*;
use crate::foundation::coordination::{
    network_grant_id, BootRequest, CapacityPort, CapacityRefusal, CompositeRecovery, Coordinator,
    ExecutionCancellation, LaunchOutcome, LaunchPlan, ObservedVm, PerimeterId, PortFailure,
    PortOperation, Readiness, ReadinessReport, ReconcileReport, RecoveryContext, RelaunchPlan,
    ReleaseOutcome, ReservationKey, ReservationPriority, ReservationRequest, ReserveOutcome,
    ResourceKind, RestoredVmReport, ReturnHold, RevocationStatus, SandboxPort, SettingsGrant,
    SnapshotManifest, VmInstanceId,
};
use crate::foundation::evidence::fakes::FakeProbe;
use crate::foundation::evidence::{
    ArtifactVerification, Backend, BackendRelease, Capability, ClockSession,
    ConfigurationFingerprint, NetworkGrant, Observation, ProbeRegistry, RuntimeOffer,
    RuntimeRequirement, RuntimeSubject, SourceClass, Subject, SupportDetail,
};
use crate::foundation::ids::{
    digest, AuthorizationEpoch, Clock, ExecutionCategory, ExecutionId, GrantId, ManualClock,
    MonotonicTime, PolicyEpoch, SandboxBootGeneration, TenantId, TrustScope,
};
use crate::foundation::transfer::GeneralReleaseBudget;
use crate::sandbox_contract::destinations::{
    Audience, AuthenticationMode, ChannelPolicy, ConnectionGrant, DestinationPort,
    InFlightAllowance, NetworkMode, PrincipalId, PublicationRequest, ReleaseAccount,
    ReleaseChannel, ReleaseTrustClass, SandboxEndpoint, ServiceIdentity,
};

pub const SECOND: Duration = Duration::from_secs(1);
pub const HOUR: Duration = Duration::from_secs(3_600);

// ---------------------------------------------------------------------------------------
// The stream port in memory

#[derive(Debug, Default)]
struct Pipes {
    /// Bytes written by the first end, for the second.
    first_to_second: VecDeque<u8>,
    second_to_first: VecDeque<u8>,
    first_closed: bool,
    second_closed: bool,
    /// An end that finished writes no more; its peer reads to the end of what it wrote.
    first_finished: bool,
    second_finished: bool,
}

/// One end of an in-memory duplex.
#[derive(Clone, Debug)]
pub struct MemoryStream {
    pipes: Arc<Mutex<Pipes>>,
    first: bool,
}

/// Two connected ends: what one writes, the other reads.
pub fn duplex() -> (MemoryStream, MemoryStream) {
    let pipes = Arc::new(Mutex::new(Pipes::default()));
    (
        MemoryStream {
            pipes: Arc::clone(&pipes),
            first: true,
        },
        MemoryStream {
            pipes,
            first: false,
        },
    )
}

impl MemoryStream {
    /// Everything readable now, and whether the peer has closed.
    pub fn drain(&mut self) -> (Vec<u8>, bool) {
        let mut out = Vec::new();
        let mut buffer = [0u8; 64];
        loop {
            match self.read(&mut buffer).unwrap() {
                StreamRead::Bytes(read) => out.extend_from_slice(&buffer[..read]),
                StreamRead::Idle => return (out, false),
                StreamRead::Ended => return (out, true),
            }
        }
    }

    /// Whether the other end was closed.
    pub fn peer_closed(&self) -> bool {
        let pipes = self.pipes.lock().unwrap();
        if self.first {
            pipes.second_closed
        } else {
            pipes.first_closed
        }
    }

    /// Bytes this end wrote that the other has not read.
    pub fn unread_by_peer(&self) -> usize {
        let pipes = self.pipes.lock().unwrap();
        if self.first {
            pipes.first_to_second.len()
        } else {
            pipes.second_to_first.len()
        }
    }
}

impl SessionStream for MemoryStream {
    fn read(&mut self, buffer: &mut [u8]) -> Result<StreamRead, StreamError> {
        let mut pipes = self.pipes.lock().unwrap();
        let peer_finished = if self.first {
            pipes.second_finished
        } else {
            pipes.first_finished
        };
        let closed = pipes.first_closed || pipes.second_closed || peer_finished;
        let incoming = if self.first {
            &mut pipes.second_to_first
        } else {
            &mut pipes.first_to_second
        };
        if incoming.is_empty() || buffer.is_empty() {
            return Ok(if closed {
                StreamRead::Ended
            } else {
                StreamRead::Idle
            });
        }
        let read = incoming.len().min(buffer.len());
        for (slot, byte) in buffer.iter_mut().zip(incoming.drain(..read)) {
            *slot = byte;
        }
        Ok(StreamRead::Bytes(read))
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), StreamError> {
        let mut pipes = self.pipes.lock().unwrap();
        let finished = if self.first {
            pipes.first_finished
        } else {
            pipes.second_finished
        };
        if pipes.first_closed || pipes.second_closed || finished {
            return Err(StreamError::Closed);
        }
        let outgoing = if self.first {
            &mut pipes.first_to_second
        } else {
            &mut pipes.second_to_first
        };
        outgoing.extend(bytes.iter().copied());
        Ok(())
    }

    fn finish(&mut self) {
        let mut pipes = self.pipes.lock().unwrap();
        if self.first {
            pipes.first_finished = true;
        } else {
            pipes.second_finished = true;
        }
    }

    fn close(&mut self) {
        let mut pipes = self.pipes.lock().unwrap();
        if self.first {
            pipes.first_closed = true;
        } else {
            pipes.second_closed = true;
        }
    }
}

/// The two ends a test keeps of a channel: the caller's and the guest's (or callee's).
pub struct Ends {
    pub caller: MemoryStream,
    pub guest: MemoryStream,
}

/// A channel's four ends: the test keeps `Ends`, the gate gets the two boxed ones.
pub fn channel() -> (Ends, Box<dyn SessionStream>, Box<dyn SessionStream>) {
    let (caller, outside) = duplex();
    let (guest, inside) = duplex();
    (Ends { caller, guest }, Box::new(outside), Box::new(inside))
}

// ---------------------------------------------------------------------------------------
// The verifier

/// Accepts the tokens it was told about, each for one principal, binding and mode, valid
/// until a set time.
#[derive(Debug, Default)]
pub struct FakeVerifier {
    tokens: BTreeMap<Vec<u8>, (PrincipalId, ProofBinding, AuthenticationMode, MonotonicTime)>,
    pub expired: BTreeSet<Vec<u8>>,
}

impl FakeVerifier {
    /// A token that holds for as long as the clock runs.
    pub fn issue(
        &mut self,
        token: &str,
        principal: &str,
        binding: ProofBinding,
        mode: AuthenticationMode,
    ) {
        self.issue_until(
            token,
            principal,
            binding,
            mode,
            MonotonicTime::from_nanos(u64::MAX),
        );
    }

    /// A token that holds until `valid_until`.
    pub fn issue_until(
        &mut self,
        token: &str,
        principal: &str,
        binding: ProofBinding,
        mode: AuthenticationMode,
        valid_until: MonotonicTime,
    ) {
        self.tokens.insert(
            token.as_bytes().to_vec(),
            (self::principal(principal), binding, mode, valid_until),
        );
    }
}

impl ProofVerifier for FakeVerifier {
    fn verify(
        &self,
        binding: &ProofBinding,
        proof: &AuthenticationProof,
        _now: MonotonicTime,
    ) -> Result<VerifiedProof, ProofRefusal> {
        if self.expired.contains(proof.material()) {
            return Err(ProofRefusal::Expired);
        }
        let (principal, issued_for, mode, valid_until) = self
            .tokens
            .get(proof.material())
            .ok_or(ProofRefusal::Invalid)?;
        if *mode != proof.mode() {
            return Err(ProofRefusal::Invalid);
        }
        if issued_for != binding {
            return Err(ProofRefusal::WrongPublication);
        }
        Ok(VerifiedProof {
            principal: principal.clone(),
            valid_until: *valid_until,
        })
    }
}

pub fn proof(mode: AuthenticationMode, token: &str) -> Option<AuthenticationProof> {
    Some(AuthenticationProof::new(mode, token.as_bytes()))
}

// ---------------------------------------------------------------------------------------
// Builders

pub fn execution(name: &str) -> ExecutionId {
    ExecutionId::new(name).unwrap()
}

pub fn service(name: &str) -> ServiceIdentity {
    ServiceIdentity::new(name).unwrap()
}

pub fn principal(name: &str) -> PrincipalId {
    PrincipalId::new(name).unwrap()
}

pub fn port(value: u16) -> DestinationPort {
    DestinationPort::new(value).unwrap()
}

pub fn scope(name: &str) -> TrustScope {
    TrustScope::named(ExecutionCategory::VmSandbox, name)
}

pub fn endpoint(sandbox: &str, scope_name: &str) -> SandboxEndpoint {
    SandboxEndpoint {
        execution: execution(sandbox),
        scope: scope(scope_name),
    }
}

/// Every service name the tests offer.
pub const KNOWN_SERVICES: [&str; 5] = ["web", "api", "admin", "preview", "model-api"];

/// CORE-04's published-service network grant of `name`, as the gate derives it.
pub fn published_grant(name: &str) -> NetworkGrant {
    published_service_grant(&service(name))
}

/// The identity CORE-04 gives [`published_grant`].
pub fn published_grant_id(name: &str) -> GrantId {
    published_service_grant_id(&service(name))
}

/// A registration offering every known service, for an authority that holds every
/// grant ([`SettableAuthority`]).
pub fn registration(sandbox: &str, scope_name: &str) -> SandboxRegistration {
    registration_of(sandbox, scope_name, &KNOWN_SERVICES)
}

/// A registration offering the services `services`; the sandbox's launch settings must
/// hold the grant derived for each.
pub fn registration_of(sandbox: &str, scope_name: &str, services: &[&str]) -> SandboxRegistration {
    SandboxRegistration {
        endpoint: endpoint(sandbox, scope_name),
        mode: NetworkMode::DeclaredTransport,
        max_publication_lifetime: HOUR,
        published_services: services.iter().map(|name| service(name)).collect(),
    }
}

pub fn public_request(name: &str, at: u16, expires_at: MonotonicTime) -> PublicationRequest {
    PublicationRequest {
        service: service(name),
        port: port(at),
        audience: Audience::Public,
        authentication: AuthenticationMode::None,
        expires_at,
    }
}

pub fn private_request(
    name: &str,
    at: u16,
    principals: &[&str],
    expires_at: MonotonicTime,
) -> PublicationRequest {
    PublicationRequest {
        service: service(name),
        port: port(at),
        audience: Audience::Private {
            principals: principals.iter().map(|name| principal(name)).collect(),
        },
        authentication: AuthenticationMode::PlatformSession,
        expires_at,
    }
}

pub fn inbound(
    sandbox: &str,
    name: &str,
    at: u16,
    proof: Option<AuthenticationProof>,
) -> InboundRequest {
    InboundRequest {
        sandbox: execution(sandbox),
        service: service(name),
        port: port(at),
        proof,
    }
}

pub fn connection_grant(
    caller: &SandboxEndpoint,
    callee: &SandboxEndpoint,
    name: &str,
    at: u16,
    expires_at: MonotonicTime,
) -> ConnectionGrant {
    ConnectionGrant {
        caller: caller.clone(),
        callee: callee.clone(),
        service: service(name),
        port: port(at),
        expires_at,
    }
}

/// A release account whose published-service response channel holds `response_bytes`.
pub fn release_account(response_bytes: u64) -> ReleaseAccount {
    ReleaseAccount::new(
        BTreeMap::from([(
            ReleaseChannel::PublishedServiceResponse,
            ChannelPolicy {
                budget_bytes: response_bytes,
                trust_class: ReleaseTrustClass::PublishedAudience,
            },
        )]),
        GeneralReleaseBudget::vm_d12_default(),
        InFlightAllowance {
            bytes: 0,
            documented_reason: "responses are charged exactly before they are sent".to_owned(),
        },
    )
    .unwrap()
}

/// One release account per named sandbox.
pub fn releases(sandboxes: &[(&str, u64)]) -> BTreeMap<ExecutionId, ReleaseAccount> {
    sandboxes
        .iter()
        .map(|(sandbox, bytes)| (execution(sandbox), release_account(*bytes)))
        .collect()
}

/// The bytes `sandbox` released on the published-service response channel.
pub fn released(releases: &BTreeMap<ExecutionId, ReleaseAccount>, sandbox: &str) -> u64 {
    releases[&execution(sandbox)].used_bytes(ReleaseChannel::PublishedServiceResponse)
}

pub fn closed(reason: CloseReason) -> ChannelState {
    ChannelState::Closed(reason)
}

// ---------------------------------------------------------------------------------------
// CORE-04 world

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

/// A sandbox backend that creates fresh VMs, reports them ready to a host probe and
/// records terminations.
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
        panic!("these tests never restore a VM")
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

fn configuration() -> ConfigurationFingerprint {
    ConfigurationFingerprint::from_digest(digest("yougori/test/configuration/v1", &[b"launch"]))
}

/// A coordinator on a shared manual clock with host evidence that one runtime is a VM
/// sandbox.
pub struct World {
    pub clock: Arc<ManualClock>,
    registry: ProbeRegistry<Arc<ManualClock>>,
    category: Arc<FakeProbe>,
    runtime: RuntimeSubject,
    pub port: QuietBackend,
    pub coordinator: Coordinator<Arc<ManualClock>, GrantAll>,
}

impl World {
    pub fn new() -> Self {
        let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(
            1_000 * 1_000_000_000,
        )));
        let mut registry = ProbeRegistry::new(Arc::clone(&clock));
        let category = Arc::new(FakeProbe::runtime_category(SourceClass::HostProbe));
        registry.register(Box::new(Arc::clone(&category))).unwrap();
        let coordinator = Coordinator::new(
            Arc::clone(&clock),
            ClockSession::from_uuid(uuid::Uuid::from_u128(2)),
            GrantAll,
        );
        Self {
            clock,
            registry,
            category,
            runtime: RuntimeSubject {
                category: ExecutionCategory::VmSandbox,
                release: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
                instance: digest("yougori/test/instance/v1", &[b"vm-host-1"]),
            },
            port: QuietBackend::default(),
            coordinator,
        }
    }

    /// The shared clock now.
    pub fn now(&self) -> MonotonicTime {
        self.clock.now()
    }

    /// `seconds` from now on the shared clock.
    pub fn in_seconds(&self, seconds: u64) -> MonotonicTime {
        self.now().saturating_add(Duration::from_secs(seconds))
    }

    pub fn advance(&self, seconds: u64) {
        self.clock.advance(Duration::from_secs(seconds));
    }

    /// Fresh host evidence that the runtime is a VM sandbox.
    fn observe_runtime(&mut self) -> RuntimeOffer {
        let subject = Subject::Runtime(self.runtime.clone());
        self.category.respond(
            &subject,
            Observation::supported(
                configuration(),
                HOUR,
                SupportDetail::RuntimeCategory {
                    category: ExecutionCategory::VmSandbox,
                },
            ),
        );
        self.registry
            .refresh(Capability::RuntimeCategory, &subject)
            .unwrap();
        RuntimeOffer::observe(&self.registry, self.runtime.clone(), HOUR, configuration()).unwrap()
    }

    /// Launches `of` to running, granted the published-service grants of `services`.
    pub fn launch(&mut self, of: &str, services: &[&str]) {
        self.launch_authority(of, services);
        self.coordinator.start_running(&execution(of)).unwrap();
    }

    /// Launches `of` to running, granted exactly the network grants `network`.
    pub fn launch_granting(&mut self, of: &str, network: BTreeSet<NetworkGrant>) {
        self.launch_authority_granting(of, network);
        self.coordinator.start_running(&execution(of)).unwrap();
    }

    /// Launches `of` to authority_active, granted the published-service grants of
    /// `services`.
    pub fn launch_authority(&mut self, of: &str, services: &[&str]) {
        let network = services.iter().map(|name| published_grant(name)).collect();
        self.launch_authority_granting(of, network);
    }

    /// Launches `of` to authority_active, granted exactly the network grants `network`.
    pub fn launch_authority_granting(&mut self, of: &str, network: BTreeSet<NetworkGrant>) {
        let of = execution(of);
        let offer = self.observe_runtime();
        let plan = LaunchPlan {
            execution: of.clone(),
            tenant: TenantId::new("tenant-a").unwrap(),
            runtime: RuntimeRequirement::VmSandbox.admit(&offer).unwrap(),
            demand: BTreeMap::from([(ResourceKind::HostMemoryBytes, 1 << 30)]),
            priority: ReservationPriority::Background,
            authority_lifetime: HOUR,
            readiness_max_age: 5 * SECOND,
            runtime_evidence_max_age: HOUR,
        };
        let settings = SettingsGrant {
            network,
            ..SettingsGrant::default()
        };
        let outcome = self
            .coordinator
            .launch_with(plan, settings, &mut self.port, &self.registry)
            .unwrap();
        assert!(
            matches!(outcome, LaunchOutcome::AuthorityActive { .. }),
            "{outcome:?}"
        );
    }

    /// Drives the revocation of `of` to stopped; every lease left is acknowledged first.
    pub fn stop_revoked(&mut self, of: &str) {
        let of = execution(of);
        let leases: Vec<_> = self
            .coordinator
            .leases()
            .map(|record| record.lease().id())
            .collect();
        for lease in leases {
            let _ = self.coordinator.acknowledge_cancellation(lease);
        }
        let status = self
            .coordinator
            .advance_revocation(&of, &mut self.port)
            .unwrap();
        assert!(
            matches!(status, RevocationStatus::Completed { .. }),
            "{status:?}"
        );
    }

    /// Boots a stopped `of` again, cold, to running under a new authorization epoch, with
    /// the settings its earlier authority granted.
    pub fn relaunch(&mut self, of: &str) {
        let of = execution(of);
        let offer = self.observe_runtime();
        let plan = RelaunchPlan {
            runtime: RuntimeRequirement::VmSandbox.admit(&offer).unwrap(),
            demand: BTreeMap::from([(ResourceKind::HostMemoryBytes, 1 << 30)]),
            authority_lifetime: HOUR,
            readiness_max_age: 5 * SECOND,
            runtime_evidence_max_age: HOUR,
            recovery: CompositeRecovery::default(),
            authorized_volumes: BTreeSet::new(),
        };
        let verified = ArtifactVerification::Verified {
            artifacts: BTreeSet::new(),
        };
        let context = RecoveryContext {
            expected_image_profile: digest("yougori/test/image/v1", &[b"image"]),
            checkpoint_evidence: None,
            artifact_verification: &verified,
        };
        let report = self
            .coordinator
            .relaunch(&of, plan, &context, &mut self.port, &self.registry)
            .unwrap();
        assert!(
            matches!(report.outcome, LaunchOutcome::AuthorityActive { .. }),
            "{report:?}"
        );
        self.coordinator.start_running(&of).unwrap();
    }

    /// The authorization epoch `of` is at.
    pub fn epoch(&self, of: &str) -> AuthorizationEpoch {
        self.coordinator
            .sandbox(&execution(of))
            .unwrap()
            .generations()
            .authorization
    }
}

/// A world with sandboxes launched and attached to a fresh gate: each named sandbox in
/// trust scope `team-a`, granted the published-service grants of `services` and
/// registered offering exactly those.
pub fn attached(sandboxes: &[&str], services: &[&str]) -> (World, ConnectionGate) {
    let mut world = World::new();
    let mut gate = ConnectionGate::with_chunk_bytes(std::num::NonZeroUsize::new(64).unwrap());
    for sandbox in sandboxes {
        world.launch(sandbox, services);
        let epoch = gate
            .attach(
                &world.coordinator,
                registration_of(sandbox, "team-a", services),
            )
            .unwrap();
        assert_eq!(epoch, world.epoch(sandbox));
    }
    (world, gate)
}

// ---------------------------------------------------------------------------------------
// An authority for clock tests

/// An authority whose clock can be set to any reading, earlier ones included. A sandbox
/// holds the first epoch and policy until revoked, relaunched or its policy raised, and
/// every network grant not revoked.
#[derive(Debug)]
pub struct SettableAuthority {
    pub now: MonotonicTime,
    pub epochs: BTreeMap<ExecutionId, Option<AuthorizationEpoch>>,
    pub policies: BTreeMap<ExecutionId, PolicyEpoch>,
    pub revoked_grants: BTreeSet<(ExecutionId, GrantId)>,
}

impl SettableAuthority {
    pub fn at(seconds: u64) -> Self {
        Self {
            now: MonotonicTime::from_nanos(seconds * 1_000_000_000),
            epochs: BTreeMap::new(),
            policies: BTreeMap::new(),
            revoked_grants: BTreeSet::new(),
        }
    }

    pub fn raise_policy(&mut self, sandbox: &str) {
        let current = self.current_policy(&execution(sandbox)).unwrap();
        self.policies
            .insert(execution(sandbox), current.next().unwrap());
    }

    pub fn set(&mut self, seconds: u64) {
        self.now = MonotonicTime::from_nanos(seconds * 1_000_000_000);
    }

    pub fn revoke(&mut self, sandbox: &str) {
        self.epochs.insert(execution(sandbox), None);
    }

    pub fn relaunch(&mut self, sandbox: &str, epoch: u64) {
        self.epochs
            .insert(execution(sandbox), Some(AuthorizationEpoch::new(epoch)));
    }
}

impl ConnectionAuthority for SettableAuthority {
    fn now(&self) -> MonotonicTime {
        self.now
    }

    fn current_epoch(&self, sandbox: &ExecutionId) -> Option<AuthorizationEpoch> {
        match self.epochs.get(sandbox) {
            Some(epoch) => *epoch,
            None => Some(AuthorizationEpoch::FIRST),
        }
    }

    fn current_policy(&self, sandbox: &ExecutionId) -> Option<PolicyEpoch> {
        Some(
            self.policies
                .get(sandbox)
                .copied()
                .unwrap_or(PolicyEpoch::FIRST),
        )
    }

    fn holds_network_grant(&self, sandbox: &ExecutionId, grant: &NetworkGrant) -> bool {
        self.current_epoch(sandbox).is_some()
            && !self.grant_revoked(sandbox, network_grant_id(grant))
    }

    fn grant_revoked(&self, sandbox: &ExecutionId, grant: GrantId) -> bool {
        self.revoked_grants.contains(&(sandbox.clone(), grant))
    }
}
