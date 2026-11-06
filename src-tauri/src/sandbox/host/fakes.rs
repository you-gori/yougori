//! The host's test world: a manual clock; a CORE-01 registry with a runtime category probe
//! and a hypervisor probe; the real CORE-03 ledger shared by the coordinator's capacity
//! port and the reservation resolver; the fake backend of VB1; the audit sink on the
//! durable spooled stream in a temporary directory; and, per sandbox, a scripted guest end
//! that seals its frames with the guest's key, a real file protocol dispatcher over the real
//! file service on a temporary root, and the CORE-05 port fakes with an honest issuer of
//! body grants. The test worlds of `sandbox::integration` and `sandbox::guest_files` are
//! private to those modules, so what this one shares with them is repeated here. Nothing
//! outside the temporary directory is touched.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;

use super::{ChannelSetup, Delivery, HostError, HostLog, HostParts, SandboxHost};
use crate::foundation::coordination::{
    LedgerCapacity, ReservationPriority, ResourceKind, SandboxState, SettingsGrant, SharedLedger,
    VmInstanceId,
};
use crate::foundation::events::{
    AuditConfig, AuditEntry, AuditFailurePolicy, AuditRecord, EmissionLimit, HostFact as AuditFact,
    JournalHead, JournalId, LogConfig, ProducerId, RedactedValue, RedactionPolicy,
};
use crate::foundation::evidence::fakes::FakeProbe;
use crate::foundation::evidence::{
    AdmittedRuntime, Backend, BackendRelease, BackendVersion, Capability, ClockSession,
    ConfigurationFingerprint, HostSubject, HypervisorKind, HypervisorSubject, Observation, OsKind,
    ProbeRegistry, RuntimeOffer, RuntimeRequirement, RuntimeSubject, SourceClass, Subject,
    SupportDetail, UnsupportedReason,
};
use crate::foundation::ids::{
    digest, Clock, ContentKey, Digest, ExecutionCategory, ExecutionId, ManualClock, MonotonicTime,
    OperationId, SandboxBootGeneration, TenantId, TrustScope,
};
use crate::foundation::ledger::{
    CapacityDeclaration, HostResource, Ledger, LedgerConfig, QueueLimits, ResourceKey,
};
use crate::foundation::transfer::fakes::{
    test_key, FakeAuthority, FakeByteLedger, FakeExtents, FakeProgress, EPOCH, SESSION,
};
use crate::foundation::transfer::{
    Direction, EnvelopeFields, ObjectGrant, SealedEnvelope, StopBounds, TransferEnvelope,
    TransferPorts, TransferScope,
};
use crate::sandbox::audit::{
    Anchoring, DurableSegments, FileSpool, NoAnchor, SegmentConfig, SegmentStorage as _,
    StoredSegment, StreamConfig, StreamDirectory,
};
use crate::sandbox::backend::{
    Architecture, BuildId, DeviceExposure, DeviceProfile, FakeBackend, FakeCall, HostBuild,
    HostScript, PinnedArtifacts, RequiredProperties,
};
use crate::sandbox::guest_files::{
    channel_limits, message_room, AuthorityRefusal, BodyAuthority, BodyPhase, BodyRequest,
    BodyTransfers, Declaration, FilesEvent, FilesLimits,
};
use crate::sandbox::integration::{
    AuditSink, LaunchProfile, LaunchTable, LedgerReservations, PortConfig,
};
use crate::sandbox::lifecycle::{
    CallTerms, IssuerId, LaunchReceipt, LaunchRequest, LeaseLimits, Profile, RevocationPolicy,
    SandboxClass, SkewPolicy, StateReset, SupervisorConfig, SupervisorDeathFallback,
    SupervisorRecovery, TerminationTiming,
};
use crate::sandbox::link::{
    encode_frame_on, BootstrapSecret, CancelCause, Channel, CloseReason, Connection,
    ConnectionNonce, DecodeStep, FileMode, FrameDecoder, GrantHandle, Hello, LinkBinding,
    LinkLimits, LinkMessage, LinkName, OpenRefusalCause, Operation, Sender, StreamId, StreamOpen,
    PROTOCOL_VERSION,
};
use crate::sandbox_contract::file_protocol::{
    FileDispatcher, GuestOperation, GuestRequest as FileRequest, RequestId,
};
use crate::sandbox_contract::files::{
    FileGrant, FileOperation, FileQuota, FileService, GrantMode, GrantedRoot, GuestName,
};

pub const SECOND: Duration = Duration::from_secs(1);
pub const MINUTE: Duration = Duration::from_secs(60);
pub const HOUR: Duration = Duration::from_secs(3_600);
pub const DAY: u64 = 86_400;
pub const GIB: u64 = 1 << 30;
/// The grant every sandbox's file channel starts with.
pub const GRANT: GrantHandle = GrantHandle(41);

pub type TestClock = Arc<ManualClock>;
pub type Capacity = LedgerCapacity<TestClock, SharedLedger<TestClock>>;
pub type Reservations = LedgerReservations<TestClock>;
pub type Sink = AuditSink<DurableSegments, FileSpool, NoAnchor, TestClock>;
pub type TestHost = SandboxHost<
    TestClock,
    Capacity,
    FakeBackend,
    Reservations,
    DurableSegments,
    FileSpool,
    NoAnchor,
>;

pub fn at(seconds: u64) -> MonotonicTime {
    MonotonicTime::from_nanos(seconds * 1_000_000_000)
}

pub fn session(number: u128) -> ClockSession {
    ClockSession::from_uuid(uuid::Uuid::from_u128(number))
}

pub fn named(domain: &str, name: &str) -> Digest {
    digest(domain, &[name.as_bytes()])
}

pub fn config(name: &str) -> ConfigurationFingerprint {
    ConfigurationFingerprint::from_settings([("host", name)]).unwrap()
}

pub fn machine() -> Digest {
    named("yougori/test/machine/v1", "workstation")
}

pub fn image() -> Digest {
    named("yougori/test/image/v1", "sandbox-image")
}

pub fn artifact() -> Digest {
    named("yougori/test/backend/v1", "fake-backend")
}

pub fn execution(name: &str) -> ExecutionId {
    ExecutionId::new(name).unwrap()
}

pub fn operation(name: &str) -> OperationId {
    OperationId::new(name).unwrap()
}

pub fn tenant() -> TenantId {
    TenantId::new("tenant-a").unwrap()
}

pub fn runtime() -> RuntimeSubject {
    RuntimeSubject {
        category: ExecutionCategory::VmSandbox,
        release: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
        instance: named("yougori/test/instance/v1", "vm-host-1"),
    }
}

pub fn hypervisor_subject() -> Subject {
    Subject::Hypervisor(HypervisorSubject {
        machine: machine(),
        hypervisor: HypervisorKind::Kvm,
    })
}

pub fn host_script() -> HostScript {
    HostScript::hardware_vm(
        HypervisorKind::Kvm,
        HostBuild {
            os: OsKind::Linux,
            build: BuildId::new("6.6.0").unwrap(),
            architecture: Architecture::X86_64,
        },
        image(),
        config("a"),
    )
}

pub fn call() -> CallTerms {
    CallTerms {
        per_call: 30 * SECOND,
        task: HOUR,
    }
}

pub fn stream(id: u32) -> StreamId {
    StreamId::new(id).unwrap()
}

pub fn id(value: u64) -> RequestId {
    RequestId::new(value)
}

pub fn name(text: &str) -> GuestName {
    GuestName::parse(text).unwrap()
}

pub fn entry(text: &str) -> LinkName {
    LinkName::new(text).unwrap()
}

/// The trust scope the host gives the sandbox `name`'s VM.
pub fn scope(name: &str) -> TrustScope {
    TrustScope::named(ExecutionCategory::VmSandbox, name)
}

/// The bootstrap secret of `name`'s VM instance, as the host delivered it to the guest.
pub fn secret(name: &str) -> BootstrapSecret {
    BootstrapSecret::new(named("yougori/test/secret/v1", name).as_bytes()).unwrap()
}

/// The nonce the host draws for connection `number` of `name`'s boot.
pub fn connection_nonce(name: &str, number: u32) -> ConnectionNonce {
    let digest = named("yougori/test/connection/v1", &format!("{name}/{number}"));
    ConnectionNonce::new(&digest.as_bytes()[..16]).unwrap()
}

/// The entry a create or write of `content` is opened with.
pub fn content_entry(content: &[u8]) -> LinkName {
    Declaration::Content {
        content: ContentKey::of(content),
    }
    .entry()
    .unwrap()
}

/// `length` bytes that differ from part to part.
pub fn pattern(length: usize, seed: u8) -> Vec<u8> {
    (0..length)
        .map(|index| (index % 251) as u8 ^ seed)
        .collect()
}

pub fn create(file: &str, content: &[u8]) -> GuestOperation {
    GuestOperation::Create {
        name: name(file),
        content: content.to_vec(),
    }
}

pub fn read(file: &str) -> GuestOperation {
    GuestOperation::Read {
        name: name(file),
        max_bytes: 1 << 16,
    }
}

pub fn list() -> GuestOperation {
    GuestOperation::List { name: None }
}

/// Every message of a request, as the guest encodes it for the default link.
pub fn messages(request: u64, operation: GuestOperation) -> Vec<Vec<u8>> {
    FileRequest {
        id: id(request),
        operation,
    }
    .encode(message_room(&LinkLimits::default()))
    .unwrap()
}

/// The CORE-03 ledger of the host: 64 GiB of RAM, 16 CPU initialization slots, the tenant
/// budgeted for all of it.
pub fn real_ledger(clock: &TestClock) -> Ledger<TestClock> {
    let host = HostSubject { machine: machine() };
    let config = LedgerConfig {
        queue: QueueLimits {
            max_entries: 8,
            max_entries_per_tenant: 4,
            max_wait: 60 * SECOND,
        },
        grant_ttl: 300 * SECOND,
        unmanaged_usage_max_age: 1000 * HOUR,
    };
    let mut ledger = Ledger::new(Arc::clone(clock), host, config);
    for (key, total) in [
        (ResourceKey::Host(HostResource::Ram), 64 * GIB),
        (ResourceKey::Host(HostResource::CpuInitializationSlots), 16),
    ] {
        ledger
            .declare_capacity(
                key,
                CapacityDeclaration {
                    total,
                    supervisor_reserve: 0,
                    unmanaged_in_use: 0,
                    source: SourceClass::HostProbe,
                },
            )
            .unwrap();
        ledger.set_tenant_budget(tenant(), key, total).unwrap();
    }
    ledger
}

pub fn supervisor_config(timing: TerminationTiming) -> SupervisorConfig {
    SupervisorConfig {
        profile: Profile::Strict,
        readiness_max_age: 5 * SECOND,
        runtime_evidence_max_age: HOUR,
        skew: SkewPolicy {
            allowed_clock_uncertainty: 30 * SECOND,
        },
        revocation: RevocationPolicy {
            timing,
            cleanup_bound: 60 * SECOND,
        },
        death_fallback: SupervisorDeathFallback::ServiceManagerRestart {
            restart_within: 30 * SECOND,
        },
        cancel_within: 5 * SECOND,
        issuer: IssuerId::named("host-a"),
        expected_image_profile: image(),
    }
}

pub fn journal() -> JournalId {
    JournalId::new("supervisor").unwrap()
}

pub fn owner() -> ProducerId {
    ProducerId::new("supervisor.audit").unwrap()
}

pub fn genesis() -> JournalHead {
    JournalHead::genesis(journal(), owner())
}

/// The supervisor's stream: a spool of eight records, two of them kept for revocations.
fn stream_config() -> StreamConfig {
    StreamConfig {
        audit: AuditConfig {
            spool_records: 8,
            revocation_reserve_records: 2,
            failure_policy: AuditFailurePolicy::SpoolHighImpact,
            guest_observations: EmissionLimit::new(16, SECOND).unwrap(),
            redaction: RedactionPolicy::metadata_only(),
        },
        segment: SegmentConfig {
            max_records_per_segment: 16,
        },
        anchoring: Anchoring::Off,
    }
}

fn log_config() -> LogConfig {
    LogConfig {
        max_entries: 10_000,
        max_bytes: 1 << 26,
        segment_entries: 64,
        segment_bytes: 1 << 16,
    }
}

/// Opens the supervisor's sink on the durable spooled stream under `directory`.
pub fn open_sink(directory: &mut StreamDirectory, clock: &TestClock) -> Sink {
    let (sink, _) = AuditSink::open_durable_spooled(
        directory,
        journal(),
        owner(),
        NoAnchor,
        Arc::clone(clock),
        stream_config(),
        log_config(),
    )
    .unwrap();
    sink
}

/// The host's issuer of body grants: every grant asked for, sealed honestly, the parent's
/// epoch the fake authority holds, expiring after a day.
#[derive(Default)]
pub struct Issuer {
    requests: Mutex<Vec<BodyRequest>>,
}

impl Issuer {
    pub fn requests(&self) -> Vec<BodyRequest> {
        self.requests.lock().unwrap().clone()
    }
}

impl BodyAuthority for Issuer {
    fn authorize(&self, request: &BodyRequest) -> Result<SealedEnvelope, AuthorityRefusal> {
        self.requests.lock().unwrap().push(request.clone());
        let fields = EnvelopeFields {
            operation: request.operation.clone(),
            tenant: request.tenant.clone(),
            parent: request.parent.clone(),
            epoch: EPOCH,
            direction: Direction::Download,
            source: request.source.clone(),
            recipient: request.recipient.clone(),
            credential: None,
            scope: TransferScope::single(
                request.object,
                ObjectGrant::whole(request.length_bytes).unwrap(),
            ),
            budget_bytes: request.length_bytes,
            stop_bounds: StopBounds {
                max_in_flight_bytes: 1 << 20,
                max_chunk_duration: 10 * SECOND,
            },
            clock: SESSION,
            expires_at: at(DAY),
        };
        Ok(test_key().seal(TransferEnvelope::new(fields).unwrap()))
    }
}

/// The guest end of one link: it seals its frames with the guest's key, the connection
/// of the host's challenge and consecutive sequences, and reads the host's frames after
/// checking their tags; a challenge it reads binds it to that connection.
pub struct GuestEnd {
    binding: LinkBinding,
    connection: Connection,
    sequence: u64,
    decoder: FrameDecoder,
}

impl GuestEnd {
    pub fn new(vm: VmInstanceId, boot: SandboxBootGeneration, secret: BootstrapSecret) -> Self {
        Self {
            binding: LinkBinding::new(vm, boot, secret),
            connection: Connection::UNCHALLENGED,
            sequence: 0,
            decoder: FrameDecoder::new(LinkLimits::default().max_frame_bytes),
        }
    }

    /// The connection the guest answers on: the last challenge it read.
    pub fn connection(&self) -> Connection {
        self.connection
    }

    pub fn frame(&mut self, message: &LinkMessage) -> Vec<u8> {
        self.sequence += 1;
        encode_frame_on(
            &self.binding,
            self.connection,
            Sender::Guest,
            self.sequence,
            message,
        )
        .unwrap()
    }

    /// The host's messages in `frames`; every tag must be the host's.
    pub fn read(&mut self, frames: &[Vec<u8>]) -> Vec<LinkMessage> {
        let mut messages = Vec::new();
        for bytes in frames {
            for step in self.decoder.push(bytes, MonotonicTime::ZERO) {
                let raw = match step {
                    DecodeStep::Frame(raw) => raw,
                    DecodeStep::Refused(refusal) => panic!("the host sent a bad frame: {refusal}"),
                };
                assert!(self.binding.verify(
                    Sender::Host,
                    &raw.header_bytes,
                    &raw.payload,
                    &raw.tag
                ));
                let channel = raw.header.channel;
                let operation = Operation::decode(channel, raw.header.operation_code).unwrap();
                let message = LinkMessage::decode(
                    channel,
                    operation,
                    raw.header.stream,
                    &raw.payload,
                    usize::MAX,
                )
                .unwrap();
                match &message {
                    LinkMessage::Challenge { connection } => {
                        assert_eq!(raw.header.connection, *connection);
                        assert_eq!(raw.header.sequence, 1);
                        self.connection = *connection;
                        self.sequence = 0;
                    }
                    _ if !self.connection.is_unchallenged() => {
                        assert_eq!(raw.header.connection, self.connection);
                    }
                    _ => {}
                }
                messages.push(message);
            }
        }
        messages
    }
}

/// Fields drop in order: the host, whose file services and audit stream hold handles in the
/// temporary directory, goes before the directory.
pub struct World {
    pub clock: TestClock,
    pub category: Arc<FakeProbe>,
    pub hypervisor: Arc<FakeProbe>,
    pub timing: TerminationTiming,
    host: Option<TestHost>,
    pub directory: StreamDirectory,
    pub authority: Arc<FakeAuthority>,
    pub ledger: Arc<FakeByteLedger>,
    pub progress: Arc<FakeProgress>,
    pub issuer: Arc<Issuer>,
    guests: BTreeMap<String, GuestEnd>,
    /// Connections drawn per sandbox so far.
    connections: BTreeMap<String, u32>,
    pub dir: tempfile::TempDir,
}

impl World {
    pub fn new() -> Self {
        Self::with(TerminationTiming::AfterChannelAcknowledgmentOrBound)
    }

    pub fn with(timing: TerminationTiming) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(ManualClock::new(at(100)));
        let mut registry = ProbeRegistry::new(Arc::clone(&clock));
        let category = Arc::new(FakeProbe::runtime_category(SourceClass::HostProbe));
        let hypervisor = Arc::new(FakeProbe::new(
            Capability::HypervisorAvailable,
            SourceClass::HostProbe,
        ));
        registry.register(Box::new(Arc::clone(&category))).unwrap();
        registry
            .register(Box::new(Arc::clone(&hypervisor)))
            .unwrap();
        let capacity = LedgerCapacity::new(real_ledger(&clock)).into_shared();
        let reservations = LedgerReservations::new(capacity.handle());
        let backend = FakeBackend::new(
            HypervisorKind::Kvm,
            BackendVersion::new("0.1.0").unwrap(),
            artifact(),
            host_script(),
        );
        let table = LaunchTable::new(PortConfig {
            machine: machine(),
            state_reset: StateReset::Unsupported {
                detail: "no state reset declared".to_owned(),
            },
        });
        let mut directory = StreamDirectory::durable(dir.path().join("audit"));
        let sink = open_sink(&mut directory, &clock);
        let parts = HostParts::new(
            Arc::clone(&clock),
            registry,
            backend,
            table,
            reservations,
            sink,
        );
        let host = SandboxHost::new(parts, session(1), capacity, supervisor_config(timing));
        let mut world = Self {
            clock,
            category,
            hypervisor,
            timing,
            host: Some(host),
            directory,
            authority: Arc::new(FakeAuthority::default()),
            ledger: Arc::new(FakeByteLedger::new(1 << 40)),
            progress: Arc::new(FakeProgress::default()),
            issuer: Arc::new(Issuer::default()),
            guests: BTreeMap::new(),
            connections: BTreeMap::new(),
            dir,
        };
        world.observe_hypervisor(true);
        world
    }

    pub fn host(&self) -> &TestHost {
        self.host.as_ref().unwrap()
    }

    pub fn host_mut(&mut self) -> &mut TestHost {
        self.host.as_mut().unwrap()
    }

    pub fn advance(&mut self, by: Duration) {
        self.clock.advance(by);
    }

    /// The hypervisor probe observes KVM available, or not, fresh for ten minutes.
    pub fn observe_hypervisor(&mut self, available: bool) {
        let observation = if available {
            Observation::supported(
                config("a"),
                600 * SECOND,
                SupportDetail::Hypervisor {
                    hypervisor: HypervisorKind::Kvm,
                },
            )
        } else {
            Observation::unsupported(
                config("a"),
                600 * SECOND,
                UnsupportedReason::HypervisorUnavailable,
            )
        };
        self.hypervisor.respond(&hypervisor_subject(), observation);
        self.host_mut()
            .registry_mut()
            .refresh(Capability::HypervisorAvailable, &hypervisor_subject())
            .unwrap();
    }

    /// The runtime's category, observed by the host probe now and admitted.
    pub fn admit(&mut self) -> AdmittedRuntime {
        let subject = Subject::Runtime(runtime());
        self.category.respond(
            &subject,
            Observation::supported(
                config("a"),
                HOUR,
                SupportDetail::RuntimeCategory {
                    category: ExecutionCategory::VmSandbox,
                },
            ),
        );
        self.host_mut()
            .registry_mut()
            .refresh(Capability::RuntimeCategory, &subject)
            .unwrap();
        let offer =
            RuntimeOffer::observe(self.host().registry(), runtime(), HOUR, config("a")).unwrap();
        RuntimeRequirement::VmSandbox.admit(&offer).unwrap()
    }

    /// The launch profile: the contract digest a V01 plan would supply, the pinned image
    /// and backend, a CPU-only device profile and the strictest properties, fresh within a
    /// minute.
    pub fn profile() -> LaunchProfile {
        LaunchProfile {
            configuration: config("a"),
            contract: named("yougori/test/contract/v1", "analysis"),
            pinned: PinnedArtifacts {
                guest_image: image(),
                backend: artifact(),
            },
            device_profile: DeviceProfile {
                identity: named("yougori/test/profile/v1", "minimal"),
                devices: DeviceExposure::cpu_only(),
            },
            required: RequiredProperties::strictest(MINUTE),
        }
    }

    pub fn request(&mut self, name: &str, class: SandboxClass) -> LaunchRequest {
        LaunchRequest {
            execution: execution(name),
            tenant: tenant(),
            runtime: self.admit(),
            demand: BTreeMap::from([
                (ResourceKind::HostMemoryBytes, 8 * GIB),
                (ResourceKind::CpuInitializationSlots, 1),
            ]),
            priority: ReservationPriority::Foreground,
            class,
            limits: LeaseLimits::defaults(class),
            settings: SettingsGrant::default(),
            volumes: BTreeMap::new(),
            provider_bills: false,
        }
    }

    /// Launches `name` through the host; its boot holds authority.
    pub fn launch(&mut self, name: &str, class: SandboxClass) -> SandboxBootGeneration {
        self.host_mut()
            .set_profile(execution(name), Self::profile());
        let request = self.request(name, class);
        match self.host_mut().launch(request).unwrap() {
            LaunchReceipt::AuthorityActive { boot, .. } => boot,
            other => panic!("{other:?}"),
        }
    }

    pub fn state(&self, name: &str) -> SandboxState {
        self.host()
            .supervisor()
            .coordinator()
            .sandbox(&execution(name))
            .unwrap()
            .state()
    }

    pub fn vm(&self, name: &str) -> VmInstanceId {
        self.host()
            .supervisor()
            .coordinator()
            .sandbox(&execution(name))
            .unwrap()
            .vm()
            .unwrap()
    }

    pub fn boot(&self, name: &str) -> SandboxBootGeneration {
        self.host()
            .supervisor()
            .coordinator()
            .sandbox(&execution(name))
            .unwrap()
            .generations()
            .boot
    }

    /// How many times the backend was asked to stop `name`'s current VM.
    pub fn stops_of(&self, name: &str) -> usize {
        let vm = self.vm(name);
        self.host()
            .backend()
            .calls()
            .iter()
            .filter(|call| matches!(call, FakeCall::Stop { vm: stopped } if *stopped == vm))
            .count()
    }

    /// How many times the backend observed a VM again.
    pub fn reobserves(&self) -> usize {
        self.host()
            .backend()
            .calls()
            .iter()
            .filter(|call| matches!(call, FakeCall::Reobserve { .. }))
            .count()
    }

    /// The granted root of `name`'s file channel, with a secret file beside it.
    pub fn root(&self, name: &str) -> PathBuf {
        let root = self.dir.path().join("roots").join(name);
        if !root.exists() {
            fs::create_dir_all(&root).unwrap();
            fs::write(root.with_extension("secret"), b"beside the root").unwrap();
        }
        root
    }

    /// A dispatcher for `name`'s scope over its root, granting every operation for a day on
    /// the transfer fakes' clock session.
    pub fn dispatcher(&self, name: &str) -> FileDispatcher<TestClock> {
        let root = GrantedRoot::open(&self.root(name)).unwrap();
        let operations: BTreeSet<FileOperation> = [
            FileOperation::Read,
            FileOperation::List,
            FileOperation::Create,
            FileOperation::Write,
            FileOperation::Delete,
            FileOperation::Rename,
            FileOperation::SetExecutable,
        ]
        .into_iter()
        .collect();
        let grant = FileGrant::new(
            root.handle(),
            GrantMode::QuarantineOutput,
            operations,
            scope(name),
            SESSION,
            at(DAY),
            FileQuota {
                max_total_bytes: 1 << 26,
                max_entries: 1_000,
                max_file_bytes: 1 << 25,
            },
        )
        .unwrap();
        FileDispatcher::new(
            FileService::new(grant, root).unwrap(),
            scope(name),
            Arc::clone(&self.clock),
            SESSION,
            channel_limits(&LinkLimits::default()),
        )
        .unwrap()
    }

    /// The host's transfer key and ports over the CORE-05 fakes, with the honest issuer.
    pub fn transfers(&self) -> BodyTransfers {
        BodyTransfers {
            key: test_key(),
            ports: TransferPorts {
                clock: Arc::clone(&self.clock) as Arc<dyn Clock>,
                clock_session: SESSION,
                authority: self.authority.clone(),
                budget: self.ledger.clone(),
                extents: Arc::new(FakeExtents::default()),
                progress: self.progress.clone(),
            },
            authority: self.issuer.clone(),
        }
    }

    /// The nonce of `name`'s next connection.
    pub fn next_nonce(&mut self, name: &str) -> ConnectionNonce {
        let number = self.connections.entry(name.to_owned()).or_insert(0);
        *number += 1;
        connection_nonce(name, *number)
    }

    /// The channels of `name`'s boot, with [`GRANT`] over its root, on a new connection.
    /// The fake transfer authority holds the sandbox as the parent of its bodies.
    pub fn setup(&mut self, name: &str) -> ChannelSetup<TestClock> {
        self.authority.grant(&execution(name), EPOCH, at(DAY));
        ChannelSetup {
            secret: secret(name),
            connection: self.next_nonce(name),
            scope: scope(name),
            link_limits: LinkLimits::default(),
            files_limits: FilesLimits::default(),
            transfers: self.transfers(),
            grants: vec![(GRANT, self.dispatcher(name))],
        }
    }

    /// Opens `name`'s channels; its guest says hello and grants 16 MiB of credit on the
    /// file channel. Returns what the hello delivered.
    pub fn open(&mut self, name: &str) -> Delivery {
        let setup = self.setup(name);
        self.host_mut()
            .open_channels(&execution(name), setup)
            .unwrap();
        self.greet(name)
    }

    /// Replaces `name`'s closed link with a new one on a new connection, as after the
    /// transport reconnected; its guest reads the new challenge, says hello again on it
    /// and grants credit. Returns what the hello delivered.
    pub fn reconnect(&mut self, name: &str) -> Delivery {
        let nonce = self.next_nonce(name);
        self.host_mut()
            .reconnect(&execution(name), secret(name), nonce)
            .unwrap();
        self.greet(name)
    }

    /// A new guest end for `name`'s boot reads the host's challenge, says hello and
    /// grants 16 MiB of credit on the file channel.
    fn greet(&mut self, name: &str) -> Delivery {
        let guest = GuestEnd::new(self.vm(name), self.boot(name), secret(name));
        self.guests.insert(name.to_owned(), guest);
        let challenge = self.drain(name);
        assert!(
            matches!(&challenge[..], [LinkMessage::Challenge { .. }]),
            "{challenge:?}"
        );
        let hello = self.send(
            name,
            LinkMessage::Hello(Hello {
                guest_version: PROTOCOL_VERSION,
                agent_build: named("yougori/test/agent/v1", "agent"),
                claimed_vm: None,
                claimed_boot: None,
            }),
        );
        let credit = self.send(
            name,
            LinkMessage::WindowUpdate {
                channel: Channel::File,
                credit_bytes: 16 << 20,
            },
        );
        assert!(credit.files.is_empty(), "{credit:?}");
        self.drain(name);
        hello
    }

    pub fn guest(&mut self, name: &str) -> &mut GuestEnd {
        self.guests.get_mut(name).unwrap()
    }

    /// Sends `message` from `name`'s guest through the host.
    pub fn try_send(&mut self, name: &str, message: LinkMessage) -> Result<Delivery, HostError> {
        let frame = self.guest(name).frame(&message);
        self.host_mut().receive(&execution(name), &frame)
    }

    pub fn send(&mut self, name: &str, message: LinkMessage) -> Delivery {
        self.try_send(name, message).unwrap()
    }

    /// Everything the host queued for `name`'s guest, as the guest reads it.
    pub fn drain(&mut self, name: &str) -> Vec<LinkMessage> {
        let frames = self.host_mut().outbound(&execution(name)).unwrap();
        self.guest(name).read(&frames)
    }

    pub fn open_file(
        &mut self,
        name: &str,
        stream_id: u32,
        entry: LinkName,
        mode: FileMode,
    ) -> Delivery {
        self.send(
            name,
            LinkMessage::Open {
                stream: stream(stream_id),
                open: StreamOpen::File {
                    grant: GRANT,
                    entry,
                    mode,
                },
            },
        )
    }

    pub fn try_data(
        &mut self,
        name: &str,
        stream_id: u32,
        bytes: &[u8],
    ) -> Result<Delivery, HostError> {
        self.try_send(
            name,
            LinkMessage::Data {
                channel: Channel::File,
                stream: stream(stream_id),
                bytes: bytes.to_vec(),
            },
        )
    }

    pub fn data(&mut self, name: &str, stream_id: u32, bytes: &[u8]) -> Delivery {
        self.try_data(name, stream_id, bytes).unwrap()
    }

    /// Opens a stream declared for `operation` and sends the whole request on it; the file
    /// events of every step, in order.
    pub fn call(
        &mut self,
        name: &str,
        stream_id: u32,
        request: u64,
        operation: GuestOperation,
    ) -> Vec<FilesEvent> {
        let (entry, mode) = match &operation {
            GuestOperation::Create { content, .. } | GuestOperation::Write { content, .. } => {
                (content_entry(content), FileMode::Write)
            }
            GuestOperation::Read { .. } => (entry("read"), FileMode::Read),
            GuestOperation::List { .. } => (entry("list"), FileMode::Read),
            other => panic!("no declaration for {other:?} here"),
        };
        let mut events = self.open_file(name, stream_id, entry, mode).files;
        for message in messages(request, operation) {
            events.extend(self.data(name, stream_id, &message).files);
        }
        events
    }

    /// Persists the supervisor, shuts the host down, releases the audit sink and opens it
    /// again, and recovers the host over the same backend and launch table, with a fresh
    /// ledger in a new clock session: a restart of the supervisor's process. Returns the
    /// recovery and what the host recorded as it shut down.
    pub fn restart(&mut self) -> (SupervisorRecovery, HostLog) {
        let mut host = self.host.take().unwrap();
        let persisted = host.persist();
        host.confirm_persisted(&persisted);
        let mut shutdown = host.shut_down();
        let released = shutdown.parts.sink.release();
        assert!(released.is_clean(), "{:?}", released.failures());
        shutdown.parts.sink = open_sink(&mut self.directory, &self.clock);
        let capacity = LedgerCapacity::new(real_ledger(&self.clock)).into_shared();
        shutdown.parts.reservations = LedgerReservations::new(capacity.handle());
        let (host, report) = SandboxHost::recover(
            shutdown.parts,
            persisted,
            session(2),
            capacity,
            supervisor_config(self.timing),
        )
        .unwrap();
        self.host = Some(host);
        self.guests.clear();
        (report, shutdown.log)
    }

    pub fn segments(&self) -> Vec<StoredSegment> {
        self.host()
            .sink()
            .stream()
            .with_storage(|storage| storage.segments().unwrap())
    }

    pub fn records(&self) -> Vec<AuditRecord> {
        self.segments()
            .into_iter()
            .flat_map(|segment| segment.records)
            .collect()
    }

    /// What each audit record records, in chain order.
    pub fn labels(&self) -> Vec<String> {
        self.records().iter().map(label).collect()
    }
}

fn text_of(value: Option<&RedactedValue>) -> Option<String> {
    match value {
        Some(RedactedValue::Text { text, .. }) => Some(text.clone()),
        _ => None,
    }
}

/// A record's label: a host fact's event, with the acknowledgment it records; a launch
/// record; a revocation; a guest report.
pub fn label(record: &AuditRecord) -> String {
    match record.event().payload() {
        AuditEntry::HostFact { fact, fields } => match text_of(fields.get("event")) {
            Some(event) => match text_of(fields.get("acknowledgment")) {
                Some(acknowledgment) => format!("{event} {acknowledgment}"),
                None => event,
            },
            None if *fact == AuditFact::LaunchFact => "launch_record".to_owned(),
            None => format!("{fact:?}"),
        },
        AuditEntry::GuestObservation { .. } => "guest_report".to_owned(),
        AuditEntry::Revocation { .. } => "revocation".to_owned(),
        AuditEntry::GrantRevocation { .. } => "grant_revocation".to_owned(),
        other => format!("{other:?}"),
    }
}

/// The data a stream carried, message by message.
pub fn data_on(messages: &[LinkMessage], stream_id: u32) -> Vec<Vec<u8>> {
    messages
        .iter()
        .filter_map(|message| match message {
            LinkMessage::Data {
                channel: Channel::File,
                stream: on,
                bytes,
            } if on.get() == stream_id => Some(bytes.clone()),
            _ => None,
        })
        .collect()
}

/// One response message: its header and its content.
pub fn parse(message: &[u8]) -> (Value, Vec<u8>) {
    let end = message.iter().position(|byte| *byte == b'\n').unwrap();
    (
        serde_json::from_slice(&message[..end]).unwrap(),
        message[end + 1..].to_vec(),
    )
}

/// The outcome of the answer a stream carried.
pub fn outcome(messages: &[LinkMessage], stream_id: u32) -> Value {
    let data = data_on(messages, stream_id);
    let first = data
        .first()
        .unwrap_or_else(|| panic!("no answer on {stream_id}: {messages:?}"));
    parse(first).0["outcome"].clone()
}

/// The content of the answer a stream carried, from all its parts.
pub fn content(messages: &[LinkMessage], stream_id: u32) -> Vec<u8> {
    data_on(messages, stream_id)
        .iter()
        .flat_map(|message| parse(message).1)
        .collect()
}

pub fn open_refused(messages: &[LinkMessage], stream_id: u32) -> Option<OpenRefusalCause> {
    messages.iter().find_map(|message| match message {
        LinkMessage::OpenRefused {
            channel: Channel::File,
            stream: on,
            cause,
        } if on.get() == stream_id => Some(*cause),
        _ => None,
    })
}

pub fn cancel_of(messages: &[LinkMessage], stream_id: u32) -> Option<CancelCause> {
    messages.iter().find_map(|message| match message {
        LinkMessage::Cancel {
            channel: Channel::File,
            stream: on,
            cause,
        } if on.get() == stream_id => Some(*cause),
        _ => None,
    })
}

/// The reason of the close frame among `messages`.
pub fn close_reason(messages: &[LinkMessage]) -> Option<CloseReason> {
    messages.iter().find_map(|message| match message {
        LinkMessage::Close { reason } => Some(*reason),
        _ => None,
    })
}

/// The body phases among `events`.
pub fn phases(events: &[FilesEvent]) -> Vec<BodyPhase> {
    events
        .iter()
        .filter_map(|event| match event {
            FilesEvent::Body { phase, .. } => Some(phase.clone()),
            _ => None,
        })
        .collect()
}
