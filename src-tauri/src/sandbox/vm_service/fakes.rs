//! Fakes of the VM service tests (module docs in `mod.rs`): the QEMU backend's three
//! host ports scripted (a host that starts no process but records every start and shows
//! the token, Job and listing a confined QEMU would show; QMP reporting the hypervisor;
//! the launch layout of a pinned image), a link connector whose streams are in-memory
//! wires, the process table of the peer check, and a guest at the far end of each wire,
//! on its own thread, built from the link's own encoder: it answers the challenge, says
//! hello, accepts terminal opens with credit, runs the scripted command, reports its exit
//! code, and powers off when asked to shut down. Nothing here starts a process, opens a
//! socket or reads a file; the audit stream lives in a temporary directory.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::{self, ErrorKind, Read, Write};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::foundation::coordination::VmInstanceId;
use crate::foundation::evidence::fakes::FakeProbe;
use crate::foundation::evidence::{
    Capability, ClockSession, HypervisorKind, HypervisorSubject, Observation, OsKind,
    ProbeRegistry, SourceClass, Subject, SupportDetail,
};
use crate::foundation::ids::{digest, Clock, Digest, ExecutionId, ManualClock, MonotonicTime};
use crate::foundation::ledger::Ledger;
use crate::foundation::process::{NoProof, ProcessError, ProcessIdentity, ProcessRole};
use crate::foundation::transfer::fakes::{
    test_key, FakeAuthority, FakeByteLedger, FakeExtents, FakeProgress, SESSION,
};
use crate::foundation::transfer::TransferPorts;
use crate::sandbox::audit::{DurableSegments, FileSpool, NoAnchor, StreamDirectory};
use crate::sandbox::backend::{
    Architecture, BackendIdentity, BackendKind, BuildId, DeviceExposure, DeviceProfile, HostBuild,
    RequiredProperties,
};
use crate::sandbox::guest_files::BodyTransfers;
use crate::sandbox::host::fakes::{
    config, machine, named, open_sink, runtime, supervisor_config, tenant, GuestEnd, Issuer,
    MINUTE, SECOND,
};
use crate::sandbox::integration::AuditSink;
use crate::sandbox::lifecycle::TerminationTiming;
use crate::sandbox::link::{
    BootstrapSecret, Channel, CloseReason, Hello, LinkMessage, LinkName, OpenRefusalCause,
    StreamId, StreamOpen, PROTOCOL_VERSION,
};
use crate::sandbox::link_transport::{LinkConnector, PeerProcess, ProcessTable, StreamShutdown};
use crate::sandbox::qemu::{
    GoldenFile, GroupState, GuestResources, HostInputs, HostPath, KernelArguments, LaunchLayout,
    LayoutRefusal, MonitorFailure, ObserveFailure, ObservedJob, PathStyle, PrivateDirectory,
    ProcessInspection, ProcessState, QemuHost, QemuLaunchInputs, QemuLaunchPlan, QemuMonitor,
    QemuPlatform, QemuSettings, RunState, StartFailure, TerminationEvidence,
    WindowsHostRestrictions, WindowsObservedState, MIB_BYTES,
};

use super::{
    DriverSettings, EvidenceSubjects, PinnedImage, VmHostPort, VmPorts, VmService, VmServiceConfig,
    VmServiceParts,
};

pub type TestClock = Arc<ManualClock>;
pub type TestLedger = crate::foundation::coordination::SharedLedger<TestClock>;

/// How long a test waits for the guest thread or the driver thread, in real time.
pub const WAIT: Duration = Duration::from_secs(20);
/// The guest memory the fake layout gives every VM.
pub const GUEST_MEMORY: u64 = 256 * MIB_BYTES;
/// The pinned QEMU build's artifact identity.
pub fn backend_artifact() -> Digest {
    named("yougori/test/vm-service/backend/v1", "qemu-secure")
}
/// The pinned guest image's identity.
pub fn guest_image() -> Digest {
    named("yougori/test/vm-service/image/v1", "sandbox-minimal")
}
/// The bootstrap secret the fake host writes for the process `pid`.
pub fn secret_for(pid: u32) -> BootstrapSecret {
    BootstrapSecret::new(
        digest("yougori/test/vm-service/secret/v1", &[&pid.to_be_bytes()]).as_bytes(),
    )
    .unwrap()
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A proof as the fake host gives it; CORE-04's `TerminationProof` has no public
/// constructor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FakeProof {
    pub identity: ProcessIdentity,
    pub role: ProcessRole,
}

impl TerminationEvidence for FakeProof {
    fn identity(&self) -> ProcessIdentity {
        self.identity
    }

    fn role(&self) -> &ProcessRole {
        &self.role
    }
}

/// One launch the fake host started, as the guest thread and the tests see it.
#[derive(Clone, Debug)]
pub struct LaunchInfo {
    pub execution: ExecutionId,
    pub vm: VmInstanceId,
    pub process: ProcessIdentity,
    pub directory: PrivateDirectory,
    pub boot: crate::foundation::ids::SandboxBootGeneration,
}

/// Both directions of one in-memory stream between the host and a guest.
#[derive(Default)]
pub struct WireState {
    /// What the guest wrote and the host has not read.
    pub to_host: VecDeque<u8>,
    /// What the host wrote and the guest has not read.
    pub to_guest: Vec<u8>,
    /// The guest's end closed (it powered off, or QEMU ended): once `to_host` is empty a
    /// read returns no bytes.
    pub guest_ended: bool,
    pub reads: usize,
    pub writes: usize,
    pub shut_downs: usize,
    pub peer_pid: u32,
    /// The stream takes no bytes for now (a full socket buffer).
    pub write_blocked: bool,
}

pub type SharedWire = Arc<Mutex<WireState>>;

/// The host's end of a wire.
pub struct Wire(pub SharedWire);

impl Read for Wire {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let mut state = lock(&self.0);
        state.reads += 1;
        if state.to_host.is_empty() {
            return if state.guest_ended {
                Ok(0)
            } else {
                Err(io::Error::from(ErrorKind::WouldBlock))
            };
        }
        let count = buffer.len().min(state.to_host.len());
        for (slot, byte) in buffer.iter_mut().zip(state.to_host.drain(..count)) {
            *slot = byte;
        }
        Ok(count)
    }
}

impl Write for Wire {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut state = lock(&self.0);
        if state.shut_downs > 0 {
            return Err(io::Error::from(ErrorKind::BrokenPipe));
        }
        if state.write_blocked {
            return Err(io::Error::from(ErrorKind::WouldBlock));
        }
        state.writes += 1;
        state.to_guest.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl StreamShutdown for Wire {
    fn shut_down(&mut self) -> io::Result<()> {
        lock(&self.0).shut_downs += 1;
        Ok(())
    }
}

impl PeerProcess for Wire {
    fn peer_process_id(&self) -> io::Result<u32> {
        Ok(lock(&self.0).peer_pid)
    }
}

/// What the fakes record and how they are scripted, shared by the ports, the guest
/// threads and the test.
#[derive(Default)]
pub struct World {
    pub launches: Vec<LaunchInfo>,
    /// The wires, in dial order, with the launch each was dialed for.
    pub wires: Vec<(usize, SharedWire)>,
    pub dialed: Vec<String>,
    pub quits: Vec<HostPath>,
    pub terminated: Vec<ProcessIdentity>,
    /// The private directories that exist on the fake host.
    pub directories: BTreeSet<String>,
    /// Processes that ended on their own (the guest powered off), by pid.
    pub exited: BTreeSet<u32>,
    // Scripts.
    pub start_failure: Option<StartFailure>,
    /// The link socket is served by another process: its pid is the QEMU pid plus this.
    pub peer_pid_offset: u32,
    pub connect_refused: bool,
    /// The process table reports no holder of the QEMU pid.
    pub holder_gone: bool,
}

pub type SharedWorld = Arc<Mutex<World>>;

/// The token, Job, handles and mitigations the host would query from a process confined
/// exactly as planned.
pub fn confined_as(expected: &WindowsHostRestrictions) -> WindowsObservedState {
    let handles = expected.inherited_handles();
    WindowsObservedState {
        token_restricted: true,
        restricting_sids: expected.token().restricting_sids.clone(),
        privileges: expected.token().retained_privileges.clone(),
        administrators: GroupState::DenyOnly,
        integrity_rid: expected.integrity().rid(),
        job: Some(ObservedJob {
            limits: expected.job().limits.clone(),
            active_process_limit: expected.job().active_process_limit,
            job_memory_limit_bytes: expected.job().job_memory_limit_bytes,
            ui_restrictions: expected.job().ui_restrictions.clone(),
        }),
        inherited_handles: vec![handles.stdin, handles.stdout, handles.stderr],
        mitigations: expected.mitigations().clone(),
    }
}

struct FakeProcess {
    role: ProcessRole,
    command_line: Vec<String>,
    windows: Option<WindowsObservedState>,
    directory: PrivateDirectory,
    secret: Option<BootstrapSecret>,
    ended: Option<u32>,
}

/// The fake QEMU host: starts no process; records each start and gives the observations
/// of a QEMU confined as planned.
pub struct FakeHost {
    world: SharedWorld,
    next_pid: u32,
    processes: BTreeMap<ProcessIdentity, FakeProcess>,
}

impl FakeHost {
    pub fn new(world: &SharedWorld) -> Self {
        Self {
            world: Arc::clone(world),
            next_pid: 4000,
            processes: BTreeMap::new(),
        }
    }

    fn ended(&self, process: &ProcessIdentity) -> Option<u32> {
        let held = self.processes.get(process)?;
        held.ended
            .or_else(|| lock(&self.world).exited.contains(&process.pid).then_some(0))
    }
}

impl QemuHost for FakeHost {
    type Proof = FakeProof;

    fn start(
        &mut self,
        role: &ProcessRole,
        executable: &HostPath,
        plan: &QemuLaunchPlan,
    ) -> Result<ProcessIdentity, StartFailure> {
        let mut world = lock(&self.world);
        if let Some(failure) = &world.start_failure {
            return Err(failure.clone());
        }
        let ProcessRole::VmHost {
            execution,
            vm,
            boot,
        } = role
        else {
            return Err(StartFailure::Prepare {
                detail: format!("not a VM host role: {role}"),
            });
        };
        let identity = ProcessIdentity {
            pid: self.next_pid,
            start_time_ticks: 133_000_000_000 + u64::from(self.next_pid),
        };
        self.next_pid += 1;
        let mut command_line = vec![executable.as_str().to_owned()];
        command_line.extend(plan.profile().argv());
        let directory = plan.profile().control().clone();
        world
            .directories
            .insert(directory.path().as_str().to_owned());
        world.launches.push(LaunchInfo {
            execution: execution.clone(),
            vm: *vm,
            process: identity,
            directory: directory.clone(),
            boot: *boot,
        });
        self.processes.insert(
            identity,
            FakeProcess {
                role: role.clone(),
                command_line,
                windows: plan.windows().map(confined_as),
                directory,
                secret: Some(secret_for(identity.pid)),
                ended: None,
            },
        );
        Ok(identity)
    }

    fn state(&self, process: &ProcessIdentity) -> Result<ProcessState, ObserveFailure> {
        if !self.processes.contains_key(process) {
            return Err(ObserveFailure::NotHeld { process: *process });
        }
        Ok(match self.ended(process) {
            Some(exit_code) => ProcessState::Ended { exit_code },
            None => ProcessState::Running,
        })
    }

    fn inspect(&self, process: &ProcessIdentity) -> Result<ProcessInspection, ObserveFailure> {
        let state = self.state(process)?;
        let held = self
            .processes
            .get(process)
            .ok_or(ObserveFailure::NotHeld { process: *process })?;
        Ok(ProcessInspection {
            state,
            command_line: held.command_line.clone(),
            windows: held.windows.clone(),
            linux: None,
        })
    }

    fn host_build(&self) -> Result<HostBuild, ObserveFailure> {
        Ok(HostBuild {
            os: OsKind::Windows,
            build: BuildId::new("26300.1").unwrap(),
            architecture: Architecture::X86_64,
        })
    }

    fn terminate(&mut self, process: &ProcessIdentity) -> Result<FakeProof, NoProof> {
        let held = self
            .processes
            .get_mut(process)
            .ok_or(NoProof::StillRunning)?;
        held.ended.get_or_insert(1);
        let role = held.role.clone();
        let directory = held.directory.path().as_str().to_owned();
        let mut world = lock(&self.world);
        world.terminated.push(*process);
        world.directories.remove(&directory);
        // QEMU's end closes its sockets: the host's stream ends.
        let wire = world
            .launches
            .iter()
            .position(|launch| launch.process == *process)
            .and_then(|index| {
                world
                    .wires
                    .iter()
                    .find(|(launch, _)| *launch == index)
                    .map(|(_, wire)| Arc::clone(wire))
            });
        drop(world);
        if let Some(wire) = wire {
            lock(&wire).guest_ended = true;
        }
        Ok(FakeProof {
            identity: *process,
            role,
        })
    }
}

impl VmHostPort for FakeHost {
    fn private_directory(&self, process: &ProcessIdentity) -> Option<PrivateDirectory> {
        self.processes
            .get(process)
            .map(|held| held.directory.clone())
    }

    fn take_secret(&mut self, process: &ProcessIdentity) -> Option<BootstrapSecret> {
        self.processes.get_mut(process)?.secret.take()
    }

    fn directory_absent(&self, directory: &PrivateDirectory) -> Result<bool, ObserveFailure> {
        Ok(!lock(&self.world)
            .directories
            .contains(directory.path().as_str()))
    }
}

/// QMP as the fake answers it: WHPX, running.
pub struct FakeMonitor {
    world: SharedWorld,
}

impl QemuMonitor for FakeMonitor {
    fn accelerator(&self, _socket: &HostPath) -> Result<String, MonitorFailure> {
        Ok("whpx".to_owned())
    }

    fn status(&self, _socket: &HostPath) -> Result<RunState, MonitorFailure> {
        Ok(RunState::Running)
    }

    fn quit(&mut self, socket: &HostPath) -> Result<(), MonitorFailure> {
        lock(&self.world).quits.push(socket.clone());
        Ok(())
    }
}

pub fn windows_path(path: &str) -> HostPath {
    HostPath::new(PathStyle::Windows, path).unwrap()
}

/// The pinned image's files and the private directory of each VM, on a Windows layout.
pub struct FakeLayout;

impl FakeLayout {
    pub fn inputs_for(vm: VmInstanceId) -> QemuLaunchInputs {
        let hex = vm.digest().to_hex();
        QemuLaunchInputs {
            platform: QemuPlatform {
                os: OsKind::Windows,
                architecture: Architecture::X86_64,
            },
            resources: GuestResources::new(1, GUEST_MEMORY).unwrap(),
            firmware_directory: windows_path(r"C:\Yougori\runtime\qemu\share"),
            kernel: windows_path(r"C:\Yougori\guest\vmlinuz"),
            initrd: Some(windows_path(r"C:\Yougori\guest\initrd")),
            kernel_arguments: KernelArguments::parse("panic=-1 quiet").unwrap(),
            root_image: windows_path(r"C:\Yougori\guest\root.img"),
            volumes: BTreeMap::new(),
            control: PrivateDirectory::new(windows_path(&format!(r"C:\Yougori\vm\{}", &hex[..16])))
                .unwrap(),
            vsock_cid: None,
            egress_endpoints: Vec::new(),
            workload_image: None,
            targets: None,
        }
    }
}

impl LaunchLayout for FakeLayout {
    fn inputs(
        &self,
        request: &crate::sandbox::backend::LaunchRequest,
        vm: VmInstanceId,
    ) -> Result<HostInputs, LayoutRefusal> {
        let mut inputs = Self::inputs_for(vm);
        // As the runtime layout does: the targets the request holds the network card to.
        inputs.targets = request.required.targets.clone();
        Ok(HostInputs {
            inputs,
            guest_image: guest_image(),
        })
    }
}

/// Dials a launch's `link.sock`: the host end of a new wire whose peer is the QEMU process
/// the fake host started for that directory.
pub struct FakeConnector {
    world: SharedWorld,
}

impl LinkConnector for FakeConnector {
    type Stream = Wire;

    fn connect(&mut self, socket: &HostPath) -> io::Result<Wire> {
        let mut world = lock(&self.world);
        world.dialed.push(socket.as_str().to_owned());
        if world.connect_refused {
            return Err(io::Error::from(ErrorKind::ConnectionRefused));
        }
        let index = world
            .launches
            .iter()
            .position(|launch| launch.directory.link_socket() == socket)
            .ok_or_else(|| io::Error::from(ErrorKind::NotFound))?;
        let peer_pid = world.launches[index].process.pid + world.peer_pid_offset;
        let wire = Arc::new(Mutex::new(WireState {
            peer_pid,
            ..WireState::default()
        }));
        world.wires.push((index, Arc::clone(&wire)));
        Ok(Wire(wire))
    }
}

/// The host's process table: the fake host's processes hold their ids.
pub struct FakeProcesses {
    world: SharedWorld,
}

impl ProcessTable for FakeProcesses {
    fn holder_of(&self, pid: u32) -> Result<Option<ProcessIdentity>, ProcessError> {
        let world = lock(&self.world);
        if world.holder_gone {
            return Ok(None);
        }
        Ok(world
            .launches
            .iter()
            .map(|launch| launch.process)
            .find(|process| process.pid == pid))
    }
}

/// The ports of the service under test.
pub struct Fakes;

impl VmPorts for Fakes {
    type Backend = crate::sandbox::qemu::QemuBackend<FakeHost, FakeMonitor, FakeLayout, <TestLedger as super::ServiceLedger<TestClock>>::View>;
    type Clock = TestClock;
    type Host = FakeHost;
    type Monitor = FakeMonitor;
    type Layout = FakeLayout;
    type Ledger = TestLedger;
    type Segments = DurableSegments;
    type Spool = FileSpool;
    type Anchor = NoAnchor;
    type Connector = FakeConnector;
    type Processes = FakeProcesses;
}

pub type TestService = VmService<Fakes>;

/// The hypervisor subject of this fake host: WHPX on the test machine.
pub fn hypervisor_subject() -> HypervisorSubject {
    HypervisorSubject {
        machine: machine(),
        hypervisor: HypervisorKind::Whpx,
    }
}

/// The backend identity of the pinned QEMU build on WHPX.
pub fn backend_identity() -> BackendIdentity {
    BackendIdentity::new(
        BackendKind::Qemu,
        "11.1.0",
        backend_artifact(),
        HypervisorKind::Whpx,
    )
    .unwrap()
}

/// The host's transfer key and ports over the CORE-05 fakes, with the honest issuer.
pub fn transfers(clock: &TestClock) -> BodyTransfers {
    BodyTransfers {
        key: test_key(),
        ports: TransferPorts {
            clock: Arc::clone(clock) as Arc<dyn Clock>,
            clock_session: SESSION,
            authority: Arc::new(FakeAuthority::default()),
            budget: Arc::new(FakeByteLedger::new(1 << 40)),
            extents: Arc::new(FakeExtents::default()),
            progress: Arc::new(FakeProgress::default()),
        },
        authority: Arc::new(Issuer::default()),
    }
}

/// The release's golden file of this fake platform's profile: the golden file of a plan
/// made for a throwaway launch, which is the same for every launch of the profile (the
/// canonical vector replaces every per-launch value).
pub fn golden(clock: &TestClock) -> GoldenFile {
    use crate::foundation::ledger::{
        Admission, Amounts, CostPurpose, Priority, Provenance, Requester, ReservationRequest,
    };
    let mut ledger = crate::sandbox::host::fakes::real_ledger(clock);
    let execution = ExecutionId::new("exe-golden").unwrap();
    let admission = ledger
        .reserve(ReservationRequest::new(
            Provenance {
                requester: Requester::VmLifecycle,
                execution: execution.clone(),
                operation: crate::foundation::ids::OperationId::new("op-golden").unwrap(),
                tenant: tenant(),
                purpose: CostPurpose::VmResources,
                retry_number: 0,
            },
            Priority::Foreground,
            Amounts::new().host_ram_bytes(1 << 30),
        ))
        .unwrap();
    let Admission::Granted(reservation) = admission else {
        panic!("the golden ledger has room");
    };
    let request = crate::sandbox::backend::LaunchRequest {
        execution: execution.clone(),
        tenant: tenant(),
        generations: crate::foundation::coordination::SandboxGenerations::FIRST,
        machine: machine(),
        configuration: config("a"),
        contract: named("yougori/test/vm-service/contract/v1", "terminal-task"),
        pinned: crate::sandbox::backend::PinnedArtifacts {
            guest_image: guest_image(),
            backend: backend_artifact(),
        },
        device_profile: device_profile(),
        required: required(),
        reservation,
    };
    let vm = crate::sandbox::backend::vm_handle(
        BackendKind::Qemu,
        &request.execution,
        request.generations.boot,
    );
    let plan = crate::sandbox::qemu::plan_launch(
        &request,
        &backend_identity(),
        &registry(clock),
        &ledger,
        FakeLayout::inputs_for(vm),
    )
    .unwrap();
    GoldenFile::of(plan.profile(), &backend_identity()).unwrap()
}

pub fn device_profile() -> DeviceProfile {
    DeviceProfile {
        identity: named("yougori/test/vm-service/device-profile/v1", "cpu-only"),
        devices: DeviceExposure::cpu_only(),
    }
}

/// The strictest properties, with the confinement the Windows platform applies.
pub fn required() -> RequiredProperties {
    let mut required = RequiredProperties::strictest(MINUTE);
    required.confinement = QemuPlatform {
        os: OsKind::Windows,
        architecture: Architecture::X86_64,
    }
    .profile()
    .map(|fixed| fixed.confinement_applied())
    .unwrap_or_default();
    required
}

/// The CORE-01 registry of the fakes: the hypervisor probe reports WHPX available and the
/// category probe reports the runtime a VM sandbox, both as host probes.
pub fn registry(clock: &TestClock) -> ProbeRegistry<TestClock> {
    let mut registry = ProbeRegistry::new(Arc::clone(clock));
    let category = Arc::new(FakeProbe::runtime_category(SourceClass::HostProbe));
    let hypervisor = Arc::new(FakeProbe::new(
        Capability::HypervisorAvailable,
        SourceClass::HostProbe,
    ));
    hypervisor.respond(
        &Subject::Hypervisor(hypervisor_subject()),
        Observation::supported(
            config("a"),
            600 * SECOND,
            SupportDetail::Hypervisor {
                hypervisor: HypervisorKind::Whpx,
            },
        ),
    );
    category.respond(
        &Subject::Runtime(runtime()),
        Observation::supported(
            config("a"),
            3_600 * SECOND,
            SupportDetail::RuntimeCategory {
                category: crate::foundation::ids::ExecutionCategory::VmSandbox,
            },
        ),
    );
    registry.register(Box::new(category)).unwrap();
    registry.register(Box::new(hypervisor)).unwrap();
    registry
        .refresh(
            Capability::HypervisorAvailable,
            &Subject::Hypervisor(hypervisor_subject()),
        )
        .unwrap();
    registry
        .refresh(Capability::RuntimeCategory, &Subject::Runtime(runtime()))
        .unwrap();
    registry
}

/// The service's configuration over the fakes.
pub fn service_config(timing: TerminationTiming) -> VmServiceConfig {
    VmServiceConfig {
        supervisor: supervisor_config(timing),
        machine: machine(),
        image: PinnedImage {
            guest_image: guest_image(),
            configuration: config("a"),
        },
        contract: named("yougori/test/vm-service/contract/v1", "terminal-task"),
        device_profile: device_profile(),
        required: required(),
        evidence: EvidenceSubjects {
            runtime: runtime(),
            hypervisor: hypervisor_subject(),
        },
        driver: DriverSettings {
            poll_interval: Duration::from_millis(2),
            wait_slice: Duration::from_millis(5),
            shutdown_grace: Duration::from_secs(1),
            ..DriverSettings::default()
        },
    }
}

/// Everything a test holds: the service, the world the fakes share, the clock and the
/// temporary directory of the audit stream (dropped last).
pub struct Harness {
    pub service: Option<TestService>,
    pub world: SharedWorld,
    pub clock: TestClock,
    pub ledger: TestLedger,
    pub session: ClockSession,
    pub timing: TerminationTiming,
    pub guests: Vec<GuestHandle>,
    _directory: StreamDirectory,
    _dir: tempfile::TempDir,
}

impl Harness {
    pub fn new() -> Self {
        Self::with(TerminationTiming::AfterChannelAcknowledgmentOrBound)
    }

    pub fn with(timing: TerminationTiming) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let clock: TestClock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(
            100 * 1_000_000_000,
        )));
        let world: SharedWorld = Arc::new(Mutex::new(World::default()));
        let ledger: TestLedger =
            Arc::new(Mutex::new(crate::sandbox::host::fakes::real_ledger(&clock)));
        let mut directory = StreamDirectory::durable(dir.path().join("audit"));
        let sink = open_sink(&mut directory, &clock);
        let session = ClockSession::generate();
        let service = Self::build(&clock, &world, &ledger, sink, session, timing);
        Self {
            service: Some(service),
            world,
            clock,
            ledger,
            session,
            timing,
            guests: Vec::new(),
            _directory: directory,
            _dir: dir,
        }
    }

    fn parts(
        clock: &TestClock,
        world: &SharedWorld,
        ledger: &TestLedger,
        sink: AuditSink<DurableSegments, FileSpool, NoAnchor, TestClock>,
        session: ClockSession,
    ) -> VmServiceParts<Fakes> {
        VmServiceParts {
            clock: Arc::clone(clock),
            session,
            registry: registry(clock),
            backend: backend_identity(),
            qemu: QemuSettings {
                executable: windows_path(r"C:\Yougori\runtime\qemu-secure\qemu-system-x86_64.exe"),
                fresh_for: 600 * SECOND,
                golden: golden(clock),
            },
            host: FakeHost::new(world),
            monitor: FakeMonitor {
                world: Arc::clone(world),
            },
            layout: FakeLayout,
            ledger: Arc::clone(ledger),
            sink,
            connector: FakeConnector {
                world: Arc::clone(world),
            },
            processes: FakeProcesses {
                world: Arc::clone(world),
            },
            transfers: transfers(clock),
        }
    }

    fn build(
        clock: &TestClock,
        world: &SharedWorld,
        ledger: &TestLedger,
        sink: AuditSink<DurableSegments, FileSpool, NoAnchor, TestClock>,
        session: ClockSession,
        timing: TerminationTiming,
    ) -> TestService {
        VmService::new(
            Self::parts(clock, world, ledger, sink, session),
            service_config(timing),
        )
        .unwrap()
    }

    pub fn service(&self) -> &TestService {
        self.service.as_ref().unwrap()
    }

    /// Shuts the service down and starts another over the same world, ledger and a fresh
    /// audit stream, recovering from `persisted`, as an engine restart does. The fake host
    /// of the new service holds no process.
    pub fn restart(
        &mut self,
        persisted: crate::sandbox::lifecycle::PersistedSupervisor,
    ) -> Result<super::RecoveryReport, super::RecoverRefusal> {
        if let Some(service) = self.service.take() {
            service.shutdown();
        }
        let session = ClockSession::generate();
        let mut directory = StreamDirectory::durable(self._dir.path().join("audit-2"));
        let sink = open_sink(&mut directory, &self.clock);
        self._directory = directory;
        let (service, report) = VmService::recover(
            Self::parts(&self.clock, &self.world, &self.ledger, sink, session),
            service_config(self.timing),
            persisted,
        )?;
        // As the engine does: the recovered state is stored and confirmed before any
        // lease is issued again.
        let state = service.persist().unwrap();
        service.confirm_persisted(&state);
        self.session = session;
        self.service = Some(service);
        Ok(report)
    }

    pub fn world(&self) -> MutexGuard<'_, World> {
        lock(&self.world)
    }

    pub fn advance(&self, by: Duration) {
        self.clock.advance(by);
    }

    /// Starts a guest for the next launch (the `index`th the fake host starts).
    pub fn guest(&mut self, index: usize, behaviour: Behaviour) -> &GuestHandle {
        let handle = Guest::spawn(Arc::clone(&self.world), index, behaviour);
        self.guests.push(handle);
        self.guests.last().unwrap()
    }

    /// The launch spec every test launches with: 1 GiB of host memory, one CPU slot.
    pub fn spec() -> super::LaunchSpec {
        super::LaunchSpec {
            gpu: false,
            gpu_memory: Vec::new(),
            internet: false,
            targets: None,
            owner_session: false,
            tenant: tenant(),
            resources: super::VmResources {
                memory_bytes: 1 << 30,
                cpu_slots: 1,
            },
            egress_endpoints: Vec::new(),
            workload_image: None,
            idle_limit: None,
            lifetime_limit: None,
            published: Vec::new(),
            connect: Vec::new(),
        }
    }

    /// Waits in real time until `condition` holds, at most [`WAIT`].
    pub fn wait_until(&self, what: &str, mut condition: impl FnMut() -> bool) {
        let started = Instant::now();
        while !condition() {
            assert!(started.elapsed() < WAIT, "timed out waiting for {what}");
            thread::sleep(Duration::from_millis(2));
        }
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        for guest in self.guests.drain(..) {
            guest.stop();
        }
        if let Some(service) = self.service.take() {
            service.shutdown();
        }
    }
}

/// How a guest answers (the Go guest's behaviour, scripted).
#[derive(Clone)]
pub struct Behaviour {
    /// Whether to answer the challenge with a hello at all.
    pub hello: bool,
    /// What a command's input produces: the output and the exit code; `None` leaves the
    /// command running until cancelled.
    pub command: Option<fn(&[u8]) -> (Vec<u8>, i32)>,
    /// Whether a shutdown request powers the guest off (a close frame, then the stream
    /// ends and the process exits).
    pub powers_off: bool,
    /// Credit granted on each terminal open.
    pub credit: u32,
    /// An egress exchange the guest makes after its welcome, if any.
    pub egress: Option<EgressScript>,
    /// A service the guest serves to the host's ingress streams, if any.
    pub ingress: Option<IngressService>,
}

/// A guest service for the host's ingress streams: an open of `listener` is accepted (any
/// other is refused as unavailable, as the agent refuses a port nothing listens on), and
/// once a request's head arrived the service answers `response` and ends its direction.
#[derive(Clone, Copy, Debug)]
pub struct IngressService {
    pub listener: &'static str,
    pub response: &'static [u8],
}

/// One egress exchange the fake guest makes: `delay` after the welcome it opens stream 1 to
/// `destination`, sends `request` and ends its direction, then keeps what the host writes.
#[derive(Clone, Copy, Debug)]
pub struct EgressScript {
    pub destination: &'static str,
    pub request: &'static [u8],
    pub delay: Duration,
}

impl Default for Behaviour {
    fn default() -> Self {
        Self {
            hello: true,
            command: Some(echo),
            powers_off: true,
            credit: 1 << 20,
            egress: None,
            ingress: None,
        }
    }
}

/// The scripted shell: writes `ran: ` and the input back, exit code 0.
pub fn echo(input: &[u8]) -> (Vec<u8>, i32) {
    let mut output = b"ran: ".to_vec();
    output.extend_from_slice(input);
    (output, 0)
}

/// A shell that fails with the input's length as its code.
pub fn fails(input: &[u8]) -> (Vec<u8>, i32) {
    (b"error\n".to_vec(), i32::try_from(input.len()).unwrap_or(1))
}

/// A shell writing 64 KiB.
pub fn chatty(_input: &[u8]) -> (Vec<u8>, i32) {
    (vec![b'x'; 64 * 1024], 0)
}

/// What the guest thread saw.
#[derive(Default, Debug)]
pub struct GuestState {
    pub challenged: bool,
    pub welcomed: bool,
    pub inputs: BTreeMap<u32, Vec<u8>>,
    pub opened: Vec<u32>,
    pub cancelled: Vec<u32>,
    pub shutdown_requests: Vec<u32>,
    pub closed: Option<CloseReason>,
    pub powered_off: bool,
    pub stopped: bool,
    /// The egress script's stream was accepted.
    pub egress_opened: bool,
    /// The egress script's open was refused with this cause.
    pub egress_refused: Option<OpenRefusalCause>,
    /// What the host wrote on the egress stream.
    pub egress_received: Vec<u8>,
    /// The host ended its direction of the egress stream.
    pub egress_ended: bool,
    /// The host cancelled the egress stream.
    pub egress_cancelled: bool,
    /// The ingress streams the guest accepted, the opens it refused, what the host wrote
    /// on each, and the streams the host cancelled.
    pub ingress_opened: Vec<u32>,
    pub ingress_refused: Vec<u32>,
    pub ingress_received: BTreeMap<u32, Vec<u8>>,
    pub ingress_cancelled: Vec<u32>,
    /// The ingress streams whose direction the host ended (its caller finished writing).
    pub ingress_ended: Vec<u32>,
}

pub struct GuestHandle {
    pub state: Arc<Mutex<GuestState>>,
    stop: Arc<Mutex<bool>>,
    thread: Option<JoinHandle<()>>,
}

impl GuestHandle {
    pub fn state(&self) -> MutexGuard<'_, GuestState> {
        lock(&self.state)
    }

    pub fn stop(mut self) {
        *lock(&self.stop) = true;
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// The guest at the far end of the `index`th wire.
struct Guest {
    world: SharedWorld,
    index: usize,
    behaviour: Behaviour,
    state: Arc<Mutex<GuestState>>,
    stop: Arc<Mutex<bool>>,
}

impl Guest {
    fn spawn(world: SharedWorld, index: usize, behaviour: Behaviour) -> GuestHandle {
        let state = Arc::new(Mutex::new(GuestState::default()));
        let stop = Arc::new(Mutex::new(false));
        let guest = Self {
            world,
            index,
            behaviour,
            state: Arc::clone(&state),
            stop: Arc::clone(&stop),
        };
        let thread = thread::Builder::new()
            .name(format!("fake-guest-{index}"))
            .spawn(move || guest.run())
            .unwrap();
        GuestHandle {
            state,
            stop,
            thread: Some(thread),
        }
    }

    fn run(self) {
        // Wait for the launch and its wire.
        let (launch, wire) = loop {
            if *lock(&self.stop) {
                return;
            }
            let world = lock(&self.world);
            let launch = world.launches.get(self.index).cloned();
            let wire = world
                .wires
                .iter()
                .find(|(launch, _)| *launch == self.index)
                .map(|(_, wire)| Arc::clone(wire));
            drop(world);
            if let (Some(launch), Some(wire)) = (launch, wire) {
                break (launch, wire);
            }
            thread::sleep(Duration::from_millis(2));
        };
        let mut end = GuestEnd::new(launch.vm, launch.boot, secret_for(launch.process.pid));
        let mut pending_exits: Vec<(u32, Vec<u8>, i32)> = Vec::new();
        let mut welcomed_at: Option<Instant> = None;
        let mut egress_open_sent = false;
        loop {
            if *lock(&self.stop) {
                lock(&self.state).stopped = true;
                return;
            }
            let bytes = std::mem::take(&mut lock(&wire).to_guest);
            let messages = if bytes.is_empty() {
                Vec::new()
            } else {
                end.read(&[bytes])
            };
            let mut replies: Vec<LinkMessage> = Vec::new();
            if let Some(script) = self.behaviour.egress {
                let due = welcomed_at.is_some_and(|at: Instant| at.elapsed() >= script.delay);
                if due && !egress_open_sent {
                    egress_open_sent = true;
                    // The stream opens with a window of its own each way (protocol 3).
                    replies.push(LinkMessage::Open {
                        stream: StreamId::new(1).unwrap(),
                        open: StreamOpen::Egress {
                            destination: LinkName::new(script.destination).unwrap(),
                        },
                    });
                }
            }
            for message in messages {
                let mut state = lock(&self.state);
                match message {
                    LinkMessage::Challenge { .. } => {
                        state.challenged = true;
                        if self.behaviour.hello {
                            replies.push(LinkMessage::Hello(Hello {
                                guest_version: PROTOCOL_VERSION,
                                agent_build: named("yougori/test/vm-service/agent/v1", "agent"),
                                claimed_vm: None,
                                claimed_boot: None,
                            }));
                        }
                    }
                    LinkMessage::Welcome(_) => {
                        state.welcomed = true;
                        welcomed_at = Some(Instant::now());
                    }
                    LinkMessage::Opened {
                        channel: Channel::Egress,
                        stream,
                    } => {
                        state.egress_opened = true;
                        if let Some(script) = self.behaviour.egress {
                            replies.push(LinkMessage::Data {
                                channel: Channel::Egress,
                                stream,
                                bytes: script.request.to_vec(),
                            });
                            replies.push(LinkMessage::EndOfStream {
                                channel: Channel::Egress,
                                stream,
                            });
                        }
                    }
                    LinkMessage::OpenRefused {
                        channel: Channel::Egress,
                        cause,
                        ..
                    } => state.egress_refused = Some(cause),
                    LinkMessage::Data {
                        channel: Channel::Egress,
                        stream,
                        bytes,
                    } => {
                        // Taken at once: the stream is credited back.
                        replies.push(LinkMessage::StreamWindowUpdate {
                            channel: Channel::Egress,
                            stream,
                            credit_bytes: bytes.len() as u32,
                        });
                        state.egress_received.extend(bytes);
                    }
                    LinkMessage::EndOfStream {
                        channel: Channel::Egress,
                        ..
                    } => state.egress_ended = true,
                    LinkMessage::Cancel {
                        channel: Channel::Egress,
                        ..
                    } => state.egress_cancelled = true,
                    LinkMessage::EndOfStream {
                        channel: Channel::Ingress,
                        stream,
                    } => state.ingress_ended.push(stream.get()),
                    LinkMessage::Open {
                        stream,
                        open: StreamOpen::Ingress { listener },
                    } => match self.behaviour.ingress {
                        Some(service) if listener.as_str() == service.listener => {
                            state.ingress_opened.push(stream.get());
                            replies.push(LinkMessage::Opened {
                                channel: Channel::Ingress,
                                stream,
                            });
                        }
                        _ => {
                            state.ingress_refused.push(stream.get());
                            replies.push(LinkMessage::OpenRefused {
                                channel: Channel::Ingress,
                                stream,
                                cause: OpenRefusalCause::Unavailable,
                            });
                        }
                    },
                    LinkMessage::Data {
                        channel: Channel::Ingress,
                        stream,
                        bytes,
                    } => {
                        // Taken at once: the stream is credited back.
                        replies.push(LinkMessage::StreamWindowUpdate {
                            channel: Channel::Ingress,
                            stream,
                            credit_bytes: bytes.len() as u32,
                        });
                        let received = state.ingress_received.entry(stream.get()).or_default();
                        let complete_before = received.windows(4).any(|w| w == b"\r\n\r\n");
                        received.extend(bytes);
                        let complete = received.windows(4).any(|w| w == b"\r\n\r\n");
                        if let (Some(service), false, true) =
                            (self.behaviour.ingress, complete_before, complete)
                        {
                            replies.push(LinkMessage::Data {
                                channel: Channel::Ingress,
                                stream,
                                bytes: service.response.to_vec(),
                            });
                            replies.push(LinkMessage::EndOfStream {
                                channel: Channel::Ingress,
                                stream,
                            });
                        }
                    }
                    LinkMessage::Cancel {
                        channel: Channel::Ingress,
                        stream,
                        ..
                    } => state.ingress_cancelled.push(stream.get()),
                    LinkMessage::Ping { nonce } => replies.push(LinkMessage::Pong { nonce }),
                    LinkMessage::Open {
                        stream,
                        open: StreamOpen::Terminal { .. },
                    } => {
                        state.opened.push(stream.get());
                        replies.push(LinkMessage::Opened {
                            channel: Channel::Terminal,
                            stream,
                        });
                        replies.push(LinkMessage::WindowUpdate {
                            channel: Channel::Terminal,
                            credit_bytes: self.behaviour.credit,
                        });
                    }
                    LinkMessage::Data {
                        channel: Channel::Terminal,
                        stream,
                        bytes,
                    } => {
                        state.inputs.entry(stream.get()).or_default().extend(bytes);
                    }
                    LinkMessage::EndOfStream {
                        channel: Channel::Terminal,
                        stream,
                    } => {
                        if let Some(command) = self.behaviour.command {
                            let input =
                                state.inputs.get(&stream.get()).cloned().unwrap_or_default();
                            let (output, code) = command(&input);
                            pending_exits.push((stream.get(), output, code));
                        }
                    }
                    LinkMessage::Cancel {
                        channel: Channel::Terminal,
                        stream,
                        ..
                    } => state.cancelled.push(stream.get()),
                    LinkMessage::Shutdown(shutdown) => {
                        state.shutdown_requests.push(shutdown.grace_seconds);
                        if self.behaviour.powers_off {
                            replies.push(LinkMessage::Close {
                                reason: CloseReason::Orderly,
                            });
                            state.powered_off = true;
                        }
                    }
                    LinkMessage::Close { reason } => {
                        state.closed = Some(reason);
                    }
                    _ => {}
                }
            }
            for (stream, output, code) in pending_exits.drain(..) {
                let stream = StreamId::new(stream).unwrap();
                for chunk in output.chunks(16_000) {
                    replies.push(LinkMessage::Data {
                        channel: Channel::Terminal,
                        stream,
                        bytes: chunk.to_vec(),
                    });
                }
                replies.push(LinkMessage::Exit { stream, code });
            }
            let powered_off = lock(&self.state).powered_off;
            if !replies.is_empty() {
                let mut frames = Vec::new();
                for reply in &replies {
                    frames.push(end.frame(reply));
                }
                let mut wire = lock(&wire);
                for frame in frames {
                    wire.to_host.extend(frame);
                }
            }
            if powered_off {
                // The guest powers off: QEMU exits, the stream ends.
                lock(&self.world).exited.insert(launch.process.pid);
                lock(&wire).guest_ended = true;
                lock(&self.state).stopped = true;
                return;
            }
            if lock(&self.state).closed.is_some() {
                lock(&self.state).stopped = true;
                return;
            }
            thread::sleep(Duration::from_millis(2));
        }
    }
}
