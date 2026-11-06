//! Real launches through `QemuBackend` over the Windows host, R2's `QmpMonitor` and
//! `RuntimeLayout`, ignored by default: run one at a time with `--ignored
//! --test-threads=1`. Each starts a local, disposable QEMU/WHPX VM from the staged,
//! checksum-verified copy of the repository's pinned runtime (`R1\runtime`), booting agent
//! G1's guest image, with no network device, no host share and no credential (the
//! profile has none; the link secret is a fresh per-launch bootstrap file). Every VM is
//! stopped by the test or refused and ended by the backend, its private directory removed,
//! and each test checks that no QEMU child of this process, no private directory and no
//! desktop is left. On a refusal the test checks the same before it fails.
//!
//! The forced hardware failure (VM-W22) cannot come from the profile: it renders
//! `-accel whpx,kernel-irqchip=off` whatever the inputs, and `QemuBackend` compares the
//! plan's vector with the golden file before it starts anything. So a test-only host
//! adapter starts the plan with that one argument changed to `kernel-irqchip=split`,
//! which QEMU's WHPX code itself refuses, after the backend approved the plan; the golden
//! file is the plan's.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::tests::{configuration, launch, windows_path, Launch, LaunchValues, GIB, MINUTE};
use super::*;
use crate::foundation::coordination::VmInstanceId;
use crate::foundation::evidence::HypervisorKind;
use crate::foundation::ids::Digest;
use crate::sandbox::backend::{
    vm_handle, Accelerator, BackendKind, ConfinementControl, HostObserved, LaunchRefusal,
    LaunchRequest, Persistence, StopOutcome, VmBackend,
};
use crate::sandbox::qemu::{
    check_windows, plan_launch, GoldenFile, GuestResources, HostInputs, KernelArguments,
    LaunchLayout, LayoutRefusal, QemuBackend, QemuMonitor, QemuPlatform, QemuSettings,
    RestrictingSid, RunState, CHANGE_NOTIFY_PRIVILEGE, LOW_INTEGRITY_RID, MIB_BYTES,
};
use crate::sandbox::qemu_host::layout::{GuestImageFiles, LayoutSettings, RuntimeLayout};
use crate::sandbox::qemu_host::private_dir::{read_sddl, STDERR_LOG_NAME};
use crate::sandbox::qemu_host::qmp::{QmpMonitor, UnixSocketConnect};

/// The staged copy of `src-tauri/resources/runtime/qemu-secure` and `qemu\share`.
const RUNTIME: &str = r"D:\YougoriBuildCache\scratch\m2\R1\runtime";
/// Agent G1's guest image build.
const GUEST: &str = r"D:\YougoriBuildCache\scratch\m2\G1\build\a";
/// G1's kernel arguments for a clean boot.
const KERNEL_ARGUMENTS: &str = "panic=-1 quiet";
/// Where the launches' private directories are made.
const CONTROL_BASE: &str = r"D:\YougoriBuildCache\scratch\m2\Q1\vm";
/// The guest's memory, as G1's boots used.
const GUEST_MEMORY_MIB: u64 = 256;
/// The VM reservation's host RAM, the job's memory limit.
const RESERVED_RAM_BYTES: u64 = GIB;
/// The version QEMU's QMP greeting reports for the pinned build.
const QEMU_VERSION: &str = "11.1.0";

fn sha256_of(path: &Path) -> Digest {
    use sha2::{Digest as _, Sha256};
    let bytes = std::fs::read(path).unwrap();
    Digest::from_bytes(Sha256::digest(&bytes).into())
}

/// One real launch's inputs: the request and evidence, the layout over the staged runtime
/// and G1's image, the plan the backend will make and the golden file of its profile.
struct Real {
    launch: Launch,
    layout: RuntimeLayout,
    vm: VmInstanceId,
    plan: QemuLaunchPlan,
    golden: GoldenFile,
    executable: HostPath,
}

fn real(execution: &str, kernel: Option<HostPath>) -> Real {
    let guest = Path::new(GUEST);
    let root_image = guest.join("root.img");
    let executable_path = Path::new(RUNTIME)
        .join("qemu-secure")
        .join("qemu-system-x86_64.exe");
    let guest_image = sha256_of(&root_image);
    let launch = launch(LaunchValues {
        os: OsKind::Windows,
        execution,
        guest_image,
        artifact: sha256_of(&executable_path),
        version: QEMU_VERSION,
        reserved_ram_bytes: RESERVED_RAM_BYTES,
        persistence: Persistence::EphemeralTask,
    });
    std::fs::create_dir_all(CONTROL_BASE).unwrap();
    let file = |name: &str| windows_path(guest.join(name).to_str().unwrap());
    let layout = RuntimeLayout::new(LayoutSettings {
        runtime_directory: windows_path(RUNTIME),
        platform: QemuPlatform {
            os: OsKind::Windows,
            architecture: Architecture::X86_64,
        },
        resources: GuestResources::new(1, GUEST_MEMORY_MIB * MIB_BYTES).unwrap(),
        images: [(
            guest_image,
            GuestImageFiles {
                kernel: file("vmlinuz"),
                initrd: Some(file("initrd")),
                root_image: file("root.img"),
                kernel_arguments: KernelArguments::parse(KERNEL_ARGUMENTS).unwrap(),
            },
        )]
        .into_iter()
        .collect(),
        volumes: BTreeMap::new(),
        control_base: windows_path(CONTROL_BASE),
        logon_sid: Some(HostSids::current().unwrap().logon().clone()),
    })
    .unwrap();
    let vm = vm_handle(
        BackendKind::Qemu,
        &launch.request.execution,
        launch.request.generations.boot,
    );
    let HostInputs { mut inputs, .. } = layout.inputs(&launch.request, vm).unwrap();
    if let Some(kernel) = kernel {
        inputs.kernel = kernel;
    }
    let plan = plan_launch(
        &launch.request,
        &launch.backend,
        &launch.registry,
        &launch.ledger,
        inputs,
    )
    .unwrap();
    let golden = GoldenFile::of(plan.profile(), &launch.backend).unwrap();
    let executable = layout.executable().clone();
    Real {
        launch,
        layout,
        vm,
        plan,
        golden,
        executable,
    }
}

fn settings(real: &Real) -> QemuSettings {
    QemuSettings {
        executable: real.executable.clone(),
        fresh_for: Duration::from_secs(600),
        golden: real.golden.clone(),
    }
}

fn monitor() -> QmpMonitor<UnixSocketConnect> {
    QmpMonitor::new(UnixSocketConnect {
        timeouts: SocketTimeouts::new(Duration::from_secs(5), Duration::from_secs(5)).unwrap(),
    })
}

fn windows_host() -> WindowsQemuHost {
    WindowsQemuHost::new(WindowsHostSettings::standard().unwrap())
}

#[link(name = "user32", kind = "raw-dylib")]
extern "system" {
    fn OpenDesktopW(
        name: *const u16,
        flags: u32,
        inherit: i32,
        access: u32,
    ) -> *mut core::ffi::c_void;
    fn CloseDesktop(desktop: *mut core::ffi::c_void) -> i32;
}

/// Whether a desktop of this name exists on this window station. The host closed its own
/// handle when the start returned, so it exists only while a process is on it.
fn desktop_exists(name: &str) -> bool {
    let wide: Vec<u16> = name.encode_utf16().chain([0]).collect();
    // SAFETY: the name is NUL-terminated; DESKTOP_READOBJECTS (1) only.
    let handle = unsafe { OpenDesktopW(wide.as_ptr(), 0, 0, 1) };
    if handle.is_null() {
        return false;
    }
    // SAFETY: the handle came from OpenDesktopW and is closed once.
    unsafe { CloseDesktop(handle) };
    true
}

/// The QEMU processes this test process started that still exist.
fn qemu_children() -> Vec<u32> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    // SAFETY: a process snapshot of the whole system; closed below.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    assert_ne!(snapshot, INVALID_HANDLE_VALUE);
    let mut entry = PROCESSENTRY32W {
        dwSize: u32::try_from(std::mem::size_of::<PROCESSENTRY32W>()).unwrap(),
        ..PROCESSENTRY32W::default()
    };
    let mut found = Vec::new();
    // SAFETY: the snapshot is open and the entry's size is set.
    let mut more = unsafe { Process32FirstW(snapshot, &mut entry) } != 0;
    while more {
        let length = entry
            .szExeFile
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(entry.szExeFile.len());
        let name = String::from_utf16_lossy(&entry.szExeFile[..length]);
        if entry.th32ParentProcessID == std::process::id()
            && name.eq_ignore_ascii_case("qemu-system-x86_64.exe")
        {
            found.push(entry.th32ProcessID);
        }
        // SAFETY: as above.
        more = unsafe { Process32NextW(snapshot, &mut entry) } != 0;
    }
    // SAFETY: the snapshot handle is closed once.
    unsafe { CloseHandle(snapshot) };
    found
}

/// Nothing of the launch is left: no private directory, no QEMU child, nothing held.
fn assert_nothing_left<H: QemuHost, M, L, R>(backend: &QemuBackend<H, M, L, R>, control: &Path)
where
    M: QemuMonitor,
    L: LaunchLayout,
    R: crate::sandbox::qemu::ReservationView,
{
    assert!(!control.exists(), "{} is left", control.display());
    assert_eq!(qemu_children(), Vec::<u32>::new());
    assert!(backend.running().is_empty());
}

fn control_of(real: &Real) -> PathBuf {
    PathBuf::from(real.plan.profile().control().path().as_str())
}

#[test]
#[ignore = "boots a local QEMU/WHPX VM; run with --ignored"]
fn a_restricted_qemu_boots_the_guest_on_whpx_and_stops_leaving_nothing() {
    let real = real("exe-q1-boot", None);
    let control = control_of(&real);
    assert!(
        !control.exists(),
        "{} exists before the launch",
        control.display()
    );
    let request: LaunchRequest = real.launch.request.clone();
    let mut backend = QemuBackend::new(
        real.launch.backend.clone(),
        settings(&real),
        windows_host(),
        monitor(),
        real.layout.clone(),
        &real.launch.ledger,
    );
    let began = Instant::now();
    let launched = backend.launch(&request, &real.launch.registry);
    let launch_took = began.elapsed();
    let launched = match launched {
        Ok(launched) => launched,
        Err(refusal) => {
            eprintln!(
                "refused after {launch_took:?}: {}",
                serde_json::to_string_pretty(&refusal).unwrap()
            );
            eprintln!("cleanup failures: {:?}", backend.host().cleanup_failures());
            assert_nothing_left(&backend, &control);
            panic!("the launch was refused: {refusal}");
        }
    };
    assert_eq!(launched.vm, real.vm);
    let process = backend.process_of(&real.vm).unwrap();
    let host = backend.host();
    eprintln!(
        "launched {process} in {launch_took:?}; QMP accepted after {:?}",
        host.qmp_answered_after(&process).unwrap()
    );

    // The host's own observation of the running process.
    let inspection = host.inspect(&process).unwrap();
    assert_eq!(inspection.state, ProcessState::Running);
    assert_eq!(inspection.command_line[0], real.executable.as_str());
    assert_eq!(inspection.command_line[1..], real.plan.profile().argv()[..]);
    let state = inspection.windows.clone().unwrap();
    eprintln!(
        "observed: {}",
        serde_json::to_string_pretty(&state).unwrap()
    );
    assert!(state.token_restricted);
    assert_eq!(state.integrity_rid, LOW_INTEGRITY_RID);
    assert_eq!(
        state.restricting_sids,
        [
            RestrictingSid::Users,
            RestrictingSid::Everyone,
            RestrictingSid::Restricted,
            RestrictingSid::LogonSession,
            RestrictingSid::AuthenticatedUsers
        ]
        .into_iter()
        .collect()
    );
    assert_eq!(
        state.privileges,
        [CHANGE_NOTIFY_PRIVILEGE.to_owned()].into_iter().collect()
    );
    assert_eq!(
        state.job.as_ref().unwrap().job_memory_limit_bytes,
        RESERVED_RAM_BYTES
    );
    let now = real.launch.registry.now();
    let check = check_windows(
        real.plan.windows().unwrap(),
        &HostObserved::stamp(state, now, Duration::from_secs(600), configuration()),
        now,
        MINUTE,
        configuration(),
    )
    .unwrap();
    eprintln!(
        "check_windows: passed {}, findings {:?}, controls {:?}",
        check.passed(),
        check.findings(),
        check.controls_observed()
    );
    assert!(check.passed());

    // Its own desktop, alive only because QEMU is on it.
    let desktop = host.desktop_of(&process).unwrap().to_owned();
    assert!(desktop_exists(&desktop), "desktop {desktop} not found");
    eprintln!("desktop {desktop} exists while QEMU runs");

    // The accelerator QEMU reports through QMP, and its run state.
    let socket = real.plan.profile().control().qmp_socket().clone();
    assert_eq!(
        *backend.actual_accelerator(&real.vm).unwrap().value(),
        Accelerator::Hardware {
            hypervisor: HypervisorKind::Whpx
        }
    );
    let asked = Instant::now();
    assert_eq!(backend.monitor().accelerator(&socket).unwrap(), "whpx");
    assert_eq!(
        backend.monitor().status(&socket).unwrap(),
        RunState::Running
    );
    eprintln!("QMP: whpx, running ({:?} for both)", asked.elapsed());

    // The sealed launch record binds what was observed.
    let record = &launched.record;
    assert_eq!(record.vm(), real.vm);
    let confinement = record.host_observed().confinement.value().unwrap();
    assert_eq!(
        *confinement,
        [
            ConfinementControl::ProcessIdentity,
            ConfinementControl::FilesystemLimits,
            ConfinementControl::OsRestrictions,
            ConfinementControl::ResourceControls
        ]
        .into_iter()
        .collect()
    );
    eprintln!(
        "launch record {} sealed; host build {:?}; checks {:?}",
        record.identity(),
        record.host_observed().host.value(),
        record.checks()
    );

    // The private directory as it stands, and QEMU's log so far.
    eprintln!("private directory: {}", read_sddl(&control).unwrap());
    eprintln!(
        "QEMU's standard error so far: {:?}",
        std::fs::read_to_string(control.join(STDERR_LOG_NAME)).unwrap()
    );

    // The bootstrap secret, once.
    assert!(backend.host_mut().take_secret(&process).is_some());
    assert!(backend.host_mut().take_secret(&process).is_none());

    // The link socket is QEMU's: its peer is the QEMU process. Held open across the stop,
    // so the guest does not see the link lost; nothing is sent on it.
    let link = connect(
        Path::new(real.plan.profile().control().link_socket().as_str()),
        SocketTimeouts::new(Duration::from_secs(5), Duration::from_secs(5)).unwrap(),
    )
    .unwrap();
    assert_eq!(link.peer_process_id().unwrap(), process.pid);
    eprintln!("link.sock peer is process {}", process.pid);

    let stopping = Instant::now();
    assert_eq!(backend.stop(&real.vm).unwrap(), StopOutcome::Stopped);
    let stop_took = stopping.elapsed();
    let proof = backend.termination(&real.vm).unwrap().clone();
    drop(link);
    eprintln!(
        "stopped in {stop_took:?}: proof of {} ({}), exit code {}, {:?}, {} job process(es), \
         observed after {:?}",
        proof.identity(),
        proof.role(),
        proof.exit_code(),
        proof.ending(),
        proof.job_processes(),
        proof.elapsed()
    );
    assert_eq!(proof.identity(), process);
    assert_eq!(
        proof.role(),
        &ProcessRole::VmHost {
            execution: request.execution.clone(),
            vm: real.vm,
            boot: request.generations.boot,
        }
    );
    assert_nothing_left(&backend, &control);
    assert!(!desktop_exists(&desktop), "desktop {desktop} is left");
    // QEMU no longer runs. Whether its PID is already free is not asserted: another
    // program of the host (an antivirus scanning a new process, here) may hold the ended
    // process's object a moment longer, and the product never relies on it.
    assert!(!process.running().unwrap(), "{process} still runs");
    assert!(backend.host().cleanup_failures().is_empty());
    assert!(backend.host().held().is_empty());
}

/// The host, with the accelerator argument of every start changed to one QEMU's WHPX code
/// refuses. Records each vector it started.
struct ForcedSplitIrqchip {
    inner: WindowsQemuHost,
    starts: Vec<Vec<String>>,
}

const PROFILE_ACCELERATOR: &str = "whpx,kernel-irqchip=off";
const REFUSED_ACCELERATOR: &str = "whpx,kernel-irqchip=split";

impl QemuHost for ForcedSplitIrqchip {
    type Proof = TerminationProof;

    fn start(
        &mut self,
        role: &ProcessRole,
        executable: &HostPath,
        plan: &QemuLaunchPlan,
    ) -> Result<ProcessIdentity, StartFailure> {
        let arguments: Vec<String> = plan
            .profile()
            .argv()
            .into_iter()
            .map(|argument| {
                if argument == PROFILE_ACCELERATOR {
                    REFUSED_ACCELERATOR.to_owned()
                } else {
                    argument
                }
            })
            .collect();
        assert!(arguments
            .iter()
            .any(|argument| argument == REFUSED_ACCELERATOR));
        self.starts.push(arguments.clone());
        self.inner
            .start_arguments(role, executable, plan, arguments)
    }

    fn state(&self, process: &ProcessIdentity) -> Result<ProcessState, ObserveFailure> {
        self.inner.state(process)
    }

    fn inspect(&self, process: &ProcessIdentity) -> Result<ProcessInspection, ObserveFailure> {
        self.inner.inspect(process)
    }

    fn host_build(&self) -> Result<HostBuild, ObserveFailure> {
        self.inner.host_build()
    }

    fn terminate(&mut self, process: &ProcessIdentity) -> Result<TerminationProof, NoProof> {
        self.inner.terminate(process)
    }
}

#[test]
#[ignore = "boots a local QEMU/WHPX VM; run with --ignored"]
fn a_forced_whpx_failure_is_refused_without_emulation_and_leaves_nothing() {
    let real = real("exe-q1-forced", None);
    let control = control_of(&real);
    assert!(!control.exists());
    let mut backend = QemuBackend::new(
        real.launch.backend.clone(),
        settings(&real),
        ForcedSplitIrqchip {
            inner: windows_host(),
            starts: Vec::new(),
        },
        monitor(),
        real.layout.clone(),
        &real.launch.ledger,
    );
    let began = Instant::now();
    let refused = backend.launch(&real.launch.request, &real.launch.registry);
    let took = began.elapsed();
    eprintln!("after {took:?}: {refused:?}");
    match refused {
        Err(LaunchRefusal::HardwareVirtualizationFailed { failure }) => {
            assert_eq!(failure.hypervisor, HypervisorKind::Whpx);
            assert!(
                failure
                    .detail
                    .contains("WHPX: split irqchip currently not supported"),
                "{}",
                failure.detail
            );
        }
        other => panic!("not a hardware virtualization refusal: {other:?}"),
    }
    // One start, of a vector naming no emulator; nothing retried.
    let starts = &backend.host().starts;
    assert_eq!(starts.len(), 1);
    assert!(!starts[0]
        .iter()
        .any(|argument| argument.to_ascii_lowercase().contains("tcg")));
    assert!(backend.host().inner.held().is_empty());
    assert!(backend.host().inner.cleanup_failures().is_empty());
    assert_nothing_left(&backend, &control);
}

/// The layout, naming a kernel that does not exist.
struct MissingKernel {
    inner: RuntimeLayout,
    kernel: HostPath,
}

impl LaunchLayout for MissingKernel {
    fn inputs(
        &self,
        request: &LaunchRequest,
        vm: VmInstanceId,
    ) -> Result<HostInputs, LayoutRefusal> {
        let mut found = self.inner.inputs(request, vm)?;
        found.inputs.kernel = self.kernel.clone();
        Ok(found)
    }
}

#[test]
#[ignore = "boots a local QEMU/WHPX VM; run with --ignored"]
fn a_qemu_that_cannot_load_its_kernel_is_refused_and_leaves_nothing() {
    let absent = windows_path(&format!(r"{CONTROL_BASE}\absent-vmlinuz"));
    assert!(!Path::new(absent.as_str()).exists());
    let real = real("exe-q1-no-kernel", Some(absent.clone()));
    let control = control_of(&real);
    assert!(!control.exists());
    let mut backend = QemuBackend::new(
        real.launch.backend.clone(),
        settings(&real),
        windows_host(),
        monitor(),
        MissingKernel {
            inner: real.layout.clone(),
            kernel: absent,
        },
        &real.launch.ledger,
    );
    let began = Instant::now();
    let refused = backend.launch(&real.launch.request, &real.launch.registry);
    let took = began.elapsed();
    eprintln!("after {took:?}: {refused:?}");
    match refused {
        Err(LaunchRefusal::CreateFailed { detail }) => {
            assert!(detail.contains("kernel"), "{detail}");
        }
        other => panic!("not a create failure: {other:?}"),
    }
    assert!(backend.host().held().is_empty());
    assert!(backend.host().cleanup_failures().is_empty());
    assert_nothing_left(&backend, &control);
}
