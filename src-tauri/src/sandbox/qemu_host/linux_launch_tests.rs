//! Real launches through `QemuBackend` over the Linux host, `QmpMonitor` and
//! `RuntimeLayout`, ignored by default: run one at a time, as root, with `--ignored
//! --test-threads=1` in the disposable WSL distro of 31 October 2026
//! (`Yougori-Agent1-Disposable-Build`). Each starts a local, disposable QEMU/KVM VM from the
//! pinned Linux build (Alpine's `qemu-system-x86_64` 11.0.3-r0, checksum-verified and
//! staged under [`RUNTIME`] by the scratch scripts), booting the pinned sandbox guest, with
//! no network device, no host share and no credential (the profile has none; the link
//! secret is a fresh per-launch bootstrap file). QEMU runs as `nobody` with the KVM
//! device's group, in a cgroup of its own beneath `yougori-test`. Every VM is stopped by
//! the test or refused and ended by the backend, its private directory and group removed,
//! and each test checks that no QEMU child of this process, no private directory and no
//! group is left. On a refusal the test checks the same before it fails.
//!
//! The forced hardware failure (VM-W22) is QEMU's own: the host gives QEMU's account no
//! group that grants the KVM device, so QEMU cannot open it and says so; the backend
//! refuses the launch and nothing retries into emulation. The crash test runs this test
//! binary again as a helper engine that launches a VM and aborts, and checks the next
//! host ends what it left.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use super::super::launch_fixture::{configuration, launch, Launch, LaunchValues, GIB, MINUTE};
use super::*;
use crate::foundation::coordination::VmInstanceId;
use crate::foundation::evidence::HypervisorKind;
use crate::foundation::ids::Digest;
use crate::sandbox::backend::{
    vm_handle, Accelerator, BackendKind, HostObserved, LaunchRefusal, LaunchRequest, Persistence,
    StopOutcome, VmBackend,
};
use crate::sandbox::qemu::{
    check_linux, plan_launch, GoldenFile, GuestResources, HostInputs, KernelArguments,
    LaunchLayout, LayoutRefusal, QemuBackend, QemuMonitor, QemuPlatform, QemuSettings, RunState,
    LINUX_CONTROLS, MIB_BYTES,
};
use crate::sandbox::qemu_host::layout::{GuestImageFiles, LayoutSettings, RuntimeLayout};
use crate::sandbox::qemu_host::qmp::{QmpMonitor, UnixSocketConnect};

/// The pinned Linux QEMU, staged as the runtime layout names it: `qemu-secure/` holds the
/// executable (its interpreter and library path set to its own `lib/`), `qemu/share/` the
/// firmware.
const RUNTIME: &str = "/opt/yougori-agent1/runtime";
/// The pinned sandbox guest: the appliance kernel, the guest's initrd and root image.
const GUEST: &str = "/opt/yougori-agent1/guest";
/// The guest's kernel arguments for a clean boot.
const KERNEL_ARGUMENTS: &str = "panic=-1 quiet";
/// Where the launches' private directories are made.
const CONTROL_BASE: &str = "/opt/yougori-agent1/vm";
/// The guest's memory.
const GUEST_MEMORY_MIB: u64 = 256;
/// The VM reservation's host RAM, the group's memory limit.
const RESERVED_RAM_BYTES: u64 = GIB;
/// The version QEMU's QMP greeting reports for the pinned build.
const QEMU_VERSION: &str = "11.0.3";
/// The account QEMU runs as: `nobody` and `nogroup`.
const QEMU_ACCOUNT: u32 = 65534;
/// The groups' base beneath the cgroup mount, as the process handle's tests use.
const CGROUP_BASE: &str = "yougori-test";
/// Set for the crash test's helper engine.
const CRASH_HELPER: &str = "YOUGORI_LINUX_CRASH_HELPER";

fn use_test_base() {
    std::env::set_var("YOUGORI_CGROUP_BASE", CGROUP_BASE);
}

fn unix_path(path: &str) -> HostPath {
    HostPath::new(PathStyle::Unix, path).unwrap()
}

fn sha256_of(path: &Path) -> Digest {
    use sha2::{Digest as _, Sha256};
    let bytes = std::fs::read(path).unwrap();
    Digest::from_bytes(Sha256::digest(&bytes).into())
}

/// One real launch's inputs: the request and evidence, the layout over the staged runtime
/// and the guest, the plan the backend will make and the golden file of its profile.
struct Real {
    launch: Launch,
    layout: RuntimeLayout,
    vm: VmInstanceId,
    plan: QemuLaunchPlan,
    golden: GoldenFile,
    executable: HostPath,
}

fn real(execution: &str, kernel: Option<HostPath>) -> Real {
    use_test_base();
    let guest = Path::new(GUEST);
    let root_image = guest.join("root.img");
    let executable_path = Path::new(RUNTIME)
        .join("qemu-secure")
        .join("qemu-system-x86_64");
    let guest_image = sha256_of(&root_image);
    let launch = launch(LaunchValues {
        os: OsKind::Linux,
        execution,
        guest_image,
        artifact: sha256_of(&executable_path),
        version: QEMU_VERSION,
        reserved_ram_bytes: RESERVED_RAM_BYTES,
        persistence: Persistence::EphemeralTask,
    });
    std::fs::create_dir_all(CONTROL_BASE).unwrap();
    let file = |name: &str| unix_path(guest.join(name).to_str().unwrap());
    let layout = RuntimeLayout::new(LayoutSettings {
        runtime_directory: unix_path(RUNTIME),
        platform: QemuPlatform {
            os: OsKind::Linux,
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
        control_base: unix_path(CONTROL_BASE),
        logon_sid: None,
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

fn nobody() -> RunAs {
    RunAs {
        uid: QEMU_ACCOUNT,
        gid: QEMU_ACCOUNT,
        groups: Vec::new(),
    }
}

fn linux_host() -> LinuxQemuHost {
    LinuxQemuHost::new(LinuxHostSettings::standard(Some(nobody())).unwrap())
}

/// The QEMU processes this test process started that still exist (zombies included).
fn qemu_children() -> Vec<u32> {
    let own = std::process::id();
    let mut found = Vec::new();
    for entry in std::fs::read_dir("/proc").unwrap().filter_map(Result::ok) {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
            continue;
        };
        let Some((name, rest)) = stat
            .split_once(" (")
            .and_then(|(_, rest)| rest.rsplit_once(") "))
        else {
            continue;
        };
        let parent = rest
            .split_whitespace()
            .nth(1)
            .and_then(|value| value.parse::<u32>().ok());
        if parent == Some(own) && name.starts_with("qemu-system") {
            found.push(pid);
        }
    }
    found
}

/// The groups beneath the test base this process created that are still there.
fn own_groups() -> Vec<String> {
    let prefix = format!("p-{}-", std::process::id());
    std::fs::read_dir(Path::new("/sys/fs/cgroup").join(CGROUP_BASE))
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .filter(|name| name.starts_with(&prefix))
                .collect()
        })
        .unwrap_or_default()
}

/// Nothing of the launch is left: no private directory, no QEMU child, no group, nothing
/// held.
fn assert_nothing_left<H: QemuHost, M, L, R>(backend: &QemuBackend<H, M, L, R>, control: &Path)
where
    M: QemuMonitor,
    L: LaunchLayout,
    R: crate::sandbox::qemu::ReservationView,
{
    assert!(!control.exists(), "{} is left", control.display());
    assert_eq!(qemu_children(), Vec::<u32>::new());
    assert_eq!(own_groups(), Vec::<String>::new());
    assert!(backend.running().is_empty());
}

fn control_of(real: &Real) -> PathBuf {
    PathBuf::from(real.plan.profile().control().path().as_str())
}

#[test]
#[ignore = "boots a local QEMU/KVM VM as root in the disposable distro; run with --ignored"]
fn a_confined_qemu_boots_the_guest_on_kvm_and_stops_leaving_nothing() {
    let real = real("exe-q1-linux-boot", None);
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
        linux_host(),
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
    eprintln!("launched {process} in {launch_took:?}");

    // The host's own observation of the running process.
    let host = backend.host();
    let inspection = host.inspect(&process).unwrap();
    assert_eq!(inspection.state, ProcessState::Running);
    assert_eq!(inspection.command_line[0], real.executable.as_str());
    assert_eq!(inspection.command_line[1..], real.plan.profile().argv()[..]);
    let state = inspection.linux.clone().unwrap();
    eprintln!(
        "observed: {}",
        serde_json::to_string_pretty(&state).unwrap()
    );
    assert_eq!(state.status.uid.real, QEMU_ACCOUNT);
    assert_eq!(state.status.gid.real, QEMU_ACCOUNT);
    assert!(state.status.no_new_privs);
    assert_eq!(state.memory_max, Some(RESERVED_RAM_BYTES));
    assert!(state
        .cgroup
        .starts_with(&format!("/{CGROUP_BASE}/p-{}-", std::process::id())));
    assert_eq!(
        state.network_interfaces,
        ["lo".to_owned()].into_iter().collect()
    );
    let now = real.launch.registry.now();
    let check = check_linux(
        real.plan.linux().unwrap(),
        &HostObserved::stamp(state, now, Duration::from_secs(600), configuration()),
        now,
        MINUTE,
        configuration(),
    )
    .unwrap();
    eprintln!(
        "check_linux: passed {}, findings {:?}, controls {:?}",
        check.passed(),
        check.findings(),
        check.controls_observed()
    );
    assert!(check.passed());

    // The private directory and the bootstrap file belong to QEMU's account alone.
    let directory = std::fs::metadata(&control).unwrap();
    assert_eq!(directory.uid(), QEMU_ACCOUNT);
    assert_eq!(directory.permissions().mode() & 0o777, 0o700);
    let secret = std::fs::metadata(control.join(crate::sandbox::qemu::LINK_SECRET_NAME)).unwrap();
    assert_eq!(secret.uid(), QEMU_ACCOUNT);
    assert_eq!(secret.permissions().mode() & 0o777, 0o400);

    // The accelerator QEMU reports through QMP, and its run state.
    let socket = real.plan.profile().control().qmp_socket().clone();
    assert_eq!(
        *backend.actual_accelerator(&real.vm).unwrap().value(),
        Accelerator::Hardware {
            hypervisor: HypervisorKind::Kvm
        }
    );
    let asked = Instant::now();
    assert_eq!(backend.monitor().accelerator(&socket).unwrap(), "kvm");
    assert_eq!(
        backend.monitor().status(&socket).unwrap(),
        RunState::Running
    );
    eprintln!("QMP: kvm, running ({:?} for both)", asked.elapsed());

    // The sealed launch record binds what was observed.
    let record = &launched.record;
    assert_eq!(record.vm(), real.vm);
    let confinement = record.host_observed().confinement.value().unwrap();
    assert_eq!(*confinement, LINUX_CONTROLS.into_iter().collect());
    eprintln!(
        "launch record {} sealed; host build {:?}; checks {:?}",
        record.identity(),
        record.host_observed().host.value(),
        record.checks()
    );
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
        "stopped in {stop_took:?}: proof of {} ({}), exit code {}, {:?}, {} group process(es), \
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
    // QEMU no longer runs. Whether its PID is already free is not asserted: another
    // program of the host (an antivirus scanning a new process, here) may hold the ended
    // process's object a moment longer, and the product never relies on it.
    assert!(!process.running().unwrap(), "{process} still runs");
    assert!(backend.host().cleanup_failures().is_empty());
    assert!(backend.host().held().is_empty());
}

#[test]
#[ignore = "boots a local QEMU/KVM VM as root in the disposable distro; run with --ignored"]
fn a_forced_kvm_failure_is_refused_without_emulation_and_leaves_nothing() {
    let device = std::fs::metadata("/dev/kvm").unwrap();
    assert_eq!(
        device.permissions().mode() & 0o006,
        0,
        "/dev/kvm grants others access here, so QEMU's account cannot be kept from it"
    );
    assert_ne!(device.gid(), QEMU_ACCOUNT);
    let real = real("exe-q1-linux-forced", None);
    let control = control_of(&real);
    assert!(!control.exists());
    let mut settings_without_kvm = LinuxHostSettings::standard(Some(nobody())).unwrap();
    settings_without_kvm.kvm_group = None;
    let mut backend = QemuBackend::new(
        real.launch.backend.clone(),
        settings(&real),
        LinuxQemuHost::new(settings_without_kvm),
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
            assert_eq!(failure.hypervisor, HypervisorKind::Kvm);
            assert!(
                failure.detail.contains("KVM") || failure.detail.contains("kvm"),
                "{}",
                failure.detail
            );
        }
        other => panic!("not a hardware virtualization refusal: {other:?}"),
    }
    // The vector named no emulator, and nothing was retried.
    assert!(!real
        .plan
        .profile()
        .argv()
        .iter()
        .any(|argument| argument.to_ascii_lowercase().contains("tcg")));
    assert!(backend.host().held().is_empty());
    assert!(backend.host().cleanup_failures().is_empty());
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
#[ignore = "boots a local QEMU/KVM VM as root in the disposable distro; run with --ignored"]
fn a_qemu_that_cannot_load_its_kernel_is_refused_and_leaves_nothing() {
    let absent = unix_path(&format!("{CONTROL_BASE}/absent-vmlinuz"));
    assert!(!Path::new(absent.as_str()).exists());
    let real = real("exe-q1-linux-no-kernel", Some(absent.clone()));
    let control = control_of(&real);
    assert!(!control.exists());
    let mut backend = QemuBackend::new(
        real.launch.backend.clone(),
        settings(&real),
        linux_host(),
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

/// The crash test's helper engine: launches a VM, reports its QEMU and private directory,
/// and aborts without ending anything. Does nothing unless [`CRASH_HELPER`] is set.
#[test]
#[ignore = "the crash test's helper; run by that test"]
fn crash_helper_launches_and_aborts() {
    if std::env::var_os(CRASH_HELPER).is_none() {
        return;
    }
    let real = real("exe-q1-linux-crash", None);
    let mut backend = QemuBackend::new(
        real.launch.backend.clone(),
        settings(&real),
        linux_host(),
        monitor(),
        real.layout.clone(),
        &real.launch.ledger,
    );
    backend
        .launch(&real.launch.request, &real.launch.registry)
        .unwrap();
    let process = backend.process_of(&real.vm).unwrap();
    let membership = std::fs::read_to_string(format!("/proc/{}/cgroup", process.pid)).unwrap();
    let group = membership
        .trim()
        .strip_prefix(&format!("0::/{CGROUP_BASE}/"))
        .unwrap_or_else(|| panic!("QEMU is not beneath the base: {membership}"))
        .to_owned();
    let mut out = std::io::stdout().lock();
    writeln!(
        out,
        "CRASH-HELPER {} {} {} {group}",
        process.pid,
        process.start_time_ticks,
        control_of(&real).display()
    )
    .unwrap();
    out.flush().unwrap();
    std::process::abort();
}

/// PROVES QEMU ends with the engine that started it, however the engine ended (here it
/// aborts): the parent-death signal, the declared OS fallback; and the next host removes
/// the group the dead engine left, found by the dead host's identity.
#[test]
#[ignore = "boots a local QEMU/KVM VM as root in the disposable distro; run with --ignored"]
fn a_qemu_ends_with_its_engine_and_the_next_host_removes_its_group() {
    use_test_base();
    let helper = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "sandbox::qemu_host::linux_host::launch_tests::crash_helper_launches_and_aborts",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CRASH_HELPER, "1")
        .output()
        .unwrap();
    use std::os::unix::process::ExitStatusExt;
    let stdout = String::from_utf8_lossy(&helper.stdout);
    assert_eq!(
        helper.status.signal(),
        Some(libc::SIGABRT),
        "the helper did not abort: {stdout} {}",
        String::from_utf8_lossy(&helper.stderr)
    );
    // The report may follow the test harness's `test ... ` on the same line.
    let line = stdout
        .lines()
        .find_map(|line| line.split_once("CRASH-HELPER ").map(|(_, report)| report))
        .unwrap_or_else(|| panic!("no report from the helper: {stdout}"));
    let mut fields = line.split(' ');
    let qemu = ProcessIdentity {
        pid: fields.next().unwrap().parse().unwrap(),
        start_time_ticks: fields.next().unwrap().parse().unwrap(),
    };
    let control = PathBuf::from(fields.next().unwrap());
    let group = fields.next().unwrap().to_owned();
    // The engine is gone, and its QEMU with it.
    let began = Instant::now();
    while qemu.running().unwrap() {
        assert!(began.elapsed() < Duration::from_secs(5), "QEMU outlived its engine");
        std::thread::sleep(Duration::from_millis(5));
    }
    eprintln!(
        "the dead engine's QEMU {qemu} was seen ended {:?} after the engine's exit was read",
        began.elapsed()
    );
    let group_path = Path::new("/sys/fs/cgroup").join(CGROUP_BASE).join(&group);
    assert!(group_path.exists(), "the dead engine's group is left");
    let began = Instant::now();
    let (removed, kept) = LinuxQemuHost::end_leftovers();
    eprintln!(
        "the next host removed {removed:?} (kept {kept:?}) in {:?}",
        began.elapsed()
    );
    assert!(removed.contains(&group), "{removed:?} {kept:?}");
    assert!(kept.is_empty());
    assert!(!Path::new("/sys/fs/cgroup")
        .join(CGROUP_BASE)
        .join(&group)
        .exists());
    // The dead engine could not remove its private directory: the engine's start sweeps
    // such leftovers (`sandbox_vm`); here the test does.
    assert!(control.exists());
    std::fs::remove_dir_all(&control).unwrap();
}
