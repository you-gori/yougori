//! The Linux host process port of the QEMU backend: [`LinuxQemuHost`] implements
//! `sandbox::qemu::QemuHost` and the VM service's `VmHostPort` (M03 by the QEMU route the
//! owner preferred on 31 October 2026; VM-W19's minimal compatible QEMU Linux profile; §6.4
//! line 2322: stable process handles, never a PID; §7.3 lines 2378–2386; VM-CP-04).
//!
//! A start, refusing at the first failure:
//!
//! 1. The role is the host process of one VM boot and the plan carries Linux restrictions;
//!    otherwise `StartFailure::Prepare` and nothing is created.
//! 2. The plan's private directory is created new, mode 0700, owned by the account QEMU
//!    runs as; an existing path is refused and left untouched.
//! 3. The link bootstrap file and the guest's endpoint list are written there, mode 0400,
//!    owned by that account; the secret is kept for one [`LinuxQemuHost::take_secret`]. A
//!    new log file there takes QEMU's standard error.
//! 4. QEMU starts with exactly the plan's vector, without a shell, with an empty
//!    environment and the private directory as working directory, through
//!    `HostProcess::spawn_contained`: a cgroup of its own with the plan's memory and task
//!    limits joined before it runs, a network namespace of its own, the account
//!    ([`LinuxHostSettings::run_as`], with the KVM device's group added), no new
//!    privileges, and a parent-death signal: QEMU ends when the engine's process does,
//!    however it ended (the declared OS fallback, `SupervisorDeathFallback::OsJobCleanup`).
//!    QEMU's own seccomp filter comes from the vector (`-sandbox on,...`).
//! 5. The host waits, bounded, until QMP answers on a connection whose peer
//!    (`SO_PEERCRED`) is QEMU's own process. If QEMU ends first, the tail of its log says
//!    why ([`classify_early_exit`]): a KVM error is `StartFailure::HardwareVirtualization`
//!    with QEMU's own text, never retried, with no emulated alternative (VM-W22).
//!
//! The observations come from the held process, never from QEMU or the guest: the state
//! from its pidfd, and the command line, status, cgroup and network namespace from
//! `/proc/<pid>` and the group's files, read while the host holds the process unreaped, so
//! the PID names it throughout ([`crate::sandbox::qemu::LinuxObservedState`]).
//! `terminate` asks the host for its proof and only then removes the private directory.
//! Dropping the host ends what it still holds and removes its directories; groups an
//! engine that died left behind are ended by [`LinuxQemuHost::end_leftovers`].

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::bootstrap::{encode_bootstrap, write_bootstrap_file};
use super::early_exit::{classify_report, log_tail};
use super::socket::{connect, SocketError, SocketTimeouts};
use crate::foundation::evidence::OsKind;
use crate::foundation::process::{
    end_leftover_groups, Escalation, HostProcess, LinuxContainment, NoProof, ProcessError,
    ProcessIdentity, ProcessRole, RunAs, SharedHandles, TerminationProof,
};
use crate::sandbox::backend::{guest_endpoints_file, Architecture, BuildId, HostBuild};
use crate::sandbox::firecracker::parse_status;
use crate::sandbox::link::BootstrapSecret;
use crate::sandbox::qemu::{
    interfaces_of, limit_of, HostPath, LinuxObservedState, ObserveFailure, PathStyle,
    PrivateDirectory, ProcessInspection, ProcessState, QemuHost, QemuLaunchPlan, StartFailure,
    EGRESS_ENDPOINTS_NAME,
};
use crate::sandbox::vm_service::VmHostPort;

/// How long the standard settings wait for QMP to answer.
pub const DEFAULT_QMP_WAIT: Duration = Duration::from_secs(30);
/// How often the standard settings look for QMP and for the process's end.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(50);
/// The standard grace before the host kills a QEMU asked to quit, and each kill round's
/// wait.
pub const DEFAULT_GRACE: Duration = Duration::from_secs(10);
pub const DEFAULT_KILL_WAIT: Duration = Duration::from_secs(10);
/// The standard timeout of the connection that checks QMP accepts.
pub const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
/// QEMU's standard error, in the private directory.
pub const STDERR_LOG_NAME: &str = "qemu-stderr.log";
/// The KVM device, whose group the account joins.
const KVM_DEVICE: &str = "/dev/kvm";
/// Words in a line of QEMU's standard error, after its program name and option location,
/// that make the line a report of the hardware hypervisor on Linux: QEMU's KVM code writes
/// `Could not access KVM kernel module: ...`, `failed to initialize kvm: ...` and
/// `KVM: entry failed, hardware error ...` (the pinned 11.0.3 build's strings). Matched
/// without regard to case.
const HARDWARE_WORDS: [&str; 1] = ["kvm"];

/// How a [`LinuxQemuHost`] starts, waits and ends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinuxHostSettings {
    pub qmp_wait: Duration,
    pub poll_interval: Duration,
    pub escalation: Escalation,
    pub probe_timeouts: SocketTimeouts,
    /// The account QEMU runs as; the host must run as root to switch to it. `None` runs QEMU
    /// as the host's own account, which the backend refuses for the account control.
    pub run_as: Option<RunAs>,
    /// The group that grants the KVM device, added to the account's groups; `None` adds
    /// none (QEMU then opens the device only if the account may already).
    pub kvm_group: Option<u32>,
}

impl LinuxHostSettings {
    /// The standard waits with `run_as`, and the KVM device's group as the host sees it now.
    pub fn standard(run_as: Option<RunAs>) -> Result<Self, SocketError> {
        Ok(Self {
            qmp_wait: DEFAULT_QMP_WAIT,
            poll_interval: DEFAULT_POLL_INTERVAL,
            escalation: Escalation {
                grace: DEFAULT_GRACE,
                kill_wait: DEFAULT_KILL_WAIT,
            },
            probe_timeouts: SocketTimeouts::new(DEFAULT_PROBE_TIMEOUT, DEFAULT_PROBE_TIMEOUT)?,
            run_as,
            kvm_group: fs::metadata(KVM_DEVICE).ok().map(|device| device.gid()),
        })
    }
}

/// Something of a launch the host could not remove.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct LinuxCleanupFailure {
    pub process: Option<ProcessIdentity>,
    pub directory: String,
    pub detail: String,
}

struct HeldQemu {
    process: HostProcess,
    directory: PathBuf,
}

/// The Linux `QemuHost` (module notes).
pub struct LinuxQemuHost {
    settings: LinuxHostSettings,
    held: BTreeMap<ProcessIdentity, HeldQemu>,
    secrets: BTreeMap<ProcessIdentity, BootstrapSecret>,
    cleanup_failures: Vec<LinuxCleanupFailure>,
}

impl fmt::Debug for LinuxQemuHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinuxQemuHost")
            .field("settings", &self.settings)
            .field("held", &self.held.keys().collect::<Vec<_>>())
            .field("secrets_kept", &self.secrets.len())
            .finish()
    }
}

fn prepare(detail: impl Into<String>) -> StartFailure {
    StartFailure::Prepare {
        detail: detail.into(),
    }
}

fn process_failure(detail: String) -> StartFailure {
    StartFailure::Process {
        error: ProcessError::Spawn { detail },
    }
}

/// What QEMU's report of an end before QMP answered means on Linux: KVM's words make it a
/// hardware-virtualization failure with QEMU's text (VM-W22), anything else a process
/// failure with the text and the exit code.
pub fn classify_early_exit(exit_code: u32, stderr: &str) -> StartFailure {
    classify_report(&HARDWARE_WORDS, &exit_text(exit_code), stderr)
}

/// An exit code as a person reads it on Linux: one a signal ended (`128 + n`) names it.
pub fn exit_text(code: u32) -> String {
    match code {
        129..=192 => format!("{code} (signal {})", code - 128),
        _ => code.to_string(),
    }
}

/// Whether the held process ended, and with which exit code.
fn exit_code_of(process: &HostProcess) -> Result<Option<u32>, String> {
    match process.check_ended() {
        Ok(proof) => Ok(Some(proof.exit_code())),
        Err(NoProof::JobStillActive { exit_code, .. }) => Ok(Some(exit_code)),
        Err(NoProof::StillRunning) => Ok(None),
        Err(no_proof @ NoProof::HostCall { .. }) => Err(no_proof.to_string()),
    }
}

/// Writes `bytes` to the new file `path`, owned by `owner` (when given), mode 0400.
fn write_owned(path: &Path, bytes: &[u8], owner: Option<&RunAs>) -> std::io::Result<()> {
    use std::io::Write;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    restrict(path, owner, 0o400)
}

/// Gives `path` to `owner` (when given) with `mode`.
fn restrict(path: &Path, owner: Option<&RunAs>, mode: u32) -> std::io::Result<()> {
    if let Some(owner) = owner {
        std::os::unix::fs::chown(path, Some(owner.uid), Some(owner.gid))?;
    }
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

impl LinuxQemuHost {
    /// A host holding no process yet.
    pub fn new(settings: LinuxHostSettings) -> Self {
        Self {
            settings,
            held: BTreeMap::new(),
            secrets: BTreeMap::new(),
            cleanup_failures: Vec::new(),
        }
    }

    /// Ends the groups an engine that died left beneath the host's base (module notes):
    /// the groups removed and those that could not be.
    pub fn end_leftovers() -> (Vec<String>, Vec<String>) {
        end_leftover_groups()
    }

    pub fn settings(&self) -> &LinuxHostSettings {
        &self.settings
    }

    /// The link bootstrap secret written for `process` at its start, once.
    pub fn take_secret(&mut self, process: &ProcessIdentity) -> Option<BootstrapSecret> {
        self.secrets.remove(process)
    }

    /// The processes the host holds.
    pub fn held(&self) -> Vec<ProcessIdentity> {
        self.held.keys().copied().collect()
    }

    /// What the host could not remove, in the order it happened.
    pub fn cleanup_failures(&self) -> &[LinuxCleanupFailure] {
        &self.cleanup_failures
    }

    /// The account QEMU runs as, with the KVM device's group added.
    fn account(&self) -> Option<RunAs> {
        let mut account = self.settings.run_as.clone()?;
        if let Some(group) = self.settings.kvm_group {
            if !account.groups.contains(&group) {
                account.groups.push(group);
            }
        }
        Some(account)
    }

    /// Starts `plan` with `arguments` as the vector (module notes).
    pub(crate) fn start_arguments(
        &mut self,
        role: &ProcessRole,
        executable: &HostPath,
        plan: &QemuLaunchPlan,
        arguments: Vec<String>,
    ) -> Result<ProcessIdentity, StartFailure> {
        if !matches!(role, ProcessRole::VmHost { .. }) {
            return Err(prepare(format!(
                "QEMU is started only as the host process of a VM boot, not as {role}"
            )));
        }
        let expected = plan
            .linux()
            .ok_or_else(|| prepare("the plan carries no Linux restrictions"))?;
        let account = self.account();
        let directory = PathBuf::from(plan.profile().control().path().as_str());
        fs::create_dir(&directory).map_err(|error| {
            prepare(format!(
                "the private directory {} could not be created: {error}",
                directory.display()
            ))
        })?;
        if let Err(error) = restrict(&directory, account.as_ref(), 0o700) {
            let failure = prepare(format!(
                "the private directory {} could not be given to QEMU's account: {error}",
                directory.display()
            ));
            return Err(self.discard_directory(None, &directory, failure));
        }
        let prepared = (|| -> Result<(BootstrapSecret, fs::File), StartFailure> {
            let (file, secret) =
                encode_bootstrap(role).map_err(|error| prepare(error.to_string()))?;
            let path = write_bootstrap_file(&directory, file)
                .map_err(|error| prepare(error.to_string()))?;
            restrict(&path, account.as_ref(), 0o400).map_err(|error| prepare(error.to_string()))?;
            write_owned(
                &directory.join(EGRESS_ENDPOINTS_NAME),
                &guest_endpoints_file(plan.egress_endpoints()),
                account.as_ref(),
            )
            .map_err(|error| prepare(format!("the endpoint list could not be written: {error}")))?;
            write_owned(
                &directory.join(crate::sandbox::qemu::WORKLOAD_NAME),
                &plan.workload_file().map_err(prepare)?,
                account.as_ref(),
            )
            .map_err(|error| {
                prepare(format!(
                    "the workload declaration could not be written: {error}"
                ))
            })?;
            let log = directory.join(STDERR_LOG_NAME);
            let file = fs::File::create_new(&log)
                .map_err(|error| prepare(format!("could not create {}: {error}", log.display())))?;
            restrict(&log, account.as_ref(), 0o600).map_err(|error| prepare(error.to_string()))?;
            Ok((secret, file))
        })();
        let (secret, log) = match prepared {
            Ok(prepared) => prepared,
            Err(failure) => return Err(self.discard_directory(None, &directory, failure)),
        };
        let mut command = Command::new(executable.as_str());
        command
            .args(&arguments)
            .env_clear()
            .current_dir(&directory)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(log));
        let containment = LinuxContainment {
            memory_limit_bytes: expected.memory_limit_bytes,
            max_processes: expected.max_tasks,
            run_as: account,
            no_network: !expected.internet,
            end_with_host: true,
            drop_capabilities: true,
            nice: None,
        };
        let process = match HostProcess::spawn_contained(&mut command, role.clone(), &containment) {
            Ok(process) => process,
            Err(error) => {
                return Err(self.discard_directory(
                    None,
                    &directory,
                    StartFailure::Process { error },
                ))
            }
        };
        let log_path = directory.join(STDERR_LOG_NAME);
        if let Err(failure) =
            self.await_qmp(&process, plan.profile().control().qmp_socket(), &log_path)
        {
            return Err(self.discard(process, &directory, failure));
        }
        let identity = process.identity();
        self.held.insert(identity, HeldQemu { process, directory });
        self.secrets.insert(identity, secret);
        Ok(identity)
    }

    /// Waits, bounded, until QMP answers on a connection served by `process` itself, or
    /// classifies QEMU's report if it ends first. The answer, not the connection, is the
    /// sign ([`answers`](super::qmp::answers)): a start that fails after QEMU listens (KVM
    /// refused, the kernel not loaded) ends before any answer and is read as the failure
    /// it is.
    fn await_qmp(
        &self,
        process: &HostProcess,
        socket: &HostPath,
        log: &Path,
    ) -> Result<(), StartFailure> {
        let started = Instant::now();
        let pid = process.identity().pid;
        loop {
            match exit_code_of(process) {
                Ok(Some(exit_code)) => return Err(classify_early_exit(exit_code, &log_tail(log))),
                Ok(None) => {}
                Err(detail) => {
                    return Err(process_failure(format!(
                        "the host could not observe QEMU while it started: {detail}"
                    )))
                }
            }
            if let Ok(stream) = connect(Path::new(socket.as_str()), self.settings.probe_timeouts) {
                let peer = stream.peer_process_id().map_err(|error| {
                    process_failure(format!(
                        "the process serving QEMU's QMP socket could not be read: {error}"
                    ))
                })?;
                if peer != pid {
                    return Err(process_failure(format!(
                        "QEMU's QMP socket is served by process {peer}, not by QEMU (process {pid})"
                    )));
                }
                if super::qmp::answers(stream, self.settings.probe_timeouts.receive()) {
                    return Ok(());
                }
            }
            if started.elapsed() >= self.settings.qmp_wait {
                return Err(process_failure(format!(
                    "QEMU's QMP socket did not answer within {} ms",
                    self.settings.qmp_wait.as_millis()
                )));
            }
            std::thread::sleep(self.settings.poll_interval);
        }
    }

    /// Ends a process whose start failed, at once, then removes its private directory.
    fn discard(
        &mut self,
        process: HostProcess,
        directory: &Path,
        failure: StartFailure,
    ) -> StartFailure {
        let identity = process.identity();
        let ended = process.terminate(Escalation {
            grace: Duration::ZERO,
            kill_wait: self.settings.escalation.kill_wait,
        });
        drop(process);
        match ended {
            Ok(_) => self.discard_directory(Some(identity), directory, failure),
            Err(no_proof) => {
                self.cleanup_failures.push(LinuxCleanupFailure {
                    process: Some(identity),
                    directory: directory.display().to_string(),
                    detail: format!("the host did not observe QEMU's end ({no_proof}); its group was killed with the handle"),
                });
                self.discard_directory(Some(identity), directory, failure)
            }
        }
    }

    fn discard_directory(
        &mut self,
        process: Option<ProcessIdentity>,
        directory: &Path,
        failure: StartFailure,
    ) -> StartFailure {
        if let Err(error) = fs::remove_dir_all(directory) {
            self.cleanup_failures.push(LinuxCleanupFailure {
                process,
                directory: directory.display().to_string(),
                detail: error.to_string(),
            });
        }
        failure
    }

    /// What the host reads of `pid` (module notes), while it holds the process unreaped.
    fn observe_linux(pid: u32) -> std::io::Result<(Vec<String>, LinuxObservedState)> {
        let invalid = |detail: String| std::io::Error::new(std::io::ErrorKind::InvalidData, detail);
        let raw = fs::read(format!("/proc/{pid}/cmdline"))?;
        let command_line: Vec<String> = raw
            .split(|byte| *byte == 0)
            .filter(|part| !part.is_empty())
            .map(|part| String::from_utf8_lossy(part).into_owned())
            .collect();
        let status_text = fs::read_to_string(format!("/proc/{pid}/status"))?;
        let status = parse_status(&status_text).map_err(|error| invalid(format!("{error:?}")))?;
        let cgroup = fs::read_to_string(format!("/proc/{pid}/cgroup"))?
            .lines()
            .find_map(|line| line.strip_prefix("0::").map(str::to_owned))
            .ok_or_else(|| invalid("no cgroup v2 line".to_owned()))?;
        let group = Path::new("/sys/fs/cgroup").join(cgroup.trim_start_matches('/'));
        let memory_max = fs::read_to_string(group.join("memory.max"))
            .ok()
            .and_then(|text| limit_of(&text));
        let pids_max = fs::read_to_string(group.join("pids.max"))
            .ok()
            .and_then(|text| limit_of(&text));
        let network_interfaces =
            interfaces_of(&fs::read_to_string(format!("/proc/{pid}/net/dev"))?);
        // SAFETY: geteuid has no preconditions and cannot fail.
        let host_uid = unsafe { libc::geteuid() };
        Ok((
            command_line,
            LinuxObservedState {
                status,
                cgroup,
                memory_max,
                pids_max,
                network_interfaces,
                host_uid,
            },
        ))
    }
}

impl QemuHost for LinuxQemuHost {
    type Proof = TerminationProof;

    /// Prepares the plan's host files and starts QEMU with exactly the plan's vector under
    /// its Linux restrictions (module notes).
    fn start(
        &mut self,
        role: &ProcessRole,
        executable: &HostPath,
        plan: &QemuLaunchPlan,
    ) -> Result<ProcessIdentity, StartFailure> {
        let arguments = plan.profile().argv();
        self.start_arguments(role, executable, plan, arguments)
    }

    fn state(&self, process: &ProcessIdentity) -> Result<ProcessState, ObserveFailure> {
        let held = self
            .held
            .get(process)
            .ok_or(ObserveFailure::NotHeld { process: *process })?;
        match exit_code_of(&held.process) {
            Ok(Some(exit_code)) => Ok(ProcessState::Ended { exit_code }),
            Ok(None) => Ok(ProcessState::Running),
            Err(detail) => Err(ObserveFailure::Unreadable { detail }),
        }
    }

    /// The state, and the command line and Linux state the host reads from `/proc` and the
    /// process's group. A process that ended can no longer be read: its listing is empty and
    /// there is no Linux state; the state alone refuses it. The state is read again after
    /// the reading, so a process that ended meanwhile (whose `/proc` entries are a zombie's
    /// or gone) is reported ended, never by what was read of it.
    fn inspect(&self, process: &ProcessIdentity) -> Result<ProcessInspection, ObserveFailure> {
        let before = self.state(process)?;
        let observed = Self::observe_linux(process.pid);
        let state = match before {
            ProcessState::Running => self.state(process)?,
            ended => ended,
        };
        match observed {
            Ok((command_line, linux)) if state == ProcessState::Running => Ok(ProcessInspection {
                state,
                command_line,
                windows: None,
                linux: Some(linux),
            }),
            _ if matches!(state, ProcessState::Ended { .. }) => Ok(ProcessInspection {
                state,
                command_line: Vec::new(),
                windows: None,
                linux: None,
            }),
            Ok(_) => Err(ObserveFailure::Unreadable {
                detail: "the process's state changed while it was read".to_owned(),
            }),
            Err(error) => Err(ObserveFailure::Unreadable {
                detail: error.to_string(),
            }),
        }
    }

    /// The kernel release (`/proc/sys/kernel/osrelease`) and the CPU architecture.
    fn host_build(&self) -> Result<HostBuild, ObserveFailure> {
        let unreadable = |detail: String| ObserveFailure::Unreadable { detail };
        let release = fs::read_to_string("/proc/sys/kernel/osrelease")
            .map_err(|error| unreadable(format!("the kernel release: {error}")))?;
        let architecture = match std::env::consts::ARCH {
            "x86_64" => Architecture::X86_64,
            "aarch64" => Architecture::Aarch64,
            other => return Err(unreadable(format!("processor architecture {other}"))),
        };
        Ok(HostBuild {
            os: OsKind::Linux,
            build: BuildId::new(release.trim())
                .map_err(|error| unreadable(format!("the kernel release: {error}")))?,
            architecture,
        })
    }

    /// `HostProcess::terminate` with the settings' escalation, then the private directory
    /// is removed. Without the host's proof nothing is removed and the process stays held.
    fn terminate(&mut self, process: &ProcessIdentity) -> Result<TerminationProof, NoProof> {
        let held = self.held.get(process).ok_or(NoProof::StillRunning)?;
        let proof = held.process.terminate(self.settings.escalation)?;
        self.secrets.remove(process);
        if let Some(held) = self.held.remove(process) {
            drop(held.process);
            if let Err(error) = fs::remove_dir_all(&held.directory) {
                self.cleanup_failures.push(LinuxCleanupFailure {
                    process: Some(*process),
                    directory: held.directory.display().to_string(),
                    detail: error.to_string(),
                });
            }
        }
        Ok(proof)
    }
}

impl VmHostPort for LinuxQemuHost {
    /// What a holder needs of the held QEMU process (`HostProcess::share_with`: on Linux
    /// nothing is duplicated; the holder opens its own pidfd for the identity and finds the
    /// group).
    fn share_process(
        &self,
        process: &ProcessIdentity,
        holder: &HostProcess,
    ) -> Result<SharedHandles, String> {
        let held = self
            .held
            .get(process)
            .ok_or_else(|| format!("the host holds no QEMU process {}", process.pid))?;
        held.process
            .share_with(holder)
            .map_err(|error| error.to_string())
    }

    fn private_directory(&self, process: &ProcessIdentity) -> Option<PrivateDirectory> {
        let held = self.held.get(process)?;
        let path = HostPath::new(PathStyle::Unix, held.directory.to_str()?).ok()?;
        PrivateDirectory::new(path).ok()
    }

    fn take_secret(&mut self, process: &ProcessIdentity) -> Option<BootstrapSecret> {
        LinuxQemuHost::take_secret(self, process)
    }

    fn directory_absent(&self, directory: &PrivateDirectory) -> Result<bool, ObserveFailure> {
        match fs::symlink_metadata(directory.path().as_str()) {
            Ok(_) => Ok(false),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
            Err(error) => Err(ObserveFailure::Unreadable {
                detail: format!(
                    "the private directory {} could not be looked up: {error}",
                    directory.path()
                ),
            }),
        }
    }
}

impl Drop for LinuxQemuHost {
    /// Ends every process still held, at once, and removes its private directory.
    fn drop(&mut self) {
        let at_once = Escalation {
            grace: Duration::ZERO,
            kill_wait: self.settings.escalation.kill_wait,
        };
        for (_, held) in std::mem::take(&mut self.held) {
            let _ = held.process.terminate(at_once);
            drop(held.process);
            let _ = fs::remove_dir_all(&held.directory);
        }
    }
}

#[cfg(test)]
#[path = "linux_launch_tests.rs"]
mod launch_tests;
