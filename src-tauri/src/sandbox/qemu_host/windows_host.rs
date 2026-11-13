//! The Windows host process port of the QEMU backend: [`WindowsQemuHost`] implements
//! `sandbox::qemu::QemuHost` (M02, M04; docs/combined-gpu-memory-and-vm-sandbox-plan.md:
//! VM-W16 row, line 2615; VM-W19 row, line 2618: "Exact machine/device build boots under
//! intended token/Job rules; no inherited sensitive handles"; VM-W22 row, line 2621; §6.4
//! line 2322: stable process handles, never a PID; §7.3 lines 2378–2386; VM-CP-04, line
//! 3154).
//!
//! A start, refusing at the first failure:
//!
//! 1. The role is the host process of one VM boot (`ProcessRole::VmHost`) and the plan
//!    carries Windows restrictions, which map one to one onto the host's restricted start
//!    ([`start_restrictions`]); otherwise `StartFailure::Prepare` and nothing is created.
//! 2. The plan's private directory is created new, with the protected DACL and low
//!    mandatory label of [`private_dir`](super::private_dir); an existing path is refused
//!    and left untouched.
//! 3. The link bootstrap file is written there by [`write_bootstrap_file`] and made
//!    readable by the restricted QEMU; its secret is kept for one
//!    [`WindowsQemuHost::take_secret`]. A new log file there takes QEMU's standard error.
//! 4. QEMU starts with exactly the plan's argument vector, without a shell, with an
//!    environment of `SystemRoot` alone and the private directory as working directory,
//!    through `HostProcess::spawn_restricted`: a restricted, lowered copy of the host's
//!    own token, a kill-on-close job with the plan's limits (its memory limit the
//!    reservation's host RAM), only the listed standard handles inherited, the mitigation
//!    policies always on, on a `SandboxDesktop` of its own. This module writes no token,
//!    job or desktop code; it calls those.
//! 5. The host waits, bounded by [`WindowsHostSettings::qmp_wait`], until QMP's socket
//!    accepts a connection whose peer is QEMU's own process, the process still running.
//!    If QEMU ends first, the tail of its log is read: a WHPX or hardware-acceleration
//!    error is `StartFailure::HardwareVirtualization` with QEMU's own text (VM-W22),
//!    anything else a process failure with the text ([`classify_early_exit`]). Nothing is
//!    retried, and there is no emulated alternative.
//! 6. For a profile with a network card, the host connects its network filter
//!    ([`NetworkFilter`]) to the four sockets QEMU serves, each checked to be served by
//!    QEMU's own process; a filter that does not start ends the launch. Until it runs, and
//!    after it ends, the card's frames reach nothing.
//!
//! Every failure after step 2 ends what started (the host's proof within a bounded kill,
//! or, without it, closing the job, which kills what is left) and removes the private
//! directory; a removal that fails is recorded ([`WindowsQemuHost::cleanup_failures`]) and
//! named in the failure.
//!
//! The observations come from the held process, never from QEMU or the guest: the state
//! from its handle, and the command line and the Windows state from
//! `HostProcess::read_restrictions`, mapped by [`observed_state`]. The inherited handles'
//! kinds come from the start's explicit handle list; only their number is observed, as the
//! handle count of the process while it was still suspended, and each handle beyond the
//! list is reported as `HandleKind::Other`, so `check_windows` refuses it. `terminate` asks
//! the host for its proof with a bounded escalation and only then removes the private
//! directory; without a proof it removes nothing. Dropping the host ends and removes
//! whatever it still holds.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use serde::Serialize;
use windows_sys::Win32::System::SystemInformation::{
    GetNativeSystemInfo, OSVERSIONINFOW, PROCESSOR_ARCHITECTURE_AMD64,
    PROCESSOR_ARCHITECTURE_ARM64, SYSTEM_INFO,
};

use super::bootstrap::{encode_bootstrap, write_bootstrap_file};
use super::early_exit::log_tail;
use super::host_map::{classify_early_exit, observed_state, start_restrictions};
use super::network_filter::{NetworkFilter, Reach};
use super::private_dir::{
    create_private_directory, remove_private_directory, restrict_bootstrap_file, HostSids,
    STDERR_LOG_NAME,
};
use super::socket::{connect, SocketError, SocketTimeouts};
use crate::foundation::evidence::OsKind;
use crate::foundation::process::{
    Escalation, HostProcess, NoProof, ProcessError, ProcessIdentity, ProcessRole, RestrictedStart,
    RestrictingGroup, SandboxDesktop, SharedHandles, StartObservation, TerminationProof,
};
use crate::sandbox::backend::{guest_endpoints_file, Architecture, BuildId, HostBuild};
use crate::sandbox::link::BootstrapSecret;
use crate::sandbox::qemu::{
    HostPath, ObserveFailure, PathStyle, PrivateDirectory, ProcessInspection, ProcessState,
    QemuHost, QemuLaunchPlan, StartFailure,
};
use crate::sandbox::vm_service::VmHostPort;

/// How long [`WindowsHostSettings::standard`] waits for QMP to accept a connection.
pub const DEFAULT_QMP_WAIT: Duration = Duration::from_secs(30);
/// How often the standard settings look for QMP and for the process's end.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(50);
/// The standard grace before the host kills a QEMU asked to quit, and each kill round's
/// wait.
pub const DEFAULT_GRACE: Duration = Duration::from_secs(10);
pub const DEFAULT_KILL_WAIT: Duration = Duration::from_secs(10);
/// The standard receive and send timeout of the connection that checks QMP accepts.
pub const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

#[link(name = "ntdll", kind = "raw-dylib")]
extern "system" {
    /// The OS version, never shimmed for an executable without a manifest.
    fn RtlGetVersion(information: *mut OSVERSIONINFOW) -> i32;
}

/// How a [`WindowsQemuHost`] waits and ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowsHostSettings {
    /// The most a start waits for QMP's socket to accept a connection.
    pub qmp_wait: Duration,
    /// How often a start looks for QMP and for the process's end.
    pub poll_interval: Duration,
    /// How [`QemuHost::terminate`] ends a process: the grace after the backend asked QEMU
    /// to quit, then kill rounds of the whole job. A failed start kills at once.
    pub escalation: Escalation,
    /// The timeouts of the connection that checks QMP accepts.
    pub probe_timeouts: SocketTimeouts,
}

impl WindowsHostSettings {
    /// The default waits: [`DEFAULT_QMP_WAIT`], [`DEFAULT_POLL_INTERVAL`],
    /// [`DEFAULT_GRACE`], [`DEFAULT_KILL_WAIT`] and [`DEFAULT_PROBE_TIMEOUT`].
    pub fn standard() -> Result<Self, SocketError> {
        Ok(Self {
            qmp_wait: DEFAULT_QMP_WAIT,
            poll_interval: DEFAULT_POLL_INTERVAL,
            escalation: Escalation {
                grace: DEFAULT_GRACE,
                kill_wait: DEFAULT_KILL_WAIT,
            },
            probe_timeouts: SocketTimeouts::new(DEFAULT_PROBE_TIMEOUT, DEFAULT_PROBE_TIMEOUT)?,
        })
    }
}

/// Something of a launch the host could not remove.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CleanupFailure {
    /// The process the files were prepared for, when it had started.
    pub process: Option<ProcessIdentity>,
    pub directory: String,
    pub detail: String,
}

/// One QEMU process the host holds, with what it prepared for it.
struct HeldQemu {
    process: HostProcess,
    started: StartObservation,
    directory: PathBuf,
    desktop: String,
    qmp_after: Duration,
    /// The filter of its network card's frames, for a profile with a card.
    network: Option<NetworkFilter>,
}

/// The Windows `QemuHost` (see the module notes).
pub struct WindowsQemuHost {
    settings: WindowsHostSettings,
    held: BTreeMap<ProcessIdentity, HeldQemu>,
    secrets: BTreeMap<ProcessIdentity, BootstrapSecret>,
    launches: u64,
    cleanup_failures: Vec<CleanupFailure>,
}

impl fmt::Debug for WindowsQemuHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WindowsQemuHost")
            .field("settings", &self.settings)
            .field("held", &self.held.keys().collect::<Vec<_>>())
            .field("secrets_kept", &self.secrets.len())
            .field("cleanup_failures", &self.cleanup_failures)
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

/// `failure` with `note` added to what it says.
fn with_note(failure: StartFailure, note: &str) -> StartFailure {
    match failure {
        StartFailure::HardwareVirtualization { detail } => StartFailure::HardwareVirtualization {
            detail: format!("{detail}; {note}"),
        },
        StartFailure::Prepare { detail } => StartFailure::Prepare {
            detail: format!("{detail}; {note}"),
        },
        StartFailure::Process { error } => process_failure(match error {
            ProcessError::Spawn { detail } => format!("{detail}; {note}"),
            other => format!("{other}; {note}"),
        }),
    }
}

/// Whether the held process ended, and with which exit code; the job may still hold a
/// process, which only a termination proof rules out.
fn exit_code_of(process: &HostProcess) -> Result<Option<u32>, String> {
    match process.check_ended() {
        Ok(proof) => Ok(Some(proof.exit_code())),
        Err(NoProof::JobStillActive { exit_code, .. }) => Ok(Some(exit_code)),
        Err(NoProof::StillRunning) => Ok(None),
        Err(no_proof @ NoProof::HostCall { .. }) => Err(no_proof.to_string()),
    }
}

/// The host's OS build, `major.minor.build`, and CPU architecture.
fn read_host_build() -> Result<HostBuild, ObserveFailure> {
    let unreadable = |detail: String| ObserveFailure::Unreadable { detail };
    let mut version = OSVERSIONINFOW {
        dwOSVersionInfoSize: u32::try_from(std::mem::size_of::<OSVERSIONINFOW>())
            .map_err(|_| unreadable("the version structure's size".to_owned()))?,
        ..OSVERSIONINFOW::default()
    };
    // SAFETY: the structure is live, of the size it declares.
    let status = unsafe { RtlGetVersion(&mut version) };
    if status < 0 {
        return Err(unreadable(format!(
            "RtlGetVersion failed with status {status:#x}"
        )));
    }
    let mut system = SYSTEM_INFO::default();
    // SAFETY: the structure is live; the call has no failure.
    unsafe { GetNativeSystemInfo(&mut system) };
    // SAFETY: GetNativeSystemInfo writes the architecture member of the union.
    let architecture = match unsafe { system.Anonymous.Anonymous.wProcessorArchitecture } {
        PROCESSOR_ARCHITECTURE_AMD64 => Architecture::X86_64,
        PROCESSOR_ARCHITECTURE_ARM64 => Architecture::Aarch64,
        other => return Err(unreadable(format!("processor architecture {other}"))),
    };
    // The build number alone, as `BuildId` spells a build (`26100`, optionally with its
    // revision) and as the host evidence inventory reads it (`CurrentBuildNumber`): the
    // doctor reads a launch record only when the record's host build is the inventory's
    // (found 30 October 2026: "10.0.26300" here against "26300" there refused every record).
    let build = BuildId::new(version.dwBuildNumber.to_string())
        .map_err(|error| unreadable(format!("the build number: {error}")))?;
    Ok(HostBuild {
        os: OsKind::Windows,
        build,
        architecture,
    })
}

impl WindowsQemuHost {
    /// A host holding no process yet.
    pub fn new(settings: WindowsHostSettings) -> Self {
        Self {
            settings,
            held: BTreeMap::new(),
            secrets: BTreeMap::new(),
            launches: 0,
            cleanup_failures: Vec::new(),
        }
    }

    /// How the host waits and ends.
    pub fn settings(&self) -> &WindowsHostSettings {
        &self.settings
    }

    /// The link bootstrap secret written for `process` at its start, once: the host's
    /// link binding derives its keys from it. A second call, or a process this host did
    /// not start, has none.
    pub fn take_secret(&mut self, process: &ProcessIdentity) -> Option<BootstrapSecret> {
        self.secrets.remove(process)
    }

    /// The processes the host holds.
    pub fn held(&self) -> Vec<ProcessIdentity> {
        self.held.keys().copied().collect()
    }

    /// The name of the desktop `process` was started on.
    pub fn desktop_of(&self, process: &ProcessIdentity) -> Option<&str> {
        self.held.get(process).map(|held| held.desktop.as_str())
    }

    /// How long after its creation `process`'s QMP socket accepted the host's connection.
    pub fn qmp_answered_after(&self, process: &ProcessIdentity) -> Option<Duration> {
        self.held.get(process).map(|held| held.qmp_after)
    }

    /// What the host could not remove, in the order it happened.
    pub fn cleanup_failures(&self) -> &[CleanupFailure] {
        &self.cleanup_failures
    }

    /// The start of `plan` with `arguments` as the vector; [`QemuHost::start`] passes the
    /// plan's own. Kept private so that only a test can start another vector under the
    /// plan's restrictions.
    fn start_arguments(
        &mut self,
        role: &ProcessRole,
        executable: &HostPath,
        plan: &QemuLaunchPlan,
        arguments: Vec<String>,
    ) -> Result<ProcessIdentity, StartFailure> {
        let ProcessRole::VmHost { vm, .. } = role else {
            return Err(prepare(format!(
                "QEMU is started only as the host process of a VM boot, not as {role}"
            )));
        };
        let expected = plan
            .windows()
            .ok_or_else(|| prepare("the plan carries no Windows restrictions"))?;
        let control = plan.profile().control();
        let mapped = start_restrictions(expected, control.path())
            .map_err(|refusal| prepare(refusal.to_string()))?;
        if !mapped.restricting.contains(&RestrictingGroup::LogonSession) {
            return Err(prepare(
                "the private directory grants the logon session's SID, which the restrictions \
                 do not name as a restricting SID",
            ));
        }
        let system_root = std::env::var_os("SystemRoot")
            .ok_or_else(|| prepare("the host's environment has no SystemRoot"))?;
        let sids = HostSids::current().map_err(|error| prepare(error.to_string()))?;
        let directory = PathBuf::from(control.path().as_str());
        create_private_directory(&directory, &sids).map_err(|error| prepare(error.to_string()))?;

        let (secret, log) = match prepare_files(role, &directory, &sids, mapped.stderr_logged, plan)
        {
            Ok(prepared) => prepared,
            Err(failure) => return Err(self.discard_directory(None, &directory, failure)),
        };
        self.launches = self.launches.saturating_add(1);
        let hex = vm.digest().to_hex();
        let desktop_name = format!(
            "ygq-{}-{}-{}",
            hex.get(..16).unwrap_or(&hex),
            std::process::id(),
            self.launches
        );
        let desktop =
            match SandboxDesktop::for_start(&desktop_name, &mapped.restricting, mapped.integrity) {
                Ok(desktop) => desktop,
                Err(error) => {
                    return Err(self.discard_directory(
                        None,
                        &directory,
                        StartFailure::Process { error },
                    ))
                }
            };
        let start = RestrictedStart {
            restricting: mapped.restricting.clone(),
            integrity: mapped.integrity,
            job: mapped.job,
            mitigations: mapped.mitigations.clone(),
            stderr: log,
            desktop,
        };
        let mut command = Command::new(executable.as_str());
        command
            .args(&arguments)
            .env_clear()
            .env("SystemRoot", system_root)
            .current_dir(&directory);
        let started = Instant::now();
        let (process, observation) =
            match HostProcess::spawn_restricted(&command, role.clone(), start) {
                Ok(spawned) => spawned,
                Err(error) => {
                    return Err(self.discard_directory(
                        None,
                        &directory,
                        StartFailure::Process { error },
                    ))
                }
            };
        let log_path = directory.join(STDERR_LOG_NAME);
        if let Err(failure) = self.await_qmp(&process, control.qmp_socket(), &log_path) {
            return Err(self.discard(process, &directory, failure));
        }
        let qmp_after = started.elapsed();
        // A card's frames pass the host's filter or nowhere: a filter that cannot start
        // ends the launch.
        let network = match Reach::of(plan) {
            Some(reach) => {
                match NetworkFilter::start(&reach, control.network_sockets(), process.identity().pid) {
                    Ok(filter) => Some(filter),
                    Err(detail) => {
                        let failure =
                            prepare(format!("the VM's network filter could not start: {detail}"));
                        return Err(self.discard(process, &directory, failure));
                    }
                }
            }
            None => None,
        };
        let identity = process.identity();
        self.held.insert(
            identity,
            HeldQemu {
                process,
                started: observation,
                directory,
                desktop: desktop_name,
                qmp_after,
                network,
            },
        );
        self.secrets.insert(identity, secret);
        Ok(identity)
    }

    /// Waits, bounded, until QMP answers on a connection served by `process` itself, or
    /// classifies QEMU's report if it ends first.
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
                        "QEMU's QMP socket is served by process {peer}, not by QEMU (process \
                         {pid})"
                    )));
                }
                // The answer, not the connection, is the sign (`qmp::answers`): a start
                // that fails after QEMU listens ends before any answer.
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

    /// Ends a process whose start failed, at once, then removes its private directory;
    /// returns `failure` with anything left named in it.
    fn discard(
        &mut self,
        process: HostProcess,
        directory: &Path,
        failure: StartFailure,
    ) -> StartFailure {
        let identity = process.identity();
        let at_once = Escalation {
            grace: Duration::ZERO,
            kill_wait: self.settings.escalation.kill_wait,
        };
        let ended = process.terminate(at_once);
        // Closing the job kills whatever is left in it.
        drop(process);
        match ended {
            Ok(_) => self.discard_directory(Some(identity), directory, failure),
            Err(no_proof) => {
                let note = format!(
                    "the host did not observe QEMU's end ({no_proof}); its job was closed, which \
                     kills what is left"
                );
                self.cleanup_failures.push(CleanupFailure {
                    process: Some(identity),
                    directory: directory.display().to_string(),
                    detail: note.clone(),
                });
                self.discard_directory(Some(identity), directory, with_note(failure, &note))
            }
        }
    }

    /// Removes a failed start's private directory; returns `failure`, naming the directory
    /// when it could not be removed.
    fn discard_directory(
        &mut self,
        process: Option<ProcessIdentity>,
        directory: &Path,
        failure: StartFailure,
    ) -> StartFailure {
        match remove_private_directory(directory) {
            Ok(()) => failure,
            Err(error) => {
                let note = error.to_string();
                self.cleanup_failures.push(CleanupFailure {
                    process,
                    directory: directory.display().to_string(),
                    detail: note.clone(),
                });
                with_note(failure, &format!("left behind: {note}"))
            }
        }
    }
}

/// Writes the bootstrap file and the guest's egress endpoint list, makes both readable by
/// the restricted QEMU and opens the log for its standard error when the restrictions log
/// it.
fn prepare_files(
    role: &ProcessRole,
    directory: &Path,
    sids: &HostSids,
    stderr_logged: bool,
    plan: &QemuLaunchPlan,
) -> Result<(BootstrapSecret, Option<File>), StartFailure> {
    let (file, secret) = encode_bootstrap(role).map_err(|error| prepare(error.to_string()))?;
    let path = write_bootstrap_file(directory, file).map_err(|error| prepare(error.to_string()))?;
    restrict_bootstrap_file(&path, sids).map_err(|error| prepare(error.to_string()))?;
    let endpoints = directory.join(crate::sandbox::qemu::EGRESS_ENDPOINTS_NAME);
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&endpoints)
        .and_then(|mut handle| {
            use std::io::Write;
            handle.write_all(&guest_endpoints_file(plan.egress_endpoints()))?;
            handle.sync_all()
        })
        .map_err(|error| prepare(format!("could not write {}: {error}", endpoints.display())))?;
    restrict_bootstrap_file(&endpoints, sids).map_err(|error| prepare(error.to_string()))?;
    let workload = directory.join(crate::sandbox::qemu::WORKLOAD_NAME);
    let bytes = plan.workload_file().map_err(prepare)?;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&workload)
        .and_then(|mut file| {
            use std::io::Write;
            file.write_all(&bytes)?;
            file.sync_all()
        })
        .map_err(|error| prepare(format!("could not write workload declaration: {error}")))?;
    restrict_bootstrap_file(&workload, sids).map_err(|error| prepare(error.to_string()))?;
    let log =
        if stderr_logged {
            let path = directory.join(STDERR_LOG_NAME);
            Some(File::create_new(&path).map_err(|error| {
                prepare(format!("could not create {}: {error}", path.display()))
            })?)
        } else {
            None
        };
    Ok((secret, log))
}

/// Acceptance builds only: when set, the next start adds a share device on purpose
/// (VM-CP-03's positive control, §17 line 3153: "a test launch with a deliberately added
/// share device fails the check"). The planned vector, which the golden file was checked
/// against, is unchanged; only the process QEMU runs differs, so the backend's reading of
/// the process's own command line must refuse it as failing the host interface check.
#[cfg(feature = "acceptance")]
pub static PLANT_SHARE_DEVICE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Acceptance builds only: when set, the next start runs QEMU emulated, its accelerator
/// replaced by TCG (with a 16 MiB translation buffer, which fits the job's commit limit; the
/// default 1 GiB buffer does not, measured 31 October 2026): what a hypervisor made unavailable falls back to when nothing stops it
/// (VM-CP-01's `cp01.forced-unavailable-refused`, VM-CP-33's `cp33.windows.whpx-unavailable`).
/// The planned vector is unchanged; the backend's reading of the process's command line must
/// refuse it as not hardware-virtualized.
#[cfg(feature = "acceptance")]
pub static PLANT_TCG: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Adds the planted share device when [`PLANT_SHARE_DEVICE`] is set, once: the vector's own
/// firmware directory, which the restricted QEMU can read, as a read-only FAT drive that
/// no device uses.
#[cfg(feature = "acceptance")]
fn plant_tcg(arguments: &mut [String]) {
    if !PLANT_TCG.swap(false, std::sync::atomic::Ordering::SeqCst) {
        return;
    }
    if let Some(index) = arguments.iter().position(|argument| argument == "-accel") {
        if let Some(value) = arguments.get_mut(index + 1) {
            // A small translation buffer: TCG's default (1 GiB) does not fit the job's
            // commit limit, and a QEMU that cannot start shows nothing about emulation.
            *value = "tcg,tb-size=16".to_owned();
        }
    }
}

#[cfg(feature = "acceptance")]
fn plant_share_device(arguments: &mut Vec<String>) {
    if !PLANT_SHARE_DEVICE.swap(false, std::sync::atomic::Ordering::SeqCst) {
        return;
    }
    let Some(firmware) = arguments
        .iter()
        .position(|argument| argument == "-L")
        .and_then(|index| arguments.get(index + 1))
        .cloned()
    else {
        return;
    };
    arguments.push("-blockdev".to_owned());
    arguments.push(format!(
        "driver=vvfat,node-name=planted-share,dir={firmware},read-only=on"
    ));
}

impl QemuHost for WindowsQemuHost {
    type Proof = TerminationProof;

    /// Prepares the plan's host files and starts QEMU with exactly the plan's vector under
    /// its Windows restrictions (see the module notes).
    fn start(
        &mut self,
        role: &ProcessRole,
        executable: &HostPath,
        plan: &QemuLaunchPlan,
    ) -> Result<ProcessIdentity, StartFailure> {
        #[allow(unused_mut)]
        let mut arguments = plan.profile().argv();
        #[cfg(feature = "acceptance")]
        {
            plant_share_device(&mut arguments);
            plant_tcg(&mut arguments);
        }
        self.start_arguments(role, executable, plan, arguments)
    }

    /// From the held process's handle: running, or ended with its exit code.
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

    /// The state, and the command line and Windows state the host reads back through the
    /// handles it holds. For a process that ended and can no longer be read back, the
    /// listing is empty and there is no Windows state; the state alone refuses it.
    fn inspect(&self, process: &ProcessIdentity) -> Result<ProcessInspection, ObserveFailure> {
        let state = self.state(process)?;
        let held = self
            .held
            .get(process)
            .ok_or(ObserveFailure::NotHeld { process: *process })?;
        match held.process.read_restrictions() {
            Ok(readback) => {
                let windows = observed_state(&readback, &held.started).map_err(|error| {
                    ObserveFailure::Unreadable {
                        detail: error.to_string(),
                    }
                })?;
                Ok(ProcessInspection {
                    state,
                    command_line: readback.command_line,
                    windows: Some(windows),
                    linux: None,
                })
            }
            Err(_) if matches!(state, ProcessState::Ended { .. }) => Ok(ProcessInspection {
                state,
                command_line: Vec::new(),
                windows: None,
                linux: None,
            }),
            Err(error) => Err(ObserveFailure::Unreadable {
                detail: error.to_string(),
            }),
        }
    }

    /// The OS build (`RtlGetVersion`) and the CPU architecture (`GetNativeSystemInfo`).
    fn host_build(&self) -> Result<HostBuild, ObserveFailure> {
        read_host_build()
    }

    /// `HostProcess::terminate` with the settings' escalation, then the private directory
    /// is removed; a removal that fails is recorded in
    /// [`WindowsQemuHost::cleanup_failures`]. Without the host's proof nothing is removed
    /// and the process stays held. A process this host does not hold has no proof.
    fn terminate(&mut self, process: &ProcessIdentity) -> Result<TerminationProof, NoProof> {
        let held = self.held.get(process).ok_or(NoProof::StillRunning)?;
        let proof = held.process.terminate(self.settings.escalation)?;
        self.secrets.remove(process);
        if let Some(held) = self.held.remove(process) {
            drop(held.process);
            drop(held.network);
            if let Err(error) = remove_private_directory(&held.directory) {
                self.cleanup_failures.push(CleanupFailure {
                    process: Some(*process),
                    directory: held.directory.display().to_string(),
                    detail: error.to_string(),
                });
            }
        }
        Ok(proof)
    }
}

impl VmHostPort for WindowsQemuHost {
    /// The private directory `start` created for `process`, while the host holds it.
    fn private_directory(&self, process: &ProcessIdentity) -> Option<PrivateDirectory> {
        let held = self.held.get(process)?;
        let path = HostPath::new(PathStyle::Windows, held.directory.to_str()?).ok()?;
        PrivateDirectory::new(path).ok()
    }

    fn take_secret(&mut self, process: &ProcessIdentity) -> Option<BootstrapSecret> {
        WindowsQemuHost::take_secret(self, process)
    }

    /// The held QEMU process's job and process handles, duplicated into `holder`.
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

    /// Whether `directory` is absent now: a lookup that follows no link.
    fn directory_absent(&self, directory: &PrivateDirectory) -> Result<bool, ObserveFailure> {
        match std::fs::symlink_metadata(directory.path().as_str()) {
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

impl Drop for WindowsQemuHost {
    /// Ends every process still held, at once, and removes its private directory, so
    /// nothing a start prepared outlives the host.
    fn drop(&mut self) {
        let at_once = Escalation {
            grace: Duration::ZERO,
            kill_wait: self.settings.escalation.kill_wait,
        };
        for (_, held) in std::mem::take(&mut self.held) {
            let _ended = held.process.terminate(at_once);
            drop(held.process);
            drop(held.network);
            let _removed = remove_private_directory(&held.directory);
        }
    }
}

#[cfg(test)]
#[path = "windows_host_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "windows_launch_tests.rs"]
mod launch_tests;

/// PROVES the acceptance plant adds one share device, the firmware directory as a
/// read-only FAT drive, to the next start only, and that the backend's reading of a
/// process command line finds it as a share device (VM-CP-03's positive control).
#[cfg(all(test, feature = "acceptance"))]
#[test]
fn the_planted_share_device_is_added_once_and_read_as_a_share_device() {
    use std::sync::atomic::Ordering;
    let mut arguments = vec![
        "qemu-system-x86_64.exe".to_owned(),
        "-L".to_owned(),
        "C:/runtime/qemu/share".to_owned(),
    ];
    plant_share_device(&mut arguments);
    assert_eq!(arguments.len(), 3, "nothing is planted unless asked");
    PLANT_SHARE_DEVICE.store(true, Ordering::SeqCst);
    plant_share_device(&mut arguments);
    assert_eq!(
        arguments[3..],
        [
            "-blockdev".to_owned(),
            "driver=vvfat,node-name=planted-share,dir=C:/runtime/qemu/share,read-only=on"
                .to_owned()
        ]
    );
    plant_share_device(&mut arguments);
    assert_eq!(arguments.len(), 5, "planted once");
    let observed = crate::sandbox::qemu::ObservedArgv::from_process_listing(&arguments).unwrap();
    let refusal = crate::sandbox::qemu::parse_observed(&observed).unwrap_err();
    assert!(
        refusal.findings().iter().any(|finding| matches!(
            finding,
            crate::sandbox::qemu::ArgvFinding::ShareDevice { .. }
        )),
        "{:?}",
        refusal.findings()
    );
}
