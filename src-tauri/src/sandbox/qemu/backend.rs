//! The QEMU backend behind the backend contract, the library half of M02
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md: VM-W16 row, line 2615; VM-W19 row,
//! line 2618; VM-W22 row, line 2621; §3.4 line 2101; §6.4 line 2322; §7.3 lines 2378
//! and 2386; §8.1 lines 2433–2439; VM-CP-01 to VM-CP-04, lines 3151–3154; VM-D2, line
//! 3196).
//!
//! [`QemuBackend`] implements [`VmBackend`] over the host ports of `ports.rs`. A launch,
//! refusing at the first failure:
//!
//! 1. A launch of a boot that runs, with the same request, is the same VM; any other
//!    launch of a boot generation that was used is refused.
//! 2. The backend's [`precheck`]: the pinned build, the features offered and fresh
//!    host-probed CORE-01 evidence that the hardware hypervisor is available. Nothing is
//!    looked up or created before it passes.
//! 3. The host layout's inputs and the plan of [`plan_launch`]: a QEMU build for this
//!    host's hypervisor, every required confinement control applied by the platform, the
//!    declared volumes only, and the CORE-03 reservation open for this launch and holding
//!    the guest memory (on Windows also the Job's memory limit).
//! 4. The release's golden file in [`QemuSettings`] approves the plan (VM-CP-02, line
//!    3152): it is intact, recorded for this build and for the plan's profile and
//!    platform, and the plan's vector is its configuration ([`GoldenFile::compare_plan`]).
//! 5. The host process port starts the exact vector under the plan's restrictions, as the
//!    host process of this VM boot (CORE-04 [`ProcessRole::VmHost`]); the boot generation
//!    counts as used from here on.
//! 6. The host observes the running VM: the process runs; its listing is the pinned
//!    executable with exactly the plan's vector ([`check_observed`]: no TCG, no share
//!    device, no network listener for a monitor); on Windows its token, Job, handles and
//!    mitigations are the plan's ([`check_windows`]); QMP reports it running and names
//!    the accelerator it actually uses. Once the listing passed, the observed vector's
//!    comparison with the golden file and the listing itself are the configuration facts
//!    of VM-CP-02 and VM-CP-03.
//! 7. [`admit_with_configuration`] checks the evidence, the accelerator (hardware, and
//!    this backend's hypervisor: VM-W22), the currency of every observation, every §1.3
//!    facet and the configuration facts, and seals the launch record, which binds them.
//!
//! Any refusal after step 5 asks QEMU to quit, ends its process with the host's proof and
//! removes it before the refusal is returned. Where the host cannot show the end, the
//! refusal says so ([`QemuRefusal::NotStopped`]) and the VM stays held and listed by
//! [`VmBackend::running`] until a stop succeeds; the contract states it as
//! [`LaunchRefusal::CleanupIncomplete`], naming the process and the host files that may
//! remain. There is no emulation path.
//!
//! [`QemuRefusal::launch_refusal`] states every refusal in the contract's terms by what
//! the host observed: a layout, profile or golden file refusal before anything started, a
//! vector or executable that is not the approved profile (VM-CP-02, VM-CP-03), Windows
//! restrictions not in effect (VM-CP-04), a process that ended or a VM QEMU reports not
//! running, or a QEMU-specific refusal such as an unusable listing or QMP. Only a start the
//! host process port refused, which leaves nothing behind, is a create failure.
//!
//! [`VmBackend::reobserve`] runs step 6 again on a running, admitted VM: the process, its
//! listing against the launch's plan, the Windows restrictions, QMP's run state and
//! accelerator, the host build, the guest image as the layout's image store verifies it
//! now at the plan's root image path, and the golden comparison and listing made again,
//! which the record judges as admission did. A process that ended, a vector that changed
//! or restrictions no longer in effect refuse as at launch.
//!
//! The facts admission judges come from the host: the accelerator from QMP; the
//! confinement controls from the Windows check; the host build from the host process
//! port; and the rest from the observed vector being exactly the plan's profile, which
//! has no network, share, display or GPU device, attaches the root image read-only and
//! the declared volumes only, and passes the link secret by a file. No guest assertion is
//! taken. On Linux and macOS this backend observes no confinement yet (the launcher of
//! VM-D15 and the macOS helper are later work), so a launch that requires any control is
//! refused there.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Duration;

use serde::Serialize;

use super::argv::{ObservedArgv, ObservedArgvError};
use super::golden::{GoldenComparison, GoldenFile, GoldenRefusal};
use super::linux::{check_linux, LinuxFinding};
use super::parse::{check_observed, ArgvFinding, ArgvRefusal};
use super::platform::hypervisor_named;
use super::ports::{
    HostInputs, LaunchLayout, LayoutRefusal, MonitorFailure, ObserveFailure, ProcessState,
    QemuHost, QemuMonitor, RunState, StartFailure, TerminationEvidence,
};
use super::profile::{plan_launch, qemu_features, ProfileRefusal, QemuLaunchPlan, ReservationView};
use super::values::{HostPath, PrivateDirectory};
use super::windows::{check_windows, WindowsFinding};
use crate::foundation::coordination::{SnapshotManifest, SnapshotOrigin, VmInstanceId};
use crate::foundation::evidence::{ClockReading, ConfigurationFingerprint, UnknownReason};
use crate::foundation::ids::{Digest, ExecutionId, SandboxBootGeneration};
use crate::foundation::process::{NoProof, ProcessIdentity, ProcessRole};
use crate::sandbox::backend::{
    admit_with_configuration, precheck, reobserved_with_configuration, vm_handle, Accelerator,
    BackendFeatures, BackendIdentity, BackendKind, BackendOperation, BackendRefusal,
    ConfigurationCheck, ConfigurationComparison, ConfigurationFacts, CredentialExposure,
    DeviceInventory, Emulator, FactName, Feature, GuestAssertions, HardwareFailure, HostEvidence,
    HostFact, HostInterfaceListing, HostObserved, IsolationObservation, LaunchFacts, LaunchRefusal,
    LaunchRequest, Launched, LeftBehind, NetworkAuthority, ObservedProperties,
    OperatorConfidentiality, Persistence, PhysicalHost, Reobservation, ReobservationRefusal,
    Restored, StopOutcome, VmBackend, VmProcessState,
};

/// What the backend is configured with besides its identity and ports.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct QemuSettings {
    /// The pinned QEMU executable, exactly as the host's process listing names it.
    pub executable: HostPath,
    /// How long each of the backend's host observations stays fresh.
    pub fresh_for: Duration,
    /// The release's golden file of this build's profile on this host (VM-CP-02, line
    /// 3152: versioned with the backend). A launch whose plan is not its configuration is
    /// refused before QEMU starts, and the running process's vector is compared with it
    /// once its listing passed [`check_observed`].
    pub golden: GoldenFile,
}

/// Why the host could not show that a VM's process ended.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum EndNotProven {
    /// The host did not observe the end of the process and its job.
    NoProof { no_proof: NoProof },
    /// The port's proof names another process or role than the one held for the VM.
    OtherProcess {
        proven: ProcessIdentity,
        role: ProcessRole,
    },
}

impl fmt::Display for EndNotProven {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoProof { no_proof } => {
                write!(
                    f,
                    "the host did not observe the end of the VM's process: {no_proof}"
                )
            }
            Self::OtherProcess { proven, role } => write!(
                f,
                "the host's proof is of {proven} as {role}, not of the process held for the VM"
            ),
        }
    }
}

impl std::error::Error for EndNotProven {}

/// Why a QEMU launch was refused, in this backend's own terms; [`VmBackend::launch`]
/// returns [`QemuRefusal::launch_refusal`]. Every refusal from [`QemuRefusal::NotObserved`]
/// down came after QEMU was started; the VM was stopped and removed before it was
/// returned, unless it is wrapped in [`QemuRefusal::NotStopped`]. Serialize only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum QemuRefusal {
    /// The backend contract's own refusal: before anything started, the precheck or a
    /// used boot generation; at start, a hardware virtualization failure, which leaves
    /// nothing behind; after start, admission.
    Launch { refusal: Box<LaunchRefusal> },
    /// The host layout has no inputs for the launch; nothing was started.
    Layout { refusal: LayoutRefusal },
    /// The profile cannot be built for the launch; nothing was started.
    Profile { refusal: Box<ProfileRefusal> },
    /// The release's golden file cannot judge the plan: its digest does not cover its
    /// content, or it was recorded for another build, profile or platform (VM-CP-02);
    /// nothing was started.
    Golden { refusal: GoldenRefusal },
    /// The plan's vector is not the release's golden configuration (VM-CP-02); nothing was
    /// started.
    NotGolden { comparison: GoldenComparison },
    /// The host process port could not start QEMU; it left nothing behind.
    Start { failure: StartFailure },
    /// The host could not observe the started process.
    NotObserved { failure: ObserveFailure },
    /// The process ended before the launch was admitted.
    Ended { exit_code: u32 },
    /// The host's process listing is not a usable vector.
    Listing { error: ObservedArgvError },
    /// The process runs another executable than the pinned QEMU build.
    OtherExecutable {
        expected: HostPath,
        observed: String,
    },
    /// The process's vector is not the plan's (VM-CP-01, VM-CP-02, VM-CP-03).
    Arguments { refusal: ArgvRefusal },
    /// The host has no observation of the process's restrictions (on Windows its token and
    /// Job, on Linux its status, cgroup and network namespace).
    RestrictionsNotObserved,
    /// On Windows, restrictions of the plan are not in effect (VM-CP-04).
    RestrictionsNotInEffect { findings: Vec<WindowsFinding> },
    /// On Linux, restrictions of the plan are not in effect (VM-CP-04).
    LinuxRestrictionsNotInEffect { findings: Vec<LinuxFinding> },
    /// QMP could not be used.
    Monitor { failure: MonitorFailure },
    /// QEMU reports the VM in another state than running.
    NotRunning { status: String },
    /// The launch of `vm` was refused after QEMU started, and the host could not show its
    /// process ended. The VM stays held and listed as running until a stop succeeds.
    NotStopped {
        vm: VmInstanceId,
        refusal: Box<QemuRefusal>,
        problem: EndNotProven,
    },
}

impl QemuRefusal {
    fn contract(refusal: LaunchRefusal) -> Self {
        Self::Launch {
            refusal: Box::new(refusal),
        }
    }

    fn from_profile(refusal: ProfileRefusal) -> Self {
        match refusal {
            ProfileRefusal::Launch { refusal } => Self::contract(refusal),
            refusal => Self::Profile {
                refusal: Box::new(refusal),
            },
        }
    }

    /// The refusal as the backend contract states it, by what the host observed. The
    /// contract's own refusals pass through; a layout refusal is
    /// [`LaunchRefusal::LayoutRefused`]; a profile refusal and a golden file that does not
    /// approve the plan are [`LaunchRefusal::ProfileRefused`]; only a start the host
    /// process port refused, which leaves nothing behind, is
    /// [`LaunchRefusal::CreateFailed`]; a vector naming TCG is
    /// [`LaunchRefusal::NotHardwareVirtualized`]; any other vector or executable than the
    /// plan's is [`LaunchRefusal::ConfigurationNotApproved`]; restrictions not observed or
    /// not in effect are [`LaunchRefusal::ConfinementNotInEffect`]; a process that ended,
    /// is not held or is not running is [`LaunchRefusal::ProcessNotRunning`]; an unusable
    /// listing, observation or QMP is [`LaunchRefusal::BackendSpecific`]; and a refusal
    /// whose VM could not be shown stopped is [`LaunchRefusal::CleanupIncomplete`], with
    /// its reason and what may remain.
    pub fn launch_refusal(&self) -> LaunchRefusal {
        let backend = BackendKind::Qemu;
        match self {
            Self::Launch { refusal } => (**refusal).clone(),
            Self::Layout { refusal } => LaunchRefusal::LayoutRefused {
                backend,
                detail: refusal.to_string(),
            },
            Self::Profile { refusal } => LaunchRefusal::ProfileRefused {
                backend,
                detail: refusal.to_string(),
            },
            Self::Golden { refusal } => LaunchRefusal::ProfileRefused {
                backend,
                detail: format!("the release's golden file cannot judge the plan: {refusal}"),
            },
            Self::NotGolden { comparison } => LaunchRefusal::ProfileRefused {
                backend,
                detail: plan_not_golden(comparison),
            },
            Self::Start { .. } => LaunchRefusal::CreateFailed {
                detail: self.to_string(),
            },
            Self::NotObserved {
                failure: ObserveFailure::NotHeld { .. },
            } => LaunchRefusal::ProcessNotRunning {
                backend,
                state: VmProcessState::Gone,
            },
            Self::NotObserved { .. } | Self::Listing { .. } | Self::Monitor { .. } => {
                LaunchRefusal::BackendSpecific {
                    backend,
                    detail: self.to_string(),
                }
            }
            Self::Ended { exit_code } => LaunchRefusal::ProcessNotRunning {
                backend,
                state: VmProcessState::Exited {
                    exit_code: *exit_code,
                },
            },
            Self::NotRunning { status } => LaunchRefusal::ProcessNotRunning {
                backend,
                state: VmProcessState::NotRunning {
                    status: status.clone(),
                },
            },
            Self::OtherExecutable { .. } => LaunchRefusal::ConfigurationNotApproved {
                backend,
                checks: BTreeSet::from([ConfigurationCheck::GoldenConfiguration]),
                findings: vec![self.to_string()],
            },
            Self::Arguments { refusal } if refusal.names_tcg() => {
                LaunchRefusal::NotHardwareVirtualized {
                    observed: Accelerator::Emulation {
                        emulator: Emulator::Tcg,
                    },
                }
            }
            Self::Arguments { refusal } => LaunchRefusal::ConfigurationNotApproved {
                backend,
                checks: configuration_checks(refusal.findings()),
                findings: refusal.findings().iter().map(ToString::to_string).collect(),
            },
            Self::RestrictionsNotObserved => LaunchRefusal::ConfinementNotInEffect {
                backend,
                observed: false,
                findings: Vec::new(),
            },
            Self::RestrictionsNotInEffect { findings } => LaunchRefusal::ConfinementNotInEffect {
                backend,
                observed: true,
                findings: findings.iter().map(ToString::to_string).collect(),
            },
            Self::LinuxRestrictionsNotInEffect { findings } => {
                LaunchRefusal::ConfinementNotInEffect {
                    backend,
                    observed: true,
                    findings: findings.iter().map(ToString::to_string).collect(),
                }
            }
            Self::NotStopped {
                vm,
                refusal,
                problem,
            } => LaunchRefusal::CleanupIncomplete {
                vm: *vm,
                refusal: Box::new(refusal.launch_refusal()),
                left: left_behind(problem),
            },
        }
    }
}

/// The configuration checks a vector's findings fail: any finding means the vector is not
/// the approved profile's (VM-CP-02); a share device, a monitor or debug interface on a
/// listener or a pipe QEMU creates, or a forward to the old agent port also fails
/// VM-CP-03.
fn configuration_checks(findings: &[ArgvFinding]) -> BTreeSet<ConfigurationCheck> {
    let mut checks = BTreeSet::from([ConfigurationCheck::GoldenConfiguration]);
    if findings.iter().any(|finding| {
        matches!(
            finding,
            ArgvFinding::ShareDevice { .. }
                | ArgvFinding::ManagementListener { .. }
                | ArgvFinding::ForwardToOldAgentPort { .. }
                | ArgvFinding::PipeEndpoint { .. }
                | ArgvFinding::DebugInterface { .. }
        )
    }) {
        checks.insert(ConfigurationCheck::HostInterfaces);
    }
    checks
}

/// How a plan's vector differs from the golden file's: the first four differences, then
/// how many more there are, and whether the arguments are in another order.
fn plan_not_golden(comparison: &GoldenComparison) -> String {
    const SHOWN: usize = 4;
    let mut found: Vec<String> = comparison
        .differences
        .iter()
        .take(SHOWN)
        .map(ToString::to_string)
        .collect();
    if comparison.differences.len() > SHOWN {
        found.push(format!("and {} more", comparison.differences.len() - SHOWN));
    }
    if comparison.reordered {
        found.push("the arguments are in another order".to_owned());
    }
    let mut text = format!(
        "the planned vector is not the configuration of golden file {}",
        comparison.golden
    );
    if !found.is_empty() {
        text.push_str(": ");
        text.push_str(&found.join("; "));
    }
    text
}

/// What may remain of a VM the host could not show stopped: its process and, when the host
/// observed no end at all, the host files the port removes only after the end.
fn left_behind(problem: &EndNotProven) -> Vec<LeftBehind> {
    let mut left = vec![LeftBehind::Process {
        detail: problem.to_string(),
    }];
    if let EndNotProven::NoProof { .. } = problem {
        left.push(LeftBehind::HostResource {
            step: "remove_host_files".to_owned(),
            detail: "the private directory and the link secret file are removed only once the \
                     host shows the process ended"
                .to_owned(),
        });
    }
    left
}

impl fmt::Display for QemuRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Launch { refusal } => write!(f, "{refusal}"),
            Self::Layout { refusal } => write!(f, "{refusal}; nothing was started"),
            Self::Profile { refusal } => write!(f, "{refusal}; nothing was started"),
            Self::Golden { refusal } => write!(
                f,
                "the release's golden file cannot judge the plan: {refusal}; nothing was started"
            ),
            Self::NotGolden { comparison } => {
                write!(f, "{}; nothing was started", plan_not_golden(comparison))
            }
            Self::Start { failure } => {
                write!(
                    f,
                    "QEMU could not be started, and nothing is left behind: {failure}"
                )
            }
            Self::NotObserved { failure } => write!(f, "{failure}"),
            Self::Ended { exit_code } => write!(
                f,
                "QEMU exited with code {exit_code} before the launch was admitted"
            ),
            Self::Listing { error } => write!(f, "the host's listing of QEMU is unusable: {error}"),
            Self::OtherExecutable { expected, observed } => write!(
                f,
                "the process runs {observed}, not the pinned QEMU build {expected}"
            ),
            Self::Arguments { refusal } => write!(f, "{refusal}"),
            Self::RestrictionsNotObserved => {
                f.write_str("the host did not observe the QEMU process's restrictions")
            }
            Self::LinuxRestrictionsNotInEffect { findings } => {
                write!(
                    f,
                    "{} of the launch's Linux restrictions {} not in effect",
                    findings.len(),
                    if findings.len() == 1 { "is" } else { "are" }
                )?;
                for (index, finding) in findings.iter().enumerate() {
                    f.write_str(if index == 0 { ": " } else { "; " })?;
                    write!(f, "{finding}")?;
                }
                Ok(())
            }
            Self::RestrictionsNotInEffect { findings } => {
                write!(
                    f,
                    "{} of the launch's Windows restrictions {} not in effect",
                    findings.len(),
                    if findings.len() == 1 { "is" } else { "are" }
                )?;
                for (index, finding) in findings.iter().enumerate() {
                    f.write_str(if index == 0 { ": " } else { "; " })?;
                    write!(f, "{finding}")?;
                }
                Ok(())
            }
            Self::Monitor { failure } => write!(f, "{failure}"),
            Self::NotRunning { status } => {
                write!(f, "QEMU reports the VM {status}, not running")
            }
            Self::NotStopped {
                refusal, problem, ..
            } => write!(
                f,
                "{refusal}; the VM could not be shown stopped ({problem}) and stays listed \
                 until a stop succeeds"
            ),
        }
    }
}

impl std::error::Error for QemuRefusal {}

/// One VM whose process the backend holds.
#[derive(Clone, Debug)]
struct HeldVm {
    request: LaunchRequest,
    /// The plan the process was started with, which a re-observation checks it against.
    plan: QemuLaunchPlan,
    process: ProcessIdentity,
    role: ProcessRole,
    control: PrivateDirectory,
    /// The admitted launch; `None` while a refused launch's VM is not shown stopped.
    launched: Option<Launched>,
}

/// Stamps the backend's host observations of one launch: now, on the evidence clock,
/// under the configuration the CORE-01 evidence was observed under.
struct Stamp {
    now: ClockReading,
    fresh_for: Duration,
    configuration: ConfigurationFingerprint,
}

impl Stamp {
    fn observed<T>(&self, value: T) -> HostObserved<T> {
        HostObserved::stamp(value, self.now, self.fresh_for, self.configuration)
    }

    fn fact<T>(&self, value: T) -> HostFact<T> {
        HostFact::observed(self.observed(value))
    }
}

/// The accelerator a QMP accelerator name stands for: a hardware hypervisor this profile
/// uses, or TCG; anything else is not one this backend can judge.
fn accelerator_named(name: &str) -> Option<Accelerator> {
    if name == Emulator::Tcg.tag() {
        return Some(Accelerator::Emulation {
            emulator: Emulator::Tcg,
        });
    }
    hypervisor_named(name).map(|hypervisor| Accelerator::Hardware { hypervisor })
}

fn unknown_from_monitor(failure: &MonitorFailure) -> UnknownReason {
    match failure {
        MonitorFailure::Unreachable { .. } => UnknownReason::Unreachable,
        MonitorFailure::Protocol { .. } => UnknownReason::Inconclusive,
    }
}

fn unknown_from_host(failure: &ObserveFailure) -> UnknownReason {
    match failure {
        ObserveFailure::NotHeld { .. } => UnknownReason::Unreachable,
        ObserveFailure::Unreadable { .. } => UnknownReason::Inconclusive,
    }
}

/// The persistence the plan's vector gives: the root image is read-only, so the attached
/// data volumes are the only writable state. Whether volumes are declared data or a
/// controlled service renewal is the request's lifecycle, not something a process shows.
fn persistence_of(request: &LaunchRequest, plan: &QemuLaunchPlan) -> Persistence {
    let attached: BTreeSet<Digest> = plan.volumes().keys().copied().collect();
    match &request.required.persistence {
        Persistence::ControlledServiceRenewal { .. } => {
            Persistence::ControlledServiceRenewal { volumes: attached }
        }
        Persistence::EphemeralTask if attached.is_empty() => Persistence::EphemeralTask,
        _ => Persistence::DeclaredDataVolumes { volumes: attached },
    }
}

/// The QEMU backend (VM-W19), over a host process port `H`, a QMP port `M`, the host
/// layout `L` and the CORE-03 reservations `R`.
///
/// A VM's handle is the digest of its sandbox and boot generation ([`vm_handle`]), bound
/// to the CORE-04 identity of the process started for that boot; the process is never
/// named by a PID alone. Every boot generation that started a process is used.
pub struct QemuBackend<H: QemuHost, M, L, R> {
    identity: BackendIdentity,
    features: BackendFeatures,
    settings: QemuSettings,
    host: H,
    monitor: M,
    layout: L,
    reservations: R,
    held: BTreeMap<VmInstanceId, HeldVm>,
    ended: BTreeMap<VmInstanceId, H::Proof>,
    used_boots: BTreeSet<(ExecutionId, SandboxBootGeneration)>,
}

impl<H: QemuHost, M, L, R> fmt::Debug for QemuBackend<H, M, L, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QemuBackend")
            .field("identity", &self.identity)
            .field("settings", &self.settings)
            .field("held", &self.held.keys().collect::<Vec<_>>())
            .field("ended", &self.ended.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl<H, M, L, R> QemuBackend<H, M, L, R>
where
    H: QemuHost,
    M: QemuMonitor,
    L: LaunchLayout,
    R: ReservationView,
{
    /// A backend for the QEMU build `identity`, offering launch and stop only
    /// ([`qemu_features`]). A build of another kind or hypervisor than the host's profile
    /// is refused at each launch by [`plan_launch`].
    pub fn new(
        identity: BackendIdentity,
        settings: QemuSettings,
        host: H,
        monitor: M,
        layout: L,
        reservations: R,
    ) -> Self {
        Self {
            identity,
            features: qemu_features(),
            settings,
            host,
            monitor,
            layout,
            reservations,
            held: BTreeMap::new(),
            ended: BTreeMap::new(),
            used_boots: BTreeSet::new(),
        }
    }

    pub fn settings(&self) -> &QemuSettings {
        &self.settings
    }

    pub fn reservations(&self) -> &R { &self.reservations }

    pub fn host(&self) -> &H {
        &self.host
    }

    pub fn host_mut(&mut self) -> &mut H {
        &mut self.host
    }

    pub fn monitor(&self) -> &M {
        &self.monitor
    }

    pub fn monitor_mut(&mut self) -> &mut M {
        &mut self.monitor
    }

    pub fn layout(&self) -> &L {
        &self.layout
    }

    pub fn layout_mut(&mut self) -> &mut L {
        &mut self.layout
    }

    /// The process the backend holds for `vm`, until the host shows it ended.
    pub fn process_of(&self, vm: &VmInstanceId) -> Option<ProcessIdentity> {
        self.held.get(vm).map(|held| held.process)
    }

    /// The host's proof that `vm`'s process ended, once a stop or a refused launch's
    /// cleanup observed it.
    pub fn termination(&self, vm: &VmInstanceId) -> Option<&H::Proof> {
        self.ended.get(vm)
    }

    /// Launches one boot, or refuses with this backend's typed refusal; the steps are in
    /// the module documentation.
    pub fn launch_qemu(
        &mut self,
        request: &LaunchRequest,
        host: &dyn HostEvidence,
    ) -> Result<Launched, QemuRefusal> {
        let boot = request.generations.boot;
        let vm = vm_handle(BackendKind::Qemu, &request.execution, boot);
        if let Some(launched) = self.running_launch(&vm, request) {
            return Ok(launched);
        }
        if self.used_boots.contains(&(request.execution.clone(), boot)) {
            return Err(QemuRefusal::contract(LaunchRefusal::BootGenerationUsed {
                execution: request.execution.clone(),
                boot,
            }));
        }
        precheck(request, &self.identity, &self.features, host).map_err(QemuRefusal::contract)?;
        let reserved = self
            .reservations
            .reserved_vm(request.reservation)
            .ok_or_else(|| {
                QemuRefusal::from_profile(ProfileRefusal::ReservationNotFound {
                    reservation: request.reservation,
                })
            })?;
        let HostInputs {
            inputs,
            guest_image,
        } = self
            .layout
            .inputs_with_reserved_resources(request, vm, reserved.ram_bytes, reserved.cpu_slots)
            .map_err(|refusal| QemuRefusal::Layout { refusal })?;
        let plan = plan_launch(request, &self.identity, host, &self.reservations, inputs)
            .map_err(QemuRefusal::from_profile)?;
        let planned = self
            .settings
            .golden
            .compare_plan(plan.profile(), &self.identity)
            .map_err(|refusal| QemuRefusal::Golden { refusal })?;
        if !planned.matches() {
            return Err(QemuRefusal::NotGolden {
                comparison: planned,
            });
        }
        let role = ProcessRole::VmHost {
            execution: request.execution.clone(),
            vm,
            boot,
        };
        let hypervisor = self.identity.hypervisor;
        let process = self
            .host
            .start(&role, &self.settings.executable, &plan)
            .map_err(|failure| match failure {
                StartFailure::HardwareVirtualization { detail } => {
                    QemuRefusal::contract(LaunchRefusal::HardwareVirtualizationFailed {
                        failure: HardwareFailure { hypervisor, detail },
                    })
                }
                failure => QemuRefusal::Start { failure },
            })?;
        self.used_boots.insert((request.execution.clone(), boot));
        self.held.insert(
            vm,
            HeldVm {
                request: request.clone(),
                plan: plan.clone(),
                process,
                role,
                control: plan.profile().control().clone(),
                launched: None,
            },
        );
        match self.observe_and_admit(request, host, &plan, guest_image, vm, process) {
            Ok(launched) => {
                if let Some(held) = self.held.get_mut(&vm) {
                    held.launched = Some(launched.clone());
                }
                Ok(launched)
            }
            Err(refusal) => Err(match self.end(vm) {
                Ok(_) => refusal,
                Err(problem) => QemuRefusal::NotStopped {
                    vm,
                    refusal: Box::new(refusal),
                    problem,
                },
            }),
        }
    }

    /// The launch of `vm` when it was admitted for this same request and its process
    /// runs.
    fn running_launch(&self, vm: &VmInstanceId, request: &LaunchRequest) -> Option<Launched> {
        let held = self.held.get(vm)?;
        let launched = held.launched.as_ref()?;
        let runs = matches!(self.host.state(&held.process), Ok(ProcessState::Running));
        (held.request == *request && runs).then(|| launched.clone())
    }

    /// Steps 6 and 7: observes the started process through the host and QMP, and admits
    /// the launch on what was observed, its configuration facts included.
    fn observe_and_admit(
        &self,
        request: &LaunchRequest,
        host: &dyn HostEvidence,
        plan: &QemuLaunchPlan,
        guest_image: Digest,
        vm: VmInstanceId,
        process: ProcessIdentity,
    ) -> Result<Launched, QemuRefusal> {
        let (facts, configuration) = self.observe(request, host, plan, Ok(guest_image), process)?;
        let record = admit_with_configuration(
            request,
            &self.identity,
            host,
            plan.evidence().clone(),
            facts,
            configuration,
            vm,
            None,
        )
        .map_err(QemuRefusal::contract)?;
        Ok(Launched { vm, record })
    }

    /// Step 6: observes the process through the host and QMP, and returns the facts of
    /// what was observed, stamped now; the guest image is the image store's identity of
    /// the plan's root image, or the reason the host has none. The configuration facts are
    /// the observed vector's comparison with the golden file, with none of the devices
    /// VM-CP-02 names since [`check_observed`] refuses each of them, and the listing with
    /// every restriction of VM-CP-03 in place, which [`check_observed`] shows.
    fn observe(
        &self,
        request: &LaunchRequest,
        host: &dyn HostEvidence,
        plan: &QemuLaunchPlan,
        guest_image: Result<Digest, UnknownReason>,
        process: ProcessIdentity,
    ) -> Result<(LaunchFacts, ConfigurationFacts), QemuRefusal> {
        let inspection = self
            .host
            .inspect(&process)
            .map_err(|failure| QemuRefusal::NotObserved { failure })?;
        if let ProcessState::Ended { exit_code } = inspection.state {
            return Err(QemuRefusal::Ended { exit_code });
        }
        let observed = ObservedArgv::from_process_listing(&inspection.command_line)
            .map_err(|error| QemuRefusal::Listing { error })?;
        if observed.executable() != self.settings.executable.as_str() {
            return Err(QemuRefusal::OtherExecutable {
                expected: self.settings.executable.clone(),
                observed: observed.executable().to_owned(),
            });
        }
        check_observed(&observed, plan.profile())
            .map_err(|refusal| QemuRefusal::Arguments { refusal })?;

        let configuration = plan.evidence().configuration();
        let max_age = request.required.evidence.max_age;
        let stamp = Stamp {
            now: host.now(),
            fresh_for: self.settings.fresh_for,
            configuration,
        };
        // The golden file was shown to apply to this plan before QEMU started.
        let golden = self
            .settings
            .golden
            .compare_applicable(&observed, plan.profile());
        let configuration_facts = ConfigurationFacts {
            comparison: Some(stamp.observed(ConfigurationComparison {
                golden: golden.golden,
                observed: golden.observed,
                network_device: plan.profile().internet(),
                console: false,
                balloon: false,
                undeclared_pci_transport: false,
            })),
            listing: Some(stamp.observed(HostInterfaceListing::clean())),
            gpu_assignments: Vec::new(),
        };
        let confinement = match (plan.windows(), plan.linux()) {
            (None, Some(expected)) => {
                let state = inspection
                    .linux
                    .ok_or(QemuRefusal::RestrictionsNotObserved)?;
                let check = check_linux(
                    expected,
                    &stamp.observed(state),
                    stamp.now,
                    max_age,
                    configuration,
                )
                .map_err(|problem| {
                    QemuRefusal::contract(LaunchRefusal::ObservationNotCurrent {
                        fact: FactName::Confinement,
                        problem,
                    })
                })?;
                if !check.passed() {
                    return Err(QemuRefusal::LinuxRestrictionsNotInEffect {
                        findings: check.findings().to_vec(),
                    });
                }
                stamp.fact(check.controls_observed())
            }
            (Some(expected), _) => {
                let state = inspection
                    .windows
                    .ok_or(QemuRefusal::RestrictionsNotObserved)?;
                let check = check_windows(
                    expected,
                    &stamp.observed(state),
                    stamp.now,
                    max_age,
                    configuration,
                )
                .map_err(|problem| {
                    QemuRefusal::contract(LaunchRefusal::ObservationNotCurrent {
                        fact: FactName::Confinement,
                        problem,
                    })
                })?;
                if !check.passed() {
                    return Err(QemuRefusal::RestrictionsNotInEffect {
                        findings: check.findings().to_vec(),
                    });
                }
                stamp.fact(check.controls_observed())
            }
            (None, None) => HostFact::unavailable(UnknownReason::NotTested),
        };

        let socket = plan.profile().control().qmp_socket();
        match self
            .monitor
            .status(socket)
            .map_err(|failure| QemuRefusal::Monitor { failure })?
        {
            RunState::Running => {}
            RunState::NotRunning { status } => return Err(QemuRefusal::NotRunning { status }),
        }
        let accelerator = match self.monitor.accelerator(socket) {
            Ok(name) => match accelerator_named(&name) {
                Some(accelerator) => stamp.fact(accelerator),
                None => HostFact::unavailable(UnknownReason::InconsistentReport),
            },
            Err(failure) => HostFact::unavailable(unknown_from_monitor(&failure)),
        };
        let host_build = match self.host.host_build() {
            Ok(build) => stamp.fact(build),
            Err(failure) => HostFact::unavailable(unknown_from_host(&failure)),
        };

        let facts = LaunchFacts {
            accelerator,
            observed: ObservedProperties {
                host: host_build,
                guest_image: match guest_image {
                    Ok(image) => stamp.fact(image),
                    Err(reason) => HostFact::unavailable(reason),
                },
                isolation: stamp.fact(IsolationObservation {
                    own_guest_kernel: true,
                    physical_host: PhysicalHost::Shared,
                }),
                confinement,
                network: stamp.fact(if plan.profile().internet() {
                    NetworkAuthority::of([crate::sandbox::backend::NetworkChannel::Internet])
                } else { NetworkAuthority::offline() }),
                credentials: stamp.fact(CredentialExposure::none()),
                persistence: stamp.fact(persistence_of(request, plan)),
                devices: stamp.fact(DeviceInventory::cpu_only()),
                confidentiality: stamp.fact(OperatorConfidentiality::None),
            },
            guest: GuestAssertions::none(),
        };
        Ok((facts, configuration_facts))
    }

    /// Ends the process held for `vm`: asks QEMU to quit unless its process already
    /// ended, then has the host end the process and its job and accepts only a proof of
    /// that very process under its role. On the proof the VM moves to the ended. Returns
    /// whether the process had ended before; a VM not held has no process to end.
    fn end(&mut self, vm: VmInstanceId) -> Result<bool, EndNotProven> {
        let Some(held) = self.held.get(&vm) else {
            return Ok(true);
        };
        let process = held.process;
        let role = held.role.clone();
        let socket = held.control.qmp_socket().clone();
        let already_ended = matches!(self.host.state(&process), Ok(ProcessState::Ended { .. }));
        if !already_ended {
            // Only a request: the end is shown by the host's proof alone, so a refused
            // or failed quit changes nothing here.
            let _asked = self.monitor.quit(&socket);
        }
        let proof = self
            .host
            .terminate(&process)
            .map_err(|no_proof| EndNotProven::NoProof { no_proof })?;
        if proof.identity() != process || *proof.role() != role {
            return Err(EndNotProven::OtherProcess {
                proven: proof.identity(),
                role: proof.role().clone(),
            });
        }
        self.held.remove(&vm);
        self.ended.insert(vm, proof);
        Ok(already_ended)
    }

    fn launched(&self, vm: &VmInstanceId) -> Result<&Launched, BackendRefusal> {
        match self.held.get(vm) {
            Some(HeldVm {
                launched: Some(launched),
                ..
            }) => Ok(launched),
            Some(_) => Err(BackendRefusal::Failed {
                operation: BackendOperation::Query,
                detail: "the VM's launch was refused and its process is not yet shown ended"
                    .to_owned(),
            }),
            None => Err(BackendRefusal::NoSuchVm { vm: *vm }),
        }
    }
}

impl<H, M, L, R> VmBackend for QemuBackend<H, M, L, R>
where
    H: QemuHost,
    M: QemuMonitor,
    L: LaunchLayout,
    R: ReservationView,
{
    fn identity(&self) -> &BackendIdentity {
        &self.identity
    }

    fn features(&self) -> &BackendFeatures {
        &self.features
    }

    fn launch(
        &mut self,
        request: &LaunchRequest,
        host: &dyn HostEvidence,
    ) -> Result<Launched, LaunchRefusal> {
        self.launch_qemu(request, host)
            .map_err(|refusal| refusal.launch_refusal())
    }

    /// Stops the VM: a VM whose end the host already proved, or whose process had ended,
    /// is already gone; one whose process the host cannot show ended is not stopped. A
    /// handle this backend never held is refused.
    fn stop(&mut self, vm: &VmInstanceId) -> Result<StopOutcome, BackendRefusal> {
        if self.ended.contains_key(vm) {
            return Ok(StopOutcome::AlreadyGone);
        }
        if !self.held.contains_key(vm) {
            return Err(BackendRefusal::NoSuchVm { vm: *vm });
        }
        match self.end(*vm) {
            Ok(true) => Ok(StopOutcome::AlreadyGone),
            Ok(false) => Ok(StopOutcome::Stopped),
            Err(problem) => Err(BackendRefusal::Failed {
                operation: BackendOperation::Stop,
                detail: problem.to_string(),
            }),
        }
    }

    /// Refused by name: the QEMU profile offers no snapshot ([`qemu_features`]).
    fn snapshot(
        &mut self,
        _vm: &VmInstanceId,
        _origin: SnapshotOrigin,
    ) -> Result<SnapshotManifest, BackendRefusal> {
        Err(BackendRefusal::Unsupported {
            feature: Feature::Snapshot,
        })
    }

    /// Refused by name before anything is checked or created: the QEMU profile offers no
    /// restore ([`qemu_features`]).
    fn restore(
        &mut self,
        _request: &LaunchRequest,
        _snapshot: &SnapshotManifest,
        _host: &dyn HostEvidence,
    ) -> Result<Restored, LaunchRefusal> {
        Err(LaunchRefusal::Unsupported {
            feature: Feature::Restore,
        })
    }

    /// The accelerator the host observed at launch, with its stamp, so a reader judges
    /// its freshness.
    fn actual_accelerator(
        &self,
        vm: &VmInstanceId,
    ) -> Result<HostObserved<Accelerator>, BackendRefusal> {
        self.launched(vm)
            .map(|launched| launched.record.accelerator().clone())
    }

    /// The host's observations at launch, with their stamps.
    fn confinement_evidence(
        &self,
        vm: &VmInstanceId,
    ) -> Result<ObservedProperties, BackendRefusal> {
        self.launched(vm)
            .map(|launched| launched.record.host_observed().clone())
    }

    /// Every VM whose process the backend holds and the host does not see ended, refused
    /// launches not yet shown stopped included. A process the host cannot observe is
    /// listed: it is not known to have ended.
    fn running(&self) -> Vec<VmInstanceId> {
        self.held
            .iter()
            .filter(|(_, held)| {
                !matches!(
                    self.host.state(&held.process),
                    Ok(ProcessState::Ended { .. })
                )
            })
            .map(|(vm, _)| *vm)
            .collect()
    }

    /// Observes an admitted, running VM again as step 6 did at launch: through the host
    /// process port, the launch's plan, QMP and the layout's image store, stamped now,
    /// with the golden comparison and the listing made again and the launch's CORE-01
    /// requirements evaluated again. A process that ended or is not running, a vector that
    /// is no longer the plan's or Windows restrictions no longer in effect refuse as they
    /// refuse a launch.
    fn reobserve(
        &mut self,
        vm: &VmInstanceId,
        host: &dyn HostEvidence,
    ) -> Result<Reobservation, ReobservationRefusal> {
        let held = self
            .held
            .get(vm)
            .ok_or(ReobservationRefusal::NoSuchVm { vm: *vm })?;
        let Some(launched) = &held.launched else {
            return Err(ReobservationRefusal::NotAdmitted { vm: *vm });
        };
        let guest_image = match self.layout.inputs(&held.request, *vm) {
            Ok(HostInputs {
                inputs,
                guest_image,
            }) if inputs.root_image == *held.plan.profile().root_image() => Ok(guest_image),
            Ok(_) => Err(UnknownReason::InconsistentReport),
            Err(_) => Err(UnknownReason::Unreachable),
        };
        let (facts, configuration) = self
            .observe(&held.request, host, &held.plan, guest_image, held.process)
            .map_err(|refusal| ReobservationRefusal::Refused {
                refusal: Box::new(refusal.launch_refusal()),
            })?;
        reobserved_with_configuration(
            &held.request,
            &launched.record,
            &self.identity,
            host,
            facts,
            configuration,
        )
    }
}
