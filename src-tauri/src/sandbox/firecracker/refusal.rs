//! Why a Firecracker launch was refused, typed, with the state of its cleanup, and how a
//! refusal reaches the backend contract (VM-W16 line 2615: no fallback may weaken required
//! properties, unsupported features are explicit; VM-W22 line 2621: nothing retries into
//! emulation).
//!
//! [`FirecrackerRefusal::launch_refusal`] states each refusal in the contract's terms by
//! what the host observed: the contract's own refusals and unsupported features pass
//! through; a reservation, plan or planned configuration the profile cannot provide is
//! [`LaunchRefusal::ProfileRefused`]; a running configuration other than the golden file
//! (VM-CP-02) is [`LaunchRefusal::ConfigurationNotApproved`]; a jailed process that
//! differs from the expected state or is not chrooted (VM-CP-04) is
//! [`LaunchRefusal::ConfinementNotInEffect`]; a process that is gone, replaced or not
//! running is [`LaunchRefusal::ProcessNotRunning`]; and the rest, such as a launcher or
//! API failure, is [`LaunchRefusal::BackendSpecific`]. [`LaunchFailure::to_launch_refusal`]
//! states a refusal whose cleanup is incomplete as [`LaunchRefusal::CleanupIncomplete`],
//! naming the process and every removal not done, never as a refusal that left nothing.
//! The typed refusal stays available from
//! [`FirecrackerBackend::launch_jailed`](super::FirecrackerBackend::launch_jailed).

use std::fmt;

use serde::Serialize;

use super::golden::{ForbiddenItem, GoldenCheck};
use super::host::IdRange;
use super::jail::{CleanupOutcome, CleanupReport, JailEnd};
use super::launcher::{ArtifactRole, LauncherRefusal};
use super::linux_state::LinuxStateReport;
use super::names::{HostPath, JailId};
use super::observe::RUNNING_STATE;
use super::plan::PlanRefusal;
use super::ports::{InstanceInfo, LauncherReport};
use super::status::StatusError;
use crate::foundation::coordination::VmInstanceId;
use crate::foundation::ids::ContentKey;
use crate::foundation::ledger::ReservationId;
use crate::foundation::process::{IdentityCheck, ProcessIdentity};
use crate::sandbox::backend::{
    BackendKind, ConfigurationCheck, LaunchRefusal, LeftBehind, VmProcessState,
};

/// Why a Firecracker launch was refused. Every variant is a refusal; none is a fallback.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FirecrackerRefusal {
    /// The contract's admission refused: its precheck before anything was created, or
    /// its admission once the host had observed the running VM.
    Admission { refusal: LaunchRefusal },
    /// The ledger holds no open reservation the request names.
    ReservationUnknown { reservation: ReservationId },
    /// An earlier launch of this boot left its jail behind, so its names are still taken.
    JailNotCleanedUp { jail: JailId },
    /// Every jail identity of the host's range is held by a running or uncleaned jail.
    NoJailIdentity { range: IdRange },
    /// No launch plan was made.
    Plan { refusal: PlanRefusal },
    /// The plan's configuration is not the approved golden file's; nothing was created.
    PlanNotGolden { check: GoldenCheck },
    /// The launch's session refused an operation; the launcher never saw it.
    Launcher { refusal: LauncherRefusal },
    /// The launcher failed an operation the session authorized.
    LauncherFailed { op: &'static str, detail: String },
    /// The launcher reported something other than the operation's result.
    UnexpectedReport {
        op: &'static str,
        report: LauncherReport,
    },
    /// The copy the launcher staged is not the pinned artifact.
    StagedArtifactDiffers {
        role: ArtifactRole,
        pinned: ContentKey,
        pinned_length: u64,
        staged: ContentKey,
        staged_length: u64,
    },
    /// The jailer exited with a failure code.
    JailerFailed { code: i32 },
    /// After the jailer ran, the jail's cgroup did not hold exactly one process.
    JailProcesses { found: Vec<ProcessIdentity> },
    /// The API socket could not be reached for `path`.
    ApiUnreachable { path: String, detail: String },
    /// Firecracker refused a call of the sequence; nothing after it was sent.
    ApiRefused {
        path: String,
        status: u16,
        fault_message: Option<String>,
    },
    /// Firecracker describes itself as another instance, not running, or with a version
    /// that is not an exact version.
    InstanceMismatch {
        expected_id: JailId,
        info: InstanceInfo,
    },
    /// The host could not make an observation it needs.
    ObservationFailed { detail: String },
    /// The process's identity no longer names a live process.
    ProcessNotHeld {
        process: ProcessIdentity,
        found: IdentityCheck,
    },
    /// The process's `/proc/<pid>/status` was refused by the strict parser.
    StatusUnreadable { error: StatusError },
    /// The status the host read names another PID than the process's.
    StatusOfAnotherProcess { process: ProcessIdentity, pid: u32 },
    /// The process's `/proc/<pid>/cgroup` is not one cgroup v2 line.
    CgroupUnreadable { text: String },
    /// VM-CP-04: what the host observed differs from the plan's expected state; every
    /// check is listed, the passing ones included.
    StateDiffers { report: LinuxStateReport },
    /// The process's root directory is not the jail's chroot.
    NotChrooted {
        expected: HostPath,
        observed: String,
    },
    /// VM-CP-02: the configuration Firecracker runs is not the approved golden file's.
    ConfigurationNotGolden { check: GoldenCheck },
}

fn shorten(text: &str) -> String {
    text.chars().take(128).collect()
}

impl FirecrackerRefusal {
    /// The refusal as the backend contract states it, by what the host observed; see the
    /// module documentation. Every variant is mapped by name.
    pub fn launch_refusal(&self) -> LaunchRefusal {
        let backend = BackendKind::Firecracker;
        let specific = || LaunchRefusal::BackendSpecific {
            backend,
            detail: self.to_string(),
        };
        let profile = || LaunchRefusal::ProfileRefused {
            backend,
            detail: self.to_string(),
        };
        let confinement = |findings: Vec<String>| LaunchRefusal::ConfinementNotInEffect {
            backend,
            observed: true,
            findings,
        };
        let process = |state| LaunchRefusal::ProcessNotRunning { backend, state };
        match self {
            Self::Admission { refusal } => refusal.clone(),
            Self::Plan {
                refusal: PlanRefusal::Unsupported { feature },
            } => LaunchRefusal::Unsupported { feature: *feature },
            Self::ReservationUnknown { .. } | Self::Plan { .. } | Self::PlanNotGolden { .. } => {
                profile()
            }
            Self::JailNotCleanedUp { .. }
            | Self::NoJailIdentity { .. }
            | Self::Launcher { .. }
            | Self::LauncherFailed { .. }
            | Self::UnexpectedReport { .. }
            | Self::StagedArtifactDiffers { .. }
            | Self::JailerFailed { .. }
            | Self::ApiUnreachable { .. }
            | Self::ApiRefused { .. }
            | Self::ObservationFailed { .. }
            | Self::StatusUnreadable { .. }
            | Self::StatusOfAnotherProcess { .. }
            | Self::CgroupUnreadable { .. } => specific(),
            Self::JailProcesses { found } if found.is_empty() => process(VmProcessState::Gone),
            Self::JailProcesses { .. } => specific(),
            Self::InstanceMismatch { expected_id, info }
                if info.id == expected_id.as_str() && info.state != RUNNING_STATE =>
            {
                process(VmProcessState::NotRunning {
                    status: info.state.clone(),
                })
            }
            Self::InstanceMismatch { .. } => LaunchRefusal::ConfigurationNotApproved {
                backend,
                checks: [ConfigurationCheck::GoldenConfiguration]
                    .into_iter()
                    .collect(),
                findings: vec![self.to_string()],
            },
            Self::ProcessNotHeld { found, .. } => process(match found {
                IdentityCheck::Reused => VmProcessState::Replaced,
                IdentityCheck::Same | IdentityCheck::Gone => VmProcessState::Gone,
            }),
            Self::StateDiffers { report } => confinement(
                report
                    .failed()
                    .iter()
                    .map(|check| check.to_string())
                    .collect(),
            ),
            Self::NotChrooted { .. } => confinement(vec![self.to_string()]),
            Self::ConfigurationNotGolden { check } => LaunchRefusal::ConfigurationNotApproved {
                backend,
                checks: [ConfigurationCheck::GoldenConfiguration]
                    .into_iter()
                    .collect(),
                findings: golden_findings(check),
            },
        }
    }
}

/// Every difference and forbidden item of a golden check, in the backend's words.
fn golden_findings(check: &GoldenCheck) -> Vec<String> {
    let entries = check
        .diff
        .unexpected
        .iter()
        .map(|entry| format!("unexpected {}", shorten(&entry.key)))
        .chain(
            check
                .diff
                .missing
                .iter()
                .map(|entry| format!("missing {}", shorten(&entry.key))),
        )
        .chain(
            check
                .diff
                .changed
                .iter()
                .map(|entry| format!("changed {}", shorten(&entry.key))),
        );
    let forbidden = check.forbidden.iter().map(|item| match item {
        ForbiddenItem::UndeclaredNetworkInterface { iface_id } => {
            format!(
                "forbidden: the undeclared network interface {:?}",
                shorten(iface_id)
            )
        }
        ForbiddenItem::Console => "forbidden: a console".to_owned(),
        ForbiddenItem::Balloon => "forbidden: a balloon device".to_owned(),
        ForbiddenItem::PciTransport => "forbidden: the PCI transport".to_owned(),
        ForbiddenItem::MetadataService => "forbidden: the metadata service".to_owned(),
        ForbiddenItem::SeccompOverride => "forbidden: a seccomp override".to_owned(),
        ForbiddenItem::SnapshotOperation => "forbidden: a snapshot operation".to_owned(),
    });
    entries.chain(forbidden).collect()
}

impl fmt::Display for FirecrackerRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Admission { refusal } => write!(f, "{refusal}"),
            Self::ReservationUnknown { reservation } => {
                write!(f, "the ledger holds no open reservation {reservation}")
            }
            Self::JailNotCleanedUp { jail } => write!(
                f,
                "an earlier launch of this boot left jail {jail} behind; its cleanup is \
                 incomplete"
            ),
            Self::NoJailIdentity { range } => write!(
                f,
                "all {} jail identities from {} are held",
                range.count, range.first
            ),
            Self::Plan { refusal } => write!(f, "{refusal}"),
            Self::PlanNotGolden { check } => write!(
                f,
                "the planned configuration is not the approved golden file's ({} unexpected, \
                 {} missing, {} changed, {} forbidden); nothing was created",
                check.diff.unexpected.len(),
                check.diff.missing.len(),
                check.diff.changed.len(),
                check.forbidden.len()
            ),
            Self::Launcher { refusal } => write!(f, "the launch's session refused: {refusal}"),
            Self::LauncherFailed { op, detail } => {
                write!(f, "the launcher could not {op}: {detail}")
            }
            Self::UnexpectedReport { op, .. } => {
                write!(f, "the launcher's report does not fit {op}")
            }
            Self::StagedArtifactDiffers { role, .. } => write!(
                f,
                "the staged {} is not the pinned artifact",
                match role {
                    ArtifactRole::Kernel => "kernel",
                    ArtifactRole::RootImage => "root image",
                }
            ),
            Self::JailerFailed { code } => write!(f, "the jailer exited with code {code}"),
            Self::JailProcesses { found } => write!(
                f,
                "the jail's cgroup holds {} processes; exactly one Firecracker process is \
                 expected",
                found.len()
            ),
            Self::ApiUnreachable { path, detail } => {
                write!(
                    f,
                    "the API socket could not be reached for {path}: {detail}"
                )
            }
            Self::ApiRefused {
                path,
                status,
                fault_message,
            } => {
                write!(f, "Firecracker refused {path} with status {status}")?;
                if let Some(fault) = fault_message {
                    write!(f, ": {}", shorten(fault))?;
                }
                Ok(())
            }
            Self::InstanceMismatch { expected_id, info } => write!(
                f,
                "Firecracker describes itself as {:?} in state {:?} at version {:?}, not the \
                 running instance {expected_id}",
                shorten(&info.id),
                shorten(&info.state),
                shorten(&info.vmm_version)
            ),
            Self::ObservationFailed { detail } => {
                write!(f, "the host could not observe the jail: {detail}")
            }
            Self::ProcessNotHeld { process, found } => write!(
                f,
                "{process} no longer runs ({})",
                match found {
                    IdentityCheck::Same => "still named",
                    IdentityCheck::Gone => "gone",
                    IdentityCheck::Reused => "its PID names another process",
                }
            ),
            Self::StatusUnreadable { error } => {
                write!(f, "the process status is refused: {error}")
            }
            Self::StatusOfAnotherProcess { process, pid } => {
                write!(f, "the status read names PID {pid}, not {process}")
            }
            Self::CgroupUnreadable { text } => write!(
                f,
                "the process's cgroup is not one cgroup v2 line: {:?}",
                shorten(text)
            ),
            Self::StateDiffers { report } => {
                f.write_str("the jailed process differs from the expected state")?;
                for (index, check) in report.failed().iter().enumerate() {
                    f.write_str(if index == 0 { ": " } else { "; " })?;
                    write!(f, "{check}")?;
                }
                Ok(())
            }
            Self::NotChrooted { expected, observed } => write!(
                f,
                "the process's root is {:?}, not the jail's chroot {expected}",
                shorten(observed)
            ),
            Self::ConfigurationNotGolden { check } => write!(
                f,
                "the running configuration is not the approved golden file's ({} unexpected, \
                 {} missing, {} changed, {} forbidden)",
                check.diff.unexpected.len(),
                check.diff.missing.len(),
                check.diff.changed.len(),
                check.forbidden.len()
            ),
        }
    }
}

impl std::error::Error for FirecrackerRefusal {}

/// A refused launch of `vm`: the refusal, and the launcher's own cleanup when anything
/// was created (`None` when the refusal came before any privileged operation).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LaunchFailure {
    pub vm: VmInstanceId,
    pub refusal: FirecrackerRefusal,
    pub cleanup: Option<CleanupReport>,
}

impl LaunchFailure {
    pub(super) fn before_creation(vm: VmInstanceId, refusal: FirecrackerRefusal) -> Self {
        Self {
            vm,
            refusal,
            cleanup: None,
        }
    }

    /// Whether nothing the launch created is left: it created nothing, or its cleanup is
    /// complete.
    pub fn nothing_left(&self) -> bool {
        self.cleanup.as_ref().is_none_or(CleanupReport::complete)
    }

    /// The refusal as the backend contract states it
    /// ([`FirecrackerRefusal::launch_refusal`]); when the cleanup is incomplete, as
    /// [`LaunchRefusal::CleanupIncomplete`] naming what may remain: the jail's process
    /// while the host has not observed its end, and every removal not done.
    pub fn to_launch_refusal(&self) -> LaunchRefusal {
        let refusal = self.refusal.launch_refusal();
        match &self.cleanup {
            Some(cleanup) if !cleanup.complete() => LaunchRefusal::CleanupIncomplete {
                vm: self.vm,
                refusal: Box::new(refusal),
                left: left_behind(cleanup),
            },
            _ => refusal,
        }
    }
}

/// What may remain after an incomplete cleanup round: the process when its end is not
/// proven, then each step not done, by its operation.
pub(super) fn left_behind(cleanup: &CleanupReport) -> Vec<LeftBehind> {
    let process = match &cleanup.end {
        JailEnd::NotProven { reason } => Some(LeftBehind::Process {
            detail: reason.to_string(),
        }),
        JailEnd::NothingStarted | JailEnd::Proven { .. } => None,
    };
    let steps = cleanup
        .steps
        .iter()
        .filter(|step| !step.outcome.is_done())
        .map(|step| LeftBehind::HostResource {
            step: step.op.to_owned(),
            detail: match &step.outcome {
                CleanupOutcome::Withheld => {
                    "withheld until the host observes the jail's end".to_owned()
                }
                CleanupOutcome::Failed { detail } => shorten(detail),
                CleanupOutcome::Refused { refusal } => {
                    format!("the launch's session refused it: {refusal}")
                }
                CleanupOutcome::Performed
                | CleanupOutcome::NotCreated
                | CleanupOutcome::NotNeeded => "done".to_owned(),
            },
        });
    process.into_iter().chain(steps).collect()
}

impl fmt::Display for LaunchFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.refusal)?;
        let Some(cleanup) = &self.cleanup else {
            return f.write_str("; nothing was created");
        };
        if cleanup.complete() {
            return f.write_str("; everything the launch created was removed");
        }
        f.write_str("; cleanup is incomplete")?;
        if let JailEnd::NotProven { reason } = &cleanup.end {
            write!(f, ": {reason}")?;
        }
        for step in cleanup.steps.iter().filter(|step| !step.outcome.is_done()) {
            write!(f, "; {} not done", step.op)?;
        }
        Ok(())
    }
}

impl std::error::Error for LaunchFailure {}
