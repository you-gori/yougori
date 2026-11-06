//! The mappings between the QEMU profile's Windows restrictions and the host's restricted
//! start, and the reading of QEMU's own report when it ends before its QMP socket answers
//! (M02, M04; docs/combined-gpu-memory-and-vm-sandbox-plan.md: VM-W19 row, line 2618:
//! "Exact machine/device build boots under intended token/Job rules; no inherited
//! sensitive handles"; VM-W22 row, line 2621; §7.3 lines 2378–2380; VM-CP-04, line 3154).
//! Pure: nothing here starts a process, opens a file or calls the OS.
//!
//! - [`start_restrictions`]: a launch's [`WindowsHostRestrictions`] as the restricted start
//!   of `foundation::process` takes them ([`StartRestrictions`]), or a typed
//!   [`MappingRefusal`] naming what that start cannot apply. Nothing asked for is dropped.
//!   Where the start applies more than is asked, it is stricter, never wider: the
//!   Administrators group is always deny-only, the job always has kill-on-close and its
//!   active-process and memory limits, and when any UI restriction is asked every one is
//!   set.
//! - [`observed_state`]: the host's read-back of the process and its job
//!   ([`RestrictionReadback`]) and what it saw while the process was suspended
//!   ([`StartObservation`]), as the [`WindowsObservedState`] `check_windows` judges. A
//!   restricting SID the profile does not know is an observation failure, never dropped.
//!   The inherited handles' kinds come from the start's explicit handle list; only their
//!   number is observed, as the suspended process's handle count, and every handle beyond
//!   the list is reported as [`HandleKind::Other`], so `check_windows` sees it.
//! - [`classify_early_exit`]: QEMU's own report, the tail of its standard error, when it
//!   ended before its QMP socket accepted a connection, read by
//!   [`classify_report`](super::early_exit::classify_report) with WHPX's words. A WHPX or
//!   hardware-acceleration error is [`StartFailure::HardwareVirtualization`] with QEMU's
//!   text (VM-W22: the launch is refused, nothing retries into emulation); anything else is
//!   a process failure with the text and the exit code, NTSTATUS failures by name.

use std::collections::BTreeSet;
use std::fmt;

use serde::Serialize;
use windows_sys::Win32::System::JobObjects::{
    JOB_OBJECT_UILIMIT_DESKTOP, JOB_OBJECT_UILIMIT_DISPLAYSETTINGS, JOB_OBJECT_UILIMIT_EXITWINDOWS,
    JOB_OBJECT_UILIMIT_GLOBALATOMS, JOB_OBJECT_UILIMIT_HANDLES, JOB_OBJECT_UILIMIT_READCLIPBOARD,
    JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS, JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
};

use super::early_exit::classify_report;
pub use super::early_exit::{MAX_FAILURE_TEXT_BYTES, MAX_STDERR_TAIL_BYTES};
use crate::foundation::process::{
    AdministratorsState, JobSettings, LoweredIntegrity, ObservedGroup, ObservedJobLimits,
    RestrictingGroup, RestrictionReadback, StartMitigation, StartObservation,
};
use crate::sandbox::qemu::{
    GroupState, HandleKind, HostPath, InheritedHandles, IntegrityLevel, JobLimit, JobLimits,
    Mitigation, ObservedJob, RestrictingSid, StartFailure, TokenRestrictions, UiRestriction,
    WindowsHostRestrictions, WindowsObservedState, CHANGE_NOTIFY_PRIVILEGE,
};

/// The most handles beyond the explicit list an observation reports one by one; a count
/// above it is still reported, as this many unexpected handles.
pub const MAX_REPORTED_EXTRA_HANDLES: u32 = 64;

/// Words in a line of QEMU's standard error, after its program name and option location,
/// that make the line a report of the hardware hypervisor: QEMU's WHPX code prefixes each
/// of its errors with `WHPX:` or `whpx:` (the pinned 11.1.0 build's strings), and the
/// accelerator setup reports `failed to initialize whpx: ...`. Matched without regard to
/// case. Only these: a wider word such as "virtualization" could appear in a path.
const HARDWARE_WORDS: [&str; 2] = ["whpx", "hardware acceleration"];

/// The job UI restrictions and their `JOB_OBJECT_UILIMIT_*` flags.
const UI_FLAGS: [(UiRestriction, u32); 8] = [
    (UiRestriction::Handles, JOB_OBJECT_UILIMIT_HANDLES),
    (
        UiRestriction::ReadClipboard,
        JOB_OBJECT_UILIMIT_READCLIPBOARD,
    ),
    (
        UiRestriction::WriteClipboard,
        JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
    ),
    (
        UiRestriction::SystemParameters,
        JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS,
    ),
    (
        UiRestriction::DisplaySettings,
        JOB_OBJECT_UILIMIT_DISPLAYSETTINGS,
    ),
    (UiRestriction::GlobalAtoms, JOB_OBJECT_UILIMIT_GLOBALATOMS),
    (UiRestriction::Desktop, JOB_OBJECT_UILIMIT_DESKTOP),
    (UiRestriction::ExitWindows, JOB_OBJECT_UILIMIT_EXITWINDOWS),
];

/// A standard stream of the started process.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StandardStream {
    Input,
    Output,
    Error,
}

/// Why a launch's Windows restrictions cannot be applied by the host's restricted start.
/// Nothing is created when a mapping is refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum MappingRefusal {
    /// No restricting SID: the token would not be restricted.
    NoRestrictingSid,
    /// A restricting SID the restricted start does not offer (it offers Users, Everyone,
    /// `RESTRICTED`, Authenticated Users and the logon session).
    RestrictingSid { sid: RestrictingSid },
    /// The restricted start keeps exactly `SeChangeNotifyPrivilege`
    /// (`DISABLE_MAX_PRIVILEGE`), so it can neither keep more nor remove that one.
    Privileges { retained: BTreeSet<String> },
    /// A job limit that would let a process leave the job.
    Breakaway { limit: JobLimit },
    /// A job limit of zero, which would mean no limit.
    ZeroLimit { limit: JobLimit },
    /// A standard handle the restricted start does not pass: input and output are the
    /// `NUL` device, error is the log file or the `NUL` device.
    StandardHandle {
        stream: StandardStream,
        kind: HandleKind,
    },
    /// A mitigation the restricted start does not set.
    Mitigation { mitigation: Mitigation },
    /// A path other than the private directory must be writable at low integrity; this
    /// host labels only the private directory it creates, never an existing file.
    WritablePath { path: HostPath },
}

impl fmt::Display for MappingRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoRestrictingSid => f.write_str(
                "the restrictions name no restricting SID, so the token is not restricted",
            ),
            Self::RestrictingSid { sid } => {
                write!(
                    f,
                    "the restricted start does not offer the restricting SID {sid:?}"
                )
            }
            Self::Privileges { retained } => write!(
                f,
                "the restricted start keeps exactly {CHANGE_NOTIFY_PRIVILEGE}, not {retained:?}"
            ),
            Self::Breakaway { limit } => {
                write!(
                    f,
                    "the job limit {limit:?} would let a process leave the job"
                )
            }
            Self::ZeroLimit { limit } => write!(f, "the job's {limit:?} limit is zero"),
            Self::StandardHandle { stream, kind } => write!(
                f,
                "the restricted start cannot pass a {kind:?} handle as standard {stream:?}"
            ),
            Self::Mitigation { mitigation } => write!(
                f,
                "the restricted start does not set the {mitigation:?} mitigation"
            ),
            Self::WritablePath { path } => write!(
                f,
                "{path} would need a low mandatory label, which this host applies only to the \
                 private directory it creates"
            ),
        }
    }
}

impl std::error::Error for MappingRefusal {}

/// A launch's Windows restrictions as the host's restricted start applies them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StartRestrictions {
    /// The restricted token's restricting SIDs, and the desktop's.
    pub restricting: BTreeSet<RestrictingGroup>,
    pub integrity: LoweredIntegrity,
    pub job: JobSettings,
    pub mitigations: BTreeSet<StartMitigation>,
    /// Standard error is the launch's log file; otherwise it is the `NUL` device.
    pub stderr_logged: bool,
}

/// Maps `restrictions` onto the restricted start, refusing what it cannot apply (see the
/// module notes). `control` is the launch's private directory, the one path this host
/// labels for the low-integrity process.
pub fn start_restrictions(
    restrictions: &WindowsHostRestrictions,
    control: &HostPath,
) -> Result<StartRestrictions, MappingRefusal> {
    let restricting = restricting_groups(restrictions.token())?;
    let job = job_settings(restrictions.job())?;
    let stderr_logged = standard_handles(restrictions.inherited_handles())?;
    let mitigations = start_mitigations(restrictions.mitigations())?;
    if let Some(path) = restrictions
        .low_integrity_writable()
        .iter()
        .find(|path| *path != control)
    {
        return Err(MappingRefusal::WritablePath { path: path.clone() });
    }
    Ok(StartRestrictions {
        restricting,
        integrity: lowered_integrity(restrictions.integrity()),
        job,
        mitigations,
        stderr_logged,
    })
}

/// The token's restricting SIDs as restricting groups; the retained privileges must be
/// exactly what the restricted start keeps. The Administrators group is always made
/// deny-only, which satisfies the profile whether or not it asks for it.
pub fn restricting_groups(
    token: &TokenRestrictions,
) -> Result<BTreeSet<RestrictingGroup>, MappingRefusal> {
    let kept: BTreeSet<String> = [CHANGE_NOTIFY_PRIVILEGE.to_owned()].into_iter().collect();
    if token.retained_privileges != kept {
        return Err(MappingRefusal::Privileges {
            retained: token.retained_privileges.clone(),
        });
    }
    if token.restricting_sids.is_empty() {
        return Err(MappingRefusal::NoRestrictingSid);
    }
    token
        .restricting_sids
        .iter()
        .map(|sid| restricting_group(*sid))
        .collect()
}

/// One restricting SID as a restricting group.
pub fn restricting_group(sid: RestrictingSid) -> Result<RestrictingGroup, MappingRefusal> {
    match sid {
        RestrictingSid::Users => Ok(RestrictingGroup::Users),
        RestrictingSid::Restricted => Ok(RestrictingGroup::Restricted),
        RestrictingSid::LogonSession => Ok(RestrictingGroup::LogonSession),
        RestrictingSid::Everyone => Ok(RestrictingGroup::Everyone),
        RestrictingSid::AuthenticatedUsers => Ok(RestrictingGroup::AuthenticatedUsers),
    }
}

/// The mandatory label of an integrity level.
pub fn lowered_integrity(level: IntegrityLevel) -> LoweredIntegrity {
    match level {
        IntegrityLevel::Low => LoweredIntegrity::Low,
        IntegrityLevel::Untrusted => LoweredIntegrity::Untrusted,
    }
}

/// The job's limits as the restricted start's job settings.
pub fn job_settings(limits: &JobLimits) -> Result<JobSettings, MappingRefusal> {
    if let Some(limit) = limits.limits.iter().find(|limit| limit.allows_breakaway()) {
        return Err(MappingRefusal::Breakaway { limit: *limit });
    }
    if limits.active_process_limit == 0 {
        return Err(MappingRefusal::ZeroLimit {
            limit: JobLimit::ActiveProcess,
        });
    }
    if limits.job_memory_limit_bytes == 0 {
        return Err(MappingRefusal::ZeroLimit {
            limit: JobLimit::JobMemory,
        });
    }
    Ok(JobSettings {
        active_process_limit: limits.active_process_limit,
        job_memory_limit_bytes: limits.job_memory_limit_bytes,
        die_on_unhandled_exception: limits.limits.contains(&JobLimit::DieOnUnhandledException),
        ui_restrictions: !limits.ui_restrictions.is_empty(),
    })
}

/// Whether standard error is the log file; input and output must be the `NUL` device.
pub fn standard_handles(handles: InheritedHandles) -> Result<bool, MappingRefusal> {
    for (stream, kind) in [
        (StandardStream::Input, handles.stdin),
        (StandardStream::Output, handles.stdout),
    ] {
        if kind != HandleKind::NullDevice {
            return Err(MappingRefusal::StandardHandle { stream, kind });
        }
    }
    match handles.stderr {
        HandleKind::LogFile => Ok(true),
        HandleKind::NullDevice => Ok(false),
        kind => Err(MappingRefusal::StandardHandle {
            stream: StandardStream::Error,
            kind,
        }),
    }
}

/// The mitigations as the restricted start's creation policies.
pub fn start_mitigations(
    mitigations: &BTreeSet<Mitigation>,
) -> Result<BTreeSet<StartMitigation>, MappingRefusal> {
    mitigations
        .iter()
        .map(|mitigation| match mitigation {
            Mitigation::StrictHandleChecks => Ok(StartMitigation::StrictHandleChecks),
            Mitigation::ExtensionPointDisable => Ok(StartMitigation::ExtensionPointDisable),
            Mitigation::ImageLoadNoRemote => Ok(StartMitigation::ImageLoadNoRemote),
            Mitigation::ImageLoadNoLowLabel => Ok(StartMitigation::ImageLoadNoLowLabel),
            Mitigation::MicrosoftSignedOnly => Err(MappingRefusal::Mitigation {
                mitigation: *mitigation,
            }),
        })
        .collect()
}

/// Why the host's read-back could not be stated as an observed state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum ObservationError {
    /// The token has a restricting SID the profile does not know.
    UnknownRestrictingSid { sid: String },
}

impl fmt::Display for ObservationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownRestrictingSid { sid } => write!(
                f,
                "the QEMU process's token has the restricting SID {sid}, which the profile does \
                 not know"
            ),
        }
    }
}

impl std::error::Error for ObservationError {}

/// The host's read-back and start observation as the state `check_windows` judges (see
/// the module notes).
pub fn observed_state(
    readback: &RestrictionReadback,
    start: &StartObservation,
) -> Result<WindowsObservedState, ObservationError> {
    let restricting_sids = readback
        .restricting
        .iter()
        .map(|group| match group {
            ObservedGroup::Users => Ok(RestrictingSid::Users),
            ObservedGroup::Restricted => Ok(RestrictingSid::Restricted),
            ObservedGroup::LogonSession => Ok(RestrictingSid::LogonSession),
            ObservedGroup::Everyone => Ok(RestrictingSid::Everyone),
            ObservedGroup::AuthenticatedUsers => Ok(RestrictingSid::AuthenticatedUsers),
            ObservedGroup::Other { sid } => {
                Err(ObservationError::UnknownRestrictingSid { sid: sid.clone() })
            }
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    Ok(WindowsObservedState {
        token_restricted: readback.token_restricted,
        restricting_sids,
        privileges: readback.privileges.clone(),
        administrators: match readback.administrators {
            AdministratorsState::Absent => GroupState::Absent,
            AdministratorsState::DenyOnly => GroupState::DenyOnly,
            AdministratorsState::Enabled => GroupState::Enabled,
        },
        integrity_rid: readback.integrity_rid,
        job: readback.in_job.then(|| observed_job(&readback.job)),
        inherited_handles: inherited_handles(start),
        mitigations: readback
            .mitigations
            .iter()
            .map(|mitigation| match mitigation {
                StartMitigation::StrictHandleChecks => Mitigation::StrictHandleChecks,
                StartMitigation::ExtensionPointDisable => Mitigation::ExtensionPointDisable,
                StartMitigation::ImageLoadNoRemote => Mitigation::ImageLoadNoRemote,
                StartMitigation::ImageLoadNoLowLabel => Mitigation::ImageLoadNoLowLabel,
            })
            .collect(),
    })
}

/// The job object's limits as queried, as the comparator's job.
pub fn observed_job(job: &ObservedJobLimits) -> ObservedJob {
    let mut limits = BTreeSet::new();
    for (present, limit) in [
        (job.kill_on_close, JobLimit::KillOnJobClose),
        (
            job.die_on_unhandled_exception,
            JobLimit::DieOnUnhandledException,
        ),
        (job.active_process_limit > 0, JobLimit::ActiveProcess),
        (job.job_memory_limit_bytes > 0, JobLimit::JobMemory),
        (job.breakaway_ok, JobLimit::BreakawayOk),
        (job.silent_breakaway_ok, JobLimit::SilentBreakawayOk),
    ] {
        if present {
            limits.insert(limit);
        }
    }
    ObservedJob {
        limits,
        active_process_limit: job.active_process_limit,
        job_memory_limit_bytes: job.job_memory_limit_bytes,
        ui_restrictions: ui_restrictions(job.ui_restrictions),
    }
}

/// The UI restrictions a `JOB_OBJECT_UILIMIT_*` class sets.
pub fn ui_restrictions(class: u32) -> BTreeSet<UiRestriction> {
    UI_FLAGS
        .iter()
        .filter(|(_, flag)| class & flag != 0)
        .map(|(restriction, _)| *restriction)
        .collect()
}

/// The handles the process inherited. The kinds are those of the start's explicit handle
/// list (the `NUL` device for standard input and output, the log file or the `NUL` device
/// for standard error); only the count is observed, as the handles the suspended process
/// held before any of its code ran. Each handle beyond the list is
/// [`HandleKind::Other`], at most [`MAX_REPORTED_EXTRA_HANDLES`] of them.
pub fn inherited_handles(start: &StartObservation) -> Vec<HandleKind> {
    let stderr = if start.stderr_logged {
        HandleKind::LogFile
    } else {
        HandleKind::NullDevice
    };
    let mut kinds = vec![HandleKind::NullDevice, HandleKind::NullDevice, stderr];
    let extra = start
        .handles_at_start
        .saturating_sub(start.listed_handles)
        .min(MAX_REPORTED_EXTRA_HANDLES);
    kinds.extend((0..extra).map(|_| HandleKind::Other));
    kinds
}

/// What QEMU's report of an end before QMP answered means (see the module notes):
/// `exit_code` is the code the host read from the process handle, `stderr` the tail of
/// QEMU's standard error.
pub fn classify_early_exit(exit_code: u32, stderr: &str) -> StartFailure {
    classify_report(&HARDWARE_WORDS, &exit_text(exit_code), stderr)
}

/// An exit code as a person reads it: NTSTATUS failures in hexadecimal, with the name of
/// the common ones.
pub fn exit_text(code: u32) -> String {
    let name = match code {
        0xC000_0005 => Some("STATUS_ACCESS_VIOLATION"),
        0xC000_0135 => Some("STATUS_DLL_NOT_FOUND"),
        0xC000_0142 => Some("STATUS_DLL_INIT_FAILED"),
        0xC000_0409 => Some("STATUS_STACK_BUFFER_OVERRUN"),
        0xC000_0374 => Some("STATUS_HEAP_CORRUPTION"),
        0xC000_0008 => Some("STATUS_INVALID_HANDLE"),
        _ => None,
    };
    match name {
        Some(name) => format!("{code:#010x} ({name})"),
        None if code >= 0xC000_0000 => format!("{code:#010x}"),
        None => code.to_string(),
    }
}
