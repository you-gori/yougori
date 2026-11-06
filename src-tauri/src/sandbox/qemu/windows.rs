//! What the launcher must apply to the QEMU/WHPX process on Windows, and the VM-CP-04
//! Windows comparator (line 3154: the token is restricted and low integrity, job limits
//! present, queried from the job object; VM-W19 row, line 2618: no inherited sensitive
//! handles; §7.3 lines 2378–2380: low-privilege identity, Job limits, handle inheritance,
//! mitigations compatible with the signed build and verified in effect). Nothing here
//! creates a token or a job; the observed state comes from the host, never the guest.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::profile::QemuProfile;
use super::values::HostPath;
use crate::foundation::evidence::{ClockReading, ConfigurationFingerprint};
use crate::sandbox::backend::{ConfinementControl, HostObserved, ObservationProblem};

/// The mandatory-label RID of low integrity.
pub const LOW_INTEGRITY_RID: u32 = 0x1000;
/// The one privilege a restricted token keeps (`DISABLE_MAX_PRIVILEGE`).
pub const CHANGE_NOTIFY_PRIVILEGE: &str = "SeChangeNotifyPrivilege";

/// A mandatory integrity level a launch may require.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityLevel {
    Untrusted,
    Low,
}

impl IntegrityLevel {
    /// The mandatory-label RID; an observed RID at or below it satisfies the level.
    pub const fn rid(self) -> u32 {
        match self {
            Self::Untrusted => 0,
            Self::Low => LOW_INTEGRITY_RID,
        }
    }
}

/// A restricting SID of a restricted token. A second access check runs against these,
/// so every extra one widens what the process can open. The profile's set is Users (the
/// QEMU install directory), Everyone, RESTRICTED and the logon session (granted on the
/// VM's own files). Everyone is in the set because USER32's initialization, which the
/// pinned QEMU build runs through, opens session objects granted to Everyone alone:
/// measured on this host (30 October 2026), a restricted process without it exits
/// `0xC0000142` before its own code runs, whatever its desktop or integrity, and runs
/// once Everyone is added (`foundation::process::restricted`). Authenticated Users is in
/// the set because the Windows Hypervisor Platform's device grants it and nothing else
/// of the set: measured on this host (30 October 2026, `whpx_capability_under_token_variants`
/// in `foundation::process`), the capability call is refused under the other four at any
/// integrity and allowed once Authenticated Users joins them, at low integrity too. With
/// it, the second check also passes what Authenticated Users is granted (on this host the
/// data drive's inherited ACL, for one); the low integrity label still keeps the process
/// from writing anything of medium integrity, and the job, the handle list and the
/// mitigations stay. Any SID beyond these five is a finding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestrictingSid {
    /// `Everyone` (S-1-1-0).
    Everyone,
    Users,
    /// `NT AUTHORITY\RESTRICTED` (S-1-5-12).
    Restricted,
    /// The logon session's SID, which the launcher grants on the VM's own files.
    LogonSession,
    /// `NT AUTHORITY\Authenticated Users` (S-1-5-11): what the hypervisor platform's
    /// device grants (the type's notes).
    AuthenticatedUsers,
}

/// A process mitigation policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mitigation {
    StrictHandleChecks,
    ExtensionPointDisable,
    ImageLoadNoRemote,
    ImageLoadNoLowLabel,
    /// "Block non-Microsoft binaries": a third-party QEMU and its libraries would not
    /// load (§7.3 line 2380), so it is refused for this profile.
    MicrosoftSignedOnly,
}

impl Mitigation {
    /// The mitigations the profile selects for the third-party QEMU build. Their effect
    /// on the signed build is verified on real hosts (VM-W19 acceptance).
    pub fn selected() -> BTreeSet<Self> {
        [
            Self::StrictHandleChecks,
            Self::ExtensionPointDisable,
            Self::ImageLoadNoRemote,
            Self::ImageLoadNoLowLabel,
        ]
        .into_iter()
        .collect()
    }
}

/// A basic or extended job limit flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobLimit {
    KillOnJobClose,
    DieOnUnhandledException,
    ActiveProcess,
    JobMemory,
    /// Lets a child leave the job; never allowed.
    BreakawayOk,
    /// Puts every child outside the job; never allowed.
    SilentBreakawayOk,
}

impl JobLimit {
    /// The limits the job must have.
    pub fn required() -> BTreeSet<Self> {
        [
            Self::KillOnJobClose,
            Self::DieOnUnhandledException,
            Self::ActiveProcess,
            Self::JobMemory,
        ]
        .into_iter()
        .collect()
    }

    /// Whether the flag lets a process leave the job.
    pub const fn allows_breakaway(self) -> bool {
        matches!(self, Self::BreakawayOk | Self::SilentBreakawayOk)
    }
}

/// A job UI restriction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UiRestriction {
    Desktop,
    DisplaySettings,
    ExitWindows,
    GlobalAtoms,
    Handles,
    ReadClipboard,
    SystemParameters,
    WriteClipboard,
}

impl UiRestriction {
    pub const ALL: [Self; 8] = [
        Self::Desktop,
        Self::DisplaySettings,
        Self::ExitWindows,
        Self::GlobalAtoms,
        Self::Handles,
        Self::ReadClipboard,
        Self::SystemParameters,
        Self::WriteClipboard,
    ];
}

/// What a handle found in the hypervisor process refers to, as the host classified it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandleKind {
    /// The `NUL` device, for standard input and output.
    NullDevice,
    /// The VM's own log file, for standard error.
    LogFile,
    File,
    Directory,
    Process,
    Thread,
    Token,
    Job,
    Section,
    Event,
    RegistryKey,
    Socket,
    Pipe,
    Other,
}

/// The handles the child inherits: exactly the three standard handles, passed by an
/// explicit handle list, so no other handle of the launcher reaches QEMU.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct InheritedHandles {
    pub stdin: HandleKind,
    pub stdout: HandleKind,
    pub stderr: HandleKind,
}

impl InheritedHandles {
    pub const STANDARD: Self = Self {
        stdin: HandleKind::NullDevice,
        stdout: HandleKind::NullDevice,
        stderr: HandleKind::LogFile,
    };

    fn counts(self) -> BTreeMap<HandleKind, usize> {
        let mut counts = BTreeMap::new();
        for kind in [self.stdin, self.stdout, self.stderr] {
            *counts.entry(kind).or_insert(0) += 1;
        }
        counts
    }
}

/// The restricted token: every privilege removed except change notification,
/// Administrators deny-only, and restricting SIDs so a second access check applies.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TokenRestrictions {
    pub retained_privileges: BTreeSet<String>,
    pub administrators_deny_only: bool,
    pub restricting_sids: BTreeSet<RestrictingSid>,
}

/// The job object's limits. The memory limit is the host RAM the CORE-03 reservation
/// holds, so the host enforces the reservation (S3 item 2, line 224); one active process
/// means QEMU starts no children.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct JobLimits {
    pub limits: BTreeSet<JobLimit>,
    pub active_process_limit: u32,
    pub job_memory_limit_bytes: u64,
    pub ui_restrictions: BTreeSet<UiRestriction>,
}

/// Why Windows restrictions were refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum WindowsRefusal {
    /// The mitigation stops the third-party build from loading (§7.3 line 2380).
    IncompatibleMitigation { mitigation: Mitigation },
}

impl fmt::Display for WindowsRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IncompatibleMitigation { mitigation } => write!(
                f,
                "the {mitigation:?} mitigation would stop the third-party QEMU build from loading"
            ),
        }
    }
}

impl std::error::Error for WindowsRefusal {}

/// The restrictions the launcher must apply to the QEMU/WHPX process before it runs
/// anything (§3.4 line 2101: resource limits apply before workload execution).
/// Serialize only: derived from a profile and a reservation, never hand-written.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WindowsHostRestrictions {
    token: TokenRestrictions,
    integrity: IntegrityLevel,
    job: JobLimits,
    inherited_handles: InheritedHandles,
    mitigations: BTreeSet<Mitigation>,
    low_integrity_writable: Vec<HostPath>,
}

impl WindowsHostRestrictions {
    /// The restrictions of one launch. The private directory and the data volumes are
    /// the only paths the low-integrity process writes, so only they carry a low label;
    /// the root image, kernel and firmware stay unwritable.
    pub fn for_profile(profile: &QemuProfile, reserved_ram_bytes: u64) -> Self {
        let mut writable = vec![profile.control().path().clone()];
        writable.extend(profile.volumes().iter().cloned());
        Self::new(writable, reserved_ram_bytes)
    }

    pub(super) fn new(low_integrity_writable: Vec<HostPath>, reserved_ram_bytes: u64) -> Self {
        Self {
            token: TokenRestrictions {
                retained_privileges: [CHANGE_NOTIFY_PRIVILEGE.to_owned()].into_iter().collect(),
                administrators_deny_only: true,
                restricting_sids: [
                    RestrictingSid::Users,
                    RestrictingSid::Everyone,
                    RestrictingSid::Restricted,
                    RestrictingSid::LogonSession,
                    RestrictingSid::AuthenticatedUsers,
                ]
                .into_iter()
                .collect(),
            },
            integrity: IntegrityLevel::Low,
            job: JobLimits {
                limits: JobLimit::required(),
                active_process_limit: 1,
                job_memory_limit_bytes: reserved_ram_bytes,
                ui_restrictions: UiRestriction::ALL.into_iter().collect(),
            },
            inherited_handles: InheritedHandles::STANDARD,
            mitigations: Mitigation::selected(),
            low_integrity_writable,
        }
    }

    /// Replaces the mitigation selection, refusing one the build cannot run under.
    pub fn with_mitigations(
        mut self,
        mitigations: BTreeSet<Mitigation>,
    ) -> Result<Self, WindowsRefusal> {
        if mitigations.contains(&Mitigation::MicrosoftSignedOnly) {
            return Err(WindowsRefusal::IncompatibleMitigation {
                mitigation: Mitigation::MicrosoftSignedOnly,
            });
        }
        self.mitigations = mitigations;
        Ok(self)
    }

    pub fn token(&self) -> &TokenRestrictions {
        &self.token
    }

    pub fn integrity(&self) -> IntegrityLevel {
        self.integrity
    }

    pub fn job(&self) -> &JobLimits {
        &self.job
    }

    pub fn inherited_handles(&self) -> InheritedHandles {
        self.inherited_handles
    }

    pub fn mitigations(&self) -> &BTreeSet<Mitigation> {
        &self.mitigations
    }

    pub fn low_integrity_writable(&self) -> &[HostPath] {
        &self.low_integrity_writable
    }
}

/// Whether the Administrators group is in the token, and how.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupState {
    Absent,
    DenyOnly,
    Enabled,
}

/// The job object as the host queried it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedJob {
    pub limits: BTreeSet<JobLimit>,
    /// Zero when the job has no active-process limit.
    pub active_process_limit: u32,
    /// Zero when the job has no memory limit.
    pub job_memory_limit_bytes: u64,
    pub ui_restrictions: BTreeSet<UiRestriction>,
}

/// The QEMU process as the host observed it: its token, its job object, the handles
/// found in it at start and the mitigation policies in effect (VM-CP-04 Windows).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsObservedState {
    /// `IsTokenRestricted`.
    pub token_restricted: bool,
    pub restricting_sids: BTreeSet<RestrictingSid>,
    /// The privileges present in the token, by name.
    pub privileges: BTreeSet<String>,
    pub administrators: GroupState,
    /// The token's mandatory-label RID.
    pub integrity_rid: u32,
    /// `None` when the process is in no job.
    pub job: Option<ObservedJob>,
    pub inherited_handles: Vec<HandleKind>,
    pub mitigations: BTreeSet<Mitigation>,
}

/// One way the observed process differs from the restrictions it should run under.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "finding", rename_all = "snake_case")]
pub enum WindowsFinding {
    TokenNotRestricted,
    RestrictingSidNotExpected {
        sid: RestrictingSid,
    },
    PrivilegePresent {
        privilege: String,
    },
    AdministratorsEnabled,
    IntegrityTooHigh {
        expected_rid: u32,
        observed_rid: u32,
    },
    NotInJob,
    JobLimitMissing {
        limit: JobLimit,
    },
    BreakawayAllowed {
        limit: JobLimit,
    },
    ActiveProcessLimit {
        expected: u32,
        observed: u32,
    },
    JobMemoryLimit {
        expected_bytes: u64,
        observed_bytes: u64,
    },
    UiRestrictionMissing {
        restriction: UiRestriction,
    },
    UnexpectedInheritedHandle {
        kind: HandleKind,
    },
    MitigationNotInEffect {
        mitigation: Mitigation,
    },
}

impl WindowsFinding {
    /// The confinement controls (§1.3 line 1900) the finding shows are not in place.
    pub fn breaks(&self) -> BTreeSet<ConfinementControl> {
        use ConfinementControl::{
            FilesystemLimits, OsRestrictions, ProcessIdentity, ResourceControls,
        };
        let controls: &[ConfinementControl] = match self {
            Self::TokenNotRestricted
            | Self::RestrictingSidNotExpected { .. }
            | Self::PrivilegePresent { .. }
            | Self::AdministratorsEnabled
            | Self::IntegrityTooHigh { .. }
            | Self::UnexpectedInheritedHandle { .. } => &[ProcessIdentity, FilesystemLimits],
            Self::NotInJob => &[ResourceControls, OsRestrictions],
            Self::JobLimitMissing { .. }
            | Self::BreakawayAllowed { .. }
            | Self::ActiveProcessLimit { .. }
            | Self::JobMemoryLimit { .. } => &[ResourceControls],
            Self::UiRestrictionMissing { .. } | Self::MitigationNotInEffect { .. } => {
                &[OsRestrictions]
            }
        };
        controls.iter().copied().collect()
    }
}

impl fmt::Display for WindowsFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TokenNotRestricted => f.write_str("the token is not restricted"),
            Self::RestrictingSidNotExpected { sid } => {
                write!(f, "the token has the unexpected restricting SID {sid:?}")
            }
            Self::PrivilegePresent { privilege } => {
                write!(f, "the token still has {privilege}")
            }
            Self::AdministratorsEnabled => {
                f.write_str("the Administrators group is enabled in the token")
            }
            Self::IntegrityTooHigh {
                expected_rid,
                observed_rid,
            } => write!(
                f,
                "the integrity level is {observed_rid:#x}, above {expected_rid:#x}"
            ),
            Self::NotInJob => f.write_str("the process is in no job object"),
            Self::JobLimitMissing { limit } => write!(f, "the job lacks the {limit:?} limit"),
            Self::BreakawayAllowed { limit } => {
                write!(f, "the job allows breakaway ({limit:?})")
            }
            Self::ActiveProcessLimit { expected, observed } => write!(
                f,
                "the job's active-process limit is {observed}, not at most {expected}"
            ),
            Self::JobMemoryLimit {
                expected_bytes,
                observed_bytes,
            } => write!(
                f,
                "the job's memory limit is {observed_bytes} bytes, not at most {expected_bytes}"
            ),
            Self::UiRestrictionMissing { restriction } => {
                write!(f, "the job lacks the {restriction:?} UI restriction")
            }
            Self::UnexpectedInheritedHandle { kind } => {
                write!(f, "the process inherited an unlisted {kind:?} handle")
            }
            Self::MitigationNotInEffect { mitigation } => {
                write!(f, "the {mitigation:?} mitigation is not in effect")
            }
        }
    }
}

/// The result of one VM-CP-04 Windows check. An unconfined test launch yields a finding
/// for each missing restriction (the check's positive control).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WindowsCheck {
    findings: Vec<WindowsFinding>,
}

impl WindowsCheck {
    pub fn findings(&self) -> &[WindowsFinding] {
        &self.findings
    }

    /// Every restriction was observed in place.
    pub fn passed(&self) -> bool {
        self.findings.is_empty()
    }

    /// The controls the observation shows in place, for the backend's host-observed
    /// confinement fact; a control any finding breaks is left out.
    pub fn controls_observed(&self) -> BTreeSet<ConfinementControl> {
        let broken: BTreeSet<ConfinementControl> = self
            .findings
            .iter()
            .flat_map(WindowsFinding::breaks)
            .collect();
        [
            ConfinementControl::ProcessIdentity,
            ConfinementControl::FilesystemLimits,
            ConfinementControl::OsRestrictions,
            ConfinementControl::ResourceControls,
        ]
        .into_iter()
        .filter(|control| !broken.contains(control))
        .collect()
    }
}

/// Compares the host's observation of the QEMU process with the restrictions it should
/// run under. The observation must be current under the launch's configuration and age
/// bound, as every host fact is (CORE-01); a stale one is refused, not judged.
pub fn check_windows(
    expected: &WindowsHostRestrictions,
    observed: &HostObserved<WindowsObservedState>,
    now: ClockReading,
    max_age: Duration,
    configuration: ConfigurationFingerprint,
) -> Result<WindowsCheck, ObservationProblem> {
    observed.current_at(now, max_age, configuration)?;
    let state = observed.value();
    let mut findings = Vec::new();
    if !state.token_restricted || state.restricting_sids.is_empty() {
        findings.push(WindowsFinding::TokenNotRestricted);
    }
    findings.extend(
        state
            .restricting_sids
            .difference(&expected.token.restricting_sids)
            .map(|sid| WindowsFinding::RestrictingSidNotExpected { sid: *sid }),
    );
    findings.extend(
        state
            .privileges
            .difference(&expected.token.retained_privileges)
            .map(|privilege| WindowsFinding::PrivilegePresent {
                privilege: privilege.clone(),
            }),
    );
    if state.administrators == GroupState::Enabled && expected.token.administrators_deny_only {
        findings.push(WindowsFinding::AdministratorsEnabled);
    }
    if state.integrity_rid > expected.integrity.rid() {
        findings.push(WindowsFinding::IntegrityTooHigh {
            expected_rid: expected.integrity.rid(),
            observed_rid: state.integrity_rid,
        });
    }
    match &state.job {
        None => findings.push(WindowsFinding::NotInJob),
        Some(job) => {
            findings.extend(
                expected
                    .job
                    .limits
                    .difference(&job.limits)
                    .map(|limit| WindowsFinding::JobLimitMissing { limit: *limit }),
            );
            findings.extend(
                job.limits
                    .iter()
                    .filter(|limit| limit.allows_breakaway())
                    .map(|limit| WindowsFinding::BreakawayAllowed { limit: *limit }),
            );
            if job.active_process_limit == 0
                || job.active_process_limit > expected.job.active_process_limit
            {
                findings.push(WindowsFinding::ActiveProcessLimit {
                    expected: expected.job.active_process_limit,
                    observed: job.active_process_limit,
                });
            }
            if job.job_memory_limit_bytes == 0
                || job.job_memory_limit_bytes > expected.job.job_memory_limit_bytes
            {
                findings.push(WindowsFinding::JobMemoryLimit {
                    expected_bytes: expected.job.job_memory_limit_bytes,
                    observed_bytes: job.job_memory_limit_bytes,
                });
            }
            findings.extend(
                expected
                    .job
                    .ui_restrictions
                    .difference(&job.ui_restrictions)
                    .map(|restriction| WindowsFinding::UiRestrictionMissing {
                        restriction: *restriction,
                    }),
            );
        }
    }
    let mut allowed = expected.inherited_handles.counts();
    for kind in &state.inherited_handles {
        match allowed.get_mut(kind) {
            Some(count) if *count > 0 => *count -= 1,
            _ => findings.push(WindowsFinding::UnexpectedInheritedHandle { kind: *kind }),
        }
    }
    findings.extend(
        expected
            .mitigations
            .difference(&state.mitigations)
            .map(|mitigation| WindowsFinding::MitigationNotInEffect {
                mitigation: *mitigation,
            }),
    );
    Ok(WindowsCheck { findings })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::evidence::{ProbeRegistry, Staleness};
    use crate::foundation::ids::ManualClock;
    use crate::sandbox::qemu::values::PathStyle;
    use std::sync::Arc;

    const GIB: u64 = 1024 * 1024 * 1024;

    fn config() -> ConfigurationFingerprint {
        ConfigurationFingerprint::from_settings([("host", "windows")]).unwrap()
    }

    fn restrictions() -> WindowsHostRestrictions {
        WindowsHostRestrictions::new(
            vec![HostPath::new(PathStyle::Windows, r"C:\vm\control").unwrap()],
            2 * GIB,
        )
    }

    fn confined() -> WindowsObservedState {
        WindowsObservedState {
            token_restricted: true,
            restricting_sids: [RestrictingSid::Restricted, RestrictingSid::LogonSession]
                .into_iter()
                .collect(),
            privileges: [CHANGE_NOTIFY_PRIVILEGE.to_owned()].into_iter().collect(),
            administrators: GroupState::DenyOnly,
            integrity_rid: LOW_INTEGRITY_RID,
            job: Some(ObservedJob {
                limits: JobLimit::required(),
                active_process_limit: 1,
                job_memory_limit_bytes: 2 * GIB,
                ui_restrictions: UiRestriction::ALL.into_iter().collect(),
            }),
            inherited_handles: vec![
                HandleKind::NullDevice,
                HandleKind::LogFile,
                HandleKind::NullDevice,
            ],
            mitigations: Mitigation::selected(),
        }
    }

    /// An unjailed launch: medium integrity, administrator, no job, every handle
    /// inherited, no mitigations.
    fn unconfined() -> WindowsObservedState {
        WindowsObservedState {
            token_restricted: false,
            restricting_sids: BTreeSet::new(),
            privileges: [
                CHANGE_NOTIFY_PRIVILEGE.to_owned(),
                "SeDebugPrivilege".to_owned(),
            ]
            .into_iter()
            .collect(),
            administrators: GroupState::Enabled,
            integrity_rid: 0x2000,
            job: None,
            inherited_handles: vec![
                HandleKind::NullDevice,
                HandleKind::NullDevice,
                HandleKind::LogFile,
                HandleKind::Process,
                HandleKind::Token,
            ],
            mitigations: BTreeSet::new(),
        }
    }

    struct Clocked {
        clock: Arc<ManualClock>,
        registry: ProbeRegistry<Arc<ManualClock>>,
    }

    fn clocked() -> Clocked {
        let clock = Arc::new(ManualClock::default());
        let registry = ProbeRegistry::new(Arc::clone(&clock));
        Clocked { clock, registry }
    }

    fn check(state: WindowsObservedState) -> WindowsCheck {
        let host = clocked();
        let observed = HostObserved::stamp(
            state,
            host.registry.now(),
            Duration::from_secs(60),
            config(),
        );
        check_windows(
            &restrictions(),
            &observed,
            host.registry.now(),
            Duration::from_secs(60),
            config(),
        )
        .unwrap()
    }

    #[test]
    fn a_confined_process_passes_and_shows_its_four_controls() {
        let result = check(confined());
        assert!(result.passed(), "{:?}", result.findings());
        assert_eq!(result.controls_observed().len(), 4);
        assert!(!result
            .controls_observed()
            .contains(&ConfinementControl::AccountIdentity));
        // Untrusted integrity and fewer restricting SIDs are stricter, not findings.
        let mut stricter = confined();
        stricter.integrity_rid = 0;
        stricter.restricting_sids = [RestrictingSid::Restricted].into_iter().collect();
        stricter.privileges.clear();
        stricter.administrators = GroupState::Absent;
        assert!(check(stricter).passed());
    }

    #[test]
    fn an_unjailed_launch_reports_every_difference() {
        let result = check(unconfined());
        let findings = result.findings();
        for expected in [
            WindowsFinding::TokenNotRestricted,
            WindowsFinding::PrivilegePresent {
                privilege: "SeDebugPrivilege".into(),
            },
            WindowsFinding::AdministratorsEnabled,
            WindowsFinding::IntegrityTooHigh {
                expected_rid: LOW_INTEGRITY_RID,
                observed_rid: 0x2000,
            },
            WindowsFinding::NotInJob,
            WindowsFinding::UnexpectedInheritedHandle {
                kind: HandleKind::Process,
            },
            WindowsFinding::UnexpectedInheritedHandle {
                kind: HandleKind::Token,
            },
            WindowsFinding::MitigationNotInEffect {
                mitigation: Mitigation::StrictHandleChecks,
            },
        ] {
            assert!(findings.contains(&expected), "{expected}");
        }
        assert!(result.controls_observed().is_empty());
        assert!(findings
            .iter()
            .all(|finding| !finding.to_string().is_empty()));
    }

    #[test]
    fn job_limits_must_be_present_and_tight() {
        let mut state = confined();
        let job = state.job.as_mut().unwrap();
        job.limits.remove(&JobLimit::KillOnJobClose);
        job.limits.insert(JobLimit::BreakawayOk);
        job.active_process_limit = 0;
        job.job_memory_limit_bytes = 3 * GIB;
        job.ui_restrictions.remove(&UiRestriction::ReadClipboard);
        let result = check(state);
        assert_eq!(
            result.findings(),
            &[
                WindowsFinding::JobLimitMissing {
                    limit: JobLimit::KillOnJobClose
                },
                WindowsFinding::BreakawayAllowed {
                    limit: JobLimit::BreakawayOk
                },
                WindowsFinding::ActiveProcessLimit {
                    expected: 1,
                    observed: 0
                },
                WindowsFinding::JobMemoryLimit {
                    expected_bytes: 2 * GIB,
                    observed_bytes: 3 * GIB
                },
                WindowsFinding::UiRestrictionMissing {
                    restriction: UiRestriction::ReadClipboard
                },
            ]
        );
        assert_eq!(
            result.controls_observed(),
            [
                ConfinementControl::ProcessIdentity,
                ConfinementControl::FilesystemLimits
            ]
            .into_iter()
            .collect()
        );
    }

    #[test]
    fn a_wider_restricting_sid_or_an_extra_handle_is_a_finding() {
        let mut state = confined();
        state.restricting_sids.clear();
        state.token_restricted = true;
        assert_eq!(
            check(state).findings(),
            &[WindowsFinding::TokenNotRestricted]
        );
        // A SID beyond the plan's set is a finding: a plan without Everyone judges a
        // token that has it.
        let mut narrower = restrictions();
        narrower
            .token
            .restricting_sids
            .remove(&RestrictingSid::Everyone);
        let mut state = confined();
        state.restricting_sids.insert(RestrictingSid::Everyone);
        let host = clocked();
        let observed = HostObserved::stamp(
            state,
            host.registry.now(),
            Duration::from_secs(60),
            config(),
        );
        let judged = check_windows(
            &narrower,
            &observed,
            host.registry.now(),
            Duration::from_secs(60),
            config(),
        )
        .unwrap();
        assert_eq!(
            judged.findings(),
            &[WindowsFinding::RestrictingSidNotExpected {
                sid: RestrictingSid::Everyone
            }]
        );
        // The plan's own set, Everyone included, passes.
        let mut state = confined();
        state.restricting_sids.insert(RestrictingSid::Everyone);
        assert!(check(state).passed());
        let mut state = confined();
        state.inherited_handles.push(HandleKind::LogFile);
        assert_eq!(
            check(state).findings(),
            &[WindowsFinding::UnexpectedInheritedHandle {
                kind: HandleKind::LogFile
            }]
        );
    }

    #[test]
    fn a_stale_or_foreign_observation_is_not_judged() {
        let host = clocked();
        let observed = HostObserved::stamp(
            confined(),
            host.registry.now(),
            Duration::from_secs(60),
            config(),
        );
        host.clock.advance(Duration::from_secs(61));
        assert!(matches!(
            check_windows(
                &restrictions(),
                &observed,
                host.registry.now(),
                Duration::from_secs(600),
                config(),
            ),
            Err(ObservationProblem::Stale {
                staleness: Staleness::TooOld { .. }
            })
        ));
        let other = ConfigurationFingerprint::from_settings([("host", "other")]).unwrap();
        assert!(matches!(
            check_windows(
                &restrictions(),
                &observed,
                host.registry.now(),
                Duration::from_secs(600),
                other,
            ),
            Err(ObservationProblem::OtherConfiguration { .. })
        ));
    }

    #[test]
    fn block_non_microsoft_binaries_is_refused_for_the_third_party_build() {
        assert_eq!(
            restrictions().with_mitigations(
                [
                    Mitigation::StrictHandleChecks,
                    Mitigation::MicrosoftSignedOnly
                ]
                .into_iter()
                .collect()
            ),
            Err(WindowsRefusal::IncompatibleMitigation {
                mitigation: Mitigation::MicrosoftSignedOnly
            })
        );
        assert!(!Mitigation::selected().contains(&Mitigation::MicrosoftSignedOnly));
        let fewer = restrictions()
            .with_mitigations([Mitigation::StrictHandleChecks].into_iter().collect())
            .unwrap();
        assert_eq!(fewer.mitigations().len(), 1);
    }

    #[test]
    fn the_restrictions_are_restricted_low_integrity_and_job_limited() {
        let restrictions = restrictions();
        assert_eq!(restrictions.integrity(), IntegrityLevel::Low);
        assert_eq!(restrictions.integrity().rid(), 0x1000);
        assert!(restrictions.token().administrators_deny_only);
        assert!(!restrictions.token().restricting_sids.is_empty());
        assert_eq!(
            restrictions.token().retained_privileges,
            [CHANGE_NOTIFY_PRIVILEGE.to_owned()].into_iter().collect()
        );
        assert_eq!(restrictions.job().active_process_limit, 1);
        assert_eq!(restrictions.job().job_memory_limit_bytes, 2 * GIB);
        assert!(!restrictions
            .job()
            .limits
            .iter()
            .any(|limit| limit.allows_breakaway()));
        assert_eq!(restrictions.job().ui_restrictions.len(), 8);
        assert_eq!(restrictions.inherited_handles(), InheritedHandles::STANDARD);
        assert_eq!(restrictions.low_integrity_writable().len(), 1);
    }

    #[test]
    fn the_observed_state_refuses_unknown_fields() {
        let json = serde_json::to_value(confined()).unwrap();
        assert_eq!(
            serde_json::from_value::<WindowsObservedState>(json.clone()).unwrap(),
            confined()
        );
        let mut extra = json.clone();
        extra["unlisted"] = true.into();
        assert!(serde_json::from_value::<WindowsObservedState>(extra).is_err());
        let mut inner = json;
        inner["job"]["cpu_rate"] = 5.into();
        assert!(serde_json::from_value::<WindowsObservedState>(inner).is_err());
    }
}
