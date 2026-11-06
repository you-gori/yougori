//! A restricted start on Windows: the host runs a process under a lowered copy of its own
//! token, inside its own job, and reads back what is in effect (M02, M04; VM part §7.3
//! lines 2378–2380: "low-privilege identity, Job limits, handle inheritance, mitigations
//! compatible with the signed build and verified in effect"; VM-W19 row, line 2618:
//! "Exact machine/device build boots under intended token/Job rules; no inherited
//! sensitive handles"; VM-CP-04, line 3154).
//!
//! This is the hypervisor process's confinement on Windows, a weaker sibling of the
//! AppContainer start in `confined.rs` for a program that needs files outside a container
//! (its executable, firmware and boot inputs) and the Windows Hypervisor Platform:
//!
//! - **Token.** `CreateRestrictedToken` over the host's own primary token with
//!   `DISABLE_MAX_PRIVILEGE` (every privilege but `SeChangeNotifyPrivilege` removed), the
//!   Administrators group deny-only, and the restricting SIDs the caller names (Users,
//!   Everyone, `RESTRICTED`, the logon session), so a second access check runs against
//!   those alone: the process opens only what grants one of them. Its mandatory label is
//!   then lowered (low or untrusted), so it writes nothing labelled above it, and its
//!   default DACL grants only the user, SYSTEM and the logon session, so the objects it
//!   creates are not opened by other users. Nothing is ever raised: each step only
//!   removes. Everyone is among the restricting SIDs because USER32's initialization
//!   opens session objects granted to Everyone alone: measured on this host (30 October
//!   2026), a restricted process without it, on its own desktop, at low or at medium
//!   integrity, exits `0xC0000142` (`STATUS_DLL_INIT_FAILED`) before its own code runs,
//!   and runs once Everyone is added; the pinned QEMU build links USER32. The same set is
//!   Chromium's interactive token level. What it widens is stated, not hidden: an object
//!   that grants Everyone passes the second check, so the token excludes only what the
//!   user alone (or a group outside this set) is granted, such as the user's profile and
//!   data; the low mandatory label is what keeps the process from writing anything of
//!   medium integrity.
//! - **Handles.** It inherits exactly the handles of an explicit list
//!   (`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`): the `NUL` device for standard input and output
//!   and, when given, one log file for standard error. They are made inheritable as fresh
//!   duplicates just for the creation and closed right after it. Another thread that
//!   starts a process with inheritance and no list during that window could receive those
//!   two duplicates (a `NUL` handle and a write handle to the log); nothing else of this
//!   process is ever inheritable for it.
//! - **Mitigations.** The selected creation mitigation policies are set always-on
//!   (`PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY`).
//! - **Job.** Created suspended, assigned to a new job with kill-on-close, no breakaway,
//!   the caller's active-process and memory limits, die-on-unhandled-exception and every UI
//!   restriction, checked to be in it, then resumed (`windows_host.rs`), as every start.
//! - **No console.** The process is created detached (`DETACHED_PROCESS`): a console
//!   application gets no console, hidden or not, so no `conhost.exe` is created for it;
//!   with `CREATE_NO_WINDOW` the console host would be started into the job, counted by
//!   its active-process limit of one and refused, which fails the client's initialization
//!   too. Its standard handles are the listed ones.
//!
//! [`RestrictionReadback`] is the host's observation of a process it started, read through
//! the process and job handles it has held since the creation: the token's restriction,
//! restricting SIDs, privileges, Administrators state and integrity, the job's limits,
//! the mitigation policies in effect and the command line. The handle count is read while
//! the process is still suspended, before any of its code has run
//! ([`StartObservation`]). Nothing here opens another process.

use std::collections::BTreeSet;
use std::fmt;
use std::fs::File;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::process::Command;
use std::ptr::{null, null_mut};

use serde::{Deserialize, Serialize};
use windows_sys::Win32::Foundation::{
    DuplicateHandle, GetLastError, LocalFree, DUPLICATE_SAME_ACCESS, ERROR_INSUFFICIENT_BUFFER,
    GENERIC_ALL, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, LUID,
};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{
    WinMediumLabelSid,
    AddAccessAllowedAce, CreateRestrictedToken, CreateWellKnownSid, EqualSid, GetLengthSid,
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, InitializeAcl,
    InitializeSecurityDescriptor, IsTokenRestricted, LookupPrivilegeNameW,
    SetSecurityDescriptorDacl, SetTokenInformation, TokenDefaultDacl, TokenGroups,
    TokenIntegrityLevel, TokenPrivileges, TokenRestrictedSids, TokenUser, WinAuthenticatedUserSid,
    WinBuiltinAdministratorsSid, WinBuiltinUsersSid, WinLocalSystemSid, WinLowLabelSid,
    WinRestrictedCodeSid, WinUntrustedLabelSid, WinWorldSid, ACL, ACL_REVISION,
    DISABLE_MAX_PRIVILEGE, PSID, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, SID_AND_ATTRIBUTES,
    TOKEN_ADJUST_DEFAULT, TOKEN_ASSIGN_PRIMARY, TOKEN_DEFAULT_DACL, TOKEN_DUPLICATE, TOKEN_GROUPS,
    TOKEN_INFORMATION_CLASS, TOKEN_MANDATORY_LABEL, TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_USER,
    WELL_KNOWN_SID_TYPE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::JobObjects::{
    IsProcessInJob, JobObjectBasicUIRestrictions, JobObjectExtendedLimitInformation,
    QueryInformationJobObject, JOBOBJECT_BASIC_UI_RESTRICTIONS,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_BREAKAWAY_OK, JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
    JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessAsUserW, GetCurrentProcess, GetProcessHandleCount, GetProcessMitigationPolicy,
    OpenProcessToken, ProcessExtensionPointDisablePolicy, ProcessImageLoadPolicy,
    ProcessStrictHandleCheckPolicy, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, DETACHED_PROCESS,
    EXTENDED_STARTUPINFO_PRESENT, PROCESS_INFORMATION, PROCESS_MITIGATION_POLICY,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
    STARTF_USESTDHANDLES, STARTUPINFOEXW,
};
use windows_sys::Win32::UI::Shell::CommandLineToArgvW;

use super::confined::{command_line, environment, wide, AttributeList};
use super::handle::ProcessError;
use super::station::SandboxDesktop;

// Token group attributes (winnt.h); `Win32_System_SystemServices` is not enabled.
const SE_GROUP_ENABLED: u32 = 0x0000_0004;
const SE_GROUP_USE_FOR_DENY_ONLY: u32 = 0x0000_0010;
const SE_GROUP_INTEGRITY: u32 = 0x0000_0020;
const SE_GROUP_LOGON_ID: u32 = 0xC000_0000;

// Creation mitigation policies, always on (winbase.h, PROCESS_CREATION_MITIGATION_POLICY_*).
const POLICY_STRICT_HANDLE_CHECKS: u64 = 1 << 24;
const POLICY_EXTENSION_POINT_DISABLE: u64 = 1 << 32;
const POLICY_IMAGE_LOAD_NO_REMOTE: u64 = 1 << 52;
const POLICY_IMAGE_LOAD_NO_LOW_LABEL: u64 = 1 << 56;

// Every job UI restriction (winnt.h JOB_OBJECT_UILIMIT_*): handles, read and write
// clipboard, system parameters, display settings, global atoms, desktop, exit Windows.
const UI_RESTRICTIONS_ALL: u32 = 0x0000_00FF;

/// `ProcessCommandLineInformation` (winternl.h, Windows 8.1 and later).
const PROCESS_COMMAND_LINE_INFORMATION: u32 = 60;
/// `STATUS_INFO_LENGTH_MISMATCH`.
const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004_u32 as i32;

/// `SECURITY_DESCRIPTOR_REVISION` (winnt.h); `windows-sys` does not export it here.
const SECURITY_DESCRIPTOR_REVISION: u32 = 1;

/// The largest SID Windows writes (`SECURITY_MAX_SID_SIZE`).
const MAX_SID_BYTES: u32 = 68;
/// The largest token or command-line answer this module reads.
const MAX_ANSWER_BYTES: u32 = 64 * 1024;
/// The longest privilege name read back.
const MAX_PRIVILEGE_NAME: u32 = 64;

#[link(name = "ntdll", kind = "raw-dylib")]
extern "system" {
    fn NtQueryInformationProcess(
        process: HANDLE,
        class: u32,
        information: *mut core::ffi::c_void,
        length: u32,
        returned: *mut u32,
    ) -> i32;
}

/// A restricting SID of a restricted token: the second access check runs against these
/// only, so each one widens what the process can open.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestrictingGroup {
    /// `BUILTIN\Users` (S-1-5-32-545).
    Users,
    /// `Everyone` (S-1-1-0): what USER32's initialization needs (module notes).
    Everyone,
    /// `NT AUTHORITY\RESTRICTED` (S-1-5-12).
    Restricted,
    /// The host's logon session (S-1-5-5-x-y), read from its own token.
    LogonSession,
    /// `NT AUTHORITY\Authenticated Users` (S-1-5-11): what the Windows Hypervisor
    /// Platform's device grants. Measured on this host (30 October 2026, the diagnostic
    /// `whpx_capability_under_token_variants`): `WHvGetCapability` is refused
    /// (`E_ACCESSDENIED`) under Users, Everyone, RESTRICTED and the logon session at any
    /// integrity, allowed with no restricting SID even at low integrity, and allowed once
    /// this SID is among them; INTERACTIVE does not do. A hypervisor-backed VM cannot run
    /// without it, so the Windows QEMU profile names it and records the widening.
    AuthenticatedUsers,
}

/// The mandatory label a restricted process runs at.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoweredIntegrity {
    /// S-1-16-4096.
    Low,
    /// S-1-16-0.
    Untrusted,
    /// The engine's own level, kept: for a process whose privileges are disabled and whose
    /// Administrators group is deny-only but which must read the user's credential store
    /// and open the engine's owner-only pipes, which refuse every lower label and every
    /// restricting SID (measured 30 October 2026, `executor_needs_under_token_variants`:
    /// the Credential Manager and an owner-only pipe answer error 5 under any restricting
    /// SID at any label; the pipe refuses the low label; both open with no restricting SID
    /// at the kept label).
    Medium,
}

impl LoweredIntegrity {
    /// The mandatory-label RID.
    pub const fn rid(self) -> u32 {
        match self {
            Self::Low => 0x1000,
            Self::Untrusted => 0,
            Self::Medium => 0x2000,
        }
    }
}

/// A process creation mitigation policy a restricted start sets always on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StartMitigation {
    StrictHandleChecks,
    ExtensionPointDisable,
    ImageLoadNoRemote,
    ImageLoadNoLowLabel,
}

impl StartMitigation {
    pub const ALL: [Self; 4] = [
        Self::StrictHandleChecks,
        Self::ExtensionPointDisable,
        Self::ImageLoadNoRemote,
        Self::ImageLoadNoLowLabel,
    ];

    const fn creation_flag(self) -> u64 {
        match self {
            Self::StrictHandleChecks => POLICY_STRICT_HANDLE_CHECKS,
            Self::ExtensionPointDisable => POLICY_EXTENSION_POINT_DISABLE,
            Self::ImageLoadNoRemote => POLICY_IMAGE_LOAD_NO_REMOTE,
            Self::ImageLoadNoLowLabel => POLICY_IMAGE_LOAD_NO_LOW_LABEL,
        }
    }
}

/// The creation flags of a mitigation set.
pub(super) fn mitigation_flags(mitigations: &BTreeSet<StartMitigation>) -> u64 {
    mitigations
        .iter()
        .fold(0, |flags, mitigation| flags | mitigation.creation_flag())
}

/// The job a restricted process runs in, beyond kill-on-close and no breakaway, which
/// every job of this module has.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobSettings {
    /// At least 1: the process itself.
    pub active_process_limit: u32,
    /// The committed memory of the whole job, in bytes; more than zero.
    pub job_memory_limit_bytes: u64,
    pub die_on_unhandled_exception: bool,
    /// Every UI restriction: desktop, display settings, exit Windows, global atoms, USER
    /// handles, clipboard read and write, system parameters.
    pub ui_restrictions: bool,
}

impl JobSettings {
    /// The job's limit flags.
    pub(super) fn limit_flags(&self) -> u32 {
        let mut flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | JOB_OBJECT_LIMIT_JOB_MEMORY;
        if self.die_on_unhandled_exception {
            flags |= JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
        }
        flags
    }

    /// The job's UI restriction class.
    pub(super) fn ui_class(&self) -> u32 {
        if self.ui_restrictions {
            UI_RESTRICTIONS_ALL
        } else {
            0
        }
    }
}

/// How a process the host starts is restricted on Windows (see the module notes).
pub struct RestrictedStart {
    /// Not empty.
    pub restricting: BTreeSet<RestrictingGroup>,
    pub integrity: LoweredIntegrity,
    pub job: JobSettings,
    pub mitigations: BTreeSet<StartMitigation>,
    /// Standard error; standard input and output are the `NUL` device, as is standard
    /// error when this is `None`.
    pub stderr: Option<File>,
    /// The desktop the process runs on ([`SandboxDesktop`](super::SandboxDesktop)). A
    /// program that links USER32, GDI32 or COM cannot initialize at low integrity on the
    /// interactive desktop, so every restricted start has one of its own.
    pub desktop: SandboxDesktop,
}

impl fmt::Debug for RestrictedStart {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RestrictedStart")
            .field("restricting", &self.restricting)
            .field("integrity", &self.integrity)
            .field("job", &self.job)
            .field("mitigations", &self.mitigations)
            .field("stderr", &self.stderr.is_some())
            .field("desktop", &self.desktop)
            .finish()
    }
}

/// What the host saw of a restricted process before it resumed it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartObservation {
    /// The process's handle count while it was suspended (`GetProcessHandleCount`),
    /// before any of its code ran.
    pub handles_at_start: u32,
    /// The handles the explicit list passed: the `NUL` device, and the log file when
    /// one was given.
    pub listed_handles: u32,
    /// Whether standard error was a log file.
    pub stderr_logged: bool,
}

/// A restricting SID as the host read it back from the process's token.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "group", rename_all = "snake_case")]
pub enum ObservedGroup {
    Users,
    Restricted,
    LogonSession,
    Everyone,
    AuthenticatedUsers,
    /// Any other SID, in its string form.
    Other {
        sid: String,
    },
}

/// The Administrators group in the token, as read back.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdministratorsState {
    Absent,
    DenyOnly,
    Enabled,
}

/// The job's limits, as queried from the job object the host holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedJobLimits {
    pub kill_on_close: bool,
    pub die_on_unhandled_exception: bool,
    pub breakaway_ok: bool,
    pub silent_breakaway_ok: bool,
    /// Zero when the job has no active-process limit.
    pub active_process_limit: u32,
    /// Zero when the job has no memory limit.
    pub job_memory_limit_bytes: u64,
    /// The UI restriction class, as `JOB_OBJECT_UILIMIT_*` flags.
    pub ui_restrictions: u32,
}

/// The host's read-back of a process it started and holds (see the module notes).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestrictionReadback {
    /// `IsTokenRestricted`.
    pub token_restricted: bool,
    pub restricting: BTreeSet<ObservedGroup>,
    /// Privilege names present in the token.
    pub privileges: BTreeSet<String>,
    pub administrators: AdministratorsState,
    pub integrity_rid: u32,
    /// Whether the process is in the job the host holds for it.
    pub in_job: bool,
    pub job: ObservedJobLimits,
    /// The mitigation policies `GetProcessMitigationPolicy` reports in effect.
    pub mitigations: BTreeSet<StartMitigation>,
    /// The process's command line, split as `CommandLineToArgvW` splits it.
    pub command_line: Vec<String>,
}

/// One step of a read-back that failed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReadbackError {
    pub step: &'static str,
    pub os_error: u32,
}

impl fmt::Display for ReadbackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "could not read back the process's {} (OS error {})",
            self.step, self.os_error
        )
    }
}

impl std::error::Error for ReadbackError {}

pub(super) fn last_error() -> u32 {
    // SAFETY: GetLastError has no preconditions.
    unsafe { GetLastError() }
}

fn start_error(what: &str) -> ProcessError {
    ProcessError::Spawn {
        detail: format!(
            "could not {what} for the restricted start (OS error {})",
            last_error()
        ),
    }
}

fn readback_error(step: &'static str) -> ReadbackError {
    ReadbackError {
        step,
        os_error: last_error(),
    }
}

/// Takes ownership of a handle a Windows call returned, `None` for null or invalid.
fn owned(raw: HANDLE) -> Option<OwnedHandle> {
    // SAFETY: a valid handle a call has just returned is open and owned by nobody else.
    (!raw.is_null() && raw != INVALID_HANDLE_VALUE)
        .then(|| unsafe { OwnedHandle::from_raw_handle(raw) })
}

/// A SID in a buffer aligned for one.
pub(super) struct Sid {
    buffer: Vec<u32>,
}

impl Sid {
    pub(super) fn well_known(kind: WELL_KNOWN_SID_TYPE) -> Option<Self> {
        let mut buffer = vec![0_u32; usize::try_from(MAX_SID_BYTES / 4).ok()?];
        let mut size = MAX_SID_BYTES;
        // SAFETY: `buffer` holds `size` writable bytes; no domain SID is needed for these.
        let made =
            unsafe { CreateWellKnownSid(kind, null_mut(), buffer.as_mut_ptr().cast(), &mut size) };
        (made != 0).then_some(Self { buffer })
    }

    /// The mandatory-label SID of `integrity`.
    pub(super) fn mandatory_label(integrity: LoweredIntegrity) -> Option<Self> {
        Self::well_known(match integrity {
            LoweredIntegrity::Low => WinLowLabelSid,
            LoweredIntegrity::Untrusted => WinUntrustedLabelSid,
            LoweredIntegrity::Medium => WinMediumLabelSid,
        })
    }

    /// Copies the SID `sid` points to.
    ///
    /// # Safety
    /// `sid` points to a valid SID.
    unsafe fn copy(sid: PSID) -> Option<Self> {
        // SAFETY: the caller's SID is valid, so its length is readable.
        let length = unsafe { GetLengthSid(sid) };
        if length == 0 || length > MAX_SID_BYTES {
            return None;
        }
        let mut buffer = vec![0_u32; usize::try_from(length.div_ceil(4)).ok()?];
        // SAFETY: the source holds `length` bytes and the buffer at least as many.
        unsafe {
            std::ptr::copy_nonoverlapping(
                sid.cast::<u8>(),
                buffer.as_mut_ptr().cast::<u8>(),
                usize::try_from(length).ok()?,
            );
        }
        Some(Self { buffer })
    }

    pub(super) fn as_psid(&self) -> PSID {
        self.buffer.as_ptr().cast_mut().cast()
    }

    pub(super) fn length(&self) -> u32 {
        // SAFETY: the buffer holds a valid SID.
        unsafe { GetLengthSid(self.as_psid()) }
    }

    fn equals(&self, sid: PSID) -> bool {
        // SAFETY: both SIDs are valid.
        unsafe { EqualSid(self.as_psid(), sid) != 0 }
    }
}

/// A token information class read into an aligned buffer.
fn token_information(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Option<Vec<u64>> {
    let mut needed = 0_u32;
    // SAFETY: a null buffer of length zero asks only for the size.
    let sized = unsafe { GetTokenInformation(token, class, null_mut(), 0, &mut needed) };
    if sized == 0 && last_error() != ERROR_INSUFFICIENT_BUFFER {
        return None;
    }
    if needed == 0 || needed > MAX_ANSWER_BYTES {
        return None;
    }
    let mut buffer = vec![0_u64; usize::try_from(needed.div_ceil(8)).ok()?];
    let mut written = 0_u32;
    // SAFETY: `buffer` holds at least `needed` writable bytes, aligned for the answer.
    let read = unsafe {
        GetTokenInformation(
            token,
            class,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut written,
        )
    };
    (read != 0).then_some(buffer)
}

/// The groups of a `TOKEN_GROUPS` answer.
///
/// # Safety
/// `buffer` holds a `TOKEN_GROUPS` answer for the token information class it was read
/// for.
unsafe fn groups(buffer: &[u64]) -> &[SID_AND_ATTRIBUTES] {
    let groups = buffer.as_ptr().cast::<TOKEN_GROUPS>();
    // SAFETY: the answer starts with a TOKEN_GROUPS whose array holds `GroupCount` entries
    // inside the same buffer.
    unsafe {
        let count = usize::try_from((*groups).GroupCount).unwrap_or(0);
        std::slice::from_raw_parts((*groups).Groups.as_ptr(), count)
    }
}

/// The host's own primary token, opened to derive the restricted one.
pub(super) fn own_token() -> Result<OwnedHandle, ProcessError> {
    let mut token: HANDLE = null_mut();
    // SAFETY: the pseudo-handle of this process is always valid; `token` is live.
    let opened = unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT,
            &mut token,
        )
    };
    if opened == 0 {
        return Err(start_error("open the host's token"));
    }
    owned(token).ok_or_else(|| start_error("open the host's token"))
}

/// The logon session SID of `token`.
pub(super) fn logon_sid(token: HANDLE) -> Result<Sid, ProcessError> {
    let buffer = token_information(token, TokenGroups)
        .ok_or_else(|| start_error("read the host's token groups"))?;
    // SAFETY: the buffer holds the TokenGroups answer.
    let found = unsafe { groups(&buffer) }
        .iter()
        .find(|group| group.Attributes & SE_GROUP_LOGON_ID == SE_GROUP_LOGON_ID);
    match found {
        // SAFETY: a group's SID in the answer is valid.
        Some(group) => unsafe { Sid::copy(group.Sid) }
            .ok_or_else(|| start_error("copy the host's logon session SID")),
        None => Err(ProcessError::Spawn {
            detail: "the host's token has no logon session SID".to_owned(),
        }),
    }
}

/// The user SID of `token`.
pub(super) fn user_sid(token: HANDLE) -> Result<Sid, ProcessError> {
    let buffer = token_information(token, TokenUser)
        .ok_or_else(|| start_error("read the host's token user"))?;
    let user = buffer.as_ptr().cast::<TOKEN_USER>();
    // SAFETY: the buffer holds the TokenUser answer, whose SID points inside it.
    unsafe { Sid::copy((*user).User.Sid) }.ok_or_else(|| start_error("copy the host's user SID"))
}

pub(super) fn well_known(kind: WELL_KNOWN_SID_TYPE, what: &str) -> Result<Sid, ProcessError> {
    Sid::well_known(kind).ok_or_else(|| start_error(&format!("make the {what} SID")))
}

/// A security descriptor whose only content is a discretionary ACL, with the
/// `SECURITY_ATTRIBUTES` that point at it. Both must outlive the call they are passed to,
/// so they are held together and borrowed.
pub(super) struct ObjectSecurity {
    descriptor: Box<SECURITY_DESCRIPTOR>,
}

impl ObjectSecurity {
    /// A descriptor granting exactly `acl`, which the caller keeps alive and unmoved.
    pub(super) fn with_dacl(acl: &mut [u32]) -> Result<Self, ProcessError> {
        let mut descriptor = Box::new(SECURITY_DESCRIPTOR::default());
        let pointer = std::ptr::from_mut(descriptor.as_mut()).cast();
        // SAFETY: the descriptor is live and owned here; the ACL outlives this value by
        // the caller's contract, so the stored pointer stays valid.
        let set = unsafe {
            InitializeSecurityDescriptor(pointer, SECURITY_DESCRIPTOR_REVISION) != 0
                && SetSecurityDescriptorDacl(pointer, 1, acl.as_mut_ptr().cast(), 0) != 0
        };
        if !set {
            return Err(start_error("build a security descriptor"));
        }
        Ok(Self { descriptor })
    }

    /// Attributes pointing at this descriptor; they must not outlive it.
    pub(super) fn attributes(&mut self) -> Result<SECURITY_ATTRIBUTES, ProcessError> {
        Ok(SECURITY_ATTRIBUTES {
            nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>())
                .map_err(|_| start_error("size the security attributes"))?,
            lpSecurityDescriptor: std::ptr::from_mut(self.descriptor.as_mut()).cast(),
            bInheritHandle: 0,
        })
    }
}

/// An ACL granting all access to each SID, in a buffer aligned for it.
fn allow_all(sids: &[&Sid]) -> Result<Vec<u32>, ProcessError> {
    // ACL header, then per ACE its header and mask (8 bytes) and the SID.
    let size = sids
        .iter()
        .fold(8_u32, |size, sid| size.saturating_add(8 + sid.length()));
    let mut buffer =
        vec![0_u32; usize::try_from(size.div_ceil(4)).map_err(|_| start_error("size an ACL"))?];
    let acl = buffer.as_mut_ptr().cast::<ACL>();
    // SAFETY: `buffer` holds `size` writable bytes, aligned for an ACL.
    if unsafe { InitializeAcl(acl, size, ACL_REVISION) } == 0 {
        return Err(start_error("initialize the default DACL"));
    }
    for sid in sids {
        // SAFETY: the ACL is initialized with room for every ACE; the SID is valid.
        if unsafe { AddAccessAllowedAce(acl, ACL_REVISION, GENERIC_ALL, sid.as_psid()) } == 0 {
            return Err(start_error("add an entry to the default DACL"));
        }
    }
    Ok(buffer)
}

/// The restricted primary token of a start (see the module notes).
fn restricted_token(start: &RestrictedStart) -> Result<OwnedHandle, ProcessError> {
    let own = own_token()?;
    let logon = logon_sid(own.as_raw_handle())?;
    let user = user_sid(own.as_raw_handle())?;
    let users = well_known(WinBuiltinUsersSid, "Users")?;
    let restricted = well_known(WinRestrictedCodeSid, "RESTRICTED")?;
    let administrators = well_known(WinBuiltinAdministratorsSid, "Administrators")?;
    let system = well_known(WinLocalSystemSid, "SYSTEM")?;
    let everyone = well_known(WinWorldSid, "Everyone")?;
    let authenticated = well_known(WinAuthenticatedUserSid, "Authenticated Users")?;
    let restricting: Vec<SID_AND_ATTRIBUTES> = start
        .restricting
        .iter()
        .map(|group| SID_AND_ATTRIBUTES {
            Sid: match group {
                RestrictingGroup::Users => users.as_psid(),
                RestrictingGroup::Everyone => everyone.as_psid(),
                RestrictingGroup::Restricted => restricted.as_psid(),
                RestrictingGroup::LogonSession => logon.as_psid(),
                RestrictingGroup::AuthenticatedUsers => authenticated.as_psid(),
            },
            Attributes: 0,
        })
        .collect();
    let disable = [SID_AND_ATTRIBUTES {
        Sid: administrators.as_psid(),
        Attributes: 0,
    }];
    let count = u32::try_from(restricting.len()).map_err(|_| start_error("count the SIDs"))?;
    let mut token: HANDLE = null_mut();
    // SAFETY: the source token is open with duplicate access; every SID array and SID is
    // live for the call; `token` is live.
    let made = unsafe {
        CreateRestrictedToken(
            own.as_raw_handle(),
            DISABLE_MAX_PRIVILEGE,
            1,
            disable.as_ptr(),
            0,
            null(),
            count,
            restricting.as_ptr(),
            &mut token,
        )
    };
    if made == 0 {
        return Err(start_error("create the restricted token"));
    }
    let token = owned(token).ok_or_else(|| start_error("create the restricted token"))?;
    let label = well_known(
        match start.integrity {
            LoweredIntegrity::Low => WinLowLabelSid,
            LoweredIntegrity::Untrusted => WinUntrustedLabelSid,
            LoweredIntegrity::Medium => WinMediumLabelSid,
        },
        "mandatory label",
    )?;
    let mandatory = TOKEN_MANDATORY_LABEL {
        Label: SID_AND_ATTRIBUTES {
            Sid: label.as_psid(),
            Attributes: SE_GROUP_INTEGRITY,
        },
    };
    let size = u32::try_from(std::mem::size_of::<TOKEN_MANDATORY_LABEL>())
        .map_err(|_| start_error("size the label"))?
        .saturating_add(label.length());
    // SAFETY: the token is open with adjust-default access; the label and its SID are live.
    let lowered = unsafe {
        SetTokenInformation(
            token.as_raw_handle(),
            TokenIntegrityLevel,
            (&mandatory as *const TOKEN_MANDATORY_LABEL).cast(),
            size,
        )
    };
    if lowered == 0 {
        return Err(start_error("lower the token's integrity"));
    }
    let mut dacl = allow_all(&[&user, &system, &logon])?;
    let default = TOKEN_DEFAULT_DACL {
        DefaultDacl: dacl.as_mut_ptr().cast(),
    };
    // SAFETY: the token is open with adjust-default access; the ACL is live.
    let set = unsafe {
        SetTokenInformation(
            token.as_raw_handle(),
            TokenDefaultDacl,
            (&default as *const TOKEN_DEFAULT_DACL).cast(),
            u32::try_from(std::mem::size_of::<TOKEN_DEFAULT_DACL>())
                .map_err(|_| start_error("size the default DACL"))?,
        )
    };
    if set == 0 {
        return Err(start_error("set the token's default DACL"));
    }
    Ok(token)
}

/// An inheritable handle to the `NUL` device.
fn null_device() -> Result<OwnedHandle, ProcessError> {
    let name: Vec<u16> = "NUL".encode_utf16().chain([0]).collect();
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>())
            .map_err(|_| start_error("size the security attributes"))?,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 1,
    };
    // SAFETY: the name is NUL-terminated and the attributes are live.
    let raw = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &attributes,
            OPEN_EXISTING,
            0,
            null_mut(),
        )
    };
    owned(raw).ok_or_else(|| start_error("open the NUL device"))
}

/// An inheritable duplicate of `file`'s handle.
fn inheritable(file: &File) -> Result<OwnedHandle, ProcessError> {
    let mut duplicate: HANDLE = null_mut();
    // SAFETY: the file handle is open; this process's pseudo-handle is always valid.
    let made = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            file.as_raw_handle(),
            GetCurrentProcess(),
            &mut duplicate,
            0,
            1,
            DUPLICATE_SAME_ACCESS,
        )
    };
    if made == 0 {
        return Err(start_error("duplicate the log file's handle"));
    }
    owned(duplicate).ok_or_else(|| start_error("duplicate the log file's handle"))
}

/// What a restricted creation returns: the process handle, its PID and what was seen of
/// it while suspended.
pub(super) struct Created {
    pub(super) handle: OwnedHandle,
    pub(super) pid: u32,
    pub(super) observation: StartObservation,
}

/// Creates `command`'s process suspended under `start` (see the module notes). The
/// program must be an absolute path; the command's standard streams and creation flags
/// are not used; the environment is only what the command sets.
pub(super) fn create_restricted_suspended(
    command: &Command,
    start: &mut RestrictedStart,
) -> Result<Created, ProcessError> {
    if !Path::new(command.get_program()).is_absolute() {
        return Err(ProcessError::Spawn {
            detail: "a restricted program is named by an absolute path".to_owned(),
        });
    }
    // A lowered start restricts through its SIDs; a start that keeps the medium label is
    // the sandbox executor's measured profile (privileges disabled, Administrators
    // deny-only, the job, the mitigations, no inherited handle), whose needs refuse every
    // restricting SID (`LoweredIntegrity::Medium`), so it alone may name none.
    if start.restricting.is_empty() && start.integrity != LoweredIntegrity::Medium {
        return Err(ProcessError::Spawn {
            detail: "a restricted start names at least one restricting SID".to_owned(),
        });
    }
    if start.job.active_process_limit == 0 || start.job.job_memory_limit_bytes == 0 {
        return Err(ProcessError::Spawn {
            detail: "a restricted start's job limits are above zero".to_owned(),
        });
    }
    let mut application = wide(command.get_program())?;
    application.push(0);
    let mut line = command_line(command)?;
    let environment = environment(command)?;
    let directory = match command.get_current_dir() {
        Some(directory) => {
            let mut directory = wide(directory.as_os_str())?;
            directory.push(0);
            Some(directory)
        }
        None => None,
    };
    let token = restricted_token(start)?;
    let null_handle = null_device()?;
    let stderr = start.stderr.as_ref().map(inheritable).transpose()?;
    let stderr_raw = stderr
        .as_ref()
        .map_or(null_handle.as_raw_handle(), |handle| handle.as_raw_handle());
    let mut listed: Vec<HANDLE> = vec![null_handle.as_raw_handle()];
    if let Some(handle) = &stderr {
        listed.push(handle.as_raw_handle());
    }
    let policy = mitigation_flags(&start.mitigations);
    let mut attributes = AttributeList::new(2)?;
    // SAFETY: `listed` and `policy` live, unmoved, until after CreateProcessAsUserW below,
    // and every handle in `listed` stays open until then.
    unsafe {
        attributes.set(
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            listed.as_ptr().cast(),
            std::mem::size_of_val(listed.as_slice()),
        )?;
        attributes.set(
            PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
            (&policy as *const u64).cast(),
            std::mem::size_of::<u64>(),
        )?;
    }
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = u32::try_from(std::mem::size_of::<STARTUPINFOEXW>())
        .map_err(|_| start_error("size the start-up information"))?;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = null_handle.as_raw_handle();
    startup.StartupInfo.hStdOutput = null_handle.as_raw_handle();
    startup.StartupInfo.hStdError = stderr_raw;
    startup.StartupInfo.lpDesktop = start.desktop.desktop_path();
    startup.lpAttributeList = attributes.as_ptr();
    let mut information = PROCESS_INFORMATION::default();
    // SAFETY: the token is a restricted primary token derived from this process's own, so
    // no assign-primary privilege is needed; every string is NUL-terminated and live; the
    // environment block is double-NUL-terminated UTF-16; the attribute list and what it
    // points to are live; inheritance is limited to the listed handles.
    let created = unsafe {
        CreateProcessAsUserW(
            token.as_raw_handle(),
            application.as_ptr(),
            line.as_mut_ptr(),
            null(),
            null(),
            1,
            CREATE_SUSPENDED
                | DETACHED_PROCESS
                | EXTENDED_STARTUPINFO_PRESENT
                | CREATE_UNICODE_ENVIRONMENT,
            environment.as_ptr().cast(),
            directory
                .as_ref()
                .map_or(null(), |directory| directory.as_ptr()),
            &startup.StartupInfo,
            &mut information,
        )
    };
    if created == 0 {
        return Err(start_error("create the restricted process"));
    }
    drop(attributes);
    drop(stderr);
    drop(null_handle);
    drop(owned(information.hThread));
    let handle =
        owned(information.hProcess).ok_or_else(|| start_error("create the restricted process"))?;
    let mut handles_at_start = 0_u32;
    // SAFETY: the process handle is open with full access; the count is live.
    if unsafe { GetProcessHandleCount(handle.as_raw_handle(), &mut handles_at_start) } == 0 {
        return Err(start_error("count the suspended process's handles"));
    }
    let listed_handles =
        u32::try_from(listed.len()).map_err(|_| start_error("count the listed handles"))?;
    Ok(Created {
        handle,
        pid: information.dwProcessId,
        observation: StartObservation {
            handles_at_start,
            listed_handles,
            stderr_logged: start.stderr.is_some(),
        },
    })
}

/// Reads back the restrictions of the process `process`, which the host holds, and of its
/// job `job` (see the module notes).
pub(super) fn read_back(
    process: HANDLE,
    job: HANDLE,
) -> Result<RestrictionReadback, ReadbackError> {
    let mut token: HANDLE = null_mut();
    // SAFETY: the process handle is open; `token` is live.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return Err(readback_error("token"));
    }
    let token = owned(token).ok_or_else(|| readback_error("token"))?;
    let token_raw = token.as_raw_handle();
    // SAFETY: the token is open with query access.
    let token_restricted = unsafe { IsTokenRestricted(token_raw) } != 0;
    let restricting = restricting_groups(token_raw)?;
    let privileges = privilege_names(token_raw)?;
    let administrators = administrators_state(token_raw)?;
    let integrity_rid = integrity_rid(token_raw)?;
    let mut in_job = 0;
    // SAFETY: both handles are open and `in_job` is a live BOOL.
    if unsafe { IsProcessInJob(process, job, &mut in_job) } == 0 {
        return Err(readback_error("job membership"));
    }
    Ok(RestrictionReadback {
        token_restricted,
        restricting,
        privileges,
        administrators,
        integrity_rid,
        in_job: in_job != 0,
        job: job_limits(job)?,
        mitigations: mitigations_in_effect(process)?,
        command_line: process_command_line(process)?,
    })
}

fn sid_string(sid: PSID) -> String {
    let mut text: *mut u16 = null_mut();
    // SAFETY: the SID is valid; `text` receives a LocalAlloc'd string.
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 || text.is_null() {
        return "unreadable".to_owned();
    }
    // SAFETY: `text` is a NUL-terminated wide string, freed once below.
    let string = unsafe {
        let length = (0..).take_while(|&at| *text.add(at) != 0).count();
        String::from_utf16_lossy(std::slice::from_raw_parts(text, length))
    };
    // SAFETY: `text` came from LocalAlloc inside the call.
    unsafe { LocalFree(text.cast()) };
    string
}

fn restricting_groups(token: HANDLE) -> Result<BTreeSet<ObservedGroup>, ReadbackError> {
    let users = Sid::well_known(WinBuiltinUsersSid).ok_or_else(|| readback_error("SIDs"))?;
    let restricted = Sid::well_known(WinRestrictedCodeSid).ok_or_else(|| readback_error("SIDs"))?;
    let everyone = Sid::well_known(WinWorldSid).ok_or_else(|| readback_error("SIDs"))?;
    let authenticated =
        Sid::well_known(WinAuthenticatedUserSid).ok_or_else(|| readback_error("SIDs"))?;
    // The restricting SIDs carry no attributes, so the logon session's is recognized by
    // the logon SID among the token's own groups.
    let own_groups =
        token_information(token, TokenGroups).ok_or_else(|| readback_error("groups"))?;
    // SAFETY: the buffer holds the TokenGroups answer.
    let logon = unsafe { groups(&own_groups) }
        .iter()
        .find(|group| group.Attributes & SE_GROUP_LOGON_ID == SE_GROUP_LOGON_ID)
        // SAFETY: a group's SID in the answer is valid.
        .and_then(|group| unsafe { Sid::copy(group.Sid) });
    let buffer = token_information(token, TokenRestrictedSids)
        .ok_or_else(|| readback_error("restricting SIDs"))?;
    // SAFETY: the buffer holds the TokenRestrictedSids answer, a TOKEN_GROUPS.
    let found = unsafe { groups(&buffer) };
    Ok(found
        .iter()
        .map(|group| {
            if users.equals(group.Sid) {
                ObservedGroup::Users
            } else if restricted.equals(group.Sid) {
                ObservedGroup::Restricted
            } else if everyone.equals(group.Sid) {
                ObservedGroup::Everyone
            } else if authenticated.equals(group.Sid) {
                ObservedGroup::AuthenticatedUsers
            } else if logon.as_ref().is_some_and(|logon| logon.equals(group.Sid)) {
                ObservedGroup::LogonSession
            } else {
                ObservedGroup::Other {
                    sid: sid_string(group.Sid),
                }
            }
        })
        .collect())
}

fn privilege_names(token: HANDLE) -> Result<BTreeSet<String>, ReadbackError> {
    let buffer =
        token_information(token, TokenPrivileges).ok_or_else(|| readback_error("privileges"))?;
    let privileges = buffer.as_ptr().cast::<TOKEN_PRIVILEGES>();
    // SAFETY: the answer starts with a TOKEN_PRIVILEGES whose array holds
    // `PrivilegeCount` entries inside the same buffer.
    let entries = unsafe {
        let count = usize::try_from((*privileges).PrivilegeCount).unwrap_or(0);
        std::slice::from_raw_parts((*privileges).Privileges.as_ptr(), count)
    };
    let mut names = BTreeSet::new();
    for entry in entries {
        names.insert(privilege_name(&entry.Luid)?);
    }
    Ok(names)
}

fn privilege_name(luid: &LUID) -> Result<String, ReadbackError> {
    let mut name = vec![0_u16; usize::try_from(MAX_PRIVILEGE_NAME).unwrap_or(64)];
    let mut length = MAX_PRIVILEGE_NAME;
    // SAFETY: `name` holds `length` writable characters; the LUID is live.
    if unsafe { LookupPrivilegeNameW(null(), luid, name.as_mut_ptr(), &mut length) } == 0 {
        return Err(readback_error("privilege names"));
    }
    let length = usize::try_from(length).unwrap_or(0).min(name.len());
    Ok(String::from_utf16_lossy(&name[..length]))
}

fn administrators_state(token: HANDLE) -> Result<AdministratorsState, ReadbackError> {
    let administrators =
        Sid::well_known(WinBuiltinAdministratorsSid).ok_or_else(|| readback_error("SIDs"))?;
    let buffer = token_information(token, TokenGroups).ok_or_else(|| readback_error("groups"))?;
    // SAFETY: the buffer holds the TokenGroups answer.
    let found = unsafe { groups(&buffer) }
        .iter()
        .find(|group| administrators.equals(group.Sid));
    Ok(match found {
        None => AdministratorsState::Absent,
        Some(group) if group.Attributes & SE_GROUP_USE_FOR_DENY_ONLY != 0 => {
            AdministratorsState::DenyOnly
        }
        Some(group) if group.Attributes & SE_GROUP_ENABLED != 0 => AdministratorsState::Enabled,
        // Present, neither enabled nor deny-only: it grants nothing.
        Some(_) => AdministratorsState::DenyOnly,
    })
}

fn integrity_rid(token: HANDLE) -> Result<u32, ReadbackError> {
    let buffer = token_information(token, TokenIntegrityLevel)
        .ok_or_else(|| readback_error("integrity level"))?;
    let label = buffer.as_ptr().cast::<TOKEN_MANDATORY_LABEL>();
    // SAFETY: the answer holds a TOKEN_MANDATORY_LABEL whose SID points inside it; the
    // last sub-authority is read only when there is one.
    unsafe {
        let sid = (*label).Label.Sid;
        let count = u32::from(*GetSidSubAuthorityCount(sid));
        if count == 0 {
            return Err(ReadbackError {
                step: "integrity level",
                os_error: 0,
            });
        }
        Ok(*GetSidSubAuthority(sid, count - 1))
    }
}

fn job_limits(job: HANDLE) -> Result<ObservedJobLimits, ReadbackError> {
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    let mut ui = JOBOBJECT_BASIC_UI_RESTRICTIONS::default();
    // SAFETY: the job handle is open with query access; each structure is live and of
    // the stated size.
    let read = unsafe {
        QueryInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            (&mut limits as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            u32::try_from(std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()).unwrap_or(0),
            null_mut(),
        ) != 0
            && QueryInformationJobObject(
                job,
                JobObjectBasicUIRestrictions,
                (&mut ui as *mut JOBOBJECT_BASIC_UI_RESTRICTIONS).cast(),
                u32::try_from(std::mem::size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>()).unwrap_or(0),
                null_mut(),
            ) != 0
    };
    if !read {
        return Err(readback_error("job limits"));
    }
    let flags = limits.BasicLimitInformation.LimitFlags;
    let has = |flag: u32| flags & flag != 0;
    Ok(ObservedJobLimits {
        kill_on_close: has(JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE),
        die_on_unhandled_exception: has(JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION),
        breakaway_ok: has(JOB_OBJECT_LIMIT_BREAKAWAY_OK),
        silent_breakaway_ok: has(JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK),
        active_process_limit: if has(JOB_OBJECT_LIMIT_ACTIVE_PROCESS) {
            limits.BasicLimitInformation.ActiveProcessLimit
        } else {
            0
        },
        job_memory_limit_bytes: if has(JOB_OBJECT_LIMIT_JOB_MEMORY) {
            u64::try_from(limits.JobMemoryLimit).unwrap_or(u64::MAX)
        } else {
            0
        },
        ui_restrictions: ui.UIRestrictionsClass,
    })
}

/// One mitigation policy's flags word.
fn policy_word(process: HANDLE, policy: PROCESS_MITIGATION_POLICY) -> Result<u32, ReadbackError> {
    let mut word = 0_u32;
    // SAFETY: the process handle is open; `word` is a live 4-byte buffer, the size of
    // each policy structure read here.
    let read = unsafe {
        GetProcessMitigationPolicy(
            process,
            policy,
            (&mut word as *mut u32).cast(),
            std::mem::size_of::<u32>(),
        )
    };
    if read == 0 {
        return Err(readback_error("mitigation policies"));
    }
    Ok(word)
}

/// The mitigations in effect, from the policy words' flags (winnt.h
/// `PROCESS_MITIGATION_*_POLICY`).
pub(super) fn mitigations_from_words(
    strict_handle: u32,
    extension_point: u32,
    image_load: u32,
) -> BTreeSet<StartMitigation> {
    let mut found = BTreeSet::new();
    // RaiseExceptionOnInvalidHandleReference and HandleExceptionsPermanentlyEnabled.
    if strict_handle & 0b11 == 0b11 {
        found.insert(StartMitigation::StrictHandleChecks);
    }
    // DisableExtensionPoints.
    if extension_point & 0b1 != 0 {
        found.insert(StartMitigation::ExtensionPointDisable);
    }
    // NoRemoteImages, then NoLowMandatoryLabelImages.
    if image_load & 0b01 != 0 {
        found.insert(StartMitigation::ImageLoadNoRemote);
    }
    if image_load & 0b10 != 0 {
        found.insert(StartMitigation::ImageLoadNoLowLabel);
    }
    found
}

fn mitigations_in_effect(process: HANDLE) -> Result<BTreeSet<StartMitigation>, ReadbackError> {
    Ok(mitigations_from_words(
        policy_word(process, ProcessStrictHandleCheckPolicy)?,
        policy_word(process, ProcessExtensionPointDisablePolicy)?,
        policy_word(process, ProcessImageLoadPolicy)?,
    ))
}

/// The command line of the process behind `process`, a handle with at least
/// `PROCESS_QUERY_LIMITED_INFORMATION`, split as `CommandLineToArgvW` splits it: what a host
/// scan of the process list reads of a hypervisor (`sandbox_vm::process_scan`).
pub fn read_command_line(process: HANDLE) -> Result<Vec<String>, ReadbackError> {
    process_command_line(process)
}

/// The process's command line, read through `NtQueryInformationProcess` and split as
/// `CommandLineToArgvW` splits it.
fn process_command_line(process: HANDLE) -> Result<Vec<String>, ReadbackError> {
    let failed = |status: i32| ReadbackError {
        step: "command line",
        os_error: u32::from_ne_bytes(status.to_ne_bytes()),
    };
    let mut needed = 0_u32;
    // SAFETY: a zero-length query writes nothing but the size needed.
    let status = unsafe {
        NtQueryInformationProcess(
            process,
            PROCESS_COMMAND_LINE_INFORMATION,
            null_mut(),
            0,
            &mut needed,
        )
    };
    if status != STATUS_INFO_LENGTH_MISMATCH || needed == 0 || needed > MAX_ANSWER_BYTES {
        return Err(failed(status));
    }
    let mut buffer = vec![0_u64; usize::try_from(needed.div_ceil(8)).map_err(|_| failed(status))?];
    let capacity = u32::try_from(buffer.len() * 8).map_err(|_| failed(status))?;
    let mut written = 0_u32;
    // SAFETY: `buffer` holds `capacity` writable bytes, aligned for the answer.
    let status = unsafe {
        NtQueryInformationProcess(
            process,
            PROCESS_COMMAND_LINE_INFORMATION,
            buffer.as_mut_ptr().cast(),
            capacity,
            &mut written,
        )
    };
    if status < 0 {
        return Err(failed(status));
    }
    // The answer is a UNICODE_STRING (length and maximum length in bytes, then a pointer)
    // whose characters follow it inside the same buffer.
    let base = buffer.as_ptr().cast::<u8>();
    // SAFETY: the buffer holds at least the UNICODE_STRING header.
    let (length, characters) = unsafe {
        let length = usize::from(*base.cast::<u16>());
        let characters = *base.add(8).cast::<*const u16>();
        (length, characters)
    };
    let start = characters as usize;
    let begin = base as usize;
    let end = begin + buffer.len() * 8;
    if length % 2 != 0 || start < begin + 16 || start.saturating_add(length) > end {
        return Err(failed(status));
    }
    // SAFETY: the characters lie inside the buffer, as just checked.
    let mut line: Vec<u16> = unsafe { std::slice::from_raw_parts(characters, length / 2) }.to_vec();
    line.push(0);
    split_command_line(&line).ok_or(ReadbackError {
        step: "command line",
        os_error: 0,
    })
}

/// `line` (NUL-terminated) as `CommandLineToArgvW` splits it.
pub(super) fn split_command_line(line: &[u16]) -> Option<Vec<String>> {
    let mut count = 0_i32;
    // SAFETY: `line` is NUL-terminated; the answer is freed once below.
    let argv = unsafe { CommandLineToArgvW(line.as_ptr(), &mut count) };
    if argv.is_null() {
        return None;
    }
    let count = usize::try_from(count).unwrap_or(0);
    // SAFETY: `argv` holds `count` NUL-terminated wide strings.
    let arguments = (0..count)
        .map(|index| unsafe {
            let argument = *argv.add(index);
            let length = (0..).take_while(|&at| *argument.add(at) != 0).count();
            String::from_utf16_lossy(std::slice::from_raw_parts(argument, length))
        })
        .collect();
    // SAFETY: `argv` came from CommandLineToArgvW.
    unsafe { LocalFree(argv.cast()) };
    Some(arguments)
}

#[cfg(test)]
#[path = "restricted_tests.rs"]
pub(crate) mod tests;
