//! The desktop a restricted process runs on (M02, M04; VM part §7.3 lines 2378–2380).
//!
//! A process at low integrity cannot open the interactive desktop `WinSta0\Default`: its
//! security descriptor grants the logged-on user at medium integrity, and USER32 attaches
//! to a desktop while it initializes. So a program that links USER32, GDI32 or COM, as the
//! pinned QEMU build does, fails with `0xC0000142` (`STATUS_DLL_INIT_FAILED`) before any
//! of its own code runs, and the launch would look like an unexplained QEMU failure.
//! Observed on this host: the pinned `qemu-system-x86_64.exe --version` exits `0xC0000142`
//! under the restricted low-integrity token, and runs once it has the desktop below.
//!
//! [`SandboxDesktop`] is one desktop of its own, on the session's existing window station,
//! created by the host for the process it restricts:
//!
//! - it carries a discretionary ACL granting the host's own user full access and the
//!   launch's restricting SIDs only what a process needs to attach and make its own
//!   windows, without journal record or playback, hooks, enumeration or desktop switching,
//!   so a program on it reaches no window of a program on the interactive desktop;
//! - it is not the interactive desktop, so a program on it draws no window the user sees
//!   and shares no input queue with the user's programs. A desktop is the boundary the
//!   job's UI restrictions complete;
//! - Windows destroys it when the last handle closes and no process is left on it, so
//!   nothing of a launch survives its launcher.
//!
//! The name is per launch, so two launches never share a desktop. Nothing here changes a
//! host setting: a desktop is an object of this logon session, like a job or an event, not
//! a machine configuration.
//!
//! **Why not a window station of its own.** A separate station would also cut the
//! clipboard and the global atom table from the session. `CreateWindowStationW` is refused
//! here with `ERROR_ACCESS_DENIED` for every access mask (probed on this host: a
//! non-elevated interactive session may not create one). The desktop boundary and the
//! job's UI restrictions are what this profile can apply; the clipboard and the global
//! atom table stay shared with the session, recorded as a limit of the Windows profile
//! rather than hidden.
//!
//! `windows-sys` declares these two calls only under a feature this crate does not enable
//! (`Win32_System_StationsAndDesktops`), and the manifest is another owner's file, so they
//! are declared here against `user32`, as `restricted.rs` declares
//! `NtQueryInformationProcess` against `ntdll`.

use std::fmt;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Security::Authorization::{SetSecurityInfo, SE_WINDOW_OBJECT};
use windows_sys::Win32::Security::{
    AddAccessAllowedAce, AddMandatoryAce, InitializeAcl, ACL, ACL_REVISION,
    LABEL_SECURITY_INFORMATION, SECURITY_ATTRIBUTES,
};

use super::handle::ProcessError;
use std::collections::BTreeSet;
use std::os::windows::io::AsRawHandle;

use windows_sys::Win32::Security::{
    WinAuthenticatedUserSid, WinBuiltinAnyPackageSid, WinBuiltinUsersSid, WinRestrictedCodeSid,
    WinWorldSid,
};

use super::restricted::{
    last_error, logon_sid, own_token, user_sid, well_known, LoweredIntegrity, ObjectSecurity,
    RestrictingGroup, Sid,
};

/// `SYSTEM_MANDATORY_LABEL_NO_WRITE_UP` (winnt.h); `windows-sys` does not export it here.
const SYSTEM_MANDATORY_LABEL_NO_WRITE_UP: u32 = 1;

/// `DESKTOP_*` (winuser.h): attach and make windows and menus, nothing else. Deliberately
/// not granted: `DESKTOP_JOURNALRECORD` and `DESKTOP_JOURNALPLAYBACK` (reading or
/// injecting the session's input), `DESKTOP_HOOKCONTROL` (hooking another program's
/// windows), `DESKTOP_ENUMERATE` (listing them) and `DESKTOP_SWITCHDESKTOP` (showing
/// itself to the user).
const DESKTOP_READOBJECTS: u32 = 0x0001;
const DESKTOP_CREATEWINDOW: u32 = 0x0002;
const DESKTOP_CREATEMENU: u32 = 0x0004;
const DESKTOP_WRITEOBJECTS: u32 = 0x0080;

/// `DESKTOP_ALL_ACCESS` (winuser.h), the host's own entry in the ACL.
const DESKTOP_ALL_ACCESS: u32 = 0x0000_01FF;

/// `DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER` (winnt.h): what the creator asks for
/// on the handle it keeps. Setting a mandatory label is an owner's right, so `WRITE_OWNER`
/// is needed to label the desktop; the creator is already its owner, so no privilege is
/// involved and nothing else on the host becomes reachable.
const HANDLE_RIGHTS: u32 = 0x0001_0000 | 0x0002_0000 | 0x0004_0000 | 0x0008_0000;

/// What a restricted process gets on its desktop.
pub(super) const DESKTOP_FOR_SANDBOX: u32 =
    DESKTOP_READOBJECTS | DESKTOP_CREATEWINDOW | DESKTOP_CREATEMENU | DESKTOP_WRITEOBJECTS;

/// The handle type of a desktop.
type HDESK = *mut core::ffi::c_void;

#[link(name = "user32", kind = "raw-dylib")]
extern "system" {
    /// `lpszDevice` and `pDevmode` are null here (the current display device and its
    /// settings), so they are declared as pointers rather than strings.
    fn CreateDesktopW(
        desktop: *const u16,
        device: *const u16,
        mode: *const core::ffi::c_void,
        flags: u32,
        access: u32,
        attributes: *const SECURITY_ATTRIBUTES,
    ) -> HDESK;
    fn CloseDesktop(desktop: HDESK) -> i32;
}

fn desktop_error(what: &str) -> ProcessError {
    ProcessError::Spawn {
        detail: format!(
            "could not {what} for the restricted start (OS error {})",
            last_error()
        ),
    }
}

/// A desktop handle, closed when dropped. Windows destroys the desktop once the last
/// handle closes and no process is left on it.
struct OwnedDesktop(HDESK);

// SAFETY: a desktop handle is a kernel handle of this process, valid on every thread
// (`CloseDesktop` closes it from any thread); the value has no thread-local state. The
// host holds it with the process it started, which another thread may stop.
unsafe impl Send for OwnedDesktop {}

impl Drop for OwnedDesktop {
    fn drop(&mut self) {
        // SAFETY: the handle came from CreateDesktopW and is closed once.
        unsafe { CloseDesktop(self.0) };
    }
}

/// The desktop of one restricted launch (see the module notes).
pub struct SandboxDesktop {
    desktop: OwnedDesktop,
    /// The name, NUL-terminated, for `STARTUPINFOW::lpDesktop`: a bare name is a desktop
    /// on the process's own window station.
    path: Vec<u16>,
    name: String,
}

impl fmt::Debug for SandboxDesktop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SandboxDesktop")
            .field("name", &self.name)
            .finish()
    }
}

impl SandboxDesktop {
    /// The desktop `name` for a restricted start with these restricting groups and this
    /// integrity: the host's own user gets full access, and exactly the SIDs the start's
    /// token is restricted to get [`DESKTOP_FOR_SANDBOX`], read from the host's own token
    /// as the token itself is built, so the desktop and the token cannot disagree.
    pub fn for_start(
        name: &str,
        restricting: &BTreeSet<RestrictingGroup>,
        integrity: LoweredIntegrity,
    ) -> Result<Self, ProcessError> {
        let own = own_token()?;
        let user = user_sid(own.as_raw_handle())?;
        let logon = logon_sid(own.as_raw_handle())?;
        let users = well_known(WinBuiltinUsersSid, "Users")?;
        let everyone = well_known(WinWorldSid, "Everyone")?;
        let restricted = well_known(WinRestrictedCodeSid, "RESTRICTED")?;
        let authenticated = well_known(WinAuthenticatedUserSid, "Authenticated Users")?;
        let sids: Vec<&Sid> = restricting
            .iter()
            .map(|group| match group {
                RestrictingGroup::Users => &users,
                RestrictingGroup::Everyone => &everyone,
                RestrictingGroup::Restricted => &restricted,
                RestrictingGroup::LogonSession => &logon,
                RestrictingGroup::AuthenticatedUsers => &authenticated,
            })
            .collect();
        Self::create_with(name, &user, &sids, integrity, DESKTOP_FOR_SANDBOX)
    }

    pub(super) fn create(
        name: &str,
        owner: &Sid,
        restricting: &[&Sid],
        integrity: LoweredIntegrity,
    ) -> Result<Self, ProcessError> {
        Self::create_with(name, owner, restricting, integrity, DESKTOP_FOR_SANDBOX)
    }

    /// The desktop of the sandbox executor: the owner's, labelled at `integrity`, granting
    /// `ALL APPLICATION PACKAGES` only [`DESKTOP_FOR_SANDBOX`], so the AppContainer relays
    /// the executor starts (which inherit its desktop) can initialize on it as they do on
    /// the interactive desktop, which grants that SID the same way.
    pub fn for_executor(name: &str, integrity: LoweredIntegrity) -> Result<Self, ProcessError> {
        let own = own_token()?;
        let user = user_sid(own.as_raw_handle())?;
        let packages = well_known(WinBuiltinAnyPackageSid, "ALL APPLICATION PACKAGES")?;
        Self::create_with(name, &user, &[&packages], integrity, DESKTOP_FOR_SANDBOX)
    }

    /// Creates the desktop `name` (1–64 letters, digits or hyphens, so it names no path)
    /// on this process's window station, granting `owner` full access and each SID of
    /// `restricting` only [`DESKTOP_FOR_SANDBOX`], labelled at `integrity` so a process at
    /// that level may use it.
    fn create_with(
        name: &str,
        owner: &Sid,
        restricting: &[&Sid],
        integrity: LoweredIntegrity,
        sandbox_access: u32,
    ) -> Result<Self, ProcessError> {
        if name.is_empty()
            || name.len() > 64
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(ProcessError::Spawn {
                detail: "a sandbox desktop is named by 1-64 letters, digits or hyphens".to_owned(),
            });
        }
        let wide: Vec<u16> = name.encode_utf16().chain([0]).collect();
        let mut acl = acl_for(owner, DESKTOP_ALL_ACCESS, restricting, sandbox_access)?;
        let created = {
            let mut security = ObjectSecurity::with_dacl(&mut acl)?;
            let attributes = security.attributes()?;
            // SAFETY: the name is NUL-terminated; the device and display mode are null,
            // which this call takes for the current ones; the attributes and the
            // descriptor and ACL they point at are live for the call.
            unsafe {
                CreateDesktopW(
                    wide.as_ptr(),
                    null(),
                    null(),
                    0,
                    DESKTOP_ALL_ACCESS | HANDLE_RIGHTS,
                    &attributes,
                )
            }
        };
        if created.is_null() {
            return Err(desktop_error("create the sandbox desktop"));
        }
        let desktop = OwnedDesktop(created);
        label(desktop.0, integrity)?;
        Ok(Self {
            desktop,
            path: wide,
            name: name.to_owned(),
        })
    }

    /// The name for `STARTUPINFOW::lpDesktop`.
    pub(super) fn desktop_path(&mut self) -> *mut u16 {
        self.path.as_mut_ptr()
    }

    /// The desktop's name.
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Labels the desktop at `integrity`, so a process at that level may use it.
fn label(handle: HDESK, integrity: LoweredIntegrity) -> Result<(), ProcessError> {
    let label =
        Sid::mandatory_label(integrity).ok_or_else(|| desktop_error("make the label SID"))?;
    let size = 8_u32.saturating_add(8 + label.length());
    let mut buffer = vec![
        0_u32;
        usize::try_from(size.div_ceil(4))
            .map_err(|_| desktop_error("size the label ACL"))?
    ];
    let acl = buffer.as_mut_ptr().cast::<ACL>();
    // SAFETY: `buffer` holds `size` writable bytes, aligned for an ACL; the SID is valid.
    let built = unsafe {
        InitializeAcl(acl, size, ACL_REVISION) != 0
            && AddMandatoryAce(
                acl,
                ACL_REVISION,
                0,
                SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
                label.as_psid(),
            ) != 0
    };
    if !built {
        return Err(desktop_error("build the label ACL"));
    }
    // SAFETY: the handle is open with WRITE_OWNER; the ACL is live for the call.
    let set = unsafe {
        SetSecurityInfo(
            handle,
            SE_WINDOW_OBJECT,
            LABEL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            null(),
            acl,
        )
    };
    if set != 0 {
        return Err(ProcessError::Spawn {
            detail: format!("could not label the sandbox desktop (error {set})"),
        });
    }
    Ok(())
}

/// An ACL granting `owner` `owner_access` and each of `restricting` `sandbox_access`.
fn acl_for(
    owner: &Sid,
    owner_access: u32,
    restricting: &[&Sid],
    sandbox_access: u32,
) -> Result<Vec<u32>, ProcessError> {
    let mut entries: Vec<(&Sid, u32)> = vec![(owner, owner_access)];
    entries.extend(restricting.iter().map(|sid| (*sid, sandbox_access)));
    let size = entries.iter().fold(8_u32, |size, (sid, _)| {
        size.saturating_add(8 + sid.length())
    });
    let mut buffer = vec![
        0_u32;
        usize::try_from(size.div_ceil(4))
            .map_err(|_| desktop_error("size the desktop's ACL"))?
    ];
    let acl = buffer.as_mut_ptr().cast::<ACL>();
    // SAFETY: `buffer` holds `size` writable bytes, aligned for an ACL.
    if unsafe { InitializeAcl(acl, size, ACL_REVISION) } == 0 {
        return Err(desktop_error("initialize the desktop's ACL"));
    }
    for (sid, access) in entries {
        // SAFETY: the ACL is initialized with room for every entry; each SID is valid.
        if unsafe { AddAccessAllowedAce(acl, ACL_REVISION, access, sid.as_psid()) } == 0 {
            return Err(desktop_error("add an entry to the desktop's ACL"));
        }
    }
    Ok(buffer)
}

#[cfg(test)]
#[path = "station_tests.rs"]
mod tests;
