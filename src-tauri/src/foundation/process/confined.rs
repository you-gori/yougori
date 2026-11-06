//! A confined start on Windows (M09E; VM part §3.1: the guest relay is its own confined
//! process with no provider secret, no host path and no lifecycle privilege; VM-W11;
//! VM-R17: close inherited handles at every subprocess boundary).
//!
//! `std::process::Command` cannot pass process attributes on stable Rust, so a confined
//! process is created here with `CreateProcessW` and an extended start-up list whose one
//! attribute, `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES`, names the AppContainer with no
//! capability SIDs: the process runs at low integrity, with no network and no access to
//! the user's files.
//!
//! It inherits no handle at all (`bInheritHandles` is false), and its standard input,
//! output and error are null. So no handle of this process is ever made inheritable for
//! it, and no other start, such as `std::process::Command::spawn` on another thread with
//! its own inheritance, can catch one meanwhile. A confined process talks to its parent
//! only through objects it opens itself under its AppContainer's access checks, such as a
//! named pipe whose DACL grants its AppContainer SID.
//!
//! Its environment is exactly the variables the command sets, nothing of this process's:
//! no `PATH`, `TEMP` or `SystemRoot` unless the command sets them, so the program must not
//! need them. Windows refuses to start an AppContainer process whose environment lacks
//! `LOCALAPPDATA` (`ERROR_ENVVAR_NOT_FOUND`) and derives the container's own folders from
//! it (and sets `TEMP` and `TMP` below it), so the command must set that variable; it need
//! not be a real path. The process is created suspended and without a window; the caller
//! contains it in its job and resumes it exactly as for an ordinary start.

use std::ffi::OsStr;
use std::fmt;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{FromRawHandle, OwnedHandle};
use std::path::Path;
use std::process::Command;
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{GetLastError, ERROR_INSUFFICIENT_BUFFER, HANDLE};
use windows_sys::Win32::Security::{
    GetLengthSid, GetSidIdentifierAuthority, GetSidSubAuthority, GetSidSubAuthorityCount,
    IsValidSid, PSID, SECURITY_CAPABILITIES,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, InitializeProcThreadAttributeList,
    UpdateProcThreadAttribute, CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
    EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION,
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, STARTF_USESTDHANDLES, STARTUPINFOEXW,
};

use super::handle::ProcessError;

/// The largest SID Windows writes (`SECURITY_MAX_SID_SIZE`).
const MAX_SID_BYTES: usize = 68;

/// The smallest SID: revision, count and authority, with no sub-authority.
const MIN_SID_BYTES: usize = 8;

/// `SECURITY_APP_PACKAGE_AUTHORITY` (winnt.h): the identifier authority of AppContainer
/// and capability SIDs, `S-1-15`, as its six big-endian bytes.
const APP_PACKAGE_AUTHORITY: [u8; 6] = [0, 0, 0, 0, 0, 15];

/// `SECURITY_APP_PACKAGE_BASE_RID` (winnt.h): the first sub-authority of an AppContainer
/// SID, `S-1-15-2-...` (a capability SID has 3).
const APP_PACKAGE_BASE_RID: u32 = 2;

/// The one attribute of a confined start: the AppContainer.
const ATTRIBUTE_COUNT: u32 = 1;

/// How a process the host starts is confined beyond its job, on Windows (see the module
/// notes): the AppContainer it runs in, with no capabilities and no inherited handle.
pub struct Confinement {
    /// The AppContainer's SID, in a buffer aligned for a SID.
    container: Vec<u32>,
}

impl fmt::Debug for Confinement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Confinement").finish_non_exhaustive()
    }
}

impl Confinement {
    /// Confinement in the AppContainer whose SID is `container`, in its binary form (as
    /// `CopySid` writes it), with no capability SIDs. Refused for anything that is not one
    /// valid SID of exactly that length, and for a valid SID that is not an AppContainer
    /// SID (`S-1-15-2-...`).
    pub fn app_container(container: &[u8]) -> Result<Self, ProcessError> {
        let refused = |what: &str| ProcessError::Spawn {
            detail: format!("the confinement SID {what}"),
        };
        if !(MIN_SID_BYTES..=MAX_SID_BYTES).contains(&container.len()) {
            return Err(refused("is not a valid SID"));
        }
        let mut buffer = vec![0_u32; container.len().div_ceil(4)];
        // SAFETY: `buffer` holds at least `container.len()` writable bytes and does not
        // overlap `container`.
        unsafe {
            std::ptr::copy_nonoverlapping(
                container.as_ptr(),
                buffer.as_mut_ptr().cast::<u8>(),
                container.len(),
            );
        }
        let sid: PSID = buffer.as_mut_ptr().cast();
        // SAFETY: `sid` points to `buffer`, which holds the whole candidate SID; IsValidSid
        // and GetLengthSid read only its eight-byte header, which the buffer holds, and the
        // length they find is compared with the bytes given.
        let valid = unsafe {
            IsValidSid(sid) != 0 && usize::try_from(GetLengthSid(sid)).ok() == Some(container.len())
        };
        if !valid {
            return Err(refused("is not a valid SID"));
        }
        // SAFETY: the SID is valid and the buffer holds all of it, every sub-authority its
        // count declares included; sub-authority 0 is read only when there is one.
        let app_container = unsafe {
            (*GetSidIdentifierAuthority(sid)).Value == APP_PACKAGE_AUTHORITY
                && *GetSidSubAuthorityCount(sid) >= 1
                && *GetSidSubAuthority(sid, 0) == APP_PACKAGE_BASE_RID
        };
        if !app_container {
            return Err(refused("is not an AppContainer SID"));
        }
        Ok(Self { container: buffer })
    }

    fn sid(&self) -> PSID {
        self.container.as_ptr().cast_mut().cast()
    }
}

fn spawn_error(what: &str) -> ProcessError {
    // SAFETY: GetLastError has no preconditions.
    let os_error = unsafe { GetLastError() };
    ProcessError::Spawn {
        detail: format!("could not {what} (OS error {os_error})"),
    }
}

/// Takes ownership of a handle a Windows call returned, `None` for null.
fn owned(raw: HANDLE) -> Option<OwnedHandle> {
    // SAFETY: a non-null handle a call has just returned is open and owned by nobody else.
    (!raw.is_null()).then(|| unsafe { OwnedHandle::from_raw_handle(raw) })
}

pub(super) fn wide(text: &OsStr) -> Result<Vec<u16>, ProcessError> {
    let wide: Vec<u16> = text.encode_wide().collect();
    if wide.contains(&0) {
        return Err(ProcessError::Spawn {
            detail: "a confined command holds a NUL character".to_owned(),
        });
    }
    Ok(wide)
}

/// Appends `argument` to `line` as `CommandLineToArgvW` reads it back: quoted when it is
/// empty or holds a space, a tab or a quote, with the backslashes before a quote doubled.
fn push_argument(line: &mut Vec<u16>, argument: &[u16]) {
    let quote = u16::from(b'"');
    let backslash = u16::from(b'\\');
    let needs_quotes = argument.is_empty()
        || argument
            .iter()
            .any(|&unit| unit == u16::from(b' ') || unit == u16::from(b'\t') || unit == quote);
    if !needs_quotes {
        line.extend_from_slice(argument);
        return;
    }
    line.push(quote);
    let mut backslashes = 0_usize;
    for &unit in argument {
        if unit == backslash {
            backslashes += 1;
            continue;
        }
        let repeat = if unit == quote {
            backslashes * 2 + 1
        } else {
            backslashes
        };
        line.extend(std::iter::repeat_n(backslash, repeat));
        backslashes = 0;
        line.push(unit);
    }
    line.extend(std::iter::repeat_n(backslash, backslashes * 2));
    line.push(quote);
}

/// The command line: the program quoted whole (a path holds no quote, and the first
/// token is read without backslash rules), then each argument.
pub(super) fn command_line(command: &Command) -> Result<Vec<u16>, ProcessError> {
    let quote = u16::from(b'"');
    let program = wide(command.get_program())?;
    if program.contains(&quote) {
        return Err(ProcessError::Spawn {
            detail: "a confined program path holds a quote".to_owned(),
        });
    }
    let mut line = vec![quote];
    line.extend_from_slice(&program);
    line.push(quote);
    for argument in command.get_args() {
        line.push(u16::from(b' '));
        push_argument(&mut line, &wide(argument)?);
    }
    line.push(0);
    Ok(line)
}

/// The environment block: only the variables the command sets, sorted by name ignoring
/// case, each `NAME=VALUE` and NUL, then a final NUL.
pub(super) fn environment(command: &Command) -> Result<Vec<u16>, ProcessError> {
    let mut variables = Vec::new();
    for (name, value) in command.get_envs() {
        if let Some(value) = value {
            let name = wide(name)?;
            if name.is_empty() || name.contains(&u16::from(b'=')) {
                return Err(ProcessError::Spawn {
                    detail: "a confined environment variable has an invalid name".to_owned(),
                });
            }
            variables.push((name, wide(value)?));
        }
    }
    variables.sort_by_key(|(name, _)| String::from_utf16_lossy(name).to_uppercase());
    let mut block = Vec::new();
    for (name, value) in variables {
        block.extend_from_slice(&name);
        block.push(u16::from(b'='));
        block.extend_from_slice(&value);
        block.push(0);
    }
    if block.is_empty() {
        block.push(0);
    }
    block.push(0);
    Ok(block)
}

/// An initialized process attribute list, deleted when dropped.
pub(super) struct AttributeList {
    /// Aligned for the list, which Windows treats as opaque.
    buffer: Vec<usize>,
}

impl AttributeList {
    pub(super) fn new(count: u32) -> Result<Self, ProcessError> {
        let mut size = 0_usize;
        // SAFETY: a null list with a size pointer asks only for the size needed.
        let sized = unsafe { InitializeProcThreadAttributeList(null_mut(), count, 0, &mut size) };
        // SAFETY: GetLastError has no preconditions.
        if sized == 0 && unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
            return Err(spawn_error("size the process attributes"));
        }
        let mut buffer = vec![0_usize; size.div_ceil(std::mem::size_of::<usize>()).max(1)];
        let mut capacity = buffer.len() * std::mem::size_of::<usize>();
        // SAFETY: `buffer` holds `capacity` writable bytes, aligned for the list.
        let initialized = unsafe {
            InitializeProcThreadAttributeList(buffer.as_mut_ptr().cast(), count, 0, &mut capacity)
        };
        if initialized == 0 {
            return Err(spawn_error("initialize the process attributes"));
        }
        Ok(Self { buffer })
    }

    pub(super) fn as_ptr(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.buffer.as_mut_ptr().cast()
    }

    /// Sets `attribute` to the `size` bytes at `value`, which must outlive the list's use.
    ///
    /// # Safety
    /// `value` points to `size` readable bytes that stay live and unmoved until the
    /// process is created.
    pub(super) unsafe fn set(
        &mut self,
        attribute: u32,
        value: *const core::ffi::c_void,
        size: usize,
    ) -> Result<(), ProcessError> {
        let attribute =
            usize::try_from(attribute).map_err(|_| spawn_error("name a process attribute"))?;
        // SAFETY: the list is initialized; the caller keeps `value` live (see above).
        let set = unsafe {
            UpdateProcThreadAttribute(self.as_ptr(), 0, attribute, value, size, null_mut(), null())
        };
        if set == 0 {
            return Err(spawn_error("set a process attribute"));
        }
        Ok(())
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        // SAFETY: the list was initialized by `new` and is deleted once.
        unsafe { DeleteProcThreadAttributeList(self.as_ptr()) };
    }
}

/// Creates `command`'s process suspended under `confinement` (see the module notes) and
/// returns its handle and PID. The program must be an absolute path; the command's
/// standard streams and creation flags are not used, and no handle is inherited.
pub(super) fn create_suspended(
    command: &Command,
    confinement: &Confinement,
) -> Result<(OwnedHandle, u32), ProcessError> {
    if !Path::new(command.get_program()).is_absolute() {
        return Err(ProcessError::Spawn {
            detail: "a confined program is named by an absolute path".to_owned(),
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
    let capabilities = SECURITY_CAPABILITIES {
        AppContainerSid: confinement.sid(),
        Capabilities: null_mut(),
        CapabilityCount: 0,
        Reserved: 0,
    };
    let mut attributes = AttributeList::new(ATTRIBUTE_COUNT)?;
    // SAFETY: `capabilities` lives, unmoved, until after CreateProcessW below; the SID it
    // points to is held by `confinement` for the same time.
    unsafe {
        attributes.set(
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
            (&capabilities as *const SECURITY_CAPABILITIES).cast(),
            std::mem::size_of::<SECURITY_CAPABILITIES>(),
        )?;
    }
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = u32::try_from(std::mem::size_of::<STARTUPINFOEXW>())
        .map_err(|_| spawn_error("size the start-up information"))?;
    // Null standard handles: nothing of this process stands in for them.
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = null_mut();
    startup.StartupInfo.hStdOutput = null_mut();
    startup.StartupInfo.hStdError = null_mut();
    startup.lpAttributeList = attributes.as_ptr();
    let mut information = PROCESS_INFORMATION::default();
    // SAFETY: every string is NUL-terminated and live; the environment block is
    // double-NUL-terminated UTF-16; the attribute list and what it points to are live;
    // `information` is live. No handle is inherited.
    let created = unsafe {
        CreateProcessW(
            application.as_ptr(),
            line.as_mut_ptr(),
            null(),
            null(),
            0,
            CREATE_SUSPENDED
                | CREATE_NO_WINDOW
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
        return Err(spawn_error("create the confined process"));
    }
    drop(owned(information.hThread));
    let process =
        owned(information.hProcess).ok_or_else(|| spawn_error("create the confined process"))?;
    Ok((process, information.dwProcessId))
}

#[cfg(test)]
#[path = "confined_tests.rs"]
mod tests;
