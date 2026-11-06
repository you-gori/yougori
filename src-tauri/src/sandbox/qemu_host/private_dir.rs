//! The launch's private directory on Windows, as the host process port creates, secures
//! and removes it (M02, M04; docs/combined-gpu-memory-and-vm-sandbox-plan.md: VM-W19 row,
//! line 2618; §7.3 lines 2378–2380; VM-CP-03, line 3153: the QMP socket in a private
//! directory).
//!
//! The restricted QEMU runs at low integrity under a restricted token whose second access
//! check runs against its restricting SIDs alone (Users, `RESTRICTED`, the logon session).
//! So the directory grants exactly this, as a security descriptor given at creation, so
//! the directory never exists with another one:
//!
//! - **The host's user** (the user SID of the host's own token): full access, inherited by
//!   everything created in the directory. The restricted QEMU passes the first access
//!   check through this entry too, since its token keeps the user SID enabled.
//! - **The logon session's SID**, the narrowest of the restricting SIDs: on the directory
//!   itself only (not inherited), [`DIRECTORY_RESTRICTED_ACCESS`]: `FILE_ADD_FILE`, so QEMU
//!   may create its two sockets `qmp.sock` and `link.sock`, `FILE_TRAVERSE` and
//!   `SYNCHRONIZE`, so it may hold the directory as its working directory. Not granted:
//!   listing, reading or writing attributes, deleting children, adding subdirectories,
//!   changing the DACL.
//! - **The bootstrap file**: after the host wrote it, its DACL is replaced by a protected
//!   one ([`restrict_bootstrap_file`]): the user full access and the logon session's SID
//!   [`BOOTSTRAP_RESTRICTED_ACCESS`] (`FILE_GENERIC_READ`), the read QEMU's `-fw_cfg file=`
//!   needs. No other file in the directory grants a restricting SID anything: the log file
//!   and the sockets carry only the user's inherited entry.
//! - The DACL is protected, so nothing of the parent's is inherited; no other SID (not
//!   SYSTEM, not Administrators, not Users) has an entry.
//! - **A low mandatory label** (`S:(ML;;NW;;;LW)`, no write up) on the directory itself,
//!   so the low-integrity process may add its sockets there. It is not inherited: the
//!   files the host creates there keep the default medium label, which a low process may
//!   read but not write; the sockets QEMU creates take its own low label.
//!
//! Every low-integrity process of the same user passes the user's entry and the low label
//! as the restricted QEMU does; the restricting-SID entries narrow only the restricted
//! QEMU. That is a limit of a user-SID DACL with a low label, stated rather than hidden.
//!
//! The SIDs are read from the host's own token with query access ([`HostSids::current`]);
//! no token is created, changed or restricted here.

use std::fmt;
use std::fs::OpenOptions;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::ptr::{null, null_mut};
use std::time::Duration;

use serde::Serialize;
use windows_sys::Win32::Foundation::{
    GetLastError, LocalFree, ERROR_ALREADY_EXISTS, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, HANDLE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW, SetSecurityInfo,
    SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    GetSecurityDescriptorDacl, GetTokenInformation, TokenGroups, TokenUser, ACL,
    DACL_SECURITY_INFORMATION, LABEL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, TOKEN_GROUPS, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, FILE_ADD_FILE, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_GENERIC_READ, FILE_TRAVERSE, READ_CONTROL, SYNCHRONIZE, WRITE_DAC,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use super::acl::LogonSid;

/// What the logon session's SID may do on the private directory itself.
pub const DIRECTORY_RESTRICTED_ACCESS: u32 = FILE_ADD_FILE | FILE_TRAVERSE | SYNCHRONIZE;
/// What the logon session's SID may do on the bootstrap file.
pub const BOOTSTRAP_RESTRICTED_ACCESS: u32 = FILE_GENERIC_READ;
/// The name of QEMU's standard error log in the private directory.
pub const STDERR_LOG_NAME: &str = "qemu-stderr.log";

/// `SE_GROUP_LOGON_ID` (winnt.h); `Win32_System_SystemServices` is not enabled.
const SE_GROUP_LOGON_ID: u32 = 0xC000_0000;
/// The largest token answer read here.
const MAX_TOKEN_ANSWER_BYTES: u32 = 64 * 1024;
/// How many times a removal is tried, and the pause between tries: a file a scanner holds
/// for a moment after the process ended is not a lasting failure.
const REMOVE_TRIES: u32 = 20;
const REMOVE_PAUSE: Duration = Duration::from_millis(50);

/// Why the private directory or its bootstrap file could not be prepared, read or
/// removed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum DirectoryError {
    /// The host's own token could not be read.
    Token { step: &'static str, os_error: u32 },
    /// The path already exists; it was not touched.
    Exists { path: String },
    /// The directory could not be created.
    Create { path: String, os_error: u32 },
    /// A security descriptor could not be built, read or applied.
    Security { step: &'static str, os_error: u32 },
    /// The bootstrap file is not the regular file the host wrote.
    NotRegularFile { path: String },
    /// A file could not be opened.
    Open { path: String, detail: String },
    /// The directory could not be removed.
    Remove { path: String, detail: String },
}

impl fmt::Display for DirectoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Token { step, os_error } => {
                write!(
                    f,
                    "could not read the host's token {step} (OS error {os_error})"
                )
            }
            Self::Exists { path } => {
                write!(
                    f,
                    "the private directory {path} already exists; it was not touched"
                )
            }
            Self::Create { path, os_error } => write!(
                f,
                "could not create the private directory {path} (OS error {os_error})"
            ),
            Self::Security { step, os_error } => {
                write!(f, "could not {step} (OS error {os_error})")
            }
            Self::NotRegularFile { path } => {
                write!(f, "{path} is not the regular file the host wrote")
            }
            Self::Open { path, detail } => write!(f, "could not open {path}: {detail}"),
            Self::Remove { path, detail } => {
                write!(f, "could not remove the private directory {path}: {detail}")
            }
        }
    }
}

impl std::error::Error for DirectoryError {}

fn last_error() -> u32 {
    // SAFETY: GetLastError has no preconditions.
    unsafe { GetLastError() }
}

/// A buffer `LocalAlloc` returned to this caller, freed once when dropped.
struct LocalBuffer(*mut core::ffi::c_void);

impl Drop for LocalBuffer {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the buffer came from LocalAlloc inside a call made for this caller and
            // is freed once, here.
            unsafe { LocalFree(self.0) };
        }
    }
}

/// The SIDs the private directory names, as SDDL text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostSids {
    user: String,
    logon: LogonSid,
}

impl HostSids {
    /// The user and logon session SIDs of the host's own token, read with query access.
    pub fn current() -> Result<Self, DirectoryError> {
        let mut raw: HANDLE = null_mut();
        // SAFETY: the pseudo-handle of this process is always valid; `raw` is live.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
            return Err(DirectoryError::Token {
                step: "for query",
                os_error: last_error(),
            });
        }
        // SAFETY: the call succeeded, so `raw` is an open token handle owned by nobody else.
        let token = unsafe { OwnedHandle::from_raw_handle(raw) };
        let user_answer = token_answer(token.as_raw_handle(), TokenUser, "user")?;
        let user = user_answer.as_ptr().cast::<TOKEN_USER>();
        // SAFETY: the buffer holds the TokenUser answer, whose SID points inside it.
        let user = sid_text(unsafe { (*user).User.Sid }, "user")?;
        let groups_answer = token_answer(token.as_raw_handle(), TokenGroups, "groups")?;
        let groups = groups_answer.as_ptr().cast::<TOKEN_GROUPS>();
        // SAFETY: the answer starts with a TOKEN_GROUPS whose array holds `GroupCount`
        // entries inside the same buffer.
        let entries = unsafe {
            let count = usize::try_from((*groups).GroupCount).unwrap_or(0);
            std::slice::from_raw_parts((*groups).Groups.as_ptr(), count)
        };
        let logon = entries
            .iter()
            .find(|group| group.Attributes & SE_GROUP_LOGON_ID == SE_GROUP_LOGON_ID)
            .ok_or(DirectoryError::Token {
                step: "logon session SID",
                os_error: 0,
            })?;
        let logon = sid_text(logon.Sid, "logon session SID")?;
        Self::new(user, &logon)
    }

    /// The SIDs from their text: `user` is `S-1-` and digits and hyphens, `logon` a logon
    /// session SID `S-1-5-5-X-Y`.
    pub fn new(user: String, logon: &str) -> Result<Self, DirectoryError> {
        let user_valid = user.strip_prefix("S-1-").is_some_and(|rest| {
            !rest.is_empty()
                && rest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || byte == b'-')
        });
        if !user_valid {
            return Err(DirectoryError::Token {
                step: "user SID text",
                os_error: 0,
            });
        }
        let logon = LogonSid::parse(logon).map_err(|_| DirectoryError::Token {
            step: "logon session SID text",
            os_error: 0,
        })?;
        Ok(Self { user, logon })
    }

    /// The user SID, `S-1-...`.
    pub fn user(&self) -> &str {
        &self.user
    }

    /// The logon session's SID.
    pub fn logon(&self) -> &LogonSid {
        &self.logon
    }
}

/// One token information class, read into an aligned buffer.
fn token_answer(
    token: HANDLE,
    class: windows_sys::Win32::Security::TOKEN_INFORMATION_CLASS,
    step: &'static str,
) -> Result<Vec<u64>, DirectoryError> {
    let failed = || DirectoryError::Token {
        step,
        os_error: last_error(),
    };
    let mut needed = 0_u32;
    // SAFETY: a null buffer of length zero asks only for the size.
    let sized = unsafe { GetTokenInformation(token, class, null_mut(), 0, &mut needed) };
    if (sized == 0 && last_error() != ERROR_INSUFFICIENT_BUFFER)
        || needed == 0
        || needed > MAX_TOKEN_ANSWER_BYTES
    {
        return Err(failed());
    }
    let mut buffer = vec![0_u64; usize::try_from(needed.div_ceil(8)).map_err(|_| failed())?];
    // SAFETY: `buffer` holds at least `needed` writable bytes, aligned for the answer.
    let read = unsafe {
        GetTokenInformation(
            token,
            class,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    };
    if read == 0 {
        return Err(failed());
    }
    Ok(buffer)
}

/// A SID's string form.
fn sid_text(sid: PSID, step: &'static str) -> Result<String, DirectoryError> {
    let mut text: *mut u16 = null_mut();
    // SAFETY: the SID is valid; `text` receives a LocalAlloc'd string.
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 || text.is_null() {
        return Err(DirectoryError::Token {
            step,
            os_error: last_error(),
        });
    }
    let owned = LocalBuffer(text.cast());
    // SAFETY: `text` is a NUL-terminated wide string, freed by `owned` after the copy.
    let string = unsafe { wide_string(text) };
    drop(owned);
    Ok(string)
}

/// A NUL-terminated wide string's text.
///
/// # Safety
/// `text` points to a NUL-terminated UTF-16 string.
unsafe fn wide_string(text: *const u16) -> String {
    // SAFETY: the caller's string is NUL-terminated, so every index below its terminator
    // is readable.
    unsafe {
        let length = (0..).take_while(|&at| *text.add(at) != 0).count();
        String::from_utf16_lossy(std::slice::from_raw_parts(text, length))
    }
}

fn wide_path(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    path.as_os_str().encode_wide().chain([0]).collect()
}

/// The private directory's security descriptor, in SDDL (see the module notes). `PAI`:
/// the DACL is protected, and marked auto-inherited so the entries files inherit from it are
/// marked inherited.
pub fn directory_sddl(sids: &HostSids) -> String {
    format!(
        "D:PAI(A;OICI;FA;;;{user})(A;;{access:#x};;;{logon})S:(ML;;NW;;;LW)",
        user = sids.user,
        access = DIRECTORY_RESTRICTED_ACCESS,
        logon = sids.logon.as_str(),
    )
}

/// The bootstrap file's DACL, in SDDL (see the module notes).
pub fn bootstrap_sddl(sids: &HostSids) -> String {
    format!(
        "D:PAI(A;;FA;;;{user})(A;;{access:#x};;;{logon})",
        user = sids.user,
        access = BOOTSTRAP_RESTRICTED_ACCESS,
        logon = sids.logon.as_str(),
    )
}

/// A security descriptor parsed from SDDL, freed when dropped.
struct Descriptor(LocalBuffer);

impl Descriptor {
    fn parse(sddl: &str) -> Result<Self, DirectoryError> {
        let wide: Vec<u16> = sddl.encode_utf16().chain([0]).collect();
        let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: the string is NUL-terminated; `descriptor` receives a LocalAlloc'd
        // descriptor, freed by the returned value; the size is not asked for.
        let parsed = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        };
        if parsed == 0 || descriptor.is_null() {
            return Err(DirectoryError::Security {
                step: "build the security descriptor",
                os_error: last_error(),
            });
        }
        Ok(Self(LocalBuffer(descriptor)))
    }

    fn as_ptr(&self) -> PSECURITY_DESCRIPTOR {
        self.0 .0
    }

    /// The descriptor's DACL; it lives as long as the descriptor.
    fn dacl(&self) -> Result<*mut ACL, DirectoryError> {
        let mut present = 0;
        let mut defaulted = 0;
        let mut dacl: *mut ACL = null_mut();
        // SAFETY: the descriptor is valid and live; every out-pointer is live.
        let read = unsafe {
            GetSecurityDescriptorDacl(self.as_ptr(), &mut present, &mut dacl, &mut defaulted)
        };
        if read == 0 || present == 0 || dacl.is_null() {
            return Err(DirectoryError::Security {
                step: "read the descriptor's DACL",
                os_error: last_error(),
            });
        }
        Ok(dacl)
    }
}

/// Creates `path` as a new directory with the private directory's security descriptor
/// (see the module notes). An existing path of any kind, a link or junction included, is
/// refused with [`DirectoryError::Exists`] and left as it is.
pub fn create_private_directory(path: &Path, sids: &HostSids) -> Result<(), DirectoryError> {
    let descriptor = Descriptor::parse(&directory_sddl(sids))?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).map_err(|_| {
            DirectoryError::Security {
                step: "size the security attributes",
                os_error: 0,
            }
        })?,
        lpSecurityDescriptor: descriptor.as_ptr(),
        bInheritHandle: 0,
    };
    let wide = wide_path(path);
    // SAFETY: the path is NUL-terminated; the attributes and the descriptor they point at
    // are live for the call.
    if unsafe { CreateDirectoryW(wide.as_ptr(), &attributes) } == 0 {
        let os_error = last_error();
        let path = path.display().to_string();
        return Err(if os_error == ERROR_ALREADY_EXISTS {
            DirectoryError::Exists { path }
        } else {
            DirectoryError::Create { path, os_error }
        });
    }
    Ok(())
}

/// Replaces the DACL of the bootstrap file at `path`, which the host has just written,
/// with the protected one of [`bootstrap_sddl`]. The file is opened without following a
/// reparse point and must be a regular file.
pub fn restrict_bootstrap_file(path: &Path, sids: &HostSids) -> Result<(), DirectoryError> {
    let file = OpenOptions::new()
        .access_mode(READ_CONTROL | WRITE_DAC)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|error| DirectoryError::Open {
            path: path.display().to_string(),
            detail: error.to_string(),
        })?;
    let metadata = file.metadata().map_err(|error| DirectoryError::Open {
        path: path.display().to_string(),
        detail: error.to_string(),
    })?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(DirectoryError::NotRegularFile {
            path: path.display().to_string(),
        });
    }
    let descriptor = Descriptor::parse(&bootstrap_sddl(sids))?;
    let dacl = descriptor.dacl()?;
    // SAFETY: the file handle is open with WRITE_DAC; the DACL lives inside the descriptor,
    // which is live for the call; no owner, group or SACL is set.
    let set = unsafe {
        SetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            dacl,
            null(),
        )
    };
    if set != ERROR_SUCCESS {
        return Err(DirectoryError::Security {
            step: "set the bootstrap file's DACL",
            os_error: set,
        });
    }
    Ok(())
}

/// The DACL and mandatory label of `path`, in SDDL, as the host reads them back.
pub fn read_sddl(path: &Path) -> Result<String, DirectoryError> {
    let wide = wide_path(path);
    let information = DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION;
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: the path is NUL-terminated; only the descriptor is asked for, which the call
    // allocates and the guard below frees.
    let code = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            information,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        )
    };
    if code != ERROR_SUCCESS {
        return Err(DirectoryError::Security {
            step: "read the security descriptor",
            os_error: code,
        });
    }
    let descriptor = LocalBuffer(descriptor);
    let mut text: *mut u16 = null_mut();
    // SAFETY: the descriptor is valid; `text` receives a LocalAlloc'd string.
    let converted = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor.0,
            SDDL_REVISION_1,
            information,
            &mut text,
            null_mut(),
        )
    };
    if converted == 0 || text.is_null() {
        return Err(DirectoryError::Security {
            step: "write the security descriptor as SDDL",
            os_error: last_error(),
        });
    }
    let owned = LocalBuffer(text.cast());
    // SAFETY: `text` is a NUL-terminated wide string, freed by `owned` after the copy.
    let string = unsafe { wide_string(text) };
    drop(owned);
    drop(descriptor);
    Ok(string)
}

/// Removes the private directory at `path` and everything in it, trying again for a short
/// while when a file is still held; a path that does not exist is already removed. Links
/// inside are removed, never followed.
pub fn remove_private_directory(path: &Path) -> Result<(), DirectoryError> {
    let mut last = String::new();
    for attempt in 0..REMOVE_TRIES {
        if attempt > 0 {
            std::thread::sleep(REMOVE_PAUSE);
        }
        match std::fs::remove_dir_all(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                last = error.to_string();
                continue;
            }
        }
        // Gone only when the path no longer resolves.
        match std::fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => last = error.to_string(),
            Ok(_) => last = "the directory still exists after its removal".to_owned(),
        }
    }
    Err(DirectoryError::Remove {
        path: path.display().to_string(),
        detail: last,
    })
}
