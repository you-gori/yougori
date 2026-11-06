//! M16D: the management key's identity file, owner-only before any use (VM-W41, M16 (b);
//! docs/combined-gpu-memory-and-vm-sandbox-plan.md, VM part §4.5: the client key is a
//! long-lived credential that stays with the engine).
//!
//! [`protect_identity_file`] restricts the private key file that
//! [`generate_management_key`](super::generate_management_key) had `ssh-keygen` write to
//! its owner, and [`check_identity_file`] reads the protection back and refuses anything
//! else. [`ManagementChannel`](super::ManagementChannel) runs the check before every call.
//! Both refuse a path that is missing or names a link, a directory or anything but a
//! regular file, before anything is set, so neither follows a link.
//!
//! - Windows: the owner becomes the current user (the process token's user) when it is
//!   not already, and the DACL is replaced, with `SetNamedSecurityInfoW`, by a protected
//!   one holding exactly two access-allowed entries without flags: full access for the
//!   current user and for SYSTEM ([`LOCAL_SYSTEM_SID`]). The check reads the owner and the
//!   DACL back with `GetNamedSecurityInfoW` and refuses another owner, no DACL (which
//!   grants everyone everything), a DACL that is not protected (the parent's inheritable
//!   entries would reach the file), an inherited entry, an entry of another type or with
//!   flags, an entry for any other trustee, and a DACL without an entry for the current
//!   user (who could not read the key). Administrators get no entry: Windows OpenSSH
//!   accepts a key file that grants access to the owner, SYSTEM and Administrators only,
//!   and requires no entry besides the owner's (from memory of Win32-OpenSSH's
//!   `check_secure_file_permission`, not checked against a real client), and the plan
//!   requires none.
//! - Unix: mode [`OWNER_ONLY_MODE`] (`0600`) set with `chmod`; the check refuses an owner
//!   other than the effective uid and any other permission bits, as OpenSSH refuses a key
//!   file with group or other bits (`sshkey_perm_ok`). This code is not compiled here (the
//!   harness builds on Windows only); it is kept to a few lines for that reason.
//!
//! The check and the client's later open are not one atomic step, and between
//! `ssh-keygen` creating the file and its protection the file has the permissions the
//! program and the directory gave it: the directory must be one only the engine writes.
//! Nothing here reads the file's contents.

use std::fmt;
use std::io;

use serde::Serialize;

use super::path::SshFilePath;

/// The SID of the LocalSystem account, the one trustee besides the current user.
pub const LOCAL_SYSTEM_SID: &str = "S-1-5-18";

/// The mode of a protected identity file on Unix: read and write for the owner only.
pub const OWNER_ONLY_MODE: u32 = 0o600;

/// The access-allowed entry type (`ACCESS_ALLOWED_ACE_TYPE` in `winnt.h`).
#[cfg(any(windows, test))]
pub(super) const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;

/// The flag of an entry inherited from the parent (`INHERITED_ACE` in `winnt.h`).
#[cfg(any(windows, test))]
pub(super) const INHERITED_ACE_FLAG: u8 = 0x10;

/// Which step of protecting or checking failed in the system.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionStep {
    /// Looking the path up.
    Inspect,
    /// Finding the current user.
    CurrentUser,
    /// Setting the owner and DACL, or the mode.
    Apply,
    /// Reading the owner and DACL, or the mode, back.
    ReadBack,
}

/// Why an identity file is not owner-only, or could not be made so.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum IdentityFileRefusal {
    /// Nothing exists at the path.
    Missing,
    /// The path names a link, a directory or anything but a regular file.
    NotAFile,
    /// The owner is not the current user: a SID string on Windows, a uid on Unix.
    OwnerNotCurrentUser { owner: Option<String> },
    /// Windows: the file has no DACL, which grants everyone full access.
    NoDacl,
    /// Windows: the DACL is not protected, so the parent's inheritable entries reach it.
    DaclNotProtected,
    /// Windows: an entry inherited from the parent.
    InheritedEntry { trustee: Option<String> },
    /// Windows: an entry that is not a plain access-allowed entry without flags.
    UnexpectedEntry { ace_type: u8, flags: u8 },
    /// Windows: an entry for a trustee other than the current user and SYSTEM.
    OtherTrustee { trustee: String },
    /// Windows: no entry lets the current user read the file.
    NoEntryForCurrentUser,
    /// Unix: permission bits other than `0600`.
    ModeNotOwnerOnly { mode: u32 },
    /// This platform has no protection here.
    Unsupported,
    /// A system call failed.
    System { step: ProtectionStep, error: String },
}

impl fmt::Display for IdentityFileRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => f.write_str("the identity file does not exist"),
            Self::NotAFile => f.write_str("the identity file path does not name a regular file"),
            Self::OwnerNotCurrentUser { owner } => write!(
                f,
                "the identity file is owned by {}, not the current user",
                owner.as_deref().unwrap_or("nobody")
            ),
            Self::NoDacl => f.write_str("the identity file has no DACL, so everyone may open it"),
            Self::DaclNotProtected => {
                f.write_str("the identity file's DACL is not protected from inheritance")
            }
            Self::InheritedEntry { .. } => {
                f.write_str("the identity file's DACL holds an inherited entry")
            }
            Self::UnexpectedEntry { ace_type, flags } => write!(
                f,
                "the identity file's DACL holds an entry of type {ace_type} with flags {flags:#x}"
            ),
            Self::OtherTrustee { trustee } => write!(
                f,
                "the identity file grants access to {trustee}, not only the current user and \
                 SYSTEM"
            ),
            Self::NoEntryForCurrentUser => {
                f.write_str("the identity file's DACL has no entry for the current user")
            }
            Self::ModeNotOwnerOnly { mode } => {
                write!(f, "the identity file has mode {mode:o}, not 600")
            }
            Self::Unsupported => f.write_str("identity files cannot be protected on this platform"),
            Self::System { step, error } => {
                write!(f, "identity file protection step {step:?} failed: {error}")
            }
        }
    }
}

impl std::error::Error for IdentityFileRefusal {}

fn system(step: ProtectionStep, error: &io::Error) -> IdentityFileRefusal {
    IdentityFileRefusal::System {
        step,
        error: error.to_string(),
    }
}

/// Refuses a path that is missing or is not a regular file; a link is never followed.
fn regular_file(path: &SshFilePath) -> Result<(), IdentityFileRefusal> {
    match std::fs::symlink_metadata(path.as_path()) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(()),
        Ok(_) => Err(IdentityFileRefusal::NotAFile),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Err(IdentityFileRefusal::Missing),
        Err(error) => Err(system(ProtectionStep::Inspect, &error)),
    }
}

/// Makes the regular file at `path` owner-only (see the module notes), then checks it.
pub fn protect_identity_file(path: &SshFilePath) -> Result<(), IdentityFileRefusal> {
    regular_file(path)?;
    platform::apply(path.as_path())?;
    check_identity_file(path)
}

/// Reads the protection of the file at `path` back and refuses anything but owner-only;
/// see the module notes.
pub fn check_identity_file(path: &SshFilePath) -> Result<(), IdentityFileRefusal> {
    regular_file(path)?;
    platform::check(path.as_path())
}

/// One DACL entry as read back: its type, its flags and, for an access-allowed entry,
/// its trustee's SID string.
#[cfg(any(windows, test))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct AclEntry {
    pub ace_type: u8,
    pub flags: u8,
    pub trustee: Option<String>,
}

/// A DACL as read back.
#[cfg(any(windows, test))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Dacl {
    pub protected: bool,
    pub entries: Vec<AclEntry>,
}

/// A file's owner and DACL as read back, SIDs as strings.
#[cfg(any(windows, test))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SecurityReadBack {
    pub owner: Option<String>,
    pub dacl: Option<Dacl>,
}

/// The Windows rule of the module notes, for the current user's SID string `user`.
#[cfg(any(windows, test))]
pub(super) fn judge_dacl(read: &SecurityReadBack, user: &str) -> Result<(), IdentityFileRefusal> {
    if read.owner.as_deref() != Some(user) {
        return Err(IdentityFileRefusal::OwnerNotCurrentUser {
            owner: read.owner.clone(),
        });
    }
    let dacl = read.dacl.as_ref().ok_or(IdentityFileRefusal::NoDacl)?;
    if !dacl.protected {
        return Err(IdentityFileRefusal::DaclNotProtected);
    }
    let mut user_entry = false;
    for entry in &dacl.entries {
        if entry.flags & INHERITED_ACE_FLAG != 0 {
            return Err(IdentityFileRefusal::InheritedEntry {
                trustee: entry.trustee.clone(),
            });
        }
        let unexpected = IdentityFileRefusal::UnexpectedEntry {
            ace_type: entry.ace_type,
            flags: entry.flags,
        };
        if entry.ace_type != ACCESS_ALLOWED_ACE_TYPE || entry.flags != 0 {
            return Err(unexpected);
        }
        match entry.trustee.as_deref() {
            Some(trustee) if trustee == user => user_entry = true,
            Some(LOCAL_SYSTEM_SID) => {}
            Some(trustee) => {
                return Err(IdentityFileRefusal::OtherTrustee {
                    trustee: trustee.to_owned(),
                })
            }
            None => return Err(unexpected),
        }
    }
    if user_entry {
        Ok(())
    } else {
        Err(IdentityFileRefusal::NoEntryForCurrentUser)
    }
}

/// The Unix rule of the module notes: owned by `current_uid`, permission bits `0600`.
#[cfg(any(unix, test))]
pub(super) fn judge_mode(
    owner_uid: u32,
    mode: u32,
    current_uid: u32,
) -> Result<(), IdentityFileRefusal> {
    if owner_uid != current_uid {
        return Err(IdentityFileRefusal::OwnerNotCurrentUser {
            owner: Some(owner_uid.to_string()),
        });
    }
    let permissions = mode & 0o7777;
    if permissions != OWNER_ONLY_MODE {
        return Err(IdentityFileRefusal::ModeNotOwnerOnly { mode: permissions });
    }
    Ok(())
}

#[cfg(all(test, windows))]
pub(super) use platform::{apply_dacl, read_security, set_null_dacl, OwnedSid};

#[cfg(windows)]
mod platform {
    use std::ffi::c_void;
    use std::mem::{offset_of, size_of};
    use std::os::windows::ffi::OsStrExt as _;
    use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
    use std::path::Path;
    use std::ptr::{null, null_mut};

    use windows_sys::Win32::Foundation::{GetLastError, LocalFree, ERROR_INSUFFICIENT_BUFFER};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, GetNamedSecurityInfoW, SetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        AclSizeInformation, AddAccessAllowedAce, CopySid, CreateWellKnownSid, GetAce,
        GetAclInformation, GetLengthSid, GetSecurityDescriptorControl, GetTokenInformation,
        InitializeAcl, IsValidSid, TokenUser, WinLocalSystemSid, ACCESS_ALLOWED_ACE, ACE_HEADER,
        ACL, ACL_REVISION, ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION,
        OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        PSID, SECURITY_MAX_SID_SIZE, SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER,
        WELL_KNOWN_SID_TYPE,
    };
    use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    use super::{
        judge_dacl, AclEntry, Dacl, IdentityFileRefusal, ProtectionStep, SecurityReadBack,
        ACCESS_ALLOWED_ACE_TYPE,
    };

    /// The last OS error of this thread; read right after the call that failed.
    fn last_error() -> u32 {
        // SAFETY: GetLastError has no preconditions.
        unsafe { GetLastError() }
    }

    fn os_error(step: ProtectionStep, code: u32) -> IdentityFileRefusal {
        IdentityFileRefusal::System {
            step,
            error: std::io::Error::from_raw_os_error(i32::try_from(code).unwrap_or(i32::MAX))
                .to_string(),
        }
    }

    /// The size of `T` as Windows takes it; every structure here is far below `u32::MAX`.
    fn size_u32<T>() -> u32 {
        u32::try_from(size_of::<T>()).unwrap_or(u32::MAX)
    }

    /// `path` as a NUL-terminated wide string, with backslashes as separators.
    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .map(|unit| {
                if unit == u16::from(b'/') {
                    u16::from(b'\\')
                } else {
                    unit
                }
            })
            .chain(Some(0))
            .collect()
    }

    /// Memory a Windows call allocated with `LocalAlloc`, freed when dropped.
    struct LocalMemory(*mut c_void);

    impl Drop for LocalMemory {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: the pointer came from a call that allocates with LocalAlloc and
                // is freed once, here.
                unsafe { LocalFree(self.0) };
            }
        }
    }

    /// The string form (`S-1-...`) of the valid SID at `sid`.
    ///
    /// # Safety
    /// `sid` points to a valid SID that lives for the call.
    unsafe fn sid_text(sid: PSID) -> Result<String, u32> {
        let mut text: *mut u16 = null_mut();
        // SAFETY: `sid` is valid (the caller's promise) and `text` is a live out-pointer.
        if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
            return Err(last_error());
        }
        let _memory = LocalMemory(text.cast());
        let mut length = 0;
        // SAFETY: the call returned a NUL-terminated string, read up to its NUL.
        while unsafe { *text.add(length) } != 0 {
            length += 1;
        }
        // SAFETY: `length` units before the NUL are initialised and live until freed.
        let units = unsafe { std::slice::from_raw_parts(text, length) };
        Ok(String::from_utf16_lossy(units))
    }

    /// A SID copied into memory of its own, aligned as Windows expects.
    pub(in super::super) struct OwnedSid(Vec<u32>);

    impl OwnedSid {
        /// A copy of the valid SID at `sid`.
        ///
        /// # Safety
        /// `sid` points to a valid SID that lives for the call.
        unsafe fn copy(sid: PSID) -> Result<Self, u32> {
            // SAFETY: `sid` is valid (the caller's promise).
            let length = unsafe { GetLengthSid(sid) };
            let words = usize::try_from(length).map_or(0, |bytes| bytes.div_ceil(4));
            let mut buffer = vec![0_u32; words];
            // SAFETY: the buffer holds at least `length` bytes and `sid` is valid.
            if unsafe { CopySid(length, buffer.as_mut_ptr().cast(), sid) } == 0 {
                return Err(last_error());
            }
            Ok(Self(buffer))
        }

        /// The user of this process's token.
        pub(in super::super) fn current_user() -> Result<Self, u32> {
            let mut raw = null_mut();
            // SAFETY: the pseudo-handle of this process needs no closing, and `raw` is a
            // live out-pointer.
            if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
                return Err(last_error());
            }
            // SAFETY: the call has just returned this handle open, owned by nobody else.
            let token = unsafe { OwnedHandle::from_raw_handle(raw) };
            let mut needed = 0;
            // SAFETY: a null buffer of length 0 only asks for the size; the expected failure
            // is ignored, and a size of 0 fails the next call.
            unsafe {
                GetTokenInformation(token.as_raw_handle(), TokenUser, null_mut(), 0, &mut needed)
            };
            let bytes = usize::try_from(needed).unwrap_or(0);
            if bytes < size_of::<TOKEN_USER>() {
                return Err(ERROR_INSUFFICIENT_BUFFER);
            }
            // A buffer of `usize`, so the TOKEN_USER at its start is aligned.
            let mut buffer = vec![0_usize; bytes.div_ceil(size_of::<usize>())];
            // SAFETY: the buffer holds `needed` bytes, aligned for TOKEN_USER.
            let read = unsafe {
                GetTokenInformation(
                    token.as_raw_handle(),
                    TokenUser,
                    buffer.as_mut_ptr().cast(),
                    needed,
                    &mut needed,
                )
            };
            if read == 0 {
                return Err(last_error());
            }
            // SAFETY: the call filled the buffer, at least a TOKEN_USER long, with one.
            let user = unsafe { buffer.as_ptr().cast::<TOKEN_USER>().read() };
            // SAFETY: the SID lies inside `buffer`, which lives past the copy.
            unsafe { Self::copy(user.User.Sid) }
        }

        /// A well-known SID that needs no domain, such as LocalSystem.
        pub(in super::super) fn well_known(kind: WELL_KNOWN_SID_TYPE) -> Result<Self, u32> {
            let mut length = SECURITY_MAX_SID_SIZE;
            let words = usize::try_from(SECURITY_MAX_SID_SIZE).map_or(0, |bytes| bytes.div_ceil(4));
            let mut buffer = vec![0_u32; words];
            // SAFETY: the buffer holds SECURITY_MAX_SID_SIZE bytes, as `length` says, and a
            // null domain is allowed for SIDs outside a domain.
            let created = unsafe {
                CreateWellKnownSid(kind, null_mut(), buffer.as_mut_ptr().cast(), &mut length)
            };
            if created == 0 {
                return Err(last_error());
            }
            Ok(Self(buffer))
        }

        /// The SID for calls that only read it.
        fn as_psid(&self) -> PSID {
            self.0.as_ptr().cast_mut().cast()
        }

        fn length(&self) -> u32 {
            // SAFETY: the buffer holds a valid SID.
            unsafe { GetLengthSid(self.as_psid()) }
        }

        /// The SID's string form.
        pub(in super::super) fn text(&self) -> Result<String, u32> {
            // SAFETY: the buffer holds a valid SID and lives for the call.
            unsafe { sid_text(self.as_psid()) }
        }
    }

    /// Replaces the DACL of the file at `path` with a protected one that grants full access
    /// to each of `trustees`, in order, and makes `owner` its owner when given.
    pub(in super::super) fn apply_dacl(
        path: &Path,
        owner: Option<&OwnedSid>,
        trustees: &[&OwnedSid],
    ) -> Result<(), IdentityFileRefusal> {
        let too_large = || os_error(ProtectionStep::Apply, ERROR_INSUFFICIENT_BUFFER);
        // The header, then per entry its fixed part (without the SID's first word) and SID.
        let entry = size_of::<ACCESS_ALLOWED_ACE>() - size_of::<u32>();
        let size = trustees
            .iter()
            .try_fold(size_of::<ACL>(), |size, sid| {
                size.checked_add(entry)?
                    .checked_add(usize::try_from(sid.length()).ok()?)
            })
            .ok_or_else(too_large)?;
        let size_u32 = u32::try_from(size).map_err(|_| too_large())?;
        let mut buffer = vec![0_u32; size.div_ceil(4)];
        let acl = buffer.as_mut_ptr().cast::<ACL>();
        // SAFETY: the buffer holds `size` bytes, DWORD-aligned.
        if unsafe { InitializeAcl(acl, size_u32, ACL_REVISION) } == 0 {
            return Err(os_error(ProtectionStep::Apply, last_error()));
        }
        for sid in trustees {
            // SAFETY: the ACL was sized for every entry and each SID is valid.
            if unsafe { AddAccessAllowedAce(acl, ACL_REVISION, FILE_ALL_ACCESS, sid.as_psid()) }
                == 0
            {
                return Err(os_error(ProtectionStep::Apply, last_error()));
            }
        }
        let mut information = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
        let owner = match owner {
            Some(owner) => {
                information |= OWNER_SECURITY_INFORMATION;
                owner.as_psid()
            }
            None => null_mut(),
        };
        let path = wide(path);
        // SAFETY: the path is NUL-terminated, the owner is null or a valid SID, the ACL is
        // initialised, and the group and SACL are not set.
        let status = unsafe {
            SetNamedSecurityInfoW(
                path.as_ptr(),
                SE_FILE_OBJECT,
                information,
                owner,
                null_mut(),
                acl,
                null(),
            )
        };
        if status != 0 {
            return Err(os_error(ProtectionStep::Apply, status));
        }
        Ok(())
    }

    /// Gives the file at `path` a null DACL, which grants everyone full access.
    #[cfg(test)]
    pub(in super::super) fn set_null_dacl(path: &Path) -> Result<(), u32> {
        let path = wide(path);
        // SAFETY: the path is NUL-terminated; a null DACL is documented to grant everyone
        // full access.
        let status = unsafe {
            SetNamedSecurityInfoW(
                path.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                null(),
                null(),
            )
        };
        if status == 0 {
            Ok(())
        } else {
            Err(status)
        }
    }

    /// The owner and DACL of the file at `path`.
    pub(in super::super) fn read_security(
        path: &Path,
    ) -> Result<SecurityReadBack, IdentityFileRefusal> {
        let failed = |code| os_error(ProtectionStep::ReadBack, code);
        let path = wide(path);
        let (mut owner, mut dacl): (PSID, *mut ACL) = (null_mut(), null_mut());
        let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: the path is NUL-terminated and every out-pointer is live; the owner and
        // DACL point into the descriptor, which is freed only after the last use below.
        let status = unsafe {
            GetNamedSecurityInfoW(
                path.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut descriptor,
            )
        };
        if status != 0 {
            return Err(failed(status));
        }
        let _descriptor = LocalMemory(descriptor);
        let owner = if owner.is_null() {
            None
        } else {
            // SAFETY: a non-null owner the call returned is a valid SID in the descriptor.
            Some(unsafe { sid_text(owner) }.map_err(failed)?)
        };
        if dacl.is_null() {
            return Ok(SecurityReadBack { owner, dacl: None });
        }
        let (mut control, mut revision) = (0, 0);
        // SAFETY: the descriptor is the one the call returned; both out-pointers are live.
        if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0 {
            return Err(failed(last_error()));
        }
        let mut size = ACL_SIZE_INFORMATION::default();
        // SAFETY: the DACL is valid and `size` is a live structure of the stated size.
        let sized = unsafe {
            GetAclInformation(
                dacl,
                (&mut size as *mut ACL_SIZE_INFORMATION).cast(),
                size_u32::<ACL_SIZE_INFORMATION>(),
                AclSizeInformation,
            )
        };
        if sized == 0 {
            return Err(failed(last_error()));
        }
        let sid_offset = offset_of!(ACCESS_ALLOWED_ACE, SidStart);
        let mut entries = Vec::new();
        for index in 0..size.AceCount {
            let mut ace: *mut c_void = null_mut();
            // SAFETY: the DACL is valid and the index is below its entry count.
            if unsafe { GetAce(dacl, index, &mut ace) } == 0 {
                return Err(failed(last_error()));
            }
            // SAFETY: every entry starts with its header.
            let header = unsafe { ace.cast::<ACE_HEADER>().read_unaligned() };
            // The smallest SID is 8 bytes; an access-allowed entry holds its SID at the end.
            let holds_sid = usize::from(header.AceSize) >= sid_offset + 8;
            let trustee = if header.AceType == ACCESS_ALLOWED_ACE_TYPE && holds_sid {
                // SAFETY: the entry is an access-allowed entry, large enough to hold a SID
                // at this offset.
                let sid: PSID = unsafe { ace.cast::<u8>().add(sid_offset) }.cast();
                // SAFETY: as above; IsValidSid only reads the SID.
                if unsafe { IsValidSid(sid) } == 0 {
                    None
                } else {
                    // SAFETY: the SID is valid and lives in the descriptor.
                    Some(unsafe { sid_text(sid) }.map_err(failed)?)
                }
            } else {
                None
            };
            entries.push(AclEntry {
                ace_type: header.AceType,
                flags: header.AceFlags,
                trustee,
            });
        }
        Ok(SecurityReadBack {
            owner,
            dacl: Some(Dacl {
                protected: control & SE_DACL_PROTECTED != 0,
                entries,
            }),
        })
    }

    fn current_user() -> Result<(OwnedSid, String), IdentityFileRefusal> {
        let failed = |code| os_error(ProtectionStep::CurrentUser, code);
        let user = OwnedSid::current_user().map_err(failed)?;
        let text = user.text().map_err(failed)?;
        Ok((user, text))
    }

    pub(super) fn apply(path: &Path) -> Result<(), IdentityFileRefusal> {
        let (user, user_text) = current_user()?;
        let system = OwnedSid::well_known(WinLocalSystemSid)
            .map_err(|code| os_error(ProtectionStep::Apply, code))?;
        // Taking ownership needs a right the owner may lack, so only when needed.
        let owned = read_security(path)?.owner.as_deref() == Some(user_text.as_str());
        apply_dacl(path, (!owned).then_some(&user), &[&user, &system])
    }

    pub(super) fn check(path: &Path) -> Result<(), IdentityFileRefusal> {
        let (_, user) = current_user()?;
        judge_dacl(&read_security(path)?, &user)
    }
}

#[cfg(unix)]
mod platform {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::path::Path;

    use super::{judge_mode, system, IdentityFileRefusal, ProtectionStep, OWNER_ONLY_MODE};

    pub(super) fn apply(path: &Path) -> Result<(), IdentityFileRefusal> {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(OWNER_ONLY_MODE))
            .map_err(|error| system(ProtectionStep::Apply, &error))
    }

    pub(super) fn check(path: &Path) -> Result<(), IdentityFileRefusal> {
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|error| system(ProtectionStep::ReadBack, &error))?;
        // SAFETY: geteuid has no preconditions and cannot fail.
        let current = unsafe { libc::geteuid() };
        judge_mode(metadata.uid(), metadata.mode(), current)
    }
}

#[cfg(not(any(windows, unix)))]
mod platform {
    use std::path::Path;

    use super::IdentityFileRefusal;

    pub(super) fn apply(_path: &Path) -> Result<(), IdentityFileRefusal> {
        Err(IdentityFileRefusal::Unsupported)
    }

    pub(super) fn check(_path: &Path) -> Result<(), IdentityFileRefusal> {
        Err(IdentityFileRefusal::Unsupported)
    }
}
