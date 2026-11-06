//! The Win32 calls under the named-pipe adapter (M09C; VM part §3.1; VM-W11): the
//! current user's SID, a protected owner-only DACL and bounded overlapped I/O.
//!
//! Every overlapped operation completes before its function returns: it finishes, or it
//! is cancelled and its cancellation is waited for, so no buffer or `OVERLAPPED` is left
//! to the kernel after its owner is gone.

use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr::{null, null_mut};
use std::time::Duration;

use windows_sys::core::BOOL;
use windows_sys::Win32::Foundation::{
    GetLastError, ERROR_INSUFFICIENT_BUFFER, ERROR_IO_PENDING, GENERIC_ALL, HANDLE, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::{
    AddAccessAllowedAce, GetLengthSid, GetTokenInformation, InitializeAcl,
    InitializeSecurityDescriptor, SetSecurityDescriptorControl, SetSecurityDescriptorDacl,
    TokenUser, ACCESS_ALLOWED_ACE, ACL, ACL_REVISION, PSID, SECURITY_ATTRIBUTES,
    SECURITY_DESCRIPTOR, SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, OpenProcessToken, WaitForSingleObject,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

use super::pipe::{PipeCall, PipeError};

/// `SECURITY_DESCRIPTOR_REVISION` (Win32 SystemServices, not enabled here).
const SECURITY_DESCRIPTOR_REVISION: u32 = 1;

/// The longest single wait, in milliseconds: one below `INFINITE`, so every wait is
/// bounded.
const MAX_WAIT_MS: u32 = u32::MAX - 1;

/// The last OS error of this thread; read right after the call that failed.
pub(super) fn last_error() -> u32 {
    // SAFETY: GetLastError has no preconditions.
    unsafe { GetLastError() }
}

pub(super) fn host_error(call: PipeCall) -> PipeError {
    PipeError::HostCall {
        call,
        os_error: last_error(),
    }
}

/// Takes ownership of a handle a Windows call returned, `None` for null.
pub(super) fn owned(raw: HANDLE) -> Option<OwnedHandle> {
    // SAFETY: a non-null handle a call has just returned is open and owned by nobody else.
    (!raw.is_null()).then(|| unsafe { OwnedHandle::from_raw_handle(raw) })
}

/// `within` in milliseconds for a bounded wait.
fn wait_millis(within: Duration) -> u32 {
    u32::try_from(within.as_millis())
        .unwrap_or(MAX_WAIT_MS)
        .min(MAX_WAIT_MS)
}

/// The size of `T` as Windows takes it. Every structure passed here is far smaller than
/// `u32::MAX`; were one not, the call would be refused for the wrong size.
fn size_u32<T>() -> u32 {
    u32::try_from(std::mem::size_of::<T>()).unwrap_or(u32::MAX)
}

/// A manual-reset event for overlapped operations, not signalled.
pub(super) fn new_event() -> Result<OwnedHandle, PipeError> {
    // SAFETY: default security, manual reset, not signalled, no name.
    owned(unsafe { CreateEventW(null(), 1, 0, null()) })
        .ok_or_else(|| host_error(PipeCall::CreateEvent))
}

/// How an overlapped operation ended without completing.
pub(super) enum Incomplete {
    TimedOut,
    Failed(u32),
}

/// Starts an overlapped operation on `handle` with `start` and waits at most `within`
/// for it; returns the bytes it transferred. On timeout the operation is cancelled and
/// the cancellation waited for; if it completed meanwhile, its result stands.
pub(super) fn complete(
    handle: &OwnedHandle,
    event: &OwnedHandle,
    within: Duration,
    start: impl FnOnce(HANDLE, *mut OVERLAPPED) -> BOOL,
) -> Result<u32, Incomplete> {
    let raw = handle.as_raw_handle();
    let mut overlapped = OVERLAPPED {
        hEvent: event.as_raw_handle(),
        ..OVERLAPPED::default()
    };
    let mut transferred = 0_u32;
    if start(raw, &mut overlapped) == 0 {
        let error = last_error();
        if error != ERROR_IO_PENDING {
            return Err(Incomplete::Failed(error));
        }
        // SAFETY: the event handle is open.
        let waited = unsafe { WaitForSingleObject(event.as_raw_handle(), wait_millis(within)) };
        if waited != WAIT_OBJECT_0 {
            let error = last_error();
            // SAFETY: the operation was started on `raw` with `overlapped`, which lives
            // until the wait for its cancellation below returns.
            let finished = unsafe {
                CancelIoEx(raw, &overlapped);
                GetOverlappedResult(raw, &overlapped, &mut transferred, 1)
            };
            if finished != 0 {
                return Ok(transferred);
            }
            return Err(if waited == WAIT_TIMEOUT {
                Incomplete::TimedOut
            } else {
                Incomplete::Failed(error)
            });
        }
    }
    // SAFETY: the operation has completed; `overlapped` and `transferred` are live.
    if unsafe { GetOverlappedResult(raw, &overlapped, &mut transferred, 0) } == 0 {
        return Err(Incomplete::Failed(last_error()));
    }
    Ok(transferred)
}

/// The SID of the user this process runs as, from its token, in an aligned buffer.
pub(super) struct UserSid {
    /// A `TOKEN_USER` and the SID it points into, aligned for both.
    buffer: Vec<u64>,
}

impl UserSid {
    pub(super) fn current() -> Result<Self, PipeError> {
        let mut raw = null_mut();
        // SAFETY: the pseudo-handle of this process needs no closing; `raw` is live.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
            return Err(host_error(PipeCall::ReadUser));
        }
        let token = owned(raw).ok_or_else(|| host_error(PipeCall::ReadUser))?;
        let mut needed = 0_u32;
        // SAFETY: a null buffer of length zero asks only for the length needed.
        let sized = unsafe {
            GetTokenInformation(token.as_raw_handle(), TokenUser, null_mut(), 0, &mut needed)
        };
        if sized == 0 && last_error() != ERROR_INSUFFICIENT_BUFFER {
            return Err(host_error(PipeCall::ReadUser));
        }
        let bytes = usize::try_from(needed)
            .map_err(|_| host_error(PipeCall::ReadUser))?
            .max(std::mem::size_of::<TOKEN_USER>());
        let mut buffer = vec![0_u64; bytes.div_ceil(8)];
        let length = u32::try_from(buffer.len() * 8).map_err(|_| PipeError::HostCall {
            call: PipeCall::ReadUser,
            os_error: ERROR_INSUFFICIENT_BUFFER,
        })?;
        // SAFETY: `buffer` holds `length` writable bytes, aligned for TOKEN_USER.
        let read = unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenUser,
                buffer.as_mut_ptr().cast(),
                length,
                &mut needed,
            )
        };
        if read == 0 {
            return Err(host_error(PipeCall::ReadUser));
        }
        Ok(Self { buffer })
    }

    /// The SID, valid while `self` lives.
    pub(super) fn sid(&self) -> PSID {
        // SAFETY: GetTokenInformation filled the buffer with a TOKEN_USER at its start.
        unsafe { (*self.buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid }
    }
}

/// A security descriptor whose protected DACL grants the current user, and no one else,
/// full access to the pipe (no Everyone, no anonymous logon, no network principal), with
/// the attributes that pass it to `CreateNamedPipeW`.
pub(super) struct OwnerOnly {
    /// Aligned for an ACL; referenced by `descriptor`.
    _acl: Vec<u32>,
    /// Referenced by `attributes`.
    descriptor: Box<SECURITY_DESCRIPTOR>,
    _user: UserSid,
}

impl OwnerOnly {
    pub(super) fn current_user() -> Result<Self, PipeError> {
        let user = UserSid::current()?;
        let sid = user.sid();
        // SAFETY: `sid` points into `user`'s buffer, which GetTokenInformation filled.
        let sid_bytes = usize::try_from(unsafe { GetLengthSid(sid) })
            .map_err(|_| host_error(PipeCall::BuildDacl))?;
        let acl_bytes = std::mem::size_of::<ACL>() + std::mem::size_of::<ACCESS_ALLOWED_ACE>()
            - std::mem::size_of::<u32>()
            + sid_bytes;
        let mut acl = vec![0_u32; acl_bytes.div_ceil(4)];
        let acl_length = u32::try_from(acl.len() * 4).map_err(|_| PipeError::HostCall {
            call: PipeCall::BuildDacl,
            os_error: ERROR_INSUFFICIENT_BUFFER,
        })?;
        let acl_pointer: *mut ACL = acl.as_mut_ptr().cast();
        let mut descriptor = Box::new(SECURITY_DESCRIPTOR::default());
        let descriptor_pointer: *mut SECURITY_DESCRIPTOR = &mut *descriptor;
        // SAFETY: `acl` holds `acl_length` writable bytes, aligned for an ACL; `sid` is a
        // valid SID; `descriptor` is a live, writable SECURITY_DESCRIPTOR.
        let built = unsafe {
            InitializeAcl(acl_pointer, acl_length, ACL_REVISION) != 0
                && AddAccessAllowedAce(acl_pointer, ACL_REVISION, GENERIC_ALL, sid) != 0
                && InitializeSecurityDescriptor(
                    descriptor_pointer.cast(),
                    SECURITY_DESCRIPTOR_REVISION,
                ) != 0
                && SetSecurityDescriptorDacl(descriptor_pointer.cast(), 1, acl_pointer, 0) != 0
                && SetSecurityDescriptorControl(
                    descriptor_pointer.cast(),
                    SE_DACL_PROTECTED,
                    SE_DACL_PROTECTED,
                ) != 0
        };
        if !built {
            return Err(host_error(PipeCall::BuildDacl));
        }
        Ok(Self {
            _acl: acl,
            descriptor,
            _user: user,
        })
    }

    /// Attributes for `CreateNamedPipeW`, valid while `self` lives; the handle is not
    /// inherited.
    pub(super) fn attributes(&mut self) -> SECURITY_ATTRIBUTES {
        let descriptor: *mut SECURITY_DESCRIPTOR = &mut *self.descriptor;
        SECURITY_ATTRIBUTES {
            nLength: size_u32::<SECURITY_ATTRIBUTES>(),
            lpSecurityDescriptor: descriptor.cast(),
            bInheritHandle: 0,
        }
    }
}
