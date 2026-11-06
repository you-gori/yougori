//! The security of a link pipe that a confined relay may open (M09E; VM part §3.1: the
//! relay is its own confined process; VM-W11). An AppContainer process passes an access
//! check only where the DACL grants both its user and its AppContainer SID, and it runs at
//! low integrity, while an object with no label counts as medium integrity with no write up.
//! So the pipe's descriptor here is the owner-only one of the adapter (a protected DACL
//! granting the current user full access) plus one ACE for the relay's AppContainer SID
//! granting [`CONTAINER_PIPE_ACCESS`], read and write and nothing else, and a low mandatory
//! label with no write up, so the low-integrity relay may write and nothing below low may.

use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_SID, GENERIC_ALL};
use windows_sys::Win32::Security::{
    AddAccessAllowedAce, AddMandatoryAce, CreateWellKnownSid, GetLengthSid,
    GetSidIdentifierAuthority, GetSidSubAuthority, GetSidSubAuthorityCount, InitializeAcl,
    InitializeSecurityDescriptor, IsValidSid, SetSecurityDescriptorControl,
    SetSecurityDescriptorDacl, SetSecurityDescriptorSacl, WinLowLabelSid, ACCESS_ALLOWED_ACE, ACL,
    ACL_REVISION, PSID, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, SECURITY_MAX_SID_SIZE,
    SE_DACL_PROTECTED, SYSTEM_MANDATORY_LABEL_ACE,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_WRITE_DATA, SYNCHRONIZE,
};

use super::pipe::{PipeCall, PipeError};
use super::pipe_os::{host_error, UserSid};

/// What the relay's AppContainer may do on its link pipe, and what a confined relay asks
/// for when it opens it: read and write the byte stream, read the pipe's attributes (which
/// reading the server's PID needs) and wait on it. No write of attributes, no new pipe
/// instance, no change of the DACL or owner, no delete.
pub const CONTAINER_PIPE_ACCESS: u32 =
    FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE;

/// `SECURITY_DESCRIPTOR_REVISION` (Win32 SystemServices, not enabled here).
const SECURITY_DESCRIPTOR_REVISION: u32 = 1;

/// `SYSTEM_MANDATORY_LABEL_NO_WRITE_UP`, 0x1 in winnt.h (Win32 SystemServices in
/// windows-sys, not enabled here): a process below the label may not write.
const SYSTEM_MANDATORY_LABEL_NO_WRITE_UP: u32 = 0x1;

/// The smallest SID: revision, count and authority, with no sub-authority.
const MIN_SID_BYTES: usize = 8;

fn invalid_sid() -> PipeError {
    PipeError::HostCall {
        call: PipeCall::BuildDacl,
        os_error: ERROR_INVALID_SID,
    }
}

fn too_large() -> PipeError {
    PipeError::HostCall {
        call: PipeCall::BuildDacl,
        os_error: ERROR_INSUFFICIENT_BUFFER,
    }
}

/// A SID in a buffer aligned for one: a copy of a binary SID, checked to be exactly one
/// valid SID.
pub(super) struct SidBuffer {
    buffer: Vec<u32>,
}

impl SidBuffer {
    /// Copies `sid`, its binary form (as `CopySid` writes it); refused for anything that is
    /// not one valid SID of exactly that length.
    pub(super) fn copy(sid: &[u8]) -> Result<Self, PipeError> {
        let max = usize::try_from(SECURITY_MAX_SID_SIZE).map_err(|_| invalid_sid())?;
        if !(MIN_SID_BYTES..=max).contains(&sid.len()) {
            return Err(invalid_sid());
        }
        let mut buffer = vec![0_u32; sid.len().div_ceil(4)];
        // SAFETY: `buffer` holds at least `sid.len()` writable bytes and does not overlap
        // `sid`.
        unsafe {
            std::ptr::copy_nonoverlapping(
                sid.as_ptr(),
                buffer.as_mut_ptr().cast::<u8>(),
                sid.len(),
            );
        }
        let copied = Self { buffer };
        let pointer = copied.sid();
        // SAFETY: `pointer` is the start of the buffer holding the candidate SID;
        // IsValidSid reads within the length its header declares, which GetLengthSid
        // reports and which must equal the bytes given.
        let valid = unsafe {
            IsValidSid(pointer) != 0
                && usize::try_from(GetLengthSid(pointer)).ok() == Some(sid.len())
        };
        if !valid {
            return Err(invalid_sid());
        }
        Ok(copied)
    }

    /// The low mandatory label's SID (S-1-16-4096).
    fn low_label() -> Result<Self, PipeError> {
        let max = usize::try_from(SECURITY_MAX_SID_SIZE).map_err(|_| too_large())?;
        let mut buffer = vec![0_u32; max.div_ceil(4)];
        let mut length = SECURITY_MAX_SID_SIZE;
        // SAFETY: `buffer` holds `length` writable bytes, aligned for a SID; no domain SID
        // is needed for a label.
        let created = unsafe {
            CreateWellKnownSid(
                WinLowLabelSid,
                null_mut(),
                buffer.as_mut_ptr().cast(),
                &mut length,
            )
        };
        if created == 0 {
            return Err(host_error(PipeCall::BuildDacl));
        }
        Ok(Self { buffer })
    }

    /// Whether the SID is an AppContainer SID: authority `SECURITY_APP_PACKAGE_AUTHORITY`
    /// (15) and first sub-authority `SECURITY_APP_PACKAGE_BASE_RID` (2), `S-1-15-2-...`.
    fn is_app_container(&self) -> bool {
        let sid = self.sid();
        // SAFETY: the buffer holds one valid SID, every sub-authority its count declares
        // included; sub-authority 0 is read only when there is one.
        unsafe {
            (*GetSidIdentifierAuthority(sid)).Value == [0, 0, 0, 0, 0, 15]
                && *GetSidSubAuthorityCount(sid) >= 1
                && *GetSidSubAuthority(sid, 0) == 2
        }
    }

    /// The SID, valid while `self` lives.
    pub(super) fn sid(&self) -> PSID {
        self.buffer.as_ptr().cast_mut().cast()
    }

    /// The SID's length in bytes.
    fn length(&self) -> Result<usize, PipeError> {
        // SAFETY: the buffer holds a valid SID (checked or written by Windows).
        usize::try_from(unsafe { GetLengthSid(self.sid()) }).map_err(|_| invalid_sid())
    }
}

/// An ACL buffer, aligned for an ACL, for one ACE of `ace_bytes` (the ACE structure,
/// whose last `u32` is where its SID starts) per SID length in `sids`.
fn acl_buffer(ace_bytes: usize, sids: &[usize]) -> Result<(Vec<u32>, u32), PipeError> {
    let per_ace = ace_bytes - std::mem::size_of::<u32>();
    let bytes = sids
        .iter()
        .try_fold(std::mem::size_of::<ACL>(), |total, sid| {
            total.checked_add(per_ace)?.checked_add(*sid)
        })
        .ok_or_else(too_large)?;
    let buffer = vec![0_u32; bytes.div_ceil(4)];
    let length = u32::try_from(buffer.len() * 4).map_err(|_| too_large())?;
    Ok((buffer, length))
}

/// A security descriptor whose protected DACL grants the current user full access and
/// the relay's AppContainer [`CONTAINER_PIPE_ACCESS`], and whose SACL holds a low
/// mandatory label with no write up, with the attributes that pass it to
/// `CreateNamedPipeW` (see the module notes).
pub(super) struct OwnerAndContainer {
    /// Aligned for an ACL; referenced by `descriptor`.
    _dacl: Vec<u32>,
    /// Aligned for an ACL; referenced by `descriptor`.
    _sacl: Vec<u32>,
    /// Referenced by `attributes`.
    descriptor: Box<SECURITY_DESCRIPTOR>,
    _user: UserSid,
    _container: SidBuffer,
    _label: SidBuffer,
}

impl OwnerAndContainer {
    /// The descriptor for a pipe that the AppContainer `container` (a binary SID) may open.
    pub(super) fn new(container: &[u8]) -> Result<Self, PipeError> {
        let container = SidBuffer::copy(container)?;
        if !container.is_app_container() {
            return Err(invalid_sid());
        }
        let label = SidBuffer::low_label()?;
        let user = UserSid::current()?;
        // SAFETY: the user SID points into `user`'s buffer, which GetTokenInformation
        // filled.
        let user_bytes = usize::try_from(unsafe { GetLengthSid(user.sid()) })
            .map_err(|_| host_error(PipeCall::BuildDacl))?;
        let (mut dacl, dacl_length) = acl_buffer(
            std::mem::size_of::<ACCESS_ALLOWED_ACE>(),
            &[user_bytes, container.length()?],
        )?;
        let (mut sacl, sacl_length) = acl_buffer(
            std::mem::size_of::<SYSTEM_MANDATORY_LABEL_ACE>(),
            &[label.length()?],
        )?;
        let dacl_pointer: *mut ACL = dacl.as_mut_ptr().cast();
        let sacl_pointer: *mut ACL = sacl.as_mut_ptr().cast();
        let mut descriptor = Box::new(SECURITY_DESCRIPTOR::default());
        let descriptor_pointer: *mut SECURITY_DESCRIPTOR = &mut *descriptor;
        // SAFETY: each ACL buffer holds its stated length in writable bytes, aligned for
        // an ACL and sized for its ACEs; every SID is valid and outlives the descriptor in
        // `Self`; `descriptor` is a live, writable SECURITY_DESCRIPTOR.
        let built = unsafe {
            InitializeAcl(dacl_pointer, dacl_length, ACL_REVISION) != 0
                && AddAccessAllowedAce(dacl_pointer, ACL_REVISION, GENERIC_ALL, user.sid()) != 0
                && AddAccessAllowedAce(
                    dacl_pointer,
                    ACL_REVISION,
                    CONTAINER_PIPE_ACCESS,
                    container.sid(),
                ) != 0
                && InitializeAcl(sacl_pointer, sacl_length, ACL_REVISION) != 0
                && AddMandatoryAce(
                    sacl_pointer,
                    ACL_REVISION,
                    0,
                    SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
                    label.sid(),
                ) != 0
                && InitializeSecurityDescriptor(
                    descriptor_pointer.cast(),
                    SECURITY_DESCRIPTOR_REVISION,
                ) != 0
                && SetSecurityDescriptorDacl(descriptor_pointer.cast(), 1, dacl_pointer, 0) != 0
                && SetSecurityDescriptorSacl(descriptor_pointer.cast(), 1, sacl_pointer, 0) != 0
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
            _dacl: dacl,
            _sacl: sacl,
            descriptor,
            _user: user,
            _container: container,
            _label: label,
        })
    }

    /// Attributes for `CreateNamedPipeW`, valid while `self` lives; the handle is not
    /// inherited.
    pub(super) fn attributes(&mut self) -> SECURITY_ATTRIBUTES {
        let descriptor: *mut SECURITY_DESCRIPTOR = &mut *self.descriptor;
        SECURITY_ATTRIBUTES {
            nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(u32::MAX),
            lpSecurityDescriptor: descriptor.cast(),
            bInheritHandle: 0,
        }
    }
}
