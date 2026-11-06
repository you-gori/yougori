//! What a Windows process can tell of its confinement and its creator (M09E; VM part
//! §3.1; VM-W11): whether a token is an AppContainer token, its integrity level, its
//! capability SIDs and its AppContainer SID; and the PID of the process that started this
//! one. The relay reads its own token before anything else and admits its pipe's server
//! only if it is its creator; tests read the launched relay's token from outside.

use std::os::windows::io::{AsHandle, AsRawHandle, BorrowedHandle, FromRawHandle, OwnedHandle};
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{
    GetLastError, ERROR_INSUFFICIENT_BUFFER, ERROR_NOT_FOUND, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::{
    GetLengthSid, GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation,
    TokenAppContainerSid, TokenCapabilities, TokenIntegrityLevel, TokenIsAppContainer,
    TOKEN_APPCONTAINER_INFORMATION, TOKEN_GROUPS, TOKEN_INFORMATION_CLASS, TOKEN_MANDATORY_LABEL,
    TOKEN_QUERY,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// The low integrity level's RID (`SECURITY_MANDATORY_LOW_RID`).
pub const LOW_INTEGRITY_RID: u32 = 0x1000;

/// The confinement facts of one token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenFacts {
    pub app_container: bool,
    /// The RID of the token's integrity level.
    pub integrity_rid: u32,
    /// How many capability SIDs the token holds.
    pub capabilities: u32,
    /// The AppContainer SID, binary, for an AppContainer token.
    pub container_sid: Option<Vec<u8>>,
}

/// The last OS error of this thread; read right after the call that failed.
fn last_error() -> u32 {
    // SAFETY: GetLastError has no preconditions.
    unsafe { GetLastError() }
}

/// One token information class, in a buffer aligned for any of them.
fn information(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Result<Vec<u64>, u32> {
    let mut needed = 0_u32;
    // SAFETY: a null buffer of length zero asks only for the length needed.
    let sized = unsafe { GetTokenInformation(token, class, null_mut(), 0, &mut needed) };
    if sized == 0 && last_error() != ERROR_INSUFFICIENT_BUFFER {
        return Err(last_error());
    }
    let bytes = usize::try_from(needed)
        .map_err(|_| ERROR_INSUFFICIENT_BUFFER)?
        .max(8);
    let mut buffer = vec![0_u64; bytes.div_ceil(8)];
    let length = u32::try_from(buffer.len() * 8).map_err(|_| ERROR_INSUFFICIENT_BUFFER)?;
    // SAFETY: `buffer` holds `length` writable bytes, aligned for every class read here.
    let read = unsafe {
        GetTokenInformation(
            token,
            class,
            buffer.as_mut_ptr().cast(),
            length,
            &mut needed,
        )
    };
    if read == 0 {
        return Err(last_error());
    }
    Ok(buffer)
}

/// Reads the facts of `token`, opened with `TOKEN_QUERY`; an OS error otherwise.
pub fn token_facts(token: BorrowedHandle<'_>) -> Result<TokenFacts, u32> {
    let token = token.as_raw_handle();
    let is_container = information(token, TokenIsAppContainer)?;
    // SAFETY: GetTokenInformation filled `is_container` with one DWORD at its start.
    let app_container = unsafe { *is_container.as_ptr().cast::<u32>() } != 0;
    let label = information(token, TokenIntegrityLevel)?;
    // SAFETY: GetTokenInformation filled `label` with a TOKEN_MANDATORY_LABEL whose SID
    // points into the same buffer; the RID is its last sub-authority.
    let integrity_rid = unsafe {
        let sid = (*label.as_ptr().cast::<TOKEN_MANDATORY_LABEL>()).Label.Sid;
        let count = *GetSidSubAuthorityCount(sid);
        *GetSidSubAuthority(sid, u32::from(count.saturating_sub(1)))
    };
    let groups = information(token, TokenCapabilities)?;
    // SAFETY: GetTokenInformation filled `groups` with a TOKEN_GROUPS.
    let capabilities = unsafe { (*groups.as_ptr().cast::<TOKEN_GROUPS>()).GroupCount };
    let container_sid = if app_container {
        let container = information(token, TokenAppContainerSid)?;
        // SAFETY: GetTokenInformation filled `container` with a
        // TOKEN_APPCONTAINER_INFORMATION whose SID points into the same buffer.
        let sid = unsafe {
            (*container.as_ptr().cast::<TOKEN_APPCONTAINER_INFORMATION>()).TokenAppContainer
        };
        if sid.is_null() {
            None
        } else {
            // SAFETY: `sid` is a valid SID inside `container`, of the length it reports.
            let bytes = unsafe {
                let length =
                    usize::try_from(GetLengthSid(sid)).map_err(|_| ERROR_INSUFFICIENT_BUFFER)?;
                std::slice::from_raw_parts(sid.cast::<u8>(), length).to_vec()
            };
            Some(bytes)
        }
    } else {
        None
    };
    Ok(TokenFacts {
        app_container,
        integrity_rid,
        capabilities,
        container_sid,
    })
}

/// Reads the facts of the token of the process behind `process`.
pub fn process_token_facts(process: BorrowedHandle<'_>) -> Result<TokenFacts, u32> {
    let mut raw = null_mut();
    // SAFETY: `process` is an open process handle; `raw` is live.
    if unsafe { OpenProcessToken(process.as_raw_handle(), TOKEN_QUERY, &mut raw) } == 0
        || raw.is_null()
    {
        return Err(last_error());
    }
    // SAFETY: a non-null token handle OpenProcessToken has just returned is owned here.
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    token_facts(token.as_handle())
}

/// The facts of this process's own token.
pub fn own_token_facts() -> Result<TokenFacts, u32> {
    // SAFETY: the pseudo-handle of this process is valid for the whole life of the
    // process and needs no closing.
    process_token_facts(unsafe { BorrowedHandle::borrow_raw(GetCurrentProcess()) })
}

/// The PID of the process that started this one, as Windows recorded it at creation (the
/// parent PID of this process's entry in a process snapshot). The PID names that process
/// only while it lives; a relay's creator holds the relay in a kill-on-close job, so it
/// does for as long as the relay runs.
pub fn own_creator_pid() -> Result<u32, u32> {
    // SAFETY: a process snapshot of the whole system takes no pointer.
    let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if raw == INVALID_HANDLE_VALUE || raw.is_null() {
        return Err(last_error());
    }
    // SAFETY: a valid snapshot handle CreateToolhelp32Snapshot has just returned is owned
    // here.
    let snapshot = unsafe { OwnedHandle::from_raw_handle(raw) };
    let me = std::process::id();
    let mut entry = PROCESSENTRY32W {
        dwSize: u32::try_from(std::mem::size_of::<PROCESSENTRY32W>()).unwrap_or(u32::MAX),
        ..PROCESSENTRY32W::default()
    };
    // SAFETY: the snapshot handle is open and `entry` is live with its size set.
    let mut more = unsafe { Process32FirstW(snapshot.as_raw_handle(), &mut entry) } != 0;
    while more {
        if entry.th32ProcessID == me {
            return Ok(entry.th32ParentProcessID);
        }
        // SAFETY: as for Process32FirstW.
        more = unsafe { Process32NextW(snapshot.as_raw_handle(), &mut entry) } != 0;
    }
    Err(ERROR_NOT_FOUND)
}
