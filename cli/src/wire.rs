use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const VERSION: u32 = 2;
pub const MAX_REQUEST: usize = 1024 * 1024;
pub const MAX_RESPONSE: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    pub version: u32,
    pub method: String,
    #[serde(default = "empty_params")]
    pub params: Value,
    #[serde(default)]
    pub confirmed: bool,
    #[serde(default)]
    pub dry_run: bool,
}
fn empty_params() -> Value {
    serde_json::json!({})
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Response {
    pub version: u32,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_details: Option<ErrorDetails>,
}

/// Protocol-v2 machine details retain the human-readable error. Responses allow
/// future additive fields; request parameters remain strict. The engine sends a
/// legacy-shaped upgrade error to v1 clients instead of incompatible details.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorDetails {
    pub code: String,
    pub affected_resource: Option<String>,
    pub retryable: bool,
    pub outcome: String,
}

/// Marks an error as the person cancelling rather than as a failure. U+0018 is the CANCEL control
/// character: no real message begins with it, and a terminal does not draw it, so a marked
/// sentence that reaches the screen by some other door still reads as it should.
pub const CANCELLED_SAID: char = '\u{18}';

/// A cancellation that says what it left behind, such as "Cancelled. Nothing was connected.".
/// However it is worded, it is shown muted rather than as a failure, the command exits 130, and
/// its code is `operation_cancelled`. An empty sentence means the screen already says it.
pub fn cancelled(said: &str) -> String {
    format!("{CANCELLED_SAID}{said}")
}

/// What a cancellation says, without its mark; `None` for an error that is not one. The plain
/// [`crate::cli_ui::CANCELLED`] is one too, and so is a marked one that something wrapped.
pub fn cancellation(error: &str) -> Option<String> {
    if error == crate::cli_ui::CANCELLED {
        return Some(error.to_owned());
    }
    error.contains(CANCELLED_SAID).then(|| error.replace(CANCELLED_SAID, "").trim().to_owned())
}

/// What kind of failure an error is, for a program to act on. A code is attached where the
/// error is made and travels beside the sentence, never inside it, so rewording a message for
/// people cannot change what a program reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Code {
    DurableStorageMissing,
    UnsupportedCapability,
    OperationCancelled,
    OperationInterrupted,
    OutcomeUnknown,
    IncompatibleEngine,
    EngineUnavailable,
    ResourceConflict,
    PermissionDenied,
    InvalidRequest,
    ResourceNotFound,
    OperationFailed,
}

impl Code {
    /// The code's name, whether trying again could help, and what became of the request.
    fn parts(self) -> (&'static str, bool, &'static str) {
        match self {
            Code::DurableStorageMissing => ("durable_storage_missing", false, "not_started"),
            Code::UnsupportedCapability => ("unsupported_capability", false, "not_started"),
            Code::OperationCancelled => ("operation_cancelled", false, "cancelled"),
            Code::OperationInterrupted => ("operation_interrupted", false, "reconciliation_required"),
            Code::OutcomeUnknown => ("outcome_unknown", false, "unknown"),
            Code::IncompatibleEngine => ("incompatible_engine", false, "not_started"),
            Code::EngineUnavailable => ("engine_unavailable", true, "not_submitted"),
            Code::ResourceConflict => ("resource_conflict", false, "not_started"),
            Code::PermissionDenied => ("permission_denied", false, "not_started"),
            Code::InvalidRequest => ("invalid_request", false, "not_started"),
            Code::ResourceNotFound => ("resource_not_found", false, "not_started"),
            Code::OperationFailed => ("operation_failed", false, "failed"),
        }
    }

    /// The kind of an error that arrived without one attached.
    ///
    /// First what cannot drift: the cancellation mark and the engine's machine tokens. Then
    /// `Usage:`, which is a form rather than a wording. Words come last, as a fallback for errors
    /// nobody has tagged yet: an error the CLI makes itself should carry its code from where it
    /// is made (`client::remember_error`), as the engine connection, its time limits, the command
    /// parser and its confirmations, and environment names already do. The test below pins the
    /// words this still relies on, so a rewording that would move a code fails there first.
    pub fn read(message: &str) -> Code {
        let lower = message.to_ascii_lowercase();
        if cancellation(message).is_some() {
            Code::OperationCancelled
        } else if message.starts_with("[YOUGORI_DURABLE_STORAGE_MISSING]") {
            Code::DurableStorageMissing
        } else if message.starts_with("YOUGORI_UNSUPPORTED_EXECUTION_CAPABILITY") {
            Code::UnsupportedCapability
        } else if message.starts_with("YOUGORI_OPERATION_CANCELLED") {
            Code::OperationCancelled
        } else if message.starts_with("YOUGORI_OPERATION_INTERRUPTED") {
            Code::OperationInterrupted
        } else if lower.starts_with("usage:") {
            Code::InvalidRequest
        } else if lower.contains("timed out") || lower.contains("outcome may be unknown") || lower.contains("connection ended") {
            Code::OutcomeUnknown
        } else if lower.contains("cancelled") || lower.contains("canceled") {
            Code::OperationCancelled
        } else if lower.contains("interrupted") {
            Code::OperationInterrupted
        } else if lower.contains("protocol mismatch") || lower.contains("does not support") {
            Code::IncompatibleEngine
        } else if lower.contains("cannot reach") {
            Code::EngineUnavailable
        } else if lower.contains("another live owner") || lower.contains("already in use") || lower.contains("revision") && lower.contains("conflict") {
            Code::ResourceConflict
        } else if lower.contains("permission") || lower.contains("requires --yes") || lower.contains("repeat with --yes") || lower.contains("--yes confirmation is required") || lower.contains("ownership") {
            Code::PermissionDenied
        } else if lower.contains("unknown parameter") || lower.contains("unknown option") || lower.contains("missing parameter") || lower.contains("must be") || lower.contains("unknown command") || lower.contains("unknown method") {
            Code::InvalidRequest
        } else if lower.contains("not found") {
            Code::ResourceNotFound
        } else {
            Code::OperationFailed
        }
    }
}

impl ErrorDetails {
    /// The details of an error whose kind is known where it is made.
    pub fn of(code: Code) -> Self {
        let (code, retryable, outcome) = code.parts();
        Self { code: code.into(), affected_resource: None, retryable, outcome: outcome.into() }
    }
    /// The details of an error that arrived without any, read from it (see [`Code::read`]).
    pub fn from_message(message: &str) -> Self {
        Self::of(Code::read(message))
    }
}
impl Response {
    pub fn success(result: Value) -> Self {
        Self {
            version: VERSION,
            ok: true,
            result: Some(result),
            error: None,
            error_details: None,
        }
    }
    pub fn failure(error: impl Into<String>) -> Self {
        let error = error.into();
        let details = ErrorDetails::from_message(&error);
        Self::failure_with_details(error, details)
    }
    pub fn failure_with_details(error: impl Into<String>, details: ErrorDetails) -> Self {
        Self {
            version: VERSION,
            ok: false,
            result: None,
            error: Some(error.into()),
            error_details: Some(details),
        }
    }
}

pub async fn read_frame(
    stream: &mut (impl AsyncRead + Unpin),
    limit: usize,
) -> io::Result<Vec<u8>> {
    let size = stream.read_u32().await? as usize;
    if size == 0 || size > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Yougori message exceeds its size limit",
        ));
    }
    let mut bytes = vec![0; size];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}
pub async fn write_frame(
    stream: &mut (impl AsyncWrite + Unpin),
    bytes: &[u8],
    limit: usize,
) -> io::Result<()> {
    if bytes.is_empty() || bytes.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Yougori message exceeds its size limit",
        ));
    }
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(bytes).await?;
    stream.flush().await
}

#[cfg(windows)]
pub fn user_sid() -> io::Result<String> {
    process_user_sid(unsafe { windows_sys::Win32::System::Threading::GetCurrentProcess() })
}

#[cfg(windows)]
fn process_user_sid(process: windows_sys::Win32::Foundation::HANDLE) -> io::Result<String> {
    use windows_sys::Win32::{
        Foundation::{CloseHandle, LocalFree},
        Security::Authorization::ConvertSidToStringSidW,
        Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER},
        System::Threading::OpenProcessToken,
    };
    // The token buffer is usize-aligned; all pointers live until copied to a String.
    unsafe {
        let mut token = std::ptr::null_mut();
        if OpenProcessToken(process, TOKEN_QUERY, &mut token) == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut needed = 0;
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed);
        let mut buffer = vec![0usize; (needed as usize).div_ceil(std::mem::size_of::<usize>())];
        let result = GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        );
        CloseHandle(token);
        if result == 0 {
            return Err(io::Error::last_os_error());
        }
        let user = &*buffer.as_ptr().cast::<TOKEN_USER>();
        let mut text = std::ptr::null_mut();
        if ConvertSidToStringSidW(user.User.Sid, &mut text) == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut len = 0;
        while *text.add(len) != 0 {
            len += 1;
        }
        let value = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
        LocalFree(text.cast());
        Ok(value)
    }
}

#[cfg(windows)]
pub fn verify_pipe_server(stream: &tokio::net::windows::named_pipe::NamedPipeClient) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::{
        Foundation::CloseHandle,
        System::{Pipes::GetNamedPipeServerProcessId, Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION}},
    };
    // A protected server DACL controls its clients, but does not prevent an
    // unrelated user from squatting the predictable pipe name before startup.
    // Authenticate the OS owner before sending commands or credential payloads.
    unsafe {
        let mut pid = 0;
        if GetNamedPipeServerProcessId(stream.as_raw_handle(), &mut pid) == 0 {
            return Err(io::Error::last_os_error());
        }
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if process.is_null() { return Err(io::Error::last_os_error()); }
        let owner = process_user_sid(process);
        CloseHandle(process);
        if owner? != user_sid()? {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "Yougori control endpoint belongs to another user"));
        }
    }
    Ok(())
}

/// No network address override: the management API is never a TCP service and
/// cannot be reached through My PC, guest ports, or Cloudflare publications.
pub fn endpoint() -> io::Result<String> {
    #[cfg(windows)]
    {
        Ok(format!(r"\\.\pipe\Yougori.Control.v1.{}", user_sid()?))
    }
    #[cfg(unix)]
    {
        Ok(format!("/tmp/yougori-{}/control-v1.sock", unsafe {
            libc::geteuid()
        }))
    }
}

#[cfg(unix)]
pub fn private_socket_directory() -> io::Result<std::path::PathBuf> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    let path = std::path::PathBuf::from(format!("/tmp/yougori-{}", unsafe { libc::geteuid() }));
    match std::fs::DirBuilder::new().mode(0o700).create(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    let meta = std::fs::symlink_metadata(&path)?;
    if !meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
        return Err(io::Error::other(
            "Yougori socket directory must be owned by this user with mode 0700",
        ));
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn machine_errors_distinguish_unknown_outcomes_and_decode_legacy_responses() {
        let old: Response = serde_json::from_value(serde_json::json!({"version":1,"ok":false,"error":"old"})).unwrap();
        assert!(old.error_details.is_none());
        let failure = Response::failure("Yougori control request timed out. The outcome may be unknown");
        let details = failure.error_details.unwrap();
        assert_eq!(details.code, "outcome_unknown");
        assert!(!details.retryable);
        assert_eq!(details.outcome, "unknown");
        assert_eq!(ErrorDetails::from_message("Usage: yougori rm ENV --yes").code, "invalid_request");
        // Missing confirmations from the CLI parser and the engine both mean nothing ran.
        for refusal in ["Deletes this environment. Repeat with --yes only if this is intended.", "Publishes a public link. Explicit --yes confirmation is required."] {
            let details = ErrorDetails::from_message(refusal);
            assert_eq!((details.code.as_str(), details.outcome.as_str()), ("permission_denied", "not_started"), "{refusal}");
        }
        assert_eq!(ErrorDetails::from_message("YOUGORI_OPERATION_INTERRUPTED: cleanup timed out").outcome,"reconciliation_required");
        let future:Response=serde_json::from_value(serde_json::json!({"version":VERSION,"ok":true,"result":{},"futureAdditiveField":true})).unwrap();
        assert!(future.ok);
    }

    /// PROVES that a cancellation reads as one however it is worded, and that only one does.
    #[test]
    fn a_cancellation_is_one_however_it_is_worded() {
        let said = cancelled("Cancelled. Nothing was connected.");
        assert_eq!(cancellation(&said).as_deref(), Some("Cancelled. Nothing was connected."));
        assert_eq!(ErrorDetails::from_message(&said).code, "operation_cancelled");
        // No word of it says "cancelled", and it still is one.
        assert_eq!(ErrorDetails::from_message(&cancelled("Stopped. Nothing else changed.")).code, "operation_cancelled");
        // Something wrapped it in words of its own: still one, and the mark never shows.
        assert_eq!(cancellation(&format!("Setup ended: {}", cancelled("Nothing was created."))).as_deref(), Some("Setup ended: Nothing was created."));
        assert_eq!(cancellation(crate::cli_ui::CANCELLED).as_deref(), Some(crate::cli_ui::CANCELLED));
        // An empty one means the screen already says it.
        assert_eq!(cancellation(&cancelled("")).as_deref(), Some(""));
        assert!(cancellation("The engine stopped while copying").is_none());
    }

    /// PINS the words the fallback still reads. Each family keeps its code whatever else changes
    /// around it; rewording one of these sentences so that it stops matching fails here, which
    /// is the moment to attach its code where it is made instead.
    #[test]
    fn the_words_an_untagged_error_is_read_by_keep_their_codes() {
        let families = [
            ("Usage: yougori rm ENV --yes", "invalid_request"),
            ("Unknown option --colour for yougori terminal.", "invalid_request"),
            ("--isolation must be standard or strict.", "invalid_request"),
            ("Deletes this environment. Repeat with --yes only if this is intended.", "permission_denied"),
            ("Environment web was not found. See your environments with yougori ps.", "resource_not_found"),
            ("Cannot reach the Yougori engine because it is not running. Start it with yougori app start.", "engine_unavailable"),
            ("Yougori did not answer in time, so the outcome may be unknown.", "outcome_unknown"),
            ("CLI/engine protocol mismatch. Update both Yougori and its CLI.", "incompatible_engine"),
            ("Port 8080 is already in use by another environment.", "resource_conflict"),
            ("The copy stopped partway; nothing more was copied.", "operation_failed"),
        ];
        for (message, code) in families {
            assert_eq!(ErrorDetails::from_message(message).code, code, "{message}");
        }
        // A code attached where the error was made does not depend on any of this.
        let details = ErrorDetails::of(Code::EngineUnavailable);
        assert_eq!((details.code.as_str(), details.retryable, details.outcome.as_str()), ("engine_unavailable", true, "not_submitted"));
    }
    #[test]
    fn bounded_frames_roundtrip_and_reject_oversize() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let (mut a, mut b) = tokio::io::duplex(128);
                write_frame(&mut a, b"hello", 8).await.unwrap();
                assert_eq!(read_frame(&mut b, 8).await.unwrap(), b"hello");
                a.write_u32(1024).await.unwrap();
                assert!(read_frame(&mut b, 8).await.is_err());
                assert!(write_frame(&mut a, b"oversized", 2).await.is_err());
            });
    }
    #[test]
    fn requests_reject_unknown_envelope_fields() {
        assert!(serde_json::from_value::<Request>(
            serde_json::json!({"version":1,"method":"state","admin":true})
        )
        .is_err());
        assert!(
            !serde_json::from_value::<Request>(serde_json::json!({"version":1,"method":"state"}))
                .unwrap()
                .confirmed
        );
        assert!(!endpoint().unwrap().contains("127.0.0.1"));
    }

    #[cfg(windows)]
    #[test]
    fn local_pipe_server_owner_is_verified_before_request_data() {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
            let endpoint = format!(r"\\.\pipe\Yougori.OwnerTest.{}.{}", std::process::id(),
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
            let server = tokio::net::windows::named_pipe::ServerOptions::new()
                .first_pipe_instance(true).create(&endpoint).unwrap();
            let client = tokio::net::windows::named_pipe::ClientOptions::new().open(&endpoint).unwrap();
            server.connect().await.unwrap();
            verify_pipe_server(&client).unwrap();
            // No protocol bytes are needed to establish the owner's identity.
            let mut bytes = [0u8; 1];
            assert_eq!(server.try_read(&mut bytes).unwrap_err().kind(), io::ErrorKind::WouldBlock);
        });
    }
}
