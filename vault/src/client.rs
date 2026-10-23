use crate::{
    platform,
    protocol::{self, Request},
};
use serde_json::Value;
use std::{
    os::windows::io::AsRawHandle,
    time::{Duration, Instant},
};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};
pub async fn connect() -> Result<NamedPipeClient, String> {
    let deadline = Instant::now() + Duration::from_secs(3);
    let stream = loop {
        match ClientOptions::new().open(platform::endpoint()?) {
            Ok(stream) => break stream,
            Err(e) if e.raw_os_error() == Some(231) && Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(40)).await
            }
            Err(_) => {
                return Err("Personal Vault is not running. Open it from Yougori Desktop.".into())
            }
        }
    };
    platform::verify_server(stream.as_raw_handle())?;
    Ok(stream)
}
/// What became of a request when it matters whether it reached the broker at all.
#[derive(Debug, PartialEq)]
pub enum Asked {
    /// The broker could not be reached, or the request could not be written: nothing was asked.
    NotSent(String),
    /// The broker answered: its result, or its refusal.
    Answered(Result<Value, String>),
    /// Sent, and no answer came: what the broker did is unknown.
    Unanswered(String),
}

/// Asks the broker `request` and says whether it was never sent, answered, or left unanswered.
pub async fn ask(request: &Request) -> Asked {
    match connect().await {
        Ok(mut stream) => send(&mut stream, request).await,
        Err(error) => Asked::NotSent(error),
    }
}

pub async fn exchange(stream: &mut NamedPipeClient, request: &Request) -> Result<Value, String> {
    match send(stream, request).await {
        Asked::Answered(result) => result,
        Asked::NotSent(error) | Asked::Unanswered(error) => Err(error),
    }
}

async fn send(stream: &mut NamedPipeClient, request: &Request) -> Asked {
    if matches!(
        request,
        Request::Manage {}
            | Request::Browse {}
            | Request::HttpSetup {}
            | Request::HttpCredentials {}
            | Request::Remote {}
            | Request::Remove { .. }
            | Request::Destroy {}
            | Request::Mcp { .. }
    ) {
        // A foreground Desktop can transfer focus permission to its already
        // authenticated broker. Windows can still refuse for background callers.
        unsafe {
            let mut process = 0;
            if windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId(
                stream.as_raw_handle(),
                &mut process,
            ) != 0
            {
                windows_sys::Win32::UI::WindowsAndMessaging::AllowSetForegroundWindow(process);
            }
        }
    }
    // Added items carry credentials: wipe the serialized copy after sending.
    let mut message = match serde_json::to_value(request) {
        Ok(message) => message,
        Err(error) => return Asked::NotSent(error.to_string()),
    };
    let written = protocol::write(stream, &message).await;
    protocol::wipe(&mut message);
    // A frame not written whole is never read by the broker: nothing was asked.
    if let Err(error) = written {
        return Asked::NotSent(error);
    }
    // A destroy waits for its approval (up to two minutes) and then deletes, so it is given
    // longer than other approvals: an answer cut off mid-delete leaves its outcome unknown.
    let timeout = match request {
        Request::Manage {} => 480,
        Request::Destroy {} => 300,
        _ => 135,
    };
    let bytes = match tokio::time::timeout(Duration::from_secs(timeout), protocol::read(stream)).await {
        Err(_) => return Asked::Unanswered("Vault request timed out; inspect activity before retrying an action".into()),
        Ok(Err(error)) => return Asked::Unanswered(error),
        Ok(Ok(bytes)) => bytes,
    };
    let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
        return Asked::Unanswered("Invalid vault response".into());
    };
    match value.get("error").and_then(Value::as_str) {
        Some(error) => Asked::Answered(Err(error.into())),
        None => Asked::Answered(Ok(value)),
    }
}
pub async fn call(request: &Request) -> Result<Value, String> {
    exchange(&mut connect().await?, request).await
}
