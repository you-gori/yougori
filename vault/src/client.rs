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
pub async fn exchange(stream: &mut NamedPipeClient, request: &Request) -> Result<Value, String> {
    if matches!(
        request,
        Request::Manage {}
            | Request::Browse {}
            | Request::HttpSetup {}
            | Request::HttpCredentials {}
            | Request::Remote {}
            | Request::Remove { .. }
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
    let mut message = serde_json::to_value(request).map_err(|e| e.to_string())?;
    let written = protocol::write(stream, &message).await;
    protocol::wipe(&mut message);
    written?;
    let timeout = if matches!(request, Request::Manage {}) {
        480
    } else {
        135
    };
    let bytes = tokio::time::timeout(Duration::from_secs(timeout), protocol::read(stream))
        .await
        .map_err(|_| "Vault request timed out; inspect activity before retrying an action")??;
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| "Invalid vault response")?;
    if let Some(error) = value.get("error").and_then(Value::as_str) {
        return Err(error.into());
    }
    Ok(value)
}
pub async fn call(request: &Request) -> Result<Value, String> {
    exchange(&mut connect().await?, request).await
}
