use crate::wire::{self, Request, Response};
use serde_json::{json, Value};
use std::{
    cell::RefCell,
    future::Future,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

/// Interactive screens show their own progress; notes on stderr would break their layout.
pub static QUIET: AtomicBool = AtomicBool::new(false);

tokio::task_local! {
    static ERROR_CAUSE: RefCell<Option<(String, wire::ErrorDetails)>>;
}

/// Preserve the engine's machine contract across the CLI's existing human-error
/// context. The scope is one command, never shared between tasks or invocations.
pub async fn capture_errors<T>(future: impl Future<Output = Result<T, String>>) -> Result<T, Response> {
    ERROR_CAUSE.scope(RefCell::new(None), async {
        let result = future.await;
        result.map_err(|error| {
            let cause = ERROR_CAUSE.with(|slot| slot.borrow_mut().take());
            // Context wrappers may add the method/job ID. An unrelated local
            // failure must not inherit details from an earlier swallowed call.
            match cause.filter(|(message, _)| !message.is_empty() && error.contains(message)) {
                Some((_, details)) => Response::failure_with_details(error, details),
                None => Response::failure(error),
            }
        })
    }).await
}

fn clear_error_cause() {
    let _ = ERROR_CAUSE.try_with(|slot| slot.borrow_mut().take());
}
fn error_cause(error: String, details: wire::ErrorDetails) -> String {
    let _ = ERROR_CAUSE.try_with(|slot| *slot.borrow_mut() = Some((error.clone(), details)));
    error
}

pub async fn call_at(endpoint: &str, request: &Request) -> Result<Value, String> {
    clear_error_cause();
    let response=exchange_at(endpoint,request).await?;
    if response.version != wire::VERSION {
        return Err("CLI/engine protocol mismatch. Update both Yougori and its CLI.".into());
    }
    if response.ok {
        Ok(response.result.unwrap_or(Value::Null))
    } else {
        let error = engine_error(&request.method, response.error.unwrap_or_else(|| "Yougori operation failed".into()));
        let details = response.error_details.unwrap_or_else(|| wire::ErrorDetails::from_message(&error));
        Err(error_cause(error, details))
    }
}

/// Discovery alone can inspect a legacy engine. Mutations never use this
/// fallback: mismatched protocols require updating both installed components.
pub async fn engine_identity()->Result<Value,String>{
    let endpoint=wire::endpoint().map_err(|e|e.to_string())?;
    engine_identity_at(&endpoint).await
}
async fn engine_identity_at(endpoint:&str)->Result<Value,String>{
    let mut req=request("app_status",json!({}));
    let mut response=exchange_at(endpoint,&req).await?;
    if response.version==1 && response.version!=wire::VERSION{
        req.version=1;
        response=exchange_at(endpoint,&req).await?;
    }
    if !response.ok{return Err(response.error.unwrap_or_else(||"Cannot inspect the running engine".into()));}
    let mut identity=response.result.filter(Value::is_object).ok_or("Invalid Yougori engine identity response")?;
    identity["protocolVersion"]=response.version.into();
    identity["protocolCompatible"]=(response.version==wire::VERSION).into();
    Ok(identity)
}

#[cfg(windows)]
type ControlStream = tokio::net::windows::named_pipe::NamedPipeClient;
#[cfg(unix)]
type ControlStream = tokio::net::UnixStream;

async fn connect_at(endpoint: &str) -> Result<ControlStream, String> {
    #[cfg(windows)]
    let stream = {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match tokio::net::windows::named_pipe::ClientOptions::new().open(endpoint) {
                Ok(stream)=>break stream,
                Err(error) if error.raw_os_error()==Some(231) && Instant::now()<deadline => tokio::time::sleep(Duration::from_millis(50)).await,
                Err(error)=>return Err(format!("Cannot reach the Yougori engine: {error}. Start/update Yougori, or run yougori app start.")),
            }
        }
    };
    #[cfg(unix)]
    let stream = tokio::net::UnixStream::connect(endpoint)
        .await
        .map_err(|error| {
            format!("Cannot reach the Yougori engine: {error}. Run yougori app start.")
        })?;
    #[cfg(windows)]
    wire::verify_pipe_server(&stream).map_err(|error| {
        format!("Cannot verify Yougori engine ownership: {error}. No request was sent.")
    })?;
    #[cfg(unix)]
    if stream
        .peer_cred()
        .map_err(|error| format!("Cannot verify Yougori engine ownership: {error}"))?
        .uid()
        != unsafe { libc::geteuid() }
    {
        return Err(
            "Yougori control endpoint belongs to another user. No request was sent.".into(),
        );
    }
    Ok(stream)
}

pub async fn open_terminal_stream(environment: &str, session: &str, offset: u64) -> Result<Option<crate::terminal_stream::Channel>, String> {
    let endpoint = wire::endpoint().map_err(|e| e.to_string())?;
    let mut stream = connect_at(&endpoint).await?;
    let request = request("terminal_stream", json!({"environmentId":environment,"sessionId":session,"offset":offset}));
    let bytes = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
    let response = tokio::time::timeout(Duration::from_secs(30), async {
        wire::write_frame(&mut stream, &bytes, wire::MAX_REQUEST).await?;
        wire::read_frame(&mut stream, wire::MAX_RESPONSE).await
    }).await.map_err(|_| "Terminal stream opening timed out; input was not sent")?.map_err(|e| e.to_string())?;
    let response: Response = serde_json::from_slice(&response).map_err(|_| "Invalid terminal stream response")?;
    if response.version != wire::VERSION { return Err("CLI/engine protocol mismatch. Update both Yougori and its CLI.".into()); }
    if !response.ok {
        let error = response.error.unwrap_or_default();
        if error == crate::terminal_stream::UNSUPPORTED || error.starts_with("Unknown method 'terminal_stream'.") { return Ok(None); }
        return Err(error);
    }
    if response.result.as_ref().and_then(|v| v["terminalStreamVersion"].as_u64()) != Some(crate::terminal_stream::VERSION as u64) { return Err("Unsupported terminal stream protocol".into()); }
    Ok(Some(crate::terminal_stream::from_io(stream)))
}

async fn exchange_at(endpoint: &str, request: &Request) -> Result<Response, String> {
    let mut stream = connect_at(endpoint).await?;
    let bytes = serde_json::to_vec(request).map_err(|e| e.to_string())?;
    let reply=tokio::time::timeout(request_timeout(request), async {
        wire::write_frame(&mut stream,&bytes,wire::MAX_REQUEST).await?;
        wire::read_frame(&mut stream,wire::MAX_RESPONSE).await
    }).await.map_err(|_|"Yougori control request timed out. The outcome may be unknown; inspect jobs and state before repeating a mutation.")?.map_err(|e|format!("Yougori connection ended: {e}. Inspect jobs/state before repeating a mutation."))?;
    let response: Response =
        serde_json::from_slice(&reply).map_err(|_| "Invalid Yougori control response")?;
    Ok(response)
}

fn engine_error(method: &str, error: String) -> String {
    if error.starts_with(&format!("Unknown method '{method}'.")) && crate::catalog::find(method).is_ok() {
        return format!("The running Yougori engine does not support {method}, but this CLI does. Restart Yougori to load the updated engine: `yougori app quit --yes`, then `yougori app start`. Quitting stops running environments and disconnects sessions. If this continues after restarting, update both the CLI and engine.");
    }
    error
}
fn request_timeout(request: &Request) -> Duration {
    // Terminal calls can include guest startup plus a 25-second guest request.
    // Keep their I/O independent of the mutation queue without timing out mid-write.
    // ARM64 hosts can spend ten minutes booting the emulated x86 guest.
    // Leave time for the subsequent guest request too, rather than abandoning
    // a terminal mutation while the engine is still preparing its guest.
    let guest_timeout = Duration::from_secs(if cfg!(target_arch = "aarch64") { 660 } else { 180 });
    match request.method.as_str() {
        "terminal_action" => guest_timeout,
        "list_environment_services"
        | "model_status"
        | "model_api_status"
        | "get_storage_allocation"
        | "vault_summary"
        | "market_status" => guest_timeout,
        "jobs_get" => {
            Duration::from_millis(20_000 + request.params["wait"].as_u64().unwrap_or(0).min(30_000))
        }
        _ => Duration::from_secs(20),
    }
}
pub async fn call(request: &Request) -> Result<Value, String> {
    call_at(&wire::endpoint().map_err(|e| e.to_string())?, request).await
}
pub fn request(method: &str, params: Value) -> Request {
    Request {
        version: wire::VERSION,
        method: method.into(),
        params,
        confirmed: false,
        dry_run: false,
    }
}

pub async fn wait_job_at(endpoint: &str, id: &str, seconds: u64) -> Result<Value, String> {
    wait_job_observed(endpoint, id, seconds, 5000, |_| {}).await
}

/// Observe measured job progress without changing the job result or timeout semantics.
/// Engines without measurements still work, with an indeterminate display.
pub async fn wait_job_with_progress(id: &str, seconds: u64, progress: impl FnMut(&Value)) -> Result<Value, String> {
    wait_job_observed(&wire::endpoint().map_err(|e| e.to_string())?, id, seconds, 250, progress).await
}

async fn wait_job_observed(endpoint: &str, id: &str, seconds: u64, wait: u64, mut progress: impl FnMut(&Value)) -> Result<Value, String> {
    let started = Instant::now();
    let mut last_progress = Instant::now();
    // The engine long-polls, answering the moment the job ends. An older engine rejects
    // `wait`; then poll quickly at first and back off, instead of a fixed half second.
    let mut long_poll = true;
    let mut pause = Duration::from_millis(10);
    loop {
        let job = if long_poll {
            match call_at(
                endpoint,
                &request("jobs_get", json!({"jobId":id,"wait":wait})),
            )
            .await
            {
                Err(error) if error.contains("Unknown parameter 'wait'") => {
                    long_poll = false;
                    continue;
                }
                other => other,
            }
        } else {
            call_at(endpoint, &request("jobs_get", json!({"jobId":id}))).await
        }
        .map_err(|e| format!("{e} Accepted job: {id}."))?;
        if let Some(measurement) = job.get("progress").filter(|v| !v.is_null()) {
            progress(measurement);
        }
        match job["status"].as_str() {
            Some("complete") => return Ok(job["result"].clone()),
            Some("failed" | "cancelled" | "interrupted") => {
                let error = format!(
                    "{}: {} (job {id})",
                    job["method"].as_str().unwrap_or("Operation"),
                    job["error"].as_str().unwrap_or("Operation failed")
                );
                let details = serde_json::from_value::<wire::ErrorDetails>(job["errorDetails"].clone()).unwrap_or_else(|_| {
                    let mut details = wire::ErrorDetails::from_message(&error);
                    details.affected_resource = Some(format!("job:{id}"));
                    if let Some(outcome) = job["outcome"].as_str() { details.outcome = outcome.into(); }
                    else if job["status"] == "cancelled" { details.code = "operation_cancelled".into(); details.outcome = "cancelled".into(); }
                    else if job["status"] == "interrupted" { details.code = "operation_interrupted".into(); details.outcome = "reconciliation_required".into(); }
                    details
                });
                return Err(error_cause(error, details))
            }
            Some("running" | "queued") => {}
            _ => return Err("Invalid job status from Yougori".into()),
        }
        if started.elapsed() >= Duration::from_secs(seconds) {
            return Err(error_cause(format!("Still running: {id}. The operation was NOT cancelled. Check 'yougori jobs get {id}' before retrying."), wire::ErrorDetails {
                code: "job_wait_timeout".into(), affected_resource: Some(format!("job:{id}")), retryable: false, outcome: "running".into(),
            }));
        }
        if last_progress.elapsed() >= Duration::from_secs(5) && !QUIET.load(Ordering::Relaxed) {
            eprintln!(
                "Yougori: {} — {}s ({id})",
                job["method"].as_str().unwrap_or("working"),
                started.elapsed().as_secs()
            );
            last_progress = Instant::now();
        }
        if !long_poll {
            tokio::time::sleep(pause).await;
            pause = (pause * 2).min(Duration::from_millis(250));
        }
    }
}
pub async fn wait_job(id: &str, seconds: u64) -> Result<Value, String> {
    wait_job_at(&wire::endpoint().map_err(|e| e.to_string())?, id, seconds).await
}

/// The installed Yougori app executable (or the development build in a checkout).
pub fn desktop_executable(explicit: Option<&str>) -> Result<PathBuf, String> {
    desktop_path(explicit)
}
fn desktop_path(explicit: Option<&str>) -> Result<PathBuf, String> {
    if let Some(path) = explicit
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("YOUGORI_APP").map(PathBuf::from))
        .or_else(|| std::env::var_os("OPENDOCK_APP").map(PathBuf::from))
    {
        if path.is_absolute() && path.is_file() {
            return Ok(path);
        }
        return Err("The Yougori app path must be an existing absolute executable path".into());
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let name = if cfg!(windows) {
        "yougori.exe"
    } else {
        "yougori"
    };
    let parent = exe.parent().ok_or("Cannot locate the CLI directory")?;
    let mut candidates = Vec::new();
    #[cfg(target_os = "linux")]
    candidates.push(PathBuf::from("/usr/bin/yougori-desktop"));
    #[cfg(target_os = "macos")]
    {
        candidates.extend(macos_app_candidates(&exe));
        if let Some(home) = std::env::var_os("HOME") {
            candidates
                .push(PathBuf::from(home).join("Applications/Yougori.app/Contents/MacOS/yougori"));
        }
        candidates.push(PathBuf::from(
            "/Applications/Yougori.app/Contents/MacOS/yougori",
        ));
    }
    if let Some(parent) = parent.parent() {
        candidates.push(parent.join(name));
    }
    candidates.extend([
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../src-tauri/target/debug")
            .join(name),
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../src-tauri/target/release")
            .join(name),
    ]);
    candidates.into_iter().find(|path|path.is_file() && path.canonicalize().ok() != exe.canonicalize().ok()).ok_or_else(||"Cannot find the desktop engine. Use 'app start --app ABSOLUTE_PATH_TO_YOUGORI' or start 'npm run desktop:dev' in the source checkout.".into())
}

#[cfg(any(target_os = "macos", test))]
fn macos_app_candidates(cli: &Path) -> Vec<PathBuf> {
    // Resolve from Resources/cli in a moved or renamed .app, without assuming
    // it was installed in /Applications or requiring a global PATH entry.
    cli.ancestors()
        .filter(|p| p.file_name().is_some_and(|name| name == "Contents"))
        .map(|contents| contents.join("MacOS/yougori"))
        .collect()
}

/// The standalone engine (`yougori-engine`, no desktop app), placed beside the CLI's folder by
/// the engine-only installers, or YOUGORI_ENGINE.
pub fn engine_executable() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("YOUGORI_ENGINE").map(PathBuf::from) {
        return (path.is_absolute() && path.is_file()).then_some(path);
    }
    let name = if cfg!(windows) {
        "yougori-engine.exe"
    } else {
        "yougori-engine"
    };
    // Resolve ~/.local/bin/yougori symlinks to the install folder (macOS reports the link path).
    let exe = std::env::current_exe().ok()?;
    let exe = exe.canonicalize().unwrap_or(exe);
    let mut candidates: Vec<PathBuf> = exe
        .ancestors()
        .skip(1)
        .take(2)
        .map(|folder| folder.join(name))
        .collect();
    candidates.extend(["debug", "release"].map(|profile| {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../engine/target")
            .join(profile)
            .join(name)
    }));
    candidates.into_iter().find(|path| path.is_file())
}

fn launch(executable: &Path, args: &[&str]) -> Result<std::process::Child, String> {
    let mut command = std::process::Command::new(executable);
    command
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
        // Windows passes every inheritable handle to the child. A shell pipe on this process's
        // stdout would then stay open for the engine's lifetime, so `yougori app start | cat`
        // would never finish. Stdio::inherit elsewhere duplicates its own inheritable copies.
        use windows_sys::Win32::{
            Foundation::{SetHandleInformation, HANDLE_FLAG_INHERIT},
            System::Console::{
                GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
            },
        };
        for id in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
            // SAFETY: only clears the inherit flag of this process's own standard handles.
            unsafe {
                let handle = GetStdHandle(id);
                if !handle.is_null() && handle as isize != -1 {
                    SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0);
                }
            }
        }
    }
    command
        .spawn()
        .map_err(|e| format!("Cannot start Yougori: {e}"))
}

async fn wait_for_engine(mut child: std::process::Child) -> Result<Value, String> {
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        if let Ok(status) = call(&request("app_status", json!({}))).await {
            return Ok(status);
        }
        if let Some(exit) = child.try_wait().map_err(|e| e.to_string())? {
            return Err(format!("Yougori exited during startup ({exit}). If an older desktop version is already open, close it normally and restart the updated build."));
        }
        if Instant::now() >= deadline {
            return Err("Yougori has not exposed its local control endpoint yet. The process was left running; check the desktop before starting another instance.".into());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

const NOT_INSTALLED: &str = "Cannot find Yougori on this computer. Install it with `irm https://yougori.com/install.ps1 | iex` (Windows) or `curl -fsSL https://yougori.com/install.sh | sh`, or pass --app ABSOLUTE_PATH.";

/// Starts the background engine unless one already runs. The desktop app (in its headless mode)
/// is preferred so its dashboard can open later; the standalone engine is used when the app is
/// not installed, or first with `prefer_engine` / YOUGORI_ENGINE_ONLY=1.
pub async fn start(explicit: Option<&str>) -> Result<Value, String> {
    start_with(
        explicit,
        std::env::var("YOUGORI_ENGINE_ONLY").is_ok_and(|v| v == "1"),
    )
    .await
}

pub async fn start_with(explicit: Option<&str>, prefer_engine: bool) -> Result<Value, String> {
    if let Ok(status) = call(&request("app_status", json!({}))).await {
        return Ok(status);
    }
    let executable = if explicit.is_some() {
        desktop_path(explicit)?
    } else if prefer_engine {
        engine_executable().ok_or("The standalone engine (yougori-engine) is not installed. Reinstall with YOUGORI_ENGINE_ONLY=1, or set YOUGORI_ENGINE.")?
    } else {
        desktop_path(None)
            .ok()
            .or_else(engine_executable)
            .ok_or(NOT_INSTALLED)?
    };
    wait_for_engine(launch(&executable, &["--headless"])?).await
}

/// Opens the dashboard. A standalone engine has none: with nothing running it steps aside and
/// the desktop app starts in its place, keeping every environment and setting.
pub async fn show() -> Result<Value, String> {
    let mut show = request("app_show", json!({}));
    show.confirmed = true;
    let desktop = desktop_path(None).ok();
    let no_app = "This computer runs the Yougori engine without the desktop app, so there is no dashboard. Install the app for one, or keep using the CLI.";
    match call(&request("app_status", json!({}))).await {
        Ok(status) if status["engineOnly"] != true => call(&show).await,
        Ok(_) => {
            let desktop = desktop.ok_or(no_app)?;
            let result = call(&show).await?;
            if result["handover"] != true {
                return Ok(result);
            }
            let deadline = Instant::now() + Duration::from_secs(90);
            while call(&request("app_status", json!({}))).await.is_ok() {
                if Instant::now() >= deadline {
                    return Err("The background engine did not stop in time; run `yougori app quit`, then `yougori app show`.".into());
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            wait_for_engine(launch(&desktop, &[])?).await?;
            Ok(json!({"visible": true, "handover": true}))
        }
        Err(_) => {
            wait_for_engine(launch(&desktop.ok_or(no_app)?, &[])?).await?;
            Ok(json!({"visible": true}))
        }
    }
}

/// Requests a graceful shutdown and waits until the control endpoint is gone.
/// Returning on the acknowledgement alone lets an immediate desktop launch
/// attach to the process that is still shutting down.
/// Only called after the command line was confirmed with --yes.
pub async fn quit() -> Result<Value, String> {
    let mut quit = request("app_quit", json!({}));
    quit.confirmed = true;
    let result = call(&quit).await?;
    let pid = result["enginePid"].as_u64().filter(|pid| *pid > 0 && *pid <= u32::MAX as u64).map(|pid| pid as u32);
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let endpoint_available = matches!(tokio::time::timeout(Duration::from_secs(2),call(&request("app_status", json!({})))).await,Ok(Ok(_)));
        let present = pid.and_then(process_present);
        if present == Some(false) || (!endpoint_available && present.is_none()) {
            return Ok(shutdown_receipt_result(result, present == Some(false), endpoint_available).await);
        }
        if Instant::now() >= deadline {
            return Err(error_cause("Yougori accepted shutdown, but its owned process did not stop within 90 seconds. Inspect the persisted shutdown report before retrying.".into(),wire::ErrorDetails{code:"shutdown_deadline".into(),affected_resource:None,retryable:false,outcome:"requires_reconciliation".into()}));
        }
    }
}

async fn bounded_receipt(work: impl FnOnce() -> Value + Send + 'static, timeout: Duration) -> Option<Value> {
    let (sender, receiver) = tokio::sync::oneshot::channel();
    // A blocked filesystem read must not become a Tokio blocking worker whose
    // runtime destructor waits indefinitely after the CLI's deadline expires.
    let worker = std::thread::Builder::new().name("yougori-shutdown-receipt".into()).spawn(move || { let _ = sender.send(work()); }).ok()?;
    drop(worker);
    tokio::time::timeout(timeout, receiver).await.ok()?.ok()
}

async fn shutdown_receipt_result(acknowledgement: Value, stopped_verified: bool, endpoint_available: bool) -> Value {
    let original=acknowledgement.clone();
    if let Some(result)=bounded_receipt(move||shutdown_result(acknowledgement,stopped_verified,endpoint_available),Duration::from_secs(2)).await { return result; }
    let mut result=original;
    result["engineStopped"] = if stopped_verified {json!(true)} else {Value::Null};
    result["controlEndpointAvailable"] = json!(endpoint_available);
    result["requiresReconciliation"] = json!(true);
    result["cleanupOutcome"] = json!("unverified");
    result["recoveryAction"] = json!("The shutdown receipt could not be read within two seconds. Inspect it or the next native startup report; guest cleanup remains unverified.");
    result
}

fn shutdown_result(mut acknowledgement: Value, stopped_verified: bool, endpoint_available: bool) -> Value {
    acknowledgement["engineStopped"] = if stopped_verified { json!(true) } else { Value::Null };
    acknowledgement["controlEndpointAvailable"] = json!(endpoint_available);
    let report = acknowledgement["shutdownReportPath"].as_str().zip(acknowledgement["shutdownRunId"].as_str()).and_then(|(path,id)| {
        let metadata = std::fs::symlink_metadata(path).ok()?;
        if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 65536 { return None; }
        use std::io::Read;
        let mut bytes=Vec::new();
        std::fs::File::open(path).ok()?.take(65537).read_to_end(&mut bytes).ok()?;
        if bytes.len()>65536 {return None;}
        let report:Value = serde_json::from_slice(&bytes).ok()?;
        (report["shutdownRunId"].as_str() == Some(id) && report["requiresReconciliation"].is_boolean() && report["stages"].is_array()).then_some(report)
    });
    if let Some(report) = report {
        acknowledgement["requiresReconciliation"] = json!(!stopped_verified || report["requiresReconciliation"] == true);
        acknowledgement["cleanupOutcome"] = json!(if report["requiresReconciliation"] == true {"incomplete"} else {"verified"});
        acknowledgement["shutdownReport"] = report;
    } else {
        acknowledgement["requiresReconciliation"] = json!(true);
        acknowledgement["cleanupOutcome"] = json!("unverified");
        acknowledgement["recoveryAction"] = json!("Inspect the shutdown report or the next native startup report; endpoint closure alone does not verify that environments stopped.");
    }
    acknowledgement
}

#[cfg(windows)]
fn process_present(pid: u32) -> Option<bool> {
    use windows_sys::Win32::{Foundation::{CloseHandle,GetLastError},System::Threading::{OpenProcess,GetExitCodeProcess,PROCESS_QUERY_LIMITED_INFORMATION}};
    unsafe {
        let process=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,0,pid);
        if process.is_null() { return match GetLastError() { 87|1168 => Some(false), _ => None }; }
        let mut code=0;
        let ok=GetExitCodeProcess(process,&mut code);
        CloseHandle(process);
        if ok==0 {None} else {Some(code==259)}
    }
}
#[cfg(unix)]
fn process_present(pid: u32) -> Option<bool> {
    if pid > i32::MAX as u32 { return None; }
    let result=unsafe {libc::kill(pid as i32,0)};
    if result==0 {
        #[cfg(target_os="linux")]
        if std::fs::read_to_string(format!("/proc/{pid}/stat")).ok().and_then(|text|text.rsplit_once(") ").map(|(_,tail)|tail.starts_with('Z')))==Some(true) {return Some(false);}
        Some(true)
    } else {match std::io::Error::last_os_error().raw_os_error() {Some(libc::ESRCH)=>Some(false),Some(libc::EPERM)=>Some(true),_=>None}}
}

#[cfg(test)]
mod macos_path_tests {
    use super::*;
    #[tokio::test]
    async fn a_stalled_receipt_does_not_block_cli_runtime_shutdown() {
        let begin=Instant::now();
        let result=bounded_receipt(||{std::thread::sleep(Duration::from_millis(300));json!({"late":true})},Duration::from_millis(30)).await;
        assert!(result.is_none());
        assert!(begin.elapsed()<Duration::from_millis(200));
    }
    #[test]
    fn shutdown_receipt_preserves_incomplete_cleanup_and_rejects_stale_reports() {
        let folder=tempfile::tempdir().unwrap();let path=folder.path().join("shutdown.json");
        std::fs::write(&path,json!({"shutdownRunId":"current","requiresReconciliation":true,"stages":[{"stage":"owned_runtimes","status":"deadline_exceeded"}]}).to_string()).unwrap();
        let result=shutdown_result(json!({"shutdownRequested":true,"shutdownReportPath":path,"shutdownRunId":"current"}),true,false);
        assert_eq!(result["engineStopped"],true);assert_eq!(result["requiresReconciliation"],true);assert_eq!(result["cleanupOutcome"],"incomplete");
        assert_eq!(result["shutdownReport"]["stages"][0]["status"],"deadline_exceeded");
        let stale=shutdown_result(json!({"shutdownRequested":true,"shutdownReportPath":path,"shutdownRunId":"another-instance"}),true,false);
        assert_eq!(stale["cleanupOutcome"],"unverified");assert_eq!(stale["requiresReconciliation"],true);assert!(stale["shutdownReport"].is_null());
    }
    #[test]
    fn endpoint_closure_without_an_owned_process_or_receipt_does_not_verify_shutdown() {
        let result=shutdown_result(json!({"shutdownRequested":true}),false,false);
        assert!(result["engineStopped"].is_null());assert!(result["stopped"].is_null());
        assert_eq!(result["cleanupOutcome"],"unverified");assert_eq!(result["requiresReconciliation"],true);
        assert_eq!(process_present(std::process::id()),Some(true));
    }
    #[test]
    fn owned_process_liveness_distinguishes_exit_from_endpoint_closure() {
        #[cfg(windows)]
        let mut command = {
            use std::os::windows::process::CommandExt;
            let mut command = std::process::Command::new("powershell.exe");
            command.args(["-NoProfile", "-NonInteractive", "-Command", "Start-Sleep -Seconds 20"]).creation_flags(0x08000000);
            command
        };
        #[cfg(unix)]
        let mut command = {
            let mut command = std::process::Command::new("sleep");
            command.arg("20");
            command
        };
        let mut child = command.stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn().unwrap();
        let pid = child.id();
        let alive = process_present(pid);
        child.kill().unwrap();
        child.wait().unwrap();
        assert_eq!(alive, Some(true));
        assert_eq!(process_present(pid), Some(false));
    }
    #[test]
    fn shutdown_requires_the_current_receipt_and_confirmed_engine_exit() {
        let folder=tempfile::tempdir().unwrap();let path=folder.path().join("shutdown.json");
        std::fs::write(&path,json!({"shutdownRunId":"current","requiresReconciliation":false,"stages":[]}).to_string()).unwrap();
        let result=shutdown_result(json!({"shutdownReportPath":path,"shutdownRunId":"current"}),true,false);
        assert_eq!(result["cleanupOutcome"],"verified");assert_eq!(result["requiresReconciliation"],false);
        let unknown=shutdown_result(json!({"shutdownReportPath":path,"shutdownRunId":"current"}),false,false);
        assert_eq!(unknown["requiresReconciliation"],true);assert!(unknown["engineStopped"].is_null());
    }
    fn resource_details() -> wire::ErrorDetails {
        wire::ErrorDetails { code: "transfer_inactive".into(), affected_resource: Some("environment:fixture".into()), retryable: false, outcome: "partial_copy_retained".into() }
    }
    #[cfg(windows)]
    #[tokio::test]
    async fn malformed_identity_results_return_errors_without_panicking() {
        use tokio::net::windows::named_pipe::ServerOptions;
        for (index, result) in [json!(null), json!("unexpected"), json!(42), json!([])].into_iter().enumerate() {
            let endpoint = format!("{}-invalid-identity-{}-{index}", wire::endpoint().unwrap(), std::process::id());
            let mut server = ServerOptions::new().first_pipe_instance(true).create(&endpoint).unwrap();
            let worker = tokio::spawn(async move {
                server.connect().await.unwrap();
                wire::read_frame(&mut server, wire::MAX_REQUEST).await.unwrap();
                wire::write_frame(&mut server, &serde_json::to_vec(&Response::success(result)).unwrap(), wire::MAX_RESPONSE).await.unwrap();
                let mut ack = [0];
                let _ = tokio::io::AsyncReadExt::read(&mut server, &mut ack).await;
            });
            let error = engine_identity_at(&endpoint).await.unwrap_err();
            assert_eq!(error, "Invalid Yougori engine identity response");
            worker.await.unwrap();
        }
    }
    #[cfg(windows)]
    #[tokio::test]
    async fn legacy_engine_identity_is_inspectable_but_mutations_never_retry_old_protocol() {
        use tokio::net::windows::named_pipe::ServerOptions;
        let endpoint = format!("{}-legacy-identity-{}", wire::endpoint().unwrap(), std::process::id());
        let mut server = ServerOptions::new().first_pipe_instance(true).create(&endpoint).unwrap();
        let address = endpoint.clone();
        let worker = tokio::spawn(async move {
            for index in 0..3 {
                server.connect().await.unwrap();
                let req: Request = serde_json::from_slice(&wire::read_frame(&mut server,wire::MAX_REQUEST).await.unwrap()).unwrap();
                assert_eq!(req.version, if index == 1 { 1 } else { wire::VERSION });
                assert_eq!(req.method, if index == 2 { "set_environment_status" } else { "app_status" });
                let mut reply = if index == 1 { Response::success(json!({"version":"1.0.4","engineOnly":true})) } else { Response::failure("Update CLI and engine together") };
                reply.version = 1;
                let next = if index < 2 { Some(ServerOptions::new().create(&address).unwrap()) } else { None };
                wire::write_frame(&mut server,&serde_json::to_vec(&reply).unwrap(),wire::MAX_RESPONSE).await.unwrap();
                let mut ack = [0]; let _ = tokio::io::AsyncReadExt::read(&mut server,&mut ack).await;
                if let Some(next) = next { server = next; }
            }
        });
        let identity = engine_identity_at(&endpoint).await.unwrap();
        assert_eq!(identity["version"],"1.0.4"); assert_eq!(identity["protocolVersion"],1); assert_eq!(identity["protocolCompatible"],false);
        let error = call_at(&endpoint,&request("set_environment_status",json!({}))).await.unwrap_err();
        assert!(error.contains("protocol mismatch"));
        worker.await.unwrap();
    }
    #[tokio::test]
    async fn structured_cause_is_command_scoped_and_not_reused_for_unrelated_errors() {
        let response = capture_errors::<()>(async {
            let _swallowed = error_cause("A transfer failed".into(), resource_details());
            Err("Usage: an unrelated local command".into())
        }).await.unwrap_err();
        assert_eq!(response.error_details.unwrap().code, "invalid_request");
        let response = capture_errors::<()>(async {
            let _swallowed = error_cause("A transfer failed".into(), resource_details());
            clear_error_cause(); // A subsequent successful call clears earlier failures.
            Err("A transfer failed".into())
        }).await.unwrap_err();
        assert_eq!(response.error_details.unwrap().code, "operation_failed");
        let first = capture_errors::<()>(async { Err(error_cause("A transfer failed".into(), resource_details())) }).await.unwrap_err();
        assert_eq!(first.error_details.unwrap().outcome, "partial_copy_retained");
        let second = capture_errors::<()>(async { Err("A transfer failed".into()) }).await.unwrap_err();
        assert_eq!(second.error_details.unwrap().outcome, "failed");
    }
    #[cfg(windows)]
    #[tokio::test]
    async fn engine_and_job_machine_errors_survive_cli_context_without_reclassification() {
        use tokio::net::windows::named_pipe::ServerOptions;
        for mode in ["engine", "job", "cancelled", "interrupted", "wait_timeout"] {
            let endpoint = format!("{}-structured-error-{}-{mode}", wire::endpoint().unwrap(), std::process::id());
            let mut server = ServerOptions::new().first_pipe_instance(true).create(&endpoint).unwrap();
            let details = resource_details();
            let response = match mode {
                "engine" => Response::failure_with_details("Press Stop to reconcile", details.clone()),
                "job" => Response::success(json!({"status":"failed","method":"copy_files_to_environment","error":"Press Stop to reconcile","outcome":"partial_copy_retained","errorDetails":details})),
                "cancelled" | "interrupted" => Response::success(json!({"status":mode,"method":"copy_files_to_environment","error":"Guest staging remains"})),
                _ => Response::success(json!({"status":"running","method":"copy_files_to_environment"})),
            };
            let worker = tokio::spawn(async move {
                server.connect().await.unwrap();
                wire::read_frame(&mut server, wire::MAX_REQUEST).await.unwrap();
                wire::write_frame(&mut server, &serde_json::to_vec(&response).unwrap(), wire::MAX_RESPONSE).await.unwrap();
                let mut ack = [0];
                let _ = tokio::io::AsyncReadExt::read(&mut server, &mut ack).await;
            });
            let result = capture_errors::<Value>(async {
                if mode == "engine" {
                    call_at(&endpoint, &request("copy_files_to_environment",json!({}))).await.map_err(|e| format!("Could not copy: {e}"))
                } else {
                    wait_job_at(&endpoint, "fixture-job", if mode == "wait_timeout" { 0 } else { 5 }).await
                }
            }).await.unwrap_err();
            worker.await.unwrap();
            let actual = result.error_details.unwrap();
            match mode {
                "engine" | "job" => {
                    assert_eq!(actual.code, "transfer_inactive");
                    assert_eq!(actual.affected_resource.as_deref(), Some("environment:fixture"));
                    assert_eq!(actual.outcome, "partial_copy_retained");
                    assert!(!actual.retryable);
                }
                "cancelled" => assert_eq!(actual.outcome, "cancelled"),
                "interrupted" => assert_eq!(actual.outcome, "reconciliation_required"),
                _ => { assert_eq!(actual.code, "job_wait_timeout"); assert_eq!(actual.outcome, "running"); assert_eq!(actual.affected_resource.as_deref(), Some("job:fixture-job")); },
            }
        }
    }
    #[cfg(windows)]
    #[tokio::test]
    async fn copy_progress_crosses_job_transport_and_older_engines_still_work() {
        use tokio::net::windows::named_pipe::ServerOptions;
        use crate::wire::Response;
        for mode in ["measured", "old", "failed"] {
            let endpoint = format!("{}-copy-progress-{}-{mode}", wire::endpoint().unwrap(), std::process::id());
            let mut server = ServerOptions::new().first_pipe_instance(true).create(&endpoint).unwrap();
            let responses = match mode {
                "measured" => vec![
                    Response::success(json!({"status":"queued"})),
                    Response::success(json!({"status":"running","progress":{"phase":"copying","completedBytes":45,"totalBytes":100}})),
                    Response::success(json!({"status":"complete","progress":{"phase":"finishing","completedBytes":100,"totalBytes":100},"result":{"destination":"/copied"}})),
                ],
                "old" => vec![
                    Response::failure("Unknown parameter 'wait'"),
                    Response::success(json!({"status":"running"})),
                    Response::success(json!({"status":"complete","result":{"destination":"/copied"}})),
                ],
                _ => vec![Response::success(json!({"status":"failed","method":"copy_files_to_environment","error":"Disk full"}))],
            };
            let count = responses.len();
            let address = endpoint.clone();
            let worker = tokio::spawn(async move {
                for (index, response) in responses.into_iter().enumerate() {
                    server.connect().await.unwrap();
                    let bytes = wire::read_frame(&mut server, wire::MAX_REQUEST).await.unwrap();
                    let req: Request = serde_json::from_slice(&bytes).unwrap();
                    assert_eq!(req.method, "jobs_get");
                    assert_eq!(req.params["jobId"], "copy-test");
                    if mode != "old" || index == 0 { assert_eq!(req.params["wait"], 250); }
                    else { assert!(req.params.get("wait").is_none()); }
                    // Reserve the next instance before the client can make its next poll.
                    let next = if index + 1 < count { Some(ServerOptions::new().create(&address).unwrap()) } else { None };
                    wire::write_frame(&mut server, &serde_json::to_vec(&response).unwrap(), wire::MAX_RESPONSE).await.unwrap();
                    let mut ack = [0];
                    let _ = tokio::io::AsyncReadExt::read(&mut server, &mut ack).await;
                    if let Some(next) = next { server = next; }
                }
            });
            let mut observed = Vec::new();
            let result = tokio::time::timeout(Duration::from_secs(10), wait_job_observed(&endpoint, "copy-test", 5, 250, |progress| observed.push(progress.clone()))).await.unwrap();
            worker.await.unwrap();
            if mode == "failed" {
                assert!(result.unwrap_err().contains("Disk full (job copy-test)"));
            } else { assert_eq!(result.unwrap()["destination"], "/copied"); }
            if mode == "measured" {
                assert_eq!(observed.len(), 2);
                assert_eq!(observed[0]["completedBytes"], 45);
                assert_eq!(observed[1]["phase"], "finishing");
            } else { assert!(observed.is_empty()); }
        }
    }
    #[test]
    fn outdated_engine_errors_explain_restart_without_retrying_requests() {
        let error = engine_error("runpod_status", "Unknown method 'runpod_status'. Run yougori schema.".into());
        assert!(error.contains("yougori app quit --yes"));
        assert!(error.contains("Quitting stops running environments"));
        let unknown = "Unknown method 'typo'. Run yougori schema.";
        assert_eq!(engine_error("typo", unknown.into()), unknown);
        assert_eq!(engine_error("runpod_status", "Account unavailable".into()), "Account unavailable");
    }
    #[test]
    fn timeout_covers_long_poll_and_guest_requests() {
        assert_eq!(
            request_timeout(&request("jobs_get", json!({"wait":30000}))),
            Duration::from_secs(50)
        );
        assert_eq!(
            request_timeout(&request("jobs_get", json!({"wait":u64::MAX}))),
            Duration::from_secs(50)
        );
        assert!(
            request_timeout(&request("terminal_action", json!({"action":"write"})))
                > Duration::from_secs(25)
        );
    }
    #[test]
    fn finds_engine_in_relocated_bundle_with_spaces() {
        assert_eq!(
            macos_app_candidates(Path::new(
                "/Users/test/My Apps/Renamed.app/Contents/Resources/cli/yougori-cli"
            )),
            vec![PathBuf::from(
                "/Users/test/My Apps/Renamed.app/Contents/MacOS/yougori"
            )]
        );
        assert!(macos_app_candidates(Path::new("/usr/bin/yougori-cli")).is_empty());
    }
}
