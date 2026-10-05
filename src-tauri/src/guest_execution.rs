//! Non-interactive guest jobs use short launch/read/cancel requests. Output is
//! bounded independently of process success, and cancellation is forwarded to
//! the selected guest process group rather than stopping its environment.
use crate::{
    models::{Environment, EnvironmentKind, EnvironmentStatus, RuntimeProviderKind},
    runtime::RuntimeManager,
    store::PlatformStore,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::Duration;
use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
};
use tauri::State;
use tokio_util::sync::CancellationToken;
mod output;
pub(crate) fn mask_protected_text(
    text: &str,
    secrets: &[String],
    withhold_partial: bool,
) -> String {
    output::mask_text(text, secrets, withhold_partial)
}

type ActiveJobs = HashMap<String, HashMap<String, CancellationToken>>;
fn active_jobs() -> &'static Mutex<ActiveJobs> {
    static ACTIVE: OnceLock<Mutex<ActiveJobs>> = OnceLock::new();
    ACTIVE.get_or_init(|| Mutex::new(HashMap::new()))
}
struct ExecutionLease {
    environment_id: String,
    execution_id: String,
}
impl Drop for ExecutionLease {
    fn drop(&mut self) {
        let mut active = active_jobs().lock().unwrap_or_else(|e| e.into_inner());
        if let Some(items) = active.get_mut(&self.environment_id) {
            items.remove(&self.execution_id);
            if items.is_empty() {
                active.remove(&self.environment_id);
            }
        }
    }
}
fn register_execution(
    environment_id: &str,
    execution_id: &str,
    cancellation: CancellationToken,
) -> ExecutionLease {
    active_jobs()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .entry(environment_id.into())
        .or_default()
        .insert(execution_id.into(), cancellation);
    ExecutionLease {
        environment_id: environment_id.into(),
        execution_id: execution_id.into(),
    }
}
pub(crate) fn cancel_environment_jobs(environment_id: &str) -> usize {
    let active = active_jobs().lock().unwrap_or_else(|e| e.into_inner());
    let Some(items) = active.get(environment_id) else {
        return 0;
    };
    for cancellation in items.values() {
        cancellation.cancel();
    }
    items.len()
}
pub(crate) fn cancel_all_jobs() -> usize {
    let active = active_jobs().lock().unwrap_or_else(|e| e.into_inner());
    let mut count = 0;
    for items in active.values() {
        for cancellation in items.values() {
            cancellation.cancel();
            count += 1;
        }
    }
    count
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct GuestJobRequest {
    pub environment_id: String,
    pub command: String,
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
}

fn selected(store: &PlatformStore, id: &str, require_running: bool) -> Result<Environment, String> {
    let environment = store.environment(&id)?;
    if require_running && environment.status != EnvironmentStatus::Running {
        return Err("The environment is not running".into());
    }
    let container = environment.kind == EnvironmentKind::Container
        && matches!(
            environment.provider,
            None | Some(RuntimeProviderKind::YougoriOci | RuntimeProviderKind::YougoriCuda)
        );
    if crate::peer_sharing::is_shared(&environment)
        || !container && environment.kind != EnvironmentKind::MicroVm
    {
        return Err("Asynchronous execution requires a local OCI/CUDA container or built-in microVM. This target supports only its existing bounded execute_environment_command capability.".into());
    }
    Ok(environment)
}
fn valid_execution_id(id: &str) -> bool {
    id.starts_with("exec-")
        && id.len() <= 128
        && id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
}
fn push_bounded(text: &mut String, extra: &str, limit: usize) -> bool {
    text.push_str(extra);
    if text.len() <= limit {
        return false;
    }
    let mut cut = text.len() - limit;
    while !text.is_char_boundary(cut) {
        cut += 1;
    }
    text.drain(..cut);
    true
}
async fn cancel_bounded(
    runtime: &RuntimeManager,
    environment: &Environment,
    execution_id: &str,
) -> Result<Value, String> {
    tokio::time::timeout(Duration::from_secs(2),runtime.workspace_request(environment,"/v1/exec/cancel",json!({"id":environment.runtime_id.as_deref().unwrap_or(&environment.id),"executionId":execution_id}))).await
        .map_err(|_|"Guest cancellation acknowledgement timed out; inspect its retained execution state".to_owned())?
}
async fn protected_output(
    runtime: &RuntimeManager,
    environment: &Environment,
    execution_id: &str,
    stdout_cursor: u64,
    stderr_cursor: u64,
    limit: u64,
    secrets: &[String],
) -> Result<Value, String> {
    output::read_with(stdout_cursor,stderr_cursor,limit,secrets,|out,err|runtime.workspace_request(environment,"/v1/exec/read",json!({"id":environment.runtime_id.as_deref().unwrap_or(&environment.id),"executionId":execution_id,"stdoutCursor":out,"stderrCursor":err,"limit":65536}))).await
}
fn cancellation_outcome(id: &str, result: Result<Value, String>) -> String {
    match result{
        Ok(v) if v["done"]==true=>format!("YOUGORI_OPERATION_CANCELLED:Guest execution cancelled; output retained as {id}"),
        Ok(_)=>format!("YOUGORI_OPERATION_INTERRUPTED:Guest execution cancellation pending; inspect {id} before repeating"),
        Err(e)=>format!("YOUGORI_OPERATION_INTERRUPTED:Guest execution cancellation outcome unknown; inspect {id}: {e}"),
    }
}
fn completed_before_cancellation(result: &Result<Value, String>) -> bool {
    result.as_ref().is_ok_and(|value| {
        value["done"] == true && value["cancelled"] == false && value["outcome"] == "complete"
    })
}

#[tauri::command]
pub(crate) async fn execute_guest_job(
    request: GuestJobRequest,
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
) -> Result<Value, String> {
    if request.command.trim().is_empty() || request.command.len() > 32768 {
        return Err("Command must be between 1 and 32768 characters".into());
    }
    let timeout = request.timeout_seconds.unwrap_or(86400);
    if !(1..=604800).contains(&timeout) {
        return Err("Guest execution timeout must be 1–604800 seconds".into());
    }
    let environment = selected(&store, &request.environment_id, true)?;
    let secrets = crate::workspace::bound_secret_values(&environment, &runtime)?;
    let operation = crate::automation::context::current();
    let execution_id = operation
        .as_ref()
        .map(|op| format!("exec-{}", op.id))
        .unwrap_or_else(|| format!("exec-{}", uuid::Uuid::new_v4()));
    let cancellation = operation
        .as_ref()
        .map(|op| op.cancellation.child_token())
        .unwrap_or_default();
    let _lease = register_execution(&environment.id, &execution_id, cancellation.clone());
    let mut cancellation_raced_completion = false;
    let id = environment.runtime_id.as_deref().unwrap_or(&environment.id);
    let start=runtime.workspace_request(&environment,"/v1/exec/start",json!({"id":id,"executionId":execution_id,"command":request.command,"timeoutSeconds":timeout}));
    tokio::select! {
        result=start=>{result.map_err(|e|format!("YOUGORI_OPERATION_INTERRUPTED:Guest execution submission failed; inspect execution {execution_id} before repeating: {e}"))?;},
        _=cancellation.cancelled()=>{let cancelled=cancel_bounded(&runtime,&environment,&execution_id).await;if completed_before_cancellation(&cancelled){cancellation_raced_completion=true;}else{return Err(cancellation_outcome(&execution_id,cancelled));}}
    }
    crate::automation::context::progress(
        json!({"phase":"executing","completedBytes":0,"executionId":execution_id}),
    );
    let mut out_cursor = 0;
    let mut err_cursor = 0;
    let mut stdout = String::new();
    let mut stderr = String::new();
    let mut truncated = false;
    loop {
        let read = protected_output(
            &runtime,
            &environment,
            &execution_id,
            out_cursor,
            err_cursor,
            65536,
            &secrets,
        );
        let result = tokio::select! {
            value=read=>value,
            _=cancellation.cancelled(),if !cancellation_raced_completion=>{let cancelled=cancel_bounded(&runtime,&environment,&execution_id).await;if completed_before_cancellation(&cancelled){cancellation_raced_completion=true;continue;}else{return Err(cancellation_outcome(&execution_id,cancelled));}}
        };
        let result=result.map_err(|e|format!("YOUGORI_OPERATION_INTERRUPTED:Guest execution outcome unknown; inspect {execution_id} before repeating. Its owner lease expires within 90 seconds if polling cannot resume: {e}"))?;
        out_cursor = result["stdoutCursor"]
            .as_u64()
            .ok_or("Invalid guest stdout cursor")?;
        err_cursor = result["stderrCursor"]
            .as_u64()
            .ok_or("Invalid guest stderr cursor")?;
        truncated |= push_bounded(
            &mut stdout,
            result["stdout"].as_str().unwrap_or(""),
            512 * 1024,
        );
        truncated |= push_bounded(
            &mut stderr,
            result["stderr"].as_str().unwrap_or(""),
            512 * 1024,
        );
        truncated |= result["stdoutTruncated"] == true || result["stderrTruncated"] == true;
        crate::automation::context::progress(
            json!({"phase":if result["done"]==true{"complete"}else{"executing"},"completedBytes":out_cursor.saturating_add(err_cursor),"stdoutBytes":out_cursor,"stderrBytes":err_cursor,"executionId":execution_id}),
        );
        if result["done"] == true
            && out_cursor >= result["stdoutBytes"].as_u64().unwrap_or(out_cursor)
            && err_cursor >= result["stderrBytes"].as_u64().unwrap_or(err_cursor)
        {
            if matches!(result["errorCode"].as_str(),Some("EXECUTION_OUTCOME_UNKNOWN"|"EXECUTION_CANCEL_UNVERIFIED"|"EXECUTION_TIMEOUT_UNVERIFIED")){return Err(format!("YOUGORI_OPERATION_INTERRUPTED: Guest execution ended without a verified outcome or cleanup; inspect retained execution {execution_id}"));}
            return Ok(
                json!({"executionId":execution_id,"environmentId":environment.id,"stdout":stdout,"stderr":stderr,"exitCode":result["exitCode"],"errorCode":result["errorCode"],"stdoutCursor":out_cursor,"stderrCursor":err_cursor,"truncated":truncated,"outputRetentionMinutes":30}),
            );
        }
        if result["done"] != true {
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }
}

#[tauri::command]
pub(crate) async fn guest_execution_output(
    environment_id: String,
    execution_id: String,
    stdout_cursor: Option<u64>,
    stderr_cursor: Option<u64>,
    limit: Option<u64>,
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
) -> Result<Value, String> {
    if !valid_execution_id(&execution_id) {
        return Err("Invalid guest execution ID".into());
    }
    let environment = selected(&store, &environment_id, false)?;
    let secrets = crate::workspace::bound_secret_values(&environment, &runtime)?;
    protected_output(
        &runtime,
        &environment,
        &execution_id,
        stdout_cursor.unwrap_or(0),
        stderr_cursor.unwrap_or(0),
        limit.unwrap_or(65536),
        &secrets,
    )
    .await
}
#[tauri::command]
pub(crate) async fn cancel_guest_execution(
    environment_id: String,
    execution_id: String,
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
) -> Result<Value, String> {
    if !valid_execution_id(&execution_id) {
        return Err("Invalid guest execution ID".into());
    }
    let environment = selected(&store, &environment_id, false)?;
    cancel_bounded(&runtime, &environment, &execution_id).await
}

#[tauri::command]
pub(crate) async fn release_guest_execution(
    environment_id: String,
    execution_id: String,
    store: State<'_, PlatformStore>,
    runtime: State<'_, RuntimeManager>,
) -> Result<Value, String> {
    if !valid_execution_id(&execution_id) {
        return Err("Invalid guest execution ID".into());
    }
    let environment = selected(&store, &environment_id, false)?;
    runtime.workspace_request(&environment,"/v1/exec/release",json!({"id":environment.runtime_id.as_deref().unwrap_or(&environment.id),"executionId":execution_id})).await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn output_truncation_preserves_utf8_and_does_not_fail_execution() {
        let mut text = "small".to_owned();
        assert!(!push_bounded(&mut text, " output", 100));
        assert!(push_bounded(&mut text, &"🦉".repeat(100), 31));
        assert!(text.len() <= 31);
        assert!(std::str::from_utf8(text.as_bytes()).is_ok());
    }
    #[test]
    fn execution_ids_cannot_target_arbitrary_guest_files() {
        assert!(valid_execution_id("exec-job-abc"));
        for id in ["../tmp/pid", "exec-../../pid", "exec-a/b", "", "exec-;kill"] {
            assert!(!valid_execution_id(id));
        }
    }
    #[test]
    fn environment_cancellation_targets_only_its_active_jobs_and_releases_registration() {
        let one = CancellationToken::new();
        let other = CancellationToken::new();
        let first = register_execution("test-exec-one", "exec-one", one.clone());
        let second = register_execution("test-exec-two", "exec-two", other.clone());
        assert_eq!(cancel_environment_jobs("test-exec-one"), 1);
        assert!(one.is_cancelled());
        assert!(!other.is_cancelled());
        drop(first);
        assert_eq!(cancel_environment_jobs("test-exec-one"), 0);
        drop(second);
    }
    #[test]
    fn cancellation_racing_completion_preserves_the_known_execution_outcome() {
        assert!(completed_before_cancellation(&Ok(
            json!({"done":true,"cancelled":false,"outcome":"complete"})
        )));
        assert!(!completed_before_cancellation(&Ok(
            json!({"done":true,"cancelled":true,"outcome":"cancelled"})
        )));
        assert!(!completed_before_cancellation(&Err(
            "transport failed".into()
        )));
    }
}
