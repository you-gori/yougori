use super::{
    context,
    coordinator::{self, Coordinator},
    dispatch,
    journal::Journal,
    CLIENT_LIMIT, HISTORY, RESULT_BUDGET, RESULT_LIMIT,
};
use crate::{store::PlatformStore, AppHandle};
use serde_json::{json, Value};
use std::{
    collections::VecDeque,
    io::Write,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex as StdMutex,
    },
    time::{Duration, Instant},
};
use tauri::{Emitter, Manager};
use tokio::sync::{Mutex, Semaphore};
use tokio_util::sync::CancellationToken;
use yougori_cli::{
    catalog,
    wire::{self, ErrorDetails, Request, Response},
};

pub(super) fn is_control_method(method: &str) -> bool {
    matches!(
        method,
        "app_quit"
            | "app_status"
            | "finish_app_close"
            | "jobs_list"
            | "jobs_cancel"
            | "jobs_result"
            | "cancel_file_transfer"
            | "cancel_guest_execution"
            | "release_guest_execution"
            | "set_environment_status"
            | "restart_environment"
            | "delete_environment"
            | "recover_environment_runtime"
            | "recover_environment_runtime_report"
            | "patch_settings"
            | "update_settings"
            | "get_settings_snapshot"
            | "get_startup_report"
    )
}

fn snapshot_stop_resource<'a>(method: &str, params: &'a Value) -> Option<&'a str> {
    if matches!(method, "restart_environment" | "delete_environment")
        || (method == "set_environment_status" && matches!(params["status"].as_str(), Some("stopped" | "paused")))
    {
        params["environmentId"].as_str()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn successful_large_execution_remains_complete_and_output_is_paged() {
        let mut job = Job {
            id: "job-large".into(),
            ..Job::default()
        };
        job.succeeded(json!({"data":"a".repeat(RESULT_LIMIT+1)}));
        assert_eq!(job.status, "complete");
        assert_eq!(job.value(true)["outcome"], "succeeded");
        assert_eq!(job.value(true)["result"]["executionCompleted"], true);
        let page = job.output.as_ref().unwrap().page(&job.id, 0, 64).unwrap();
        assert_eq!(page["nextCursor"], 64);
        assert_eq!(page["done"], false);
    }
    #[test]
    fn tiny_utf8_pages_advance_without_replacing_a_truncated_code_point() {
        let output = CapturedOutput {
            data: "😀é".as_bytes().to_vec(),
            total: 6,
        };
        let page = output.page("utf8", 0, 1).unwrap();
        assert_eq!(page["data"], "😀");
        assert_eq!(page["nextCursor"], 4);
        let truncated = CapturedOutput {
            data: vec![b'a', 0xf0, 0x9f],
            total: 5,
        };
        let page = truncated.page("utf8", 0, 20).unwrap();
        assert_eq!(page["data"], "a");
        assert_eq!(page["done"], true);
        assert_eq!(page["truncated"], true);
    }
    #[test]
    fn truncated_output_metadata_reports_only_pageable_bytes() {
        let output = CapturedOutput {
            data: vec![b'a', 0xf0, 0x9f],
            total: 5,
        };
        assert_eq!(output.metadata("utf8")["availableBytes"], 1);
        let page = output.page("utf8", 0, 20).unwrap();
        assert_eq!(page["availableBytes"], 1);
        assert_eq!(page["nextCursor"], page["availableBytes"]);
        assert_eq!(output.page("utf8", 1, 20).unwrap()["done"], true);
        let text = "ASCII😀é世";
        for cutoff in 0..=text.len() {
            let bytes = text.as_bytes()[..cutoff].to_vec();
            let available = std::str::from_utf8(&bytes)
                .map(str::len)
                .unwrap_or_else(|error| error.valid_up_to());
            let output = CapturedOutput { data: bytes, total: text.len() as u64 };
            assert_eq!(output.metadata("utf8")["availableBytes"], available);
            let page = output.page("utf8", 0, 65536).unwrap();
            assert_eq!(page["data"], &text[..available]);
            assert_eq!(page["nextCursor"], available);
            assert_eq!(page["done"], true);
        }
    }
    #[tokio::test]
    async fn early_snapshot_interruption_releases_its_environment_for_stop() {
        let coordinator = Coordinator::default();
        let exports = crate::runtime::SnapshotExports::default();
        let keys = vec!["environment:env-snapshot-a".into()];
        let token = CancellationToken::new();
        let owner = coordinator.acquire(&keys, "snapshot", &token, |_, _| {}).await.unwrap();
        let export = exports.begin("env-snapshot-a").unwrap();
        let independent = exports.begin("env-snapshot-b").unwrap();
        for method in ["set_environment_status", "restart_environment", "delete_environment"] {
            assert_eq!(snapshot_stop_resource(method, &json!({"environmentId":"env-snapshot-a","status":"stopped"})), Some("env-snapshot-a"));
        }
        assert!(snapshot_stop_resource("set_environment_status", &json!({"environmentId":"env-snapshot-a","status":"running"})).is_none());
        let interruption = exports.interrupt("env-snapshot-a");
        assert!(export.cancellation.is_cancelled());
        assert!(!independent.cancellation.is_cancelled());
        assert!(exports.begin("env-snapshot-a").is_err());
        let cleanup = async { export.cancellation.cancelled().await; drop(owner); drop(export); };
        let stop = coordinator.acquire(&keys, "stop", &token, |_, _| {});
        let (_, stop) = tokio::time::timeout(Duration::from_millis(100), async { tokio::join!(cleanup, stop) }).await.unwrap();
        drop(stop.unwrap());
        assert!(!independent.cancellation.is_cancelled());
        drop(interruption);
        assert!(exports.begin("env-snapshot-a").is_ok());
    }
    #[test]
    fn snapshot_cancellation_is_available_only_during_export_and_retains_partial_outcome() {
        let (progress, measurement) = tokio::sync::watch::channel(None);
        let mut job = Job { method: "run_backup".into(), status: "running", progress: measurement, ..Job::default() };
        assert!(!job.can_cancel());
        progress.send_replace(Some(json!({"phase":"snapshotExport","cancellable":true})));
        assert!(job.can_cancel());
        assert_eq!(job.value(false)["cancellable"], true);
        progress.send_replace(Some(json!({"phase":"snapshotExportFinished","cancellable":false})));
        assert!(!job.can_cancel());
        job.failed("YOUGORI_OPERATION_CANCELLED: snapshot export interrupted; no snapshot published; originals preserved".into());
        assert_eq!(job.value(false)["status"], "cancelled");
        assert_eq!(job.value(false)["outcome"], "partial");
        assert_eq!(job.value(false)["errorCode"], "operation_cancelled");
    }
    #[test]
    fn job_failure_retains_specific_code_resource_and_unknown_outcome() {
        let mut job = Job {
            resources: vec!["transfer:env-00000000-0000-0000-0000-000000000001".into()],
            ..Job::default()
        };
        job.failed("YOUGORI_TRANSFER_INACTIVE: copy stalled".into());
        assert_eq!(
            job.value(false)["errorDetails"]["code"],
            "transfer_inactive"
        );
        assert_eq!(job.value(false)["outcome"], "partial");
        job.failed("[YOUGORI_DURABLE_STORAGE_MISSING] Restore the saved disk".into());
        assert_eq!(job.value(false)["errorDetails"]["code"], "durable_storage_missing");
        assert_eq!(job.value(false)["outcome"], "not_started");
        assert_eq!(
            job.value(false)["errorDetails"]["affectedResource"],
            "env-00000000-0000-0000-0000-000000000001"
        );
        job.failed("Copy target cancelled/data.txt could not be written".into());
        assert_eq!(job.status, "failed");
        assert_eq!(job.value(false)["outcome"], "failed");
        job.failed("Guest control request timed out; outcome may be unknown".into());
        assert_eq!(job.value(false)["outcome"], "unknown");
        assert_eq!(job.value(false)["errorDetails"]["retryable"], false);
    }
    #[tokio::test]
    async fn saturated_work_has_reserved_control_capacity_and_bounded_shutdown() {
        let directory = tempfile::tempdir().unwrap();
        let store = PlatformStore::load(directory.path().join("state.json")).unwrap();
        let control = Arc::new(Control::new("test-only".into(), true, &store));
        let mut permits = Vec::new();
        for _ in 0..32 {
            permits.push(control.operations.clone().try_acquire_owned().unwrap());
        }
        assert!(control.operations.clone().try_acquire_owned().is_err());
        let stop = control
            .control_operations
            .clone()
            .try_acquire_owned()
            .unwrap();
        assert!(is_control_method("set_environment_status"));
        drop(stop);
        let token = CancellationToken::new();
        control.jobs.lock().await.push_back(Job {
            id: "job-00000000-0000-0000-0000-000000000001".into(),
            method: "copy_files_to_environment".into(),
            status: "running",
            cancellable: true,
            cancellation: token.clone(),
            resources: vec!["transfer:env-00000000-0000-0000-0000-000000000001".into()],
            ..Job::default()
        });
        let start = Instant::now();
        let report = control.prepare_shutdown(Duration::from_millis(40)).await;
        assert!(start.elapsed() < Duration::from_secs(2));
        assert!(token.is_cancelled());
        assert_eq!(report["drained"], false);
        assert_eq!(
            report["remainingJobs"][0]["jobId"],
            "job-00000000-0000-0000-0000-000000000001"
        );
        assert!(
            control.shutdown.child_token().is_cancelled(),
            "A late admitted operation must inherit shutdown cancellation"
        );
        let restored = Control::new("test-only".into(), true, &store);
        let jobs = restored.jobs.lock().await;
        assert_eq!(jobs[0].value(false)["outcome"], "reconciliation_required");
        assert_eq!(
            jobs[0].resources,
            vec!["transfer:env-00000000-0000-0000-0000-000000000001"]
        );
    }
}

pub(super) struct Job {
    pub(super) id: String,
    pub(super) method: String,
    pub(super) status: &'static str,
    pub(super) created: String,
    pub(super) completed: Option<Instant>,
    pub(super) completed_at: Option<String>,
    pub(super) result: Option<Value>,
    pub(super) error: Option<String>,
    pub(super) error_details: Option<ErrorDetails>,
    pub(super) bytes: usize,
    pub(super) progress: tokio::sync::watch::Receiver<Option<Value>>,
    pub(super) started_at: Option<String>,
    pub(super) resources: Vec<String>,
    pub(super) cancellation: CancellationToken,
    pub(super) cancellable: bool,
    pub(super) waiting: Arc<StdMutex<Option<Value>>>,
    pub(super) output: Option<CapturedOutput>,
    pub(super) retained_metadata: Option<Value>,
}
impl Default for Job {
    fn default() -> Self {
        Self {
            id: String::new(),
            method: String::new(),
            status: "queued",
            created: now(),
            completed: None,
            completed_at: None,
            result: None,
            error: None,
            error_details: None,
            bytes: 0,
            progress: tokio::sync::watch::channel(None).1,
            started_at: None,
            resources: Vec::new(),
            cancellation: CancellationToken::new(),
            cancellable: false,
            waiting: Arc::new(StdMutex::new(None)),
            output: None,
            retained_metadata: None,
        }
    }
}
impl Job {
    fn can_cancel(&self) -> bool {
        self.cancellable || (matches!(self.method.as_str(), "create_snapshot" | "run_backup" | "export_local_backup")
            && self.progress.borrow().as_ref().is_some_and(|progress| {
                progress["phase"] == "snapshotExport" && progress["cancellable"] == true
            }))
    }
    fn succeeded(&mut self, value: Value) {
        let mut output = CapturedOutput {
            data: Vec::new(),
            total: 0,
        };
        self.status = "complete";
        if serde_json::to_writer(&mut output, &value).is_ok() {
            if output.total <= RESULT_LIMIT as u64 {
                self.bytes = output.total as usize;
                self.result = Some(value);
            } else {
                self.result =
                    Some(json!({"executionCompleted":true,"output":output.metadata(&self.id)}));
                self.bytes = output.data.len();
                self.output = Some(output);
            }
        } else {
            self.result = Some(json!({"executionCompleted":true,"outputAvailable":false}));
        }
    }
    fn failed(&mut self, error: String) {
        let mut details = ErrorDetails::from_message(&error);
        let cancelled = error.starts_with("YOUGORI_OPERATION_CANCELLED");
        let interrupted = error.starts_with("YOUGORI_OPERATION_INTERRUPTED");
        if !cancelled
            && !interrupted
            && matches!(
                details.code.as_str(),
                "operation_cancelled" | "operation_interrupted"
            )
        {
            details.code = "operation_failed".into();
            details.outcome = "failed".into();
        }
        if error.starts_with("YOUGORI_TRANSFER_INACTIVE") {
            details.code = "transfer_inactive".into();
            details.outcome = "partial".into();
            details.retryable = false;
        } else if error.starts_with("YOUGORI_OPERATION_CANCELLED: snapshot export interrupted;") {
            details.outcome = "partial".into();
            details.retryable = false;
        } else if error.starts_with("YOUGORI_TRANSFER_DEADLINE") {
            details.code = "transfer_deadline".into();
            details.outcome = "partial".into();
            details.retryable = false;
        }
        details.affected_resource = self
            .resources
            .iter()
            .find_map(|resource| {
                ["environment:", "transfer:", "execution:"]
                    .iter()
                    .find_map(|prefix| resource.strip_prefix(prefix))
            })
            .map(str::to_owned);
        self.status = if cancelled {
            "cancelled"
        } else if interrupted {
            "interrupted"
        } else {
            "failed"
        };
        self.error = Some(error);
        self.error_details = Some(details);
    }
    pub(super) fn value(&self, result: bool) -> Value {
        let outcome = self
            .error_details
            .as_ref()
            .map(|details| details.outcome.as_str())
            .unwrap_or_else(|| match self.status {
                "complete" => "succeeded",
                "failed" => "failed",
                "cancelled" => "cancelled",
                "interrupted" => "reconciliation_required",
                _ => "pending",
            });
        let mut value = json!({"jobId":self.id,"method":self.method,"status":self.status,"outcome":outcome,"createdAt":self.created,"startedAt":self.started_at,"completedAt":self.completed_at,"resources":self.resources,"cancellable":self.can_cancel(),"cancelRequested":self.cancellation.is_cancelled()});
        if let Some(progress) = self.progress.borrow().as_ref() {
            value["lastProgressAt"] = progress["lastProgressAt"].clone();
            value["progress"] = progress.clone();
        }
        value["waitingFor"] = self
            .waiting
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .unwrap_or_else(|| {
                self.progress
                    .borrow()
                    .as_ref()
                    .and_then(|progress| progress.get("waitingFor"))
                    .cloned()
                    .unwrap_or(Value::Null)
            });
        if let Some(output) = &self.output {
            value["output"] = output.metadata(&self.id);
        } else if let Some(metadata) = &self.retained_metadata {
            value["output"] = metadata.clone();
            value["output"]["outputAvailable"] = json!(false);
        }
        if self.status == "interrupted" {
            value["errorCode"] = json!("engine_interrupted");
        }
        if self.status == "cancelled" {
            value["errorCode"] = json!("operation_cancelled");
        }
        if self.status == "failed" {
            value["errorCode"] = json!("operation_failed");
        }
        if let Some(details) = &self.error_details {
            value["errorCode"] = json!(details.code);
            value["errorDetails"] = json!(details);
        }
        if result {
            value["result"] = self.result.clone().unwrap_or(Value::Null);
            value["error"] = self.error.clone().map(Value::String).unwrap_or(Value::Null);
        }
        value
    }
    fn restored(value: Value) -> Self {
        let status = match value["status"].as_str() {
            Some("complete") => "complete",
            Some("failed") => "failed",
            Some("cancelled") => "cancelled",
            _ => "interrupted",
        };
        let measurement = value.get("progress").cloned();
        Self {
            id: value["jobId"].as_str().unwrap_or("").into(),
            method: value["method"].as_str().unwrap_or("").into(),
            status,
            created: value["createdAt"].as_str().unwrap_or("").into(),
            started_at: value["startedAt"].as_str().map(str::to_owned),
            completed: Some(Instant::now()),
            completed_at: value["completedAt"].as_str().map(str::to_owned),
            progress: tokio::sync::watch::channel(measurement).1,
            resources: value["resources"]
                .as_array()
                .map(|v| {
                    v.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default(),
            error_details: value
                .get("errorDetails")
                .and_then(|details| serde_json::from_value(details.clone()).ok()),
            retained_metadata: value.get("output").cloned(),
            error: if status == "interrupted" {
                Some("Engine stopped during this operation. Reconcile the affected resource before retrying.".into())
            } else {
                None
            },
            ..Self::default()
        }
    }
}
fn now() -> String {
    chrono::Utc::now().to_rfc3339()
}
pub(super) struct CapturedOutput {
    data: Vec<u8>,
    total: u64,
}
impl Write for CapturedOutput {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.total = self.total.saturating_add(data.len() as u64);
        let available = (32 * 1024 * 1024usize).saturating_sub(self.data.len());
        self.data
            .extend_from_slice(&data[..data.len().min(available)]);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl CapturedOutput {
    fn available_bytes(&self) -> usize {
        // Captured JSON is valid UTF-8 until the byte budget cuts its final
        // character. Inspect only that character so metadata polling does not
        // repeatedly scan a retained 32 MiB result.
        let mut start = self.data.len().saturating_sub(4);
        while start < self.data.len() && self.data[start] & 0xc0 == 0x80 {
            start += 1;
        }
        std::str::from_utf8(&self.data[start..])
            .map(|_| self.data.len())
            .unwrap_or_else(|error| start + error.valid_up_to())
    }
    fn metadata(&self, id: &str) -> Value {
        let available = self.available_bytes();
        json!({"delivery":"paged","resultHandle":id,"totalBytes":self.total,"availableBytes":available,"truncated":self.total>available as u64})
    }
    fn page(&self, id: &str, cursor: usize, limit: usize) -> Result<Value, String> {
        let available = self.available_bytes();
        if cursor > available {
            return Err("Result cursor exceeds retained output".into());
        }
        // A capture limit can split the final code point. Drop that incomplete
        // suffix; retained cursors always refer to the original UTF-8 bytes.
        let text = std::str::from_utf8(&self.data[..available])
            .map_err(|_| "Invalid result encoding")?;
        let mut end = (cursor + limit.clamp(1, 65536)).min(text.len());
        if !text.is_char_boundary(cursor) {
            return Err("Result cursor is not a UTF-8 boundary".into());
        }
        while end > cursor && !text.is_char_boundary(end) {
            end -= 1;
        }
        if end == cursor && cursor < text.len() {
            end = cursor + text[cursor..].chars().next().unwrap().len_utf8();
        }
        Ok(
            json!({"jobId":id,"encoding":"json","data":&text[cursor..end],"cursor":cursor,"nextCursor":end,"totalBytes":self.total,"availableBytes":available,"truncated":self.total>available as u64,"done":end>=text.len()}),
        )
    }
}
pub struct Control {
    pub(super) endpoint: String,
    pub headless: bool,
    pub(super) jobs: Mutex<VecDeque<Job>>,
    coordinator: Coordinator,
    operations: Arc<Semaphore>,
    control_operations: Arc<Semaphore>,
    pub(super) clients: Arc<Semaphore>,
    pub(super) regular_clients: Arc<Semaphore>,
    pub(super) control_clients: Arc<Semaphore>,
    finished: tokio::sync::Notify,
    journal: Arc<Journal>,
    journal_writes: Arc<Mutex<()>>,
    pub(super) quiescing: AtomicBool,
    pub(super) shutdown: CancellationToken,
}
impl Control {
    pub(super) fn new(endpoint: String, headless: bool, store: &PlatformStore) -> Self {
        let journal = Arc::new(Journal::new(&store.data_folder("operations")));
        let jobs = journal
            .load()
            .into_iter()
            .map(Job::restored)
            .filter(|job| !job.id.is_empty())
            .collect();
        Self {
            endpoint,
            headless,
            jobs: Mutex::new(jobs),
            coordinator: Coordinator::default(),
            operations: Arc::new(Semaphore::new(32)),
            control_operations: Arc::new(Semaphore::new(8)),
            clients: Arc::new(Semaphore::new(CLIENT_LIMIT)),
            regular_clients: Arc::new(Semaphore::new(32)),
            control_clients: Arc::new(Semaphore::new(8)),
            finished: tokio::sync::Notify::new(),
            journal,
            journal_writes: Arc::new(Mutex::new(())),
            quiescing: AtomicBool::new(false),
            shutdown: CancellationToken::new(),
        }
    }
    pub(super) fn prune(jobs: &mut VecDeque<Job>) {
        while jobs.len() >= HISTORY {
            let Some(index) = jobs.iter().position(|job| job.completed.is_some()) else {
                break;
            };
            jobs.remove(index);
        }
        while jobs.iter().map(|job| job.bytes).sum::<usize>() > RESULT_BUDGET {
            let Some(job) = jobs
                .iter_mut()
                .find(|job| job.completed.is_some() && job.bytes > 0)
            else {
                break;
            };
            job.retained_metadata = Some(if let Some(output) = &job.output {
                output.metadata(&job.id)
            } else {
                json!({"delivery":"evicted","availableBytes":0,"totalBytes":job.bytes,"outputAvailable":false})
            });
            job.result = None;
            job.output = None;
            job.bytes = 0;
        }
    }
    async fn persist(&self) {
        let write = async {
            let write_guard = self.journal_writes.clone().lock_owned().await;
            let entries = self
                .jobs
                .lock()
                .await
                .iter()
                .map(|job| job.value(false))
                .collect::<Vec<_>>();
            let journal = self.journal.clone();
            tokio::task::spawn_blocking(move || {
                let _write = write_guard;
                journal.save(&entries)
            })
            .await
            .map_err(|_| "journal writer stopped".to_string())?
        };
        if !matches!(
            tokio::time::timeout(Duration::from_secs(2), write).await,
            Ok(Ok(()))
        ) {
            eprintln!("Operation journal was not flushed before its deadline; live outcomes remain available.");
        }
    }
    pub(super) async fn handle(self: &Arc<Self>, app: AppHandle, request: Request) -> Response {
        if request.version == 1 && wire::VERSION != 1 {
            // Shipped v1 clients reject unknown fields, so this mismatch reply
            // deliberately uses their original envelope without errorDetails.
            return Response{version:1,ok:false,result:None,error:Some("CLI/engine protocol mismatch: this engine requires protocol 2. Update the Yougori CLI and engine together before submitting work.".into()),error_details:None};
        }
        let resource = request.params["environmentId"].as_str().map(str::to_owned);
        match self.submit(app, request).await {
            Ok(result) => Response::success(result),
            Err(error) => {
                let mut details = ErrorDetails::from_message(&error);
                details.affected_resource = resource;
                if error.starts_with("YOUGORI_QUIESCING") {
                    details.code = "engine_shutting_down".into();
                    details.retryable = true;
                    details.outcome = "not_started".into();
                } else if error.starts_with("YOUGORI_NOT_CANCELLABLE") {
                    details.code = "not_cancellable".into();
                } else if error.starts_with("YOUGORI_JOB_NOT_FOUND") {
                    details.code = "job_not_found".into();
                } else if error.starts_with("YOUGORI_BUSY") {
                    details.code = "operation_lane_busy".into();
                    details.retryable = true;
                    details.outcome = "not_started".into();
                }
                Response::failure_with_details(error, details)
            }
        }
    }
    async fn submit(
        self: &Arc<Self>,
        app: AppHandle,
        mut request: Request,
    ) -> Result<Value, String> {
        if request.version != wire::VERSION {
            return Err("CLI/engine protocol mismatch. Update both components.".into());
        }
        let method = catalog::find(&request.method)?;
        method.validate(&request.params)?;
        dispatch::validate(&request.method, &request.params)?;
        let confirmation = method.confirmation_for(&request.params);
        if request.dry_run {
            return Ok(
                json!({"dryRun":true,"method":method.name,"validSyntax":true,"confirmationRequired":confirmation,"runtimeChecked":false}),
            );
        }
        if !request.confirmed {
            if let Some(reason) = confirmation {
                return Err(format!("{reason} Explicit --yes confirmation is required."));
            }
        }
        match method.name {
            "app_status" => {
                return Ok(
                    json!({"running":true,"version":env!("CARGO_PKG_VERSION"),"protocolVersion":wire::VERSION,"headless":self.headless,"engineOnly":crate::ENGINE_ONLY,"endpoint":self.endpoint,"pid":std::process::id(),"acceptingWork":!self.quiescing.load(Ordering::Acquire),"lastShutdown":crate::shutdown::latest(&app.state::<PlatformStore>())}),
                )
            }
            "jobs_list" => {
                let mut jobs = self.jobs.lock().await;
                Self::prune(&mut jobs);
                return Ok(json!(jobs
                    .iter()
                    .map(|job| job.value(false))
                    .collect::<Vec<_>>()));
            }
            "jobs_cancel" => {
                let mut jobs = self.jobs.lock().await;
                let job = jobs
                    .iter_mut()
                    .find(|job| Some(job.id.as_str()) == request.params["jobId"].as_str())
                    .ok_or("YOUGORI_JOB_NOT_FOUND: operation not found in retained history")?;
                if job.completed.is_none() {
                    if job.status == "running" && !job.can_cancel() {
                        return Err("YOUGORI_NOT_CANCELLABLE: this operation must finish or be reconciled; cancelling its client does not undo its effects".into());
                    }
                    job.cancellation.cancel();
                }
                return Ok(job.value(false));
            }
            "jobs_result" => {
                let jobs = self.jobs.lock().await;
                let job = jobs
                    .iter()
                    .find(|job| Some(job.id.as_str()) == request.params["jobId"].as_str())
                    .ok_or("YOUGORI_JOB_NOT_FOUND: operation not found in retained history")?;
                let cursor = request.params["cursor"].as_u64().unwrap_or(0) as usize;
                let limit = request.params["limit"].as_u64().unwrap_or(16384).min(65536) as usize;
                if let Some(output) = &job.output {
                    return output.page(&job.id, cursor, limit);
                }
                if let Some(result) = &job.result {
                    let data = serde_json::to_vec(result).map_err(|e| e.to_string())?;
                    return CapturedOutput {
                        total: data.len() as u64,
                        data,
                    }
                    .page(&job.id, cursor, limit);
                }
                return Ok(
                    json!({"jobId":job.id,"outcome":job.value(false)["outcome"],"outputAvailable":false,"reason":"Output bodies are bounded and are not retained across engine restarts. Inspect current resource state; do not repeat a completed operation."}),
                );
            }
            "jobs_get" => {
                let deadline = tokio::time::Instant::now()
                    + Duration::from_millis(
                        request.params["wait"].as_u64().unwrap_or(0).min(30000),
                    );
                loop {
                    let changed = self.finished.notified();
                    tokio::pin!(changed);
                    changed.as_mut().enable();
                    {
                        let jobs = self.jobs.lock().await;
                        let job = jobs
                            .iter()
                            .find(|job| Some(job.id.as_str()) == request.params["jobId"].as_str())
                            .ok_or(
                                "YOUGORI_JOB_NOT_FOUND: operation not found in retained history",
                            )?;
                        if job.completed.is_some() || tokio::time::Instant::now() >= deadline {
                            return Ok(job.value(true));
                        }
                    }
                    let _ = tokio::time::timeout_at(deadline, changed).await;
                }
            }
            "app_quit" => {
                self.quiescing.store(true, Ordering::Release);
                self.shutdown.cancel();
                crate::lifecycle::cancel_startup(&app);
                self.cancel_pending(None).await;
                return dispatch::dispatch(&app, method.name, &request.params).await;
            }
            "cancel_file_transfer" => {
                return Ok(crate::file_import::cancel_transfers(
                    request.params["environmentId"]
                        .as_str()
                        .ok_or("Missing environment ID")?,
                    request.params["transferId"].as_str(),
                ))
            }
            _ => {}
        }
        if self.quiescing.load(Ordering::Acquire) {
            return Err(
                "YOUGORI_QUIESCING: engine shutdown has begun; no new operations are accepted"
                    .into(),
            );
        }
        if method.name == "finish_app_close" {
            return dispatch::dispatch(&app, method.name, &request.params).await;
        }
        if matches!(
            method.name,
            "get_platform_state"
                | "list_environment_windows"
                | "terminal_action"
                | "host_terminal_action"
                | "list_environment_downloads"
                | "keep_environment_downloads_alive"
                | "stop_environment_download"
                | "list_environment_services"
                | "list_saved_domains"
                | "model_status"
                | "model_api_status"
                | "get_storage_allocation"
                | "vault_summary"
                | "model_chat_begin"
                | "model_chat_read"
                | "get_startup_report"
                | "get_settings_snapshot"
                | "guest_execution_output"
                | "cancel_guest_execution"
                | "release_guest_execution"
                | "deployment_status"
                | "publication_preflight"
                | "get_environment_health_check"
                | "get_environment_log_window"
                | "market_status"
        ) {
            return dispatch::dispatch(&app, method.name, &request.params).await;
        }
        let lane = if is_control_method(method.name) {
            &self.control_operations
        } else {
            &self.operations
        };
        let permit=lane.clone().try_acquire_owned().map_err(|_|"YOUGORI_BUSY: this operation lane is full. Inspect jobs or cancel queued work; shutdown and cancellation remain independent.")?;
        // Cancel a conflicting export before waiting for its environment lease.
        // Keep the barrier until this lifecycle operation ends so an export
        // still preparing its stream cannot race past the cancellation.
        let snapshot_interruption = if let Some(environment_id) = snapshot_stop_resource(method.name, &request.params) {
            let state = app.state::<PlatformStore>().snapshot()?;
            state.environments.iter().find(|environment| environment.id == environment_id)
                .and_then(|environment| app.try_state::<crate::runtime::RuntimeManager>()
                    .map(|runtime| runtime.interrupt_snapshot_exports(environment.runtime_id.as_deref().unwrap_or(&environment.id))))
        } else { None };
        if method.name == "start_environment_download" {
            let id = request.params["request"]["environmentId"]
                .as_str()
                .ok_or("Invalid environment ID")?;
            request.params["_downloadGeneration"] = app
                .state::<crate::environment_download::Downloads>()
                .queued_generation(id)?
                .into();
        }
        let id = format!("job-{}", uuid::Uuid::new_v4().simple());
        let keys = coordinator::resources(method.name, &request.params, method.mutating);
        let cancellation = self.shutdown.child_token();
        let waiting = Arc::new(StdMutex::new(None));
        let (progress, measurement) = tokio::sync::watch::channel(None);
        let cancellable = matches!(
            method.name,
            "copy_files_to_environment"
                | "copy_files_from_environment"
                | "copy_files_between_environments"
                | "execute_guest_job"
                | "project_action"
        );
        {
            let mut jobs = self.jobs.lock().await;
            Self::prune(&mut jobs);
            jobs.push_back(Job {
                id: id.clone(),
                method: request.method.clone(),
                resources: keys.clone(),
                cancellation: cancellation.clone(),
                cancellable,
                waiting: waiting.clone(),
                progress: measurement,
                ..Job::default()
            });
        }
        self.persist().await;
        let accepted = json!({"accepted":true,"jobId":id,"status":"queued","cancellable":cancellable,"resources":keys});
        let control = self.clone();
        let job_id = id.clone();
        tauri::async_runtime::spawn(async move {
            let _permit = permit;
            let _snapshot_interruption = snapshot_interruption;
            let blocker = waiting.clone();
            let lease = control
                .coordinator
                .acquire(&keys, &job_id, &cancellation, move |resource, owner| {
                    *blocker.lock().unwrap_or_else(|e| e.into_inner()) =
                        Some(json!({"resource":resource,"jobId":owner}));
                })
                .await;
            let result = match lease {
                Err(error) => Err(error),
                Ok(_lease) => {
                    *waiting.lock().unwrap_or_else(|e| e.into_inner()) = None;
                    {
                        let mut jobs = control.jobs.lock().await;
                        if let Some(job) = jobs.iter_mut().find(|job| job.id == job_id) {
                            job.status = "running";
                            job.started_at = Some(now());
                        }
                    }
                    control.persist().await;
                    control.finished.notify_waiters();
                    let task_app = app.clone();
                    let signal = control.clone();
                    let last_checkpoint = Arc::new(std::sync::atomic::AtomicI64::new(0));
                    let report: Arc<dyn Fn(Value) + Send + Sync> = Arc::new(move |mut value| {
                        let changed = progress.borrow().as_ref().is_none_or(|old| {
                            [
                                "phase",
                                "completedBytes",
                                "totalBytes",
                                "sentBytes",
                                "confirmedBytes",
                                "scannedEntries",
                                "step",
                                "waitingFor",
                            ]
                            .iter()
                            .any(|field| old[*field] != value[*field])
                        });
                        if changed {
                            value["lastProgressAt"] = json!(now());
                            progress.send_replace(Some(value));
                            signal.finished.notify_waiters();
                            let stamp = chrono::Utc::now().timestamp_millis();
                            let previous = last_checkpoint.load(Ordering::Relaxed);
                            if stamp.saturating_sub(previous) >= 2000
                                && last_checkpoint
                                    .compare_exchange(
                                        previous,
                                        stamp,
                                        Ordering::Relaxed,
                                        Ordering::Relaxed,
                                    )
                                    .is_ok()
                            {
                                let checkpoint = signal.clone();
                                tauri::async_runtime::spawn(async move {
                                    checkpoint.persist().await;
                                });
                            }
                        }
                    });
                    let operation = context::OperationContext {
                        id: job_id.clone(),
                        cancellation: cancellation.clone(),
                        progress: report.clone(),
                    };
                    let mut task = tokio::spawn(context::scope(operation, async move {
                        if context::current()
                            .is_some_and(|operation| operation.cancellation.is_cancelled())
                        {
                            return Err(
                                "YOUGORI_OPERATION_CANCELLED: cancelled before operation dispatch"
                                    .into(),
                            );
                        }
                        dispatch::dispatch_with_progress(
                            &task_app,
                            &request.method,
                            &request.params,
                            report,
                        )
                        .await
                    }));
                    if cancellable {
                        tokio::select! {
                            result=&mut task=>result.unwrap_or_else(|_|Err("YOUGORI_OPERATION_INTERRUPTED: operation failed internally; reconcile state before retrying.".into())),
                            _=cancellation.cancelled()=>{
                                match tokio::time::timeout(Duration::from_secs(if method.name=="project_action"{20}else{5}),&mut task).await {
                                    Ok(result)=>result.unwrap_or_else(|_|Err("YOUGORI_OPERATION_INTERRUPTED: operation cleanup failed internally; reconcile affected state before retrying".into())),
                                    Err(_)=>{task.abort();let _=task.await;Err("YOUGORI_OPERATION_INTERRUPTED: cancellation cleanup exceeded its deadline; reconcile partial transfer or process state".into())}
                                }
                            }
                        }
                    } else {
                        task.await.unwrap_or_else(|_|Err("YOUGORI_OPERATION_INTERRUPTED: operation failed internally; reconcile state before retrying.".into()))
                    }
                }
            };
            {
                let mut jobs = control.jobs.lock().await;
                if let Some(job) = jobs.iter_mut().find(|job| job.id == job_id) {
                    match result {
                        Ok(value) => {
                            job.succeeded(value);
                        }
                        Err(error) => job.failed(error),
                    }
                    job.completed = Some(Instant::now());
                    job.completed_at = Some(now());
                }
                Self::prune(&mut jobs);
            }
            control.persist().await;
            control.finished.notify_waiters();
            if method.mutating {
                if let Ok(state) = app.state::<PlatformStore>().snapshot() {
                    let _ = app.emit("yougori-platform-state", state);
                }
            }
        });
        Ok(accepted)
    }
    async fn cancel_pending(&self, except: Option<&str>) {
        for job in self.jobs.lock().await.iter() {
            if job.completed.is_none() && Some(job.id.as_str()) != except {
                job.cancellation.cancel();
            }
        }
        crate::file_import::cancel_all_transfers();
        self.finished.notify_waiters();
    }
    pub(super) async fn prepare_shutdown(&self, timeout: Duration) -> Value {
        self.quiescing.store(true, Ordering::Release);
        self.shutdown.cancel();
        let context = context::current();
        let except = context.as_ref().map(|context| context.id.as_str());
        self.cancel_pending(except).await;
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let changed = self.finished.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let pending = self
                .jobs
                .lock()
                .await
                .iter()
                .filter(|job| job.completed.is_none() && Some(job.id.as_str()) != except)
                .map(|job| job.value(false))
                .collect::<Vec<_>>();
            if pending.is_empty() || tokio::time::Instant::now() >= deadline {
                self.persist().await;
                return json!({"acceptingWork":false,"drained":pending.is_empty(),"remainingJobs":pending,"deadlineSeconds":timeout.as_secs()});
            }
            let _ = tokio::time::timeout_at(deadline, changed).await;
        }
    }
}
