//! The engine's one VM service and its automation method (module docs in `mod.rs`).
//!
//! The service is built on first use from the verified pinned inputs, the host's evidence
//! and the host's ledger, and kept for the engine's life; its supervisor state is written
//! to the engine's data directory after every call that changed it and recovered from
//! there after a restart. Every call of the method runs the service off the async
//! runtime, since the service blocks (a launch for the VM's start and the guest's hello,
//! a stop for the shutdown grace and the VM's end).
//!
//! Each launch's private control directory is created and removed by the host port,
//! and swept at start and by `cleanup`. Windows keeps these sockets in the user's temp directory,
//! separately from roaming state. Under `sandbox-vm/`: `audit/` is the durable spooled
//! audit stream, `supervisor.json` the
//! persisted supervisor, and `workspaces/` each sandbox's staged workspace (module docs
//! in `workspace`), recovered at start: an import cut short is removed and a promotion cut
//! short is reported file by file.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use serde_json::{json, Value};

use crate::foundation::coordination::SandboxState;
use crate::foundation::events::{
    write_atomic, AuditConfig, AuditFailurePolicy, EmissionLimit, JournalId, LogConfig, ProducerId,
    RedactionPolicy,
};
use crate::foundation::events::{AuditReceipt, AuditRefusal, Field, HostFact, Phase};
use crate::foundation::evidence::{
    Backend, BackendRelease, ClockSession, ConfigurationFingerprint, HypervisorKind,
    HypervisorSubject, OsKind, ProbeRegistry, RuntimeSubject,
};
use crate::foundation::ids::{
    digest, Clock, Digest, ExecutionCategory, ExecutionId, SandboxBootGeneration, SystemClock,
    TenantId, TrustScope,
};
use crate::foundation::ledger::{HostResource, Ledger, ResourceKey};
use crate::foundation::process::ProcessIdentity;
use crate::host_evidence::host_fingerprint;
use crate::sandbox::audit::{Anchoring, NoAnchor, SegmentConfig, StreamConfig, StreamDirectory};
use crate::sandbox::backend::HostObserved;
use crate::sandbox::backend::{check_endpoints, GuestEgressEndpoint};
use crate::sandbox::backend::{
    Architecture, BackendIdentity, BackendKind, DeviceExposure, DeviceProfile, RequiredProperties,
};
use crate::sandbox::integration::AuditSink;
use crate::sandbox::lifecycle::{
    IssuerId, PersistedSupervisor, Profile, RevocationPolicy, SkewPolicy, SupervisorConfig,
    SupervisorDeathFallback, TerminationTiming,
};
use crate::sandbox::probes::{
    ControlledFault, NegativeOutcome, ProcessScan, ScanMoment, Vm05Evaluation,
};
use crate::sandbox::qemu::{
    GuestResources, HostPath, PathStyle, QemuPlatform, QemuSettings, MIB_BYTES,
};
use crate::sandbox::qemu_host::{
    GuestImageFiles, LayoutSettings, LinkSocketConnector, QmpMonitor, RuntimeLayout,
    SocketTimeouts, UnixSocketConnect,
};
#[cfg(windows)]
use crate::sandbox::qemu_host::{HostSids, WindowsHostSettings, WindowsQemuHost};
#[cfg(target_os = "linux")]
use crate::sandbox::qemu_host::{LinuxHostSettings, LinuxQemuHost};
use crate::sandbox::vm_service::{
    check_connect, check_published, ConnectionEndpoint, DriverSettings, EvidenceSubjects,
    ExecRequest, HostProcessTable, LaunchSpec, PinnedImage, PublishedPort, RecoveryReport,
    RevokeReason, SandboxId, VmResources, VmService, VmServiceConfig, VmServiceParts,
    MAX_COMMAND_OUTPUT_BYTES, MAX_EXEC_DEADLINE,
};
use crate::sandbox_contract::confinement::{
    evaluate, ConfinementProfile, ConfinementVerdict, GuestReport, HostCorroboration,
    KernelBuildRecord, KernelSetting, WorkloadProfile, MAX_GUEST_REPORT_BYTES,
};
#[cfg(windows)]
use crate::sandbox_contract::effects::SecretClass;
use crate::sandbox_contract::files::{ArtifactOrigin, InspectionMethod};
use crate::sandbox_contract::files::{FileQuota, PromotionAudit};
use crate::sandbox_contract::relay_host::StopReason;
#[cfg(windows)]
use crate::sandbox_contract::relay_link::guest_pipe::GuestPipeListener;
#[cfg(windows)]
use crate::sandbox_contract::relay_link::RelayPipeName;
use crate::sandbox_contract::response::{NotificationOutcome, ResponseAction};
use crate::sandbox_contract::untrusted::{
    route_raw, DeclaredFormat, JobGrants, NormalizationJob, NormalizationOutcome,
    NormalizationReport, NormalizationRequest, NormalizerExecution, NormalizerFailure,
    NormalizerIdentity, OutputFormat, RawArtifact, RawRetention, ResultRefusal,
};
#[cfg(windows)]
use crate::sandbox_contract::vault::ValueForm;
use crate::AppHandle;

use super::artifacts::{self, VerifiedGuest};
#[cfg(windows)]
use super::executor::protocol::wipe;
use super::executor::RouteDeclaration;
#[cfg(windows)]
use super::executor::{ExecutorClient, ExecutorReply, ExecutorRequest, PipeEgressPort};
use super::lifetimes::{self, Lifetimes};
use super::ports::{GuestBodies, ProductionPorts};
#[cfg(target_os = "linux")]
use super::probes::KvmProbe;
#[cfg(windows)]
use super::probes::WhpxProbe;
use super::probes::{platform_report, PinnedRuntimeProbe};
use super::responses::{Decided, Notice, ViolationResponses};
use super::workspace::{self as staged, WorkspaceStore};

/// The service's directory under the engine's data directory.
pub const DATA_DIRECTORY: &str = "sandbox-vm";
#[cfg(not(windows))]
const CONTROL_DIRECTORY: &str = "control";
const AUDIT_DIRECTORY: &str = "audit";
const STATE_FILE: &str = "supervisor.json";
const WORKSPACE_DIRECTORY: &str = "workspaces";
/// Where the lifetime supervisors write their journals (module docs in `supervisor`).
const SUPERVISOR_DIRECTORY: &str = "supervisor";
/// The longest a workspace grant lasts; a stop or revocation takes it off earlier.
const WORKSPACE_GRANT_FOR: Duration = Duration::from_secs(24 * 60 * 60);
/// The tenant every launch of this engine is charged to.
const TENANT: &str = "local";

/// The doctor's VM-CP-29 connection drill (M08).
mod combine;
mod drill;
mod images;
mod grid_hosting;
mod author;
mod network;
mod remote_home;
mod remote_management;
#[cfg(not(test))]
pub(super) fn start_remote_recovery(app: &AppHandle) {
    tauri::async_runtime::spawn(remote_home::resume_if_needed(app.clone()));
}
/// The pinned QEMU build's version, as its QMP greeting reports it: the Windows build, or
/// Alpine's `qemu-system-x86_64` 11.0.3-r0 on Linux.
#[cfg(windows)]
pub(super) const QEMU_VERSION: &str = "11.1.0";
#[cfg(target_os = "linux")]
pub(super) const QEMU_VERSION: &str = "11.0.3";
/// The platform's hardware hypervisor, its OS and the name the summary gives the pair.
#[cfg(windows)]
const HYPERVISOR: HypervisorKind = HypervisorKind::Whpx;
#[cfg(target_os = "linux")]
const HYPERVISOR: HypervisorKind = HypervisorKind::Kvm;
#[cfg(windows)]
pub(super) const HOST_OS: OsKind = OsKind::Windows;
#[cfg(target_os = "linux")]
pub(super) const HOST_OS: OsKind = OsKind::Linux;
#[cfg(windows)]
const PLATFORM_NAME: &str = "windows-whpx";
#[cfg(target_os = "linux")]
const PLATFORM_NAME: &str = "linux-kvm";
/// Linux: the account QEMU runs as unless `YOUGORI_VM_ACCOUNT` names another; an account
/// of its own, created with the package (`useradd --system --no-create-home yougori-vm`).
#[cfg(target_os = "linux")]
const DEFAULT_VM_ACCOUNT: &str = "yougori-vm";
/// Linux: why routes and credentials are refused (module docs in `mod.rs`).
#[cfg(target_os = "linux")]
const RELAYS_UNAVAILABLE: &str = "Declared routes and credentials need the sandbox executor and its confined guest relay, which run on Windows in this build; their Linux sockets and confinement are open work. Launch without routes; nothing was started.";
/// The guest's memory and vCPU count: what the pinned image boots with.
pub(super) const GUEST_MEMORY_BYTES: u64 = 256 * MIB_BYTES;
fn launch_cpu_count(params: &Value) -> Result<u64, String> {
    match params.get("gpu") {
        None | Some(Value::Bool(false)) => {},
        Some(Value::Bool(true)) if cfg!(windows) => {},
        Some(Value::Bool(true)) => return Err("Direct GPU acceleration is not supported by this Sandbox VM backend. No VM was created.".into()),
        _ => return Err("gpu must be true or false.".into()),
    }
    match params.get("cpu") {
        None => Ok(1),
        Some(value) => value.as_u64().filter(|count| (1..=255).contains(count))
            .ok_or_else(|| "cpu must be a whole number between 1 and 255.".into()),
    }
}

/// The host memory a launch reserves, in GiB (`memoryGb`; 1 unless given). A value that is
/// not a positive number is refused rather than read as the default: a launch asked for
/// `"8"` must not start a 1 GiB VM.
fn launch_memory_gb(params: &Value) -> Result<f64, String> {
    match params.get("memoryGb") {
        None | Some(Value::Null) => Ok(1.0),
        Some(value) => value
            .as_f64()
            .filter(|memory_gb| memory_gb.is_finite() && *memory_gb > 0.0)
            .ok_or_else(|| "memoryGb must be a positive number of gigabytes.".to_owned()),
    }
}

#[cfg(test)]
mod launch_resource_tests {
    use super::*;
    #[test]
    fn cpu_is_explicit_and_invalid_or_unsupported_resources_are_refused() {
        assert_eq!(launch_cpu_count(&json!({})).unwrap(), 1);
        assert_eq!(launch_cpu_count(&json!({"cpu": 4, "gpu": false})).unwrap(), 4);
        for value in [json!(0), json!(-1), json!(1.5), json!(256), json!("4"), Value::Null] {
            assert!(launch_cpu_count(&json!({"cpu":value})).is_err());
        }
        assert_eq!(launch_cpu_count(&json!({"gpu":true})).is_ok(), cfg!(windows));
    }

    #[test]
    fn memory_that_is_not_a_positive_number_is_refused_rather_than_defaulted() {
        assert_eq!(launch_memory_gb(&json!({})).unwrap(), 1.0);
        assert_eq!(launch_memory_gb(&json!({"memoryGb": null})).unwrap(), 1.0);
        assert_eq!(launch_memory_gb(&json!({"memoryGb": 4})).unwrap(), 4.0);
        assert_eq!(launch_memory_gb(&json!({"memoryGb": 0.5})).unwrap(), 0.5);
        for value in [json!("8"), json!(0), json!(-1), json!(true), json!([8]), json!({})] {
            assert_eq!(
                launch_memory_gb(&json!({"memoryGb": value})).unwrap_err(),
                "memoryGb must be a positive number of gigabytes."
            );
        }
    }
}

pub(super) const GUEST_VCPUS: u16 = 1;
/// The least a launch may reserve: the guest's memory and room for QEMU's own under the
/// job's memory limit (measured on WHPX, 31 October 2026: 256 and 288 MiB fail with "cannot
/// set up guest memory", 320 MiB starts).
pub(super) const LEAST_LAUNCH_MEMORY_BYTES: u64 = 320 * MIB_BYTES;
/// The host memory a launch reserves unless asked otherwise: 1 GiB, above the guest's
/// memory and QEMU's own commit.
const DEFAULT_LAUNCH_MEMORY_BYTES: u64 = 1 << 30;
/// The most a launch may reserve through the method: 64 GiB.
const MAX_LAUNCH_MEMORY_BYTES: u64 = 64 << 30;
/// Default bounds of a command through the method.
const DEFAULT_OUTPUT_BYTES: usize = 1 << 20;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);
/// The most bytes read of the persisted state.
const MAX_STATE_BYTES: u64 = 64 << 20;
/// The hex digits of a VM handle that name its private directory.
const CONTROL_NAME_HEX_DIGITS: usize = 16;
/// How long the started executor may take to connect and answer the hello.
#[cfg(windows)]
const EXECUTOR_START_WITHIN: Duration = Duration::from_secs(30);
/// How often the engine asks the executor what its relays refused and which ended, so a
/// violation is answered while the sandbox runs, not only when someone asks for the status.
const POLL_EVERY: Duration = Duration::from_secs(2);
/// The window event that carries the response path's notices.
const NOTICE_EVENT: &str = "sandbox-vm-response";
/// The most desktop notifications one look shows.
#[cfg(windows)]
const MAX_DESKTOP_NOTICES: usize = 3;
/// The confinement probe in the guest: the agent's own binary on a read-only tmpfs
/// (appliance/agent/cmd/yougori-sandbox-agent/confine_linux.go).
const CONFINEMENT_PROBE: &str = "/run/yougori/bin/yougori-probe";
/// How long the probe may take.
const PROBE_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a confinement verdict stays fresh for the doctor.
const CONFINEMENT_FRESH_FOR: Duration = Duration::from_secs(15 * 60);
/// Normalization (VM-W58): where results are kept under the service's data folder, the
/// normalizer's name and version (the guest agent's `normalize` command), the most raw bytes
/// a job takes, how long it may run, the most of its report read back, and the most of its
/// output shown in the answer (all of it is stored).
const NORMALIZED_DIRECTORY: &str = "normalized";
const NORMALIZER_NAME: &str = "yougori-normalize";
const NORMALIZER_VERSION: &str = "1.0.0";
const MAX_NORMALIZE_INPUT_BYTES: u64 = 32 << 20;
const NORMALIZE_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_NORMALIZER_REPORT_BYTES: usize = 64 << 10;
const MAX_SHOWN_OUTPUT_CHARS: usize = 64 << 10;
/// The default and largest output bound of a normalization through the method.
const DEFAULT_NORMALIZE_OUTPUT_BYTES: u64 = 4 << 20;
const MAX_NORMALIZE_OUTPUT_BYTES: u64 = 16 << 20;
/// Acceptance builds: the variable naming the route whose next refusal the executor reports
/// as a violation (`acceptance_mark`).
#[cfg(all(feature = "acceptance", windows))]
const ACCEPTANCE_VIOLATION_ROUTE: &str = "YOUGORI_ACCEPTANCE_VIOLATION_ROUTE";
/// How long one executor request may take (a relay start launches a confined process and
/// waits for its admission within the relay host's bound).
#[cfg(windows)]
const EXECUTOR_REQUEST_WITHIN: Duration = Duration::from_secs(60);
/// How long the started relay may take to open the guest pipe the engine serves.
#[cfg(windows)]
const GUEST_PIPE_ACCEPT_WITHIN: Duration = Duration::from_secs(30);

type Service = VmService<ProductionPorts>;

/// A host folder import or a stopped VM's registered private state.
enum WorkspaceInput {
    Folder(PathBuf),
    Saved(ExecutionId),
}

/// The engine's service with what it was built from.
pub struct Production {
    host_access: super::host_access::Shared,
    remote_home: OnceLock<Result<Arc<remote_home::Manager>, String>>,
    remote_management: std::sync::Mutex<BTreeMap<Digest, std::sync::Weak<std::sync::Mutex<()>>>>,
    images: std::sync::Mutex<images::ImageState>,
    /// Cancels host-capacity probes performed after a guest's boot on blocking workers.
    shutdown: tokio_util::sync::CancellationToken,
    service: Service,
    /// The backend build every launch record of this service names.
    backend: BackendIdentity,
    /// This host's configuration when the service was composed: a confinement verdict is
    /// stamped under it, so the doctor refuses it after a change.
    configuration: ConfigurationFingerprint,
    /// The latest VM-CP-05 verdict of a sandbox's strict-profile confinement, for the
    /// doctor.
    confinement: std::sync::Mutex<Option<Vm05Evaluation>>,
    /// The controlled negative launches of this run, for the doctor: acceptance builds
    /// plant a fault in one launch (`YOUGORI_ACCEPTANCE_PLANT`) and record how the backend
    /// answered; a product build has none.
    negatives: std::sync::Mutex<Vec<(ControlledFault, NegativeOutcome)>>,
    /// The process-list scans taken right after each refused negative launch, against the
    /// list taken right before it, for the doctor.
    scans: std::sync::Mutex<Vec<HostObserved<ProcessScan>>>,
    /// The host's observations of the latest VM-CP-29 connection drills (`drill`).
    drills: std::sync::Mutex<Vec<HostObserved<crate::sandbox::probes::ConnectionDrill>>>,
    /// Acceptance builds: the faults the next launches plant, one each, in order.
    #[cfg_attr(not(feature = "acceptance"), allow(dead_code))]
    plant: std::sync::Mutex<std::collections::VecDeque<ControlledFault>>,
    layout: RuntimeLayout,
    guest: VerifiedGuest,
    state_file: PathBuf,
    control_base: PathBuf,
    summary: Value,
    /// Serializes the state's write and confirmation: two calls that end together (a cancel
    /// beside the command it ends) would otherwise race on the atomic write's temporary
    /// file (observed 30 October 2026: "supervisor.json could not be written: The system
    /// cannot find the file specified", and the command's outcome lost to its caller).
    checkpoint_lock: std::sync::Mutex<()>,
    /// The executor process and each sandbox's relay (module docs in `executor`).
    relays: std::sync::Mutex<Relays>,
    /// The response path for what the executor observes (module docs in `responses`). Its
    /// lock is never taken while the relays' lock is held.
    responses: std::sync::Mutex<ViolationResponses<SystemClock>>,
    /// The staged workspaces (module docs in `workspace`), one call at a time.
    workspaces: std::sync::Mutex<WorkspaceStore>,
    /// The lifetime supervisor and the VMs it holds (module docs in `supervisor`). Its
    /// lock is never taken while the relays' lock is held.
    lifetimes: std::sync::Mutex<Lifetimes>,
    /// The CORE-05 ports of the guests' file bodies (module docs in `ports`), told each
    /// sandbox's authority after every call that may change it and by the poller.
    bodies: Arc<GuestBodies>,
    /// The host clock a promotion's approval is timed on.
    clock: SystemClock,
    /// The audit stream's directory, held for the service's life.
    _audit: StreamDirectory,
    /// The loopback listeners of published guest services and the gate's pump (module
    /// docs in `preview`).
    previews: Arc<super::preview::Previews>,
    /// The status view's last complete answer (see [`StatusView`]).
    status_view: Arc<StatusView>,
}

/// How long a status request waits for a fresh answer before it answers from the last one.
const STATUS_WAIT: Duration = Duration::from_millis(1500);

/// The status view's last complete answer. A launch holds the VM service's state lock for
/// its whole transaction (for a GPU VM that includes the Windows approval prompt and the
/// boot), and every part of a status answer reads that state. A status request therefore
/// waits at most [`STATUS_WAIT`] for a fresh answer, then answers from the last complete
/// one, marked stale, while a single refresh keeps waiting in the background and replaces
/// it. At most one refresh runs at a time, so polling never piles up blocked workers.
#[derive(Default)]
pub(super) struct StatusView {
    last: std::sync::Mutex<Option<Value>>,
    refreshing: std::sync::atomic::AtomicBool,
}

impl StatusView {
    fn remember(&self, value: &Value) {
        if let Ok(mut last) = self.last.lock() {
            *last = Some(value.clone());
        }
    }

    fn stale(&self) -> Option<Value> {
        let mut value = self.last.lock().ok()?.clone()?;
        value["stale"] = json!(true);
        Some(value)
    }
}

/// A fresh status from `compute` if it finishes within `wait`, else the last complete answer
/// (see [`StatusView`]). Waits for `compute` only when there is no earlier answer at all.
pub(super) async fn answer_status(
    view: Arc<StatusView>,
    wait: Duration,
    compute: impl FnOnce() -> Result<Value, String> + Send + 'static,
) -> Result<Value, String> {
    use std::sync::atomic::Ordering;
    if view.refreshing.swap(true, Ordering::AcqRel) {
        // A refresh is already waiting for the service: answer from the last answer, and
        // compute only if there has never been one.
        if let Some(value) = view.stale() {
            return Ok(value);
        }
        return tokio::task::spawn_blocking(compute)
            .await
            .map_err(|error| error.to_string())?;
    }
    let refresh = Arc::clone(&view);
    let mut handle = tokio::task::spawn_blocking(move || {
        struct Done(Arc<StatusView>);
        impl Drop for Done {
            fn drop(&mut self) {
                self.0.refreshing.store(false, Ordering::Release);
            }
        }
        let done = Done(refresh);
        let value = compute();
        if let Ok(value) = &value {
            done.0.remember(value);
        }
        value
    });
    match tokio::time::timeout(wait, &mut handle).await {
        Ok(joined) => joined.map_err(|error| error.to_string())?,
        Err(_) => match view.stale() {
            Some(value) => Ok(value),
            None => handle.await.map_err(|error| error.to_string())?,
        },
    }
}

#[cfg(test)]
mod status_view_tests {
    use super::*;

    fn slow(value: Value, millis: u64) -> impl FnOnce() -> Result<Value, String> + Send + 'static {
        move || {
            std::thread::sleep(Duration::from_millis(millis));
            Ok(value)
        }
    }

    #[tokio::test]
    async fn a_busy_service_answers_from_the_last_complete_status() {
        let view = Arc::new(StatusView::default());
        let first = answer_status(Arc::clone(&view), STATUS_WAIT, slow(json!({"sandboxes": [1]}), 0))
            .await
            .unwrap();
        assert_eq!(first, json!({"sandboxes": [1]}));
        // A launch holds the service: the answer comes from the last one, marked stale,
        // long before the blocked refresh finishes.
        let started = std::time::Instant::now();
        let busy = answer_status(Arc::clone(&view), Duration::from_millis(50), slow(json!({"sandboxes": [1, 2]}), 600))
            .await
            .unwrap();
        assert!(started.elapsed() < Duration::from_millis(500));
        assert_eq!(busy, json!({"sandboxes": [1], "stale": true}));
        // While that refresh still waits, another request starts no second refresh.
        let again = answer_status(Arc::clone(&view), Duration::from_millis(50), || panic!("second refresh"))
            .await
            .unwrap();
        assert_eq!(again["stale"], true);
        // Once the service is free the waiting refresh has replaced the answer.
        tokio::time::sleep(Duration::from_millis(800)).await;
        let fresh = answer_status(Arc::clone(&view), STATUS_WAIT, slow(json!({"sandboxes": [1, 2, 3]}), 0))
            .await
            .unwrap();
        assert_eq!(fresh, json!({"sandboxes": [1, 2, 3]}));
        assert_eq!(view.stale().unwrap()["sandboxes"], json!([1, 2, 3]));
    }

    #[tokio::test]
    async fn without_an_earlier_answer_the_request_waits_for_a_fresh_one() {
        let view = Arc::new(StatusView::default());
        let value = answer_status(Arc::clone(&view), Duration::from_millis(20), slow(json!({"sandboxes": []}), 200))
            .await
            .unwrap();
        assert_eq!(value, json!({"sandboxes": []}));
    }

    #[tokio::test]
    async fn a_failed_refresh_keeps_the_last_good_answer_and_frees_the_next_refresh() {
        let view = Arc::new(StatusView::default());
        answer_status(Arc::clone(&view), STATUS_WAIT, slow(json!({"ok": 1}), 0)).await.unwrap();
        let failed = answer_status(Arc::clone(&view), STATUS_WAIT, || Err("service gone".into())).await;
        assert_eq!(failed, Err("service gone".into()));
        assert_eq!(view.stale().unwrap()["ok"], 1);
        let next = answer_status(Arc::clone(&view), STATUS_WAIT, slow(json!({"ok": 2}), 0)).await.unwrap();
        assert_eq!(next, json!({"ok": 2}));
    }
}

/// The engine's side of the relays: the executor process, started on first need, and what
/// each sandbox's relay is.
#[derive(Default)]
struct Relays {
    #[cfg(windows)]
    executor: Option<ExecutorClient>,
    records: BTreeMap<ExecutionId, RelayRecord>,
}

/// One sandbox's relay as the engine knows it: no credential, no guest byte.
#[derive(Clone, Debug, serde::Serialize)]
struct RelayRecord {
    relay: ProcessIdentity,
    guest_pipe: String,
    routes: Vec<String>,
    credentialed_routes: Vec<String>,
    /// The host's own addresses the relay's policy refuses, and the inventory's error if
    /// only the loopback addresses were known.
    host_addresses: usize,
    host_inventory_error: Option<String>,
    /// The executor's last word on the running relay.
    status: Option<Value>,
    /// How the relay ended, once it did; `None` while it runs.
    ended: Option<Value>,
    /// Acceptance builds: the route whose next refusal the executor reports as a violation.
    #[serde(skip_serializing_if = "Option::is_none")]
    acceptance_mark: Option<Value>,
}

/// Where the guest agent mounts the workspace (appliance/agent `workspace_linux.go`); the
/// guest shell's `WORKSPACE` names it.
const GUEST_WORKSPACE: &str = "/run/yougori/workspace";

/// A promotion's audit (`files::apply_in`) in the sandbox's durable audit stream, as a
/// high-impact operation in the context of the sandbox its files came from: the admission
/// is the permission to write (the transferring phase), and the outcome follows it
/// (completed or failed). The records name the sandbox, its boot and its trust scope in
/// their own fields, so a promotion after the sandbox stopped, or after a restart of the
/// engine, stays attributed to it.
struct StreamAudit<'a> {
    service: &'a Service,
    sandbox: &'a SandboxId,
}

impl StreamAudit<'_> {
    fn record(&mut self, phase: Phase, fields: Vec<Field>) -> Result<AuditReceipt, AuditRefusal> {
        match self
            .service
            .record_fact(self.sandbox, phase, HostFact::HighImpactOperation, fields)
        {
            Ok(Ok(receipt)) => Ok(receipt),
            Ok(Err(refusal)) => Err(AuditRefusal::Encoding {
                message: format!("the audit stream refused the record: {refusal}"),
            }),
            Err(error) => Err(AuditRefusal::Encoding {
                message: format!("the audit stream is unavailable: {error}"),
            }),
        }
    }
}

impl PromotionAudit for StreamAudit<'_> {
    fn admit(&mut self, mut fields: Vec<Field>) -> Result<AuditReceipt, AuditRefusal> {
        fields.push(Field::metadata("promotion", "admitted"));
        self.record(Phase::Transferring, fields)
    }

    fn record_outcome(
        &mut self,
        applied: bool,
        mut fields: Vec<Field>,
    ) -> Result<AuditReceipt, AuditRefusal> {
        fields.push(Field::metadata(
            "promotion",
            if applied { "applied" } else { "rolled_back" },
        ));
        self.record(
            if applied {
                Phase::Completed
            } else {
                Phase::Failed
            },
            fields,
        )
    }
}

static PRODUCTION: OnceLock<tokio::sync::Mutex<Option<Arc<Production>>>> = OnceLock::new();

/// Acceptance builds: the fault `YOUGORI_ACCEPTANCE_PLANT` names for the first launch of
/// this run (`share_device`: VM-CP-03's positive control); a product build plants none, nor
/// does the Linux host port yet.
#[cfg(all(feature = "acceptance", windows))]
fn acceptance_plant() -> std::collections::VecDeque<ControlledFault> {
    std::env::var("YOUGORI_ACCEPTANCE_PLANT")
        .unwrap_or_default()
        .split(',')
        .filter_map(|name| match name.trim() {
            "share_device" => Some(ControlledFault::PlantedShareDevice),
            "tcg" => Some(ControlledFault::HypervisorUnavailable),
            "gpu" => Some(ControlledFault::GpuPathUnavailable),
            _ => None,
        })
        .collect()
}

#[cfg(not(all(feature = "acceptance", windows)))]
fn acceptance_plant() -> std::collections::VecDeque<ControlledFault> {
    std::collections::VecDeque::new()
}

/// What a normalizer's failure means to the person who asked (VM-W58).
fn failure_text(failure: NormalizerFailure) -> String {
    match failure {
        NormalizerFailure::UnsupportedFormat => format!(
            "unsupported_format ({NORMALIZER_NAME} {NORMALIZER_VERSION} reads html, archive (zip, tar, tar.gz) and plain_text into plain_text or markdown)"
        ),
        NormalizerFailure::MalformedInput => {
            "malformed_input (the bytes are not the declared format)".into()
        }
        NormalizerFailure::InputTooLarge => "input_too_large".into(),
        NormalizerFailure::ResourceLimit => "resource_limit (the text passed maxOutputBytes, or an archive passed 10000 entries or 512 MiB expanded)".into(),
        NormalizerFailure::Timeout => "timeout".into(),
    }
}

fn encoded(value: impl serde::Serialize) -> Result<Value, String> {
    serde_json::to_value(value).map_err(|error| error.to_string())
}

/// `path` as the platform's host path.
fn host_path(path: &Path) -> Result<HostPath, String> {
    let text = path
        .to_str()
        .ok_or_else(|| format!("{} is not a UTF-8 path", path.display()))?;
    #[cfg(windows)]
    let made = HostPath::new(PathStyle::Windows, text.replace('/', "\\"));
    #[cfg(not(windows))]
    let made = HostPath::new(PathStyle::Unix, text);
    made.map_err(|error| format!("{} is not a usable host path: {error}", path.display()))
}

/// Linux: the account QEMU runs as (`YOUGORI_VM_ACCOUNT`, or [`DEFAULT_VM_ACCOUNT`]),
/// looked up in the account database. The engine must run as root to start QEMU as it
/// (VM-D15's narrower launcher is open); otherwise nothing could keep QEMU out of the
/// engine's own account, and the backend's comparison would refuse every launch.
#[cfg(target_os = "linux")]
fn vm_account() -> Result<crate::foundation::process::RunAs, String> {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        return Err("The VM sandbox on Linux starts QEMU as an account of its own, which needs the engine to run as root (a narrower privileged launcher, VM-D15, is open work).".to_owned());
    }
    let name = std::env::var("YOUGORI_VM_ACCOUNT")
        .ok()
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| DEFAULT_VM_ACCOUNT.to_owned());
    let account = std::ffi::CString::new(name.clone())
        .map_err(|_| format!("The VM account name {name:?} holds a NUL byte."))?;
    // SAFETY: getpwnam reads the account database for a NUL-terminated name; the fields
    // used are copied before any other call to it.
    let entry = unsafe { libc::getpwnam(account.as_ptr()) };
    if entry.is_null() {
        return Err(format!("QEMU's account {name} does not exist; create it (useradd --system --no-create-home {name}) or name another in YOUGORI_VM_ACCOUNT."));
    }
    // SAFETY: a non-null entry getpwnam just returned.
    let (uid, gid) = unsafe { ((*entry).pw_uid, (*entry).pw_gid) };
    if uid == 0 {
        return Err(format!(
            "QEMU's account {name} is root; it must be an account of its own."
        ));
    }
    Ok(crate::foundation::process::RunAs {
        uid,
        gid,
        groups: Vec::new(),
    })
}

/// The supervisor's stream: a spool of 64 records, 8 kept for revocations, 64 records
/// per segment; the log keeps 100,000 entries or 64 MiB in 256 KiB log segments (retention
/// must keep the header of the segment being written: `check_retention`, tested below).
fn stream_config() -> Result<StreamConfig, String> {
    Ok(StreamConfig {
        audit: AuditConfig {
            spool_records: 64,
            revocation_reserve_records: 8,
            failure_policy: AuditFailurePolicy::SpoolHighImpact,
            guest_observations: EmissionLimit::new(64, Duration::from_secs(1))
                .map_err(|error| error.to_string())?,
            redaction: RedactionPolicy::metadata_only(),
        },
        segment: SegmentConfig {
            max_records_per_segment: 64,
        },
        anchoring: Anchoring::Off,
    })
}

fn log_config() -> LogConfig {
    LogConfig {
        max_entries: 100_000,
        max_bytes: 64 << 20,
        segment_entries: 1_024,
        segment_bytes: 256 << 10,
    }
}

/// The resources a launch reserves on the host ledger: host RAM and the engine's
/// initialization slots (`vm_service` maps a `LaunchSpec`'s memory and CPU slots to them).
const BUDGETED: [ResourceKey; 2] = [
    ResourceKey::Host(HostResource::Ram),
    ResourceKey::Host(HostResource::CpuInitializationSlots),
];

/// Installs the VM tenant's budget on the host's shared ledger. The host capacity owner
/// invents none (`model_runner/optimizer/capacity/host.rs`: "the VM supervisor must install
/// its reviewed budget before reserving"). The budget here is, for each resource, the
/// host's observed capacity less the supervisor reserve the host scheduler keeps (10 %, at
/// least 1 GiB of RAM): a sandbox may use what a model may use and never the reserve. A
/// budget is a tenant cap; admission still checks the one physical pool both tenants
/// share, so a model's reservation and a sandbox's compete there, not here. Installed at
/// every composition, so a capacity observed again carries a current budget. Returns what
/// was installed, for the status summary.
fn install_tenant_budget<C: Clock>(
    ledger: &mut Ledger<C>,
    tenant: &TenantId,
) -> Result<Value, String> {
    let mut installed = serde_json::Map::new();
    for key in BUDGETED {
        let capacity = ledger.capacity(key).ok_or_else(|| {
            format!("the host ledger has not observed {key:?}; no VM budget can be set")
        })?;
        let amount = capacity.total.saturating_sub(capacity.supervisor_reserve);
        ledger
            .set_tenant_budget(tenant.clone(), key, amount)
            .map_err(|error| format!("the VM tenant's budget for {key:?} was refused: {error}"))?;
        let name = match key {
            ResourceKey::Host(HostResource::Ram) => "host_memory_bytes",
            _ => "cpu_initialization_slots",
        };
        installed.insert(name.to_owned(), json!(ledger.tenant_budget(tenant, key)));
    }
    Ok(Value::Object(installed))
}

#[cfg(test)]
mod config_tests {
    use super::*;

    /// The first acceptance run of 30 October refused every launch because the log's byte
    /// bound could not keep one segment's header under retention (1 MiB log segments need
    /// 73 MiB); the bounds now pass the durable log's own check.
    #[test]
    fn the_audit_log_bounds_keep_the_segment_being_written() {
        let stream = stream_config().unwrap();
        crate::sandbox::audit::check_retention(&stream.segment, &log_config()).unwrap();
    }

    /// The second acceptance run of 30 October refused every launch for want of a tenant
    /// budget (the host capacity owner installs none for the VM tenant); the composition
    /// installs the observed capacity less the supervisor reserve, for both resources.
    #[test]
    fn the_vm_tenant_is_budgeted_with_the_hosts_managed_capacity() {
        use crate::foundation::evidence::SourceClass;
        use crate::foundation::ledger::CapacityDeclaration;
        let clock = std::sync::Arc::new(crate::foundation::ids::ManualClock::new(
            crate::foundation::ids::MonotonicTime::ZERO,
        ));
        let mut ledger = crate::sandbox::host::fakes::real_ledger(&clock);
        let tenant = TenantId::new(TENANT).unwrap();
        for key in BUDGETED {
            assert_eq!(ledger.tenant_budget(&tenant, key), 0);
        }
        // A reserve the host scheduler keeps is never budgeted.
        ledger
            .declare_capacity(
                ResourceKey::Host(HostResource::Ram),
                CapacityDeclaration {
                    total: 64 << 30,
                    supervisor_reserve: 6 << 30,
                    unmanaged_in_use: 0,
                    source: SourceClass::HostProbe,
                },
            )
            .unwrap();
        let installed = install_tenant_budget(&mut ledger, &tenant).unwrap();
        assert_eq!(installed["host_memory_bytes"], json!(58u64 << 30));
        assert_eq!(installed["cpu_initialization_slots"], json!(16));
        assert_eq!(
            ledger.tenant_budget(&tenant, ResourceKey::Host(HostResource::Ram)),
            58 << 30
        );
        // The fakes' own tenant keeps its budget: one tenant's budget never moves another's.
        assert_eq!(
            ledger.tenant_budget(
                &crate::sandbox::host::fakes::tenant(),
                ResourceKey::Host(HostResource::Ram)
            ),
            64 << 30
        );
    }
}

/// The guest image's publisher check (M18, VM-W45): the trust roots' policy for the guest
/// image class (`foundation::catalog::ArtifactClass::GuestImage`). With no trust-root file
/// in force, or none naming a guest-image key, the guest stays pinned by the checksums of
/// the runtime it ships in, and the check says so: the owner's release keys and trust-root
/// file are the gate. With guest-image publishers in force, a guest without a publisher
/// signature is refused, and no signed guest record exists yet (its signing comes with the
/// release keys, M01/M18), so such a policy refuses this guest rather than pass it unsigned.
fn guest_publisher() -> Result<Value, String> {
    use crate::foundation::catalog::ArtifactClass;
    let policy = crate::trust_roots::service().policy(ArtifactClass::GuestImage);
    match policy {
        Err(refusal) => Ok(json!({
            "checked": false,
            "reason": refusal.to_string(),
            "pinned_by": "the runtime's SHA256SUMS and the guest's own checksum list",
            "gate": "the owner's release keys and trust-root file (YOUGORI_TRUST_ROOTS); a signed guest record comes with them",
        })),
        Ok(_) => Err("The trust roots in force name guest-image publishers, but the pinned guest carries no publisher signature (no signed guest record exists yet), so the VM sandbox refuses it.".to_owned()),
    }
}

/// The supervisor's configuration: the strict profile, readiness observed again after five
/// seconds, revocation stopping the VM once the channels are acknowledged closed or the
/// lease bound passed, a minute for cleanup, the OS as the death fallback (on Windows the
/// kill-on-close job, on Linux QEMU's parent-death signal: every QEMU ends with the
/// engine), five seconds for child work to stop.
fn supervisor_config(machine: Digest, guest_image: Digest) -> SupervisorConfig {
    SupervisorConfig {
        profile: Profile::Strict,
        readiness_max_age: Duration::from_secs(5),
        runtime_evidence_max_age: Duration::from_secs(3_600),
        skew: SkewPolicy {
            allowed_clock_uncertainty: Duration::from_secs(30),
        },
        revocation: RevocationPolicy {
            timing: TerminationTiming::AfterChannelAcknowledgmentOrBound,
            cleanup_bound: Duration::from_secs(60),
        },
        death_fallback: SupervisorDeathFallback::OsJobCleanup,
        cancel_within: Duration::from_secs(5),
        issuer: IssuerId::new(digest(IssuerId::DOMAIN, &[machine.as_bytes()])),
        expected_image_profile: guest_image,
    }
}

/// The required properties of every launch: the strictest, with the confinement this
/// platform applies and host observations at most a minute old at admission.
fn required_properties() -> RequiredProperties {
    let mut required = RequiredProperties::strictest(Duration::from_secs(60));
    required.confinement = QemuPlatform {
        os: HOST_OS,
        architecture: Architecture::X86_64,
    }
    .profile()
    .map(|fixed| fixed.confinement_applied())
    .unwrap_or_default();
    required
}

/// This machine's identity and configuration from the host evidence inventory, collected
/// now when it has not been.
async fn host_identity(
    app: &AppHandle,
) -> Result<(Digest, ConfigurationFingerprint, Value), String> {
    let (mut inventory, _) = crate::host_evidence::inventory_and_now().await?;
    if inventory.is_none() {
        crate::host_evidence::dispatch(app.clone(), Some("refresh".to_owned())).await?;
        inventory = crate::host_evidence::inventory_and_now().await?.0;
    }
    let inventory =
        inventory.ok_or("Host evidence has not collected this computer's inventory.")?;
    let machine = inventory
        .machine
        .digest()
        .ok_or("Host evidence could not identify this computer.")?;
    let configuration = host_fingerprint(&inventory).map_err(|error| error.to_string())?;
    let os = inventory.os.as_ref().map(|os| {
        json!({
            "kind": os.kind.to_string(),
            "build": os.build,
            "architecture": os.architecture,
        })
    });
    Ok((machine, configuration, json!({ "os": os })))
}

/// Reads the persisted supervisor, if an earlier run left one.
fn read_state(path: &Path) -> Result<Option<PersistedSupervisor>, String> {
    use std::io::Read;
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("{} could not be read: {error}", path.display())),
    };
    let mut bytes = Vec::new();
    file.take(MAX_STATE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("{} could not be read: {error}", path.display()))?;
    if bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(format!(
            "{} is larger than {MAX_STATE_BYTES} bytes",
            path.display()
        ));
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|error| format!("{} is not a persisted supervisor: {error}", path.display()))
}

/// Removes every private directory under `control_base` that no live sandbox uses: after
/// a restart none is live (every QEMU of the earlier run ended with its job); at a cleanup
/// the live ones are those of the service's sandboxes with a process. Returns what was
/// removed and what could not be.
fn sweep_control(control_base: &Path, live: &BTreeSet<String>) -> Value {
    let mut removed = Vec::new();
    let mut failed = Vec::new();
    let mut kept = Vec::new();
    let Ok(entries) = fs::read_dir(control_base) else {
        return json!({ "removed": removed, "failed": failed, "kept": kept });
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = entry.path();
        let is_directory = fs::symlink_metadata(&path).is_ok_and(|metadata| metadata.is_dir());
        if !is_directory {
            continue;
        }
        if live.contains(&name) {
            kept.push(name);
            continue;
        }
        #[cfg(windows)]
        let removed_now = crate::sandbox::qemu_host::remove_private_directory(&path);
        #[cfg(not(windows))]
        let removed_now = fs::remove_dir_all(&path);
        match removed_now {
            Ok(()) => removed.push(name),
            Err(error) => failed.push(json!({ "directory": name, "error": error.to_string() })),
        }
    }
    json!({ "removed": removed, "failed": failed, "kept": kept })
}

/// The directory names of the sandboxes whose QEMU process the service still holds.
fn live_control_names(service: &Service) -> BTreeSet<String> {
    service
        .status()
        .into_iter()
        .filter(|status| status.process.is_some())
        .filter_map(|status| status.vm)
        .map(|vm| {
            let hex = vm.digest().to_hex();
            hex.get(..CONTROL_NAME_HEX_DIGITS)
                .unwrap_or(&hex)
                .to_owned()
        })
        .collect()
}

/// What a service is composed from; the parts are rebuilt when a recovery is refused.
struct Composition {
    runtime: PathBuf,
    data: PathBuf,
    control_base: PathBuf,
    machine: Digest,
    configuration: ConfigurationFingerprint,
    guest: VerifiedGuest,
    executable: PathBuf,
    artifact: Digest,
    golden: crate::sandbox::qemu::GoldenFile,
    ledger: crate::foundation::coordination::SharedLedger<SystemClock>,
    clock: SystemClock,
    instance: Digest,
}

impl Composition {
    fn runtime_subject(&self) -> Result<RuntimeSubject, String> {
        Ok(RuntimeSubject {
            category: ExecutionCategory::VmSandbox,
            release: BackendRelease::new(Backend::Qemu, QEMU_VERSION)
                .map_err(|error| error.to_string())?,
            instance: self.instance,
        })
    }

    fn hypervisor_subject(&self) -> HypervisorSubject {
        HypervisorSubject {
            machine: self.machine,
            hypervisor: HYPERVISOR,
        }
    }

    fn backend(&self) -> Result<BackendIdentity, String> {
        BackendIdentity::new(BackendKind::Qemu, QEMU_VERSION, self.artifact, HYPERVISOR)
            .map_err(|error| error.to_string())
    }

    fn layout(&self) -> Result<RuntimeLayout, String> {
        let images = [(
            self.guest.guest_image,
            GuestImageFiles {
                kernel: host_path(&self.guest.kernel)?,
                initrd: Some(host_path(&self.guest.initrd)?),
                root_image: host_path(&self.guest.root_image)?,
                kernel_arguments: self.guest.kernel_arguments.clone(),
            },
        )]
        .into_iter()
        .collect();
        // The restricted QEMU's logon session SID passes the second access check on Windows.
        #[cfg(windows)]
        let logon_sid = Some(
            HostSids::current()
                .map_err(|error| error.to_string())?
                .logon()
                .clone(),
        );
        #[cfg(not(windows))]
        let logon_sid = None;
        RuntimeLayout::new(LayoutSettings {
            runtime_directory: host_path(&self.runtime)?,
            platform: QemuPlatform {
                os: HOST_OS,
                architecture: Architecture::X86_64,
            },
            resources: GuestResources::new(GUEST_VCPUS, GUEST_MEMORY_BYTES)
                .map_err(|error| error.to_string())?,
            images,
            volumes: Default::default(),
            control_base: host_path(&self.control_base)?,
            logon_sid,
        })
        .map_err(|error| error.to_string())
    }

    fn config(&self) -> Result<VmServiceConfig, String> {
        Ok(VmServiceConfig {
            supervisor: supervisor_config(self.machine, self.guest.guest_image),
            machine: self.machine,
            image: PinnedImage {
                guest_image: self.guest.guest_image,
                configuration: self.configuration,
            },
            contract: digest(
                "yougori/sandbox-vm/contract/v1",
                &[if cfg!(windows) {
                    b"terminal-task-windows-whpx".as_slice()
                } else {
                    b"terminal-task-linux-kvm".as_slice()
                }],
            ),
            device_profile: DeviceProfile {
                identity: digest("yougori/sandbox-vm/device-profile/v1", &[b"cpu-only"]),
                devices: DeviceExposure::cpu_only(),
            },
            required: required_properties(),
            evidence: EvidenceSubjects {
                runtime: self.runtime_subject()?,
                hypervisor: self.hypervisor_subject(),
            },
            driver: DriverSettings::default(),
        })
    }

    /// Fresh parts: the registry with the two host probes, the Windows host, QMP, the
    /// layout, the audit sink on its stream directory, the link connector.
    fn parts(
        &self,
        session: ClockSession,
    ) -> Result<
        (
            VmServiceParts<ProductionPorts>,
            StreamDirectory,
            RuntimeLayout,
            Arc<GuestBodies>,
        ),
        String,
    > {
        let bodies = GuestBodies::new(self.clock, session)?;
        let mut registry = ProbeRegistry::new(self.clock);
        #[cfg(windows)]
        let hypervisor_probe = WhpxProbe {
            machine: self.machine,
            configuration: self.configuration,
        };
        #[cfg(target_os = "linux")]
        let hypervisor_probe = KvmProbe {
            machine: self.machine,
            configuration: self.configuration,
        };
        let runtime_probe = PinnedRuntimeProbe {
            instance: self.instance, artifact: self.artifact,
            executable: self.executable.clone(), configuration: self.configuration,
        };
        #[cfg(windows)]
        {
            let identity = crate::sandbox::hcs::runtime::native_identity()?;
            let subjects = crate::sandbox::hcs::runtime::evidence(&identity, self.machine)?;
            registry.register(Box::new(super::probes::Alternatives(Box::new(hypervisor_probe),
                Box::new(super::probes::HcsProbe { machine: self.machine, configuration: self.configuration })))).map_err(|e|e.to_string())?;
            registry.register(Box::new(super::probes::Alternatives(Box::new(runtime_probe),
                Box::new(PinnedRuntimeProbe { instance: subjects.runtime.instance, artifact: identity.artifact,
                    executable: std::env::current_exe().map_err(|e|e.to_string())?, configuration: self.configuration })))).map_err(|e|e.to_string())?;
        }
        #[cfg(not(windows))]
        {
            registry.register(Box::new(hypervisor_probe)).map_err(|e|e.to_string())?;
            registry.register(Box::new(runtime_probe)).map_err(|e|e.to_string())?;
        }
        let layout = self.layout()?;
        let mut directory = StreamDirectory::durable(self.data.join(AUDIT_DIRECTORY));
        let (sink, _opening) = AuditSink::open_durable_spooled(
            &mut directory,
            JournalId::new("sandbox-vm").map_err(|error| error.to_string())?,
            ProducerId::new("sandbox-vm.supervisor").map_err(|error| error.to_string())?,
            NoAnchor,
            self.clock,
            stream_config()?,
            log_config(),
        )
        .map_err(|error| format!("the audit stream could not be opened: {error}"))?;
        let timeouts = SocketTimeouts::new(Duration::from_secs(5), Duration::from_secs(5))
            .map_err(|error| error.to_string())?;
        #[cfg(windows)]
        let host = WindowsQemuHost::new(
            WindowsHostSettings::standard().map_err(|error| error.to_string())?,
        );
        #[cfg(target_os = "linux")]
        let host = LinuxQemuHost::new(
            LinuxHostSettings::standard(Some(vm_account()?)).map_err(|error| error.to_string())?,
        );
        let parts = VmServiceParts {
            clock: self.clock,
            session,
            registry,
            backend: self.backend()?,
            qemu: QemuSettings {
                executable: host_path(&self.executable)?,
                fresh_for: Duration::from_secs(600),
                golden: self.golden.clone(),
            },
            host,
            monitor: QmpMonitor::new(UnixSocketConnect { timeouts }),
            layout: layout.clone(),
            ledger: Arc::clone(&self.ledger),
            sink,
            connector: LinkSocketConnector { timeouts },
            processes: HostProcessTable,
            transfers: bodies.transfers(),
        };
        Ok((parts, directory, layout, bodies))
    }
}

/// Builds the engine's service (module docs).
async fn compose(app: &AppHandle) -> Result<Production, String> {
    let data = crate::acceptance::app_data(app)?.join(DATA_DIRECTORY);
    // AF_UNIX endpoints need a shared local IPC location. Windows app-data
    // virtualization can make sockets there inaccessible to a native child process;
    // the per-user temp directory is shared by the engine and QEMU.
    // Namespace by state directory so disposable engines retain separate controls.
    // Per-launch directories still receive the same private ACLs and low label.
    #[cfg(windows)]
    let control_base = {
        let scope = digest("yougori/sandbox-vm/control-scope/v1", &[data.to_string_lossy().as_bytes()]).to_string();
        std::env::temp_dir().join("yougori-vm").join(&scope[..16])
    };
    #[cfg(not(windows))]
    let control_base = data.join(CONTROL_DIRECTORY);
    for directory in [&data, &control_base, &data.join(AUDIT_DIRECTORY)] {
        fs::create_dir_all(directory)
            .map_err(|error| format!("{} could not be created: {error}", directory.display()))?;
    }
    let resources = crate::resource_dir(app)?;
    let runtime = crate::runtime::bundled_runtime_root(&resources)?;
    let (machine, configuration, host) = host_identity(app).await?;
    let guest = artifacts::verify_guest(&runtime).map_err(|error| error.to_string())?;
    // Recorded, not required: trust roots naming guest-image publishers refuse every launch
    // (launch_mode_identified) while listing, stopping and cleaning up keep working.
    let publisher = guest_publisher().unwrap_or_else(|refusal| json!({"checked": true, "refused": refusal}));
    let (executable, artifact) =
        artifacts::pinned_executable(&runtime).map_err(|error| error.to_string())?;
    let golden = artifacts::load_golden(&runtime).map_err(|error| error.to_string())?;
    let ledger =
        crate::model_runner::refresh_host_capacity(&crate::automation::shutdown_signal(app))
            .await?;
    let tenant = TenantId::new(TENANT).map_err(|error| error.to_string())?;
    let (clock, tenant_budget) = {
        let mut guard = ledger.lock().map_err(|_| "the host ledger is poisoned")?;
        let budget = install_tenant_budget(&mut guard, &tenant)?;
        (*guard.clock(), budget)
    };
    let instance = digest(
        "yougori/sandbox-vm/runtime-instance/v1",
        &[machine.as_bytes(), artifact.as_bytes()],
    );
    let composition = Composition {
        runtime: runtime.clone(),
        data: data.clone(),
        control_base: control_base.clone(),
        machine,
        configuration,
        guest: guest.clone(),
        executable: executable.clone(),
        artifact,
        golden,
        ledger,
        clock,
        instance,
    };
    let state_file = data.join(STATE_FILE);
    let persisted = read_state(&state_file);
    let session = ClockSession::generate();
    let (parts, directory, layout, bodies) = composition.parts(session)?;
    let config = composition.config()?;
    let mut recovery: Option<RecoveryReport> = None;
    let mut state_refused: Option<String> = None;
    let (service, directory, layout, bodies) = match persisted {
        Ok(Some(state)) => match VmService::recover(parts, config, state) {
            Ok((service, report)) => {
                recovery = Some(report);
                (service, directory, layout, bodies)
            }
            Err(refusal) => {
                state_refused = Some(refusal.to_string());
                let refused = state_file.with_extension("refused.json");
                let _ = fs::rename(&state_file, &refused);
                drop(directory);
                let session = ClockSession::generate();
                let (parts, directory, layout, bodies) = composition.parts(session)?;
                let config = composition.config()?;
                (
                    VmService::new(parts, config).map_err(|error| error.to_string())?,
                    directory,
                    layout,
                    bodies,
                )
            }
        },
        Ok(None) => (
            VmService::new(parts, config).map_err(|error| error.to_string())?,
            directory,
            layout,
            bodies,
        ),
        Err(error) => {
            state_refused = Some(error);
            let refused = state_file.with_extension("refused.json");
            let _ = fs::rename(&state_file, &refused);
            (
                VmService::new(parts, config).map_err(|error| error.to_string())?,
                directory,
                layout,
                bodies,
            )
        }
    };
    bodies.refresh(service.authorities());
    // An earlier engine's supervisor ends that engine's task VMs and then itself (VM-D7);
    // its journal is read once it has, and what it ended is recorded in each sandbox's
    // audit stream, attributed by the records' own fields.
    let supervisor_dir = data.join(SUPERVISOR_DIRECTORY);
    let earlier = lifetimes::earlier_supervisors(&supervisor_dir);
    let (supervisors_at_start, earlier_ends) = lifetimes::summarize(&earlier);
    for (end, supervisor) in &earlier_ends {
        let _ = service.record_fact(
            &SandboxId::new(end.sandbox.clone()),
            Phase::Completed,
            HostFact::TerminationReceipt,
            lifetimes::end_fields(end, supervisor.as_ref(), "journal"),
        );
    }
    // After a restart no QEMU of the earlier run survives: its supervisor ended it, or its
    // kill-on-close job did once no handle was left, so every private directory left is a
    // leftover. While an earlier supervisor still holds a VM, nothing is swept.
    // On Linux the groups a dead engine left (its QEMU ended with it, by its parent-death
    // signal; a group outlives its processes) are removed first, under the same condition.
    #[cfg(target_os = "linux")]
    let groups_at_start = if earlier.still_running.is_empty() {
        let (removed, kept) = LinuxQemuHost::end_leftovers();
        json!({ "removed": removed, "kept": kept })
    } else {
        json!({ "skipped": "an earlier engine's supervisor still holds a VM" })
    };
    #[cfg(not(target_os = "linux"))]
    let groups_at_start = Value::Null;
    let swept = if earlier.still_running.is_empty() {
        sweep_control(&control_base, &BTreeSet::new())
    } else {
        json!({
            "skipped": "an earlier engine's supervisor still holds a VM",
            "still_running": earlier.still_running,
        })
    };
    // The workspaces outlive their sandboxes: what the last run left is recovered, and a
    // promotion it cut short is undone and recorded in the stream, attributed to its
    // sandbox by the record's own fields.
    let workspaces = WorkspaceStore::new(data.join(WORKSPACE_DIRECTORY));
    let mut workspaces_recovered = workspaces.recover();
    // A normalization the last run's end cut short left its throwaway sandbox's copy and
    // staged input (VM-W58); no job runs at a start, so both go.
    let job_inputs = data.join(NORMALIZED_DIRECTORY).join("sources");
    workspaces_recovered["throwaway_copies_removed"] =
        json!(workspaces.discard_imported_from(&job_inputs));
    let _ = fs::remove_dir_all(&job_inputs);
    for interrupted in workspaces_recovered["interrupted_promotions"]
        .as_array()
        .into_iter()
        .flatten()
    {
        let Some(sandbox) = interrupted["sandbox"].as_str() else {
            continue;
        };
        let state = &interrupted["state"];
        let count = |field: &str| state[field].as_array().map_or(0, Vec::len) as u64;
        let fields = vec![
            Field::metadata("action", "artifact_promotion"),
            Field::metadata("promotion", "interrupted"),
            Field::metadata(
                "execution",
                crate::foundation::events::FieldValue::Digest(
                    crate::sandbox_contract::files::execution_reference(
                        &ExecutionId::new(sandbox).unwrap_or_else(|_| ExecutionId::generate()),
                    ),
                ),
            ),
            Field::metadata(
                "outcome",
                state["state"].as_str().unwrap_or("unknown").to_owned(),
            ),
            Field::metadata("restored", count("restored")),
            Field::metadata("removed", count("removed")),
            Field::metadata("left", count("left").saturating_add(count("changed"))),
        ];
        if let Ok(execution) = ExecutionId::new(sandbox) {
            let _ = service.record_fact(
                &SandboxId::new(execution),
                Phase::Failed,
                HostFact::HighImpactOperation,
                fields,
            );
        }
    }
    let summary = json!({
        "platform": PLATFORM_NAME,
        "runtime_directory": runtime.display().to_string(),
        "data_directory": data.display().to_string(),
        "control_directory": control_base.display().to_string(),
        "guest": {
            "profile": guest.profile,
            "kernel_release": guest.kernel_release,
            "guest_image": guest.guest_image.to_hex(),
            "kernel_sha256": guest.kernel_digest.to_hex(),
            "initrd_sha256": guest.initrd_digest.to_hex(),
            "agent_build": guest.agent_build.to_hex(),
            "record_sha256": guest.record_digest.to_hex(),
            "kernel_arguments": guest.kernel_arguments.command_line(),
            "memory_bytes": GUEST_MEMORY_BYTES,
            "memory_bytes_scope": "minimum; actual guest RAM is sized per launch from its host reservation",
            "host_headroom_bytes": crate::sandbox::qemu_host::layout::GUEST_HOST_HEADROOM_BYTES,
            "vcpus": GUEST_VCPUS,
            "publisher": publisher,
        },
        "backend": {
            "kind": "qemu",
            "version": QEMU_VERSION,
            "executable": executable.display().to_string(),
            "artifact": artifact.to_hex(),
            "hypervisor": HYPERVISOR.tag(),
            "golden_digest": composition.golden.digest.to_hex(),
        },
        "machine": machine.to_hex(),
        "configuration": configuration.digest().to_hex(),
        "host": host,
        "tenant": TENANT,
        "tenant_budget": tenant_budget,
        "recovery": encoded(&recovery)?,
        "state_refused": state_refused,
        "swept_at_start": swept,
        "groups_at_start": groups_at_start,
        "workspaces_at_start": workspaces_recovered,
        "combine_at_start": combine::recover(&data),
        "supervisors_at_start": supervisors_at_start,
    });
    let production = Production {
        host_access: super::host_access::Access::open(data.join("host-access.json"))?,
        remote_management: std::sync::Mutex::new(BTreeMap::new()),
        remote_home: OnceLock::new(),
        images: std::sync::Mutex::new(images::ImageState::new(clock)),
        shutdown: crate::automation::shutdown_signal(app),
        service,
        backend: composition.backend()?,
        configuration,
        confinement: std::sync::Mutex::new(None),
        negatives: std::sync::Mutex::new(Vec::new()),
        scans: std::sync::Mutex::new(Vec::new()),
        drills: std::sync::Mutex::new(Vec::new()),
        plant: std::sync::Mutex::new(acceptance_plant()),
        layout,
        guest,
        state_file,
        control_base,
        summary,
        checkpoint_lock: std::sync::Mutex::new(()),
        relays: std::sync::Mutex::new(Relays::default()),
        responses: std::sync::Mutex::new(ViolationResponses::new(clock, ClockSession::generate())?),
        workspaces: std::sync::Mutex::new(workspaces),
        lifetimes: std::sync::Mutex::new(Lifetimes::new(supervisor_dir, lifetimes::settings())),
        bodies,
        clock,
        _audit: directory,
        previews: Arc::new(super::preview::Previews::new()),
        status_view: Arc::new(StatusView::default()),
    };
    production.recover_image_views()?;
    production.checkpoint()?;
    Ok(production)
}

impl super::preview::PreviewHost for Production {
    fn admit(
        &self,
        sandbox: &SandboxId,
        service: &str,
        proof: Option<crate::sandbox_contract::connections::AuthenticationProof>,
        verifier: &dyn crate::sandbox_contract::connections::ProofVerifier,
        outside: Box<dyn crate::sandbox_contract::connections::SessionStream>,
        caller_room: crate::sandbox::vm_service::CallerRoom,
    ) -> Result<
        (u64, crate::sandbox::vm_service::GuestIngressWatch),
        crate::sandbox_contract::connections::GateRefusal,
    > {
        self.service.admit(
            sandbox,
            service,
            proof,
            verifier,
            outside,
            Some(caller_room),
        )
    }

    fn pump(&self) -> crate::sandbox::vm_service::SessionsPumped {
        self.service.pump_sessions()
    }

    fn publication_state(&self, sandbox: &SandboxId, publication: u64) -> Option<&'static str> {
        self.service
            .publications(sandbox)
            .publications
            .into_iter()
            .find(|view| view.publication == publication)
            .map(|view| view.state)
    }
}

impl Production {
    /// Publishes a declared guest service of `sandbox` (M14; module docs in `preview`): a
    /// spent or expired earlier publication of it is withdrawn first, the gate publishes it
    /// for `lifetime` with a response budget of `budget_bytes`, and a loopback listener
    /// serves it; an owner's address carries a token of its own.
    fn publish(
        self: &Arc<Self>,
        sandbox: &SandboxId,
        service: &str,
        audience: crate::sandbox::vm_service::PublicationAudience,
        lifetime: Duration,
        budget_bytes: u64,
        application: bool,
    ) -> Result<Value, String> {
        if application && audience != crate::sandbox::vm_service::PublicationAudience::Owner {
            return Err("Application sessions require an isolated owner-token origin.".into());
        }
        let before = self.service.publications(sandbox);
        let guest_port = before
            .declared
            .iter()
            .find(|port| port.service == service)
            .map(|port| port.port)
            .ok_or_else(|| {
                format!(
                    "The sandbox {sandbox} was not launched to publish {service} (launch --publish {service}=PORT)."
                )
            })?;
        for earlier in before
            .publications
            .iter()
            .filter(|view| view.service == service && !matches!(view.state, "active" | "withdrawn"))
        {
            let _ = self.service.withdraw(sandbox, earlier.publication);
            self.previews.close(sandbox, earlier.publication);
        }
        let (publication, expires_at) = self
            .service
            .publish(sandbox, service, audience, lifetime, budget_bytes)
            .map_err(|error| error.to_string())?;
        let binding = self
            .service
            .proof_binding(sandbox, publication)
            .ok_or("the publication ended at once")?;
        let host: std::sync::Weak<dyn super::preview::PreviewHost> = Arc::downgrade(self) as _;
        let opened = match self.previews.open_mode(
            host.clone(),
            sandbox,
            publication,
            service,
            guest_port,
            audience,
            binding,
            expires_at,
            application,
        ) {
            Ok(opened) => opened,
            Err(error) => {
                let _ = self.service.withdraw(sandbox, publication);
                return Err(error);
            }
        };
        self.previews.start_pump(host);
        // What the service applied, not what was asked: an owner session's publication gets
        // the session's whole release account (vm_service::OWNER_SESSION_RELEASE_BYTES).
        let after = self.service.publications(sandbox);
        let applied_budget = after
            .publications
            .iter()
            .find(|view| view.publication == publication)
            .map_or(budget_bytes, |view| view.response_budget.limit_bytes);
        Ok(json!({
            "sandbox": sandbox,
            "publication": publication,
            "service": service,
            "guest_port": guest_port,
            "application": application,
            "audience": audience,
            "url": opened.url,
            "port": opened.port,
            "expires_in_seconds": lifetime.as_secs(),
            "response_budget_bytes": applied_budget,
            "released_so_far_bytes": before.released_bytes,
            "release_bound_bytes": after.release_bound_bytes,
        }))
    }

    /// Grants `caller`'s connection endpoint `endpoint` the declared `service` of `callee`
    /// (M14; module docs in `vm_service::connect`) and keeps the gate's pump running.
    fn connect(
        self: &Arc<Self>,
        caller: &SandboxId,
        endpoint: &str,
        callee: &SandboxId,
        service: &str,
        lifetime: Duration,
        budget_bytes: u64,
    ) -> Result<Value, String> {
        let endpoint = endpoint.trim().to_ascii_lowercase();
        let port = self
            .service
            .connections(caller)
            .endpoints
            .iter()
            .find(|declared| declared.name == endpoint)
            .map(|declared| declared.port)
            .ok_or_else(|| {
                format!(
                    "The sandbox {caller} was not launched with the connection endpoint {endpoint} (launch --connect {endpoint}=PORT)."
                )
            })?;
        self.service
            .connect(caller, &endpoint, callee, service, lifetime, budget_bytes)
            .map_err(|error| error.to_string())?;
        let host: std::sync::Weak<dyn super::preview::PreviewHost> = Arc::downgrade(self) as _;
        self.previews.start_pump(host);
        Ok(json!({
            "sandbox": caller,
            "endpoint": endpoint,
            "to": callee,
            "service": service,
            "address": format!("{endpoint}:{port}"),
            "expires_in_seconds": lifetime.as_secs(),
            "budget_bytes": budget_bytes,
        }))
    }

    /// Every sandbox's connection endpoints, grants and connections, for those with any.
    fn connection_views(&self) -> Value {
        let mut views = serde_json::Map::new();
        for status in self.service.status() {
            let connections = self.service.connections(&status.sandbox);
            if connections.endpoints.is_empty() && connections.callers.is_empty() {
                continue;
            }
            if let Ok(view) = serde_json::to_value(&connections) {
                views.insert(status.sandbox.execution().as_str().to_owned(), view);
            }
        }
        Value::Object(views)
    }

    /// Stops `sandbox` as `yougori sandbox stop` does: the guest is asked to power off, the VM
    /// is revoked and stopped with the host's proof, its previews and relay end and the
    /// lifetime supervisor lets it go.
    fn stop_sandbox(&self, id: &SandboxId) -> Result<Value, String> {
        // Stopping is idempotent. A VM that has already stopped (for example one the
        // engine found ended after a crash and restart) answers with its state rather
        // than a lifecycle refusal; the engine-side cleanups below still run, and each
        // is a no-op once done.
        let already_stopped = self.service.status().iter().any(|status| {
            status.sandbox == *id && matches!(status.state, Some(SandboxState::Stopped))
        });
        let stopped = if already_stopped {
            Ok(json!({"sandbox": id.execution().as_str(), "state": "stopped", "already_stopped": true}))
        } else {
            self.service
                .stop(id)
                .map_err(|error| error.to_string())
                .and_then(|receipt| encoded(receipt))
        };
        self.refresh_authorities();
        let previews_closed = self.previews.close_sandbox(id);
        let mut value = stopped?;
        if previews_closed > 0 {
            value["previews_closed"] = json!(previews_closed);
        }
        if let Some(relay) = self.stop_relay(id, StopReason::Teardown) {
            value["relay"] = relay;
        }
        if let Some(released) = self.lifetimes().release(id) {
            value["supervisor"] = released;
        }
        self.responses().forget(id.execution());
        Ok(value)
    }

    /// Every sandbox's declared services, publications and listeners.
    fn publication_views(&self) -> Value {
        let mut views = serde_json::Map::new();
        for status in self.service.status() {
            let publications = self.service.publications(&status.sandbox);
            if publications.declared.is_empty() {
                continue;
            }
            views.insert(
                status.sandbox.execution().as_str().to_owned(),
                json!({
                    "declared": publications.declared,
                    "publications": publications.publications,
                    "released_bytes": publications.released_bytes,
                    "previews": self.previews.view(&status.sandbox),
                }),
            );
        }
        Value::Object(views)
    }

    /// Launches one sandbox for `spec` (module docs in `mod.rs`): an acceptance plant armed
    /// first; the lifetime supervisor holds the VM before this returns; the relay for
    /// `routes` and the staged copy of `workspace` beside it. A step that fails stops the
    /// sandbox again, and the error says why. The sandbox and what the launch shows.
    fn launch_with(
        &self,
        spec: LaunchSpec,
        routes: Option<Vec<RouteDeclaration>>,
        workspace: Option<WorkspaceInput>,
    ) -> Result<(SandboxId, Value), String> {
        self.launch_mode(spec, routes, workspace, false)
    }

    fn launch_mode(
        &self,
        spec: LaunchSpec,
        routes: Option<Vec<RouteDeclaration>>,
        workspace: Option<WorkspaceInput>,
        remote_bootstrap: bool,
    ) -> Result<(SandboxId, Value), String> {
        self.launch_mode_identified(spec, routes, workspace, remote_bootstrap, None)
    }

    fn launch_mode_identified(
        &self,
        mut spec: LaunchSpec,
        routes: Option<Vec<RouteDeclaration>>,
        workspace: Option<WorkspaceInput>,
        remote_bootstrap: bool,
        execution: Option<ExecutionId>,
    ) -> Result<(SandboxId, Value), String> {
        // The trust roots in force decide at every launch, not only when the service was
        // composed: a reload that names guest-image publishers refuses the next launch (M18).
        guest_publisher()?;
        if !remote_bootstrap {
            spec.egress_endpoints.push(GuestEgressEndpoint::new(
                super::host_access::ENDPOINT, super::host_access::HOST, 80,
            ).map_err(|e| e.to_string())?);
            check_endpoints(&spec.egress_endpoints).map_err(|e| e.to_string())?;
        }
        if execution.is_some() && !remote_bootstrap {
            return Err("A persisted remote identity needs an empty delegated bootstrap.".into());
        }
        if remote_bootstrap && (routes.is_some() || workspace.is_some()) {
            return Err(
                "A remote bootstrap cannot receive routes or a workspace before delegation.".into(),
            );
        }
        let started = std::time::Instant::now();
        let planted = self.arm_plant();
        let (refused_before, listed_before) = if planted.is_some() {
            (
                self.service.refused_launches(),
                super::process_scan::list_processes().ok(),
            )
        } else {
            (Vec::new(), None)
        };
        let outcome = if remote_bootstrap {
            match execution {
                Some(execution) => self.service.launch_remote_identified(spec, execution),
                None => self.service.launch_remote(spec),
            }
        } else {
            self.service.launch(spec)
        };
        if let Some(fault) = planted {
            self.record_negative(
                fault,
                &refused_before,
                listed_before.as_deref(),
                outcome.as_ref().ok(),
            );
        }
        let id = outcome.map_err(|error| {
            format!(
                "The launch was refused: {error} ({})",
                serde_json::to_string(&error).unwrap_or_default()
            )
        })?;
        // Its guest's file bodies move under the authority the launch granted.
        self.refresh_authorities();
        // The lifetime supervisor holds the VM before the launch returns: a VM it
        // cannot hold is stopped, so no sandbox runs without its end independent of
        // this process (VM-W26).
        let supervisor = match self.lifetimes().hold(&self.service, &id) {
            Ok(held) => held,
            Err(error) => {
                let stopped = self
                    .service
                    .stop(&id)
                    .map(|report| encoded(report).unwrap_or(Value::Null))
                    .map_err(|error| error.to_string());
                return Err(format!(
                    "The sandbox {id} was launched but the lifetime supervisor could not hold it, so it was stopped: {error} (stop: {stopped:?})"
                ));
            }
        };
        // The relay beside the VM: a relay that does not start leaves no sandbox
        // without its declared network, so the launch is undone.
        let relay = match routes {
            Some(routes) => match self.start_relay(&id, routes) {
                Ok(relay) => Some(relay),
                Err(error) => {
                    let stopped = self
                        .service
                        .stop(&id)
                        .map(|report| encoded(report).unwrap_or(Value::Null))
                        .map_err(|error| error.to_string());
                    return Err(format!(
                        "The sandbox {id} was launched but its relay could not start, so it was stopped: {error} (stop: {stopped:?})"
                    ));
                }
            },
            None => {
                if !remote_bootstrap {
                    if let Err(error) = self.service.attach_egress(&id,
                        super::host_access::transport::port(Arc::clone(&self.host_access), id.execution().as_str().into(), None)) {
                        let _ = self.service.stop(&id);
                        return Err(format!("The host-access channel could not start; the VM was stopped: {error}"));
                    }
                }
                None
            },
        };
        // The staged workspace: one that cannot be staged leaves no sandbox running
        // without the files it was launched for.
        let staged = match workspace {
            Some(source) => match self.stage_workspace_input(&id, source) {
                Ok(view) => Some(view),
                Err(error) => {
                    let relay = self.stop_relay(&id, StopReason::Teardown);
                    self.responses().forget(id.execution());
                    let stopped = self
                        .service
                        .stop(&id)
                        .map(|report| encoded(report).unwrap_or(Value::Null))
                        .map_err(|error| error.to_string());
                    return Err(format!(
                        "The sandbox {id} was launched but its workspace could not be staged, so it was stopped: {error} (stop: {stopped:?}; relay: {relay:?})"
                    ));
                }
            },
            None => None,
        };
        let status = self
            .service
            .status()
            .into_iter()
            .find(|status| status.sandbox == id);
        let value = json!({
            "sandbox": id,
            "launch_ms": started.elapsed().as_millis() as u64,
            "status": status,
            "relay": relay,
            "workspace": staged,
            "supervisor": supervisor,
        });
        Ok((id, value))
    }

    /// Normalizes the file `name` of `producer`'s staged workspace (VM-W58; module docs in
    /// `mod.rs`): the raw bytes read without following a link and named by their content
    /// key, a job planned for a throwaway sandbox that is not the producer (no network, no
    /// credential, no host path; its workspace holds the raw bytes alone), the guest's
    /// normalizer run as its terminal, its report read strictly and accepted against the
    /// plan and the output bytes read back, the result stored with its provenance under the
    /// data folder (the raw source beside it when kept) and labelled as normalized, never as
    /// safe. The throwaway sandbox is stopped and its copy removed whatever happened.
    fn normalize(
        &self,
        producer: &SandboxId,
        name: &str,
        declared: DeclaredFormat,
        target: OutputFormat,
        retention: RawRetention,
        max_output_bytes: u64,
    ) -> Result<Value, String> {
        let started = std::time::Instant::now();
        // What this normalizer reads; anything else is refused before a sandbox starts (the
        // guest refuses it too).
        if !matches!(
            declared,
            DeclaredFormat::Html | DeclaredFormat::Archive | DeclaredFormat::PlainText
        ) || !matches!(target, OutputFormat::PlainText | OutputFormat::Markdown)
        {
            return Err(format!(
                "{name} was not normalized and no sandbox was started: {}",
                failure_text(NormalizerFailure::UnsupportedFormat)
            ));
        }
        let (raw_bytes, provenance) = {
            let store = self.workspaces();
            let workspace = store
                .open(producer.execution())?
                .ok_or_else(|| format!("The sandbox {producer} has no staged workspace."))?;
            workspace.read_produced(name, MAX_NORMALIZE_INPUT_BYTES)?
        };
        let raw = route_raw(
            &raw_bytes,
            declared,
            provenance,
            ArtifactOrigin::GuestProduced,
        );
        let base = self.state_file.parent().map_or_else(
            || PathBuf::from(NORMALIZED_DIRECTORY),
            |data| data.join(NORMALIZED_DIRECTORY),
        );
        // The throwaway sandbox's workspace: the raw bytes alone, under the name `input`.
        let source = base
            .join("sources")
            .join(uuid::Uuid::new_v4().simple().to_string());
        fs::create_dir_all(&source)
            .and_then(|()| fs::write(source.join("input"), &raw_bytes))
            .map_err(|error| format!("the job's input could not be staged: {error}"))?;
        let spec = LaunchSpec {
            gpu: false,
            gpu_memory: Vec::new(),
            internet: false,
            owner_session: false,
            tenant: TenantId::new(TENANT).map_err(|error| error.to_string())?,
            resources: VmResources {
                memory_bytes: DEFAULT_LAUNCH_MEMORY_BYTES,
                cpu_slots: 1,
            },
            egress_endpoints: Vec::new(),
            workload_image: None,
            idle_limit: Some(NORMALIZE_TIMEOUT * 2),
            lifetime_limit: Some(NORMALIZE_TIMEOUT * 4),
            published: Vec::new(),
            connect: Vec::new(),
        };
        let launched = self.launch_with(spec, None, Some(WorkspaceInput::Folder(source.clone())));
        let _ = fs::remove_dir_all(&source);
        let (sandbox, _) = launched?;
        let normalized = self.run_normalizer(
            &sandbox,
            raw,
            &raw_bytes,
            target,
            retention,
            max_output_bytes,
            &base,
        );
        // The throwaway sandbox ends whatever happened, and its copy with it.
        let stopped = self
            .service
            .stop(&sandbox)
            .map(|report| encoded(report).unwrap_or(Value::Null))
            .map_err(|error| error.to_string());
        self.refresh_authorities();
        let released = self.lifetimes().release(&sandbox);
        self.responses().forget(sandbox.execution());
        let discarded = self.workspaces().discard(sandbox.execution());
        let mut value = normalized?;
        value["normalizer_sandbox"] = json!({
            "sandbox": sandbox,
            "stopped": match stopped {
                Ok(report) => report,
                Err(error) => json!({ "error": error }),
            },
            "supervisor": released,
            "copy_removed": discarded.unwrap_or(false),
        });
        value["took_ms"] = json!(started.elapsed().as_millis() as u64);
        Ok(value)
    }

    /// The job in `sandbox` (see [`Self::normalize`]): planned, run, accepted, stored.
    #[allow(clippy::too_many_arguments)]
    fn run_normalizer(
        &self,
        sandbox: &SandboxId,
        raw: RawArtifact,
        raw_bytes: &[u8],
        target: OutputFormat,
        retention: RawRetention,
        max_output_bytes: u64,
        base: &Path,
    ) -> Result<Value, String> {
        let execution = sandbox.execution().clone();
        let boot = self
            .service
            .status()
            .into_iter()
            .find(|status| status.sandbox == *sandbox)
            .and_then(|status| status.boot)
            .unwrap_or(SandboxBootGeneration::FIRST);
        let recipe = digest(
            "yougori/sandbox-vm/normalizer-recipe/v1",
            &[
                self.guest.guest_image.as_bytes(),
                self.guest.agent_build.as_bytes(),
            ],
        );
        let normalizer = NormalizerIdentity::new(NORMALIZER_NAME, NORMALIZER_VERSION, recipe)
            .map_err(|error| error.to_string())?;
        let declared = raw.declared();
        let job = NormalizationJob::plan(NormalizationRequest {
            raw,
            target,
            retention,
            normalizer,
            execution: NormalizerExecution {
                execution: execution.clone(),
                category: ExecutionCategory::VmSandbox,
                boot,
                scope: TrustScope::named(ExecutionCategory::VmSandbox, execution.as_str()),
            },
            grants: JobGrants::none(),
            inspection: InspectionMethod::SeparateVm,
            max_output_bytes,
        })
        .map_err(|refusal| refusal.to_string())?;
        job.check_input(raw_bytes)
            .map_err(|refusal| refusal.to_string())?;
        let tag = |value: Value| value.as_str().unwrap_or_default().to_owned();
        let command = format!(
            "{CONFINEMENT_PROBE} normalize {} {} {} {NORMALIZER_NAME} {NORMALIZER_VERSION} {} {} {} {max_output_bytes} \"$WORKSPACE/input\" \"$WORKSPACE/output\"\n",
            job.digest().to_hex(),
            execution.as_str(),
            boot.get(),
            recipe.to_hex(),
            tag(json!(declared)),
            tag(json!(target)),
        );
        let outcome = self
            .service
            .exec(
                sandbox,
                ExecRequest::new(
                    command.into_bytes(),
                    MAX_NORMALIZER_REPORT_BYTES,
                    NORMALIZE_TIMEOUT,
                ),
            )
            .map_err(|error| format!("The normalizer could not run: {error}"))?;
        let printed = String::from_utf8_lossy(outcome.output.as_bytes()).into_owned();
        let line = printed
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .ok_or_else(|| {
                format!(
                    "The normalizer printed no report (exit {:?}).",
                    outcome.exit_code
                )
            })?;
        let report: NormalizationReport = serde_json::from_str(line)
            .map_err(|error| format!("The normalizer's report was refused: {error}"))?;
        let output = match report.outcome {
            NormalizationOutcome::Normalized { .. } => {
                let store = self.workspaces();
                let workspace = store
                    .open(&execution)?
                    .ok_or("the throwaway sandbox's workspace is gone")?;
                workspace
                    .read_produced("output", max_output_bytes.saturating_add(1))?
                    .0
            }
            NormalizationOutcome::Failed { .. } => Vec::new(),
        };
        let artifact = job
            .accept(report, &output)
            .map_err(|refusal| match refusal {
                ResultRefusal::NormalizerFailed { failure } => {
                    format!(
                        "The normalizer did not normalize the file: {}",
                        failure_text(failure)
                    )
                }
                refusal => format!("The normalizer's result was refused: {refusal}"),
            })?;
        let stored = base.join(job.digest().to_hex());
        fs::create_dir_all(&stored)
            .map_err(|error| format!("{} could not be created: {error}", stored.display()))?;
        let write = |name: &str, bytes: &[u8]| {
            write_atomic(&stored.join(name), bytes).map_err(|error| {
                format!(
                    "{} could not be written: {error}",
                    stored.join(name).display()
                )
            })
        };
        write("output", &output)?;
        if retention == RawRetention::KeepSeparately {
            write("raw", raw_bytes)?;
        }
        let record = encoded(&artifact)?;
        write(
            "artifact.json",
            &serde_json::to_vec_pretty(&record).map_err(|error| error.to_string())?,
        )?;
        let text = String::from_utf8_lossy(&output);
        let shown: String = text.chars().take(MAX_SHOWN_OUTPUT_CHARS).collect();
        Ok(json!({
            "job": job.digest(),
            "artifact": record,
            "label": artifact.label(),
            "stored": stored.display().to_string(),
            "output_text": shown,
            "output_truncated": shown.len() < text.len(),
        }))
    }

    /// Writes the supervisor's state durably and confirms it to the service.
    fn checkpoint(&self) -> Result<(), String> {
        let _one_at_a_time = self
            .checkpoint_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(state) = self.service.persist() else {
            return Ok(());
        };
        let bytes = serde_json::to_vec_pretty(&state).map_err(|error| error.to_string())?;
        write_atomic(&self.state_file, &bytes).map_err(|error| {
            format!(
                "{} could not be written: {error}",
                self.state_file.display()
            )
        })?;
        self.service.confirm_persisted(&state);
        Ok(())
    }

    #[cfg_attr(not(windows), allow(dead_code))]
    fn relays(&self) -> std::sync::MutexGuard<'_, Relays> {
        self.relays
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The executor, started on first need and again after its death (the relays it held
    /// died with it, in its job: their records say so).
    #[cfg(windows)]
    fn executor(relays: &mut Relays) -> Result<&mut ExecutorClient, String> {
        if relays.executor.as_ref().is_some_and(ExecutorClient::alive) {
            return relays
                .executor
                .as_mut()
                .ok_or_else(|| "the executor vanished".to_owned());
        }
        if relays.executor.take().is_some() {
            for record in relays.records.values_mut() {
                if record.ended.is_none() {
                    record.ended = Some(json!({ "end": "executor_ended" }));
                }
            }
        }
        let executable = std::env::current_exe()
            .map_err(|error| format!("the engine's executable is unknown: {error}"))?;
        let client = ExecutorClient::start(&executable, EXECUTOR_START_WITHIN)
            .map_err(|error| format!("The sandbox executor could not be started: {error}"))?;
        Ok(relays.executor.insert(client))
    }

    fn lifetimes(&self) -> std::sync::MutexGuard<'_, Lifetimes> {
        self.lifetimes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The lifetime supervisor's heartbeat (module docs in `supervisor`): each end it
    /// reports is recorded in the sandbox's audit stream and revoked for its cause (the
    /// engine counted as failed, or a lease limit past its grace), after which the
    /// service observes the VM's end itself and the relay of a sandbox that lost its
    /// authority is stopped.
    fn supervise(&self) {
        let ends = self.lifetimes().supervise(&self.service);
        self.record_supervisor_ends(&ends);
    }

    fn record_supervisor_ends(
        &self,
        ends: &[(
            super::supervisor::protocol::HeldEnd,
            Option<crate::foundation::process::ProcessIdentity>,
        )],
    ) {
        if ends.is_empty() {
            return;
        }
        for (end, supervisor) in ends {
            let id = SandboxId::new(end.sandbox.clone());
            let _ = self.service.record_fact(
                &id,
                Phase::Completed,
                HostFact::TerminationReceipt,
                lifetimes::end_fields(end, supervisor.as_ref(), "supervisor"),
            );
            if let Some(cause) = lifetimes::revocation_cause(end.cause) {
                let _ = self.service.revoke_ended(&id, cause);
            }
        }
        self.refresh_authorities();
        let _ = self.reconcile_relays();
        let _ = self.checkpoint();
    }

    fn confirm_remote_bound(&self, id: &SandboxId) -> Result<(), String> {
        let (result, ends) = self.lifetimes().confirm_remote_bound(&self.service, id);
        self.record_supervisor_ends(&ends);
        result
    }

    fn accept_remote_frame(
        &self,
        id: &SandboxId,
        frame: &crate::sandbox_contract::remote::SealedFrame,
    ) -> Result<Value, String> {
        let result = (|| {
            if let Some(bound) = self
                .service
                .remote_frame(id, frame)
                .map_err(|e| e.to_string())?
            {
                // Prepare only narrows the supervisor view; it grants no new
                // work. Never acknowledge or activate a grant before that view
                // has reached the independent lifetime process.
                self.confirm_remote_bound(id)?;
                self.service
                    .commit_remote_grant(id, bound)
                    .map_err(|e| e.to_string())?;
                // A renewal can now safely extend the previously narrower
                // deadline, while the old one still enforces the transition.
                self.confirm_remote_bound(id)?;
            }
            Ok(json!({"accepted":true}))
        })();
        if result.is_err() {
            self.service.remote_close(id);
        }
        result
    }

    /// The response path (module docs in `responses`).
    fn responses(&self) -> std::sync::MutexGuard<'_, ViolationResponses<SystemClock>> {
        self.responses
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Starts `sandbox`'s relay for `routes` (below), registered with the response path
    /// first so its first refusal is answered for; a relay that does not start leaves the
    /// sandbox unregistered.
    fn start_relay(
        &self,
        sandbox: &SandboxId,
        routes: Vec<RouteDeclaration>,
    ) -> Result<Value, String> {
        self.responses().register(sandbox.execution())?;
        let started = self.start_registered_relay(sandbox, routes);
        if started.is_err() {
            self.responses().forget(sandbox.execution());
        }
        started
    }

    /// Linux: no relay starts (module docs in `mod.rs`); a launch with routes is refused
    /// before anything starts, so this is reached only by a caller that skipped that.
    #[cfg(not(windows))]
    fn start_registered_relay(
        &self,
        _sandbox: &SandboxId,
        _routes: Vec<RouteDeclaration>,
    ) -> Result<Value, String> {
        Err(RELAYS_UNAVAILABLE.to_owned())
    }

    /// Starts `sandbox`'s relay for `routes` through the executor and attaches the guest
    /// pipe the relay opens as the sandbox's egress port. A relay that does not start or
    /// open its pipe is stopped again, and the error says why.
    #[cfg(windows)]
    fn start_registered_relay(
        &self,
        sandbox: &SandboxId,
        routes: Vec<RouteDeclaration>,
    ) -> Result<Value, String> {
        let names: Vec<String> = routes.iter().map(|route| route.name.clone()).collect();
        let mut relays = self.relays();
        let executor = Self::executor(&mut relays)?;
        let reply = executor.request(
            &ExecutorRequest::StartRelay {
                sandbox: sandbox.execution().clone(),
                routes,
            },
            EXECUTOR_REQUEST_WITHIN,
        )?;
        let (
            relay,
            container_sid,
            guest_pipe,
            credentialed_routes,
            host_addresses,
            host_inventory_error,
        ) = match reply {
            ExecutorReply::RelayStarted {
                relay,
                container_sid,
                guest_pipe,
                credentialed_routes,
                host_addresses,
                host_inventory_error,
                ..
            } => (
                relay,
                container_sid,
                guest_pipe,
                credentialed_routes,
                host_addresses,
                host_inventory_error,
            ),
            ExecutorReply::Refused { detail } => {
                return Err(format!("The relay was refused: {detail}"))
            }
            other => {
                return Err(format!(
                    "The executor answered {other:?} to the relay start."
                ))
            }
        };
        let attached = (|| -> Result<(), String> {
            let sid = hex::decode(&container_sid)
                .map_err(|error| format!("the relay's container SID is not hex: {error}"))?;
            let name = RelayPipeName::new(guest_pipe.clone()).map_err(|error| error.to_string())?;
            let mut listener = GuestPipeListener::create(name, &sid)
                .map_err(|error| format!("the guest pipe could not be created: {error}"))?;
            let server = listener
                .accept(&relay, GUEST_PIPE_ACCEPT_WITHIN)
                .map_err(|error| format!("the relay did not open the guest pipe: {error}"))?;
            self.service
                .attach_egress(sandbox, super::host_access::transport::port(
                    Arc::clone(&self.host_access), sandbox.execution().as_str().into(),
                    Some(Box::new(PipeEgressPort::new(server)))))
                .map_err(|error| format!("the egress port could not be attached: {error}"))
        })();
        if let Err(error) = attached {
            let _ = executor.request(
                &ExecutorRequest::StopRelay {
                    sandbox: sandbox.execution().clone(),
                    reason: StopReason::Teardown,
                },
                EXECUTOR_REQUEST_WITHIN,
            );
            return Err(format!(
                "The relay started but its guest pipe was not attached: {error}"
            ));
        }
        let acceptance_mark = acceptance_mark(executor, sandbox, &names);
        let record = RelayRecord {
            relay,
            guest_pipe,
            routes: names,
            credentialed_routes,
            host_addresses,
            host_inventory_error,
            status: None,
            ended: None,
            acceptance_mark,
        };
        let value = encoded(&record)?;
        relays.records.insert(sandbox.execution().clone(), record);
        Ok(value)
    }

    /// Linux: detaches `sandbox`'s egress port; no relay runs there.
    #[cfg(not(windows))]
    fn stop_relay(&self, sandbox: &SandboxId, _reason: StopReason) -> Option<Value> {
        let _ = self.service.detach_egress(sandbox);
        None
    }

    /// Detaches `sandbox`'s egress port (guest opens refused, open streams cancelled) and
    /// stops its relay for `reason`; the record, or `None` for a sandbox without a relay.
    #[cfg(windows)]
    fn stop_relay(&self, sandbox: &SandboxId, reason: StopReason) -> Option<Value> {
        let _ = self.service.detach_egress(sandbox);
        let mut relays = self.relays();
        let Relays { executor, records } = &mut *relays;
        let record = records.get_mut(sandbox.execution())?;
        if record.ended.is_none() {
            let life = match executor.as_mut().filter(|client| client.alive()) {
                Some(client) => match client.request(
                    &ExecutorRequest::StopRelay {
                        sandbox: sandbox.execution().clone(),
                        reason,
                    },
                    EXECUTOR_REQUEST_WITHIN,
                ) {
                    Ok(ExecutorReply::RelayStopped { life, .. }) => {
                        json!({ "end": "stopped", "reason": reason, "life": life })
                    }
                    Ok(other) => {
                        json!({ "end": "stopped", "reason": reason, "unexpected": format!("{other:?}") })
                    }
                    Err(error) => json!({ "end": "stopped", "reason": reason, "error": error }),
                },
                None => json!({ "end": "executor_ended" }),
            };
            record.ended = Some(life);
        }
        encoded(&*record).ok()
    }

    /// Asks the executor what happened since the last look: relays that ended on their own
    /// are noticed and their egress ports detached, an executor that died marks every relay
    /// it held, and the refused exchanges go to the response path, whose decisions are
    /// audited and then enforced here, outside the relays' lock (enforcing stops relays).
    /// The poller runs this every [`POLL_EVERY`]; the status runs it too.
    #[cfg(windows)]
    fn poll_relays(&self) {
        let (refusals, dropped) = {
            let mut relays = self.relays();
            let Relays { executor, records } = &mut *relays;
            match executor.as_mut() {
                Some(client) if client.alive() => {
                    match client.request(&ExecutorRequest::Poll, EXECUTOR_REQUEST_WITHIN) {
                        Ok(ExecutorReply::Ended {
                            lives,
                            refusals,
                            refusals_dropped,
                        }) => {
                            for life in lives {
                                if let Some(record) = records.get_mut(&life.sandbox) {
                                    if record.ended.is_none() {
                                        let _ = self
                                            .service
                                            .detach_egress(&SandboxId::new(life.sandbox.clone()));
                                        record.ended =
                                            Some(json!({ "end": "relay_ended", "life": life }));
                                    }
                                }
                            }
                            (refusals, refusals_dropped)
                        }
                        _ => return,
                    }
                }
                Some(_) => {
                    for (sandbox, record) in records.iter_mut() {
                        if record.ended.is_none() {
                            let _ = self.service.detach_egress(&SandboxId::new(sandbox.clone()));
                            record.ended = Some(json!({ "end": "executor_ended" }));
                        }
                    }
                    return;
                }
                None => return,
            }
        };
        let mut changed = false;
        if !refusals.is_empty() || dropped != 0 {
            let (faults, decisions) = {
                let mut responses = self.responses();
                let faults = responses.ingest(refusals, dropped);
                (faults, responses.decide())
            };
            for fault in faults {
                let audit =
                    self.audit_running(&fault.sandbox, HostFact::DetectionSignal, fault.fields);
                self.responses().fault_audited(&fault.sandbox, audit);
            }
            for decided in decisions {
                changed |= self.enforce(decided);
            }
        }
        changed |= self.reconcile_relays() > 0;
        if changed {
            // The revocation is in the service's memory; the next checkpoint retries a
            // failed write.
            let _ = self.checkpoint();
        }
    }

    /// Linux: no executor to ask; nothing is refused through a relay there.
    #[cfg(not(windows))]
    fn poll_relays(&self) {}

    /// Stops the relay of every sandbox that no longer holds authority although nobody
    /// stopped its relay: its lease expired, its guest powered off or its link was lost, or
    /// it was revoked elsewhere. Each relay is stopped with the revocation's reason (its
    /// credential grant and egress go with it) and the sandbox leaves the response path.
    /// How many were stopped.
    fn reconcile_relays(&self) -> usize {
        let live: Vec<ExecutionId> = self
            .relays()
            .records
            .iter()
            .filter(|(_, record)| record.ended.is_none())
            .map(|(sandbox, _)| sandbox.clone())
            .collect();
        if live.is_empty() {
            return 0;
        }
        let statuses = self.service.status();
        let mut stopped = 0;
        for sandbox in live {
            let holds = statuses
                .iter()
                .find(|status| status.sandbox.execution() == &sandbox)
                .and_then(|status| status.state)
                .is_some_and(SandboxState::holds_authority);
            if !holds {
                let _ = self.stop_relay(&SandboxId::new(sandbox.clone()), StopReason::Revoked);
                self.responses().forget(&sandbox);
                stopped += 1;
            }
        }
        stopped
    }

    /// Audits one decision (its signals, then the decision) and enforces it on every target
    /// (module docs in `responses`): `Stop` or `Revoke` stop the relay with the revocation's
    /// reason and revoke the sandbox for a violation; `Isolate` stops the relay and refuses
    /// new commands while the VM keeps its state; `DenyNewHighImpact` refuses new commands;
    /// `NotifyUser`, when the responder's rate allows it, tells the user what was done.
    /// Whether the service's state changed.
    #[cfg_attr(not(windows), allow(dead_code))]
    fn enforce(&self, decided: Decided) -> bool {
        let Decided { signals, record } = decided;
        let origin = record.key.sandbox.clone();
        let mut audit: Vec<Value> = signals
            .iter()
            .map(|signal| {
                self.audit_running(&origin, HostFact::DetectionSignal, signal.audit_fields())
            })
            .collect();
        audit.push(self.audit_running(
            &origin,
            HostFact::AuthorizationDecision,
            record.audit_fields(),
        ));
        let what = format!(
            "{} observed by the {}",
            record.decision.input.class.label(),
            record
                .decision
                .input
                .source
                .observer()
                .map_or("host", |observer| observer.label())
        );
        let mut enforced = Vec::new();
        let mut changed = false;
        for target in &record.targets {
            let sandbox = SandboxId::new(target.sandbox.clone());
            let actions = &target.new_actions;
            let mut done: Vec<&str> = Vec::new();
            if actions.contains(&ResponseAction::Stop) || actions.contains(&ResponseAction::Revoke)
            {
                let relay = self.stop_relay(&sandbox, StopReason::Revoked);
                self.responses().forget(&target.sandbox);
                let revoked = self.service.revoke(&sandbox, RevokeReason::Violation);
                changed = true;
                done.push(if revoked.is_ok() {
                    "its relay was stopped and the sandbox revoked"
                } else {
                    "its relay was stopped; the revocation was refused (see the status)"
                });
                enforced.push(json!({
                    "sandbox": target.sandbox,
                    "action": "revoke",
                    "relay": relay,
                    "revocation": match revoked {
                        Ok(report) => encoded(report).unwrap_or(Value::Null),
                        Err(error) => json!({ "refused": error.to_string() }),
                    },
                }));
            } else {
                if actions.contains(&ResponseAction::Isolate) {
                    let relay = self.stop_relay(&sandbox, StopReason::Revoked);
                    self.responses()
                        .restrict(&target.sandbox, ResponseAction::Isolate);
                    done.push(
                        "its relay was stopped and new commands are refused; the VM keeps its state",
                    );
                    enforced.push(json!({
                        "sandbox": target.sandbox,
                        "action": "isolate",
                        "relay": relay,
                    }));
                }
                if actions.contains(&ResponseAction::DenyNewHighImpact) {
                    self.responses()
                        .restrict(&target.sandbox, ResponseAction::DenyNewHighImpact);
                    done.push("new commands are refused");
                    enforced.push(json!({
                        "sandbox": target.sandbox,
                        "action": "deny_new_high_impact",
                    }));
                }
            }
            if let Some(NotificationOutcome::Sent { .. }) = target.notification {
                let done = if done.is_empty() {
                    "nothing more was needed".to_owned()
                } else {
                    done.join("; ")
                };
                self.responses().notice(
                    &target.sandbox,
                    format!("Sandbox {}: a violation ({what}); {done}.", target.sandbox),
                );
            }
        }
        self.responses().settle(record, audit, enforced);
        changed
    }

    /// Runs the confinement probe in `sandbox` as its terminal (the guest's report of its
    /// inner confinement under the strict tool profile) and evaluates it (V15, VM-CP-05)
    /// with the host's own corroboration: the root image this host verified and booted and
    /// the build facts of the pinned kernel's configuration. No signed manifest exists for
    /// the guest image yet (M01/M18), so none is compared. The verdict and what it was made
    /// from.
    fn probe_confinement(
        &self,
        sandbox: &SandboxId,
    ) -> Result<(Value, ConfinementVerdict), String> {
        let profile = ConfinementProfile::builtin(WorkloadProfile::StrictTool)
            .map_err(|error| format!("The strict tool profile could not be built: {error}"))?;
        let command = format!(
            "{CONFINEMENT_PROBE} probe-confinement {}\n",
            profile.digest().to_hex()
        );
        let outcome = self
            .service
            .exec(
                sandbox,
                ExecRequest::new(
                    command.into_bytes(),
                    MAX_GUEST_REPORT_BYTES + 4096,
                    PROBE_TIMEOUT,
                ),
            )
            .map_err(|error| format!("The confinement probe could not run: {error}"))?;
        let text = String::from_utf8_lossy(outcome.output.as_bytes()).into_owned();
        let mut lines = text.lines().map(str::trim).filter(|line| !line.is_empty());
        let document = lines.next().ok_or_else(|| {
            format!(
                "The confinement probe printed nothing (exit {:?}).",
                outcome.exit_code
            )
        })?;
        let report = GuestReport::from_json(document).map_err(|error| {
            format!("The guest's confinement report was refused: {error} ({document})")
        })?;
        let seccomp = lines
            .next()
            .and_then(|line| serde_json::from_str::<Value>(line).ok())
            .unwrap_or(Value::Null);
        let (kernel_digest, configuration_digest, options) = {
            #[cfg(windows)]
            {
                let launch = combine::launch_params(self, sandbox)?;
                if launch["gpu"] == true {
                    let manifest = crate::sandbox::hcs::runtime::verify_bundle(Path::new(self.layout.settings().runtime_directory.as_str()), self.guest.guest_image)?;
                    let root = crate::sandbox::hcs::runtime::bundle_path();
                    (Digest::from_hex(manifest["files"]["kernel"].as_str().ok_or("GPU kernel identity missing")?).map_err(|e|e.to_string())?,
                     Digest::from_hex(manifest["files"]["kernel.config"].as_str().ok_or("GPU kernel configuration missing")?).map_err(|e|e.to_string())?,
                     artifacts::kernel_options_of(&std::fs::read_to_string(root.join("kernel.config")).map_err(|e|e.to_string())?))
                } else { (self.guest.kernel_digest,self.guest.kernel_configuration_digest,self.guest.kernel_options.clone()) }
            }
            #[cfg(not(windows))]
            { (self.guest.kernel_digest,self.guest.kernel_configuration_digest,self.guest.kernel_options.clone()) }
        };
        let kernel = KernelBuildRecord::new(kernel_digest, options.iter().copied())
        .map_err(|error| format!("The kernel build record was refused: {error}"))?;
        let host = HostCorroboration::host_observed(
            self.guest.guest_image,
            kernel,
            Vec::<KernelSetting>::new(),
        );
        let verdict = evaluate(&profile, Some(&report), Some(&host), None);
        let view = json!({
            "profile": profile.digest(),
            "workload": profile.workload(),
            "probe_exit_code": outcome.exit_code,
            "guest_report": serde_json::from_str::<Value>(document).unwrap_or(Value::Null),
            "guest_seccomp": seccomp,
            "host": {
                "root_image": self.guest.guest_image,
                "kernel_image": kernel_digest,
                "kernel_configuration": configuration_digest,
                "kernel_options": options.iter().map(|(option, state)| json!({ "option": option, "state": state })).collect::<Vec<_>>(),
                "signed_manifest": Value::Null,
            },
            "verdict": encoded(&verdict)?,
        });
        Ok((view, verdict))
    }

    /// Gives the supervisor's durable audit stream one fact about `sandbox` from the
    /// response path; the receipt (its sequence and where the record is) or why it was
    /// refused.
    #[cfg_attr(not(windows), allow(dead_code))]
    fn audit_running(&self, sandbox: &ExecutionId, fact: HostFact, fields: Vec<Field>) -> Value {
        match self
            .service
            .record_running_fact(&SandboxId::new(sandbox.clone()), fact, fields)
        {
            Ok(Ok(receipt)) => json!({
                "fact": fact,
                "sequence": receipt.sequence,
                "durability": format!("{:?}", receipt.durability),
            }),
            Ok(Err(refusal)) => json!({ "fact": fact, "refused": refusal.to_string() }),
            Err(error) => json!({ "fact": fact, "refused": error.to_string() }),
        }
    }

    /// Linux: no executor and no relay (module docs in `mod.rs`); the response path.
    #[cfg(not(windows))]
    fn relay_status(&self) -> Value {
        json!({
            "executor": Value::Null,
            "relays": {},
            "available": false,
            "reason": RELAYS_UNAVAILABLE,
            "responses": self.responses().view(),
        })
    }

    /// Polls the executor ([`Self::poll_relays`]), then shows the executor, every relay with
    /// the executor's last word on it, and the response path.
    #[cfg(windows)]
    fn relay_status(&self) -> Value {
        self.poll_relays();
        let mut relays = self.relays();
        let Relays { executor, records } = &mut *relays;
        let executor_view = match executor.as_mut() {
            Some(client) if client.alive() => {
                for (sandbox, record) in records.iter_mut() {
                    if record.ended.is_some() {
                        continue;
                    }
                    if let Ok(ExecutorReply::Status { relay, .. }) = client.request(
                        &ExecutorRequest::Status {
                            sandbox: sandbox.clone(),
                        },
                        EXECUTOR_REQUEST_WITHIN,
                    ) {
                        record.status = encoded(&relay).ok();
                    }
                }
                json!({
                    "process": client.identity(),
                    "alive": true,
                    "start": client.observation(),
                    "restrictions": client.restrictions().unwrap_or_else(|error| json!({ "unreadable": error })),
                })
            }
            Some(client) => json!({ "process": client.identity(), "alive": false }),
            None => Value::Null,
        };
        let relays_view: serde_json::Map<String, Value> = records
            .iter()
            .map(|(sandbox, record)| (sandbox.to_string(), encoded(record).unwrap_or(Value::Null)))
            .collect();
        drop(relays);
        json!({
            "executor": executor_view,
            "relays": relays_view,
            "responses": self.responses().view(),
        })
    }

    /// Acceptance builds: arms the planted fault for this launch, once (module docs in
    /// `qemu_host::windows_host`); a product build plants nothing.
    fn arm_plant(&self) -> Option<ControlledFault> {
        let fault = self
            .plant
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pop_front()?;
        #[cfg(all(feature = "acceptance", windows))]
        {
            use std::sync::atomic::Ordering::SeqCst;
            match fault {
                ControlledFault::PlantedShareDevice => {
                    crate::sandbox::qemu_host::windows_host::PLANT_SHARE_DEVICE.store(true, SeqCst)
                }
                ControlledFault::HypervisorUnavailable => {
                    crate::sandbox::qemu_host::windows_host::PLANT_TCG.store(true, SeqCst)
                }
                ControlledFault::GpuPathUnavailable => {
                    crate::sandbox::vm_service::PLANT_GPU_REQUEST.store(true, SeqCst)
                }
                _ => {}
            }
        }
        Some(fault)
    }

    /// Acceptance builds only: with `YOUGORI_ACCEPTANCE_LEAVE_FALLBACK=1`, a refused negative
    /// launch leaves a start behind on purpose (VM-CP-33's failure case): the pinned QEMU,
    /// emulated, with no machine and paused, as this engine's child. The scan after the
    /// refusal must find it and fail `cp33.fallback-start`. The acceptance run kills it.
    #[cfg(feature = "acceptance")]
    fn leave_fallback(&self) {
        if std::env::var("YOUGORI_ACCEPTANCE_LEAVE_FALLBACK")
            .ok()
            .as_deref()
            != Some("1")
        {
            return;
        }
        let Some(executable) = self.summary["backend"]["executable"].as_str() else {
            return;
        };
        let _ = std::process::Command::new(executable)
            .args([
                "-accel",
                "tcg",
                "-machine",
                "none",
                "-nodefaults",
                "-display",
                "none",
                "-S",
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
    }

    /// Clears every plant, once its launch was answered.
    fn disarm_plants(&self) {
        #[cfg(all(feature = "acceptance", windows))]
        {
            use std::sync::atomic::Ordering::SeqCst;
            crate::sandbox::qemu_host::windows_host::PLANT_SHARE_DEVICE.store(false, SeqCst);
            crate::sandbox::qemu_host::windows_host::PLANT_TCG.store(false, SeqCst);
            crate::sandbox::vm_service::PLANT_GPU_REQUEST.store(false, SeqCst);
        }
    }

    /// A process-list scan taken now, stamped on the service's evidence clock under this
    /// host's configuration; `before` is the list taken right before a negative launch.
    fn process_scan(
        &self,
        moment: ScanMoment,
        before: Option<&[crate::sandbox::probes::ListedProcess]>,
    ) -> Option<HostObserved<ProcessScan>> {
        let list = super::process_scan::list_processes().ok()?;
        let now = self.service.clock_reading()?;
        Some(HostObserved::stamp(
            ProcessScan::build(moment, &list, std::process::id(), before),
            now,
            CONFINEMENT_FRESH_FOR,
            self.configuration,
        ))
    }

    /// Records how the backend answered a launch that planted `fault`: the refusal it made
    /// for this launch (one not in `before`), stamped on the service's evidence clock under
    /// this host's configuration, or the record it sealed anyway.
    fn record_negative(
        &self,
        fault: ControlledFault,
        before: &[crate::sandbox::integration::RefusedLaunch],
        listed_before: Option<&[crate::sandbox::probes::ListedProcess]>,
        launched: Option<&SandboxId>,
    ) {
        self.disarm_plants();
        let outcome = match launched {
            Some(sandbox) => self
                .service
                .launch_records()
                .into_iter()
                .rev()
                .find(|record| record.sandbox().execution == *sandbox.execution())
                .map(|record| NegativeOutcome::Launched {
                    record: Box::new(record),
                }),
            None => {
                let refusal = self
                    .service
                    .refused_launches()
                    .into_iter()
                    .rev()
                    .find(|refused| !before.contains(refused))
                    .and_then(|refused| match refused.problem {
                        crate::sandbox::integration::LaunchProblem::Backend { refusal } => {
                            Some(refusal)
                        }
                        _ => None,
                    });
                match (refusal, self.service.clock_reading()) {
                    (Some(refusal), Some(now)) => Some(NegativeOutcome::Refused {
                        refusal: crate::sandbox::backend::HostObserved::stamp(
                            refusal,
                            now,
                            CONFINEMENT_FRESH_FOR,
                            self.configuration,
                        ),
                    }),
                    _ => None,
                }
            }
        };
        // After a refusal: what the attempt left running, against the list from before it.
        if matches!(outcome, Some(NegativeOutcome::Refused { .. })) {
            #[cfg(feature = "acceptance")]
            self.leave_fallback();
            if let Some(scan) = self.process_scan(ScanMoment::AfterRefusal { fault }, listed_before)
            {
                self.scans
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push(scan);
            }
        }
        if let Some(outcome) = outcome {
            self.negatives
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push((fault, outcome));
        }
    }

    /// Keeps `params`, the parameters `id` was launched with, beside it while it runs.
    fn record_launch(&self, id: &SandboxId, params: &Value) {
        let Some(data) = self.state_file.parent() else { return };
        let folder = data.join(combine::LAUNCHES_DIRECTORY);
        let record = json!({"sandbox": id, "params": params});
        if fs::create_dir_all(&folder).is_ok() {
            if let Ok(bytes) = serde_json::to_vec(&record) {
                let _ = write_atomic(&folder.join(format!("{}.json", id.execution().as_str())), &bytes);
            }
        }
    }

    /// Tells the body ports each sandbox's authority now (module docs in `ports`).
    fn refresh_authorities(&self) {
        self.refresh_images();
        self.bodies.refresh(self.service.authorities());
        combine::prune_launches(self);
        // Ended identities never lend their approvals to another VM. Retry a failed
        // durable cleanup on the next refresh; the ended VM's port is already closed.
        if let Ok(mut access) = self.host_access.try_lock() {
            let live = self.service.status().into_iter()
                .filter(|row| row.state.is_some_and(SandboxState::holds_authority))
                .map(|row| row.sandbox.execution().as_str().to_owned()).collect();
            let _ = access.retain_running(&live);
        }
    }

    fn workspaces(&self) -> std::sync::MutexGuard<'_, WorkspaceStore> {
        self.workspaces
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Stages `folder` as `sandbox`'s workspace: a copy without its credential locations,
    /// attached to the sandbox's file channel as the workspace grant. A grant that is
    /// refused leaves no workspace.
    fn stage_workspace(&self, sandbox: &SandboxId, folder: &Path) -> Result<Value, String> {
        self.stage_workspace_input(sandbox, WorkspaceInput::Folder(folder.to_owned()))
    }

    fn stage_workspace_input(&self, sandbox: &SandboxId, input: WorkspaceInput) -> Result<Value, String> {
        let boot = self
            .service
            .status()
            .into_iter()
            .find(|status| status.sandbox == *sandbox)
            .and_then(|status| status.boot)
            .map_or(1, |boot| boot.get());
        let store = self.workspaces();
        let workspace = match input {
            WorkspaceInput::Folder(folder) => store.import(sandbox.execution(), boot, &folder)?,
            WorkspaceInput::Saved(previous) => {
                if self.service.status().iter().any(|status| status.sandbox.execution() == &previous && status.state.is_some_and(SandboxState::holds_authority)) {
                    return Err("Stop the previous VM before restoring its private workspace".into());
                }
                store.restore(sandbox.execution(), boot, &previous)?
            }
        };
        let quota = FileQuota {
            max_total_bytes: staged::MAX_TOTAL_BYTES,
            max_entries: (staged::MAX_FILES as u64).saturating_mul(2),
            max_file_bytes: staged::MAX_FILE_BYTES,
        };
        let uploads = workspace.uploads();
        if let Err(error) = self.service.attach_workspace(
            sandbox,
            &workspace.staging(),
            Some(&uploads),
            quota,
            WORKSPACE_GRANT_FOR,
        ) {
            let _ = store.discard(sandbox.execution());
            return Err(error.to_string());
        }
        let mut view = workspace.view();
        view["mounted_in_guest_at"] = json!(GUEST_WORKSPACE);
        Ok(view)
    }

    /// Every workspace, with whether its sandbox still runs (and so still reaches it).
    fn workspace_views(&self) -> Vec<Value> {
        let running: BTreeSet<ExecutionId> = self
            .service
            .status()
            .into_iter()
            .filter(|status| status.phase == Some(crate::sandbox::vm_service::BootPhase::Ready))
            .map(|status| status.sandbox.execution().clone())
            .collect();
        self.workspaces()
            .list()
            .into_iter()
            .map(|record| {
                json!({
                    "sandbox": record.sandbox,
                    "sandbox_running": running.contains(&record.sandbox),
                    "folder": record.source,
                    "imported_at": record.imported_at,
                    "files": record.baseline.len(),
                    "excluded": record.excluded.len(),
                    "skipped": record.skipped.len(),
                    "state": record.state,
                })
            })
            .collect()
    }

    /// The `workspace` action: `list`, `show`, `review`, `promote` or `discard`.
    fn workspace(&self, params: &Value) -> Result<Value, String> {
        let op = string(params, "op").unwrap_or_else(|| "list".to_owned());
        if op == "list" {
            return Ok(json!({ "workspaces": self.workspace_views() }));
        }
        let sandbox = sandbox_id(params)?;
        if op == "discard" {
            // The guest loses the workspace first, then it is removed.
            let detached = self.service.detach_workspace(&sandbox);
            let removed = self.workspaces().discard(sandbox.execution())?;
            if !removed {
                return Err(format!("Sandbox {sandbox} has no workspace."));
            }
            return Ok(
                json!({ "sandbox": sandbox, "discarded": true, "detached_from_guest": detached }),
            );
        }
        let store = self.workspaces();
        let mut workspace = store
            .open(sandbox.execution())?
            .ok_or_else(|| format!("Sandbox {sandbox} has no workspace."))?;
        match op.as_str() {
            "source" => Ok(json!({"source":workspace.staging()})),
            "show" => {
                let mut view = workspace.view();
                view["changes"] = encoded(workspace.changes()?)?;
                Ok(view)
            }
            "review" => workspace.review(),
            "promote" => {
                let review = string(params, "review").ok_or(
                    "The review being approved is required (review, from workspace review).",
                )?;
                let files: Vec<String> = match params.get("files") {
                    Some(Value::Array(items)) => items
                        .iter()
                        .map(|item| {
                            item.as_str()
                                .map(str::to_owned)
                                .ok_or("files must be names")
                        })
                        .collect::<Result<_, _>>()?,
                    _ => {
                        return Err(
                            "The approved files are required (files, names from the review)."
                                .to_owned(),
                        )
                    }
                };
                let mut audit = StreamAudit {
                    service: &self.service,
                    sandbox: &sandbox,
                };
                let promoted = workspace.promote(
                    &review,
                    &files,
                    &mut audit,
                    &self.clock,
                    ClockSession::generate(),
                )?;
                Ok(
                    json!({ "sandbox": sandbox, "folder": workspace.record.source, "promoted": promoted }),
                )
            }
            other => Err(format!(
                "Unknown workspace op '{other}'. Use list, show, review, promote or discard."
            )),
        }
    }

    /// Linux: no executor holds a vault there (module docs in `mod.rs`).
    #[cfg(not(windows))]
    fn credential(&self, _params: &Value) -> Result<Value, String> {
        Err(RELAYS_UNAVAILABLE.to_owned())
    }

    /// Enrolls, removes or checks a credential in the executor's vault store. The secret
    /// arrives in the request (from the CLI's `--file -`), crosses to the executor once and
    /// is overwritten here; nothing of it is answered.
    #[cfg(windows)]
    fn credential(&self, params: &Value) -> Result<Value, String> {
        let op = string(params, "op")
            .ok_or("A credential operation is required (op: enroll, remove or holds).")?;
        let name = string(params, "name").ok_or("A credential name is required (name).")?;
        let request = match op.as_str() {
            "enroll" => {
                let mut secret = string(params, "secret").ok_or(
                    "The secret is required (secret), given through --file - and never on the command line.",
                )?;
                if secret.is_empty() {
                    return Err("The secret is empty.".to_owned());
                }
                let form = match params
                    .get("form")
                    .and_then(Value::as_str)
                    .unwrap_or("bearer")
                {
                    "raw" => ValueForm::Raw,
                    "bearer" => ValueForm::Bearer,
                    other => return Err(format!("form must be raw or bearer, not {other}.")),
                };
                let secret_hex = hex::encode(secret.as_bytes());
                // SAFETY: the bytes are overwritten with ASCII zeros, which keeps the string
                // valid UTF-8.
                wipe(unsafe { secret.as_bytes_mut() });
                ExecutorRequest::Enroll {
                    name,
                    class: SecretClass::LongLivedProviderCredential,
                    form,
                    secret_hex,
                }
            }
            "remove" => ExecutorRequest::Remove { name },
            "holds" => ExecutorRequest::Holds { name },
            other => return Err(format!("op must be enroll, remove or holds, not {other}.")),
        };
        let reply = {
            let mut relays = self.relays();
            let executor = Self::executor(&mut relays)?;
            executor.request(&request, EXECUTOR_REQUEST_WITHIN)
        };
        if let ExecutorRequest::Enroll { mut secret_hex, .. } = request {
            // SAFETY: as above, zeros keep the string valid UTF-8.
            wipe(unsafe { secret_hex.as_bytes_mut() });
        }
        match reply? {
            ExecutorReply::Refused { detail } => {
                Err(format!("The credential operation was refused: {detail}"))
            }
            other => encoded(&other),
        }
    }

    /// What a launch would check and use, without launching: the platform's own report
    /// of the hypervisor, the layout's checks of the runtime and the image for the
    /// restricted QEMU, and the pinned inputs.
    fn plan(&self) -> Value {
        let hypervisor = match platform_report().describe() {
            (Some(true), _) => json!({ "present": true }),
            (present, reason) => json!({ "present": present, "reason": reason }),
        };
        let runtime = match self.layout.check_runtime() {
            Ok(grants) => json!({ "ok": true, "grants": encoded(grants).unwrap_or(Value::Null) }),
            Err(error) => json!({ "ok": false, "refusal": error.to_string() }),
        };
        let image = match self.layout.settings().images.get(&self.guest.guest_image) {
            Some(files) => match self.layout.check_image(files) {
                Ok(grants) => {
                    json!({ "ok": true, "grants": encoded(grants).unwrap_or(Value::Null) })
                }
                Err(error) => json!({ "ok": false, "refusal": error.to_string() }),
            },
            None => {
                json!({ "ok": false, "refusal": "the layout holds no files for the pinned image" })
            }
        };
        // The trust roots in force now, as a launch checks them.
        let publisher = match guest_publisher() {
            Ok(check) => json!({ "ok": true, "check": check }),
            Err(refusal) => json!({ "ok": false, "refusal": refusal }),
        };
        let launchable = hypervisor["present"] == true
            && runtime["ok"] == true
            && image["ok"] == true
            && publisher["ok"] == true;
        json!({
            "launchable": launchable,
            "guest_publisher": publisher,
            "hypervisor": hypervisor,
            "runtime_readable_by_restricted_qemu": runtime,
            "image_readable_by_restricted_qemu": image,
            "config": self.summary,
            "note": "A launch also needs the host ledger to hold the memory asked for, and admits only on fresh host evidence; this plan ran the read-only checks and changed nothing.",
        })
    }
}

/// The engine's service, built on first use.
async fn production(app: &AppHandle) -> Result<Arc<Production>, String> {
    let slot = PRODUCTION.get_or_init(|| tokio::sync::Mutex::new(None));
    let mut guard = slot.lock().await;
    if let Some(production) = guard.as_ref() {
        return Ok(Arc::clone(production));
    }
    let production = Arc::new(compose(app).await?);
    start_poller(app, &production);
    if let Ok(remote) = production.remote_home() {
        remote.recover(Arc::clone(&production));
    }
    *guard = Some(Arc::clone(&production));
    Ok(production)
}

/// What the doctor reads of this engine run's sandboxes (M08): the backend build, the
/// launch records its sandboxes sealed and the latest confinement verdict (VM-CP-05);
/// `None` when no sandbox method ran since the engine started (the doctor never composes
/// the service: that would observe the host and open the audit stream).
pub(crate) async fn doctor_records() -> Option<super::DoctorRecords> {
    let production = PRODUCTION.get()?.lock().await.as_ref().map(Arc::clone)?;
    tokio::task::spawn_blocking(move || {
        let confinement = production
            .confinement
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let negatives = production
            .negatives
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let mut scans = production
            .scans
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        scans.extend(production.process_scan(ScanMoment::Examination, None));
        let drills = production
            .drills
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        super::DoctorRecords {
            backend: production.backend.clone(),
            records: production.service.launch_records(),
            negatives,
            scans,
            drills,
            confinement,
            now: production.service.clock_reading(),
        }
    })
    .await
    .ok()
}

/// Runs [`Production::poll_relays`] every [`POLL_EVERY`] until the engine shuts down, and
/// tells the user of each new notice (`show_notices`); and, on a loop of its own so a slow
/// executor request never delays it toward the supervisor's silence bound, the lifetime
/// supervisor's heartbeat ([`Production::supervise`]) every [`POLL_EVERY`].
fn start_poller(app: &AppHandle, production: &Arc<Production>) {
    let heartbeat = Arc::downgrade(production);
    let stopping = crate::automation::shutdown_signal(app);
    tauri::async_runtime::spawn(async move {
        let mut timer = tokio::time::interval(POLL_EVERY);
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = stopping.cancelled() => break,
                _ = timer.tick() => {}
            }
            let Some(production) = heartbeat.upgrade() else {
                break;
            };
            let _ = tokio::task::spawn_blocking(move || production.supervise()).await;
        }
    });
    let app = app.clone();
    let production = Arc::downgrade(production);
    let shutdown = crate::automation::shutdown_signal(&app);
    tauri::async_runtime::spawn(async move {
        let mut timer = tokio::time::interval(POLL_EVERY);
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = timer.tick() => {}
            }
            let Some(production) = production.upgrade() else {
                break;
            };
            let notices = tokio::task::spawn_blocking(move || {
                production.poll_relays();
                production.refresh_authorities();
                production.responses().take_unshown()
            })
            .await
            .unwrap_or_default();
            show_notices(&app, &notices);
        }
    });
}

/// Tells the user of the response path's notices: an event for the window and a desktop
/// notification each (at most [`MAX_DESKTOP_NOTICES`] a look). A notice names the sandbox,
/// the route and what was done; never a guest byte.
fn show_notices(app: &AppHandle, notices: &[Notice]) {
    use tauri::Emitter;
    if notices.is_empty() {
        return;
    }
    let _ = app.emit_to("main", NOTICE_EVENT, notices);
    #[cfg(windows)]
    show_desktop_notices(app, notices);
}

/// The desktop notifications of [`show_notices`] (the notification plugin is the Windows
/// build's; on Linux the window's event carries them).
#[cfg(windows)]
fn show_desktop_notices(app: &AppHandle, notices: &[Notice]) {
    use tauri::Manager;
    use tauri_plugin_notification::NotificationExt;
    if app
        .try_state::<tauri_plugin_notification::Notification<crate::Rt>>()
        .is_none()
    {
        return;
    }
    for notice in notices.iter().take(MAX_DESKTOP_NOTICES) {
        let _ = app
            .notification()
            .builder()
            .title("Yougori \u{b7} sandbox response")
            .body(notice.text.as_str())
            .show();
    }
}

/// Acceptance builds only: when the disposable engine's environment names a route in
/// [`ACCEPTANCE_VIOLATION_ROUTE`] and this relay serves it, the executor is told to report
/// the next refused exchange on it as a perimeter violation (once), so the response path
/// runs end to end from a refusal the guest really causes. A violation proper cannot be
/// caused through the relay: the broker picks every address and every reservation itself.
#[cfg(all(feature = "acceptance", windows))]
fn acceptance_mark(
    executor: &mut ExecutorClient,
    sandbox: &SandboxId,
    routes: &[String],
) -> Option<Value> {
    crate::acceptance::data_directory()?;
    let route = std::env::var(ACCEPTANCE_VIOLATION_ROUTE).ok()?;
    if !routes.iter().any(|name| *name == route) {
        return None;
    }
    let reply = executor.request(
        &ExecutorRequest::MarkNextRefusal {
            sandbox: sandbox.execution().clone(),
            route: route.clone(),
        },
        EXECUTOR_REQUEST_WITHIN,
    );
    Some(match reply {
        Ok(ExecutorReply::Marked { .. }) => json!({ "route": route, "marked": true }),
        Ok(other) => json!({ "route": route, "marked": false, "reply": format!("{other:?}") }),
        Err(error) => json!({ "route": route, "marked": false, "error": error }),
    })
}

/// A product build marks nothing.
#[cfg(all(not(feature = "acceptance"), windows))]
fn acceptance_mark(_: &mut ExecutorClient, _: &SandboxId, _: &[String]) -> Option<Value> {
    None
}

/// A launch's declared services (M14): a list of `{service, port}`, or `name=port` pairs
/// separated by commas; checked as the service checks them.
fn published_ports(value: Option<&Value>) -> Result<Vec<PublishedPort>, String> {
    let ports: Vec<PublishedPort> = match value {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::String(text)) => text
            .split(',')
            .map(str::trim)
            .filter(|pair| !pair.is_empty())
            .map(|pair| {
                let (service, port) = pair
                    .split_once('=')
                    .ok_or_else(|| format!("publish: {pair} is not NAME=PORT"))?;
                let port = port
                    .trim()
                    .parse::<u16>()
                    .map_err(|_| format!("publish: {} is not a guest port", port.trim()))?;
                Ok(PublishedPort {
                    service: service.trim().to_owned(),
                    port,
                })
            })
            .collect::<Result<_, String>>()?,
        Some(value) => serde_json::from_value(value.clone())
            .map_err(|error| format!("publish must be a list of {{service, port}}: {error}"))?,
    };
    check_published(&ports).map_err(|error| format!("publish: {error}"))?;
    Ok(ports)
}

/// The connection endpoints a launch declares (M14), as `[{"name":"api","port":8080}]` or
/// `api=8080,db=5432`: names the guest's programs reach on those ports, granted nothing yet.
fn connection_endpoints(value: Option<&Value>) -> Result<Vec<ConnectionEndpoint>, String> {
    let endpoints: Vec<ConnectionEndpoint> = match value {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::String(text)) => text
            .split(',')
            .map(str::trim)
            .filter(|pair| !pair.is_empty())
            .map(|pair| {
                let (name, port) = pair
                    .split_once('=')
                    .ok_or_else(|| format!("connect: {pair} is not NAME=PORT"))?;
                let port = port
                    .trim()
                    .parse::<u16>()
                    .map_err(|_| format!("connect: {} is not a port", port.trim()))?;
                Ok(ConnectionEndpoint {
                    name: name.trim().to_ascii_lowercase(),
                    port,
                })
            })
            .collect::<Result<_, String>>()?,
        Some(value) => serde_json::from_value(value.clone())
            .map_err(|error| format!("connect must be a list of {{name, port}}: {error}"))?,
    };
    check_connect(&endpoints, &[]).map_err(|error| format!("connect: {error}"))?;
    Ok(endpoints)
}

fn string(params: &Value, key: &str) -> Option<String> {
    params.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn sandbox_id(params: &Value) -> Result<SandboxId, String> {
    let text = string(params, "sandbox").ok_or("A sandbox id is required (sandbox).")?;
    ExecutionId::new(text)
        .map(SandboxId::new)
        .map_err(|error| format!("Invalid sandbox id: {error}"))
}

/// Runs `call` on the production off the async runtime, then checkpoints the state.
async fn blocking<T: Send + 'static>(
    production: Arc<Production>,
    call: impl FnOnce(&Production) -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tokio::task::spawn_blocking(move || {
        let result = call(&production);
        let checkpoint = production.checkpoint();
        let value = result?;
        checkpoint?;
        Ok(value)
    })
    .await
    .map_err(|error| error.to_string())?
}

/// One launch from the method's parameters (the `launch` action, and the VM a combine boots):
/// the parameters checked, the host's capacity observed again, the VM launched, and its
/// parameters kept beside it while it runs (`launches/<execution>.json`, no secret is among
/// them) so a combine can merge them, or launch an original again after a failed combine.
async fn launch_from(app: &AppHandle, production: &Arc<Production>, params: Value) -> Result<Value, String> {
        let internet = network::launch_internet(&params)?;
        // An attended session of the owner (an inference harness): owner-only publications
        // with a larger release account (vm_service::OWNER_SESSION_RELEASE_BYTES).
        let owner_session = match params.get("ownerSession") {
            None | Some(Value::Null) => false,
            Some(Value::Bool(value)) => *value,
            _ => return Err("ownerSession must be true or false.".into()),
        };
        let cpu_count = launch_cpu_count(&params)?;
        let gpu = params.get("gpu").and_then(Value::as_bool).unwrap_or(false);
        let grid_hosting = grid_hosting::selected(&params)?;
        let memory_gb = launch_memory_gb(&params)?;
        if gpu && memory_gb < 4.0 { return Err("GPU VMs require at least 4 GB of memory.".into()); }
        let memory_bytes = (memory_gb * (1u64 << 30) as f64) as u64;
        if memory_bytes < LEAST_LAUNCH_MEMORY_BYTES || memory_bytes > MAX_LAUNCH_MEMORY_BYTES {
            return Err(format!(
                "memoryGb must reserve between {} MiB (the guest's {} MiB and the hypervisor's own) and 64 GiB.",
                LEAST_LAUNCH_MEMORY_BYTES / MIB_BYTES,
                GUEST_MEMORY_BYTES / MIB_BYTES
            ));
        }
        let _ = DEFAULT_LAUNCH_MEMORY_BYTES;
        let routes: Option<Vec<RouteDeclaration>> = match params.get("routes") {
            None | Some(Value::Null) => None,
            Some(value) => Some(serde_json::from_value(value.clone()).map_err(|error| {
                format!("routes are not valid route declarations: {error}")
            })?),
        };
        if routes.as_ref().is_some_and(Vec::is_empty) {
            return Err("routes must name at least one route when given.".to_owned());
        }
        #[cfg(not(windows))]
        if routes.is_some() {
            return Err(RELAYS_UNAVAILABLE.to_owned());
        }
        // The folder whose copy the guest works on; the folder itself changes only
        // through a reviewed promotion.
        let workspace: Option<PathBuf> = match params.get("workspace") {
            None | Some(Value::Null) => None,
            Some(Value::String(path)) if !path.trim().is_empty() => Some(PathBuf::from(path.trim())),
            Some(_) => return Err("workspace must be the path of a folder.".to_owned()),
        };
        if let Some(folder) = &workspace {
            if !folder.is_dir() {
                return Err(format!("The workspace folder {} is not a folder.", folder.display()));
            }
        }
        let workspace = if let Some(previous) = string(&params, "restoreWorkspace") {
            if workspace.is_some() || params["remoteBootstrap"] == true { return Err("Private workspace restore cannot be combined with a host folder or remote bootstrap".into()); }
            Some(WorkspaceInput::Saved(ExecutionId::new(previous).map_err(|e| e.to_string())?))
        } else { workspace.map(WorkspaceInput::Folder) };
        // The guest learns the routes' endpoint names, hosts and ports at boot and maps
        // each to a loopback address of its own; the relay serving them is attached once
        // the VM is up.
        let egress_endpoints: Vec<GuestEgressEndpoint> = routes
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(|route| GuestEgressEndpoint::new(&route.name, &route.host, route.port))
            .collect::<Result<_, _>>()
            .map_err(|error| format!("routes: {error}"))?;
        check_endpoints(&egress_endpoints).map_err(|error| format!("routes: {error}"))?;
        // The host's capacity observation lapses after a few seconds (the models path
        // observes again before every admission); observe again so the ledger admits
        // on a current reading instead of refusing `NotObserved`.
        let capacity = if gpu {
            crate::model_runner::refresh_gpu_capacity(&crate::automation::shutdown_signal(app)).await?
        } else {
            crate::model_runner::refresh_host_capacity(&crate::automation::shutdown_signal(app)).await?
        };
        let mut gpu_memory = Vec::new();
        if gpu {
            let mut ledger = capacity.lock().map_err(|_| "The host ledger is unavailable")?;
            let tenant = TenantId::new(TENANT).map_err(|e|e.to_string())?;
            for key in ledger.vram_resources() {
                let ResourceKey::Vram(device) = key else { continue };
                let available = ledger.available(key).filter(|bytes| *bytes >= 256 << 20)
                    .ok_or("There is not enough unreserved GPU memory to start a GPU VM. Stop a model or another GPU VM first.")?;
                let total = ledger.capacity(key).ok_or("GPU capacity is unavailable")?.total;
                ledger.set_tenant_budget(tenant.clone(), key, total).map_err(|e|e.to_string())?;
                gpu_memory.push((device.key(), available));
            }
            if gpu_memory.is_empty() { return Err("Yougori has not detected GPU memory on this computer.".into()); }
        }
        // A task sandbox's lease limits, lowered below their defaults when asked (the
        // service refuses a raise): how long it may go without a command and live.
        let seconds = |key: &str| -> Result<Option<Duration>, String> {
            match params.get(key) {
                None | Some(Value::Null) => Ok(None),
                Some(value) => value
                    .as_u64()
                    .map(|seconds| Some(Duration::from_secs(seconds)))
                    .ok_or_else(|| format!("{key} must be whole seconds; 0 means until stopped.")),
            }
        };
        let idle_limit = seconds("idleSeconds")?.or_else(|| (!grid_hosting.is_empty()).then_some(Duration::ZERO));
        let lifetime_limit = seconds("lifetimeSeconds")?.or_else(|| (!grid_hosting.is_empty()).then_some(Duration::ZERO));
        // The guest services the sandbox may publish (M14), as `[{"service":"web",
        // "port":8080}]` or `web=8080,api=3000`; nothing else is ever published.
        let mut published = published_ports(params.get("publish"))?;
        if !grid_hosting.is_empty() {
            if published.iter().any(|p| (p.service == "grid" && p.port != 8787) || (p.port == 8787 && p.service != "grid")) {
                return Err("Grid hosting reserves service grid on port 8787.".into());
            }
            if !published.iter().any(|p| p.service == "grid") {
                published.push(PublishedPort { service: "grid".into(), port: 8787 });
            }
            check_published(&published).map_err(|e| e.to_string())?;
        }
        // The names its programs may reach other sandboxes' services by (M14), as
        // `api=8080`; each reaches nothing until `connect` grants it one.
        let connect = connection_endpoints(params.get("connect"))?;
        let image = string(&params, "image").map(|id| production.image_record(&id)).transpose()?;
        let remote_bootstrap = params.get("remoteBootstrap").and_then(Value::as_bool).unwrap_or(false);
        if remote_bootstrap && (internet || owner_session || image.is_some() || !grid_hosting.is_empty()) {
            return Err("A remote bootstrap must be an empty VM; workload execution follows delegation.".into());
        }
        let spec = LaunchSpec {
            gpu,
            gpu_memory,
            internet,
            owner_session,
            tenant: TenantId::new(TENANT).map_err(|error| error.to_string())?,
            resources: VmResources {
                memory_bytes,
                cpu_slots: cpu_count,
            },
            egress_endpoints,
            workload_image: None,
            idle_limit,
            lifetime_limit,
            published,
            connect,
        };
        let kept = params.clone();
        let (id, launched) = blocking(Arc::clone(production), move |production| {
            let (id, launched) = match image {
                Some(record) => production.launch_image(spec, routes, workspace, record, &grid_hosting, params["runEntrypoint"] != false),
                None => {
                    let (id, mut result) = production.launch_mode(spec, routes, workspace, remote_bootstrap)?;
                    production.prepare_grid_tools(&id, &mut result, &grid_hosting)?;
                    if !remote_bootstrap { production.prepare_setup_tools(&id, &mut result)?; }
                    Ok((id, result))
                }
            }?;
            Ok((id, launched))
        })
        .await?;
        if !remote_bootstrap {
            production.record_launch(&id, &kept);
        }
        Ok(launched)
}

/// The automation method `sandbox_vm` (module docs in `mod.rs`).
pub(crate) async fn dispatch(
    app: AppHandle,
    action: Option<String>,
    params: Value,
) -> Result<Value, String> {
    let action = action.unwrap_or_else(|| "status".to_owned());
    // Refuse unsupported networking before production initialization, including
    // host probes or supervisor recovery. launch_from also checks combine calls.
    if action == "launch" {
        network::launch_internet(&params)?;
    }
    let production = production(&app).await?;
    match action.as_str() {
        "capabilities" => blocking(Arc::clone(&production), move |p| {
            #[cfg(windows)]
            let gpu = match crate::sandbox::hcs::runtime::verify_bundle(
                Path::new(p.layout.settings().runtime_directory.as_str()), p.guest.guest_image) {
                Ok(_) => json!({"available":true,"backend":"hcs_gpu_pv","minimumMemoryGb":4,"shared":true,"requiresElevation":true}),
                Err(reason) => json!({"available":false,"reason":reason}),
            };
            #[cfg(not(windows))]
            let gpu = json!({"available":false,"reason":"This VM backend does not yet provide direct GPU access."});
            Ok(json!({"gpu":gpu}))
        }).await,
        "template" => blocking(Arc::clone(&production), move |p| p.capture_template(&params)).await,
        "application" => blocking(Arc::clone(&production), move |p| p.start_application(&params)).await,
        "host_access" => {
            let id = sandbox_id(&params)?;
            blocking(Arc::clone(&production), move |production| {
                if !production.service.status().iter().any(|row| row.sandbox == id) {
                    return Err("VM sandbox not found.".into());
                }
                production.host_access.lock().map_err(|_| "Host-access settings are unavailable")?
                    .owner(id.execution().as_str(), &params)
            }).await
        }
        "remote" => remote_home::dispatch(production, app, params).await,
        "remote_manage" => {
            let mut input = params;
            input.as_object_mut().ok_or("A remote management object is required.")?.remove("action");
            let request: crate::sandbox_contract::remote_ssh::RemoteManagementRequest =
                serde_json::from_value(input).map_err(|_| "Invalid remote management request.")?;
            if matches!(&request, crate::sandbox_contract::remote_ssh::RemoteManagementRequest::Launch { .. }) {
                crate::model_runner::refresh_host_capacity(&crate::automation::shutdown_signal(&app)).await?;
            }
            blocking(Arc::clone(&production), move |production| production.remote_manage(request)).await
        }
        "remote_control" => {
            // Stdio agents talk to this existing engine. Keys/frames never enter the
            // durable job queue; only the real coordinator's lease state is stored.
            let id = sandbox_id(&params)?;
            let op = string(&params, "op").unwrap_or_else(|| "status".to_owned());
            let persist = matches!(op.as_str(), "open" | "frame" | "close");
            tokio::task::spawn_blocking(move || {
                use crate::sandbox_contract::remote::{ControlKey, SealedFrame};
                let frame = || -> Result<SealedFrame, String> {
                    let value = params.get("frame").ok_or("A sealed control frame is required.")?;
                    if serde_json::to_vec(value).map_err(|_| "Invalid control frame")?.len()
                        > crate::sandbox_contract::remote_ssh::MAX_CONTROL_FRAME_BYTES as usize
                    { return Err("The control frame is too large.".into()); }
                    serde_json::from_value(value.clone()).map_err(|_| "Invalid sealed control frame.".into())
                };
                let result = match op.as_str() {
                    "open" => {
                        let secret = params["secret"].as_str().ok_or("A control key on stdin is required.")?;
                        if secret.len() != 64 { return Err("The control key must contain exactly 32 bytes.".into()); }
                        let bytes = hex::decode(secret).map_err(|_| "Invalid control key encoding.")?;
                        let key = ControlKey::new(bytes).map_err(|_| "Invalid control key.")?;
                        production.service.remote_open(&id, key, &frame()?)
                            .map_err(|e| e.to_string()).and_then(encoded)
                    }
                    "frame" => production.accept_remote_frame(&id, &frame()?),
                    "poll" => production.service.remote_poll(&id)
                        .map_err(|e| e.to_string()).and_then(encoded),
                    "close" => { production.service.remote_close(&id); Ok(json!({"closed":true})) },
                    "status" => Ok(json!({"control":production.service.remote_view(&id)})),
                    _ => Err("remote_control op must be open, frame, poll, close or status.".into()),
                };
                if persist {
                    if let Err(failure) = production.checkpoint() {
                        production.service.remote_close(&id);
                        return Err(failure);
                    }
                }
                result
            }).await.map_err(|error| error.to_string())?
        }
        "image" => {
            match string(&params, "operation").as_deref().unwrap_or("list") {
                "list" => blocking(Arc::clone(&production), move |p| p.image_list()).await,
                "import" => {
                    if params.get("ownerSelected").and_then(Value::as_bool) != Some(true) {
                        return Err("Importing an unsigned image requires ownerSelected=true for your own catalog scope".into());
                    }
                    let layout = string(&params, "layout");
                    let reference = string(&params, "reference");
                    if layout.is_some() == reference.is_some() {
                        return Err("Image import needs exactly one of layout or reference (HTTPS registry/repository@sha256:DIGEST)".into());
                    }
                    let secret = string(&params, "secret");
                    let auth_origin = string(&params, "authOrigin");
                    if layout.is_some() && (secret.is_some() || auth_origin.is_some()) {
                        return Err("Registry authentication is only valid with reference".into());
                    }
                    let root_gb = params.get("rootGb").and_then(Value::as_f64).unwrap_or(0.5);
                    if !root_gb.is_finite() || !(0.0625..=8.0).contains(&root_gb) {
                        return Err("rootGb must be between 0.0625 and 8".into());
                    }
                    crate::model_runner::refresh_host_capacity(&crate::automation::shutdown_signal(&app)).await?;
                    let runtime = tokio::runtime::Handle::current();
                    blocking(Arc::clone(&production), move |p| {
                        let bytes = (root_gb * (1u64 << 30) as f64) as u64;
                        match (layout, reference) {
                            (Some(layout), None) => p.import_image(Path::new(&layout), bytes),
                            (None, Some(reference)) => p.import_registry(&reference, secret, auth_origin, runtime, bytes),
                            _ => unreachable!("source was checked above"),
                        }
                    }).await
                },
                _ => Err("Image operation must be list or import".into()),
            }
        }
        "status" => {
            let shared = Arc::clone(&production);
            // Never waits behind a long launch: see `StatusView`.
            answer_status(Arc::clone(&production.status_view), STATUS_WAIT, move || {
                // The relays first: their poll may enforce a decision the sandboxes then show.
                let relays = shared.relay_status();
                let sandboxes = shared.service.status();
                let workspaces = shared.workspace_views();
                let supervisor = shared.lifetimes().view();
                let publications = shared.publication_views();
                let connections = shared.connection_views();
                Ok(json!({
                    "config": shared.summary,
                    "sandboxes": encoded(sandboxes)?,
                    "relays": relays,
                    "workspaces": workspaces,
                    "supervisor": supervisor,
                    "publications": publications,
                    "connections": connections,
                    "guest_bodies": shared.bodies.view(),
                    "images": shared.image_status(),
                }))
            })
            .await
        }
        "plan" => {
            let production = Arc::clone(&production);
            tokio::task::spawn_blocking(move || production.plan())
                .await
                .map_err(|error| error.to_string())
        }
        "launch" => launch_from(&app, &production, params).await,
        "exec" => {
            let id = sandbox_id(&params)?;
            let input = match (string(&params, "input"), string(&params, "inputHex")) {
                (Some(text), None) => text.into_bytes(),
                (None, Some(hex)) => hex::decode(hex.trim()).map_err(|error| format!("inputHex is not hex: {error}"))?,
                (None, None) => return Err("A command needs input (input, text for the guest shell) or inputHex.".to_owned()),
                (Some(_), Some(_)) => return Err("Give input or inputHex, not both.".to_owned()),
            };
            let max_output = params
                .get("maxOutputBytes")
                .and_then(Value::as_u64)
                .map_or(DEFAULT_OUTPUT_BYTES, |bytes| usize::try_from(bytes).unwrap_or(usize::MAX));
            if max_output == 0 || max_output > MAX_COMMAND_OUTPUT_BYTES {
                return Err(format!("maxOutputBytes must be between 1 and {MAX_COMMAND_OUTPUT_BYTES}."));
            }
            let timeout = params
                .get("timeoutSeconds")
                .and_then(Value::as_u64)
                .map_or(DEFAULT_TIMEOUT, Duration::from_secs);
            if timeout > MAX_EXEC_DEADLINE {
                return Err(format!(
                    "timeoutSeconds must be 0 (until stopped) or between 1 and {}.",
                    MAX_EXEC_DEADLINE.as_secs()
                ));
            }
            let request = ExecRequest::new(input, max_output, if timeout.is_zero() { Duration::MAX } else { timeout });
            blocking(Arc::clone(&production), move |production| {
                production.responses().admits_exec(id.execution())?;
                let outcome = production.service.exec(&id, request).map_err(|error| {
                    format!(
                        "The command was refused: {error} ({})",
                        serde_json::to_string(&error).unwrap_or_default()
                    )
                })?;
                let mut value = encoded(&outcome)?;
                value["output_text"] = json!(String::from_utf8_lossy(outcome.output.as_bytes()));
                value["source"] = json!("guest_report");
                Ok(value)
            })
            .await
        }
        "cancel" => {
            let id = sandbox_id(&params)?;
            let command = params
                .get("command")
                .cloned()
                .ok_or("A command number is required (command).")?;
            let command: crate::sandbox::vm_service::CommandId =
                serde_json::from_value(command).map_err(|error| format!("Invalid command: {error}"))?;
            blocking(Arc::clone(&production), move |production| {
                production
                    .service
                    .cancel(&id, command)
                    .map_err(|error| error.to_string())?;
                Ok(json!({ "cancelled": command }))
            })
            .await
        }
        "stop" => {
            let id = sandbox_id(&params)?;
            blocking(Arc::clone(&production), move |production| production.stop_sandbox(&id)).await
        }
        // A deliberate drill of one boundary check on throwaway VMs of its own (M08).
        "drill" => {
            match string(&params, "check").map(|check| check.to_ascii_lowercase()).as_deref() {
                Some(drill::DRILL_CHECK) => {}
                _ => return Err(format!("check must be {}: the drill this build runs.", drill::DRILL_CHECK)),
            }
            let production = Arc::clone(&production);
            // Each of its launches needs a current reading of the host's capacity, as the
            // method's own launch does.
            let shutdown = crate::automation::shutdown_signal(&app);
            let observe_capacity = move || {
                tauri::async_runtime::block_on(crate::model_runner::refresh_host_capacity(&shutdown)).map(|_| ())
            };
            tokio::task::spawn_blocking(move || production.drill_connections(&observe_capacity))
                .await
                .map_err(|error| error.to_string())?
        }
        "revoke" => {
            let id = sandbox_id(&params)?;
            let reason = params
                .get("reason")
                .cloned()
                .unwrap_or_else(|| json!("user_requested"));
            let reason: RevokeReason = serde_json::from_value(reason)
                .map_err(|_| "reason must be user_requested, policy_changed, violation or owner_reclaimed.".to_owned())?;
            blocking(Arc::clone(&production), move |production| {
                // The relay goes first, with the revocation's close reason: no guest open
                // is accepted while the VM is being stopped.
                let relay = production.stop_relay(&id, StopReason::Revoked);
                production.responses().forget(id.execution());
                let revoked = production
                    .service
                    .revoke(&id, reason)
                    .map_err(|error| error.to_string());
                production.refresh_authorities();
                production.previews.close_sandbox(&id);
                let mut value = encoded(revoked?)?;
                if let Some(relay) = relay {
                    value["relay"] = relay;
                }
                Ok(value)
            })
            .await
        }
        "credential" => {
            let production = Arc::clone(&production);
            tokio::task::spawn_blocking(move || production.credential(&params))
                .await
                .map_err(|error| error.to_string())?
        }
        "confinement" => {
            let id = sandbox_id(&params)?;
            let shared = Arc::clone(&production);
            let (mut view, verdict) =
                tokio::task::spawn_blocking(move || shared.probe_confinement(&id))
                    .await
                    .map_err(|error| error.to_string())??;
            // Stamped on the service's evidence clock (the one its launch records carry)
            // under this host's configuration, the verdict is the doctor's VM-CP-05 input
            // while it stays fresh.
            let shared = Arc::clone(&production);
            let now = match tokio::task::spawn_blocking(move || shared.service.clock_reading()).await {
                Ok(Some(now)) => Ok(now),
                Ok(None) => Err("the sandbox service has shut down".to_owned()),
                Err(error) => Err(error.to_string()),
            };
            match now {
                Ok(now) => {
                    *production
                        .confinement
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(
                        Vm05Evaluation::evaluated(
                            verdict,
                            now,
                            CONFINEMENT_FRESH_FOR,
                            production.configuration,
                        ),
                    );
                    view["doctor"] = json!({ "kept_for_seconds": CONFINEMENT_FRESH_FOR.as_secs() });
                }
                Err(error) => view["doctor"] = json!({ "not_kept": error }),
            }
            Ok(view)
        }
        "workspace" => {
            let production = Arc::clone(&production);
            tokio::task::spawn_blocking(move || production.workspace(&params))
                .await
                .map_err(|error| error.to_string())?
        }
        "normalize" => {
            let producer = sandbox_id(&params)?;
            let name = string(&params, "file")
                .ok_or("A file of the sandbox's staged workspace is required (file).")?;
            let declared: DeclaredFormat = serde_json::from_value(
                params
                    .get("format")
                    .cloned()
                    .ok_or("The file's format is required (format: html, archive, plain_text, pdf, image, office_document or unknown).")?,
            )
            .map_err(|_| "format must be html, archive, plain_text, pdf, image, office_document or unknown.".to_owned())?;
            let target: OutputFormat = match params.get("target") {
                None | Some(Value::Null) => OutputFormat::PlainText,
                Some(value) => serde_json::from_value(value.clone())
                    .map_err(|_| "target must be plain_text, markdown or png.".to_owned())?,
            };
            let retention = match params.get("keepRaw").and_then(Value::as_bool) {
                Some(false) => RawRetention::Discard,
                _ => RawRetention::KeepSeparately,
            };
            let max_output = params
                .get("maxOutputBytes")
                .and_then(Value::as_u64)
                .unwrap_or(DEFAULT_NORMALIZE_OUTPUT_BYTES);
            if max_output == 0 || max_output > MAX_NORMALIZE_OUTPUT_BYTES {
                return Err(format!("maxOutputBytes must be between 1 and {MAX_NORMALIZE_OUTPUT_BYTES}."));
            }
            // A throwaway sandbox reserves host memory as any launch does.
            crate::model_runner::refresh_host_capacity(&crate::automation::shutdown_signal(&app))
                .await?;
            blocking(Arc::clone(&production), move |production| {
                production.normalize(&producer, &name, declared, target, retention, max_output)
            })
            .await
        }
        "publish" => {
            let id = sandbox_id(&params)?;
            let application = match params.get("application") {
                None => false,
                Some(Value::Bool(value)) => *value,
                _ => return Err("application must be true or false.".into()),
            };
            let service = string(&params, "service")
                .ok_or("The service to publish is required (service, as the launch declared it).")?;
            let audience: crate::sandbox::vm_service::PublicationAudience =
                match params.get("audience") {
                    None | Some(Value::Null) => crate::sandbox::vm_service::PublicationAudience::Owner,
                    Some(value) => serde_json::from_value(value.clone())
                        .map_err(|_| "audience must be owner or public.".to_owned())?,
                };
            let minutes = params.get("minutes").and_then(Value::as_u64).unwrap_or(60);
            let lifetime = Duration::from_secs(minutes.saturating_mul(60));
            let until_stopped = minutes == 0 && audience == crate::sandbox::vm_service::PublicationAudience::Owner;
            if (minutes == 0 && !until_stopped) || lifetime > crate::sandbox::vm_service::MAX_PUBLICATION_LIFETIME {
                return Err(format!(
                    "minutes must be between 1 and {}, or 0 for an owner publication until withdrawn.",
                    crate::sandbox::vm_service::MAX_PUBLICATION_LIFETIME.as_secs() / 60
                ));
            }
            let lifetime = if until_stopped { Duration::MAX } else { lifetime };
            let budget = params
                .get("budgetBytes")
                .and_then(Value::as_u64)
                .unwrap_or(crate::sandbox::vm_service::PUBLISHED_RESPONSE_BYTES);
            if budget == 0 || budget > crate::sandbox::vm_service::PUBLISHED_RESPONSE_BYTES {
                return Err(format!(
                    "budgetBytes must be between 1 and {} (a sandbox's publications release at most that in all).",
                    crate::sandbox::vm_service::PUBLISHED_RESPONSE_BYTES
                ));
            }
            let production = Arc::clone(&production);
            tokio::task::spawn_blocking(move || {
                production.publish(&id, &service, audience, lifetime, budget, application)
            })
            .await
            .map_err(|error| error.to_string())?
        }
        "connect" => {
            let caller = sandbox_id(&params)?;
            let endpoint = string(&params, "endpoint")
                .ok_or("The connection endpoint is required (endpoint, as the launch declared it).")?;
            let callee = string(&params, "to")
                .ok_or("The sandbox to reach is required (to).")
                .and_then(|text| ExecutionId::new(text).map(SandboxId::new).map_err(|_| "Invalid sandbox id (to)."))?;
            let service = string(&params, "service")
                .ok_or("The service to reach is required (service, as that sandbox's launch declared it).")?;
            let minutes = params.get("minutes").and_then(Value::as_u64).unwrap_or(60);
            let lifetime = Duration::from_secs(minutes.saturating_mul(60));
            if minutes == 0 || lifetime > crate::sandbox::vm_service::MAX_CONNECTION_LIFETIME {
                return Err(format!(
                    "minutes must be between 1 and {}.",
                    crate::sandbox::vm_service::MAX_CONNECTION_LIFETIME.as_secs() / 60
                ));
            }
            let budget = params
                .get("budgetBytes")
                .and_then(Value::as_u64)
                .unwrap_or(crate::sandbox::vm_service::DEFAULT_CONNECTION_BUDGET_BYTES);
            if budget == 0 || budget > crate::sandbox::vm_service::MAX_CONNECTION_BUDGET_BYTES {
                return Err(format!(
                    "budgetBytes must be between 1 and {} (what one connection carries each way).",
                    crate::sandbox::vm_service::MAX_CONNECTION_BUDGET_BYTES
                ));
            }
            let production = Arc::clone(&production);
            tokio::task::spawn_blocking(move || {
                production.connect(&caller, &endpoint, &callee, &service, lifetime, budget)
            })
            .await
            .map_err(|error| error.to_string())?
        }
        "disconnect" => {
            let caller = sandbox_id(&params)?;
            let endpoint = string(&params, "endpoint")
                .ok_or("The connection endpoint is required (endpoint).")?;
            blocking(Arc::clone(&production), move |production| {
                let closed = production
                    .service
                    .disconnect(&caller, &endpoint)
                    .map_err(|error| error.to_string())?;
                Ok(json!({
                    "sandbox": caller,
                    "endpoint": endpoint,
                    "connections_closed": closed,
                }))
            })
            .await
        }
        "withdraw" => {
            let id = sandbox_id(&params)?;
            let publication = params
                .get("publication")
                .and_then(Value::as_u64)
                .ok_or("The publication to withdraw is required (publication, its number).")?;
            blocking(Arc::clone(&production), move |production| {
                let closed = production
                    .service
                    .withdraw(&id, publication)
                    .map_err(|error| error.to_string())?;
                let listener_closed = production.previews.close(&id, publication);
                Ok(json!({
                    "sandbox": id,
                    "publication": publication,
                    "sessions_closed": closed,
                    "listener_closed": listener_closed,
                }))
            })
            .await
        }
        "combine" => combine::dispatch(&app, &production, params).await,
        "cleanup" => {
            let production = Arc::clone(&production);
            tokio::task::spawn_blocking(move || {
                let live = live_control_names(&production.service);
                sweep_control(&production.control_base, &live)
            })
            .await
            .map_err(|error| error.to_string())
        }
        other => Err(format!(
            "Unknown sandbox_vm action '{other}'. Use status, plan, launch, exec, cancel, stop, revoke, confinement, workspace, normalize, publish, withdraw, combine, cleanup or credential."
        )),
    }
}
