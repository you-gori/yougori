//! `model_prepare`: the bounded prepare operation of the readiness library (GPU §4.1,
//! [`PrepareOperation`]) as the product's "prepare next model" control (GPU-W11: "Make 'keep
//! ready,' 'memory budget,' 'prepare next model' and 'allow remote placement' understandable
//! and visible"; U02; G05).
//!
//! `start` prepares a stopped model environment on the catalog path ahead of its use:
//!
//! - its exact execution identity is derived from what the engine holds of it
//!   ([`execution_identity`]): the catalog's content key and the size of every file, the
//!   published dtype read from its `config.json` in the catalog, its precision, the pinned
//!   runner release and the GPU's architecture;
//! - the operation is admitted only when its estimate fits the deadline asked: the last
//!   readiness this engine measured for the environment, else a declared estimate, labelled
//!   as such ([`PrepareOperation::admit`] refuses work that cannot finish in time);
//! - the model is started through the normal path, so its GPU admission is the scheduler's
//!   and the host ledger's: a model that cannot be admitted waits, and a wait past the
//!   deadline releases the preparation;
//! - once the runner is ready the prepared state is kept for the retention TTL; the first
//!   request to the model consumes it (the model then serves as any started one), and a TTL
//!   that passes unused, a deadline missed or a cancellation (`cancel`) stops the model again,
//!   unless a request took it first.
//!
//! A request is any use the runner saw: the engine's own chat path, the loopback API, Neo Grid
//! or Swarm traffic (the runner's active and queued requests, or its idle clock restarting). A
//! model serving a request is never stopped by its preparation. While a preparation is still
//! loading with no request for it, it is background work: the GPU scheduler serves real demand
//! first and never parks, trims or switches out another model for it ([`speculative`]); a
//! prepared model is not unloaded or parked for idleness while it is kept ([`keeps`]).
//! `status` also accounts for what preparations saved and what the unused ones cost.
//!
//! One preparation per environment, at most [`MAX_PREPARATIONS`] at once. Preparations live in
//! the engine process: an engine restart ends them (the restarted engine lists the model stopped
//! and ends the runtime it did not start by verified recovery), and none is restored.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{LazyLock, Mutex, PoisonError};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::foundation::evidence::BackendRelease;
use crate::foundation::ids::{
    Clock, ContentKey, DigestBuilder, ExecutionId, MonotonicTime, OperationId, SystemClock,
    TenantId,
};
use crate::model_memory::boundaries::PreparationStep;
use crate::model_memory::identity::{
    AdapterRecipe, CodePolicy, CommitId, CompileConfiguration, Dtype, ExecutionIdentity,
    ExecutionSpec, ImmutableRevision, Label, LogicalModelSpec, Quantization, RankTopology,
    RelativePath, SourceFile, SourceLocation, SourceSpec, VersionedName,
};
use crate::model_memory::math::prefetch::CandidateOrigin;
use crate::model_memory::readiness::intent::{
    Arrival, CancelReason, CancellationToken, PrepareBounds, PrepareOperation, PrepareRefusal,
    PrepareRequest, PrepareState, PrepareTarget, PrepareWork,
};

pub(crate) const MAX_PREPARATIONS: usize = 4;
const DEFAULT_READY_WITHIN: Duration = Duration::from_secs(600);
const DEFAULT_KEEP: Duration = Duration::from_secs(900);
/// What admission assumes for a model this engine never measured ready: a first import of a
/// small model through the read-only mount took about five minutes on this host.
const DECLARED_ESTIMATE: Duration = Duration::from_secs(300);
/// Start-to-ready samples kept per environment; admission uses their nearest-rank 95th
/// percentile, so one fast start does not promise every later one.
const READY_SAMPLES: usize = 8;
/// Finished preparations whose outcome `status` accounts for.
const ACCOUNTS: usize = 64;
/// Attempts to stop a model whose preparation released it, 2 s apart.
const STOP_ATTEMPTS: u32 = 3;
const BOUNDS: PrepareBounds = PrepareBounds {
    max_lead: Duration::from_secs(3600),
    max_retention_ttl: Duration::from_secs(4 * 3600),
};
const TOKENIZER_FILES: [&str; 8] = [
    "tokenizer.json",
    "tokenizer_config.json",
    "special_tokens_map.json",
    "added_tokens.json",
    "vocab.json",
    "merges.txt",
    "tokenizer.model",
    "chat_template.jinja",
];

/// What the engine holds of a model environment, the inputs of its execution identity.
#[derive(Clone, Debug)]
pub(crate) struct Facts {
    /// `YOUGORI_MODEL`.
    pub model: String,
    /// `YOUGORI_MODEL_REVISION`: a commit, or the local manifest's digest.
    pub revision: Option<String>,
    /// `YOUGORI_MODEL_PRECISION`.
    pub precision: String,
    /// Every file: path, size and the catalog's content key.
    pub files: Vec<(String, u64, ContentKey)>,
    /// The model's `config.json`, read from the catalog.
    pub config: Vec<u8>,
    /// `YOUGORI_LOCAL_CODE`: the model's own Python files are executed.
    pub local_code: bool,
    pub runner: BackendRelease,
    /// The GPU's architecture, such as `sm_120`.
    pub gpu_architecture: String,
}

fn identity_error(error: impl std::fmt::Display) -> String {
    format!("the model's execution identity: {error}")
}

/// The content key of the file at `path`, if the model has one.
fn content_of(facts: &Facts, path: &str) -> Option<ContentKey> {
    facts
        .files
        .iter()
        .find(|(name, _, _)| name == path)
        .map(|(_, _, content)| *content)
}

/// One digest over the content keys of the files `names` the model has, by name.
fn digest_of(facts: &Facts, domain: &str, names: &[&str]) -> crate::foundation::ids::Digest {
    let mut builder = DigestBuilder::new(domain);
    for (path, _, content) in &facts.files {
        if names.contains(&path.as_str()) {
            builder = builder
                .bytes(path.as_bytes())
                .bytes(content.digest().as_bytes());
        }
    }
    builder.finish()
}

/// The exact execution identity of a model environment (§3.2 items 1–3) from what the engine
/// holds of it. Refused where a fact is not known rather than guessed.
pub(crate) fn execution_identity(facts: &Facts) -> Result<ExecutionIdentity, String> {
    let config: Value = serde_json::from_slice(&facts.config)
        .map_err(|e| identity_error(format!("config.json is not JSON: {e}")))?;
    let published = match config
        .get("torch_dtype")
        .or_else(|| config.get("dtype"))
        .and_then(Value::as_str)
    {
        Some("bfloat16") => Dtype::BFloat16,
        Some("float16") => Dtype::Float16,
        Some("float32") => Dtype::Float32,
        other => {
            return Err(identity_error(format!(
                "config.json names no dtype this engine knows ({other:?})"
            )))
        }
    };
    if facts.precision != "original" {
        return Err(identity_error(format!(
            "a model loaded at precision {} is not prepared yet; only the published precision is",
            facts.precision
        )));
    }
    let revision = match facts.revision.as_deref() {
        Some(commit) if commit.len() == 40 && commit.bytes().all(|b| b.is_ascii_hexdigit()) => {
            ImmutableRevision::Commit(CommitId::new(commit).map_err(identity_error)?)
        }
        _ => ImmutableRevision::FileDigests,
    };
    let files = facts
        .files
        .iter()
        .map(|(path, length_bytes, content)| {
            Ok(SourceFile {
                path: RelativePath::new(path.clone()).map_err(identity_error)?,
                length_bytes: *length_bytes,
                content: *content,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let configuration = content_of(facts, "config.json")
        .ok_or_else(|| identity_error("the model has no config.json"))?;
    let source = SourceSpec {
        location: SourceLocation::Local {
            name: Label::new(facts.model.clone()).map_err(identity_error)?,
        },
        revision,
        files,
        configuration: *configuration.digest(),
        published_dtype: published,
        // The engine reads no licence; the identity says so rather than naming one.
        license: Label::new("unrecorded").map_err(identity_error)?,
        provenance: None,
    }
    .identity()
    .map_err(identity_error)?;
    let code_policy = if facts.local_code {
        let python: Vec<&str> = facts
            .files
            .iter()
            .map(|(path, _, _)| path.as_str())
            .filter(|path| path.ends_with(".py"))
            .collect();
        CodePolicy::PinnedRemoteCode {
            code: digest_of(facts, "yougori/prepare/local-code/v1", &python),
        }
    } else {
        CodePolicy::BuiltInOnly
    };
    let logical = LogicalModelSpec {
        source,
        dtype: published,
        quantization: Quantization::None,
        tokenizer: digest_of(facts, "yougori/prepare/tokenizer/v1", &TOKENIZER_FILES),
        generation_config: digest_of(
            facts,
            "yougori/prepare/generation-config/v1",
            &["generation_config.json"],
        ),
        adapters: AdapterRecipe::None,
        code_policy,
    }
    .identity();
    let version = facts.runner.version.to_string();
    ExecutionSpec {
        logical,
        runner: VersionedName::new(facts.runner.backend.tag(), &version).map_err(identity_error)?,
        architecture_adapter: VersionedName::new("auto-model-for-causal-lm", &version)
            .map_err(identity_error)?,
        // The Transformers runner loads with eager attention (model_server.py).
        kernel_layout: VersionedName::new("eager-attention", &version).map_err(identity_error)?,
        gpu_architectures: BTreeSet::from([
            Label::new(facts.gpu_architecture.clone()).map_err(identity_error)?
        ]),
        topology: RankTopology::SINGLE,
        processed_weights: VersionedName::new("safetensors-as-published", "1")
            .map_err(identity_error)?,
        compile: CompileConfiguration::Eager,
    }
    .identity()
    .map_err(identity_error)
}

/// What the runner reported, as a preparation reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RunnerView {
    Stopped,
    Loading,
    /// Ready; `used`: a request is being served or waits for it now, or one was served since the
    /// last look (its idle clock restarted) — whichever path it came by.
    Ready { allocated_bytes: u64, used: bool },
    Failed { error: String },
}

/// What the driver does next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Action {
    /// Start the model (once).
    Start,
    /// Wait and look again.
    Watch,
    /// Stop the model the preparation started: its prepared state is released.
    Stop,
    /// Done; the model stays as it is (a request took it).
    Finish,
}

/// One preparation.
#[derive(Debug)]
pub(crate) struct Entry {
    pub operation: PrepareOperation,
    pub target: PrepareTarget,
    pub estimate: Duration,
    pub estimate_basis: &'static str,
    pub started_at: Option<Instant>,
    pub started_model: bool,
    pub failure: Option<String>,
    pub finished: bool,
    /// When the runner was first seen ready for this preparation.
    pub ready_at: Option<Instant>,
    /// A request used what was prepared (or arrived while it loaded: `promoted`).
    pub used: bool,
    pub promoted: bool,
}

impl Entry {
    /// The next action, given what the runner reported: the operation's own state decides
    /// (its token, deadline and TTL applied at the clock's now).
    pub(crate) fn decide(&mut self, runner: &RunnerView, clock: &dyn Clock) -> Action {
        match self.operation.poll(clock) {
            PrepareState::Running { .. } => match runner {
                RunnerView::Ready { allocated_bytes, used } => {
                    let _ = self.operation.complete(*allocated_bytes, clock);
                    if *used {
                        // Seen in use the moment it is ready: the request came while it loaded.
                        self.arrived(clock);
                        self.used = true;
                        self.promoted = true;
                        return Action::Finish;
                    }
                    Action::Watch
                }
                RunnerView::Failed { error } => {
                    self.failure = Some(error.clone());
                    Action::Stop
                }
                RunnerView::Stopped if !self.started_model => Action::Start,
                RunnerView::Stopped => {
                    self.failure = Some("the model stopped before it was ready".into());
                    Action::Finish
                }
                RunnerView::Loading => Action::Watch,
            },
            PrepareState::Ready { .. } => match runner {
                RunnerView::Ready { used: true, .. } => {
                    self.arrived(clock);
                    Action::Finish
                }
                RunnerView::Ready { .. } => Action::Watch,
                RunnerView::Failed { error } => {
                    self.failure = Some(error.clone());
                    Action::Stop
                }
                // Stopped or reloading underneath: what was prepared is gone.
                _ => {
                    self.failure = Some("the prepared model stopped before it was used".into());
                    Action::Finish
                }
            },
            PrepareState::Consumed { .. } => {
                self.used = true;
                Action::Finish
            }
            // Released (kept time over, deadline missed or cancelled): a model serving a request
            // now is left serving; only an unused one this preparation started is stopped.
            PrepareState::Released { .. } if matches!(runner, RunnerView::Ready { used: true, .. }) => {
                self.used = true;
                Action::Finish
            }
            PrepareState::Released { .. } if self.started_model => Action::Stop,
            PrepareState::Released { .. } => Action::Finish,
        }
    }

    fn arrived(&mut self, clock: &dyn Clock) {
        let target = self.target;
        match self.operation.request_arrived(&target, clock) {
            Arrival::Used { .. } => self.used = true,
            Arrival::Promoted => {
                self.used = true;
                self.promoted = true;
            }
            _ => {}
        }
    }

    /// What this preparation saved or cost, once it has ended (GPU §4.5: preparations are
    /// accounted for by realized value; nothing here is a prediction). A used preparation saved
    /// its request the measured load; one a request reached while it loaded saved part of it,
    /// which is not attributed. An unused one spent its load and held its bytes for nothing.
    fn account(&self, environment: &str, ended: Instant) -> Value {
        let load = match (self.started_at, self.ready_at) {
            (Some(started), Some(ready)) => Some(ready.saturating_duration_since(started).as_secs_f64()),
            _ => None,
        };
        let held = self.ready_at.map(|ready| ended.saturating_duration_since(ready).as_secs_f64());
        let bytes = self.operation.prepared_bytes();
        let outcome = if self.used && self.promoted {
            "promoted"
        } else if self.used {
            "used"
        } else if self.failure.is_some() {
            "failed"
        } else if !self.started_model {
            "not-started"
        } else {
            match self.operation.state() {
                PrepareState::Released { reason, .. } => match serde_json::to_value(reason) {
                    Ok(value) if value["release"].is_string() => {
                        return self.account_of(environment, value["release"].as_str().map(str::to_owned), load, held, bytes)
                    }
                    _ => "released",
                },
                _ => "released",
            }
        };
        self.account_of(environment, Some(outcome.to_owned()), load, held, bytes)
    }

    fn account_of(&self, environment: &str, outcome: Option<String>, load: Option<f64>, held: Option<f64>, bytes: u64) -> Value {
        let wasted = !self.used && self.started_model;
        json!({
            "environment": environment,
            "outcome": outcome,
            "loadSeconds": load,
            "heldSeconds": held,
            "preparedBytes": bytes,
            "savedSeconds": if self.used && !self.promoted { load } else { None },
            "wastedLoadSeconds": if wasted { load } else { None },
            "wastedGibSeconds": if wasted { held.map(|held| held * bytes as f64 / (1u64 << 30) as f64) } else { None },
        })
    }

    fn view(&self, environment: &str, clock: &dyn Clock) -> Value {
        let now = clock.now();
        let seconds =
            |at: MonotonicTime| (at.as_nanos() as i128 - now.as_nanos() as i128) as f64 / 1e9;
        let state = self.operation.state();
        let (name, detail) = match state {
            PrepareState::Running { .. } => ("preparing", Value::Null),
            PrepareState::Ready { expires_at, .. } => (
                "ready",
                json!({ "expiresInSeconds": seconds(expires_at).round() }),
            ),
            PrepareState::Consumed { .. } => ("used", Value::Null),
            PrepareState::Released { reason, .. } => (
                "released",
                serde_json::to_value(reason).unwrap_or(Value::Null),
            ),
        };
        json!({
            "environment": environment,
            "state": if self.failure.is_some() { "failed" } else { name },
            "detail": detail,
            "failure": self.failure,
            "deadlineInSeconds": seconds(self.operation.request().deadline).round(),
            "keepSeconds": self.operation.request().retention_ttl.as_secs(),
            "estimateSeconds": self.estimate.as_secs(),
            "estimate": self.estimate_basis,
            "preparedBytes": self.operation.prepared_bytes(),
            "finished": self.finished,
        })
    }
}

static CLOCK: LazyLock<SystemClock> = LazyLock::new(SystemClock::new);
static ENTRIES: Mutex<BTreeMap<String, Entry>> = Mutex::new(BTreeMap::new());
/// The start-to-ready times preparations measured, by environment, newest last.
static READY_TIMES: Mutex<BTreeMap<String, VecDeque<Duration>>> = Mutex::new(BTreeMap::new());
/// What the finished preparations saved or cost, newest last.
static FINISHED: Mutex<VecDeque<Value>> = Mutex::new(VecDeque::new());

fn entries() -> std::sync::MutexGuard<'static, BTreeMap<String, Entry>> {
    ENTRIES.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The admission estimate from the measured samples: their nearest-rank 95th percentile.
pub(crate) fn estimate_of(samples: &VecDeque<Duration>) -> Option<Duration> {
    let mut sorted = samples.iter().copied().collect::<Vec<_>>();
    sorted.sort();
    let rank = (sorted.len() * 95).div_ceil(100);
    sorted.get(rank.max(1) - 1).copied()
}

/// Whether `environment` is prepared and kept for its first request: the GPU scheduler neither
/// unloads it for idleness nor parks it for another model meanwhile.
pub(crate) fn keeps(environment: &str) -> bool {
    entries().get(environment).is_some_and(|entry| {
        !entry.finished && matches!(entry.operation.state(), PrepareState::Ready { .. })
    })
}

/// Whether `environment` waits for the GPU only because a preparation started it: background
/// demand, which real requests go ahead of and which displaces no other model.
pub(crate) fn speculative(environment: &str) -> bool {
    entries().get(environment).is_some_and(|entry| {
        !entry.finished && !entry.used && matches!(entry.operation.state(), PrepareState::Running { .. })
    })
}

/// The accounting of finished preparations, for `status`.
fn accounting() -> Value {
    let finished = FINISHED.lock().unwrap_or_else(PoisonError::into_inner);
    let sum = |field: &str| finished.iter().filter_map(|row| row[field].as_f64()).sum::<f64>();
    let count = |outcome: &str| finished.iter().filter(|row| row["outcome"] == outcome).count();
    json!({
        "finished": finished.len(),
        "used": count("used"),
        "promoted": count("promoted"),
        "unused": finished.len() - count("used") - count("promoted"),
        "savedSeconds": sum("savedSeconds"),
        "wastedLoadSeconds": sum("wastedLoadSeconds"),
        "wastedGibSeconds": sum("wastedGibSeconds"),
        "recent": finished.iter().rev().take(16).cloned().collect::<Vec<_>>(),
    })
}

/// A request reached `environment`: a preparation that is ready serves it, one still loading
/// is promoted (§2.9: the same work serves the request).
pub(crate) fn request_arrived(environment: &str) {
    let mut entries = entries();
    if let Some(entry) = entries.get_mut(environment).filter(|entry| !entry.finished) {
        entry.arrived(&*CLOCK);
    }
}

/// The facts of `environment`'s workload, read from its options and the engine's catalog.
async fn facts_of(app: &crate::AppHandle, environment: &str) -> Result<Facts, String> {
    use tauri::Manager;
    let env = app
        .state::<crate::store::PlatformStore>()
        .environment(environment)?;
    let options = app
        .state::<crate::runtime::RuntimeManager>()
        .workload_options(env.runtime_id.as_deref().unwrap_or(&env.id))?;
    let variables = &options.environment;
    let model = variables
        .get("YOUGORI_MODEL")
        .cloned()
        .ok_or("This is not a model environment")?;
    let contents: BTreeMap<String, String> = variables
        .get("YOUGORI_CATALOG_CONTENT")
        .and_then(|text| serde_json::from_str(text).ok())
        .ok_or("Preparing needs a model on the catalog path, whose files the engine knows; this one reads its folder or downloads")?;
    let manifest: Value = variables
        .get("YOUGORI_LOCAL_MANIFEST")
        .and_then(|text| serde_json::from_str(text).ok())
        .ok_or("The model's manifest is missing from its options")?;
    let sizes: BTreeMap<String, u64> = manifest["files"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|file| Some((file["name"].as_str()?.to_owned(), file["size"].as_u64()?)))
        .collect();
    let mut files = Vec::new();
    for (path, key) in &contents {
        let size = *sizes
            .get(path)
            .ok_or_else(|| format!("the manifest has no size for {path}"))?;
        let digest = crate::foundation::ids::Digest::from_hex(key)
            .map_err(|_| format!("the content key of {path} is not a digest"))?;
        files.push((path.clone(), size, ContentKey::from_digest(digest)));
    }
    let config_key = contents
        .get("config.json")
        .and_then(|key| crate::foundation::ids::Digest::from_hex(key).ok())
        .map(ContentKey::from_digest)
        .ok_or("the model has no config.json in the catalog")?;
    let config = tokio::task::spawn_blocking(move || {
        crate::catalog_service::read_owner_original(config_key, 1 << 20)
    })
    .await
    .map_err(|e| e.to_string())??;
    let runner = match super::helpers::release_of(variables)? {
        Ok(release) => release,
        Err(skipped) => return Err(format!("not a model runner: {skipped}")),
    };
    Ok(Facts {
        model,
        revision: variables.get("YOUGORI_MODEL_REVISION").cloned(),
        precision: variables
            .get("YOUGORI_MODEL_PRECISION")
            .cloned()
            .unwrap_or_else(|| "original".into()),
        files,
        config,
        local_code: variables
            .get("YOUGORI_LOCAL_CODE")
            .is_some_and(|v| v == "1"),
        runner,
        gpu_architecture: gpu_architecture().await?,
    })
}

/// The local GPU's architecture as `sm_<major><minor>`, from its compute capability.
async fn gpu_architecture() -> Result<String, String> {
    let mut command = tokio::process::Command::new("nvidia-smi");
    command
        .args(["--query-gpu=compute_cap", "--format=csv,noheader"])
        .kill_on_drop(true);
    #[cfg(windows)]
    command.creation_flags(0x08000000);
    let output = tokio::time::timeout(Duration::from_secs(15), command.output())
        .await
        .map_err(|_| "the GPU did not answer for its architecture".to_owned())?
        .map_err(|e| format!("the GPU's architecture could not be read: {e}"))?;
    let text = String::from_utf8_lossy(&output.stdout);
    let first = text.lines().next().unwrap_or_default().trim();
    let (major, minor) = first
        .split_once('.')
        .ok_or_else(|| format!("the GPU reported no compute capability ({first:?})"))?;
    if !major.bytes().all(|b| b.is_ascii_digit()) || !minor.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!(
            "the GPU reported no compute capability ({first:?})"
        ));
    }
    Ok(format!("sm_{major}{minor}"))
}

/// What the runner reports, with whether a request is being served or waits now and its idle
/// clock (seconds since its last request), from which `drive` tells a request served between
/// two looks. Runners whose allocator reports nothing (vLLM, llama.cpp) count their grant.
struct Look {
    runner: RunnerView,
    /// A request is being served or waits now (the runner's queue, or a request in the GPU).
    busy: bool,
    /// The runner's idle clock: seconds since its last request.
    idle: Option<u64>,
    /// How long its load waited for the GPU, in seconds (not the model's readiness).
    gpu_wait: f64,
}

async fn runner_view(app: &crate::AppHandle, environment: &str) -> Look {
    let look = |runner| Look { runner, busy: false, idle: None, gpu_wait: 0.0 };
    match tokio::time::timeout(Duration::from_secs(15), super::model_status(environment.to_owned(), app.clone())).await {
        Err(_) => look(RunnerView::Loading),
        Ok(Ok(health)) => {
            let optimizer = &health["optimizer"];
            let queue = &health["requestQueue"];
            let busy = optimizer["active"].as_u64().unwrap_or(0) > 0
                || queue["active"].as_u64().unwrap_or(0) + queue["waiting"].as_u64().unwrap_or(0) > 0;
            Look { runner: runner_state(&health), busy, idle: optimizer["idleSeconds"].as_u64(),
                   gpu_wait: health["load"]["stages"]["admission_wait"].as_f64().unwrap_or(0.0) / 1000.0 }
        }
        Ok(Err(_)) => {
            use tauri::Manager;
            let stopped = app
                .state::<crate::store::PlatformStore>()
                .environment(environment)
                .is_ok_and(|env| env.status == crate::models::EnvironmentStatus::Stopped);
            look(if stopped { RunnerView::Stopped } else { RunnerView::Loading })
        }
    }
}

fn runner_state(health: &Value) -> RunnerView {
    match health["status"].as_str() {
            Some("ready") => RunnerView::Ready {
                allocated_bytes: health["optimizer"]["allocatedBytes"].as_u64()
                    .or_else(|| health["admission"]["bytes"].as_u64()).unwrap_or(0),
                used: false,
            },
            Some("error") => RunnerView::Failed {
                error: health["error"]
                    .as_str()
                    .unwrap_or("the model failed to load")
                    .chars()
                    .take(300)
                    .collect(),
            },
            _ => RunnerView::Loading,
    }
}

/// Follows the preparation of `environment` until it is used, released or failed.
async fn drive(app: crate::AppHandle, environment: String) {
    // The runner's idle clock at the last look: one that restarted since was used meanwhile
    // (the engine's own status reads never restart it).
    let mut idle_seen: Option<u64> = None;
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let Look { mut runner, busy, idle, gpu_wait } = runner_view(&app, &environment).await;
        if let RunnerView::Ready { used, .. } = &mut runner {
            // The idle clock only grows between requests: lower than at the last look, one ran.
            let restarted = matches!((idle_seen, idle), (Some(before), Some(now)) if now < before);
            *used = busy || restarted;
            idle_seen = idle;
        } else {
            idle_seen = None;
        }
        let mut account = None;
        let action = {
            let mut entries = entries();
            let Some(entry) = entries.get_mut(&environment) else {
                return;
            };
            // A request queued for a model still loading (any path: the loopback API, Neo Grid,
            // Swarm) is demand: the preparation is promoted and the model loads as a request's.
            if busy && !entry.used && matches!(runner, RunnerView::Loading | RunnerView::Stopped) && entry.started_model {
                entry.arrived(&*CLOCK);
            }
            let action = entry.decide(&runner, &*CLOCK);
            if entry.ready_at.is_none() && matches!(runner, RunnerView::Ready { .. }) && entry.started_model {
                entry.ready_at = Some(Instant::now());
                if let Some(started) = entry.started_at {
                    let mut times = READY_TIMES.lock().unwrap_or_else(PoisonError::into_inner);
                    let samples = times.entry(environment.clone()).or_default();
                    // The model's readiness, not the time it waited for the GPU behind others.
                    samples.push_back(started.elapsed().saturating_sub(Duration::from_secs_f64(gpu_wait.max(0.0))));
                    while samples.len() > READY_SAMPLES {
                        samples.pop_front();
                    }
                }
            }
            if matches!(action, Action::Stop | Action::Finish) {
                entry.finished = true;
                if matches!(action, Action::Stop) {
                    // Taken now: a new preparation may replace this finished entry while the
                    // stop runs.
                    account = Some(entry.account(&environment, Instant::now()));
                } else {
                    finish(&environment, entry);
                }
            }
            action
        };
        match action {
            Action::Start => {
                // A stop or another lifecycle operation still in progress holds the
                // environment's lifecycle lock (a stop on the Windows CUDA runtime takes minutes
                // while the disk is released), and a start then refuses at once: the preparation
                // waits for that operation within its deadline instead of failing (found on
                // this host's GPU: a preparation right after another one's stop failed).
                let remaining = entries().get(&environment).map(|entry| {
                    Duration::from_nanos(
                        entry
                            .operation
                            .request()
                            .deadline
                            .as_nanos()
                            .saturating_sub(CLOCK.now().as_nanos()),
                    )
                });
                let Some(remaining) = remaining else { return };
                let lock = crate::commands::environment_network_lock(&environment).await;
                if tokio::time::timeout(remaining, lock.lock()).await.is_err() {
                    continue;
                }
                // The wait may have outlived the preparation (cancelled, deadline passed): then
                // nothing is started. The readiness measured for the next estimate starts here,
                // after any wait for another operation: that wait is this host's, not the model's.
                {
                    let mut entries = entries();
                    let Some(entry) = entries.get_mut(&environment) else { return };
                    if !matches!(entry.operation.poll(&*CLOCK), PrepareState::Running { .. }) {
                        continue;
                    }
                    entry.started_at = Some(Instant::now());
                }
                let started = super::start_model(environment.clone(), app.clone()).await;
                let mut entries = entries();
                let Some(entry) = entries.get_mut(&environment) else { return };
                match started {
                    // Only a model this preparation did start is ever stopped by it.
                    Ok(_) => entry.started_model = true,
                    Err(error) => {
                        entry.failure = Some(format!("the model did not start: {error}"));
                        entry.finished = true;
                        finish(&environment, entry);
                        return;
                    }
                }
            }
            Action::Stop => {
                let mut outcome = Ok(());
                let mut taken = false;
                for attempt in 0..STOP_ATTEMPTS {
                    if attempt > 0 {
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        // A request that came meanwhile keeps the model: it is never stopped
                        // under one.
                        if runner_view(&app, &environment).await.busy {
                            taken = true;
                            break;
                        }
                    }
                    outcome = super::stop_model(environment.clone(), app.clone()).await.map(|_| ());
                    if outcome.is_ok() {
                        break;
                    }
                }
                let mut account = account.unwrap_or(Value::Null);
                if taken {
                    account["outcome"] = json!("used-after-release");
                } else if let Err(error) = outcome {
                    account["stopFailure"] = json!(format!("the prepared model could not be stopped: {error}"));
                    if let Some(entry) = entries().get_mut(&environment) {
                        entry.failure = Some(format!("the prepared model could not be stopped: {error}"));
                    }
                }
                let mut finished = FINISHED.lock().unwrap_or_else(PoisonError::into_inner);
                finished.push_back(account);
                while finished.len() > ACCOUNTS {
                    finished.pop_front();
                }
                return;
            }
            Action::Finish => return,
            Action::Watch => {}
        }
    }
}

/// Records what a finished preparation saved or cost.
fn finish(environment: &str, entry: &Entry) {
    let mut finished = FINISHED.lock().unwrap_or_else(PoisonError::into_inner);
    finished.push_back(entry.account(environment, Instant::now()));
    while finished.len() > ACCOUNTS {
        finished.pop_front();
    }
}

fn seconds(params: &Value, name: &str, default: Duration) -> Result<Duration, String> {
    match params[name].as_u64() {
        None if params[name].is_null() => Ok(default),
        Some(value) if value > 0 => Ok(Duration::from_secs(value)),
        _ => Err(format!("{name} must be a positive number of seconds")),
    }
}

/// `model_prepare`: start, cancel or status; see the module documentation.
pub(crate) async fn dispatch(app: crate::AppHandle, params: Value) -> Result<Value, String> {
    use tauri::Manager;
    let action = params["action"].as_str().unwrap_or("status");
    let clock: &dyn Clock = &*CLOCK;
    match action {
        "status" => {
            let entries = entries();
            Ok(json!({
                "preparations": entries.iter().map(|(env, entry)| entry.view(env, clock)).collect::<Vec<_>>(),
                "limit": MAX_PREPARATIONS,
                "accounting": accounting(),
            }))
        }
        "cancel" => {
            let environment = params["environment"]
                .as_str()
                .ok_or("model_prepare cancel: environment is required")?;
            let mut entries = entries();
            let entry = entries
                .get_mut(environment)
                .filter(|entry| !entry.finished)
                .ok_or("no preparation of this model is running")?;
            entry.operation.cancel(CancelReason::Requester, clock);
            Ok(entry.view(environment, clock))
        }
        "start" => {
            let environment = params["environment"]
                .as_str()
                .ok_or("model_prepare start: environment is required")?
                .to_owned();
            let ready_within = seconds(&params, "readyWithinSeconds", DEFAULT_READY_WITHIN)?;
            let keep = seconds(&params, "keepSeconds", DEFAULT_KEEP)?;
            let origin = match params["intent"].as_str().unwrap_or("selection") {
                "workflow" => CandidateOrigin::QueuedWork,
                "selection" => CandidateOrigin::ExplicitUserIntent,
                other => {
                    return Err(format!(
                        "unknown intent '{other}'; use workflow or selection"
                    ))
                }
            };
            let env = app
                .state::<crate::store::PlatformStore>()
                .environment(&environment)?;
            if env.status != crate::models::EnvironmentStatus::Stopped {
                return Err(
                    "The model is not stopped: a preparation starts it ahead of its use".into(),
                );
            }
            let facts = facts_of(&app, &environment).await?;
            let target = PrepareTarget {
                model: execution_identity(&facts)?,
                adapter: None,
            };
            let (estimate, basis) = match READY_TIMES
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(&environment)
                .and_then(estimate_of)
            {
                Some(measured) => (measured, "measured"),
                None => (DECLARED_ESTIMATE, "declared"),
            };
            let now = clock.now();
            let deadline = now
                .checked_add(ready_within)
                .ok_or("the deadline does not fit the clock")?;
            let request = PrepareRequest {
                operation: OperationId::generate(),
                execution: ExecutionId::generate(),
                tenant: TenantId::new("owner").map_err(|e| e.to_string())?,
                target,
                origin,
                deadline,
                retention_ttl: keep,
                cancellation: CancellationToken::new(),
                work: [
                    PreparationStep::Reserve,
                    PreparationStep::Verify,
                    PreparationStep::Activate,
                ]
                .into_iter()
                .map(|step| PrepareWork::Step { step })
                .collect(),
                assigned_request: None,
            };
            let operation =
                PrepareOperation::admit(request, estimate, &BOUNDS, clock).map_err(|refusal| {
                    let why = match refusal {
                        PrepareRefusal::CannotFinishByDeadline { .. } => format!(
                            "the model would be ready in about {} s ({basis} estimate), after the {} s asked",
                            estimate.as_secs(),
                            ready_within.as_secs()
                        ),
                        PrepareRefusal::DeadlineTooFar { .. } => format!(
                            "a preparation looks at most {} s ahead",
                            BOUNDS.max_lead.as_secs()
                        ),
                        PrepareRefusal::RetentionTtlTooLong { max, .. } => {
                            format!("a prepared model is kept at most {} s", max.as_secs())
                        }
                        other => other.to_string(),
                    };
                    format!("The preparation was refused: {why}")
                })?;
            {
                let mut entries = entries();
                entries.retain(|_, entry| !entry.finished);
                if entries.contains_key(&environment) {
                    return Err("This model is already being prepared".into());
                }
                // A second environment with the same execution identity would load a second copy
                // of the same files: refused, so prepared work is never duplicated.
                if let Some((other, _)) = entries.iter().find(|(_, entry)| entry.target == target) {
                    let name = app.state::<crate::store::PlatformStore>().environment(other).map_or_else(|_| other.clone(), |env| env.name);
                    return Err(format!("The same model files are already being prepared in {name}; use that environment, or cancel its preparation first"));
                }
                if entries.len() >= MAX_PREPARATIONS {
                    return Err(format!(
                        "{MAX_PREPARATIONS} preparations are running; cancel one or wait for it"
                    ));
                }
                entries.insert(
                    environment.clone(),
                    Entry {
                        operation,
                        target,
                        estimate,
                        estimate_basis: basis,
                        started_at: None,
                        started_model: false,
                        failure: None,
                        finished: false,
                        ready_at: None,
                        used: false,
                        promoted: false,
                    },
                );
            }
            tauri::async_runtime::spawn(drive(app.clone(), environment.clone()));
            let entries = entries();
            Ok(entries
                .get(&environment)
                .map(|entry| entry.view(&environment, clock))
                .unwrap_or(Value::Null))
        }
        other => Err(format!(
            "Unknown model_prepare action '{other}'. Use start, cancel or status."
        )),
    }
}

#[cfg(test)]
mod tests;
