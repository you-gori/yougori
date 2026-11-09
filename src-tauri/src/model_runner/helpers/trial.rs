//! The measured trial of a helper rollout stage (G08; GPU-W11: "Roll out in shadow-observation,
//! opt-in, then backend-specific default stages").
//!
//! `model_helpers trial` has the engine itself run a track's candidate at its stage, or its
//! default bundle, on a model environment its owner designates for the trial (stopped before;
//! started, measured and stopped again by the trial; its options restored after), measure it
//! beside what serves, and decide on criteria stated in the trial's summary:
//!
//! - **shadow**: one phase. The runner serves as the track says and runs the candidate in
//!   shadow (`model_server.py`, `shadow_attach`); the candidate passes when every decision it
//!   was given agreed with the serving helper's, none failed, hung or was dropped, and its
//!   time and Python allocations stay within the criteria;
//! - **opt-in** and **backend default**: a baseline phase (the runner not opted in, or served
//!   by source injection for this one start) and a candidate phase (opted in, or the default).
//!   The candidate passes when the runner reported it served, every reply equals the
//!   baseline's for the same prompt at temperature 0, its median request latency and peak GPU
//!   allocation stay within the criteria of the baseline's, and nothing failed.
//!
//! The records are the runner's own: each phase opens a measurement window on the runner
//! (`/v1/diagnostics/timings`), streams its requests, replays the window's journal through the
//! measurement collector and adapts every completed request with the context the engine knows
//! for its own trial (`measurement::report::adapt`: the trusted report context), so a record
//! carries the runner's boundaries and token emissions and nothing the trial did not measure.
//! They ran in the owner's disposable trial environment (`AuthorizedDisposable`, authorization
//! `helper-trial`). A trial whose baseline or measurement was incomplete decides nothing and is
//! kept as inconclusive; a conclusive verdict is recorded in the rollout journal (a failure
//! rolls the track back at once). The records and the summary are kept under
//! `<journal>/trials/<trial>/`, and a promotion or the removal of source injection takes a
//! passed trial from this store: an evidence file from elsewhere is recorded by `record` but
//! never promotes.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;

use super::*;
use crate::foundation::ids::{DigestBuilder, ExecutionCategory};
use crate::foundation::report as core;
use crate::model_runner::measurement::{collector, cursor::CursorStore, report};

pub(crate) const TRIALS_DIRECTORY: &str = "trials";
/// One start of the trial runner is served by source injection with no shadow, the
/// baseline of an opt-in or default trial; set by the trial and removed after it.
pub(crate) const TRIAL_OPTION: &str = "YOUGORI_HELPERS_TRIAL";
pub(crate) const TRIAL_BASELINE: &str = "source-injection";
const RECORDS_FILE: &str = "records.json";
const SUMMARY_FILE: &str = "summary.json";
const DEFAULT_REQUESTS: u32 = 6;
const MAX_REQUESTS: u32 = 32;
const MAX_TOKENS: u32 = 48;
const PHASE_READY_LIMIT: Duration = Duration::from_secs(30 * 60);
const STOP_LIMIT: Duration = Duration::from_secs(5 * 60);
const REQUEST_DEADLINE: Duration = Duration::from_secs(10 * 60);
const TIMINGS: &str = "/v1/diagnostics/timings";
const AUTHORIZATION: &str = "helper-trial";
const PLAN_DOMAIN: &str = "yougori/helper-trial/plan/v1";
const BUILD_DOMAIN: &str = "yougori/helper-trial/runner-build/v1";
const IMAGE_DOMAIN: &str = "yougori/helper-trial/launch-image/v1";
/// The trial's prompts: short, fixed and synthetic, sent in turn; only their digest is kept.
pub(crate) const PROMPTS: [&str; 4] = [
    "In two sentences, what is an API?",
    "Name three primary colors.",
    "What is 12 times 12? Answer with the number only.",
    "Write one sentence about the sea.",
];

/// What a trial requires, written into its summary.
#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Criteria {
    /// Measured requests per phase (after one unmeasured warm-up request).
    pub requests: u32,
    /// The candidate's median request latency may be at most this times the baseline's...
    pub latency_ratio: f64,
    /// ...plus this many milliseconds.
    pub latency_slack_millis: u64,
    /// The candidate's peak GPU allocation may exceed the baseline's by at most this.
    pub gpu_memory_slack_bytes: u64,
    /// A shadow candidate must have been given at least this many decisions.
    pub shadow_min_calls: u64,
    /// Its total time may be at most this times the serving helper's...
    pub shadow_time_ratio: f64,
    /// ...plus this many nanoseconds per call.
    pub shadow_time_slack_nanos: u64,
    /// The Python allocations during its calls may peak at most at this (process-wide, so
    /// an upper bound of the candidate's own).
    pub shadow_peak_bytes: u64,
}

impl Criteria {
    pub(crate) fn with_requests(requests: u32) -> Self {
        Self {
            requests,
            latency_ratio: 1.25,
            latency_slack_millis: 100,
            gpu_memory_slack_bytes: 64 << 20,
            shadow_min_calls: 1,
            shadow_time_ratio: 2.0,
            shadow_time_slack_nanos: 1_000_000,
            shadow_peak_bytes: 16 << 20,
        }
    }
}

/// One measured request of a phase, as the engine sent it. Only the reply's digest is kept.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Attempt {
    pub prompt: usize,
    pub operation: String,
    /// The request's wall time at the engine, the client.
    pub elapsed_nanos: u64,
    pub ok: bool,
    pub reply_digest: Option<String>,
    pub output_tokens: Option<u64>,
    pub error: Option<String>,
}

/// One start of the trial runner and what it showed.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Phase {
    /// `shadow`, `baseline` or `candidate`.
    pub name: String,
    /// How the runner reported serving the helper (its health's `helpers` entry).
    pub serving: Value,
    /// The shadow candidate's counts (its health's `helperShadow` entry), when one ran.
    pub shadow: Value,
    pub ready_millis: Option<u64>,
    pub attempts: Vec<Attempt>,
    pub peak_gpu_bytes: Option<u64>,
    /// Where `peak_gpu_bytes` was read: `runner-allocator` (the Transformers runner's own
    /// peak) or `host-probe-after-requests` (a runner that reports none: the GPU's use read by
    /// the host probe with it loaded after its requests). Readings of different sources are
    /// never compared.
    pub peak_gpu_source: Option<String>,
    /// The GPU the runner reported.
    pub gpu: Option<String>,
    /// The runner's measurement window: the requests it completed and the CORE-08 records
    /// adapted from them, with every conversion gap.
    pub observed_requests: usize,
    pub records: usize,
    pub gaps: Vec<String>,
    /// Why the phase did not complete, when it did not.
    pub error: Option<String>,
}

/// A trial's outcome: conclusive (passed or failed, recorded in the journal) or inconclusive
/// (a baseline or measurement problem decides nothing about the candidate).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Judgement {
    pub conclusive: bool,
    pub passed: bool,
    /// Why the candidate failed, or why nothing was decided.
    pub reasons: Vec<String>,
}

fn median(mut values: Vec<u64>) -> Option<u64> {
    values.sort_unstable();
    values.get(values.len() / 2).copied()
}

fn number(value: &Value, name: &str) -> u64 {
    value[name].as_u64().unwrap_or(0)
}

/// The verdict on `phases` under `criteria` for the candidate `pin` at `stage`.
pub(crate) fn judge(
    stage: RolloutStage,
    pin: &str,
    phases: &[Phase],
    criteria: &Criteria,
) -> Judgement {
    let mut failed = Vec::new();
    let mut undecided = Vec::new();
    // The phase where only the candidate serves; anything else is the baseline or the
    // shadow phase, where the track's serving path runs.
    let candidate_phase = |phase: &Phase| phase.name == "candidate";
    for phase in phases {
        let problems = if candidate_phase(phase) {
            &mut failed
        } else {
            &mut undecided
        };
        if let Some(error) = &phase.error {
            problems.push(format!("phase-failed:{}:{}", phase.name, short(error)));
            continue;
        }
        if phase.attempts.len() != criteria.requests as usize {
            problems.push(format!("requests-missing:{}", phase.name));
        }
        if phase.attempts.iter().any(|attempt| !attempt.ok) {
            problems.push(format!("request-failed:{}", phase.name));
        }
        if phase.records != phase.attempts.len() {
            undecided.push(format!("measurement-incomplete:{}", phase.name));
        }
    }
    let phase = |name: &str| phases.iter().find(|phase| phase.name == name);
    match stage {
        RolloutStage::Shadow => match phase("shadow") {
            None => undecided.push("phase-missing:shadow".into()),
            Some(shadow) if shadow.error.is_none() => {
                let counts = &shadow.shadow;
                if counts["pin"].as_str() != Some(pin) {
                    undecided.push("shadow-not-run".into());
                } else {
                    if !counts["loadError"].is_null() {
                        failed.push("shadow-load-failed".into());
                    }
                    let calls = number(counts, "calls");
                    if calls < criteria.shadow_min_calls {
                        undecided.push("shadow-no-decisions".into());
                    }
                    if number(counts, "disagreed") > 0 {
                        failed.push("shadow-disagreed".into());
                    }
                    if number(counts, "candidateErrors") > 0 {
                        failed.push("shadow-candidate-failed".into());
                    }
                    if number(counts, "dropped") > 0 || number(counts, "uncompared") > 0 {
                        failed.push("shadow-decisions-not-compared".into());
                    }
                    if counts["hung"].as_bool() == Some(true) {
                        failed.push("shadow-hung".into());
                    }
                    let budget = (number(counts, "servingNanos") as f64
                        * criteria.shadow_time_ratio) as u64
                        + criteria.shadow_time_slack_nanos * calls.max(1);
                    if number(counts, "candidateNanos") > budget {
                        failed.push("shadow-time-over-budget".into());
                    }
                    if number(counts, "candidatePeakBytes") > criteria.shadow_peak_bytes {
                        failed.push("shadow-memory-over-budget".into());
                    }
                }
                if shadow.serving["pin"].as_str() == Some(pin) {
                    failed.push("shadow-candidate-served".into());
                }
            }
            Some(_) => {}
        },
        RolloutStage::OptIn | RolloutStage::BackendDefault => {
            match (phase("baseline"), phase("candidate")) {
                (Some(baseline), Some(candidate))
                    if baseline.error.is_none() && candidate.error.is_none() =>
                {
                    if candidate.serving["served"].as_str() != Some("bundle")
                        || candidate.serving["pin"].as_str() != Some(pin)
                    {
                        failed.push("candidate-not-served".into());
                    }
                    if baseline.serving["pin"].as_str() == Some(pin) {
                        undecided.push("baseline-served-the-candidate".into());
                    }
                    let replies = |phase: &Phase| {
                        phase
                            .attempts
                            .iter()
                            .map(|attempt| (attempt.prompt, attempt.reply_digest.clone()))
                            .collect::<Vec<_>>()
                    };
                    if replies(baseline) != replies(candidate) {
                        failed.push("replies-differ".into());
                    }
                    let latency = |phase: &Phase| {
                        median(phase.attempts.iter().map(|a| a.elapsed_nanos).collect())
                    };
                    match (latency(baseline), latency(candidate)) {
                        (Some(base), Some(new)) => {
                            let budget = (base as f64 * criteria.latency_ratio) as u64
                                + criteria.latency_slack_millis * 1_000_000;
                            if new > budget {
                                failed.push("latency-over-budget".into());
                            }
                        }
                        _ => undecided.push("latency-not-measured".into()),
                    }
                    match (baseline.peak_gpu_bytes, candidate.peak_gpu_bytes) {
                        (Some(base), Some(new))
                            if baseline.peak_gpu_source == candidate.peak_gpu_source =>
                        {
                            if new > base + criteria.gpu_memory_slack_bytes {
                                failed.push("gpu-memory-over-budget".into());
                            }
                        }
                        (Some(_), Some(_)) => undecided.push("gpu-memory-not-comparable".into()),
                        _ => undecided.push("gpu-memory-not-measured".into()),
                    }
                }
                (Some(_), Some(_)) => {}
                _ => undecided.push("phase-missing".into()),
            }
        }
    }
    if !undecided.is_empty() {
        undecided.extend(failed);
        return Judgement {
            conclusive: false,
            passed: false,
            reasons: undecided,
        };
    }
    Judgement {
        conclusive: true,
        passed: failed.is_empty(),
        reasons: failed,
    }
}

/// A short label-safe form of an error for a reason.
fn short(error: &str) -> String {
    let mut text: String = error
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    while text.contains("--") {
        text = text.replace("--", "-");
    }
    text.trim_matches('-').chars().take(40).collect()
}

/// `value` as a CORE-08 label: the characters a label allows, the rest as '-', at most 64;
/// `unknown` when nothing is left or the result is refused (a label never carries a path, a
/// space or anything credential-shaped).
fn report_label(value: &str) -> core::Label {
    let mut text: String = value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+') {
                c
            } else {
                '-'
            }
        })
        .collect();
    while text.contains("--") {
        text = text.replace("--", "-");
    }
    let text: String = text
        .trim_matches(|c: char| !c.is_ascii_alphanumeric())
        .chars()
        .take(64)
        .collect();
    core::Label::new(text).unwrap_or_else(|_| core::Label::new("unknown").expect("fixed label"))
}

/// The fixture reference of [`PROMPTS`].
pub(crate) fn prompts_fixture() -> core::FixtureRef {
    let content = serde_json::to_vec(&PROMPTS).expect("fixed prompts");
    core::FixtureRef::digesting(
        core::Label::new("helper-trial-prompts-v1").expect("fixed label"),
        &content,
        core::Disclosure::PermittedSynthetic,
    )
}

fn stage_tag(stage: RolloutStage) -> &'static str {
    match stage {
        RolloutStage::Shadow => "shadow",
        RolloutStage::OptIn => "opt-in",
        RolloutStage::BackendDefault => "default",
    }
}

/// The CORE-08 context every record of a trial shares; the engine knows each part of it
/// for its own trial, so it is the trusted report context of the runner's observations.
#[derive(Clone, Debug)]
pub(crate) struct Context {
    pub execution: ExecutionId,
    pub stage: RolloutStage,
    pub plan: crate::foundation::ids::Digest,
    pub runner_build: crate::foundation::ids::Digest,
    pub engine: core::EngineIdentity,
    pub host: core::HostDescription,
    pub launch: core::LaunchDescription,
    pub paired: bool,
}

/// The trusted metadata of one measured request of `phase`.
fn metadata(
    context: &Context,
    phase: &str,
    attempt: &Attempt,
    burst: u32,
) -> Result<report::RunMetadata, String> {
    use core::{Measured as M, NotMeasuredReason as N};
    Ok(report::RunMetadata {
        attempt: core::AttemptIdentity {
            bench: core::BenchId::Bench01,
            variant: report_label(&format!(
                "helper-trial-{}-{phase}",
                stage_tag(context.stage)
            )),
            execution: context.execution.clone(),
            operation: OperationId::new(attempt.operation.clone()).map_err(|e| e.to_string())?,
            role: core::AttemptRole::Initial,
            burst,
            deadline_nanos: M::measured(REQUEST_DEADLINE.as_nanos() as u64),
        },
        substrate: core::RunSubstrate::AuthorizedDisposable {
            authorization: core::Label::new(AUTHORIZATION).expect("fixed label"),
        },
        build: core::BuildIdentity {
            plan: context.plan,
            runner_build: context.runner_build,
            runner_version: report_label(env!("CARGO_PKG_VERSION")),
        },
        execution_category: ExecutionCategory::SharedKernelGpuRuntime,
        model: M::not_measured(N::NotRecorded),
        precision: M::not_measured(N::NotRecorded),
        engine: M::measured(context.engine.clone()),
        host: context.host.clone(),
        workload: M::measured(core::Workload {
            fixture: prompts_fixture(),
            family: core::FixtureFamily::Prose,
            input_tokens: 0,
            max_output_tokens: u64::from(MAX_TOKENS),
            sampling: core::Sampling {
                temperature: core::NonNegative::ZERO,
                top_p: M::not_measured(N::NotApplicable),
                top_k: M::not_measured(N::NotApplicable),
                seed: M::not_measured(N::NotApplicable),
            },
            tool_schema: M::not_measured(N::NotApplicable),
            paired: context.paired,
            cold_test_nonce: core::NonceDisclosure::NotUsed,
        }),
        client: core::ClientDescription {
            name: core::Label::new("yougori-engine-helper-trial").expect("fixed label"),
            version: report_label(env!("CARGO_PKG_VERSION")),
            region: core::Label::new("same-host").expect("fixed label"),
            placement: core::ClientPlacement::SameHost,
        },
        load: core::LoadDescription {
            concurrent_requests: 1,
            arrival: core::ArrivalMode::Sequential,
        },
        state: M::measured(core::StartState {
            temperature: core::StartTemperature::Hot,
            model_at_arrival: core::ModelAtArrival::ReadyToServe,
            cache_tier: core::CacheTier::GpuMemory,
            prefill: core::PrefillMode::Fresh,
            cold_provenance: core::ColdProvenance::NotCold,
        }),
        launch: context.launch.clone(),
        price: M::not_measured(N::NotRecorded),
    })
}

/// The CORE-08 records of `phase`'s measured requests, adapted from the runner's completed
/// request observations of measurement window `session` (in completion order, which is the
/// order the engine sent them, one at a time), and every conversion gap.
pub(crate) fn records_of(
    context: &Context,
    phase: &Phase,
    burst: u32,
    session: &str,
    events: &[Value],
) -> (Vec<core::RunRecord>, usize, Vec<String>) {
    let mut records = Vec::new();
    let mut gaps = Vec::new();
    let finished: Vec<&Value> = events
        .iter()
        .filter(|event| event["event"] == "finish" && event["record"]["kind"] == "request")
        .collect();
    if finished.len() != phase.attempts.len() {
        gaps.push(format!(
            "the runner completed {} requests in the window, the engine sent {}",
            finished.len(),
            phase.attempts.len()
        ));
    }
    for (event, attempt) in finished.iter().zip(&phase.attempts) {
        let outcome = (|| -> Result<Option<core::RunRecord>, String> {
            let observation =
                report::parse_completed(&event["record"]).map_err(|e| e.to_string())?;
            let identity = report::ObservationIdentity::new(
                session,
                event["instanceId"].as_str().unwrap_or_default(),
                event["attemptId"].as_u64().unwrap_or_default(),
            )
            .map_err(|e| e.to_string())?;
            let context = report::ReportContext {
                identity: identity.clone(),
                expected_kind: report::AttemptKind::Request,
                metadata: metadata(context, &phase.name, attempt, burst)?,
            };
            let adapted =
                report::adapt(&observation, &identity, &context).map_err(|e| e.to_string())?;
            for gap in &adapted.gaps {
                let gap = format!("{gap:?}");
                if !gaps.contains(&gap) {
                    gaps.push(gap);
                }
            }
            Ok(adapted.record)
        })();
        match outcome {
            Ok(Some(record)) => records.push(record),
            Ok(None) => {}
            Err(error) => gaps.push(format!("an observation was refused: {error}")),
        }
    }
    (records, finished.len(), gaps)
}

/// The summary a trial keeps beside its records.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Summary {
    pub trial: String,
    pub helper: String,
    pub backend: String,
    pub pin: String,
    pub stage: String,
    pub environment: String,
    pub criteria: Criteria,
    pub phases: Vec<Phase>,
    pub conclusive: bool,
    pub passed: bool,
    pub reasons: Vec<String>,
    /// The CORE-08 evidence digest of the records (the journal's evidence reference).
    pub evidence: Option<String>,
    pub measured: bool,
}

fn trials_root(directory: &Path) -> PathBuf {
    directory.join(TRIALS_DIRECTORY)
}

/// The directory of the journal, where the trial store is.
fn journal_directory() -> Result<PathBuf, String> {
    let state = state();
    match &*state {
        State::Open { directory, .. } => Ok(directory.clone()),
        other => Err(format!(
            "the helper rollout journal is unavailable: {}",
            unavailable_detail(other)
        )),
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let parent = path.parent().ok_or("a trial file has no directory")?;
    let mut file = tempfile::NamedTempFile::new_in(parent).map_err(|e| e.to_string())?;
    file.write_all(bytes)
        .and_then(|_| file.as_file().sync_all())
        .map_err(|e| e.to_string())?;
    file.persist(path).map_err(|e| e.to_string())?;
    Ok(())
}

/// Keeps a trial's records and summary under `directory`'s store.
pub(crate) fn store(
    directory: &Path,
    summary: &Summary,
    records: &[core::RunRecord],
) -> Result<PathBuf, String> {
    let folder = trials_root(directory).join(&summary.trial);
    std::fs::create_dir_all(&folder).map_err(|e| format!("the trial store: {e}"))?;
    write_atomic(
        &folder.join(RECORDS_FILE),
        &serde_json::to_vec(&json!({ "records": records })).map_err(|e| e.to_string())?,
    )?;
    write_atomic(
        &folder.join(SUMMARY_FILE),
        &serde_json::to_vec_pretty(summary).map_err(|e| e.to_string())?,
    )?;
    Ok(folder)
}

/// The trials kept in `directory`'s store, newest first (at most 20): what each ran and found,
/// for the status.
pub(crate) fn listing(directory: &Path) -> Vec<Value> {
    let Ok(entries) = std::fs::read_dir(trials_root(directory)) else {
        return Vec::new();
    };
    let mut trials: Vec<(std::time::SystemTime, Value)> = entries
        .flatten()
        .filter_map(|entry| {
            let modified = entry.metadata().ok()?.modified().ok()?;
            let bytes = read_bounded(&entry.path().join(SUMMARY_FILE), MAX_EVIDENCE_BYTES).ok()?;
            let summary: Value = serde_json::from_slice(&bytes).ok()?;
            Some((
                modified,
                json!({
                    "trial": summary["trial"], "helper": summary["helper"], "backend": summary["backend"],
                    "pin": summary["pin"], "stage": summary["stage"], "environment": summary["environment"],
                    "conclusive": summary["conclusive"], "passed": summary["passed"], "reasons": summary["reasons"],
                }),
            ))
        })
        .collect();
    trials.sort_by(|a, b| b.0.cmp(&a.0));
    trials.into_iter().take(20).map(|(_, view)| view).collect()
}

/// The evidence of trial `trial` in `directory`'s store for a decision about the pin `pin` at
/// `stage`: its records' provenance, when the trial was conclusive and passed, ran that pin
/// at that stage and its records still digest to what the summary says.
pub(crate) fn evidence_of(
    directory: &Path,
    trial: &str,
    pin: &str,
    stage: RolloutStage,
) -> Result<Provenance, String> {
    let trial = trial.trim();
    if trial.is_empty()
        || !trial
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err("the trial id is not one this engine gives".into());
    }
    let folder = trials_root(directory).join(trial);
    let summary: Value = serde_json::from_slice(
        &read_bounded(&folder.join(SUMMARY_FILE), MAX_EVIDENCE_BYTES)
            .map_err(|e| format!("no trial {trial} is kept on this engine: {e}"))?,
    )
    .map_err(|e| format!("the summary of trial {trial} is not JSON: {e}"))?;
    if summary["conclusive"] != true || summary["passed"] != true {
        return Err(format!(
            "trial {trial} did not pass ({}); only a passed trial promotes",
            summary["reasons"]
        ));
    }
    if summary["pin"].as_str() != Some(pin) {
        return Err(format!("trial {trial} ran another bundle than the track's"));
    }
    if summary["stage"].as_str() != Some(stage_tag(stage)) {
        return Err(format!(
            "trial {trial} ran at the {} stage, not the {} stage",
            summary["stage"].as_str().unwrap_or("?"),
            stage_tag(stage)
        ));
    }
    let provenance = evidence_from(&folder.join(RECORDS_FILE))?;
    let digest = provenance
        .comparable_evidence()
        .map_err(|e| e.to_string())?
        .to_string();
    if summary["evidence"].as_str() != Some(digest.as_str()) {
        return Err(format!(
            "the records of trial {trial} no longer match its summary"
        ));
    }
    Ok(provenance)
}

/// The evidence of trial `trial` for a decision about `pin` at `stage`, from this engine's
/// store.
pub(crate) fn stored_evidence(
    trial: &str,
    pin: &HelperPin,
    stage: RolloutStage,
) -> Result<Provenance, String> {
    evidence_of(&journal_directory()?, trial, &pin.id().to_string(), stage)
}

/// The trial's pin and the stage it runs at: the track's candidate at its stage, or its
/// default bundle when `stage` asks for the default.
fn trial_subject(
    helper: &HelperId,
    backend: Backend,
    stage: Option<&str>,
) -> Result<(HelperPin, RolloutStage), String> {
    let state = state();
    let State::Open { journal, .. } = &*state else {
        return Err(format!(
            "the helper rollout journal is unavailable: {}",
            unavailable_detail(&state)
        ));
    };
    let track = journal.rollouts().track(helper, backend).ok_or_else(|| {
        format!(
            "{} has no track on {}; propose a bundle first",
            helper.as_str(),
            backend.tag()
        )
    })?;
    let wanted = stage.map(stage_named).transpose()?;
    match (wanted, &track.candidate) {
        (Some(RolloutStage::BackendDefault), _) => match &track.default {
            crate::model_memory::helpers::DefaultPath::Bundle { pin } => {
                Ok((pin.clone(), RolloutStage::BackendDefault))
            }
            _ => Err("the track's default is not a bundle; a default trial needs one".into()),
        },
        (Some(wanted), Some((pin, stage))) if wanted == *stage => Ok((pin.clone(), *stage)),
        (Some(wanted), Some((_, stage))) => Err(format!(
            "the track's candidate is at the {stage} stage, not the {wanted} stage"
        )),
        (None, Some((pin, stage))) => Ok((pin.clone(), *stage)),
        (_, None) => {
            Err("the track has no candidate; propose a bundle, or ask for the default stage".into())
        }
    }
}

fn reply_digest(text: &str) -> String {
    DigestBuilder::new("yougori/helper-trial/reply/v1")
        .bytes(text.as_bytes())
        .finish()
        .to_string()
}

/// Waits until `environment`'s runner reports `ready`, or fails with what it reported.
async fn wait_ready(app: &crate::AppHandle, environment: &str) -> Result<u64, String> {
    let started = Instant::now();
    let mut nudged = false;
    loop {
        match crate::model_runner::model_status(environment.to_owned(), app.clone()).await {
            Ok(health) => match health["status"].as_str() {
                Some("ready") => return Ok(started.elapsed().as_millis() as u64),
                Some("error") => {
                    return Err(format!(
                        "the trial runner failed to load: {}",
                        health["error"].as_str().unwrap_or("no detail")
                    ))
                }
                // A runner the scheduler left unloaded loads on a request: one unmeasured
                // request wakes it.
                Some("idle") if !nudged && started.elapsed() > Duration::from_secs(20) => {
                    nudged = true;
                    let _ = stream(app, environment, PROMPTS[0]).await;
                }
                _ => {}
            },
            Err(_) if started.elapsed() < Duration::from_secs(120) => {}
            Err(error) => return Err(format!("the trial runner does not answer: {error}")),
        }
        if started.elapsed() > PHASE_READY_LIMIT {
            return Err("the trial runner did not become ready within 30 minutes".into());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// One streamed request at temperature 0: the reply's text and the runner's result.
async fn stream(
    app: &crate::AppHandle,
    environment: &str,
    prompt: &str,
) -> Result<(String, Value), String> {
    let body = crate::model_runner::chat_body(
        json!([{ "role": "user", "content": prompt }]),
        Some(MAX_TOKENS),
        Some(0.0),
        true,
        None,
    )?;
    let cancel = tokio::sync::Notify::new();
    let mut text = String::new();
    let result = tokio::time::timeout(
        REQUEST_DEADLINE,
        crate::model_runner::stream_deltas(app, environment, &cancel, &body, |piece| {
            if let Some(content) = piece["content"].as_str() {
                text.push_str(content);
            }
            Ok(())
        }),
    )
    .await
    .map_err(|_| "the request did not complete within 10 minutes".to_owned())??;
    Ok((text, result))
}

async fn stop(app: &crate::AppHandle, environment: &str) {
    let _ = crate::model_runner::stop_model(environment.to_owned(), app.clone()).await;
    let started = Instant::now();
    while started.elapsed() < STOP_LIMIT {
        let stopped = {
            use tauri::Manager;
            app.state::<crate::store::PlatformStore>()
                .environment(environment)
                .is_ok_and(|env| env.status == crate::models::EnvironmentStatus::Stopped)
        };
        if stopped {
            return;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// The runner's measurement window `session` over `environment`: opened before the measured
/// requests, its journal replayed through the collector (sealed, every event kept), released.
async fn window_events(
    app: &crate::AppHandle,
    environment: &str,
    session: &str,
    cursor_dir: &Path,
) -> Result<Vec<Value>, String> {
    std::fs::create_dir_all(cursor_dir).map_err(|e| e.to_string())?;
    let mut cursor = CursorStore::open(cursor_dir, environment, session)
        .map_err(|_| "the measurement cursor could not be opened".to_owned())?;
    let events = Arc::new(Mutex::new(Vec::new()));
    let send = |env: String, path: String, body: Option<Value>| async move {
        crate::model_runner::model_request(app, &env, &path, body).await
    };
    let persist = |batch: collector::ValidatedBatch| {
        let events = Arc::clone(&events);
        async move {
            events
                .lock()
                .map_err(|_| "poisoned".to_owned())?
                .extend(batch.records.iter().cloned());
            Ok(collector::PersistAck {
                environment_id: batch.environment_id,
                session_id: batch.session_id,
                through: batch.through,
            })
        }
    };
    let collected = collector::collect(
        environment,
        session,
        &mut cursor,
        collector::Limits {
            page_size: 64,
            max_pages: 64,
            deadline: Duration::from_secs(30),
            seal: true,
        },
        &CancellationToken::new(),
        &send,
        &persist,
    )
    .await;
    let _ = crate::model_runner::model_request(
        app,
        environment,
        TIMINGS,
        Some(json!({"action": "release", "sessionId": session})),
    )
    .await;
    let collection =
        collected.map_err(|failure| format!("the runner's measurement window: {failure:?}"))?;
    if collection.end != collector::End::Sealed {
        return Err(format!(
            "the runner's measurement window ended {:?}, not sealed",
            collection.end
        ));
    }
    let events = events.lock().map_err(|_| "poisoned".to_owned())?.clone();
    Ok(events)
}

/// One start of the trial runner with `settings` on its options: ready, one unmeasured
/// warm-up request, a measurement window over `criteria.requests` streamed requests, its
/// health read, stopped. Returns the phase and the window's events.
#[allow(clippy::too_many_arguments)]
async fn run_phase(
    app: &crate::AppHandle,
    environment: &str,
    name: &str,
    helper: &str,
    settings: &[(&str, Option<&str>)],
    criteria: &Criteria,
    folder: &Path,
) -> (Phase, String, Vec<Value>) {
    let mut phase = Phase {
        name: name.to_owned(),
        ..Phase::default()
    };
    let session = uuid::Uuid::new_v4().simple().to_string();
    if let Err(error) = set_options(app, environment, settings) {
        phase.error = Some(error);
        return (phase, session, Vec::new());
    }
    if let Err(error) = crate::model_runner::start_model(environment.to_owned(), app.clone()).await
    {
        phase.error = Some(format!("the trial runner did not start: {error}"));
        stop(app, environment).await;
        return (phase, session, Vec::new());
    }
    match wait_ready(app, environment).await {
        Ok(millis) => phase.ready_millis = Some(millis),
        Err(error) => {
            phase.error = Some(error);
            stop(app, environment).await;
            return (phase, session, Vec::new());
        }
    }
    if let Err(error) = stream(app, environment, PROMPTS[0]).await {
        phase.error = Some(format!("the warm-up request failed: {error}"));
        stop(app, environment).await;
        return (phase, session, Vec::new());
    }
    let started = crate::model_runner::model_request(
        app,
        environment,
        TIMINGS,
        Some(json!({"action": "start", "sessionId": session})),
    )
    .await;
    let recording = started.as_ref().is_ok_and(|v| {
        v["journal"]["sessionId"] == session.as_str() && v["journal"]["status"] == "recording"
    });
    if !recording {
        phase.error = Some(format!(
            "the runner did not open its measurement window: {}",
            started.err().unwrap_or_else(|| "not recording".into())
        ));
        stop(app, environment).await;
        return (phase, session, Vec::new());
    }
    for index in 0..criteria.requests as usize {
        let prompt = index % PROMPTS.len();
        let operation = OperationId::generate();
        let sent = Instant::now();
        let reply = stream(app, environment, PROMPTS[prompt]).await;
        let mut attempt = Attempt {
            prompt,
            operation: operation.as_str().to_owned(),
            elapsed_nanos: sent.elapsed().as_nanos() as u64,
            ok: false,
            reply_digest: None,
            output_tokens: None,
            error: None,
        };
        match reply {
            Ok((text, result)) if result["finishReason"] != "cancelled" => {
                attempt.ok = true;
                attempt.reply_digest = Some(reply_digest(&text));
                attempt.output_tokens = result["usage"]["completion_tokens"].as_u64();
            }
            Ok(_) => attempt.error = Some("the request was cancelled".into()),
            Err(error) => attempt.error = Some(error.chars().take(300).collect()),
        }
        phase.attempts.push(attempt);
    }
    let events = match window_events(
        app,
        environment,
        &session,
        &folder.join(format!("cursor-{name}")),
    )
    .await
    {
        Ok(events) => events,
        Err(error) => {
            phase.gaps.push(error);
            Vec::new()
        }
    };
    match crate::model_runner::model_status(environment.to_owned(), app.clone()).await {
        Ok(health) => {
            phase.serving = health["helpers"][helper].clone();
            phase.shadow = health["helperShadow"][helper].clone();
            phase.peak_gpu_bytes = health["optimizer"]["peakAllocatedBytes"].as_u64();
            phase.peak_gpu_source = phase.peak_gpu_bytes.map(|_| "runner-allocator".to_owned());
            phase.gpu = health["gpu"].as_str().map(str::to_owned);
        }
        Err(error) => phase.error = Some(format!("the runner's health could not be read: {error}")),
    }
    // A vLLM or llama.cpp runner reports no allocator peak: the host probe's reading with the
    // runner loaded after its requests stands in (vLLM takes its pool at start, llama.cpp its
    // KV and buffers by the first request; neither grows later).
    if phase.error.is_none() && phase.peak_gpu_bytes.is_none() {
        if let Some(used) = crate::model_runner::optimizer::host_gpu_used().await {
            phase.peak_gpu_bytes = Some(used);
            phase.peak_gpu_source = Some("host-probe-after-requests".to_owned());
        }
    }
    stop(app, environment).await;
    (phase, session, events)
}

/// Sets (`Some`) or removes (`None`) each of `settings` on the environment's saved options.
fn set_options(
    app: &crate::AppHandle,
    environment: &str,
    settings: &[(&str, Option<&str>)],
) -> Result<(), String> {
    use tauri::Manager;
    let env = app
        .state::<crate::store::PlatformStore>()
        .environment(environment)?;
    let runtime = app.state::<crate::runtime::RuntimeManager>();
    let options_id = env.runtime_id.as_deref().unwrap_or(&env.id).to_owned();
    let mut options = runtime.workload_options(&options_id)?;
    for (name, value) in settings {
        match value {
            Some(value) => {
                options
                    .environment
                    .insert((*name).to_owned(), (*value).to_owned());
            }
            None => {
                options.environment.remove(*name);
            }
        }
    }
    runtime.save_workload_options(&options_id, &options)
}

fn host_description(gpu: Option<&str>, gpu_total: Option<u64>) -> core::HostDescription {
    use core::{Measured as M, NotMeasuredReason as N};
    let mut system = sysinfo::System::new();
    system.refresh_memory();
    system.refresh_cpu_all();
    let cpu = system
        .cpus()
        .first()
        .map(|cpu| cpu.brand().to_owned())
        .unwrap_or_default();
    core::HostDescription {
        os: report_label(&sysinfo::System::name().unwrap_or_default()),
        os_version: report_label(&sysinfo::System::os_version().unwrap_or_default()),
        cpu: core::CpuDescription {
            model: report_label(&cpu),
            logical_cores: system.cpus().len() as u32,
        },
        host_memory_bytes: system.total_memory(),
        gpus: match (gpu, gpu_total) {
            (Some(gpu), Some(total)) => M::measured(vec![core::GpuDescription {
                model: report_label(gpu),
                memory_bytes: total,
            }]),
            _ => M::not_measured(N::NotRecorded),
        },
        gpu_driver: M::not_measured(N::NotRecorded),
        gpu_power_clock: M::not_measured(N::InstrumentUnavailable),
        power_source: M::not_measured(N::NotRecorded),
        displays_on_gpu: M::not_measured(N::NotRecorded),
    }
}

/// `model_helpers trial`: see the module documentation.
pub(crate) async fn run(app: crate::AppHandle, params: Value) -> Result<Value, String> {
    use tauri::Manager;
    let text = |name: &str| -> Result<String, String> {
        params[name]
            .as_str()
            .filter(|value| !value.trim().is_empty())
            .map(|value| value.trim().to_owned())
            .ok_or_else(|| format!("model_helpers trial: {name} is required"))
    };
    let helper = HelperId::new(text("helper")?).map_err(|error| format!("helper: {error}"))?;
    let backend = backend_named(&text("backend")?)?;
    let environment = text("environment")?;
    let requests = match params["requests"].as_u64() {
        None => DEFAULT_REQUESTS,
        Some(n) if (1..=u64::from(MAX_REQUESTS)).contains(&n) => n as u32,
        Some(_) => return Err(format!("requests must be 1 to {MAX_REQUESTS}")),
    };
    let criteria = Criteria::with_requests(requests);
    let (pin, stage) = trial_subject(&helper, backend, params["stage"].as_str())?;
    let attestation = attestation_of(&pin)?;
    let release = release_for(backend)?;

    // The trial environment: a model of this backend's pinned release, stopped.
    let env = app
        .state::<crate::store::PlatformStore>()
        .environment(&environment)?;
    if env.status != crate::models::EnvironmentStatus::Stopped {
        return Err("Stop the model first: a trial starts, measures and stops it itself".into());
    }
    let runtime = app.state::<crate::runtime::RuntimeManager>();
    let options_id = env.runtime_id.as_deref().unwrap_or(&env.id).to_owned();
    let options = runtime.workload_options(&options_id)?;
    match release_of(&options.environment)? {
        Ok(runner) if runner == release => {}
        Ok(runner) => {
            return Err(format!(
                "the environment's runner is {runner}, not the track's {release}"
            ))
        }
        Err(skipped) => return Err(format!("the environment is not a trial subject: {skipped}")),
    }
    let saved_opt_in = options.environment.get(OPT_IN_OPTION).cloned();
    let saved_trial = options.environment.get(TRIAL_OPTION).cloned();
    let image = env.runtime.clone();
    drop(options);

    let directory = journal_directory()?;
    let execution = ExecutionId::generate();
    let trial = format!("trial-{}", uuid::Uuid::new_v4().simple());
    let folder = trials_root(&directory).join(&trial);
    std::fs::create_dir_all(&folder).map_err(|e| format!("the trial store: {e}"))?;
    let name = helper.as_str().to_owned();
    let plan_phases: Vec<(&str, Vec<(&str, Option<&str>)>)> = match stage {
        RolloutStage::Shadow => vec![("shadow", vec![(OPT_IN_OPTION, None), (TRIAL_OPTION, None)])],
        RolloutStage::OptIn => vec![
            (
                "baseline",
                vec![(OPT_IN_OPTION, None), (TRIAL_OPTION, None)],
            ),
            (
                "candidate",
                vec![(OPT_IN_OPTION, Some("1")), (TRIAL_OPTION, None)],
            ),
        ],
        RolloutStage::BackendDefault => vec![
            (
                "baseline",
                vec![(OPT_IN_OPTION, None), (TRIAL_OPTION, Some(TRIAL_BASELINE))],
            ),
            (
                "candidate",
                vec![(OPT_IN_OPTION, None), (TRIAL_OPTION, None)],
            ),
        ],
    };
    let mut phases = Vec::new();
    let mut windows = Vec::new();
    for (phase_name, settings) in &plan_phases {
        let (phase, session, events) = run_phase(
            &app,
            &environment,
            phase_name,
            &name,
            settings,
            &criteria,
            &folder,
        )
        .await;
        phases.push(phase);
        windows.push((session, events));
    }
    // The owner's settings come back whatever happened.
    let restored = set_options(
        &app,
        &environment,
        &[
            (OPT_IN_OPTION, saved_opt_in.as_deref()),
            (TRIAL_OPTION, saved_trial.as_deref()),
        ],
    );

    let gpu_total = crate::model_runner::optimizer::local_gpu_total_bytes().await;
    let gpu_name = phases.iter().find_map(|phase| phase.gpu.clone());
    let context = Context {
        execution: execution.clone(),
        stage,
        plan: DigestBuilder::new(PLAN_DOMAIN)
            .bytes(
                &serde_json::to_vec(
                    &json!({"criteria": criteria, "stage": stage_tag(stage), "prompts": PROMPTS}),
                )
                .map_err(|e| e.to_string())?,
            )
            .finish(),
        runner_build: DigestBuilder::new(BUILD_DOMAIN)
            .bytes(release.to_string().as_bytes())
            .bytes(pin.id().to_string().as_bytes())
            .finish(),
        engine: core::EngineIdentity {
            name: report_label(backend.tag()),
            version: report_label(&release.version.to_string()),
        },
        host: host_description(gpu_name.as_deref(), gpu_total),
        launch: core::LaunchDescription {
            image: DigestBuilder::new(IMAGE_DOMAIN)
                .bytes(image.as_bytes())
                .finish(),
            backend: core::Label::new("wsl2-cuda").expect("fixed label"),
        },
        paired: stage != RolloutStage::Shadow,
    };
    let mut records = Vec::new();
    for (burst, (phase, (session, events))) in phases.iter_mut().zip(&windows).enumerate() {
        let (adapted, observed, gaps) =
            records_of(&context, phase, burst as u32 + 1, session, events);
        phase.observed_requests = observed;
        phase.records = adapted.len();
        phase.gaps.extend(gaps);
        records.extend(adapted);
    }
    let judgement = judge(stage, &pin.id().to_string(), &phases, &criteria);
    let provenance = if records.is_empty() {
        None
    } else {
        Some(Provenance::of_records(&records).map_err(|e| format!("the trial's records: {e}"))?)
    };
    let evidence = provenance
        .as_ref()
        .map(|p| p.comparable_evidence().map(|d| d.to_string()))
        .transpose()
        .map_err(|e| e.to_string())?;
    let summary = Summary {
        trial: trial.clone(),
        helper: name.clone(),
        backend: backend.tag().to_owned(),
        pin: pin.id().to_string(),
        stage: stage_tag(stage).to_owned(),
        environment: environment.clone(),
        criteria,
        phases,
        conclusive: judgement.conclusive,
        passed: judgement.passed,
        reasons: judgement.reasons.clone(),
        evidence: evidence.clone(),
        measured: provenance
            .as_ref()
            .is_some_and(|p| p.yougori_evidence().is_ok()),
    };
    store(&directory, &summary, &records)?;
    let journal = match (judgement.conclusive, provenance) {
        (true, Some(provenance)) => {
            let verdict = if judgement.passed {
                TrialVerdict::Passed
            } else {
                TrialVerdict::Failed {
                    reason: label("reason", &judgement.reasons[0])?,
                }
            };
            let component = component_of(&pin, &attestation);
            let mut state = state();
            let State::Open { journal, .. } = &mut *state else {
                return Err(format!(
                    "the helper rollout journal is unavailable: {}",
                    unavailable_detail(&state)
                ));
            };
            let outcome = record_trial(
                journal,
                &pin,
                release.clone(),
                stage,
                verdict,
                provenance,
                component,
            )?;
            json!({ "recorded": true, "outcome": outcome_view(&outcome), "track": track_view(journal, &helper, backend) })
        }
        _ => {
            json!({ "recorded": false, "detail": "an inconclusive trial decides nothing; the track is unchanged" })
        }
    };
    Ok(json!({
        "trial": trial,
        "conclusive": judgement.conclusive,
        "passed": judgement.passed,
        "reasons": judgement.reasons,
        "stage": stage_tag(stage),
        "pin": pin.id().to_string(),
        "evidence": evidence,
        "records": records.len(),
        "store": folder.display().to_string(),
        "summary": summary,
        "journal": journal,
        "optionsRestored": restored.is_ok(),
    }))
}

#[cfg(test)]
mod tests;
