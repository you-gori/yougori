//! G08 on the production path: the helper rollout journal and the runner pins the engine
//! keeps (`model_memory::helpers`; GPU-W11: "Roll out in shadow-observation, opt-in, then
//! backend-specific default stages", "Avoid ever-growing source injection"; G08 in
//! docs/combined-plan-remaining-only.md: "Wire admit on delivery, then select, open and
//! RunnerPins::start in run_model_at_revision, run_registry_model, local::run_verified and
//! refresh_server ... Open the rollout journal at engine start"). The library half is used
//! as it is: this module opens its durable journal under the engine's data directory at
//! start ([`open`]), selects and records what every model runner the engine starts gets
//! ([`serve`] then [`record_start`], from the three creation paths and `refresh_server`), records a
//! runner's end once the engine sees its environment stopped or failed
//! ([`reconcile_runners`], every scheduler pass), and answers the `model_helpers` method.
//!
//! The loader (helper ABI [`LOADER_ABI`]): a signed bundle is admitted through the catalog under
//! the trust roots in force ([`admit`]; `model_helper` class, the owner's key, never an unsigned
//! bundle), proposed onto a helper's track for a backend ([`propose`]), and selected for a
//! runner by the rollout's stages. A selected bundle is opened through the catalog, its
//! verified files written under the engine's data directory ([`SERVED_DIRECTORY`]), bound
//! read-only at [`HELPERS_TARGET`] in the runner's container and named in [`HELPERS_OPTION`];
//! the runner reads each named helper's entry file from there instead of the injected source
//! (model_server.py, `helper_bytes`), and a model server served from a bundle is the container
//! command itself. The start is recorded with exactly what was served ([`record_start`]).
//! Source injection stays for every helper no bundle serves, and a selection that cannot be
//! served (a bundle that no longer opens) refuses the start rather than serving something
//! else. Promotion on recorded trials, source-injection removal and remote delivery stay open
//! under G08; the status says so.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use serde_json::{json, Value};

use std::sync::Arc;

use crate::catalog_service::EngineCatalog;
use crate::foundation::catalog::{ArtifactClass, Catalog, PublisherId, Uninterrupted};
use crate::foundation::events::{DurableStreamId, LogConfig, ProducerId};
use crate::foundation::evidence::{Backend, BackendRelease};
use crate::foundation::ids::{ExecutionId, OperationId};
use crate::foundation::report::{Label, Provenance, RunRecord};
use crate::foundation::signing::SignedComponent;
use crate::foundation::signing::SystemCalendar;
use crate::model_memory::helpers::{
    pin_statement, EvidenceReference, HelperAbi, HelperAdmission, HelperId, HelperOffer, HelperPin,
    HelperSignature, HostHelperAbi, OnQuarantine, PinAdmissibility, PinRefusal, Promotion,
    RecordOutcome, ReplayReport, RollbackTarget, RolloutEvidence, RolloutJournal, RolloutStage,
    RunnerHelpers, RunnerInstance, RunnerStart, ServingHelper, SourceInjectionRemoval,
    TrialVerdict, Withdrawal, MAX_BUNDLE_BYTES,
};

pub(crate) mod trial;

/// Where the journal lives under the engine's data directory.
pub(crate) const DIRECTORY: &str = "model-helpers";
/// Where admitted bundles' attestations are kept, under [`DIRECTORY`]: one JSON file per
/// pin holding the pin and the detached signature, so a trial's signed component can be
/// identified again under the roots in force after a restart.
const ATTESTATIONS_DIRECTORY: &str = "attestations";
/// Bounds of a trial's evidence file: CORE-08 run records.
const MAX_EVIDENCE_BYTES: u64 = 16 << 20;
const MAX_EVIDENCE_RECORDS: usize = 4096;
/// The role recorded with the owner's rollout decisions.
const DECIDED_BY: &str = "owner";
/// How long a recorded start is left alone by [`reconcile_runners`] whatever the environment's
/// status: a start is recorded before the environment comes up (`refresh_server` runs while it
/// is still stopped), and the scheduler's pass in between must not end it (the third rollout
/// run of 30 October lost every start that way). A runner that never comes up ends at the
/// first pass after this.
const START_GRACE: Duration = Duration::from_secs(180);
/// The stream and its one owner, as the library documents them.
const STREAM: &str = "model-memory.helper-rollouts";
const OWNER: &str = "model-memory.rollouts";
/// The journal's retention: a record is a few hundred bytes and a runner start and stop
/// are two, so this keeps years of ordinary use; the journal restates its state before
/// retention could drop what no restatement holds.
const CONFIG: LogConfig = LogConfig {
    max_entries: 65_536,
    max_bytes: 64 << 20,
    segment_entries: 1_024,
    segment_bytes: 1 << 20,
};

/// The llama.cpp build the model server installs (`preflight::inspect_gguf` names it as the
/// GGUF runner's dependency; engine_backends.py pins it).
pub(crate) const LLAMA_CPP_RELEASE: &str = "b11425";

/// The helpers a runner gets, each by the workload variable that carries its compressed
/// source today (`model_runner.rs`: `server_payload`, `optimizer::source`,
/// `publisher_source`, `registry_source`, `clef_source`, `backends_source`).
const HELPERS: [(&str, &str); 6] = [
    ("model-server", "YOUGORI_MODEL_SERVER_SOURCE"),
    ("gpu-optimizer", "YOUGORI_GPU_SOURCE"),
    ("publisher-routes", "YOUGORI_PUBLISHER_SOURCE"),
    ("registry-verifier", "YOUGORI_REGISTRY_SOURCE"),
    ("clef-adapter", "YOUGORI_CLEF_SOURCE"),
    ("engine-backends", "YOUGORI_BACKENDS_SOURCE"),
];

/// The helper ABI this host's runner loader provides: 1.0, the first. A bundle names the ABI
/// it needs; a major this loader does not provide is not admissible.
pub(crate) const LOADER_ABI: HelperAbi = HelperAbi { major: 1, minor: 0 };

/// Where the served bundles are bound, read-only, in the runner's container.
pub(crate) const HELPERS_TARGET: &str = "/yougori-helpers";

/// The workload variable naming the helpers served from bundles: a JSON object of helper
/// name to `{"entry": "<path under /yougori-helpers>", "pin": "<pin id>"}`.
pub(crate) const HELPERS_OPTION: &str = "YOUGORI_HELPERS";

/// The same for shadow candidates, written beside and reported by the runner, never run.
pub(crate) const SHADOW_OPTION: &str = "YOUGORI_HELPERS_SHADOW";

/// The workload variable a person's opt-in sets to `1`: the runner's next start takes the
/// opt-in candidates of its helpers' tracks.
pub(crate) const OPT_IN_OPTION: &str = "YOUGORI_HELPERS_OPT_IN";

/// Where served bundles' files are written, under the engine's data directory: one directory
/// per served runner, removed with its environment.
pub(crate) const SERVED_DIRECTORY: &str = "model-helpers/served";

/// This host's helper loader: it provides [`LOADER_ABI`], nothing else decides admissibility
/// here (the catalog's publication and trust checks run at admission and when a bundle is
/// opened).
struct HostLoader;

impl PinAdmissibility for HostLoader {
    fn check(&self, pin: &HelperPin) -> Result<(), PinRefusal> {
        HostHelperAbi::single(LOADER_ABI)
            .check(pin.abi)
            .map_err(|refusal| PinRefusal::IncompatibleAbi { refusal })
    }
}

/// The admission under the trust roots in force, or why there is none.
fn admission() -> Result<HelperAdmission, String> {
    let roots = crate::trust_roots::service().shared().ok_or_else(|| {
        "no trust roots are in force (YOUGORI_TRUST_ROOTS): no helper bundle can be admitted or opened".to_owned()
    })?;
    Ok(HelperAdmission::new(
        HostHelperAbi::single(LOADER_ABI),
        roots,
        Arc::new(SystemCalendar),
    ))
}

/// Runs `f` on the engine's open catalog, or says why it is not open.
fn with_catalog<T>(f: impl FnOnce(&mut Catalog) -> T) -> Result<T, String> {
    match crate::catalog_service::engine() {
        EngineCatalog::Open { service, .. } => Ok(f(&mut service.catalog())),
        other => Err(format!(
            "the engine's catalog is not open, so no helper bundle can be admitted or opened: {}",
            crate::catalog_service::not_open_detail(other)
        )),
    }
}

pub(super) fn decode_hex(text: &str) -> Result<Vec<u8>, String> {
    let text = text.trim();
    if text.len() % 2 != 0 {
        return Err("the signature is not hexadecimal".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&text[i..i + 2], 16)
                .map_err(|_| "the signature is not hexadecimal".to_owned())
        })
        .collect()
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let metadata = std::fs::metadata(path)
        .map_err(|error| format!("{} cannot be read: {error}", path.display()))?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(format!(
            "{} is not a regular file of at most {limit} bytes",
            path.display()
        ));
    }
    std::fs::read(path).map_err(|error| format!("{} cannot be read: {error}", path.display()))
}

fn pin_view(pin: &HelperPin) -> Value {
    json!({
        "id": pin.id().to_string(),
        "helper": pin.helper.as_str(),
        "version": pin.version.to_string(),
        "abi": format!("{}.{}", pin.abi.major, pin.abi.minor),
        "runners": pin.runners.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "object": json!(pin.object),
        "bundle": pin.bundle.to_string(),
        "lengthBytes": pin.length_bytes,
        "publisher": json!(pin.publisher),
    })
}

/// The backend a person names for a track.
fn backend_named(name: &str) -> Result<Backend, String> {
    match name.trim().to_ascii_lowercase().as_str() {
        "transformers" => Ok(Backend::Transformers),
        "vllm" => Ok(Backend::Vllm),
        "llama_cpp" | "llama-cpp" | "llamacpp" => Ok(Backend::LlamaCpp),
        other => Err(format!(
            "unknown backend '{other}'; use transformers, vllm or llama_cpp"
        )),
    }
}

/// Admits the signed bundle at `bundle`, whose detached attestation (`yougori-sign`'s
/// `sign_artifact` output: the publisher and the hexadecimal signature) is at `attestation`,
/// through the engine's catalog under the trust roots in force; the catalog runs the trust
/// and structure checks, nothing is published without them. The admitted pin is kept for
/// [`propose`] and shown by the status.
pub(crate) fn admit(bundle: &Path, attestation: &Path) -> Result<Value, String> {
    let bytes = read_bounded(bundle, MAX_BUNDLE_BYTES)?;
    let attestation: Value = serde_json::from_slice(&read_bounded(attestation, 8192)?)
        .map_err(|error| format!("the attestation is not JSON: {error}"))?;
    let publisher: PublisherId = serde_json::from_value(attestation["publisher"].clone())
        .map_err(|error| format!("the attestation names no publisher: {error}"))?;
    let signature = decode_hex(
        attestation["signature"]
            .as_str()
            .ok_or("the attestation carries no signature")?,
    )?;
    let admission = admission()?;
    let admitted = with_catalog(|catalog| {
        admission.admit(
            catalog,
            HelperOffer {
                bundle: bytes,
                signature: Some(HelperSignature {
                    publisher,
                    signature: signature.clone(),
                }),
                operation: OperationId::generate(),
                execution: ExecutionId::generate(),
            },
            &mut Uninterrupted,
        )
    })?
    .map_err(|refusal| format!("the helper bundle was not admitted: {refusal}"))?;
    let view = pin_view(&admitted.pin);
    let attestation = Attestation {
        publisher,
        signature,
    };
    let mut state = state();
    let kept = if let State::Open {
        admitted: known,
        attestations,
        directory,
        ..
    } = &mut *state
    {
        let id = admitted.pin.id().to_string();
        known.insert(id.clone(), admitted.pin.clone());
        attestations.insert(id, attestation.clone());
        write_attestation(
            &directory.join(ATTESTATIONS_DIRECTORY),
            &admitted.pin,
            &attestation,
        )
    } else {
        Err("the journal is not open, so the attestation is kept for this run only".to_owned())
    };
    Ok(json!({
        "admitted": view,
        "key": admitted.key.to_string(),
        "newlyPublished": admitted.newly_published,
        "attestation": match kept {
            Ok(path) => json!({ "kept": true, "path": path.display().to_string() }),
            Err(problem) => json!({ "kept": false, "problem": problem }),
        },
        "manifest": {
            "entry": admitted.manifest.entry().as_str(),
            "files": admitted.manifest.files().len(),
            "filesBytes": admitted.manifest.files_bytes(),
        },
    }))
}

/// Makes the admitted pin `pin` the shadow candidate of its helper's track on `backend`
/// (`HelperRollouts::propose`, through the journal): the rollout's first stage.
pub(crate) fn propose(pin: &str, backend: &str) -> Result<Value, String> {
    let backend = backend_named(backend)?;
    let mut state = state();
    let State::Open {
        journal, admitted, ..
    } = &mut *state
    else {
        return Err(format!(
            "the helper rollout journal is unavailable: {}",
            unavailable_detail(&state)
        ));
    };
    let pin = admitted
        .get(pin.trim())
        .cloned()
        .ok_or_else(|| format!("no admitted bundle has the pin {pin}; admit it first (the status lists the admitted pins)"))?;
    journal
        .propose(pin.clone(), backend, &HostLoader)
        .map_err(|error| format!("the proposal was refused: {error:?}"))?;
    let track = journal
        .rollouts()
        .track(&pin.helper, backend)
        .map(|view| serde_json::to_value(view).unwrap_or(Value::Null))
        .unwrap_or(Value::Null);
    Ok(json!({ "proposed": pin_view(&pin), "backend": backend.tag(), "track": track }))
}

/// The helpers a runner started from `environment` loads: those whose source the workload
/// carries.
pub(crate) fn helpers_of(environment: &BTreeMap<String, String>) -> Vec<HelperId> {
    HELPERS
        .iter()
        .filter(|(_, variable)| environment.contains_key(*variable))
        .filter_map(|(helper, _)| HelperId::new(*helper).ok())
        .collect()
}

/// Why a runner's helpers are not recorded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Skipped {
    /// A source-only publisher serves files, not a model: it has no backend release.
    SourceOnly,
    /// The workload carries no model server.
    NotAModelRunner,
}

impl std::fmt::Display for Skipped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SourceOnly => f.write_str("a source-only publisher runs no model backend"),
            Self::NotAModelRunner => f.write_str("the workload runs no model server"),
        }
    }
}

/// The exact backend release a runner started from `environment` runs: the pinned vLLM
/// release for a vLLM workload, the pinned llama.cpp build for GGUF (on the GPU or the
/// CPU), else the pinned Transformers release. `Ok(Err(..))` for a workload that runs no
/// model backend.
pub(crate) fn release_of(
    environment: &BTreeMap<String, String>,
) -> Result<Result<BackendRelease, Skipped>, String> {
    if !environment.contains_key("YOUGORI_MODEL_SERVER_SOURCE") {
        return Ok(Err(Skipped::NotAModelRunner));
    }
    let backend = match environment.get("YOUGORI_MODEL_FORMAT").map(String::as_str) {
        Some("source") => return Ok(Err(Skipped::SourceOnly)),
        Some("vllm") => Backend::Vllm,
        Some("gguf") => Backend::LlamaCpp,
        _ => Backend::Transformers,
    };
    release_for(backend).map(Ok)
}

/// The exact release this engine runs of `backend`: the pinned vLLM release, the pinned
/// llama.cpp build, the pinned Transformers release.
pub(crate) fn release_for(backend: Backend) -> Result<BackendRelease, String> {
    match backend {
        Backend::Vllm => super::optimizer::pinned_release()
            .map(Clone::clone)
            .map_err(str::to_owned),
        Backend::LlamaCpp => BackendRelease::new(Backend::LlamaCpp, LLAMA_CPP_RELEASE)
            .map_err(|error| format!("The engine's pinned llama.cpp build is invalid: {error}")),
        Backend::Transformers => super::optimizer::pinned_transformers_release()
            .map(Clone::clone)
            .map_err(str::to_owned),
        Backend::Qemu => Err("QEMU runs no model helper".to_owned()),
        Backend::Hcs => Err("HCS runs no model helper".to_owned()),
    }
}

/// A rollout stage as a person names it.
fn stage_named(name: &str) -> Result<RolloutStage, String> {
    match name.trim().to_ascii_lowercase().as_str() {
        "shadow" => Ok(RolloutStage::Shadow),
        "opt-in" | "opt_in" | "optin" => Ok(RolloutStage::OptIn),
        "backend-default" | "backend_default" | "default" => Ok(RolloutStage::BackendDefault),
        other => Err(format!(
            "unknown stage '{other}'; use shadow, opt-in or backend-default"
        )),
    }
}

/// A public label (the report module's redaction rules) for a decision's `name`.
fn label(name: &str, value: &str) -> Result<Label, String> {
    Label::new(value.trim()).map_err(|error| format!("{name}: {error}"))
}

/// The CORE-08 run records of a trial, read from `path`: a JSON array of records, or an
/// object whose `records` holds one, each validated as the report module validates it.
/// Their provenance is the rollout's evidence: a Yougori measurement only when every record
/// ran in an authorized disposable environment; a fake-substrate run is recorded but never
/// promotes.
pub(crate) fn evidence_from(path: &Path) -> Result<Provenance, String> {
    let value: Value = serde_json::from_slice(&read_bounded(path, MAX_EVIDENCE_BYTES)?)
        .map_err(|error| format!("the evidence file is not JSON: {error}"))?;
    let records =
        match &value {
            Value::Array(records) => records.as_slice(),
            Value::Object(object) => object
                .get("records")
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .ok_or("the evidence file holds no records array")?,
            _ => return Err(
                "the evidence file is neither an array of run records nor an object with records"
                    .to_owned(),
            ),
        };
    if records.len() > MAX_EVIDENCE_RECORDS {
        return Err(format!(
            "{} run records; the limit is {MAX_EVIDENCE_RECORDS}",
            records.len()
        ));
    }
    let records = records
        .iter()
        .enumerate()
        .map(|(index, record)| {
            RunRecord::from_json(&record.to_string())
                .map_err(|error| format!("run record {index} is refused: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Provenance::of_records(&records)
        .map_err(|error| format!("the records give no provenance: {error}"))
}

/// The admitted pin `id` and its attestation.
fn admitted_pin(id: &str) -> Result<(HelperPin, Attestation), String> {
    let state = state();
    let State::Open {
        admitted,
        attestations,
        ..
    } = &*state
    else {
        return Err(format!(
            "the helper rollout journal is unavailable: {}",
            unavailable_detail(&state)
        ));
    };
    let pin = admitted
        .get(id.trim())
        .cloned()
        .ok_or_else(|| format!("no admitted bundle has the pin {id}; admit it first (the status lists the admitted pins)"))?;
    let attestation = attestations.get(id.trim()).cloned().ok_or_else(|| {
        format!("the attestation of pin {id} is not kept; admit the bundle again")
    })?;
    Ok((pin, attestation))
}

/// The attestation kept for `pin`.
fn attestation_of(pin: &HelperPin) -> Result<Attestation, String> {
    admitted_pin(&pin.id().to_string()).map(|(_, attestation)| attestation)
}

/// `pin`'s bundle as a CORE-08 signed component: its attestation verified again under the
/// trust roots in force now, so a trial of a bundle whose key was revoked since is refused.
fn component_of(pin: &HelperPin, attestation: &Attestation) -> SignedComponent {
    crate::trust_roots::service().identify(
        ArtifactClass::ModelHelper,
        &attestation.publisher,
        pin_statement(pin),
        &attestation.signature,
    )
}

fn track_view(journal: &RolloutJournal, helper: &HelperId, backend: Backend) -> Value {
    journal
        .rollouts()
        .track(helper, backend)
        .map(|view| serde_json::to_value(view).unwrap_or(Value::Null))
        .unwrap_or(Value::Null)
}

fn rollback_view(to: &RollbackTarget) -> Value {
    match to {
        RollbackTarget::SourceInjection => json!("source_injection"),
        RollbackTarget::Bundle { pin } => json!({ "bundle": pin.to_string() }),
        RollbackTarget::Unavailable => json!("unavailable"),
    }
}

fn outcome_view(outcome: &RecordOutcome) -> Value {
    match outcome {
        RecordOutcome::Recorded => json!({ "outcome": "recorded" }),
        RecordOutcome::RolledBack { failed, stage, to } => json!({
            "outcome": "rolled_back",
            "failed": failed.to_string(),
            "stage": stage.to_string(),
            "to": rollback_view(to),
        }),
    }
}

fn promotion_view(promotion: &Promotion) -> Value {
    json!({ "pin": promotion.pin.to_string(), "from": promotion.from.to_string(), "to": promotion.to.to_string() })
}

/// Records one trial of `pin` in `journal` (see [`record`]).
fn record_trial(
    journal: &mut RolloutJournal,
    pin: &HelperPin,
    runner: BackendRelease,
    stage: RolloutStage,
    verdict: TrialVerdict,
    provenance: Provenance,
    component: SignedComponent,
) -> Result<RecordOutcome, String> {
    journal
        .record(
            RolloutEvidence {
                pin: pin.id(),
                runner,
                stage,
                verdict,
                provenance,
            },
            component,
            &HostLoader,
        )
        .map_err(|error| format!("the trial was not recorded: {error}"))
}

/// Records a trial of the admitted pin `pin` on `backend`'s pinned release at `stage`
/// (`HelperRollouts::record`, through the journal): `verdict` is `passed` or `failed`
/// (with its `reason`), `evidence` the path of the trial's CORE-08 run records. A failure
/// rolls the track back at once; a measured pass makes the candidate promotable.
pub(crate) fn record(
    pin: &str,
    backend: &str,
    stage: &str,
    verdict: &str,
    reason: Option<&str>,
    evidence: &Path,
) -> Result<Value, String> {
    let backend = backend_named(backend)?;
    let stage = stage_named(stage)?;
    let verdict = match verdict.trim().to_ascii_lowercase().as_str() {
        "passed" | "pass" => TrialVerdict::Passed,
        "failed" | "fail" => TrialVerdict::Failed {
            reason: label("reason", reason.ok_or("a failed trial needs its reason")?)?,
        },
        other => return Err(format!("unknown verdict '{other}'; use passed or failed")),
    };
    let provenance = evidence_from(evidence)?;
    let runner = release_for(backend)?;
    let (pin, attestation) = admitted_pin(pin)?;
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
        runner.clone(),
        stage,
        verdict,
        provenance.clone(),
        component,
    )?;
    Ok(json!({
        "recorded": {
            "pin": pin.id().to_string(),
            "helper": pin.helper.as_str(),
            "backend": backend.tag(),
            "runner": runner.to_string(),
            "stage": stage.to_string(),
            "evidence": provenance.label(),
            "measured": provenance.yougori_evidence().is_ok(),
        },
        "outcome": outcome_view(&outcome),
        "track": track_view(journal, &pin.helper, backend),
    }))
}

/// The candidate pin of `helper`'s track on `backend`, or the default bundle when `default`.
/// The stage of the candidate of `helper`'s track on `backend`.
fn candidate_stage(helper: &HelperId, backend: Backend) -> Result<RolloutStage, String> {
    let state = state();
    let State::Open { journal, .. } = &*state else {
        return Err(format!(
            "the helper rollout journal is unavailable: {}",
            unavailable_detail(&state)
        ));
    };
    journal
        .rollouts()
        .track(helper, backend)
        .and_then(|track| track.candidate.map(|(_, stage)| stage))
        .ok_or_else(|| "the track has no candidate; propose a bundle first".to_owned())
}

fn track_pin(helper: &HelperId, backend: Backend, default: bool) -> Result<HelperPin, String> {
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
    if default {
        match track.default {
            crate::model_memory::helpers::DefaultPath::Bundle { pin } => Ok(pin),
            _ => Err(
                "the track's default is not a bundle; promote one to the backend default first"
                    .to_owned(),
            ),
        }
    } else {
        track
            .candidate
            .map(|(pin, _)| pin)
            .ok_or_else(|| "the track has no candidate; propose a bundle first".to_owned())
    }
}

/// Promotes the candidate of `helper`'s track on `backend` one stage on (shadow to
/// opt-in, opt-in to backend default), given the engine's passed trial of it at its stage
/// (`model_helpers trial`): the journal checks the trial's records are the measured pass it
/// recorded there. An evidence file from elsewhere never promotes.
pub(crate) fn promote(helper: &str, backend: &str, trial: &str) -> Result<Value, String> {
    let backend = backend_named(backend)?;
    let helper = HelperId::new(helper.trim()).map_err(|error| format!("helper: {error}"))?;
    let candidate = track_pin(&helper, backend, false)?;
    let provenance = trial::stored_evidence(trial, &candidate, candidate_stage(&helper, backend)?)?;
    let component = component_of(&candidate, &attestation_of(&candidate)?);
    let reference = EvidenceReference::of(&provenance, component)
        .map_err(|error| format!("the evidence backs no decision: {error}"))?;
    let mut state = state();
    let State::Open { journal, .. } = &mut *state else {
        return Err(format!(
            "the helper rollout journal is unavailable: {}",
            unavailable_detail(&state)
        ));
    };
    let promotion = journal
        .promote(&helper, backend, &reference, &HostLoader)
        .map_err(|error| format!("the promotion was refused: {error}"))?;
    Ok(
        json!({ "promoted": promotion_view(&promotion), "backend": backend.tag(), "track": track_view(journal, &helper, backend) }),
    )
}

/// Records the owner's decision to remove source injection from `helper`'s track on
/// `backend`, given the engine's passed trial of its default bundle as the backend default
/// and the `reason`; from then on a runner the bundles cannot serve is refused.
pub(crate) fn remove_source_injection(
    helper: &str,
    backend: &str,
    trial: &str,
    reason: &str,
) -> Result<Value, String> {
    let backend = backend_named(backend)?;
    let helper = HelperId::new(helper.trim()).map_err(|error| format!("helper: {error}"))?;
    let reason = label("reason", reason)?;
    let default = track_pin(&helper, backend, true)?;
    let provenance = trial::stored_evidence(trial, &default, RolloutStage::BackendDefault)?;
    let component = component_of(&default, &attestation_of(&default)?);
    let reference = EvidenceReference::of(&provenance, component)
        .map_err(|error| format!("the evidence backs no decision: {error}"))?;
    let decision = SourceInjectionRemoval {
        decided_by: label("decided_by", DECIDED_BY)?,
        reason,
    };
    let mut state = state();
    let State::Open { journal, .. } = &mut *state else {
        return Err(format!(
            "the helper rollout journal is unavailable: {}",
            unavailable_detail(&state)
        ));
    };
    journal
        .remove_source_injection(&helper, backend, decision, &reference)
        .map_err(|error| format!("the removal was refused: {error}"))?;
    Ok(
        json!({ "removed": "source_injection", "helper": helper.as_str(), "backend": backend.tag(), "track": track_view(journal, &helper, backend) }),
    )
}

/// Withdraws the admitted pin `pin` from every track that names it, for `reason`: a
/// serving default rolls back, a candidate is dropped, a rollback target is forgotten.
pub(crate) fn withdraw(pin: &str, reason: &str) -> Result<Value, String> {
    let reason = label("reason", reason)?;
    let (pin, _) = admitted_pin(pin)?;
    let decision = Withdrawal {
        decided_by: label("decided_by", DECIDED_BY)?,
        reason,
    };
    let mut state = state();
    let State::Open { journal, .. } = &mut *state else {
        return Err(format!(
            "the helper rollout journal is unavailable: {}",
            unavailable_detail(&state)
        ));
    };
    let withdrawn = journal
        .withdraw(pin.id(), decision, &HostLoader)
        .map_err(|error| format!("the withdrawal was refused: {error}"))?;
    let tracks: Vec<Value> = withdrawn
        .iter()
        .map(|track| {
            json!({
                "helper": track.helper.as_str(),
                "backend": track.backend.tag(),
                "outcome": track.outcome.as_ref().map(outcome_view),
                "track": track_view(journal, &track.helper, track.backend),
            })
        })
        .collect();
    Ok(json!({ "withdrawn": pin.id().to_string(), "tracks": tracks }))
}

/// What opening the journal found, kept for the status.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Opened {
    created: bool,
    records: u64,
    markers: usize,
    gaps: usize,
    fell_back: usize,
    restated: bool,
}

impl Opened {
    fn of(report: &ReplayReport) -> Self {
        Self {
            created: report.opened.created,
            records: report.records,
            markers: report.markers.len(),
            gaps: report.gaps.len(),
            fell_back: report.fell_back.len(),
            restated: report.restated,
        }
    }

    fn view(&self) -> Value {
        json!({
            "created": self.created,
            "records": self.records,
            "markers": self.markers,
            "gaps": self.gaps,
            "fellBack": self.fell_back,
            "restated": self.restated,
        })
    }
}

/// The engine's journal, as [`open`] left it.
enum State {
    /// [`open`] has not run.
    NotOpened,
    /// [`open`] ran and the journal refused; nothing is recorded until the next start.
    Refused { directory: PathBuf, error: String },
    Open {
        directory: PathBuf,
        journal: RolloutJournal,
        opened: Opened,
        /// The admitted pins by id: those kept under [`ATTESTATIONS_DIRECTORY`] at open and
        /// those [`admit`] added since.
        admitted: BTreeMap<String, HelperPin>,
        /// Each admitted pin's detached attestation, by pin id.
        attestations: BTreeMap<String, Attestation>,
        /// Attestation files that were not read back at open, with the reason.
        attestation_problems: Vec<String>,
        /// Where served bundles are written ([`SERVED_DIRECTORY`] under the data directory).
        served_root: PathBuf,
        /// When each runner's start was recorded, for [`START_GRACE`].
        started: BTreeMap<String, std::time::Instant>,
    },
}

/// A bundle's detached attestation as `yougori-sign` writes it: the publisher and the
/// signature over the bundle's content statement.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Attestation {
    publisher: PublisherId,
    signature: Vec<u8>,
}

/// Reads every attestation file of `directory` back: the pins and attestations it holds,
/// and the files it could not read.
fn load_attestations(
    directory: &Path,
) -> (
    BTreeMap<String, HelperPin>,
    BTreeMap<String, Attestation>,
    Vec<String>,
) {
    let (mut pins, mut attestations, mut problems) = (BTreeMap::new(), BTreeMap::new(), Vec::new());
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return (pins, attestations, problems)
        }
        Err(error) => {
            problems.push(format!("{}: {error}", directory.display()));
            return (pins, attestations, problems);
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|extension| extension != "json") {
            continue;
        }
        match read_attestation(&path) {
            Ok((pin, attestation)) => {
                let id = pin.id().to_string();
                if path.file_stem().is_none_or(|stem| stem != id.as_str()) {
                    problems.push(format!("{}: names another pin ({id})", path.display()));
                    continue;
                }
                pins.insert(id.clone(), pin);
                attestations.insert(id, attestation);
            }
            Err(problem) => problems.push(format!("{}: {problem}", path.display())),
        }
    }
    (pins, attestations, problems)
}

fn read_attestation(path: &Path) -> Result<(HelperPin, Attestation), String> {
    let value: Value = serde_json::from_slice(&read_bounded(path, 64 << 10)?)
        .map_err(|error| format!("not JSON: {error}"))?;
    let pin: HelperPin = serde_json::from_value(value["pin"].clone())
        .map_err(|error| format!("the pin does not read: {error}"))?;
    let publisher: PublisherId = serde_json::from_value(value["publisher"].clone())
        .map_err(|error| format!("the publisher does not read: {error}"))?;
    if publisher != pin.publisher {
        return Err("the attestation's publisher is not the pin's".to_owned());
    }
    let signature = decode_hex(value["signature"].as_str().ok_or("no signature")?)?;
    Ok((
        pin,
        Attestation {
            publisher,
            signature,
        },
    ))
}

/// Writes `pin`'s attestation under `directory`, named by the pin id.
fn write_attestation(
    directory: &Path,
    pin: &HelperPin,
    attestation: &Attestation,
) -> Result<PathBuf, String> {
    std::fs::create_dir_all(directory)
        .map_err(|error| format!("{}: {error}", directory.display()))?;
    let path = directory.join(format!("{}.json", pin.id()));
    let hex: String = attestation
        .signature
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let document = json!({ "pin": pin, "publisher": attestation.publisher, "signature": hex });
    std::fs::write(&path, document.to_string())
        .map_err(|error| format!("{}: {error}", path.display()))?;
    Ok(path)
}

static STATE: Mutex<State> = Mutex::new(State::NotOpened);

fn state() -> std::sync::MutexGuard<'static, State> {
    STATE.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Opens the journal in `directory`, creating the stream on first use, and replays it with
/// this host's loader ([`HostLoader`]) and `OnQuarantine::Refuse`.
pub(crate) fn open_journal(directory: &Path) -> Result<(RolloutJournal, ReplayReport), String> {
    let stream = DurableStreamId::new(STREAM).map_err(|error| error.to_string())?;
    let owner = ProducerId::new(OWNER).map_err(|error| error.to_string())?;
    std::fs::create_dir_all(directory).map_err(|error| {
        format!(
            "the directory {} could not be made: {error}",
            directory.display()
        )
    })?;
    RolloutJournal::open(
        directory,
        stream,
        owner,
        CONFIG,
        &HostLoader,
        OnQuarantine::Refuse,
    )
    .map_err(|error| format!("{error:?}"))
}

/// Opens the engine's journal under `data_directory` at engine start. A refusal is kept
/// for the status and returned; runners then start as before, unrecorded, since every one
/// is served by source injection in this build either way.
pub(crate) fn open(data_directory: &Path) -> Result<(), String> {
    let directory = data_directory.join(DIRECTORY);
    let outcome = open_journal(&directory);
    let mut state = state();
    match outcome {
        Ok((journal, report)) => {
            let (admitted, attestations, attestation_problems) =
                load_attestations(&directory.join(ATTESTATIONS_DIRECTORY));
            let served_root = data_directory.join(SERVED_DIRECTORY);
            if let Err(error) = std::fs::create_dir_all(&served_root) {
                eprintln!(
                    "The served helpers directory {} could not be made: {error}",
                    served_root.display()
                );
            }
            crate::host_files::allow_engine_guest_folder(&served_root);
            *state = State::Open {
                directory,
                opened: Opened::of(&report),
                journal,
                admitted,
                attestations,
                attestation_problems,
                served_root,
                started: BTreeMap::new(),
            };
            Ok(())
        }
        Err(error) => {
            *state = State::Refused {
                directory: directory.clone(),
                error: error.clone(),
            };
            Err(format!(
                "the helper rollout journal at {} was not opened: {error}",
                directory.display()
            ))
        }
    }
}

/// Why a runner's start was not recorded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum StartRefusal {
    /// The journal is not open; the reason is in the status.
    JournalUnavailable { detail: String },
    /// The environment id is not an identifier.
    Instance { detail: String },
    /// No backend release is known for the workload.
    Release { detail: String },
    /// The rollout refused the selection: source injection was removed from a track and
    /// no admissible bundle can serve this runner.
    Selection { helper: HelperId, detail: String },
    /// A selected bundle could not be opened through the catalog or written for the runner.
    Bundle { helper: HelperId, detail: String },
    /// The journal refused or failed to record the start.
    Journal { detail: String },
}

impl std::fmt::Display for StartRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::JournalUnavailable { detail } => {
                write!(f, "the helper rollout journal is unavailable: {detail}")
            }
            Self::Instance { detail } => {
                write!(f, "the runner's id is not an identifier: {detail}")
            }
            Self::Release { detail } => {
                write!(f, "the runner's backend release is unknown: {detail}")
            }
            Self::Selection { helper, detail } => {
                write!(f, "no helper can serve {helper} on this runner: {detail}")
            }
            Self::Bundle { helper, detail } => write!(
                f,
                "the helper bundle selected for {helper} could not be served: {detail}; the model is \
                 not started with another helper than the rollout names"
            ),
            Self::Journal { detail } => write!(f, "the helper rollout journal refused: {detail}"),
        }
    }
}

impl std::error::Error for StartRefusal {}

/// What a runner starts with, or why nothing is recorded for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Start {
    Recorded(Vec<RunnerHelpers>),
    /// The same start is already recorded: nothing was appended.
    Unchanged(Vec<RunnerHelpers>),
    Skipped(Skipped),
}

impl Start {
    /// The run result's `helpers` entry: each helper with how it is served.
    pub(crate) fn view(&self) -> Value {
        match self {
            Self::Recorded(selected) | Self::Unchanged(selected) => json!({
                "state": if matches!(self, Self::Recorded(_)) { "recorded" } else { "unchanged" },
                "loader": format!("{}.{}", LOADER_ABI.major, LOADER_ABI.minor),
                "helpers": selected.iter().map(describe).collect::<Vec<_>>(),
            }),
            Self::Skipped(why) => json!({ "state": "skipped", "detail": why.to_string() }),
        }
    }
}

fn describe(selected: &RunnerHelpers) -> Value {
    json!({
        "helper": selected.helper.as_str(),
        "runner": selected.runner.to_string(),
        "serve": match &selected.serve {
            ServingHelper::SourceInjection => json!("source_injection"),
            ServingHelper::Bundle { pin } => json!({ "bundle": pin.id().to_string() }),
        },
        "shadow": selected.shadow.as_ref().map(|pin| pin.id().to_string()),
        "fallback": selected.fallback,
    })
}

/// What a runner is served (G08): the selection of every helper, the directory holding the
/// bundles' files when any bundle serves or shadows (bound read-only at [`HELPERS_TARGET`]),
/// the workload variables naming them, and the container command when the model server itself
/// comes from a bundle.
#[derive(Clone, Debug, Default)]
pub(crate) struct Served {
    pub(crate) selected: Vec<RunnerHelpers>,
    pub(crate) directory: Option<PathBuf>,
    pub(crate) variables: Vec<(&'static str, String)>,
    pub(crate) command: Option<String>,
}

impl Served {
    /// The bind of the served directory, when any bundle is served.
    pub(crate) fn bind(&self) -> Option<Value> {
        self.directory.as_ref().map(|directory| {
            json!({ "source": directory.display().to_string(), "target": HELPERS_TARGET, "readOnly": true })
        })
    }
}

/// Whether `environment` opts its runner in to the opt-in stage of its helpers' tracks.
pub(crate) fn opted_in(environment: &BTreeMap<String, String>) -> bool {
    environment
        .get(OPT_IN_OPTION)
        .is_some_and(|value| value == "1")
}

/// Selects every helper of a runner on `release` through `journal`.
fn select_in(
    journal: &RolloutJournal,
    release: &BackendRelease,
    helpers: &[HelperId],
    opted_in: bool,
) -> Result<Vec<RunnerHelpers>, StartRefusal> {
    helpers
        .iter()
        .map(|helper| {
            journal
                .select(helper, release, opted_in, &HostLoader)
                .map_err(|refusal| StartRefusal::Selection {
                    helper: helper.clone(),
                    detail: refusal.to_string(),
                })
        })
        .collect()
}

/// The model server's shadow runner (`helper_shadow.py`), at the path the server reads it from
/// (`SHADOW_RUNNER` in model_server.py) under `directory`.
pub(crate) const SHADOW_RUNNER: &str = "shadow/yougori-shadow.py";

fn write_shadow_runner(directory: &Path) -> Result<(), String> {
    let path = directory.join(SHADOW_RUNNER);
    let parent = path.parent().ok_or("the shadow runner has no directory")?;
    std::fs::create_dir_all(parent).map_err(|e| format!("the shadow runner's directory: {e}"))?;
    std::fs::write(
        &path,
        include_str!("helper_shadow.py").replace("\r\n", "\n"),
    )
    .map_err(|e| format!("the shadow runner could not be written: {e}"))
}

/// The first helper `shadows` names, for a refusal's subject.
fn bundles_helper(shadows: &serde_json::Map<String, Value>) -> HelperId {
    shadows
        .keys()
        .next()
        .and_then(|name| HelperId::new(name.as_str()).ok())
        .unwrap_or_else(|| HelperId::new("model-server").expect("fixed helper id"))
}

/// The baseline of a trial (`trial::TRIAL_OPTION`): every helper of the runner served by
/// source injection with no shadow, for that one start; refused where a track removed source
/// injection, since the trial then has no baseline to compare with.
fn baseline_in(
    journal: &RolloutJournal,
    release: &BackendRelease,
    helpers: &[HelperId],
) -> Result<Vec<RunnerHelpers>, StartRefusal> {
    helpers
        .iter()
        .map(|helper| {
            let removed = journal
                .rollouts()
                .track(helper, release.backend)
                .is_some_and(|track| {
                    !matches!(
                        track.source_injection,
                        crate::model_memory::helpers::SourceInjection::Retained
                    )
                });
            if removed {
                return Err(StartRefusal::Selection {
                    helper: helper.clone(),
                    detail: "source injection was removed from this track, so a trial has no \
                             baseline to compare with"
                        .to_owned(),
                });
            }
            Ok(RunnerHelpers {
                helper: helper.clone(),
                runner: release.clone(),
                serve: ServingHelper::SourceInjection,
                shadow: None,
                fallback: None,
            })
        })
        .collect()
}

/// Writes the files of `pin`'s bundle, opened through `catalog`, under `directory/<helper>`
/// and returns the entry path inside the container.
fn write_bundle(
    admission: &HelperAdmission,
    catalog: &mut Catalog,
    directory: &Path,
    helper: &HelperId,
    pin: &HelperPin,
    execution: &ExecutionId,
) -> Result<String, StartRefusal> {
    let bundle = admission
        .open(catalog, pin, execution, Duration::from_secs(300))
        .map_err(|refusal| StartRefusal::Bundle {
            helper: helper.clone(),
            detail: refusal.to_string(),
        })?;
    let target = directory.join(helper.as_str());
    let write = |detail: std::io::Error| StartRefusal::Bundle {
        helper: helper.clone(),
        detail: format!("{}: {detail}", target.display()),
    };
    std::fs::create_dir_all(&target).map_err(write)?;
    for (file, bytes) in bundle.files() {
        let path = target.join(file.path.as_str());
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(write)?;
        }
        std::fs::write(&path, bytes).map_err(write)?;
    }
    Ok(format!(
        "{HELPERS_TARGET}/{}/{}",
        helper.as_str(),
        bundle.manifest().entry().as_str()
    ))
}

/// The most bytes and files one remote delivery carries (the pod's model run refuses more).
pub(crate) const MAX_REMOTE_BYTES: usize = 32 << 20;
pub(crate) const MAX_REMOTE_FILES: usize = 64;

/// What a remote runner is delivered (G08: the applicable remote delivery consumer, a NeoCloud
/// pod's model run): the selection, and the payload the pod writes under its own helpers
/// directory: `files` (path relative to that directory, base64 bytes, SHA-256), `named` and
/// `shadow` (helper to its entry, relative, and pin) as `YOUGORI_HELPERS` and
/// `YOUGORI_HELPERS_SHADOW` name them locally. `None` when nothing but source injection serves.
pub(crate) struct RemoteDelivery {
    pub(crate) selected: Vec<RunnerHelpers>,
    pub(crate) payload: Option<Value>,
}

/// The payload of `files` with the entries `named` and `shadow`, refused past the bounds.
pub(crate) fn remote_payload(
    files: &[(String, Vec<u8>)],
    named: serde_json::Map<String, Value>,
    shadow: serde_json::Map<String, Value>,
) -> Result<Value, String> {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let total: usize = files.iter().map(|(_, bytes)| bytes.len()).sum();
    if files.len() > MAX_REMOTE_FILES || total > MAX_REMOTE_BYTES {
        return Err(format!(
            "{} helper files of {total} bytes are more than a remote delivery carries \
             ({MAX_REMOTE_FILES} files, {MAX_REMOTE_BYTES} bytes)",
            files.len()
        ));
    }
    let files: Vec<Value> = files
        .iter()
        .map(|(path, bytes)| {
            json!({
                "path": path,
                "data": base64::engine::general_purpose::STANDARD.encode(bytes),
                "sha256": hex::encode(Sha256::digest(bytes)),
            })
        })
        .collect();
    Ok(json!({ "files": files, "named": named, "shadow": shadow }))
}

/// Selects and opens the helpers of a remote runner started from `environment` (as
/// [`serve`] does for a local one) and returns its delivery; nothing is written here.
pub(crate) fn remote_delivery(
    environment: &BTreeMap<String, String>,
) -> Result<RemoteDelivery, StartRefusal> {
    let release =
        match release_of(environment).map_err(|detail| StartRefusal::Release { detail })? {
            Ok(release) => release,
            Err(_) => {
                return Ok(RemoteDelivery {
                    selected: Vec::new(),
                    payload: None,
                })
            }
        };
    let helpers = helpers_of(environment);
    let state = state();
    let State::Open { journal, .. } = &*state else {
        return Err(StartRefusal::JournalUnavailable {
            detail: unavailable_detail(&state),
        });
    };
    let selected = select_in(journal, &release, &helpers, opted_in(environment))?;
    drop(state);
    let bundles: Vec<(&HelperId, &HelperPin, bool)> = selected
        .iter()
        .flat_map(|selection| {
            let serving = match &selection.serve {
                ServingHelper::Bundle { pin } => Some((&selection.helper, pin, false)),
                ServingHelper::SourceInjection => None,
            };
            serving.into_iter().chain(
                selection
                    .shadow
                    .as_ref()
                    .map(|pin| (&selection.helper, pin, true)),
            )
        })
        .collect();
    if bundles.is_empty() {
        return Ok(RemoteDelivery {
            selected,
            payload: None,
        });
    }
    let admission = admission().map_err(|detail| StartRefusal::Bundle {
        helper: bundles[0].0.clone(),
        detail,
    })?;
    let execution = ExecutionId::generate();
    let mut files = Vec::new();
    let mut named = serde_json::Map::new();
    let mut shadow = serde_json::Map::new();
    for (helper, pin, shadowed) in bundles {
        let bundle = with_catalog(|catalog| {
            admission.open(catalog, pin, &execution, Duration::from_secs(300))
        })
        .map_err(|detail| StartRefusal::Bundle {
            helper: helper.clone(),
            detail,
        })?
        .map_err(|refusal| StartRefusal::Bundle {
            helper: helper.clone(),
            detail: refusal.to_string(),
        })?;
        let base = if shadowed {
            format!("shadow/{}", helper.as_str())
        } else {
            helper.as_str().to_owned()
        };
        for (file, bytes) in bundle.files() {
            files.push((format!("{base}/{}", file.path.as_str()), bytes.to_vec()));
        }
        let record = json!({
            "entry": format!("{base}/{}", bundle.manifest().entry().as_str()),
            "pin": pin.id().to_string(),
        });
        if shadowed {
            shadow.insert(helper.as_str().to_owned(), record);
        } else {
            named.insert(helper.as_str().to_owned(), record);
        }
    }
    if !shadow.is_empty() {
        files.push((
            SHADOW_RUNNER.to_owned(),
            include_str!("helper_shadow.py")
                .replace("\r\n", "\n")
                .into_bytes(),
        ));
    }
    let payload = remote_payload(&files, named, shadow).map_err(|detail| StartRefusal::Bundle {
        helper: helpers
            .first()
            .cloned()
            .unwrap_or_else(|| HelperId::new("model-server").expect("fixed helper id")),
        detail,
    })?;
    Ok(RemoteDelivery {
        selected,
        payload: Some(payload),
    })
}

/// Serves the helpers the rollout selects for a runner started from `environment`: bundles
/// are opened through the catalog and written under a fresh directory in the served root,
/// each named in [`HELPERS_OPTION`] (shadows in [`SHADOW_OPTION`]); a model server served from
/// a bundle becomes the container command. Nothing is recorded yet ([`record_start`] does, once
/// the runner exists). A workload that runs no model backend is served nothing.
pub(crate) fn serve(environment: &BTreeMap<String, String>) -> Result<Served, StartRefusal> {
    let release =
        match release_of(environment).map_err(|detail| StartRefusal::Release { detail })? {
            Ok(release) => release,
            Err(_) => return Ok(Served::default()),
        };
    let helpers = helpers_of(environment);
    let opted_in = opted_in(environment);
    let state = state();
    let State::Open {
        journal,
        served_root,
        ..
    } = &*state
    else {
        return Err(StartRefusal::JournalUnavailable {
            detail: unavailable_detail(&state),
        });
    };
    let selected = if environment
        .get(trial::TRIAL_OPTION)
        .is_some_and(|value| value == trial::TRIAL_BASELINE)
    {
        baseline_in(journal, &release, &helpers)?
    } else {
        select_in(journal, &release, &helpers, opted_in)?
    };
    let served_root = served_root.clone();
    drop(state);
    let mut served = Served {
        selected: selected.clone(),
        ..Served::default()
    };
    let bundles: Vec<(&HelperId, &HelperPin, bool)> = selected
        .iter()
        .flat_map(|selection| {
            let serving = match &selection.serve {
                ServingHelper::Bundle { pin } => Some((&selection.helper, pin, false)),
                ServingHelper::SourceInjection => None,
            };
            serving.into_iter().chain(
                selection
                    .shadow
                    .as_ref()
                    .map(|pin| (&selection.helper, pin, true)),
            )
        })
        .collect();
    if bundles.is_empty() {
        return Ok(served);
    }
    let admission = admission().map_err(|detail| StartRefusal::Bundle {
        helper: bundles[0].0.clone(),
        detail,
    })?;
    let directory = served_root.join(uuid::Uuid::new_v4().simple().to_string());
    let execution = ExecutionId::generate();
    let mut named = serde_json::Map::new();
    let mut shadows = serde_json::Map::new();
    for (helper, pin, shadow) in bundles {
        let base = if shadow {
            directory.join("shadow")
        } else {
            directory.clone()
        };
        let entry = with_catalog(|catalog| {
            write_bundle(&admission, catalog, &base, helper, pin, &execution)
        })
        .map_err(|detail| StartRefusal::Bundle {
            helper: helper.clone(),
            detail,
        })??;
        let entry = if shadow {
            entry.replacen(HELPERS_TARGET, &format!("{HELPERS_TARGET}/shadow"), 1)
        } else {
            entry
        };
        let record = json!({ "entry": entry, "pin": pin.id().to_string() });
        if shadow {
            shadows.insert(helper.as_str().to_owned(), record);
        } else {
            if helper.as_str() == "model-server" {
                served.command = Some(format!("exec python3 -u {entry}"));
            }
            named.insert(helper.as_str().to_owned(), record);
        }
    }
    if !named.is_empty() {
        served
            .variables
            .push((HELPERS_OPTION, Value::Object(named).to_string()));
    }
    if !shadows.is_empty() {
        // The shadow runner the model server executes for its candidates: this engine's own
        // source, written beside them and bound read-only with them, so the source every
        // runner carries in its workload does not grow for what only a shadowing runner needs.
        write_shadow_runner(&directory).map_err(|detail| StartRefusal::Bundle {
            helper: bundles_helper(&shadows),
            detail,
        })?;
        served
            .variables
            .push((SHADOW_OPTION, Value::Object(shadows).to_string()));
    }
    served.directory = Some(directory);
    Ok(served)
}

/// Records what the runner of environment `environment_id`, started from `environment` with
/// `selected` served, runs: a start already recorded with the same selection appends nothing,
/// and one recorded with another selection (a release the engine never saw end) is ended
/// first.
pub(crate) fn record_start(
    environment_id: &str,
    environment: &BTreeMap<String, String>,
    selected: Vec<RunnerHelpers>,
) -> Result<Start, StartRefusal> {
    let release =
        match release_of(environment).map_err(|detail| StartRefusal::Release { detail })? {
            Ok(release) => release,
            Err(skipped) => return Ok(Start::Skipped(skipped)),
        };
    let instance = RunnerInstance::new(environment_id).map_err(|error| StartRefusal::Instance {
        detail: error.to_string(),
    })?;
    let mut state = state();
    let State::Open {
        journal, started, ..
    } = &mut *state
    else {
        return Err(StartRefusal::JournalUnavailable {
            detail: unavailable_detail(&state),
        });
    };
    let start = record_in(journal, instance, release, selected)?;
    started.insert(environment_id.to_owned(), std::time::Instant::now());
    Ok(start)
}

/// Records `selected` for `instance` in `journal` (see [`record_start`]).
fn record_in(
    journal: &mut RolloutJournal,
    instance: RunnerInstance,
    release: BackendRelease,
    selected: Vec<RunnerHelpers>,
) -> Result<Start, StartRefusal> {
    if let Some(running) = journal.runners().get(&instance) {
        let same = running.release == release
            && running.helpers.len() == selected.len()
            && selected
                .iter()
                .all(|selection| running.helpers.get(&selection.helper) == Some(selection));
        if same {
            return Ok(Start::Unchanged(selected));
        }
        journal
            .stop_runner(&instance)
            .map_err(|error| StartRefusal::Journal {
                detail: format!("{error:?}"),
            })?;
    }
    journal
        .start_runner(instance, release, selected.clone())
        .map_err(|error| StartRefusal::Journal {
            detail: format!("{error:?}"),
        })?;
    Ok(Start::Recorded(selected))
}

/// Removes the served directory a workload's options bind at [`HELPERS_TARGET`], when it is
/// under the served root: the environment is being deleted. `Ok(false)` when none is bound.
pub(crate) fn release_served(options: &yougori_cli::workload::Options) -> Result<bool, String> {
    let Some(bind) = options
        .binds
        .iter()
        .find(|bind| bind.target == HELPERS_TARGET)
    else {
        return Ok(false);
    };
    let source = PathBuf::from(&bind.source);
    let root = {
        let state = state();
        match &*state {
            State::Open { served_root, .. } => served_root.clone(),
            _ => return Ok(false),
        }
    };
    if !source.starts_with(&root) {
        return Err(format!(
            "{} is not under the served helpers root; left alone",
            source.display()
        ));
    }
    match remove_served(&source) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("{}: {error}", source.display())),
    }
}

/// Removes a served directory, retrying briefly: on Windows the folder server of a runner that
/// just stopped can still hold it open for a moment (the fourth rollout run of 31 October left
/// one behind, empty, on a sharing violation).
fn remove_served(directory: &Path) -> std::io::Result<()> {
    let mut attempt = 0;
    loop {
        match std::fs::remove_dir_all(directory) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound && attempt < 5 => {
                attempt += 1;
                std::thread::sleep(Duration::from_millis(300));
            }
            other => return other,
        }
    }
}

/// Removes a served directory an environment no longer binds once its share server let it
/// go: a restarted runner's previous serving stays open in its workload's share server until
/// the start serves the new binds (Windows refuses removing an open directory), so the
/// removal is retried for two minutes in the background; what is left after that, the
/// scheduler's sweep takes.
pub(crate) fn remove_served_later(directory: PathBuf) {
    tauri::async_runtime::spawn(async move {
        for _ in 0..24 {
            let target = directory.clone();
            let removed =
                tokio::task::spawn_blocking(move || match std::fs::remove_dir_all(&target) {
                    Ok(()) => true,
                    Err(error) => error.kind() == std::io::ErrorKind::NotFound,
                })
                .await
                .unwrap_or(false);
            if removed {
                return;
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });
}

/// The served directories under `root` that `bound` (every environment's helpers bind source)
/// does not name: left behind when a removal failed or an environment was lost.
fn orphaned_served(
    root: &Path,
    bound: &BTreeSet<PathBuf>,
    older_than: Option<Duration>,
) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    let old_enough = |path: &Path| {
        older_than.is_none_or(|age| {
            std::fs::metadata(path)
                .and_then(|metadata| metadata.modified())
                .ok()
                .and_then(|modified| modified.elapsed().ok())
                .is_some_and(|elapsed| elapsed >= age)
        })
    };
    let mut orphans: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .filter(|path| {
            let canonical = path.canonicalize().unwrap_or_else(|_| path.clone());
            !bound.contains(path) && !bound.contains(&canonical)
        })
        .filter(|path| old_enough(path))
        .collect();
    orphans.sort();
    orphans
}

/// Sweeps the served directories no environment binds (`bound`: every environment's helpers
/// bind source, as its options record it): at the engine's start, and from the scheduler with
/// `older_than` set, so a directory a start is writing before its options bind it is never
/// taken. Returns what was removed and what could not be (a directory a share server still
/// holds open is left for a later sweep).
pub(crate) fn sweep_served(
    bound: &BTreeSet<PathBuf>,
    older_than: Option<Duration>,
) -> (Vec<PathBuf>, Vec<String>) {
    let root = {
        let state = state();
        match &*state {
            State::Open { served_root, .. } => served_root.clone(),
            _ => return (Vec::new(), Vec::new()),
        }
    };
    let bound: BTreeSet<PathBuf> = bound
        .iter()
        .flat_map(|path| {
            [
                path.clone(),
                path.canonicalize().unwrap_or_else(|_| path.clone()),
            ]
        })
        .collect();
    let (mut removed, mut failures) = (Vec::new(), Vec::new());
    for orphan in orphaned_served(&root, &bound, older_than) {
        match remove_served(&orphan) {
            Ok(()) => removed.push(orphan),
            Err(error) => failures.push(format!("{}: {error}", orphan.display())),
        }
    }
    (removed, failures)
}

fn unavailable_detail(state: &State) -> String {
    match state {
        State::NotOpened => "the engine did not open it at start".to_owned(),
        State::Refused { error, .. } => error.clone(),
        State::Open { .. } => String::new(),
    }
}

/// Whether `refusal` must keep the runner from starting: a selection the rollout refused
/// or one this build cannot load. Everything else is bookkeeping the start proceeds without.
pub(crate) fn blocks_start(refusal: &StartRefusal) -> bool {
    matches!(
        refusal,
        StartRefusal::Selection { .. } | StartRefusal::Bundle { .. }
    )
}

/// Records the end of every recorded runner whose environment `alive` does not name:
/// stopped, failed or gone, as the engine itself observed through the platform store.
/// Returns the runners ended, each with its outcome. Nothing without an open journal.
pub(crate) fn reconcile_runners(alive: &dyn Fn(&str) -> bool) -> Vec<(String, Result<(), String>)> {
    let mut state = state();
    let State::Open {
        journal, started, ..
    } = &mut *state
    else {
        return Vec::new();
    };
    let ended = ended_runners(
        journal.runners().running().map(|start| &start.runner),
        started,
        std::time::Instant::now(),
        alive,
    );
    ended
        .into_iter()
        .map(|runner| {
            started.remove(runner.as_str());
            let outcome = journal
                .stop_runner(&runner)
                .map(|_| ())
                .map_err(|error| format!("{error:?}"));
            (runner.as_str().to_owned(), outcome)
        })
        .collect()
}

/// The recorded runners that have ended: those `alive` does not name, except one whose start
/// was recorded less than [`START_GRACE`] before `now` (its environment is coming up).
fn ended_runners<'a>(
    running: impl Iterator<Item = &'a RunnerInstance>,
    started: &BTreeMap<String, std::time::Instant>,
    now: std::time::Instant,
    alive: &dyn Fn(&str) -> bool,
) -> Vec<RunnerInstance> {
    running
        .filter(|runner| !alive(runner.as_str()))
        .filter(|runner| {
            started
                .get(runner.as_str())
                .is_none_or(|at| now.saturating_duration_since(*at) >= START_GRACE)
        })
        .cloned()
        .collect()
}

/// The `model_helpers` method's status: the journal's state and what it restored, this
/// build's loader (ABI 1.0), the admitted pins and their kept attestations, every running
/// runner's helpers, the tracks' records and what G08 leaves open.
pub(crate) fn status() -> Value {
    let state = state();
    let (journal_view, runners, records) = match &*state {
        State::NotOpened => (json!({ "state": "not_opened" }), Vec::new(), Vec::new()),
        State::Refused { directory, error } => (
            json!({ "state": "refused", "directory": directory.display().to_string(), "error": error }),
            Vec::new(),
            Vec::new(),
        ),
        State::Open {
            directory,
            journal,
            opened,
            ..
        } => (
            json!({
                "state": "open",
                "directory": directory.display().to_string(),
                "stream": STREAM,
                "owner": OWNER,
                "replay": opened.view(),
            }),
            journal.runners().running().map(runner_view).collect(),
            journal
                .rollouts()
                .records()
                .iter()
                .map(|record| serde_json::to_value(record).unwrap_or(Value::Null))
                .collect(),
        ),
    };
    let admitted: Vec<Value> = match &*state {
        State::Open { admitted, .. } => admitted.values().map(pin_view).collect(),
        _ => Vec::new(),
    };
    // Every track as its owner sees it: the default, the candidate and its stage, the
    // rollback targets, the failed pins and whether source injection was removed.
    let tracks: Vec<Value> = match &*state {
        State::Open { journal, .. } => HELPERS
            .iter()
            .filter_map(|(helper, _)| HelperId::new(*helper).ok())
            .flat_map(|helper| {
                [Backend::Transformers, Backend::Vllm, Backend::LlamaCpp]
                    .into_iter()
                    .filter_map(move |backend| {
                        journal.rollouts().track(&helper, backend).map(|view| {
                            json!({ "helper": helper.as_str(), "backend": backend.tag(), "track": view })
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .collect(),
        _ => Vec::new(),
    };
    let trials = match &*state {
        State::Open { directory, .. } => trial::listing(directory),
        _ => Vec::new(),
    };
    let served_root = match &*state {
        State::Open { served_root, .. } => Some(served_root.display().to_string()),
        _ => None,
    };
    let attestations = match &*state {
        State::Open {
            attestations,
            attestation_problems,
            ..
        } => json!({
            "kept": attestations.len(),
            "problems": attestation_problems,
        }),
        _ => Value::Null,
    };
    json!({
        "attestations": attestations,
        "journal": journal_view,
        "loader": {
            "provided": [format!("{}.{}", LOADER_ABI.major, LOADER_ABI.minor)],
            "target": HELPERS_TARGET,
            "servedRoot": served_root,
            "detail": format!("This engine's runner loads a pinned bundle's entry file from {HELPERS_TARGET}, bound read-only from the served root and named in {HELPERS_OPTION}; a model server served from a bundle is the container command. Bundles are admitted under the trust roots in force (YOUGORI_TRUST_ROOTS, class model_helper) and proposed onto a track; new runners take a track's default, and its opt-in candidate when {OPT_IN_OPTION} is set. A trial (trial) runs the candidate at its stage on a stopped model the owner designates, measured beside what serves (the runner runs a shadow candidate's decisions and compares them; an opt-in or default candidate is compared with a baseline start), keeps its CORE-08 records and summary under trials/ beside the journal and records its verdict; candidates are promoted on a passed trial (promote), source injection removed on a passed default trial (remove-source-injection), outside evidence recorded (record, never promoting) and pins withdrawn (withdraw); the admitted bundles' attestations are kept beside the journal."),
        },
        "admitted": admitted,
        "tracks": tracks,
        "trials": trials,
        "helpers": HELPERS.iter().map(|(helper, variable)| json!({ "helper": helper, "source": variable })).collect::<Vec<_>>(),
        "runners": runners,
        "records": records,
    })
}

fn runner_view(start: &RunnerStart) -> Value {
    json!({
        "runner": start.runner.as_str(),
        "release": start.release.to_string(),
        "helpers": start.helpers.values().map(describe).collect::<Vec<_>>(),
    })
}

/// The `model_helpers` automation method: `status` (the default), `admit` (`bundle` and
/// `attestation` paths), `propose` (`pin` and `backend`), `record` (`pin`, `backend`,
/// `stage`, `verdict`, `evidence` and a failure's `reason`), `promote` (`helper`,
/// `backend`, `evidence`), `remove-source-injection` (`helper`, `backend`, `evidence`,
/// `reason`) and `withdraw` (`pin`, `reason`). `opt-in` needs the runtime and is dispatched
/// by `model_runner::helpers_dispatch`.
pub(crate) fn dispatch(action: Option<String>, params: &Value) -> Result<Value, String> {
    let text = |name: &str| -> Result<String, String> {
        params[name]
            .as_str()
            .filter(|value| !value.trim().is_empty())
            .map(str::to_owned)
            .ok_or_else(|| {
                format!(
                    "model_helpers {}: {name} is required",
                    action.as_deref().unwrap_or("")
                )
            })
    };
    match action.as_deref().unwrap_or("status") {
        "status" => Ok(status()),
        "admit" => {
            let (bundle, attestation) = (text("bundle")?, text("attestation")?);
            let mut result = admit(Path::new(&bundle), Path::new(&attestation))?;
            result["status"] = status();
            Ok(result)
        }
        "propose" => {
            let (pin, backend) = (text("pin")?, text("backend")?);
            let mut result = propose(&pin, &backend)?;
            result["status"] = status();
            Ok(result)
        }
        "record" => {
            let (pin, backend, stage, verdict, evidence) = (
                text("pin")?,
                text("backend")?,
                text("stage")?,
                text("verdict")?,
                text("evidence")?,
            );
            let reason = params["reason"].as_str();
            let mut result = record(
                &pin,
                &backend,
                &stage,
                &verdict,
                reason,
                Path::new(&evidence),
            )?;
            result["status"] = status();
            Ok(result)
        }
        "promote" => {
            let (helper, backend, trial) = (text("helper")?, text("backend")?, text("trial")?);
            let mut result = promote(&helper, &backend, &trial)?;
            result["status"] = status();
            Ok(result)
        }
        "remove-source-injection" | "remove_source_injection" => {
            let (helper, backend, trial, reason) = (
                text("helper")?,
                text("backend")?,
                text("trial")?,
                text("reason")?,
            );
            let mut result = remove_source_injection(&helper, &backend, &trial, &reason)?;
            result["status"] = status();
            Ok(result)
        }
        "withdraw" => {
            let (pin, reason) = (text("pin")?, text("reason")?);
            let mut result = withdraw(&pin, &reason)?;
            result["status"] = status();
            Ok(result)
        }
        other => Err(format!(
            "Unknown model_helpers action '{other}'. Use status, admit, propose, trial, record, \
             promote, remove-source-injection, withdraw or opt-in."
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_remote_delivery_carries_every_file_with_its_digest_and_refuses_past_its_bounds() {
        use base64::Engine;
        let files = vec![
            (
                "gpu-optimizer/gpu_optimizer.py".to_owned(),
                b"A = 1\n".to_vec(),
            ),
            (
                "shadow/gpu-optimizer/gpu_optimizer.py".to_owned(),
                b"A = 2\n".to_vec(),
            ),
        ];
        let mut named = serde_json::Map::new();
        named.insert(
            "gpu-optimizer".into(),
            json!({"entry": "gpu-optimizer/gpu_optimizer.py", "pin": "a".repeat(64)}),
        );
        let payload = remote_payload(&files, named, serde_json::Map::new()).unwrap();
        assert_eq!(payload["files"].as_array().unwrap().len(), 2);
        let first = &payload["files"][0];
        assert_eq!(first["path"], "gpu-optimizer/gpu_optimizer.py");
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(first["data"].as_str().unwrap())
                .unwrap(),
            b"A = 1\n"
        );
        {
            use sha2::{Digest, Sha256};
            assert_eq!(first["sha256"], hex::encode(Sha256::digest(b"A = 1\n")));
        }
        assert_eq!(payload["named"]["gpu-optimizer"]["pin"], "a".repeat(64));
        // Past the file count or the byte budget nothing is delivered.
        let many: Vec<(String, Vec<u8>)> = (0..=MAX_REMOTE_FILES)
            .map(|index| (format!("h/{index}.py"), vec![b'x']))
            .collect();
        assert!(remote_payload(&many, serde_json::Map::new(), serde_json::Map::new()).is_err());
        let large = vec![("h/big.bin".to_owned(), vec![0u8; MAX_REMOTE_BYTES + 1])];
        assert!(
            remote_payload(&large, serde_json::Map::new(), serde_json::Map::new())
                .unwrap_err()
                .contains("more than a remote delivery carries")
        );
    }

    #[test]
    fn the_shadow_runner_is_written_beside_the_candidates_where_the_server_reads_it() {
        let dir = tempfile::tempdir().unwrap();
        write_shadow_runner(dir.path()).unwrap();
        let written = std::fs::read_to_string(dir.path().join("shadow/yougori-shadow.py")).unwrap();
        assert_eq!(
            written,
            include_str!("helper_shadow.py").replace("\r\n", "\n")
        );
        assert!(written.contains("\nattach = shadow_attach\n"));
        assert!(written.contains("\nsnapshot = shadow_snapshot\n"));
        // The model server reads it at the same place under its read-only helpers bind.
        assert!(include_str!("../model_server.py")
            .contains(&format!("SHADOW_RUNNER = \"{SHADOW_RUNNER}\"")));
    }

    fn transformers_environment() -> BTreeMap<String, String> {
        BTreeMap::from([
            (
                "YOUGORI_MODEL".to_owned(),
                "Qwen/Qwen2.5-0.5B-Instruct".to_owned(),
            ),
            ("YOUGORI_MODEL_SERVER_SOURCE".to_owned(), "...".to_owned()),
            ("YOUGORI_GPU_SOURCE".to_owned(), "...".to_owned()),
            ("YOUGORI_PUBLISHER_SOURCE".to_owned(), "...".to_owned()),
        ])
    }

    #[test]
    fn a_runners_helpers_are_the_sources_its_workload_carries_and_its_release_is_the_pinned_one() {
        let environment = transformers_environment();
        let helpers: Vec<String> = helpers_of(&environment)
            .iter()
            .map(|helper| helper.as_str().to_owned())
            .collect();
        assert_eq!(
            helpers,
            ["model-server", "gpu-optimizer", "publisher-routes"]
        );
        let release = release_of(&environment).unwrap().unwrap();
        assert_eq!(release.backend, Backend::Transformers);
        assert_eq!(
            release,
            *super::super::optimizer::pinned_transformers_release().unwrap()
        );

        let mut gguf = environment.clone();
        gguf.insert("YOUGORI_MODEL_FORMAT".into(), "gguf".into());
        gguf.insert("YOUGORI_MODEL_CPU".into(), "1".into());
        gguf.insert("YOUGORI_REGISTRY_SOURCE".into(), "...".into());
        let release = release_of(&gguf).unwrap().unwrap();
        assert_eq!(
            (release.backend, release.version.as_str()),
            (Backend::LlamaCpp, LLAMA_CPP_RELEASE)
        );
        assert_eq!(helpers_of(&gguf).len(), 4);
        // The build the preflight names as the GGUF runner's dependency is this one.
        let gguf_check = super::super::preflight::inspect_gguf(
            "x/y",
            &json!({"sha": "b".repeat(40), "pipeline_tag": "text-generation"}),
            "Q4_K_M",
            &[json!({"rfilename": "x-Q4_K_M.gguf", "lfs": {"size": 5, "sha256": "a".repeat(64)}})],
        );
        assert_eq!(gguf_check["dependencies"]["llamaCpp"], LLAMA_CPP_RELEASE);

        let mut vllm = environment.clone();
        vllm.insert("YOUGORI_MODEL_FORMAT".into(), "vllm".into());
        assert_eq!(release_of(&vllm).unwrap().unwrap().backend, Backend::Vllm);

        let mut source_only = environment.clone();
        source_only.insert("YOUGORI_MODEL_FORMAT".into(), "source".into());
        assert_eq!(release_of(&source_only).unwrap(), Err(Skipped::SourceOnly));
        assert_eq!(
            release_of(&BTreeMap::new()).unwrap(),
            Err(Skipped::NotAModelRunner)
        );
    }

    #[test]
    fn every_runner_start_and_stop_is_recorded_as_source_injection_and_survives_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let directory = dir.path().join(DIRECTORY);
        let (mut journal, report) = open_journal(&directory).unwrap();
        assert!(report.opened.created);
        assert_eq!(report.records, 0);
        let environment = transformers_environment();
        let release = release_of(&environment).unwrap().unwrap();
        let helpers = helpers_of(&environment);
        let instance = RunnerInstance::new("env-model-a").unwrap();
        let start_in = |journal: &mut RolloutJournal,
                        instance: RunnerInstance,
                        release: BackendRelease,
                        helpers: &[HelperId]| {
            let selected = select_in(journal, &release, helpers, false)?;
            record_in(journal, instance, release, selected)
        };

        let started = start_in(&mut journal, instance.clone(), release.clone(), &helpers).unwrap();
        let Start::Recorded(selected) = &started else {
            panic!("{started:?}")
        };
        assert_eq!(selected.len(), 3);
        assert!(selected.iter().all(
            |selection| selection.serve == ServingHelper::SourceInjection
                && selection.shadow.is_none()
                && selection.fallback.is_none()
                && selection.runner == release
        ));
        let view = started.view();
        assert_eq!(view["state"], "recorded");
        assert_eq!(view["loader"], "1.0");
        assert_eq!(view["helpers"][1]["helper"], "gpu-optimizer");
        assert_eq!(view["helpers"][1]["serve"], "source_injection");
        // The same start again appends nothing; a start with other helpers ends the old one.
        assert!(matches!(
            start_in(&mut journal, instance.clone(), release.clone(), &helpers).unwrap(),
            Start::Unchanged(_)
        ));
        let fewer = &helpers[..2];
        assert!(matches!(
            start_in(&mut journal, instance.clone(), release.clone(), fewer).unwrap(),
            Start::Recorded(_)
        ));
        assert_eq!(journal.runners().get(&instance).unwrap().helpers.len(), 2);
        let other = RunnerInstance::new("env-model-b").unwrap();
        start_in(&mut journal, other.clone(), release.clone(), &helpers).unwrap();
        assert_eq!(journal.runners().running().count(), 2);

        // A restart restores exactly the running runners' pins.
        drop(journal);
        let (mut journal, report) = open_journal(&directory).unwrap();
        assert!(!report.opened.created);
        assert!(report.gaps.is_empty() && report.fell_back.is_empty());
        let restored: Vec<&str> = journal
            .runners()
            .running()
            .map(|start| start.runner.as_str())
            .collect();
        assert_eq!(restored, ["env-model-a", "env-model-b"]);
        assert_eq!(journal.runners().get(&instance).unwrap().helpers.len(), 2);
        assert_eq!(journal.runners().get(&instance).unwrap().release, release);

        // The engine saw model A end: its pin is stopped; a stop that was never started is none.
        assert!(journal.stop_runner(&instance).unwrap().is_some());
        assert!(journal.stop_runner(&instance).unwrap().is_none());
        assert_eq!(journal.runners().running().count(), 1);
        drop(journal);
        let (journal, _) = open_journal(&directory).unwrap();
        assert_eq!(
            journal
                .runners()
                .running()
                .map(|start| start.runner.as_str())
                .collect::<Vec<_>>(),
            ["env-model-b"]
        );
    }

    #[test]
    fn the_host_loader_provides_abi_1_0_and_refuses_a_pin_of_another_major() {
        use crate::foundation::catalog::{ArtifactClass, ObjectId, Scope};
        use crate::foundation::ids::ContentKey;
        use crate::foundation::signing::Ed25519PublicKey;
        use crate::model_memory::helpers::{HelperAbiRefusal, HelperVersion};
        let bundle = ContentKey::of(b"bundle");
        let pin = |abi: HelperAbi| HelperPin {
            helper: HelperId::new("gpu-optimizer").unwrap(),
            version: HelperVersion::parse("1.2.0").unwrap(),
            abi,
            runners: std::collections::BTreeSet::new(),
            object: ObjectId::new(&Scope::Host, ArtifactClass::ModelHelper, bundle),
            bundle,
            length_bytes: 6,
            publisher: Ed25519PublicKey::from_bytes(&[7u8; 32])
                .unwrap()
                .publisher_id(),
        };
        assert!(HostLoader.check(&pin(HelperAbi::new(1, 0))).is_ok());
        let refused = HostLoader.check(&pin(HelperAbi::new(2, 0))).unwrap_err();
        assert!(
            matches!(refused, PinRefusal::IncompatibleAbi { refusal: HelperAbiRefusal::MajorNotProvided { ref provided, .. } } if *provided == vec![LOADER_ABI]),
            "{refused:?}"
        );
        // A bookkeeping refusal never blocks a start; a refused selection or an unopenable
        // bundle does.
        assert!(!blocks_start(&StartRefusal::JournalUnavailable {
            detail: String::new()
        }));
        assert!(blocks_start(&StartRefusal::Bundle {
            helper: HelperId::new("x").unwrap(),
            detail: String::new()
        }));
        assert!(blocks_start(&StartRefusal::Selection {
            helper: HelperId::new("x").unwrap(),
            detail: String::new()
        }));
        let status = status();
        assert_eq!(status["loader"]["provided"], json!(["1.0"]));
        assert_eq!(status["helpers"].as_array().unwrap().len(), HELPERS.len());
    }
}

#[cfg(test)]
mod loader_tests {
    use super::*;
    use crate::catalog_service::{open as open_catalog, Settings};
    use crate::foundation::ids::{ManualClock, MonotonicTime};
    use crate::foundation::signing::{Ed25519PublicKey, TrustRootLocation, TrustRootService};
    use crate::model_memory::helpers::{bundle_statement, HelperBundle, HelperPath, HelperVersion};
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn pair(seed: u8) -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap()
    }

    fn public(seed: u8) -> Ed25519PublicKey {
        Ed25519PublicKey::from_bytes(pair(seed).public_key().as_ref()).unwrap()
    }

    /// A trust-root file with one key for `model_helper`, valid through 2027.
    fn roots_file(dir: &Path, seed: u8) -> PathBuf {
        let path = dir.join("roots.json");
        let document = json!({"format": 1, "keys": [{
            "id": "helpers-test", "algorithm": "ed25519", "public_key": public(seed).to_hex(),
            "classes": ["model_helper"], "valid_from": "2026-01-01T00:00:00Z", "valid_until": "2028-01-01T00:00:00Z",
        }]});
        std::fs::write(&path, document.to_string()).unwrap();
        path
    }

    fn bundle(entry_source: &[u8]) -> Vec<u8> {
        let release = super::super::optimizer::pinned_transformers_release()
            .unwrap()
            .clone();
        HelperBundle::build(
            HelperId::new("gpu-optimizer").unwrap(),
            HelperVersion::parse("1.0.0").unwrap(),
            LOADER_ABI,
            vec![release],
            HelperPath::new("gpu_optimizer.py").unwrap(),
            vec![(
                HelperPath::new("gpu_optimizer.py").unwrap(),
                entry_source.to_vec(),
            )],
        )
        .unwrap()
        .encode()
        .unwrap()
    }

    fn signed(seed: u8, bytes: &[u8]) -> HelperSignature {
        let publisher = public(seed).publisher_id();
        let statement = bundle_statement(&publisher, bytes);
        HelperSignature {
            publisher,
            signature: pair(seed).sign(statement.as_bytes()).as_ref().to_vec(),
        }
    }

    /// `pin`'s attestation verified under the test roots of `dir`.
    fn component_under(
        dir: &Path,
        pin: &HelperPin,
        signature: &HelperSignature,
    ) -> SignedComponent {
        let roots = crate::foundation::signing::TrustRoots::from_json(
            &std::fs::read_to_string(dir.join("roots.json")).unwrap(),
        )
        .unwrap();
        SignedComponent::check(
            &roots,
            ArtifactClass::ModelHelper,
            &signature.publisher,
            pin_statement(pin),
            &signature.signature,
            crate::foundation::signing::TrustCalendar::now(&SystemCalendar),
        )
    }

    /// An evidence file holding the CORE-08 golden run record, run in an authorized
    /// disposable environment when `measured`, else on the fake time-controlled runner.
    fn evidence_file(dir: &Path, measured: bool) -> PathBuf {
        use crate::foundation::report::{RunSubstrate, RUN_RECORD_SAMPLE_JSON};
        let mut record: RunRecord = serde_json::from_str(RUN_RECORD_SAMPLE_JSON).unwrap();
        record.substrate = if measured {
            RunSubstrate::AuthorizedDisposable {
                authorization: Label::new("loader-test").unwrap(),
            }
        } else {
            RunSubstrate::FakeTimeControlled
        };
        let path = dir.join(if measured {
            "measured.json"
        } else {
            "simulated.json"
        });
        std::fs::write(
            &path,
            serde_json::to_vec(&json!({ "records": [record] })).unwrap(),
        )
        .unwrap();
        path
    }

    fn offer(bytes: Vec<u8>, signature: HelperSignature) -> HelperOffer {
        HelperOffer {
            bundle: bytes,
            signature: Some(signature),
            operation: OperationId::generate(),
            execution: ExecutionId::generate(),
        }
    }

    /// A temporary catalog opened with the test roots, and the admission under the same roots.
    fn catalog_and_admission(dir: &Path) -> (EngineCatalog, HelperAdmission) {
        let roots = roots_file(dir, 1);
        let mut trust = TrustRootService::open(
            TrustRootLocation::from_setting("YOUGORI_TEST_HELPER_ROOTS", Some(roots.as_os_str())),
            Arc::new(SystemCalendar),
        );
        let catalog = open_catalog(
            &Settings::from_values(
                Some(dir.join("catalog").as_os_str()),
                Some(std::ffi::OsStr::new("1073741824")),
            ),
            &mut trust,
            Arc::new(ManualClock::new(MonotonicTime::from_nanos(1))),
            Arc::new(SystemCalendar),
        );
        let shared = trust.shared().expect("roots in force");
        let admission = HelperAdmission::new(
            HostHelperAbi::single(LOADER_ABI),
            shared,
            Arc::new(SystemCalendar),
        );
        (catalog, admission)
    }

    #[test]
    fn a_signed_bundle_is_admitted_proposed_selected_for_an_opted_in_runner_and_written_with_its_entry(
    ) {
        let dir = tempfile::tempdir().unwrap();
        let (catalog, admission) = catalog_and_admission(dir.path());
        let EngineCatalog::Open { service, .. } = &catalog else {
            panic!("catalog not open")
        };
        let bytes = bundle(b"GPU_OPTIMIZER_FROM_BUNDLE = True\n");
        let admitted = admission
            .admit(
                &mut service.catalog(),
                offer(bytes.clone(), signed(1, &bytes)),
                &mut Uninterrupted,
            )
            .unwrap();
        assert!(admitted.newly_published);
        assert_eq!(admitted.pin.helper.as_str(), "gpu-optimizer");
        assert!(HostLoader.check(&admitted.pin).is_ok());
        // The same bundle again is the same pin, already published.
        let again = admission
            .admit(
                &mut service.catalog(),
                offer(bytes.clone(), signed(1, &bytes)),
                &mut Uninterrupted,
            )
            .unwrap();
        assert!(!again.newly_published && again.pin == admitted.pin);

        // Proposed onto the Transformers track, the pin shadows every runner, opted in or
        // not: shadow never serves.
        let (mut journal, _) = open_journal(&dir.path().join("journal")).unwrap();
        journal
            .propose(admitted.pin.clone(), Backend::Transformers, &HostLoader)
            .unwrap();
        let release = super::super::optimizer::pinned_transformers_release()
            .unwrap()
            .clone();
        let helpers = [
            HelperId::new("gpu-optimizer").unwrap(),
            HelperId::new("model-server").unwrap(),
        ];
        let default = select_in(&journal, &release, &helpers, false).unwrap();
        assert!(matches!(default[0].serve, ServingHelper::SourceInjection));
        assert_eq!(default[0].shadow.as_ref(), Some(&admitted.pin));
        assert!(
            matches!(default[1].serve, ServingHelper::SourceInjection)
                && default[1].shadow.is_none()
        );
        let opted = select_in(&journal, &release, &helpers, true).unwrap();
        assert!(
            matches!(opted[0].serve, ServingHelper::SourceInjection)
                && opted[0].shadow.as_ref() == Some(&admitted.pin)
        );

        // A measured passing shadow trial, whose signed component is the bundle's
        // attestation verified under the roots, promotes the candidate to opt-in; now the
        // opted-in runner is served the bundle and the default one still shadows it.
        let signature = signed(1, &bytes);
        let component = component_under(dir.path(), &admitted.pin, &signature);
        assert!(component.is_verified(), "{component:?}");
        let measured = evidence_from(&evidence_file(dir.path(), true)).unwrap();
        assert!(measured.yougori_evidence().is_ok());
        let outcome = record_trial(
            &mut journal,
            &admitted.pin,
            release.clone(),
            RolloutStage::Shadow,
            TrialVerdict::Passed,
            measured.clone(),
            component.clone(),
        )
        .unwrap();
        assert_eq!(outcome, RecordOutcome::Recorded);
        // A fake-substrate pass is recorded but promotes nothing by itself.
        let simulated = evidence_from(&evidence_file(dir.path(), false)).unwrap();
        assert!(simulated.yougori_evidence().is_err());
        let reference = EvidenceReference::of(&measured, component.clone()).unwrap();
        let promotion = journal
            .promote(&helpers[0], Backend::Transformers, &reference, &HostLoader)
            .unwrap();
        assert_eq!(
            (promotion.from, promotion.to),
            (RolloutStage::Shadow, RolloutStage::OptIn)
        );
        let opted = select_in(&journal, &release, &helpers, true).unwrap();
        assert!(matches!(&opted[0].serve, ServingHelper::Bundle { pin } if *pin == admitted.pin));
        let serving_bundle = opted.clone();
        let default = select_in(&journal, &release, &helpers, false).unwrap();
        assert!(
            matches!(default[0].serve, ServingHelper::SourceInjection)
                && default[0].shadow.is_none()
        );
        // Evidence from another pass does not back the promotion to the default.
        let other = EvidenceReference::of(&simulated, component.clone()).unwrap();
        assert!(journal
            .promote(&helpers[0], Backend::Transformers, &other, &HostLoader)
            .is_err());
        record_trial(
            &mut journal,
            &admitted.pin,
            release.clone(),
            RolloutStage::OptIn,
            TrialVerdict::Passed,
            measured.clone(),
            component.clone(),
        )
        .unwrap();
        let promotion = journal
            .promote(&helpers[0], Backend::Transformers, &reference, &HostLoader)
            .unwrap();
        assert_eq!(promotion.to, RolloutStage::BackendDefault);
        let default = select_in(&journal, &release, &helpers, false).unwrap();
        assert!(matches!(&default[0].serve, ServingHelper::Bundle { pin } if *pin == admitted.pin));
        // A failure as the default rolls the track back to source injection.
        let rolled = record_trial(
            &mut journal,
            &admitted.pin,
            release.clone(),
            RolloutStage::BackendDefault,
            TrialVerdict::Failed {
                reason: Label::new("mismatch").unwrap(),
            },
            measured.clone(),
            component.clone(),
        )
        .unwrap();
        assert!(
            matches!(
                rolled,
                RecordOutcome::RolledBack {
                    to: RollbackTarget::SourceInjection,
                    ..
                }
            ),
            "{rolled:?}"
        );
        let default = select_in(&journal, &release, &helpers, false).unwrap();
        assert!(matches!(default[0].serve, ServingHelper::SourceInjection));
        // A failed version never comes back: proposing it again is refused.
        assert!(journal
            .propose(admitted.pin.clone(), Backend::Transformers, &HostLoader)
            .is_err());
        let opted = serving_bundle;

        // Written for the runner: the entry file under the helper's directory, read-only bind
        // path inside the container.
        let served = dir.path().join("served");
        let entry = write_bundle(
            &admission,
            &mut service.catalog(),
            &served,
            &helpers[0],
            &admitted.pin,
            &ExecutionId::generate(),
        )
        .unwrap();
        assert_eq!(
            entry,
            format!("{HELPERS_TARGET}/gpu-optimizer/gpu_optimizer.py")
        );
        assert_eq!(
            std::fs::read(served.join("gpu-optimizer").join("gpu_optimizer.py")).unwrap(),
            b"GPU_OPTIMIZER_FROM_BUNDLE = True\n"
        );
        // The start is recorded with exactly what was served.
        let instance = RunnerInstance::new("env-1").unwrap();
        journal
            .start_runner(instance.clone(), release.clone(), opted.clone())
            .unwrap();
        let recorded = journal.runners().get(&instance).unwrap();
        assert!(
            matches!(&recorded.helpers[&helpers[0]].serve, ServingHelper::Bundle { pin } if *pin == admitted.pin)
        );
    }

    #[test]
    fn a_bundle_with_another_key_or_a_tampered_byte_is_refused_and_nothing_is_published() {
        let dir = tempfile::tempdir().unwrap();
        let (catalog, admission) = catalog_and_admission(dir.path());
        let EngineCatalog::Open { service, .. } = &catalog else {
            panic!("catalog not open")
        };
        let bytes = bundle(b"print('helper')\n");
        // Signed by a key the roots do not hold.
        let refused = admission.admit(
            &mut service.catalog(),
            offer(bytes.clone(), signed(2, &bytes)),
            &mut Uninterrupted,
        );
        assert!(refused.is_err(), "{refused:?}");
        // The right key, but the bundle's bytes changed after signing.
        let signature = signed(1, &bytes);
        let mut tampered = bytes.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        let refused = admission.admit(
            &mut service.catalog(),
            offer(tampered, signature),
            &mut Uninterrupted,
        );
        assert!(refused.is_err(), "{refused:?}");
        // No signature at all: a checksum is not trust.
        let refused = admission.admit(
            &mut service.catalog(),
            HelperOffer {
                bundle: bytes,
                signature: None,
                operation: OperationId::generate(),
                execution: ExecutionId::generate(),
            },
            &mut Uninterrupted,
        );
        assert!(refused.is_err(), "{refused:?}");
        let status = crate::catalog_service::status(&catalog).unwrap();
        let helper_class = status["catalog"]["scopes"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|scope| scope["classes"].as_array().cloned().unwrap_or_default())
            .find(|class| class["class"] == "model_helper");
        assert!(
            helper_class.is_none_or(|class| class["published"]["objects"] == 0),
            "{status}"
        );
    }

    #[test]
    fn attestations_are_kept_beside_the_journal_and_read_back_strictly() {
        let dir = tempfile::tempdir().unwrap();
        let (catalog, admission) = catalog_and_admission(dir.path());
        let EngineCatalog::Open { service, .. } = &catalog else {
            panic!("catalog not open")
        };
        let bytes = bundle(b"x = 1\n");
        let signature = signed(1, &bytes);
        let admitted = admission
            .admit(
                &mut service.catalog(),
                offer(bytes.clone(), signature.clone()),
                &mut Uninterrupted,
            )
            .unwrap();
        let attestation = Attestation {
            publisher: signature.publisher,
            signature: signature.signature.clone(),
        };
        let directory = dir.path().join("attestations");
        let path = write_attestation(&directory, &admitted.pin, &attestation).unwrap();
        assert_eq!(
            path.file_name().unwrap().to_str().unwrap(),
            format!("{}.json", admitted.pin.id())
        );
        // Another pin's attestation under this name, a file naming another publisher and a
        // non-JSON file are left out with their reasons; the good one is read back.
        std::fs::write(directory.join("other.json"), std::fs::read(&path).unwrap()).unwrap();
        let mut forged: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        forged["publisher"] = json!(public(2).publisher_id());
        std::fs::write(directory.join("forged.json"), forged.to_string()).unwrap();
        std::fs::write(directory.join("broken.json"), b"{").unwrap();
        std::fs::write(directory.join("notes.txt"), b"ignored").unwrap();
        let (pins, attestations, problems) = load_attestations(&directory);
        assert_eq!(pins.len(), 1);
        assert_eq!(attestations[&admitted.pin.id().to_string()], attestation);
        assert_eq!(problems.len(), 3, "{problems:?}");
        // The evidence reader refuses what is not a validated run record.
        std::fs::write(dir.path().join("bad.json"), b"[{\"schema_version\": 3}]").unwrap();
        assert!(evidence_from(&dir.path().join("bad.json"))
            .unwrap_err()
            .contains("run record 0"));
        std::fs::write(dir.path().join("none.json"), b"{\"records\": []}").unwrap();
        assert!(evidence_from(&dir.path().join("none.json")).is_err());
        assert_eq!(stage_named("Opt-In").unwrap(), RolloutStage::OptIn);
        assert!(stage_named("canary").is_err());
        assert_eq!(
            release_for(Backend::LlamaCpp).unwrap().version.as_str(),
            LLAMA_CPP_RELEASE
        );
        assert!(release_for(Backend::Qemu).is_err());
    }

    #[test]
    fn a_start_recorded_moments_ago_is_not_ended_by_the_reconciliation_before_its_environment_is_up(
    ) {
        let coming_up = RunnerInstance::new("env-coming-up").unwrap();
        let gone = RunnerInstance::new("env-gone").unwrap();
        let alive_one = RunnerInstance::new("env-alive").unwrap();
        let running = [coming_up.clone(), gone.clone(), alive_one.clone()];
        let now = std::time::Instant::now();
        let started = BTreeMap::from([(coming_up.as_str().to_owned(), now)]);
        let alive = |id: &str| id == "env-alive";
        // Within the grace the stopped-looking newcomer stays; the one never started here ends.
        assert_eq!(
            ended_runners(running.iter(), &started, now, &alive),
            vec![gone.clone()]
        );
        assert_eq!(
            ended_runners(
                running.iter(),
                &started,
                now + Duration::from_secs(10),
                &alive
            ),
            vec![gone.clone()]
        );
        // After the grace it ends like any other runner whose environment is not alive.
        assert_eq!(
            ended_runners(running.iter(), &started, now + START_GRACE, &alive),
            vec![coming_up.clone(), gone.clone()]
        );
        // An alive environment's runner never ends, grace or not.
        assert!(
            ended_runners([alive_one.clone()].iter(), &BTreeMap::new(), now, &alive).is_empty()
        );
    }

    #[test]
    fn served_directories_no_environment_binds_are_the_orphans_and_bound_ones_stay() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("served");
        for name in ["bound-one", "orphan-a", "orphan-b"] {
            std::fs::create_dir_all(root.join(name).join("gpu-optimizer")).unwrap();
        }
        std::fs::write(root.join("a-file"), b"not a directory").unwrap();
        let bound = BTreeSet::from([root.join("bound-one")]);
        assert_eq!(
            orphaned_served(&root, &bound, None),
            vec![root.join("orphan-a"), root.join("orphan-b")]
        );
        // The scheduler's sweep takes none younger than its age: a start may be writing one.
        assert!(orphaned_served(&root, &bound, Some(Duration::from_secs(600))).is_empty());
        assert_eq!(
            orphaned_served(&root, &bound, Some(Duration::ZERO)).len(),
            2
        );
        assert!(orphaned_served(&dir.path().join("missing"), &bound, None).is_empty());
        remove_served(&root.join("orphan-a")).unwrap();
        assert!(!root.join("orphan-a").exists() && root.join("bound-one").is_dir());
        assert_eq!(
            remove_served(&root.join("orphan-a")).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
    }

    #[test]
    fn the_names_and_the_attestations_hex_are_read_strictly() {
        assert_eq!(
            backend_named(" Transformers ").unwrap(),
            Backend::Transformers
        );
        assert_eq!(backend_named("llama-cpp").unwrap(), Backend::LlamaCpp);
        assert!(backend_named("cuda").is_err());
        assert_eq!(decode_hex("00ff10").unwrap(), vec![0, 255, 16]);
        assert!(decode_hex("abc").is_err() && decode_hex("zz").is_err());
        let served = Served {
            directory: Some(PathBuf::from("/x")),
            ..Served::default()
        };
        assert_eq!(served.bind().unwrap()["target"], HELPERS_TARGET);
        assert!(Served::default().bind().is_none());
    }
}
