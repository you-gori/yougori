//! The strict tags on real records: the defect where serde buffers a record, every
//! converted enum with a real written sample, the golden fixtures, and the enums it does
//! not concern.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use super::{check_tag, read_tagged};

/// A string no enum here names as a variant.
const PROBE: &str = "st1_no_such_variant";

/// A real persisted coordinator state, as `Coordinator::persist` wrote it for a launched
/// sandbox with an active model and a child lease, after its revocation began.
const PERSISTED_STATE: &str = include_str!("fixtures/coordination_persisted_state.json");

/// Real records of the durable helper rollout stream, one per line, as the journal wrote
/// them: a default with its measured pass, a candidate promoted to opt-in, two runners and
/// a failure that rolled the track back.
const HELPER_JOURNAL: &str = include_str!("fixtures/helper_journal.jsonl");

/// Reads `T` as serde reads a field of another internally tagged enum: buffered.
#[derive(Deserialize)]
#[serde(tag = "wrap", rename_all = "snake_case")]
enum Wrapped<T> {
    Inner { value: T },
}

/// One step of a path into a JSON value.
#[derive(Clone, Debug)]
enum Step {
    Key(String),
    Index(usize),
}

fn shown(path: &[Step]) -> String {
    let mut text = String::new();
    for step in path {
        match step {
            Step::Key(key) if text.is_empty() => text.push_str(key),
            Step::Key(key) => {
                text.push('.');
                text.push_str(key);
            }
            Step::Index(index) => text.push_str(&format!("[{index}]")),
        }
    }
    text
}

fn at<'a>(value: &'a mut Value, path: &[Step]) -> &'a mut Value {
    path.iter().fold(value, |value, step| match step {
        Step::Key(key) => &mut value[key.as_str()],
        Step::Index(index) => &mut value[*index],
    })
}

/// Every string in `value`, with its path.
fn strings(value: &Value, path: &mut Vec<Step>, found: &mut Vec<(Vec<Step>, String)>) {
    match value {
        Value::String(text) => found.push((path.clone(), text.clone())),
        Value::Object(fields) => {
            for (key, field) in fields {
                path.push(Step::Key(key.clone()));
                strings(field, path, found);
                path.pop();
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                path.push(Step::Index(index));
                strings(item, path, found);
                path.pop();
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// The variant names an "unknown variant" refusal of [`PROBE`] lists, in declaration
/// order: the order serde gives the variant indices.
fn expected_variants(message: &str) -> Option<Vec<String>> {
    let (_, rest) = message.split_once(&format!("unknown variant `{PROBE}`, expected "))?;
    Some(
        rest.split('`')
            .skip(1)
            .step_by(2)
            .map(str::to_owned)
            .collect(),
    )
}

fn read_top<T: DeserializeOwned>(value: &Value) -> Result<T, String> {
    serde_json::from_str(&value.to_string()).map_err(|error| error.to_string())
}

fn read_nested<T: DeserializeOwned>(value: &Value) -> Result<T, String> {
    let wrapped = json!({ "wrap": "inner", "value": value });
    serde_json::from_str::<Wrapped<T>>(&wrapped.to_string())
        .map(|Wrapped::Inner { value }| value)
        .map_err(|error| error.to_string())
}

/// A string of a sample that names an enum variant, and the index serde gives it.
#[derive(Debug)]
struct VariantName {
    path: Vec<Step>,
    name: String,
    index: u64,
}

/// Every string of `sample` that names a variant of an enum `T` reads: the tags of its
/// tagged enums at any depth, and the names of unit variants of plain enums. A string is
/// one when `T` refuses [`PROBE`] in its place as an unknown variant.
fn variant_names<T: DeserializeOwned>(sample: &Value) -> Vec<VariantName> {
    let mut found = Vec::new();
    strings(sample, &mut Vec::new(), &mut found);
    found
        .into_iter()
        .filter_map(|(path, name)| {
            let mut probe = sample.clone();
            *at(&mut probe, &path) = Value::from(PROBE);
            let names = expected_variants(&read_top::<T>(&probe).err()?)?;
            let index = names.iter().position(|candidate| *candidate == name)?;
            Some(VariantName {
                path,
                name,
                index: u64::try_from(index).unwrap(),
            })
        })
        .collect()
}

/// Swaps every variant name of `sample` for its index, one at a time, and reports each
/// swap `T` reads, at the top level or buffered. Returns the problems and the names.
fn check_indices<T: DeserializeOwned>(
    label: &str,
    sample: &Value,
) -> (Vec<String>, Vec<VariantName>) {
    let names = variant_names::<T>(sample);
    let mut problems = Vec::new();
    for name in &names {
        let mut swapped = sample.clone();
        *at(&mut swapped, &name.path) = Value::from(name.index);
        let path = shown(&name.path);
        if read_top::<T>(&swapped).is_ok() {
            problems.push(format!(
                "{label}: `{path}` = {} for `{}` was read",
                name.index, name.name
            ));
        }
        if read_nested::<T>(&swapped).is_ok() {
            problems.push(format!(
                "{label}: `{path}` = {} for `{}` was read nested",
                name.index, name.name
            ));
        }
    }
    (problems, names)
}

/// Checks one written sample of `T`: it reads at the top level and buffered, writes back
/// byte for byte both times, and no variant name of it reads as its index.
fn check_sample<T: Serialize + DeserializeOwned>(
    label: &str,
    sample: &str,
) -> (Vec<String>, Vec<VariantName>) {
    let mut problems = Vec::new();
    let value: Value = serde_json::from_str(sample).unwrap();
    let top = serde_json::from_str::<T>(sample).map_err(|error| error.to_string());
    for (how, read) in [("", top), (" nested", read_nested::<T>(&value))] {
        match read {
            Ok(read) => {
                let written = serde_json::to_string(&read).unwrap();
                if written != sample {
                    problems.push(format!(
                        "{label}: {sample} read{how} writes back as {written}"
                    ));
                }
            }
            Err(error) => problems.push(format!("{label}: {sample} refused{how}: {error}")),
        }
    }
    let (refused, names) = check_indices::<T>(label, &value);
    problems.extend(refused);
    (problems, names)
}

/// Every variant of `T` written from its tag alone: its unit variants and those whose
/// fields may all be left out.
fn tag_only_samples<T: Serialize + DeserializeOwned>(tag: &str) -> Vec<String> {
    let record = |name: &str| Value::Object(Map::from_iter([(tag.to_owned(), Value::from(name))]));
    let Err(message) = read_top::<T>(&record(PROBE)) else {
        return Vec::new();
    };
    expected_variants(&message)
        .unwrap_or_default()
        .iter()
        .filter_map(|name| read_top::<T>(&record(name)).ok())
        .map(|read| serde_json::to_string(&read).unwrap())
        .collect()
}

/// Checks a converted enum with every variant written from its tag alone and `samples`,
/// and that its own tag names a variant in each.
fn check_converted<T: Serialize + DeserializeOwned>(
    label: &str,
    tag: &str,
    samples: &[&str],
) -> Vec<String> {
    let mut all = tag_only_samples::<T>(tag);
    all.extend(samples.iter().map(|sample| (*sample).to_owned()));
    if all.is_empty() {
        return vec![format!("{label}: no sample")];
    }
    let mut problems = Vec::new();
    for sample in &all {
        let (found, names) = check_sample::<T>(label, sample);
        problems.extend(found);
        let own = names
            .iter()
            .any(|name| matches!(name.path.as_slice(), [Step::Key(key)] if key == tag));
        if !own {
            problems.push(format!(
                "{label}: the tag `{tag}` of {sample} names no variant"
            ));
        }
    }
    problems
}

/// Checks each `Type => "tag"`, followed by an array of written samples where its tag
/// alone writes no variant or its nesting needs one.
macro_rules! converted {
    ($($type:ty => $tag:literal $($samples:expr)?),* $(,)?) => {{
        let mut problems: Vec<String> = Vec::new();
        let mut types = 0_usize;
        $(
            types += 1;
            let samples: &[&str] = None$(.or(Some(&$samples[..])))?.unwrap_or_default();
            problems.extend(check_converted::<$type>(stringify!($type), $tag, samples));
        )*
        (types, problems)
    }};
}

/// One written sample of every variant of [`FloorUpgrade`], which the recovery stream
/// reads back nested in its records.
///
/// [`FloorUpgrade`]: crate::foundation::coordination::FloorUpgrade
const FLOOR_UPGRADES: [&str; 8] = [
    r#"{"upgrade":"incarnation","from":1,"to":2}"#,
    r#"{"upgrade":"next_lease","from":1,"to":1048578}"#,
    r#"{"upgrade":"sandbox_raised","execution":"exe-a","from":{"boot":1,"policy":1,"authorization":1},"to":{"boot":1,"policy":1,"authorization":2}}"#,
    r#"{"upgrade":"sandbox_recreated","execution":"exe-a","generations":{"boot":1,"policy":1,"authorization":1}}"#,
    r#"{"upgrade":"sandbox_retired","execution":"exe-a","recorded":"authority_active"}"#,
    r#"{"upgrade":"model_raised","execution":"exe-a","model":"108cceb7ad8a5c5674e8c8e974cc9942687562122737593fd3024b1cca353efd","from":{"activation":1,"gpu_allocation":1},"to":{"activation":2,"gpu_allocation":2}}"#,
    r#"{"upgrade":"model_recreated","execution":"exe-a","model":"108cceb7ad8a5c5674e8c8e974cc9942687562122737593fd3024b1cca353efd","next":{"activation":2,"gpu_allocation":2}}"#,
    r#"{"upgrade":"tombstones_restored","execution":"exe-a","grants":["108cceb7ad8a5c5674e8c8e974cc9942687562122737593fd3024b1cca353efd"]}"#,
];

fn assert_no_problems(problems: &[String]) {
    assert!(
        problems.is_empty(),
        "{} problems:\n{}",
        problems.len(),
        problems.join("\n")
    );
}

#[test]
fn serde_reads_a_buffered_number_tag_as_a_variant_index() {
    // The defect itself, on an enum that does not use the check: serde refuses a number
    // tag read straight from JSON and reads it as a variant index once it buffered it.
    #[derive(Debug, PartialEq, Deserialize)]
    #[serde(tag = "class", rename_all = "snake_case")]
    enum Lax {
        Scratch,
        Persistent,
    }
    assert!(serde_json::from_str::<Lax>(r#"{"class":1}"#).is_err());
    assert_eq!(
        read_nested::<Lax>(&json!({ "class": 1 })),
        Ok(Lax::Persistent)
    );
}

#[test]
fn a_number_tag_is_refused_in_a_persisted_coordination_state() {
    let sample = PERSISTED_STATE.trim_end();
    let (problems, names) =
        check_sample::<crate::foundation::coordination::PersistedState>("persisted state", sample);
    assert_no_problems(&problems);
    // The network grant of the launch's `activate_authority` step sits inside the step's
    // tagged enum, where serde buffers it.
    let shown_names: Vec<String> = names.iter().map(|name| shown(&name.path)).collect();
    for path in [
        "sandboxes[0].log[4].step.settings.network[0].grant",
        "sandboxes[0].log[4].step.step",
        "leases[0].state.state",
        "models[0].activations[0].settings.artifact_verification.verification",
    ] {
        assert!(
            shown_names.iter().any(|name| name == path),
            "{path} not checked"
        );
    }
}

#[test]
fn a_number_tag_is_refused_in_helper_journal_records() {
    use crate::model_memory::helpers::journal::JournalRecord;
    let mut problems = Vec::new();
    let mut checked = Vec::new();
    for (line, record) in HELPER_JOURNAL.lines().enumerate() {
        let (found, names) = check_sample::<JournalRecord>(&format!("record {line}"), record);
        problems.extend(found);
        checked.extend(names.iter().map(|name| shown(&name.path)));
    }
    assert_no_problems(&problems);
    assert_eq!(HELPER_JOURNAL.lines().count(), 12);
    // The rollback's target is a tagged enum inside the outcome's tagged enum.
    assert!(checked.iter().any(|path| path == "trial.outcome.to.path"));
    assert!(checked.iter().any(|path| path == "trial.outcome.outcome"));
}

#[test]
fn a_number_tag_is_refused_in_the_golden_documents() {
    use crate::foundation::product::{ProductView, GOLDEN_FIXTURES, PRODUCT_CONTRACT_VERSION};
    use crate::foundation::report::{RunRecord, RUN_RECORD_SAMPLE_JSON};
    let mut problems = Vec::new();
    let mut checked = 0;
    for fixture in GOLDEN_FIXTURES
        .iter()
        .filter(|fixture| fixture.version == PRODUCT_CONTRACT_VERSION)
    {
        let value: Value = serde_json::from_str(fixture.json).unwrap();
        assert!(read_top::<ProductView>(&value).is_ok(), "{}", fixture.name);
        let (found, names) = check_indices::<ProductView>(fixture.name, &value);
        problems.extend(found);
        checked += names.len();
    }
    let value: Value = serde_json::from_str(RUN_RECORD_SAMPLE_JSON).unwrap();
    assert!(read_top::<RunRecord>(&value).is_ok());
    let (found, names) = check_indices::<RunRecord>("run record", &value);
    problems.extend(found);
    checked += names.len();
    assert_no_problems(&problems);
    assert!(checked > 100, "only {checked} variant names checked");
}

#[test]
fn every_converted_enum_refuses_a_number_tag_and_writes_back_unchanged() {
    let (types, problems) = converted! {
        crate::foundation::catalog::ManifestError => "error" [
            r#"{"error":"empty_extent","extent":1}"#,
        ],
        crate::foundation::catalog::Scope => "scope",
        crate::foundation::catalog::ObjectRole => "role",
        crate::foundation::catalog::Checkpoint => "checkpoint" [
            r#"{"checkpoint":"extent","extent":3}"#,
        ],
        crate::foundation::catalog::ImportRefusal => "kind",
        crate::foundation::catalog::FailureReason => "reason",
        crate::foundation::catalog::MetadataError => "error",
        crate::foundation::catalog::QuotaRefusal => "refusal" [
            r#"{"refusal":"no_budget","scope":{"scope":"tenant","tenant":"tenant-a"}}"#,
        ],
        crate::foundation::catalog::IntegrityFailure => "integrity",
        crate::foundation::catalog::TrustBasis => "basis" [
            r#"{"basis":"user_selected","tenant":"tenant-a"}"#,
        ],
        crate::foundation::catalog::VerifierRejection => "rejection",
        crate::foundation::catalog::TrustRefusal => "refusal" [
            r#"{"refusal":"no_verifier","class":"model_weights"}"#,
            r#"{"refusal":"attestation_rejected","class":"model_weights","publisher":"108cceb7ad8a5c5674e8c8e974cc9942687562122737593fd3024b1cca353efd","rejection":{"rejection":"wrong_format","detail":"d"}}"#,
        ],
        crate::foundation::coordination::ReservationPurpose => "purpose" [
            r#"{"purpose":"sandbox","boot":1}"#,
        ],
        crate::foundation::coordination::ReserveOutcome => "outcome",
        crate::foundation::coordination::CapacityRefusal => "refusal" [
            r#"{"refusal":"refused","reason":"full"}"#,
            r#"{"refusal":"unknown_reservation","key":"108cceb7ad8a5c5674e8c8e974cc9942687562122737593fd3024b1cca353efd"}"#,
        ],
        crate::foundation::coordination::RecoveryEvent => "outcome" [
            r#"{"outcome":"untrusted_vm_terminated","vm":"108cceb7ad8a5c5674e8c8e974cc9942687562122737593fd3024b1cca353efd"}"#,
            r#"{"outcome":"floor_raised","floor":2,"upgrades":[{"upgrade":"incarnation","from":1,"to":2}],"stale":["exe-a"]}"#,
            r#"{"outcome":"failed","error":"e"}"#,
        ],
        crate::foundation::coordination::RevocationRequest => "revoke" [
            r#"{"revoke":"execution","operation":"op-a"}"#,
            r#"{"revoke":"grant","grant":"108cceb7ad8a5c5674e8c8e974cc9942687562122737593fd3024b1cca353efd","operation":"op-a"}"#,
        ],
        crate::foundation::coordination::Compensation => "compensation" [
            r#"{"compensation":"terminate_vm","vm":"108cceb7ad8a5c5674e8c8e974cc9942687562122737593fd3024b1cca353efd"}"#,
        ],
        crate::foundation::coordination::StallCause => "cause" [
            r#"{"cause":"capacity","refusal":{"refusal":"refused","reason":"full"}}"#,
        ],
        crate::foundation::coordination::Regression => "regression" [
            r#"{"regression":"incarnation","floor":2,"state":1}"#,
            r#"{"regression":"sandbox_missing","execution":"exe-a"}"#,
        ],
        crate::foundation::coordination::FloorRefusal => "refusal" [
            r#"{"refusal":"revocation_log_behind","floor":5,"found":4}"#,
        ],
        crate::foundation::coordination::FloorUpgrade => "upgrade" FLOOR_UPGRADES,
        crate::foundation::coordination::LeaseState => "state",
        crate::foundation::coordination::LeaseRefusal => "refusal",
        crate::foundation::coordination::ActivationState => "state",
        crate::foundation::coordination::HoldingId => "holding" [
            r#"{"holding":"gpu","allocation":1}"#,
        ],
        crate::foundation::coordination::HoldingMemory => "memory" [
            r#"{"memory":"host","memory_bytes":1,"pinned_memory_bytes":0}"#,
        ],
        crate::foundation::coordination::DemandProblem => "problem",
        crate::foundation::coordination::ModelRefusal => "model_refusal",
        crate::foundation::coordination::Readiness => "readiness",
        crate::foundation::coordination::SnapshotDefect => "defect",
        crate::foundation::coordination::CheckpointDefect => "defect",
        crate::foundation::coordination::CacheDefect => "defect",
        crate::foundation::coordination::ComponentDefects => "component" [
            r#"{"component":"vm_snapshot","defects":[{"defect":"not_pre_tenant"},{"defect":"image_profile_mismatch","expected":"108cceb7ad8a5c5674e8c8e974cc9942687562122737593fd3024b1cca353efd","found":"362c9f7e893370450d35b94fa1d3007274f0243f467b240609281d81c6365119"}]}"#,
        ],
        crate::foundation::coordination::ValidatorVerdict => "verdict",
        crate::foundation::coordination::RestoreFailure => "failure",
        crate::foundation::coordination::SandboxRecovery => "recovery",
        crate::foundation::coordination::ReplayConfigError => "problem",
        crate::foundation::coordination::ScopeFloor => "floor",
        crate::foundation::coordination::ReplayRefusal => "refusal",
        crate::foundation::coordination::ReleaseMechanism => "mechanism",
        crate::foundation::coordination::SessionMoveRefusal => "refusal",
        crate::foundation::coordination::ExitRefusal => "exit_refusal",
        crate::foundation::coordination::ReturnRefusal => "return_refusal",
        crate::foundation::coordination::MilestoneSource => "established_by",
        crate::foundation::coordination::DeniedRequest => "request" [
            r#"{"request":"lease_check","lease":1}"#,
        ],
        crate::foundation::coordination::Denial => "denied_by" [
            r#"{"denied_by":"coordinator","request":{"request":"lease_renewal","lease":2},"refusal":{"refusal":"cancelled","cause":"revocation"}}"#,
            r#"{"denied_by":"enforcement_point","source":"host_probe"}"#,
        ],
        crate::foundation::coordination::UncertainOutcome => "outcome" [
            r#"{"outcome":"ledger_not_cancelled","refusal":{"refusal":"refused","reason":"full"}}"#,
        ],
        crate::foundation::coordination::SandboxStep => "step",
        crate::foundation::coordination::TransitionRefusal => "refusal",
        crate::foundation::coordination::LaunchFailure => "launch_failure" [
            r#"{"launch_failure":"not_ready","detail":"d"}"#,
            r#"{"launch_failure":"capacity","refusal":{"refusal":"unknown_reservation","key":"108cceb7ad8a5c5674e8c8e974cc9942687562122737593fd3024b1cca353efd"}}"#,
        ],
        crate::foundation::coordination::ScopeRefusal => "refusal",
        crate::foundation::coordination::ViewRefusal => "reason",
        crate::foundation::coordination::WatcherHolder => "holder",
        crate::foundation::coordination::WatcherEnd => "ended",
        crate::foundation::coordination::WatcherStanding => "standing",
        crate::foundation::coordination::WatcherRefusal => "reason" [
            r#"{"reason":"view","refusal":{"reason":"other_clock"}}"#,
            r#"{"reason":"view","refusal":{"reason":"expired","fresh_until":5}}"#,
        ],
        crate::foundation::events::AuditEntry => "kind" [
            r#"{"kind":"guest_observation","fields":{"fields":[],"omitted_fields":0}}"#,
            r#"{"kind":"linkage","head":{"journal":"journal-a","owner":"producer-a","last":null,"digest":"108cceb7ad8a5c5674e8c8e974cc9942687562122737593fd3024b1cca353efd"}}"#,
        ],
        crate::foundation::events::LogMarker => "kind",
        crate::foundation::events::MetricValue => "kind" [
            r#"{"kind":"counter","count":3}"#,
        ],
        crate::foundation::events::QueueReason => "reason",
        crate::foundation::events::CancellationBoundary => "boundary",
        crate::foundation::events::RedactedValue => "kind" [
            r#"{"kind":"signed","value":-5}"#,
            r#"{"kind":"text","text":"é\"","full_bytes":3}"#,
        ],
        crate::foundation::evidence::RuntimeRequirement => "requires",
        crate::foundation::evidence::CategoryRefusal => "refusal" [
            r#"{"refusal":"vm_sandbox_required","offered":"shared_kernel_gpu_runtime"}"#,
            r#"{"refusal":"not_explicitly_allowed","offered":"provider_container_runtime","allowed":["vm_sandbox"]}"#,
        ],
        crate::foundation::evidence::SupportDetail => "kind",
        crate::foundation::evidence::ObservationResult => "outcome" [
            r#"{"outcome":"supported","detail":{"kind":"plain"}}"#,
        ],
        crate::foundation::evidence::NetworkGrant => "grant" [
            r#"{"grant":"named_route","route":"108cceb7ad8a5c5674e8c8e974cc9942687562122737593fd3024b1cca353efd"}"#,
        ],
        crate::foundation::evidence::ArtifactVerification => "verification",
        crate::foundation::evidence::ArtifactBypass => "kind",
        crate::foundation::evidence::FallbackViolation => "violation" [
            r#"{"violation":"reopens_network_access","added":[{"grant":"named_route","route":"108cceb7ad8a5c5674e8c8e974cc9942687562122737593fd3024b1cca353efd"}]}"#,
            r#"{"violation":"bypasses_artifact_verification","bypass":{"kind":"verification_skipped"}}"#,
        ],
        crate::foundation::evidence::ModeRefusal => "refusal" [
            r#"{"refusal":"unknown_release","release":{"backend":"vllm","version":"0.29.0"}}"#,
        ],
        crate::foundation::evidence::NotEnabled => "reason",
        crate::foundation::evidence::Remedy => "action",
        crate::foundation::evidence::Staleness => "kind",
        crate::foundation::evidence::EvidenceRefusal => "refusal" [
            r#"{"refusal":"missing","capability":"runtime_category"}"#,
            r#"{"refusal":"source_too_weak","capability":"runtime_category","observed":"host_probe","required":"host_probe"}"#,
        ],
        crate::foundation::evidence::Subject => "kind" [
            r#"{"kind":"runtime","category":"vm_sandbox","release":{"backend":"vllm","version":"0.31.0"},"instance":"108cceb7ad8a5c5674e8c8e974cc9942687562122737593fd3024b1cca353efd"}"#,
        ],
        crate::foundation::process::ProcessRole => "role" [
            r#"{"role":"vm_host","execution":"exe-a","vm":"108cceb7ad8a5c5674e8c8e974cc9942687562122737593fd3024b1cca353efd","boot":1}"#,
        ],
        crate::foundation::product::UnsupportedReason => "reason",
        crate::foundation::product::FeatureSupport => "support" [
            r#"{"support":"supported","cases":3}"#,
            r#"{"support":"unsupported","reason":{"reason":"not_in_dialect"}}"#,
        ],
        crate::foundation::product::Evidence => "state" [
            r#"{"state":"verified","by":{"kind":"host_probe","capability":"runtime_category"},"observed_at":1000,"fresh_until":3600000001000}"#,
            r#"{"state":"unavailable","refusal":{"code":{"domain":"evidence","code":"evidence_source_too_weak"},"reason":"io_uring needs a host probe, and a guest report never satisfies a host-only requirement","remedy":{"remedy":"evidence","step":{"action":"obtain_stronger_evidence","required":"host_probe"}},"remedy_text":"obtain evidence from a host probe or a stronger source"}}"#,
            r#"{"state":"asserted","by":"guest","received_at":1000001000}"#,
        ],
        crate::foundation::product::VerifiedBy => "kind",
        crate::foundation::product::GrantScope => "scope",
        crate::foundation::product::GrantStatus => "status",
        crate::foundation::product::LegacyChoice => "recorded" [
            r#"{"recorded":"category","category":"vm_sandbox"}"#,
        ],
        crate::foundation::product::MigrationOption => "option",
        crate::foundation::product::MigrationOutcome => "outcome",
        crate::foundation::product::MigrationStatus => "status",
        crate::foundation::product::Preparation => "preparation" [
            r#"{"preparation":"used","at":5}"#,
        ],
        crate::foundation::product::PermissionStatus => "status",
        crate::foundation::product::RefusalCode => "domain" [
            r#"{"domain":"category","code":"vm_sandbox_required"}"#,
            r#"{"domain":"evidence","code":"evidence_source_too_weak"}"#,
        ],
        crate::foundation::product::Remedy => "remedy",
        crate::foundation::report::ClaimUnderTest => "kind" [
            r#"{"kind":"yougori","bench":"BENCH-01","statement":"fast"}"#,
        ],
        crate::foundation::report::Applicability => "kind",
        crate::foundation::report::RecordStatistic => "kind",
        crate::foundation::report::PublicationStatus => "kind",
        crate::foundation::report::Provenance => "kind" [
            r#"{"kind":"fake_substrate","evidence":"108cceb7ad8a5c5674e8c8e974cc9942687562122737593fd3024b1cca353efd"}"#,
        ],
        crate::foundation::report::ClaimConfiguration => "kind",
        crate::foundation::report::TracePattern => "kind",
        crate::foundation::report::PriceProvenance => "kind",
        crate::foundation::report::EventKind => "kind",
        crate::foundation::report::AlignmentDeclaration => "kind",
        crate::foundation::report::Measured<u64> => "status" [
            r#"{"status":"measured","value":7}"#,
            r#"{"status":"not_measured","reason":"instrument_unavailable"}"#,
        ],
        crate::foundation::report::ModelRevision => "kind" [
            r#"{"kind":"tag","name":"v1"}"#,
        ],
        crate::foundation::report::AttemptRole => "kind",
        crate::foundation::report::Scenario => "clock",
        crate::foundation::report::RunSubstrate => "kind",
        crate::foundation::report::NonceDisclosure => "kind",
        crate::foundation::report::ClientPlacement => "kind",
        crate::foundation::report::ArrivalMode => "kind",
        crate::foundation::report::ReasoningTrace => "kind",
        crate::foundation::report::Outcome => "result",
        crate::foundation::report::Quotient => "status" [
            r#"{"status":"defined","value":0.5}"#,
        ],
        crate::foundation::report::Resolution => "kind",
        crate::foundation::signing::ComponentVerification => "outcome",
        crate::foundation::transfer::ParentStatus => "status",
        crate::foundation::transfer::ReservationRefusal => "resource" [
            r#"{"resource":"bytes","refusal":{"requested_bytes":2,"available_bytes":1,"retry_can_progress":true}}"#,
        ],
        crate::foundation::transfer::ProgressPhase => "kind",
        crate::foundation::transfer::TransferStatus => "status",
        crate::foundation::transfer::StopReason => "kind",
        crate::model_memory::executor::ReadStatus => "status",
        crate::model_memory::executor::SourceKind => "kind",
        crate::model_memory::executor::StagingPlace => "place",
        crate::model_memory::executor::TransferPath => "path",
        crate::model_memory::executor::ReservedResource => "resource",
        crate::model_memory::executor::ReservationPurpose => "purpose",
        crate::model_memory::helpers::journal::RecordedVerdict => "verdict",
        crate::model_memory::helpers::journal::RecordedTarget => "path",
        crate::model_memory::helpers::journal::RecordedAbiRefusal => "refusal" [
            r#"{"refusal":"minor_too_new","required":{"major":1,"minor":3},"provided":{"major":1,"minor":2}}"#,
            r#"{"refusal":"major_not_provided","required":{"major":2,"minor":0},"provided":[{"major":1,"minor":2}]}"#,
        ],
        crate::model_memory::helpers::journal::RecordedPinRefusal => "pin",
        crate::model_memory::helpers::journal::RecordedOutcome => "outcome",
        crate::model_memory::helpers::journal::RecordedDefault => "path",
        crate::model_memory::helpers::journal::RecordedSourceInjection => "source_injection",
        crate::model_memory::helpers::journal::RecordedServing => "path",
        crate::model_memory::helpers::journal::RecordedFallback => "reason" [
            r#"{"reason":"runner_not_supported","pin":"108cceb7ad8a5c5674e8c8e974cc9942687562122737593fd3024b1cca353efd"}"#,
            r#"{"reason":"not_admissible","pin":"108cceb7ad8a5c5674e8c8e974cc9942687562122737593fd3024b1cca353efd","refusal":{"pin":"not_published"}}"#,
        ],
        crate::model_memory::placement::PlacementChoice => "choice" [
            r#"{"choice":"reuse","placement":3}"#,
            r#"{"choice":"new","process":2}"#,
        ],
        crate::model_memory::placement::RequestProblem => "problem",
        crate::model_memory::placement::ReadinessReport => "readiness",
        crate::model_memory::placement::BarrierError => "error" [
            r#"{"error":"unknown_rank","rank":0}"#,
        ],
        crate::model_memory::placement::EarlyRefusal => "kind",
        crate::model_memory::placement::PlacementEvent => "event" [
            r#"{"event":"parked","slot":"108cceb7ad8a5c5674e8c8e974cc9942687562122737593fd3024b1cca353efd","placement":3}"#,
        ],
        crate::model_memory::placement::ProcessLiveness => "process",
        crate::model_memory::placement::ShapeRefusal => "refusal" [
            r#"{"refusal":"context_too_long","requested_tokens":9,"supported_tokens":8}"#,
        ],
        crate::model_memory::placement::ResourceKind => "resource",
        crate::model_memory::placement::ReservationRefusal => "kind" [
            r#"{"kind":"capacity","refusal":{"resource":{"resource":"host_ram"},"requested_bytes":2,"available_bytes":1,"retry":"fits_after_release"}}"#,
        ],
        crate::model_memory::placement::CoordinationRefusal => "refusal",
        crate::model_memory::placement::PublicationRefusal => "kind",
        crate::model_memory::placement::GateError => "error" [
            r#"{"error":"unknown_reference","reference":4}"#,
        ],
        crate::model_memory::placement::PauseReason => "reason" [
            r#"{"reason":"single_generation_capacity","refusal":{"resource":{"resource":"host_ram"},"requested_bytes":2,"available_bytes":1,"retry":"exceeds_capacity"}}"#,
        ],
        crate::model_memory::placement::PauseOutcome => "outcome",
        crate::model_memory::placement::TicketError => "error",
        crate::model_memory::placement::RollbackOutlook => "rollback",
        crate::model_memory::placement::SlotError => "kind" [
            r#"{"kind":"not_resident","placement":3}"#,
            r#"{"kind":"gate","error":{"error":"unknown_event","event":2}}"#,
        ],
        crate::model_memory::placement::FailureReason => "reason",
        crate::model_memory::placement::PlacementState => "state",
        crate::model_memory::profiles::QualityEvidence => "quality",
        crate::model_memory::profiles::CheckResult => "outcome",
        crate::model_memory::profiles::GateResult => "gate",
        crate::model_memory::profiles::QualificationHost => "host",
        crate::model_memory::profiles::Cleanup => "cleanup",
        crate::model_memory::profiles::Review => "review",
        crate::model_memory::profiles::Origin => "origin",
        crate::model_memory::profiles::Prerequisite => "prerequisite",
        crate::model_memory::profiles::ProfileFailure => "kind" [
            r#"{"kind":"capacity","resource":"gpu_memory","needed_bytes":2,"available_bytes":1}"#,
            r#"{"kind":"tool_semantics","failure":"parser_unavailable"}"#,
        ],
        crate::model_memory::profiles::ToolCalls => "tool_calls",
        crate::model_memory::vmm::DriverError => "error",
        crate::model_memory::vmm::OrderViolation => "violation",
        crate::model_memory::vmm::DriverCall => "call" [
            r#"{"call":"malloc","size_bytes":4096}"#,
            r#"{"call":"pool_allocate","size_bytes":1,"expandable_segments":true}"#,
        ],
        crate::model_memory::vmm::GraphResource => "resource" [
            r#"{"resource":"artifact","artifact":"108cceb7ad8a5c5674e8c8e974cc9942687562122737593fd3024b1cca353efd","offset_bytes":0,"length_bytes":8}"#,
        ],
        crate::model_memory::vmm::AllocationKind => "kind",
        crate::model_memory::vmm::AllocationContents => "contents" [
            r#"{"contents":"private","label":"108cceb7ad8a5c5674e8c8e974cc9942687562122737593fd3024b1cca353efd"}"#,
        ],
    };
    assert_eq!(types, 171);
    assert_no_problems(&problems);
}

#[test]
fn external_and_untagged_enums_are_unaffected() {
    // An externally tagged enum names its variant as a string or a map key; serde refuses
    // a number for it at the top level and buffered alike, so it needs no check.
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum External {
        Unit,
        Struct { value: u64 },
    }
    for text in [
        r#"0"#,
        r#"1"#,
        r#"{"0":{"value":1}}"#,
        r#"{"1":{"value":1}}"#,
    ] {
        let value: Value = serde_json::from_str(text).unwrap();
        assert!(read_top::<External>(&value).is_err(), "{text}");
        assert!(read_nested::<External>(&value).is_err(), "{text} nested");
    }
    assert_eq!(read_nested::<External>(&json!("unit")), Ok(External::Unit));

    // An untagged enum has no variant name to misread: the same input reads the same
    // variant at the top level and buffered.
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    #[serde(untagged)]
    enum Untagged {
        Count { count: u64 },
        Name { name: String },
    }
    for (value, expected) in [
        (json!({ "count": 1 }), Some(Untagged::Count { count: 1 })),
        (
            json!({ "name": "a" }),
            Some(Untagged::Name { name: "a".into() }),
        ),
        (json!({ "name": 0 }), None),
        (json!(0), None),
    ] {
        assert_eq!(read_top::<Untagged>(&value).ok(), expected, "{value}");
        assert_eq!(
            read_nested::<Untagged>(&value).ok(),
            expected,
            "{value} nested"
        );
    }

    // Real ones, which have no check of their own: the rollout stage of the helper
    // journal's externally tagged records, a plain enum, refuses its index at the top
    // level and buffered; so does the transfer endpoint, read through a struct whose kind
    // is a plain enum.
    use crate::foundation::transfer::Endpoint;
    use crate::model_memory::helpers::journal::JournalRecord;
    let mut stages = 0;
    for record in HELPER_JOURNAL.lines() {
        let value: Value = serde_json::from_str(record).unwrap();
        for name in variant_names::<JournalRecord>(&value) {
            if !matches!(name.path.last(), Some(Step::Key(key)) if key == "stage") {
                continue;
            }
            stages += 1;
            let mut swapped = value.clone();
            *at(&mut swapped, &name.path) = Value::from(name.index);
            assert!(read_top::<JournalRecord>(&swapped).is_err(), "{swapped}");
            assert!(
                read_nested::<JournalRecord>(&swapped).is_err(),
                "{swapped} nested"
            );
        }
    }
    assert!(stages > 0);
    let endpoint = json!({ "kind": "host_catalog" });
    assert!(read_nested::<Endpoint>(&endpoint).is_ok());
    let names = variant_names::<Endpoint>(&endpoint);
    assert_eq!(names.len(), 1);
    for swapped in [json!({ "kind": names[0].index }), json!({ "kind": 1 })] {
        assert!(read_top::<Endpoint>(&swapped).is_err(), "{swapped}");
        assert!(
            read_nested::<Endpoint>(&swapped).is_err(),
            "{swapped} nested"
        );
    }
}

#[test]
fn check_tag_refuses_as_the_sandbox_contract_does() {
    let check = |value: Value| {
        check_tag::<serde_json::Error>(&value, "kind").map_err(|error| error.to_string())
    };
    assert_eq!(check(json!({ "kind": "a", "other": 1 })), Ok(()));
    assert_eq!(
        check(json!({ "other": 1 })),
        Err("missing field `kind`".to_owned())
    );
    for (value, unexpected) in [
        (json!({ "kind": 1 }), "integer `1`"),
        (json!({ "kind": -1 }), "integer `-1`"),
        (json!({ "kind": 1.5 }), "floating point `1.5`"),
        (json!({ "kind": null }), "null"),
        (json!({ "kind": true }), "boolean `true`"),
        (json!({ "kind": ["a"] }), "sequence"),
        (json!({ "kind": { "a": 1 } }), "map"),
    ] {
        assert_eq!(
            check(value),
            Err(format!(
                "invalid type: {unexpected}, expected a variant name"
            ))
        );
    }
    for (value, unexpected) in [
        (json!(["a", 1]), "sequence"),
        (json!("a"), "string \"a\""),
        (json!(1), "integer `1`"),
        (json!(null), "null"),
    ] {
        assert_eq!(
            check(value),
            Err(format!("invalid type: {unexpected}, expected a map"))
        );
    }
}

#[test]
fn read_tagged_refuses_a_repeated_key_and_keeps_everything_else() {
    #[derive(Debug)]
    struct Read(Value);
    impl<'de> Deserialize<'de> for Read {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            read_tagged(deserializer, "kind").map(Read)
        }
    }
    let text = r#"{"kind":"a","big":18446744073709551615,"low":-9223372036854775808,"float":0.1,"text":"é\"","list":[null,true,{"b":[]}]}"#;
    let Read(value) = serde_json::from_str(text).unwrap();
    assert_eq!(value, serde_json::from_str::<Value>(text).unwrap());
    // Read buffered too, as a field of another tagged enum.
    let Read(nested) = read_nested::<Read>(&serde_json::from_str(text).unwrap()).unwrap();
    assert_eq!(nested, value);
    for text in [
        r#"{"kind":"a","kind":"b"}"#,
        r#"{"kind":"a","x":1,"x":1}"#,
        r#"{"kind":"a","list":[{"y":1,"y":2}]}"#,
    ] {
        let error = serde_json::from_str::<Read>(text).unwrap_err().to_string();
        assert!(error.starts_with("duplicate field"), "{text}: {error}");
    }
    assert!(serde_json::from_str::<Read>(r#"{"kind":0}"#).is_err());
}

#[test]
fn a_repeated_field_or_tag_stays_refused() {
    // Read straight from JSON, serde refuses a repeated tag or field; reading through a
    // JSON value must not start keeping the last one.
    use crate::foundation::coordination::LeaseState;
    use crate::model_memory::helpers::journal::RecordedOutcome;
    let nested = |text: &str| format!(r#"{{"wrap":"inner","value":{text}}}"#);
    assert!(serde_json::from_str::<LeaseState>(r#"{"state":"released","at":1}"#).is_ok());
    for text in [
        r#"{"state":"released","at":1,"at":2}"#,
        r#"{"state":"released","state":"active","at":1}"#,
    ] {
        assert!(serde_json::from_str::<LeaseState>(text).is_err(), "{text}");
        assert!(
            serde_json::from_str::<Wrapped<LeaseState>>(&nested(text)).is_err(),
            "{text} nested"
        );
    }
    for text in [
        r#"{"outcome":"recorded","outcome":"recorded"}"#,
        r#"{"outcome":"rolled_back","to":{"path":"source_injection"},"skipped":[],"skipped":[]}"#,
        r#"{"outcome":"rolled_back","to":{"path":"source_injection","path":"source_injection"},"skipped":[]}"#,
    ] {
        assert!(
            serde_json::from_str::<RecordedOutcome>(text).is_err(),
            "{text}"
        );
        assert!(
            serde_json::from_str::<Wrapped<RecordedOutcome>>(&nested(text)).is_err(),
            "{text} nested"
        );
    }
}

#[test]
fn generic_and_strict_enums_keep_their_rules() {
    use crate::foundation::report::Measured;
    let measured = r#"{"status":"measured","value":7}"#;
    assert_eq!(
        serde_json::to_string(&serde_json::from_str::<Measured<u64>>(measured).unwrap()).unwrap(),
        measured
    );
    for text in [
        r#"{"status":"measured","value":7,"extra":1}"#,
        r#"{"status":"measured"}"#,
        r#"{"status":0,"value":7}"#,
        r#"{"status":"measured","value":"7"}"#,
    ] {
        let value: Value = serde_json::from_str(text).unwrap();
        assert!(read_top::<Measured<u64>>(&value).is_err(), "{text}");
        assert!(
            read_nested::<Measured<u64>>(&value).is_err(),
            "{text} nested"
        );
    }
}

#[test]
fn a_floor_upgrade_refuses_an_unknown_field() {
    // The recovery stream reads floor upgrades back nested in its records, so every
    // variant refuses a field it does not name, at the top level and buffered.
    use crate::foundation::coordination::FloorUpgrade;
    for sample in FLOOR_UPGRADES {
        let mut value: Value = serde_json::from_str(sample).unwrap();
        assert!(read_top::<FloorUpgrade>(&value).is_ok(), "{sample}");
        assert!(
            read_nested::<FloorUpgrade>(&value).is_ok(),
            "{sample} nested"
        );
        value["unknown"] = json!(1);
        assert!(read_top::<FloorUpgrade>(&value).is_err(), "{value}");
        assert!(
            read_nested::<FloorUpgrade>(&value).is_err(),
            "{value} nested"
        );
    }
}
