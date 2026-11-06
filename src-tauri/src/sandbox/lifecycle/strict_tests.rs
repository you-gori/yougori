//! Strict tags on the lifecycle's read-back records (tracker E01Y follow-up after ST1):
//! every tagged enum here that derives `Deserialize` reads through
//! [`crate::foundation::strict_serde`], so a tag that is not a string and a key repeated in
//! one record are refused, read at the top level and buffered as serde buffers a field of
//! another tagged enum, and the written form is unchanged. The table covers every
//! converted enum; the bounded lifecycle messages are checked through
//! [`MessageFrame::parse`], and the persisted supervisor state in the scenario tests.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::*;

/// A string no enum here names as a variant.
const PROBE: &str = "lifecycle_no_such_variant";

/// Reads `T` as serde reads a field of another internally tagged enum: buffered.
#[derive(Deserialize)]
#[serde(tag = "wrap", rename_all = "snake_case")]
enum Wrapped<T> {
    Inner { value: T },
}

/// One step of a path into a JSON value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Step {
    Key(String),
    Index(usize),
}

pub(super) fn shown(path: &[Step]) -> String {
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

/// The path and keys of every object in `value`.
fn objects(value: &Value, path: &mut Vec<Step>, found: &mut Vec<(Vec<Step>, Vec<String>)>) {
    match value {
        Value::Object(fields) => {
            found.push((path.clone(), fields.keys().cloned().collect()));
            for (key, field) in fields {
                path.push(Step::Key(key.clone()));
                objects(field, path, found);
                path.pop();
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                path.push(Step::Index(index));
                objects(item, path, found);
                path.pop();
            }
        }
        Value::Null | Value::Bool(_) | Value::String(_) | Value::Number(_) => {}
    }
}

/// `value` written as JSON with the entry `key` of the object at `target` written twice.
fn repeating(value: &Value, target: &[Step], key: &str) -> String {
    fn write(value: &Value, path: &mut Vec<Step>, target: &[Step], key: &str, out: &mut String) {
        match value {
            Value::Object(fields) => {
                out.push('{');
                let mut first = true;
                for (name, field) in fields {
                    let times = if path.as_slice() == target && name == key {
                        2
                    } else {
                        1
                    };
                    for _ in 0..times {
                        if !first {
                            out.push(',');
                        }
                        first = false;
                        out.push_str(&Value::from(name.as_str()).to_string());
                        out.push(':');
                        path.push(Step::Key(name.clone()));
                        write(field, path, target, key, out);
                        path.pop();
                    }
                }
                out.push('}');
            }
            Value::Array(items) => {
                out.push('[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    path.push(Step::Index(index));
                    write(item, path, target, key, out);
                    path.pop();
                }
                out.push(']');
            }
            other => out.push_str(&other.to_string()),
        }
    }
    let mut out = String::new();
    write(value, &mut Vec::new(), target, key, &mut out);
    out
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

fn read_top<T: DeserializeOwned>(text: &str) -> Result<T, String> {
    serde_json::from_str(text).map_err(|error| error.to_string())
}

fn read_nested<T: DeserializeOwned>(text: &str) -> Result<T, String> {
    serde_json::from_str::<Wrapped<T>>(&format!(r#"{{"wrap":"inner","value":{text}}}"#))
        .map(|Wrapped::Inner { value }| value)
        .map_err(|error| error.to_string())
}

/// A string of a sample that names an enum variant, and the index serde gives it.
#[derive(Debug)]
pub(super) struct VariantName {
    pub(super) path: Vec<Step>,
    pub(super) name: String,
    pub(super) index: u64,
}

/// Every string of `sample` that names a variant of an enum `T` reads: the tags of its
/// tagged enums at any depth and the names of unit variants of plain enums. A string is
/// one when `T` refuses [`PROBE`] in its place as an unknown variant.
fn variant_names<T: DeserializeOwned>(sample: &Value) -> Vec<VariantName> {
    let mut found = Vec::new();
    strings(sample, &mut Vec::new(), &mut found);
    found
        .into_iter()
        .filter_map(|(path, name)| {
            let mut probe = sample.clone();
            *at(&mut probe, &path) = Value::from(PROBE);
            let names = expected_variants(&read_top::<T>(&probe.to_string()).err()?)?;
            let index = names.iter().position(|candidate| *candidate == name)?;
            Some(VariantName {
                path,
                name,
                index: u64::try_from(index).ok()?,
            })
        })
        .collect()
}

/// Reports each of `texts` that `read` takes, at the top level or buffered.
fn refused_everywhere<T: DeserializeOwned>(label: &str, texts: &[(String, String)]) -> Vec<String> {
    let mut problems = Vec::new();
    for (what, text) in texts {
        if read_top::<T>(text).is_ok() {
            problems.push(format!("{label}: {what} was read: {text}"));
        }
        if read_nested::<T>(text).is_ok() {
            problems.push(format!("{label}: {what} was read nested: {text}"));
        }
    }
    problems
}

/// Every variant name of `sample` swapped for its index, one at a time.
fn index_swaps(sample: &Value, names: &[VariantName]) -> Vec<(String, String)> {
    names
        .iter()
        .map(|name| {
            let mut swapped = sample.clone();
            *at(&mut swapped, &name.path) = Value::from(name.index);
            (
                format!(
                    "`{}` = {} for `{}`",
                    shown(&name.path),
                    name.index,
                    name.name
                ),
                swapped.to_string(),
            )
        })
        .collect()
}

/// `sample` with one key of one object written twice, for each key of each object at
/// `paths`.
fn repeats(sample: &Value, paths: &[(Vec<Step>, Vec<String>)]) -> Vec<(String, String)> {
    paths
        .iter()
        .flat_map(|(path, keys)| {
            keys.iter().map(move |key| {
                (
                    format!("`{key}` repeated in `{}`", shown(path)),
                    repeating(sample, path, key),
                )
            })
        })
        .collect()
}

/// Checks one written sample of `T`: it reads at the top level and buffered and writes
/// back byte for byte both times, and no variant name of it read as its index is taken.
/// Returns the problems and the variant names found.
pub(super) fn check_sample<T: Serialize + DeserializeOwned>(
    label: &str,
    sample: &str,
) -> (Vec<String>, Vec<VariantName>) {
    let mut problems = Vec::new();
    for (how, read) in [
        ("", read_top::<T>(sample)),
        (" nested", read_nested::<T>(sample)),
    ] {
        match read.map(|read| serde_json::to_string(&read)) {
            Ok(Ok(written)) if written == sample => {}
            Ok(Ok(written)) => problems.push(format!(
                "{label}: {sample} read{how} writes back as {written}"
            )),
            Ok(Err(error)) => problems.push(format!("{label}: {sample} not written{how}: {error}")),
            Err(error) => problems.push(format!("{label}: {sample} refused{how}: {error}")),
        }
    }
    let Ok(value) = serde_json::from_str::<Value>(sample) else {
        problems.push(format!("{label}: {sample} is not JSON"));
        return (problems, Vec::new());
    };
    let names = variant_names::<T>(&value);
    problems.extend(refused_everywhere::<T>(label, &index_swaps(&value, &names)));
    (problems, names)
}

/// Checks a written record of a tagged enum `T`: [`check_sample`], and a key repeated in
/// any object of it, at any depth, is refused at the top level and buffered.
fn check_record<T: Serialize + DeserializeOwned>(
    label: &str,
    sample: &str,
) -> (Vec<String>, Vec<VariantName>) {
    let (mut problems, names) = check_sample::<T>(label, sample);
    if let Ok(value) = serde_json::from_str::<Value>(sample) {
        let mut found = Vec::new();
        objects(&value, &mut Vec::new(), &mut found);
        problems.extend(refused_everywhere::<T>(label, &repeats(&value, &found)));
    }
    (problems, names)
}

/// Checks the records of a struct `T` that are read back: every object of `sample` that
/// holds a variant name under a key `T` requires there (a tagged record, or a record with
/// an enum field) refuses each of its keys repeated, at the top level and buffered.
/// Objects that are maps keep serde's reading. Returns the problems and the paths of the
/// objects checked.
pub(super) fn check_repeats_in_records<T: DeserializeOwned>(
    label: &str,
    sample: &str,
    names: &[VariantName],
) -> (Vec<String>, Vec<String>) {
    let Ok(value) = serde_json::from_str::<Value>(sample) else {
        return (vec![format!("{label}: {sample} is not JSON")], Vec::new());
    };
    let mut records: Vec<(Vec<Step>, Vec<String>)> = Vec::new();
    for name in names {
        let Some((Step::Key(key), parent)) = name.path.split_last() else {
            continue;
        };
        if records.iter().any(|(path, _)| path.as_slice() == parent) {
            continue;
        }
        let mut without = value.clone();
        let Some(fields) = at(&mut without, parent).as_object_mut() else {
            continue;
        };
        let keys: Vec<String> = fields.keys().cloned().collect();
        fields.remove(key);
        if read_top::<T>(&without.to_string()).is_err() {
            records.push((parent.to_vec(), keys));
        }
    }
    let checked = records.iter().map(|(path, _)| shown(path)).collect();
    (
        refused_everywhere::<T>(label, &repeats(&value, &records)),
        checked,
    )
}

/// Every variant of `T` written from its tag alone: its unit variants and those whose
/// fields may all be left out.
fn tag_only_samples<T: Serialize + DeserializeOwned>(tag: &str) -> Vec<String> {
    let record = |name: &str| {
        Value::Object(Map::from_iter([(tag.to_owned(), Value::from(name))])).to_string()
    };
    let Err(message) = read_top::<T>(&record(PROBE)) else {
        return Vec::new();
    };
    expected_variants(&message)
        .unwrap_or_default()
        .iter()
        .filter_map(|name| read_top::<T>(&record(name)).ok())
        .filter_map(|read| serde_json::to_string(&read).ok())
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
        let (found, names) = check_record::<T>(label, sample);
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
/// alone writes no variant or a variant's fields need one.
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

pub(super) fn assert_no_problems(problems: &[String]) {
    assert!(
        problems.is_empty(),
        "{} problems:\n{}",
        problems.len(),
        problems.join("\n")
    );
}

/// One written lifecycle message of each kind, as a peer sends it.
const MESSAGES: [&str; 7] = [
    r#"{"message":"activity","execution":"exe-a","kind":"command"}"#,
    r#"{"message":"acknowledge","execution":"exe-a","acknowledgment":"channels_closed"}"#,
    r#"{"message":"revoke","execution":"exe-a","cause":{"cause":"user_requested"}}"#,
    r#"{"message":"revoke","execution":"exe-a","cause":{"cause":"lease_expired","kind":"idle"}}"#,
    r#"{"message":"revoke_grant","execution":"exe-a","grant":"108cceb7ad8a5c5674e8c8e974cc9942687562122737593fd3024b1cca353efd","cause":"policy_changed"}"#,
    r#"{"message":"stop","execution":"exe-a"}"#,
    r#"{"message":"cleanup","execution":"exe-a","target":{"root":"108cceb7ad8a5c5674e8c8e974cc9942687562122737593fd3024b1cca353efd","path":"tmp/build"}}"#,
];

#[test]
fn every_read_back_tagged_enum_refuses_a_number_tag_or_a_repeated_key_and_writes_back_unchanged() {
    let (types, problems) = converted! {
        HandleIdentity => "identity" [r#"{"identity":"reused","holder":"exe-b"}"#],
        StateReset => "reset" [r#"{"reset":"unsupported","detail":"no reset"}"#],
        BindingRefusal => "refusal" [
            r#"{"refusal":"missing_field","kind":"guest_channel","field":"snapshot"}"#,
            r#"{"refusal":"stale","field":"authorization"}"#,
        ],
        GenerationClaim => "claim" [
            r#"{"claim":"authorization_epoch","epoch":1}"#,
            r#"{"claim":"policy_epoch","epoch":1}"#,
            r#"{"claim":"sandbox_boot","generation":1}"#,
            r#"{"claim":"model_activation","generation":1}"#,
            r#"{"claim":"gpu_allocation","generation":1}"#,
        ],
        LimitRefusal => "refusal" [
            r#"{"refusal":"cannot_raise","kind":"idle","default":{"secs":900,"nanos":0},"requested":{"secs":1800,"nanos":0}}"#,
            r#"{"refusal":"zero","kind":"per_call"}"#,
            r#"{"refusal":"not_applicable","kind":"service_renewal","class":"task"}"#,
        ],
        ActivityRefusal => "refusal" [
            r#"{"refusal":"not_activity","kind":"network_traffic"}"#,
            r#"{"refusal":"expired","expiry":{"kind":"idle","at":5}}"#,
        ],
        RenewalRefusal => "refusal" [
            r#"{"refusal":"not_a_service","class":"task"}"#,
            r#"{"refusal":"expired","expiry":{"kind":"absolute","at":5}}"#,
        ],
        LeaseRestoreRefusal => "refusal" [
            r#"{"refusal":"clock_rolled_back","reading":4,"high_water":5}"#,
            r#"{"refusal":"already_expired","expiry":{"kind":"task","at":5}}"#,
        ],
        BoundNotApplicable => "reason",
        PhysicalWipe => "physical" [
            r#"{"physical":"covered_by_key_destruction","covered":["ram","swap"]}"#,
        ],
        PoolRefusal => "refusal" [
            r#"{"refusal":"not_golden","origin":"tenant_workload"}"#,
            r#"{"refusal":"defects","defects":[{"defect":"not_pre_tenant"},{"defect":"contains","content":"live_tenant_secrets"},{"defect":"image_profile_mismatch","expected":"108cceb7ad8a5c5674e8c8e974cc9942687562122737593fd3024b1cca353efd","found":"108cceb7ad8a5c5674e8c8e974cc9942687562122737593fd3024b1cca353efd"}]}"#,
        ],
        ColdFallback => "fallback" [
            r#"{"fallback":"state_reset_unsupported","detail":"no reset"}"#,
        ],
        CheckoutDecision => "decision" [
            r#"{"decision":"cold_boot","fallback":{"fallback":"pool_depleted"}}"#,
            r#"{"decision":"cold_boot","fallback":{"fallback":"state_reset_unsupported","detail":"no reset"}}"#,
        ],
        VolumeRefusal => "refusal",
        VolumeAttachment => "attachment" [
            r#"{"attachment":"attached","behavior":"retain_with_validation"}"#,
            r#"{"attachment":"not_attached","refusal":{"refusal":"quarantined"}}"#,
        ],
        ShutdownMode => "shutdown" [
            r#"{"shutdown":"application_consistent","quiesce_within":{"secs":30,"nanos":0}}"#,
        ],
        RollbackPlan => "rollback",
        RenewalPlanProblem => "problem",
        ObservedReadiness => "readiness" [
            r#"{"readiness":"ready","at":5}"#,
            r#"{"readiness":"unavailable","since":5,"detail":"the launch record is not current"}"#,
        ],
        ReplayRefusal => "refusal" [
            r#"{"refusal":"replayed","scope":{"issuer":"108cceb7ad8a5c5674e8c8e974cc9942687562122737593fd3024b1cca353efd","sandbox":"exe-a","boot":1,"authorization":1},"nonce":7}"#,
            r#"{"refusal":"tombstoned_generation","scope":{"issuer":"108cceb7ad8a5c5674e8c8e974cc9942687562122737593fd3024b1cca353efd","sandbox":"exe-a","boot":1,"authorization":1},"tombstoned":1}"#,
        ],
        KeptReason => "reason" [r#"{"reason":"capability_may_exist","until":5}"#],
        AckSource => "by" [
            r#"{"by":"coordination","milestone":"first_denied_authorization","source":{"established_by":"coordinator"}}"#,
            r#"{"by":"coordination","milestone":"all_channels_closed","source":{"established_by":"acknowledged","source":"host_probe"}}"#,
            r#"{"by":"coordination","milestone":"all_channels_closed","source":{"established_by":"implied_by","by":"sockets_closed","source":"host_probe"}}"#,
            r#"{"by":"provider","provider":"108cceb7ad8a5c5674e8c8e974cc9942687562122737593fd3024b1cca353efd"}"#,
        ],
        RevocationCause => "cause" [r#"{"cause":"lease_expired","kind":"idle"}"#],
        ProviderBilling => "billing" [r#"{"billing":"stopped","provider":"108cceb7ad8a5c5674e8c8e974cc9942687562122737593fd3024b1cca353efd","at":5}"#],
        CleanupState => "cleanup" [
            r#"{"cleanup":"started","at":5,"bound_at":65}"#,
            r#"{"cleanup":"finished","at":6,"report":{"actions":["overlay_deleted","perimeter_removed"],"physical":{"physical":"not_proven"}},"late":false}"#,
            r#"{"cleanup":"finished","at":6,"report":{"actions":[],"physical":{"physical":"covered_by_key_destruction","covered":["snapshots"]}},"late":true}"#,
        ],
        Uncertain => "uncertain" [
            r#"{"uncertain":"channels_unacknowledged","bound_at":5}"#,
            r#"{"uncertain":"cleanup_incomplete","bound_at":5}"#,
            r#"{"uncertain":"provider_billing_unconfirmed","since":5}"#,
            r#"{"uncertain":"vm_stop_uncertain","detail":"stalled"}"#,
            r#"{"uncertain":"coordination","outcome":{"outcome":"unacknowledged_lease","lease":3,"kind":"child_work","bound_at":5,"expires_at":6}}"#,
            r#"{"uncertain":"coordination","outcome":{"outcome":"ledger_not_cancelled","refusal":{"refusal":"refused","reason":"full"}}}"#,
        ],
        AckRefusal => "refusal" [
            r#"{"refusal":"before_decision","at":4,"decided_at":5}"#,
            r#"{"refusal":"taken_from_coordination","milestone":"all_channels_closed"}"#,
        ],
        PathRefusal => "refusal" [
            r#"{"refusal":"too_long","bytes":2000,"max":1024}"#,
            r#"{"refusal":"component_too_long","bytes":300,"max":255}"#,
            r#"{"refusal":"forbidden_character","character":":"}"#,
        ],
        CleanupRefusal => "refusal" [
            r#"{"refusal":"unknown_root","root":"108cceb7ad8a5c5674e8c8e974cc9942687562122737593fd3024b1cca353efd"}"#,
            r#"{"refusal":"other_sandbox","root":"108cceb7ad8a5c5674e8c8e974cc9942687562122737593fd3024b1cca353efd","owner":"exe-a"}"#,
            r#"{"refusal":"user_source_preserved","root":"108cceb7ad8a5c5674e8c8e974cc9942687562122737593fd3024b1cca353efd"}"#,
        ],
        LifecycleMessage => "message" MESSAGES,
        PeerIdentity => "peer" [r#"{"peer":"authenticated","principal":"engine"}"#],
        FrameRefusal => "refusal" [
            r#"{"refusal":"too_large","bytes":5000,"max":4096}"#,
            r#"{"refusal":"malformed","detail":"d"}"#,
            r#"{"refusal":"bad_principal","error":"e"}"#,
        ],
        SupervisorDeathFallback => "fallback" [
            r#"{"fallback":"service_manager_restart","restart_within":{"secs":30,"nanos":0}}"#,
        ],
        WatchdogRefusal => "refusal" [
            r#"{"refusal":"mutual_dependency","cycle":["supervisor","service-manager","supervisor"]}"#,
            r#"{"refusal":"self_watch","watchdog":"supervisor"}"#,
        ],
        EngineState => "engine" [r#"{"engine":"down","since":5}"#],
    };
    assert_eq!(types, 35);
    assert_no_problems(&problems);
}

/// §6.4 "only bounded lifecycle messages": a frame reads only its written form. Inside a
/// message serde buffers the record, so a nested tag written as a number used to read as
/// that variant (`"cause":{"cause":0}` as `user_requested`); a number tag, nested or not,
/// and a key repeated in any record of the frame are refused as malformed.
#[test]
fn an_ipc_frame_with_a_number_tag_or_a_repeated_key_is_refused() {
    let peer = PeerIdentity::Authenticated {
        principal: "engine".to_owned(),
    };
    let parse = |text: &str| MessageFrame::parse(&peer, text.as_bytes());
    let malformed = |text: &str| matches!(parse(text), Err(FrameRefusal::Malformed { .. }));
    let mut problems = Vec::new();
    let mut checked = 0_usize;
    for sample in MESSAGES {
        match parse(sample).map(|message| serde_json::to_string(&message)) {
            Ok(Ok(written)) if written == sample => {}
            other => problems.push(format!("{sample} read as {other:?}")),
        }
        let value: Value = serde_json::from_str(sample).unwrap();
        let names = variant_names::<LifecycleMessage>(&value);
        let mut found = Vec::new();
        objects(&value, &mut Vec::new(), &mut found);
        for (what, text) in index_swaps(&value, &names)
            .into_iter()
            .chain(repeats(&value, &found))
        {
            checked += 1;
            if !malformed(&text) {
                problems.push(format!("{what} was read: {text}"));
            }
        }
    }
    assert_no_problems(&problems);
    assert!(checked > 30, "only {checked} frames checked");

    for text in [
        r#"{"message":"revoke","execution":"exe-a","cause":{"cause":0}}"#,
        r#"{"message":"revoke","execution":"exe-a","cause":{"cause":2,"kind":"idle"}}"#,
        r#"{"message":"revoke","execution":"exe-a","cause":{"cause":"lease_expired","kind":1}}"#,
        r#"{"message":5,"execution":"exe-a"}"#,
        r#"{"message":"stop","message":"stop","execution":"exe-a"}"#,
        r#"{"message":"stop","execution":"exe-a","execution":"exe-b"}"#,
        r#"{"message":"revoke","execution":"exe-a","cause":{"cause":"user_requested","cause":"violation"}}"#,
        r#"{"message":"revoke","execution":"exe-a","cause":{"cause":"lease_expired","kind":"idle","kind":"task"}}"#,
    ] {
        assert!(malformed(text), "{text}: {:?}", parse(text));
    }
    let detail = |text: &str| match parse(text) {
        Err(FrameRefusal::Malformed { detail }) => detail,
        other => panic!("{other:?}"),
    };
    assert!(
        detail(r#"{"message":"revoke","execution":"exe-a","cause":{"cause":0}}"#)
            .contains("expected a variant name")
    );
    assert!(
        detail(r#"{"message":"stop","execution":"exe-a","execution":"exe-b"}"#)
            .starts_with("duplicate field")
    );
    // The written form itself is unchanged and still drives the supervisor's parse.
    assert_eq!(
        parse(r#"{"message":"revoke","execution":"exe-a","cause":{"cause":"user_requested"}}"#),
        Ok(LifecycleMessage::Revoke {
            execution: crate::foundation::ids::ExecutionId::new("exe-a").unwrap(),
            cause: RevocationCause::UserRequested,
        })
    );
}
