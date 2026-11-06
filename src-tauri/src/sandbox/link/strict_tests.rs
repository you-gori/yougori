//! Strict tags on the conformance corpus's steps (`foundation::strict_serde`; the S06 item
//! "Strict tags of read-back tagged enums" of docs/combined-plan-leftover-tasks.md): every
//! written [`Step`] and [`HostAction`] reads at the top level and nested, where serde
//! buffers it, and writes back byte for byte both times; each string of it that names a
//! variant, swapped for the variant's index, and each key of it written twice, is refused
//! both ways. The shipped corpus with either in one of its steps does not parse. The
//! helpers are local: this module depends on no other sandbox module.

use std::collections::BTreeSet;

use serde::de::DeserializeOwned;
use serde::ser::{SerializeMap, SerializeSeq};
use serde::{Deserialize, Serialize, Serializer};
use serde_json::Value;

use super::corpus::{Corpus, CorpusError, HostAction, Step, CORPUS_JSON};

/// A string no enum here names as a variant.
const PROBE: &str = "vst2_no_such_variant";

/// Reads `T` as serde reads a field of another internally tagged enum: buffered.
#[derive(Deserialize)]
#[serde(tag = "wrap", rename_all = "snake_case")]
enum Wrapped<T> {
    Inner { value: T },
}

/// One step of a path into a JSON value.
#[derive(Clone, Debug, PartialEq, Eq)]
enum PathStep {
    Key(String),
    Index(usize),
}

/// `path` as `a.b[2].c`.
fn shown(path: &[PathStep]) -> String {
    let mut text = String::new();
    for step in path {
        match step {
            PathStep::Key(key) if text.is_empty() => text.push_str(key),
            PathStep::Key(key) => {
                text.push('.');
                text.push_str(key);
            }
            PathStep::Index(index) => text.push_str(&format!("[{index}]")),
        }
    }
    text
}

fn at<'a>(value: &'a mut Value, path: &[PathStep]) -> &'a mut Value {
    path.iter().fold(value, |value, step| match step {
        PathStep::Key(key) => &mut value[key.as_str()],
        PathStep::Index(index) => &mut value[*index],
    })
}

/// Every string of `value` with its path, and every key of its objects with the path of
/// the object.
fn walk(
    value: &Value,
    path: &mut Vec<PathStep>,
    strings: &mut Vec<(Vec<PathStep>, String)>,
    keys: &mut Vec<(Vec<PathStep>, String)>,
) {
    match value {
        Value::String(text) => strings.push((path.clone(), text.clone())),
        Value::Object(fields) => {
            for (key, field) in fields {
                keys.push((path.clone(), key.clone()));
                path.push(PathStep::Key(key.clone()));
                walk(field, path, strings, keys);
                path.pop();
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                path.push(PathStep::Index(index));
                walk(item, path, strings, keys);
                path.pop();
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn read_top<T: DeserializeOwned>(text: &str) -> Result<T, String> {
    serde_json::from_str(text).map_err(|error| error.to_string())
}

fn read_nested<T: DeserializeOwned>(text: &str) -> Result<T, String> {
    serde_json::from_str::<Wrapped<T>>(&format!(r#"{{"wrap":"inner","value":{text}}}"#))
        .map(|Wrapped::Inner { value }| value)
        .map_err(|error| error.to_string())
}

/// The variant names an "unknown variant" refusal of [`PROBE`] lists, in declaration
/// order: the order serde gives the variant indices.
fn listed_variants(message: &str) -> Option<Vec<String>> {
    let (_, rest) = message.split_once(&format!("unknown variant `{PROBE}`, expected "))?;
    Some(
        rest.split('`')
            .skip(1)
            .step_by(2)
            .map(str::to_owned)
            .collect(),
    )
}

/// A string of a sample that names an enum variant, and the index serde gives it.
struct VariantName {
    path: Vec<PathStep>,
    name: String,
    index: u64,
}

/// Every string of `sample` that names a variant of an enum `T` reads: the tags of its
/// tagged enums at any depth and the names of the variants of its plain enums. A string
/// is one when `T` refuses [`PROBE`] in its place as an unknown variant.
fn variant_names<T: DeserializeOwned>(sample: &Value) -> Vec<VariantName> {
    let mut strings = Vec::new();
    walk(sample, &mut Vec::new(), &mut strings, &mut Vec::new());
    strings
        .into_iter()
        .filter_map(|(path, name)| {
            let mut probe = sample.clone();
            *at(&mut probe, &path) = Value::from(PROBE);
            let names = listed_variants(&read_top::<T>(&probe.to_string()).err()?)?;
            let index = names.iter().position(|candidate| *candidate == name)?;
            Some(VariantName {
                path,
                name,
                index: u64::try_from(index).unwrap(),
            })
        })
        .collect()
}

/// `value` written as JSON with the key `key` of the object at `object` written twice,
/// both times with its value: a form `serde_json::Value` cannot hold.
fn repeated(value: &Value, object: &[PathStep], key: &str) -> String {
    serde_json::to_string(&Part {
        value,
        repeated: Some((object, key)),
    })
    .unwrap()
}

/// One part of a document written by [`repeated`].
struct Part<'a> {
    value: &'a Value,
    repeated: Option<(&'a [PathStep], &'a str)>,
}

impl Serialize for Part<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let Some((object, key)) = self.repeated else {
            return self.value.serialize(serializer);
        };
        match (self.value, object.split_first()) {
            (Value::Object(fields), None) => {
                let mut map = serializer.serialize_map(None)?;
                for (name, field) in fields {
                    map.serialize_entry(name, field)?;
                    if name == key {
                        map.serialize_entry(name, field)?;
                    }
                }
                map.end()
            }
            (Value::Object(fields), Some((PathStep::Key(next), rest))) => {
                let mut map = serializer.serialize_map(None)?;
                for (name, field) in fields {
                    let repeated = (name == next).then_some((rest, key));
                    map.serialize_entry(
                        name,
                        &Part {
                            value: field,
                            repeated,
                        },
                    )?;
                }
                map.end()
            }
            (Value::Array(items), Some((PathStep::Index(next), rest))) => {
                let mut seq = serializer.serialize_seq(None)?;
                for (index, item) in items.iter().enumerate() {
                    let repeated = (index == *next).then_some((rest, key));
                    seq.serialize_element(&Part {
                        value: item,
                        repeated,
                    })?;
                }
                seq.end()
            }
            _ => self.value.serialize(serializer),
        }
    }
}

/// Checks one written sample of `T`: it reads at the top level and nested and writes
/// back byte for byte both times; each string of it that names a variant, swapped for the
/// variant's index, and each key of it written twice, is refused at the top level and
/// nested.
fn check_sample<T: Serialize + DeserializeOwned>(label: &str, sample: &str) -> Vec<String> {
    let mut problems = Vec::new();
    for (how, read) in [
        ("", read_top::<T>(sample)),
        (" nested", read_nested::<T>(sample)),
    ] {
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
    let mut refused = |what: String, text: &str| {
        if read_top::<T>(text).is_ok() {
            problems.push(format!("{label}: {sample}: {what} was read"));
        }
        if read_nested::<T>(text).is_ok() {
            problems.push(format!("{label}: {sample}: {what} was read nested"));
        }
    };
    let value: Value = serde_json::from_str(sample).unwrap();
    for name in variant_names::<T>(&value) {
        let mut swapped = value.clone();
        *at(&mut swapped, &name.path) = Value::from(name.index);
        let what = format!(
            "`{}` = {} for `{}`",
            shown(&name.path),
            name.index,
            name.name
        );
        refused(what, &swapped.to_string());
    }
    let mut keys = Vec::new();
    walk(&value, &mut Vec::new(), &mut Vec::new(), &mut keys);
    for (object, key) in keys {
        let what = format!("`{key}` twice in `{}`", shown(&object));
        refused(what, &repeated(&value, &object, &key));
    }
    problems
}

/// Checks `T` over `samples`: each passes [`check_sample`], and together they write
/// every variant of `T`'s own `tag`.
fn check_type<T: Serialize + DeserializeOwned>(
    label: &str,
    tag: &str,
    samples: &[String],
) -> Vec<String> {
    let mut problems = Vec::new();
    let mut written = BTreeSet::new();
    for sample in samples {
        problems.extend(check_sample::<T>(label, sample));
        if let Ok(Value::Object(fields)) = serde_json::from_str::<Value>(sample) {
            if let Some(Value::String(name)) = fields.get(tag) {
                written.insert(name.clone());
            }
        }
    }
    let variants = read_top::<T>(&format!(r#"{{"{tag}":"{PROBE}"}}"#))
        .err()
        .and_then(|message| listed_variants(&message))
        .unwrap_or_default();
    if variants.is_empty() {
        problems.push(format!("{label}: `{tag}` names no variant"));
    }
    for variant in variants {
        if !written.contains(&variant) {
            problems.push(format!("{label}: no sample writes `{variant}`"));
        }
    }
    problems
}

/// One written sample of every host action.
const HOST_ACTIONS: [&str; 8] = [
    r#"{"action":"opened","channel":"egress","stream":1}"#,
    r#"{"action":"open_refused","channel":"file","stream":2,"cause":"quota_exceeded"}"#,
    r#"{"action":"open_terminal","stream":2,"columns":80,"rows":24}"#,
    r#"{"action":"open_ingress","stream":3,"listener":"web"}"#,
    r#"{"action":"open_file","stream":2,"grant":9,"entry":"out.bin","mode":"write"}"#,
    r#"{"action":"cancel","channel":"terminal","stream":2,"cause":"timed_out"}"#,
    r#"{"action":"end_of_stream","channel":"egress","stream":1}"#,
    r#"{"action":"close","reason":"orderly"}"#,
];

#[test]
fn every_step_refuses_a_number_tag_and_a_repeated_key() {
    let mut steps: BTreeSet<String> = HOST_ACTIONS
        .iter()
        .map(|action| format!(r#"{{"kind":"host","action":{action}}}"#))
        .collect();
    steps.insert(r#"{"kind":"guest","frame_hex":"59474c4b"}"#.to_owned());
    let shipped = Corpus::shipped().unwrap();
    for case in &shipped.cases {
        steps.extend(
            case.steps
                .iter()
                .map(|step| serde_json::to_string(step).unwrap()),
        );
    }
    let steps: Vec<String> = steps.into_iter().collect();
    let actions: Vec<String> = HOST_ACTIONS
        .iter()
        .map(|action| action.to_string())
        .collect();
    let mut problems = check_type::<Step>("Step", "kind", &steps);
    problems.extend(check_type::<HostAction>("HostAction", "action", &actions));
    assert!(
        problems.is_empty(),
        "{} problems:\n{}",
        problems.len(),
        problems.join("\n")
    );
}

#[test]
fn a_corpus_with_a_number_tag_or_a_repeated_key_in_a_step_does_not_parse() {
    let corpus: Value = serde_json::from_str(CORPUS_JSON).unwrap();
    assert!(Corpus::parse(&corpus.to_string()).is_ok());
    let refused = |text: &str| matches!(Corpus::parse(text), Err(CorpusError::Json(_)));
    // Each place a variant name is written in a step, once: swapped for its index, and
    // its key written twice.
    let mut checked: Vec<String> = Vec::new();
    for (case, written) in corpus["cases"].as_array().unwrap().iter().enumerate() {
        for (step, sample) in written["steps"].as_array().unwrap().iter().enumerate() {
            let at_step = [
                PathStep::Key("cases".to_owned()),
                PathStep::Index(case),
                PathStep::Key("steps".to_owned()),
                PathStep::Index(step),
            ];
            for name in variant_names::<Step>(sample) {
                let path = shown(&name.path);
                if checked.contains(&path) {
                    continue;
                }
                let whole: Vec<PathStep> = at_step.iter().chain(&name.path).cloned().collect();
                let mut swapped = corpus.clone();
                *at(&mut swapped, &whole) = Value::from(name.index);
                assert!(refused(&swapped.to_string()), "{}", shown(&whole));
                if let Some((PathStep::Key(key), object)) = whole.split_last() {
                    let twice = repeated(&corpus, object, key);
                    assert!(refused(&twice), "`{key}` twice in {}", shown(object));
                }
                checked.push(path);
            }
        }
    }
    for path in ["kind", "action.action", "action.channel"] {
        assert!(
            checked.iter().any(|found| found == path),
            "{path}: {checked:?}"
        );
    }
}
