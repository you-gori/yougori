//! Strict tags on every tagged enum this module reads back (`foundation::strict_serde`; the
//! S06 item "Strict tags of read-back tagged enums" of
//! docs/combined-plan-leftover-tasks.md): the lines of the durable log and of the spool,
//! the lines of the test file storage, and the segment, anchor and correlation enums. Each
//! written sample reads at the top level and nested, where serde buffers it, and writes
//! back byte for byte both times; each string of it that names a variant, swapped for the
//! variant's index, and each key of it written twice, is refused both ways. The helpers
//! also serve the stored-line tests of `durable_tests` and `spool`.

use std::collections::BTreeSet;

use serde::de::DeserializeOwned;
use serde::ser::{SerializeMap, SerializeSeq};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

use super::anchor::AnchorVerdict;
use super::correlation::{IncidentScope, ObservationSummary, TelemetrySource};
use super::durable::SegmentLine;
use super::fakes::{
    context, execution, journal_id, manual_clock, producer, stream_config, FakeAnchor,
    FakeSegmentStorage, FakeSpool, Line,
};
use super::segment::{Damage, ResumeFinding, SegmentOpening, StoredSegment};
use super::spool::SpoolLine;
use super::stream::{AuditEvent, AuditStream, StreamDirectory};
use crate::foundation::events::{
    Field, GrantRevocation, HostFact, Phase, Revocation, RevocationReason,
};
use crate::foundation::ids::{digest, AuthorizationEpoch, GrantId};

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
pub(super) enum PathStep {
    Key(String),
    Index(usize),
}

/// `path` as `a.b[2].c`.
pub(super) fn shown(path: &[PathStep]) -> String {
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

pub(super) fn read_top<T: DeserializeOwned>(text: &str) -> Result<T, String> {
    serde_json::from_str(text).map_err(|error| error.to_string())
}

pub(super) fn read_nested<T: DeserializeOwned>(text: &str) -> Result<T, String> {
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
#[derive(Clone, Debug)]
pub(super) struct VariantName {
    pub(super) path: Vec<PathStep>,
    pub(super) name: String,
    pub(super) index: u64,
}

impl VariantName {
    /// `sample` with this name swapped for its index.
    pub(super) fn swapped(&self, sample: &Value) -> Value {
        let mut swapped = sample.clone();
        *at(&mut swapped, &self.path) = Value::from(self.index);
        swapped
    }

    /// The object holding this name and the key it is under; none for an array item.
    pub(super) fn key(&self) -> Option<(&[PathStep], &str)> {
        match self.path.split_last() {
            Some((PathStep::Key(key), object)) => Some((object, key.as_str())),
            _ => None,
        }
    }
}

/// Every string of `sample` that names a variant of an enum `T` reads: the tags of its
/// tagged enums at any depth and the names of the variants of its plain enums. A string
/// is one when `T` refuses [`PROBE`] in its place as an unknown variant.
pub(super) fn variant_names<T: DeserializeOwned>(sample: &Value) -> Vec<VariantName> {
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

/// A JSON document, written with the key `key` of the object at `object` twice, both
/// times with its value, when it names one: a form `serde_json::Value` cannot hold.
#[derive(Clone, Debug)]
pub(super) struct Document {
    value: Value,
    repeated: Option<(Vec<PathStep>, String)>,
}

impl Document {
    pub(super) fn new(value: Value) -> Self {
        Self {
            value,
            repeated: None,
        }
    }

    pub(super) fn repeating(value: Value, object: &[PathStep], key: &str) -> Self {
        Self {
            value,
            repeated: Some((object.to_vec(), key.to_owned())),
        }
    }

    pub(super) fn text(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}

impl Serialize for Document {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let repeated = self
            .repeated
            .as_ref()
            .map(|(object, key)| (object.as_slice(), key.as_str()));
        Part {
            value: &self.value,
            repeated,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Document {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Value::deserialize(deserializer).map(Self::new)
    }
}

/// One part of a [`Document`] as it is written.
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
/// nested. Returns the problems and the paths of the names swapped.
pub(super) fn check_sample<T: Serialize + DeserializeOwned>(
    label: &str,
    sample: &str,
) -> (Vec<String>, Vec<String>) {
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
            problems.push(format!("{label}: {what} was read"));
        }
        if read_nested::<T>(text).is_ok() {
            problems.push(format!("{label}: {what} was read nested"));
        }
    };
    let value: Value = serde_json::from_str(sample).unwrap();
    let names = variant_names::<T>(&value);
    for name in &names {
        let what = format!(
            "`{}` = {} for `{}`",
            shown(&name.path),
            name.index,
            name.name
        );
        refused(what, &name.swapped(&value).to_string());
    }
    let mut keys = Vec::new();
    walk(&value, &mut Vec::new(), &mut Vec::new(), &mut keys);
    for (object, key) in keys {
        let what = format!("`{key}` twice in `{}`", shown(&object));
        refused(
            what,
            &Document::repeating(value.clone(), &object, &key).text(),
        );
    }
    (
        problems,
        names.iter().map(|name| shown(&name.path)).collect(),
    )
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
        problems.extend(check_sample::<T>(label, sample).0);
        if let Ok(Value::Object(fields)) = serde_json::from_str::<Value>(sample) {
            if let Some(Value::String(name)) = fields.get(tag) {
                written.insert(name.clone());
            }
        }
    }
    let probe = format!(r#"{{"{tag}":"{PROBE}"}}"#);
    let variants = read_top::<T>(&probe)
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

/// Checks each `Type => "tag", samples`, where `samples` iterates over written samples.
macro_rules! strict_table {
    ($($type:ty => $tag:literal, $samples:expr;)+) => {{
        let mut problems: Vec<String> = Vec::new();
        let mut types = 0_usize;
        $(
            types += 1;
            let samples: Vec<String> = $samples.iter().map(|sample| sample.to_string()).collect();
            problems.extend(check_type::<$type>(stringify!($type), $tag, &samples));
        )+
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

/// The segments of one real stream on in-memory storage: the first, opened at genesis,
/// sealed after a host fact, a revocation and a grant revocation; the second, opened by
/// rotation, left without a seal when the process stopped; and the third, opened when the
/// stream resumed, sealed by a close.
pub(super) fn sample_segments() -> Vec<StoredSegment> {
    let storage = FakeSegmentStorage::new(100);
    let mut directory = StreamDirectory::new();
    let (mut stream, mut authority) = AuditStream::open(
        &mut directory,
        journal_id("engine"),
        producer("engine.audit"),
        storage.clone(),
        FakeSpool::new(),
        FakeAnchor::new(),
        manual_clock(),
        stream_config(4, 1, 3),
    )
    .unwrap();
    let fact = |step: u64| AuditEvent::HostFact {
        fact: HostFact::Lease,
        fields: vec![Field::metadata("step", step)],
    };
    let running = || context("op-1", Phase::Running);
    let _ = stream.record(&mut authority, running(), fact(1)).unwrap();
    let _ = stream
        .record_revocation(
            &mut authority,
            running(),
            Revocation {
                execution: execution("exe-1"),
                epoch: AuthorizationEpoch::new(2),
                reason: RevocationReason::SecurityEvent,
            },
        )
        .unwrap();
    let _ = stream
        .record_grant_revocation(
            &mut authority,
            running(),
            GrantRevocation {
                execution: execution("exe-1"),
                grant: GrantId::from_digest(digest("yougori/test/grant/v1", &[b"route-a"])),
                epoch: AuthorizationEpoch::FIRST,
                reason: RevocationReason::SecurityEvent,
            },
        )
        .unwrap();
    let _ = stream.record(&mut authority, running(), fact(4)).unwrap();
    drop((stream, authority));
    let (stream, authority, _) = AuditStream::resume(
        &mut directory,
        journal_id("engine"),
        producer("engine.audit"),
        storage.clone(),
        FakeSpool::new(),
        FakeAnchor::new(),
        manual_clock(),
        stream_config(4, 1, 3),
    )
    .unwrap();
    stream.close().unwrap();
    drop(authority);
    let segments = storage.snapshot();
    assert_eq!(segments.len(), 3);
    assert!(matches!(
        segments[2].header.opening(),
        SegmentOpening::Resume { .. }
    ));
    segments
}

/// Every line of `segments` as the durable log keeps it: each header, record and seal.
pub(super) fn segment_lines(segments: &[StoredSegment]) -> Vec<SegmentLine> {
    let mut lines = Vec::new();
    for segment in segments {
        lines.push(SegmentLine::Header {
            header: segment.header.clone(),
        });
        lines.extend(segment.records.iter().map(|record| SegmentLine::Record {
            record: Box::new(record.clone()),
        }));
        lines.extend(
            segment
                .seal
                .iter()
                .map(|seal| SegmentLine::Seal { seal: seal.clone() }),
        );
    }
    lines
}

fn written<T: Serialize>(items: &[T]) -> Vec<String> {
    items
        .iter()
        .map(|item| serde_json::to_string(item).unwrap())
        .collect()
}

#[test]
fn every_tagged_enum_read_back_refuses_a_number_tag_and_a_repeated_key() {
    let segments = sample_segments();
    let records: Vec<_> = segments
        .iter()
        .flat_map(|segment| segment.records.iter().cloned())
        .collect();
    let durable = written(&segment_lines(&segments));
    let mut files = Vec::new();
    for segment in &segments {
        files.push(Line::Header {
            header: segment.header.clone(),
        });
        files.extend(segment.records.iter().map(|record| Line::Record {
            record: record.clone(),
        }));
        files.extend(
            segment
                .seal
                .iter()
                .map(|seal| Line::Seal { seal: seal.clone() }),
        );
    }
    let files = written(&files);
    // The file storage of the tests writes its lines as the durable log does.
    assert_eq!(files, durable);
    let mut spooled: Vec<SpoolLine> = records
        .iter()
        .map(|record| SpoolLine::Spooled {
            record: Box::new(record.clone()),
        })
        .collect();
    spooled.push(SpoolLine::Removed {
        sequence: records[0].sequence(),
        digest: records[0].digest(),
    });
    let spooled = written(&spooled);

    let (types, problems) = strict_table! {
        SegmentLine => "line", durable;
        SpoolLine => "line", spooled;
        Line => "line", files;
        SegmentOpening => "reason", [
            r#"{"reason":"genesis"}"#,
            r#"{"reason":"rotation"}"#,
            r#"{"reason":"resume","finding":{"kind":"truncated","intact_through":3,"continued_from":5,"witness":"anchor"}}"#,
        ];
        ResumeFinding => "kind", [
            r#"{"kind":"sealed"}"#,
            r#"{"kind":"unsealed","records_found":2}"#,
            r#"{"kind":"truncated","intact_through":3,"continued_from":5,"witness":"seal"}"#,
            r#"{"kind":"truncated","intact_through":null,"continued_from":1,"witness":"anchor"}"#,
        ];
        Damage => "kind", [
            r#"{"kind":"tail_truncated","segment":2,"intact_through":3,"continued_from":5,"witness":"seal"}"#,
            r#"{"kind":"unsealed","segment":2,"records_found":1}"#,
        ];
        AnchorVerdict => "verdict", [
            r#"{"verdict":"not_anchored"}"#,
            r#"{"verdict":"reaches","anchored":4}"#,
            r#"{"verdict":"truncated","anchored":6,"stored_through":4}"#,
            r#"{"verdict":"truncated","anchored":6,"stored_through":null}"#,
            r#"{"verdict":"rewritten","anchored":4}"#,
            r#"{"verdict":"other_stream"}"#,
            r#"{"verdict":"dropped","anchored":4}"#,
        ];
        TelemetrySource => "source", [
            r#"{"source":"host_observation"}"#,
            r#"{"source":"guest_report","kind":"syscall_report"}"#,
            r#"{"source":"hypervisor_host_syscalls"}"#,
            r#"{"source":"other_source","class":"provider_api"}"#,
        ];
        ObservationSummary => "measure", [
            r#"{"measure":"exit_code","code":-1}"#,
            r#"{"measure":"bytes","bytes":4096}"#,
            r#"{"measure":"syscalls","calls":12}"#,
            r#"{"measure":"events","events":3}"#,
            r#"{"measure":"denied_attempts","attempts":2}"#,
        ];
        IncidentScope => "scope", [
            r#"{"scope":"execution","execution":"exe-1"}"#,
            r#"{"scope":"operation","operation":"op-1"}"#,
            r#"{"scope":"request","request":"req-1"}"#,
        ];
    };
    assert_eq!(types, 10);
    assert_no_problems(&problems);

    // The resumed segment's header holds a tagged enum two levels down, read buffered.
    let header = durable
        .iter()
        .filter(|line| line.contains(r#""reason":"resume""#))
        .collect::<Vec<_>>();
    assert_eq!(header.len(), 1);
    let (problems, paths) = check_sample::<SegmentLine>("resumed header", header[0]);
    assert_no_problems(&problems);
    for path in [
        "line",
        "header.opening.reason",
        "header.opening.finding.kind",
    ] {
        assert!(
            paths.iter().any(|checked| checked == path),
            "{path}: {paths:?}"
        );
    }
}
