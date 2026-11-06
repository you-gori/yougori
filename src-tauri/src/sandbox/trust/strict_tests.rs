//! The trust state as the store keeps it, read with a number for a variant name or with a
//! field written twice (`foundation::strict_serde`; the S06 item "Strict tags of read-back
//! tagged enums" of docs/combined-plan-leftover-tasks.md). The state holds no internally or
//! adjacently tagged enum, the one form serde reads a number for once it has buffered a
//! record, so its line is read straight from JSON and nothing here goes through
//! `strict_serde`: a number for a plain enum, as a value or as a map key, and a struct
//! field written twice are refused as they always were. A key written twice inside one of
//! the state's maps, or inside a signed payload, is read as serde reads maps, keeping the
//! last value; this test does not write one.

use std::path::Path;

use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

use super::tests::Fixture;
use super::{StoreRefusal, TrustStore, TrustStoreConfig};
use crate::foundation::events::{
    DurableLog, DurableStreamId, LineProblem, LogConfig, LogDamage, LogError, ProducerId,
};

/// A JSON document, written with the field `key` of the object at the path `object` twice,
/// both times with its value, when it names one: a form `serde_json::Value` cannot hold.
#[derive(Clone, Debug)]
struct Document {
    value: Value,
    repeated: Option<(Vec<String>, String)>,
}

impl Document {
    fn new(value: Value) -> Self {
        Self {
            value,
            repeated: None,
        }
    }

    fn repeating(value: &Value, object: &[&str], key: &str) -> Self {
        Self {
            value: value.clone(),
            repeated: Some((
                object.iter().map(|name| (*name).to_owned()).collect(),
                key.to_owned(),
            )),
        }
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
    repeated: Option<(&'a [String], &'a str)>,
}

impl Serialize for Part<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let (Value::Object(fields), Some((object, key))) = (self.value, self.repeated) else {
            return self.value.serialize(serializer);
        };
        let mut map = serializer.serialize_map(None)?;
        for (name, field) in fields {
            match object.split_first() {
                None => {
                    map.serialize_entry(name, field)?;
                    if name == key {
                        map.serialize_entry(name, field)?;
                    }
                }
                Some((next, rest)) => {
                    let repeated = (name == next).then_some((rest, key));
                    map.serialize_entry(
                        name,
                        &Part {
                            value: field,
                            repeated,
                        },
                    )?;
                }
            }
        }
        map.end()
    }
}

fn config(directory: &Path) -> TrustStoreConfig {
    TrustStoreConfig {
        directory: directory.to_path_buf(),
        stream: DurableStreamId::new("sandbox.update-trust").unwrap(),
        owner: ProducerId::new("engine.update-trust").unwrap(),
        log: LogConfig {
            max_entries: 1_000,
            max_bytes: 1 << 24,
            segment_entries: 64,
            segment_bytes: 1 << 20,
        },
    }
}

/// Keeps `document` as the only state of a new store and opens the store: the state it
/// reads back, as JSON.
fn kept(document: &Document) -> Result<Option<Value>, StoreRefusal> {
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path());
    let (mut log, _) = DurableLog::<Document>::open(
        &config.directory,
        config.stream.clone(),
        config.owner.clone(),
        config.log,
    )
    .unwrap();
    log.append(document.clone()).unwrap();
    log.close().unwrap();
    TrustStore::open(&config).map(|(store, state, _)| {
        store.close().unwrap();
        state.map(|state| serde_json::to_value(state).unwrap())
    })
}

/// Whether the store refuses `document` as a line that does not decode.
fn refused(document: &Document) -> bool {
    matches!(
        kept(document),
        Err(StoreRefusal::Log(LogError::Damaged(LogDamage::Line {
            problem: LineProblem::Encoding,
            ..
        })))
    )
}

#[test]
fn a_kept_state_with_a_number_for_a_variant_or_a_field_written_twice_is_refused() {
    let state = serde_json::to_value(Fixture::new().loaded().state()).unwrap();
    assert_eq!(kept(&Document::new(state.clone())), Ok(Some(state.clone())));

    // The profile by its index: production is the first.
    assert_eq!(state["profile"], "production");
    let mut by_index = state.clone();
    by_index["profile"] = Value::from(0);
    assert!(refused(&Document::new(by_index)));
    // A role by its index as the key of the versions trusted and of the floors: the root
    // is the first role.
    for map in ["trusted", "floors"] {
        let mut by_index = state.clone();
        let roles = by_index[map].as_object_mut().unwrap();
        let root = roles.remove("root").unwrap();
        roles.insert("0".to_owned(), root);
        assert!(refused(&Document::new(by_index)), "{map}");
    }
    // Each field of the state, and of a role's record, written twice.
    for key in state.as_object().unwrap().keys() {
        assert!(refused(&Document::repeating(&state, &[], key)), "{key}");
    }
    assert!(refused(&Document::repeating(
        &state,
        &["trusted", "root"],
        "version"
    )));
}
