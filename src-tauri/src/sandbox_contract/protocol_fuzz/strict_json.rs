//! What the two strict readers of durable host state share under the fuzzer (VM-W50):
//! whether an accepted JSON input denotes exactly the record the reader made of it, and
//! the edits a strict reader must refuse, an unknown member in any of its objects and a
//! value of another JSON type at any of its leaves.

use serde_json::{json, Value};

/// The member added to each object to see that a reader refuses it.
const UNKNOWN_MEMBER: &str = "protocol_fuzz_unknown";

/// Whether `input`, JSON a reader accepted, denotes exactly `written`, the record it made
/// of it written back: the same members with the same values, up to the spellings of one
/// value (hexadecimal digits in either case, a set's members in any order or repeated, and
/// a member that is null on one side and absent on the other). Anything else means the
/// reader ignored, defaulted or changed part of what it read.
pub(super) fn denotes(input: &Value, written: &Value) -> bool {
    match (input, written) {
        (Value::Object(given), Value::Object(kept)) => {
            given
                .keys()
                .chain(kept.keys())
                .all(|key| match (given.get(key), kept.get(key)) {
                    (Some(given), Some(kept)) => denotes(given, kept),
                    (Some(only), None) | (None, Some(only)) => only.is_null(),
                    (None, None) => true,
                })
        }
        (Value::Array(given), Value::Array(kept)) => {
            (given.len() == kept.len()
                && given
                    .iter()
                    .zip(kept)
                    .all(|(given, kept)| denotes(given, kept)))
                || (given
                    .iter()
                    .all(|given| kept.iter().any(|kept| denotes(given, kept)))
                    && kept
                        .iter()
                        .all(|kept| given.iter().any(|given| denotes(given, kept))))
        }
        (Value::String(given), Value::String(kept)) => {
            given == kept
                || (hexadecimal(given) && hexadecimal(kept) && given.eq_ignore_ascii_case(kept))
        }
        _ => input == written,
    }
}

fn hexadecimal(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// The JSON pointer of member `key` of the value at `parent`.
fn member(parent: &str, key: &str) -> String {
    format!("{parent}/{}", key.replace('~', "~0").replace('/', "~1"))
}

/// Collects the pointers of every object and every string, number and boolean in `value`,
/// outside the values of members named in `free`.
fn walk(
    value: &Value,
    pointer: &str,
    free: &[&str],
    objects: &mut Vec<String>,
    leaves: &mut Vec<String>,
) {
    match value {
        Value::Object(map) => {
            objects.push(pointer.to_owned());
            for (key, child) in map {
                if !free.contains(&key.as_str()) {
                    walk(child, &member(pointer, key), free, objects, leaves);
                }
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                walk(child, &format!("{pointer}/{index}"), free, objects, leaves);
            }
        }
        Value::String(_) | Value::Number(_) | Value::Bool(_) => leaves.push(pointer.to_owned()),
        Value::Null => {}
    }
}

/// A value of another JSON type for `leaf`: a string becomes a number that is no
/// enumeration's variant index (`0.5`; integers in place of tags are a finding of the
/// journal target), a number a string, and a boolean a string.
fn other_type(leaf: &Value) -> Value {
    match leaf {
        Value::String(_) => json!(0.5),
        Value::Number(_) => json!("7"),
        _ => json!("true"),
    }
}

/// Fails, naming the edit, unless `read` refuses `written` with an unknown member added to
/// any of its objects and with any of its leaves replaced by a value of another JSON type,
/// one edit at a time, outside the values of the members named in `free` (JSON a record
/// keeps as it was given, by design).
pub(super) fn refuses_edits<T>(
    written: &Value,
    free: &[&str],
    read: impl Fn(&[u8]) -> Result<T, serde_json::Error>,
) -> Result<(), String> {
    let mut objects = Vec::new();
    let mut leaves = Vec::new();
    walk(written, "", free, &mut objects, &mut leaves);
    let refused = |edited: &Value| -> Result<bool, String> {
        let bytes = serde_json::to_vec(edited).map_err(|error| error.to_string())?;
        Ok(read(&bytes).is_err())
    };
    for pointer in objects {
        let mut edited = written.clone();
        if let Some(Value::Object(map)) = edited.pointer_mut(&pointer) {
            map.insert(UNKNOWN_MEMBER.to_owned(), json!(true));
        }
        ensure!(
            refused(&edited)?,
            "an unknown member in the object at {pointer:?} was accepted"
        );
    }
    for pointer in leaves {
        let mut edited = written.clone();
        let Some(slot) = edited.pointer_mut(&pointer) else {
            continue;
        };
        let replacement = other_type(slot);
        *slot = replacement.clone();
        ensure!(
            refused(&edited)?,
            "{replacement} in place of the value at {pointer:?} was accepted"
        );
    }
    Ok(())
}

/// The label of a refusal: serde_json's category, then the kind named by the first of
/// `kinds` whose text the message holds.
pub(super) fn refusal_label(error: &serde_json::Error, kinds: &[(&str, &str)]) -> String {
    let message = error.to_string();
    match kinds.iter().find(|(text, _)| message.contains(text)) {
        Some((_, kind)) => format!("refused:{:?}:{kind}", error.classify()),
        None => format!("refused:{:?}", error.classify()),
    }
}

#[test]
fn json_denotes_only_the_record_written_back() {
    let written = json!({"a": "ab12", "b": [1, 2], "c": null, "d": {"e": true}});
    assert!(denotes(&written, &written));
    assert!(denotes(
        &json!({"a": "AB12", "b": [2, 1, 2], "d": {"e": true}}),
        &written
    ));
    assert!(denotes(
        &json!({"a": "ab12", "b": [1, 2], "c": null, "d": {"e": true}, "g": null}),
        &written
    ));
    assert!(!denotes(
        &json!({"a": "ab12", "b": [1, 2], "c": null}),
        &written
    ));
    assert!(!denotes(
        &json!({"a": "ab12", "b": [1, 2], "c": null, "d": {"e": true}, "f": 1}),
        &written
    ));
    assert!(!denotes(
        &json!({"a": "ab13", "b": [1, 2], "c": null, "d": {"e": true}}),
        &written
    ));
    assert!(!denotes(
        &json!({"a": "ab12", "b": [1], "c": null, "d": {"e": 1}}),
        &written
    ));
    let mut objects = Vec::new();
    let mut leaves = Vec::new();
    walk(
        &json!({"x/y": {"z": 1}, "free": {"w": 2}, "list": ["s", null]}),
        "",
        &["free"],
        &mut objects,
        &mut leaves,
    );
    assert_eq!(objects, ["", "/x~1y"]);
    assert_eq!(leaves, ["/list/0", "/x~1y/z"]);
}
