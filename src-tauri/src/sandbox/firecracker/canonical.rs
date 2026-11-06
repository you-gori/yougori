//! Canonical JSON for API plans and golden files: object keys sorted by their bytes, no
//! insignificant whitespace, scalars and strings written as `serde_json` writes them. The
//! output does not depend on the map ordering `serde_json` was built with, so the same
//! plan gives the same bytes, and the same digest, in every build (VM-CP-02 line 3152:
//! a golden file is compared, so its text must be reproducible).

use serde_json::Value;

/// The canonical text of `value`.
pub fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write_value(value, &mut out);
    out
}

fn write_value(value: &Value, out: &mut String) {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|left, right| left.0.cmp(right.0));
            out.push('{');
            for (index, (key, item)) in entries.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String(key.clone()).to_string());
                out.push(':');
                write_value(item, out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_value(item, out);
            }
            out.push(']');
        }
        scalar => out.push_str(&scalar.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn keys_are_sorted_at_every_depth_and_whitespace_is_dropped() {
        let value = json!({"b": 1, "a": {"z": [true, null, "x"], "c": "q\"uote"}, "aa": -2});
        assert_eq!(
            canonical_json(&value),
            r#"{"a":{"c":"q\"uote","z":[true,null,"x"]},"aa":-2,"b":1}"#
        );
    }

    #[test]
    fn equal_values_give_equal_text_whatever_the_insertion_order() {
        let mut first = serde_json::Map::new();
        first.insert("x".to_owned(), json!(1));
        first.insert("y".to_owned(), json!(2));
        let mut second = serde_json::Map::new();
        second.insert("y".to_owned(), json!(2));
        second.insert("x".to_owned(), json!(1));
        assert_eq!(
            canonical_json(&Value::Object(first)),
            canonical_json(&Value::Object(second))
        );
        assert_eq!(canonical_json(&json!({})), "{}");
        assert_eq!(canonical_json(&json!([])), "[]");
        assert_eq!(canonical_json(&json!("a\nb")), "\"a\\nb\"");
    }
}
