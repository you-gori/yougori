//! Tool parameter schemas, limited to the JSON Schema keywords this module can check
//! (S9 line 167: tool execution requires the validated complete payload; S7 line 127:
//! schema validity conditional on a triggered call).
//!
//! A schema that uses any other validation keyword, such as `$ref` or `pattern`, is
//! refused when the tool is declared: a call against it could not be validated, so it
//! could never be executed. Annotation keywords (`description`, `title`, `default`,
//! `examples`, `format`, `$schema`, `$comment`, `deprecated`, `readOnly`, `writeOnly`)
//! are accepted and do not constrain.

use std::collections::BTreeMap;
use std::fmt;

use serde_json::{Map, Value};

const ANNOTATIONS: [&str; 10] = [
    "description",
    "title",
    "default",
    "examples",
    "format",
    "$schema",
    "$comment",
    "deprecated",
    "readOnly",
    "writeOnly",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JsonType {
    Object,
    Array,
    String,
    Number,
    Integer,
    Boolean,
    Null,
}

impl JsonType {
    fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "object" => Self::Object,
            "array" => Self::Array,
            "string" => Self::String,
            "number" => Self::Number,
            "integer" => Self::Integer,
            "boolean" => Self::Boolean,
            "null" => Self::Null,
            _ => return None,
        })
    }

    fn matches(self, value: &Value) -> bool {
        match (self, value) {
            (Self::Object, Value::Object(_))
            | (Self::Array, Value::Array(_))
            | (Self::String, Value::String(_))
            | (Self::Number, Value::Number(_))
            | (Self::Boolean, Value::Bool(_))
            | (Self::Null, Value::Null) => true,
            (Self::Integer, Value::Number(number)) => {
                number.is_i64()
                    || number.is_u64()
                    || number
                        .as_f64()
                        .is_some_and(|n| n.is_finite() && n.fract() == 0.0)
            }
            _ => false,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
enum Node {
    Accept,
    Reject,
    Rules(Box<Rules>),
}

#[derive(Clone, Debug, Default, PartialEq)]
struct Rules {
    types: Option<Vec<JsonType>>,
    properties: BTreeMap<String, Node>,
    required: Vec<String>,
    additional: Option<Node>,
    items: Option<Node>,
    allowed: Option<Vec<Value>>,
    constant: Option<Value>,
    any_of: Vec<Node>,
    one_of: Vec<Node>,
    all_of: Vec<Node>,
    minimum: Option<f64>,
    maximum: Option<f64>,
    exclusive_minimum: Option<f64>,
    exclusive_maximum: Option<f64>,
    min_length: Option<u64>,
    max_length: Option<u64>,
    min_items: Option<u64>,
    max_items: Option<u64>,
}

/// Why a declared schema was refused (S9 line 167).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SchemaError {
    /// A tool's parameters must be an object schema.
    RootNotObject,
    /// Something in a schema position is neither an object nor a boolean.
    NotASchema { path: String },
    /// A validation keyword outside the supported set.
    UnsupportedKeyword { path: String, keyword: String },
    /// A supported keyword with a value of the wrong shape.
    InvalidKeyword { path: String, keyword: String },
}

impl fmt::Display for SchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RootNotObject => f.write_str("the parameters schema is not of type object"),
            Self::NotASchema { path } => write!(f, "{path} is not a schema"),
            Self::UnsupportedKeyword { path, keyword } => {
                write!(f, "{path}: keyword {keyword:?} cannot be validated")
            }
            Self::InvalidKeyword { path, keyword } => {
                write!(f, "{path}: keyword {keyword:?} has an invalid value")
            }
        }
    }
}

impl std::error::Error for SchemaError {}

/// Where and why arguments failed their schema (S7 line 127 schema validity).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchemaViolation {
    /// A JSON path such as `$.path` or `$.items[2]`.
    pub path: String,
    pub detail: String,
}

impl fmt::Display for SchemaViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path, self.detail)
    }
}

/// A tool's checked parameter schema (S9 line 167).
#[derive(Clone, Debug, PartialEq)]
pub struct ToolSchema {
    root: Node,
}

impl ToolSchema {
    /// Accepts an object schema built only from supported keywords.
    pub fn parse(schema: &Value) -> Result<Self, SchemaError> {
        let root = parse_node(schema, "$")?;
        match &root {
            Node::Rules(rules) if rules.types.as_deref() == Some(&[JsonType::Object]) => {
                Ok(Self { root })
            }
            _ => Err(SchemaError::RootNotObject),
        }
    }

    /// An object schema with no constraints, for a tool declared without parameters.
    pub fn empty_object() -> Self {
        Self {
            root: Node::Rules(Box::new(Rules {
                types: Some(vec![JsonType::Object]),
                ..Rules::default()
            })),
        }
    }

    /// Checks complete arguments against the schema.
    pub fn validate(&self, value: &Value) -> Result<(), SchemaViolation> {
        check(&self.root, value, "$")
    }
}

fn invalid(path: &str, keyword: &str) -> SchemaError {
    SchemaError::InvalidKeyword {
        path: path.to_owned(),
        keyword: keyword.to_owned(),
    }
}

fn parse_node(schema: &Value, path: &str) -> Result<Node, SchemaError> {
    match schema {
        Value::Bool(true) => Ok(Node::Accept),
        Value::Bool(false) => Ok(Node::Reject),
        Value::Object(map) => parse_rules(map, path).map(|rules| Node::Rules(Box::new(rules))),
        _ => Err(SchemaError::NotASchema {
            path: path.to_owned(),
        }),
    }
}

fn parse_rules(map: &Map<String, Value>, path: &str) -> Result<Rules, SchemaError> {
    let mut rules = Rules::default();
    for (keyword, value) in map {
        let keyword = keyword.as_str();
        match keyword {
            "type" => rules.types = Some(parse_types(value, path)?),
            "properties" => {
                let properties = value.as_object().ok_or_else(|| invalid(path, keyword))?;
                for (name, schema) in properties {
                    let node = parse_node(schema, &format!("{path}.{name}"))?;
                    rules.properties.insert(name.clone(), node);
                }
            }
            "required" => {
                let names = value.as_array().ok_or_else(|| invalid(path, keyword))?;
                for name in names {
                    let name = name.as_str().ok_or_else(|| invalid(path, keyword))?;
                    rules.required.push(name.to_owned());
                }
            }
            "additionalProperties" => {
                rules.additional = Some(parse_node(value, &format!("{path}.*"))?)
            }
            "items" => rules.items = Some(parse_node(value, &format!("{path}[]"))?),
            "enum" => {
                let values = value.as_array().ok_or_else(|| invalid(path, keyword))?;
                if values.is_empty() {
                    return Err(invalid(path, keyword));
                }
                rules.allowed = Some(values.clone());
            }
            "const" => rules.constant = Some(value.clone()),
            "anyOf" | "oneOf" | "allOf" => {
                let branches = value.as_array().ok_or_else(|| invalid(path, keyword))?;
                if branches.is_empty() {
                    return Err(invalid(path, keyword));
                }
                let nodes = branches
                    .iter()
                    .enumerate()
                    .map(|(index, branch)| parse_node(branch, &format!("{path}/{keyword}/{index}")))
                    .collect::<Result<Vec<_>, _>>()?;
                match keyword {
                    "anyOf" => rules.any_of = nodes,
                    "oneOf" => rules.one_of = nodes,
                    _ => rules.all_of = nodes,
                }
            }
            "minimum" | "maximum" | "exclusiveMinimum" | "exclusiveMaximum" => {
                let bound = value.as_f64().ok_or_else(|| invalid(path, keyword))?;
                let slot = match keyword {
                    "minimum" => &mut rules.minimum,
                    "maximum" => &mut rules.maximum,
                    "exclusiveMinimum" => &mut rules.exclusive_minimum,
                    _ => &mut rules.exclusive_maximum,
                };
                *slot = Some(bound);
            }
            "minLength" | "maxLength" | "minItems" | "maxItems" => {
                let bound = value.as_u64().ok_or_else(|| invalid(path, keyword))?;
                let slot = match keyword {
                    "minLength" => &mut rules.min_length,
                    "maxLength" => &mut rules.max_length,
                    "minItems" => &mut rules.min_items,
                    _ => &mut rules.max_items,
                };
                *slot = Some(bound);
            }
            annotation if ANNOTATIONS.contains(&annotation) => {}
            other => {
                return Err(SchemaError::UnsupportedKeyword {
                    path: path.to_owned(),
                    keyword: other.to_owned(),
                })
            }
        }
    }
    Ok(rules)
}

fn parse_types(value: &Value, path: &str) -> Result<Vec<JsonType>, SchemaError> {
    let names: Vec<&Value> = match value {
        Value::Array(names) if !names.is_empty() => names.iter().collect(),
        Value::String(_) => vec![value],
        _ => return Err(invalid(path, "type")),
    };
    names
        .into_iter()
        .map(|name| {
            name.as_str()
                .and_then(JsonType::parse)
                .ok_or_else(|| invalid(path, "type"))
        })
        .collect()
}

fn fail(path: &str, detail: impl Into<String>) -> Result<(), SchemaViolation> {
    Err(SchemaViolation {
        path: path.to_owned(),
        detail: detail.into(),
    })
}

fn check(node: &Node, value: &Value, path: &str) -> Result<(), SchemaViolation> {
    let rules = match node {
        Node::Accept => return Ok(()),
        Node::Reject => return fail(path, "no value is allowed here"),
        Node::Rules(rules) => rules,
    };
    if let Some(types) = &rules.types {
        if !types.iter().any(|kind| kind.matches(value)) {
            return fail(path, format!("expected {types:?}, found {value}"));
        }
    }
    if let Some(allowed) = &rules.allowed {
        if !allowed.contains(value) {
            return fail(path, format!("{value} is not one of the allowed values"));
        }
    }
    if let Some(constant) = &rules.constant {
        if constant != value {
            return fail(path, format!("{value} is not {constant}"));
        }
    }
    match value {
        Value::Number(number) => check_number(rules, number.as_f64(), path)?,
        Value::String(text) => {
            let length = text.chars().count() as u64;
            check_bounds(length, rules.min_length, rules.max_length, "length", path)?;
        }
        Value::Array(items) => {
            check_bounds(
                items.len() as u64,
                rules.min_items,
                rules.max_items,
                "item count",
                path,
            )?;
            if let Some(schema) = &rules.items {
                for (index, item) in items.iter().enumerate() {
                    check(schema, item, &format!("{path}[{index}]"))?;
                }
            }
        }
        Value::Object(object) => check_object(rules, object, path)?,
        Value::Bool(_) | Value::Null => {}
    }
    for branch in &rules.all_of {
        check(branch, value, path)?;
    }
    if !rules.any_of.is_empty()
        && !rules
            .any_of
            .iter()
            .any(|branch| check(branch, value, path).is_ok())
    {
        return fail(path, "matches none of anyOf");
    }
    if !rules.one_of.is_empty() {
        let matching = rules
            .one_of
            .iter()
            .filter(|branch| check(branch, value, path).is_ok())
            .count();
        if matching != 1 {
            return fail(
                path,
                format!("matches {matching} branches of oneOf, not exactly 1"),
            );
        }
    }
    Ok(())
}

fn check_number(rules: &Rules, number: Option<f64>, path: &str) -> Result<(), SchemaViolation> {
    let Some(number) = number else {
        return fail(path, "a number outside the comparable range");
    };
    let checks = [
        (
            rules.minimum,
            number >= rules.minimum.unwrap_or(f64::NEG_INFINITY),
            "minimum",
        ),
        (
            rules.maximum,
            number <= rules.maximum.unwrap_or(f64::INFINITY),
            "maximum",
        ),
        (
            rules.exclusive_minimum,
            number > rules.exclusive_minimum.unwrap_or(f64::NEG_INFINITY),
            "exclusiveMinimum",
        ),
        (
            rules.exclusive_maximum,
            number < rules.exclusive_maximum.unwrap_or(f64::INFINITY),
            "exclusiveMaximum",
        ),
    ];
    for (bound, holds, name) in checks {
        if let (Some(bound), false) = (bound, holds) {
            return fail(path, format!("{number} breaks {name} {bound}"));
        }
    }
    Ok(())
}

fn check_bounds(
    count: u64,
    minimum: Option<u64>,
    maximum: Option<u64>,
    what: &str,
    path: &str,
) -> Result<(), SchemaViolation> {
    if minimum.is_some_and(|minimum| count < minimum)
        || maximum.is_some_and(|maximum| count > maximum)
    {
        return fail(
            path,
            format!("{what} {count} is outside [{minimum:?}, {maximum:?}]"),
        );
    }
    Ok(())
}

fn check_object(
    rules: &Rules,
    object: &Map<String, Value>,
    path: &str,
) -> Result<(), SchemaViolation> {
    for name in &rules.required {
        if !object.contains_key(name) {
            return fail(path, format!("required property {name:?} is missing"));
        }
    }
    for (name, value) in object {
        let property_path = format!("{path}.{name}");
        match (rules.properties.get(name), &rules.additional) {
            (Some(schema), _) => check(schema, value, &property_path)?,
            (None, Some(additional)) => check(additional, value, &property_path)?,
            (None, None) => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn path_schema() -> ToolSchema {
        ToolSchema::parse(&json!({
            "type": "object",
            "description": "synthetic",
            "properties": {
                "path": {"type": "string", "minLength": 1},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100},
                "mode": {"enum": ["read", "list"]},
                "tags": {"type": "array", "items": {"type": "string"}, "maxItems": 2},
                "note": {"anyOf": [{"type": "string"}, {"type": "null"}]}
            },
            "required": ["path"],
            "additionalProperties": false
        }))
        .unwrap()
    }

    #[test]
    fn valid_arguments_pass() {
        let schema = path_schema();
        assert_eq!(schema.validate(&json!({"path": "src/lib.rs"})), Ok(()));
        let full = json!({"path": "a", "limit": 1.0, "mode": "list", "tags": ["x"], "note": null});
        assert_eq!(schema.validate(&full), Ok(()));
        assert_eq!(
            ToolSchema::empty_object().validate(&json!({"any": [1]})),
            Ok(())
        );
    }

    #[test]
    fn invalid_arguments_name_the_path() {
        let schema = path_schema();
        let cases = [
            (json!({}), "$"),
            (json!({"path": "a", "extra": 1}), "$.extra"),
            (json!({"path": 3}), "$.path"),
            (json!({"path": ""}), "$.path"),
            (json!({"path": "a", "limit": 1.5}), "$.limit"),
            (json!({"path": "a", "limit": 101}), "$.limit"),
            (json!({"path": "a", "mode": "write"}), "$.mode"),
            (json!({"path": "a", "tags": ["x", 2]}), "$.tags[1]"),
            (json!({"path": "a", "tags": ["x", "y", "z"]}), "$.tags"),
            (json!({"path": "a", "note": 4}), "$.note"),
            (json!(["path"]), "$"),
        ];
        for (arguments, path) in cases {
            let violation = schema.validate(&arguments).unwrap_err();
            assert_eq!(violation.path, path, "{arguments}");
        }
    }

    #[test]
    fn one_of_needs_exactly_one_branch() {
        let schema = ToolSchema::parse(&json!({
            "type": "object",
            "properties": {"n": {"oneOf": [{"type": "integer"}, {"type": "number"}]}}
        }))
        .unwrap();
        // 2 is both an integer and a number, so it matches two branches.
        assert!(schema.validate(&json!({"n": 2})).is_err());
        assert_eq!(schema.validate(&json!({"n": 2.5})), Ok(()));
    }

    #[test]
    fn schemas_that_cannot_be_checked_are_refused() {
        assert_eq!(
            ToolSchema::parse(&json!({"type": "object", "properties": {"p": {"$ref": "#/x"}}})),
            Err(SchemaError::UnsupportedKeyword {
                path: "$.p".to_owned(),
                keyword: "$ref".to_owned()
            })
        );
        assert!(matches!(
            ToolSchema::parse(
                &json!({"type": "object", "properties": {"p": {"type": "string", "pattern": "^a"}}})
            ),
            Err(SchemaError::UnsupportedKeyword { .. })
        ));
        assert_eq!(
            ToolSchema::parse(&json!({"type": "string"})),
            Err(SchemaError::RootNotObject)
        );
        assert_eq!(
            ToolSchema::parse(&json!({"properties": {}})),
            Err(SchemaError::RootNotObject)
        );
        assert!(matches!(
            ToolSchema::parse(&json!({"type": "object", "required": "path"})),
            Err(SchemaError::InvalidKeyword { .. })
        ));
        assert!(matches!(
            ToolSchema::parse(&json!({"type": "object", "properties": {"p": 3}})),
            Err(SchemaError::NotASchema { .. })
        ));
        assert!(matches!(
            ToolSchema::parse(&json!({"type": "objekt"})),
            Err(SchemaError::InvalidKeyword { .. })
        ));
    }
}
