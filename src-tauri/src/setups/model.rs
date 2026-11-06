//! The records the engine keeps for each setup. None of them holds a credential value: a setup
//! carries secret references only, and realm data stays in each realm's own store.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use yougori_setup::{dto::SourceRef, resource::Kind};

/// Where a setup is in its life, separate from how its last operation went.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Lifecycle {
    Draft,
    Creating,
    Running,
    Stopped,
    Updating,
    Removing,
    Retained,
    Removed,
}

/// How a setup is doing, from the last real observation of its resources.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Health {
    Unknown,
    Ready,
    Starting,
    NeedsSignIn,
    WaitingForComputer,
    Degraded,
    Failed,
    Unsupported,
}

/// What the setup wants a resource to be.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Desired {
    Running,
    Stopped,
    Absent,
}

/// What the resource was found to be the last time it was looked at.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Observed {
    Unknown,
    Missing,
    Present,
    Running,
    Stopped,
}

/// What a resource costs while it exists. Zero is never assumed without evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Cost {
    /// Runs on this computer or another free resource.
    Free,
    Unknown,
    Accruing,
    /// Asked to stop charging, and the provider confirmed it.
    Stopped,
    /// Asked to stop charging, but the provider could not confirm it.
    ShutdownUnconfirmed,
}

/// The resource of another setup that a borrowing resource points at.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct OwnerRef {
    pub setup: String,
    pub resource: String,
}

/// A setup that borrows one of this setup's resources.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Borrower {
    pub setup: String,
    pub resource: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Resource {
    /// The logical ID from the template, unique inside its setup.
    pub id: String,
    pub kind: Kind,
    /// Resources of the same setup this one needs. Stopping and removing go in reverse.
    pub depends_on: Vec<String>,
    /// The provider's own ID once the resource exists.
    pub runtime_id: Option<String>,
    /// `None` when this setup owns the resource. A borrowed resource is never stopped or removed
    /// by this setup; detaching only drops this setup's binding to it.
    pub owner: Option<OwnerRef>,
    pub borrowers: Vec<Borrower>,
    /// Goes up every time the resource is created again, so a replayed step for an older
    /// generation can never bring a removed resource back.
    pub generation: u64,
    pub desired: Desired,
    pub observed: Observed,
    pub retained_data: bool,
    pub cost: Cost,
    pub last_observed_at: Option<String>,
    /// Why the observed resource no longer matches what the setup wants.
    pub drift: Option<String>,
    /// The safe, reference-only specification the resource was last applied with.
    pub spec: Value,
    pub spec_digest: String,
}

impl Resource {
    pub(crate) fn borrowed(&self) -> bool {
        self.owner.is_some()
    }
}

/// Where the setup came from: a Hub item or a local package, pinned to one exact version and
/// package digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Source {
    pub reference: SourceRef,
    pub digest: String,
}

impl Source {
    pub(crate) fn version(&self) -> String {
        match &self.reference {
            SourceRef::Hub { version, .. } => version.clone(),
            _ => String::new(),
        }
    }
}

/// The setup-level part of a reviewed plan: what the setup's own record becomes once the
/// operation completes. A new setup gets it at once; an update only when it has fully applied,
/// so the old version stays pinned until then.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct InstanceChange {
    pub name: String,
    pub source: Source,
    pub format_version: u32,
    pub protocol_version: u32,
    pub lock_digest: Option<String>,
    pub answers: BTreeMap<String, Value>,
    pub capabilities: Vec<String>,
    /// Secret question to the name of the binding that holds its value. Never a value.
    #[serde(default)]
    pub secret_bindings: BTreeMap<String, String>,
    /// What the plan resolved (`yougori_setup::lock::Lock`): the template and every component's
    /// item, version and digest, the capabilities on and the resource graph. Never a secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lock: Option<Value>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct HistoryEntry {
    pub at: String,
    pub operation: String,
    pub change: String,
    pub source_version: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Instance {
    pub id: String,
    pub name: String,
    pub source: Source,
    pub format_version: u32,
    pub protocol_version: u32,
    pub lock_digest: Option<String>,
    /// The configuration the setup was last asked to have.
    pub config_revision: u64,
    /// Every committed change moves this on. A plan reviewed against an older revision is
    /// refused instead of being applied over someone else's change.
    pub revision: u64,
    /// Public answers only. Private answers and secret references live elsewhere.
    pub answers: BTreeMap<String, Value>,
    /// Secret question to the name of the binding that holds its value. Never a value.
    #[serde(default)]
    pub secret_bindings: BTreeMap<String, String>,
    /// The lock of the plan the setup was last applied from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lock: Option<Value>,
    pub customizations: BTreeMap<String, Value>,
    pub capabilities: Vec<String>,
    pub realms: Vec<String>,
    pub storage: Option<String>,
    pub outputs: BTreeMap<String, String>,
    /// The operation holding this setup. It stays set while that operation is running or its
    /// outcome is unknown, so a restart keeps the claim.
    pub current_operation: Option<String>,
    pub lifecycle: Lifecycle,
    pub health: Health,
    pub history: Vec<HistoryEntry>,
    pub resources: BTreeMap<String, Resource>,
    pub created_at: String,
    pub updated_at: String,
}

/// What is left of a removed resource or setup: enough to refuse an old plan or operation that
/// would bring it back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Tombstone {
    pub generation: u64,
    pub operation: String,
    pub at: String,
}

/// A plain explanation with a stable code. Every refusal and failure the engine reports has
/// one, and none of them carries a credential, URL or raw provider error.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Diagnostic {
    pub code: String,
    pub message: String,
    pub retryable: bool,
    /// The question or file the problem is about, such as `inputs.port`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub next: Vec<String>,
}

impl Diagnostic {
    pub(crate) fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: crate::lifecycle::safe_diagnostic(&message.into()),
            retryable: false,
            field: None,
            resource: None,
            step: None,
            operation: None,
            next: Vec::new(),
        }
    }
    pub(crate) fn retryable(mut self) -> Self {
        self.retryable = true;
        self
    }
    pub(crate) fn at(mut self, field: &str) -> Self {
        self.field = Some(field.into());
        self
    }
    pub(crate) fn resource(mut self, id: &str) -> Self {
        self.resource = Some(id.into());
        self
    }
    pub(crate) fn step(mut self, id: &str) -> Self {
        self.step = Some(id.into());
        self
    }
    pub(crate) fn operation(mut self, id: &str) -> Self {
        self.operation = Some(id.into());
        self
    }
    pub(crate) fn next(mut self, actions: &[&str]) -> Self {
        self.next = actions.iter().map(|action| (*action).to_owned()).collect();
        self
    }
}

impl std::fmt::Display for Diagnostic {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

pub(crate) fn now() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// `setup-<uuid>`, `op-<uuid>` and the like: only IDs the engine itself could have made.
pub(crate) fn valid_id(value: &str, prefix: &str) -> bool {
    value
        .strip_prefix(prefix)
        .is_some_and(|id| uuid::Uuid::parse_str(id).is_ok())
}

pub(crate) fn new_id(prefix: &str) -> String {
    format!("{prefix}{}", uuid::Uuid::new_v4())
}

/// A template's logical resource ID: short, lowercase, and safe in a provider label.
/// A resource ID, or a component's resource under its namespace (`NAMESPACE.ID`, as the planner
/// flattens a pinned component).
pub(crate) fn valid_resource_id(value: &str) -> bool {
    let part = |part: &str| {
        !part.is_empty()
            && part.len() <= 64
            && part.as_bytes()[0].is_ascii_lowercase()
            && part.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
    };
    match value.split_once('.') {
        None => part(value),
        Some((namespace, id)) => part(namespace) && part(id),
    }
}

/// Field names that only ever hold a credential. A plan or specification that carries one with a
/// plain value is refused: setups keep secret references, never the secrets.
const CREDENTIAL_FIELDS: [&str; 14] = [
    "password",
    "passphrase",
    "secret",
    "token",
    "apikey",
    "api_key",
    "accesstoken",
    "access_token",
    "refreshtoken",
    "refresh_token",
    "clientsecret",
    "client_secret",
    "privatekey",
    "private_key",
];

/// The first path in `value` that holds what looks like a credential value. A `secrets` map and
/// a `{{secrets.ID}}` placeholder hold binding names, which is what a plan is meant to carry.
pub(crate) fn credential_field(value: &Value) -> Option<String> {
    fn reference(text: &str) -> bool {
        let text = text.trim();
        text.starts_with("{{") && text.ends_with("}}") && text.trim_matches(['{', '}', ' ']).starts_with("secrets.")
    }
    fn walk(value: &Value, path: &str) -> Option<String> {
        match value {
            Value::Object(map) => map.iter().find_map(|(key, inner)| {
                let lower = key.to_ascii_lowercase().replace('-', "_");
                let plain = lower.replace('_', "");
                let here = if path.is_empty() { key.clone() } else { format!("{path}.{key}") };
                if lower == "secrets" {
                    return None;
                }
                if (CREDENTIAL_FIELDS.contains(&lower.as_str()) || CREDENTIAL_FIELDS.contains(&plain.as_str()))
                    && matches!(inner, Value::String(text) if !text.is_empty() && !reference(text))
                {
                    return Some(here);
                }
                walk(inner, &here)
            }),
            Value::Array(items) => items
                .iter()
                .enumerate()
                .find_map(|(index, inner)| walk(inner, &format!("{path}[{index}]"))),
            _ => None,
        }
    }
    walk(value, "")
}

/// A stable digest of a JSON value: keys sorted, no whitespace.
pub(crate) fn digest(value: &impl Serialize) -> String {
    use sha2::{Digest, Sha256};
    // Another crate in the build may switch serde_json to insertion order, so keys are sorted
    // here rather than trusting the map's own order.
    fn canonical(value: &Value, out: &mut String) {
        match value {
            Value::Object(map) => {
                let mut keys = map.keys().collect::<Vec<_>>();
                keys.sort();
                out.push('{');
                for (index, key) in keys.into_iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    out.push_str(&Value::String(key.clone()).to_string());
                    out.push(':');
                    canonical(&map[key], out);
                }
                out.push('}');
            }
            Value::Array(items) => {
                out.push('[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    canonical(item, out);
                }
                out.push(']');
            }
            other => out.push_str(&other.to_string()),
        }
    }
    let mut text = String::new();
    canonical(&serde_json::to_value(value).unwrap_or(Value::Null), &mut text);
    format!("sha256:{}", hex::encode(Sha256::digest(text.as_bytes())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn credential_values_are_found_but_references_are_not() {
        assert_eq!(credential_field(&json!({"db": {"password": "hunter2"}})).as_deref(), Some("db.password"));
        assert_eq!(credential_field(&json!({"items": [{"API-Key": "x"}]})).as_deref(), Some("items[0].API-Key"));
        assert_eq!(credential_field(&json!({"db": {"password": {"secretRef": "db-password"}}})), None);
        assert_eq!(credential_field(&json!({"tokenRef": "github"})), None);
        assert_eq!(credential_field(&json!({"password": ""})), None);
        // What the planner writes: binding names under `secrets`, and placeholders.
        assert_eq!(credential_field(&json!({"secrets": {"API_KEY": "hub-site-key-openai", "password": "db-password"}})), None);
        assert_eq!(credential_field(&json!({"admin": {"password": "{{ secrets.admin }}"}})), None);
        assert_eq!(credential_field(&json!({"admin": {"password": "{{secrets.admin}} and more"}})).as_deref(), Some("admin.password"));
    }

    #[test]
    fn digests_ignore_key_order() {
        assert_eq!(digest(&json!({"a": 1, "b": [1, 2]})), digest(&json!({"b": [1, 2], "a": 1})));
        assert_ne!(digest(&json!({"a": 1})), digest(&json!({"a": 2})));
    }
}
