//! What a grid says back. One shape for every command, read or write, rehearsed or committed.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A grid as a person refers to it. The name is what the admin typed; the handle is the short
/// word `--grid` takes; the id belongs to JSON.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Named {
    pub id: String,
    /// The company name the admin typed.
    pub name: String,
    /// The short word a person types for `--grid`.
    pub handle: String,
    /// `primary` or `research`, the two words the core's own realm kinds use.
    pub kind: String,
    /// What this grid does, in the core's own words: models, workspaces, credentials, research.
    pub does: Vec<String>,
    /// `open`, `paused`, `closing` or `gone`.
    pub lifecycle: String,
    /// Which door answered: `product` while a product still holds its own hub, `core` once it
    /// has moved onto Grid Core.
    pub served_by: String,
    /// Whether this computer runs the grid's hub or only belongs to it.
    pub role: String,
}

/// What a change did, or what a rehearsal says it would do.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Change {
    /// What kind of thing: a person, a model plan, a desk, a credential.
    pub what: String,
    /// Added, changed, removed, and so on.
    pub how: String,
    /// The memorable name, never an identifier, when the thing has one.
    pub which: String,
    /// One clause of detail, or empty.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
}

impl Change {
    pub fn new(what: &str, how: &str, which: impl Into<String>) -> Change {
        Change { what: what.to_owned(), how: how.to_owned(), which: which.into(), detail: String::new() }
    }
    pub fn detail(mut self, detail: impl Into<String>) -> Change {
        self.detail = detail.into();
        self
    }
}

/// One answer. There is no second shape and no bag of loose fields.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Answer {
    /// Which grid answered, when the command was about one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grid: Option<Named>,
    /// This command's own name, which every event it causes carries.
    pub command: String,
    /// What a person is told. One sentence, no identifiers, no code.
    pub said: String,
    /// What changed, or what a rehearsal says would change.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub changed: Vec<Change>,
    /// True when nothing was written because this was a rehearsal.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub rehearsed: bool,
    /// The audit events this command caused, by sequence. A grid whose record does not yet carry
    /// command names reports none, and says so rather than implying it caused nothing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recorded: Vec<u64>,
    /// Whether this grid's record ties its events to the command that caused them.
    pub correlated: bool,
    /// What the command found, for a read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub found: Option<Value>,
    /// The obvious next step, in words, when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
}

impl Answer {
    pub fn new(command: &str, said: impl Into<String>) -> Answer {
        Answer {
            grid: None,
            command: command.to_owned(),
            said: said.into(),
            changed: Vec::new(),
            rehearsed: false,
            recorded: Vec::new(),
            correlated: false,
            found: None,
            next: None,
        }
    }
    pub fn about(mut self, grid: Named) -> Answer {
        self.grid = Some(grid);
        self
    }
    pub fn found(mut self, found: Value) -> Answer {
        self.found = Some(found);
        self
    }
    pub fn next(mut self, next: impl Into<String>) -> Answer {
        self.next = Some(next.into());
        self
    }
    pub fn changed(mut self, changed: Vec<Change>) -> Answer {
        self.changed = changed;
        self
    }
    pub fn rehearsed(mut self) -> Answer {
        self.rehearsed = true;
        self
    }
}
