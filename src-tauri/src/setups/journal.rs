//! The operation journal: what each setup operation intends, how far it got, and the receipt of
//! every effect it confirmed. Intent is saved before a step touches anything, and the receipt
//! right after, so a crash in between leaves a step whose outcome is known to be unknown.
use super::model::{now, Cost, Diagnostic, InstanceChange, Observed, OwnerRef};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use yougori_setup::resource::Kind;

/// Events kept per operation. Older ones are dropped and a reader that asks for them is told so.
pub(crate) const EVENT_LIMIT: usize = 200;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OperationState {
    Planned,
    AwaitingInput,
    Applying,
    Cancelling,
    Completed,
    Failed,
    Cancelled,
    /// A step may or may not have taken effect. Nothing more runs until it is reconciled.
    Unknown,
}

impl OperationState {
    pub(crate) fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::AwaitingInput => "awaiting_input",
            Self::Applying => "applying",
            Self::Cancelling => "cancelling",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OperationKind {
    Create,
    Update,
    Start,
    Stop,
    Remove,
    Repair,
}

impl OperationKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Update => "update",
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Remove => "remove",
            Self::Repair => "repair",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Action {
    Create,
    Update,
    Start,
    Stop,
    /// Bind this setup to a resource another setup owns. No handler is called and nothing is
    /// created: the engine records the borrower on the owner and copies the owner's runtime ID.
    Attach,
    /// Drop this setup's binding to a borrowed resource. The resource itself is not touched.
    Detach,
    Remove,
}

impl Action {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Update => "update",
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Attach => "attach",
            Self::Detach => "detach",
            Self::Remove => "remove",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StepState {
    Pending,
    /// Intent is saved and the handler may be acting right now.
    Applying,
    Done,
    Failed,
    Unknown,
    Cancelled,
}

/// What a confirmed effect left behind. Saved together with the resource's ownership record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Receipt {
    pub runtime_id: Option<String>,
    pub observed: Observed,
    pub retained_data: bool,
    pub cost: Cost,
    pub at: String,
    /// Found by reconciliation after an interruption rather than reported by the call itself.
    pub adopted: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Step {
    pub id: String,
    pub resource: String,
    pub kind: Kind,
    pub action: Action,
    /// Steps of this operation that must be done first.
    pub depends_on: Vec<String>,
    /// Resources of the same setup this resource needs, kept on its record.
    pub requires: Vec<String>,
    /// Reference-only specification; never a credential value.
    pub spec: Value,
    /// The resource generation this step works on (a create makes a new one).
    pub generation: u64,
    pub owner: Option<OwnerRef>,
    pub state: StepState,
    /// Scoped to operation, resource and action. Handlers label what they create with it, so
    /// reconciliation can find an effect whose receipt was never saved.
    pub idempotency_key: String,
    pub attempts: u32,
    pub receipt: Option<Receipt>,
    pub error: Option<Diagnostic>,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
}

pub(crate) fn step_key(operation: &str, resource: &str, action: Action) -> String {
    format!("{operation}/{resource}/{}", action.as_str())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Event {
    pub seq: u64,
    pub at: String,
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<String>,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Operation {
    /// Chosen by the client for each request, so a repeat of the request joins this operation
    /// instead of starting a second one.
    pub id: String,
    pub setup: String,
    pub kind: OperationKind,
    pub plan_digest: String,
    /// The planner's digest of the reviewed template plan, when there was one. A client that
    /// continues this operation may name either digest.
    pub source_digest: Option<String>,
    /// The setup revision the plan was reviewed against.
    pub base_revision: u64,
    /// The setup revision while this operation holds the setup.
    pub claimed_revision: u64,
    pub state: OperationState,
    pub steps: Vec<Step>,
    /// What the setup's own record becomes when this operation completes.
    pub change: Option<InstanceChange>,
    pub cancel_requested: bool,
    pub error: Option<Diagnostic>,
    pub created_at: String,
    pub updated_at: String,
    pub completed_at: Option<String>,
    pub events: Vec<Event>,
    pub next_seq: u64,
    /// What the person agreed to when applying (`copy_signin:RESOURCE/TOOL`). Never a secret.
    #[serde(default, skip_serializing_if = "std::collections::BTreeSet::is_empty")]
    pub consents: std::collections::BTreeSet<String>,
}

impl Operation {
    pub(crate) fn event(&mut self, step: Option<&str>, message: impl Into<String>) {
        let at = now();
        self.events.push(Event {
            seq: self.next_seq,
            at: at.clone(),
            state: self.state.as_str().into(),
            step: step.map(str::to_owned),
            message: crate::lifecycle::safe_diagnostic(&message.into()),
        });
        self.next_seq += 1;
        if self.events.len() > EVENT_LIMIT {
            let excess = self.events.len() - EVENT_LIMIT;
            self.events.drain(..excess);
        }
        self.updated_at = at;
    }

    pub(crate) fn set_state(&mut self, state: OperationState) {
        self.state = state;
        if state.is_terminal() {
            self.completed_at = Some(now());
        }
    }

    pub(crate) fn step_mut(&mut self, id: &str) -> Option<&mut Step> {
        self.steps.iter_mut().find(|step| step.id == id)
    }

    /// The next step that may run: pending, with every step it depends on done.
    pub(crate) fn runnable(&self) -> Option<&Step> {
        self.steps.iter().find(|step| {
            step.state == StepState::Pending
                && step.depends_on.iter().all(|dependency| {
                    self.steps
                        .iter()
                        .any(|other| &other.id == dependency && other.state == StepState::Done)
                })
        })
    }

    pub(crate) fn all_done(&self) -> bool {
        self.steps.iter().all(|step| step.state == StepState::Done)
    }

    pub(crate) fn has_unknown(&self) -> bool {
        self.steps.iter().any(|step| matches!(step.state, StepState::Unknown | StepState::Applying))
    }

    /// Events from `cursor` on. `gap` says events between the cursor and the first one returned
    /// were dropped; `next` is where the reader continues.
    pub(crate) fn events_from(&self, cursor: u64) -> Result<(Vec<Event>, u64, bool), Diagnostic> {
        if cursor > self.next_seq {
            return Err(Diagnostic::new(
                "invalid_cursor",
                "This progress position is ahead of the operation. Read again from the start.",
            )
            .operation(&self.id));
        }
        let first = self.events.first().map(|event| event.seq).unwrap_or(self.next_seq);
        let events = self
            .events
            .iter()
            .filter(|event| event.seq >= cursor)
            .cloned()
            .collect();
        Ok((events, self.next_seq, cursor < first))
    }
}

/// A client-chosen operation ID: short and plain, so it is safe in records and provider labels.
pub(crate) fn valid_operation_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".:_-".contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn operation() -> Operation {
        Operation {
            id: "op-1".into(),
            setup: "setup-1".into(),
            kind: OperationKind::Create,
            plan_digest: String::new(),
            source_digest: None,
            base_revision: 0,
            claimed_revision: 1,
            state: OperationState::Applying,
            steps: Vec::new(),
            change: None,
            cancel_requested: false,
            error: None,
            created_at: now(),
            updated_at: now(),
            completed_at: None,
            events: Vec::new(),
            next_seq: 0,
            consents: Default::default(),
        }
    }

    #[test]
    fn a_reader_behind_the_retained_events_is_told_about_the_gap() {
        let mut operation = operation();
        for index in 0..(EVENT_LIMIT + 5) {
            operation.event(None, format!("event {index}"));
        }
        let (events, next, gap) = operation.events_from(0).unwrap();
        assert!(gap);
        assert_eq!(events.len(), EVENT_LIMIT);
        assert_eq!(events[0].seq, 5);
        assert_eq!(next, (EVENT_LIMIT + 5) as u64);
        let (events, next_again, gap) = operation.events_from(next).unwrap();
        assert!(events.is_empty() && !gap && next_again == next);
        let (events, _, gap) = operation.events_from(10).unwrap();
        assert!(!gap);
        assert_eq!(events[0].seq, 10);
        assert_eq!(operation.events_from(next + 1).unwrap_err().code, "invalid_cursor");
    }

    #[test]
    fn event_text_never_keeps_a_credential_or_address() {
        let mut operation = operation();
        operation.event(None, "provider said token=abc123 at https://example.invalid/x");
        let text = &operation.events[0].message;
        assert!(!text.contains("abc123") && !text.contains("example.invalid"));
    }

    #[test]
    fn operation_ids_stay_plain() {
        assert!(valid_operation_id("op-6f1c2a1e-1b55-4c55-9a64-2d4a0b5c3e10"));
        assert!(valid_operation_id("ui:1730000000.42-a"));
        assert!(!valid_operation_id(""));
        assert!(!valid_operation_id("has space"));
        assert!(!valid_operation_id("a/b"));
        assert!(!valid_operation_id(&"x".repeat(129)));
    }
}
