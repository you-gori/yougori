//! The messages the engine, CLI and desktop exchange: operations, setups, questions, diagnostics
//! and events.
//!
//! Every type here is a plain data shape. Fields are camelCase on the wire and enum values are
//! snake_case, matching `resource::Kind` and the capability ids, so the generated TypeScript mirror
//! reads the same words. Nothing here is a secret: a token is never serialised, only a reference to
//! one. The engine is the authoritative writer; these are what it hands the CLI and desktop to show.
//!
//! A number that counts is `u64`; a time is seconds since the epoch as `i64`, the convention the
//! client already uses. `next_actions` is always typed: the UI is never asked to run a command
//! string a template returned.

use serde::{Deserialize, Serialize};
use std::borrow::Cow;

use crate::resource::Kind;

/// The version of these message shapes. The engine, CLI and desktop check it so an older client and
/// a newer engine can tell they disagree before they act on a shape neither understands. Bump it
/// when a field changes in a way a reader must notice.
pub const CONTRACT_VERSION: u32 = 1;

// ---- States ----

/// Where one operation is in its life. Separate from how the running application is doing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    /// Worked out, not yet started.
    Planned,
    /// Waiting for the user to answer something before it can go on.
    AwaitingInput,
    /// Running now.
    Applying,
    /// Being stopped at the user's request.
    Cancelling,
    /// Finished and succeeded.
    Completed,
    /// Finished and failed, with a reason.
    Failed,
    /// The outcome is not yet known and is being reconciled. A timeout lands here, never on failed,
    /// until the engine has checked what really happened.
    Unknown,
}

/// Where a setup is in its life. A setup with no workers online is still `Running`; that it has no
/// workers is a health matter, not a lifecycle one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstanceState {
    /// Being edited, not yet applied.
    Draft,
    /// Being created for the first time.
    Creating,
    /// Up and in use.
    Running,
    /// Deliberately stopped; its data is kept.
    Stopped,
    /// A change is being applied to it.
    Updating,
    /// Being taken down.
    Removing,
    /// Removed, but some data was kept on purpose.
    Retained,
    /// Gone, with nothing left.
    Removed,
}

/// How one capability of a setup is doing, apart from the setup's lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityHealth {
    /// Working and ready to use.
    Ready,
    /// Coming up.
    Starting,
    /// Waiting for someone to sign in to a provider.
    NeedsSignIn,
    /// Waiting for a computer to be available for its work.
    WaitingForComputer,
    /// Working, but not fully: some part is unavailable.
    Degraded,
    /// Not working, with a reason.
    Failed,
    /// Not supported on this computer.
    Unsupported,
}

// ---- Diagnostics ----

/// How serious a diagnostic is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Stops the operation.
    Error,
    /// Worth saying, but not a blocker.
    Warning,
    /// A note.
    Info,
}

/// Something the user can do next, named by what it is rather than by a command to run. The UI turns
/// it into a button; it is never a shell string a template supplied.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", rename_all_fields = "camelCase")]
pub enum NextAction {
    /// Sign in to the named provider.
    SignIn { provider: String },
    /// Answer an input, at the given field path.
    ProvideInput { field: String },
    /// Pick a supported option where the chosen one is not available here.
    ChooseSupportedOption { field: String },
    /// Try the operation again. For a cancelled or failed operation, this continues only the
    /// unfinished steps.
    Retry,
    /// Continue an operation that is waiting.
    Continue { operation: String },
    /// Check what really happened after a crash, timeout or cancel, so an unknown outcome can be
    /// resolved. Distinct from Retry: it does not change anything, it finds out.
    Reconcile { operation: String },
    /// Stop a running or waiting operation.
    Cancel { operation: String },
    /// Open the review to look at the plan again.
    Review,
    /// Free up or add a computer for the work.
    AddComputer,
    /// Open the setup's logs.
    ViewLogs,
    /// Read a page that explains this.
    OpenDocs { topic: String },
}

/// One thing the engine wants to tell the user about an operation or a setup: a stable code, a plain
/// sentence, and typed next actions. Used for both problems and errors; an error is just a
/// `Diagnostic` with `severity = error`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Diagnostic {
    /// A stable identifier for this kind of diagnostic, e.g. `capability_not_enableable`. Borrowed
    /// when built from a literal; owned when read back from the wire.
    pub code: Cow<'static, str>,
    /// A plain sentence a person can read.
    pub message: String,
    /// Where the problem is, if it has a place: a field path such as `inputs[2].group` or
    /// `capabilities.grid.create.grid_name`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(default = "error_severity")]
    pub severity: Severity,
    /// Whether trying again might work. False for a problem that needs a change first.
    #[serde(default)]
    pub retryable: bool,
    /// The resource this is about, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    /// The operation this is about, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    /// The step within the operation, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<String>,
    /// What the user can do about it, typed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub next_actions: Vec<NextAction>,
}

fn error_severity() -> Severity {
    Severity::Error
}

impl Diagnostic {
    /// An error diagnostic with a stable code and a plain message. Chain `.at`, `.retry`, and the
    /// rest to fill in the optional parts. The code takes a `&'static str` literal or an owned
    /// `Cow`, so an adapter converting another crate's problem type can hand over its code directly.
    pub fn error(code: impl Into<Cow<'static, str>>, message: impl Into<String>) -> Diagnostic {
        Diagnostic {
            code: code.into(),
            message: message.into(),
            field: None,
            severity: Severity::Error,
            retryable: false,
            resource: None,
            operation: None,
            step: None,
            next_actions: Vec::new(),
        }
    }

    /// A warning diagnostic: worth showing, not a blocker.
    pub fn warning(code: &'static str, message: impl Into<String>) -> Diagnostic {
        Diagnostic { severity: Severity::Warning, ..Diagnostic::error(code, message) }
    }

    /// Point it at a field.
    pub fn at(mut self, field: impl Into<String>) -> Diagnostic {
        self.field = Some(field.into());
        self
    }

    /// Mark it as worth retrying.
    pub fn retry(mut self) -> Diagnostic {
        self.retryable = true;
        self
    }

    /// Attach the resource it is about.
    pub fn on_resource(mut self, resource: impl Into<String>) -> Diagnostic {
        self.resource = Some(resource.into());
        self
    }

    /// Attach the operation and step it belongs to.
    pub fn in_operation(mut self, operation: impl Into<String>, step: Option<String>) -> Diagnostic {
        self.operation = Some(operation.into());
        self.step = step;
        self
    }

    /// Offer a typed next action.
    pub fn with_action(mut self, action: NextAction) -> Diagnostic {
        self.next_actions.push(action);
        self
    }

    pub fn is_error(&self) -> bool {
        matches!(self.severity, Severity::Error)
    }
}

/// An error the engine returns from a call, as opposed to one attached to a running operation. The
/// same shape, so a reader has one thing to handle.
pub type ApiError = Diagnostic;

// ---- Sources and references ----

/// Where a template or setup comes from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", rename_all_fields = "camelCase")]
pub enum SourceRef {
    /// A folder on this computer.
    LocalFolder { path: String },
    /// A published Hub item, `PUBLISHER/NAME@VERSION`. The version is pinned; a setup never silently
    /// follows a moving latest.
    Hub { publisher: String, name: String, version: String },
    /// A template already installed as a setup, referenced to fork or inspect.
    InstalledSetup { setup_id: String },
}

/// A pointer to an operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationRef {
    pub operation_id: String,
    pub setup_id: String,
}

// ---- Requests ----

/// Ask the engine to resolve a package and work out a concrete plan, changing nothing.
///
/// `deny_unknown_fields`: a request is what a caller sends the engine, so an unknown field is a typo
/// (an `existing_setup` that never reaches `existingSetup` would silently plan a new setup) and is
/// refused outright rather than ignored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PlanRequest {
    pub source: SourceRef,
    /// The setup's name, when planning a new one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Public answers to the template's questions, by field path.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub answers: Vec<Answer>,
    /// Private answers delivered by reference, never by value. The engine resolves the reference
    /// from its own secret store; the value never travels in this message.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bindings: Vec<Binding>,
    /// When set, plan a change to this existing setup rather than a new one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub existing_setup: Option<String>,
}

/// One public answer to a question.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Answer {
    /// The field path the answer is for.
    pub field: String,
    /// The answer, as JSON, so it can be a string, number, boolean or list.
    pub value: serde_json::Value,
}

/// A private value delivered by reference. The reference names a secret the engine already holds, or
/// one the user will enter privately; the value is not in this message.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Binding {
    /// The field path the binding is for.
    pub field: String,
    /// The name of the secret reference, resolved by the engine.
    pub secret_ref: String,
}

/// Apply a plan the user has reviewed. The digest ties the apply to exactly the plan that was shown,
/// so a plan that changed underneath is caught; the operation id makes a replay safe; the expected
/// revision stops two writers racing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplyRequest {
    pub setup_id: String,
    /// The digest of the exact plan that was reviewed. The engine refuses to apply a different one.
    pub plan_digest: String,
    /// A caller-chosen id, so replaying this request after an interruption does not create a second
    /// set of resources.
    pub operation_id: String,
    /// The setup revision the caller believes it is changing. A mismatch means someone else wrote
    /// first, and the apply is refused for review.
    pub expected_revision: u64,
}

/// The answer to [`PlanRequest`]: the concrete plan, ready to review and apply. For a brand-new setup
/// the engine reserves the setup's id at plan time and returns it here with `base_revision` 0; the
/// client sends that id back in [`ApplyRequest`], which is what stops a replayed create plan from
/// making a second setup. For a change to an existing setup, both name that setup.
///
/// `plan` is the author's resolved graph from the planner, carried as-is: its resource specs keep the
/// snake_case field names the author wrote, so the desktop's source view and `template export` show
/// the same YAML. Only this envelope is camelCase. `digest` is `plan.digest`, copied up so a reader
/// need not reach into the plan to match it in `ApplyRequest`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanResponse {
    /// The id the engine reserved for this setup (new or existing); sent back in `ApplyRequest`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setup_id: Option<String>,
    /// The setup revision this plan was built against. 0 for a new setup.
    pub base_revision: u64,
    /// The digest of the plan, equal to `plan.digest`. `ApplyRequest.plan_digest` must match it.
    pub digest: String,
    /// The human-readable review of the plan: resources, placement, downloads, permissions, cost and
    /// any change to existing resources. The same review the CLI prints and the desktop shows.
    pub review: crate::plan::Review,
    /// The author's resolved plan graph, carried verbatim (snake_case specs inside).
    pub plan: crate::plan::Plan,
}

// ---- Operations and progress ----

/// One recorded step of an operation's progress.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationEvent {
    /// A monotonic position, so a reader can resume after it.
    pub cursor: u64,
    /// Seconds since the epoch.
    pub at: i64,
    /// A short machine tag for the step, e.g. `reserving_storage`.
    pub step: String,
    /// A plain sentence for a person.
    pub message: String,
    /// The resource this step touched, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    /// A diagnostic raised at this step, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostic: Option<Diagnostic>,
}

/// A bounded read of an operation's progress, resumable by cursor. The gap flag says the reader has
/// missed events the engine has already dropped, so the UI can say so rather than imply completeness.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OperationProgress {
    pub operation: OperationRef,
    pub state: OperationState,
    /// The events in this read, oldest first.
    pub events: Vec<OperationEvent>,
    /// The cursor to pass next to continue after the last event here.
    pub next_cursor: u64,
    /// True when earlier events were dropped before this read, so `events` is not the whole history.
    #[serde(default)]
    pub truncated: bool,
    /// Set when the operation has finished and failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<Diagnostic>,
    /// The digest of the plan this operation applies, as [`ApplyRequest::plan_digest`] names it. A
    /// client that was not there when the plan was reviewed (a terminal opened later, say) can
    /// answer an operation waiting for input by sending this digest and the operation's id back,
    /// so the operation that asked continues and no second one is made. Optional on the wire: an
    /// older engine does not send it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_digest: Option<String>,
}

// ---- Setups ----

/// The short view of a setup, for a list.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetupSummary {
    pub setup_id: String,
    pub name: String,
    pub source: SourceRef,
    pub state: InstanceState,
    /// Whether the engine has actually observed this setup's state. An adopted legacy grid is managed
    /// from its own page, so its state was never observed here (invariant 16): `state` reads `stopped`
    /// (never implying it is running or can be started), and the UI shows "state not checked" rather
    /// than the state word. Defaults to true; omitted when true.
    #[serde(default = "bool_true", skip_serializing_if = "is_true")]
    pub state_observed: bool,
    /// The grid profile this setup presents as, when it is one of the four. `None` for an ordinary
    /// setup. Kept separate from capability names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<GridProfile>,
    /// True for an older grid adopted into a setup rather than created as one.
    #[serde(default)]
    pub adopted_legacy: bool,
    /// The combined health across the setup's capabilities, so a list can show "degraded" without
    /// fetching every detail. `None` before the setup has run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health: Option<CapabilityHealth>,
    /// Seconds since the epoch.
    pub created_at: i64,
    /// The operation in flight on this setup, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_operation: Option<OperationRef>,
}

/// The full view of one setup. It carries only safe state: selected capabilities and their health,
/// the resources it owns or borrows, and outputs that are safe to show. No secret values, and no
/// private answers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetupDetail {
    pub summary: SetupSummary,
    /// The setup revision, as `ApplyRequest::expected_revision` uses it.
    pub revision: u64,
    pub capabilities: Vec<CapabilityStatus>,
    pub resources: Vec<ResourceRef>,
    /// Outputs safe to show: a public URL, a port, a workspace link. Never a token.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outputs: Vec<Output>,
    /// The actions available on the setup now.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<SetupAction>,
    /// The standard views the template declared (`format::VIEWS`), read again from its kept package.
    /// The desktop uses them to shape the setup's tabs; a build that doesn't fill them shows the
    /// usual tabs from its capabilities, so this stays optional on the wire.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub views: Vec<String>,
}

/// One selected capability and how it is doing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityStatus {
    /// The capability id, e.g. `grid.create`.
    pub id: String,
    pub health: CapabilityHealth,
    /// A plain sentence when the health needs explaining (a sign-in needed, a reason it is degraded).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// What the user can do about this capability's state, if anything.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub next_actions: Vec<NextAction>,
}

/// What the engine last saw of a resource. `Unknown` until observed; `Missing` when it was expected
/// but is not there, which is how drift surfaces.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceObserved {
    Unknown,
    Missing,
    Present,
    Running,
    Stopped,
}

/// What a resource is costing. A stop never implies "costs nothing" without evidence: an
/// unconfirmed shutdown says so plainly rather than claiming the cost has ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceCost {
    /// Nothing to pay for.
    Free,
    /// Not yet known.
    Unknown,
    /// Costing money now.
    Accruing,
    /// Stopped, and confirmed to no longer cost.
    Stopped,
    /// A shutdown was asked for but not confirmed, so a charge may still be running.
    ShutdownUnconfirmed,
}

/// A reference to a resource a setup owns or borrows. Owned resources follow the setup's lifecycle;
/// a borrowed one is never destroyed by the borrowing setup.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceRef {
    pub resource_id: String,
    pub kind: Kind,
    /// True when this setup created it; false when it was attached.
    pub owned: bool,
    /// A short, safe label for the resource.
    pub label: String,
    /// What the engine last saw of it.
    #[serde(default = "observed_unknown", skip_serializing_if = "is_observed_unknown")]
    pub observed: ResourceObserved,
    /// A plain sentence when the resource has drifted from what was expected, e.g.
    /// "Removed outside Yougori." `None` when it matches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drift: Option<String>,
    /// What it is costing.
    #[serde(default = "cost_unknown", skip_serializing_if = "is_cost_unknown")]
    pub cost: ResourceCost,
    /// Whether removing the setup would leave this resource's data behind.
    #[serde(default, skip_serializing_if = "is_false")]
    pub retained_data: bool,
    /// For a borrowed resource, the setup that owns it. `None` for an owned resource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub borrowed_from: Option<String>,
}

fn observed_unknown() -> ResourceObserved {
    ResourceObserved::Unknown
}

fn is_observed_unknown(value: &ResourceObserved) -> bool {
    matches!(value, ResourceObserved::Unknown)
}

fn cost_unknown() -> ResourceCost {
    ResourceCost::Unknown
}

fn is_cost_unknown(value: &ResourceCost) -> bool {
    matches!(value, ResourceCost::Unknown)
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn bool_true() -> bool {
    true
}

fn is_true(value: &bool) -> bool {
    *value
}

/// One safe output of a setup.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Output {
    /// A short machine tag, e.g. `public_url` or `service_port`.
    pub key: String,
    /// A label for a person.
    pub label: String,
    /// The value, safe to show. Never a secret.
    pub value: String,
}

/// An action a user can take on a whole setup. These are the typed lifecycle actions; the engine
/// turns each into a reviewed operation. Destructive ones (delete data) always need their own
/// explicit step.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SetupAction {
    /// Start a stopped setup.
    Start,
    /// Stop a running setup, keeping its data.
    Stop,
    /// Take the setup down. Borrowed resources are untouched; owned data is kept unless deletion is
    /// a separate, explicit action.
    Remove,
    /// Detach a borrowed resource from the setup, leaving the resource itself alone.
    Detach,
    /// Stop admitting new work, while letting current work finish.
    PauseAdmission,
    /// Release rented or shared compute the setup was using.
    ReleaseCompute,
    /// Delete the setup's own retained data. Always a separate, explicit action.
    DeleteData,
}

/// Which of the four grids a setup presents as, kept separate from capability names so that adding a
/// recipe does not add a profile to every grid. Defined in `capability` because the registry's
/// per-profile support lists use it; re-exported here so `dto::GridProfile` stays a valid path for
/// the engine, CLI and desktop.
pub use crate::capability::GridProfile;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_builds_and_round_trips() {
        let diag = Diagnostic::error("capability_not_enableable", "This capability cannot be enabled here.")
            .at("capabilities.run.schedule")
            .with_action(NextAction::ChooseSupportedOption { field: "capabilities.run.schedule".into() });
        let json = serde_json::to_string(&diag).unwrap();
        // camelCase on the wire.
        assert!(json.contains("\"nextActions\""));
        assert!(json.contains("choose_supported_option"));
        let back: Diagnostic = serde_json::from_str(&json).unwrap();
        assert_eq!(back, diag);
        assert!(back.is_error());
    }

    #[test]
    fn optional_fields_are_omitted_when_empty() {
        let diag = Diagnostic::error("x", "y");
        let json = serde_json::to_string(&diag).unwrap();
        assert!(!json.contains("field"));
        assert!(!json.contains("resource"));
        assert!(!json.contains("nextActions"));
    }

    #[test]
    fn states_serialise_snake_case() {
        assert_eq!(serde_json::to_string(&OperationState::AwaitingInput).unwrap(), "\"awaiting_input\"");
        assert_eq!(serde_json::to_string(&InstanceState::Retained).unwrap(), "\"retained\"");
        assert_eq!(serde_json::to_string(&CapabilityHealth::NeedsSignIn).unwrap(), "\"needs_sign_in\"");
    }

    #[test]
    fn grid_profile_slugs_match_aliases() {
        use crate::capability::{alias, AliasTarget};
        for profile in [
            GridProfile::NeoGrid,
            GridProfile::SandboxGrid,
            GridProfile::AccessGrid,
            GridProfile::SwarmMiningGrid,
        ] {
            let slug = profile.recipe_slug().unwrap();
            // The alias table and the profile agree on the slug.
            assert!(matches!(
                alias(match profile {
                    GridProfile::NeoGrid => "neo grid",
                    GridProfile::SandboxGrid => "sandbox grid",
                    GridProfile::AccessGrid => "access grid",
                    GridProfile::SwarmMiningGrid => "swarm mining",
                    GridProfile::Generic => unreachable!(),
                }),
                Some(AliasTarget::Recipe { slug: s }) if s == slug
            ));
        }
        assert_eq!(GridProfile::Generic.recipe_slug(), None);
    }

    #[test]
    fn source_ref_tags_its_kind() {
        let hub = SourceRef::Hub {
            publisher: "you-gori".into(),
            name: "sandbox-grid".into(),
            version: "1.0.0".into(),
        };
        let json = serde_json::to_string(&hub).unwrap();
        assert!(json.contains("\"kind\":\"hub\""));
    }

    #[test]
    fn a_request_refuses_an_unknown_field() {
        // A typo such as `existing_setup` (instead of `existingSetup`) must be refused, not silently
        // ignored — otherwise it would quietly plan a new setup instead of a change to an existing one.
        let typo = r#"{"source":{"kind":"installed_setup","setupId":"setup-1"},"existing_setup":"setup-1"}"#;
        assert!(serde_json::from_str::<PlanRequest>(typo).is_err());
        // The correct field is accepted.
        let correct = r#"{"source":{"kind":"installed_setup","setupId":"setup-1"},"existingSetup":"setup-1"}"#;
        assert!(serde_json::from_str::<PlanRequest>(correct).is_ok());
        // ApplyRequest, Answer and Binding refuse unknown fields too.
        let apply = r#"{"setupId":"s","planDigest":"d","operationId":"op","expectedRevision":0,"extra":1}"#;
        assert!(serde_json::from_str::<ApplyRequest>(apply).is_err());
        assert!(serde_json::from_str::<Answer>(r#"{"field":"name","value":"x","typo":1}"#).is_err());
        assert!(serde_json::from_str::<Binding>(r#"{"field":"f","secretRef":"r","typo":1}"#).is_err());
    }
}
