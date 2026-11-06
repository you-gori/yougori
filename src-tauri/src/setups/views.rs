//! The engine's records as the shared messages (`yougori_setup::dto`) the desktop and CLI read.
//! Only safe state crosses: no specifications, provider labels or secret references.
use super::handler::words;
use super::journal::{Action, Operation, OperationState};
use super::model::{Cost, Desired, Diagnostic, Health, Instance, Lifecycle, Observed};
use super::service::ReviewedPlan;
use super::store::Registry;
use crate::foundation::product::ProductView;
use serde::Serialize;
use serde_json::{json, Value};
use std::{borrow::Cow, collections::BTreeMap};
use yougori_setup::{dto, resource::Kind};

/// Seconds since the epoch, the messages' time format.
pub(crate) fn seconds(stamp: &str) -> i64 {
    chrono::DateTime::parse_from_rfc3339(stamp).map(|time| time.timestamp()).unwrap_or(0)
}

pub(crate) fn state(lifecycle: Lifecycle) -> dto::InstanceState {
    match lifecycle {
        Lifecycle::Draft => dto::InstanceState::Draft,
        Lifecycle::Creating => dto::InstanceState::Creating,
        Lifecycle::Running => dto::InstanceState::Running,
        Lifecycle::Stopped => dto::InstanceState::Stopped,
        Lifecycle::Updating => dto::InstanceState::Updating,
        Lifecycle::Removing => dto::InstanceState::Removing,
        Lifecycle::Retained => dto::InstanceState::Retained,
        Lifecycle::Removed => dto::InstanceState::Removed,
    }
}

/// A cancelled operation is a failed one whose error code says it was cancelled.
pub(crate) fn operation_state(state: OperationState) -> dto::OperationState {
    match state {
        OperationState::Planned => dto::OperationState::Planned,
        OperationState::AwaitingInput => dto::OperationState::AwaitingInput,
        OperationState::Applying => dto::OperationState::Applying,
        OperationState::Cancelling => dto::OperationState::Cancelling,
        OperationState::Completed => dto::OperationState::Completed,
        OperationState::Failed | OperationState::Cancelled => dto::OperationState::Failed,
        OperationState::Unknown => dto::OperationState::Unknown,
    }
}

/// `None` until something was actually checked.
pub(crate) fn health(health: Health) -> Option<dto::CapabilityHealth> {
    Some(match health {
        Health::Unknown => return None,
        Health::Ready => dto::CapabilityHealth::Ready,
        Health::Starting => dto::CapabilityHealth::Starting,
        Health::NeedsSignIn => dto::CapabilityHealth::NeedsSignIn,
        Health::WaitingForComputer => dto::CapabilityHealth::WaitingForComputer,
        Health::Degraded => dto::CapabilityHealth::Degraded,
        Health::Failed => dto::CapabilityHealth::Failed,
        Health::Unsupported => dto::CapabilityHealth::Unsupported,
    })
}

pub(crate) fn observed(observed: Observed) -> dto::ResourceObserved {
    match observed {
        Observed::Unknown => dto::ResourceObserved::Unknown,
        Observed::Missing => dto::ResourceObserved::Missing,
        Observed::Present => dto::ResourceObserved::Present,
        Observed::Running => dto::ResourceObserved::Running,
        Observed::Stopped => dto::ResourceObserved::Stopped,
    }
}

pub(crate) fn cost(cost: Cost) -> dto::ResourceCost {
    match cost {
        Cost::Free => dto::ResourceCost::Free,
        Cost::Unknown => dto::ResourceCost::Unknown,
        Cost::Accruing => dto::ResourceCost::Accruing,
        Cost::Stopped => dto::ResourceCost::Stopped,
        Cost::ShutdownUnconfirmed => dto::ResourceCost::ShutdownUnconfirmed,
    }
}

pub(crate) fn api_error(diagnostic: &Diagnostic) -> dto::Diagnostic {
    let next_actions = diagnostic
        .next
        .iter()
        .filter_map(|action| match action.as_str() {
            "retry" => Some(dto::NextAction::Retry),
            "plan" => Some(dto::NextAction::Review),
            "continue" => diagnostic
                .operation
                .clone()
                .map(|operation| dto::NextAction::Continue { operation }),
            "reconcile" => diagnostic
                .operation
                .clone()
                .map(|operation| dto::NextAction::Reconcile { operation }),
            "cancel" => diagnostic
                .operation
                .clone()
                .map(|operation| dto::NextAction::Cancel { operation }),
            _ => None,
        })
        .collect();
    dto::Diagnostic {
        code: Cow::Owned(diagnostic.code.clone()),
        message: diagnostic.message.clone(),
        field: diagnostic.field.clone(),
        severity: dto::Severity::Error,
        retryable: diagnostic.retryable,
        resource: diagnostic.resource.clone(),
        operation: diagnostic.operation.clone(),
        step: diagnostic.step.clone(),
        next_actions,
    }
}

fn profile(instance: &Instance) -> Option<dto::GridProfile> {
    instance
        .resources
        .values()
        .filter(|resource| resource.kind == yougori_setup::resource::Kind::Grid && !resource.borrowed())
        .find_map(|resource| resource.spec.get("profile").cloned())
        .and_then(|profile| serde_json::from_value(profile).ok())
}

pub(crate) fn summary(instance: &Instance) -> dto::SetupSummary {
    dto::SetupSummary {
        setup_id: instance.id.clone(),
        name: instance.name.clone(),
        source: instance.source.reference.clone(),
        state: state(instance.lifecycle),
        profile: profile(instance),
        adopted_legacy: false,
        state_observed: true,
        health: health(instance.health),
        created_at: seconds(&instance.created_at),
        current_operation: instance.current_operation.as_ref().map(|operation| dto::OperationRef {
            operation_id: operation.clone(),
            setup_id: instance.id.clone(),
        }),
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OperationBrief {
    pub operation_id: String,
    pub kind: &'static str,
    pub state: dto::OperationState,
    pub created_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<dto::Diagnostic>,
}

/// `dto::SetupDetail` on the wire, plus the engine's own observations. A client that only knows
/// `SetupDetail` reads it unchanged.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Detail {
    #[serde(flatten)]
    pub setup: dto::SetupDetail,
    /// Recent operations on this setup, newest first.
    pub operations: Vec<OperationBrief>,
    /// Plain notes, such as why an adopted setup can't be changed here.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    /// False when Yougori found the setup's records but could not read them.
    pub readable: bool,
    /// What the person chose, for an update to start from: `{answers, capabilities, added}`.
    /// Public answers only; secrets are never here.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customization: Option<Value>,
    /// The lock of the plan the setup was last applied from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lock: Option<Value>,
    /// Per resource, beside `resources`: what it depends on, where it runs and what it connects,
    /// in plain fields. Never a secret: specifications hold binding names only.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub resource_details: BTreeMap<String, Value>,
    /// The setup's CORE-07 product document (`setups::product`), the same one the desktop and
    /// the CLI read. Absent for an adopted grid, which has no template record.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<ProductView>,
    /// Why there is no product document when one was expected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product_unavailable: Option<String>,
}

fn brief(operation: &Operation) -> OperationBrief {
    OperationBrief {
        operation_id: operation.id.clone(),
        kind: operation.kind.as_str(),
        state: operation_state(operation.state),
        created_at: seconds(&operation.created_at),
        completed_at: operation.completed_at.as_deref().map(seconds),
        error: operation_error(operation),
    }
}

fn operation_error(operation: &Operation) -> Option<dto::Diagnostic> {
    match (&operation.error, operation.state) {
        (Some(error), _) => Some(api_error(error)),
        (None, OperationState::Cancelled) => Some(api_error(
            &Diagnostic::new("operation_cancelled", "This change was cancelled. Everything already created is still tracked.")
                .retryable()
                .operation(&operation.id)
                .next(&["retry"]),
        )),
        _ => None,
    }
}

/// How one capability is doing, from its own parts rather than the whole setup's (plan 8.2): a
/// website that works stays ready while the model beside it is missing, and the model says so.
/// The setup's combined health is used only for what its parts can't tell: before anything was
/// checked, while it is stopped, and for a capability with no parts of its own. A part that was
/// changed outside Yougori or has gone missing makes its capability degraded, naming the part.
pub(crate) fn capability_status(instance: &Instance, id: &str, combined: Option<dto::CapabilityHealth>) -> dto::CapabilityStatus {
    let whole = || dto::CapabilityStatus {
        id: id.to_owned(),
        health: combined.unwrap_or(dto::CapabilityHealth::Starting),
        detail: combined.is_none().then(|| "Not checked yet. Refresh the setup to check it.".to_owned()),
        next_actions: Vec::new(),
    };
    let Some(kinds) = yougori_setup::capability::find(id).map(|capability| capability.kinds) else { return whole() };
    let parts = instance
        .resources
        .values()
        .filter(|resource| kinds.contains(&resource.kind) && resource.desired != super::model::Desired::Absent)
        .collect::<Vec<_>>();
    // Nothing of its own, nothing checked yet, or a setup that isn't meant to be running: the
    // setup's own words are the right ones.
    if parts.is_empty() || combined.is_none() || instance.lifecycle != Lifecycle::Running {
        return whole();
    }
    let missing = parts.iter().filter(|part| part.observed == Observed::Missing).map(|part| part.id.as_str()).collect::<Vec<_>>();
    let drifted = parts.iter().filter_map(|part| part.drift.as_deref().map(|drift| (part.id.as_str(), drift))).collect::<Vec<_>>();
    let unchecked = parts.iter().filter(|part| part.observed == Observed::Unknown).map(|part| part.id.as_str()).collect::<Vec<_>>();
    let status = |health, detail: String| dto::CapabilityStatus { id: id.to_owned(), health, detail: Some(detail), next_actions: Vec::new() };
    if !missing.is_empty() {
        return status(
            dto::CapabilityHealth::Degraded,
            format!("{} {} missing. Repair the setup to make {} again; nothing else is touched.", missing.join(", "), if missing.len() == 1 { "is" } else { "are" }, if missing.len() == 1 { "it" } else { "them" }),
        );
    }
    if let Some((part, drift)) = drifted.first() {
        return status(dto::CapabilityHealth::Degraded, format!("{part}: {drift}"));
    }
    if !unchecked.is_empty() {
        return status(dto::CapabilityHealth::Starting, format!("{} {} not checked yet. Refresh the setup to check.", unchecked.join(", "), if unchecked.len() == 1 { "is" } else { "are" }));
    }
    // Its own parts are all there. What only the setup as a whole can say (a sign-in it needs,
    // a computer it waits for) still counts; a problem that is plainly another part's does not.
    match combined {
        Some(dto::CapabilityHealth::Degraded | dto::CapabilityHealth::Failed) => dto::CapabilityStatus { id: id.to_owned(), health: dto::CapabilityHealth::Ready, detail: None, next_actions: Vec::new() },
        other => dto::CapabilityStatus { id: id.to_owned(), health: other.unwrap_or(dto::CapabilityHealth::Ready), detail: None, next_actions: Vec::new() },
    }
}

pub(crate) fn detail(registry: &Registry, instance: &Instance) -> Detail {
    let busy = instance.current_operation.is_some();
    let mut actions = Vec::new();
    if !busy {
        match instance.lifecycle {
            Lifecycle::Running => {
                // A part stopped since the setup started it (Yougori closed, or by hand) is started
                // again by Start, which runs only what isn't running. Found driving the app: the
                // setup read running, Repair found nothing to put back, and nothing started it.
                if instance.resources.values().any(|resource| !resource.borrowed() && resource.desired != Desired::Absent && resource.observed == Observed::Stopped) {
                    actions.push(dto::SetupAction::Start);
                }
                actions.extend([dto::SetupAction::Stop, dto::SetupAction::Remove])
            }
            Lifecycle::Stopped => actions.extend([dto::SetupAction::Start, dto::SetupAction::Remove]),
            Lifecycle::Creating | Lifecycle::Updating | Lifecycle::Removing | Lifecycle::Retained => {
                actions.push(dto::SetupAction::Remove)
            }
            Lifecycle::Draft | Lifecycle::Removed => {}
        }
    }
    let combined = health(instance.health);
    let mut operations = registry
        .operations
        .values()
        .filter(|operation| operation.setup == instance.id)
        .collect::<Vec<_>>();
    operations.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Detail {
        setup: dto::SetupDetail {
            summary: summary(instance),
            revision: instance.revision,
            capabilities: instance.capabilities.iter().map(|id| capability_status(instance, id, combined)).collect(),
            resources: instance
                .resources
                .values()
                .map(|resource| dto::ResourceRef {
                    resource_id: resource.id.clone(),
                    kind: resource.kind,
                    owned: !resource.borrowed(),
                    label: resource.id.clone(),
                    observed: observed(resource.observed),
                    drift: resource.drift.clone(),
                    cost: cost(resource.cost),
                    retained_data: resource.retained_data,
                    borrowed_from: resource.owner.as_ref().map(|owner| owner.setup.clone()),
                })
                .collect(),
            outputs: instance
                .outputs
                .iter()
                .map(|(key, value)| dto::Output { key: key.clone(), label: key.replace('_', " "), value: value.clone() })
                .collect(),
            actions,
            // Filled in by Service::get from the setup's kept package; empty here keeps the usual tabs.
            views: Vec::new(),
        },
        operations: operations.into_iter().take(20).map(brief).collect(),
        notes: Vec::new(),
        readable: true,
        customization: None,
        lock: instance.lock.clone(),
        resource_details: instance.resources.values().map(|resource| (resource.id.clone(), resource_detail(resource))).collect(),
        // Filled in by the `setup_get` door, which reads the engine's evidence clock.
        product: None,
        product_unavailable: None,
    }
}

/// The plain facts of one resource for the setup page.
fn resource_detail(resource: &super::model::Resource) -> Value {
    let spec = &resource.spec;
    let end = |field: &str| spec[field]["resource"].as_str().map(str::to_owned);
    let placement = match resource.kind {
        Kind::Environment | Kind::Volume => Some("this computer".to_owned()),
        Kind::VmSandbox if spec["remote"].is_object() => Some(format!("a restricted VM on SSH connection {}", spec["remote"]["connection"].as_str().unwrap_or("unknown"))),
        Kind::VmSandbox => Some("a restricted VM on this computer".to_owned()),
        Kind::Grid => spec["profile"].as_str().map(|profile| format!("{} ({})", profile.replace('_', " "), spec["mode"].as_str().unwrap_or("create"))),
        _ => None,
    };
    let connection = match resource.kind {
        Kind::Connection => Some(json!({ "from": end("from"), "to": end("to"), "ports": spec["ports"], "direction": spec["direction"].as_str().unwrap_or("one_way") })),
        Kind::ServicePublication => Some(json!({ "to": end("target"), "port": spec["port"], "access": spec["access"].as_str().unwrap_or("quick") })),
        _ => None,
    };
    json!({
        "dependsOn": resource.depends_on,
        "placement": placement,
        "remoteVm": resource.kind == Kind::VmSandbox && spec["remote"].is_object(),
        "connection": connection,
        "image": spec["image"].as_str(),
        "generation": resource.generation,
        // When Yougori last looked at this part, and, when that look found it well (there, and as
        // the setup wants it), that this is when it was last seen healthy. Never guessed: a part
        // found missing or changed has no "last healthy" time here.
        "lastCheckedAt": resource.last_observed_at.as_deref().map(seconds),
        "lastHealthyAt": resource
            .last_observed_at
            .as_deref()
            .filter(|_| matches!(resource.observed, Observed::Running | Observed::Present | Observed::Stopped) && resource.drift.is_none())
            .map(seconds),
        // What may be done to this part on its own; `Service::get` fills it in from the same rule
        // a one-part review applies (`service::part_actions`). Empty here, when nothing is known.
        "actions": Vec::<String>::new(),
    })
}

pub(crate) fn progress(operation: &Operation, cursor: u64) -> Result<dto::OperationProgress, Diagnostic> {
    let (events, next_cursor, truncated) = operation.events_from(cursor)?;
    Ok(dto::OperationProgress {
        operation: dto::OperationRef { operation_id: operation.id.clone(), setup_id: operation.setup.clone() },
        state: operation_state(operation.state),
        events: events
            .into_iter()
            .map(|event| dto::OperationEvent {
                cursor: event.seq,
                at: seconds(&event.at),
                step: event.step.clone().unwrap_or_else(|| "operation".into()),
                message: event.message,
                resource: event.step,
                diagnostic: None,
            })
            .collect(),
        next_cursor,
        truncated,
        error: operation_error(operation),
        plan_digest: Some(operation.plan_digest.clone()),
    })
}

/// A reviewed plan as the desktop's review screen reads it.
pub(crate) fn plan(plan: &ReviewedPlan) -> Value {
    let verb = |action: Action| match action {
        Action::Create => "Create",
        Action::Update => "Update",
        Action::Start => "Start",
        Action::Stop => "Stop",
        Action::Attach => "Use",
        Action::Detach => "Detach",
        Action::Remove => "Remove",
    };
    let headline = match (plan.intent, plan.steps.len()) {
        (_, 0) => "Nothing needs to change.".to_owned(),
        (kind, count) => format!(
            "{} this setup: {count} {}.",
            match kind {
                super::journal::OperationKind::Create => "Create",
                super::journal::OperationKind::Update => "Update",
                super::journal::OperationKind::Start => "Start",
                super::journal::OperationKind::Stop => "Stop",
                super::journal::OperationKind::Remove => "Remove",
                super::journal::OperationKind::Repair => "Repair",
            },
            if count == 1 { "step" } else { "steps" }
        ),
    };
    json!({
        "planId": plan.plan_id,
        "setupId": plan.setup_id,
        "intent": plan.intent,
        "digest": plan.digest,
        "baseRevision": plan.base_revision,
        "expiresAt": seconds(&plan.expires_at),
        "headline": headline,
        "steps": plan.steps.iter().map(|step| json!({
            "title": match step.spec["adopted"].as_bool() {
                Some(true) => format!("Adopt {} ({}) already on this computer", step.resource, words(step.kind)),
                _ => format!("{} {} ({})", verb(step.action), step.resource, words(step.kind)),
            },
            "detail": match (step.action, step.owner.is_some()) {
                (Action::Detach, _) => Some("Only this setup's access is removed. The resource stays with its owner."),
                (Action::Remove, _) => match step.kind {
                    Kind::Environment => Some("Its data is kept unless you delete it separately."),
                    // A volume says which of the two it is, rather than pointing at a separate
                    // step while a box that deletes it sits in the same review.
                    Kind::Volume if plan.offered.iter().any(|offer| offer["id"] == super::ordinary::delete_consent(&step.resource)) => {
                        Some("Its data and backups are kept unless you tick its deletion below.")
                    }
                    Kind::Volume => Some("Its data and its backups are kept."),
                    Kind::Grid => Some("The notes say what removing it deletes, and when."),
                    Kind::VmSandbox if plan.offered.iter().any(|offer| offer["id"] == super::vm_sandbox::delete_workspace_consent(&step.resource)) => {
                        Some("Its staged copy stays for review unless you tick its deletion below. Your own folder is not touched.")
                    }
                    Kind::VmSandbox => Some("The VM is stopped. None of your files is touched."),
                    Kind::CredentialBroker => Some("The credentials it added are deleted with their rules."),
                    _ => None,
                },
                (Action::Attach, _) => Some("Uses a resource another setup owns. Nothing is created, and that setup keeps owning it."),
                _ => None,
            },
        })).collect::<Vec<_>>(),
        "resources": plan.steps.iter().map(|step| json!({
            "resourceId": step.resource,
            "label": step.resource,
            "kind": step.kind,
            "owned": step.owner.is_none(),
            "action": step.action,
        })).collect::<Vec<_>>(),
        "retained": plan.notes.iter().filter(|note| note.starts_with("The data of")).collect::<Vec<_>>(),
        "notes": plan.notes,
        // What the person must agree to for this plan to do all it says: each is sent back with
        // `setup_apply` as `consents`, or that part is left for them to do themselves.
        //
        // A removal's deletion offers travel here too, and only from the plan that made them: an
        // apply agrees to what THIS review offered, never to a name a caller invents. Every one
        // arrives unticked, names the volume and its backups, and says it cannot be undone.
        "consents": plan
            .steps
            .iter()
            .filter(|step| step.kind == Kind::Environment && matches!(step.action, Action::Create | Action::Update))
            .flat_map(|step| super::ordinary::consents(&plan.setup_id, &step.resource, &step.spec))
            .chain(plan.offered.iter().cloned())
            .collect::<Vec<_>>(),
        "warnings": Vec::<String>::new(),
        "blockers": Vec::<dto::Diagnostic>::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::super::model::{Desired, Resource, Source};
    use super::*;

    fn part(id: &str, kind: Kind, observed: Observed, drift: Option<&str>) -> Resource {
        Resource {
            id: id.into(),
            kind,
            depends_on: Vec::new(),
            runtime_id: Some(format!("rt-{id}")),
            owner: None,
            borrowers: Vec::new(),
            generation: 1,
            desired: Desired::Running,
            observed,
            retained_data: false,
            cost: Cost::Free,
            last_observed_at: None,
            drift: drift.map(str::to_owned),
            spec: json!({}),
            spec_digest: String::new(),
        }
    }

    fn setup(parts: Vec<Resource>, health: Health, lifecycle: Lifecycle) -> Instance {
        Instance {
            id: "setup-1".into(),
            name: "Shop".into(),
            source: Source { reference: dto::SourceRef::InstalledSetup { setup_id: "x".into() }, digest: "sha256:0".into() },
            format_version: 2,
            protocol_version: 1,
            lock_digest: None,
            config_revision: 1,
            revision: 1,
            answers: BTreeMap::new(),
            secret_bindings: BTreeMap::new(),
            lock: None,
            customizations: BTreeMap::new(),
            capabilities: vec!["web.service".into(), "models.local".into(), "data.volumes".into(), "grid.create".into()],
            realms: Vec::new(),
            storage: None,
            outputs: BTreeMap::new(),
            current_operation: None,
            lifecycle,
            health,
            history: Vec::new(),
            resources: parts.into_iter().map(|part| (part.id.clone(), part)).collect(),
            created_at: String::new(),
            updated_at: String::new(),
        }
    }

    fn of<'a>(statuses: &'a [dto::CapabilityStatus], id: &str) -> &'a dto::CapabilityStatus {
        statuses.iter().find(|status| status.id == id).unwrap()
    }

    /// PROVES each capability says how its own parts are doing: a working website stays ready while
    /// the model beside it is missing, the model names what is wrong, and a part changed outside
    /// Yougori names its own change. What only the whole setup knows stays the whole setup's.
    #[test]
    fn a_ready_website_and_a_missing_model_each_say_their_own_state() {
        let instance = setup(
            vec![
                part("site", Kind::ServicePublication, Observed::Running, None),
                part("model", Kind::ModelService, Observed::Missing, None),
                part("data", Kind::Volume, Observed::Present, Some("Its size was changed outside Yougori.")),
            ],
            Health::Degraded,
            Lifecycle::Running,
        );
        let statuses = instance.capabilities.iter().map(|id| capability_status(&instance, id, health(instance.health))).collect::<Vec<_>>();
        assert_eq!(of(&statuses, "web.service").health, dto::CapabilityHealth::Ready, "the website's own parts are fine");
        let model = of(&statuses, "models.local");
        assert_eq!(model.health, dto::CapabilityHealth::Degraded);
        assert_eq!(model.detail.as_deref(), Some("model is missing. Repair the setup to make it again; nothing else is touched."));
        let data = of(&statuses, "data.volumes");
        assert_eq!((data.health, data.detail.as_deref()), (dto::CapabilityHealth::Degraded, Some("data: Its size was changed outside Yougori.")));
        // A capability with no parts of its own reads as the whole setup does.
        assert_eq!(of(&statuses, "grid.create").health, dto::CapabilityHealth::Degraded);
    }

    #[test]
    fn each_part_says_when_it_was_last_checked_and_last_seen_well() {
        let mut well = part("site", Kind::ServicePublication, Observed::Running, None);
        well.last_observed_at = Some("2026-10-26T18:00:00Z".into());
        let at = seconds("2026-10-26T18:00:00Z");
        assert_eq!(at, 1_793_037_600);
        let detail = resource_detail(&well);
        assert_eq!(detail["lastCheckedAt"], at);
        assert_eq!(detail["lastHealthyAt"], at);
        let mut changed = part("data", Kind::Volume, Observed::Present, Some("Its size was changed outside Yougori."));
        changed.last_observed_at = Some("2026-10-26T18:00:00Z".into());
        let detail = resource_detail(&changed);
        assert_eq!(detail["lastCheckedAt"], at);
        assert!(detail["lastHealthyAt"].is_null(), "a changed part is not called healthy");
        assert!(resource_detail(&part("new", Kind::Volume, Observed::Unknown, None))["lastCheckedAt"].is_null());
    }

    #[test]
    fn before_anything_is_checked_or_while_stopped_the_setups_own_words_stand() {
        let parts = || vec![part("site", Kind::ServicePublication, Observed::Running, None), part("model", Kind::ModelService, Observed::Missing, None)];
        let unchecked = setup(parts(), Health::Unknown, Lifecycle::Running);
        let status = capability_status(&unchecked, "models.local", health(unchecked.health));
        assert_eq!((status.health, status.detail.as_deref()), (dto::CapabilityHealth::Starting, Some("Not checked yet. Refresh the setup to check it.")));
        let stopped = setup(parts(), Health::Ready, Lifecycle::Stopped);
        assert_eq!(capability_status(&stopped, "models.local", health(stopped.health)).health, dto::CapabilityHealth::Ready, "a stopped setup isn't called broken");
        // A part not checked yet says so by name; a sign-in the whole setup needs still counts.
        let waiting = setup(vec![part("site", Kind::ServicePublication, Observed::Unknown, None)], Health::NeedsSignIn, Lifecycle::Running);
        let status = capability_status(&waiting, "web.service", health(waiting.health));
        assert_eq!((status.health, status.detail.as_deref()), (dto::CapabilityHealth::Starting, Some("site is not checked yet. Refresh the setup to check.")));
        let signed_out = setup(vec![part("site", Kind::ServicePublication, Observed::Running, None)], Health::NeedsSignIn, Lifecycle::Running);
        assert_eq!(capability_status(&signed_out, "web.service", health(signed_out.health)).health, dto::CapabilityHealth::NeedsSignIn);
    }
}
