//! The contract every resource handler meets, and the table of handlers by resource kind.
//!
//! Validation and planning never change anything. Every other call receives the step's scoped
//! idempotency key as a label and puts it on what it creates, so `observe` can find an effect
//! whose receipt was never saved. An operation a handler does not support returns a structured
//! reason; it never pretends to succeed.
//!
//! No product handler is registered yet (`engine_handlers`), so parts of this contract are only
//! exercised by the test handlers until the grid, model and workspace handlers land. That is why
//! unused items are allowed here rather than removed.
#![allow(dead_code)]
use super::journal::{Action, Receipt};
use super::model::{now, Cost, Diagnostic, Health, Observed, OwnerRef, Resource};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    pin::Pin,
    sync::Arc,
};
use tokio_util::sync::CancellationToken;
use yougori_setup::resource::Kind;

pub(crate) type HandlerFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, HandlerError>> + Send + 'a>>;

/// Everything a handler is told about the step it is asked to carry out.
#[derive(Clone)]
pub(crate) struct StepContext {
    pub setup: String,
    pub operation: String,
    pub step: String,
    pub resource: String,
    pub kind: Kind,
    pub action: Action,
    /// The step's scoped idempotency key. Put it on what you create.
    pub label: String,
    /// The label of the step that created the resource, used to find it before a receipt exists.
    pub created_label: Option<String>,
    pub generation: u64,
    pub spec: Value,
    pub runtime_id: Option<String>,
    /// The other setup's resource this one borrows, when it is a binding.
    pub owner: Option<OwnerRef>,
    /// The setup's other resources as they are recorded now: what this step may refer to.
    pub peers: BTreeMap<String, Peer>,
    /// The other resources this same operation is about to make or change, as planned. A
    /// product that makes two declared resources in one call (an Access Grid and its first
    /// administrator) reads its partner here.
    pub planned: BTreeMap<String, Peer>,
    pub cancel: CancellationToken,
    /// Secret values given for this operation. They live in memory only and are gone after a
    /// restart; a handler that needs one then reports `needs_input`.
    pub secrets: Arc<BTreeMap<String, String>>,
    /// When this step last began (Unix seconds): what a handler finds that is older than this was
    /// not made by it.
    pub started_at: Option<i64>,
    /// The resource's recorded specification before this step, when it has a record.
    pub recorded: Option<Value>,
    /// What the person agreed to when applying, such as copying a sign-in from this computer
    /// (`copy_signin:RESOURCE/TOOL`). A template's own setting never stands in for it.
    pub consents: Arc<BTreeSet<String>>,
}

/// Another resource of the same setup, as the registry records it.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Peer {
    pub kind: Kind,
    pub spec: Value,
    pub runtime_id: Option<String>,
    pub owned: bool,
}

impl StepContext {
    /// The value behind a secret binding name from a plan. `apply.FIELD` is a value given with
    /// this operation's `setup_apply`, keyed by its field; other names are looked up as given.
    /// `None` when this operation was not given it: report `Outcome::NeedsInput` then.
    pub(crate) fn secret(&self, binding: &str) -> Option<&str> {
        let given = |key: &str| self.secrets.get(key).map(String::as_str);
        match binding.strip_prefix("apply.") {
            Some(field) => given(field).or_else(|| given(&format!("apply:{field}"))),
            None => given(binding),
        }
    }
}

/// What a handler found when it looked for a resource.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Observation {
    Absent,
    Present {
        runtime_id: String,
        observed: Observed,
        /// The label of the last step applied to it, when the provider keeps one.
        label: Option<String>,
        retained_data: bool,
        cost: Cost,
    },
    /// The provider could not be asked, so nothing can be concluded.
    Unknown { reason: String },
}

/// What reconciliation concluded about a step whose outcome was unknown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Recovery {
    /// The effect happened. The receipt is adopted; nothing is done again.
    Applied(Receipt),
    /// The effect did not happen, so the step may safely run again.
    NotApplied,
    Unknown { reason: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// Nothing was changed: the step may run again as it is.
    NotStarted,
    /// The handler is sure the step failed and left nothing behind it does not report.
    Failed,
    /// The call may have taken effect (a timeout, a lost connection, a cancelled call).
    Unknown,
    /// This handler cannot do this here. Nothing was changed.
    Unsupported,
    /// The step needs an answer or secret the operation does not have. Nothing was changed.
    NeedsInput,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HandlerError {
    pub code: String,
    pub message: String,
    pub retryable: bool,
    pub outcome: Outcome,
    /// The field an answer is for, when the error is `Outcome::NeedsInput` and the handler knows
    /// which question's value it lacks: the question's id, as a client sends secrets by.
    pub field: Option<String>,
}

impl HandlerError {
    pub(crate) fn new(outcome: Outcome, code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            retryable: matches!(outcome, Outcome::NotStarted | Outcome::Unknown),
            outcome,
            field: None,
        }
    }
    /// Names the field the missing answer is for.
    pub(crate) fn at(mut self, field: &str) -> Self {
        self.field = Some(field.to_owned());
        self
    }
    pub(crate) fn unsupported(kind: Kind, operation: &str) -> Self {
        Self::new(
            Outcome::Unsupported,
            "unsupported_operation",
            format!("Yougori can't {operation} a {} resource on this computer yet. Nothing was changed.", words(kind)),
        )
    }
    pub(crate) fn diagnostic(&self) -> Diagnostic {
        let mut diagnostic = Diagnostic::new(&self.code, self.message.clone());
        diagnostic.retryable = self.retryable;
        diagnostic.field = self.field.clone();
        diagnostic
    }
}

/// How a resource is doing, from a real probe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HealthReport {
    pub health: Health,
    pub detail: String,
}

/// A planning answer for one declared resource.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Planned {
    /// The resource already matches; no step is needed.
    Unchanged,
    Step(Action),
}

/// What a change to new work asks of a resource that takes work in (`ResourceHandler::admission`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Admission {
    /// Take no new work. With `drain`, what is running runs to its end; without, each running piece
    /// is asked to stop, as a cancel asks. Nothing is killed and nothing is deleted.
    Pause { drain: bool },
    /// Take new work again.
    Resume,
}

pub(crate) trait ResourceHandler: Send + Sync {
    fn kind(&self) -> Kind;

    /// Checks a specification without touching anything.
    fn validate(&self, spec: &Value) -> Result<(), HandlerError>;

    /// Plain notes for the review of a step on this resource, such as a sign-in left for a person
    /// or what removing it deletes and when.
    fn notes(&self, setup: &str, resource: &str, spec: &Value, action: Action) -> Vec<String> {
        let _ = (setup, resource, spec, action);
        Vec::new()
    }

    /// What removing the whole setup may also do to this resource, only if the person ticks it,
    /// such as deleting a grid it made at once instead of pausing it. Each `{"id", "message"}` is
    /// shown unticked on the removal review; an id starting with `delete_` is accepted only from
    /// the review that offered it, and reaches `remove` as `context.consents`. Nothing by default.
    fn removal_offers(&self, setup: &str, resource: &str, spec: &Value) -> Vec<Value> {
        let _ = (setup, resource, spec);
        Vec::new()
    }

    /// What changing this resource in place does beyond its new settings, for the review: a
    /// sandbox made anew from a new image, say, and what happens to the data of the old one.
    fn change_notes(&self, setup: &str, resource: &str, previous: &Value, spec: &Value) -> Vec<String> {
        let _ = (setup, resource, previous, spec);
        Vec::new()
    }

    /// Checks a declared resource against the rest of its setup at review, before anything runs:
    /// what the resources it names must be for it to work. `others` holds the setup's other
    /// declared resources by ID.
    fn review(&self, id: &str, spec: &Value, others: &BTreeMap<String, (Kind, Value)>) -> Result<(), HandlerError> {
        let _ = (id, spec, others);
        Ok(())
    }

    /// Forgets what the handler keeps for a setup outside its resources, such as vault entries,
    /// once the setup has been removed.
    fn forget_setup<'a>(&'a self, setup: &'a str) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        let _ = setup;
        Box::pin(async {})
    }

    /// Whether resources of this kind run, so that stopping and starting a setup applies to them.
    /// A volume or a connection doesn't run; it is left alone by stop and start.
    fn stoppable(&self) -> bool {
        true
    }

    /// Whether this one resource stops and starts with its setup. Most kinds answer as their
    /// handler does (`stoppable`); a kind where it depends on the resource says so here.
    fn stops(&self, spec: &Value) -> bool {
        let _ = spec;
        self.stoppable()
    }

    /// Whether starting the setup again should reach this resource while it runs, because it holds
    /// something a start renews (a VM sandbox's connection grants, which expire). Its `apply` with
    /// `Start` then renews it without making it again. No by default.
    fn renews_when_running(&self, spec: &Value) -> bool {
        let _ = spec;
        false
    }

    /// Decides the step for a declared resource, from its record and the wanted specification.
    /// The default creates what does not exist and updates what changed.
    fn plan(&self, current: Option<&Resource>, spec: &Value, spec_digest: &str) -> Result<Planned, HandlerError> {
        Ok(match current {
            None => Planned::Step(Action::Create),
            Some(resource) if resource.runtime_id.is_none() => Planned::Step(Action::Create),
            Some(resource) if resource.spec_digest != spec_digest => {
                let _ = spec;
                Planned::Step(Action::Update)
            }
            Some(_) => Planned::Unchanged,
        })
    }

    /// Looks the resource up by its runtime ID, or by `created_label` before it has one.
    fn observe<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Observation>;

    /// Creates, updates or starts the resource, as `context.action` says.
    fn apply<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Receipt>;

    fn health<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, HealthReport> {
        Box::pin(async move { Err(HandlerError::unsupported(context.kind, "check the health of")) })
    }

    /// What this resource shows of itself right now: the outputs its kind declares
    /// (`Kind::outputs`), as the product reports them. Only values that are known; one that isn't
    /// yet is left out, never filled with a stand-in. A private one, such as an invite, is given
    /// here too, and the engine keeps it nowhere: it is only ever rendered for a reveal. Looks
    /// only; it never changes anything.
    fn outputs<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, BTreeMap<String, String>> {
        let _ = context;
        Box::pin(async { Ok(BTreeMap::new()) })
    }

    /// Whether this kind of resource takes work in, such as a job queue, so that new work can be
    /// paused for it and resumed (`admission`).
    fn takes_work(&self) -> bool {
        false
    }

    /// Pauses or resumes new work for this resource, keeping everything it holds, and says what
    /// was done in a sentence. Unsupported unless it `takes_work`.
    fn admission<'a>(&'a self, context: &'a StepContext, change: Admission) -> HandlerFuture<'a, String> {
        let _ = change;
        Box::pin(async move { Err(HandlerError::unsupported(context.kind, "pause new work for")) })
    }

    /// The rented compute this resource holds now that may be billing, for a release's review:
    /// `{provider, computers: [{id, name, …}], notes}`, the notes saying in the provider's own
    /// terms what releasing does and when its charges stop. `None` when it holds none. Only looks.
    fn rented<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Option<Value>> {
        let _ = context;
        Box::pin(async { Ok(None) })
    }

    /// Gives back the rented compute this resource holds, as its provider does it, and answers what
    /// came of it: `{provider, said, unconfirmed, confirmed}`. Charges are called stopped only once
    /// the provider confirms it; anything it hasn't is named in `unconfirmed`. Unsupported unless
    /// it holds rented compute.
    fn release<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Value> {
        Box::pin(async move { Err(HandlerError::unsupported(context.kind, "release the rented computers of")) })
    }

    fn stop<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Receipt> {
        Box::pin(async move { Err(HandlerError::unsupported(context.kind, "stop")) })
    }

    /// Drops this setup's binding to a borrowed resource. Must never stop or delete it.
    fn detach<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Receipt> {
        Box::pin(async move { Err(HandlerError::unsupported(context.kind, "detach")) })
    }

    /// Removes the resource. Its data is kept unless the specification explicitly says otherwise.
    fn remove<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Receipt> {
        Box::pin(async move { Err(HandlerError::unsupported(context.kind, "remove")) })
    }

    /// Settles a step whose outcome is unknown, by looking rather than acting again.
    fn recover<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Recovery> {
        Box::pin(async move { Ok(recovery_from(context, self.observe(context).await?)) })
    }
}

/// The default reading of an observation for each kind of step.
pub(crate) fn recovery_from(context: &StepContext, observation: Observation) -> Recovery {
    let receipt = |runtime_id: Option<String>, observed, retained_data, cost| Receipt {
        runtime_id,
        observed,
        retained_data,
        cost,
        at: now(),
        adopted: true,
    };
    match (context.action, observation) {
        (_, Observation::Unknown { reason }) => Recovery::Unknown { reason },
        (Action::Create | Action::Update, Observation::Present { runtime_id, observed, label, retained_data, cost }) => {
            if label.as_deref() == Some(context.label.as_str()) {
                Recovery::Applied(receipt(Some(runtime_id), observed, retained_data, cost))
            } else if context.action == Action::Update {
                Recovery::NotApplied
            } else {
                Recovery::Unknown {
                    reason: "A resource with this name exists, but Yougori can't confirm it is the one this step created.".into(),
                }
            }
        }
        (Action::Create, Observation::Absent) => Recovery::NotApplied,
        (Action::Update | Action::Start | Action::Stop, Observation::Absent) => Recovery::Unknown {
            reason: "The resource is no longer there.".into(),
        },
        (Action::Start, Observation::Present { runtime_id, observed, retained_data, cost, .. }) => match observed {
            Observed::Running => Recovery::Applied(receipt(Some(runtime_id), observed, retained_data, cost)),
            _ => Recovery::NotApplied,
        },
        (Action::Stop, Observation::Present { runtime_id, observed, retained_data, cost, .. }) => match observed {
            Observed::Stopped => Recovery::Applied(receipt(Some(runtime_id), observed, retained_data, cost)),
            _ => Recovery::NotApplied,
        },
        (Action::Remove, Observation::Absent) => Recovery::Applied(receipt(None, Observed::Missing, false, Cost::Unknown)),
        (Action::Remove, Observation::Present { .. }) => Recovery::NotApplied,
        // The engine's own record changes, saved with their receipt in one commit.
        (Action::Attach | Action::Detach, _) => Recovery::NotApplied,
    }
}

/// Handlers by resource kind. A kind with no handler is refused before anything changes.
#[derive(Clone, Default)]
pub(crate) struct Handlers {
    by_kind: BTreeMap<Kind, Arc<dyn ResourceHandler>>,
}

impl Handlers {
    pub(crate) fn register(&mut self, handler: Arc<dyn ResourceHandler>) {
        self.by_kind.insert(handler.kind(), handler);
    }

    pub(crate) fn get(&self, kind: Kind) -> Result<Arc<dyn ResourceHandler>, Diagnostic> {
        self.by_kind.get(&kind).cloned().ok_or_else(|| {
            Diagnostic::new(
                "unsupported_resource",
                format!("Yougori can't manage {} resources on this computer yet. Nothing was changed.", words(kind)),
            )
        })
    }

    pub(crate) fn kinds(&self) -> Vec<Kind> {
        self.by_kind.keys().copied().collect()
    }

    pub(crate) fn all(&self) -> impl Iterator<Item = &Arc<dyn ResourceHandler>> {
        self.by_kind.values()
    }
}

/// A resource kind as words in a sentence: `model_service` → `model service`.
pub(crate) fn words(kind: Kind) -> String {
    kind.as_str().replace('_', " ")
}


#[cfg(test)]
pub(crate) mod fake {
    //! An in-memory provider for tests only. It counts every effect so a test can prove nothing
    //! was created twice, and it can fail, block or lose answers on request.
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Mutex;

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) struct FakeResource {
        pub label: String,
        pub running: bool,
    }

    #[derive(Default)]
    pub(crate) struct Provider {
        pub resources: BTreeMap<String, FakeResource>,
        pub creates: u32,
        pub calls: Vec<String>,
        /// Resource IDs whose next N applies fail.
        pub fail: BTreeMap<String, u32>,
        /// Resource IDs whose apply waits for cancellation, then reports an unknown outcome.
        pub hang: BTreeSet<String>,
        /// Resource IDs whose apply creates the resource and then loses the answer.
        pub lose_answer: BTreeSet<String>,
        /// Resource IDs whose apply waits on `gate` before acting.
        pub gated: BTreeSet<String>,
        /// Observation fails as an unreachable provider would.
        pub unreachable: bool,
        /// Resource IDs whose removal keeps their data.
        pub retain: BTreeSet<String>,
        /// Resource IDs whose apply needs the secret named in their spec's `secretRef`.
        pub needs_secret: BTreeSet<String>,
        next: u32,
    }

    pub(crate) struct FakeHandler {
        pub kind: Kind,
        pub provider: Arc<Mutex<Provider>>,
        pub gate: Arc<tokio::sync::Semaphore>,
        pub entered: Arc<tokio::sync::Notify>,
    }

    impl FakeHandler {
        pub(crate) fn new(kind: Kind) -> Self {
            Self {
                kind,
                provider: Default::default(),
                gate: Arc::new(tokio::sync::Semaphore::new(0)),
                entered: Default::default(),
            }
        }
        fn receipt(runtime_id: Option<String>, observed: Observed) -> Receipt {
            Receipt { runtime_id, observed, retained_data: false, cost: Cost::Free, at: now(), adopted: false }
        }
    }

    impl ResourceHandler for FakeHandler {
        fn kind(&self) -> Kind {
            self.kind
        }

        fn validate(&self, spec: &Value) -> Result<(), HandlerError> {
            if spec.get("invalid").is_some() {
                return Err(HandlerError::new(Outcome::Failed, "invalid_spec", "This resource's settings are not valid."));
            }
            Ok(())
        }

        fn observe<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Observation> {
            Box::pin(async move {
                let provider = self.provider.lock().unwrap();
                if provider.unreachable {
                    return Ok(Observation::Unknown { reason: "The provider did not answer.".into() });
                }
                let found = match &context.runtime_id {
                    Some(id) => provider.resources.get(id).map(|resource| (id.clone(), resource.clone())),
                    None => provider
                        .resources
                        .iter()
                        .find(|(_, resource)| Some(&resource.label) == context.created_label.as_ref())
                        .map(|(id, resource)| (id.clone(), resource.clone())),
                };
                Ok(match found {
                    None => Observation::Absent,
                    Some((runtime_id, resource)) => Observation::Present {
                        runtime_id,
                        observed: if resource.running { Observed::Running } else { Observed::Stopped },
                        label: Some(resource.label),
                        retained_data: false,
                        cost: Cost::Free,
                    },
                })
            })
        }

        fn apply<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Receipt> {
            Box::pin(async move {
                let (gated, hang) = {
                    let mut provider = self.provider.lock().unwrap();
                    provider.calls.push(format!("{}:{}", context.action.as_str(), context.resource));
                    (provider.gated.contains(&context.resource), provider.hang.contains(&context.resource))
                };
                self.entered.notify_one();
                if gated {
                    tokio::select! {
                        permit = self.gate.acquire() => permit.unwrap().forget(),
                        _ = context.cancel.cancelled() => {
                            return Err(HandlerError::new(Outcome::NotStarted, "operation_cancelled", "Cancelled before anything was created."));
                        }
                    }
                }
                if self.provider.lock().unwrap().needs_secret.contains(&context.resource) {
                    let name = context.spec["secretRef"].as_str().unwrap_or_default();
                    if !context.secrets.contains_key(name) {
                        return Err(HandlerError::new(Outcome::NeedsInput, "needs_secret", "This step needs a password that hasn't been given yet."));
                    }
                }
                if hang {
                    context.cancel.cancelled().await;
                    return Err(HandlerError::new(Outcome::Unknown, "outcome_unknown", "The provider call was cancelled while it was running."));
                }
                let mut provider = self.provider.lock().unwrap();
                if let Some(remaining) = provider.fail.get_mut(&context.resource) {
                    if *remaining > 0 {
                        *remaining -= 1;
                        let mut error = HandlerError::new(Outcome::Failed, "provider_failed", "The provider refused to create this resource.");
                        error.retryable = true;
                        return Err(error);
                    }
                }
                match context.action {
                    Action::Create => {
                        provider.next += 1;
                        provider.creates += 1;
                        let id = format!("fake-{}", provider.next);
                        provider.resources.insert(
                            id.clone(),
                            FakeResource { label: context.label.clone(), running: true },
                        );
                        if provider.lose_answer.remove(&context.resource) {
                            return Err(HandlerError::new(Outcome::Unknown, "outcome_unknown", "The provider stopped answering."));
                        }
                        Ok(Self::receipt(Some(id), Observed::Running))
                    }
                    Action::Update | Action::Start => {
                        let id = context.runtime_id.clone().ok_or_else(|| {
                            HandlerError::new(Outcome::Failed, "resource_missing", "This resource does not exist yet.")
                        })?;
                        let resource = provider.resources.get_mut(&id).ok_or_else(|| {
                            HandlerError::new(Outcome::Failed, "resource_missing", "This resource is no longer there.")
                        })?;
                        resource.running = true;
                        resource.label = context.label.clone();
                        Ok(Self::receipt(Some(id), Observed::Running))
                    }
                    _ => Err(HandlerError::unsupported(self.kind, context.action.as_str())),
                }
            })
        }

        fn stop<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Receipt> {
            Box::pin(async move {
                let mut provider = self.provider.lock().unwrap();
                provider.calls.push(format!("stop:{}", context.resource));
                let id = context.runtime_id.clone().unwrap_or_default();
                let resource = provider.resources.get_mut(&id).ok_or_else(|| {
                    HandlerError::new(Outcome::Failed, "resource_missing", "This resource is no longer there.")
                })?;
                resource.running = false;
                Ok(Self::receipt(Some(id), Observed::Stopped))
            })
        }

        fn detach<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Receipt> {
            Box::pin(async move {
                self.provider.lock().unwrap().calls.push(format!("detach:{}", context.resource));
                Ok(Self::receipt(context.runtime_id.clone(), Observed::Present))
            })
        }

        fn remove<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Receipt> {
            Box::pin(async move {
                let mut provider = self.provider.lock().unwrap();
                provider.calls.push(format!("remove:{}", context.resource));
                if let Some(id) = &context.runtime_id {
                    provider.resources.remove(id);
                }
                let mut receipt = Self::receipt(None, Observed::Missing);
                receipt.retained_data = provider.retain.contains(&context.resource);
                Ok(receipt)
            })
        }
    }
}
