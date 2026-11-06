//! Handlers for the grid resources of the Neo Grid, Sandbox Grid and Access Grid recipes: the grid
//! itself (created here, joined as a computer, or signed in to as a person), its pool of
//! computers, the models it serves (Neo), its workspaces and people (Sandbox), and its people and
//! brokered credentials (Access). They call each product's own functions (`grid_create`,
//! `desks_create`, `access_create`, `grid_plan_add`, `desks_person_add`, `access_manage` and the
//! rest) through the same entry the CLI uses, so a grid made from a template is the same grid its
//! own tab in My setups manages.
//!
//! Several grids of one kind can share a computer: each product keeps each grid in an instance of
//! its own (`default` for a computer's first, `i-` and eight hex digits for each later one, with its
//! own folder, ports and vault names). A grid made, joined or signed in to gets its instance from
//! the product, a setup records which (`ID@KEY`, `located`), and every call about that grid names
//! it. One instance is held by one setup at a time (`service::one_owner_per_instance`). A research
//! grid (Swarm Mining) and its worker are handled in `research`.
//!
//! A handler only ever acts on what this setup made: the hub, membership, sign-in, plan, person or
//! credential whose ID it recorded (or, before a receipt exists, one the product says was made
//! after the step began). Anything else of the same kind belongs to the person, and is left alone.
use super::handler::{HandlerError, HandlerFuture, HealthReport, Observation, Outcome, Planned, Recovery, ResourceHandler, StepContext};
use super::local_models::{self, LocalModels};
use super::share::{self, Shares};
use super::journal::{Action, Receipt};
use super::model::{now, Cost, Health, Observed, Resource};
use super::ordinary::BoxFuture;
use serde_json::{json, Value};
use std::{collections::BTreeMap, sync::Arc};
use yougori_setup::resource::Kind;

pub(crate) mod research;

/// The product calls the grid handlers make. `EngineGrids` calls the engine; tests use a fake.
pub(crate) trait GridCalls: Send + Sync {
    fn call<'a>(&'a self, method: &'a str, params: Value) -> BoxFuture<'a, Result<Value, String>>;
    /// Keeps a value in this computer's credential vault under `name`.
    fn keep(&self, name: &str, value: &str) -> Result<(), String> {
        crate::projects::secrets::store_bytes(name, value.as_bytes())
    }
    /// What `keep` kept under `name`, if anything.
    fn kept(&self, name: &str) -> Result<Option<String>, String> {
        Ok(crate::projects::secrets::resolve_bytes(name)?.and_then(|bytes| String::from_utf8(bytes).ok()))
    }
    /// Forgets what `keep` kept under `name`.
    fn forget(&self, name: &str) -> Result<(), String> {
        crate::projects::secrets::forget(name)
    }
}

/// A person's scoped invitation (`people.invites`): the grid's own invite, with the username and
/// the password their account was made with, as one code to paste. It is one person's way in, at
/// the role their account has, and stops working when the password is changed or the account
/// removed. Nobody types the password; the code is a private output, read only when asked.
pub(crate) mod scoped {
    use base64::Engine;
    use serde_json::{json, Value};

    pub(crate) const PREFIX: &str = "yougori-invite:";

    pub(crate) struct Invitation {
        pub invite: String,
        pub username: String,
        pub password: String,
    }

    pub(crate) fn encode(invite: &str, username: &str, password: &str) -> String {
        let body = json!({"v": 1, "invite": invite, "username": username, "password": password}).to_string();
        format!("{PREFIX}{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(body))
    }

    pub(crate) fn decode(text: &str) -> Option<Invitation> {
        let body = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(text.trim().strip_prefix(PREFIX)?).ok()?;
        let value: Value = serde_json::from_slice(&body).ok()?;
        let field = |key: &str| value[key].as_str().map(str::to_owned).filter(|text| !text.is_empty());
        (value["v"] == 1).then_some(())?;
        Some(Invitation { invite: field("invite")?, username: field("username")?, password: field("password")? })
    }

    /// A password nobody types: 24 letters and digits.
    pub(crate) fn password() -> String {
        let mut made = String::new();
        while made.len() < 24 {
            made.extend(uuid::Uuid::new_v4().simple().to_string().chars().filter(|c| c.is_ascii_alphanumeric()));
        }
        made.truncate(24);
        made
    }
}

pub(crate) struct EngineGrids {
    app: crate::AppHandle,
}

impl EngineGrids {
    pub(crate) fn new(app: crate::AppHandle) -> Self {
        Self { app }
    }
}

impl GridCalls for EngineGrids {
    fn call<'a>(&'a self, method: &'a str, params: Value) -> BoxFuture<'a, Result<Value, String>> {
        Box::pin(async move { crate::automation::dispatch::dispatch(&self.app, method, &params).await })
    }
}

#[derive(Clone)]
pub(crate) struct Grids {
    calls: Arc<dyn GridCalls>,
}

/// What a product call returns when the step was cancelled while it waited.
const CANCELLED: &str = "\u{0}cancelled";

/// The image a rented GPU runs: RunPod's own PyTorch image with CUDA and SSH, which the grid's
/// stand-in for it signs in to.
const RENTED_IMAGE: &str = "runpod/pytorch:2.8.0-py3.11-cuda12.8.1-cudnn-devel-ubuntu22.04";
/// How often a rented GPU that is still starting is asked to join again.
#[cfg(not(test))]
const POD_WAIT: std::time::Duration = std::time::Duration::from_secs(10);
#[cfg(test)]
const POD_WAIT: std::time::Duration = std::time::Duration::from_millis(10);

impl Grids {
    pub(crate) fn new(calls: Arc<dyn GridCalls>) -> Self {
        Self { calls }
    }

    pub(crate) fn handlers(&self) -> Vec<Arc<dyn ResourceHandler>> {
        vec![
            Arc::new(GridHandler(self.clone())),
            Arc::new(ComputePoolHandler(self.clone())),
            Arc::new(ModelServiceHandler(self.clone())),
            Arc::new(WorkspacePoolHandler),
            Arc::new(AccessBindingHandler(self.clone())),
            Arc::new(CredentialBrokerHandler(self.clone())),
            Arc::new(research::WorkerGroupHandler(self.clone())),
        ]
    }

    /// A product call that gives way to the step's cancellation. The product may still finish
    /// what it began, so a cancelled call's outcome is settled by looking (`failed`).
    async fn ask(&self, context: &StepContext, method: &str, params: Value) -> Result<Value, String> {
        tokio::select! {
            result = self.calls.call(method, params) => result,
            _ = context.cancel.cancelled() => Err(CANCELLED.into()),
        }
    }

    /// `ask`, about the grid in the product's instance `key` (`gridId`).
    async fn ask_in(&self, context: &StepContext, key: &str, method: &str, mut params: Value) -> Result<Value, String> {
        params["gridId"] = json!(key);
        self.ask(context, method, params).await
    }

    /// Manages this setup's Access Grid, in the instance `key`, as its owner. Call `own_access`
    /// first.
    async fn manage(&self, context: &StepContext, key: &str, request: Value) -> Result<Value, String> {
        self.ask_in(context, key, "access_manage", json!({ "request": request })).await
    }

    /// What this setup's Access Grid, in the instance `key`, holds: its people, credentials and
    /// rules.
    async fn overview(&self, key: &str) -> Result<Value, String> {
        self.calls.call("access_manage", json!({"request": {"action": "overview"}, "gridId": key})).await
    }

    /// The product's status of every grid of its kind on this computer: the first one's in the
    /// single fields, every one in its lists (`hubs`, `members`, `logins`).
    async fn status_all(&self, product: Product) -> Result<Value, HandlerError> {
        self.calls.call(product.status, json!({})).await.map_err(|error| unavailable(&error))
    }

    /// The product's status of the grid in its instance `key` alone. `None` when the product no
    /// longer has that instance (the grid in it was deleted and forgotten), which reads as the grid
    /// being gone; an error only when the product could not be asked.
    async fn status_in(&self, product: Product, key: &str) -> Result<Option<Value>, HandlerError> {
        match self.calls.call(product.status, json!({"gridId": key})).await {
            Ok(status) => Ok(Some(status)),
            Err(error) => {
                let all = self.status_all(product).await?;
                let listed = ["hubs", "members", "logins"].iter().flat_map(|field| all[*field].as_array().into_iter().flatten()).any(|entry| entry["instance"].as_str() == Some(key));
                if listed {
                    Err(unavailable(&error))
                } else {
                    Ok(None)
                }
            }
        }
    }

    /// The Access Grid this setup made (`grid`, as recorded), running here, open, and managed by
    /// its owner: never a company's grid reached through someone's sign-in on this computer
    /// (`access_manage` acts as whoever is signed in). `None` when it is gone or paused for
    /// deletion.
    async fn own_access(&self, grid: &str) -> Result<Option<Value>, HandlerError> {
        let (id, key) = located(grid);
        let Some(status) = self.status_in(Product::ACCESS, key).await? else { return Ok(None) };
        let hub = &status["hub"];
        if hub["id"].as_str() != Some(id) || !hub["closing"].is_null() {
            return Ok(None);
        }
        let owner = hub["owner"].as_str().unwrap_or_default();
        if let Some(signed_in) = status["member"]["username"].as_str() {
            if !signed_in.eq_ignore_ascii_case(owner) {
                return Err(HandlerError {
                    retryable: true,
                    ..HandlerError::new(
                        Outcome::NotStarted,
                        "someone_else_signed_in",
                        "Someone other than the Access Grid's owner is signed in to it on this computer, so a change would be made as them. Sign them out from the grid in My setups, then retry.",
                    )
                });
            }
        }
        Ok(Some(status))
    }
}

/// The product calls of one grid profile.
#[derive(Clone, Copy)]
struct Product {
    status: &'static str,
    create: &'static str,
    join: &'static str,
    delete: &'static str,
    leave: &'static str,
    name: &'static str,
}

impl Product {
    const NEO: Product = Product { status: "grid_status", create: "grid_create", join: "grid_join", delete: "grid_delete", leave: "grid_leave", name: "Neo Grid" };
    const SANDBOX: Product = Product { status: "desks_status", create: "desks_create", join: "desks_join", delete: "desks_delete", leave: "desks_leave", name: "Sandbox Grid" };
    /// An Access Grid has people, not computers: nobody joins it as a computer.
    const ACCESS: Product = Product { status: "access_status", create: "access_create", join: "", delete: "access_delete", leave: "", name: "Access Grid" };

    fn of(spec: &Value) -> Option<Product> {
        match spec["profile"].as_str() {
            Some("neo_grid") => Some(Product::NEO),
            Some("sandbox_grid") => Some(Product::SANDBOX),
            Some("access_grid") => Some(Product::ACCESS),
            _ => None,
        }
    }

    fn is(self, other: Product) -> bool {
        self.status == other.status
    }

    /// Where the product's status keeps this computer's sign-in as a person.
    fn session(self, status: &Value) -> &Value {
        if self.is(Product::ACCESS) { &status["member"] } else { &status["desk"] }
    }
}

/// The product of the grid another resource of this setup names with `{resource: ID}`.
fn product_of(context: &StepContext, reference: &Value) -> Option<Product> {
    reference["resource"].as_str().and_then(|id| context.peers.get(id)).and_then(|peer| Product::of(&peer.spec))
}

/// The recorded hub ID of the grid another resource names with `{resource: ID}`.
fn grid_id(context: &StepContext, reference: &Value) -> Option<String> {
    reference["resource"].as_str().and_then(|id| context.peers.get(id)).and_then(|peer| peer.runtime_id.clone())
}

/// The declared grid a resource names, at review: its profile and mode.
fn declared_grid<'a>(reference: &Value, others: &'a BTreeMap<String, (Kind, Value)>) -> Option<(&'a str, &'a str)> {
    let (kind, spec) = others.get(reference["resource"].as_str()?)?;
    (*kind == Kind::Grid).then(|| (spec["profile"].as_str().unwrap_or_default(), spec["mode"].as_str().unwrap_or("create")))
}

fn refused(message: &str) -> HandlerError {
    HandlerError::new(Outcome::Unsupported, "unsupported_here", format!("{message} Nothing was changed."))
}

fn invalid(message: impl Into<String>) -> HandlerError {
    HandlerError::new(Outcome::Failed, "invalid_spec", message)
}

/// A product's message without the CLI commands it suggests, which mean nothing here.
fn plain(message: &str) -> String {
    let message = crate::lifecycle::safe_diagnostic(message);
    // The products end some refusals with the command to type next; a setup has its own next steps.
    let kept = message.split_inclusive(". ").filter(|sentence| !sentence.contains('`') && !sentence.contains(" --")).collect::<String>();
    let kept = kept.trim();
    if kept.is_empty() { message.trim().to_owned() } else { kept.to_owned() }
}

/// A product refusal, or a call cut short by cancelling, whose outcome is then unknown.
fn failed(context: &StepContext, error: String) -> HandlerError {
    if error == CANCELLED || context.cancel.is_cancelled() {
        return HandlerError::new(Outcome::Unknown, "outcome_unknown", "Cancelled while waiting for the grid. Checking what happened before anything else runs.");
    }
    HandlerError::new(Outcome::Failed, "grid_refused", plain(&error))
}

/// Something of this kind on this computer that this setup didn't make: never taken over.
fn taken(message: String) -> HandlerError {
    HandlerError { retryable: true, ..HandlerError::new(Outcome::Failed, "already_in_use", message) }
}

fn receipt(runtime_id: Option<String>, observed: Observed, retained_data: bool) -> Receipt {
    Receipt { runtime_id, observed, retained_data, cost: Cost::Free, at: now(), adopted: false }
}

fn text(spec: &Value, field: &str) -> Option<String> {
    spec[field].as_str().map(str::trim).filter(|value| !value.is_empty()).map(str::to_owned)
}

/// Each grid product's first instance: the one every setup's grid was in before several grids of a
/// kind could share a computer, and the one a computer's first grid of a kind still takes.
pub(crate) const FIRST: &str = crate::grid::instances::DEFAULT;

/// A grid's recorded ID and the product instance it is in: `ID@KEY` for a grid in one of the
/// product's later instances (`i-` and eight hex digits), the ID alone for one in its first.
pub(crate) fn located(record: &str) -> (&str, &str) {
    match record.rsplit_once('@') {
        Some((id, key)) if key != FIRST && crate::grid::instances::is_key(key) => (id, key),
        _ => (record, FIRST),
    }
}

/// How a grid in the product's instance `key` is recorded (`located` reads it back).
fn recorded(id: &str, key: &str) -> String {
    if key == FIRST {
        id.to_owned()
    } else {
        format!("{id}@{key}")
    }
}

/// The instance a product's answer says it acted in: its own `instance`, or its hub's, its
/// membership's or its sign-in's. The first when it names none.
fn answered_in(answer: &Value) -> String {
    [&answer["instance"], &answer["hub"]["instance"], &answer["member"]["instance"], &answer["desk"]["instance"]]
        .into_iter()
        .find_map(|value| value.as_str().filter(|key| crate::grid::instances::is_key(key)))
        .unwrap_or(FIRST)
        .to_owned()
}

/// A product that could not be asked: nothing can be concluded from it.
fn unavailable(error: &str) -> HandlerError {
    HandlerError::new(Outcome::Unknown, "grid_unavailable", plain(error))
}

/// Where computers or people reach a hub, as its status says: its tunnel's link once that is
/// connected when it has one, otherwise its address and port. `None` while a tunnel has no link.
fn reach(hub: &Value) -> Option<String> {
    if !hub["tunnel"].is_null() {
        return text(&hub["tunnel"], "url");
    }
    let address = hub["address"].as_str()?;
    let port = hub["port"].as_u64()?;
    Some(if address.contains(':') { format!("[{address}]:{port}") } else { format!("{address}:{port}") })
}

/// The value of a secret binding the spec names under `secrets:`, given with this operation.
fn secret(context: &StepContext, name: &str) -> Result<String, HandlerError> {
    let binding = context.spec["secrets"][name].as_str().unwrap_or_default();
    context.secret(binding).map(str::to_owned).ok_or_else(|| {
        HandlerError::new(
            Outcome::NeedsInput,
            "secret_needed",
            format!("{} needs the {} before it can continue.", context.resource, name.replace('_', " ")),
        )
    })
}

/// Unix seconds from a product timestamp: seconds, milliseconds or RFC 3339.
fn seconds(value: &Value) -> Option<i64> {
    match value {
        Value::Number(number) => number.as_i64().map(|at| if at > 100_000_000_000 { at / 1000 } else { at }),
        Value::String(at) => chrono::DateTime::parse_from_rfc3339(at).ok().map(|at| at.timestamp()),
        _ => None,
    }
}

/// Whether something the product made at `made` was made by this step: only when the step's own
/// start is known and it came after (allowing a few seconds of clock rounding).
fn made_by_step(context: &StepContext, made: &Value) -> bool {
    matches!((context.started_at, seconds(made)), (Some(start), Some(at)) if at >= start - 5)
}

/// The default plan, except that a resource that can't be changed in place is refused at review
/// rather than half-way through applying.
fn fixed_once_made(current: Option<&Resource>, spec_digest: &str, message: &str) -> Result<Planned, HandlerError> {
    Ok(match current {
        None => Planned::Step(Action::Create),
        Some(resource) if resource.runtime_id.is_none() => Planned::Step(Action::Create),
        Some(resource) if resource.spec_digest != spec_digest => return Err(refused(message)),
        Some(_) => Planned::Unchanged,
    })
}

/// The day a grid paused today is deleted.
fn deletion_day() -> String {
    (chrono::Local::now() + chrono::Duration::days(3)).format("%-d %B %Y").to_string()
}

/// The removal review's choice, never ticked for the person, to delete a grid the setup made at
/// once instead of pausing it. `submit_agreed` accepts it only from the review that offered it.
pub(crate) const DELETE_GRID: &str = "delete_grid:";

pub(crate) fn delete_grid_consent(grid: &str) -> String {
    format!("{DELETE_GRID}{grid}")
}

// ----- The grid -----

pub(crate) struct GridHandler(Grids);

/// Where this setup's grid is now, as its product reports it.
struct Located {
    /// How it is recorded: its ID, with the instance it is in when that isn't the first.
    record: String,
    /// The product instance it is in, which every call about it names.
    key: String,
    /// Whether it is up: a hub not paused for deletion, a membership connected, a sign-in held.
    up: bool,
    /// The product's status of that instance.
    status: Value,
}

impl GridHandler {
    /// An Access Grid is made together with its first administrator, declared as an access
    /// binding with `admin:` on this grid; that binding's password is the administrator's.
    async fn create_access(&self, context: &StepContext) -> Result<Receipt, HandlerError> {
        let spec = &context.spec;
        let admin = context
            .planned
            .values()
            .chain(context.peers.values())
            .find(|peer| peer.kind == Kind::AccessBinding && peer.spec["grid"]["resource"].as_str() == Some(context.resource.as_str()) && !peer.spec["admin"].is_null())
            .map(|peer| peer.spec.clone())
            .ok_or_else(|| refused("An Access Grid is made with its first administrator; declare one with admin: on an access binding."))?;
        let binding = admin["secrets"]["admin_password"].as_str().unwrap_or_default();
        let password = context.secret(binding).map(str::to_owned).ok_or_else(|| {
            HandlerError::new(Outcome::NeedsInput, "secret_needed", format!("{} needs the administrator's password before it can be made.", context.resource))
        })?;
        let username = admin["admin"]["username"].as_str().unwrap_or_default();
        let request = json!({
            "company": text(spec, "name"),
            "address": text(spec, "address"),
            "username": username,
            "name": admin["admin"]["display_name"].as_str().unwrap_or(username),
            "password": password,
            "tunnel": Self::tunnel(spec),
        });
        let answer = self.0.ask(context, "access_create", request).await.map_err(|error| failed(context, error))?;
        let id = answer["hub"]["id"].as_str().ok_or_else(|| HandlerError::new(Outcome::Unknown, "outcome_unknown", "The grid didn't report its hub."))?;
        Ok(receipt(Some(recorded(id, &answered_in(&answer))), Observed::Running, true))
    }

    fn tunnel(spec: &Value) -> Option<String> {
        match spec["access"].as_str().unwrap_or("lan") {
            "quick" => Some("quick".to_owned()),
            "domain" => text(spec, "domain"),
            _ => None,
        }
    }

    fn joins(spec: &Value) -> bool {
        spec["mode"].as_str() == Some("join")
    }

    /// A hub the legacy product already runs here, adopted into this setup.
    fn adopted(spec: &Value) -> bool {
        spec["adopted"].as_bool() == Some(true)
    }

    /// A person signing in to a Sandbox or Access Grid, rather than a computer joining it.
    fn signs_in(spec: &Value) -> bool {
        Self::joins(spec) && spec["member"].as_str() == Some("person")
    }

    /// A grid this setup makes itself, not one it joins, signs in to or adopts: the only kind its
    /// removal may delete at once, and only when the person ticks that.
    fn creates(spec: &Value) -> bool {
        spec["mode"].as_str().unwrap_or("create") == "create" && !Self::adopted(spec)
    }

    /// The removal review's choice to delete this grid at once, naming what goes as the product's
    /// delete `now` takes it.
    fn deletion(resource: &str, calls: Product, spec: &Value) -> Value {
        let grid = format!("the {} {}", calls.name, text(spec, "name").unwrap_or_else(|| resource.to_owned()));
        let goes = if calls.is(Product::NEO) {
            "It stops at once, and its model plans, teams and API keys go with it. Each of its computers leaves it at its next check-in and removes the model the grid installed; then the grid's keys and company password are removed from this computer."
        } else if calls.is(Product::SANDBOX) {
            "It stops at once, and its people's accounts go with it. Each computer that hosts its desks, this one included, deletes them with their data at its next check-in; then the grid's keys and company password are removed from this computer."
        } else {
            "Its people, rules and stored credentials are wiped at once, and everyone is signed out. It tells people's computers it was deleted for 30 days, then removes itself."
        };
        json!({"id": delete_grid_consent(resource), "message": format!("Also delete {grid} now instead of pausing it. {goes} This can't be undone.")})
    }

    fn product(spec: &Value) -> Result<Product, HandlerError> {
        Product::of(spec).ok_or_else(|| refused("This kind of grid can't be set up from My setups yet."))
    }

    /// The Neo Grid this setup made, while it is here: its hub ID. `None` for any other grid: one
    /// it joined or signed in to, a hub it adopted, a Sandbox or an Access Grid.
    async fn own_neo_hub(&self, context: &StepContext) -> Result<Option<String>, HandlerError> {
        if !Self::creates(&context.spec) || !Product::of(&context.spec).is_some_and(|calls| calls.is(Product::NEO)) {
            return Ok(None);
        }
        Ok(self.locate(context, Product::NEO).await?.map(|found| located(&found.record).0.to_owned()))
    }

    /// The rented GPUs the product lists in the grid `grid` that may be billing, and only those:
    /// running or getting there, unchecked, or a stop NeoCloud hasn't confirmed yet ("Stopping").
    async fn billing_pods(&self, context: &StepContext, grid: &str) -> Result<Vec<Value>, HandlerError> {
        let status = self.0.ask(context, "grid_neocloud_status", json!({"gridId": grid})).await.map_err(|error| failed(context, error))?;
        Ok(status["members"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|pod| pod["gridId"].as_str() == Some(grid) && pod["podState"].as_str().is_some_and(|state| crate::rented_gpu::billing(state) || state == "Stopping"))
            .cloned()
            .collect())
    }

    /// This setup's hub, membership or sign-in as its product reports it now, with the status of
    /// the instance it is in: the one with the recorded ID, an adopted hub in the instance it was
    /// reviewed in, or before a receipt exists one made after this step began, wherever the
    /// product put it. `None` when it isn't there.
    async fn locate(&self, context: &StepContext, calls: Product) -> Result<Option<Located>, HandlerError> {
        let spec = &context.spec;
        let (id, key) = match context.runtime_id.as_deref() {
            Some(record) => {
                let (id, key) = located(record);
                (Some(id.to_owned()), key.to_owned())
            }
            // The person reviewed adopting the hub of this instance: it is this one.
            None if Self::adopted(spec) => (None, text(spec, "instance").unwrap_or_else(|| FIRST.to_owned())),
            None => match Self::made_now(context, calls, &self.0.status_all(calls).await?) {
                Some((id, key)) => (Some(id), key),
                None => return Ok(None),
            },
        };
        let Some(status) = self.0.status_in(calls, &key).await? else { return Ok(None) };
        Ok(Self::found(spec, calls, &status, id.as_deref()).map(|(id, up)| Located { record: recorded(&id, &key), key, up, status }))
    }

    /// This setup's hub, membership or sign-in in the status of the instance it is in, with whether
    /// it is up: the one with the recorded ID, or with none recorded (a hub being adopted), the
    /// instance's own.
    fn found(spec: &Value, calls: Product, status: &Value, id: Option<&str>) -> Option<(String, bool)> {
        if Self::signs_in(spec) {
            let session = calls.session(status);
            let name = session["username"].as_str()?;
            let wanted = id.map(str::to_owned).or_else(|| text(spec, "username"))?;
            return name.eq_ignore_ascii_case(&wanted).then_some((wanted, true));
        }
        if Self::joins(spec) {
            let member = &status["member"];
            let found = member["memberId"].as_str()?;
            return id.is_none_or(|id| id == found).then(|| (found.to_owned(), member["connected"] == true));
        }
        let hub = &status["hub"];
        let found = hub["id"].as_str()?;
        id.is_none_or(|id| id == found).then(|| (found.to_owned(), hub["closing"].is_null()))
    }

    /// What this step made before its receipt was saved, wherever the product put it: the hub,
    /// membership or sign-in that was made after the step began. Never one that was there before.
    fn made_now(context: &StepContext, calls: Product, all: &Value) -> Option<(String, String)> {
        let spec = &context.spec;
        let listed = |field: &str, single: &Value| {
            let mut entries = all[field].as_array().cloned().unwrap_or_default();
            if entries.is_empty() && !single.is_null() {
                entries.push(single.clone());
            }
            entries
        };
        let key = |entry: &Value| entry["instance"].as_str().filter(|key| crate::grid::instances::is_key(key)).unwrap_or(FIRST).to_owned();
        if Self::signs_in(spec) {
            let wanted = text(spec, "username")?;
            let field = if calls.is(Product::ACCESS) { "members" } else { "logins" };
            let found = listed(field, calls.session(all))
                .into_iter()
                .find(|entry| entry["username"].as_str().is_some_and(|name| name.eq_ignore_ascii_case(&wanted)) && made_by_step(context, &entry["signedInAt"]))?;
            return Some((wanted, key(&found)));
        }
        if Self::joins(spec) {
            let found = listed("members", &all["member"]).into_iter().find(|entry| made_by_step(context, &entry["joinedAt"]))?;
            return Some((found["memberId"].as_str()?.to_owned(), key(&found)));
        }
        let found = listed("hubs", &all["hub"]).into_iter().find(|entry| made_by_step(context, &entry["createdAt"]))?;
        Some((found["id"].as_str()?.to_owned(), key(&found)))
    }

    /// Whether this computer is already a member of the grid an invitation is for, by the
    /// fingerprint the invitation carries: joining it again would only move that membership,
    /// whoever's it is. An invitation that can't be read is left for the product to refuse.
    fn member_of(calls: Product, all: &Value, invite: &str) -> bool {
        let decoded = if calls.is(Product::SANDBOX) { yougori_grid::invite::decode_desk(invite) } else { yougori_grid::invite::decode(invite) };
        let Ok(invite) = decoded else { return false };
        all["members"]
            .as_array()
            .into_iter()
            .flatten()
            .chain(std::iter::once(&all["member"]))
            .any(|member| member["fingerprint"].as_str().is_some_and(|known| known.eq_ignore_ascii_case(&invite.fingerprint)))
    }

    /// The grid this computer is already signed in to that an invitation is for: a second sign-in
    /// to it would replace the first, whoever's it is. An Access Grid sign-in is told apart by the
    /// grid's fingerprint; a Sandbox Grid sign-in only by the grid's name, so two Sandbox Grids of
    /// one name count as one here.
    fn signed_in_to(calls: Product, all: &Value, invite: &str) -> Option<String> {
        if calls.is(Product::ACCESS) {
            let invite = yougori_grid::invite::decode_access(invite).ok()?;
            let mut sessions = all["members"].as_array().into_iter().flatten().chain(std::iter::once(&all["member"]));
            return sessions.any(|session| session["fingerprint"].as_str().is_some_and(|known| known.eq_ignore_ascii_case(&invite.fingerprint))).then_some(invite.company);
        }
        let invite = yougori_grid::invite::decode_desk(invite).ok()?;
        let mut logins = all["logins"].as_array().into_iter().flatten().chain(std::iter::once(&all["desk"]));
        logins.any(|login| login["grid"].as_str().is_some_and(|grid| grid.trim().eq_ignore_ascii_case(invite.company.trim()))).then_some(invite.company)
    }
}

impl ResourceHandler for GridHandler {
    fn kind(&self) -> Kind {
        Kind::Grid
    }

    fn validate(&self, spec: &Value) -> Result<(), HandlerError> {
        match spec["profile"].as_str() {
            Some("neo_grid" | "sandbox_grid" | "access_grid") => {}
            Some(research::PROFILE) => return research::validate_grid(spec),
            _ => return Err(refused("This kind of grid can't be set up from My setups yet.")),
        }
        if Self::adopted(spec) {
            if spec.get("instance").is_some() && !text(spec, "instance").is_some_and(|key| crate::grid::instances::is_key(&key)) {
                return Err(invalid("An adopted grid's instance is `default` or `i-` and eight hex digits."));
            }
            return match spec["mode"].as_str().unwrap_or("create") {
                "create" => Ok(()),
                _ => Err(refused("Only a grid's hub on this computer can be adopted for now.")),
            };
        }
        match spec["mode"].as_str().unwrap_or("create") {
            "create" => {
                if text(spec, "name").is_none() || text(spec, "address").is_none() {
                    return Err(invalid("A new grid needs its name and this computer's address on the company network."));
                }
                if spec["access"].as_str() == Some("domain") && text(spec, "domain").is_none() {
                    return Err(invalid("Reaching the grid through a domain needs a saved domain."));
                }
                // An Access Grid has no company password: its first administrator signs in.
                if spec["profile"].as_str() != Some("access_grid") && spec["secrets"]["join_password"].as_str().unwrap_or_default().is_empty() {
                    return Err(invalid("A new grid needs a company password, given privately."));
                }
            }
            "join" => {
                if spec["secrets"]["invitation"].as_str().unwrap_or_default().is_empty() {
                    return Err(invalid("Joining a grid needs its invitation, given privately."));
                }
                if spec["profile"].as_str() == Some("access_grid") && !Self::signs_in(spec) {
                    return Err(refused("An Access Grid has people, not computers; people sign in to it."));
                }
                if Self::signs_in(spec) {
                    if spec["profile"].as_str() == Some("neo_grid") {
                        return Err(refused("People sign in to a Sandbox or Access Grid; computers join a Neo Grid."));
                    }
                    if spec["sign_in"].as_str() == Some("sso") {
                        return Err(refused("Signing in with a company account opens a browser, so it is done from the grid's own tab in My setups."));
                    }
                    let scoped = spec["secrets"]["password"] == spec["secrets"]["invitation"];
                    if !scoped && (text(spec, "username").is_none() || spec["secrets"]["password"].as_str().unwrap_or_default().is_empty()) {
                        return Err(invalid("Signing in needs a username and a password, given privately."));
                    }
                }
            }
            _ => return Err(refused("Using another setup's grid is done by borrowing it.")),
        }
        Ok(())
    }

    fn review(&self, id: &str, spec: &Value, others: &BTreeMap<String, (Kind, Value)>) -> Result<(), HandlerError> {
        if research::is_research(spec) {
            return research::review_grid(id, spec, others);
        }
        let creates_access = spec["profile"].as_str() == Some("access_grid") && spec["mode"].as_str().unwrap_or("create") == "create" && !Self::adopted(spec);
        let admin = others.values().any(|(kind, other)| *kind == Kind::AccessBinding && other["grid"]["resource"].as_str() == Some(id) && !other["admin"].is_null());
        if creates_access && !admin {
            return Err(refused("An Access Grid is made with its first administrator; declare one with admin: on an access binding."));
        }
        Ok(())
    }

    /// A grid keeps running for its computers and people: stopping and starting a setup leave it.
    fn stoppable(&self) -> bool {
        false
    }

    fn plan(&self, current: Option<&Resource>, _spec: &Value, spec_digest: &str) -> Result<Planned, HandlerError> {
        fixed_once_made(current, spec_digest, "Changing a grid after it was made is done on its own tab in My setups for now.")
    }

    fn notes(&self, _setup: &str, resource: &str, spec: &Value, action: Action) -> Vec<String> {
        if research::is_research(spec) && !Self::adopted(spec) {
            return research::notes_grid(spec, action);
        }
        if action == Action::Create && Self::adopted(spec) {
            let name = Product::of(spec).map(|calls| calls.name).unwrap_or("grid");
            return vec![format!(
                "This adopts the {name} hub already running on this computer into the setup. Nothing is moved, restarted or re-keyed, and its own records stay as they are. Removing the setup later pauses the grid for three days, like any grid a setup made."
            )];
        }
        if action == Action::Create && Self::creates(spec) {
            // Where the grid is coordinated decides what it survives (plan 6.5). This computer
            // runs it, so it is said plainly before anything is made.
            let name = Product::of(spec).map(|calls| calls.name).unwrap_or("grid");
            return vec![format!(
                "This computer coordinates the {name}. While it is turned off, asleep or offline, the grid's other computers can't reach it: nobody new can join, and work waits until it is back. Closing the Yougori window doesn't stop it; turning the computer off does."
            )];
        }
        if action != Action::Remove {
            return Vec::new();
        }
        let name = text(spec, "name").map(|name| format!(" {name}")).unwrap_or_default();
        let mut note = match (spec["profile"].as_str().unwrap_or_default(), Self::signs_in(spec), Self::joins(spec)) {
            (_, true, _) => format!("This computer signs out of the grid {resource} names. The person's account stays."),
            ("sandbox_grid", false, true) => "This computer leaves the Sandbox Grid and stops hosting desks for it. Their sandboxes and data stay on this computer.".to_owned(),
            (_, false, true) => "This computer leaves the Neo Grid. The grid keeps running for its other computers.".to_owned(),
            ("neo_grid", ..) => format!("Removing pauses the Neo Grid{name} for three days, until {}. Then it is deleted with its model plans, and its computers leave it. Restore it before then from My setups.", deletion_day()),
            ("sandbox_grid", ..) => format!("Removing pauses the Sandbox Grid{name} for three days, until {}. Then every desk in it is deleted with its data, on every computer that hosts one. Restore it before then from My setups.", deletion_day()),
            _ => format!("Removing pauses the Access Grid{name} for three days, until {}. Then its people, rules and stored credentials are deleted for good. Restore it before then from My setups.", deletion_day()),
        };
        if Self::creates(spec) {
            // The pause stays the default; `removal_offers` puts the choice on the review.
            note.push_str(" To delete it now instead, tick its deletion below.");
        }
        vec![note]
    }

    /// A grid this setup made may go at once with it instead of being paused, only if the person
    /// ticks that. A grid it joined, signed in to or adopted is never offered.
    fn removal_offers(&self, _setup: &str, resource: &str, spec: &Value) -> Vec<Value> {
        match Product::of(spec) {
            Some(calls) if Self::creates(spec) => vec![Self::deletion(resource, calls, spec)],
            _ => Vec::new(),
        }
    }

    fn observe<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Observation> {
        Box::pin(async move {
            if research::is_research(&context.spec) {
                return research::observe_grid(&self.0, context).await;
            }
            let calls = Self::product(&context.spec)?;
            Ok(match self.locate(context, calls).await {
                Ok(Some(found)) => Observation::Present {
                    runtime_id: found.record,
                    observed: if found.up { Observed::Running } else { Observed::Stopped },
                    label: None,
                    retained_data: !Self::joins(&context.spec),
                    cost: Cost::Free,
                },
                Ok(None) => Observation::Absent,
                Err(error) => Observation::Unknown { reason: error.message },
            })
        })
    }

    /// Never takes over what is already here: a membership of, or a sign-in to, the very grid an
    /// invitation is for is the person's (or another setup's), so the step is refused with what to
    /// do instead. A grid made here gets an instance of its own from the product, beside any other
    /// grid of its kind, and the setup records which.
    fn apply<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Receipt> {
        Box::pin(async move {
            if research::is_research(&context.spec) {
                return research::apply_grid(&self.0, context).await;
            }
            if context.action != Action::Create {
                return Err(refused("Changing a grid after it was made is done on its own tab in My setups for now."));
            }
            let spec = &context.spec;
            let calls = Self::product(spec)?;
            if Self::adopted(spec) {
                // Bookkeeping only: the hub's status is read, never changed.
                let found = self.locate(context, calls).await?.ok_or_else(|| {
                    HandlerError::new(Outcome::Failed, "target_missing", format!("That {} hub isn't running on this computer anymore, so there is nothing to adopt.", calls.name))
                })?;
                let observed = if found.up { Observed::Running } else { Observed::Stopped };
                return Ok(Receipt { runtime_id: Some(found.record), observed, retained_data: true, cost: Cost::Free, at: now(), adopted: true });
            }
            if Self::signs_in(spec) {
                let given = secret(context, "invitation")?;
                // A person's scoped invitation carries their username and password with the
                // grid's invite; anything else is the grid's invite, with theirs given apart.
                let scoped = scoped::decode(&given);
                let invite = scoped.as_ref().map(|scoped| scoped.invite.clone()).unwrap_or(given);
                if let Some(grid) = Self::signed_in_to(calls, &self.0.status_all(calls).await?, &invite) {
                    return Err(taken(format!("This computer is already signed in to the {} {grid}. This setup won't replace that sign-in; sign out from the grid in My setups first, then retry.", calls.name)));
                }
                let (username, password) = match &scoped {
                    Some(scoped) => (scoped.username.clone(), scoped.password.clone()),
                    None => (text(spec, "username").unwrap_or_default(), secret(context, "password")?),
                };
                let method = if calls.is(Product::ACCESS) { "access_signin" } else { "desk_login" };
                let answer = self.0.ask(context, method, json!({"invite": invite, "username": username, "password": password, "sso": false})).await.map_err(|error| failed(context, error))?;
                return Ok(receipt(Some(recorded(&username, &answered_in(&answer))), Observed::Running, false));
            }
            if Self::joins(spec) {
                let invite = secret(context, "invitation")?;
                if Self::member_of(calls, &self.0.status_all(calls).await?, &invite) {
                    return Err(taken(format!("This computer is already in that {}. This setup won't take that membership over; leave it from its own tab in My setups first, or adopt it into a setup.", calls.name)));
                }
                let password = secret(context, "join_password")?;
                let answer = self.0.ask(context, calls.join, json!({"invite": invite, "password": password})).await.map_err(|error| failed(context, error))?;
                let id = answer["member"]["memberId"].as_str().ok_or_else(|| HandlerError::new(Outcome::Unknown, "outcome_unknown", "The grid didn't report this computer as a member."))?;
                return Ok(receipt(Some(recorded(id, &answered_in(&answer))), Observed::Running, false));
            }
            if calls.is(Product::ACCESS) {
                return self.create_access(context).await;
            }
            let password = secret(context, "join_password")?;
            let request = json!({"name": text(spec, "name"), "address": text(spec, "address"), "password": password, "tunnel": Self::tunnel(spec)});
            let answer = self.0.ask(context, calls.create, request).await.map_err(|error| failed(context, error))?;
            let id = answer["hub"]["id"].as_str().ok_or_else(|| HandlerError::new(Outcome::Unknown, "outcome_unknown", "The grid didn't report its hub."))?;
            Ok(receipt(Some(recorded(id, &answered_in(&answer))), Observed::Running, true))
        })
    }

    fn stop<'a>(&'a self, _context: &'a StepContext) -> HandlerFuture<'a, Receipt> {
        Box::pin(async move {
            Err(refused("A grid keeps running for its computers and people; it can't be stopped. Remove the setup to pause the grid for three days."))
        })
    }

    /// A created grid is paused for three days and can be restored, or deleted at once if the
    /// person ticked that on the review; a joined one is left; a sign-in is signed out. Only this
    /// setup's own, in the instance it is in: one that is already gone, or that isn't the one
    /// recorded, is left alone and the removal finishes.
    fn remove<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Receipt> {
        Box::pin(async move {
            if research::is_research(&context.spec) {
                return research::remove_grid(&self.0, context).await;
            }
            let calls = Self::product(&context.spec)?;
            let Some(found) = self.locate(context, calls).await? else {
                return Ok(receipt(None, Observed::Missing, false));
            };
            if Self::signs_in(&context.spec) {
                let method = if calls.is(Product::ACCESS) { "access_signout" } else { "desk_logout" };
                self.0.ask_in(context, &found.key, method, json!({})).await.map_err(|error| failed(context, error))?;
                return Ok(receipt(None, Observed::Missing, false));
            }
            if Self::joins(&context.spec) {
                self.0.ask_in(context, &found.key, calls.leave, json!({})).await.map_err(|error| failed(context, error))?;
                return Ok(receipt(None, Observed::Missing, false));
            }
            if Self::creates(&context.spec) && context.consents.contains(&delete_grid_consent(&context.resource)) {
                // A paused grid is deleted now too. One deleted already is left as it is, so a
                // retry asks nothing twice.
                if found.status["hub"]["closing"]["gone"] != true {
                    self.0.ask_in(context, &found.key, calls.delete, json!({"when": "now"})).await.map_err(|error| failed(context, error))?;
                }
                return Ok(receipt(None, Observed::Missing, false));
            }
            if found.up {
                self.0.ask_in(context, &found.key, calls.delete, json!({"when": "later"})).await.map_err(|error| failed(context, error))?;
            }
            Ok(receipt(None, Observed::Stopped, true))
        })
    }

    fn health<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, HealthReport> {
        Box::pin(async move {
            if research::is_research(&context.spec) {
                return research::health_grid(&self.0, context).await;
            }
            let calls = Self::product(&context.spec)?;
            let found = self.locate(context, calls).await?.map(|found| found.up);
            Ok(match found {
                None if Self::signs_in(&context.spec) => HealthReport { health: Health::NeedsSignIn, detail: "Not signed in to the grid.".into() },
                None => HealthReport { health: Health::Failed, detail: "This grid isn't on this computer anymore.".into() },
                Some(_) if Self::signs_in(&context.spec) => HealthReport { health: Health::Ready, detail: "Signed in to the grid.".into() },
                Some(true) if Self::joins(&context.spec) => HealthReport { health: Health::Ready, detail: "Connected to the grid.".into() },
                Some(_) if Self::joins(&context.spec) => HealthReport { health: Health::Degraded, detail: "Not connected to the grid right now.".into() },
                Some(false) => HealthReport { health: Health::Degraded, detail: "The grid is paused for deletion.".into() },
                Some(true) => HealthReport { health: Health::Ready, detail: "The grid's hub is running.".into() },
            })
        })
    }

    /// The grid as its product reports it now, while it is this setup's own: its name and where it
    /// is managed; for a grid made here, also where computers or people reach it and, while it is
    /// open, its invite (a private output). Nothing for a grid that isn't there.
    fn outputs<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, BTreeMap<String, String>> {
        Box::pin(async move {
            if research::is_research(&context.spec) {
                return research::outputs_grid(&self.0, context).await;
            }
            let calls = Self::product(&context.spec)?;
            let mut outputs = BTreeMap::new();
            let Some(found) = self.locate(context, calls).await? else { return Ok(outputs) };
            let status = &found.status;
            let name = if Self::signs_in(&context.spec) {
                let session = calls.session(status);
                text(session, "grid").or_else(|| text(session, "company"))
            } else if Self::joins(&context.spec) {
                text(&status["member"], "grid")
            } else {
                let hub = &status["hub"];
                if let Some(address) = reach(hub) {
                    outputs.insert("join_address".to_owned(), address);
                }
                if let Some(invite) = text(hub, "invite").filter(|_| hub["closing"].is_null()) {
                    outputs.insert("invitation".to_owned(), invite);
                }
                text(hub, "name").or_else(|| text(hub, "company"))
            };
            if let Some(name) = name {
                outputs.insert("name".to_owned(), name);
            }
            outputs.insert("page".to_owned(), format!("Its {} tab in My setups", calls.name));
            Ok(outputs)
        })
    }

    /// The rented NeoCloud GPUs in the Neo Grid this setup made that may be billing, for a
    /// release's review: each by name, what it is and what it costs an hour. Nothing for any other
    /// grid, and never a pod outside this one.
    fn rented<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Option<Value>> {
        Box::pin(async move {
            let Some(grid) = self.own_neo_hub(context).await? else { return Ok(None) };
            let pods = self.billing_pods(context, &grid).await?;
            if pods.is_empty() {
                return Ok(None);
            }
            let name = text(&context.spec, "name").unwrap_or_else(|| context.resource.clone());
            let computers = pods
                .iter()
                .map(|pod| json!({"id": pod["environmentId"], "name": pod["name"], "gpu": pod["gpu"], "gpuCount": pod["gpuCount"], "hourlyUsd": pod["hourlyUsd"], "state": pod["podState"]}))
                .collect::<Vec<_>>();
            Ok(Some(json!({
                "provider": "NeoCloud",
                "computers": computers,
                "notes": [
                    format!("Releasing stops every rented GPU in the Neo Grid {name} through NeoCloud, which rents them from RunPod. Nothing else in the setup changes."),
                    "GPU charges stop once NeoCloud confirms each pod is stopped. A pod NeoCloud still shows stopping stays listed here and is checked again until it does.",
                    "Each pod's disk is kept, and disks may still cost storage until you delete the pod in NeoCloud.",
                    format!("The pods stay in {name}, offline, until you start them in NeoCloud."),
                ],
            })))
        })
    }

    /// Stops the rented GPUs in the Neo Grid this setup made, through the product's own stop for
    /// that grid, which never reaches a pod outside it or one Swarm Mining uses. Answers what came
    /// of it and names every pod NeoCloud hasn't confirmed stopped yet: a charge is never called
    /// stopped without its word.
    fn release<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Value> {
        Box::pin(async move {
            let Some(grid) = self.own_neo_hub(context).await? else {
                return Err(refused("Only the rented GPUs in a Neo Grid this setup made can be released here."));
            };
            let stopped = self.0.ask(context, "grid_neocloud_stop_all", json!({"gridId": grid})).await.map_err(|error| failed(context, error))?;
            let unconfirmed = self
                .billing_pods(context, &grid)
                .await?
                .iter()
                .map(|pod| text(pod, "name").unwrap_or_else(|| pod["environmentId"].as_str().unwrap_or_default().to_owned()))
                .collect::<Vec<_>>();
            let confirmed = unconfirmed.is_empty() && stopped["warning"].is_null();
            let said = text(&stopped, "warning").or_else(|| text(&stopped, "message")).map(|said| plain(&said)).unwrap_or_default();
            Ok(json!({"provider": "NeoCloud", "said": said, "unconfirmed": unconfirmed, "confirmed": confirmed}))
        })
    }

    /// What this step made is found by its recorded ID or its time; anything else is not taken.
    fn recover<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Recovery> {
        Box::pin(async move {
            if research::is_research(&context.spec) && context.action == Action::Create {
                // A review hosted by the lost step is found by its creation time when the step runs again.
                return Ok(Recovery::NotApplied);
            }
            let observation = self.observe(context).await?;
            Ok(match (context.action, observation) {
                (Action::Create, Observation::Present { runtime_id, observed, retained_data, cost, .. }) => {
                    Recovery::Applied(Receipt { runtime_id: Some(runtime_id), observed, retained_data, cost, at: now(), adopted: true })
                }
                (_, observation) => super::handler::recovery_from(context, observation),
            })
        })
    }
}

// ----- The pool of computers -----

/// The computers that serve a grid. Neo Grid has no pool object: its availability, idle minutes
/// and hours are applied to each model plan, as the grid's own tab does. A Sandbox Grid pool of this
/// computer sets this computer's share (`desks_member_share`).
pub(crate) struct ComputePoolHandler(Grids);

impl ComputePoolHandler {
    /// The computers a pool of picked computers names, by the names they joined with. An entry
    /// may name several, separated by commas, as one answer to a question gives them.
    pub(crate) fn picked(spec: &Value) -> Vec<String> {
        spec["computers"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .flat_map(|entry| entry.split(','))
            .map(|name| name.trim().to_owned())
            .filter(|name| !name.is_empty())
            .collect()
    }

    fn selects(spec: &Value) -> bool {
        spec["source"].as_str() == Some("selected_computers")
    }

    fn rents(spec: &Value) -> bool {
        spec["source"].as_str() == Some("cloud")
    }

    /// A Neo Grid's rented GPUs come from RunPod; a Sandbox Grid makes computers in the
    /// company's own cloud account.
    fn rents_gpus(spec: &Value) -> bool {
        Self::rents(spec) && spec["cloud"]["provider"].as_str() == Some("runpod")
    }

    /// What a rented GPU's pod is called in NeoCloud: the setup's own, so it is found again.
    fn pod_name(context: &StepContext) -> String {
        let setup: String = context.setup.trim_start_matches("setup-").chars().filter(char::is_ascii_alphanumeric).take(8).collect();
        let resource: String = context.resource.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).take(24).collect();
        format!("yougori-{setup}-{resource}")
    }

    /// Rents one GPU in NeoCloud at no more than the hourly price the template allows, and has it
    /// join this setup's Neo Grid. Answers its NeoCloud environment.
    async fn rent(&self, context: &StepContext, key: &str) -> Result<String, HandlerError> {
        let cloud = &context.spec["cloud"];
        let status = self.0.ask(context, "runpod_status", json!({})).await.map_err(|error| failed(context, error))?;
        if status["connected"] != true {
            return Err(HandlerError {
                retryable: true,
                ..HandlerError::new(Outcome::NotStarted, "sign_in_needed", "Connect your RunPod account in NeoCloud first: rented GPUs are billed to it. Then apply the setup again.")
            });
        }
        let name = Self::pod_name(context);
        let existing = |state: &Value| state["environments"].as_array().into_iter().flatten().find(|environment| environment["name"].as_str() == Some(name.as_str())).and_then(|environment| environment["id"].as_str().map(str::to_owned));
        let state = self.0.ask(context, "get_platform_state", json!({})).await.map_err(|error| failed(context, error))?;
        let pod = match existing(&state) {
            Some(id) => id,
            None => {
                let request = json!({
                    "name": name, "compute": "gpu", "gpuId": text(cloud, "gpu_type"), "gpuCount": 1, "cloud": "secure",
                    "location": text(cloud, "region").unwrap_or_default(), "image": RENTED_IMAGE, "containerDiskGb": 40,
                    "maxHourlyUsd": cloud["max_hourly_cost"],
                });
                let made = self.0.ask(context, "runpod_create_pod", json!({"request": request})).await.map_err(|error| failed(context, error))?;
                existing(&made).ok_or_else(|| HandlerError::new(Outcome::Unknown, "outcome_unknown", "NeoCloud didn't list the pod it was asked to rent."))?
            }
        };
        // It joins once NeoCloud shows it running: a pod takes a minute or two to start.
        let until = tokio::time::Instant::now() + std::time::Duration::from_secs(15 * 60);
        loop {
            match self.0.ask_in(context, key, "grid_neocloud_add", json!({"environmentId": pod})).await {
                Ok(_) => return Ok(pod),
                Err(error) if error.contains("already in the grid") => return Ok(pod),
                Err(error) if error.contains("still being created") && tokio::time::Instant::now() < until => {}
                Err(error) => return Err(HandlerError { retryable: true, ..failed(context, error) }),
            }
            tokio::select! {
                _ = context.cancel.cancelled() => return Err(HandlerError::new(Outcome::Unknown, "outcome_unknown", "Cancelled while the rented GPU started. It is still rented; checking it before anything else runs.")),
                _ = tokio::time::sleep(POD_WAIT) => {}
            }
        }
    }

    /// Takes a rented GPU out of the grid and deletes its pod, so it stops billing.
    async fn release(&self, context: &StepContext, key: &str, pod: &str) -> Result<(), HandlerError> {
        match self.0.ask_in(context, key, "grid_neocloud_remove", json!({"environmentId": pod})).await {
            Ok(_) => {}
            Err(error) if error.contains("not in") || error.contains("no longer exists") => {}
            Err(error) => return Err(failed(context, error)),
        }
        match self.0.ask(context, "runpod_action", json!({"environmentId": pod, "action": "delete", "confirmation": Self::pod_name(context)})).await {
            Ok(_) => Ok(()),
            Err(error) if error.contains("not found") || error.contains("no longer") => Ok(()),
            Err(error) => Err(failed(context, error)),
        }
    }

    /// A Sandbox Grid's own cloud: the computers it makes in the company's account when no
    /// computer of the grid has room, as its own tab sets them.
    fn fallback(spec: &Value) -> Value {
        let cloud = &spec["cloud"];
        let field = |key: &str| json!(text(cloud, key).unwrap_or_default());
        json!({
            "action": "cloudFallbackSet", "enabled": true, "provider": field("provider"), "account": field("account"), "region": field("region"),
            "image": field("image"), "imageProject": field("image_project"), "machineType": field("machine_type"), "subnet": field("subnet"),
            "securityGroup": field("security_group"), "keyPair": field("key_pair"), "resourceGroup": field("resource_group"),
            "sshPublicKey": field("ssh_public_key"), "username": field("username"), "identityFile": cloud["identity_path"].as_str().unwrap_or_default(),
            "maxComputers": cloud["max_computers"].as_u64().unwrap_or(1),
        })
    }

    fn limited(spec: &Value) -> bool {
        spec["limits"].as_object().is_some_and(|limits| limits.values().any(|limit| !limit.is_null()))
    }

    fn sets_share(context: &StepContext) -> bool {
        product_of(context, &context.spec["grid"]).is_some_and(|calls| calls.is(Product::SANDBOX)) && context.spec["source"].as_str() == Some("this_computer")
    }

    /// Sets this computer's share of this setup's Sandbox Grid (`grid`, as recorded), and says which
    /// member it set.
    async fn share(&self, context: &StepContext, grid: &str) -> Result<String, HandlerError> {
        let (id, key) = located(grid);
        let status = self
            .0
            .status_in(Product::SANDBOX, key)
            .await?
            .filter(|status| status["hub"]["id"].as_str() == Some(id))
            .ok_or_else(|| HandlerError::new(Outcome::NotStarted, "target_missing", "This setup's Sandbox Grid isn't running on this computer."))?;
        let member = status["member"]["memberId"]
            .as_str()
            .ok_or_else(|| HandlerError::new(Outcome::NotStarted, "target_missing", "This computer isn't in the Sandbox Grid yet."))?
            .to_owned();
        let spec = &context.spec;
        let request = json!({
            "memberId": member,
            "cpu": spec["limits"]["cpu"],
            "memoryGb": spec["limits"]["memory_gb"],
            "diskGb": spec["limits"]["disk_gb"],
            "gpu": spec["gpu"].as_str().is_some_and(|gpu| gpu != "none"),
            "idleOnly": spec["availability"].as_str() == Some("idle"),
        });
        self.0.ask_in(context, key, "desks_member_share", request).await.map_err(|error| failed(context, error))?;
        Ok(member)
    }

    /// A Neo pool's serving rules, applied again to each model plan of this setup it serves.
    async fn rules_to_plans(&self, context: &StepContext, grid: &str) -> Result<(), HandlerError> {
        let served = context
            .peers
            .values()
            .filter(|peer| peer.kind == Kind::ModelService && peer.spec["compute"]["resource"].as_str() == Some(context.resource.as_str()) && !ModelServiceHandler::is_team(&peer.spec))
            .filter_map(|peer| peer.runtime_id.clone())
            .collect::<Vec<_>>();
        if served.is_empty() {
            return Ok(());
        }
        let (id, key) = located(grid);
        if !self.0.status_in(Product::NEO, key).await?.is_some_and(|status| status["hub"]["id"].as_str() == Some(id)) {
            return Err(HandlerError::new(Outcome::NotStarted, "target_missing", "This setup's Neo Grid isn't running on this computer."));
        }
        let (idle_after, schedule) = ModelServiceHandler::rules(&context.spec);
        for plan in served {
            let request = json!({"planId": plan, "schedule": schedule.clone().unwrap_or_default(), "idleAfter": idle_after});
            self.0.ask_in(context, key, "grid_plan_update", request).await.map_err(|error| failed(context, error))?;
        }
        Ok(())
    }
}

impl ResourceHandler for ComputePoolHandler {
    fn kind(&self) -> Kind {
        Kind::ComputePool
    }

    fn validate(&self, spec: &Value) -> Result<(), HandlerError> {
        if spec["grid"]["resource"].as_str().is_none() {
            return Err(invalid("A pool of computers names its grid with grid: {resource: ID}."));
        }
        if !spec["cloud"].is_null() && !Self::rents(spec) {
            return Err(invalid("cloud: describes rented computers; say source: cloud."));
        }
        if Self::rents(spec) {
            match spec["cloud"]["provider"].as_str() {
                Some("runpod") => {
                    if text(&spec["cloud"], "gpu_type").is_none() {
                        return Err(invalid("A rented GPU names its type with cloud.gpu_type, as NeoCloud lists it (such as NVIDIA GeForce RTX 4090)."));
                    }
                    if !spec["cloud"]["max_hourly_cost"].as_f64().is_some_and(|cost| cost > 0.0) {
                        return Err(invalid("A rented GPU needs the most it may cost an hour, cloud.max_hourly_cost, so nothing dearer is ever rented."));
                    }
                }
                Some("aws" | "azure" | "google") => {
                    for (field, what) in [("account", "the CLI profile or account"), ("region", "the region"), ("image", "the image"), ("machine_type", "the machine type"), ("subnet", "the subnet")] {
                        if text(&spec["cloud"], field).is_none() {
                            return Err(invalid(&format!("A company cloud computer needs {what} (cloud.{field}).")));
                        }
                    }
                    if spec["cloud"]["identity_file"]["binding"].as_str().is_none() {
                        return Err(invalid("A company cloud computer needs the SSH key file Yougori signs in with: cloud.identity_file: {binding: ID}, a file the person chooses."));
                    }
                }
                _ => return Err(invalid("cloud.provider is runpod for a Neo Grid's rented GPUs, or aws, azure or google for a Sandbox Grid's own cloud.")),
            }
        }
        if Self::limited(spec) && spec["source"].as_str() != Some("this_computer") {
            return Err(refused("Limits apply to this computer's share; other computers set their own share from the grid in My setups."));
        }
        if Self::selects(spec) {
            let picked = Self::picked(spec);
            if picked.is_empty() {
                return Err(invalid("A pool of picked computers names them with computers: [NAME, ...], as they joined the grid."));
            }
            if picked.len() > 64 {
                return Err(invalid("A pool picks at most 64 computers."));
            }
        }
        if spec["availability"].as_str() == Some("scheduled") && text(spec, "schedule").is_none() {
            return Err(invalid("A scheduled pool needs its hours."));
        }
        Ok(())
    }

    fn review(&self, _id: &str, spec: &Value, others: &BTreeMap<String, (Kind, Value)>) -> Result<(), HandlerError> {
        let Some((profile, mode)) = declared_grid(&spec["grid"], others) else {
            return Err(refused("A pool of computers belongs to a grid this setup makes or joins."));
        };
        if Self::limited(spec) && !matches!(profile, "sandbox_grid" | research::PROFILE) {
            return Err(refused("A Neo Grid shares each computer by model plan; limits for its pool aren't available."));
        }
        if profile == research::PROFILE && spec["source"].as_str() != Some("this_computer") {
            return Err(refused("A review's worker works on this computer; other computers take part by joining it."));
        }
        if profile == "sandbox_grid" && spec["source"].as_str() == Some("this_computer") && mode != "create" {
            return Err(refused("On a Sandbox Grid this setup joins, this computer's share is set by the grid's admin."));
        }
        if Self::selects(spec) && (mode != "create" || !matches!(profile, "neo_grid" | "sandbox_grid")) {
            return Err(refused("Which computers run work is chosen on a Neo or Sandbox Grid this setup makes."));
        }
        if Self::rents(spec) {
            let fits = match (profile, spec["cloud"]["provider"].as_str()) {
                ("neo_grid", Some("runpod")) => true,
                ("sandbox_grid", Some("aws" | "azure" | "google")) => true,
                _ => false,
            };
            if mode != "create" || !fits {
                return Err(refused("Rented GPUs from RunPod join a Neo Grid this setup makes, and a company's own cloud computers a Sandbox Grid it makes."));
            }
        }
        Ok(())
    }

    fn notes(&self, _setup: &str, resource: &str, spec: &Value, action: Action) -> Vec<String> {
        if !Self::rents(spec) || !matches!(action, Action::Create | Action::Update) {
            return Vec::new();
        }
        let cloud = &spec["cloud"];
        if Self::rents_gpus(spec) {
            let mut notes = vec![format!(
                "{resource} rents one {} GPU from RunPod, at no more than ${:.2} an hour, and it joins the grid. RunPod bills your account for every hour it runs, and for its disk while it is kept.",
                text(cloud, "gpu_type").unwrap_or_default(),
                cloud["max_hourly_cost"].as_f64().unwrap_or_default()
            )];
            if let Some(budget) = cloud["budget_usd"].as_f64() {
                notes.push(format!("It is stopped before this month's rented hours pass ${budget:.2}, and stays stopped until next month or until you raise the budget."));
            }
            notes.push("Stopping the setup stops the GPU; removing the setup deletes it.".into());
            return notes;
        }
        vec![format!(
            "When the grid's computers have no room for a workspace, it makes up to {} computer(s) in your {} account and removes each again once it has hosted nothing for an hour. That cloud bills your account; Yougori knows no price for it.",
            cloud["max_computers"].as_u64().unwrap_or(1),
            text(cloud, "provider").unwrap_or_default()
        )]
    }

    fn stoppable(&self) -> bool {
        false
    }

    /// Only rented GPUs stop with the setup, so they stop billing; any other pool is a share
    /// of computers that stays as it is.
    fn stops(&self, spec: &Value) -> bool {
        Self::rents_gpus(spec)
    }

    fn stop<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Receipt> {
        Box::pin(async move {
            if Self::rents_gpus(&context.spec) {
                if let Some(pod) = context.runtime_id.as_deref().filter(|id| !id.is_empty()) {
                    self.0.ask(context, "runpod_action", json!({"environmentId": pod, "action": "stop"})).await.map_err(|error| failed(context, error))?;
                    return Ok(Receipt { runtime_id: Some(pod.to_owned()), observed: Observed::Stopped, retained_data: false, cost: Cost::Stopped, at: now(), adopted: false });
                }
            }
            Ok(receipt(context.runtime_id.clone(), Observed::Present, false))
        })
    }

    fn observe<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Observation> {
        Box::pin(async move {
            if Self::rents_gpus(&context.spec) {
                let Some(pod) = context.runtime_id.clone() else { return Ok(Observation::Absent) };
                let grid = grid_id(context, &context.spec["grid"]).unwrap_or_default();
                let status = match self.0.ask(context, "grid_neocloud_status", json!({"gridId": located(&grid).1})).await {
                    Ok(status) => status,
                    Err(error) => return Ok(Observation::Unknown { reason: error }),
                };
                let found = status["members"].as_array().into_iter().flatten().find(|member| member["environmentId"].as_str() == Some(pod.as_str())).cloned();
                return Ok(match found {
                    Some(member) => {
                        let billing = member["podState"].as_str().is_some_and(|state| matches!(state, "Running" | "Starting" | "Creating"));
                        Observation::Present {
                            runtime_id: pod,
                            observed: if billing { Observed::Running } else { Observed::Stopped },
                            label: None,
                            retained_data: false,
                            cost: if billing { Cost::Accruing } else { Cost::Stopped },
                        }
                    }
                    None => Observation::Absent,
                });
            }
            Ok(match grid_id(context, &context.spec["grid"]) {
                Some(id) => Observation::Present {
                    runtime_id: context.runtime_id.clone().unwrap_or_else(|| format!("{id}/computers")),
                    observed: Observed::Present,
                    label: None,
                    retained_data: false,
                    cost: Cost::Free,
                },
                None => Observation::Absent,
            })
        })
    }

    fn apply<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Receipt> {
        Box::pin(async move {
            let grid = context.spec["grid"]["resource"].as_str().unwrap_or_default();
            let id = grid_id(context, &context.spec["grid"]).ok_or_else(|| HandlerError::new(Outcome::NotStarted, "target_missing", format!("{grid} doesn't exist yet in this setup.")))?;
            if Self::sets_share(context) {
                let member = self.share(context, &id).await?;
                return Ok(receipt(Some(format!("{id}/computers/{member}")), Observed::Present, false));
            }
            let product = product_of(context, &context.spec["grid"]);
            if Self::rents_gpus(&context.spec) {
                let (_, key) = located(&id);
                // Started again with the setup: the pod it rented, not a new one.
                if context.action == Action::Start {
                    if let Some(pod) = context.runtime_id.as_deref().filter(|pod| !pod.is_empty()) {
                        self.0.ask(context, "runpod_action", json!({"environmentId": pod, "action": "start"})).await.map_err(|error| failed(context, error))?;
                        return Ok(Receipt { runtime_id: Some(pod.to_owned()), observed: Observed::Running, retained_data: false, cost: Cost::Accruing, at: now(), adopted: false });
                    }
                }
                let pod = self.rent(context, key).await?;
                return Ok(Receipt { runtime_id: Some(pod), observed: Observed::Running, retained_data: false, cost: Cost::Accruing, at: now(), adopted: false });
            }
            if Self::rents(&context.spec) && product.is_some_and(|calls| calls.is(Product::SANDBOX)) {
                let (_, key) = located(&id);
                self.0.ask_in(context, key, "desks_manage", json!({"request": Self::fallback(&context.spec)})).await.map_err(|error| failed(context, error))?;
                return Ok(Receipt { runtime_id: Some(format!("{id}/cloud")), observed: Observed::Present, retained_data: false, cost: Cost::Unknown, at: now(), adopted: false });
            }
            if Self::selects(&context.spec) && product.is_some_and(|calls| calls.is(Product::SANDBOX)) {
                // Only these computers take desks from now on, a computer that joins later
                // included; desks already placed stay where they are.
                let (_, key) = located(&id);
                self.0
                    .ask_in(context, key, "desks_manage", json!({"request": {"action": "computersOnly", "names": Self::picked(&context.spec)}}))
                    .await
                    .map_err(|error| failed(context, error))?;
                return Ok(receipt(Some(format!("{id}/computers")), Observed::Present, false));
            }
            if context.action == Action::Update && product.is_some_and(|calls| calls.is(Product::NEO)) {
                let before = context.recorded.as_ref().map(Self::picked).unwrap_or_default();
                if Self::selects(&context.spec) && before != Self::picked(&context.spec) {
                    return Err(refused("On a Neo Grid the computers a model runs on are picked when the model is added. Remove the model and add it again to move it."));
                }
                self.rules_to_plans(context, &id).await?;
            }
            Ok(receipt(Some(format!("{id}/computers")), Observed::Present, false))
        })
    }

    /// Back to the share the grid suggests, only for the member this setup set, in the grid this
    /// setup made; a grid or membership that is gone is left alone.
    fn remove<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Receipt> {
        Box::pin(async move {
            if Self::rents(&context.spec) {
                let grid = grid_id(context, &context.spec["grid"]);
                if Self::rents_gpus(&context.spec) {
                    if let (Some(grid), Some(pod)) = (grid, context.runtime_id.as_deref().filter(|pod| !pod.is_empty())) {
                        self.release(context, located(&grid).1, pod).await?;
                    }
                } else if let Some(grid) = grid {
                    let (id, key) = located(&grid);
                    if self.0.status_in(Product::SANDBOX, key).await?.is_some_and(|status| status["hub"]["id"].as_str() == Some(id)) {
                        self.0.ask_in(context, key, "desks_manage", json!({"request": {"action": "cloudFallbackClear"}})).await.map_err(|error| failed(context, error))?;
                    }
                }
                return Ok(Receipt { runtime_id: None, observed: Observed::Missing, retained_data: false, cost: Cost::Stopped, at: now(), adopted: false });
            }
            if Self::selects(&context.spec) && product_of(context, &context.spec["grid"]).is_some_and(|calls| calls.is(Product::SANDBOX)) {
                if let Some(grid) = grid_id(context, &context.spec["grid"]) {
                    let (id, key) = located(&grid);
                    if self.0.status_in(Product::SANDBOX, key).await?.is_some_and(|status| status["hub"]["id"].as_str() == Some(id)) {
                        self.0.ask_in(context, key, "desks_manage", json!({"request": {"action": "computersOnly", "names": Value::Null}})).await.map_err(|error| failed(context, error))?;
                    }
                }
                return Ok(receipt(None, Observed::Missing, false));
            }
            let recorded = context.runtime_id.as_deref().and_then(|id| id.split_once("/computers/")).map(|(grid, member)| (grid.to_owned(), member.to_owned()));
            if let (true, Some((grid, member))) = (Self::sets_share(context), recorded) {
                let (id, key) = located(&grid);
                if let Some(status) = self.0.status_in(Product::SANDBOX, key).await? {
                    if status["hub"]["id"].as_str() == Some(id) && status["member"]["memberId"].as_str() == Some(member.as_str()) {
                        self.0.ask_in(context, key, "desks_member_share", json!({"memberId": member, "suggested": true})).await.map_err(|error| failed(context, error))?;
                    }
                }
            }
            Ok(receipt(None, Observed::Missing, false))
        })
    }

    /// A share whose outcome is unknown is set again only by retrying the change, never on its
    /// own while the engine starts.
    fn recover<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Recovery> {
        Box::pin(async move {
            Ok(match context.action {
                Action::Create | Action::Update => Recovery::NotApplied,
                _ => super::handler::recovery_from(context, self.observe(context).await?),
            })
        })
    }
}

// ----- Models -----

/// A model plan the grid serves through its OpenAI-compatible API, or a team of models that
/// answers as one (`swarm/NAME`).
pub(crate) struct ModelServiceHandler(Grids);

impl ModelServiceHandler {
    /// A pool's serving rules: when its computers may serve. Hours apply to every availability
    /// but `always`; idle minutes default to the product's own with `idle`, and to none with
    /// `scheduled`, which serves throughout its hours.
    fn rules(pool: &Value) -> (Option<u64>, Option<String>) {
        let idle = pool["idle_after_minutes"].as_u64();
        match pool["availability"].as_str().unwrap_or("always") {
            "always" => (Some(0), None),
            "idle" => (idle, text(pool, "schedule")),
            _ => (Some(idle.unwrap_or(0)), text(pool, "schedule")),
        }
    }

    fn pool<'a>(context: &'a StepContext) -> Option<&'a Value> {
        context.spec["compute"]["resource"].as_str().and_then(|id| context.peers.get(id)).map(|peer| &peer.spec)
    }

    /// The recorded hub ID of the Neo Grid this model's pool belongs to.
    fn grid(context: &StepContext) -> Option<String> {
        Self::pool(context).and_then(|pool| grid_id(context, &pool["grid"]))
    }

    fn plan_request(context: &StepContext) -> Value {
        let spec = &context.spec;
        let (idle_after, schedule) = Self::pool(context).map(Self::rules).unwrap_or((None, None));
        json!({
            "model": text(spec, "model"),
            "percent": spec["share_percent"].as_u64().unwrap_or(100),
            "schedule": schedule.unwrap_or_default(),
            "idleAfter": idle_after,
            "quant": text(spec, "quantization"),
            "scope": spec["placement"].as_str().unwrap_or("remaining"),
        })
    }

    /// The model name of another model service of this setup, for a team's lead and workers.
    fn model_of(context: &StepContext, reference: &Value) -> Result<String, HandlerError> {
        let id = reference["resource"].as_str().unwrap_or_default();
        context
            .peers
            .get(id)
            .and_then(|peer| text(&peer.spec, "model"))
            .ok_or_else(|| HandlerError::new(Outcome::NotStarted, "target_missing", format!("{id} doesn't exist yet in this setup.")))
    }

    fn team(context: &StepContext) -> Result<Value, HandlerError> {
        let spec = &context.spec;
        let team = &spec["team"];
        let name = text(spec, "model").unwrap_or_default();
        let workers = team["workers"].as_array().cloned().unwrap_or_default().iter().map(|worker| Self::model_of(context, worker)).collect::<Result<Vec<_>, _>>()?;
        Ok(json!({
            "name": name.trim_start_matches("swarm/"),
            "strategy": team["strategy"].as_str().unwrap_or("plan"),
            "lead": Self::model_of(context, &team["lead"])?,
            "workers": workers,
            "computers": team["computers"].as_u64().unwrap_or(2),
            "rounds": team["rounds"].as_u64(),
        }))
    }

    fn is_team(spec: &Value) -> bool {
        !spec["team"].is_null()
    }

    /// This setup's Neo Grid status and the instance it is in, or `None` when its hub isn't the one
    /// this setup made.
    async fn own_hub(&self, context: &StepContext) -> Result<Option<(Value, String)>, HandlerError> {
        let Some(grid) = Self::grid(context) else { return Ok(None) };
        let (id, key) = located(&grid);
        let Some(status) = self.0.status_in(Product::NEO, key).await? else { return Ok(None) };
        Ok((status["hub"]["id"].as_str() == Some(id)).then(|| (status, key.to_owned())))
    }

    /// A model on this computer alone (no `compute`) is run by the model runner, in
    /// `setups::local_models`.
    fn local(&self) -> LocalModels {
        LocalModels::new(self.0.calls.clone())
    }
}

impl ResourceHandler for ModelServiceHandler {
    fn kind(&self) -> Kind {
        Kind::ModelService
    }

    fn validate(&self, spec: &Value) -> Result<(), HandlerError> {
        if local_models::is_local(spec) {
            return self.local().validate(spec);
        }
        if text(spec, "model").is_none() {
            return Err(invalid("A model service needs its model."));
        }
        if spec["compute"]["resource"].as_str().is_none() {
            return Err(refused("A model or team on a Neo Grid that another setup runs can't be added from a setup yet; add it from that grid's page."));
        }
        if !spec["network"].is_null() {
            return Err(refused("Listing a model on the Yougori Network is done from the Network page for now."));
        }
        if spec["replicas"].as_u64().is_some_and(|replicas| replicas > 1) {
            return Err(refused("Neo Grid places a model by share, not by replica count; use share_percent."));
        }
        if Self::is_team(spec) && !text(spec, "model").is_some_and(|model| model.starts_with("swarm/")) {
            return Err(invalid("A team is called swarm/NAME."));
        }
        Ok(())
    }

    fn review(&self, id: &str, spec: &Value, others: &BTreeMap<String, (Kind, Value)>) -> Result<(), HandlerError> {
        if research::made_by_worker(Kind::ModelService, id, others.values().map(|(kind, spec)| (*kind, spec))) {
            // The research worker runs this model itself; its own review says what it may be.
            return Ok(());
        }
        if local_models::is_local(spec) {
            return self.local().review(id, spec);
        }
        if spec["compute"]["resource"].as_str().and_then(|id| others.get(id)).is_some_and(|(kind, _)| *kind == Kind::Environment) {
            return Err(refused("Running a model inside a sandbox isn't available yet; leave out compute: to run it in its own model sandbox on this computer."));
        }
        let pool = spec["compute"]["resource"].as_str().and_then(|id| others.get(id)).filter(|(kind, _)| *kind == Kind::ComputePool);
        let grid = pool.and_then(|(_, pool)| declared_grid(&pool["grid"], others));
        if grid != Some(("neo_grid", "create")) {
            return Err(refused("A model is served by a pool of a Neo Grid this setup makes."));
        }
        if Self::is_team(spec) {
            let members = std::iter::once(&spec["team"]["lead"]).chain(spec["team"]["workers"].as_array().into_iter().flatten());
            for member in members {
                if !member["resource"].as_str().and_then(|id| others.get(id)).is_some_and(|(kind, _)| *kind == Kind::ModelService) {
                    return Err(invalid("A team's lead and workers are model services of this setup."));
                }
            }
        }
        Ok(())
    }

    fn plan(&self, current: Option<&Resource>, spec: &Value, spec_digest: &str) -> Result<Planned, HandlerError> {
        if local_models::is_local(spec) {
            return self.local().plan(current, spec_digest);
        }
        if Self::is_team(spec) {
            return fixed_once_made(current, spec_digest, "A team is changed by removing it and adding it again.");
        }
        Ok(match current {
            None => Planned::Step(Action::Create),
            Some(resource) if resource.runtime_id.is_none() => Planned::Step(Action::Create),
            Some(resource) if resource.spec_digest != spec_digest => Planned::Step(Action::Update),
            Some(_) => Planned::Unchanged,
        })
    }

    fn notes(&self, _setup: &str, resource: &str, spec: &Value, action: Action) -> Vec<String> {
        if local_models::is_local(spec) {
            return self.local().notes(resource, spec, action);
        }
        Vec::new()
    }

    fn stoppable(&self) -> bool {
        false
    }

    fn stop<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Receipt> {
        Box::pin(async move {
            if research::part_of_worker(context) {
                return Ok(research::part_receipt(context));
            }
            if local_models::is_local(&context.spec) {
                return self.local().stop(context).await;
            }
            Err(HandlerError::unsupported(context.kind, "stop"))
        })
    }

    fn health<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, HealthReport> {
        Box::pin(async move {
            if research::part_of_worker(context) {
                return Ok(research::part_health());
            }
            if local_models::is_local(&context.spec) {
                return self.local().health(context).await;
            }
            Err(HandlerError::unsupported(context.kind, "check the health of"))
        })
    }

    /// The model's name for apps and the grid's API address, while its plan or team is in the
    /// grid this setup made. A model on this computer alone shows nothing here yet.
    fn outputs<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, BTreeMap<String, String>> {
        Box::pin(async move {
            let mut outputs = BTreeMap::new();
            let Some(id) = context.runtime_id.clone().filter(|_| !local_models::is_local(&context.spec)) else { return Ok(outputs) };
            let Some((status, _)) = self.own_hub(context).await? else { return Ok(outputs) };
            let list = if Self::is_team(&context.spec) { &status["hub"]["harnesses"] } else { &status["hub"]["plans"] };
            if !list.as_array().is_some_and(|entries| entries.iter().any(|entry| entry["id"].as_str() == Some(id.as_str()))) {
                return Ok(outputs);
            }
            if let Some(model) = text(&context.spec, "model") {
                outputs.insert("model".to_owned(), model);
            }
            if let Some(endpoint) = text(&status["hub"], "url") {
                outputs.insert("endpoint".to_owned(), endpoint);
            }
            outputs.insert("id".to_owned(), id);
            Ok(outputs)
        })
    }

    /// The plan or team whose ID was recorded, in this setup's grid; before a receipt exists, one
    /// of this model added after the step began. A plan the person added is never taken.
    fn observe<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Observation> {
        Box::pin(async move {
            if research::part_of_worker(context) {
                return Ok(research::part_observation(context));
            }
            if local_models::is_local(&context.spec) {
                return self.local().observe(context).await;
            }
            let status = match self.own_hub(context).await {
                Ok(Some((status, _))) => status,
                Ok(None) => return Ok(Observation::Absent),
                Err(error) => return Ok(Observation::Unknown { reason: error.message }),
            };
            let list = if Self::is_team(&context.spec) { &status["hub"]["harnesses"] } else { &status["hub"]["plans"] };
            let model = text(&context.spec, "model").unwrap_or_default();
            let wanted = |entry: &&Value| match &context.runtime_id {
                Some(id) => entry["id"].as_str() == Some(id.as_str()),
                None => {
                    (entry["model"].as_str() == Some(model.as_str()) || entry["name"].as_str() == Some(model.trim_start_matches("swarm/")))
                        && made_by_step(context, &entry["createdAt"])
                }
            };
            Ok(match list.as_array().and_then(|entries| entries.iter().find(wanted)) {
                Some(entry) => Observation::Present {
                    runtime_id: entry["id"].as_str().unwrap_or_default().to_owned(),
                    observed: if entry["ready"].as_u64().unwrap_or(0) > 0 { Observed::Running } else { Observed::Present },
                    label: None,
                    retained_data: false,
                    cost: Cost::Free,
                },
                None => Observation::Absent,
            })
        })
    }

    fn apply<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Receipt> {
        Box::pin(async move {
            if research::part_of_worker(context) {
                return Ok(research::part_receipt(context));
            }
            if local_models::is_local(&context.spec) {
                return self.local().apply(context).await;
            }
            let Some((_, key)) = self.own_hub(context).await? else {
                return Err(HandlerError::new(Outcome::NotStarted, "target_missing", "This setup's Neo Grid isn't running on this computer."));
            };
            if Self::is_team(&context.spec) {
                if context.action == Action::Update {
                    return Err(refused("A team is changed by removing it and adding it again."));
                }
                let result = self.0.ask_in(context, &key, "grid_swarm_add", Self::team(context)?).await.map_err(|error| failed(context, error))?;
                let id = result["harness"]["id"].as_str().ok_or_else(|| HandlerError::new(Outcome::Unknown, "outcome_unknown", "The grid didn't report the team."))?;
                return Ok(receipt(Some(id.to_owned()), Observed::Present, false));
            }
            let mut plan = Self::plan_request(context);
            // On picked computers: those of them in the grid now, by the names they joined with.
            if let Some(pool) = Self::pool(context).filter(|pool| ComputePoolHandler::selects(pool)) {
                if context.action != Action::Update {
                    let status = self.0.status_in(Product::NEO, &key).await?.unwrap_or(Value::Null);
                    let wanted = ComputePoolHandler::picked(pool);
                    let members = status["hub"]["members"].as_array().cloned().unwrap_or_default();
                    let ids: Vec<String> = members
                        .iter()
                        .filter(|member| member["name"].as_str().is_some_and(|name| wanted.iter().any(|wanted| wanted.eq_ignore_ascii_case(name))))
                        .filter_map(|member| member["id"].as_str().map(str::to_owned))
                        .collect();
                    if ids.is_empty() {
                        return Err(HandlerError {
                            retryable: true,
                            ..HandlerError::new(Outcome::NotStarted, "waiting_for_computer", format!("None of the computers this model runs on has joined the grid yet ({}). Apply the setup again once one has.", wanted.join(", ")))
                        });
                    }
                    plan["computers"] = json!(ids);
                    plan.as_object_mut().map(|object| object.remove("scope"));
                }
            }
            let result = match (context.action, &context.runtime_id) {
                (Action::Update, Some(id)) => {
                    plan["planId"] = json!(id);
                    plan.as_object_mut().map(|object| object.remove("scope"));
                    self.0.ask_in(context, &key, "grid_plan_update", plan).await
                }
                _ => {
                    // An empty schedule clears hours on an update; a new plan simply has none.
                    if plan["schedule"] == "" {
                        plan["schedule"] = Value::Null;
                    }
                    self.0.ask_in(context, &key, "grid_plan_add", plan).await
                }
            }
            .map_err(|error| failed(context, error))?;
            let id = result["plan"]["id"]
                .as_str()
                .map(str::to_owned)
                .or_else(|| context.runtime_id.clone())
                .ok_or_else(|| HandlerError::new(Outcome::Unknown, "outcome_unknown", "The grid didn't report the model plan."))?;
            Ok(receipt(Some(id), Observed::Present, false))
        })
    }

    fn remove<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Receipt> {
        Box::pin(async move {
            if research::part_of_worker(context) {
                return Ok(research::part_receipt(context));
            }
            if local_models::is_local(&context.spec) {
                return self.local().remove(context).await;
            }
            // The grid itself may already be gone (removed first, or deleted elsewhere).
            if let (Some(id), Some((_, key))) = (&context.runtime_id, self.own_hub(context).await?) {
                let (method, field, gone) = if Self::is_team(&context.spec) {
                    ("grid_swarm_remove", "harnessId", "No harness with that ID or name exists in this grid")
                } else {
                    ("grid_plan_remove", "planId", "No plan with that ID exists in this grid")
                };
                match self.0.ask_in(context, &key, method, json!({ field: id })).await {
                    Ok(_) => {}
                    Err(error) if error == gone => {}
                    Err(error) => return Err(failed(context, error)),
                }
            }
            Ok(receipt(None, Observed::Missing, false))
        })
    }

    fn recover<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Recovery> {
        Box::pin(async move {
            if research::part_of_worker(context) {
                return Ok(Recovery::NotApplied);
            }
            if local_models::is_local(&context.spec) {
                return self.local().recover(context).await;
            }
            let observation = self.observe(context).await?;
            Ok(match (context.action, observation) {
                (Action::Create, Observation::Present { runtime_id, observed, retained_data, cost, .. }) => {
                    Recovery::Applied(Receipt { runtime_id: Some(runtime_id), observed, retained_data, cost, at: now(), adopted: true })
                }
                // Whether an update took is not visible in the plan list: set it again.
                (Action::Update, Observation::Present { .. }) => Recovery::NotApplied,
                (_, observation) => super::handler::recovery_from(context, observation),
            })
        })
    }
}

// ----- Workspaces and people (Sandbox Grid) -----

/// How a Sandbox Grid gives people workspaces. With one per person, each person's workspace is
/// ordered with their account (see `AccessBindingHandler`), so the pool itself is a recorded
/// policy; nothing is created for it alone.
pub(crate) struct WorkspacePoolHandler;

impl WorkspacePoolHandler {
    /// The desk a person gets from a pool, in the product's terms.
    fn desk(spec: &Value) -> Value {
        json!({
            "kind": match spec["runtime"].as_str().unwrap_or("container") { "microvm" => "microvm", "vm" => "vm", _ => "container" },
            "cpu": spec["resources"]["cpu"],
            "memoryGb": spec["resources"]["memory_gb"],
            "diskGb": spec["resources"]["disk_gb"],
            "gpu": spec["gpu"].as_bool().unwrap_or(false),
        })
    }
}

impl ResourceHandler for WorkspacePoolHandler {
    fn kind(&self) -> Kind {
        Kind::WorkspacePool
    }

    fn validate(&self, spec: &Value) -> Result<(), HandlerError> {
        if spec["allocation"].as_str() == Some("shared") {
            return Err(refused("Shared workspaces are ordered from the grid's own tab in My setups for now; setups give each person their own."));
        }
        for (field, what) in [("parking", "Parking workspaces in a bucket"), ("backup", "Workspace backups"), ("cloud_fallback", "A cloud fallback computer")] {
            if spec[field].as_bool() == Some(true) {
                return Err(refused(&format!("{what} is set on the grid's own tab in My setups for now.")));
            }
        }
        if !spec["drive"].is_null() || !spec["data"].is_null() {
            return Err(refused("Choosing where workspaces keep their data is done on the grid's own tab in My setups for now."));
        }
        if spec["runtime"].as_str() == Some("vm") && text(spec, "image").is_none() {
            return Err(invalid("A workspace that is a full virtual machine needs its image."));
        }
        Ok(())
    }

    fn review(&self, _id: &str, spec: &Value, others: &BTreeMap<String, (Kind, Value)>) -> Result<(), HandlerError> {
        if spec["grid"]["resource"].as_str().is_some() && declared_grid(&spec["grid"], others) != Some(("sandbox_grid", "create")) {
            return Err(refused("Workspaces are given by a Sandbox Grid this setup makes."));
        }
        Ok(())
    }

    fn stoppable(&self) -> bool {
        false
    }

    fn observe<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Observation> {
        Box::pin(async move {
            Ok(Observation::Present { runtime_id: format!("{}/workspaces", context.resource), observed: Observed::Present, label: None, retained_data: false, cost: Cost::Free })
        })
    }

    fn apply<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Receipt> {
        Box::pin(async move { Ok(receipt(Some(format!("{}/workspaces", context.resource)), Observed::Present, false)) })
    }

    fn remove<'a>(&'a self, _context: &'a StepContext) -> HandlerFuture<'a, Receipt> {
        // Each person's workspace stays with its data until that person or workspace is removed.
        Box::pin(async move { Ok(receipt(None, Observed::Missing, false)) })
    }

    fn recover<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Recovery> {
        Box::pin(async move {
            Ok(match context.action {
                Action::Create | Action::Update => Recovery::Applied(self.apply(context).await?),
                _ => Recovery::NotApplied,
            })
        })
    }
}

/// A person of a Sandbox or Access Grid this setup made: their account and, from a workspace
/// pool, their own workspace.
pub(crate) struct AccessBindingHandler(Grids);

impl AccessBindingHandler {
    /// A grid's sign-in settings rather than a person: company sign-in (and an Access Grid's
    /// two-step rule) for everyone.
    fn is_setting(spec: &Value) -> bool {
        spec["person"].is_null() && spec["admin"].is_null() && !share::is_share(spec) && (!spec["sso"].is_null() || spec["mfa"].as_bool() == Some(true))
    }

    fn invited(spec: &Value) -> bool {
        spec["invite"].as_bool() == Some(true)
    }

    /// The person's role, the strongest one their binding lists: `member` when it lists none.
    fn role(spec: &Value) -> &'static str {
        let listed = spec["roles"].as_array().cloned().unwrap_or_default();
        ["admin", "operator", "approver", "auditor"].into_iter().find(|role| listed.iter().any(|given| given.as_str() == Some(role))).unwrap_or("member")
    }

    /// The role as a product names it: an Access Grid's permission, a Sandbox Grid's
    /// administrative role.
    fn product_role(access: bool, role: &str) -> &'static str {
        match (access, role) {
            (true, "admin") => "admin",
            (true, "approver") => "approver",
            (true, "auditor") => "auditor",
            (true, _) => "member",
            (false, "admin") => "administrator",
            (false, "operator") => "operator",
            (false, "auditor") => "auditor",
            (false, _) => "user",
        }
    }

    /// Whether everything but a person's role, or a grid's sign-in settings, is as it was: the
    /// two things that change in place.
    fn changes_in_place(previous: &Value, spec: &Value) -> bool {
        let without = |value: &Value| {
            let mut copy = value.clone();
            if let Some(object) = copy.as_object_mut() {
                object.remove("roles");
                object.remove("sso");
                object.remove("mfa");
            }
            copy
        };
        without(previous) == without(spec) && (Self::is_setting(spec) || spec["admin"].is_null())
    }

    /// Where an invited person's password is kept on this computer.
    fn invitation_account(context: &StepContext) -> String {
        format!("setup-invite.{}.{}", context.setup, context.resource)
    }

    /// The product request that sets company sign-in for everyone.
    fn sso_request(access: bool, sso: &Value) -> Value {
        let claim = text(sso, "username_claim").unwrap_or_else(|| "email".into());
        let mut request = json!({"action": "ssoSet", "issuer": text(sso, "issuer"), "clientId": text(sso, "client_id"), "passwordless": sso["passwordless"].as_bool().unwrap_or(false)});
        request[if access { "claim" } else { "usernameClaim" }] = json!(claim);
        request
    }

    /// Sets a grid's sign-in settings: company sign-in, and an Access Grid's two-step rule.
    async fn apply_setting(&self, context: &StepContext) -> Result<Receipt, HandlerError> {
        let spec = &context.spec;
        let grid = grid_id(context, &spec["grid"]).ok_or_else(|| HandlerError::new(Outcome::NotStarted, "target_missing", "This setup's grid doesn't exist yet."))?;
        let access = Self::on_access(context);
        if access {
            self.0.own_access(&grid).await?.ok_or_else(|| HandlerError::new(Outcome::NotStarted, "target_missing", "This setup's Access Grid isn't open on this computer."))?;
            let key = located(&grid).1;
            if spec["sso"].is_object() {
                self.0.manage(context, key, Self::sso_request(true, &spec["sso"])).await.map_err(|error| failed(context, error))?;
            } else if context.recorded.as_ref().is_some_and(|before| before["sso"].is_object()) {
                self.0.manage(context, key, json!({"action": "ssoClear"})).await.map_err(|error| failed(context, error))?;
            }
            if spec["mfa"].as_bool() == Some(true) {
                self.0.manage(context, key, json!({"action": "settingsSet", "requireTwoStep": true})).await.map_err(|error| failed(context, error))?;
            }
        } else {
            let (_, key) = self.own_desks(context).await?.ok_or_else(|| HandlerError::new(Outcome::NotStarted, "target_missing", "This setup's Sandbox Grid isn't running on this computer."))?;
            let before = context.recorded.clone().unwrap_or(Value::Null);
            if spec["sso"].is_object() || before["sso"].is_object() {
                let request = if spec["sso"].is_object() { Self::sso_request(false, &spec["sso"]) } else { json!({"action": "ssoClear"}) };
                self.0.ask_in(context, &key, "desks_manage", json!({"request": request})).await.map_err(|error| failed(context, error))?;
            }
            // Two-step sign-in for everyone: until it is on for them, a person signs in only to turn it on.
            let wants = spec["mfa"].as_bool() == Some(true);
            if wants || before["mfa"].as_bool() == Some(true) {
                self.0.ask_in(context, &key, "desks_manage", json!({"request": {"action": "twoStepRequire", "required": wants}})).await.map_err(|error| failed(context, error))?;
            }
        }
        Ok(receipt(Some(format!("{grid}/sign-in")), Observed::Present, false))
    }

    /// Gives a person already in the grid the role their binding says now.
    async fn change_role(&self, context: &StepContext) -> Result<(), HandlerError> {
        let id = context.runtime_id.clone().ok_or_else(|| HandlerError::new(Outcome::NotStarted, "target_missing", "This person isn't in the grid yet."))?;
        let role = Self::role(&context.spec);
        if Self::on_access(context) {
            let grid = grid_id(context, &context.spec["grid"]).unwrap_or_default();
            self.0.own_access(&grid).await?.ok_or_else(|| HandlerError::new(Outcome::NotStarted, "target_missing", "This setup's Access Grid isn't open on this computer."))?;
            self.0.manage(context, located(&grid).1, json!({"action": "personUpdate", "person": id, "permission": Self::product_role(true, role)})).await.map_err(|error| failed(context, error))?;
        } else {
            let (_, key) = self.own_desks(context).await?.ok_or_else(|| HandlerError::new(Outcome::NotStarted, "target_missing", "This setup's Sandbox Grid isn't running on this computer."))?;
            self.0.ask_in(context, &key, "desks_manage", json!({"request": {"action": "personUpdate", "id": id, "adminRole": Self::product_role(false, role)}})).await.map_err(|error| failed(context, error))?;
        }
        Ok(())
    }

    /// The password a person's account is made with: theirs, given privately, or, for one who is
    /// invited, one nobody types, kept on this computer for their invitation.
    fn password_for(&self, context: &StepContext) -> Result<String, HandlerError> {
        if !Self::invited(&context.spec) {
            return secret(context, "password");
        }
        let account = Self::invitation_account(context);
        if let Some(kept) = self.0.calls.kept(&account).map_err(|error| HandlerError::new(Outcome::NotStarted, "vault_unavailable", error))? {
            return Ok(kept);
        }
        let made = scoped::password();
        self.0.calls.keep(&account, &made).map_err(|error| HandlerError::new(Outcome::NotStarted, "vault_unavailable", error))?;
        Ok(made)
    }

    fn username(spec: &Value) -> Option<String> {
        spec["person"]["username"].as_str().map(str::trim).filter(|name| !name.is_empty()).map(str::to_owned)
    }

    fn on_access(context: &StepContext) -> bool {
        product_of(context, &context.spec["grid"]).is_some_and(|calls| calls.is(Product::ACCESS))
    }

    fn has_workspace(spec: &Value) -> bool {
        spec["workspace_pool"]["resource"].as_str().is_some() && spec["workspaces"].as_str().unwrap_or("individual") == "individual"
    }

    /// The Access Grid person this binding is about, in this setup's Access Grid: by recorded ID;
    /// the first administrator as the grid's owner; anyone else, before a receipt exists, by
    /// username (the policy's lower case) and only if added after the step began.
    async fn access_person(&self, context: &StepContext, status: &Value, key: &str) -> Result<Option<String>, HandlerError> {
        let overview = self.0.overview(key).await.map_err(|error| unavailable(&error))?;
        let admin = !context.spec["admin"].is_null();
        let username = if admin { status["hub"]["owner"].as_str().map(str::to_owned) } else { Self::username(&context.spec) };
        let found = overview["people"].as_array().into_iter().flatten().find(|person| match &context.runtime_id {
            Some(id) => person["id"].as_str() == Some(id.as_str()),
            None => {
                let named = username.as_deref().is_some_and(|wanted| person["username"].as_str().is_some_and(|name| name.eq_ignore_ascii_case(wanted)));
                named && (admin || made_by_step(context, &person["createdAt"]))
            }
        });
        Ok(found.and_then(|person| person["id"].as_str().map(str::to_owned)))
    }

    /// An Access Grid person: the first administrator was made with the grid, so it is only
    /// confirmed (and two-step sign-in set); anyone else is added.
    async fn apply_access(&self, context: &StepContext) -> Result<Receipt, HandlerError> {
        let spec = &context.spec;
        let grid = grid_id(context, &spec["grid"]).ok_or_else(|| HandlerError::new(Outcome::NotStarted, "target_missing", "This setup's Access Grid doesn't exist yet."))?;
        let status = self.0.own_access(&grid).await?.ok_or_else(|| HandlerError::new(Outcome::NotStarted, "target_missing", "This setup's Access Grid isn't open on this computer."))?;
        let key = located(&grid).1;
        let id = if spec["admin"].is_null() {
            let password = self.password_for(context)?;
            let username = Self::username(spec).unwrap_or_default();
            let request = json!({"action": "personAdd", "username": username, "name": spec["person"]["display_name"].as_str().unwrap_or(&username), "password": password, "permission": Self::product_role(true, Self::role(spec))});
            let added = self.0.manage(context, key, request).await.map_err(|error| failed(context, error))?;
            added["personId"].as_str().or_else(|| added["person"]["id"].as_str()).map(str::to_owned)
        } else {
            self.access_person(context, &status, key).await?
        }
        .ok_or_else(|| HandlerError::new(Outcome::Unknown, "outcome_unknown", "The grid didn't report this person."))?;
        if spec["mfa"].as_bool() == Some(true) {
            self.0.manage(context, key, json!({"action": "settingsSet", "requireTwoStep": true})).await.map_err(|error| failed(context, error))?;
        }
        Ok(receipt(Some(id), Observed::Present, false))
    }

    /// This setup's Sandbox Grid status and the instance it is in, or `None` when its hub isn't the
    /// one this setup made.
    async fn own_desks(&self, context: &StepContext) -> Result<Option<(Value, String)>, HandlerError> {
        let Some(grid) = grid_id(context, &context.spec["grid"]) else { return Ok(None) };
        let (id, key) = located(&grid);
        let Some(status) = self.0.status_in(Product::SANDBOX, key).await? else { return Ok(None) };
        Ok((status["hub"]["id"].as_str() == Some(id)).then(|| (status, key.to_owned())))
    }

    /// The round this person's workspace was last made again at. Raising it is the only thing
    /// that makes a workspace again, and it only ever touches this one person's.
    fn round(spec: &Value) -> u64 {
        spec["reset"].as_u64().unwrap_or(0)
    }

    /// Whether this change is a reset and nothing else: everything but the round is as it was.
    /// Anything else about a person still can't be changed here, so a reset can never smuggle in
    /// another change.
    fn only_a_reset(previous: &Value, spec: &Value) -> bool {
        let without_round = |value: &Value| {
            let mut copy = value.clone();
            if let Some(object) = copy.as_object_mut() {
                object.remove("reset");
            }
            copy
        };
        Self::round(spec) > Self::round(previous) && without_round(previous) == without_round(spec)
    }

    /// The name a reset workspace carries, which says which round made it. It is this step's
    /// stamp in the product's own field: a step that runs again finds the workspace it already
    /// made and leaves it alone, so a lost receipt can never destroy a fresh workspace.
    fn desk_name(username: &str, round: u64) -> String {
        let room = 64 - format!(" (round {round})").chars().count();
        let username = username.chars().take(room).collect::<String>();
        format!("{username} (round {round})")
    }

    /// Makes this one person's workspace again from scratch.
    ///
    /// Only desks the grid says belong to the person ID this setup recorded when it added them
    /// are removed, never one found by a name another person could also carry. The pool, the
    /// grid, this person's account and everybody else's workspace are left exactly as they are.
    async fn reset_workspace(&self, context: &StepContext, round: u64) -> Result<(), HandlerError> {
        let spec = &context.spec;
        let username = Self::username(spec).unwrap_or_default();
        let person = context.runtime_id.clone().ok_or_else(|| {
            HandlerError::new(Outcome::NotStarted, "target_missing", format!("{username} doesn't have an account in the grid yet, so there is no workspace to make again. Nothing was changed."))
        })?;
        let pool = spec["workspace_pool"]["resource"]
            .as_str()
            .and_then(|id| context.peers.get(id))
            .filter(|pool| pool.kind == Kind::WorkspacePool)
            .ok_or_else(|| HandlerError::new(Outcome::NotStarted, "target_missing", format!("The pool {username}'s workspace comes from isn't part of this setup. Nothing was changed.")))?;
        let (status, key) = self
            .own_desks(context)
            .await?
            .ok_or_else(|| HandlerError::new(Outcome::NotStarted, "target_missing", "This setup's Sandbox Grid isn't running on this computer. Nothing was changed."))?;
        let desks = status["hub"]["desks"].as_array().cloned().unwrap_or_default();
        let theirs = desks.iter().filter(|desk| desk["personId"].as_str() == Some(person.as_str())).collect::<Vec<_>>();
        let wanted = Self::desk_name(&username, round);
        if theirs.iter().any(|desk| desk["name"].as_str() == Some(wanted.as_str())) {
            // This round's workspace is already there: an earlier attempt of this step made it.
            return Ok(());
        }
        for desk in &theirs {
            let id = desk["id"].as_str().unwrap_or_default();
            match self.0.ask_in(context, &key, "desks_remove", json!({ "desk": id })).await {
                Ok(_) => {}
                Err(error) if error == "No desk with that ID is in this grid" => {}
                Err(error) => return Err(HandlerError { retryable: true, ..failed(context, error) }),
            }
        }
        let mut request = WorkspacePoolHandler::desk(&pool.spec);
        request["name"] = json!(wanted);
        request["person"] = json!(person);
        request["image"] = json!(text(&pool.spec, "image"));
        self.0.ask_in(context, &key, "desks_add", request).await.map_err(|error| {
            let refusal = failed(context, error);
            if theirs.is_empty() {
                return refusal;
            }
            // Their old workspace is gone and the new one was not ordered: say so plainly, and
            // leave it to the retry rather than deciding anything here.
            HandlerError::new(
                Outcome::Unknown,
                "outcome_unknown",
                format!("{username}'s old workspace was removed, but the new one wasn't ordered: {} Retrying orders it; nothing else was touched.", refusal.message),
            )
        })?;
        Ok(())
    }

    /// One sandbox shared with one person (`share:`) goes through the remote gateway, in
    /// `setups::share`.
    fn share(&self) -> Shares {
        Shares::new(self.0.calls.clone())
    }
}

impl ResourceHandler for AccessBindingHandler {
    fn kind(&self) -> Kind {
        Kind::AccessBinding
    }

    fn validate(&self, spec: &Value) -> Result<(), HandlerError> {
        if share::is_share(spec) {
            return self.share().validate(spec);
        }
        if spec["invitations"].as_u64().unwrap_or(0) > 0 {
            return Err(refused("A number of invitations isn't something a grid makes. Invite each person by name with person: {username: ...} and invite: true."));
        }
        if !spec["sso"].is_null() {
            if text(&spec["sso"], "issuer").is_none_or(|issuer| !issuer.starts_with("https://")) {
                return Err(invalid("Company sign-in needs the provider's https:// issuer address."));
            }
            if text(&spec["sso"], "client_id").is_none() {
                return Err(invalid("Company sign-in needs the client ID of the app registered at the provider."));
            }
            if Self::is_setting(spec) {
                if spec["grid"]["resource"].as_str().is_none() {
                    return Err(invalid("Company sign-in names its grid with grid: {resource: ID}."));
                }
                return Ok(());
            }
        }
        if !spec["admin"].is_null() {
            // The first administrator of an Access Grid, made with the grid.
            if spec["admin"]["username"].as_str().unwrap_or_default().trim().is_empty() || spec["secrets"]["admin_password"].as_str().unwrap_or_default().is_empty() {
                return Err(invalid("An administrator needs a username and a password, given privately."));
            }
        } else {
            if spec["roles"].as_array().is_some_and(|roles| roles.iter().any(|role| role.as_str() == Some("owner"))) {
                return Err(invalid("The owner is the grid's first administrator, made with it: declare them with admin:."));
            }
            if Self::is_setting(spec) {
                if spec["grid"]["resource"].as_str().is_none() {
                    return Err(invalid("A grid's settings name their grid with grid: {resource: ID}."));
                }
                return Ok(());
            }
            if Self::username(spec).is_none() {
                return Err(invalid("A person needs a username."));
            }
            if Self::round(spec) > 0 && spec["workspace_pool"]["resource"].as_str().is_none() {
                return Err(invalid("A reset makes this person's own workspace again; name where it comes from with workspace_pool: {resource: ID}."));
            }
            if !Self::invited(spec) && spec["sso"].is_null() && spec["secrets"]["password"].as_str().unwrap_or_default().is_empty() {
                return Err(invalid("A person needs a password, given privately, or to be invited (invite: true)."));
            }
        }
        if spec["grid"]["resource"].as_str().is_none() {
            return Err(invalid("A person names their grid with grid: {resource: ID}."));
        }
        Ok(())
    }

    fn review(&self, id: &str, spec: &Value, others: &BTreeMap<String, (Kind, Value)>) -> Result<(), HandlerError> {
        if share::is_share(spec) {
            return self.share().review(id, spec, others);
        }
        match declared_grid(&spec["grid"], others) {
            Some(("access_grid", "create")) => {
                if Self::role(spec) == "operator" {
                    return Err(refused("An Access Grid has members, approvers, auditors and admins; operators belong to a Sandbox Grid."));
                }
                Ok(())
            }
            Some(("sandbox_grid", "create")) if !spec["admin"].is_null() => {
                Err(refused("A Sandbox Grid's first administrator is the person who runs it on this computer. Give the people it adds a role instead."))
            }
            Some(("sandbox_grid", "create")) if spec["mfa"].as_bool() == Some(true) && !Self::is_setting(spec) => {
                Err(refused("On a Sandbox Grid two-step sign-in is a rule for everyone: declare mfa: true on a binding of its own, without a person."))
            }
            Some(("sandbox_grid", "create")) => {
                if Self::role(spec) == "approver" {
                    return Err(refused("A Sandbox Grid has users, operators, auditors and administrators; approvers belong to an Access Grid."));
                }
                Ok(())
            }
            _ => Err(refused("People are added to a Sandbox or Access Grid this setup makes.")),
        }
    }

    fn plan(&self, current: Option<&Resource>, spec: &Value, spec_digest: &str) -> Result<Planned, HandlerError> {
        if share::is_share(spec) {
            return self.share().plan(current, spec_digest);
        }
        // Raising this person's reset round makes their workspace again. It is the one change a
        // person's record takes in place; everything else about them is still set on the grid's
        // own tab in My setups, and a lowered round changes nothing at all.
        if let Some(resource) = current.filter(|resource| resource.runtime_id.is_some()) {
            if resource.spec_digest != spec_digest && (Self::only_a_reset(&resource.spec, spec) || Self::changes_in_place(&resource.spec, spec)) {
                return Ok(Planned::Step(Action::Update));
            }
        }
        fixed_once_made(current, spec_digest, "A person's account is changed on the grid's own tab in My setups for now.")
    }

    /// What a reset deletes, named before anything runs. A workspace is only ever made again
    /// when this person's own round is raised, never as a side effect of another change.
    fn change_notes(&self, _setup: &str, _resource: &str, previous: &Value, spec: &Value) -> Vec<String> {
        if share::is_share(spec) || !Self::only_a_reset(previous, spec) {
            return Vec::new();
        }
        let username = Self::username(spec).unwrap_or_else(|| "this person".into());
        vec![format!(
            "{username}'s workspace is made again from scratch (round {}). Everything in it goes: their files, anything they installed and anything they left running. It comes back empty, the same size as before. Nobody else's workspace is touched, and {username}'s account and password stay as they are.",
            Self::round(spec)
        )]
    }

    fn notes(&self, _setup: &str, resource: &str, spec: &Value, action: Action) -> Vec<String> {
        if share::is_share(spec) {
            return self.share().notes(resource, spec, action);
        }
        match (action, Self::username(spec)) {
            (Action::Remove, Some(name)) if Self::has_workspace(spec) => {
                vec![format!("{name}'s account is removed. Their workspace stays, unassigned, with its data; delete it from the grid's own tab in My setups when it is no longer needed.")]
            }
            _ => Vec::new(),
        }
    }

    fn stoppable(&self) -> bool {
        false
    }

    fn health<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, HealthReport> {
        Box::pin(async move {
            if share::is_share(&context.spec) {
                return self.share().health(context).await;
            }
            Err(HandlerError::unsupported(context.kind, "check the health of"))
        })
    }

    fn observe<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Observation> {
        Box::pin(async move {
            if share::is_share(&context.spec) {
                return self.share().observe(context).await;
            }
            let present = |id: String| Observation::Present { runtime_id: id, observed: Observed::Present, label: None, retained_data: false, cost: Cost::Free };
            if Self::is_setting(&context.spec) {
                return Ok(match &context.runtime_id {
                    Some(id) => present(id.clone()),
                    None => Observation::Absent,
                });
            }
            if Self::on_access(context) {
                let Some(grid) = grid_id(context, &context.spec["grid"]) else { return Ok(Observation::Absent) };
                let status = match self.0.own_access(&grid).await {
                    Ok(Some(status)) => status,
                    Ok(None) => return Ok(Observation::Absent),
                    Err(error) => return Ok(Observation::Unknown { reason: error.message }),
                };
                return Ok(match self.access_person(context, &status, located(&grid).1).await {
                    Ok(Some(id)) => present(id),
                    Ok(None) => Observation::Absent,
                    Err(error) => Observation::Unknown { reason: error.message },
                });
            }
            let status = match self.own_desks(context).await {
                Ok(Some((status, _))) => status,
                Ok(None) => return Ok(Observation::Absent),
                Err(error) => return Ok(Observation::Unknown { reason: error.message }),
            };
            let username = Self::username(&context.spec).unwrap_or_default();
            let found = status["hub"]["people"].as_array().into_iter().flatten().find(|person| match &context.runtime_id {
                Some(id) => person["id"].as_str() == Some(id.as_str()),
                None => person["username"].as_str().is_some_and(|name| name.eq_ignore_ascii_case(&username)) && made_by_step(context, &person["createdAt"]),
            });
            Ok(match found.and_then(|person| person["id"].as_str()) {
                Some(id) => present(id.to_owned()),
                None => Observation::Absent,
            })
        })
    }

    fn apply<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Receipt> {
        Box::pin(async move {
            if share::is_share(&context.spec) {
                return self.share().apply(context).await;
            }
            if Self::is_setting(&context.spec) {
                return self.apply_setting(context).await;
            }
            if context.action == Action::Update {
                let previous = context.recorded.clone().unwrap_or(Value::Null);
                if Self::changes_in_place(&previous, &context.spec) {
                    self.change_role(context).await?;
                    return Ok(receipt(context.runtime_id.clone(), Observed::Present, false));
                }
                if !Self::only_a_reset(&previous, &context.spec) {
                    return Err(refused("Only a person's role, and making their workspace again, change in place; anything else about them is changed on the grid's own tab in My setups."));
                }
                self.reset_workspace(context, Self::round(&context.spec)).await?;
                return Ok(receipt(context.runtime_id.clone(), Observed::Present, false));
            }
            if context.action != Action::Create {
                return Err(refused("A person's account is changed on the grid's own tab in My setups for now."));
            }
            match product_of(context, &context.spec["grid"]) {
                Some(calls) if calls.is(Product::ACCESS) => return self.apply_access(context).await,
                Some(calls) if calls.is(Product::SANDBOX) => {}
                _ => return Err(refused("People are added to a Sandbox or Access Grid; this grid doesn't have accounts.")),
            }
            let Some((_, key)) = self.own_desks(context).await? else {
                return Err(HandlerError::new(Outcome::NotStarted, "target_missing", "This setup's Sandbox Grid isn't running on this computer."));
            };
            let spec = &context.spec;
            let username = Self::username(spec).unwrap_or_default();
            let password = self.password_for(context)?;
            let mut request = json!({
                "username": username,
                "name": spec["person"]["display_name"].as_str().unwrap_or(&username),
                "password": password,
            });
            let pool = spec["workspace_pool"]["resource"].as_str().and_then(|id| context.peers.get(id));
            if let (Some(pool), true) = (pool, Self::has_workspace(spec)) {
                let desk = WorkspacePoolHandler::desk(&pool.spec);
                for field in ["kind", "cpu", "memoryGb", "diskGb", "gpu"] {
                    request[field] = desk[field].clone();
                }
            }
            let person = self.0.ask_in(context, &key, "desks_person_add", request).await.map_err(|error| failed(context, error))?;
            let id = person["id"].as_str().ok_or_else(|| HandlerError::new(Outcome::Unknown, "outcome_unknown", "The grid didn't report the person."))?;
            // A role other than a user's is given right after: the product adds people as users.
            if Self::role(spec) != "member" {
                self.0
                    .ask_in(context, &key, "desks_manage", json!({"request": {"action": "personUpdate", "id": id, "adminRole": Self::product_role(false, Self::role(spec))}}))
                    .await
                    .map_err(|error| failed(context, error))?;
            }
            Ok(receipt(Some(id.to_owned()), Observed::Present, false))
        })
    }

    /// Removes the account this setup added, in the grid this setup made; a grid or person that
    /// is gone is left alone. A Sandbox Grid person's workspace stays, unassigned, with its data.
    /// An Access Grid's first administrator goes with the grid.
    fn remove<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Receipt> {
        Box::pin(async move {
            if share::is_share(&context.spec) {
                return self.share().remove(context).await;
            }
            let Some(id) = context.runtime_id.clone() else { return Ok(receipt(None, Observed::Missing, false)) };
            if Self::invited(&context.spec) {
                let _ = self.0.calls.forget(&Self::invitation_account(context));
            }
            if Self::is_setting(&context.spec) {
                // A Sandbox Grid's two-step rule goes with the setup; its people keep two-step on
                // where they turned it on.
                if context.spec["mfa"].as_bool() == Some(true) && !Self::on_access(context) {
                    if let Some((_, key)) = self.own_desks(context).await? {
                        self.0.ask_in(context, &key, "desks_manage", json!({"request": {"action": "twoStepRequire", "required": false}})).await.map_err(|error| failed(context, error))?;
                    }
                }
                // Company sign-in goes; the grid's people and their passwords stay as they are.
                if context.spec["sso"].is_object() {
                    let grid = grid_id(context, &context.spec["grid"]).unwrap_or_default();
                    let present = if Self::on_access(context) { self.0.own_access(&grid).await?.is_some() } else { self.own_desks(context).await?.is_some() };
                    if present {
                        if Self::on_access(context) {
                            self.0.manage(context, located(&grid).1, json!({"action": "ssoClear"})).await.map_err(|error| failed(context, error))?;
                        } else if let Some((_, key)) = self.own_desks(context).await? {
                            self.0.ask_in(context, &key, "desks_manage", json!({"request": {"action": "ssoClear"}})).await.map_err(|error| failed(context, error))?;
                        }
                    }
                }
                return Ok(receipt(None, Observed::Missing, false));
            }
            if Self::on_access(context) {
                let grid = grid_id(context, &context.spec["grid"]).unwrap_or_default();
                if context.spec["admin"].is_null() && self.0.own_access(&grid).await?.is_some() {
                    match self.0.manage(context, located(&grid).1, json!({"action": "personRemove", "person": id})).await {
                        Ok(_) => {}
                        Err(error) if error == "No such person" => {}
                        Err(error) => return Err(failed(context, error)),
                    }
                }
                return Ok(receipt(None, Observed::Missing, false));
            }
            let kept = Self::has_workspace(&context.spec);
            if let Some((status, key)) = self.own_desks(context).await? {
                if status["hub"]["people"].as_array().into_iter().flatten().any(|person| person["id"].as_str() == Some(id.as_str())) {
                    self.0.ask_in(context, &key, "desks_person_remove", json!({"person": id})).await.map_err(|error| failed(context, error))?;
                }
            }
            Ok(receipt(None, Observed::Missing, kept))
        })
    }

    /// The person's ID and, for one who is invited, their invitation: the grid's invite with
    /// their username and the password their account was made with, as one code (a private
    /// output, read only when asked).
    fn outputs<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, BTreeMap<String, String>> {
        Box::pin(async move {
            let mut outputs = BTreeMap::new();
            if share::is_share(&context.spec) || Self::is_setting(&context.spec) {
                return Ok(outputs);
            }
            let Some(id) = context.runtime_id.clone() else { return Ok(outputs) };
            outputs.insert("id".to_owned(), id);
            if Self::invited(&context.spec) {
                let status = if Self::on_access(context) {
                    let grid = grid_id(context, &context.spec["grid"]).unwrap_or_default();
                    self.0.own_access(&grid).await?
                } else {
                    self.own_desks(context).await?.map(|(status, _)| status)
                };
                let invite = status.as_ref().and_then(|status| text(&status["hub"], "invite").filter(|_| status["hub"]["closing"].is_null()));
                let password = self.0.calls.kept(&Self::invitation_account(context)).ok().flatten();
                if let (Some(invite), Some(password), Some(username)) = (invite, password, Self::username(&context.spec)) {
                    outputs.insert("invitation".to_owned(), scoped::encode(&invite, &username, &password));
                }
            }
            Ok(outputs)
        })
    }

    /// A person found by the recorded ID, or added by this step, is this step's; nobody is added
    /// twice and nobody the person added is taken.
    fn recover<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Recovery> {
        Box::pin(async move {
            if share::is_share(&context.spec) {
                return self.share().recover(context).await;
            }
            let observation = self.observe(context).await?;
            Ok(match (context.action, observation) {
                (Action::Create, Observation::Present { runtime_id, observed, retained_data, cost, .. }) => {
                    Recovery::Applied(Receipt { runtime_id: Some(runtime_id), observed, retained_data, cost, at: now(), adopted: true })
                }
                (_, observation) => super::handler::recovery_from(context, observation),
            })
        })
    }
}

// ----- Brokered credentials (Access Grid) -----

/// The credentials an Access Grid holds and the rules for using them. Each credential's value
/// is a secret given with this operation; it goes straight to the grid, which seals it.
///
/// What this setup adds carries its stamp in the product's own `note`, so a credential or rule
/// is known as this step's across attempts and restarts, and nothing the person added under the
/// same name is ever taken over, changed or deleted.
pub(crate) struct CredentialBrokerHandler(Grids);

impl CredentialBrokerHandler {
    fn credentials(spec: &Value) -> Vec<Value> {
        spec["credentials"].as_array().cloned().unwrap_or_default()
    }

    /// The note on what this resource adds: the setup, resource and generation it belongs to.
    fn stamp(context: &StepContext) -> String {
        format!("Added by My setups: {}/{} (generation {})", context.setup, context.resource, context.generation)
    }

    /// The product's decision for a credential's approval.
    fn decision(credential: &Value) -> &'static str {
        match credential["approval"].as_str().unwrap_or("ask") {
            "standing" => "allow",
            "never" => "never",
            _ => "ask",
        }
    }

    fn paths(credential: &Value) -> Vec<Value> {
        credential["paths"].as_array().cloned().filter(|paths| !paths.is_empty()).unwrap_or_else(|| vec![json!("/")])
    }

    /// What this setup's Access Grid (`grid`, as recorded) holds.
    async fn overview(&self, context: &StepContext, grid: &str) -> Result<Value, HandlerError> {
        self.0.overview(located(grid).1).await.map_err(|error| failed(context, error))
    }

    /// This step's credentials in the overview, by name, when each has all of its rules.
    fn complete(context: &StepContext, overview: &Value) -> Option<Vec<String>> {
        let stamp = Self::stamp(context);
        let mut ids = Vec::new();
        for credential in Self::credentials(&context.spec) {
            let name = text(&credential, "name").unwrap_or_default();
            let held = overview["credentials"].as_array().into_iter().flatten().find(|held| held["name"].as_str() == Some(name.as_str()) && held["note"].as_str() == Some(stamp.as_str()))?;
            let id = held["id"].as_str()?.to_owned();
            let rules = overview["rules"].as_array().into_iter().flatten().filter(|rule| rule["credential"].as_str() == Some(id.as_str()) && rule["note"].as_str().is_some_and(|note| note.starts_with(&stamp))).count();
            if rules < Self::paths(&credential).len() {
                return None;
            }
            ids.push(id);
        }
        Some(ids)
    }
}

impl ResourceHandler for CredentialBrokerHandler {
    fn kind(&self) -> Kind {
        Kind::CredentialBroker
    }

    /// Where signed-in computers send this setup's credential requests: the Access Grid this setup
    /// made, while it is open. Nothing once it is paused or gone.
    fn outputs<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, BTreeMap<String, String>> {
        Box::pin(async move {
            let mut outputs = BTreeMap::new();
            let grid = grid_id(context, &context.spec["grid"]).unwrap_or_default();
            let Some(status) = self.0.own_access(&grid).await? else { return Ok(outputs) };
            if let Some(endpoint) = reach(&status["hub"]) {
                outputs.insert("endpoint".to_owned(), endpoint);
            }
            if let Some(id) = context.runtime_id.clone().filter(|id| !id.is_empty()) {
                outputs.insert("id".to_owned(), id);
            }
            Ok(outputs)
        })
    }

    fn validate(&self, spec: &Value) -> Result<(), HandlerError> {
        if spec["grid"]["resource"].as_str().is_none() {
            return Err(invalid("A credential broker names its grid with grid: {resource: ID}."));
        }
        if spec["audit_export"].as_bool() == Some(true) {
            return Err(refused("Exporting the activity log is done from the grid's own tab in My setups for now."));
        }
        for credential in Self::credentials(spec) {
            if text(&credential, "name").is_none() || text(&credential, "kind").is_none() {
                return Err(invalid("Each credential needs a name and a kind."));
            }
            let value = credential["value"].as_str().unwrap_or_default();
            if spec["secrets"][value].as_str().unwrap_or_default().is_empty() {
                return Err(invalid("Each credential's value is a secret given privately, named under secrets:."));
            }
        }
        Ok(())
    }

    fn review(&self, _id: &str, spec: &Value, others: &BTreeMap<String, (Kind, Value)>) -> Result<(), HandlerError> {
        if declared_grid(&spec["grid"], others) != Some(("access_grid", "create")) {
            return Err(refused("Credentials are brokered by an Access Grid this setup makes."));
        }
        Ok(())
    }

    fn plan(&self, current: Option<&Resource>, _spec: &Value, spec_digest: &str) -> Result<Planned, HandlerError> {
        fixed_once_made(current, spec_digest, "Credentials and their rules are changed on the grid's own tab in My setups for now.")
    }

    fn notes(&self, _setup: &str, _resource: &str, spec: &Value, action: Action) -> Vec<String> {
        let names = Self::credentials(spec).iter().filter_map(|credential| text(credential, "name")).collect::<Vec<_>>();
        match action {
            Action::Remove if !names.is_empty() => vec![format!("The credentials this setup added ({}) are deleted from the Access Grid with their rules. Others are left alone.", names.join(", "))],
            _ => Vec::new(),
        }
    }

    fn stoppable(&self) -> bool {
        false
    }

    fn observe<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Observation> {
        Box::pin(async move {
            let grid = grid_id(context, &context.spec["grid"]).unwrap_or_default();
            match self.0.own_access(&grid).await {
                Ok(Some(_)) => {}
                Ok(None) => return Ok(Observation::Absent),
                Err(error) => return Ok(Observation::Unknown { reason: error.message }),
            }
            let overview = match self.overview(context, &grid).await {
                Ok(overview) => overview,
                Err(error) => return Ok(Observation::Unknown { reason: error.message }),
            };
            Ok(match Self::complete(context, &overview) {
                Some(ids) => Observation::Present { runtime_id: ids.join(","), observed: Observed::Present, label: None, retained_data: true, cost: Cost::Free },
                None => Observation::Absent,
            })
        })
    }

    /// Adds each credential and its rules. A credential of the same name that this setup didn't
    /// add refuses the step before anything changes. Once one is added, a later failure leaves
    /// the outcome to be settled by looking: a retry adds only what is missing, and never skips a
    /// rule for a credential that isn't this step's.
    fn apply<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Receipt> {
        Box::pin(async move {
            if context.action != Action::Create {
                return Err(refused("Credentials and their rules are changed on the grid's own tab in My setups for now."));
            }
            let grid = grid_id(context, &context.spec["grid"]).ok_or_else(|| HandlerError::new(Outcome::NotStarted, "target_missing", "This setup's Access Grid doesn't exist yet."))?;
            self.0.own_access(&grid).await?.ok_or_else(|| HandlerError::new(Outcome::NotStarted, "target_missing", "This setup's Access Grid isn't open on this computer."))?;
            let key = located(&grid).1;
            let stamp = Self::stamp(context);
            let overview = self.overview(context, &grid).await?;
            let held = overview["credentials"].as_array().cloned().unwrap_or_default();
            for credential in Self::credentials(&context.spec) {
                let name = text(&credential, "name").unwrap_or_default();
                if held.iter().any(|other| other["name"].as_str() == Some(name.as_str()) && other["note"].as_str() != Some(stamp.as_str())) {
                    return Err(HandlerError::new(
                        Outcome::Failed,
                        "credential_exists",
                        format!("The Access Grid already holds a credential named {name} that this setup didn't add. Nothing was changed; rename it in the template, or remove the existing one from the grid's own tab in My setups."),
                    ));
                }
            }
            let mut ids = Vec::new();
            let mut changed = false;
            let half_done = |error: String, changed: bool| {
                let failure = failed(context, error);
                if changed {
                    HandlerError::new(Outcome::Unknown, "outcome_unknown", format!("{} Some credentials were added; retrying adds only what is missing.", failure.message))
                } else {
                    failure
                }
            };
            for credential in Self::credentials(&context.spec) {
                let name = text(&credential, "name").unwrap_or_default();
                let id = match held.iter().find(|other| other["name"].as_str() == Some(name.as_str())).and_then(|other| other["id"].as_str()) {
                    // Added by an earlier attempt of this step: kept, never added twice.
                    Some(id) => id.to_owned(),
                    None => {
                        let binding = context.spec["secrets"][credential["value"].as_str().unwrap_or_default()].as_str().unwrap_or_default();
                        let value = context.secret(binding).map(str::to_owned).ok_or_else(|| {
                            HandlerError::new(Outcome::NeedsInput, "secret_needed", format!("The credential {name} needs its value before it can be added."))
                        })?;
                        let mut add = json!({"action": "credentialAdd", "name": name, "kind": credential["kind"], "destinations": credential["destinations"], "value": value, "note": stamp});
                        if let Some(field) = text(&credential, "field") {
                            add["field"] = json!(field);
                        }
                        let added = self.0.manage(context, key, add).await.map_err(|error| half_done(error, changed))?;
                        changed = true;
                        added["credentialId"].as_str().ok_or_else(|| HandlerError::new(Outcome::Unknown, "outcome_unknown", "The grid didn't report the credential."))?.to_owned()
                    }
                };
                for (index, path) in Self::paths(&credential).into_iter().enumerate() {
                    let note = format!("{stamp}, rule {}", index + 1);
                    let exists = overview["rules"].as_array().into_iter().flatten().any(|rule| rule["credential"].as_str() == Some(id.as_str()) && rule["note"].as_str() == Some(note.as_str()));
                    if exists {
                        continue;
                    }
                    let rule = json!({
                        "action": "ruleAdd",
                        "credential": id,
                        "who": "everyone",
                        "methods": credential["methods"],
                        "path": path,
                        "decision": Self::decision(&credential),
                        "limit": credential["per_hour"],
                        "hours": credential["expires_hours"],
                        "note": note,
                    });
                    self.0.manage(context, key, rule).await.map_err(|error| {
                        let failure = failed(context, error);
                        HandlerError::new(Outcome::Unknown, "outcome_unknown", format!("The credential {name} was added, but not all of its rules: {} Retrying adds only the missing rules.", failure.message))
                    })?;
                    changed = true;
                }
                ids.push(id);
            }
            Ok(receipt(Some(ids.join(",")), Observed::Present, true))
        })
    }

    /// Deletes the credentials this setup added, with their rules, and nothing else. Their sealed
    /// values go too. A grid that is gone or paused for deletion takes them with it.
    fn remove<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Receipt> {
        Box::pin(async move {
            let grid = grid_id(context, &context.spec["grid"]).unwrap_or_default();
            if self.0.own_access(&grid).await?.is_none() {
                return Ok(receipt(None, Observed::Missing, false));
            }
            let stamp = Self::stamp(context);
            let overview = self.overview(context, &grid).await?;
            for id in context.runtime_id.iter().flat_map(|ids| ids.split(',')).filter(|id| !id.is_empty()) {
                let ours = overview["credentials"].as_array().into_iter().flatten().any(|held| held["id"].as_str() == Some(id) && held["note"].as_str() == Some(stamp.as_str()));
                if !ours {
                    continue;
                }
                match self.0.manage(context, located(&grid).1, json!({"action": "credentialRemove", "credential": id})).await {
                    Ok(_) => {}
                    Err(error) if error == "No such credential" => {}
                    Err(error) => return Err(failed(context, error)),
                }
            }
            Ok(receipt(None, Observed::Missing, false))
        })
    }

    /// Done only when every credential and rule of this step is there; otherwise it runs again,
    /// which adds only what is missing.
    fn recover<'a>(&'a self, context: &'a StepContext) -> HandlerFuture<'a, Recovery> {
        Box::pin(async move {
            Ok(match context.action {
                Action::Create => match self.observe(context).await? {
                    Observation::Present { runtime_id, observed, retained_data, cost, .. } => {
                        Recovery::Applied(Receipt { runtime_id: Some(runtime_id), observed, retained_data, cost, at: now(), adopted: true })
                    }
                    Observation::Unknown { reason } => Recovery::Unknown { reason },
                    Observation::Absent => Recovery::NotApplied,
                },
                _ => super::handler::recovery_from(context, self.observe(context).await?),
            })
        })
    }
}

#[cfg(test)]
mod workshop {
    //! Workshop Lab's reset: one named participant's workspace is made again from scratch, and
    //! nobody else's. Everything runs against the grid products in memory.
    use super::*;
    use crate::setups::{
        handler::{Handlers, Peer},
        journal::OperationState,
        model::{new_id, InstanceChange, Source},
        service::{DeclaredResource, PlanIntent, ReviewedPlan, Service, SetupDraft},
    };
    use std::{collections::BTreeMap, path::PathBuf};
    use yougori_setup::dto;

    struct Bench {
        _root: tempfile::TempDir,
        setups: PathBuf,
        data: PathBuf,
        grids: Arc<fake::FakeGrids>,
    }

    impl Bench {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let data = root.path().join("data");
            std::fs::create_dir_all(&data).unwrap();
            Self { setups: data.join("setups"), data, _root: root, grids: Default::default() }
        }

        fn service(&self) -> Arc<Service> {
            let mut handlers = Handlers::default();
            for each in Grids::new(self.grids.clone()).handlers() {
                handlers.register(each);
            }
            Arc::new(Service::open(&self.setups, &self.data, handlers))
        }

        fn state(&self) -> std::sync::MutexGuard<'_, fake::State> {
            self.grids.state.lock().unwrap()
        }

        /// The workspaces the grid holds, as (name, person id).
        fn desks(&self) -> Vec<(String, String)> {
            self.state()
                .desks
                .iter()
                .map(|desk| (desk["name"].as_str().unwrap_or_default().to_owned(), desk["personId"].as_str().unwrap_or_default().to_owned()))
                .collect()
        }

        fn called(&self, method: &str) -> usize {
            self.state().calls.iter().filter(|call| *call == method).count()
        }
    }

    fn change() -> InstanceChange {
        InstanceChange {
            name: "Workshop".into(),
            source: Source { reference: dto::SourceRef::Hub { publisher: "example".into(), name: "workshop-lab".into(), version: "1.0.0".into() }, digest: "sha256:0000".into() },
            format_version: 2,
            protocol_version: 1,
            lock_digest: None,
            lock: None,
            answers: BTreeMap::new(),
            capabilities: vec!["people.workspaces".into()],
            secret_bindings: BTreeMap::new(),
        }
    }

    fn declared(id: &str, kind: Kind, spec: Value, requires: &[&str]) -> DeclaredResource {
        DeclaredResource { id: id.into(), kind, spec, requires: requires.iter().map(|id| (*id).to_owned()).collect(), owner: None }
    }

    /// The workshop: a Sandbox Grid, this computer's share, a pool of identical workspaces and
    /// two participants, each with their own workspace from that pool and their own round.
    fn workshop(alice: u64, bob: u64) -> Vec<DeclaredResource> {
        let participant = |id: &str, round: u64| {
            declared(
                id,
                Kind::AccessBinding,
                json!({"grid": {"resource": "grid"}, "person": {"username": id}, "workspaces": "individual",
                    "workspace_pool": {"resource": "workspaces"}, "reset": round, "secrets": {"password": format!("apply.{id}_password")}}),
                &["grid", "workspaces"],
            )
        };
        vec![
            declared("grid", Kind::Grid, json!({"profile": "sandbox_grid", "mode": "create", "name": "Workshop", "address": "10.0.0.5", "access": "lan", "secrets": {"join_password": "apply.grid_password"}}), &[]),
            declared("computers", Kind::ComputePool, json!({"grid": {"resource": "grid"}, "source": "this_computer", "availability": "always"}), &["grid"]),
            declared(
                "workspaces",
                Kind::WorkspacePool,
                json!({"compute": {"resource": "computers"}, "runtime": "container", "image": "workshop:1", "resources": {"cpu": 2, "memory_gb": 4, "disk_gb": 20}}),
                &["computers"],
            ),
            participant("alice", alice),
            participant("bob", bob),
        ]
    }

    fn secrets() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("grid_password".to_owned(), "correct horse battery".to_owned()),
            ("alice_password".to_owned(), "alice's long passphrase".to_owned()),
            ("bob_password".to_owned(), "bob's long passphrase".to_owned()),
        ])
    }

    fn state_of(service: &Service, operation: &str) -> OperationState {
        service.snapshot().operations[operation].state
    }

    /// The workshop, set up and running, with both participants' workspaces made.
    async fn running(bench: &Bench) -> (Arc<Service>, String) {
        let service = bench.service();
        let plan = service.plan(PlanIntent::Create(SetupDraft { change: change(), resources: workshop(0, 0) })).unwrap();
        let operation = new_id("op-");
        service.apply(&plan, &operation, secrets()).await.unwrap();
        assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);
        assert_eq!(bench.desks().len(), 2, "each participant has a workspace: {:?}", bench.desks());
        (service, plan.setup_id)
    }

    /// Raises the participants' reset rounds, as the person running the workshop does between
    /// rounds.
    fn reset_plan(service: &Service, setup: &str, alice: u64, bob: u64) -> Result<ReviewedPlan, crate::setups::model::Diagnostic> {
        service.plan(PlanIntent::Update { setup: setup.to_owned(), draft: SetupDraft { change: change(), resources: workshop(alice, bob) } })
    }

    #[tokio::test]
    async fn a_reset_makes_one_participants_workspace_again_and_never_another_s() {
        let bench = Bench::new();
        let (service, setup) = running(&bench).await;
        let before = bench.desks();
        let bob = before.iter().find(|(name, _)| name == "bob").cloned().unwrap();
        let alice_person = before.iter().find(|(name, _)| name == "alice").unwrap().1.clone();

        let plan = reset_plan(&service, &setup, 1, 0).unwrap();
        assert!(plan.notes.iter().any(|note| note.contains("alice's workspace is made again from scratch (round 1)") && note.contains("Everything in it goes")), "{:?}", plan.notes);
        assert!(plan.notes.iter().any(|note| note.contains("Nobody else's workspace is touched")), "{:?}", plan.notes);
        assert_eq!(plan.steps.iter().map(|step| step.resource.as_str()).collect::<Vec<_>>(), vec!["alice"], "only alice's record changes");

        let operation = new_id("op-");
        service.apply(&plan, &operation, secrets()).await.unwrap();
        assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);

        let after = bench.desks();
        assert!(after.contains(&bob), "bob's workspace is untouched: {after:?}");
        assert!(after.contains(&("alice (round 1)".to_owned(), alice_person)), "alice has a fresh workspace: {after:?}");
        assert!(!after.iter().any(|(name, _)| name == "alice"), "her old one is gone with its work: {after:?}");
        assert_eq!(after.len(), 2, "one each, still: {after:?}");
    }

    /// The row's acceptance: a participant's reset can never reach another participant's
    /// workspace, however it is named. Here bob's workspace carries exactly the name alice's
    /// reset is about to make, and it still survives untouched, because only desks the grid says
    /// belong to the person ID this setup recorded are ever removed.
    #[tokio::test]
    async fn one_participant_cannot_reset_another_s_however_it_is_named() {
        let bench = Bench::new();
        let (service, setup) = running(&bench).await;
        let bob_person = {
            let mut state = bench.state();
            let bob = state.desks.iter_mut().find(|desk| desk["name"] == "bob").unwrap();
            bob["name"] = json!("alice (round 1)");
            bob["personId"].as_str().unwrap().to_owned()
        };

        let plan = reset_plan(&service, &setup, 1, 0).unwrap();
        let operation = new_id("op-");
        service.apply(&plan, &operation, secrets()).await.unwrap();
        assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);

        let state = bench.state();
        let bobs = state.desks.iter().filter(|desk| desk["personId"] == bob_person.as_str()).collect::<Vec<_>>();
        assert_eq!(bobs.len(), 1, "bob still has exactly one workspace: {:?}", state.desks);
        assert_eq!(bobs[0]["name"], "alice (round 1)", "and it is the very one he had, untouched");
        assert_eq!(state.desks.len(), 2, "alice's was replaced, bob's was not: {:?}", state.desks);
    }

    #[tokio::test]
    async fn a_round_that_stays_put_resets_nothing_and_a_reset_is_never_done_twice() {
        let bench = Bench::new();
        let (service, setup) = running(&bench).await;
        let plan = reset_plan(&service, &setup, 1, 0).unwrap();
        service.apply(&plan, &new_id("op-"), secrets()).await.unwrap();
        assert_eq!((bench.called("desks_remove"), bench.called("desks_add")), (1, 1));

        // The same round again plans nothing at all: a workshop applied twice destroys nothing.
        let again = reset_plan(&service, &setup, 1, 0).unwrap();
        assert!(again.steps.is_empty(), "{:?}", again.steps);
        assert!(again.notes.iter().all(|note| !note.contains("made again from scratch")), "{:?}", again.notes);
        // Nor does lowering it.
        let lowered = reset_plan(&service, &setup, 0, 0).unwrap_err();
        assert_eq!(lowered.code, "unsupported_here", "{}", lowered.message);

        // A step that runs again after a lost receipt finds the workspace it already made.
        let context = binding_context(&service, &setup, "alice", 1, 0);
        let handler = AccessBindingHandler(Grids::new(bench.grids.clone()));
        handler.apply(&context).await.unwrap();
        assert_eq!((bench.called("desks_remove"), bench.called("desks_add")), (1, 1), "nothing was removed or made a second time");
    }

    /// A step context for one participant, as the engine builds it for an update from `previous`
    /// to `round`.
    fn binding_context(service: &Service, setup: &str, participant: &str, round: u64, previous: u64) -> StepContext {
        let registry = service.snapshot();
        let instance = &registry.instances[setup];
        let record = &instance.resources[participant];
        let mut spec = record.spec.clone();
        spec["reset"] = json!(round);
        let mut recorded = record.spec.clone();
        recorded["reset"] = json!(previous);
        let peers = instance
            .resources
            .values()
            .filter(|resource| resource.id != participant)
            .map(|resource| (resource.id.clone(), Peer { kind: resource.kind, spec: resource.spec.clone(), runtime_id: resource.runtime_id.clone(), owned: true }))
            .collect();
        StepContext {
            setup: setup.into(),
            operation: "op-test".into(),
            step: participant.into(),
            resource: participant.into(),
            kind: Kind::AccessBinding,
            action: Action::Update,
            label: format!("op-test/{participant}/update"),
            created_label: None,
            generation: record.generation,
            spec,
            runtime_id: record.runtime_id.clone(),
            owner: None,
            peers,
            planned: Default::default(),
            cancel: Default::default(),
            secrets: Default::default(),
            started_at: None,
            recorded: Some(recorded),
            consents: Default::default(),
        }
    }

    #[tokio::test]
    async fn a_new_workspace_that_cannot_be_ordered_says_so_plainly_and_a_retry_finishes_it() {
        let bench = Bench::new();
        let (service, setup) = running(&bench).await;
        bench.state().fail_desk_add = Some("Desk capacity reached".into());
        let plan = reset_plan(&service, &setup, 1, 0).unwrap();
        let operation = new_id("op-");
        service.apply(&plan, &operation, secrets()).await.unwrap();
        assert_eq!(state_of(&service, &operation), OperationState::Unknown);
        let error = service.snapshot().operations[&operation].steps[0].error.clone().unwrap();
        assert!(error.message.contains("alice's old workspace was removed, but the new one wasn't ordered"), "{}", error.message);
        assert!(error.message.contains("Desk capacity reached"), "{}", error.message);

        // Settled by looking first, as the engine does with any unknown outcome, and only then
        // retried. The retry orders it, and takes nothing else away.
        service.reconcile(&operation).await.unwrap();
        service.prepare_retry(&operation).unwrap();
        service.run(&operation).await.unwrap();
        assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);
        let desks = bench.desks();
        assert_eq!(desks.len(), 2, "{desks:?}");
        assert!(desks.iter().any(|(name, _)| name == "alice (round 1)") && desks.iter().any(|(name, _)| name == "bob"), "{desks:?}");
    }

    #[tokio::test]
    async fn a_reset_cannot_smuggle_in_another_change_to_a_persons_account() {
        let bench = Bench::new();
        let (service, setup) = running(&bench).await;
        let mut resources = workshop(1, 0);
        let alice = resources.iter_mut().find(|resource| resource.id == "alice").unwrap();
        alice.spec["person"]["display_name"] = json!("Alice Someone Else");
        let refused = service
            .plan(PlanIntent::Update { setup: setup.clone(), draft: SetupDraft { change: change(), resources } })
            .unwrap_err();
        assert_eq!(refused.code, "unsupported_here");
        assert!(refused.message.contains("A person's account is changed on the grid's own tab in My setups"), "{}", refused.message);
        assert_eq!(bench.called("desks_remove"), 0, "nothing was touched");
    }

    #[tokio::test]
    async fn the_pool_the_grid_and_the_accounts_are_never_touched_by_a_reset() {
        let bench = Bench::new();
        let (service, setup) = running(&bench).await;
        let people = bench.state().people.clone();
        let before = bench.state().calls.len();
        let plan = reset_plan(&service, &setup, 2, 0).unwrap();
        service.apply(&plan, &new_id("op-"), secrets()).await.unwrap();
        let state = bench.state();
        assert_eq!(state.people, people, "both accounts and their passwords are as they were");
        let during = &state.calls[before..];
        assert_eq!(during.iter().filter(|call| !["desks_status", "desks_remove", "desks_add"].contains(&call.as_str())).count(), 0, "a reset reads the grid and swaps one workspace, nothing else: {during:?}");
        assert!(state.desk_hub.as_ref().is_some_and(|hub| hub["closing"].is_null()), "the grid is untouched");
        assert_eq!(state.desks.iter().filter(|desk| desk["name"] == "alice (round 2)").count(), 1);
    }

    #[tokio::test]
    async fn a_person_with_no_workspace_of_their_own_cannot_ask_for_a_reset() {
        let bench = Bench::new();
        let service = bench.service();
        let mut resources = workshop(0, 0);
        let alice = resources.iter_mut().find(|resource| resource.id == "alice").unwrap();
        alice.spec["workspace_pool"] = Value::Null;
        alice.spec["reset"] = json!(1);
        let refused = service.plan(PlanIntent::Create(SetupDraft { change: change(), resources })).unwrap_err();
        assert_eq!(refused.code, "invalid_spec", "{}", refused.message);
        assert!(refused.message.contains("name where it comes from with workspace_pool"), "{}", refused.message);
    }
}

#[cfg(test)]
mod removal {
    //! Removing a setup that made a grid pauses the grid for three days, restorable, unless the
    //! person ticks its deletion on the review; then it is deleted at once. A grid the setup
    //! joined, signed in to or adopted is never offered for deletion. Everything runs against the
    //! grid products in memory.
    use super::*;
    use crate::setups::{
        handler::Handlers,
        journal::OperationState,
        model::{new_id, InstanceChange, Lifecycle, Source},
        service::{DeclaredResource, PlanIntent, Service, SetupDraft},
    };
    use std::{collections::BTreeSet, path::PathBuf};
    use yougori_setup::dto;

    /// Each grid profile, with its product's delete call.
    const PRODUCTS: [(&str, &str); 3] = [("neo_grid", "grid_delete"), ("sandbox_grid", "desks_delete"), ("access_grid", "access_delete")];

    struct Bench {
        _root: tempfile::TempDir,
        setups: PathBuf,
        data: PathBuf,
        grids: Arc<fake::FakeGrids>,
    }

    impl Bench {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let data = root.path().join("data");
            std::fs::create_dir_all(&data).unwrap();
            Self { setups: data.join("setups"), data, _root: root, grids: Default::default() }
        }

        fn service(&self) -> Arc<Service> {
            let mut handlers = Handlers::default();
            for each in Grids::new(self.grids.clone()).handlers() {
                handlers.register(each);
            }
            Arc::new(Service::open(&self.setups, &self.data, handlers))
        }

        fn called(&self, method: &str) -> usize {
            self.grids.state.lock().unwrap().calls.iter().filter(|call| *call == method).count()
        }

        /// The hub of `profile` as the product has it now.
        fn hub(&self, profile: &str) -> Value {
            hub_of(&mut self.grids.state.lock().unwrap(), profile).clone().unwrap_or_default()
        }
    }

    /// Where the products in memory keep the hub of `profile`.
    fn hub_of<'a>(state: &'a mut fake::State, profile: &str) -> &'a mut Option<Value> {
        match profile {
            "neo_grid" => &mut state.hub,
            "sandbox_grid" => &mut state.desk_hub,
            _ => &mut state.access_hub,
        }
    }

    /// The products in memory, running a hub `hub-1` of `profile` whose deletion stands at `closing`.
    fn products_with(profile: &str, closing: Value) -> Arc<fake::FakeGrids> {
        let grids = Arc::new(fake::FakeGrids::default());
        *hub_of(&mut grids.state.lock().unwrap(), profile) = Some(json!({"id": "hub-1", "name": "Acme", "company": "Acme", "owner": "ada", "closing": closing, "createdAt": 1}));
        grids
    }

    /// A grid this setup makes, of `profile`.
    fn made(profile: &str) -> Value {
        let mut spec = json!({"profile": profile, "mode": "create", "name": "Acme", "address": "10.0.0.5", "access": "lan"});
        if profile != "access_grid" {
            spec["secrets"] = json!({"join_password": "apply.grid_password"});
        }
        spec
    }

    /// A setup whose one part is a grid it made, set up and running.
    async fn running(bench: &Bench, profile: &str) -> (Arc<Service>, String) {
        let service = bench.service();
        let change = InstanceChange {
            name: "Acme".into(),
            source: Source { reference: dto::SourceRef::Hub { publisher: "example".into(), name: "company-grid".into(), version: "1.0.0".into() }, digest: "sha256:0000".into() },
            format_version: 2,
            protocol_version: 1,
            lock_digest: None,
            lock: None,
            answers: BTreeMap::new(),
            capabilities: vec!["run.health_logs".into()],
            secret_bindings: BTreeMap::new(),
        };
        let grid = DeclaredResource { id: "company".into(), kind: Kind::Grid, spec: made(profile), requires: Vec::new(), owner: None };
        let plan = service.plan(PlanIntent::Create(SetupDraft { change, resources: vec![grid] })).unwrap();
        let operation = new_id("op-");
        service.apply(&plan, &operation, BTreeMap::from([("grid_password".to_owned(), "correct horse battery".to_owned())])).await.unwrap();
        assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);
        (service, plan.setup_id)
    }

    fn state_of(service: &Service, operation: &str) -> OperationState {
        service.snapshot().operations[operation].state
    }

    /// What the person ticked on the review: deleting the grid `company` now.
    fn ticked() -> BTreeSet<String> {
        BTreeSet::from([delete_grid_consent("company")])
    }

    /// The step that removes the grid `spec` describes, recorded as `runtime_id`, with what the
    /// person ticked on the review.
    fn removing(spec: Value, runtime_id: &str, tick: &[&str]) -> StepContext {
        StepContext {
            setup: "setup-acme".into(),
            operation: "op-test".into(),
            step: "company".into(),
            resource: "company".into(),
            kind: Kind::Grid,
            action: Action::Remove,
            label: "op-test/company/remove".into(),
            created_label: None,
            generation: 1,
            spec,
            runtime_id: Some(runtime_id.into()),
            owner: None,
            peers: Default::default(),
            planned: Default::default(),
            cancel: Default::default(),
            secrets: Default::default(),
            started_at: None,
            recorded: None,
            consents: Arc::new(tick.iter().map(|id| (*id).to_owned()).collect()),
        }
    }

    #[tokio::test]
    async fn removing_the_setup_pauses_a_grid_it_made_for_three_days_unless_its_deletion_is_ticked() {
        let bench = Bench::new();
        let (service, setup) = running(&bench, "neo_grid").await;
        let remove = service.plan(PlanIntent::Remove { setup: setup.clone() }).unwrap();
        let offered = remove.offered.iter().map(|offer| offer["id"].clone()).collect::<Vec<_>>();
        assert_eq!(offered, [json!("delete_grid:company")], "offered, and never ticked for the person");
        let note = remove.notes.iter().find(|note| note.starts_with("Removing pauses the Neo Grid Acme for three days, until")).unwrap_or_else(|| panic!("{:?}", remove.notes));
        assert!(note.contains("Restore it before then from My setups.") && note.ends_with("To delete it now instead, tick its deletion below."), "{note}");

        let operation = new_id("op-");
        service.apply(&remove, &operation, BTreeMap::new()).await.unwrap();
        assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);
        assert_eq!(bench.called("grid_delete"), 1);
        assert_eq!(bench.hub("neo_grid")["closing"], json!({"when": "later", "gone": false}), "paused for three days, restorable");
        assert_eq!(service.snapshot().instances[&setup].lifecycle, Lifecycle::Retained, "the paused grid stays the setup's");
    }

    #[tokio::test]
    async fn a_ticked_deletion_deletes_the_grid_the_setup_made_at_once() {
        for (profile, delete) in [("neo_grid", "grid_delete"), ("sandbox_grid", "desks_delete")] {
            let bench = Bench::new();
            let (service, setup) = running(&bench, profile).await;
            let remove = service.plan(PlanIntent::Remove { setup: setup.clone() }).unwrap();
            let operation = new_id("op-");
            service.submit_agreed(&remove, &operation, remove.base_revision, BTreeMap::new(), ticked()).unwrap();
            service.run(&operation).await.unwrap();
            assert_eq!(state_of(&service, &operation), OperationState::Completed, "{profile}: {:?}", service.operation(&operation, 0).unwrap().error);
            assert_eq!(bench.called(delete), 1, "{profile}");
            assert_eq!(bench.hub(profile)["closing"], json!({"when": "now", "gone": true}), "{profile}: deleted at once, not paused");
            assert!(!service.snapshot().instances.contains_key(&setup), "{profile}: nothing of it is kept, so the setup goes too");
        }
    }

    #[tokio::test]
    async fn removing_the_grid_on_its_own_offers_its_deletion_the_same_way() {
        let bench = Bench::new();
        let (service, setup) = running(&bench, "neo_grid").await;
        let part = service.plan(PlanIntent::Part { setup, resource: "company".into(), action: Action::Remove }).unwrap();
        assert_eq!(part.offered.iter().map(|offer| offer["id"].clone()).collect::<Vec<_>>(), [json!("delete_grid:company")]);
        assert!(part.notes.iter().any(|note| note.ends_with("To delete it now instead, tick its deletion below.")), "{:?}", part.notes);
        let operation = new_id("op-");
        service.submit_agreed(&part, &operation, part.base_revision, BTreeMap::new(), ticked()).unwrap();
        service.run(&operation).await.unwrap();
        assert_eq!(state_of(&service, &operation), OperationState::Completed, "{:?}", service.operation(&operation, 0).unwrap().error);
        assert_eq!(bench.called("grid_delete"), 1);
        assert_eq!(bench.hub("neo_grid")["closing"]["when"], "now");
    }

    #[tokio::test]
    async fn each_grid_is_paused_by_default_and_deleted_now_only_with_its_own_tick() {
        for (profile, delete) in PRODUCTS {
            for (tick, when) in [(&[][..], "later"), (&["delete_grid:another"][..], "later"), (&["delete_grid:company"][..], "now")] {
                let grids = products_with(profile, Value::Null);
                let outcome = GridHandler(Grids::new(grids.clone())).remove(&removing(made(profile), "hub-1", tick)).await.unwrap();
                let mut state = grids.state.lock().unwrap();
                assert_eq!(state.calls.iter().filter(|call| *call == delete).count(), 1, "{profile} {tick:?}");
                assert_eq!(hub_of(&mut state, profile).as_ref().unwrap()["closing"]["when"], when, "{profile} {tick:?}");
                assert_eq!(outcome.retained_data, when == "later", "{profile}: a paused grid is kept to restore, a deleted one is not");
            }
        }
    }

    #[tokio::test]
    async fn a_paused_grid_is_deleted_now_with_the_tick_and_one_deleted_already_is_left_as_it_is() {
        for (profile, delete) in PRODUCTS {
            let grids = products_with(profile, json!({"until": 1, "gone": false}));
            let handler = GridHandler(Grids::new(grids.clone()));
            let context = removing(made(profile), "hub-1", &["delete_grid:company"]);
            handler.remove(&context).await.unwrap();
            // Run again, as a retry does: it is deleted already, so nothing is asked twice.
            let again = handler.remove(&context).await.unwrap();
            let mut state = grids.state.lock().unwrap();
            assert_eq!(state.calls.iter().filter(|call| *call == delete).count(), 1, "{profile}");
            assert_eq!(hub_of(&mut state, profile).as_ref().unwrap()["closing"]["when"], "now", "{profile}: the pause became a deletion");
            assert_eq!((again.observed, again.retained_data), (Observed::Missing, false), "{profile}");
        }
    }

    #[tokio::test]
    async fn a_joined_grid_a_sign_in_and_an_adopted_grid_are_never_offered_for_deletion() {
        let joined = json!({"profile": "neo_grid", "mode": "join", "member": "computer", "secrets": {"invitation": "apply.invite", "join_password": "apply.join_password"}});
        let signed_in = json!({"profile": "sandbox_grid", "mode": "join", "member": "person", "username": "ada", "secrets": {"invitation": "apply.invite", "password": "apply.password"}});
        let adopted = json!({"profile": "neo_grid", "mode": "create", "adopted": true});
        let handler = GridHandler(Grids::new(Arc::new(fake::FakeGrids::default())));
        for spec in [&joined, &signed_in, &adopted] {
            assert!(handler.removal_offers("setup-acme", "company", spec).is_empty(), "{spec}");
            assert!(handler.notes("setup-acme", "company", spec, Action::Remove).iter().all(|note| !note.contains("tick")), "{spec}");
        }

        // A tick that reached the step some other way deletes none of them either: each is left,
        // signed out of or paused, as it would be without it.
        let tick = ["delete_grid:company"];
        let grids = Arc::new(fake::FakeGrids::default());
        grids.state.lock().unwrap().member = Some(json!({"memberId": "member-1", "connected": true, "joinedAt": 1}));
        GridHandler(Grids::new(grids.clone())).remove(&removing(joined, "member-1", &tick)).await.unwrap();
        assert_eq!(grids.state.lock().unwrap().calls, ["grid_status", "grid_leave"]);

        let grids = Arc::new(fake::FakeGrids::default());
        grids.state.lock().unwrap().signed_in = Some("ada".into());
        GridHandler(Grids::new(grids.clone())).remove(&removing(signed_in, "ada", &tick)).await.unwrap();
        assert_eq!(grids.state.lock().unwrap().calls, ["desks_status", "desk_logout"]);

        let grids = products_with("neo_grid", Value::Null);
        GridHandler(Grids::new(grids.clone())).remove(&removing(adopted, "hub-1", &tick)).await.unwrap();
        assert_eq!(grids.state.lock().unwrap().hub.as_ref().unwrap()["closing"]["when"], "later", "an adopted grid is only ever paused");
    }

    #[test]
    fn the_offer_names_what_goes_and_that_it_cannot_be_undone() {
        let handler = GridHandler(Grids::new(Arc::new(fake::FakeGrids::default())));
        for (profile, goes) in [
            ("neo_grid", ["Also delete the Neo Grid Acme now", "its model plans, teams and API keys go with it", "removes the model the grid installed", "the grid's keys and company password are removed from this computer"]),
            ("sandbox_grid", ["Also delete the Sandbox Grid Acme now", "its people's accounts go with it", "this one included, deletes them with their data", "the grid's keys and company password are removed from this computer"]),
            ("access_grid", ["Also delete the Access Grid Acme now", "people, rules and stored credentials are wiped at once", "everyone is signed out", "for 30 days, then removes itself"]),
        ] {
            let offers = handler.removal_offers("setup-acme", "company", &made(profile));
            assert_eq!(offers.len(), 1, "{profile}");
            assert_eq!(offers[0]["id"], "delete_grid:company");
            let message = offers[0]["message"].as_str().unwrap_or_default();
            assert!(goes.iter().all(|what| message.contains(what)) && message.ends_with("This can't be undone."), "{profile}: {message}");
        }
    }
}

#[cfg(test)]
mod rented {
    //! Releasing rented compute: only the NeoCloud GPUs in the Neo Grid this setup made, never a
    //! pod outside it, stopped through the product's own stop for that grid. Everything runs
    //! against the products in memory; nothing calls NeoCloud.
    use super::*;

    fn neo(spec: Value) -> StepContext {
        StepContext {
            setup: "setup-acme".into(),
            operation: String::new(),
            step: "company".into(),
            resource: "company".into(),
            kind: Kind::Grid,
            action: Action::Update,
            label: String::new(),
            created_label: None,
            generation: 1,
            spec,
            runtime_id: Some("hub-1".into()),
            owner: None,
            peers: Default::default(),
            planned: Default::default(),
            cancel: Default::default(),
            secrets: Default::default(),
            started_at: None,
            recorded: None,
            consents: Default::default(),
        }
    }

    fn made() -> Value {
        json!({"profile": "neo_grid", "mode": "create", "name": "Acme", "address": "10.0.0.5", "access": "lan", "secrets": {"join_password": "apply.grid_password"}})
    }

    fn pod(id: &str, grid: &str, state: &str) -> Value {
        json!({"environmentId": id, "gridId": grid, "name": format!("{id}-gpu"), "gpu": "RTX 4090", "gpuCount": 1, "hourlyUsd": 0.69, "podState": state})
    }

    /// The products in memory running the Neo Grid hub `hub-1`, with these rented GPUs.
    fn products(pods: Vec<Value>) -> Arc<fake::FakeGrids> {
        let grids = Arc::new(fake::FakeGrids::default());
        {
            let mut state = grids.state.lock().unwrap();
            state.hub = Some(json!({"id": "hub-1", "name": "Acme", "closing": null, "createdAt": 1}));
            state.pods = pods;
        }
        grids
    }

    fn stops(grids: &fake::FakeGrids) -> usize {
        grids.state.lock().unwrap().calls.iter().filter(|call| *call == "grid_neocloud_stop_all").count()
    }

    #[tokio::test]
    async fn only_the_rented_gpus_in_this_setups_own_neo_grid_are_listed_and_stopped() {
        let grids = products(vec![pod("ours", "hub-1", "Running"), pod("idle", "hub-1", "Exited"), pod("theirs", "grid-elsewhere", "Running")]);
        let handler = GridHandler(Grids::new(grids.clone()));
        let rented = handler.rented(&neo(made())).await.unwrap().unwrap();
        let ids = rented["computers"].as_array().unwrap().iter().map(|computer| computer["id"].clone()).collect::<Vec<_>>();
        assert_eq!(ids, [json!("ours")], "one already stopped bills nothing, and one outside the grid is never offered");
        let notes = rented["notes"].to_string();
        assert!(notes.contains("GPU charges stop once NeoCloud confirms each pod") && notes.contains("disks may still cost storage"), "{notes}");
        assert_eq!(stops(&grids), 0, "listing stops nothing");

        let released = handler.release(&neo(made())).await.unwrap();
        assert_eq!(released["confirmed"], true, "{released}");
        assert_eq!(stops(&grids), 1);
        let state = grids.state.lock().unwrap();
        let of = |id: &str| state.pods.iter().find(|pod| pod["environmentId"] == id).unwrap()["podState"].clone();
        assert_eq!(of("ours"), "Exited");
        assert_eq!(of("theirs"), "Running", "a pod outside the grid is never stopped");
    }

    #[tokio::test]
    async fn a_stop_neocloud_has_not_confirmed_is_named_and_never_called_stopped() {
        let grids = products(vec![pod("ours", "hub-1", "Running")]);
        grids.state.lock().unwrap().stop_pending = true;
        let handler = GridHandler(Grids::new(grids.clone()));
        let released = handler.release(&neo(made())).await.unwrap();
        assert_eq!(released["confirmed"], false, "{released}");
        assert_eq!(released["unconfirmed"], json!(["ours-gpu"]));
        // Still shown stopping, so it is still offered: the release can be reviewed and applied again.
        assert!(handler.rented(&neo(made())).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn no_other_grid_holds_rented_compute_to_release() {
        let joined = json!({"profile": "neo_grid", "mode": "join", "member": "computer", "secrets": {"invitation": "apply.invite", "join_password": "apply.join_password"}});
        let adopted = json!({"profile": "neo_grid", "mode": "create", "adopted": true});
        let desks = json!({"profile": "sandbox_grid", "mode": "create", "name": "Acme", "address": "10.0.0.5", "access": "lan", "secrets": {"join_password": "apply.grid_password"}});
        for spec in [joined, adopted, desks] {
            let grids = products(vec![pod("ours", "hub-1", "Running")]);
            let handler = GridHandler(Grids::new(grids.clone()));
            assert!(handler.rented(&neo(spec.clone())).await.unwrap().is_none(), "{spec}");
            assert_eq!(handler.release(&neo(spec.clone())).await.unwrap_err().code, "unsupported_here", "{spec}");
            assert!(grids.state.lock().unwrap().calls.is_empty(), "nothing was even asked: {spec}");
        }
    }
}

#[cfg(test)]
mod messages {
    #[test]
    fn product_command_hints_stay_out_of_setup_messages() {
        assert_eq!(super::plain("The grid is paused. Run yougori grid resume --yes to restore it."), "The grid is paused.");
        assert_eq!(super::plain("The grid is paused. Use `yougori grid resume` to restore it."), "The grid is paused.");
        assert_eq!(super::plain("No space left on device."), "No space left on device.");
    }
}

#[cfg(test)]
pub(crate) mod fake {
    //! The grid products in memory, for tests. They behave as the products do where it matters
    //! to a setup: each keeps each grid in an instance of its own (the first, `default`, in the
    //! fields below; later ones in `neo_later`, `desks_later` and `access_later`), answers about the
    //! instance a call names (`gridId`: its key, its hub's ID, or the grid a membership is for), a
    //! join or sign-in to a grid already here goes back to that instance and quietly replaces what
    //! is there, `access_manage` acts as whoever is signed in, and refusals use the products'
    //! exact words.
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    pub(crate) struct State {
        pub hub: Option<Value>,
        pub member: Option<Value>,
        pub plans: Vec<Value>,
        pub harnesses: Vec<Value>,
        pub calls: Vec<String>,
        pub desk_hub: Option<Value>,
        pub desk_member: Option<Value>,
        pub people: Vec<Value>,
        pub desks: Vec<Value>,
        pub share: Option<Value>,
        pub signed_in: Option<String>,
        pub access_hub: Option<Value>,
        pub access_people: Vec<Value>,
        pub credentials: Vec<Value>,
        pub rules: Vec<Value>,
        pub two_step: bool,
        /// Each grid's company sign-in, as its product holds it: the Access Grid's, the Sandbox Grid's.
        pub access_sso: Option<Value>,
        pub desk_sso: Option<Value>,
        /// The computers a Sandbox Grid is told to use only, its own cloud's settings, and whether
        /// it requires two-step sign-in of everyone.
        pub desk_only: Option<Value>,
        pub desk_two_step: bool,
        pub desk_cloud: Option<Value>,
        /// What `keep` kept, in place of this computer's credential vault.
        pub vault: BTreeMap<String, String>,
        pub access_member: Option<String>,
        /// `access_manage` calls that would have gone to another grid as the signed-in person.
        pub remote_manage: u32,
        /// The next `ruleAdd` fails.
        pub fail_rule: bool,
        /// The next `desks_add` fails with this.
        pub fail_desk_add: Option<String>,
        /// Rented NeoCloud GPUs, each with the grid it works in (`gridId`).
        pub pods: Vec<Value>,
        /// The next stop is sent but NeoCloud can't read the pods back yet: they show "Stopping".
        pub stop_pending: bool,
        /// Whether a RunPod account is connected, and the pods rented through NeoCloud (not yet
        /// in a grid), by environment ID: `{name, gpuId, maxHourlyUsd, podState}`.
        pub runpod_connected: bool,
        pub rented: BTreeMap<String, Value>,
        /// How many times NeoCloud says a new pod is still starting before it can join.
        pub pod_starts: u32,
        /// Swarm Mining, as its closed review keeps it: the review this computer hosts (its status
        /// view), what `hostSource` was asked, the folders taken in, the policy of a review
        /// someone else hosts (what `connect` finds), the open connections by ticket, what each
        /// `startWorker` was asked, and the workers.
        pub bounty: Option<Value>,
        pub hosted_with: Option<Value>,
        pub inspected: Vec<String>,
        pub remote_policy: Option<Value>,
        pub tickets: BTreeMap<String, Value>,
        pub started_with: Vec<Value>,
        pub workers: Vec<Value>,
        /// The Sandbox Grid this computer is signed in to (`signed_in`), by name.
        pub signed_in_grid: Option<String>,
        /// The Access Grid this computer is signed in to (`access_member`): `{company, fingerprint}`.
        pub access_member_grid: Option<Value>,
        /// Each product's later instances by key (`i-` and eight hex digits): a state of its own,
        /// of which only that product's fields are used.
        pub neo_later: BTreeMap<String, State>,
        pub desks_later: BTreeMap<String, State>,
        pub access_later: BTreeMap<String, State>,
        next: u32,
    }

    #[derive(Default)]
    pub(crate) struct FakeGrids {
        pub state: Mutex<State>,
    }

    fn at() -> i64 {
        chrono::Utc::now().timestamp()
    }

    /// One of the grid products.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Family {
        Neo,
        Desks,
        Access,
    }

    impl Family {
        /// The product a call is for. Rented GPUs are this computer's, not one grid's.
        fn of(method: &str) -> Option<Family> {
            if method.starts_with("grid_neocloud_") {
                None
            } else if method.starts_with("grid_") {
                Some(Family::Neo)
            } else if method.starts_with("desks_") || method.starts_with("desk_") {
                Some(Family::Desks)
            } else if method.starts_with("access_") {
                Some(Family::Access)
            } else {
                None
            }
        }

        fn status(self) -> &'static str {
            match self {
                Family::Neo => "grid_status",
                Family::Desks => "desks_status",
                Family::Access => "access_status",
            }
        }

        fn name(self) -> &'static str {
            match self {
                Family::Neo => "Neo Grid",
                Family::Desks => "Sandbox Grid",
                Family::Access => "Access Grid",
            }
        }
    }

    /// What an invitation says, as the products read it: its grid's company name and fingerprint.
    /// A text that isn't one stands for itself, so a test can use a short one.
    fn invited(text: &str) -> (String, String) {
        use yougori_grid::invite::{decode, decode_access, decode_desk};
        decode(text)
            .or_else(|_| decode_desk(text))
            .or_else(|_| decode_access(text))
            .map(|invite| (invite.company, invite.fingerprint))
            .unwrap_or_else(|_| ("Grid".to_owned(), text.to_owned()))
    }

    /// One instance of a product, as its status shows it.
    fn view(family: Family, state: &State, key: &str) -> Value {
        match family {
            Family::Neo => {
                let hub = state.hub.clone().map(|mut hub| {
                    hub["plans"] = json!(state.plans);
                    hub["harnesses"] = json!(state.harnesses);
                    hub["instance"] = json!(key);
                    hub["gridId"] = hub["id"].clone();
                    hub
                });
                let member = state.member.clone().map(|mut member| {
                    member["instance"] = json!(key);
                    member
                });
                json!({"hub": hub, "member": member})
            }
            Family::Desks => {
                let hub = state.desk_hub.clone().map(|mut hub| {
                    hub["people"] = json!(state.people);
                    hub["desks"] = json!(state.desks);
                    hub["instance"] = json!(key);
                    hub["gridId"] = hub["id"].clone();
                    hub
                });
                let member = state.desk_member.clone().map(|mut member| {
                    member["instance"] = json!(key);
                    member
                });
                let desk = state.signed_in.as_ref().map(|name| json!({"username": name, "signedInAt": at(), "grid": state.signed_in_grid, "instance": key}));
                json!({"hub": hub, "member": member, "desk": desk})
            }
            Family::Access => {
                let hub = state.access_hub.clone().map(|mut hub| {
                    hub["instance"] = json!(key);
                    hub["gridId"] = hub["id"].clone();
                    hub
                });
                let member = state.access_member.as_ref().map(|name| {
                    let mut member = json!({"username": name, "signedInAt": at(), "instance": key});
                    if let Some(grid) = &state.access_member_grid {
                        member["company"] = grid["company"].clone();
                        member["fingerprint"] = grid["fingerprint"].clone();
                    }
                    member
                });
                json!({"hub": hub, "member": member})
            }
        }
    }

    impl State {
        fn later(&self, family: Family) -> &BTreeMap<String, State> {
            match family {
                Family::Neo => &self.neo_later,
                Family::Desks => &self.desks_later,
                Family::Access => &self.access_later,
            }
        }

        fn later_mut(&mut self, family: Family) -> &mut BTreeMap<String, State> {
            match family {
                Family::Neo => &mut self.neo_later,
                Family::Desks => &mut self.desks_later,
                Family::Access => &mut self.access_later,
            }
        }

        /// Every instance of a product here, the first first.
        fn keys(&self, family: Family) -> Vec<String> {
            std::iter::once(FIRST.to_owned()).chain(self.later(family).keys().cloned()).collect()
        }

        fn instance(&self, family: Family, key: &str) -> &State {
            if key == FIRST {
                self
            } else {
                &self.later(family)[key]
            }
        }

        fn at(&mut self, family: Family, key: &str) -> &mut State {
            if key == FIRST {
                self
            } else {
                self.later_mut(family).entry(key.to_owned()).or_default()
            }
        }

        /// Whether this instance holds anything of a product: its hub, a membership or a sign-in.
        fn holds(&self, family: Family) -> bool {
            match family {
                Family::Neo => self.hub.is_some() || self.member.is_some(),
                Family::Desks => self.desk_hub.is_some() || self.desk_member.is_some() || self.signed_in.is_some(),
                Family::Access => self.access_hub.is_some() || self.access_member.is_some(),
            }
        }

        /// The instance `grid` names: its key, its hub's ID, or the grid its membership is for.
        fn resolve(&self, family: Family, grid: &str) -> Option<String> {
            self.keys(family).into_iter().find(|key| {
                let view = view(family, self.instance(family, key), key);
                key == grid || ["hub", "member", "desk"].iter().any(|field| view[*field]["id"] == grid || view[*field]["gridId"] == grid)
            })
        }

        /// The first instance when it holds nothing of this kind, else a new one.
        fn free(&mut self, family: Family, next: u32, taken: impl Fn(&State) -> bool) -> String {
            if !taken(self) {
                return FIRST.to_owned();
            }
            let key = format!("i-{next:08x}");
            self.later_mut(family).insert(key.clone(), State::default());
            key
        }

        /// The instance a call is about, as the products choose it: the one `gridId` names; for a
        /// new grid, the first when it is free, else a new one; for a join or sign-in, the one that
        /// already has that grid, else likewise. Any other call with several instances here and no
        /// `gridId` is refused, as the products refuse it.
        fn instance_for(&mut self, family: Family, method: &str, params: &Value, next: u32) -> Result<String, String> {
            if let Some(grid) = params["gridId"].as_str() {
                return self.resolve(family, grid).ok_or_else(|| format!("No {} on this computer has the ID {grid}.", family.name()));
            }
            let (company, fingerprint) = invited(params["invite"].as_str().unwrap_or_default());
            let known = |state: &State, key: &str| -> bool {
                let state = state.instance(family, key);
                match method {
                    "grid_join" => state.member.as_ref().is_some_and(|member| member["fingerprint"] == fingerprint.as_str()),
                    "desks_join" => state.desk_member.as_ref().is_some_and(|member| member["fingerprint"] == fingerprint.as_str()),
                    "desk_login" => state.signed_in_grid.as_deref() == Some(company.as_str()),
                    "access_signin" => state.access_member_grid.as_ref().is_some_and(|grid| grid["fingerprint"] == fingerprint.as_str()),
                    _ => false,
                }
            };
            match method {
                "grid_create" | "desks_create" | "access_create" => Ok(self.free(family, next, |state| state.holds(family))),
                "grid_join" | "desks_join" | "access_signin" => match self.keys(family).into_iter().find(|key| known(self, key)) {
                    Some(key) => Ok(key),
                    None => Ok(self.free(family, next, |state| state.holds(family))),
                },
                "desk_login" => match self.keys(family).into_iter().find(|key| known(self, key)) {
                    Some(key) => Ok(key),
                    None => Ok(self.free(family, next, |state| state.signed_in.is_some())),
                },
                _ if self.later(family).is_empty() => Ok(FIRST.to_owned()),
                _ => Err(format!("There are {} {}s on this computer. Say which with gridId.", self.later(family).len() + 1, family.name())),
            }
        }

        /// A product's status, as the products answer it: the instance `grid` names, else the
        /// first, in the single fields; every instance in the lists.
        fn status(&self, family: Family, grid: Option<&str>) -> Result<Value, String> {
            let key = match grid {
                Some(grid) => self.resolve(family, grid).ok_or_else(|| format!("No {} on this computer has the ID {grid}.", family.name()))?,
                None => FIRST.to_owned(),
            };
            let views = self.keys(family).into_iter().map(|key| (view(family, self.instance(family, &key), &key), key)).collect::<Vec<_>>();
            let mut status = views.iter().find(|(_, found)| *found == key).map(|(view, _)| view.clone()).unwrap_or_else(|| json!({}));
            let listed = |field: &str| views.iter().map(|(view, _)| view[field].clone()).filter(Value::is_object).collect::<Vec<_>>();
            status["instance"] = json!(key);
            status["hubs"] = json!(listed("hub"));
            status["members"] = json!(listed("member"));
            status["logins"] = json!(listed("desk"));
            Ok(status)
        }
    }

    impl GridCalls for FakeGrids {
        fn keep(&self, name: &str, value: &str) -> Result<(), String> {
            self.state.lock().unwrap().vault.insert(name.to_owned(), value.to_owned());
            Ok(())
        }
        fn kept(&self, name: &str) -> Result<Option<String>, String> {
            Ok(self.state.lock().unwrap().vault.get(name).cloned())
        }
        fn forget(&self, name: &str) -> Result<(), String> {
            self.state.lock().unwrap().vault.remove(name);
            Ok(())
        }
        fn call<'a>(&'a self, method: &'a str, params: Value) -> BoxFuture<'a, Result<Value, String>> {
            Box::pin(async move {
                let mut guard = self.state.lock().unwrap();
                guard.calls.push(method.to_owned());
                guard.next += 1;
                let next = guard.next;
                let Some(family) = Family::of(method) else { return act(&mut guard, method, params, next) };
                if method == family.status() {
                    return guard.status(family, params["gridId"].as_str());
                }
                let key = guard.instance_for(family, method, &params, next)?;
                let mut answer = act(guard.at(family, &key), method, params, next)?;
                // As the products: an answer says which instance it is about.
                if let Some(answer) = answer.as_object_mut() {
                    answer.insert("instance".into(), json!(key));
                    for field in ["hub", "member"] {
                        if let Some(part) = answer.get_mut(field).and_then(Value::as_object_mut) {
                            part.insert("instance".into(), json!(key));
                        }
                    }
                }
                Ok(answer)
            })
        }
    }

    /// One call, in the one instance it is about.
    fn act(state: &mut State, method: &str, params: Value, next: u32) -> Result<Value, String> {
                let status = |state: &State| {
                    let mut hub = state.hub.clone();
                    if let Some(hub) = hub.as_mut() {
                        hub["plans"] = json!(state.plans);
                        hub["harnesses"] = json!(state.harnesses);
                    }
                    json!({"hub": hub, "member": state.member})
                };
                let desks = |state: &State| {
                    let mut hub = state.desk_hub.clone();
                    if let Some(hub) = hub.as_mut() {
                        hub["people"] = json!(state.people);
                        hub["desks"] = json!(state.desks);
                    }
                    json!({"hub": hub, "member": state.desk_member, "desk": state.signed_in.as_ref().map(|name| json!({"username": name, "signedInAt": at()}))})
                };
                match method {
                    "access_status" => Ok(view(Family::Access, state, FIRST)),
                    "access_create" => {
                        if state.access_hub.is_some() {
                            return Err("This computer already runs an Access Grid".into());
                        }
                        // As the product's policy: usernames are kept in lower case.
                        let owner = params["username"].as_str().unwrap_or_default().to_ascii_lowercase();
                        // As the product's status: where people reach it, and its invite.
                        state.access_hub = Some(json!({"id": format!("access-{next}"), "company": params["company"], "owner": owner, "closing": null, "createdAt": at(),
                            "address": params["address"], "port": 7465, "invite": format!("access-invite:fake-{next}")}));
                        state.access_people.push(json!({"id": format!("person-{next}"), "username": owner, "createdAt": at()}));
                        Ok(json!({"hub": state.access_hub}))
                    }
                    "access_delete" => {
                        let hub = state.access_hub.as_mut().ok_or("This computer does not run an Access Grid")?;
                        // As the product: `later` pauses it, `now` deletes it for good.
                        hub["closing"] = json!({"when": params["when"], "gone": params["when"] == "now"});
                        Ok(json!({}))
                    }
                    "access_signin" => {
                        let (company, fingerprint) = invited(params["invite"].as_str().unwrap_or_default());
                        state.access_member = params["username"].as_str().map(str::to_owned);
                        state.access_member_grid = Some(json!({"company": company, "fingerprint": fingerprint}));
                        Ok(json!({}))
                    }
                    "access_signout" => {
                        state.access_member = None;
                        state.access_member_grid = None;
                        Ok(json!({}))
                    }
                    "access_manage" => {
                        // As the product: the owner acts on the hub here only when it is open and
                        // nobody else is signed in; otherwise the call goes to the signed-in grid.
                        let owner = state.access_hub.as_ref().filter(|hub| hub["closing"].is_null()).and_then(|hub| hub["owner"].as_str().map(str::to_owned));
                        let local = owner.is_some_and(|owner| state.access_member.as_deref().is_none_or(|member| member == owner));
                        if !local {
                            state.remote_manage += 1;
                            return Err("Sign in to an Access Grid first".into());
                        }
                        let request = &params["request"];
                        let find = |list: &[Value], key: &str, wanted: &Value| list.iter().position(|item| item["id"] == *wanted || item[key] == *wanted);
                        match request["action"].as_str().unwrap_or_default() {
                            "overview" => Ok(json!({"people": state.access_people, "credentials": state.credentials, "rules": state.rules})),
                            "personAdd" => {
                                let username = request["username"].as_str().unwrap_or_default().to_ascii_lowercase();
                                if state.access_people.iter().any(|person| person["username"] == username.as_str()) {
                                    return Err("A person with that username already exists".into());
                                }
                                let id = format!("person-{next}");
                                state.access_people.push(json!({"id": id, "username": username, "permission": request["permission"].as_str().unwrap_or("member"), "password": request["password"], "createdAt": at()}));
                                Ok(json!({"personId": id}))
                            }
                            "personRemove" => {
                                let index = find(&state.access_people, "username", &request["person"]).ok_or("No such person")?;
                                state.access_people.remove(index);
                                Ok(json!({}))
                            }
                            "settingsSet" => {
                                state.two_step = request["requireTwoStep"].as_bool().unwrap_or(false);
                                Ok(json!({}))
                            }
                            "personUpdate" => {
                                let index = find(&state.access_people, "username", &request["person"]).ok_or("No such person")?;
                                if let Some(permission) = request["permission"].as_str() {
                                    if !["member", "approver", "auditor", "admin"].contains(&permission) {
                                        return Err(format!("'{permission}' is not a permission; use member, approver, auditor or admin"));
                                    }
                                    state.access_people[index]["permission"] = json!(permission);
                                }
                                Ok(json!({"personId": state.access_people[index]["id"]}))
                            }
                            "ssoSet" => {
                                if request["clientId"].as_str().unwrap_or_default().is_empty() {
                                    return Err("Give the client ID of the app registered at the provider".into());
                                }
                                state.access_sso = Some(request.clone());
                                Ok(json!({"sso": request}))
                            }
                            "ssoClear" => {
                                state.access_sso = None;
                                Ok(json!({"sso": null}))
                            }
                            "credentialAdd" => {
                                if state.credentials.iter().any(|credential| credential["name"] == request["name"]) {
                                    return Err(format!("A credential named {} already exists", request["name"].as_str().unwrap_or_default()));
                                }
                                let id = format!("cred-{next}");
                                state.credentials.push(json!({"id": id, "name": request["name"], "kind": request["kind"], "note": request["note"].as_str().unwrap_or_default()}));
                                Ok(json!({"credentialId": id}))
                            }
                            "ruleAdd" => {
                                let index = find(&state.credentials, "name", &request["credential"]).ok_or("No such credential")?;
                                let decision = request["decision"].as_str().unwrap_or_default();
                                if !["allow", "ask", "never", ""].contains(&decision) {
                                    return Err(format!("'{decision}' is not a decision; use allow, ask or never"));
                                }
                                if std::mem::take(&mut state.fail_rule) {
                                    return Err("An Access Grid holds at most 500 rules".into());
                                }
                                let mut rule = request.clone();
                                rule["id"] = json!(format!("rule-{next}"));
                                rule["credential"] = state.credentials[index]["id"].clone();
                                rule["note"] = json!(request["note"].as_str().unwrap_or_default());
                                state.rules.push(rule);
                                Ok(json!({"ruleId": format!("rule-{next}")}))
                            }
                            "credentialRemove" => {
                                let index = find(&state.credentials, "name", &request["credential"]).ok_or("No such credential")?;
                                let removed = state.credentials.remove(index);
                                state.rules.retain(|rule| rule["credential"] != removed["id"]);
                                Ok(json!({}))
                            }
                            other => Err(format!("The fake Access Grid doesn't know {other}")),
                        }
                    }
                    "desks_status" => Ok(desks(&*state)),
                    "desks_create" => {
                        if state.desk_hub.is_some() {
                            return Err("This computer already runs a sandbox grid".into());
                        }
                        let address = params["address"].as_str().unwrap_or_default().to_owned();
                        state.desk_hub = Some(json!({"id": format!("desks-{next}"), "name": params["name"], "closing": null, "createdAt": at(),
                            "address": address, "port": 7470, "url": format!("https://{address}:7470/v1"), "invite": format!("desk-invite:fake-{next}")}));
                        state.desk_member = Some(json!({"memberId": "desk-member-self", "connected": true, "joinedAt": at()}));
                        Ok(desks(&*state))
                    }
                    "desks_join" => {
                        // As the product: an invite for the grid already joined just re-addresses it.
                        if state.desk_member.is_none() {
                            let (company, fingerprint) = invited(params["invite"].as_str().unwrap_or_default());
                            state.desk_member = Some(json!({"memberId": format!("desk-member-{next}"), "connected": true, "joinedAt": at(), "grid": company, "fingerprint": fingerprint, "gridId": format!("desks-joined-{next}")}));
                        }
                        Ok(desks(&*state))
                    }
                    "desks_delete" => {
                        let hub = state.desk_hub.as_mut().ok_or("This computer does not run a sandbox grid")?;
                        // As the product: `later` pauses it, `now` deletes it for good, and a grid
                        // deleted already can't be deleted again.
                        if hub["closing"]["gone"] == true {
                            return Err("This grid is already deleted; its computers are being told".into());
                        }
                        hub["closing"] = json!({"when": params["when"], "gone": params["when"] == "now"});
                        Ok(desks(&*state))
                    }
                    "desks_leave" => {
                        state.desk_member.take().ok_or("This computer is not in a sandbox grid")?;
                        Ok(desks(&*state))
                    }
                    "desks_member_share" => {
                        state.share = Some(params.clone());
                        Ok(json!({}))
                    }
                    "desks_person_add" => {
                        state.desk_hub.as_ref().ok_or("This computer does not run a sandbox grid")?;
                        if state.people.iter().any(|person| person["username"] == params["username"]) {
                            return Err("A person with that username already exists".into());
                        }
                        let id = format!("person-{next}");
                        let person = json!({"id": id, "username": params["username"], "desk": {"kind": params["kind"], "cpu": params["cpu"]}, "createdAt": at()});
                        state.people.push(person.clone());
                        // As the product: a person given a size gets their desk in the same step,
                        // named after them.
                        if !params["kind"].is_null() || !params["cpu"].is_null() {
                            let name = params["username"].as_str().unwrap_or_default().to_owned();
                            state.desks.push(json!({"id": format!("desk-{next}"), "name": name, "personId": id, "state": "ready",
                                "spec": {"kind": params["kind"], "cpu": params["cpu"], "memoryGb": params["memoryGb"], "diskGb": params["diskGb"], "gpu": params["gpu"]}, "image": Value::Null, "createdAt": at()}));
                        }
                        Ok(person)
                    }
                    "desks_add" => {
                        state.desk_hub.as_ref().ok_or("This computer does not run a sandbox grid")?;
                        let person = params["person"].as_str().unwrap_or_default().to_owned();
                        if !person.is_empty() && !state.people.iter().any(|known| known["id"] == person.as_str()) {
                            return Err("No person with that ID or username is in this grid".into());
                        }
                        if let Some(error) = state.fail_desk_add.take() {
                            return Err(error);
                        }
                        let desk = json!({"id": format!("desk-{next}"), "name": params["name"], "personId": if person.is_empty() { Value::Null } else { json!(person) }, "state": "ready",
                            "spec": {"kind": params["kind"], "cpu": params["cpu"], "memoryGb": params["memoryGb"], "diskGb": params["diskGb"], "gpu": params["gpu"]}, "image": params["image"], "createdAt": at()});
                        state.desks.push(desk.clone());
                        Ok(desk)
                    }
                    "desks_remove" => {
                        let before = state.desks.len();
                        state.desks.retain(|desk| desk["id"] != params["desk"]);
                        if state.desks.len() == before {
                            return Err("No desk with that ID is in this grid".into());
                        }
                        Ok(json!({"deskId": params["desk"], "removed": true}))
                    }
                    "desks_person_remove" => {
                        state.people.retain(|person| person["id"] != params["person"]);
                        Ok(json!({"removed": true}))
                    }
                    "desks_manage" => {
                        state.desk_hub.as_ref().ok_or("This computer does not run a sandbox grid")?;
                        let request = &params["request"];
                        match request["action"].as_str().unwrap_or_default() {
                            "personUpdate" => {
                                let wanted = request["id"].clone();
                                let person = state.people.iter_mut().find(|person| person["id"] == wanted || person["username"] == wanted).ok_or("No person with that ID or username is in this grid")?;
                                let role = request["adminRole"].as_str().unwrap_or("user");
                                if !["user", "auditor", "operator", "administrator"].contains(&role) {
                                    return Err("Invalid administrative role".into());
                                }
                                person["adminRole"] = json!(role);
                                Ok(json!({"id": person["id"]}))
                            }
                            "ssoSet" => {
                                state.desk_sso = Some(request.clone());
                                Ok(json!({"id": "sso", "set": true}))
                            }
                            "ssoClear" => {
                                state.desk_sso = None;
                                Ok(json!({"id": "sso", "set": false}))
                            }
                            "twoStepRequire" => {
                                state.desk_two_step = request["required"].as_bool().ok_or("Say required: true or false")?;
                                Ok(json!({"id": "twoStep", "required": state.desk_two_step}))
                            }
                            "computersOnly" => {
                                state.desk_only = if request["names"].is_null() { None } else { Some(request["names"].clone()) };
                                Ok(json!({"id": "computersOnly", "names": request["names"]}))
                            }
                            "cloudFallbackSet" => {
                                if !matches!(request["provider"].as_str(), Some("aws" | "azure" | "google")) {
                                    return Err("The cloud provider is aws, azure or google".into());
                                }
                                if request["identityFile"].as_str().unwrap_or_default().is_empty() {
                                    return Err("Give the cloud identity file".into());
                                }
                                state.desk_cloud = Some(request.clone());
                                Ok(json!({"id": "cloudFallback", "set": true}))
                            }
                            "cloudFallbackClear" => {
                                state.desk_cloud = None;
                                Ok(json!({"id": "cloudFallback", "set": false}))
                            }
                            _ => Err("Unknown Sandbox Grid management operation".into()),
                        }
                    }
                    "desk_login" => {
                        // As the product: a new sign-in replaces the saved one.
                        state.signed_in = params["username"].as_str().map(str::to_owned);
                        state.signed_in_grid = Some(invited(params["invite"].as_str().unwrap_or_default()).0);
                        Ok(json!({}))
                    }
                    "desk_logout" => {
                        state.signed_in = None;
                        state.signed_in_grid = None;
                        Ok(json!({}))
                    }
                    "grid_status" => Ok(status(&*state)),
                    "grid_create" => {
                        if state.hub.is_some() {
                            return Err("This computer already runs a Closed Neo Grid hub".into());
                        }
                        if params["password"].as_str().unwrap_or_default().len() < 10 {
                            return Err("The company password must be at least 10 characters".into());
                        }
                        let address = params["address"].as_str().unwrap_or_default().to_owned();
                        state.hub = Some(json!({"id": format!("grid-{next}"), "name": params["name"], "closing": null, "createdAt": at(),
                            "address": address, "port": 7460, "url": format!("https://{address}:7460/v1"), "invite": format!("grid-invite:fake-{next}")}));
                        state.member = Some(json!({"memberId": "member-self", "connected": true, "joinedAt": at()}));
                        Ok(status(&*state))
                    }
                    "grid_join" => {
                        // As the product: an invite for the grid already joined just re-addresses it.
                        if state.member.is_none() {
                            let (company, fingerprint) = invited(params["invite"].as_str().unwrap_or_default());
                            state.member = Some(json!({"memberId": format!("member-{next}"), "connected": true, "joinedAt": at(), "grid": company, "fingerprint": fingerprint, "gridId": format!("grid-joined-{next}")}));
                        }
                        Ok(status(&*state))
                    }
                    "grid_delete" => {
                        let hub = state.hub.as_mut().ok_or("This computer does not run a grid hub. Admins create one with `yougori grid create`.")?;
                        if hub["closing"]["gone"] == true {
                            return Err("This grid is already deleted; its computers are being told".into());
                        }
                        hub["closing"] = json!({"when": params["when"], "gone": params["when"] == "now"});
                        Ok(status(&*state))
                    }
                    "grid_leave" => {
                        state.member.take().ok_or("This computer is not in a grid")?;
                        Ok(status(&*state))
                    }
                    "grid_plan_add" => {
                        state.hub.as_ref().ok_or("This computer does not run a grid hub. Admins create one with `yougori grid create`.")?;
                        let plan = json!({"id": format!("plan-{next}"), "model": params["model"], "percent": params["percent"], "idleAfterMinutes": params["idleAfter"], "schedule": params["schedule"], "computers": params["computers"], "ready": 0, "createdAt": at()});
                        state.plans.push(plan.clone());
                        Ok(json!({"plan": plan}))
                    }
                    "grid_plan_update" => {
                        let plan = state.plans.iter_mut().find(|plan| plan["id"] == params["planId"]).ok_or("No plan with that ID exists in this grid")?;
                        for (field, given) in [("percent", "percent"), ("model", "model"), ("idleAfterMinutes", "idleAfter")] {
                            if !params[given].is_null() {
                                plan[field] = params[given].clone();
                            }
                        }
                        match params["schedule"].as_str() {
                            Some("") => plan["schedule"] = Value::Null,
                            Some(_) => plan["schedule"] = params["schedule"].clone(),
                            None => {}
                        }
                        Ok(json!({"plan": plan.clone()}))
                    }
                    "grid_plan_remove" => {
                        let before = state.plans.len();
                        state.plans.retain(|plan| plan["id"] != params["planId"]);
                        if state.plans.len() == before {
                            return Err("No plan with that ID exists in this grid".into());
                        }
                        Ok(json!({}))
                    }
                    "grid_swarm_add" => {
                        let harness = json!({"id": format!("harness-{next}"), "name": params["name"], "lead": params["lead"], "workers": params["workers"], "createdAt": at()});
                        state.harnesses.push(harness.clone());
                        Ok(json!({"harness": harness}))
                    }
                    "grid_swarm_remove" => {
                        let before = state.harnesses.len();
                        state.harnesses.retain(|harness| harness["id"] != params["harnessId"]);
                        if state.harnesses.len() == before {
                            return Err("No harness with that ID or name exists in this grid".into());
                        }
                        Ok(json!({}))
                    }
                    "runpod_status" => Ok(json!({"installed": true, "connected": state.runpod_connected})),
                    "get_platform_state" => Ok(json!({"environments": state.rented.iter().map(|(id, pod)| json!({"id": id, "name": pod["name"]})).collect::<Vec<_>>()})),
                    "runpod_create_pod" => {
                        let request = &params["request"];
                        if !request["maxHourlyUsd"].as_f64().is_some_and(|price| price > 0.0) {
                            return Err("Review the hourly price before creating the pod".into());
                        }
                        let id = format!("env-pod-{next}");
                        state.rented.insert(id.clone(), json!({"name": request["name"], "gpuId": request["gpuId"], "maxHourlyUsd": request["maxHourlyUsd"], "podState": "Running"}));
                        Ok(json!({"environments": state.rented.iter().map(|(id, pod)| json!({"id": id, "name": pod["name"]})).collect::<Vec<_>>()}))
                    }
                    "grid_neocloud_add" => {
                        let id = params["environmentId"].as_str().unwrap_or_default().to_owned();
                        let pod = state.rented.get(&id).cloned().ok_or("That NeoCloud pod no longer exists")?;
                        if state.pod_starts > 0 {
                            state.pod_starts -= 1;
                            return Err(format!("{} is still being created in NeoCloud, or needs checking there. Add it once NeoCloud shows it Running or Stopped.", pod["name"].as_str().unwrap_or_default()));
                        }
                        if state.pods.iter().any(|member| member["environmentId"] == id.as_str()) {
                            return Err("This pod is already in the grid.".into());
                        }
                        state.pods.push(json!({"environmentId": id, "gridId": params["gridId"], "name": pod["name"], "hourlyUsd": pod["maxHourlyUsd"], "podState": "Running", "state": "ready"}));
                        Ok(json!({"memberId": format!("member-{next}")}))
                    }
                    "grid_neocloud_remove" => {
                        let id = params["environmentId"].as_str().unwrap_or_default().to_owned();
                        state.pods.retain(|member| member["environmentId"] != id.as_str());
                        Ok(json!({}))
                    }
                    "runpod_action" => {
                        let id = params["environmentId"].as_str().unwrap_or_default().to_owned();
                        let action = params["action"].as_str().unwrap_or_default();
                        let pod = state.rented.get(&id).cloned().ok_or("Pod not found")?;
                        if action == "delete" && params["confirmation"] != pod["name"] {
                            return Err("Type the name to delete it".into());
                        }
                        match action {
                            "delete" => {
                                state.rented.remove(&id);
                            }
                            "stop" | "start" => {
                                let now = if action == "stop" { "Exited" } else { "Running" };
                                if let Some(pod) = state.rented.get_mut(&id) {
                                    pod["podState"] = json!(now);
                                }
                                for member in state.pods.iter_mut().filter(|member| member["environmentId"] == id.as_str()) {
                                    member["podState"] = json!(now);
                                }
                            }
                            other => return Err(format!("{other} is not a pod action")),
                        }
                        Ok(json!({}))
                    }
                    "bounty_status" => Ok(json!({"host": state.bounty})),
                    "bounty_delete" => {
                        state.bounty = None;
                        Ok(json!({"deleted": true}))
                    }
                    "bounty_dispatch" => {
                        let request = params["request"].clone();
                        match request["action"].as_str().unwrap_or_default() {
                            "inspectProject" => {
                                let folder = request["path"].as_str().unwrap_or_default().to_owned();
                                if folder.is_empty() {
                                    return Err("Choose a project folder".into());
                                }
                                state.inspected.push(folder);
                                Ok(json!({"name": "project", "fileCount": 3, "bytes": 2048, "importId": format!("import-{next}")}))
                            }
                            "hostSource" => {
                                if request["confirmed"] != true {
                                    return Err("Confirm the project and hosting scope".into());
                                }
                                if state.bounty.is_some() {
                                    return Err("This computer already hosts a closed bounty; delete it first with 'yougori bounty delete --yes'".into());
                                }
                                if request["authorization"].as_str().unwrap_or_default().trim().is_empty() {
                                    return Err("Describe what the workers are authorised to test".into());
                                }
                                if request["target"]["kind"] == "url" {
                                    return Err("The fake never hosts a live target".into());
                                }
                                state.hosted_with = Some(request.clone());
                                let host = json!({"id": format!("bounty-{next}"), "name": request["name"], "address": request["address"], "port": 7462, "createdAt": at(),
                                    "computers": {"total": 1, "online": 1, "working": 0}, "members": [], "invite": format!("{}fake-{next}", yougori_grid::invite::BOUNTY_PREFIX)});
                                state.bounty = Some(host.clone());
                                Ok(host)
                            }
                            action @ ("localConnect" | "connect") => {
                                let policy = if action == "localConnect" {
                                    let hosted = state.hosted_with.clone().ok_or("Host a private bounty first")?;
                                    state.bounty.as_ref().ok_or("Host a private bounty first")?;
                                    json!({"networkMode": "closed", "title": hosted["title"], "objective": hosted["instructions"], "authorization": hosted["authorization"],
                                        "scopeMode": "local_source_only", "target": hosted["target"], "termsDigest": format!("{:0>64}", format!("{next}a1b2c3d4e5f6"))})
                                } else {
                                    if request["password"].as_str() != Some("correct horse battery") {
                                        return Err("The project password is wrong".into());
                                    }
                                    state.remote_policy.clone().ok_or("No review answers at that address")?
                                };
                                let ticket = format!("ticket-{next}");
                                state.tickets.insert(ticket.clone(), policy.clone());
                                Ok(json!({"ticket": ticket, "policy": policy}))
                            }
                            "discardConnection" => {
                                state.tickets.remove(request["ticket"].as_str().unwrap_or_default());
                                Ok(json!({"discarded": true}))
                            }
                            "startWorker" => {
                                if request["confirmed"] != true {
                                    return Err("Review the private project and its commands before starting".into());
                                }
                                let policy = state.tickets.remove(request["ticket"].as_str().unwrap_or_default()).ok_or("Connection expired; connect again")?;
                                if policy["termsDigest"] != request["termsDigest"] {
                                    return Err("The project changed; review it again".into());
                                }
                                state.started_with.push(request.clone());
                                let worker = json!({"id": format!("worker-{next}"), "name": request["worker"]["name"], "model": request["worker"]["model"], "networkMode": "closed", "state": "preparing", "error": Value::Null});
                                state.workers.push(worker.clone());
                                Ok(json!({"worker": worker, "background": true}))
                            }
                            _ => Err("Unknown private bounty operation".into()),
                        }
                    }
                    "swarm_dispatch" => {
                        let request = &params["request"];
                        let id = request["workerId"].as_str().unwrap_or_default().to_owned();
                        let action = request["action"].as_str().unwrap_or_default();
                        let index = state.workers.iter().position(|worker| worker["id"] == id.as_str()).ok_or("No worker with that ID")?;
                        match action {
                            "status" => Ok(json!({"worker": state.workers[index]})),
                            "pause" | "resume" => {
                                state.workers[index]["state"] = json!(if action == "pause" { "paused" } else { "running" });
                                Ok(json!({"worker": state.workers[index]}))
                            }
                            "delete" => {
                                let worker = state.workers.remove(index);
                                Ok(json!({"worker": worker, "deleted": true}))
                            }
                            other => Err(format!("The fake worker doesn't know {other}")),
                        }
                    }
                    "grid_neocloud_status" => {
                        // As the product: the rented GPUs of the grid named, or of every grid.
                        let grid = params["gridId"].as_str();
                        let members = state.pods.iter().filter(|pod| grid.is_none_or(|grid| pod["gridId"] == grid)).cloned().collect::<Vec<_>>();
                        Ok(json!({"members": members}))
                    }
                    "grid_neocloud_stop_all" => {
                        // The product stops every grid's GPUs when no grid is named. The fake
                        // refuses that, so a test proves a setup always names its own grid.
                        let grid = params["gridId"].as_str().ok_or("The fake refuses a stop of every grid's rented GPUs")?.to_owned();
                        let pending = std::mem::take(&mut state.stop_pending);
                        for pod in state.pods.iter_mut().filter(|pod| pod["gridId"] == grid.as_str()) {
                            pod["podState"] = json!(if pending { "Stopping" } else { "Exited" });
                        }
                        Ok(json!({"message": if pending {
                            "Every rented GPU in the grid was sent a stop. NeoCloud still shows 1 of them stopping; Yougori checks them again shortly. They stay in the grid, offline, until you start them in NeoCloud."
                        } else {
                            "Every rented GPU in the grid was stopped. They stay in the grid, offline, until you start them in NeoCloud."
                        }}))
                    }
                    other => Err(format!("The fake grid doesn't know {other}")),
                }
    }
}
